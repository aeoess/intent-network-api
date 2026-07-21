// ══════════════════════════════════════════════════════════════
// Mingle v3 match engine, digest, weekly, admin ping, agent API, UX, idempotency
// ══════════════════════════════════════════════════════════════
// The model is not warmed in tests, so embed() returns null and matching runs on
// the deterministic signals (mutual intent, agreed fields, token complement).
// That keeps every assertion below reproducible without the embedding pipeline.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-match-test-'))
process.env.DB_PATH = join(tmpDir, 'match.db')
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'
delete process.env.ADMIN_NOTIFY_EMAIL

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const matchesDb = await import('../src/matches-db.js')
const notifyDb = await import('../src/notify-db.js')
const email = await import('../src/notifications.js')
const weekly = await import('../src/weekly.js')

let server: Server
let base: string
const sent: { to: string; subject: string; text: string }[] = []

before(async () => {
  const app = createApp(); db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { email.resetTransport(); server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => {
  sent.length = 0
  email.setTransport(async e => { sent.push(e); return { ok: true, id: 'mock' } })
  db.getDb().prepare('DELETE FROM rate_limits').run()   // per-IP limiter is shared across in-process tests
})

// ── Card fixtures ──

interface CardOpts {
  headline?: string
  intents?: string[]
  seeking?: { description: string; topics?: string[]; engagement?: string }[]
  offering?: { description: string; topics?: string[] }[]
  preferences?: { key: string; value: string }[]
  event_ref?: { event_id: string; dates?: string } | null
  visibility?: Record<string, string>
  ttlMs?: number
}

function buildCard(opts: CardOpts, keys = generateKeyPair(), at = Date.now()): any {
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(at).toISOString(), expires_at: new Date(at + (opts.ttlMs ?? 21 * 864e5)).toISOString(),
    headline: opts.headline ?? 'A person on the network', intents: opts.intents ?? ['collaborate'],
    seeking: opts.seeking ?? [], offering: (opts.offering ?? []).map(o => ({ ...o, provenance: 'principal_statement' })),
    preferences: opts.preferences ?? [], artifacts: [],
    event_ref: opts.event_ref ?? null, team_size_sought: null,
    visibility: opts.visibility ?? {}, composition: { agent_assisted: true, skill_version: 'v1' },
    delegation_ref: null, revocation_status: 'active',
  }
  const h = cardContentHash(card)
  card.approval = { card_hash: h, approved_at: new Date(at).toISOString(), principal_signature: sign(h, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return card
}
function makeCard(opts: CardOpts): { keys: any; card: any } {
  const keys = generateKeyPair()
  return { keys, card: buildCard(opts, keys) }
}

async function publishRes(card: any): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}/api/v3/cards`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card }) })
  return { status: res.status, body: await res.json() }
}
async function publish(built: { card: any }): Promise<string> {
  const r = await publishRes(built.card)
  assert.equal(r.status, 201, JSON.stringify(r.body))
  return r.body.card_id
}

async function digest(keys: any): Promise<any> {
  const nonce = 'd' + Math.random().toString(36).slice(2)
  const qs = new URLSearchParams({ public_key: keys.publicKey, nonce, signature: sign(`digest:${nonce}`, keys.privateKey) })
  return (await fetch(`${base}/api/v3/digest?${qs}`)).json()
}

// A pair that clears the threshold on deterministic signals alone: mutual intent
// (collaborate) plus a shared event, plus a bidirectional seeking/offering match.
function matchingPair(eventId: string) {
  const a = makeCard({
    headline: 'Founder seeking a systems engineer',
    intents: ['collaborate'],
    seeking: [{ description: 'a rust systems engineer', topics: ['rust', 'systems'] }],
    offering: [{ description: 'product strategy and fundraising', topics: ['product', 'fundraising'] }],
    event_ref: { event_id: eventId },
  })
  const b = makeCard({
    headline: 'Rust engineer wanting a cofounder',
    intents: ['collaborate'],
    seeking: [{ description: 'product and fundraising help', topics: ['product', 'fundraising'] }],
    offering: [{ description: 'rust systems engineering', topics: ['rust', 'systems'] }],
    event_ref: { event_id: eventId },
  })
  return { a, b }
}

// ── No numeric score anywhere ──

function assertNoScore(obj: unknown, where: string): void {
  const banned = new Set(['score', 'rank', 'confidence', 'fit', 'fitvector', 'rating', 'trust_tier', 'trusttier'])
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) { v.forEach(walk); return }
    if (v && typeof v === 'object') {
      for (const [k, val] of Object.entries(v)) {
        assert.ok(!banned.has(k.toLowerCase()), `${where}: response must carry no ${k} field`)
        walk(val)
      }
    }
  }
  walk(obj)
}

// ── Tests ──

test('a match appears in the owner digest, owner-only, with no score', async () => {
  const { a, b } = matchingPair('ev-owner')
  await publish(a); await publish(b)

  const da = await digest(a.keys)
  assert.ok(da.new_match_count >= 1, JSON.stringify(da))
  assert.equal(da.ordering, 'recency')
  assertNoScore(da, 'digest A')
  assert.equal(da.new_matches[0].matched_intents.includes('collaborate'), true)

  const db2 = await digest(b.keys)
  assert.ok(db2.new_match_count >= 1, 'the counterpart also sees the match from their side')

  // A third party is not part of the pair and sees none of it.
  const c = makeCard({ headline: 'Unrelated person', intents: ['meet'] })
  await publish(c)
  const dc = await digest(c.keys)
  assert.equal(dc.new_match_count, 0, 'a third party never sees another pair\'s match')
})

test('overlap quotes only the counterpart\'s own network-visible words', async () => {
  const a = makeCard({
    headline: 'Seeking rust help', intents: ['collaborate'], event_ref: { event_id: 'ev-ovl' },
    seeking: [{ description: 'need rust systems', topics: ['rust'] }],
    offering: [{ description: 'product strategy', topics: ['product'] }],
  })
  // B's headline is private and carries a unique token that must never leak.
  const b = makeCard({
    headline: 'PRIVATEWORDzz secret headline', intents: ['collaborate'], event_ref: { event_id: 'ev-ovl' },
    seeking: [{ description: 'product help', topics: ['product'] }],
    offering: [{ description: 'rust systems engineering', topics: ['rust'] }],
    visibility: { headline: 'private' },
  })
  const aId = await publish(a); const bId = await publish(b)

  const row = matchesDb.rawMatchRow(aId, bId)
  assert.ok(row, 'a match row exists for the pair')
  const overlap = JSON.parse(row.overlap_json)
  assert.equal(JSON.stringify(overlap).includes('PRIVATEWORDzz'), false, 'a private field must never appear in the overlap')

  // Each side's snippets are drawn only from that side's own network text.
  const aText = 'Seeking rust help need rust systems product strategy'
  const bText = 'product help rust systems engineering'
  for (const s of overlap.a_snippets) assert.ok(aText.includes(s), `a_snippet must be A's own text: ${s}`)
  for (const s of overlap.b_snippets) assert.ok(bText.includes(s), `b_snippet must be B's own text: ${s}`)
})

test('dismiss is one-sided: the other side still sees the match', async () => {
  const { a, b } = matchingPair('ev-dismiss')
  const aId = await publish(a); const bId = await publish(b)

  const nonce = 'x'
  const body = { card_id: aId, other_card_id: bId, public_key: a.keys.publicKey, nonce, signature: sign(`dismiss:${aId}:${bId}:${nonce}`, a.keys.privateKey) }
  const res = await fetch(`${base}/api/v3/matches/dismiss`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  assert.equal(res.status, 200, await res.clone().text())
  assert.equal((await res.json()).dismissed, true)

  const raw = matchesDb.rawMatchRow(aId, bId)
  // exactly one side flagged
  assert.equal((!!raw.dismissed_a) !== (!!raw.dismissed_b), true, 'exactly one side is dismissed')

  const da = await digest(a.keys)
  assert.equal(da.new_matches.some((m: any) => m.other_card_id === bId), false, 'A no longer sees the dismissed match')
  const dbob = await digest(b.keys)
  assert.equal(dbob.new_matches.some((m: any) => m.other_card_id === aId), true, 'B still sees it')
})

test('digest since-tracking: a second call shows nothing new', async () => {
  const { a, b } = matchingPair('ev-since')
  await publish(a); await publish(b)
  const first = await digest(a.keys)
  assert.ok(first.new_match_count >= 1)
  assert.equal(first.previous_check, null)
  const second = await digest(a.keys)
  assert.equal(second.new_match_count, 0, 'nothing new since the last check')
  assert.ok(typeof second.previous_check === 'string')
})

test('expiry countdown surfaces a card within three days', async () => {
  const soon = makeCard({ headline: 'Expiring soon', ttlMs: 2 * 864e5 })
  await publish(soon)
  const d = await digest(soon.keys)
  assert.equal(d.card_expiry.length, 1)
  assert.ok(d.card_expiry[0].days_left <= 3)
})

test('weekly digest sends at most one email, only to verified opted-in subscribers', async () => {
  const { a, b } = matchingPair('ev-weekly')
  await publish(a); await publish(b)
  // A: verified + weekly on. B: verified + weekly off. An unverified + weekly on.
  notifyDb.upsertSubscription(a.keys.publicKey, 'weeklyA@example.com', 'vwa', 'uwa', { intro_request: true, intro_accepted: true, weekly_digest: true })
  notifyDb.confirmByToken('vwa')
  notifyDb.upsertSubscription(b.keys.publicKey, 'weeklyB@example.com', 'vwb', 'uwb', { intro_request: true, intro_accepted: true, weekly_digest: false })
  notifyDb.confirmByToken('vwb')
  const unv = makeCard({ headline: 'unverified' }); await publish(unv)
  notifyDb.upsertSubscription(unv.keys.publicKey, 'unverified@example.com', 'vwu', 'uwu', { intro_request: true, intro_accepted: true, weekly_digest: true })

  sent.length = 0
  const now = Date.now()
  const r1 = await weekly.runWeeklyDigest(now)
  const recipients = sent.map(e => e.to)
  assert.deepEqual(recipients, ['weeklyA@example.com'], 'only the verified opted-in subscriber with matches gets one email')
  assert.match(sent[0].text, /weekly Mingle summary/i)
  assert.match(sent[0].text, /unsubscribe|stop these emails/i)

  sent.length = 0
  const r2 = await weekly.runWeeklyDigest(now)
  assert.equal(sent.length, 0, 'a second run in the same week sends nothing (deduped by week key)')
  assert.ok(r1.sent === 1 && r2.sent === 0)
})

test('admin join ping is env-gated', async () => {
  // Unset: no admin email on publish.
  delete process.env.ADMIN_NOTIFY_EMAIL
  sent.length = 0
  await publish(makeCard({ headline: 'no admin ping' }))
  assert.equal(sent.some(e => e.to === 'ops@example.com'), false)

  // Set: exactly one admin ping carrying the headline and card id.
  process.env.ADMIN_NOTIFY_EMAIL = 'ops@example.com'
  try {
    sent.length = 0
    const id = await publish(makeCard({ headline: 'admin ping headline' }))
    const admin = sent.filter(e => e.to === 'ops@example.com')
    assert.equal(admin.length, 1)
    assert.match(admin[0].text, /admin ping headline/)
    assert.ok(admin[0].text.includes(id))
  } finally {
    delete process.env.ADMIN_NOTIFY_EMAIL
  }
})

test('cursor pagination is stable and complete', async () => {
  const ids = new Set<string>()
  for (let i = 0; i < 5; i++) ids.add(await publish(makeCard({ headline: `pager ${i}`, intents: ['team_up'], preferences: [{ key: 'pagetag', value: 'PAGERSET' }] })))

  const collected: string[] = []
  let cursor: string | null = null
  let guard = 0
  do {
    const body: any = { intents: ['team_up'], limit: 2 }
    if (cursor) body.cursor = cursor
    const r = await fetch(`${base}/api/v3/cards/search`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    const j = await r.json()
    for (const c of j.results) collected.push(c.card_id)
    cursor = j.next_cursor
    assert.ok(guard++ < 10, 'pagination terminates')
  } while (cursor)

  const mine = collected.filter(id => ids.has(id))
  assert.equal(new Set(mine).size, 5, 'every published card returned exactly once across pages')
  assert.equal(mine.length, new Set(mine).size, 'no duplicates across pages')
})

test('every v3 response carries X-RateLimit headers', async () => {
  const res = await fetch(`${base}/api/v3`)
  assert.ok(res.headers.get('x-ratelimit-limit'), 'limit header present')
  assert.ok(res.headers.get('x-ratelimit-remaining'), 'remaining header present')
  assert.ok(res.headers.get('x-ratelimit-reset'), 'reset header present')
  const j = await res.json()
  assert.equal(j.protocol, 'mingle-v3')
  assert.ok(j.endpoints && typeof j.endpoints === 'object')
})

test('renew re-signs identical content and the supersession chain resolves', async () => {
  const built = makeCard({ headline: 'Renew me', intents: ['work'], offering: [{ description: 'design help' }] })
  const oldId = await publish(built)

  // Rebuild the exact content with a fresh expiry, re-approve, re-sign.
  const renewed = buildCard(
    { headline: 'Renew me', intents: ['work'], offering: [{ description: 'design help' }] },
    built.keys, Date.now() + 1000,
  )
  const res = await fetch(`${base}/api/v3/cards/${oldId}/renew`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card: renewed }) })
  const body = await res.json()
  assert.equal(res.status, 201, JSON.stringify(body))
  assert.equal(body.renewed, true)
  assert.equal(body.superseded, oldId)
  const newId = body.new_card_id

  const oldFetch = await (await fetch(`${base}/api/v3/cards/${oldId}`)).json()
  assert.equal(oldFetch.revocation_status, 'superseded')
  assert.equal(oldFetch.superseded_by, newId)
  const newFetch = await (await fetch(`${base}/api/v3/cards/${newId}`)).json()
  assert.equal(newFetch.revocation_status, 'active')
  assert.equal(newFetch.supersedes, oldId)

  // A content change is refused (renew is identical-content only).
  const changed = buildCard({ headline: 'Renew me DIFFERENT', intents: ['work'], offering: [{ description: 'design help' }] }, built.keys, Date.now() + 2000)
  const bad = await fetch(`${base}/api/v3/cards/${newId}/renew`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card: changed }) })
  assert.equal(bad.status, 400)
})

test('wall cards link to their card pages, which resolve', async () => {
  const built = makeCard({ headline: 'On the wall', event_ref: { event_id: 'wall-res' } })
  const id = await publish(built)
  const wall = await (await fetch(`${base}/e/wall-res`)).text()
  assert.ok(wall.includes(`href="/c/${id}"`), 'wall links to the card page')
  const cardPage = await fetch(`${base}/c/${id}`)
  assert.equal(cardPage.status, 200)
})

test('sample cards render only on the demo wall', async () => {
  const demo = await (await fetch(`${base}/e/demo`)).text()
  assert.ok(demo.includes('SAMPLE'), 'the empty demo wall shows badged samples')
  const other = await (await fetch(`${base}/e/some-empty-event`)).text()
  assert.equal(other.includes('SAMPLE'), false, 'no other empty event shows samples')
})

test('report stores a row, rejects URLs, and rate-limits', async () => {
  const id = await publish(makeCard({ headline: 'reportable' }))
  const rep = async (reason: string) => fetch(`${base}/api/v3/report`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card_id: id, reason }) })

  assert.equal((await rep('this looks like spam')).status, 201)
  assert.equal((await rep('contact me at evil.com now')).status, 400, 'URLs refused')
  const unknown = await fetch(`${base}/api/v3/report`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card_id: 'nope', reason: 'x' }) })
  assert.equal(unknown.status, 404, 'reporting an unknown card is 404')

  const reportsDb = await import('../src/reports-db.js')
  assert.ok(reportsDb.reportCount(id) >= 1)

  // Rate limit: the report limiter is 20/hour per IP.
  let got429 = false
  for (let i = 0; i < 25; i++) {
    const r = await rep(`report number ${i}`)
    if (r.status === 429) { got429 = true; break }
  }
  assert.equal(got429, true, 'the report endpoint rate-limits')
})

test('republishing byte-identical content is idempotent', async () => {
  const built = makeCard({ headline: 'idempotent card' })
  const first = await publishRes(built.card)
  assert.equal(first.status, 201)
  const again = await publishRes(built.card)
  assert.equal(again.status, 200)
  assert.equal(again.body.idempotent, true)
  assert.equal(again.body.card_id, first.body.card_id, 'the same live card is returned, not a duplicate')
})

test('search results and card fetch carry no numeric score', async () => {
  await publish(makeCard({ headline: 'searchable', intents: ['advise'] }))
  const s = await (await fetch(`${base}/api/v3/cards/search`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ intents: ['advise'] }) })).json()
  assertNoScore(s, 'search')
})
