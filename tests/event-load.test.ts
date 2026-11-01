// Event load and coordinated publication, measured. Part one: 25 real participants on
// one venue network publish, search, read their intro inbox, request intros and sign up
// for email. Part two: one other source spreads near identical cards across 20 keys
// into the same event. Hard rules are asserted. Shared limits and the effect on
// discovery and matching are measured and printed as METRIC lines for the review.
// Synthetic keys and data only.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-event-test-'))
process.env.DB_PATH = join(tmpDir, 'event-test.db')
process.env.MINGLE_ALLOW_RESERVED_EMAIL_DOMAINS = '0'

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const matchesDb = await import('../src/matches-db.js')
const v3db = await import('../src/v3-db.js')
const blocks = await import('../src/source-blocks.js')
const email = await import('../src/notifications.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(resolve => { server = app.listen(0, '127.0.0.1', () => resolve()) })
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })

type Keys = { publicKey: string; privateKey: string }

function makeCard(keys: Keys, overrides: Record<string, unknown> = {}, createdOffsetMs = 0): Record<string, any> {
  const now = Date.now() + createdOffsetMs
  const card: Record<string, any> = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(now).toISOString(),
    expires_at: new Date(now + 21 * 24 * 3600 * 1000).toISOString(),
    headline: 'Engineer seeking collaborators on agent delegation',
    intents: ['collaborate'],
    seeking: [{ description: 'Collaborators on agent delegation and revocation', topics: ['delegation', 'revocation'], engagement: 'part_time' }],
    offering: [{ description: 'Experience building delegation verifiers', topics: ['delegation'], provenance: 'principal_statement' }],
    preferences: [], artifacts: [], event_ref: null, team_size_sought: null,
    visibility: { headline: 'network', seeking: 'network', offering: 'network' },
    composition: { agent_assisted: true, skill_version: 'mingle-composer-v1' },
    delegation_ref: null, revocation_status: 'active',
    ...overrides,
  }
  return seal(card, keys)
}

function seal(card: Record<string, any>, keys: Keys): Record<string, any> {
  delete card.signature; delete card.approval
  const card_hash = cardContentHash(card)
  card.approval = { card_hash, approved_at: new Date().toISOString(), principal_signature: sign(card_hash, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return card
}





const sentMail: { to: string }[] = []
email.setTransport(async (e) => { sentMail.push(e); return { ok: true, id: 'mock' } })
let ipSeq = 10
const newSource = () => ({ 'X-Forwarded-For': `198.18.0.${ipSeq++}, 84.17.44.229` })
async function req(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) })
  const text = await r.text(); let j: any = null; try { j = JSON.parse(text) } catch { /* html */ }
  return { status: r.status, body: j, text }
}
const publish = (card: Record<string, any>, h: Record<string, string>) => req('POST', '/api/v3/cards', { card }, h)
const search = (filters: Record<string, unknown>, h: Record<string, string>, key?: string) => req('POST', '/api/v3/cards/search', { limit: 50, ...filters }, key ? { ...h, 'X-Public-Key': key } : h)
const verb = (k: Keys, id: string, name: string, h: Record<string, string>) => req('POST', `/api/v3/cards/${id}/${name}`, { public_key: k.publicKey, signature: sign(`${name}:${id}`, k.privateKey) }, h)
const intro = (k: Keys, from: string, to: string, h: Record<string, string>) => {
  const nonce = `n-${Math.random().toString(16).slice(2)}`
  return req('POST', '/api/v3/intros/request', { from_card: from, to_card: to, purpose: 'collaborate', note: 'hi', public_key: k.publicKey, nonce, signature: sign(`intro-request:${from}:${to}:collaborate:${nonce}`, k.privateKey) }, h)
}
const respond = (k: Keys, introId: string, action: string, h: Record<string, string>, contact?: string) => {
  const nonce = `r-${Math.random().toString(16).slice(2)}`
  return req('POST', `/api/v3/intros/${introId}/respond`, { action, public_key: k.publicKey, nonce, signature: sign(`intro-respond:${introId}:${action}:${nonce}`, k.privateKey), ...(contact ? { contact } : {}) }, h)
}
const subscribe = (k: Keys, addr: string, h: Record<string, string>) => {
  const nonce = `s-${Math.random().toString(16).slice(2)}`
  return req('POST', '/api/v3/notifications/subscribe', { subject_key: k.publicKey, email: addr, nonce, signature: sign(`${addr}:${nonce}`, k.privateKey) }, h)
}
const statuses = (rs: { status: number }[]) => rs.map(r => r.status)
const count = (rs: { status: number }[], s: number) => rs.filter(r => r.status === s).length


const EVENT = 'event-load-2611'
const TOPICS = ['delegation', 'robotics', 'climate data', 'fintech', 'design systems', 'bioinformatics', 'edtech', 'music tools', 'security', 'open hardware']
const metric = (name: string, value: unknown) => console.log(`METRIC ${name} ${JSON.stringify(value)}`)
const tally = (rs: { status: number }[]) => rs.reduce((m: Record<number, number>, r) => { m[r.status] = (m[r.status] ?? 0) + 1; return m }, {})
const people: { k: Keys; card: string }[] = []
const venue = newSource()

test('EVENT 25 participants on one venue network', async () => {
  const pub = []
  for (let i = 0; i < 25; i++) {
    const k = generateKeyPair()
    const t = TOPICS[i % TOPICS.length]
    const r = await publish(makeCard(k, {
      headline: `Attendee ${i} working on ${t}`, intents: ['collaborate'], event_ref: { event_id: EVENT },
      seeking: [{ description: `People who build ${t} tools, for a pilot`, topics: [t], engagement: 'part_time' }],
      offering: [{ description: `Two years of ${t} work and a working prototype`, topics: [t], provenance: 'principal_statement' }],
    }), venue)
    pub.push(r)
    if (r.status === 201) people.push({ k, card: r.body.card_id })
  }
  metric('event.publish', tally(pub))
  assert.equal(people.length, 25, 'every attendee can publish')

  const srch = []
  for (const p of people) for (let j = 0; j < 2; j++) srch.push(await search({ event_ref: EVENT }, venue, p.k.publicKey))
  metric('event.search', tally(srch))
  assert.equal(srch.filter(r => r.status === 200).length, 50, 'search is per key, so a venue does not share one budget')

  const inbox = []
  for (const p of people) for (let j = 0; j < 3; j++) inbox.push(await req('GET', `/api/v3/intros/mine?public_key=${encodeURIComponent(p.k.publicKey)}`, undefined, venue))
  metric('event.intro_inbox_reads', { refused_429: inbox.filter(r => r.status === 429).length, of: inbox.length })

  const intros = []
  for (let i = 0; i < 25; i++) intros.push(await intro(people[i].k, people[i].card, people[(i + 1) % 25].card, venue))
  metric('event.intro_requests', tally(intros))

  const before = sentMail.length
  const subs = []
  for (let i = 0; i < 25; i++) subs.push(await subscribe(people[i].k, `attendee${i}@event-mail.org`, venue))
  metric('event.email_signup', { ...tally(subs), emails_sent: sentMail.length - before })
})

test('COORDINATED one source spreads near identical cards across 20 keys into the same event', async () => {
  const ev = (e: string) => (db.getDb().prepare(`SELECT COUNT(*) n FROM card_events WHERE event = ?`).get(e) as any).n
  const realIds = new Set(people.map(p => p.card))
  const runsBefore = ev('matching_started')
  const matchesTouchingReal = () => (db.getDb().prepare('SELECT card_a, card_b FROM v3_matches').all() as any[]).filter(m => realIds.has(m.card_a) || realIds.has(m.card_b))
  const realMatchesBefore = matchesTouchingReal().length

  const src = newSource(); const pub = []; const theirs = new Set<string>()
  for (let k = 0; k < 20; k++) {
    const keys = generateKeyPair()
    for (let i = 0; i < 3; i++) {
      const r = await publish(makeCard(keys, {
        headline: `Open-data release confirmed: DR-${16 + k} joins the register (${i})`, intents: ['collaborate'], event_ref: { event_id: EVENT },
        seeking: [{ description: `Sign-off from the register reviewer, batch ${k}.${i}`, topics: TOPICS, engagement: 'part_time' }],
        offering: [{ description: `Open-data release of DR-${16 + k} under permit PRM-2026-${26 + i}`, topics: TOPICS, provenance: 'principal_statement' }],
      }, i * 1000), src)
      pub.push(r)
      if (r.status === 201) theirs.add(r.body.card_id)
    }
  }
  metric('coord.publish', tally(pub))
  assert.ok(theirs.size <= SOURCE_CAP_E, `accepted ${theirs.size}`)

  const viewer = generateKeyPair()
  const wall = await search({ event_ref: EVENT, limit: 50 }, newSource(), viewer.publicKey)
  const ids: string[] = (wall.body.results ?? []).map((c: any) => c.card_id)
  metric('coord.event_search_top50', { real: ids.filter(i => realIds.has(i)).length, coordinated: ids.filter(i => theirs.has(i)).length })
  assert.equal(ids.filter(i => realIds.has(i)).length, 25, 'every attendee is still on the first page of the event')
  assert.ok(ids.filter(i => theirs.has(i)).length <= 3, 'the coordinated source shows at most 3 near identical cards')
  const topical = await search({ topics: ['robotics'], limit: 50 }, newSource(), viewer.publicKey)
  const tids: string[] = (topical.body.results ?? []).map((c: any) => c.card_id)
  metric('coord.topic_search_top50', { real: tids.filter(i => realIds.has(i)).length, coordinated: tids.filter(i => theirs.has(i)).length })
  assert.ok(tids.filter(i => realIds.has(i)).length >= 1, 'the real robotics attendees are on the page')

  const touching = matchesTouchingReal()
  const fromThem = touching.filter(m => theirs.has(m.card_a) || theirs.has(m.card_b)).length
  metric('coord.matches_touching_real_cards', { before: realMatchesBefore, after: touching.length, with_coordinated_card: fromThem })
  metric('coord.matching_runs', ev('matching_started') - runsBefore)
  assert.ok(fromThem <= 6 * 25, `near identical repeats do not match: ${fromThem} matches with coordinated cards`)
  assert.ok(ev('matching_started') - runsBefore <= 10, 'repeats skip the matching run')
  assert.equal(touching.length - fromThem, realMatchesBefore, 'the real attendees still match each other exactly as before')
  const sameKey = (db.getDb().prepare('SELECT COUNT(*) n FROM v3_matches x JOIN v3_cards a ON a.card_id=x.card_a JOIN v3_cards b ON b.card_id=x.card_b WHERE a.subject_key = b.subject_key').get() as any).n
  assert.equal(sameKey, 0, 'no key matches its own cards')
  metric('coord.match_emails_sent', sentMail.filter(e => /new match/i.test((e as any).subject ?? '')).length)
})

const SOURCE_CAP_E = Number(process.env.MINGLE_PUBLISH_PER_SOURCE ?? 60)

test('EVENT with an operator email allowance every attendee can confirm their email', async () => {
  const { allowSourceEmail } = await import('../src/confirm-guard.js')
  const hall = newSource()
  allowSourceEmail(hall['X-Forwarded-For'].split(',')[0], 40, 'test event', 'operator-test', { hours: 6 })
  const before = sentMail.length; const rs = []
  for (let i = 0; i < 25; i++) rs.push(await subscribe(generateKeyPair(), `hall${i}@event-mail.org`, hall))
  metric('event.email_signup_with_allowance', { ...tally(rs), emails_sent: sentMail.length - before })
  assert.equal(sentMail.length - before, 25)
})

test('FAIRNESS a key shows at most 3 cards on a page, and similar cards from different networks are never folded', async () => {
  const k = generateKeyPair(); const h = newSource()
  for (let i = 0; i < 5; i++) await publish(makeCard(k, { headline: `Fairness key card ${i} on ${TOPICS[i]}`, event_ref: { event_id: 'fair-1' }, seeking: [{ description: `Partners in ${TOPICS[i]}`, topics: [TOPICS[i]], engagement: 'part_time' }] }, i * 1000), h)
  const r = await search({ event_ref: 'fair-1' }, newSource(), generateKeyPair().publicKey)
  assert.equal((r.body.results ?? []).length, 3)
  assert.equal(r.body.folded_for_fairness, 2)
  const same = { headline: 'Same wording on two networks', event_ref: { event_id: 'fair-2' } }
  for (let i = 0; i < 5; i++) await publish(makeCard(generateKeyPair(), same), newSource())
  const r2 = await search({ event_ref: 'fair-2' }, newSource(), generateKeyPair().publicKey)
  assert.equal((r2.body.results ?? []).length, 5, 'the same words from five networks are five people')
})
