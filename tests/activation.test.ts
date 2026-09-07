// ══════════════════════════════════════════════════════════════
// Activation pass 1 - expired vs withdrawn, event ledger, stats, match push
// ══════════════════════════════════════════════════════════════
// Same bootstrap as matches.test.ts: in-process app, throwaway DB, real
// Ed25519 signatures, a recording email transport. The embedding model is cold
// here too, so matching runs on the deterministic signals only.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-activation-test-'))
process.env.DB_PATH = join(tmpDir, 'activation.db')
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'
delete process.env.ADMIN_NOTIFY_EMAIL

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const v3db = await import('../src/v3-db.js')
const matchesDb = await import('../src/matches-db.js')
const notifyDb = await import('../src/notify-db.js')
const cardEvents = await import('../src/card-events.js')
const email = await import('../src/notifications.js')

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
  db.getDb().prepare('DELETE FROM rate_limits').run()
})

// ── Fixtures ──

interface CardOpts {
  headline?: string
  intents?: string[]
  seeking?: { description: string; topics?: string[]; engagement?: string }[]
  offering?: { description: string; topics?: string[] }[]
  preferences?: { key: string; value: string }[]
  ttlMs?: number
}

function buildCard(opts: CardOpts, keys: { publicKey: string; privateKey: string }, at = Date.now()): any {
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(at).toISOString(), expires_at: new Date(at + (opts.ttlMs ?? 21 * 864e5)).toISOString(),
    headline: opts.headline ?? 'A person on the network', intents: opts.intents ?? ['collaborate'],
    seeking: opts.seeking ?? [], offering: (opts.offering ?? []).map(o => ({ ...o, provenance: 'principal_statement' })),
    preferences: opts.preferences ?? [], artifacts: [],
    event_ref: null, team_size_sought: null,
    visibility: {}, composition: { agent_assisted: true, skill_version: 'v1' },
    delegation_ref: null, revocation_status: 'active',
  }
  const h = cardContentHash(card)
  card.approval = { card_hash: h, approved_at: new Date(at).toISOString(), principal_signature: sign(h, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return card
}

async function publish(card: any): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}/api/v3/cards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card }),
  })
  return { status: res.status, body: await res.json() }
}

/** A complementary pair that always clears the overlap threshold: mutual
 *  intent plus agreed fields, so matching does not depend on the cold model. */
function complementaryPair(tag: string, ttlMs?: number): { a: any; b: any; ka: any; kb: any } {
  const ka = generateKeyPair(); const kb = generateKeyPair()
  const prefs = [{ key: 'engagement', value: 'part_time' }, { key: 'location', value: 'remote' }]
  const a = buildCard({
    headline: `${tag} seeks rust`, intents: ['collaborate', 'team_up'], ttlMs,
    seeking: [{ description: 'a rust protocol engineer', topics: ['rust', 'protocols'] }],
    offering: [{ description: 'seed funding for developer tools', topics: ['funding'] }],
    preferences: prefs,
  }, ka)
  const b = buildCard({
    headline: `${tag} offers rust`, intents: ['collaborate', 'team_up'], ttlMs,
    seeking: [{ description: 'seed funding for developer tools', topics: ['funding'] }],
    offering: [{ description: 'a rust protocol engineer, 8 years', topics: ['rust', 'protocols'] }],
    preferences: prefs,
  }, kb)
  return { a, b, ka, kb }
}

async function subscribeConfirmed(keys: any, addr: string, prefs?: Record<string, boolean>): Promise<void> {
  const nonce = `n-${Math.random()}`
  await fetch(`${base}/api/v3/notifications/subscribe`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject_key: keys.publicKey, email: addr, nonce, signature: sign(`${addr}:${nonce}`, keys.privateKey), prefs }),
  })
  const token = (db.getDb().prepare('SELECT verify_token FROM notifications WHERE subject_key = ?').get(keys.publicKey) as any).verify_token
  await fetch(`${base}/api/v3/notifications/confirm/${token}`)
}

// ══════════════════════════════════════════════════════════════
// Part 1 - expired is not withdrawn
// ══════════════════════════════════════════════════════════════

test('the sweep marks a lapsed card expired, never withdrawn', async () => {
  const keys = generateKeyPair()
  const pub = await publish(buildCard({ headline: 'lapses fast' }, keys, Date.now() - 1000))
  assert.equal(pub.status, 201)
  db.getDb().prepare("UPDATE v3_cards SET expires_at = '2000-01-01T00:00:00.000Z' WHERE card_id = ?").run(pub.body.card_id)

  const swept = v3db.sweepExpiredV3Cards()
  assert.ok(swept.swept >= 1)
  const after = v3db.getV3Card(pub.body.card_id)!
  assert.equal(after.revocation_status, 'expired')
  assert.notEqual(after.revocation_status, 'withdrawn')
})

test('the withdraw verb still sets withdrawn, and the sweep never overwrites it', async () => {
  const keys = generateKeyPair()
  const pub = await publish(buildCard({ headline: 'withdrawn on purpose' }, keys))
  const cardId = pub.body.card_id
  const res = await fetch(`${base}/api/v3/cards/${cardId}/withdraw`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: keys.publicKey, signature: sign(`withdraw:${cardId}`, keys.privateKey) }),
  })
  assert.equal(res.status, 200)
  assert.equal(v3db.getV3Card(cardId)!.revocation_status, 'withdrawn')

  // Now push it past expiry and sweep: a withdrawn card stays withdrawn.
  db.getDb().prepare("UPDATE v3_cards SET expires_at = '2000-01-01T00:00:00.000Z' WHERE card_id = ?").run(cardId)
  v3db.sweepExpiredV3Cards()
  assert.equal(v3db.getV3Card(cardId)!.revocation_status, 'withdrawn',
    'a card the principal withdrew must never be relabelled by the expiry sweep')
})

test('every eligibility filter requires active AND unexpired', () => {
  // The filters that mean "this card is live on the network". Each must reject
  // an expired-status row, so adding a status cannot silently widen the network.
  const keys = generateKeyPair()
  const cardId = 'v3-filter-probe'
  db.getDb().prepare(`INSERT INTO v3_cards (card_id, card_type, subject_key, card_hash, card_json, headline, intents_json, created_at, expires_at, revocation_status)
    VALUES (?, 'connection', ?, 'h', '{"card_type":"connection","intents":[],"seeking":[],"offering":[],"preferences":[],"visibility":{}}', 'probe', '[]', ?, ?, 'expired')`)
    .run(cardId, keys.publicKey, new Date().toISOString(), new Date(Date.now() + 864e5).toISOString())

  assert.equal(v3db.isCardMatchable(cardId), false, 'isCardMatchable (v3-db.ts) must reject expired')
  assert.equal(v3db.activeCardIdsForSubject(keys.publicKey).includes(cardId), false, 'activeCardIdsForSubject must reject expired')
  assert.equal(v3db.listActiveCardsForMatching(500).some(c => c.card_id === cardId), false, 'listActiveCardsForMatching must reject expired')
  assert.equal(v3db.findActiveCardByHash(keys.publicKey, 'h'), null, 'findActiveCardByHash must reject expired')
  assert.equal(v3db.searchV3Cards({}).some((r: any) => r.card_id === cardId), false, 'searchV3Cards must reject expired')
  assert.equal(v3db.searchV3CardsPaged({}).results.some((r: any) => r.card_id === cardId), false, 'searchV3CardsPaged must reject expired')
  db.getDb().prepare('DELETE FROM v3_cards WHERE card_id = ?').run(cardId)
})

// ══════════════════════════════════════════════════════════════
// Part 2 - append-only card_events ledger
// ══════════════════════════════════════════════════════════════

test('publish writes card_published and the matching events', async () => {
  const { a } = complementaryPair('ledger')
  const pub = await publish(a)
  const evs = cardEvents.eventsForCard(pub.body.card_id).map(e => e.event)
  assert.ok(evs.includes('card_published'), `expected card_published, got ${evs.join(',')}`)
  assert.ok(evs.includes('matching_started'), `expected matching_started, got ${evs.join(',')}`)
  const started = cardEvents.eventsForCard(pub.body.card_id).find(e => e.event === 'matching_started')!
  assert.ok(typeof JSON.parse(started.detail_json!).candidate_count === 'number', 'matching_started must carry the candidate count')
})

test('a created match writes match_created with the other card, overlap count and cosine', async () => {
  const { a, b } = complementaryPair('mc')
  const pa = await publish(a)
  const pb = await publish(b)
  const created = cardEvents.eventsForCard(pb.body.card_id).filter(e => e.event === 'match_created')
  assert.ok(created.length >= 1, 'publishing the complement must record match_created')
  const detail = JSON.parse(created[0].detail_json!)
  assert.equal(detail.other_card_id, pa.body.card_id)
  assert.ok(typeof detail.overlap_count === 'number')
  assert.ok('cosine' in detail, 'cosine must be recorded even when null (cold model)')
})

test('the sweep writes card_expired and withdraw writes card_withdrawn', async () => {
  const k1 = generateKeyPair()
  const p1 = await publish(buildCard({ headline: 'expire me' }, k1))
  db.getDb().prepare("UPDATE v3_cards SET expires_at = '2000-01-01T00:00:00.000Z' WHERE card_id = ?").run(p1.body.card_id)
  v3db.sweepExpiredV3Cards()
  assert.ok(cardEvents.eventsForCard(p1.body.card_id).some(e => e.event === 'card_expired'))

  const k2 = generateKeyPair()
  const p2 = await publish(buildCard({ headline: 'withdraw me' }, k2))
  await fetch(`${base}/api/v3/cards/${p2.body.card_id}/withdraw`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: k2.publicKey, signature: sign(`withdraw:${p2.body.card_id}`, k2.privateKey) }),
  })
  const e2 = cardEvents.eventsForCard(p2.body.card_id).map(e => e.event)
  assert.ok(e2.includes('card_withdrawn'), `expected card_withdrawn, got ${e2.join(',')}`)
  assert.equal(e2.includes('card_expired'), false, 'a withdrawn card must not also be logged as expired')
})

test('the ledger is append-only: no UPDATE or DELETE against card_events in src', () => {
  const offenders: string[] = []
  for (const f of readdirSync('src').filter(f => f.endsWith('.ts'))) {
    const body = readFileSync(join('src', f), 'utf8')
    for (const line of body.split('\n')) {
      if (!/card_events/.test(line)) continue
      if (/\b(UPDATE|DELETE)\b/i.test(line) && !/^\s*(\/\/|\*)/.test(line)) offenders.push(`${f}: ${line.trim()}`)
    }
  }
  assert.deepEqual(offenders, [], 'card_events must have no update or delete path anywhere in src')
})

// ══════════════════════════════════════════════════════════════
// Part 3 - stats that tell the truth
// ══════════════════════════════════════════════════════════════

test('GET /api/stats reports v3 numbers from the v3 tables, and keeps the legacy block', async () => {
  const stats = await fetch(`${base}/api/stats`).then(r => r.json())
  assert.ok(stats.v3, 'a v3 block must be present')
  assert.ok(stats.legacy_v2, 'the legacy counters must remain, marked as legacy')
  assert.ok('total_matches_computed' in stats.legacy_v2, 'the misleading v2 counter belongs in legacy_v2')

  const d = db.getDb()
  const q = (sql: string): number => (d.prepare(sql).get() as any).n
  assert.equal(stats.v3.cards_lifetime, q('SELECT COUNT(*) AS n FROM v3_cards'))
  assert.equal(stats.v3.cards_active, q(`SELECT COUNT(*) AS n FROM v3_cards WHERE expires_at > ${db.SQL_NOW_ISO} AND revocation_status = 'active'`))
  assert.equal(stats.v3.cards_withdrawn, q("SELECT COUNT(*) AS n FROM v3_cards WHERE revocation_status = 'withdrawn'"))
  assert.equal(stats.v3.subjects_lifetime, q('SELECT COUNT(DISTINCT subject_key) AS n FROM v3_cards'))
  assert.equal(stats.v3.matches_current, q('SELECT COUNT(*) AS n FROM v3_matches'))
  assert.equal(stats.v3.matches_lifetime, q("SELECT COUNT(*) AS n FROM card_events WHERE event = 'match_created'"))
  assert.equal(stats.v3.intros_requested, q("SELECT COUNT(*) AS n FROM card_events WHERE event = 'intro_requested'"))
})

test('the 3.2.0 marker is written once and never moves', () => {
  const marker = v3db.v32DeployMarker()
  assert.ok(marker, 'a marker must exist after the schema is initialised')
  assert.ok(!Number.isNaN(Date.parse(marker!)), 'the marker must be an ISO timestamp')

  // Re-running the server's own stamp is what a restart looks like to this
  // table. This calls the real write path, not a copy of it, so a change from
  // INSERT OR IGNORE to INSERT OR REPLACE is caught here.
  db.stampDeployMarkerOnce()
  db.stampDeployMarkerOnce()
  assert.equal(v3db.v32DeployMarker(), marker, 'a later start must never overwrite the marker')

  const rows = (db.getDb().prepare('SELECT COUNT(*) AS n FROM schema_markers WHERE key = ?').get(db.V3_2_MARKER_KEY) as any).n
  assert.equal(rows, 1, 'exactly one marker row')
})

test('cards_legacy_status_ambiguous counts pre-marker withdrawals only', async () => {
  const marker = v3db.v32DeployMarker()!
  const before = new Date(Date.parse(marker) - 864e5).toISOString()
  const after = new Date(Date.parse(marker) + 864e5).toISOString()
  const ins = db.getDb().prepare(`INSERT INTO v3_cards (card_id, card_type, subject_key, card_hash, card_json, headline, intents_json, created_at, expires_at, revocation_status, updated_at)
    VALUES (?, 'connection', ?, 'h', '{}', 'a', '[]', ?, ?, ?, ?)`)
  // Written before 3.2.0 existed: the sweep of the day and a real withdrawal
  // produced this same value, so it is ambiguous.
  ins.run('mk-pre', 'ka', before, before, 'withdrawn', before)
  // Withdrawn AFTER the deploy, by the verb, on a card created long before it.
  // Under the old created_at test this was miscounted; under updated_at it is not.
  ins.run('mk-post', 'kb', before, before, 'withdrawn', after)
  // Not withdrawn at all.
  ins.run('mk-active', 'kc', before, after, 'active', before)

  const v3 = (await fetch(`${base}/api/stats`).then(r => r.json())).v3
  const d = db.getDb()
  const counted = (id: string): number => (d.prepare(
    "SELECT COUNT(*) AS n FROM v3_cards WHERE card_id = ? AND revocation_status = 'withdrawn' AND updated_at < ?",
  ).get(id, marker) as any).n

  assert.equal(counted('mk-pre'), 1, 'a pre-marker withdrawn row is ambiguous')
  assert.equal(counted('mk-post'), 0, 'a post-marker withdrawal is the principal\'s own and is not counted')
  assert.equal(counted('mk-active'), 0, 'an active row is never counted')

  assert.equal(v3.cards_legacy_status_ambiguous, (d.prepare(
    "SELECT COUNT(*) AS n FROM v3_cards WHERE revocation_status = 'withdrawn' AND updated_at < ?",
  ).get(marker) as any).n, 'the endpoint must match the query run directly')
  assert.ok(v3.cards_legacy_status_ambiguous >= 1, 'the seeded pre-marker row must be counted')
  assert.ok(v3.cards_legacy_status_ambiguous <= v3.cards_withdrawn,
    'the ambiguous count must be a subset of cards_withdrawn')

  d.prepare("DELETE FROM v3_cards WHERE card_id LIKE 'mk-%'").run()
})

test('matches_lifetime keeps counting after the live rows are deleted', async () => {
  const before = (await fetch(`${base}/api/stats`).then(r => r.json())).v3
  const { a, b } = complementaryPair('lifetime')
  await publish(a)
  const pb = await publish(b)
  const mid = (await fetch(`${base}/api/stats`).then(r => r.json())).v3
  assert.ok(mid.matches_lifetime > before.matches_lifetime, 'a new pair must raise matches_lifetime')
  assert.ok(mid.matches_current > before.matches_current)

  matchesDb.deleteMatchArtifacts(pb.body.card_id)
  const after = (await fetch(`${base}/api/stats`).then(r => r.json())).v3
  assert.ok(after.matches_current < mid.matches_current, 'deleting the pair must lower matches_current')
  assert.equal(after.matches_lifetime, mid.matches_lifetime, 'lifetime is history and must not fall')
})

// ══════════════════════════════════════════════════════════════
// Part 4 - push new matches to both sides
// ══════════════════════════════════════════════════════════════

test('a new match enqueues one notification for BOTH sides, and not twice on recompute', async () => {
  const { a, b, ka, kb } = complementaryPair('push')
  await subscribeConfirmed(ka, 'a-push@example.test', { new_match: true })
  await subscribeConfirmed(kb, 'b-push@example.test', { new_match: true })
  sent.length = 0

  const pa = await publish(a)
  const pb = await publish(b)

  // Both addresses were mailed. The counts are scoped to THIS pair below,
  // because a card on a shared test network legitimately matches others too.
  const to = new Set(sent.filter(m => m.subject === 'A new match on Mingle').map(m => m.to))
  assert.ok(to.has('a-push@example.test') && to.has('b-push@example.test'), 'both sides must be mailed')

  const notifiedFor = (cardId: string, otherId: string): number =>
    cardEvents.eventsForCard(cardId).filter(e =>
      e.event === 'match_notified' && JSON.parse(e.detail_json!).other_card_id === otherId).length
  assert.equal(notifiedFor(pa.body.card_id, pb.body.card_id), 1, 'side A told exactly once about this pair')
  assert.equal(notifiedFor(pb.body.card_id, pa.body.card_id), 1, 'side B told exactly once about this pair')

  // Recomputing the same pair must not re-notify: the dedupe id is the pair.
  sent.length = 0
  matchesDb.recomputeMatchesForCard(pb.body.card_id)
  matchesDb.recomputeMatchesForCard(pa.body.card_id)
  assert.equal(notifiedFor(pa.body.card_id, pb.body.card_id), 1, 'recompute must not add a second notification')
  const again = notifyDb.reserveSend(kb.publicKey, `match:${[pa.body.card_id, pb.body.card_id].sort().join(':')}`, 'new_match')
  assert.equal(again.ok, false, 'the pair dedupe key must already be reserved, so a second mail is impossible')
  assert.equal(again.reason, 'duplicate')
  assert.equal(sent.filter(m => m.subject === 'A new match on Mingle').length, 0, 'recompute must not re-mail')
})

test('a subject with no confirmed email is recorded and skipped, never invented a channel', async () => {
  const { a, b, ka } = complementaryPair('nosub')
  await subscribeConfirmed(ka, 'only-a@example.test', { new_match: true })
  sent.length = 0
  await publish(a)
  const pb = await publish(b)

  const pa = v3db.activeCardIdsForSubject(ka.publicKey)[0]
  const skipped = cardEvents.eventsForCard(pb.body.card_id)
    .filter(e => e.event === 'match_notify_skipped' && JSON.parse(e.detail_json!).other_card_id === pa)
  assert.equal(skipped.length, 1, 'the unsubscribed side must leave exactly one match_notify_skipped for this pair')
  assert.equal(JSON.parse(skipped[0].detail_json!).reason, 'not_subscribed')

  const notified = cardEvents.eventsForCard(pa)
    .filter(e => e.event === 'match_notified' && JSON.parse(e.detail_json!).other_card_id === pb.body.card_id)
  assert.equal(notified.length, 1, 'the subscribed side is still told exactly once about this pair')
  assert.ok(sent.some(m => m.to === 'only-a@example.test'), 'and that notification really was an email')
})

test('new_match is off for a subscription stored before the pref existed', () => {
  const keys = generateKeyPair()
  db.getDb().prepare(`INSERT INTO notifications (subject_key, email, verified, verify_token, unsub_token, prefs_json)
    VALUES (?, 'old@example.test', 1, ?, ?, '{"intro_request":true,"intro_accepted":true,"weekly_digest":false}')`)
    .run(keys.publicKey, `vt-${Math.random()}`, `ut-${Math.random()}`)
  const sub = notifyDb.getSubscription(keys.publicKey)!
  assert.equal(sub.prefs.new_match, false, 'an existing subscriber must not start receiving a new kind of mail')
  assert.equal(sub.prefs.intro_request, true, 'the prefs they did set are unchanged')
})

test('GET /matches/pending returns the new matches without advancing the digest marker', async () => {
  const { a, b, ka } = complementaryPair('pending')
  await publish(a)
  await publish(b)

  const ask = async (): Promise<any> => {
    const nonce = `n-${Math.random()}`
    const qs = new URLSearchParams({ public_key: ka.publicKey, nonce, signature: sign(`matches-pending:${nonce}`, ka.privateKey) })
    return fetch(`${base}/api/v3/matches/pending?${qs}`).then(r => r.json())
  }
  const first = await ask()
  assert.ok(first.pending_count >= 1, 'the pair must show as pending')
  const second = await ask()
  assert.equal(second.pending_count, first.pending_count, 'polling must not consume the window')

  // The digest DOES advance it.
  const nonce = `n-${Math.random()}`
  const qs = new URLSearchParams({ public_key: ka.publicKey, nonce, signature: sign(`digest:${nonce}`, ka.privateKey) })
  await fetch(`${base}/api/v3/digest?${qs}`).then(r => r.json())
  const third = await ask()
  assert.equal(third.pending_count, 0, 'after a digest read the pending window must be empty')
})

test('/matches/pending refuses a replayed digest signature', async () => {
  const keys = generateKeyPair()
  const nonce = 'replay-nonce'
  const qs = new URLSearchParams({ public_key: keys.publicKey, nonce, signature: sign(`digest:${nonce}`, keys.privateKey) })
  const res = await fetch(`${base}/api/v3/matches/pending?${qs}`)
  assert.equal(res.status, 403, 'a digest signature must not authorize /matches/pending')
})
