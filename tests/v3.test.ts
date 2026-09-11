// ══════════════════════════════════════════════════════════════
// Mingle v3 tests - schema, lint, hash binding, visibility, verbs
// ══════════════════════════════════════════════════════════════
// Same bootstrap as api.test.ts: in-process app, throwaway DB, real
// Ed25519 signatures. Embedding model intentionally cold; explicit-field
// search paths are exercised, the semantic query path is covered by its
// unavailable-model error contract.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-v3-test-'))
process.env.DB_PATH = join(tmpDir, 'v3-test.db')

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { validateV3Card, cardContentHash, findBannedContent } = await import('../src/v3-cards.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(resolve => { server = app.listen(0, '127.0.0.1', () => resolve()) })
  const addr = server.address() as { port: number }
  base = `http://127.0.0.1:${addr.port}`
})

after(() => {
  server?.close()
  db.closeDb()
  rmSync(tmpDir, { recursive: true, force: true })
})

// ── Fixtures ──
// Each card gets a fresh keypair so per-subject_key rate limits never cross
// tests. The keypair rides on the returned object for verb signing.

type Keyed = Record<string, any> & { __keys: { publicKey: string; privateKey: string } }

function makeCard(overrides: Record<string, unknown> = {}, opts: { expiresInMs?: number } = {}): Keyed {
  const keys = generateKeyPair()
  const now = Date.now()
  const card: Record<string, any> = {
    card_type: 'connection',
    subject_key: keys.publicKey,
    version: 1,
    created_at: new Date(now).toISOString(),
    expires_at: new Date(now + (opts.expiresInMs ?? 21 * 24 * 3600 * 1000)).toISOString(),
    headline: 'Protocol engineer seeking collaborators on agent identity',
    intents: ['collaborate', 'team_up'],
    seeking: [{ description: 'Collaborators on open agent-identity protocols', topics: ['agent identity', 'delegation'], engagement: 'part_time' }],
    offering: [{ description: 'I build TypeScript SDKs, shipped a delegation chain verifier', topics: ['typescript'], provenance: 'principal_statement' }],
    preferences: [{ key: 'communication', value: 'written context first' }, { key: 'location', value: 'remote, EU timezones' }],
    artifacts: [{
      claim: 'Author of the agent-passport-system npm package',
      source: 'artifact_link',
      method: 'link provided by principal, existence checkable',
      verified_fact: 'a package by this name exists at the given link',
      date: new Date(now).toISOString(),
    }],
    event_ref: null,
    team_size_sought: null,
    visibility: { headline: 'network', seeking: 'network', offering: 'network', preferences: 'intro_request', artifacts: 'network' },
    composition: { agent_assisted: true, skill_version: 'mingle-composer-v1' },
    delegation_ref: null,
    revocation_status: 'active',
    ...overrides,
  }
  const card_hash = cardContentHash(card)
  card.approval = {
    card_hash,
    approved_at: new Date(now).toISOString(),
    principal_signature: sign(card_hash, keys.privateKey),
  }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  card.__keys = keys
  return card as Keyed
}

async function publish(card: Keyed): Promise<{ status: number; body: any }> {
  const { __keys, ...wire } = card
  const res = await fetch(`${base}/api/v3/cards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ card: wire }),
  })
  return { status: res.status, body: await res.json() }
}

function signedVerbBody(card: Keyed, verb: string, cardId: string): string {
  return JSON.stringify({ public_key: card.__keys.publicKey, signature: sign(`${verb}:${cardId}`, card.__keys.privateKey) })
}

// ── Schema round-trip, both card types ──

test('connection card round-trips through validation', () => {
  const { __keys, ...card } = makeCard()
  const v = validateV3Card(card)
  assert.equal(v.valid, true, (v as any).error)
})

test('opportunity card with event fields round-trips and publishes', async () => {
  const card = makeCard({
    card_type: 'opportunity',
    headline: 'Hackathon team forming: agent-identity tooling',
    intents: ['team_up'],
    event_ref: { event_id: 'hackathon-vienna-2026', dates: '2026-09-12/2026-09-14' },
    team_size_sought: 4,
  })
  const { __keys, ...bare } = card
  const v = validateV3Card(bare)
  assert.equal(v.valid, true, (v as any).error)
  const { status, body } = await publish(card)
  assert.equal(status, 201, JSON.stringify(body))
  // event_ref is searchable as an explicit field
  const res = await fetch(`${base}/api/v3/cards/search`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event_ref: 'hackathon-vienna-2026' }),
  })
  const found = await res.json()
  assert.ok((found.results as any[]).some(r => r.card_id === body.card_id))
})

// ── Banned-key rejection (invariants 1 and 2 at the type layer) ──

test('banned keys are rejected wherever they appear', () => {
  const cases: Record<string, unknown>[] = [
    { fitVector: [0.2, 0.9] },
    { assessment: 'strong candidate' },
    { hostile_notes: 'avoid' },
    { trust_tier: 2 },
    { extra: { nested: { score: 0.7 } } },
    { seeking: [{ description: 'x', rank: 1 }] },
    { preferences: [{ key: 'confidence', value: 'high' }] },
  ]
  for (const extra of cases) {
    const card = makeCard(extra as Record<string, unknown>)
    const v = validateV3Card(card)
    assert.equal(v.valid, false, `expected rejection for ${JSON.stringify(extra).slice(0, 60)}`)
    assert.match((v as any).error, /prohibited field content/)
  }
})

test('banned tokens as exact string values are rejected, prose is not', () => {
  assert.notEqual(findBannedContent({ kind: 'trust_tier' }), null)
  assert.notEqual(findBannedContent({ list: ['fit_vector'] }), null)
  assert.equal(findBannedContent({ text: 'we keep musical scores and ranked lists out of scope' }), null)
})

test('publish rejects a banned-key card at the API layer', async () => {
  const card = makeCard({ assessment: 'smuggled' })
  const { status, body } = await publish(card)
  assert.equal(status, 400)
  assert.match(body.error, /prohibited field content/)
})

// ── Hash approval binding (invariant 4) ──

test('publish rejects when approval.card_hash does not match content', async () => {
  const card = makeCard()
  card.headline = 'Edited after approval'
  // re-sign the card so ONLY the hash binding is stale
  const { signature, __keys, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), card.__keys.privateKey)
  const { status, body } = await publish(card)
  assert.equal(status, 403)
  assert.match(body.error, /card_hash does not match/)
})

test('publish rejects a bad approval signature', async () => {
  const card = makeCard()
  const other = generateKeyPair()
  card.approval.principal_signature = sign(card.approval.card_hash, other.privateKey)
  const { signature, __keys, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), card.__keys.privateKey)
  const { status, body } = await publish(card)
  assert.equal(status, 403)
  assert.match(body.error, /principal_signature/)
})

test('publish rejects a bad card signature', async () => {
  const card = makeCard()
  const other = generateKeyPair()
  const { signature, __keys, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), other.privateKey)
  const { status, body } = await publish(card)
  assert.equal(status, 403)
  assert.match(body.error, /card signature/)
})

test('a fully valid card publishes and fetch shows status', async () => {
  const { status, body } = await publish(makeCard())
  assert.equal(status, 201)
  assert.equal(body.published, true)
  const res = await fetch(`${base}/api/v3/cards/${body.card_id}`)
  const fetched = await res.json()
  assert.equal(fetched.revocation_status, 'active')
  assert.equal(fetched.card.headline.includes('Protocol engineer'), true)
})

// ── Visibility filtering ──

test('a private field never appears in search results', async () => {
  const card = makeCard({
    headline: 'Visibility probe card',
    visibility: { headline: 'network', seeking: 'network', offering: 'private', preferences: 'private', artifacts: 'intro_request' },
  })
  const pub = await publish(card)
  assert.equal(pub.status, 201)
  const res = await fetch(`${base}/api/v3/cards/search`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ card_type: 'connection', intents: ['collaborate'] }),
  })
  const body = await res.json()
  const probe = (body.results as any[]).find(r => r.headline === 'Visibility probe card')
  assert.ok(probe, 'probe card should appear in search')
  assert.equal(probe.offering, undefined, 'private offering must not appear')
  assert.equal(probe.preferences, undefined, 'private preferences must not appear')
  assert.equal(probe.artifacts, undefined, 'intro_request artifacts must not appear in network search')
  assert.ok(probe.seeking, 'network-visible seeking should appear')
})

// ── Expiry sweep including index removal ──

test('expired cards are swept and leave search', async () => {
  const card = makeCard({ headline: 'Short-lived sweep probe' }, { expiresInMs: 50 })
  const pub = await publish(card)
  assert.equal(pub.status, 201)
  await new Promise(r => setTimeout(r, 80))
  const sweep = await fetch(`${base}/api/v3/sweep`, { method: 'POST' }).then(r => r.json())
  assert.ok(sweep.swept >= 1, `expected at least one swept card, got ${sweep.swept}`)
  const res = await fetch(`${base}/api/v3/cards/search`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ card_type: 'connection' }),
  })
  const body = await res.json()
  assert.equal((body.results as any[]).some(r => r.headline === 'Short-lived sweep probe'), false)
  // status still shown on direct fetch after sweep, and it says EXPIRED: the
  // sweep no longer claims the principal withdrew a card that simply lapsed.
  const fetched = await fetch(`${base}/api/v3/cards/${pub.body.card_id}`).then(r => r.json())
  assert.equal(fetched.revocation_status, 'expired')
})

// ── Revocation verbs (invariant 7) ──

test('every revocation verb transitions status correctly', async () => {
  const verbs: [string, string][] = [
    ['withdraw', 'withdrawn'],
    ['supersede', 'superseded'],
    ['revoke-authority', 'authority_revoked'],
    ['stop-new-matches', 'stopped_new_matches'],
  ]
  for (const [verb, expected] of verbs) {
    const card = makeCard({ headline: `Verb probe ${verb}` })
    const pub = await publish(card)
    assert.equal(pub.status, 201, JSON.stringify(pub.body))
    const res = await fetch(`${base}/api/v3/cards/${pub.body.card_id}/${verb}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: signedVerbBody(card, verb, pub.body.card_id),
    })
    const body = await res.json()
    assert.equal(res.status, 200, JSON.stringify(body))
    assert.equal(body.revocation_status, expected)
    const fetched = await fetch(`${base}/api/v3/cards/${pub.body.card_id}`).then(r => r.json())
    assert.equal(fetched.revocation_status, expected)
  }
})

test('delete-server-copy blanks content but keeps status visible', async () => {
  const card = makeCard({ headline: 'Delete probe' })
  const pub = await publish(card)
  const res = await fetch(`${base}/api/v3/cards/${pub.body.card_id}/delete-server-copy`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: signedVerbBody(card, 'delete-server-copy', pub.body.card_id),
  })
  assert.equal(res.status, 200)
  const fetched = await fetch(`${base}/api/v3/cards/${pub.body.card_id}`).then(r => r.json())
  assert.equal(fetched.revocation_status, 'deleted')
  assert.equal(fetched.card.headline ?? '[deleted]', '[deleted]')
})

test('a verb signed by a different key is refused', async () => {
  const pub = await publish(makeCard({ headline: 'Foreign key probe' }))
  const other = generateKeyPair()
  const res = await fetch(`${base}/api/v3/cards/${pub.body.card_id}/withdraw`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: other.publicKey, signature: sign(`withdraw:${pub.body.card_id}`, other.privateKey) }),
  })
  assert.equal(res.status, 403)
})

// ── No bulk endpoints (invariant 8) ──

test('the v3 router exposes no bulk-export or category-download route', async () => {
  const v3Routes = (await import('../src/v3-routes.js')).default as any
  const paths: string[] = []
  for (const layer of v3Routes.stack) {
    if (layer.route?.path) paths.push(layer.route.path)
  }
  assert.ok(paths.length >= 8, `router should expose its known routes, saw ${paths.length}`)
  for (const p of paths) {
    assert.doesNotMatch(p, /export|bulk|category|download|dump|all-cards/i, `route ${p} looks like a bulk endpoint`)
  }
  // And the search cap holds: ask for 10000, never receive more than 50.
  const res = await fetch(`${base}/api/v3/cards/search`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ limit: 10000 }),
  })
  const body = await res.json()
  assert.ok(body.count <= 50, `search must cap results, got ${body.count}`)
})

// ── Semantic search is one ranked window ──
// The model is cold in this file, so these tests write synthetic unit vectors
// straight into the index and hand the hit ids to the search, as the route does.

function unitVec(weights: Record<number, number>): Float32Array {
  const v = new Float32Array(384)
  for (const [i, w] of Object.entries(weights)) v[Number(i)] = w
  const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0))
  return v.map(x => x / norm)
}

test('a query search ranks by embedding distance, so an older closer card comes first', async () => {
  const v3db = await import('../src/v3-db.js')
  const older = makeCard({ headline: 'Semantic probe, older and closer', created_at: new Date(Date.now() - 3600_000).toISOString() })
  const newer = makeCard({ headline: 'Semantic probe, newer and farther' })
  const po = await publish(older); const pn = await publish(newer)
  assert.equal(po.status, 201, JSON.stringify(po.body)); assert.equal(pn.status, 201, JSON.stringify(pn.body))
  const olderId = po.body.card_id, newerId = pn.body.card_id
  v3db.storeV3Embedding(olderId, unitVec({ 0: 1, 1: 0.1 }))
  v3db.storeV3Embedding(newerId, unitVec({ 0: 0.2, 1: 1 }))
  const mine = (ids: unknown[]) => ids.filter(id => id === olderId || id === newerId)

  const ids = v3db.semanticSearchV3(unitVec({ 0: 1 }), 20).map(h => h.card_id)
  assert.deepEqual(mine(ids), [olderId, newerId], 'the index ranks the older card nearer')

  const page = v3db.searchV3CardsPaged({ card_type: 'connection' }, { semanticIds: ids, limit: 20 })
  assert.deepEqual(mine(page.results.map(r => r.card_id)), [olderId, newerId], 'results follow distance order, not recency')
  assert.equal(page.next_cursor, null, 'a semantic search is one window and is never paged')

  const top = v3db.searchV3CardsPaged({ card_type: 'connection' }, { semanticIds: ids, limit: 1 })
  assert.deepEqual(top.results.map(r => r.card_id), [olderId], 'limit cuts the ranked list from the top')
  assert.equal(top.next_cursor, null)

  // The wall search takes the same ids and keeps the same order.
  assert.deepEqual(mine(v3db.searchV3Cards({ card_type: 'connection' }, ids, 20).map(r => r.card_id)), [olderId, newerId])
})

test('query plus cursor is refused with a 400 that says why', async () => {
  const cursor = Buffer.from(JSON.stringify({ created_at: new Date().toISOString(), card_id: 'v3-connection-x' })).toString('base64url')
  const search = (body: unknown) => fetch(`${base}/api/v3/cards/search`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  const res = await search({ query: 'agent identity', cursor })
  assert.equal(res.status, 400)
  const body = await res.json()
  assert.match(body.error, /cursor/)
  assert.match(body.error, /query/)
  // A cursor without a query still pages through the keyset path.
  assert.equal((await search({ card_type: 'connection', cursor })).status, 200)
})

// ── Replace: a new version supersedes the old one in one transaction ──

/** Another card for the same key, signed like any other. */
function sibling(of: Keyed, overrides: Record<string, unknown>): Keyed {
  const { __keys, approval, signature, ...content } = of
  const now = Date.now()
  const card: Record<string, any> = { ...content, created_at: new Date(now).toISOString(), ...overrides }
  const card_hash = cardContentHash(card)
  card.approval = { card_hash, approved_at: new Date(now).toISOString(), principal_signature: sign(card_hash, __keys.privateKey) }
  const { signature: _unused, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), __keys.privateKey)
  card.__keys = __keys
  return card as Keyed
}

async function replace(oldId: string, card: Keyed): Promise<{ status: number; body: any }> {
  const { __keys, ...wire } = card
  const res = await fetch(`${base}/api/v3/cards/${oldId}/replace`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ card: wire }),
  })
  return { status: res.status, body: await res.json() }
}

const countOf = (sql: string, arg: string): number => (db.getDb().prepare(sql).get(arg) as any).n

test('replace supersedes the old card, links the lineage and leaves a second card of the same key alone', async () => {
  const v3db = await import('../src/v3-db.js')
  const matchesDb = await import('../src/matches-db.js')
  const first = makeCard({ headline: 'Replace probe, first version' })
  const other = sibling(first, { headline: 'Replace probe, an unrelated second card' })
  const pFirst = await publish(first); const pOther = await publish(other)
  assert.equal(pFirst.status, 201, JSON.stringify(pFirst.body)); assert.equal(pOther.status, 201, JSON.stringify(pOther.body))
  const oldId = pFirst.body.card_id, otherId = pOther.body.card_id
  // Give the old card index and match artifacts so their removal is observable.
  v3db.storeV3Embedding(oldId, unitVec({ 5: 1 })); matchesDb.storeMatchVector(oldId, unitVec({ 5: 1 }))
  const otherBefore = db.getDb().prepare('SELECT * FROM v3_cards WHERE card_id = ?').get(otherId)

  const r = await replace(oldId, sibling(first, { headline: 'Replace probe, second version' }))
  assert.equal(r.status, 201, JSON.stringify(r.body))
  const newId = r.body.new_card_id
  assert.equal(r.body.superseded, oldId)

  assert.equal(v3db.getV3Card(oldId)!.revocation_status, 'superseded')
  assert.equal(v3db.getV3Card(newId)!.revocation_status, 'active')
  assert.equal(v3db.getSupersededBy(oldId), newId)
  assert.equal(v3db.getSupersedes(newId), oldId)
  const lineage = [oldId, newId].map(id => v3db.getV3Card(id)!.revocation_status)
  assert.equal(lineage.filter(s => s === 'active').length, 1, 'the replacement lineage has exactly one active member')
  assert.equal((await (await fetch(`${base}/api/v3/cards/${oldId}`)).json()).superseded_by, newId)

  assert.equal(countOf('SELECT COUNT(*) AS n FROM v3_embedding_cards WHERE card_id = ?', oldId), 0, 'old index entry removed')
  assert.equal(countOf('SELECT COUNT(*) AS n FROM v3_match_vectors WHERE card_id = ?', oldId), 0, 'old match vector removed')
  // Several live cards per key are allowed, so the unrelated card stays active beside the new one.
  assert.deepEqual(db.getDb().prepare('SELECT * FROM v3_cards WHERE card_id = ?').get(otherId), otherBefore, 'the unrelated card is untouched')
})

test('replace refuses another key, a missing card, a card that is no longer active and a bad signature', async () => {
  const mine = makeCard({ headline: 'Replace refusal probe' })
  const pub = await publish(mine)
  const stranger = makeCard({ headline: 'Replace refusal probe, a stranger' })
  assert.equal((await replace(pub.body.card_id, stranger)).status, 403, 'another key cannot replace it')
  assert.equal((await replace('v3-connection-missing', sibling(mine, { headline: 'Replace refusal probe, nowhere' }))).status, 404)
  const ok = await replace(pub.body.card_id, sibling(mine, { headline: 'Replace refusal probe, v2' }))
  assert.equal(ok.status, 201, JSON.stringify(ok.body))
  assert.equal((await replace(pub.body.card_id, sibling(mine, { headline: 'Replace refusal probe, v3' }))).status, 409, 'a superseded card cannot be replaced again')
  const forged = sibling(mine, { headline: 'Replace refusal probe, forged' })
  forged.signature = sign('not the card', stranger.__keys.privateKey)
  assert.equal((await replace(ok.body.new_card_id, forged)).status, 403)
})

test('a failure inside the replace transaction leaves both cards as they were', async () => {
  const v3db = await import('../src/v3-db.js')
  const matchesDb = await import('../src/matches-db.js')
  const card = makeCard({ headline: 'Replace rollback probe' })
  const pub = await publish(card)
  const oldId = pub.body.card_id
  v3db.storeV3Embedding(oldId, unitVec({ 6: 1 })); matchesDb.storeMatchVector(oldId, unitVec({ 6: 1 }))
  const next = sibling(card, { headline: 'Replace rollback probe, never lands' })

  // The lineage link is the last write in the transaction, after the insert, the
  // supersede and the artifact removal. A temp trigger makes exactly that write fail.
  v3db.getSupersededBy('ensure-table')
  db.getDb().exec(`CREATE TEMP TRIGGER fail_replace BEFORE INSERT ON v3_supersessions BEGIN SELECT RAISE(ABORT, 'injected failure'); END`)
  try {
    const r = await replace(oldId, next)
    assert.equal(r.status, 500, JSON.stringify(r.body))
  } finally {
    db.getDb().exec('DROP TRIGGER IF EXISTS fail_replace')
  }

  assert.equal(v3db.getV3Card(oldId)!.revocation_status, 'active', 'the old card is still active')
  assert.equal(countOf('SELECT COUNT(*) AS n FROM v3_cards WHERE card_hash = ?', next.approval.card_hash), 0, 'the new card was never inserted')
  assert.equal(v3db.getSupersededBy(oldId), null, 'no lineage link')
  assert.equal(countOf('SELECT COUNT(*) AS n FROM v3_embedding_cards WHERE card_id = ?', oldId), 1, 'the index entry is intact')
  assert.equal(countOf('SELECT COUNT(*) AS n FROM v3_match_vectors WHERE card_id = ?', oldId), 1, 'the match vector is intact')
  assert.equal(v3db.semanticSearchV3(unitVec({ 6: 1 }), 5)[0]?.card_id, oldId, 'the vector itself survived the rollback')

  // With the fault gone the same replacement goes through.
  assert.equal((await replace(oldId, next)).status, 201)
})

// ── delete-server-copy is per card, the subscription is per identity ──

test('deleting one of two cards leaves the identity-level subscription intact', async () => {
  const notifyDb = await import('../src/notify-db.js')
  const a = makeCard({ headline: 'Delete keeps subscription, card one' })
  const b = sibling(a, { headline: 'Delete keeps subscription, card two' })
  const pa = await publish(a); const pb = await publish(b)
  notifyDb.upsertSubscription(a.__keys.publicKey, 'keep@example.com', 'vt-keep', 'ut-keep', { intro_request: true, intro_accepted: true, weekly_digest: false, new_match: false })
  const res = await fetch(`${base}/api/v3/cards/${pa.body.card_id}/delete-server-copy`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: signedVerbBody(a, 'delete-server-copy', pa.body.card_id),
  })
  assert.equal(res.status, 200)
  assert.notEqual(notifyDb.getSubscription(a.__keys.publicKey), null, 'the subscription belongs to the identity, not to one card')
  assert.equal((await (await fetch(`${base}/api/v3/cards/${pb.body.card_id}`)).json()).revocation_status, 'active')
})

// ── The bare sweep route is rate limited. The scheduler calls the function. ──

test('the v3 sweep route allows 6 calls an hour per client, then answers 429', async () => {
  db.getDb().prepare("DELETE FROM rate_limits WHERE action = 'v3_sweep'").run()
  const codes: number[] = []
  for (let i = 0; i < 7; i++) codes.push((await fetch(`${base}/api/v3/sweep`, { method: 'POST' })).status)
  assert.deepEqual(codes, [200, 200, 200, 200, 200, 200, 429])
})
