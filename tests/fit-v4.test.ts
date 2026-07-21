// ══════════════════════════════════════════════════════════════
// Mingle v4 private fit - Stage 1: Fit Policy (schema, storage, approval)
// ══════════════════════════════════════════════════════════════
// Values are typed and private; the schema is public. A policy is approved as a
// whole set by its content hash, is versioned/supersedable, and never lets the
// work intent carry a dimension.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-v4-test-'))
process.env.DB_PATH = join(tmpDir, 'v4.db')
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const { policyHash } = await import('../src/fit-policy-db.js')
const airlock = await import('../src/fit-airlock.js')
const handshakeDb = await import('../src/fit-handshake-db.js')
const serverKey = await import('../src/server-key.js')

let server: Server
let base: string

before(async () => {
  const app = createApp(); db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => { db.getDb().prepare('DELETE FROM rate_limits').run() })

function makeCard(headline: string, intents: string[]): { keys: any; card: any } {
  const keys = generateKeyPair()
  const now = Date.now()
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(now).toISOString(), expires_at: new Date(now + 21 * 864e5).toISOString(),
    headline, intents, seeking: [], offering: [{ description: 'x', provenance: 'principal_statement' }],
    preferences: [], artifacts: [], event_ref: null, team_size_sought: null,
    visibility: {}, composition: { agent_assisted: true, skill_version: 'v1' },
    delegation_ref: null, revocation_status: 'active',
  }
  const h = cardContentHash(card)
  card.approval = { card_hash: h, approved_at: new Date(now).toISOString(), principal_signature: sign(h, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return { keys, card }
}
async function publish(built: { card: any }): Promise<string> {
  const r = await (await fetch(`${base}/api/v3/cards`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card: built.card }) })).json()
  return r.card_id
}
const future = () => new Date(Date.now() + 30 * 864e5).toISOString()

function dim(dimension: string, value: any, disclosure_state = 'testable', importance = 'useful', allowed_intents = ['cofound']): any {
  return { dimension, value, sensitivity: 'low', disclosure_state, allowed_intents, expires_at: future(), importance }
}

async function setPolicy(who: any, cardId: string, dimensions: any[]): Promise<{ status: number; body: any }> {
  const approved_hash = policyHash(dimensions)
  const nonce = 'p' + Math.random().toString(16).slice(2)
  const body = { card_id: cardId, dimensions, approved_hash, public_key: who.keys.publicKey, nonce, signature: sign(`set-fit-policy:${cardId}:${approved_hash}:${nonce}`, who.keys.privateKey) }
  const res = await fetch(`${base}/api/v4/fit/policy`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}
async function getPolicy(who: any, cardId: string): Promise<any> {
  const nonce = 'g' + Math.random().toString(16).slice(2)
  const qs = new URLSearchParams({ card_id: cardId, public_key: who.keys.publicKey, nonce, signature: sign(`get-fit-policy:${cardId}:${nonce}`, who.keys.privateKey) })
  return (await fetch(`${base}/api/v4/fit/policy?${qs}`)).json()
}

test('a valid policy is stored, versioned, and readable by the owner', async () => {
  const alice = makeCard('Alice', ['cofound', 'collaborate'])
  const cardId = await publish(alice)
  const dims = [
    dim('weekly_commitment', { min: 20, max: 40 }),
    dim('cadence', 'mixed', 'reveal_overlap'),
    dim('role_spike', ['product', 'fundraising'], 'reveal_bucket'),
  ]
  const r = await setPolicy(alice, cardId, dims)
  assert.equal(r.status, 201, JSON.stringify(r.body))
  assert.equal(r.body.version, 1)
  assert.match(r.body.policy_hash, /^[0-9a-f]{64}$/)

  const got = await getPolicy(alice, cardId)
  assert.equal(got.version, 1)
  assert.equal(got.dimensions.length, 3)

  // Supersede: a second set bumps the version.
  const r2 = await setPolicy(alice, cardId, [dim('weekly_commitment', { min: 10, max: 20 })])
  assert.equal(r2.body.version, 2)
})

test('the work intent may never carry a dimension', async () => {
  const alice = makeCard('Alice', ['cofound', 'work'])
  const cardId = await publish(alice)
  const r = await setPolicy(alice, cardId, [dim('weekly_commitment', { min: 10, max: 20 }, 'testable', 'useful', ['cofound', 'work'])])
  assert.equal(r.status, 400)
  assert.match(r.body.error, /work is excluded/i)
})

test('an approval hash that does not match the dimensions is rejected', async () => {
  const alice = makeCard('Alice', ['cofound'])
  const cardId = await publish(alice)
  const dims = [dim('cadence', 'mixed')]
  const nonce = 'x'
  const wrongHash = createHash('sha256').update('nope').digest('hex')
  const body = { card_id: cardId, dimensions: dims, approved_hash: wrongHash, public_key: alice.keys.publicKey, nonce, signature: sign(`set-fit-policy:${cardId}:${wrongHash}:${nonce}`, alice.keys.privateKey) }
  const res = await fetch(`${base}/api/v4/fit/policy`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  assert.equal(res.status, 400)
})

test('unknown dimensions and bad enum values are rejected', async () => {
  const alice = makeCard('Alice', ['cofound'])
  const cardId = await publish(alice)
  assert.equal((await setPolicy(alice, cardId, [dim('made_up', 'x')])).status, 400)
  assert.equal((await setPolicy(alice, cardId, [dim('cadence', 'not_a_cadence')])).status, 400)
  assert.equal((await setPolicy(alice, cardId, [dim('role_spike', ['not_a_tag'])])).status, 400)
})

test('only the card owner can set or read a policy', async () => {
  const alice = makeCard('Alice', ['cofound']); const bob = makeCard('Bob', ['cofound'])
  const cardId = await publish(alice); await publish(bob)
  const r = await setPolicy(bob, cardId, [dim('cadence', 'mixed')])
  assert.equal(r.status, 403)
  const got = await getPolicy(bob, cardId)
  assert.equal(got.error ?? 'blocked', got.error)  // 403 body has error
})

// ── AIRLOCK (headline invariant) ──

test('the airlock extractor input has exactly {answer, question, schema}', () => {
  const input = { answer: 'about 20 hours, AIRLOCKMARKER', question: 'How many hours?', schema: { dimension: 'weekly_commitment' } }
  assert.deepEqual(Object.keys(input).sort(), ['answer', 'question', 'schema'])
  // The type of extract() accepts nothing else; there is no owner-data field.
})

test('a marker in a counterparty answer never crosses into the extraction', () => {
  const marker = 'AIRLOCKMARKER_SECRET'
  const out = airlock.extract({ answer: `I can do about 25 hours a week. ${marker}`, question: 'How many hours?', schema: { dimension: 'weekly_commitment' } })
  const j = JSON.stringify(out)
  assert.equal(j.includes(marker), false, 'the raw answer text must not appear in the extraction')
  assert.equal(out.status, 'answered')
  assert.equal(out.value_bucket, '21-40')
  // The raw answer (the human view) DOES still contain the marker; the airlock
  // never removes it from what the human sees, only from what the extractor emits.
  assert.equal(`I can do about 25 hours a week. ${marker}`.includes(marker), true)
})

test('the extractor is deterministic: hedges become conditions, empty is not_answered', () => {
  const hedged = airlock.extract({ answer: 'maybe async_first, depends on the project', question: 'What cadence?', schema: { dimension: 'cadence' } })
  assert.ok(hedged.conditions.includes('conditional') || hedged.conditions.includes('uncertain'))
  assert.notEqual(hedged.status, 'answered')
  const empty = airlock.extract({ answer: '   ', question: 'What cadence?', schema: { dimension: 'cadence' } })
  assert.equal(empty.status, 'not_answered')
  const clean = airlock.extract({ answer: 'daily_sync works for me', question: 'What cadence?', schema: { dimension: 'cadence' } })
  assert.equal(clean.status, 'answered')
  assert.equal(clean.value_bucket, 'daily_sync')
})

// ── NO server-side ordering / score (local-ordering boundary, server half) ──

test('the v4 fit surface exposes no ordering or score endpoint, and the policy carries no score', async () => {
  // No endpoint accepts or returns an ordering / sort / score of people.
  for (const path of ['order', 'rank', 'sort', 'score', 'prioritize']) {
    const res = await fetch(`${base}/api/v4/fit/${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
    assert.equal(res.status, 404, `/api/v4/fit/${path} must not exist`)
  }
  // The stored policy is typed dimensions only; no score/rank field anywhere.
  const alice = makeCard('Alice', ['cofound'])
  const cardId = await publish(alice)
  await setPolicy(alice, cardId, [dim('cadence', 'mixed'), dim('weekly_commitment', { min: 10, max: 20 })])
  const got = await getPolicy(alice, cardId)
  const banned = new Set(['score', 'rank', 'rating', 'order', 'overlap_count'])
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) { v.forEach(walk); return }
    if (v && typeof v === 'object') for (const [k, val] of Object.entries(v)) { assert.ok(!banned.has(k.toLowerCase()), `policy must carry no ${k}`); walk(val) }
  }
  walk(got)
})

test('the planner takes only the extraction and forces human review when not clean', () => {
  // The planner signature has no raw-answer parameter (extraction + policy view).
  const clean = airlock.plan({ dimension: 'cadence', status: 'answered', conditions: [] }, { disclosure_state: 'reveal_overlap', importance: 'useful', sensitivity: 'low' })
  assert.equal(clean.requires_human, false)
  const conditioned = airlock.plan({ dimension: 'cadence', status: 'answered', conditions: ['conditional'] }, { disclosure_state: 'reveal_overlap', importance: 'useful', sensitivity: 'low' })
  assert.equal(conditioned.requires_human, true)
  const unclear = airlock.plan({ dimension: 'cadence', status: 'unclear', conditions: [] }, { disclosure_state: 'reveal_overlap', importance: 'useful', sensitivity: 'low' })
  assert.equal(unclear.requires_human, true)
  // A high-sensitivity dimension escalates even on a clean answer.
  const highSens = airlock.plan({ dimension: 'decision_model', status: 'answered', conditions: [] }, { disclosure_state: 'reveal_overlap', importance: 'essential', sensitivity: 'high' })
  assert.equal(highSens.requires_human, true)
})

// ══════════════════════════════════════════════════════════════
// Stage 3: bilateral predicate handshake
// ══════════════════════════════════════════════════════════════

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')
const rid = () => Math.random().toString(16).slice(2)

async function requestIntro(from: any, fromCard: string, toCard: string, purpose: string): Promise<string> {
  const nonce = 'ri' + rid()
  const body = { from_card: fromCard, to_card: toCard, purpose, note: '', public_key: from.keys.publicKey, nonce, signature: sign(`intro-request:${fromCard}:${toCard}:${purpose}:${nonce}`, from.keys.privateKey) }
  return (await (await fetch(`${base}/api/v3/intros/request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json()).id
}
async function acceptIntro(to: any, introId: string): Promise<any> {
  const nonce = 'ai' + rid()
  const body = { action: 'accept', contact: 'x@e.example', public_key: to.keys.publicKey, nonce, signature: sign(`intro-respond:${introId}:accept:${nonce}`, to.keys.privateKey) }
  return (await fetch(`${base}/api/v3/intros/${introId}/respond`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json()
}
async function openHandshake(intent: string, aliceDims: any[] | null, bobDims: any[] | null): Promise<any> {
  const alice = makeCard('Alice', [intent, 'collaborate']); const bob = makeCard('Bob', [intent])
  const aliceCard = await publish(alice); const bobCard = await publish(bob)
  if (aliceDims) await setPolicy(alice, aliceCard, aliceDims)
  if (bobDims) await setPolicy(bob, bobCard, bobDims)
  const introId = await requestIntro(alice, aliceCard, bobCard, intent)
  const acc = await acceptIntro(bob, introId)
  return { introId, alice, bob, aliceCard, bobCard, acc }
}
async function hsRequest(who: any, introId: string, requested: string[], reciprocal: string[], dims: any[]): Promise<{ status: number; body: any }> {
  const policy_hash = policyHash(dims); const nonce = 'hq' + rid()
  const body = { requested_dimensions: requested, reciprocal_offer: reciprocal, predicate_version: 1, policy_hash, query_budget: 5, public_key: who.keys.publicKey, nonce, signature: sign(`fit-request:${introId}:${nonce}`, who.keys.privateKey) }
  const res = await fetch(`${base}/api/v4/fit/${introId}/request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}
async function hsCommit(who: any, introId: string, accept: string[], reciprocal: string[], dims: any[]): Promise<{ status: number; body: any }> {
  const policy_hash = policyHash(dims); const nonce = 'hc' + rid()
  const body = { accept_dimensions: accept, reciprocal_offer: reciprocal, policy_hash, public_key: who.keys.publicKey, nonce, signature: sign(`fit-commit:${introId}:${nonce}`, who.keys.privateKey) }
  const res = await fetch(`${base}/api/v4/fit/${introId}/commit`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}
async function hsGet(who: any, introId: string): Promise<any> {
  const nonce = 'hg' + rid()
  const qs = new URLSearchParams({ public_key: who.keys.publicKey, nonce, signature: sign(`fit-hs-get:${introId}:${nonce}`, who.keys.privateKey) })
  return (await fetch(`${base}/api/v4/fit/${introId}?${qs}`)).json()
}
async function hsReveal(who: any, introId: string, dimension: string): Promise<{ status: number; body: any }> {
  const nonce = 'hr' + rid()
  const body = { dimension, public_key: who.keys.publicKey, nonce, signature: sign(`fit-reveal:${introId}:${dimension}:${nonce}`, who.keys.privateKey) }
  const res = await fetch(`${base}/api/v4/fit/${introId}/reveal`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}
const factFor = (map: any[], d: string) => map.find((e: any) => e.dimension === d)

// ── RECIPROCITY (must-not-cut) ──

test('no predicate is evaluated until BOTH sides commit (one-sided probe yields nothing)', async () => {
  const aDims = [dim('weekly_commitment', { min: 20, max: 40 }, 'reveal_overlap', 'essential')]
  const bDims = [dim('weekly_commitment', { min: 30, max: 50 }, 'reveal_overlap', 'essential')]
  const hs = await openHandshake('cofound', aDims, bDims)
  assert.equal(hs.acc.fit_mode, 'v4', JSON.stringify(hs.acc))
  assert.ok(hs.acc.fit_handshake)

  const rq = await hsRequest(hs.alice, hs.introId, ['weekly_commitment'], ['weekly_commitment'], aDims)
  assert.equal(rq.status, 201, JSON.stringify(rq.body))
  const g1 = await hsGet(hs.alice, hs.introId)
  assert.equal(g1.state, 'requested')
  assert.equal(g1.overlap_map, undefined, 'nothing is evaluated before the counterparty commits')

  const cm = await hsCommit(hs.bob, hs.introId, ['weekly_commitment'], ['weekly_commitment'], bDims)
  assert.equal(cm.status, 200, JSON.stringify(cm.body))
  assert.ok(Array.isArray(cm.body.overlap_map))
  assert.equal(factFor(cm.body.overlap_map, 'weekly_commitment').overlap, true)  // 20-40 vs 30-50 overlap
})

test('the requester cannot also commit; only the counterparty can', async () => {
  const aDims = [dim('cadence', 'mixed', 'reveal_overlap', 'essential')]
  const hs = await openHandshake('cofound', aDims, aDims)
  await hsRequest(hs.alice, hs.introId, ['cadence'], ['cadence'], aDims)
  const self = await hsCommit(hs.alice, hs.introId, ['cadence'], ['cadence'], aDims)
  assert.equal(self.status, 403)
})

test('the evaluable set is only the mutual intersection', async () => {
  const aDims = [dim('weekly_commitment', { min: 10, max: 20 }, 'reveal_overlap', 'essential'), dim('cadence', 'mixed', 'reveal_overlap', 'useful')]
  const bDims = [dim('weekly_commitment', { min: 10, max: 20 }, 'reveal_overlap', 'essential'), dim('cadence', 'async_first', 'reveal_overlap', 'useful')]
  const hs = await openHandshake('cofound', aDims, bDims)
  await hsRequest(hs.alice, hs.introId, ['weekly_commitment', 'cadence'], ['weekly_commitment'], aDims)  // only reciprocates commitment
  const cm = await hsCommit(hs.bob, hs.introId, ['weekly_commitment', 'cadence'], ['weekly_commitment'], bDims)
  const dims = cm.body.overlap_map.map((e: any) => e.dimension)
  assert.ok(dims.includes('weekly_commitment'))
  assert.equal(dims.includes('cadence'), false, 'cadence was not reciprocally offered by both, so it is not evaluated')
})

// ── DISCLOSURE STATES ──

test('disclosure states: overlap reveals only yes/no, bucket reveals a bucket, exact needs a human reveal, testable reveals nothing', async () => {
  // reveal_overlap: overlap only, no bucket
  {
    const a = [dim('weekly_commitment', { min: 20, max: 40 }, 'reveal_overlap', 'essential')]
    const b = [dim('weekly_commitment', { min: 25, max: 30 }, 'reveal_overlap', 'essential')]
    const hs = await openHandshake('cofound', a, b)
    await hsRequest(hs.alice, hs.introId, ['weekly_commitment'], ['weekly_commitment'], a)
    const cm = await hsCommit(hs.bob, hs.introId, ['weekly_commitment'], ['weekly_commitment'], b)
    const f = factFor(cm.body.overlap_map, 'weekly_commitment')
    assert.equal(f.result, 'overlap')
    assert.equal(f.bucket_a, undefined)
  }
  // reveal_bucket: buckets present
  {
    const a = [dim('weekly_commitment', { min: 20, max: 40 }, 'reveal_bucket', 'essential')]
    const b = [dim('weekly_commitment', { min: 25, max: 30 }, 'reveal_bucket', 'essential')]
    const hs = await openHandshake('cofound', a, b)
    await hsRequest(hs.alice, hs.introId, ['weekly_commitment'], ['weekly_commitment'], a)
    const cm = await hsCommit(hs.bob, hs.introId, ['weekly_commitment'], ['weekly_commitment'], b)
    const f = factFor(cm.body.overlap_map, 'weekly_commitment')
    assert.equal(f.result, 'bucket')
    assert.ok(f.bucket_a && f.bucket_b)
  }
  // testable: predicate may run but reveals nothing
  {
    const a = [dim('weekly_commitment', { min: 20, max: 40 }, 'testable', 'essential')]
    const b = [dim('weekly_commitment', { min: 25, max: 30 }, 'testable', 'essential')]
    const hs = await openHandshake('cofound', a, b)
    await hsRequest(hs.alice, hs.introId, ['weekly_commitment'], ['weekly_commitment'], a)
    const cm = await hsCommit(hs.bob, hs.introId, ['weekly_commitment'], ['weekly_commitment'], b)
    const f = factFor(cm.body.overlap_map, 'weekly_commitment')
    assert.equal(f.result, 'not_disclosed')
    assert.equal(f.overlap, undefined)
  }
  // local_only: never participates
  {
    const a = [dim('weekly_commitment', { min: 20, max: 40 }, 'local_only', 'essential')]
    const b = [dim('weekly_commitment', { min: 25, max: 30 }, 'reveal_overlap', 'essential')]
    const hs = await openHandshake('cofound', a, b)
    await hsRequest(hs.alice, hs.introId, ['weekly_commitment'], ['weekly_commitment'], a)
    const cm = await hsCommit(hs.bob, hs.introId, ['weekly_commitment'], ['weekly_commitment'], b)
    const f = factFor(cm.body.overlap_map, 'weekly_commitment')
    assert.equal(f.result, 'not_checked')
  }
})

test('reveal_exact keeps the exact private until a human-tap reveal by the owner', async () => {
  const a = [dim('weekly_commitment', { min: 20, max: 40 }, 'reveal_exact', 'essential')]
  const b = [dim('weekly_commitment', { min: 25, max: 30 }, 'reveal_exact', 'essential')]
  const hs = await openHandshake('cofound', a, b)
  await hsRequest(hs.alice, hs.introId, ['weekly_commitment'], ['weekly_commitment'], a)
  const cm = await hsCommit(hs.bob, hs.introId, ['weekly_commitment'], ['weekly_commitment'], b)
  const f = factFor(cm.body.overlap_map, 'weekly_commitment')
  assert.equal(f.result, 'exact_available')
  // Before any reveal, GET carries no exact value.
  const g1 = await hsGet(hs.alice, hs.introId)
  assert.equal(factFor(g1.overlap_map, 'weekly_commitment').exact_a, undefined)
  // Alice taps reveal for her own dimension; now GET carries the exact values.
  const rv = await hsReveal(hs.alice, hs.introId, 'weekly_commitment')
  assert.equal(rv.status, 200)
  const g2 = await hsGet(hs.bob, hs.introId)
  assert.ok(factFor(g2.overlap_map, 'weekly_commitment').exact_a !== undefined)
})

// ── ANTI-NARROWING (must-not-cut) ──

test('the per-principal-pair query budget caps repeats (unit)', () => {
  const pk = handshakeDb.principalPairKey('KA', 'KB')
  for (let i = 0; i < handshakeDb.QUERY_BUDGET_MAX; i++) assert.equal(handshakeDb.budgetConsume(pk, 'weekly_commitment').allowed, true)
  assert.equal(handshakeDb.budgetConsume(pk, 'weekly_commitment').allowed, false, 'over the lifetime cap the dimension is refused')
})

test('a budget-exhausted dimension is refused, not re-evaluated, across threads', async () => {
  const a = [dim('cadence', 'mixed', 'reveal_overlap', 'essential')]
  const b = [dim('cadence', 'mixed', 'reveal_overlap', 'essential')]
  const hs = await openHandshake('cofound', a, b)
  // Exhaust the (pair, cadence) budget out of band, as if it had been tested on
  // other cards/threads between the same two principals.
  const pk = handshakeDb.principalPairKey(hs.alice.keys.publicKey, hs.bob.keys.publicKey)
  for (let i = 0; i < handshakeDb.QUERY_BUDGET_MAX; i++) handshakeDb.budgetConsume(pk, 'cadence')
  await hsRequest(hs.alice, hs.introId, ['cadence'], ['cadence'], a)
  const cm = await hsCommit(hs.bob, hs.introId, ['cadence'], ['cadence'], b)
  assert.equal(factFor(cm.body.overlap_map, 'cadence').result, 'budget_exhausted')
})

// ── NO-SCORE / NO-ACCUMULATION ──

test('the overlap map is capped, carries no score/count, and only essential+useful dims', async () => {
  const many = [
    dim('weekly_commitment', { min: 10, max: 20 }, 'reveal_overlap', 'essential'),
    dim('start_window', 'now', 'reveal_overlap', 'essential'),
    dim('time_horizon', 'months', 'reveal_overlap', 'essential'),
    dim('cadence', 'mixed', 'reveal_overlap', 'essential'),
    dim('project_stage', 'building', 'reveal_overlap', 'essential'),
    dim('relationship_shape', 'co_owner', 'reveal_overlap', 'essential'),
    dim('decision_model', 'consensus', 'reveal_overlap', 'essential'),
    dim('timezone', { zone: 'UTC', sync_overlap_needed: false }, 'reveal_overlap', 'optional'),  // optional: excluded
  ]
  const all = many.map((m: any) => m.dimension)
  const hs = await openHandshake('cofound', many, many)
  await hsRequest(hs.alice, hs.introId, all, all, many)
  const cm = await hsCommit(hs.bob, hs.introId, all, all, many)
  const dimFacts = cm.body.overlap_map.filter((e: any) => e.dimension !== 'complementarity')
  assert.ok(dimFacts.length <= 6, `capped at 6, got ${dimFacts.length}`)
  assert.equal(dimFacts.some((e: any) => e.dimension === 'timezone'), false, 'optional dimension excluded from the map')
  const banned = new Set(['score', 'rank', 'rating', 'count', 'overlap_count', 'strength'])
  const walk = (v: unknown): void => { if (Array.isArray(v)) v.forEach(walk); else if (v && typeof v === 'object') for (const [k, val] of Object.entries(v)) { assert.ok(!banned.has(k.toLowerCase()), `no ${k}`); walk(val) } }
  walk(cm.body.overlap_map)
})

test('complementarity appears as a distinct fact, not a score', async () => {
  const a = [dim('role_spike', ['product', 'fundraising'], 'reveal_overlap', 'essential'), dim('role_antiportfolio', ['backend', 'infra'], 'reveal_overlap', 'essential')]
  const b = [dim('role_spike', ['backend', 'infra'], 'reveal_overlap', 'essential'), dim('role_antiportfolio', ['product', 'fundraising'], 'reveal_overlap', 'essential')]
  const hs = await openHandshake('cofound', a, b)
  await hsRequest(hs.alice, hs.introId, ['role_spike', 'role_antiportfolio'], ['role_spike', 'role_antiportfolio'], a)
  const cm = await hsCommit(hs.bob, hs.introId, ['role_spike', 'role_antiportfolio'], ['role_spike', 'role_antiportfolio'], b)
  const compl = factFor(cm.body.overlap_map, 'complementarity')
  assert.ok(compl, 'complementarity fact present')
  assert.equal(compl.overlap, true, 'they are strong in what the other listed as anti-portfolio, both directions')
})

// ── WORK excluded + FALLBACK ──

test('a work intro opens neither a v4 handshake nor a v3 exchange', async () => {
  const alice = makeCard('Alice', ['work']); const bob = makeCard('Bob', ['work'])
  const aliceCard = await publish(alice); const bobCard = await publish(bob)
  const introId = await requestIntro(alice, aliceCard, bobCard, 'work')
  const acc = await acceptIntro(bob, introId)
  assert.equal(acc.fit_handshake, null)
  assert.equal(acc.fit_exchange, null)
})

test('a pair without policies falls back to the v3 fit exchange, unchanged', async () => {
  const hs = await openHandshake('cofound', null, null)  // no policies set
  assert.equal(hs.acc.fit_handshake, null)
  assert.equal(hs.acc.fit_mode, 'v3')
  assert.ok(hs.acc.fit_exchange, 'the v3 question-bank exchange opened')
})

// ── RECEIPTS ──

test('the receipt verifies and binds both policy hashes, predicates, purpose, and expiry', async () => {
  const a = [dim('cadence', 'mixed', 'reveal_overlap', 'essential')]
  const b = [dim('cadence', 'mixed', 'reveal_overlap', 'essential')]
  const hs = await openHandshake('cofound', a, b)
  await hsRequest(hs.alice, hs.introId, ['cadence'], ['cadence'], a)
  const cm = await hsCommit(hs.bob, hs.introId, ['cadence'], ['cadence'], b)
  const rc = cm.body.receipt_content
  assert.equal(rc.policy_hash_a, policyHash(a))
  assert.equal(rc.policy_hash_b, policyHash(b))
  assert.equal(rc.purpose, 'cofound')
  assert.ok(rc.requested_predicates.includes('cadence'))
  assert.ok(typeof rc.expiry === 'string')
  // The digest binds the content, and the server receipt verifies over it.
  assert.equal(sha(canonicalize(rc)), cm.body.receipt_digest)
  assert.equal(serverKey.verifyReceipt(cm.body.receipt_digest, cm.body.receipt), true)
  assert.equal(serverKey.verifyReceipt('f'.repeat(64), cm.body.receipt), false)
})

test('a non-party cannot read a handshake', async () => {
  const a = [dim('cadence', 'mixed', 'reveal_overlap', 'essential')]
  const hs = await openHandshake('cofound', a, a)
  const stranger = { keys: generateKeyPair() }
  const g = await hsGet(stranger, hs.introId)
  assert.equal(g.error ?? 'blocked', g.error)
})

// ══════════════════════════════════════════════════════════════
// Stage 5: adaptive questions through the airlock
// ══════════════════════════════════════════════════════════════

async function hsQuestions(who: any, introId: string): Promise<any> {
  const nonce = 'qq' + rid()
  const body = { public_key: who.keys.publicKey, nonce, signature: sign(`fit-questions:${introId}:${nonce}`, who.keys.privateKey) }
  return (await fetch(`${base}/api/v4/fit/${introId}/questions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json()
}
async function hsAnswers(who: any, introId: string, answers: any[]): Promise<{ status: number; body: any }> {
  const nonce = 'qa' + rid()
  const hash = sha(canonicalize({ intro_id: introId, nonce, answers }))
  const body = { answers, public_key: who.keys.publicKey, nonce, signature: sign(hash, who.keys.privateKey) }
  const res = await fetch(`${base}/api/v4/fit/${introId}/answers`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}
async function hsQa(who: any, introId: string): Promise<any> {
  const nonce = 'qg' + rid()
  const qs = new URLSearchParams({ public_key: who.keys.publicKey, nonce, signature: sign(`fit-qa-get:${introId}:${nonce}`, who.keys.privateKey) })
  return (await fetch(`${base}/api/v4/fit/${introId}/qa?${qs}`)).json()
}

test('AIRLOCK-IN-QUESTIONS: a marker in a drafted answer never enters the extraction, only the human view', async () => {
  const a = [dim('cadence', 'mixed', 'reveal_overlap', 'essential')]
  const b = [dim('cadence', 'mixed', 'reveal_overlap', 'essential')]
  const hs = await openHandshake('cofound', a, b)
  const marker = 'AIRLOCK5_SECRET'
  const r = await hsAnswers(hs.bob, hs.introId, [{ dimension: 'cadence', mode: 'drafted', text: `I like a daily_sync rhythm. ${marker}` }])
  assert.equal(r.status, 200, JSON.stringify(r.body))
  const qa = await hsQa(hs.alice, hs.introId)
  const entry = qa.record.find((e: any) => e.dimension === 'cadence')
  const bobAnswer = entry.answers.find((x: any) => x.answerer_key === hs.bob.keys.publicKey)
  assert.equal(bobAnswer.raw_text.includes(marker), true, 'the human view keeps the raw answer')
  assert.equal(JSON.stringify(bobAnswer.extraction).includes(marker), false, 'the extraction never carries the raw text')
  // The planner hint (alice viewing bob's answer) is computed from the extraction only.
  assert.ok(bobAnswer.plan_hint)
})

test('UNRESOLVED-ONLY: /questions returns only unsettled essential/useful dims, capped at 4', async () => {
  const dims = [
    dim('weekly_commitment', { min: 20, max: 40 }, 'reveal_overlap', 'essential'),
    dim('cadence', 'mixed', 'reveal_overlap', 'essential'),
    dim('start_window', 'now', 'reveal_overlap', 'essential'),
    dim('time_horizon', 'months', 'reveal_overlap', 'essential'),
    dim('project_stage', 'building', 'reveal_overlap', 'essential'),
  ]
  const hs = await openHandshake('cofound', dims, dims)
  // Settle only weekly_commitment through the handshake.
  await hsRequest(hs.alice, hs.introId, ['weekly_commitment'], ['weekly_commitment'], dims)
  await hsCommit(hs.bob, hs.introId, ['weekly_commitment'], ['weekly_commitment'], dims)
  const q = await hsQuestions(hs.alice, hs.introId)
  const asked = q.questions.map((x: any) => x.dimension)
  assert.ok(q.questions.length <= 4, `capped at 4, got ${q.questions.length}`)
  assert.equal(asked.includes('weekly_commitment'), false, 'a handshake-settled dimension is not re-asked')
  for (const d of asked) assert.ok(['cadence', 'start_window', 'time_horizon', 'project_stage'].includes(d))
})

test('DRAFTED answers are still post-gated (contact data refused)', async () => {
  const a = [dim('cadence', 'mixed', 'reveal_overlap', 'essential')]
  const hs = await openHandshake('cofound', a, a)
  const r = await hsAnswers(hs.bob, hs.introId, [{ dimension: 'cadence', mode: 'drafted', text: 'reach me at bob at example dot com' }])
  assert.equal(r.status, 400)
})

test('a skip is not_answered and never negative; a round2 request marks it partially', async () => {
  const a = [dim('cadence', 'mixed', 'reveal_overlap', 'essential')]
  const hs = await openHandshake('cofound', a, a)
  await hsAnswers(hs.bob, hs.introId, [{ dimension: 'cadence', mode: 'skip' }])
  // alice asks for more on cadence
  const nonce = 'r2' + rid()
  await fetch(`${base}/api/v4/fit/${hs.introId}/round2`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ dimension_ids: ['cadence'], public_key: hs.alice.keys.publicKey, nonce, signature: sign(`fit-qa-round2:${hs.introId}:${nonce}`, hs.alice.keys.privateKey) }) })
  const qa = await hsQa(hs.alice, hs.introId)
  const bobAns = qa.record.find((e: any) => e.dimension === 'cadence').answers.find((x: any) => x.answerer_key === hs.bob.keys.publicKey)
  assert.equal(bobAns.classification, 'partially_answered')
})
