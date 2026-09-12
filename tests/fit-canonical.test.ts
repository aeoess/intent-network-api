// ══════════════════════════════════════════════════════════════
// The five fit actions, canonical, plus the policy commitment
// ══════════════════════════════════════════════════════════════
// DOUBLE GATE: every route here is behind MINGLE_FIT_ENABLED as well as behind the
// canonical pipeline, and that flag is unset in production. This suite sets it
// explicitly, so what it covers is code that does not run in production today.
//
// The three repairs this step exists for:
//   reciprocal_offer and query_budget are REQUIRED on the canonical lane, so the
//     defaulting at fit-v4-routes.ts:153-154 cannot reach a receipt as a field nobody
//     signed
//   fit_commit carries request_write_ref, so a commit names the request it answers
//   first_step_approve does its digest comparison and its write in one transaction
//
// Plus the one that matters most for release_exact: the signed commitment is the
// AUTHORIZATION and the stored policy is the PERMISSION, so a mismatch is an error and
// never a substitution.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes, createHash } from 'node:crypto'
import type { Server } from 'node:http'
import Database from 'better-sqlite3'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-fitcanon-test-'))
const DB_FILE = join(tmpDir, 'fitcanon.db')
process.env.DB_PATH = DB_FILE
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'
process.env.MINGLE_FIT_ENABLED = '1'
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const env = await import('../src/write-envelope.js')
const facts = await import('../src/connection-facts.js')
const state = await import('../src/connection-state.js')
const policyDb = await import('../src/fit-policy-db.js')
const handshakeDb = await import('../src/fit-handshake-db.js')
const firstStepDb = await import('../src/fit-firststep-db.js')
const autonomyDb = await import('../src/fit-autonomy-db.js')
const commitments = await import('../src/policy-commitment.js')
const artifacts = await import('../src/private-artifacts.js')
const evidence = await import('../src/write-evidence.js')
const qaDb = await import('../src/fit-qa-db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const { newNonce, jcs } = await import('../src/canonical-write.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => { db.getDb().prepare('DELETE FROM rate_limits').run() })

// ── Fixtures ──────────────────────────────────────────────────────────────

const rid = () => randomBytes(4).toString('hex')
const future = () => new Date(Date.now() + 30 * 864e5).toISOString()

function makeCard(headline: string, intents: string[]): any {
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

async function publish(built: any): Promise<string> {
  const r = await (await fetch(`${base}/api/v3/cards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card: built.card }),
  })).json()
  assert.ok(r.card_id, JSON.stringify(r))
  return r.card_id
}

function dim(dimension: string, value: any, disclosure_state = 'testable', allowed_intents = ['cofound']): any {
  return { dimension, value, sensitivity: 'low', disclosure_state, allowed_intents, expires_at: future(), importance: 'useful' }
}

async function setPolicy(who: any, cardId: string, dimensions: any[]): Promise<any> {
  const approved_hash = policyDb.policyHash(dimensions)
  const nonce = 'p' + rid()
  const res = await fetch(`${base}/api/v4/fit/policy`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      card_id: cardId, dimensions, approved_hash, public_key: who.keys.publicKey, nonce,
      signature: sign(`set-fit-policy:${cardId}:${approved_hash}:${nonce}`, who.keys.privateKey),
    }),
  })
  return { status: res.status, body: await res.json() }
}

/** Register a salted commitment to the card's current policy. Returns the commitment. */
async function registerCommitment(who: any, cardId: string, dimensions: any[]): Promise<{ commitment: string; salt: string; status: number; body: any }> {
  const salt = randomBytes(32).toString('base64url')
  const commitment = commitments.policyCommitment(salt, dimensions as any)
  const nonce = 'pc' + rid()
  const res = await fetch(`${base}/api/v4/fit/policy/commitment`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      card_id: cardId, commitment, salt, public_key: who.keys.publicKey, nonce,
      signature: sign(`register-policy-commitment:${cardId}:${commitment}:${nonce}`, who.keys.privateKey),
    }),
  })
  return { commitment, salt, status: res.status, body: await res.json() }
}

function signedBody(over: { operation: string; resource: any; payload?: any; keys: any; nonce?: string; opening?: any }) {
  const payload = over.payload ?? {}
  const built = env.buildEnvelope({
    operation: over.operation as any, actorKey: over.keys.publicKey, resource: over.resource,
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
    nonce: over.nonce ?? newNonce(), payload,
  })
  const body: Record<string, unknown> = {
    envelope: built.envelope, signature: sign(jcs(built.envelope), over.keys.privateKey), payload,
  }
  if (over.opening !== undefined) body.opening = over.opening
  return { body, built }
}

async function postJson(url: string, body: unknown) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  let json: any = null
  try { json = await res.json() } catch { /* none */ }
  return { status: res.status, json }
}

const fitUrl = (introId: string, tail: string) => `${base}/api/v4/fit/${introId}${tail}`
const introUrl = (tail: string) => `${base}/api/v3/intros/${tail}`

interface Pair {
  introId: string
  alice: any
  bob: any
  aliceCard: string
  bobCard: string
  aliceDims: any[]
  bobDims: any[]
  aliceCommitment: string
  bobCommitment: string
}

/** A canonically created intro in `interested`, both cards carrying a Fit Policy and a
 *  registered commitment. Alice is the requester. */
async function pair(aliceDims?: any[], bobDims?: any[]): Promise<Pair> {
  const alice = makeCard('Alice ' + rid(), ['cofound', 'collaborate'])
  const bob = makeCard('Bob ' + rid(), ['cofound'])
  const aliceCard = await publish(alice)
  const bobCard = await publish(bob)
  const aDims = aliceDims ?? [
    dim('cadence', 'mixed', 'reveal_overlap'),
    dim('weekly_commitment', { min: 20, max: 40 }, 'reveal_exact'),
  ]
  const bDims = bobDims ?? [
    dim('cadence', 'mixed', 'reveal_overlap'),
    dim('weekly_commitment', { min: 10, max: 30 }, 'reveal_exact'),
  ]
  assert.equal((await setPolicy(alice, aliceCard, aDims)).status, 201)
  assert.equal((await setPolicy(bob, bobCard, bDims)).status, 201)
  const ac = await registerCommitment(alice, aliceCard, aDims)
  const bc = await registerCommitment(bob, bobCard, bDims)
  assert.equal(ac.status, 201, JSON.stringify(ac.body))
  assert.equal(bc.status, 201, JSON.stringify(bc.body))

  const requestId = randomBytes(16).toString('hex')
  const req = await postJson(introUrl('request'), signedBody({
    operation: 'request_intro', resource: { type: 'intro_request', id: requestId },
    payload: { from_card: aliceCard, to_card: bobCard, purpose: 'cofound', note: 'lets talk' },
    keys: alice.keys,
  }).body)
  assert.equal(req.status, 201, JSON.stringify(req.json))
  const introId = req.json.intro_id
  const interest = await postJson(introUrl(`${introId}/respond`), signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: bob.keys,
  }).body)
  assert.equal(interest.status, 201, JSON.stringify(interest.json))

  return {
    introId, alice, bob, aliceCard, bobCard, aliceDims: aDims, bobDims: bDims,
    aliceCommitment: ac.commitment, bobCommitment: bc.commitment,
  }
}

/** The same shape, built entirely through the published 3.2.x routes: a legacy intro
 *  request and a legacy accept. So there is no write_create_map row to resolve back to, and
 *  the legacy fit lane is reachable. The accept is what opens the handshake for an old
 *  client, exactly as it does today. */
async function legacyPair(): Promise<Pair> {
  const alice = makeCard('Alice L' + rid(), ['cofound', 'collaborate'])
  const bob = makeCard('Bob L' + rid(), ['cofound'])
  const aliceCard = await publish(alice)
  const bobCard = await publish(bob)
  const aDims = [dim('cadence', 'mixed', 'reveal_overlap'), dim('weekly_commitment', { min: 20, max: 40 }, 'reveal_exact')]
  const bDims = [dim('cadence', 'mixed', 'reveal_overlap'), dim('weekly_commitment', { min: 10, max: 30 }, 'reveal_exact')]
  assert.equal((await setPolicy(alice, aliceCard, aDims)).status, 201)
  assert.equal((await setPolicy(bob, bobCard, bDims)).status, 201)
  const ac = await registerCommitment(alice, aliceCard, aDims)
  const bc = await registerCommitment(bob, bobCard, bDims)

  const rn = 'lri' + rid()
  const req = await postJson(introUrl('request'), {
    from_card: aliceCard, to_card: bobCard, purpose: 'cofound', note: 'old client',
    public_key: alice.keys.publicKey, nonce: rn,
    signature: sign(`intro-request:${aliceCard}:${bobCard}:cofound:${rn}`, alice.keys.privateKey),
  })
  assert.equal(req.status, 201, JSON.stringify(req.json))
  const introId = req.json.id
  const an = 'lai' + rid()
  const acc = await postJson(introUrl(`${introId}/respond`), {
    action: 'accept', contact: 'x@e.example', public_key: bob.keys.publicKey, nonce: an,
    signature: sign(`intro-respond:${introId}:accept:${an}`, bob.keys.privateKey),
  })
  assert.equal(acc.status, 200, JSON.stringify(acc.json))
  assert.equal(handshakeDb.existsHandshakeForIntro(introId), true, 'the legacy accept opens the handshake')
  return {
    introId, alice, bob, aliceCard, bobCard, aliceDims: aDims, bobDims: bDims,
    aliceCommitment: ac.commitment, bobCommitment: bc.commitment,
  }
}

function fitRequestPayload(p: Pair, over: Partial<Record<string, unknown>> = {}) {
  return {
    requested_dimensions: ['cadence', 'weekly_commitment'],
    reciprocal_offer: ['cadence', 'weekly_commitment'],
    predicate_version: 1,
    policy_commitment: p.aliceCommitment,
    query_budget: 5,
    ...over,
  }
}

async function canonicalFitRequest(p: Pair, over: Partial<Record<string, unknown>> = {}) {
  const s = signedBody({
    operation: 'fit_request', resource: { type: 'intro', id: p.introId },
    payload: fitRequestPayload(p, over), keys: p.alice.keys,
  })
  return { ...(await postJson(fitUrl(p.introId, '/request'), s.body)), built: s.built, body: s.body }
}

async function canonicalFitCommit(p: Pair, requestRef: string, over: Partial<Record<string, unknown>> = {}) {
  const s = signedBody({
    operation: 'fit_commit', resource: { type: 'intro', id: p.introId },
    payload: {
      accept_dimensions: ['cadence', 'weekly_commitment'],
      reciprocal_offer: ['cadence', 'weekly_commitment'],
      policy_commitment: p.bobCommitment,
      request_write_ref: requestRef,
      ...over,
    },
    keys: p.bob.keys,
  })
  return { ...(await postJson(fitUrl(p.introId, '/commit'), s.body)), built: s.built }
}

/** A committed handshake, ready for a reveal. */
async function committed(): Promise<{ p: Pair; requestRef: string }> {
  const p = await pair()
  const req = await canonicalFitRequest(p)
  assert.equal(req.status, 201, JSON.stringify(req.json))
  const com = await canonicalFitCommit(p, req.built.writeRef)
  assert.equal(com.status, 201, JSON.stringify(com.json))
  return { p, requestRef: req.built.writeRef }
}

// ══════════════════════════════════════════════════════════════
// The policy commitment
// ══════════════════════════════════════════════════════════════

test('COMMITMENT: registration with a correct opening succeeds, a wrong one is refused, and the salt is never stored', async () => {
  const alice = makeCard('Alice pc', ['cofound'])
  const cardId = await publish(alice)
  const dims = [dim('cadence', 'mixed', 'reveal_overlap')]
  assert.equal((await setPolicy(alice, cardId, dims)).status, 201)

  const good = await registerCommitment(alice, cardId, dims)
  assert.equal(good.status, 201, JSON.stringify(good.body))
  assert.equal(good.body.already_registered, false)

  // Idempotent: the same commitment again is a 200 and not a second row.
  const again = await postJson(`${base}/api/v4/fit/policy/commitment`, {
    card_id: cardId, commitment: good.commitment, salt: good.salt, public_key: alice.keys.publicKey,
    nonce: 'pc2', signature: sign(`register-policy-commitment:${cardId}:${good.commitment}:pc2`, alice.keys.privateKey),
  })
  assert.equal(again.status, 200)
  assert.equal(again.json.already_registered, true)

  // A wrong opening: the right shape, the wrong salt for that commitment.
  const wrongSalt = randomBytes(32).toString('base64url')
  const bad = await postJson(`${base}/api/v4/fit/policy/commitment`, {
    card_id: cardId, commitment: good.commitment, salt: wrongSalt, public_key: alice.keys.publicKey,
    nonce: 'pc3', signature: sign(`register-policy-commitment:${cardId}:${good.commitment}:pc3`, alice.keys.privateKey),
  })
  assert.equal(bad.status, 400)
  assert.equal(bad.json.code, 'commitment_mismatch')

  // THE SALT IS ABSENT FROM THE DATABASE, asserted by querying the table rather than by
  // reading the code. This is what makes "the server cannot recompute your commitment"
  // a fact about storage.
  const rows = db.getDb().prepare('SELECT * FROM policy_commitments WHERE card_id = ?').all(cardId) as any[]
  assert.equal(rows.length, 1)
  const blob = JSON.stringify(rows[0])
  assert.equal(blob.includes(good.salt), false, 'no salt anywhere in the row')
  assert.equal(Object.keys(rows[0]).includes('salt'), false, 'and no column that could hold one')
  assert.equal(rows[0].policy_hash, policyDb.policyHash(dims), 'only the internal version pointer is kept')
})

test('COMMITMENT: normalization sorts by code unit, not localeCompare', async () => {
  // policyHash at fit-policy-db.ts:99 uses localeCompare, which agrees with code unit order
  // on the current ten dimension names and diverges in general, because localeCompare is
  // locale and ICU dependent. The new commitment does not inherit the problem, and the
  // existing function is deliberately unchanged so no stored policy_hash moves.
  const dims = [dim('weekly_commitment', { min: 1, max: 2 }), dim('cadence', 'mixed')]
  const reordered = [dims[1], dims[0]]
  const salt = randomBytes(32).toString('base64url')
  assert.equal(
    commitments.policyCommitment(salt, dims as any),
    commitments.policyCommitment(salt, reordered as any),
    'the input order does not change the commitment',
  )
  const names = (commitments.normalizePolicy(dims as any) as any[]).map(x => x.dimension)
  assert.deepEqual(names, [...names].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)))
  // A different salt over the same policy is a different commitment, which is the whole
  // reason a receipt may carry it where policy_hash may not.
  assert.notEqual(
    commitments.policyCommitment(salt, dims as any),
    commitments.policyCommitment(randomBytes(32).toString('base64url'), dims as any),
  )
})

// ══════════════════════════════════════════════════════════════
// fit_request
// ══════════════════════════════════════════════════════════════

test('FIT_REQUEST: the canonical lane opens the handshake, binds all five fields, and moves the pair to connecting', async () => {
  const p = await pair()
  assert.equal(facts.stateOf(p.introId), 'interested')
  assert.equal(handshakeDb.existsHandshakeForIntro(p.introId), false,
    'canonical express_interest opens no handshake, as decided')

  const r = await canonicalFitRequest(p)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.handshake_state, 'requested')
  assert.equal(r.json.state, 'connecting', 'the first fit action moves the pair to connecting')
  assert.deepEqual(r.json.requested_dimensions, ['cadence', 'weekly_commitment'])
  assert.equal(r.json.query_budget, 5)

  const hs = handshakeDb.getHandshake(p.introId)!
  assert.equal(hs.requester_key, p.alice.keys.publicKey)
  assert.equal(hs.req_policy_hash, policyDb.policyHash(p.aliceDims), 'resolved through the commitment')
  assert.equal(JSON.parse(hs.req_reciprocal_json!).length, 2)

  const ev = db.getDb().prepare('SELECT * FROM write_evidence WHERE write_ref = ?').get(r.built.writeRef) as any
  assert.equal(ev.evidence, 'canonical')
  assert.deepEqual(JSON.parse(ev.bound_fields_json), [
    'operation', 'resource.id', 'payload.requested_dimensions', 'payload.reciprocal_offer',
    'payload.predicate_version', 'payload.policy_commitment', 'payload.query_budget',
  ], 'all five semantic fields, where the legacy lane binds only the intro id')
})

test('FIT_REQUEST: reciprocal_offer and query_budget are required rather than defaulted', async () => {
  const p = await pair()
  // fit-v4-routes.ts:153 falls back to requested_dimensions AFTER verification, and :154
  // coerces, floors and clamps the budget. Both then appear in a receipt as fields no
  // principal signed. On this lane their absence is a refusal.
  const noReciprocal = await postJson(fitUrl(p.introId, '/request'), signedBody({
    operation: 'fit_request', resource: { type: 'intro', id: p.introId },
    payload: {
      requested_dimensions: ['cadence'], predicate_version: 1,
      policy_commitment: p.aliceCommitment, query_budget: 3,
    },
    keys: p.alice.keys,
  }).body)
  assert.equal(noReciprocal.status, 400)
  assert.equal(noReciprocal.json.code, 'malformed_payload')
  assert.match(noReciprocal.json.error, /missing reciprocal_offer/)

  const noBudget = await postJson(fitUrl(p.introId, '/request'), signedBody({
    operation: 'fit_request', resource: { type: 'intro', id: p.introId },
    payload: {
      requested_dimensions: ['cadence'], reciprocal_offer: ['cadence'],
      predicate_version: 1, policy_commitment: p.aliceCommitment,
    },
    keys: p.alice.keys,
  }).body)
  assert.equal(noBudget.json.code, 'malformed_payload')
  assert.match(noBudget.json.error, /missing query_budget/)

  // And a budget outside the range is refused rather than clamped.
  const clamped = await canonicalFitRequest(p, { query_budget: 999 })
  assert.equal(clamped.status, 400)
  assert.match(clamped.json.error, /query_budget must be an integer from 1 to/)
  const floored = await canonicalFitRequest(p, { query_budget: 0 })
  assert.equal(floored.status, 400)
  // None of the four refusals opened a handshake, because the payload gate runs before any
  // write. A refusal on this lane touches nothing at all.
  assert.equal(handshakeDb.existsHandshakeForIntro(p.introId), false)
  assert.equal(facts.stateOf(p.introId), 'interested', 'and the pair did not move to connecting')
})

test('FIT_REQUEST: an unsorted or duplicated dimension list is refused rather than sorted', async () => {
  const p = await pair()
  const unsorted = await canonicalFitRequest(p, { requested_dimensions: ['weekly_commitment', 'cadence'] })
  assert.equal(unsorted.status, 400)
  assert.match(unsorted.json.error, /sorted by code unit/)
  const dup = await canonicalFitRequest(p, { requested_dimensions: ['cadence', 'cadence'] })
  assert.equal(dup.status, 400)
  assert.match(dup.json.error, /duplicate/)
})

test('FIT_REQUEST: a commitment that was never registered, or names an older policy, is refused', async () => {
  const p = await pair()
  const never = await canonicalFitRequest(p, { policy_commitment: 'a'.repeat(64) })
  assert.equal(never.status, 400)
  assert.equal(never.json.code, 'policy_commitment_unknown',
    'so policy_commitment is a check and not an opaque string copied into a receipt')

  // Supersede the policy. The old commitment still resolves, which keeps an old receipt
  // verifiable, but a fit act must use a commitment on the policy in force now.
  const newDims = [dim('cadence', 'mixed', 'testable')]
  assert.equal((await setPolicy(p.alice, p.aliceCard, newDims)).status, 201)
  const stale = await canonicalFitRequest(p, { requested_dimensions: ['cadence'], reciprocal_offer: ['cadence'] })
  assert.equal(stale.status, 400)
  assert.equal(stale.json.code, 'policy_commitment_stale')
  assert.equal(commitments.policyHashForCommitment(p.aliceCard, p.aliceCommitment) !== null, true,
    'the old commitment still resolves, so an old receipt stays verifiable')
})

test('FIT_REQUEST: a dimension outside the actor\'s policy is refused', async () => {
  const p = await pair()
  const r = await canonicalFitRequest(p, {
    requested_dimensions: ['cadence', 'role_spike'], reciprocal_offer: ['cadence', 'role_spike'],
  })
  assert.equal(r.status, 400)
  assert.equal(r.json.code, 'dimension_not_in_policy')
})

// ══════════════════════════════════════════════════════════════
// fit_commit
// ══════════════════════════════════════════════════════════════

test('FIT_COMMIT: request_write_ref must name the request on this handshake', async () => {
  const p = await pair()
  const req = await canonicalFitRequest(p)
  assert.equal(req.status, 201)

  // A different request's write_ref: taken from a second pair's request, so it is a real
  // write_ref of a real fit_request and not a random string.
  const other = await pair()
  const otherReq = await canonicalFitRequest(other)
  assert.equal(otherReq.status, 201)

  const wrong = await canonicalFitCommit(p, otherReq.built.writeRef)
  assert.equal(wrong.status, 409, JSON.stringify(wrong.json))
  assert.equal(wrong.json.code, 'request_write_ref_mismatch',
    'a commit cannot be applied to a different request than the one the principal saw')
  assert.equal(handshakeDb.getHandshake(p.introId)!.state, 'requested', 'and nothing moved')

  const right = await canonicalFitCommit(p, req.built.writeRef)
  assert.equal(right.status, 201, JSON.stringify(right.json))
  assert.equal(right.json.handshake_state, 'committed')
  assert.ok(right.json.receipt_digest)
  assert.equal(right.json.authorized_under_standing_scope, false)
})

test('FIT_COMMIT: the requester cannot also commit, and a legacy request leaves no ref to answer', async () => {
  const p = await pair()
  const req = await canonicalFitRequest(p)
  const self = await postJson(fitUrl(p.introId, '/commit'), signedBody({
    operation: 'fit_commit', resource: { type: 'intro', id: p.introId },
    payload: {
      accept_dimensions: ['cadence'], reciprocal_offer: ['cadence'],
      policy_commitment: p.aliceCommitment, request_write_ref: req.built.writeRef,
    },
    keys: p.alice.keys,
  }).body)
  assert.equal(self.status, 403)
  assert.equal(self.json.code, 'requester_cannot_commit')

  // A handshake whose request came in legacy has no canonical write_ref, so a canonical
  // commit has nothing to name. Stated as a refusal rather than silently accepted.
  const q = await pair()
  const nonce = 'lq' + rid()
  const legacyReq = await postJson(fitUrl(q.introId, '/request'), {
    requested_dimensions: ['cadence'], reciprocal_offer: ['cadence'], predicate_version: 1,
    policy_hash: policyDb.policyHash(q.aliceDims), query_budget: 3,
    public_key: q.alice.keys.publicKey, nonce,
    signature: sign(`fit-request:${q.introId}:${nonce}`, q.alice.keys.privateKey),
  })
  assert.equal(legacyReq.status, 404, 'no handshake yet, because only fit_request opens one now')

  // Open it canonically, then replace the request with a legacy one on a fresh pair.
  const r2 = await canonicalFitRequest(q)
  assert.equal(r2.status, 201)
  db.getDb().prepare("DELETE FROM connection_authorizations WHERE intro_id = ? AND operation = 'fit_request'").run(q.introId)
  const orphan = await canonicalFitCommit(q, r2.built.writeRef)
  assert.equal(orphan.status, 409)
  assert.equal(orphan.json.code, 'request_not_canonical')
})

test('FIT_COMMIT: standing_scope_commitment must name a scope the principal signed', async () => {
  const p = await pair()
  const req = await canonicalFitRequest(p)

  const bogus = await canonicalFitCommit(p, req.built.writeRef, { standing_scope_commitment: 'b'.repeat(64) })
  assert.equal(bogus.status, 400)
  assert.equal(bogus.json.code, 'standing_scope_unknown',
    'where today `autonomous` is an unsigned boolean that alone decides whether the graduated checks run')

  // Register a real scope, then commit under it. The scope permits nothing above testable,
  // and weekly_commitment is reveal_exact on both sides, so the graduated check refuses it.
  // ask_before_exact stays true, which is the default, and weekly_commitment is
  // reveal_exact on both sides, so the graduated check must refuse an autonomous commit
  // that would disclose it.
  const scope = autonomyDb.validateScope({
    intents: ['cofound'], dimensions: ['cadence', 'weekly_commitment'],
    auto_reveal_overlap: true, reveal_bucket_on_reciprocity: true,
    ask_before_exact: true, forbidden_categories: [], expiry: future(),
  }).scope!
  const scopeHash = autonomyDb.scopeHash(scope)
  const sn = 'sa' + rid()
  const setScope = await postJson(`${base}/api/v4/fit/autonomy`, {
    card_id: p.bobCard, scope, approved_hash: scopeHash, public_key: p.bob.keys.publicKey, nonce: sn,
    signature: sign(`set-fit-autonomy:${p.bobCard}:${scopeHash}:${sn}`, p.bob.keys.privateKey),
  })
  assert.equal(setScope.status, 201, JSON.stringify(setScope.json))

  const refused = await canonicalFitCommit(p, req.built.writeRef, { standing_scope_commitment: scopeHash })
  assert.equal(refused.status, 403, JSON.stringify(refused.json))
  assert.equal(refused.json.code, 'outside_autonomy_scope')
  assert.equal(handshakeDb.getHandshake(p.introId)!.state, 'requested', 'and nothing was evaluated')

  // Without the scope field it is an individually approved act and it goes through.
  const human = await canonicalFitCommit(p, req.built.writeRef)
  assert.equal(human.status, 201, JSON.stringify(human.json))
  assert.equal(human.json.authorized_under_standing_scope, false)
})

// ══════════════════════════════════════════════════════════════
// release_exact
// ══════════════════════════════════════════════════════════════

function revealBody(p: Pair, who: any, commitment: string, dimension: string, value: unknown, over: { openingValue?: unknown; salt?: string; nonce?: string } = {}) {
  const resource = { type: 'intro' as const, id: p.introId }
  const salt = over.salt ?? randomBytes(32).toString('base64url')
  const valueCommitment = env.privateValueCommitment('release_exact', resource, salt, value)
  return signedBody({
    operation: 'release_exact', resource,
    payload: { dimension, policy_commitment: commitment, private_value_commitment: valueCommitment },
    keys: who.keys, nonce: over.nonce,
    opening: { value: over.openingValue !== undefined ? over.openingValue : value, salt },
  })
}

test('RELEASE_EXACT: the signed value must equal the stored policy value, and a mismatch is an error not a substitution', async () => {
  const { p } = await committed()
  const stored = { min: 20, max: 40 }

  // The opening recomputes to the commitment, so check one passes. The value simply is not
  // what the policy holds, so check two refuses. Today the value is not signed at all:
  // dimMapFor at fit-v4-routes.ts:304 returns whatever the policy holds when the request
  // lands, so a policy edited between commit and reveal changes what one signature releases.
  const wrongValue = await postJson(fitUrl(p.introId, '/reveal'),
    revealBody(p, p.alice, p.aliceCommitment, 'weekly_commitment', { min: 1, max: 2 }).body)
  assert.equal(wrongValue.status, 409, JSON.stringify(wrongValue.json))
  assert.equal(wrongValue.json.code, 'value_not_in_policy')
  assert.equal(handshakeDb.releasersFor(
    handshakeDb.parseReleased(handshakeDb.getHandshake(p.introId)!.released_exacts_json), 'weekly_commitment',
  ).length, 0, 'and nothing was released')

  const right = await postJson(fitUrl(p.introId, '/reveal'),
    revealBody(p, p.alice, p.aliceCommitment, 'weekly_commitment', stored).body)
  assert.equal(right.status, 201, JSON.stringify(right.json))
  assert.equal(right.json.revealed, 'weekly_commitment')
  assert.equal(right.json.added, true)
  assert.deepEqual(handshakeDb.releasersFor(
    handshakeDb.parseReleased(handshakeDb.getHandshake(p.introId)!.released_exacts_json), 'weekly_commitment',
  ), [p.alice.keys.publicKey])
})

test('RELEASE_EXACT: a bad opening is refused with commitment_mismatch, before the policy is consulted at all', async () => {
  const { p } = await committed()
  const tampered = await postJson(fitUrl(p.introId, '/reveal'),
    revealBody(p, p.alice, p.aliceCommitment, 'weekly_commitment', { min: 20, max: 40 },
      { openingValue: { min: 999, max: 999 } }).body)
  assert.equal(tampered.status, 400)
  assert.equal(tampered.json.code, 'commitment_mismatch',
    'step 7 of the pipeline runs before the handler, so the policy is never read')
  // And to show the ordering rather than assert it by inspection: the same request with a
  // dimension the policy does not carry STILL answers commitment_mismatch when the opening
  // is broken, because the opening is checked first.
  const both = await postJson(fitUrl(p.introId, '/reveal'),
    revealBody(p, p.alice, p.aliceCommitment, 'not_a_dimension', { min: 1, max: 1 },
      { openingValue: 'different' }).body)
  assert.equal(both.json.code, 'commitment_mismatch')
})

test('RELEASE_EXACT: twice by the same key adds one releaser, and the second call is idempotent', async () => {
  const { p } = await committed()
  const value = { min: 20, max: 40 }
  const first = revealBody(p, p.alice, p.aliceCommitment, 'weekly_commitment', value)
  assert.equal((await postJson(fitUrl(p.introId, '/reveal'), first.body)).status, 201)

  // The same envelope: the nonce store answers with the stored result.
  const replay = await postJson(fitUrl(p.introId, '/reveal'), first.body)
  assert.equal(replay.status, 200)
  assert.equal(replay.json.idempotent, true)

  // A fresh envelope for the same dimension: releaseExact answers added = false, because a
  // repeat tap discloses nothing new.
  const fresh = await postJson(fitUrl(p.introId, '/reveal'),
    revealBody(p, p.alice, p.aliceCommitment, 'weekly_commitment', value).body)
  assert.equal(fresh.status, 201)
  assert.equal(fresh.json.added, false)
  assert.deepEqual(handshakeDb.releasersFor(
    handshakeDb.parseReleased(handshakeDb.getHandshake(p.introId)!.released_exacts_json), 'weekly_commitment',
  ), [p.alice.keys.publicKey], 'one releaser, not two')
})

test('RELEASE_EXACT: a release by A does not add B, and a dimension named constructor reads as absent', async () => {
  const { p } = await committed()
  assert.equal((await postJson(fitUrl(p.introId, '/reveal'),
    revealBody(p, p.alice, p.aliceCommitment, 'weekly_commitment', { min: 20, max: 40 }).body)).status, 201)
  const releasers = handshakeDb.releasersFor(
    handshakeDb.parseReleased(handshakeDb.getHandshake(p.introId)!.released_exacts_json), 'weekly_commitment')
  assert.deepEqual(releasers, [p.alice.keys.publicKey], 'the 9d056b5 regression: A releasing does not add B')
  assert.equal(releasers.includes(p.bob.keys.publicKey), false)

  // Object.hasOwn at fit-handshake-db.ts:138 is the prototype pollution guard.
  assert.deepEqual(handshakeDb.releasersFor({}, 'constructor'), [])
  assert.deepEqual(handshakeDb.releasersFor({}, 'toString'), [])
  assert.deepEqual(handshakeDb.releasersFor({ constructor: 'kA' } as any, 'constructor'), ['kA'],
    'an OWN member named constructor is a real release')
})

test('RELEASE_EXACT: the artifact carries the value, the evidence does not, and the subject is the dimension', async () => {
  const { p } = await committed()
  const value = { min: 20, max: 40 }
  const s = revealBody(p, p.alice, p.aliceCommitment, 'weekly_commitment', value)
  assert.equal((await postJson(fitUrl(p.introId, '/reveal'), s.body)).status, 201)

  const auth = db.getDb().prepare(
    "SELECT * FROM connection_authorizations WHERE intro_id = ? AND operation = 'release_exact'").get(p.introId) as any
  assert.equal(auth.subject, 'weekly_commitment', 'which is why the subject column exists')
  assert.equal(auth.actor_key, p.alice.keys.publicKey)

  const ev = db.getDb().prepare('SELECT * FROM write_evidence WHERE write_ref = ?').get(s.built.writeRef) as any
  assert.deepEqual(JSON.parse(ev.bound_fields_json),
    ['operation', 'resource.id', 'payload.dimension', 'payload.policy_commitment', 'payload.private_value_commitment'])
  assert.equal(JSON.stringify(ev).includes('"min":20'), false, 'the value is not in evidence')

  const art = db.getDb().prepare(
    'SELECT * FROM private_artifacts WHERE intro_id = ? AND operation = ?').get(p.introId, 'release_exact') as any
  assert.equal(art.subject, 'weekly_commitment')
  assert.equal(art.recipient_key, p.bob.keys.publicKey, 'the recipient is the counterparty, chosen by the server')
  assert.deepEqual(JSON.parse(art.opening_json).value, value)
  // The recipient verifies it alone, exactly as for a contact.
  const read = artifacts.readArtifact(art.artifact_id, p.bob.keys.publicKey)
  assert.equal(read.ok, true)
  // The author key is a REQUIRED argument now. Without it, `ok: true` meant only that
  // somebody signed something that opens to this value, which a stranger can also produce.
  const v = artifacts.verifyArtifactStandalone(
    artifacts.standaloneFrom((read as any).artifact), p.introId, p.alice.keys.publicKey)
  assert.equal(v.ok, true)
  assert.equal(v.author_is_expected, true)
  const wrongAuthor = artifacts.verifyArtifactStandalone(
    artifacts.standaloneFrom((read as any).artifact), p.introId, p.bob.keys.publicKey)
  assert.equal(wrongAuthor.author_is_expected, false)
  assert.equal(wrongAuthor.ok, false, 'a release_exact artifact is bound to WHO released it')
  assert.equal(artifacts.readArtifact(art.artifact_id, generateKeyPair().publicKey).ok, false)
})

test('RELEASE_EXACT: the commitment must name the policy version the HANDSHAKE was committed under', async () => {
  // Found by a review, and it was the sharpest of the fit findings. resolvePolicy pinned the
  // authorization to whatever policy is in force NOW, while GET /:introId discloses the value
  // from the COMMIT-TIME version. With the two halves on different versions, an owner could
  // edit a dimension after a commit that had authorized no disclosure of it, sign a release of
  // the new value, and have the counterparty handed the old one.
  const { p } = await committed()
  const committedHash = policyDb.policyHash(p.aliceDims)
  assert.equal(handshakeDb.getHandshake(p.introId)!.req_policy_hash, committedHash)

  // Supersede Alice's policy and register a commitment to the NEW version.
  const newDims = [
    dim('cadence', 'mixed', 'reveal_overlap'),
    dim('weekly_commitment', { min: 1, max: 2 }, 'reveal_exact'),
  ]
  assert.equal((await setPolicy(p.alice, p.aliceCard, newDims)).status, 201)
  const fresh = await registerCommitment(p.alice, p.aliceCard, newDims)
  assert.equal(fresh.status, 201, JSON.stringify(fresh.body))

  // A release under the CURRENT commitment is refused, because the handshake did not authorize
  // against that version.
  const underCurrent = await postJson(fitUrl(p.introId, '/reveal'),
    revealBody(p, p.alice, fresh.commitment, 'weekly_commitment', { min: 1, max: 2 }).body)
  assert.equal(underCurrent.status, 409, JSON.stringify(underCurrent.json))
  assert.equal(underCurrent.json.code, 'policy_commitment_not_committed')
  assert.equal(handshakeDb.releasersFor(
    handshakeDb.parseReleased(handshakeDb.getHandshake(p.introId)!.released_exacts_json), 'weekly_commitment',
  ).length, 0, 'and nothing was released')

  // The COMMITTED commitment still works, and the value it names is the committed one, which is
  // the value the read surface serves.
  const underCommitted = await postJson(fitUrl(p.introId, '/reveal'),
    revealBody(p, p.alice, p.aliceCommitment, 'weekly_commitment', { min: 20, max: 40 }).body)
  assert.equal(underCommitted.status, 201, JSON.stringify(underCommitted.json))
  assert.equal(underCommitted.json.added, true)
})

test('FIT_COMMIT: a standing scope must itself apply, even when nothing is evaluable', async () => {
  // Found by a review. The scope's expiry, intents and dimensions were enforced ONLY inside the
  // per-dimension loop, which is skipped entirely when nothing is mutually evaluable. So a
  // server-signed receipt could say "authorized under standing scope S" for a scope that had
  // expired years ago or was registered for another intent.
  const p = await pair()
  const req = await canonicalFitRequest(p, {
    requested_dimensions: ['cadence'], reciprocal_offer: ['cadence'],
  })
  assert.equal(req.status, 201, JSON.stringify(req.json))

  const expired = autonomyDb.validateScope({
    intents: ['cofound'], dimensions: ['cadence', 'weekly_commitment'],
    auto_reveal_overlap: true, reveal_bucket_on_reciprocity: true,
    ask_before_exact: true, forbidden_categories: [],
    expiry: new Date(Date.now() - 365 * 864e5).toISOString(),
  }).scope!
  const expiredHash = autonomyDb.scopeHash(expired)
  const sn = 'sx' + rid()
  assert.equal((await postJson(`${base}/api/v4/fit/autonomy`, {
    card_id: p.bobCard, scope: expired, approved_hash: expiredHash, public_key: p.bob.keys.publicKey, nonce: sn,
    signature: sign(`set-fit-autonomy:${p.bobCard}:${expiredHash}:${sn}`, p.bob.keys.privateKey),
  })).status, 201, 'validateScope accepts any parseable expiry, including a past one')

  // accept_dimensions names something the request did not, so nothing is evaluable and the
  // per-dimension loop never runs.
  const r = await canonicalFitCommit(p, req.built.writeRef, {
    accept_dimensions: ['weekly_commitment'], reciprocal_offer: ['weekly_commitment'],
    standing_scope_commitment: expiredHash,
  })
  assert.equal(r.status, 403, JSON.stringify(r.json))
  assert.equal(r.json.code, 'standing_scope_expired')
  assert.equal(handshakeDb.getHandshake(p.introId)!.state, 'requested', 'and nothing was committed')
})

test('FIT_COMMIT: a standing scope registered for another intent is refused', async () => {
  const p = await pair()
  const req = await canonicalFitRequest(p)
  const other = autonomyDb.validateScope({
    intents: ['collaborate'], dimensions: ['cadence'],
    auto_reveal_overlap: true, reveal_bucket_on_reciprocity: true,
    ask_before_exact: true, forbidden_categories: [], expiry: future(),
  }).scope!
  const h = autonomyDb.scopeHash(other)
  const sn = 'sy' + rid()
  assert.equal((await postJson(`${base}/api/v4/fit/autonomy`, {
    card_id: p.bobCard, scope: other, approved_hash: h, public_key: p.bob.keys.publicKey, nonce: sn,
    signature: sign(`set-fit-autonomy:${p.bobCard}:${h}:${sn}`, p.bob.keys.privateKey),
  })).status, 201)
  const r = await canonicalFitCommit(p, req.built.writeRef, { standing_scope_commitment: h })
  assert.equal(r.status, 403, JSON.stringify(r.json))
  assert.equal(r.json.code, 'standing_scope_wrong_intent',
    'the handshake intent is cofound and the scope covers collaborate')
})

// ══════════════════════════════════════════════════════════════
// first_step_propose and first_step_approve
// ══════════════════════════════════════════════════════════════

function half(over: Partial<Record<string, unknown>> = {}): Record<string, unknown> {
  return {
    purpose: 'compare notes on delegation chains',
    next_action: 'a 30 minute call',
    meeting_length: '30m',
    agenda: ['scope', 'then constraints'],
    each_wants: 'clarity on the shared interface',
    boundaries: ['no recruiting'],
    expiry: future(),
    ...over,
  }
}

async function propose(p: Pair, who: any, body = half()) {
  const s = signedBody({
    operation: 'first_step_propose', resource: { type: 'intro', id: p.introId }, payload: body, keys: who.keys,
  })
  return { ...(await postJson(fitUrl(p.introId, '/first-step'), s.body)), built: s.built }
}

test('FIRST_STEP_PROPOSE: the half is the payload, so the digest covers every field, and a link is refused', async () => {
  const { p } = await committed()
  const mine = half()
  const r = await propose(p, p.alice, mine)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.proposed, true)
  assert.equal(r.json.both_proposed, false)

  // Byte identical: rebuild the digest from the stored half and check it against the signed
  // envelope. Today the preimage is fit-firststep:${introId}:${nonce} and the entire half is
  // unbound, so nothing detects a change between preview and confirm.
  const row = firstStepDb.getFirstStep(p.introId)!
  const stored = JSON.parse(row.half_a_json!)
  const rebuilt = env.buildEnvelope({
    operation: 'first_step_propose', actorKey: p.alice.keys.publicKey,
    resource: { type: 'intro', id: p.introId },
    issuedAt: r.built.envelope.issued_at, nonce: r.built.envelope.nonce, payload: stored,
  })
  assert.equal(rebuilt.payloadDigest, r.built.payloadDigest,
    'the stored half reproduces the digest the principal signed')

  const ev = db.getDb().prepare('SELECT * FROM write_evidence WHERE write_ref = ?').get(r.built.writeRef) as any
  assert.deepEqual(JSON.parse(ev.bound_fields_json), [
    'operation', 'resource.id', 'payload.purpose', 'payload.next_action', 'payload.meeting_length',
    'payload.agenda', 'payload.each_wants', 'payload.boundaries', 'payload.expiry',
  ])

  // The URL strip is computed at fit-v4-routes.ts:525 and then DISCARDED, so URLs survive
  // on the legacy lane. On this lane a half whose text carries a link is refused.
  const linked = await propose(p, p.bob, half({ agenda: ['read https://evil.com/x first'] }))
  assert.equal(linked.status, 400)
  assert.equal(linked.json.code, 'half_contains_link')
  assert.equal(firstStepDb.getFirstStep(p.introId)!.half_b_json, null, 'and nothing was stored')
})

test('FIRST_STEP_PROPOSE: an EXTRA signed field is refused rather than silently dropped', async () => {
  // Found by a review. This was the one canonical fit action with no payload key gate, because
  // validateHalf copies seven known keys into a fresh object and ignores the rest. So an eighth
  // field was covered by payload_digest, accepted with a 201, and discarded, and the
  // counterparty would then approve a merged digest from which the principal's signed clause
  // had vanished. That is exactly what gatePayloadKeys refuses everywhere else.
  const { p } = await committed()
  const withExtra = await propose(p, p.alice, { ...half(), equity_split: '50/50' })
  assert.equal(withExtra.status, 400, JSON.stringify(withExtra.json))
  assert.equal(withExtra.json.code, 'malformed_payload')
  assert.match(withExtra.json.error, /unexpected payload field: equity_split/)
  assert.equal(firstStepDb.getFirstStep(p.introId), null, 'and nothing was stored')

  // A missing required field is refused the same way, by the gate rather than by validateHalf.
  const { expiry, ...withoutExpiry } = half()
  const missing = await propose(p, p.alice, withoutExpiry)
  assert.equal(missing.status, 400)
  assert.equal(missing.json.code, 'malformed_payload')
  assert.match(missing.json.error, /missing expiry/)

  // The exact seven still pass.
  assert.equal((await propose(p, p.alice, half())).status, 201)
})

test('FIRST_STEP_APPROVE: a digest that changed between read and write is refused, inside one transaction', async () => {
  const { p } = await committed()
  assert.equal((await propose(p, p.alice)).status, 201)
  assert.equal((await propose(p, p.bob, half({ agenda: ['bob agenda'] }))).status, 201)
  const row = firstStepDb.getFirstStep(p.introId)!
  const digest = firstStepDb.sharedDigest(row)

  // A stale digest, which is the ordinary case of the race: the client read, someone
  // re-proposed, and the client approved what it read.
  const stale = await postJson(fitUrl(p.introId, '/first-step/approve'), signedBody({
    operation: 'first_step_approve', resource: { type: 'intro', id: p.introId },
    payload: { approved_digest: 'c'.repeat(64) }, keys: p.alice.keys,
  }).body)
  assert.equal(stale.status, 409)
  assert.equal(stale.json.code, 'digest_changed')

  // The real race, driven at the database level with a second connection: the half changes
  // between the read and the approve. Inside the canonical handler both are in one
  // transaction, so the compare cannot be made against a row the write no longer matches.
  const other = new Database(DB_FILE)
  try {
    other.prepare('UPDATE v4_fit_first_step SET half_b_json = ? WHERE intro_id = ?')
      .run(JSON.stringify(half({ agenda: ['changed by another process'] })), p.introId)
  } finally { other.close() }
  const afterChange = await postJson(fitUrl(p.introId, '/first-step/approve'), signedBody({
    operation: 'first_step_approve', resource: { type: 'intro', id: p.introId },
    payload: { approved_digest: digest }, keys: p.alice.keys,
  }).body)
  assert.equal(afterChange.status, 409, JSON.stringify(afterChange.json))
  assert.equal(afterChange.json.code, 'digest_changed',
    'the digest the principal approved is no longer the shared artifact')

  // Re-read and approve the current digest, which succeeds.
  const fresh = firstStepDb.sharedDigest(firstStepDb.getFirstStep(p.introId)!)
  const ok = await postJson(fitUrl(p.introId, '/first-step/approve'), signedBody({
    operation: 'first_step_approve', resource: { type: 'intro', id: p.introId },
    payload: { approved_digest: fresh }, keys: p.alice.keys,
  }).body)
  assert.equal(ok.status, 201, JSON.stringify(ok.json))
  assert.equal(ok.json.approved, true)
  assert.equal(ok.json.finalized, false, 'one side only')
})

// ══════════════════════════════════════════════════════════════
// The legacy fit lane: evidence, and the two refusals
// ══════════════════════════════════════════════════════════════

test('LEGACY FIT: each of the five records a legacy_unbound row whose bound list matches its preimage', async () => {
  // One handshake driven entirely through the published 3.2.x shapes. The point of the test
  // is the bound field lists: each names exactly what its old preimage covered and nothing
  // more, so no receipt can promote any of them.
  // An OLD client all the way through, which means the intro was created legacily too.
  // A canonically created intro would be refused here by anti-downgrade, resolved through
  // write_create_map back to the create, and that is the correct behavior rather than
  // something to work around: it is asserted in its own test below.
  const q = await legacyPair()

  const rq = 'lr' + rid()
  const legacyRequest = await postJson(fitUrl(q.introId, '/request'), {
    requested_dimensions: ['cadence', 'weekly_commitment'], reciprocal_offer: ['cadence'],
    predicate_version: 1, policy_hash: policyDb.policyHash(q.aliceDims), query_budget: 5,
    public_key: q.alice.keys.publicKey, nonce: rq,
    signature: sign(`fit-request:${q.introId}:${rq}`, q.alice.keys.privateKey),
  })
  assert.equal(legacyRequest.status, 201, JSON.stringify(legacyRequest.json))

  const cn = 'lc' + rid()
  const legacyCommit = await postJson(fitUrl(q.introId, '/commit'), {
    accept_dimensions: ['cadence', 'weekly_commitment'], reciprocal_offer: ['cadence'],
    policy_hash: policyDb.policyHash(q.bobDims),
    public_key: q.bob.keys.publicKey, nonce: cn,
    signature: sign(`fit-commit:${q.introId}:${cn}`, q.bob.keys.privateKey),
  })
  assert.equal(legacyCommit.status, 200, JSON.stringify(legacyCommit.json))
  assert.ok(legacyCommit.json.receipt_digest, 'the legacy receipt is unchanged in shape')

  const rv = 'lv' + rid()
  const legacyReveal = await postJson(fitUrl(q.introId, '/reveal'), {
    dimension: 'weekly_commitment', public_key: q.alice.keys.publicKey, nonce: rv,
    signature: sign(`fit-reveal:${q.introId}:weekly_commitment:${rv}`, q.alice.keys.privateKey),
  })
  assert.equal(legacyReveal.status, 200, JSON.stringify(legacyReveal.json))

  const fs = 'lf' + rid()
  const legacyPropose = await postJson(fitUrl(q.introId, '/first-step'), {
    half: half(), public_key: q.alice.keys.publicKey, nonce: fs,
    signature: sign(`fit-firststep:${q.introId}:${fs}`, q.alice.keys.privateKey),
  })
  assert.equal(legacyPropose.status, 201, JSON.stringify(legacyPropose.json))
  const fsb = 'lfb' + rid()
  assert.equal((await postJson(fitUrl(q.introId, '/first-step'), {
    half: half({ agenda: ['bob'] }), public_key: q.bob.keys.publicKey, nonce: fsb,
    signature: sign(`fit-firststep:${q.introId}:${fsb}`, q.bob.keys.privateKey),
  })).status, 201)

  const digest = firstStepDb.sharedDigest(firstStepDb.getFirstStep(q.introId)!)
  const fa = 'la' + rid()
  const legacyApprove = await postJson(fitUrl(q.introId, '/first-step/approve'), {
    approved_digest: digest, public_key: q.alice.keys.publicKey, nonce: fa,
    signature: sign(`fit-firststep-approve:${q.introId}:${digest}:${fa}`, q.alice.keys.privateKey),
  })
  assert.equal(legacyApprove.status, 200, JSON.stringify(legacyApprove.json))

  const rows = evidence.evidenceForResource('intro', q.introId)
  const byOp = new Map(rows.filter(r => r.evidence === 'legacy_unbound').map(r => [r.operation, r]))
  assert.deepEqual(JSON.parse(byOp.get('fit_request')!.bound_fields_json), ['intro_id'],
    'the dimensions, the reciprocal offer and the budget are all unbound')
  assert.deepEqual(JSON.parse(byOp.get('fit_commit')!.bound_fields_json), ['intro_id'],
    'and whether the act was autonomous is established by nothing')
  assert.deepEqual(JSON.parse(byOp.get('release_exact')!.bound_fields_json), ['intro_id', 'dimension'],
    'the strongest of the five, and it still omits the value and the policy it came from')
  assert.deepEqual(JSON.parse(byOp.get('first_step_propose')!.bound_fields_json), ['intro_id'],
    'the entire half is unbound')
  assert.deepEqual(JSON.parse(byOp.get('first_step_approve')!.bound_fields_json), ['intro_id', 'approved_digest'],
    'the one fit action whose legacy signature covers its whole semantic content')
  for (const op of ['fit_request', 'fit_commit', 'release_exact', 'first_step_propose', 'first_step_approve']) {
    assert.equal(byOp.get(op)!.write_ref, null, `${op}: no envelope, so no write_ref`)
    assert.equal(byOp.get(op)!.payload_digest, null, `${op}: and no payload digest`)
  }
  // No artifact on the legacy lane, because a legacy act has no opening to write.
  const arts = db.getDb().prepare(
    'SELECT COUNT(*) AS n FROM private_artifacts WHERE intro_id = ?').get(q.introId) as any
  assert.equal(arts.n, 0)
})

test('LEGACY FIT: after the cutoff every legacy fit route answers 426, and anti-downgrade refuses a fallback', async () => {
  const { p } = await committed()
  // p's actors have used canonical authorization on this intro, so their next legacy act on
  // it is a downgrade, inside the window.
  const rv = 'dv' + rid()
  const downgrade = await postJson(fitUrl(p.introId, '/reveal'), {
    dimension: 'weekly_commitment', public_key: p.alice.keys.publicKey, nonce: rv,
    signature: sign(`fit-reveal:${p.introId}:weekly_commitment:${rv}`, p.alice.keys.privateKey),
  })
  assert.equal(downgrade.status, 426, JSON.stringify(downgrade.json))
  assert.equal(downgrade.json.code, 'client_upgrade_required')
  assert.equal(downgrade.json.error, 'Update Mingle to continue this connection.')

  // And the cutoff, on a pair with no canonical fit history.
  const q = await pair()
  assert.equal((await canonicalFitRequest(q)).status, 201)
  db.getDb().prepare('DELETE FROM write_auth_mode WHERE resource_id = ?').run(q.introId)
  db.getDb().prepare('INSERT OR REPLACE INTO schema_markers (key, value) VALUES (?, ?)')
    .run(db.LEGACY_WRITE_CUTOFF_KEY, new Date(Date.now() - 1000).toISOString())
  try {
    const fs = 'cf' + rid()
    const closed = await postJson(fitUrl(q.introId, '/first-step'), {
      half: half(), public_key: q.alice.keys.publicKey, nonce: fs,
      signature: sign(`fit-firststep:${q.introId}:${fs}`, q.alice.keys.privateKey),
    })
    assert.equal(closed.status, 426)
    assert.equal(closed.json.code, 'client_upgrade_required')
    // The canonical lane is unaffected by the cutoff, which is the point of having one.
    const stillFine = await propose(q, q.alice)
    assert.equal(stillFine.status, 201, JSON.stringify(stillFine.json))
  } finally {
    db.getDb().prepare('DELETE FROM schema_markers WHERE key = ?').run(db.LEGACY_WRITE_CUTOFF_KEY)
  }
})

test('AGREEMENT: every canonical fit act renews the connecting window and the column agrees', async () => {
  const rows = db.getDb().prepare(
    "SELECT DISTINCT intro_id FROM connection_authorizations WHERE evidence = 'canonical'").all() as { intro_id: string }[]
  assert.ok(rows.length > 3, `the suite wrote canonical facts, found ${rows.length}`)
  for (const { intro_id } of rows) {
    const f = facts.introFacts(intro_id)
    if (f === null) continue
    const derived = state.deriveIntroState(f)
    const got = (db.getDb().prepare('SELECT status FROM v3_intros WHERE id = ?').get(intro_id) as any).status
    assert.equal(got, state.materializedStatus(derived), `${intro_id} derives ${derived}`)
    // Every fit action is a continuation, so the derived expiry is measured from the most
    // recent one rather than from the interest.
    if (f.authorizations.some(a => a.live && a.operation !== 'request_intro' && a.operation !== 'express_interest')) {
      assert.equal(derived, 'connecting', `${intro_id} holds a live continuation`)
    }
  }
})

// ══════════════════════════════════════════════════════════════
// fit_answers, canonical (step 22)
// ══════════════════════════════════════════════════════════════
// Matrix row 34, rank 21, PARTIAL. The ledger item TEXT that ledger mode quotes was
// fetched live while only ledger_id was signed, and the stored drafted text was the
// post-gate cleaned string. So the record could not be recomputed from the signature in
// either mode, and the quoted words were warranted by nothing.

/** Recompute the payload digest from what the DATABASE holds, the way a later reader would. */
function digestOfStoredQa(introId: string, answererKey: string): string {
  const rows = qaDb.qaForIntro(introId)
    .filter(r => r.answerer_key === answererKey)
    .sort((a, b) => (a.dimension < b.dimension ? -1 : 1))
  const answers = rows.map(r => {
    if (r.mode === 'skip') return { dimension: r.dimension, mode: r.mode }
    if (r.mode === 'ledger') return { dimension: r.dimension, ledger_id: ledgerIdOf(r), mode: r.mode, text: r.text }
    return { dimension: r.dimension, mode: r.mode, text: r.text }
  })
  return env.buildEnvelope({
    operation: 'fit_answers' as any, actorKey: answererKey,
    resource: { type: 'intro', id: introId } as any,
    issuedAt: '2026-01-01T00:00:00.000Z', nonce: 'y'.repeat(22), payload: { answers },
  }).payloadDigest
}
/** v4_fit_qa has no ledger_id column, so the test carries the id it signed. */
let signedLedgerId = ''
function ledgerIdOf(_row: unknown): string { return signedLedgerId }

async function setLedgerFor(who: any, cardId: string, texts: string[]): Promise<{ id: string; text: string }> {
  const approved_hash = (await import('../src/fit-db.js')).ledgerHash(texts)
  const nonce = 'dl' + rid()
  const r = await (await fetch(`${base}/api/v3/fit/disclosures`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      card_id: cardId, items: texts.map(t => ({ text: t })), approved_hash,
      public_key: who.keys.publicKey, nonce,
      signature: sign(`set-disclosures:${cardId}:${approved_hash}:${nonce}`, who.keys.privateKey),
    }),
  })).json()
  assert.ok(r.items, JSON.stringify(r))
  return { id: r.items[0].id, text: r.items[0].text }
}

test('FIT ANSWERS: the stored answer recomputes to the signed payload digest, in all three modes', async () => {
  const p = await pair([
    dim('cadence', 'mixed', 'reveal_overlap'),
    dim('weekly_commitment', { min: 20, max: 40 }, 'reveal_exact'),
    dim('start_window', 'flexible', 'reveal_overlap'),
  ], [
    dim('cadence', 'mixed', 'reveal_overlap'),
    dim('weekly_commitment', { min: 10, max: 30 }, 'reveal_exact'),
    dim('start_window', 'within_month', 'reveal_overlap'),
  ])
  // A handshake must exist, exactly as the legacy route has always required. fit_request is
  // the one act that opens one, and answering is not it.
  assert.equal((await canonicalFitRequest(p)).status, 201)
  const item = await setLedgerFor(p.bob, p.bobCard, ['I can give three evenings and one weekend day.'])
  signedLedgerId = item.id

  const answers = [
    { dimension: 'cadence', mode: 'drafted', text: 'Mixed, with one live day a week.' },
    { dimension: 'start_window', mode: 'skip' },
    { dimension: 'weekly_commitment', ledger_id: item.id, mode: 'ledger', text: item.text },
  ]
  const s = signedBody({
    operation: 'fit_answers', resource: { type: 'intro', id: p.introId }, payload: { answers }, keys: p.bob.keys,
  })
  const res = await postJson(fitUrl(p.introId, '/answers'), s.body)
  assert.equal(res.status, 201, JSON.stringify(res.json))
  assert.equal(res.json.answered, 3)

  assert.equal(digestOfStoredQa(p.introId, p.bob.keys.publicKey), s.built.payloadDigest,
    'the stored rows must rebuild the exact payload the principal signed')

  const rows = qaDb.qaForIntro(p.introId)
  const ledgerRow = rows.find(r => r.dimension === 'weekly_commitment')!
  assert.equal(ledgerRow.text, item.text)
  assert.equal(ledgerRow.text!.includes('Their approved brief states'), false,
    'no server composed wrap around words the principal signed')
  assert.equal(rows.find(r => r.dimension === 'start_window')!.text, null)
  // The airlock extraction is still stored for a drafted answer, derived from the signed
  // text by a deterministic function, so it asserts nothing the signature does not cover.
  assert.ok(rows.find(r => r.dimension === 'cadence')!.extraction_json)

  const row = evidence.evidenceByWriteRef(s.built.writeRef)!
  assert.deepEqual(evidence.boundFieldsOf(row), ['operation', 'resource.id', 'payload.answers'])
})

test('FIT ANSWERS: it is a CONTINUATION, so it moves the connecting deadline', async () => {
  // The same treatment fit_round2 has, and for the same reason: a signed act by a party on
  // a live connection. Answering is activity, and expiry measures inactivity.
  const p = await pair()
  assert.equal(facts.introProjection(p.introId, p.bob.keys.publicKey)!.state, 'interested')
  assert.equal((await canonicalFitRequest(p)).status, 201)

  const answers = [{ dimension: 'cadence', mode: 'drafted', text: 'Mixed works for me.' }]
  const s = signedBody({
    operation: 'fit_answers', resource: { type: 'intro', id: p.introId }, payload: { answers }, keys: p.bob.keys,
  })
  assert.equal((await postJson(fitUrl(p.introId, '/answers'), s.body)).status, 201)

  const after = facts.introProjection(p.introId, p.bob.keys.publicKey)!
  assert.equal(after.state, 'connecting')
  assert.ok(state.CONTINUATIONS.includes('fit_answers' as any), 'it is in the continuation list')
  const auth = facts.authorizationOf(p.introId, p.bob.keys.publicKey, 'fit_answers' as any)!
  assert.equal(auth.live, 1)
  assert.equal(auth.evidence, 'canonical')
  // The deadline is 30 days from THIS act's own time, which is what makes answering count as
  // activity. Asserted against the row rather than against a clock, so it is exact.
  assert.equal(after.expires_at, new Date(Date.parse(auth.created_at) + 30 * 864e5).toISOString())
})

test('FIT ANSWERS: a rewritten text, a substituted ledger text and an unaskable dimension are all refused', async () => {
  const p = await pair()
  assert.equal((await canonicalFitRequest(p)).status, 201)
  const item = await setLedgerFor(p.bob, p.bobCard, ['I can give three evenings.'])
  const bad: [string, any, number, string][] = [
    ['a link the gate would strip',
      [{ dimension: 'cadence', mode: 'drafted', text: 'See https://example.com/cadence' }], 400, 'text_not_stored_as_signed'],
    ['contact data',
      [{ dimension: 'cadence', mode: 'drafted', text: 'Reach me at me@example.com' }], 400, 'post_gate_refused'],
    ['a ledger text of the signer\'s choosing',
      [{ dimension: 'weekly_commitment', ledger_id: item.id, mode: 'ledger', text: 'I can give nine evenings.' }], 409, 'ledger_text_mismatch'],
    ['a ledger id that names nothing',
      [{ dimension: 'weekly_commitment', ledger_id: 'nope', mode: 'ledger', text: 'x' }], 409, 'ledger_item_superseded'],
    ['a dimension with no canonical question',
      [{ dimension: 'favourite_colour', mode: 'drafted', text: 'Blue.' }], 400, 'dimension_not_askable'],
    ['unsorted answers',
      [{ dimension: 'weekly_commitment', mode: 'skip' }, { dimension: 'cadence', mode: 'skip' }], 400, 'malformed_payload'],
    ['a skip carrying text',
      [{ dimension: 'cadence', mode: 'skip', text: 'x' }], 400, 'malformed_payload'],
  ]
  for (const [why, answers, status, code] of bad) {
    const s = signedBody({
      operation: 'fit_answers', resource: { type: 'intro', id: p.introId }, payload: { answers }, keys: p.bob.keys,
    })
    const res = await postJson(fitUrl(p.introId, '/answers'), s.body)
    assert.equal(res.status, status, `${why}: ${JSON.stringify(res.json)}`)
    assert.equal(res.json.code, code, why)
  }
  assert.deepEqual(qaDb.qaForIntro(p.introId), [], 'and not one refusal left a row behind')
})

test('FIT ANSWERS: the legacy lane still works, is recorded as weak, and is no continuation', async () => {
  const p = await legacyPair()
  const nonce = 'la' + rid()
  const answers = [{ dimension: 'cadence', mode: 'drafted', text: 'Mixed, see https://example.com/x' }]
  const hash = createHash('sha256').update(canonicalize({ intro_id: p.introId, nonce, answers }), 'utf8').digest('hex')
  const res = await postJson(fitUrl(p.introId, '/answers'), {
    answers, public_key: p.bob.keys.publicKey, nonce, signature: sign(hash, p.bob.keys.privateKey),
  })
  assert.equal(res.status, 200, JSON.stringify(res.json))
  const row = qaDb.qaForIntro(p.introId).find(r => r.dimension === 'cadence')!
  assert.equal(row.text!.includes('https://example.com'), false, 'the legacy lane still cleans')

  const ev = evidence.evidenceForResource('intro', p.introId).filter(e => e.operation === 'fit_answers')
  assert.equal(ev.length, 1)
  assert.equal(ev[0].evidence, 'legacy_unbound')
  assert.deepEqual(evidence.boundFieldsOf(ev[0]), ['intro_id', 'answers_submitted'])
  assert.equal(evidence.covers(ev[0], 'payload.answers'), false)
  // No authorization row, so a legacy answer never moves a deadline: nothing in those bytes
  // says which answers were authorized.
  assert.equal(facts.authorizationOf(p.introId, p.bob.keys.publicKey, 'fit_answers' as any), null)
})

test('FIT ANSWERS: anti-downgrade, a canonical answer closes the legacy form for that key', async () => {
  const p = await legacyPair()
  const s = signedBody({
    operation: 'fit_answers', resource: { type: 'intro', id: p.introId },
    payload: { answers: [{ dimension: 'cadence', mode: 'drafted', text: 'Mixed.' }] }, keys: p.bob.keys,
  })
  assert.equal((await postJson(fitUrl(p.introId, '/answers'), s.body)).status, 201)

  const nonce = 'ld' + rid()
  const answers = [{ dimension: 'cadence', mode: 'drafted', text: 'Actually async.' }]
  const hash = createHash('sha256').update(canonicalize({ intro_id: p.introId, nonce, answers }), 'utf8').digest('hex')
  const back = await postJson(fitUrl(p.introId, '/answers'), {
    answers, public_key: p.bob.keys.publicKey, nonce, signature: sign(hash, p.bob.keys.privateKey),
  })
  assert.equal(back.status, 426)
  assert.equal(back.json.code, 'client_upgrade_required')
  assert.equal(qaDb.qaForIntro(p.introId).find(r => r.dimension === 'cadence')!.text, 'Mixed.',
    'and the refused call changed nothing')
})
