// ══════════════════════════════════════════════════════════════
// API tests — full HTTP surface on an ephemeral in-process server
// ══════════════════════════════════════════════════════════════
// Boots createApp() (no port bound at import) on port 0 with
// DB_PATH pointed at a throwaway SQLite file in a temp directory.
// Cards are real Ed25519-signed IntentCards from the
// agent-passport-system SDK, so signature verification runs for
// real. Never touches data/intent-network.db or api.aeoess.com.
//
// The embedding model is intentionally NOT warmed up: tests assert
// the documented cold-start behavior (matchingVersion:
// 'pending-embeddings'). Semantic matching math is covered in
// db.test.ts with synthetic vectors.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { createIntentCard, generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'intent-net-api-test-'))
process.env.DB_PATH = join(tmpDir, 'api-test.db')

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(resolve => {
    server = app.listen(0, '127.0.0.1', () => resolve())
  })
  const addr = server.address() as { port: number }
  base = `http://127.0.0.1:${addr.port}`
})

after(() => {
  server?.close()
  db.closeDb()
  rmSync(tmpDir, { recursive: true, force: true })
})

// ── Fixtures: real signed cards ──
const keysAlice = generateKeyPair()
const keysBob = generateKeyPair()

const cardAlice = createIntentCard({
  agentId: 'alice-agent', principalAlias: 'Alice (Founder)',
  publicKey: keysAlice.publicKey, privateKey: keysAlice.privateKey,
  needs: [{ category: 'engineering', description: 'Senior Rust backend engineer', priority: 'high', tags: ['rust'], visibility: 'public' }],
  offers: [{ category: 'funding', description: 'Seed investment for dev tools', priority: 'medium', tags: ['seed'], visibility: 'public' }],
  openTo: ['introductions'], notOpenTo: ['cold-sales'],
  ttlSeconds: 86400,
})

const cardBob = createIntentCard({
  agentId: 'bob-agent', principalAlias: 'Bob (Engineer)',
  publicKey: keysBob.publicKey, privateKey: keysBob.privateKey,
  needs: [{ category: 'funding', description: 'Seed funding for a dev tools startup', priority: 'high', tags: ['seed'], visibility: 'public' }],
  offers: [{ category: 'engineering', description: 'Senior Rust engineer, 8yr protocol exp', priority: 'high', tags: ['rust'], visibility: 'public' }],
  openTo: ['introductions'], notOpenTo: [],
  ttlSeconds: 86400,
})

/** Sign an arbitrary request body the way requireSignature verifies it. */
function signedBody(payload: Record<string, unknown>, privateKey: string): Record<string, unknown> {
  const signature = sign(canonicalize(payload), privateKey)
  return { ...payload, signature }
}

async function req(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return { status: res.status, json: await res.json() as any }
}

// ── Health + root ──

test('GET /health returns ok with version and uptime', async () => {
  const { status, json } = await req('GET', '/health')
  assert.equal(status, 200)
  assert.equal(json.status, 'ok')
  assert.equal(json.version, '0.4.0')
  assert.equal(typeof json.uptime, 'number')
})

test('GET / documents the endpoint map', async () => {
  const { status, json } = await req('GET', '/')
  assert.equal(status, 200)
  assert.equal(json.name, 'AEOESS Intent Network API')
  assert.ok(json.endpoints['POST /api/cards'])
  assert.ok(json.endpoints['GET /api/digest/:agentId'])
})

// ── Card publish + retrieval ──

test('POST /api/cards publishes a validly signed card', async () => {
  const { status, json } = await req('POST', '/api/cards', { ...cardAlice, publicKey: keysAlice.publicKey })
  assert.equal(status, 201)
  assert.equal(json.published, true)
  assert.equal(json.cardId, cardAlice.cardId)
  assert.equal(json.agentId, 'alice-agent')
  assert.equal(json.expiresAt, cardAlice.expiresAt)
  assert.equal(json.networkSize, 1)
  // Model not warmed in tests → cold-start contract
  assert.equal(json.matchingVersion, 'pending-embeddings')
  assert.deepEqual(json.topMatches, [])
})

test('GET /api/cards/:agentId returns the persisted card intact', async () => {
  const { status, json } = await req('GET', '/api/cards/alice-agent')
  assert.equal(status, 200)
  assert.equal(json.card.cardId, cardAlice.cardId)
  assert.equal(json.card.agentId, 'alice-agent')
  assert.equal(json.card.principalAlias, 'Alice (Founder)')
  assert.equal(json.card.needs[0].description, 'Senior Rust backend engineer')
  assert.equal(json.card.signature, cardAlice.signature, 'signature survives persistence round-trip')
})

test('GET /api/cards/:agentId → 404 for unknown agent', async () => {
  const { status, json } = await req('GET', '/api/cards/no-such-agent')
  assert.equal(status, 404)
  assert.ok(json.error)
})

// ── Negative cases: publish ──

test('POST /api/cards without signature → 401', async () => {
  const { signature, ...unsigned } = cardAlice as any
  const { status, json } = await req('POST', '/api/cards', { ...unsigned, publicKey: keysAlice.publicKey })
  assert.equal(status, 401)
  assert.match(json.error, /signature/i)
})

test('POST /api/cards with tampered payload → 403 (signature mismatch)', async () => {
  const tampered = JSON.parse(JSON.stringify(cardAlice))
  tampered.needs[0].description = 'ATTACKER-EDITED need'
  const { status, json } = await req('POST', '/api/cards', { ...tampered, publicKey: keysAlice.publicKey })
  assert.equal(status, 403)
  assert.match(json.error, /signature/i)
  // Persisted card unchanged
  const check = await req('GET', '/api/cards/alice-agent')
  assert.equal(check.json.card.needs[0].description, 'Senior Rust backend engineer')
})

test('POST /api/cards with no needs and no offers → 400', async () => {
  const empty = createIntentCard({
    agentId: 'empty-agent', principalAlias: 'Empty',
    publicKey: keysBob.publicKey, privateKey: keysBob.privateKey,
    needs: [], offers: [], openTo: [], notOpenTo: [], ttlSeconds: 3600,
  })
  const { status, json } = await req('POST', '/api/cards', { ...empty, publicKey: keysBob.publicKey })
  assert.equal(status, 400)
  assert.match(json.error, /at least one need or offer/i)
})

// ── Matching (cold model) ──

test('GET /api/matches/:agentId without embeddings → pending-embeddings, zero matches', async () => {
  const { status, json } = await req('GET', '/api/matches/alice-agent', undefined, { 'X-Agent-Id': 'alice-agent' })
  assert.equal(status, 200)
  assert.equal(json.matchingVersion, 'pending-embeddings')
  assert.equal(json.matchCount, 0)
  assert.deepEqual(json.matches, [])
})

test('GET /api/matches/:agentId → 404 without a published card', async () => {
  const { status } = await req('GET', '/api/matches/no-card-agent', undefined, { 'X-Agent-Id': 'no-card-agent' })
  assert.equal(status, 404)
})

test('POST /api/matches/ghost with empty body → 400', async () => {
  const { status, json } = await req('POST', '/api/matches/ghost', {})
  assert.equal(status, 400)
  assert.match(json.error, /at least one need or offer/i)
})

test('POST /api/matches/ghost (cold model) → zero matches, ghost flag set', async () => {
  const { status, json } = await req('POST', '/api/matches/ghost', { needs: ['rust engineer'] })
  assert.equal(status, 200)
  assert.equal(json.ghost, true)
  assert.equal(json.matchCount, 0)
})

// ── Intro protocol (signed end-to-end) ──

let introId: string

test('POST /api/intros creates a pending intro (Bob → Alice)', async () => {
  // Bob needs a card too (intros track the target's profile via cards)
  const pub = await req('POST', '/api/cards', { ...cardBob, publicKey: keysBob.publicKey })
  assert.equal(pub.status, 201)

  const body = signedBody({
    agentId: 'bob-agent',
    publicKey: keysBob.publicKey,
    matchId: 'match-manual-1',
    targetAgentId: 'alice-agent',
    message: 'Saw your card — I am a Rust engineer looking for seed funding.',
  }, keysBob.privateKey)

  const { status, json } = await req('POST', '/api/intros', body)
  assert.equal(status, 201)
  assert.equal(json.status, 'pending')
  assert.equal(json.targetAgentId, 'alice-agent')
  assert.ok(json.introId)
  introId = json.introId
})

test('POST /api/intros → 404 when target has no card', async () => {
  const body = signedBody({
    agentId: 'bob-agent',
    publicKey: keysBob.publicKey,
    matchId: 'match-manual-2',
    targetAgentId: 'nobody-home',
    message: 'hello?',
  }, keysBob.privateKey)
  const { status, json } = await req('POST', '/api/intros', body)
  assert.equal(status, 404)
  assert.match(json.error, /no active card/i)
})

test('GET /api/digest/:agentId shows the pending intro to the target', async () => {
  const { status, json } = await req('GET', '/api/digest/alice-agent', undefined, { 'X-Agent-Id': 'alice-agent' })
  assert.equal(status, 200)
  assert.equal(json.agentId, 'alice-agent')
  assert.equal(json.hasCard, true)
  assert.equal(json.networkSize, 2)
  assert.equal(json.introsReceived.length, 1)
  assert.equal(json.introsReceived[0].introId, introId)
  assert.equal(json.introsReceived[0].requestedBy, 'bob-agent')
  assert.match(json.summary, /1 intro for you to review/)
})

test('PUT /api/intros/:introId by a non-target agent → 403', async () => {
  const body = signedBody({
    agentId: 'bob-agent', // Bob is the requester, not the target
    publicKey: keysBob.publicKey,
    verdict: 'approve',
  }, keysBob.privateKey)
  const { status, json } = await req('PUT', `/api/intros/${introId}`, body)
  assert.equal(status, 403)
  assert.match(json.error, /only the target/i)
})

test('PUT /api/intros/:introId with invalid verdict → 400', async () => {
  const body = signedBody({
    agentId: 'alice-agent',
    publicKey: keysAlice.publicKey,
    verdict: 'maybe',
  }, keysAlice.privateKey)
  const { status, json } = await req('PUT', `/api/intros/${introId}`, body)
  assert.equal(status, 400)
  assert.match(json.error, /approve.*decline|decline.*approve/i)
})

test('PUT /api/intros/:introId — target approves, state transitions', async () => {
  const body = signedBody({
    agentId: 'alice-agent',
    publicKey: keysAlice.publicKey,
    verdict: 'approve',
    message: 'Happy to connect.',
  }, keysAlice.privateKey)
  const { status, json } = await req('PUT', `/api/intros/${introId}`, body)
  assert.equal(status, 200)
  assert.equal(json.status, 'approved')

  // No longer pending in the digest
  const digest = await req('GET', '/api/digest/alice-agent', undefined, { 'X-Agent-Id': 'alice-agent' })
  assert.equal(digest.json.introsReceived.length, 0)

  // Second response is rejected
  const again = await req('PUT', `/api/intros/${introId}`, body)
  assert.equal(again.status, 400)
  assert.match(again.json.error, /already approved/i)
})

// ── Feedback + trust ──

test('POST /api/feedback/:introId records feedback; bad rating → 400', async () => {
  const bad = await req('POST', `/api/feedback/${introId}`, { rating: 'amazing' }, { 'X-Agent-Id': 'alice-agent' })
  assert.equal(bad.status, 400)

  const ok = await req('POST', `/api/feedback/${introId}`, { rating: 'useful' }, { 'X-Agent-Id': 'alice-agent' })
  assert.equal(ok.status, 200)
  assert.equal(ok.json.submitted, true)

  // Bob (the other party) gets the useful-feedback credit
  const trust = await req('GET', '/api/trust/bob-agent')
  assert.equal(trust.status, 200)
  assert.equal(trust.json.feedbackUseful, 1)
})

test('GET /api/trust/:agentId reflects intro activity', async () => {
  const { status, json } = await req('GET', '/api/trust/bob-agent')
  assert.equal(status, 200)
  assert.equal(json.agentId, 'bob-agent')
  assert.equal(json.totalPublished, 1)
  assert.equal(json.totalIntrosSent, 1)
  assert.equal(json.totalIntrosAccepted, 1)
  assert.ok(['new', 'established'].includes(json.trustLevel))
})

// ── Identity resolution ──

test('GET /api/resolve?did=did:aps:… resolves a published identity', async () => {
  const { status, json } = await req('GET', '/api/resolve?did=did:aps:alice-agent')
  assert.equal(status, 200)
  assert.equal(json.did, 'did:aps:alice-agent')
  assert.equal(json.source_protocol, 'aps')
  assert.equal(json.public_key, Buffer.from(keysAlice.publicKey, 'base64').toString('hex'))
  assert.equal(json.public_key_type, 'Ed25519VerificationKey2020')
  assert.deepEqual(json.card_summary.needs, ['Senior Rust backend engineer'])
})

test('GET /api/resolve without did → 400; unknown did → 404', async () => {
  assert.equal((await req('GET', '/api/resolve')).status, 400)
  assert.equal((await req('GET', '/api/resolve?did=did:aps:nope')).status, 404)
})

// ── Stats + detailed health ──

test('GET /api/stats counts publishes and active cards', async () => {
  const { status, json } = await req('GET', '/api/stats')
  assert.equal(status, 200)
  assert.equal(json.total_cards_published, 2, 'alice + bob')
  assert.equal(json.active_cards, 2)
  assert.equal(json.total_intros_requested, 1)
  assert.equal(json.total_intros_approved, 1)
  assert.equal(json.version, '0.4.0')
})

test('GET /api/health reports live DB-backed numbers', async () => {
  const { status, json } = await req('GET', '/api/health')
  assert.equal(status, 200)
  assert.equal(json.status, 'ok')
  assert.equal(json.activeCards, 2)
  assert.equal(json.activeUsers, 2, 'two distinct public keys')
  assert.equal(json.pendingIntros, 0)
  assert.ok(json.lastCardPublished)
})

// ── Card deletion ──

test('DELETE /api/cards/:cardId — wrong key 404, owner key removes', async () => {
  // Alice tries to delete Bob's card: signature valid but key does not own the card
  const wrong = signedBody({ agentId: 'alice-agent', publicKey: keysAlice.publicKey }, keysAlice.privateKey)
  const denied = await req('DELETE', `/api/cards/${cardBob.cardId}`, wrong)
  assert.equal(denied.status, 404)
  assert.match(denied.json.error, /not found or not owned/i)
  assert.equal((await req('GET', '/api/cards/bob-agent')).status, 200, 'card survives')

  // Bob deletes his own card
  const own = signedBody({ agentId: 'bob-agent', publicKey: keysBob.publicKey }, keysBob.privateKey)
  const removed = await req('DELETE', `/api/cards/${cardBob.cardId}`, own)
  assert.equal(removed.status, 200)
  assert.equal(removed.json.removed, true)
  assert.equal((await req('GET', '/api/cards/bob-agent')).status, 404, 'card gone')
})
