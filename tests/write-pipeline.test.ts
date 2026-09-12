// ══════════════════════════════════════════════════════════════
// The canonical write chain, end to end over HTTP
// ══════════════════════════════════════════════════════════════
// No product route exists yet, so the chain is mounted on a test only route. That
// is the point of proving it here: the transport, the check order and the
// transaction boundary are settled before any route depends on them.
//
// The assertion that matters most: a refusal at ANY stage writes nothing. Not a
// nonce row, not a fact, not an evidence row, not a rate-limit-visible side effect
// on the domain. The test drives one refusal per stage and counts rows after each.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import express from 'express'
import { generateKeyPair, sign } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-pipeline-test-'))
process.env.DB_PATH = join(tmpDir, 'pipe.db')
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey

const db = await import('../src/db.js')
const wdb = await import('../src/write-db.js')
const env = await import('../src/write-envelope.js')
const pipe = await import('../src/write-pipeline.js')
const { newNonce } = await import('../src/canonical-write.js')

const actor = generateKeyPair()
const INTRO = { type: 'intro' as const, id: 'intro-pipe-1' }

let server: Server
let base: string
let handlerRuns = 0
let afterCommitRuns = 0
let refuseNext: { status: number; code: string; error: string } | null = null

before(async () => {
  db.getDb()
  wdb.initWriteSchema()
  const app = express()
  app.use(express.json({ limit: '100kb' }))
  // A test only route. Accepts two operations so the "not on this route" refusal is
  // reachable with a real signed envelope.
  app.post('/test/canonical', pipe.canonicalWriteRoute({
    operations: ['express_interest', 'share_contact'],
    handler: ctx => {
      handlerRuns++
      if (refuseNext) pipe.refuseWrite(refuseNext.status, refuseNext.code, refuseNext.error)
      // Keyed on write_ref, so the subject is unique per act and this fixture
      // cannot collide across tests. An earlier version keyed on a counter that
      // beforeEach reset, which collided on the primary key and surfaced a real
      // defect: an unexpected throw escaped the async Express handler and hung the
      // request with no response. That is now a 500 with a code, and this test
      // keeps a clean fixture so it tests the pipeline rather than the boundary.
      db.getDb().prepare('INSERT INTO connection_authorizations (intro_id, actor_key, operation, subject, evidence_id, evidence) VALUES (?,?,?,?,?,?)')
        .run(INTRO.id, actor.publicKey, 'express_interest', ctx.write.writeRef.slice(0, 16), 'ev-pipe', 'canonical')
      return { accepted: true, runs: handlerRuns }
    },
    afterCommit: () => { afterCommitRuns++ },
  }))
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })

beforeEach(() => {
  db.getDb().prepare('DELETE FROM rate_limits').run()
  handlerRuns = 0
  afterCommitRuns = 0
  refuseNext = null
})

function counts() {
  const d = db.getDb()
  const one = (sql: string) => (d.prepare(sql).get() as any).n
  return {
    nonces: one('SELECT COUNT(*) AS n FROM write_nonces'),
    facts: one('SELECT COUNT(*) AS n FROM connection_authorizations'),
    evidence: one('SELECT COUNT(*) AS n FROM write_evidence'),
    modes: one('SELECT COUNT(*) AS n FROM write_auth_mode'),
  }
}

async function post(body: unknown) {
  const res = await fetch(`${base}/test/canonical`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  let json: any = null
  try { json = await res.json() } catch { /* empty body */ }
  return { status: res.status, json }
}

const { jcs } = await import('../src/canonical-write.js')

interface BodyOver { operation?: any; payload?: any; resource?: any; issuedAt?: string; nonce?: string; privateKey?: string; opening?: any; envelopePatch?: any }

function signedBody(over: BodyOver = {}) {
  const operation = over.operation ?? 'express_interest'
  const payload = over.payload ?? {}
  const built = env.buildEnvelope({
    operation, actorKey: actor.publicKey, resource: over.resource ?? INTRO,
    issuedAt: over.issuedAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
    nonce: over.nonce ?? newNonce(), payload,
  })
  const envelope: Record<string, unknown> = { ...built.envelope, ...(over.envelopePatch ?? {}) }
  const signature = sign(jcs(envelope), over.privateKey ?? actor.privateKey)
  const body: Record<string, unknown> = { envelope, signature, payload }
  if (over.opening !== undefined) body.opening = over.opening
  return { body, built }
}

// ── The happy path ────────────────────────────────────────────────────────

test('PIPELINE: a valid canonical write commits, responds 201 and runs afterCommit once', async () => {
  const { body, built } = signedBody()
  const r = await post(body)
  assert.equal(r.status, 201)
  assert.equal(r.json.accepted, true)
  assert.equal(r.json.write_ref, built.writeRef)
  assert.equal(r.json.idempotent, false)
  assert.equal(handlerRuns, 1)
  // afterCommit is awaited after the response, so give the event loop a turn.
  await new Promise(r2 => setTimeout(r2, 20))
  assert.equal(afterCommitRuns, 1)
})

test('PIPELINE: an identical resend returns the stored result with 200 and runs neither the handler nor afterCommit again', async () => {
  const { body } = signedBody()
  const first = await post(body)
  assert.equal(first.status, 201)
  await new Promise(r2 => setTimeout(r2, 20))
  const runsBefore = handlerRuns
  const afterBefore = afterCommitRuns

  const again = await post(body)
  assert.equal(again.status, 200, 'an idempotent resend is not a creation')
  assert.equal(again.json.idempotent, true)
  assert.equal(again.json.runs, first.json.runs, 'the stored answer, byte for byte')
  await new Promise(r2 => setTimeout(r2, 20))
  assert.equal(handlerRuns, runsBefore, 'the handler did not run again')
  assert.equal(afterCommitRuns, afterBefore, 'and no email would be sent twice')
})

// ── A refusal at every stage writes nothing ───────────────────────────────

test('PIPELINE: a refusal at any stage leaves no nonce, no fact, no evidence, no mode row', async () => {
  const cases: [string, unknown, number, string][] = [
    ['malformed body, an array is valid JSON but not an object', [1, 2], 400, 'malformed_body'],
    ['unknown domain', signedBody({ envelopePatch: { domain: 'mingle-write-v9' } }).body, 400, 'unknown_envelope_domain'],
    ['unknown operation', signedBody({ envelopePatch: { operation: 'nope' } }).body, 400, 'unknown_operation'],
    ['bad nonce', signedBody({ nonce: 'short' }).body, 400, 'malformed_nonce'],
    ['null in payload', signedBody({ payload: { note: null } }).body, 400, 'null_in_payload'],
    ['extra envelope field', signedBody({ envelopePatch: { scope: 'x' } }).body, 400, 'unexpected_envelope_field'],
    ['bad signature', signedBody({ privateKey: generateKeyPair().privateKey }).body, 403, 'signature_invalid'],
    ['stale', signedBody({ issuedAt: '2020-01-01T00:00:00.000Z' }).body, 401, 'stale_authorization'],
    ['wrong route operation', signedBody({ operation: 'decline' }).body, 400, 'operation_not_on_this_route'],
    ['unexpected opening', signedBody({ opening: { value: 'x', salt: 'A'.repeat(43) } }).body, 400, 'unexpected_opening'],
  ]
  for (const [label, body, status, code] of cases) {
    const before = counts()
    const r = await post(body)
    assert.equal(r.status, status, `${label}: status`)
    assert.equal(r.json.code, code, `${label}: ${r.json.code} ${r.json.error ?? ''}`)
    assert.deepEqual(counts(), before, `${label}: nothing was written`)
  }
  assert.equal(handlerRuns, 0, 'the handler never ran for any refusal')
  await new Promise(r2 => setTimeout(r2, 20))
  assert.equal(afterCommitRuns, 0, 'and no non transactional effect fired')
})

test('PIPELINE: a payload swapped after signing is refused and writes nothing', async () => {
  const { body } = signedBody({ payload: { note: 'the real note' } })
  const before = counts()
  const r = await post({ ...body, payload: { note: 'swapped' } })
  assert.equal(r.status, 400)
  assert.equal(r.json.code, 'payload_digest_mismatch')
  assert.deepEqual(counts(), before)
})

test('PIPELINE: a WriteRefusal from the handler rolls back its own writes and the nonce', async () => {
  refuseNext = { status: 409, code: 'wrong_state', error: 'not awaiting a response' }
  const { body } = signedBody()
  const before = counts()
  const r = await post(body)
  assert.equal(r.status, 409)
  assert.equal(r.json.code, 'wrong_state')
  assert.equal(handlerRuns, 1, 'the handler did run, and then refused')
  assert.deepEqual(counts(), before, 'and took its own writes, the mode row and the nonce with it')
  await new Promise(r2 => setTimeout(r2, 20))
  assert.equal(afterCommitRuns, 0)
})

test('PIPELINE: the same nonce with a different write_ref is 409 replay_conflict', async () => {
  const shared = newNonce()
  // Two acts that BOTH pass envelope verification, so the 409 comes from the nonce
  // store rather than from an earlier shape refusal. Same nonce, different resource,
  // therefore a different write_ref.
  const first = signedBody({ nonce: shared, operation: 'express_interest' })
  const second = signedBody({ nonce: shared, operation: 'express_interest', resource: { type: 'intro', id: 'intro-pipe-other' } })
  assert.equal((await post(first.body)).status, 201)
  const runsBefore = handlerRuns
  const r = await post(second.body)
  assert.equal(r.status, 409)
  assert.equal(r.json.code, 'replay_conflict')
  assert.equal(handlerRuns, runsBefore, 'the body never ran')
})

// ── Anti-downgrade is recorded by a canonical write ───────────────────────

test('PIPELINE: a canonical write records the mode for the signer only, and makes a later legacy write a downgrade', async () => {
  const { body } = signedBody()
  assert.equal((await post(body)).status, 201)
  assert.equal(pipe.isDowngrade('intro', INTRO.id, actor.publicKey), true,
    'this actor has used canonical authorization on this resource')
  assert.equal(pipe.isDowngrade('intro', INTRO.id, generateKeyPair().publicKey), false,
    'and the counterparty is untouched, because a mode row is written only for the signer')
  assert.equal(pipe.DOWNGRADE_REFUSAL.status, 426)
  assert.equal(pipe.DOWNGRADE_REFUSAL.error, 'Update Mingle to continue this connection.')
  assert.equal(pipe.DOWNGRADE_REFUSAL.logReason, 'downgrade prevention')
})

// ── The opening reaches the handler verified ──────────────────────────────

test('PIPELINE: share_contact requires an opening that recomputes, and a tampered one is refused', async () => {
  const salt = 'Z'.repeat(43)
  const commitment = env.privateValueCommitment('share_contact', INTRO, salt, 'alice@example.com')
  const payload = { private_value_commitment: commitment }

  const missing = await post(signedBody({ operation: 'share_contact', payload }).body)
  assert.equal(missing.json.code, 'missing_opening')

  const tampered = await post(signedBody({ operation: 'share_contact', payload, opening: { value: 'attacker@evil.example', salt } }).body)
  assert.equal(tampered.status, 400)
  assert.equal(tampered.json.code, 'commitment_mismatch', 'the opening did not recompute to the commitment')
  assert.equal(handlerRuns, 0, 'and the handler never saw it')

  const good = await post(signedBody({ operation: 'share_contact', payload, opening: { value: 'alice@example.com', salt } }).body)
  assert.equal(good.status, 201)
  assert.equal(handlerRuns, 1)
})

// ── Rate limiting ─────────────────────────────────────────────────────────

test('PIPELINE: the rate limit action name collides with nothing already stored', async () => {
  await post(signedBody().body)
  const rows = db.getDb().prepare('SELECT DISTINCT action FROM rate_limits').all() as any[]
  const actions = rows.map(r => r.action)
  assert.ok(actions.includes(pipe.WRITE_RATE_ACTION))
  assert.equal(pipe.WRITE_RATE_ACTION, 'write_canonical')
  // The 33 stored names at 909ffe3 all carry a different prefix or shape.
  for (const existing of ['publish', 'search', 'intro', 'digest', 'v3_publish', 'v3_verb', 'intro_request',
    'intro_respond', 'intro_complete', 'intro_mine', 'fit_answer', 'fitv4_hs', 'notif_subscribe', 'page_card', 'v3_req']) {
    assert.notEqual(pipe.WRITE_RATE_ACTION, existing)
  }
})

test('PIPELINE: over the limit is 429 and writes nothing', async () => {
  const key = 'write:::ffff:127.0.0.1'
  // Fill the window directly rather than sending 120 requests.
  const d = db.getDb()
  const window = new Date(); window.setMinutes(0, 0, 0)
  for (const k of [key, 'write:127.0.0.1']) {
    d.prepare(`INSERT INTO rate_limits (public_key, action, window_start, count) VALUES (?, ?, ?, ?)
               ON CONFLICT(public_key, action, window_start) DO UPDATE SET count = ?`)
      .run(k, pipe.WRITE_RATE_ACTION, window.toISOString(), pipe.WRITE_RATE_LIMIT, pipe.WRITE_RATE_LIMIT)
  }
  const before = counts()
  const r = await post(signedBody().body)
  assert.equal(r.status, 429)
  assert.equal(r.json.code, 'rate_limited')
  assert.deepEqual(counts(), before, 'and the transport refusal touched no domain state')
  assert.equal(handlerRuns, 0)
})
