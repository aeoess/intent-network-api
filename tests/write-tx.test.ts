// ══════════════════════════════════════════════════════════════
// The nonce claim, the transaction boundary, and the evidence recorder
// ══════════════════════════════════════════════════════════════
// The four assertions that carry the weight:
//
//   same nonce, same write_ref  -> the stored result, one mutation
//   same nonce, different ref   -> 409 replay_conflict
//   a failure inside            -> no nonce row, no fact, no receipt
//   a legacy evidence row never lists a field its signature did not cover
//
// The cross-process race is driven at the database level with two connections,
// because inside one process better-sqlite3 is synchronous and nothing interleaves,
// so an HTTP-level test would prove nothing about it.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { generateKeyPair, sign } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-write-tx-test-'))
const DB_FILE = join(tmpDir, 'tx.db')
process.env.DB_PATH = DB_FILE
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey

const db = await import('../src/db.js')
const w = await import('../src/write-db.js')
const env = await import('../src/write-envelope.js')
const tx = await import('../src/write-tx.js')
const ev = await import('../src/write-evidence.js')
const { newNonce, jcs, sha256Hex } = await import('../src/canonical-write.js')

const actor = generateKeyPair()
const INTRO = { type: 'intro' as const, id: 'intro-tx-1' }

before(() => { db.getDb(); w.initWriteSchema() })
after(() => { db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })

function verified(over: { nonce?: string; payload?: any; operation?: any; resource?: any } = {}) {
  const operation = over.operation ?? 'express_interest'
  const payload = over.payload ?? {}
  const resource = over.resource ?? INTRO
  const built = env.buildEnvelope({
    operation, actorKey: actor.publicKey, resource,
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
    nonce: over.nonce ?? newNonce(), payload,
  })
  const signature = sign(built.envelopeBytes, actor.privateKey)
  const r = env.verifyWriteBody({ envelope: built.envelope, signature, payload })
  assert.equal(r.ok, true, r.ok ? '' : (r as any).error)
  return (r as any).write as import('../src/write-envelope.js').VerifiedWrite
}

// ── Idempotency ───────────────────────────────────────────────────────────

test('WRITE TX: a committed write stores its result and reports committed', () => {
  const v = verified()
  let ran = 0
  const out = tx.runCanonicalWrite(v, () => { ran++; return { id: 'r1' } })
  assert.equal(out.ok, true)
  assert.equal((out as any).kind, 'committed')
  assert.deepEqual((out as any).result, { id: 'r1' })
  assert.equal(ran, 1)
  const row = tx.nonceRow(v.envelope.actor_key, v.envelope.nonce)!
  assert.equal(row.status, 'committed')
  assert.deepEqual(JSON.parse(row.result_json!), { id: 'r1' })
})

test('WRITE TX: the same nonce with the same write_ref returns the stored result and runs the body once', () => {
  const v = verified()
  let ran = 0
  const first = tx.runCanonicalWrite(v, () => { ran++; return { id: 'only-once' } })
  const second = tx.runCanonicalWrite(v, () => { ran++; return { id: 'SHOULD NOT RUN' } })
  assert.equal((first as any).kind, 'committed')
  assert.equal((second as any).kind, 'idempotent')
  assert.deepEqual((second as any).result, { id: 'only-once' }, 'the stored answer, not a fresh one')
  assert.equal(ran, 1, 'one mutation for two identical requests')
})

test('WRITE TX: the same nonce with a different write_ref is 409 replay_conflict', () => {
  const shared = newNonce()
  const a = verified({ nonce: shared, operation: 'express_interest' })
  const b = verified({ nonce: shared, operation: 'decline' })
  assert.notEqual(a.writeRef, b.writeRef, 'two different acts')
  assert.equal((tx.runCanonicalWrite(a, () => ({ ok: 1 })) as any).kind, 'committed')
  let ran = 0
  const out = tx.runCanonicalWrite(b, () => { ran++; return { ok: 2 } })
  assert.equal(out.ok, false)
  assert.equal((out as any).status, 409)
  assert.equal((out as any).code, 'replay_conflict')
  assert.equal(ran, 0, 'the body never ran')
})

// ── The transaction boundary ──────────────────────────────────────────────

test('WRITE TX: a failure inside leaves no nonce reservation, no fact and no evidence', () => {
  const v = verified()
  const before = (db.getDb().prepare('SELECT COUNT(*) AS n FROM write_evidence').get() as any).n
  assert.throws(() => tx.runCanonicalWrite(v, () => {
    // A real write would do exactly this shape: facts, then evidence, then throw.
    db.getDb().prepare('INSERT INTO connection_authorizations (intro_id, actor_key, operation, subject, evidence_id, evidence) VALUES (?,?,?,?,?,?)')
      .run(INTRO.id, actor.publicKey, 'express_interest', '', 'ev-doomed', 'canonical')
    ev.recordCanonicalEvidence(v)
    throw new Error('injected failure after the facts were written')
  }), /injected failure/)

  assert.equal(tx.nonceRow(v.envelope.actor_key, v.envelope.nonce), null, 'no nonce reservation survived')
  assert.equal(db.getDb().prepare('SELECT 1 FROM connection_authorizations WHERE evidence_id = ?').get('ev-doomed'), undefined, 'no fact survived')
  assert.equal((db.getDb().prepare('SELECT COUNT(*) AS n FROM write_evidence').get() as any).n, before, 'no evidence survived')
})

test('WRITE TX: a rolled back nonce is usable again, so a refusal costs the caller nothing', () => {
  const v = verified()
  assert.throws(() => tx.runCanonicalWrite(v, () => { throw new Error('transient') }), /transient/)
  const retry = tx.runCanonicalWrite(v, () => ({ id: 'second-attempt-worked' }))
  assert.equal((retry as any).kind, 'committed', 'the same envelope is a first attempt again')
})

test('WRITE TX: a WriteRefusal from inside becomes a coded rejection and rolls everything back', () => {
  const v = verified()
  const out = tx.runCanonicalWrite(v, () => {
    db.getDb().prepare('INSERT INTO connection_authorizations (intro_id, actor_key, operation, subject, evidence_id, evidence) VALUES (?,?,?,?,?,?)')
      .run('intro-refused', actor.publicKey, 'express_interest', '', 'ev-refused', 'canonical')
    throw new tx.WriteRefusal(409, 'wrong_state', 'this introduction is not awaiting a response')
  })
  assert.equal(out.ok, false)
  assert.equal((out as any).status, 409)
  assert.equal((out as any).code, 'wrong_state')
  assert.equal(db.getDb().prepare('SELECT 1 FROM connection_authorizations WHERE evidence_id = ?').get('ev-refused'), undefined,
    'a refusal decided inside the transaction takes its own writes with it')
  assert.equal(tx.nonceRow(v.envelope.actor_key, v.envelope.nonce), null, 'and leaves the nonce usable')
})

// ── The cross process race, at the database level ─────────────────────────

test('WRITE TX: two connections claiming one nonce, exactly one wins', () => {
  // Inside one process nothing interleaves, so the race is only reachable with a
  // second connection to the same file. SQLite serializes the writes and the loser
  // hits the primary key, which is the property the design rests on.
  const v = verified()
  const other = new Database(DB_FILE)
  try {
    const claim = (conn: any) => {
      try {
        conn.prepare(`INSERT INTO write_nonces (actor_key, nonce, write_ref, operation, resource_type, resource_id, issued_at, status)
                      VALUES (?, ?, ?, ?, ?, ?, ?, 'committed')`)
          .run(v.envelope.actor_key, v.envelope.nonce, v.writeRef, v.envelope.operation,
            v.envelope.resource.type, v.envelope.resource.id, v.envelope.issued_at)
        return true
      } catch { return false }
    }
    const first = claim(db.getDb())
    const second = claim(other)
    assert.equal(first, true)
    assert.equal(second, false, 'the second connection is refused by the primary key, not by a read')
    const n = (db.getDb().prepare('SELECT COUNT(*) AS n FROM write_nonces WHERE nonce = ?').get(v.envelope.nonce) as any).n
    assert.equal(n, 1, 'exactly one row exists')
  } finally {
    other.close()
  }
})

// ── Retention arithmetic ──────────────────────────────────────────────────

test('WRITE TX: 24 hour retention against a 10 minute window leaves no replayable gap', () => {
  // An envelope is acceptable only inside a 12 minute band around issued_at, from
  // 2 minutes early to 10 minutes late. The record is kept at least 24 hours from
  // first_seen_at, which falls inside that band. So the earliest a record can be
  // purged is about 23 hours 48 minutes after the envelope stopped being fresh.
  // There is no instant at which an envelope is both fresh and un-remembered.
  const issued = new Date('2026-09-12T00:00:00.000Z')
  const freshUntil = issued.getTime() + env.FRESHNESS_PAST_MS
  const earliestPurge = issued.getTime() - env.FRESHNESS_FUTURE_MS + 24 * 3600 * 1000
  assert.ok(earliestPurge > freshUntil, 'the record outlives the freshness window')
  assert.equal(Math.round((earliestPurge - freshUntil) / 60000), 24 * 60 - 12, 'by 23 hours and 48 minutes')

  // And a purged nonce is not replayable, because freshness refuses it first.
  const stale = env.buildEnvelope({
    operation: 'decline', actorKey: actor.publicKey, resource: INTRO,
    issuedAt: '2026-09-12T00:00:00.000Z', nonce: newNonce(), payload: {},
  })
  const check = env.checkFreshness(stale.envelope, new Date('2026-09-13T00:00:00.000Z'))
  assert.equal(check!.code, 'stale_authorization', 'stale by a day, refused before uniqueness is consulted')
})

// ── The evidence recorder ─────────────────────────────────────────────────

test('EVIDENCE: a canonical row stores the exact signed bytes and re-derives its write_ref', () => {
  const v = verified({ operation: 'request_intro', resource: { type: 'intro_request', id: 'req-ev-1' }, payload: { from_card: 'c1', to_card: 'c2', purpose: 'collaborate', note: 'hi' } })
  const id = ev.recordCanonicalEvidence(v)
  const row = ev.evidenceById(id)!
  assert.equal(row.evidence, 'canonical')
  assert.equal(row.write_ref, v.writeRef)
  // The stored bytes are the bytes that were signed, so a reader re-derives rather
  // than trusts.
  assert.equal(row.envelope_json, v.envelopeBytes)
  assert.equal(sha256Hex(row.envelope_json!), row.write_ref)
})

test('EVIDENCE: the canonical bound field list matches the payload schema, field by field', () => {
  assert.deepEqual(ev.boundFieldsFor('request_intro', 'canonical'),
    ['operation', 'resource.id', 'payload.from_card', 'payload.to_card', 'payload.purpose', 'payload.note'])
  assert.deepEqual(ev.boundFieldsFor('share_contact', 'canonical'),
    ['operation', 'resource.id', 'payload.private_value_commitment'])
  assert.deepEqual(ev.boundFieldsFor('first_step_approve', 'canonical'),
    ['operation', 'resource.id', 'payload.approved_digest'])
  assert.deepEqual(ev.boundFieldsFor('withdraw_contact', 'canonical'), ['operation', 'resource.id'])
})

test('EVIDENCE: a legacy row never lists a field its signature did not cover', () => {
  // The single assertion that stops the worst overclaim. A 3.2.2 accept signs
  // intro-respond:${id}:${action}:${nonce} and attaches the contact separately, so
  // no receipt built from that row can name the contact.
  const id = ev.recordLegacyEvidence({
    actorKey: actor.publicKey, operation: 'express_interest',
    resourceType: 'intro', resourceId: 'intro-legacy-1', signature: 'legacy-sig',
  })
  const row = ev.evidenceById(id)!
  assert.equal(row.evidence, 'legacy_unbound')
  assert.equal(row.write_ref, null, 'there is no envelope, so there is no write_ref')
  assert.deepEqual(ev.boundFieldsOf(row), ['id', 'action'])
  assert.equal(ev.covers(row, 'payload.contact'), false)
  assert.equal(ev.covers(row, 'contact'), false)
  assert.equal(row.legacy_preimage, 'intro-respond:${id}:${action}:${nonce}',
    'the preimage is recorded verbatim so a reader sees what was signed')
})

test('EVIDENCE: no legacy bound list names a contact, a dimension list or a plan field', () => {
  const forbidden = ['contact', 'payload.contact', 'requested_dimensions', 'accept_dimensions', 'half', 'note', 'questions', 'question_ids', 'dimension_ids']
  for (const op of ['request_intro', 'express_interest', 'decline', 'share_contact', 'fit_request', 'fit_commit', 'first_step_propose'] as const) {
    const bound = ev.boundFieldsFor(op, 'legacy_unbound')
    for (const f of forbidden) {
      assert.equal(bound.includes(f), false, `legacy ${op} must not claim ${f}`)
    }
  }
})

test('EVIDENCE: release_exact legacy binds the dimension but never the value', () => {
  // The one legacy fit preimage that binds more than the intro id, and it still
  // omits the value and the policy it was read from.
  const bound = ev.boundFieldsFor('release_exact', 'legacy_unbound')
  assert.deepEqual(bound, ['intro_id', 'dimension'])
  assert.equal(bound.includes('payload.private_value_commitment'), false)
})

test('EVIDENCE: covers() fails closed on an unparseable list', () => {
  const id = ev.recordLegacyEvidence({ actorKey: 'k', operation: 'decline', resourceType: 'intro', resourceId: 'intro-bad-json', signature: 's' })
  db.getDb().prepare('UPDATE write_evidence SET bound_fields_json = ? WHERE evidence_id = ?').run('not json', id)
  const row = ev.evidenceById(id)!
  assert.deepEqual(ev.boundFieldsOf(row), [])
  assert.equal(ev.covers(row, 'id'), false, 'a damaged list covers nothing')
})

test('EVIDENCE: the partial unique index allows many legacy rows and one row per write_ref', () => {
  for (let i = 0; i < 3; i++) {
    ev.recordLegacyEvidence({ actorKey: 'kL', operation: 'decline', resourceType: 'intro', resourceId: `intro-many-${i}`, signature: 's' })
  }
  const v = verified()
  ev.recordCanonicalEvidence(v)
  assert.throws(() => ev.recordCanonicalEvidence(v), /UNIQUE|constraint/i, 'one evidence row per canonical write_ref')
})
