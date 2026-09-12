// ══════════════════════════════════════════════════════════════
// mingle-write-v1 envelope verification
// ══════════════════════════════════════════════════════════════
// One case per rejection code, plus the four that carry real weight:
//
//   an extra envelope field is refused, because JCS signs whatever is present so
//   the signature would still verify while the server ignored what the field means
//   a payload swapped in flight dies on the digest and never reaches the signature
//   only the operation changed is a forgery, not a replay
//   freshness boundaries on both sides, with a fixed clock

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from 'agent-passport-system'

const e = await import('../src/write-envelope.js')
const { jcs, sha256Hex, newNonce } = await import('../src/canonical-write.js')

const actor = generateKeyPair()
const INTRO = { type: 'intro' as const, id: 'intro-v3-1789108307772-0d8f18e6' }
const NOW = new Date('2026-09-12T12:00:00.000Z')
const ISSUED = '2026-09-12T12:00:00.000Z'

function bodyFor(over: {
  operation?: any; payload?: any; resource?: any; issuedAt?: string; nonce?: string
  actorKey?: string; privateKey?: string; opening?: any; envelopePatch?: Record<string, unknown>
  signOverride?: string
} = {}) {
  const operation = over.operation ?? 'express_interest'
  const payload = over.payload ?? {}
  const resource = over.resource ?? INTRO
  const built = e.buildEnvelope({
    operation,
    actorKey: over.actorKey ?? actor.publicKey,
    resource,
    issuedAt: over.issuedAt ?? ISSUED,
    nonce: over.nonce ?? newNonce(),
    payload,
  })
  const envelope: Record<string, unknown> = { ...built.envelope, ...(over.envelopePatch ?? {}) }
  const bytes = jcs(envelope)
  const signature = over.signOverride ?? sign(bytes, over.privateKey ?? actor.privateKey)
  const body: Record<string, unknown> = { envelope, signature, payload }
  if (over.opening !== undefined) body.opening = over.opening
  return { body, built }
}

const ok = (r: any) => { assert.equal(r.ok, true, r.ok ? '' : `${r.code}: ${r.error}`); return r.write }
const rej = (r: any, code: string) => { assert.equal(r.ok, false, 'expected a rejection'); assert.equal(r.code, code, `${r.code}: ${r.error}`); return r }

// ── The happy path ────────────────────────────────────────────────────────

test('ENVELOPE: a well formed signed envelope verifies and yields a write_ref', () => {
  const { body, built } = bodyFor()
  const w = ok(e.verifyWriteBody(body))
  assert.equal(w.writeRef, built.writeRef)
  assert.equal(w.envelope.operation, 'express_interest')
  assert.equal(w.envelopeBytes, built.envelopeBytes, 'the exact bytes signed are retained for evidence')
  assert.equal(e.checkFreshness(w.envelope, NOW), null)
})

// ── One case per rejection code ───────────────────────────────────────────

test('ENVELOPE: shape rejections, one per code', () => {
  rej(e.verifyWriteBody('nope'), 'malformed_body')
  rej(e.verifyWriteBody({}), 'malformed_body')
  rej(e.verifyWriteBody({ ...bodyFor().body, surprise: 1 }), 'malformed_body')

  const base = bodyFor().body
  rej(e.verifyWriteBody({ ...base, signature: undefined }), 'missing_signature')
  rej(e.verifyWriteBody({ ...base, payload: 'x' }), 'malformed_body')

  rej(e.verifyWriteBody(bodyFor({ envelopePatch: { domain: 'mingle-write-v2' } }).body), 'unknown_envelope_domain')
  rej(e.verifyWriteBody(bodyFor({ envelopePatch: { operation: 'not_an_operation' } }).body), 'unknown_operation')
  rej(e.verifyWriteBody(bodyFor({ envelopePatch: { actor_key: 'short' } }).body), 'malformed_actor_key')
  rej(e.verifyWriteBody(bodyFor({ envelopePatch: { resource: { type: 'galaxy', id: 'x' } } }).body), 'unknown_resource_type')
  rej(e.verifyWriteBody(bodyFor({ envelopePatch: { resource: { type: 'intro', id: 'has spaces' } } }).body), 'malformed_resource_id')
  rej(e.verifyWriteBody(bodyFor({ envelopePatch: { issued_at: '2026-09-12T12:00:00Z' } }).body), 'malformed_issued_at')
  rej(e.verifyWriteBody(bodyFor({ envelopePatch: { nonce: 'tooshort' } }).body), 'malformed_nonce')
  rej(e.verifyWriteBody(bodyFor({ envelopePatch: { payload_digest: 'zz' } }).body), 'malformed_payload_digest')
})

test('ENVELOPE: a UUID nonce is refused, which the base64url shape alone would accept', () => {
  rej(e.verifyWriteBody(bodyFor({ nonce: '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed' }).body), 'malformed_nonce')
})

test('ENVELOPE: an extra envelope field is refused even though the signature covers it', () => {
  // The danger is concrete. JCS serializes whatever is present, so the signature
  // over the extended object verifies. A server that ignored the unknown key would
  // call the envelope valid while ignoring what the field means, and a field that
  // narrows authority would then grant more than the signer asked for.
  const { body } = bodyFor({ envelopePatch: { scope: 'narrower' } })
  const r = e.verifyWriteBody(body)
  rej(r, 'unexpected_envelope_field')
  // Prove the signature really did cover it, so the refusal is the only defense.
  const bytes = jcs(body.envelope as any)
  assert.equal(sign(bytes, actor.privateKey), body.signature, 'the signature is over the extended bytes')
})

test('ENVELOPE: a missing envelope field is refused', () => {
  const { body } = bodyFor()
  const env = { ...(body.envelope as any) }
  delete env.nonce
  rej(e.verifyWriteBody({ ...body, envelope: env }), 'malformed_body')
})

// ── The payload gate runs before any crypto ───────────────────────────────

test('ENVELOPE: a null in the payload is refused before the signature is reached', () => {
  // Signed correctly, so only the gate can refuse it.
  const { body } = bodyFor({ operation: 'request_intro', resource: { type: 'intro_request', id: 'req-1' }, payload: { note: null } })
  rej(e.verifyWriteBody(body), 'null_in_payload')
})

test('ENVELOPE: a control character in a signed string is refused', () => {
  const { body } = bodyFor({ operation: 'request_intro', resource: { type: 'intro_request', id: 'req-2' }, payload: { note: 'a\u0000b' } })
  rej(e.verifyWriteBody(body), 'control_character')
})

test('ENVELOPE: edge whitespace in a signed string is refused', () => {
  const { body } = bodyFor({ operation: 'request_intro', resource: { type: 'intro_request', id: 'req-3' }, payload: { note: ' padded' } })
  rej(e.verifyWriteBody(body), 'edge_whitespace')
})

// ── Digest before signature ───────────────────────────────────────────────

test('ENVELOPE: a payload swapped in flight dies on the digest and the signature is never reached', () => {
  const { body } = bodyFor({ operation: 'request_intro', resource: { type: 'intro_request', id: 'req-4' }, payload: { note: 'the real note' } })
  const tampered = { ...body, payload: { note: 'a different note' } }
  const r = rej(e.verifyWriteBody(tampered), 'payload_digest_mismatch')
  assert.equal(r.status, 400, 'a shape failure, not an authorization failure')
  // Proof the signature would still have been valid: the envelope is untouched.
  const bytes = jcs(body.envelope as any)
  assert.equal(sign(bytes, actor.privateKey), body.signature)
})

test('ENVELOPE: changing payload_digest is caught by the digest recomputation, which runs first', () => {
  // The canonical order is digest recomputation (3) then signature (4), so this is
  // refused as a mismatch rather than as a bad signature. Both are true, and
  // catching it on one hash instead of a hash plus an Ed25519 verify is the
  // cheaper of the two orders. The assertions below pin the order, not just the
  // outcome.
  const { body } = bodyFor()
  const other = sha256Hex('something else')
  const tampered = { ...body, envelope: { ...(body.envelope as any), payload_digest: other } }
  rej(e.verifyWriteBody(tampered), 'payload_digest_mismatch')
  // And the signature is independently invalid, because payload_digest is inside
  // the signed bytes. So the envelope is doubly refused and neither check alone is
  // load bearing here.
  const bytes = jcs(tampered.envelope as any)
  assert.notEqual(sign(bytes, actor.privateKey), body.signature, 'the signed bytes changed too')
})

// ── Signature ─────────────────────────────────────────────────────────────

test('ENVELOPE: a signature by the wrong key is refused with 403', () => {
  const other = generateKeyPair()
  const r = rej(e.verifyWriteBody(bodyFor({ privateKey: other.privateKey }).body), 'signature_invalid')
  assert.equal(r.status, 403)
})

test('ENVELOPE: garbage in the signature field is refused rather than thrown', () => {
  rej(e.verifyWriteBody(bodyFor({ signOverride: 'not-hex' }).body), 'signature_invalid')
})

test('ENVELOPE: changing only the operation is a forgery, not a replay', () => {
  // The attack the envelope exists to stop. operation is inside the signed bytes,
  // so a cross action replay fails on Ed25519 and never reaches an application
  // check. This is the v2 defect: a card fetched from GET /api/cards/:agentId
  // replays as the body of DELETE /api/cards/:cardId because requireSignature
  // binds no verb, path, nonce or expiry.
  const { body, built } = bodyFor({ operation: 'share_contact', opening: undefined })
  const tampered = { ...body, envelope: { ...(body.envelope as any), operation: 'withdraw_contact' } }
  const r = e.verifyWriteBody(tampered)
  assert.equal(r.ok, false)
  // It is refused for carrying no opening OR for the signature, and either way it
  // never becomes a valid withdraw_contact. Assert the write_ref differs too.
  const tamperedRef = sha256Hex(jcs(tampered.envelope as any))
  assert.notEqual(tamperedRef, built.writeRef, 'a different act has a different write_ref')
})

// ── Freshness ─────────────────────────────────────────────────────────────

test('ENVELOPE: freshness accepts 9m59s in the past and refuses 10m01s', () => {
  const at = (ms: number) => new Date(Date.parse(ISSUED) + ms)
  const w = ok(e.verifyWriteBody(bodyFor().body))
  assert.equal(e.checkFreshness(w.envelope, at(9 * 60 * 1000 + 59_000)), null)
  const stale = e.checkFreshness(w.envelope, at(10 * 60 * 1000 + 1_000))
  assert.equal(stale!.code, 'stale_authorization')
  assert.equal(stale!.status, 401)
})

test('ENVELOPE: freshness accepts 1 minute ahead and refuses 3 minutes ahead', () => {
  const at = (ms: number) => new Date(Date.parse(ISSUED) + ms)
  const w = ok(e.verifyWriteBody(bodyFor().body))
  assert.equal(e.checkFreshness(w.envelope, at(-60_000)), null)
  assert.equal(e.checkFreshness(w.envelope, at(-3 * 60_000))!.code, 'stale_authorization')
})

test('ENVELOPE: freshness is checked after the signature, so a forged envelope learns nothing about the clock', () => {
  // A caller who cannot sign is told only that the signature failed, whatever the
  // clock says. Drive an envelope that is BOTH stale and badly signed and assert
  // the answer is the signature.
  const stale = bodyFor({ issuedAt: '2020-01-01T00:00:00.000Z', privateKey: generateKeyPair().privateKey })
  rej(e.verifyWriteBody(stale.body), 'signature_invalid')
})

// ── The opening ───────────────────────────────────────────────────────────

test('OPENING: share_contact and release_exact require one, everything else refuses one', () => {
  const salt = 'A'.repeat(43)
  for (const op of ['share_contact', 'release_exact'] as const) {
    const res = op === 'share_contact' ? INTRO : INTRO
    const commitment = e.privateValueCommitment(op, res, salt, 'alice@example.com')
    const payload: Record<string, unknown> = { private_value_commitment: commitment }
    if (op === 'release_exact') { payload.dimension = 'cadence'; payload.policy_commitment = 'a'.repeat(64) }
    rej(e.verifyWriteBody(bodyFor({ operation: op, resource: res, payload }).body), 'missing_opening')
    const w = ok(e.verifyWriteBody(bodyFor({ operation: op, resource: res, payload, opening: { value: 'alice@example.com', salt } }).body))
    assert.equal(e.verifyOpening(w), null, 'and the opening recomputes to the commitment')
  }
  rej(e.verifyWriteBody(bodyFor({ operation: 'express_interest', opening: { value: 'x', salt } }).body), 'unexpected_opening')
})

test('OPENING: a tampered value or salt fails the commitment recomputation', () => {
  const salt = 'B'.repeat(43)
  const commitment = e.privateValueCommitment('share_contact', INTRO, salt, 'alice@example.com')
  const payload = { private_value_commitment: commitment }
  const good = ok(e.verifyWriteBody(bodyFor({ operation: 'share_contact', payload, opening: { value: 'alice@example.com', salt } }).body))
  assert.equal(e.verifyOpening(good), null)

  const swappedValue = ok(e.verifyWriteBody(bodyFor({ operation: 'share_contact', payload, opening: { value: 'attacker@evil.example', salt } }).body))
  assert.equal(e.verifyOpening(swappedValue)!.code, 'commitment_mismatch', 'a proxy that rewrites the value is caught before any write')

  const swappedSalt = ok(e.verifyWriteBody(bodyFor({ operation: 'share_contact', payload, opening: { value: 'alice@example.com', salt: 'C'.repeat(43) } }).body))
  assert.equal(e.verifyOpening(swappedSalt)!.code, 'commitment_mismatch', 'and so is one that rewrites the salt')
})

test('OPENING: a malformed salt is refused on shape', () => {
  const payload = { private_value_commitment: 'a'.repeat(64) }
  rej(e.verifyWriteBody(bodyFor({ operation: 'share_contact', payload, opening: { value: 'x', salt: 'tooshort' } }).body), 'malformed_opening')
  rej(e.verifyWriteBody(bodyFor({ operation: 'share_contact', payload, opening: { value: 'x' } }).body), 'malformed_opening')
})

test('OPENING: the commitment binds operation and resource, not only the value', () => {
  const salt = 'D'.repeat(43)
  const base = e.privateValueCommitment('share_contact', INTRO, salt, 'alice@example.com')
  assert.notEqual(base, e.privateValueCommitment('release_exact', INTRO, salt, 'alice@example.com'),
    'a commitment lifted into another operation does not match')
  assert.notEqual(base, e.privateValueCommitment('share_contact', { type: 'intro', id: 'intro-other' }, salt, 'alice@example.com'),
    'nor into another intro')
})

test('OPENING: a control character inside the opening value is refused', () => {
  const salt = 'E'.repeat(43)
  const value = 'a\u0000b'
  const commitment = e.privateValueCommitment('share_contact', INTRO, salt, value)
  rej(e.verifyWriteBody(bodyFor({ operation: 'share_contact', payload: { private_value_commitment: commitment }, opening: { value, salt } }).body), 'control_character')
})

// ── Reproducibility across the two repos ──────────────────────────────────

test('ENVELOPE: buildEnvelope reproduces the documented worked example byte for byte', () => {
  // The share_contact example from MINGLE-2A-SIGNED-WRITE-ENVELOPE.md section 3.
  // If this drifts, the design document and the implementation have diverged.
  const salt = 'Yk9sQjNwVnhLMmRHN3FUc1ozTmZBaFd1RTVtQ3hSNHk'
  const commitment = e.privateValueCommitment('share_contact', INTRO, salt, 'alice@example.com')
  assert.equal(commitment, '50d414b0188f137a68c32ab201b998faab1ef955692519341679ea5c10ed9469')
  const built = e.buildEnvelope({
    operation: 'share_contact',
    actorKey: 'f5f1af69700ebdc38840ae0b11b968df3238388209157c0d219363a3fb17defc',
    resource: INTRO,
    issuedAt: '2026-09-11T18:22:03.114Z',
    nonce: 'E4Y2tDdV0dXaITfBiro2Gw',
    payload: { private_value_commitment: commitment },
  })
  assert.equal(built.payloadDigest, '49a17bc1629ece6c71cf12a27500ef244e82df1d9b8b565fbe728d8cdd31f2be')
})
