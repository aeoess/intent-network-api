// ══════════════════════════════════════════════════════════════
// mingle-write-v1 canonical serialization (RFC 8785) and the payload gate
// ══════════════════════════════════════════════════════════════
// Two things are under test and they are never used apart.
//
// 1. jcs() is RFC 8785. The APS `canonicalize` is NOT: it deletes object
//    members whose value is null, so {a:1,b:null} and {a:1} produce identical
//    bytes and therefore the same signature. Every existing preimage keeps the
//    APS function (card_hash, approved_hash, sharedDigest) and nothing here
//    touches them.
// 2. assertCanonicalPayload() refuses anything a canonical signed payload may
//    not contain, before a signature is ever verified. Null is the case that
//    matters, because a JCS library serializes it happily and {note:null}
//    versus {} would then be two signable payloads meaning one thing.
//
// The shared fixture file is the contract with mingle-mcp. 2C copies it across
// and asserts the same bytes there. A disagreement between the two repos has to
// surface as a fixture diff, not as a signature failure three layers away.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'

const here = dirname(fileURLToPath(import.meta.url))

const { jcs, sha256Hex, assertCanonicalPayload, CanonicalPayloadError, newNonce, NONCE_RE, isValidNonce } =
  await import('../src/canonical-write.js')

interface Fixture {
  name: string
  input: unknown
  canonical: string
  digest: string
}
interface Rejection {
  name: string
  input: unknown
  code: string
}
const fixtures = JSON.parse(
  readFileSync(join(here, '..', 'fixtures', 'mingle-write-v1-canonical.json'), 'utf8'),
) as { accepted: Fixture[]; rejected: Rejection[] }

// ── The shared fixture file ───────────────────────────────────────────────

test('CANONICAL: every accepted fixture produces its recorded bytes and digest', () => {
  assert.ok(fixtures.accepted.length >= 12, 'the fixture file must carry a real corpus')
  for (const f of fixtures.accepted) {
    assert.equal(jcs(f.input), f.canonical, `bytes for ${f.name}`)
    assert.equal(sha256Hex(jcs(f.input)), f.digest, `digest for ${f.name}`)
  }
})

test('CANONICAL: every rejected fixture is refused with its recorded code', () => {
  assert.ok(fixtures.rejected.length >= 6, 'the rejection corpus must be real too')
  for (const f of fixtures.rejected) {
    assert.throws(
      () => assertCanonicalPayload(f.input),
      (e: unknown) => e instanceof CanonicalPayloadError && (e as any).code === f.code,
      `${f.name} must be refused as ${f.code}`,
    )
  }
})

test('CANONICAL: the fixture file names the astral key-order case and the null cases', () => {
  const names = fixtures.accepted.map(f => f.name).concat(fixtures.rejected.map(f => f.name))
  assert.ok(names.some(n => n.includes('astral')), 'astral key ordering case present')
  assert.ok(fixtures.rejected.some(f => f.code === 'null_in_payload'), 'null rejection present')
})

// ── RFC 8785 behavior ─────────────────────────────────────────────────────

test('CANONICAL: keys sort by UTF-16 code unit, including an astral key', () => {
  // '\u{1f600}' is a surrogate pair, so its first code unit (0xd83d) sorts
  // BELOW U+FFFF. A code-point sort would put it after. This is the case that
  // separates a real JCS implementation from a plausible one.
  const out = jcs({ '￿': 1, '\u{1f600}': 2, z: 3 })
  assert.equal(out, '{"z":3,"\u{1f600}":2,"￿":1}')
})

test('CANONICAL: numbers use ES6 number-to-string', () => {
  assert.equal(jcs({ a: 1e21, b: 1e-7, c: -0, d: 5e-324, e: 0.1 }),
    '{"a":1e+21,"b":1e-7,"c":0,"d":5e-324,"e":0.1}')
})

test('CANONICAL: null inside an array is serialized, unlike the APS canonicalizer', async () => {
  const aps = (await import('agent-passport-system')).canonicalize
  assert.equal(jcs({ a: [1, null, 2] }), '{"a":[1,null,2]}')
  // The divergence that disqualifies the APS function for this envelope.
  assert.equal(aps({ a: 1, b: null }), aps({ a: 1 }), 'APS collapses a null member')
  assert.notEqual(jcs({ a: 1, b: null }), jcs({ a: 1 }), 'JCS keeps it distinct')
})

test('CANONICAL: key order in the source object is irrelevant', () => {
  assert.equal(jcs({ b: 2, a: 1 }), jcs({ a: 1, b: 2 }))
})

// ── The payload gate ──────────────────────────────────────────────────────

test('PAYLOAD GATE: null and undefined are refused at any depth', () => {
  for (const bad of [
    { a: null },
    { a: { b: null } },
    { a: [{ b: null }] },
    { a: undefined },
  ]) {
    assert.throws(() => assertCanonicalPayload(bad), { code: 'null_in_payload' })
  }
})

test('PAYLOAD GATE: non finite numbers, Date and class instances are refused', () => {
  assert.throws(() => assertCanonicalPayload({ a: NaN }), { code: 'non_finite_number' })
  assert.throws(() => assertCanonicalPayload({ a: Infinity }), { code: 'non_finite_number' })
  assert.throws(() => assertCanonicalPayload({ a: new Date() }), { code: 'unsupported_value' })
  assert.throws(() => assertCanonicalPayload({ a: new Map() }), { code: 'unsupported_value' })
})

test('PAYLOAD GATE: control characters and edge whitespace in strings are refused', () => {
  assert.throws(() => assertCanonicalPayload({ a: 'x\u0000y' }), { code: 'control_character' })
  assert.throws(() => assertCanonicalPayload({ a: 'x\u001fy' }), { code: 'control_character' })
  assert.throws(() => assertCanonicalPayload({ a: 'x\u007fy' }), { code: 'control_character' })
  assert.throws(() => assertCanonicalPayload({ a: 'x\ty' }), { code: 'control_character' })
  assert.throws(() => assertCanonicalPayload({ a: ' x' }), { code: 'edge_whitespace' })
  assert.throws(() => assertCanonicalPayload({ a: 'x ' }), { code: 'edge_whitespace' })
})

test('PAYLOAD GATE: a lone surrogate is refused', () => {
  assert.throws(() => assertCanonicalPayload({ a: '\ud800' }), { code: 'malformed_unicode' })
})

test('PAYLOAD GATE: an ordinary payload passes and is returned unchanged', () => {
  const p = { from_card: 'v3-c-1', to_card: 'v3-c-2', purpose: 'collaborate', note: 'hello there' }
  assert.equal(assertCanonicalPayload(p), p, 'the gate never repairs, it returns the same object')
})

test('PAYLOAD GATE: an empty object and nested empties pass', () => {
  assertCanonicalPayload({})
  assertCanonicalPayload({ a: {}, b: [] })
})

// ── Nonces ────────────────────────────────────────────────────────────────

test('NONCE: 16 bytes from randomBytes, base64url, never a UUID', () => {
  const n = newNonce()
  assert.match(n, NONCE_RE)
  assert.equal(n.length, 22, '16 bytes unpadded base64url is 22 characters')
  assert.equal(/^[0-9a-f]{8}-/.test(n), false, 'not a UUID')
  const many = new Set(Array.from({ length: 500 }, () => newNonce()))
  assert.equal(many.size, 500, 'no collisions across 500 draws')
})

test('NONCE: the shape gate accepts 16 to 32 bytes and refuses anything shorter', () => {
  assert.equal(isValidNonce('A'.repeat(22)), true, '16 bytes passes')
  assert.equal(isValidNonce('A'.repeat(43)), true, '32 bytes passes')
  assert.equal(isValidNonce('A'.repeat(21)), false, '15 bytes is refused')
  assert.equal(isValidNonce('A'.repeat(44)), false, 'past 32 bytes is refused')
  assert.equal(isValidNonce('A'.repeat(21) + '+'), false, 'base64 padding alphabet is refused')
  assert.equal(isValidNonce(12), false, 'a non string is refused')
})

test('NONCE: a UUID is refused even though it matches the base64url shape', () => {
  const uuid = '1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed'
  // The trap this guards: a UUID is 36 characters drawn entirely from the
  // base64url alphabet, so a length-and-charset check alone lets one through.
  assert.match(uuid, NONCE_RE)
  assert.equal(isValidNonce(uuid), false, 'the UUID exclusion catches what the shape does not')
  assert.equal(isValidNonce(randomUUID()), false, 'including a real one')
})

// ── The legacy canonicalizer is untouched ─────────────────────────────────

test('CANONICAL: card_hash still uses the APS canonicalization, byte for byte', async () => {
  const { cardContentHash } = await import('../src/v3-cards.js')
  // A fixed card, so this value is a regression lock. If someone swaps the
  // canonicalizer repo wide, this is the test that catches it.
  const card = {
    card_type: 'connection', subject_key: 'aa'.repeat(32), headline: 'h',
    created_at: '2026-09-11T00:00:00.000Z', expires_at: '2026-10-02T00:00:00.000Z',
    signature: 'ignored', approval: { card_hash: 'ignored' }, revocation_status: 'active',
  }
  assert.equal(cardContentHash(card as any),
    'a1175de8324c377dd197e8f326a8a1a378a567bf739977fd45572883f78fec9a')
})
