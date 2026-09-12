// Generate the shared canonical fixture file for mingle-write-v1.
// Inputs are written here, expected bytes and digests are computed, so the file
// is never hand-typed. 2C copies the result into mingle-mcp unchanged.
import { jcs, sha256Hex } from '../src/canonical-write.ts'
import { cardContentHash } from '../src/v3-cards.ts'

const accepted = [
  ['flat keys out of order', { b: 2, a: 1, C: 3, c: 4 }],
  ['keys differing only in case', { ZEBRA: 3, Zebra: 1, zEBRA: 4, zebra: 2 }],
  ['astral key sorts by UTF-16 code unit, below U+FFFF', { '\u{1f600}': 1, '￿': 2, z: 3 }],
  ['surrogate pair key against an empty key', { '': 1, '\u{10000}': 2 }],
  ['unicode keys, e-acute and fullwidth Z', { 'é': 1, Z: 2, 'Ｚ': 3, a: 4 }],
  ['integers including past 2^53', { a: 0, b: -1, c: 2147483647, d: 9007199254740991, e: 9007199254740993 }],
  ['decimals and exponents', { a: 0.1, b: 1e21, c: 1e-7, d: 5e-324, e: -0 }],
  ['string escapes, quote and backslash', { s: 'q"uote back\\slash' }],
  ['non BMP string', { s: 'hi \u{1f600} there' }],
  ['null inside an array is kept', { a: [1, null, 2] }],
  ['empty object and empty array', { o: {}, a: [] }],
  ['deep nesting', { a: { b: { c: { d: [1, { e: 'f' }] } } } }],
  ['mingle-write-v1 envelope', {
    domain: 'mingle-write-v1',
    operation: 'share_contact',
    actor_key: 'f5f1af69700ebdc38840ae0b11b968df3238388209157c0d219363a3fb17defc',
    resource: { type: 'intro', id: 'intro-v3-1789108307772-0d8f18e6' },
    issued_at: '2026-09-11T18:22:03.114Z',
    nonce: 'E4Y2tDdV0dXaITfBiro2Gw',
    payload_digest: '49a17bc1629ece6c71cf12a27500ef244e82df1d9b8b565fbe728d8cdd31f2be',
  }],
  ['mingle-payload-v1 payload', {
    domain: 'mingle-payload-v1',
    operation: 'request_intro',
    resource: { type: 'intro_request', id: '2e3235ae49f03d65216aca1a8f4c53ed' },
    payload: { from_card: 'v3-connection-1', to_card: 'v3-connection-2', purpose: 'collaborate', note: 'compare notes' },
  }],
  ['mingle-private-value-v1 commitment input', {
    domain: 'mingle-private-value-v1',
    operation: 'share_contact',
    resource: { type: 'intro', id: 'intro-v3-1789108307772-0d8f18e6' },
    salt: 'Yk9sQjNwVnhLMmRHN3FUc1ozTmZBaFd1RTVtQ3hSNHk',
    value: 'alice@example.com',
  }],
]

// Rejections. These are expected REFUSALS of assertCanonicalPayload, not bytes,
// because null anywhere in a canonical signed payload is refused before a
// signature is verified.
const rejected = [
  ['null member', { a: 1, b: null }, 'null_in_payload'],
  ['nested null member', { p: { contact: 'x', note: null } }, 'null_in_payload'],
  ['null in a deeper object', { a: { b: { c: null } } }, 'null_in_payload'],
  ['control character in a string', { a: 'x\u0000y' }, 'control_character'],
  ['DEL in a string', { a: 'x\u007fy' }, 'control_character'],
  ['leading whitespace', { a: ' x' }, 'edge_whitespace'],
  ['lone surrogate', { a: '\ud800' }, 'malformed_unicode'],
]

// Three refusals cannot live in this file, because the value itself is not
// representable in JSON and a round trip through the file would change what the
// case tests. They are asserted in code instead, in tests/canonical-write.test.ts.
// Named here so the omission is deliberate rather than an oversight, and so the
// 2C copy in mingle-mcp asserts the same three in its own code.
const notRepresentable = [
  { name: 'undefined member', code: 'null_in_payload', why: 'JSON.stringify drops the member, so the file would carry {a:1} which is a valid payload' },
  { name: 'NaN', code: 'non_finite_number', why: 'JSON.stringify emits null, so the file would carry {a:null} and the case would test null_in_payload instead' },
  { name: 'Date or class instance', code: 'unsupported_value', why: 'a Date serializes to a string and a Map to {}, so neither survives as the value under test' },
  // Two ACCEPTED cases whose most interesting input cannot survive the file either. Named here
  // after a review pointed out that the case names promise something the file cannot deliver:
  // 2C reads the file, sees the rounded value, and would think it had locked the edge case.
  { name: 'negative zero', expected: '0', why: 'JSON.stringify writes -0 as 0, so the file cannot carry the input. RFC 8785 requires -0 to serialize as "0", and 2C must assert jcs({e: -0}) === \'{"e":0}\' in its own code' },
  { name: 'an integer past 2^53', expected: '9007199254740992', why: 'a JS number literal of 9007199254740993 IS 9007199254740992, so no file can carry it. 2C must assert that the rounded value is what serializes, in its own code' },
]

const out = {
  note: 'Shared canonical fixtures for mingle-write-v1. RFC 8785 via canonicalize@5.0.0. Generated, never hand edited. 2C copies this file into mingle-mcp unchanged and asserts the same bytes there.',
  serializer: 'canonicalize@5.0.0',
  not_representable: notRepresentable,
  accepted: accepted.map(([name, input]) => ({
    name, input, canonical: jcs(input), digest: sha256Hex(jcs(input)),
  })),
  rejected: rejected.map(([name, input, code]) => ({ name, input, code })),
}

// JSON.stringify already escapes every code point below U+0020 inside a string,
// but it leaves DEL and the C1 range raw, so those would land in the file as
// literal bytes. Escape exactly that range and nothing else: widening it to the
// C0 range would also hit the newlines the pretty printer emits between members
// and produce a file that no longer parses.
const escaped = JSON.stringify(out, null, 2).replace(
  /[\u007f-\u009f]/g,
  c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'),
)
console.log(escaped)

// The card_hash regression lock, printed separately so the test can carry it.
const card = {
  card_type: 'connection', subject_key: 'aa'.repeat(32), headline: 'h',
  created_at: '2026-09-11T00:00:00.000Z', expires_at: '2026-10-02T00:00:00.000Z',
  signature: 'ignored', approval: { card_hash: 'ignored' }, revocation_status: 'active',
}
console.error('CARD_HASH_LOCK ' + cardContentHash(card))
