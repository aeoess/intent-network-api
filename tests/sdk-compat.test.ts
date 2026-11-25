// Known-answer vectors produced by agent-passport-system 1.13.0, the version this
// API ran before the move to 8.x. Each test checks that the installed SDK still
// reproduces or accepts exactly those bytes, so a card, a v3 preimage or a
// receipt written under 1.13 keeps verifying, and a new one is the same bytes a
// 1.x client or verifier would produce.
//
// The keys are derived from fixed public strings. They are test vectors, not
// secrets, and no deployment uses them.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { sign, verify, canonicalize, publicKeyFromPrivate } from 'agent-passport-system'
import { verifyIntentCard, isCardExpired } from '../src/intent-card.js'
import { verifyReceiptWith, deriveIssuerKeyId } from '../src/server-key.js'

const seed = (s: string) => createHash('sha256').update(s).digest('hex')
const AGENT_PRIV = seed('intent-network-api 1.13 vector agent key')
const SERVER_PRIV = seed('intent-network-api 1.13 vector receipt key')
const AGENT_PUB = 'b017b7bbd95bc35bf1fb88c740ccbfb1f835b101721fc6d07b963fa777b2e6df'
const SERVER_PUB = 'e94923b36561e5c639a8933c25381d8c553ada1529610070895ae6759f41f49b'

// Signed by 1.13.0 sign over 1.13.0 canonicalize, with fixed timestamps and cardId.
// verifyIntentCard in 1.13.0 returned true for this card.
const CARD_113 = {
  cardId: 'card_0f3c2a9b-1d4',
  agentId: 'vector-agent',
  principalAlias: 'Vector',
  publicKey: AGENT_PUB,
  needs: [{ category: 'engineering', description: 'review a signing change', priority: 'high', tags: ['ed25519', 'review'], visibility: 'public' }],
  offers: [{ category: 'research', description: 'notes on canonical JSON', priority: 'low', tags: ['json'], visibility: 'on-match', budget: { amount: 0, currency: 'USD' } }],
  openTo: [],
  notOpenTo: [],
  approvalRequired: ['disclose-budget', 'share-contact'],
  autonomy: 'propose-intros',
  ttlSeconds: 86400,
  createdAt: '2026-11-24T12:00:00.000Z',
  expiresAt: '2026-11-25T12:00:00.000Z',
  signature: 'e20a69cd30498c5f912f7cb9f8ee13661d45f5f150d7eb58566b8269cf11c2a280fb2302e7bd801330634b56efbf21465d73cc52befd67e7d4c887a28e853f00',
} as any

const V3_INPUT = { subject_key: AGENT_PUB, note: null, items: ['a', null, 'b'], nested: { z: 1, a: 'é' } }
const V3_CANONICAL_113 = '{"items":["a",null,"b"],"nested":{"a":"é","z":1},"subject_key":"b017b7bbd95bc35bf1fb88c740ccbfb1f835b101721fc6d07b963fa777b2e6df"}'
const DIGEST_113 = '2bfe3dba929b56b182c3407535b8d95a41ae3fb455c8ec003b18130111fe515e'
const RECEIPT_SIG_113 = '174cac1f840dc425283ff4a51827d7239806d23fbeb26ea1735bf169f6d2eeb72c8c6bca27d6f6b10275d68f865fb19f1877387925dabd7c51aa5f31efb8460f'

test('SDK COMPAT: keys derive to the same public keys as under 1.13', () => {
  assert.equal(publicKeyFromPrivate(AGENT_PRIV), AGENT_PUB)
  assert.equal(publicKeyFromPrivate(SERVER_PRIV), SERVER_PUB)
})

test('SDK COMPAT: a 48h card signed under 1.13 verifies, and a tampered one does not', () => {
  assert.equal(verifyIntentCard(CARD_113), true)
  assert.equal(verifyIntentCard({ ...CARD_113, principalAlias: 'Someone else' }), false)
  assert.equal(verifyIntentCard({ ...CARD_113, publicKey: SERVER_PUB }), false)
})

test('SDK COMPAT: signing the same card preimage gives the 1.13 signature byte for byte', () => {
  const { signature, ...unsigned } = CARD_113
  assert.equal(sign(canonicalize(unsigned), AGENT_PRIV), signature)
})

test('SDK COMPAT: canonicalize is byte-identical to 1.13, null members removed, array nulls kept', () => {
  const out = canonicalize(V3_INPUT)
  assert.equal(out, V3_CANONICAL_113)
  assert.equal(createHash('sha256').update(out).digest('hex'), DIGEST_113)
})

test('SDK COMPAT: a receipt signed under 1.13 verifies through the trusted key set, and 8.x signs the same bytes', () => {
  const env = { MINGLE_RECEIPT_PRIVKEY: SERVER_PRIV, MINGLE_RECEIPT_PUBKEY: SERVER_PUB }
  assert.equal(verifyReceiptWith(env, DIGEST_113, RECEIPT_SIG_113, deriveIssuerKeyId(SERVER_PUB)), true)
  assert.equal(sign(DIGEST_113, SERVER_PRIV), RECEIPT_SIG_113)
  assert.equal(verify(DIGEST_113.replace(/^2/, '3'), RECEIPT_SIG_113, SERVER_PUB), false)
})

test('SDK COMPAT: isCardExpired keeps the 1.x answer for a valid expiresAt and fails closed on an unparseable one', () => {
  assert.equal(isCardExpired({ ...CARD_113, expiresAt: '2000-01-01T00:00:00.000Z' }), true)
  assert.equal(isCardExpired({ ...CARD_113, expiresAt: new Date(Date.now() + 60_000).toISOString() }), false)
  assert.equal(isCardExpired({ ...CARD_113, expiresAt: 'not a date' }), true)
  assert.equal(isCardExpired({ ...CARD_113, expiresAt: undefined as any }), true)
})

test('SDK COMPAT: a small-order key with a degenerate signature is refused (1.13 accepted it for every message)', () => {
  const identity = '01' + '00'.repeat(31)
  const degenerate = '01' + '00'.repeat(31) + '00'.repeat(32)
  assert.equal(verify('any message', degenerate, identity), false)
})
