// ══════════════════════════════════════════════════════════════
// The receipt key: required, derived, matched, resolvable, retained
// ══════════════════════════════════════════════════════════════
// Before this step the key fell back to a pair generated per process when the
// two env vars were unset, so every receipt issued before a restart stopped
// verifying after it and nothing failed loudly. That is the whole reason a
// server observation could not be evidence to anyone.
//
// The rule now: both variables required, the public key derived from the private
// key and matched against the supplied one, a stable issuer_key_id derived from
// the public key and carried in every canonical receipt, verifiers resolving that
// id against a configured trusted set rather than against a key handed to them in
// the artifact they are checking, and retired keys retained so old receipts keep
// verifying after a rotation.
//
// Most of this file drives the PURE loader with fabricated environments, which is
// why there is no reset hook in src. The cached accessor is exercised once,
// through the key the harness injects.

import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, publicKeyFromPrivate, sign } from 'agent-passport-system'

// The harness injects an explicit test-only key. src has no fallback that would
// invent one, so a test that forgets this and touches a receipt fails loudly.
const testKey = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = testKey.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = testKey.publicKey

const sk = await import('../src/server-key.js')

// ── The pure loader ───────────────────────────────────────────────────────

test('RECEIPT KEY: a complete matching pair loads', () => {
  const r = sk.loadReceiptKeyFrom({
    MINGLE_RECEIPT_PRIVKEY: testKey.privateKey,
    MINGLE_RECEIPT_PUBKEY: testKey.publicKey,
  })
  assert.equal(r.ok, true)
  if (!r.ok) return
  assert.equal(r.key.publicKey, testKey.publicKey)
  assert.match(r.key.issuerKeyId, /^mk1_[0-9a-f]{32}$/)
})

test('RECEIPT KEY: a missing variable is refused and the message names it', () => {
  const noPriv = sk.loadReceiptKeyFrom({ MINGLE_RECEIPT_PUBKEY: testKey.publicKey })
  assert.equal(noPriv.ok, false)
  if (noPriv.ok) return
  assert.equal(noPriv.code, 'receipt_key_missing')
  assert.match(noPriv.error, /MINGLE_RECEIPT_PRIVKEY/)

  const noPub = sk.loadReceiptKeyFrom({ MINGLE_RECEIPT_PRIVKEY: testKey.privateKey })
  assert.equal(noPub.ok, false)
  if (noPub.ok) return
  assert.equal(noPub.code, 'receipt_key_missing')
  assert.match(noPub.error, /MINGLE_RECEIPT_PUBKEY/)

  const neither = sk.loadReceiptKeyFrom({})
  assert.equal(neither.ok, false)
  if (neither.ok) return
  assert.match(neither.error, /MINGLE_RECEIPT_PUBKEY/)
  assert.match(neither.error, /MINGLE_RECEIPT_PRIVKEY/)
})

test('RECEIPT KEY: an empty string counts as missing, not as a key', () => {
  const r = sk.loadReceiptKeyFrom({ MINGLE_RECEIPT_PRIVKEY: '', MINGLE_RECEIPT_PUBKEY: '' })
  assert.equal(r.ok, false)
})

test('RECEIPT KEY: a public key that does not belong to the private key is refused', () => {
  // The case a naive presence check misses, and the one that would otherwise
  // produce receipts nobody can verify while the service looks healthy.
  const other = generateKeyPair()
  const r = sk.loadReceiptKeyFrom({
    MINGLE_RECEIPT_PRIVKEY: testKey.privateKey,
    MINGLE_RECEIPT_PUBKEY: other.publicKey,
  })
  assert.equal(r.ok, false)
  if (r.ok) return
  assert.equal(r.code, 'receipt_key_mismatch')
  assert.match(r.error, /derived/)
})

test('RECEIPT KEY: a malformed private key is refused rather than throwing', () => {
  const r = sk.loadReceiptKeyFrom({
    MINGLE_RECEIPT_PRIVKEY: 'not-a-key',
    MINGLE_RECEIPT_PUBKEY: testKey.publicKey,
  })
  assert.equal(r.ok, false)
  if (r.ok) return
  assert.equal(r.code, 'receipt_key_unusable')
})

test('RECEIPT KEY: issuer_key_id is derived from the public key and is stable', () => {
  const a = sk.deriveIssuerKeyId(testKey.publicKey)
  const b = sk.deriveIssuerKeyId(testKey.publicKey)
  assert.equal(a, b, 'same key, same id, every time')
  assert.notEqual(a, sk.deriveIssuerKeyId(generateKeyPair().publicKey), 'different key, different id')
  assert.match(a, /^mk1_[0-9a-f]{32}$/)
  // Derived, not configured, so it cannot drift from the key it names.
  assert.equal(sk.loadReceiptKeyFrom({
    MINGLE_RECEIPT_PRIVKEY: testKey.privateKey,
    MINGLE_RECEIPT_PUBKEY: testKey.publicKey,
  }).ok && sk.loadReceiptKeyFrom({
    MINGLE_RECEIPT_PRIVKEY: testKey.privateKey,
    MINGLE_RECEIPT_PUBKEY: testKey.publicKey,
  }).key.issuerKeyId, a)
})

// ── The trusted key set and resolution ────────────────────────────────────

test('RECEIPT KEY: the trusted set holds the current key plus every retired one', () => {
  const retired1 = generateKeyPair()
  const retired2 = generateKeyPair()
  const set = sk.trustedKeySetFrom({
    MINGLE_RECEIPT_PRIVKEY: testKey.privateKey,
    MINGLE_RECEIPT_PUBKEY: testKey.publicKey,
    MINGLE_RECEIPT_RETIRED_PUBKEYS: `${retired1.publicKey},${retired2.publicKey}`,
  })
  assert.equal(set.size, 3)
  assert.equal(set.get(sk.deriveIssuerKeyId(testKey.publicKey)), testKey.publicKey)
  assert.equal(set.get(sk.deriveIssuerKeyId(retired1.publicKey)), retired1.publicKey)
  assert.equal(set.get(sk.deriveIssuerKeyId(retired2.publicKey)), retired2.publicKey)
})

test('RECEIPT KEY: a receipt signed under a retired key still verifies after rotation', () => {
  const old = generateKeyPair()
  const fresh = generateKeyPair()
  const digest = 'a'.repeat(64)
  const receipt = sign(digest, old.privateKey)
  const oldId = sk.deriveIssuerKeyId(old.publicKey)

  // After rotation the current key is `fresh` and `old` is retained.
  const env = {
    MINGLE_RECEIPT_PRIVKEY: fresh.privateKey,
    MINGLE_RECEIPT_PUBKEY: fresh.publicKey,
    MINGLE_RECEIPT_RETIRED_PUBKEYS: old.publicKey,
  }
  assert.equal(sk.verifyReceiptWith(env, digest, receipt, oldId), true,
    'retention is what stops a rotation invalidating history')

  // Drop the retained key and the same receipt becomes unresolvable rather than
  // invalid. Those are different failures and an operator needs to see which.
  const without = { MINGLE_RECEIPT_PRIVKEY: fresh.privateKey, MINGLE_RECEIPT_PUBKEY: fresh.publicKey }
  assert.equal(sk.resolveIssuerKeyWith(without, oldId), null)
  assert.equal(sk.verifyReceiptWith(without, digest, receipt, oldId), false)
})

test('RECEIPT KEY: an unresolvable issuer_key_id is reported as unresolvable, not as a bad signature', () => {
  const env = { MINGLE_RECEIPT_PRIVKEY: testKey.privateKey, MINGLE_RECEIPT_PUBKEY: testKey.publicKey }
  const unknown = sk.deriveIssuerKeyId(generateKeyPair().publicKey)
  assert.equal(sk.resolveIssuerKeyWith(env, unknown), null)
  const out = sk.checkReceiptWith(env, 'a'.repeat(64), 'ff'.repeat(64), unknown)
  assert.equal(out.ok, false)
  if (out.ok) return
  assert.equal(out.reason, 'issuer_unresolved', 'an operator sent to the wrong place is worse than no message')
})

test('RECEIPT KEY: verification never trusts a key carried beside the artifact', () => {
  // An attacker who can choose both halves of a response can make any signature
  // "verify" against the key they shipped with it. Resolution from a configured
  // set is what makes the signature evidence about the issuer.
  const rogue = generateKeyPair()
  const digest = 'b'.repeat(64)
  const forged = sign(digest, rogue.privateKey)
  const env = { MINGLE_RECEIPT_PRIVKEY: testKey.privateKey, MINGLE_RECEIPT_PUBKEY: testKey.publicKey }
  // The rogue key is not in the trusted set, so its id resolves to nothing.
  assert.equal(sk.resolveIssuerKeyWith(env, sk.deriveIssuerKeyId(rogue.publicKey)), null)
  assert.equal(sk.verifyReceiptWith(env, digest, forged, sk.deriveIssuerKeyId(rogue.publicKey)), false)
  // And the module exposes no function that accepts a public key as an argument
  // for verification, which is the shape that would invite the mistake.
  assert.equal(typeof (sk as any).verifyReceiptWithPublicKey, 'undefined')
})

// ── The cached accessors, and the startup gate ────────────────────────────

test('RECEIPT KEY: the cached accessors work under the injected harness key', () => {
  assert.equal(sk.serverPublicKey(), testKey.publicKey)
  assert.equal(sk.issuerKeyId(), sk.deriveIssuerKeyId(testKey.publicKey))
  const digest = 'c'.repeat(64)
  const receipt = sk.signReceipt(digest)
  assert.equal(sk.verifyReceipt(digest, receipt), true)
  assert.equal(sk.verifyReceipt('d'.repeat(64), receipt), false)
  assert.equal(publicKeyFromPrivate(testKey.privateKey), sk.serverPublicKey())
})

test('RECEIPT KEY: assertReceiptKeyConfigured throws on a bad environment and is silent on a good one', () => {
  assert.throws(() => sk.assertReceiptKeyConfigured({}), /MINGLE_RECEIPT_PUBKEY/)
  assert.throws(
    () => sk.assertReceiptKeyConfigured({ MINGLE_RECEIPT_PRIVKEY: testKey.privateKey, MINGLE_RECEIPT_PUBKEY: generateKeyPair().publicKey }),
    /derived/,
  )
  sk.assertReceiptKeyConfigured({ MINGLE_RECEIPT_PRIVKEY: testKey.privateKey, MINGLE_RECEIPT_PUBKEY: testKey.publicKey })
})

test('RECEIPT KEY: src carries no fallback that invents a key', async () => {
  const { readFileSync } = await import('node:fs')
  const src = readFileSync(new URL('../src/server-key.ts', import.meta.url), 'utf8')
  // Check for the import and for a call, not for the word, so a comment naming
  // the removed behavior does not trip the guard.
  const code = src.split('\n').filter(l => !l.trim().startsWith('//') && !l.trim().startsWith('*')).join('\n')
  assert.equal(/\bgenerateKeyPair\b/.test(code), false,
    'a generated fallback is the defect this step removes, so the symbol must not appear in code')
  assert.equal(/from 'agent-passport-system'/.test(code), true, 'it still imports the crypto it does use')
  assert.equal(/publicKeyFromPrivate/.test(code), true, 'and derives the public key rather than trusting it')
})
