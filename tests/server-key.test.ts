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

// ── The trusted key set, with roles ───────────────────────────────────────

const RETIRED_AT = '2026-06-01T00:00:00.000Z'
const BEFORE_RETIREMENT = '2026-05-20T12:00:00.000Z'
const AFTER_RETIREMENT = '2026-06-01T00:00:00.001Z'

test('ROTATION: every entry holds exactly one role and there is exactly one active signer', () => {
  const retired1 = generateKeyPair()
  const retired2 = generateKeyPair()
  const set = sk.loadTrustedKeySetFrom({
    MINGLE_RECEIPT_PRIVKEY: testKey.privateKey,
    MINGLE_RECEIPT_PUBKEY: testKey.publicKey,
    MINGLE_RECEIPT_RETIRED_PUBKEYS: `${retired1.publicKey}@${RETIRED_AT},${retired2.publicKey}@2025-01-02T03:04:05.678Z`,
  })
  assert.equal(set.ok, true)
  if (!set.ok) return
  assert.equal(set.entries.length, 3)
  assert.equal(set.entries.filter(e => e.role === 'active_signer').length, 1)
  assert.equal(set.active.publicKey, testKey.publicKey)
  assert.equal(set.active.retiredAt, undefined, 'the active signer carries no retirement time')

  const byId = new Map(set.entries.map(e => [e.issuerKeyId, e]))
  assert.equal(byId.get(sk.deriveIssuerKeyId(retired1.publicKey))!.role, 'verification_only')
  assert.equal(byId.get(sk.deriveIssuerKeyId(retired1.publicKey))!.retiredAt, RETIRED_AT)
  assert.equal(byId.get(sk.deriveIssuerKeyId(retired2.publicKey))!.retiredAt, '2025-01-02T03:04:05.678Z')
  // And the roles are disjoint, which is what "exactly one of" means.
  for (const e of set.entries) {
    assert.equal(e.role === 'verification_only', typeof e.retiredAt === 'string')
  }
})

test('ROTATION: a retired key cannot sign, because retirement is a public key plus a time', () => {
  const old = generateKeyPair()
  const fresh = generateKeyPair()
  const env = {
    MINGLE_RECEIPT_PRIVKEY: fresh.privateKey,
    MINGLE_RECEIPT_PUBKEY: fresh.publicKey,
    MINGLE_RECEIPT_RETIRED_PUBKEYS: `${old.publicKey}@${RETIRED_AT}`,
  }
  const set = sk.loadTrustedKeySetFrom(env)
  assert.equal(set.ok, true)
  if (!set.ok) return
  // The only key with a private half anywhere in the configuration is the active
  // signer, so "only the active signer creates new receipts" is structural rather than
  // a check that could be forgotten. A retired entry carries no private key at all.
  assert.equal(set.active.publicKey, fresh.publicKey)
  for (const e of set.entries) assert.equal((e as any).privateKey, undefined)
  // And a receipt actually signed with the retired private half does not pass as a new
  // receipt: it resolves to the retired entry, which is bounded in time.
  const digest = 'e'.repeat(64)
  const nowIsh = new Date(Date.parse(RETIRED_AT) + 86400000).toISOString()
  const out = sk.checkReceiptWith(env, digest, sign(digest, old.privateKey), sk.deriveIssuerKeyId(old.publicKey), nowIsh)
  assert.equal(out.ok, false)
  if (out.ok) return
  assert.equal(out.reason, 'issuer_retired_before_record')
})

test('ROTATION: a historical receipt under a retired key still verifies', () => {
  const old = generateKeyPair()
  const fresh = generateKeyPair()
  const digest = 'a'.repeat(64)
  const receipt = sign(digest, old.privateKey)
  const oldId = sk.deriveIssuerKeyId(old.publicKey)

  // After rotation the active signer is `fresh` and `old` is retained with its time.
  const env = {
    MINGLE_RECEIPT_PRIVKEY: fresh.privateKey,
    MINGLE_RECEIPT_PUBKEY: fresh.publicKey,
    MINGLE_RECEIPT_RETIRED_PUBKEYS: `${old.publicKey}@${RETIRED_AT}`,
  }
  const out = sk.checkReceiptWith(env, digest, receipt, oldId, BEFORE_RETIREMENT)
  assert.equal(out.ok, true, 'retention is what stops a rotation invalidating history')
  if (!out.ok) return
  assert.equal(out.role, 'verification_only')
  // The boundary itself is inside the bound, because the rule is "not after".
  assert.equal(sk.verifyReceiptWith(env, digest, receipt, oldId, RETIRED_AT), true)

  // Drop the retained key and the same receipt becomes unresolvable rather than
  // invalid. Those are different failures and an operator needs to see which.
  const without = { MINGLE_RECEIPT_PRIVKEY: fresh.privateKey, MINGLE_RECEIPT_PUBKEY: fresh.publicKey }
  assert.equal(sk.trustedKeyEntryFor(without, oldId), null)
  assert.equal(sk.verifyReceiptWith(without, digest, receipt, oldId, BEFORE_RETIREMENT), false)
})

test('ROTATION: a receipt under a retired key recorded AFTER retired_at is refused', () => {
  const old = generateKeyPair()
  const fresh = generateKeyPair()
  const digest = 'b'.repeat(64)
  const receipt = sign(digest, old.privateKey)
  const oldId = sk.deriveIssuerKeyId(old.publicKey)
  const env = {
    MINGLE_RECEIPT_PRIVKEY: fresh.privateKey,
    MINGLE_RECEIPT_PUBKEY: fresh.publicKey,
    MINGLE_RECEIPT_RETIRED_PUBKEYS: `${old.publicKey}@${RETIRED_AT}`,
  }
  // One millisecond past the bound. The signature itself is perfectly valid, which is
  // the point: what is wrong is the receipt existing at that time under that key.
  const out = sk.checkReceiptWith(env, digest, receipt, oldId, AFTER_RETIREMENT)
  assert.equal(out.ok, false)
  if (out.ok) return
  assert.equal(out.reason, 'issuer_retired_before_record')

  // And a missing record time fails closed rather than waiving the bound, because a
  // waived bound is the same as no retirement at all.
  const noTime = sk.checkReceiptWith(env, digest, receipt, oldId)
  assert.equal(noTime.ok, false)
  if (noTime.ok) return
  assert.equal(noTime.reason, 'record_time_unknown')
  // A malformed record time is the same failure, not an accepted one.
  assert.equal(sk.verifyReceiptWith(env, digest, receipt, oldId, '2026-06-01'), false)

  // The active signer needs no record time, because it is not bounded.
  const currentDigest = 'c'.repeat(64)
  assert.equal(
    sk.verifyReceiptWith(env, currentDigest, sign(currentDigest, fresh.privateKey), sk.deriveIssuerKeyId(fresh.publicKey)),
    true)
})

test('ROTATION: a malformed, duplicated or self-referential retired entry refuses at startup', () => {
  const old = generateKeyPair()
  const base = { MINGLE_RECEIPT_PRIVKEY: testKey.privateKey, MINGLE_RECEIPT_PUBKEY: testKey.publicKey }
  const codeOf = (retired: string) => {
    const r = sk.loadTrustedKeySetFrom({ ...base, MINGLE_RECEIPT_RETIRED_PUBKEYS: retired })
    return r.ok ? 'ok' : (r as any).code
  }
  // No retirement time at all, which is the entry shape before this ruling. Refused
  // rather than trusted forever, because trusted forever is the active signer's trust.
  assert.equal(codeOf(old.publicKey), 'retired_key_malformed')
  assert.equal(codeOf(`${old.publicKey}@`), 'retired_key_malformed')
  assert.equal(codeOf(`${old.publicKey}@not-a-date`), 'retired_key_malformed')
  // A shape V8 would silently roll over into a different day.
  assert.equal(codeOf(`${old.publicKey}@2026-02-30T00:00:00.000Z`), 'retired_key_malformed')
  assert.equal(codeOf(`${old.publicKey}@2026-06-01T00:00:00Z`), 'retired_key_malformed')
  // The same key twice, so its bound would depend on parse order.
  assert.equal(codeOf(`${old.publicKey}@${RETIRED_AT},${old.publicKey}@2020-01-01T00:00:00.000Z`), 'retired_key_duplicate')
  // The active signer listed as retired, which is one entry holding two roles.
  assert.equal(codeOf(`${testKey.publicKey}@${RETIRED_AT}`), 'retired_key_is_active_signer')
  // A retired entry whose public key is not a key at all. It used to be accepted, so a typo
  // became a trusted entry with a derived id nobody's receipts carry, which SILENTLY deleted
  // the history the entry was added to preserve while the boot log said one retired key was
  // trusted. It fails closed, and the loss was total either way.
  assert.equal(codeOf(`not-a-public-key@${RETIRED_AT}`), 'retired_key_malformed')
  assert.equal(codeOf(`${old.publicKey.toUpperCase()}@${RETIRED_AT}`), 'retired_key_malformed')
  assert.equal(codeOf(`${old.publicKey.slice(0, -2)}@${RETIRED_AT}`), 'retired_key_malformed',
    'a truncated key is the realistic typo, and it must not be trusted')
  // And an invalid set resolves NOTHING, so a misconfiguration cannot widen trust.
  assert.equal(sk.trustedKeyEntryFor({ ...base, MINGLE_RECEIPT_RETIRED_PUBKEYS: old.publicKey },
    sk.deriveIssuerKeyId(testKey.publicKey)), null)
  assert.throws(() => sk.assertReceiptKeyConfigured({ ...base, MINGLE_RECEIPT_RETIRED_PUBKEYS: old.publicKey }),
    /PUBKEY@RETIRED_AT/)
  assert.throws(() => sk.assertTrustedKeySetConfigured({ ...base, MINGLE_RECEIPT_RETIRED_PUBKEYS: `${testKey.publicKey}@${RETIRED_AT}` }),
    /two roles|exactly one role/)
})

test('ROTATION: the module says out loud what it does not prevent', async () => {
  // The time bound rests on the server's own record of when it issued a receipt. It
  // bounds an honest server and a key that leaks later. It cannot contradict a holder
  // of a compromised retired private key who claims a time at or before retired_at,
  // and the module header has to say so rather than implying a guarantee it has not
  // got. Asserted mechanically so the limit cannot be quietly deleted.
  const { readFileSync } = await import('node:fs')
  const src = readFileSync(new URL('../src/server-key.ts', import.meta.url), 'utf8')
  assert.match(src, /BACKDATING/, 'the header must name the attack it does not stop')
  assert.match(src, /transparency log|timestamp/, 'and must name what would stop it')
  assert.match(src, /outside 2B/, 'and must say the mechanism is out of scope here')
  // Configuration and verifier machinery only: no key management surface landed.
  assert.equal(typeof (sk as any).rotateKey, 'undefined')
  assert.equal(typeof (sk as any).retireKey, 'undefined')
  assert.equal(typeof (sk as any).setActiveSigner, 'undefined')
  assert.equal(src.includes('CREATE TABLE'), false, 'no database backed rotation service')
})

test('RECEIPT KEY: an unresolvable issuer_key_id is reported as unresolvable, not as a bad signature', () => {
  const env = { MINGLE_RECEIPT_PRIVKEY: testKey.privateKey, MINGLE_RECEIPT_PUBKEY: testKey.publicKey }
  const unknown = sk.deriveIssuerKeyId(generateKeyPair().publicKey)
  assert.equal(sk.trustedKeyEntryFor(env, unknown), null)
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
  assert.equal(sk.trustedKeyEntryFor(env, sk.deriveIssuerKeyId(rogue.publicKey)), null)
  assert.equal(sk.verifyReceiptWith(env, digest, forged, sk.deriveIssuerKeyId(rogue.publicKey)), false)
  // And the module exposes no function that accepts a public key as an argument
  // for verification, which is the shape that would invite the mistake.
  assert.equal(typeof (sk as any).verifyReceiptWithPublicKey, 'undefined')
  // NOR one that hands back a bare public key with no time bound and no parameter that could
  // carry one. resolveIssuerKeyWith used to, so a caller who resolved and then verified
  // bypassed the retirement rule entirely and nothing in its signature hinted at it.
  assert.equal(typeof (sk as any).resolveIssuerKeyWith, 'undefined')
  // trustedKeyEntryFor is the replacement, and it hands back the role and the retired_at
  // beside the key, so a caller cannot see the key without seeing the bound.
  const retired = generateKeyPair()
  const withRetired = { ...env, MINGLE_RECEIPT_RETIRED_PUBKEYS: `${retired.publicKey}@${RETIRED_AT}` }
  const entry = sk.trustedKeyEntryFor(withRetired, sk.deriveIssuerKeyId(retired.publicKey))!
  assert.equal(entry.role, 'verification_only')
  assert.equal(entry.retiredAt, RETIRED_AT)
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
