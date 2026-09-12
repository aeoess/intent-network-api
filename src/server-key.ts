// ══════════════════════════════════════════════════════════════
// Mingle receipt key: required, derived, matched, resolvable, retained
// ══════════════════════════════════════════════════════════════
// The server signs receipt digests so a party can verify that the artifact they
// hold is the one the server issued. That is only evidence to a third party if
// the signing key is durable and resolvable, so the rule is:
//
//   1. MINGLE_RECEIPT_PRIVKEY and MINGLE_RECEIPT_PUBKEY are both required.
//      Startup refuses to serve without them. There is NO fallback here that
//      invents a pair, which is what this module used to do.
//   2. The public key is derived from the private key and compared to the
//      supplied one. A mismatch is a startup failure, because it would otherwise
//      produce receipts nobody can verify while the service looks healthy.
//   3. issuer_key_id is DERIVED from the public key, never configured, so it
//      cannot drift from the key it names. Every canonical receipt carries it.
//   4. A verifier resolves issuer_key_id against the configured trusted set. It
//      never verifies against a key carried beside the artifact, because whoever
//      wrote the artifact chose both halves and such a check proves only that the
//      response is internally consistent.
//   5. Retired public keys stay in the trusted set (MINGLE_RECEIPT_RETIRED_PUBKEYS),
//      so a receipt issued under a rotated-out key still verifies. Rotation
//      without retention would silently invalidate history.
//
// What this module used to do, for the record: when the two variables were unset
// it generated an ephemeral pair per process, so every receipt stopped verifying
// after a restart and nothing failed loudly. Railway redeploys.
//
// The loader is a PURE function of an environment object. Tests drive it with
// fabricated environments and inject an explicit test-only key through the
// harness, so there is no reset hook and no test-only branch in this file.

import { publicKeyFromPrivate, sign, verify } from 'agent-passport-system'
import { createHash } from 'node:crypto'

export interface ReceiptKey {
  publicKey: string
  privateKey: string
  issuerKeyId: string
}

export type ReceiptKeyFailure = 'receipt_key_missing' | 'receipt_key_mismatch' | 'receipt_key_unusable'

export type ReceiptKeyResult =
  | { ok: true; key: ReceiptKey }
  | { ok: false; code: ReceiptKeyFailure; error: string }

/** Env shape this module reads. Narrow on purpose, so a caller cannot pass the
 *  whole process environment by accident in a context that should be explicit. */
export interface ReceiptKeyEnv {
  MINGLE_RECEIPT_PRIVKEY?: string
  MINGLE_RECEIPT_PUBKEY?: string
  MINGLE_RECEIPT_RETIRED_PUBKEYS?: string
}

/** Stable identifier for a signing key, derived from the public key.
 *  `mk1_` names the derivation so a future scheme is distinguishable rather than
 *  ambiguous. 128 bits of a SHA-256 over the key is far more than enough to name
 *  one of a handful of keys, and the full key is never the identifier because an
 *  identifier travels in artifacts and gets logged. */
export function deriveIssuerKeyId(publicKey: string): string {
  return 'mk1_' + createHash('sha256').update(publicKey, 'utf8').digest('hex').slice(0, 32)
}

/** Pure loader. Never throws, never invents a key. */
export function loadReceiptKeyFrom(env: ReceiptKeyEnv): ReceiptKeyResult {
  const privateKey = env.MINGLE_RECEIPT_PRIVKEY
  const publicKey = env.MINGLE_RECEIPT_PUBKEY
  const missing: string[] = []
  if (!privateKey) missing.push('MINGLE_RECEIPT_PRIVKEY')
  if (!publicKey) missing.push('MINGLE_RECEIPT_PUBKEY')
  if (missing.length > 0) {
    return {
      ok: false,
      code: 'receipt_key_missing',
      error: `receipt key not configured: ${missing.join(' and ')} must be set. Mingle refuses to sign receipts with a key it did not persist, because such a receipt stops verifying at the next restart.`,
    }
  }
  let derived: string
  try {
    derived = publicKeyFromPrivate(privateKey!)
  } catch (e: any) {
    return { ok: false, code: 'receipt_key_unusable', error: `MINGLE_RECEIPT_PRIVKEY is not a usable Ed25519 private key: ${e?.message ?? e}` }
  }
  if (derived !== publicKey) {
    return {
      ok: false,
      code: 'receipt_key_mismatch',
      error: `MINGLE_RECEIPT_PUBKEY does not match the key derived from MINGLE_RECEIPT_PRIVKEY. Derived ${derived}, configured ${publicKey}. A mismatch would issue receipts that verify against neither.`,
    }
  }
  return { ok: true, key: { publicKey: publicKey!, privateKey: privateKey!, issuerKeyId: deriveIssuerKeyId(publicKey!) } }
}

/** The trusted set: the current key plus every retained retired key, by id. */
export function trustedKeySetFrom(env: ReceiptKeyEnv): Map<string, string> {
  const set = new Map<string, string>()
  const loaded = loadReceiptKeyFrom(env)
  if (loaded.ok) set.set(loaded.key.issuerKeyId, loaded.key.publicKey)
  for (const raw of (env.MINGLE_RECEIPT_RETIRED_PUBKEYS ?? '').split(',')) {
    const k = raw.trim()
    if (k.length > 0) set.set(deriveIssuerKeyId(k), k)
  }
  return set
}

export function resolveIssuerKeyWith(env: ReceiptKeyEnv, issuerKeyId: string): string | null {
  return trustedKeySetFrom(env).get(issuerKeyId) ?? null
}

export type ReceiptCheck =
  | { ok: true; issuerKeyId: string }
  | { ok: false; reason: 'issuer_unresolved' | 'signature_invalid' }

/** Resolve then verify, reporting which of the two failed. An unresolvable issuer
 *  and a bad signature are different problems and an operator told the wrong one
 *  looks in the wrong place. */
export function checkReceiptWith(env: ReceiptKeyEnv, digest: string, receipt: string, issuerKeyId: string): ReceiptCheck {
  const key = resolveIssuerKeyWith(env, issuerKeyId)
  if (key === null) return { ok: false, reason: 'issuer_unresolved' }
  try {
    return verify(digest, receipt, key) ? { ok: true, issuerKeyId } : { ok: false, reason: 'signature_invalid' }
  } catch {
    return { ok: false, reason: 'signature_invalid' }
  }
}

export function verifyReceiptWith(env: ReceiptKeyEnv, digest: string, receipt: string, issuerKeyId: string): boolean {
  return checkReceiptWith(env, digest, receipt, issuerKeyId).ok
}

/** Startup gate. Throws with a message that names what is wrong, so a failed
 *  boot is self explanatory in a deploy log. */
export function assertReceiptKeyConfigured(env: ReceiptKeyEnv = process.env as ReceiptKeyEnv): ReceiptKey {
  const loaded = loadReceiptKeyFrom(env)
  if (loaded.ok === true) return loaded.key
  // tsconfig runs with strictNullChecks off, so a boolean-literal discriminant
  // does not narrow the union on the failure branch. Name the failure type.
  throw new Error((loaded as { ok: false; code: ReceiptKeyFailure; error: string }).error)
}

// ── Cached accessors, for the running service ─────────────────────────────
// Resolved once from process.env on first use. A caller that reaches these
// without a configured key gets the loader's message, not a generated key.

let cached: ReceiptKey | null = null

function current(): ReceiptKey {
  if (!cached) cached = assertReceiptKeyConfigured(process.env as ReceiptKeyEnv)
  return cached
}

export function serverPublicKey(): string { return current().publicKey }
export function issuerKeyId(): string { return current().issuerKeyId }
export function signReceipt(digest: string): string { return sign(digest, current().privateKey) }

/** Verify against the CURRENT key. Kept for the v3 and v4 receipts, which are
 *  read back inside the instance that issued them and carry no issuer id. */
export function verifyReceipt(digest: string, receipt: string): boolean {
  try { return verify(digest, receipt, current().publicKey) } catch { return false }
}

/** Verify a receipt that carries an issuer id, resolving from the trusted set. */
export function checkReceipt(digest: string, receipt: string, id: string): ReceiptCheck {
  return checkReceiptWith(process.env as ReceiptKeyEnv, digest, receipt, id)
}

export function trustedKeySet(): Map<string, string> {
  return trustedKeySetFrom(process.env as ReceiptKeyEnv)
}
