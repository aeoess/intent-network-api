// ══════════════════════════════════════════════════════════════
// Mingle receipt key: required, derived, matched, resolvable, retained, roled
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
// ── Rotation, per the closed ruling ───────────────────────────────────────
//
// Every entry in the trusted set carries exactly one ROLE:
//
//   active_signer      the one key that creates new receipts. Exactly one, and
//                      startup refuses if there is not exactly one.
//   verification_only  a retired key. It carries retired_at, it signs nothing,
//                      and it is trusted ONLY for a receipt whose recorded time
//                      is not after its retired_at.
//
// A retired key without a retired_at is refused rather than trusted without a
// bound, because a retired key trusted for all time is the same trust the active
// signer has and the role then means nothing. An entry that is both the active
// signer and a retired key is refused for the same reason.
//
// WHAT THIS DOES NOT DO, and the limit matters more than the mechanism. The time
// bound rests on recorded_at, which is the server's own record of when it issued
// the receipt. It stops a retired key from being used for NEW work by an honest
// server, and it bounds the damage from a retired key that leaks later. It does
// NOT prevent a holder of a compromised retired private key from BACKDATING: such
// a holder can sign any digest and claim any recorded_at at or before retired_at,
// and nothing in this module can contradict them. Strong anti-backdating needs a
// mechanism outside 2B, either a transparency log that publishes receipt digests
// as they are issued or a third party timestamp over each one, so that a receipt
// with no entry in the log at its claimed time is refutable. That is a Stage 2C or
// later decision and this module deliberately does not pretend otherwise.
//
// This is configuration and verifier machinery ONLY. There is no key management
// API here, no admin surface, no database backed rotation service and no automatic
// rotation workflow. Rotating a key is an operator editing two environment
// variables and restarting, which is the whole design.
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
  /** Comma separated `PUBKEY@RETIRED_AT`, where RETIRED_AT is ISO 8601 with
   *  milliseconds and a trailing Z. Unset means no rotation has happened. */
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

// ── The trusted key set, with roles ───────────────────────────────────────

export type KeyRole = 'active_signer' | 'verification_only'

export interface TrustedKeyEntry {
  issuerKeyId: string
  publicKey: string
  role: KeyRole
  /** Present exactly when the role is verification_only. */
  retiredAt?: string
}

export type TrustedSetFailure =
  | ReceiptKeyFailure
  | 'retired_key_malformed'
  | 'retired_key_duplicate'
  | 'retired_key_is_active_signer'

export type TrustedSetResult =
  | { ok: true; entries: TrustedKeyEntry[]; active: TrustedKeyEntry }
  | { ok: false; code: TrustedSetFailure; error: string }

// One timestamp shape, round trip checked, so two implementations cannot disagree
// about what a retirement time means. Same rule the write envelope applies to
// issued_at, and for the same reason: the shape alone admits a calendar invalid
// instant that V8 silently rolls over.
const ISO_MS_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

function isExactIso(value: string): boolean {
  if (!ISO_MS_Z.test(value)) return false
  const t = Date.parse(value)
  return !Number.isNaN(t) && new Date(t).toISOString() === value
}

function setFail(code: TrustedSetFailure, error: string): TrustedSetResult {
  return { ok: false, code, error }
}

/** Load and VALIDATE the whole trusted set. Pure, never throws.
 *
 *  Exactly one active_signer, by construction: it is the configured pair, and there
 *  is one of those or the load already failed. Every other entry is
 *  verification_only and must carry a parseable retired_at. */
export function loadTrustedKeySetFrom(env: ReceiptKeyEnv): TrustedSetResult {
  const loaded = loadReceiptKeyFrom(env)
  if (loaded.ok !== true) {
    const f = loaded as { ok: false; code: ReceiptKeyFailure; error: string }
    return setFail(f.code, f.error)
  }
  const active: TrustedKeyEntry = {
    issuerKeyId: loaded.key.issuerKeyId,
    publicKey: loaded.key.publicKey,
    role: 'active_signer',
  }
  const entries: TrustedKeyEntry[] = [active]
  const byId = new Map<string, TrustedKeyEntry>([[active.issuerKeyId, active]])

  for (const raw of (env.MINGLE_RECEIPT_RETIRED_PUBKEYS ?? '').split(',')) {
    const item = raw.trim()
    if (item.length === 0) continue
    const at = item.lastIndexOf('@')
    if (at <= 0 || at === item.length - 1) {
      return setFail('retired_key_malformed',
        `MINGLE_RECEIPT_RETIRED_PUBKEYS entry "${item}" is not PUBKEY@RETIRED_AT. A retired key with no retirement time would be trusted for all time, which is the trust the active signer has, so the role would mean nothing.`)
    }
    const publicKey = item.slice(0, at).trim()
    const retiredAt = item.slice(at + 1).trim()
    if (publicKey.length === 0 || !isExactIso(retiredAt)) {
      return setFail('retired_key_malformed',
        `MINGLE_RECEIPT_RETIRED_PUBKEYS entry for ${publicKey.slice(0, 16) || '(empty)'} carries retired_at "${retiredAt}", which must be ISO 8601 with milliseconds and a trailing Z and must name a real instant.`)
    }
    const issuerKeyId = deriveIssuerKeyId(publicKey)
    if (issuerKeyId === active.issuerKeyId) {
      return setFail('retired_key_is_active_signer',
        'a key listed in MINGLE_RECEIPT_RETIRED_PUBKEYS is also the configured signing key. One entry holds exactly one role, and a key that is both signs while claiming it does not.')
    }
    if (byId.has(issuerKeyId)) {
      return setFail('retired_key_duplicate',
        `MINGLE_RECEIPT_RETIRED_PUBKEYS lists ${issuerKeyId} twice, so its retired_at is ambiguous and the time bound would depend on parse order.`)
    }
    const entry: TrustedKeyEntry = { issuerKeyId, publicKey, role: 'verification_only', retiredAt }
    byId.set(issuerKeyId, entry)
    entries.push(entry)
  }
  return { ok: true, entries, active }
}

/** One entry by id, or null. An invalid trusted set resolves NOTHING, so a
 *  misconfigured retired list cannot widen what is trusted. */
export function trustedKeyEntryFor(env: ReceiptKeyEnv, issuerKeyId: string): TrustedKeyEntry | null {
  const set = loadTrustedKeySetFrom(env)
  if (set.ok !== true) return null
  return (set as { ok: true; entries: TrustedKeyEntry[] }).entries.find(e => e.issuerKeyId === issuerKeyId) ?? null
}

export function resolveIssuerKeyWith(env: ReceiptKeyEnv, issuerKeyId: string): string | null {
  return trustedKeyEntryFor(env, issuerKeyId)?.publicKey ?? null
}

export type ReceiptCheckReason =
  | 'issuer_unresolved'
  | 'signature_invalid'
  | 'issuer_retired_before_record'
  | 'record_time_unknown'

export type ReceiptCheck =
  | { ok: true; issuerKeyId: string; role: KeyRole }
  | { ok: false; reason: ReceiptCheckReason }

/** Resolve, apply the role's time bound, then verify, reporting which step failed.
 *
 *  Each failure is its own reason because each sends an operator somewhere
 *  different: an unresolvable issuer is a configuration problem, a bad signature is
 *  a tampered artifact, and a retired key used after its retirement is a receipt
 *  that should not exist.
 *
 *  `recordedAt` is when the SERVER recorded issuing the receipt, which for a
 *  lifecycle receipt is its rendered_at. It is required for a verification_only
 *  key and ignored for the active signer. Omitting it against a retired key fails
 *  closed rather than waiving the bound. */
export function checkReceiptWith(
  env: ReceiptKeyEnv, digest: string, receipt: string, issuerKeyId: string, recordedAt?: string,
): ReceiptCheck {
  const entry = trustedKeyEntryFor(env, issuerKeyId)
  if (entry === null) return { ok: false, reason: 'issuer_unresolved' }
  if (entry.role === 'verification_only') {
    if (typeof recordedAt !== 'string' || !isExactIso(recordedAt)) {
      return { ok: false, reason: 'record_time_unknown' }
    }
    // "not after", so a receipt recorded exactly at retired_at is inside the bound.
    if (Date.parse(recordedAt) > Date.parse(entry.retiredAt as string)) {
      return { ok: false, reason: 'issuer_retired_before_record' }
    }
  }
  try {
    return verify(digest, receipt, entry.publicKey)
      ? { ok: true, issuerKeyId, role: entry.role }
      : { ok: false, reason: 'signature_invalid' }
  } catch {
    return { ok: false, reason: 'signature_invalid' }
  }
}

export function verifyReceiptWith(
  env: ReceiptKeyEnv, digest: string, receipt: string, issuerKeyId: string, recordedAt?: string,
): boolean {
  return checkReceiptWith(env, digest, receipt, issuerKeyId, recordedAt).ok
}

/** Startup gate. Throws with a message that names what is wrong, so a failed
 *  boot is self explanatory in a deploy log.
 *
 *  It validates the WHOLE trusted set, not only the pair, so a malformed retired
 *  entry stops the boot rather than silently narrowing what verifies later. */
export function assertReceiptKeyConfigured(env: ReceiptKeyEnv = process.env as ReceiptKeyEnv): ReceiptKey {
  const loaded = loadReceiptKeyFrom(env)
  if (loaded.ok !== true) {
    // tsconfig runs with strictNullChecks off, so a boolean-literal discriminant
    // does not narrow the union on the failure branch. Name the failure type.
    throw new Error((loaded as { ok: false; code: ReceiptKeyFailure; error: string }).error)
  }
  const set = loadTrustedKeySetFrom(env)
  if (set.ok !== true) {
    throw new Error((set as { ok: false; code: TrustedSetFailure; error: string }).error)
  }
  return loaded.key
}

/** The trusted set, or a throw naming what is misconfigured. Exactly one
 *  active_signer whenever it returns. */
export function assertTrustedKeySetConfigured(env: ReceiptKeyEnv = process.env as ReceiptKeyEnv): TrustedKeyEntry[] {
  const set = loadTrustedKeySetFrom(env)
  if (set.ok !== true) {
    throw new Error((set as { ok: false; code: TrustedSetFailure; error: string }).error)
  }
  const ok = set as { ok: true; entries: TrustedKeyEntry[] }
  const signers = ok.entries.filter(e => e.role === 'active_signer')
  if (signers.length !== 1) {
    throw new Error(`the trusted receipt key set must hold exactly one active_signer and holds ${signers.length}`)
  }
  return ok.entries
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

/** Sign a receipt digest under the ACTIVE SIGNER, which is the only key that ever
 *  creates a new receipt. A retired key cannot sign here because it has no private
 *  half in this process: retirement is a public key plus a time, by construction. */
export function signReceipt(digest: string): string { return sign(digest, current().privateKey) }

/** Verify against the ACTIVE SIGNER only. Kept for the v3 and v4 receipts, which are
 *  read back inside the instance that issued them and carry no issuer id.
 *
 *  It never accepts a retired key, so it is not the function for verifying history
 *  across a rotation. checkReceipt is. */
export function verifyReceipt(digest: string, receipt: string): boolean {
  try { return verify(digest, receipt, current().publicKey) } catch { return false }
}

/** Verify a receipt that carries an issuer id, resolving from the trusted set and
 *  applying the retired key's time bound. */
export function checkReceipt(digest: string, receipt: string, id: string, recordedAt?: string): ReceiptCheck {
  return checkReceiptWith(process.env as ReceiptKeyEnv, digest, receipt, id, recordedAt)
}

export function trustedKeySet(): TrustedKeyEntry[] {
  return assertTrustedKeySetConfigured(process.env as ReceiptKeyEnv)
}
