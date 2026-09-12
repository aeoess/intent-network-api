// ══════════════════════════════════════════════════════════════
// The policy commitment: registration, opening, and what is kept
// ══════════════════════════════════════════════════════════════
// A salted commitment to a Fit Policy, registered once by its owner, that can travel in
// a shared receipt where policy_hash must not.
//
// WHY policy_hash cannot travel. It is an unsalted SHA-256 over a domain small enough to
// enumerate: the widest dimension enum is 7 values, disclosure_state has 5, sensitivity
// 3, importance 4, the tag sets are 2^16, and the only high entropy field is expires_at.
// Today policy_hash_a and policy_hash_b are receipt fields at fit-v4-routes.ts:233,
// returned to both parties and stored. Anyone holding such a receipt can enumerate
// candidate policies and find the one that hashes to it.
//
// The deterministic policy_hash STAYS, unchanged, for the server's own version lookup.
// Changing it would change every stored policy_hash and invalidate every retained
// version. What changes is only what is allowed to leave the server.
//
// THE SALT IS NOT STORED. The owner keeps the policy, the salt, the commitment and its
// signed authorization. The server verifies the opening once at registration and then
// holds only the commitment, so the strongest thing it can say afterwards is that a
// commitment was opened to it once. It cannot recompute one, and it cannot be compelled
// to produce a salt it does not have.
//
// NORMALIZATION SORTS BY CODE UNIT, not localeCompare. policyHash at
// fit-policy-db.ts:99 uses localeCompare, which agrees with code unit order on the
// current ten dimension names and diverges in general: localeCompare is locale and ICU
// dependent, so two servers with different ICU data could disagree about the order and
// therefore about the hash. The existing function is not changed, because changing it
// would change every stored policy_hash. The new commitment does not inherit the problem.

import type { Database } from 'better-sqlite3'
import { getDb } from './db.js'
import { jcs, sha256Hex } from './canonical-write.js'
import * as policyDb from './fit-policy-db.js'

export const POLICY_COMMITMENT_DOMAIN = 'mingle-policy-commitment-v1'

const HEX64 = /^[0-9a-f]{64}$/
const SALT_RE = /^[A-Za-z0-9_-]{43}$/

function d(): Database {
  return getDb()
}

/** The normalized policy the commitment is computed over.
 *
 *  Sorted by code unit and with each dimension's own field set fixed, so two clients that
 *  built the same policy in a different order reach the same commitment. */
export function normalizePolicy(dimensions: policyDb.PolicyDimension[]): unknown[] {
  return [...dimensions]
    .map(x => ({
      dimension: x.dimension,
      value: x.value,
      sensitivity: x.sensitivity,
      disclosure_state: x.disclosure_state,
      allowed_intents: [...x.allowed_intents].sort(),
      expires_at: x.expires_at,
      importance: x.importance,
    }))
    // Code unit order. `<` on strings compares UTF-16 code units, which is what JCS uses
    // for object keys and what a verifier in another language will reproduce.
    .sort((a, b) => (a.dimension < b.dimension ? -1 : a.dimension > b.dimension ? 1 : 0))
}

/** commitment = SHA-256(JCS({domain, salt, policy: normalized})) */
export function policyCommitment(salt: string, dimensions: policyDb.PolicyDimension[]): string {
  return sha256Hex(jcs({
    domain: POLICY_COMMITMENT_DOMAIN,
    salt,
    policy: normalizePolicy(dimensions),
  }))
}

export interface PolicyCommitmentRow {
  card_id: string
  commitment: string
  subject_key: string
  policy_hash: string
  version: number
  registered_at: string
}

export type RegisterFailure =
  | 'malformed_commitment'
  | 'malformed_salt'
  | 'no_policy'
  | 'commitment_mismatch'

export type RegisterResult =
  | { ok: true; row: PolicyCommitmentRow; already: boolean }
  | { ok: false; code: RegisterFailure; error: string }

/** Register a commitment to the card's CURRENT policy, verifying the opening once.
 *
 *  The opening is `{salt}` plus the policy the server already holds: the owner does not
 *  resend the policy body, because the server has it and a resent body could differ from
 *  the stored one. So the only secret in the opening is the salt, and it is verified and
 *  then dropped. */
export function registerPolicyCommitment(args: {
  cardId: string
  subjectKey: string
  commitment: unknown
  salt: unknown
}): RegisterResult {
  if (typeof args.commitment !== 'string' || !HEX64.test(args.commitment)) {
    return { ok: false, code: 'malformed_commitment', error: 'commitment must be 64 lowercase hex characters' }
  }
  if (typeof args.salt !== 'string' || !SALT_RE.test(args.salt)) {
    return { ok: false, code: 'malformed_salt', error: 'salt must be 32 CSPRNG bytes as unpadded base64url' }
  }
  const policy = policyDb.getCurrentPolicy(args.cardId)
  if (policy === null) {
    return { ok: false, code: 'no_policy', error: 'this card has no Fit Policy to commit to' }
  }
  const recomputed = policyCommitment(args.salt, policy.dimensions)
  if (recomputed !== args.commitment) {
    return {
      ok: false, code: 'commitment_mismatch',
      error: 'the salt does not open the commitment against your current policy',
    }
  }
  const existing = commitmentRow(args.cardId, args.commitment)
  if (existing !== null) return { ok: true, row: existing, already: true }

  // The salt is deliberately absent from this INSERT and from the table.
  d().prepare(`
    INSERT INTO policy_commitments (card_id, commitment, subject_key, policy_hash, version)
    VALUES (?, ?, ?, ?, ?)
  `).run(args.cardId, args.commitment, args.subjectKey, policy.policy_hash, policy.version)
  return { ok: true, row: commitmentRow(args.cardId, args.commitment)!, already: false }
}

export function commitmentRow(cardId: string, commitment: string): PolicyCommitmentRow | null {
  return (d().prepare('SELECT * FROM policy_commitments WHERE card_id = ? AND commitment = ?')
    .get(cardId, commitment) as PolicyCommitmentRow) ?? null
}

/** The policy version a registered commitment names, or null when the commitment was
 *  never registered for this card.
 *
 *  This is the lookup a canonical fit act uses: the payload names a commitment, and the
 *  server resolves it to the policy_hash it may then use internally. A commitment that
 *  was never registered resolves to nothing, so an unregistered commitment in a signed
 *  payload is refused rather than trusted. */
export function policyHashForCommitment(cardId: string, commitment: string): string | null {
  return commitmentRow(cardId, commitment)?.policy_hash ?? null
}

/** Does this commitment name the card's CURRENT policy?
 *
 *  A commitment registered against an older version still resolves, which is what lets an
 *  old receipt stay verifiable, but a fit act must use a commitment on the policy in force
 *  now, exactly as the legacy routes require policy_hash to equal the current hash. */
export function commitmentIsCurrent(cardId: string, commitment: string): boolean {
  const row = commitmentRow(cardId, commitment)
  if (row === null) return false
  const policy = policyDb.getCurrentPolicy(cardId)
  return policy !== null && policy.policy_hash === row.policy_hash
}

/** The commitment a receipt should name for one card and one stored policy version.
 *
 *  The handshake stores policy_hash, not the commitment, and no column can be added to it
 *  at this revision. So the receipt renderer resolves back through this table. When an
 *  owner registered two commitments on the same policy version, two different salts over
 *  the same body, the newest wins. Both are equally valid openings of the same policy, so
 *  the choice is arbitrary rather than wrong, and it is deterministic. */
export function commitmentForPolicyHash(cardId: string, policyHash: string): string | null {
  const row = d().prepare(`
    SELECT commitment FROM policy_commitments
    WHERE card_id = ? AND policy_hash = ?
    ORDER BY registered_at DESC, version DESC LIMIT 1
  `).get(cardId, policyHash) as { commitment: string } | undefined
  return row?.commitment ?? null
}

/** Every commitment registered for one card, newest first. For an owner surface and for
 *  the test that asserts no salt is anywhere in the table. */
export function commitmentsForCard(cardId: string): PolicyCommitmentRow[] {
  return d().prepare('SELECT * FROM policy_commitments WHERE card_id = ? ORDER BY registered_at DESC, version DESC')
    .all(cardId) as PolicyCommitmentRow[]
}
