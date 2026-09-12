// ══════════════════════════════════════════════════════════════
// mingle-write-v1: parse, shape, digest, signature, freshness
// ══════════════════════════════════════════════════════════════
// Pure. No database, no Express, no side effect of any kind. It takes a wire body
// and returns either a rejection with a code or a verified envelope with its
// write_ref. Everything that touches state happens after this module has said yes.
//
// The check order is fixed, and the order is the security property:
//
//   1 parse and shape          cheap, and rejects junk before any crypto
//   2 payload gate             null, control characters, non finite numbers
//   3 recompute payload_digest a payload swapped in flight dies here
//   4 verify the signature     over JCS(envelope)
//   5 freshness                10 minutes past, 2 minutes future
//
// Signature before freshness is deliberate. A caller who cannot produce a valid
// signature learns only that the signature failed, and never anything about the
// server's clock tolerance. The crypto cost is bounded because express.json caps
// the body at 100kb.
//
// payload_digest recomputation before signature verification is also deliberate,
// and it is the cheaper of the two orders: a tampered payload is caught by one
// hash rather than by one hash plus one Ed25519 verify, and the digest comparison
// leaks nothing a caller did not already send.
//
// The opening (value, salt) behind a private_value_commitment is verified in step
// 7 of the pipeline, not here, because it needs the payload schema for the
// operation. This module only establishes that the envelope is authentic.

import { verify } from 'agent-passport-system'
import { jcs, sha256Hex, checkCanonicalPayload, isValidNonce } from './canonical-write.js'
import { OPERATIONS, PROTOCOL_OPERATIONS } from './connection-state.js'
import type { Operation } from './connection-state.js'

export const WRITE_DOMAIN = 'mingle-write-v1'
export const PAYLOAD_DOMAIN = 'mingle-payload-v1'
export const PRIVATE_VALUE_DOMAIN = 'mingle-private-value-v1'

/** Operations an envelope may name: the thirteen product actions plus every protocol
 *  sub-action. One list, built from the two the lifecycle module owns, so an operation
 *  cannot exist for the guard matrix and not for the wire, or the other way round. */
export const ENVELOPE_OPERATIONS: readonly Operation[] = [...OPERATIONS, ...PROTOCOL_OPERATIONS] as const

export const RESOURCE_TYPES = ['intro', 'intro_request', 'card_pair', 'card', 'fit_exchange'] as const
export type ResourceType = typeof RESOURCE_TYPES[number]

/** The resource type each operation names, which the design fixes exactly: a create
 *  names the request it is idempotent on, a block names the pair, and every other
 *  act names the intro.
 *
 *  Enforced here rather than per route, because it is a property of the protocol and
 *  not of a path. Without it an envelope could name `operation: "withdraw_request"`
 *  against `resource: { type: "card_pair" }`, pass every shape check, verify, and
 *  land on whichever route accepted the operation. Then two envelopes for the same
 *  act would carry two different resource identities, and anti-downgrade, evidence
 *  and the nonce store all key on that identity. */
export const OPERATION_RESOURCE_TYPE: Record<Operation, ResourceType> = {
  request_intro: 'intro_request',
  block_pair: 'card_pair',
  withdraw_request: 'intro',
  express_interest: 'intro',
  decline: 'intro',
  withdraw_interest: 'intro',
  share_contact: 'intro',
  withdraw_contact: 'intro',
  fit_request: 'intro',
  fit_commit: 'intro',
  fit_round2: 'intro',
  fit_answers: 'intro',
  // The v3 fit exchange is its own resource. It has its own 72 hour window, its own
  // parties and its own state machine, and an act on it is not an act on the intro even
  // though an exchange belongs to one. Naming the intro instead would put two different
  // resources behind one identity, and the nonce store, the evidence rows and
  // anti-downgrade all key on that identity.
  fit_exchange_round2: 'fit_exchange',
  fit_exchange_custom: 'fit_exchange',
  fit_exchange_answers: 'fit_exchange',
  fit_exchange_close: 'fit_exchange',
  // Card scoped. Autonomy is a property of a card's standing policy, not of any one
  // introduction, so the resource is the card and the pause applies wherever that card acts.
  autonomy_pause: 'card',
  release_exact: 'intro',
  first_step_propose: 'intro',
  first_step_approve: 'intro',
}

/** The two operations that carry a private value, so the two that require an
 *  `opening` beside the payload and refuse one anywhere else. */
export const PRIVATE_VALUE_OPERATIONS: readonly Operation[] = ['share_contact', 'release_exact'] as const

export const FRESHNESS_PAST_MS = 10 * 60 * 1000
export const FRESHNESS_FUTURE_MS = 2 * 60 * 1000

export interface Resource { type: ResourceType; id: string }

export interface WriteEnvelope {
  domain: typeof WRITE_DOMAIN
  operation: Operation
  actor_key: string
  resource: Resource
  issued_at: string
  nonce: string
  payload_digest: string
}

export interface WireBody {
  envelope?: unknown
  signature?: unknown
  payload?: unknown
  opening?: unknown
}

export interface VerifiedWrite {
  envelope: WriteEnvelope
  signature: string
  payload: Record<string, unknown>
  opening: { value: unknown; salt: string } | null
  /** SHA-256 of JCS(envelope). Identifies this exact signed act. */
  writeRef: string
  /** The exact bytes signed, retained so evidence can store them verbatim. */
  envelopeBytes: string
}

export type EnvelopeRejection =
  | 'malformed_body'
  | 'unknown_envelope_domain'
  | 'unknown_operation'
  | 'malformed_actor_key'
  | 'unknown_resource_type'
  | 'resource_type_mismatch'
  | 'malformed_resource_id'
  | 'malformed_issued_at'
  | 'malformed_nonce'
  | 'malformed_payload_digest'
  | 'unexpected_envelope_field'
  | 'missing_signature'
  | 'malformed_signature'
  | 'payload_digest_mismatch'
  | 'signature_invalid'
  | 'stale_authorization'
  | 'unexpected_opening'
  | 'missing_opening'
  | 'malformed_opening'
  | 'commitment_mismatch'
  // Forwarded from the payload gate, so a caller sees which rule refused.
  | 'null_in_payload'
  | 'non_finite_number'
  | 'unsupported_value'
  | 'control_character'
  | 'edge_whitespace'
  | 'malformed_unicode'
  | 'payload_too_deep'

export type EnvelopeResult =
  | { ok: true; write: VerifiedWrite }
  | { ok: false; status: number; code: EnvelopeRejection; error: string }

/** Exported so a recipient-side verifier can apply the SAME unknown-field rule the server
 *  applies. A verifier weaker than the server endorses what the server would refuse. */
export const ENVELOPE_FIELDS = ['domain', 'operation', 'actor_key', 'resource', 'issued_at', 'nonce', 'payload_digest'] as const
const HEX64 = /^[0-9a-f]{64}$/
const SIG_HEX = /^[0-9a-f]{128}$/
// ISO 8601 with milliseconds and a literal Z. One shape, so two implementations
// cannot disagree about what a timestamp means.
const ISO_MS_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const RESOURCE_ID_RE = /^[A-Za-z0-9_.:@+-]{1,200}$/

function bad(status: number, code: EnvelopeRejection, error: string): EnvelopeResult {
  return { ok: false, status, code, error }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== 'object') return false
  const proto = Object.getPrototypeOf(v)
  return proto === Object.prototype || proto === null
}

/** Verify a wire body. Pure, and the only way into the canonical write path. */
export function verifyWriteBody(body: WireBody | unknown): EnvelopeResult {
  // ── 1. Parse and shape ──
  if (!isPlainObject(body)) return bad(400, 'malformed_body', 'the request body must be a JSON object')
  const { envelope, signature, payload, opening } = body as WireBody

  const extraTop = Object.keys(body).filter(k => !['envelope', 'signature', 'payload', 'opening'].includes(k))
  if (extraTop.length > 0) {
    return bad(400, 'malformed_body', `unexpected top level field: ${extraTop.join(', ')}`)
  }
  if (!isPlainObject(envelope)) return bad(400, 'malformed_body', 'envelope must be an object')
  if (typeof signature !== 'string' || signature.length === 0) return bad(400, 'missing_signature', 'signature required')
  // The SHAPE, not only the presence. The APS verifier decodes with parseInt per byte pair,
  // which accepts uppercase, whitespace and a sign and truncates at the first non-hex
  // character, so many distinct strings decode to the same 64 bytes and all of them verify.
  // Evidence stores the string verbatim and promises a later reader can re-verify it without
  // trusting the row, and a strict hex decoder in another language rejects those spellings.
  // One shape, so the stored bytes mean the same thing everywhere.
  if (!SIG_HEX.test(signature)) {
    return bad(400, 'malformed_signature', 'signature must be 128 lowercase hex characters')
  }
  if (!isPlainObject(payload)) return bad(400, 'malformed_body', 'payload must be an object')

  // Refusing an unknown envelope field matters, and the danger is concrete. JCS
  // serializes whatever is present, so an extra key changes the signed bytes and
  // the signature still verifies. A server that ignored unknown keys would accept
  // the envelope as valid while ignoring what the field means, and if that field
  // ever narrows authority (a scope, an expiry, a counterparty restriction) the
  // server grants more than the signer authorized while the signature says the
  // signer asked for it. The domain string catches a future v2 envelope. It does
  // not catch a v1 envelope carrying an extra field, which is this case.
  const extra = Object.keys(envelope).filter(k => !(ENVELOPE_FIELDS as readonly string[]).includes(k))
  if (extra.length > 0) {
    return bad(400, 'unexpected_envelope_field', `unexpected envelope field: ${extra.join(', ')}`)
  }
  const missing = ENVELOPE_FIELDS.filter(k => envelope[k] === undefined)
  if (missing.length > 0) {
    return bad(400, 'malformed_body', `envelope is missing: ${missing.join(', ')}`)
  }

  if (envelope.domain !== WRITE_DOMAIN) {
    return bad(400, 'unknown_envelope_domain', `envelope domain must be ${WRITE_DOMAIN}`)
  }
  if (typeof envelope.operation !== 'string' || !(ENVELOPE_OPERATIONS as readonly string[]).includes(envelope.operation)) {
    return bad(400, 'unknown_operation', 'envelope operation is not a Mingle write operation')
  }
  const operation = envelope.operation as Operation
  if (typeof envelope.actor_key !== 'string' || !HEX64.test(envelope.actor_key)) {
    return bad(400, 'malformed_actor_key', 'actor_key must be 64 lowercase hex characters')
  }
  if (!isPlainObject(envelope.resource)) return bad(400, 'unknown_resource_type', 'resource must be an object')
  const resource = envelope.resource as Record<string, unknown>
  const resKeys = Object.keys(resource)
  if (resKeys.length !== 2 || !resKeys.includes('type') || !resKeys.includes('id')) {
    return bad(400, 'malformed_resource_id', 'resource must carry exactly type and id')
  }
  if (typeof resource.type !== 'string' || !(RESOURCE_TYPES as readonly string[]).includes(resource.type)) {
    return bad(400, 'unknown_resource_type', `resource.type must be one of ${RESOURCE_TYPES.join(', ')}`)
  }
  if (typeof resource.id !== 'string' || !RESOURCE_ID_RE.test(resource.id)) {
    return bad(400, 'malformed_resource_id', 'resource.id is not a well formed identifier')
  }
  const wantType = OPERATION_RESOURCE_TYPE[operation]
  if (resource.type !== wantType) {
    return bad(400, 'resource_type_mismatch', `${operation} names a ${wantType}, not a ${resource.type}`)
  }
  if (typeof envelope.issued_at !== 'string' || !ISO_MS_Z.test(envelope.issued_at)
      || Number.isNaN(Date.parse(envelope.issued_at))
      // The shape alone admits a calendar-invalid instant that V8 silently rolls over, so
      // 2026-02-30 parses as 2026-03-02 and hour 24 as the next midnight. Go, Python and Rust
      // all reject those, which would leave a signed record with no agreed meaning, and hour
      // 24 additionally gives two signable strings for one instant. The round trip is what
      // makes the comment above true.
      || new Date(Date.parse(envelope.issued_at)).toISOString() !== envelope.issued_at) {
    return bad(400, 'malformed_issued_at', 'issued_at must be ISO 8601 with milliseconds and a trailing Z, and must name a real instant')
  }
  if (!isValidNonce(envelope.nonce)) {
    return bad(400, 'malformed_nonce', 'nonce must be unpadded base64url of at least 16 CSPRNG bytes, and never a UUID')
  }
  if (typeof envelope.payload_digest !== 'string' || !HEX64.test(envelope.payload_digest)) {
    return bad(400, 'malformed_payload_digest', 'payload_digest must be 64 lowercase hex characters')
  }

  // ── The opening, shape only. Its arithmetic is step 7 of the pipeline. ──
  const wantsOpening = (PRIVATE_VALUE_OPERATIONS as readonly string[]).includes(operation)
  if (!wantsOpening && opening !== undefined) {
    return bad(400, 'unexpected_opening', `${operation} carries no private value, so it takes no opening`)
  }
  let parsedOpening: { value: unknown; salt: string } | null = null
  if (wantsOpening) {
    if (opening === undefined) {
      return bad(400, 'missing_opening', `${operation} requires an opening carrying the value and its salt`)
    }
    if (!isPlainObject(opening)) return bad(400, 'malformed_opening', 'opening must be an object')
    const oKeys = Object.keys(opening)
    if (oKeys.length !== 2 || !oKeys.includes('value') || !oKeys.includes('salt')) {
      return bad(400, 'malformed_opening', 'opening must carry exactly value and salt')
    }
    if (typeof opening.salt !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(opening.salt)) {
      return bad(400, 'malformed_opening', 'opening.salt must be 32 CSPRNG bytes as unpadded base64url')
    }
    parsedOpening = { value: (opening as any).value, salt: opening.salt }
  }

  // ── 2. The payload gate, before any crypto ──
  // tsconfig runs with strictNullChecks off, so a boolean-literal discriminant does
  // not narrow the union on the failure branch. Name the failure type.
  type GateFail = { ok: false; code: string; path: string; error: string }
  const gate = checkCanonicalPayload(payload)
  if (gate.ok !== true) {
    const g = gate as GateFail
    return bad(400, g.code as EnvelopeRejection, g.error)
  }
  // The opening travels outside the signed payload, so it is gated separately.
  if (parsedOpening !== null) {
    const og = checkCanonicalPayload({ value: parsedOpening.value, salt: parsedOpening.salt })
    if (og.ok !== true) {
      const g = og as GateFail
      return bad(400, g.code as EnvelopeRejection, `opening: ${g.error}`)
    }
  }

  // ── 3. Recompute payload_digest ──
  const recomputed = sha256Hex(jcs({
    domain: PAYLOAD_DOMAIN,
    operation,
    resource: { type: resource.type, id: resource.id },
    payload,
  }))
  if (recomputed !== envelope.payload_digest) {
    return bad(400, 'payload_digest_mismatch',
      'payload does not match the payload_digest inside the signed envelope')
  }

  // ── 4. Verify the signature over JCS(envelope) ──
  const clean: WriteEnvelope = {
    domain: WRITE_DOMAIN,
    operation,
    actor_key: envelope.actor_key,
    resource: { type: resource.type as ResourceType, id: resource.id },
    issued_at: envelope.issued_at,
    nonce: envelope.nonce as string,
    payload_digest: envelope.payload_digest,
  }
  const envelopeBytes = jcs(clean)
  let valid = false
  try {
    valid = verify(envelopeBytes, signature, clean.actor_key)
  } catch {
    valid = false
  }
  if (!valid) return bad(403, 'signature_invalid', 'the envelope signature does not verify under actor_key')

  return {
    ok: true,
    write: {
      envelope: clean,
      signature,
      payload: payload as Record<string, unknown>,
      opening: parsedOpening,
      writeRef: sha256Hex(envelopeBytes),
      envelopeBytes,
    },
  }
}

/** Step 5 of the check order, separate so a caller can order it explicitly and a
 *  test can drive it with a fixed clock. */
export function checkFreshness(envelope: WriteEnvelope, now: Date = new Date()): EnvelopeResult | null {
  const issued = Date.parse(envelope.issued_at)
  const age = now.getTime() - issued
  if (age > FRESHNESS_PAST_MS) {
    return bad(401, 'stale_authorization', 'issued_at is more than 10 minutes in the past')
  }
  if (age < -FRESHNESS_FUTURE_MS) {
    return bad(401, 'stale_authorization', 'issued_at is more than 2 minutes in the future')
  }
  return null
}

/** The signed resource id for a card pair: the two card ids sorted by UTF-16 code
 *  unit, then JCS, then SHA-256.
 *
 *  Hashed rather than joined so the signed id has a fixed shape and no separator
 *  question. The internal storage key at intros-db.ts:78 stays exactly as it is, a
 *  raw NUL join, so no stored block row changes and isBlocked keeps working. This
 *  form exists only inside signed bytes. */
export function cardPairResourceId(cardA: string, cardB: string): string {
  const sorted = [cardA, cardB].sort()
  return sha256Hex(jcs(sorted))
}

/** The commitment behind a private value. Binds operation and resource as well as
 *  the value, so a commitment lifted from one act cannot be replayed into another
 *  even before the envelope's own binding is considered. */
export function privateValueCommitment(operation: Operation, resource: Resource, salt: string, value: unknown): string {
  return sha256Hex(jcs({ domain: PRIVATE_VALUE_DOMAIN, operation, resource, salt, value }))
}

/** Step 7 of the pipeline: the opening must recompute to the commitment inside
 *  the signed payload, before any write. */
export function verifyOpening(write: VerifiedWrite, commitmentField = 'private_value_commitment'): EnvelopeResult | null {
  if (write.opening === null) return null
  const claimed = write.payload[commitmentField]
  if (typeof claimed !== 'string' || !HEX64.test(claimed)) {
    return bad(400, 'malformed_opening', `payload.${commitmentField} must be 64 lowercase hex characters`)
  }
  const recomputed = privateValueCommitment(
    write.envelope.operation, write.envelope.resource, write.opening.salt, write.opening.value,
  )
  if (recomputed !== claimed) {
    // Its OWN code, not payload_digest_mismatch. The payload digest matched: what failed is
    // the commitment, and a caller that cannot tell those apart cannot tell a proxy that
    // rewrote the value from a client that built the envelope wrong.
    return bad(400, 'commitment_mismatch', 'the opening does not recompute to the commitment in the signed payload')
  }
  return null
}

/** Build an envelope and sign it. Exported for tests and for the 2C client to
 *  mirror, so the two repos cannot disagree about the byte layout. */
export function buildEnvelope(args: {
  operation: Operation
  actorKey: string
  resource: Resource
  issuedAt: string
  nonce: string
  payload: Record<string, unknown>
}): { envelope: WriteEnvelope; envelopeBytes: string; writeRef: string; payloadDigest: string } {
  const payloadDigest = sha256Hex(jcs({
    domain: PAYLOAD_DOMAIN, operation: args.operation, resource: args.resource, payload: args.payload,
  }))
  const envelope: WriteEnvelope = {
    domain: WRITE_DOMAIN,
    operation: args.operation,
    actor_key: args.actorKey,
    resource: args.resource,
    issued_at: args.issuedAt,
    nonce: args.nonce,
    payload_digest: payloadDigest,
  }
  const envelopeBytes = jcs(envelope)
  return { envelope, envelopeBytes, writeRef: sha256Hex(envelopeBytes), payloadDigest }
}
