// ══════════════════════════════════════════════════════════════
// mingle-write-v1 canonical serialization and the payload gate
// ══════════════════════════════════════════════════════════════
// Everything a mingle-write-v1 envelope or a new evidence record is hashed or
// signed over goes through jcs() here. Nothing else does.
//
// Why not the APS canonicalize. It deletes object members whose value is null
// (node_modules/agent-passport-system/dist/src/core/canonical.js, the filter on
// Object.keys), so canonicalize({a:1,b:null}) === canonicalize({a:1}). A
// signature over that binds an equivalence class of documents rather than one
// document. Measured against the RFC 8785 reference on a 16 case suite: 13
// agree, 3 differ, and all three differences are that one cause. Restricted to
// payloads with no null the two agree on all 16.
//
// So this module does two things that are never used apart:
//   jcs()                    RFC 8785, from canonicalize@5.0.0
//   assertCanonicalPayload() refuses what a canonical signed payload may not
//                            contain, BEFORE any signature is verified
//
// Both halves are needed and neither replaces the other. The real JCS library is
// for third parties: a verifier in another language reaches for RFC 8785 and has
// to agree with us without knowing our null rule. The gate is for us: a JCS
// library serializes null happily, so {note: null} and {} would be two signable
// payloads meaning the same thing, and that ambiguity is worth refusing.
//
// Legacy preimages are untouched and must stay that way. card_hash
// (v3-cards.ts), approved_hash (fit-routes.ts, fit-v4-routes.ts) and
// sharedDigest (fit-firststep-db.ts) keep the APS canonicalization, because
// changing it would invalidate every published card and every in-flight First
// Step.

import canonicalize from 'canonicalize'
import { createHash, randomBytes } from 'node:crypto'

/** RFC 8785 canonical JSON. The only serializer for mingle-write-v1. */
export function jcs(value: unknown): string {
  const out = canonicalize(value as any)
  if (typeof out !== 'string') {
    throw new CanonicalPayloadError('unsupported_value', 'value is not serializable as canonical JSON')
  }
  return out
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}

/** Digest of a canonical object, the shape every digest in this design uses. */
export function canonicalDigest(value: unknown): string {
  return sha256Hex(jcs(value))
}

// ── Nonces ────────────────────────────────────────────────────────────────
// 16 bytes from a CSPRNG, base64url, never randomUUID. A UUIDv4 carries 122
// random bits because 4 bits are the version and 2 the variant, which is below
// the decided floor, and its shape invites a client to reach for a convenience
// function instead of a CSPRNG.

const NONCE_BYTES = 16

export function newNonce(): string {
  return randomBytes(NONCE_BYTES).toString('base64url')
}

/** 16 to 32 bytes of unpadded base64url, so 22 to 43 characters. A floor, not a
 *  fixed width, because the decision states a minimum. The ceiling only stops an
 *  unbounded field from becoming part of a primary key. */
export const NONCE_RE = /^[A-Za-z0-9_-]{22,43}$/

/** A UUID is 36 characters drawn entirely from the base64url alphabet, so
 *  NONCE_RE alone accepts one. The decision is explicit that a canonical nonce is
 *  never randomUUID, both because a UUIDv4 carries 122 random bits rather than
 *  128 and because reaching for a convenience function is how a client ends up
 *  with a non-CSPRNG generator. Refuse the shape rather than trusting the
 *  caller's word about how it was produced. */
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

/** The predicate a route calls. Shape, plus the UUID exclusion. */
export function isValidNonce(nonce: unknown): boolean {
  return typeof nonce === 'string' && NONCE_RE.test(nonce) && !UUID_RE.test(nonce)
}

// ── The payload gate ──────────────────────────────────────────────────────

export type CanonicalRejection =
  | 'null_in_payload'
  | 'non_finite_number'
  | 'unsupported_value'
  | 'control_character'
  | 'edge_whitespace'
  | 'malformed_unicode'
  | 'payload_too_deep'

export class CanonicalPayloadError extends Error {
  readonly code: CanonicalRejection
  readonly path: string
  constructor(code: CanonicalRejection, message: string, path = '') {
    super(path ? `${message} at ${path}` : message)
    this.name = 'CanonicalPayloadError'
    this.code = code
    this.path = path
  }
}

const MAX_DEPTH = 12

// C0 controls, DEL, and the C1 range. A contact line reaches a plain-text email
// body by interpolation (notifications.ts), and a note reaches a database column
// and that same body, so a newline in either is a way to add lines to a message
// somebody else reads.
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/
// A lone surrogate is not well formed Unicode. JSON.stringify would escape it
// rather than fail, so it has to be refused here or it reaches a signature.
const LONE_SURROGATE_RE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== 'object') return false
  const proto = Object.getPrototypeOf(v)
  return proto === Object.prototype || proto === null
}

function walk(value: unknown, path: string, depth: number): void {
  if (depth > MAX_DEPTH) {
    throw new CanonicalPayloadError('payload_too_deep', `nesting deeper than ${MAX_DEPTH}`, path)
  }
  if (value === null || value === undefined) {
    throw new CanonicalPayloadError('null_in_payload', 'null and undefined are not allowed in a canonical payload', path)
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new CanonicalPayloadError('non_finite_number', 'NaN and Infinity are not allowed', path)
    }
    return
  }
  if (typeof value === 'boolean') return
  if (typeof value === 'string') {
    if (CONTROL_RE.test(value)) {
      throw new CanonicalPayloadError('control_character', 'control characters are not allowed in a signed string', path)
    }
    if (LONE_SURROGATE_RE.test(value)) {
      throw new CanonicalPayloadError('malformed_unicode', 'a lone surrogate is not well formed Unicode', path)
    }
    if (value !== value.trim()) {
      throw new CanonicalPayloadError('edge_whitespace', 'leading or trailing whitespace is not allowed in a signed string', path)
    }
    return
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => walk(v, `${path}[${i}]`, depth + 1))
    return
  }
  if (isPlainObject(value)) {
    for (const k of Object.keys(value)) walk(value[k], path ? `${path}.${k}` : k, depth + 1)
    return
  }
  throw new CanonicalPayloadError('unsupported_value', `${Object.prototype.toString.call(value)} is not allowed in a canonical payload`, path)
}

/** Validate or reject, never repair. Returns the SAME object on success so a
 *  caller cannot accidentally sign a normalized copy: invariant 4 says any
 *  normalization happens before the preview, on the client, and the server's job
 *  is to refuse what it will not store verbatim. */
export function assertCanonicalPayload<T>(payload: T): T {
  walk(payload, '', 0)
  return payload
}

/** Non throwing form, for a route that wants to answer with a code. */
export function checkCanonicalPayload(payload: unknown): { ok: true } | { ok: false; code: CanonicalRejection; path: string; error: string } {
  try {
    assertCanonicalPayload(payload)
    return { ok: true }
  } catch (e) {
    if (e instanceof CanonicalPayloadError) return { ok: false, code: e.code, path: e.path, error: e.message }
    throw e
  }
}
