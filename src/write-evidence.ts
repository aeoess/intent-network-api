// ══════════════════════════════════════════════════════════════
// The evidence recorder, and bound_fields as the overclaim guard
// ══════════════════════════════════════════════════════════════
// One row per accepted write, canonical or legacy, and one column that does the
// real work: bound_fields_json names every semantic field the recorded signature
// actually covers.
//
// A receipt renderer reads that list and emits only clauses whose fields appear in
// it. That makes "a receipt never claims more authorization than principal-signed
// evidence establishes" mechanical rather than a matter of care, which is the
// difference between this and fit-v4-routes.ts:238, where a server-signed sentence
// names dimensions, disclosure levels, a policy hash and a purpose and four of the
// six clauses are warranted by nothing.
//
// The bound field list is computed HERE from the operation and the evidence kind.
// It is never passed in by a caller, because a caller that can name its own bound
// fields is a caller that can overclaim.

import { randomBytes } from 'node:crypto'
import { getDb } from './db.js'
import type { AuthEvidence } from './write-db.js'
import type { VerifiedWrite } from './write-envelope.js'
import type { Operation } from './connection-state.js'

/** What a canonical envelope's signature covers, per operation.
 *
 *  `operation` and `resource.id` are always covered because they are envelope
 *  fields. Everything else listed here is a payload field, covered through
 *  payload_digest. */
const CANONICAL_BOUND: Record<Operation, string[]> = {
  request_intro: ['operation', 'resource.id', 'payload.from_card', 'payload.to_card', 'payload.purpose', 'payload.note'],
  withdraw_request: ['operation', 'resource.id'],
  express_interest: ['operation', 'resource.id'],
  decline: ['operation', 'resource.id'],
  block_pair: ['operation', 'resource.id', 'payload.card_a', 'payload.card_b', 'payload.intro_id'],
  withdraw_interest: ['operation', 'resource.id'],
  share_contact: ['operation', 'resource.id', 'payload.private_value_commitment'],
  withdraw_contact: ['operation', 'resource.id'],
  fit_request: ['operation', 'resource.id', 'payload.requested_dimensions', 'payload.reciprocal_offer', 'payload.predicate_version', 'payload.policy_commitment', 'payload.query_budget'],
  fit_commit: ['operation', 'resource.id', 'payload.accept_dimensions', 'payload.reciprocal_offer', 'payload.policy_commitment', 'payload.request_write_ref'],
  release_exact: ['operation', 'resource.id', 'payload.dimension', 'payload.policy_commitment', 'payload.private_value_commitment'],
  first_step_propose: ['operation', 'resource.id', 'payload.purpose', 'payload.next_action', 'payload.meeting_length', 'payload.agenda', 'payload.each_wants', 'payload.boundaries', 'payload.expiry'],
  first_step_approve: ['operation', 'resource.id', 'payload.approved_digest'],
  fit_round2: ['operation', 'resource.id', 'payload.dimension_ids', 'payload.antecedent_write_ref'],
  fit_exchange_round2: ['operation', 'resource.id', 'payload.question_ids', 'payload.antecedent_write_ref'],
  fit_exchange_custom: ['operation', 'resource.id', 'payload.questions'],
}

/** What a published 3.2.2 legacy preimage covers, per operation, taken from the
 *  tarball's build/index.js. These lists are deliberately short. A legacy accept
 *  signs `intro-respond:${id}:${action}:${nonce}` and attaches the contact
 *  separately, so `contact` is absent here and no receipt can name it. */
const LEGACY_BOUND: Partial<Record<Operation, string[]>> = {
  request_intro: ['from_card', 'to_card', 'purpose'],
  express_interest: ['id', 'action'],
  decline: ['id', 'action'],
  block_pair: ['id', 'action'],
  share_contact: ['id'],
  fit_request: ['intro_id'],
  fit_commit: ['intro_id'],
  release_exact: ['intro_id', 'dimension'],
  first_step_propose: ['intro_id'],
  first_step_approve: ['intro_id', 'approved_digest'],
  // `id` is the EXCHANGE id here, which is what fit-round2:${id}:${nonce} interpolates.
  // question_ids is absent because not one character of it is in those bytes.
  fit_exchange_round2: ['id'],
  // Same shape, same omission: fit-custom:${id}:${nonce} covers no character of the text.
  fit_exchange_custom: ['id'],
}

/** The legacy preimage template each adapter accepts, recorded verbatim so a later
 *  reader sees what was actually signed rather than inferring it from the route. */
export const LEGACY_PREIMAGES: Partial<Record<Operation, string>> = {
  request_intro: 'intro-request:${from_card}:${to_card}:${purpose}:${nonce}',
  express_interest: 'intro-respond:${id}:${action}:${nonce}',
  decline: 'intro-respond:${id}:${action}:${nonce}',
  block_pair: 'intro-respond:${id}:${action}:${nonce}',
  share_contact: 'intro-complete:${id}:${nonce}',
  fit_request: 'fit-request:${introId}:${nonce}',
  fit_commit: 'fit-commit:${introId}:${nonce}',
  release_exact: 'fit-reveal:${introId}:${dimension}:${nonce}',
  first_step_propose: 'fit-firststep:${introId}:${nonce}',
  first_step_approve: 'fit-firststep-approve:${introId}:${approved_digest}:${nonce}',
  fit_exchange_round2: 'fit-round2:${id}:${nonce}',
  fit_exchange_custom: 'fit-custom:${id}:${nonce}',
}

export function boundFieldsFor(operation: Operation, evidence: AuthEvidence): string[] {
  if (evidence === 'canonical') return [...(CANONICAL_BOUND[operation] ?? ['operation', 'resource.id'])]
  return [...(LEGACY_BOUND[operation] ?? [])]
}

export interface EvidenceRow {
  evidence_id: string
  write_ref: string | null
  actor_key: string
  operation: string
  resource_type: string
  resource_id: string
  evidence: AuthEvidence
  envelope_json: string | null
  signature: string
  payload_digest: string | null
  bound_fields_json: string
  legacy_preimage: string | null
  recorded_at: string
}

function newEvidenceId(): string {
  return 'ev_' + randomBytes(12).toString('hex')
}

/** Record a canonical write. Stores the exact signed bytes, so a later reader can
 *  re-derive write_ref and re-verify the signature without trusting this row. */
export function recordCanonicalEvidence(write: VerifiedWrite): string {
  const id = newEvidenceId()
  getDb().prepare(`
    INSERT INTO write_evidence
      (evidence_id, write_ref, actor_key, operation, resource_type, resource_id,
       evidence, envelope_json, signature, payload_digest, bound_fields_json, legacy_preimage)
    VALUES (?, ?, ?, ?, ?, ?, 'canonical', ?, ?, ?, ?, NULL)
  `).run(
    id, write.writeRef, write.envelope.actor_key, write.envelope.operation,
    write.envelope.resource.type, write.envelope.resource.id,
    write.envelopeBytes, write.signature, write.envelope.payload_digest,
    JSON.stringify(boundFieldsFor(write.envelope.operation, 'canonical')),
  )
  return id
}

/** Record a legacy write. write_ref is null because there is no envelope, and
 *  bound_fields names only what the old preimage covered.
 *
 *  Canonical evidence is never manufactured from a legacy signature. That is the
 *  entire job of this function being separate from the one above. */
export function recordLegacyEvidence(args: {
  actorKey: string
  operation: Operation
  resourceType: string
  resourceId: string
  signature: string
  preimage?: string
}): string {
  const id = newEvidenceId()
  getDb().prepare(`
    INSERT INTO write_evidence
      (evidence_id, write_ref, actor_key, operation, resource_type, resource_id,
       evidence, envelope_json, signature, payload_digest, bound_fields_json, legacy_preimage)
    VALUES (?, NULL, ?, ?, ?, ?, 'legacy_unbound', NULL, ?, NULL, ?, ?)
  `).run(
    id, args.actorKey, args.operation, args.resourceType, args.resourceId,
    args.signature,
    JSON.stringify(boundFieldsFor(args.operation, 'legacy_unbound')),
    args.preimage ?? LEGACY_PREIMAGES[args.operation] ?? null,
  )
  return id
}

export function evidenceById(id: string): EvidenceRow | null {
  const row = getDb().prepare('SELECT * FROM write_evidence WHERE evidence_id = ?').get(id) as any
  return row ?? null
}

/** One row by its write_ref, which is how a later act names the act it follows. Null for
 *  a legacy row, which has no write_ref, and for a ref that names nothing. */
export function evidenceByWriteRef(writeRef: string): EvidenceRow | null {
  const row = getDb().prepare('SELECT * FROM write_evidence WHERE write_ref = ?').get(writeRef) as any
  return row ?? null
}

export function evidenceForResource(resourceType: string, resourceId: string): EvidenceRow[] {
  return getDb().prepare('SELECT * FROM write_evidence WHERE resource_type = ? AND resource_id = ? ORDER BY recorded_at, evidence_id')
    .all(resourceType, resourceId) as any[]
}

export function boundFieldsOf(row: EvidenceRow): string[] {
  try {
    const parsed = JSON.parse(row.bound_fields_json)
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : []
  } catch {
    return []
  }
}

/** Is this field covered by the signature this row records?
 *
 *  The predicate a receipt renderer calls before emitting a clause. Fail closed:
 *  an unparseable list covers nothing. */
export function covers(row: EvidenceRow, field: string): boolean {
  return boundFieldsOf(row).includes(field)
}
