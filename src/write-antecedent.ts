// ══════════════════════════════════════════════════════════════
// antecedent_write_ref: the act this one follows
// ══════════════════════════════════════════════════════════════
// Its own module because it is resource generic. A v3 exchange act names a prior act on
// that exchange and a v4 round two names a prior act on that intro, and the check is the
// same either way, so it belongs to neither module's guards.
//
// WHAT IT CHECKS, exactly, and the claim is deliberately narrower than the one this comment
// used to make. The ref must name a canonical act THIS SERVER RECORDED, on THIS SAME
// RESOURCE, for an operation in the family the caller names. So a signature over a set of
// ids cannot be lifted onto another conversation, and it cannot be satisfied by an act from
// outside the fit conversation it claims to answer: the review found an express_interest
// write_ref, signed before any handshake existed, unblocking a round two.
//
// WHAT IT DOES NOT CHECK, because saying so is the point of a narrow claim. Not the actor,
// deliberately, because a round two answers the COUNTERPARTY's act and naming theirs is the
// natural form. Not ordering, and not recency: it does not establish that the signer was
// answering the CURRENT state of the conversation. Making it the current head is the same
// shape as the close echo and would deliver that property, at the cost of one concurrent act
// invalidating a signature. Recorded for 2C rather than decided here.
//
// Checked by RESOLUTION rather than accepted as an opaque string, because an opaque string
// copied into evidence is a field that looks like a check and is not.

import { refuseWrite } from './write-pipeline.js'
import { evidenceByWriteRef, evidenceForResource } from './write-evidence.js'

/** The intro-scoped acts that belong to a v4 fit conversation. An intro also carries
 *  lifecycle acts, and those are not an antecedent for a fit escalation. */
export const V4_FIT_ANTECEDENTS: readonly string[] = [
  'fit_request', 'fit_commit', 'fit_answers', 'fit_round2', 'release_exact',
  'first_step_propose', 'first_step_approve',
] as const

/** The exchange-scoped acts. Every act on a fit_exchange resource is an exchange act, so
 *  this list is the whole family and the resource check already implies it. Named anyway,
 *  so both call sites pass an explicit family rather than one passing nothing. */
export const V3_EXCHANGE_ANTECEDENTS: readonly string[] = [
  'fit_exchange_answers', 'fit_exchange_round2', 'fit_exchange_custom', 'fit_exchange_close',
] as const

export function requireAntecedent(
  resourceType: string, resourceId: string, writeRef: string, family: readonly string[],
): void {
  const row = evidenceByWriteRef(writeRef)
  if (row === null) {
    refuseWrite(400, 'unknown_antecedent', 'antecedent_write_ref names no write this server recorded')
  }
  const ev = row as { resource_type: string; resource_id: string; operation: string }
  if (ev.resource_type !== resourceType || ev.resource_id !== resourceId) {
    refuseWrite(400, 'antecedent_other_resource',
      'antecedent_write_ref names an act on a different resource, so it cannot place this one in a conversation')
  }
  if (!family.includes(ev.operation)) {
    refuseWrite(400, 'antecedent_not_a_fit_act',
      `antecedent_write_ref names a ${ev.operation}, which is not part of the fit conversation this act claims to answer`)
  }
}

/** The canonical acts on a resource that may serve as an antecedent, for a read surface.
 *  write_ref, operation, actor and time, and nothing about the payload. */
export function canonicalActsOn(resourceType: string, resourceId: string, family: readonly string[]):
  { write_ref: string; operation: string; actor_key: string; recorded_at: string }[] {
  return evidenceForResource(resourceType, resourceId)
    .filter(r => r.evidence === 'canonical' && r.write_ref !== null && family.includes(r.operation))
    .map(r => ({ write_ref: r.write_ref as string, operation: r.operation, actor_key: r.actor_key, recorded_at: r.recorded_at }))
}
