// ══════════════════════════════════════════════════════════════
// The four canonical actions that have no legacy form
// ══════════════════════════════════════════════════════════════
// withdraw_request, withdraw_interest, withdraw_contact, and standalone block_pair.
// No 3.2.x client can send any of them, because the tools do not exist in the
// published surface, so there is no adapter here, no legacy_unbound path and no
// cutoff to apply. They are canonical from the first day.
//
// They live in their own module rather than in intros-routes.ts because that file is
// the legacy lane and stays readable as one. Every route here is canonical only, and
// the adapters land beside their legacy handlers in the next step.
//
// THE RESOURCE COMES FROM THE SIGNED ENVELOPE AND NOWHERE ELSE. None of these paths
// carries an :id parameter. A path id would be a second, unsigned copy of the
// resource identity, and the only interesting question about it would be what
// happens when the two disagree. With one copy there is no such question.
//
// withdraw_request also fixes a live product defect. hasPendingBetween at
// intros-db.ts:88-94 is bidirectional and unbounded, so today one unanswered request
// permanently stops a pair from requesting again in either direction, with no way
// out. Materializing status = 'withdrawn' is what makes that query stop matching.

import { Router } from 'express'
import * as introsDb from './intros-db.js'
import { getDb } from './db.js'
import { canonicalWriteRoute, refuseWrite } from './write-pipeline.js'
import type { CanonicalContext } from './write-pipeline.js'
import { recordCanonicalEvidence } from './write-evidence.js'
import { cardPairResourceId } from './write-envelope.js'
import {
  introFacts, authorizationOf, recordAuthorization, withdrawAuthorization,
  withdrawArtifacts, materializeStatus, isReleased, contactsExchanged,
  grandfatheredRequestOpen,
} from './connection-facts.js'
import { deriveIntroState, isWriteAllowedInState, guardRefusal } from './connection-state.js'
import type { IntroFacts, IntroState, Operation } from './connection-state.js'

const router = Router()

/** The approved fresh review copy for a block, to be shown before signing and used
 *  verbatim. Exported so the one string has one home and a test can hold it to the
 *  character.
 *
 *  It names cards rather than people, because the block is keyed on two card ids at
 *  intros-db.ts:76-79 and a v3 card carries a 21 day default TTL at v3-cards.ts:29,
 *  so it does not follow a person who publishes a new card. Subject level blocking is
 *  Stage 4, and the copy must not imply the mechanism reaches further than it does. */
export const BLOCK_PAIR_REVIEW_COPY = "You won't be matched or introduced through these two cards again."

// ── Shared guards ─────────────────────────────────────────────────────────

/** Load the facts for one intro, or refuse. */
function factsOrRefuse(introId: string): IntroFacts {
  const facts = introFacts(introId)
  if (facts === null) refuseWrite(404, 'intro_not_found', 'no such introduction')
  return facts as IntroFacts
}

/** The standing state guard, run against the derivation rather than against any
 *  stored column, with the refusal code the matrix decided for this pair. */
function guardState(operation: Operation, facts: IntroFacts, now: Date): IntroState {
  const state = deriveIntroState(facts, now)
  if (!isWriteAllowedInState(operation, state)) {
    const r = guardRefusal(operation, state)
    refuseWrite(409, r.code, r.error)
  }
  return state
}

function requireParty(facts: IntroFacts, actorKey: string, want: 'requester' | 'target' | 'either'): void {
  const isFrom = actorKey === facts.from_key
  const isTo = actorKey === facts.to_key
  if (want === 'requester' && !isFrom) refuseWrite(403, 'not_the_requester', 'only the requester may withdraw its own request')
  if (want === 'target' && !isTo) refuseWrite(403, 'not_the_target', 'only the target may withdraw its own interest')
  if (want === 'either' && !isFrom && !isTo) refuseWrite(403, 'not_a_party', 'only a party to this introduction may act on it')
}

/** Blank this actor's own stored contact column, and never the counterparty's. That
 *  asymmetry is the decision: a withdrawal removes what the withdrawer authorized. */
function blankOwnContact(facts: IntroFacts, actorKey: string): void {
  const column = actorKey === facts.from_key ? 'from_contact' : 'to_contact'
  getDb().prepare(`UPDATE v3_intros SET ${column} = NULL WHERE id = ?`).run(facts.intro_id)
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    refuseWrite(400, 'malformed_payload', `${field} must be a non empty string`)
  }
  return value as string
}

// ── POST /withdraw-request ────────────────────────────────────────────────

router.post('/withdraw-request', canonicalWriteRoute({
  operations: ['withdraw_request'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    const introId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key
    const facts = factsOrRefuse(introId)
    requireParty(facts, actorKey, 'requester')

    const antecedent = authorizationOf(introId, actorKey, 'request_intro')

    // An already withdrawn request answers with its own code rather than with the
    // terminal-state refusal, because the caller's situation is specific and a fresh
    // envelope for an act already done is a state answer, not a replay answer.
    if (antecedent !== null && antecedent.live !== 1) {
      refuseWrite(409, 'already_withdrawn', 'this request was already withdrawn')
    }
    // No canonical antecedent at all. Allowed only for a pre-2A row whose legacy
    // request is still open, which ends the grandfathered path cleanly, and refused
    // otherwise so nobody can retract a request that was never recorded.
    const grandfathered = antecedent === null
    if (grandfathered && !grandfatheredRequestOpen(introId)) {
      refuseWrite(409, 'no_open_request', 'this introduction carries no open request to withdraw')
    }
    guardState('withdraw_request', facts, now)

    const evidenceId = recordCanonicalEvidence(write)
    if (grandfathered) {
      // Recorded as legacy_unbound, because that is what authorized the REQUEST. The
      // withdrawal itself is canonical and its own evidence row says so. Labelling
      // this row 'canonical' would manufacture canonical evidence for an act that was
      // never canonically signed, which is the one thing the adapters may never do.
      recordAuthorization({ introId, actorKey, operation: 'request_intro', evidenceId, evidence: 'legacy_unbound' })
    }
    if (!withdrawAuthorization({ introId, actorKey, operation: 'request_intro', withdrawnBy: write.writeRef })) {
      refuseWrite(409, 'already_withdrawn', 'this request was already withdrawn')
    }
    const state = materializeStatus(introId, now)
    return { intro_id: introId, state, grandfathered }
  },
}))

// ── POST /withdraw-interest ───────────────────────────────────────────────

router.post('/withdraw-interest', canonicalWriteRoute({
  operations: ['withdraw_interest'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    const introId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key
    const facts = factsOrRefuse(introId)
    requireParty(facts, actorKey, 'target')

    // Read the release inside this transaction, which is what makes the race in
    // section 14.2 answerable. Once contacts are released Mingle never pretends they
    // can be unshared.
    if (isReleased(introId)) {
      refuseWrite(409, 'contact_already_released',
        'contacts were released, and Mingle does not pretend a released contact can be unshared')
    }
    guardState('withdraw_interest', facts, now)
    if (!withdrawAuthorization({ introId, actorKey, operation: 'express_interest', withdrawnBy: write.writeRef })) {
      refuseWrite(409, 'already_withdrawn', 'this interest was already withdrawn')
    }
    // The contact authorization goes with it, as defence in depth rather than as a
    // reachable path. The guard above already refuses withdraw_interest in connecting
    // with connection_in_progress, and a live share_contact IS a live continuation, so
    // under the current matrix this cannot fire. It stays because the invariant it
    // protects has to hold structurally: a live contact authorization under a withdrawn
    // interest would let the other side's share complete a connection this actor had
    // backed out of, and that must not depend on a guard table staying exactly as it is.
    //
    // Item 6 of withdraw_interest describes the cascade as the normal path and section
    // 14.4 rule 3 refuses the act outright. 14.4 wins: allowing it would let an intro
    // derive withdrawn by rule 3 while continuations are live, so rule 5 could never be
    // reached. The product path is withdraw_contact, then withdraw_interest.
    const alsoContact = withdrawAuthorization({ introId, actorKey, operation: 'share_contact', withdrawnBy: write.writeRef })
    if (alsoContact) {
      blankOwnContact(facts, actorKey)
      withdrawArtifacts(introId, actorKey, 'share_contact')
    }
    recordCanonicalEvidence(write)
    const state = materializeStatus(introId, now)
    return { intro_id: introId, state, contact_authorization_withdrawn: alsoContact }
  },
}))

// ── POST /withdraw-contact ────────────────────────────────────────────────

router.post('/withdraw-contact', canonicalWriteRoute({
  operations: ['withdraw_contact'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    const introId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key
    const facts = factsOrRefuse(introId)
    requireParty(facts, actorKey, 'either')

    // The release check and the withdrawal write are in ONE transaction. Split them
    // and there is a window where a withdrawal succeeds against a release that has
    // already happened, which would leave Mingle claiming a contact was not released
    // when it was. Refusing rolls the whole transaction back including the nonce
    // reservation, so the refusal costs the caller nothing.
    if (isReleased(introId)) {
      refuseWrite(409, 'contact_already_released',
        'contacts were released, and Mingle does not pretend a released contact can be unshared')
    }
    guardState('withdraw_contact', facts, now)
    if (!withdrawAuthorization({ introId, actorKey, operation: 'share_contact', withdrawnBy: write.writeRef })) {
      refuseWrite(409, 'no_contact_authorization', 'this key holds no live contact authorization on this introduction')
    }
    blankOwnContact(facts, actorKey)
    const artifacts = withdrawArtifacts(introId, actorKey, 'share_contact')
    recordCanonicalEvidence(write)
    // The state is recomputed, not assigned. If another continuation is live it stays
    // connecting; if the withdrawn contact was the only one it regresses to
    // interested.
    const state = materializeStatus(introId, now)
    return { intro_id: introId, state, artifacts_withdrawn: artifacts }
  },
}))

// ── POST /block-pair ──────────────────────────────────────────────────────

router.post('/block-pair', canonicalWriteRoute({
  operations: ['block_pair'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    const actorKey = write.envelope.actor_key
    const payload = write.payload

    // Payload shape. Exactly three fields, so nothing rides along inside the digest
    // unexamined.
    const keys = Object.keys(payload).sort()
    if (keys.length !== 3 || keys[0] !== 'card_a' || keys[1] !== 'card_b' || keys[2] !== 'intro_id') {
      refuseWrite(400, 'malformed_payload', 'block_pair payload carries exactly card_a, card_b and intro_id')
    }
    const cardA = requireString(payload.card_a, 'card_a')
    const cardB = requireString(payload.card_b, 'card_b')
    const introId = requireString(payload.intro_id, 'intro_id')
    if (cardA === cardB) refuseWrite(400, 'malformed_payload', 'a pair is two different cards')
    if ([cardA, cardB].sort()[0] !== cardA) {
      refuseWrite(400, 'malformed_payload', 'card_a and card_b must be in sorted order')
    }

    // Check 1. The signed resource id recomputes from the readable payload. Without
    // it the id and the named pair could differ, and the id is what the nonce store,
    // the evidence row and anti-downgrade all key on.
    if (cardPairResourceId(cardA, cardB) !== write.envelope.resource.id) {
      refuseWrite(400, 'resource_id_mismatch', 'resource.id is not the hash of this card pair')
    }

    // Check 2. The pair matches the intro. Without it, a signature naming one intro
    // would authorize a block on any two cards the signer chose to list, and check 1
    // would still pass because the id is derived from those same two cards.
    const facts = factsOrRefuse(introId)
    const row = introsDb.getIntro(introId) as introsDb.IntroRow
    const introPair = [row.from_card, row.to_card].sort()
    if (introPair[0] !== cardA || introPair[1] !== cardB) {
      refuseWrite(400, 'pair_not_in_intro', 'the named introduction is not between these two cards')
    }

    // Check 3. The actor is a party to that intro. Nothing about a card pair
    // identifies who may act on it, so this is the only check that establishes it.
    requireParty(facts, actorKey, 'either')
    guardState('block_pair', facts, now)

    const evidenceId = recordCanonicalEvidence(write)
    introsDb.addBlock(cardA, cardB)

    // The branch, and it is the whole mechanism for the decided rule that a block
    // after a connection does not rewrite connected. The derivation needs no
    // exception and gets none.
    if (contactsExchanged(introId)) {
      // No intro level fact, so rule 2 finds no blocked fact, rule 1 has already
      // matched, and the intro stays connected. No materialization either: nothing
      // changed at the intro level, and the column is the one place a block could
      // still overwrite a finished connection.
      return {
        intro_id: introId, pair_blocked: true, intro_ended: false,
        state: deriveIntroState(facts, now), review_copy: BLOCK_PAIR_REVIEW_COPY,
      }
    }
    recordAuthorization({ introId, actorKey, operation: 'block_pair', evidenceId, evidence: 'canonical' })
    return {
      intro_id: introId, pair_blocked: true, intro_ended: true,
      state: materializeStatus(introId, now), review_copy: BLOCK_PAIR_REVIEW_COPY,
    }
  },
}))

export default router
