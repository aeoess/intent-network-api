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
  authorizationOf, recordAuthorization, withdrawAuthorization,
  withdrawArtifacts, materializeStatus, isReleased, contactsExchanged,
  PRE_2A_ANTECEDENT,
} from './connection-facts.js'
import { factsForWrite, guardState, requireParty } from './intro-guards.js'
import { closeUnfinishedContinuations } from './continuation-close.js'
import { deriveIntroState } from './connection-state.js'
import type { IntroFacts } from './connection-state.js'

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

// ── Local helpers ─────────────────────────────────────────────────────────

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
    const facts = factsForWrite(introId)
    requireParty(facts, actorKey, 'requester', 'only the requester may withdraw its own request')

    // A pre-2A row's antecedent was bridged by factsForWrite, so there is ONE path here
    // rather than two. That is a simplification the bridge bought: the grandfathered branch
    // this handler used to carry, and the second reader of the legacy column it needed, are
    // both gone.
    const antecedent = authorizationOf(introId, actorKey, 'request_intro')
    if (antecedent === null) {
      refuseWrite(409, 'no_open_request', 'this introduction carries no open request to withdraw')
    }
    // An already withdrawn request answers with its own code rather than with the
    // terminal-state refusal, because the caller's situation is specific and a fresh
    // envelope for an act already done is a state answer, not a replay answer.
    if (antecedent!.live !== 1) {
      refuseWrite(409, 'already_withdrawn', 'this request was already withdrawn')
    }
    // Read the release inside this transaction. A concurrent final contact release that
    // commits first makes the intro `connected`, and the guard below then refuses this
    // withdrawal atomically, so nothing changes. If this commits first, the later release is
    // refused by the terminal guard. Exactly one of the two wins and neither leaves a partial
    // state. A released contact is never retracted by anything.
    if (isReleased(introId)) {
      refuseWrite(409, 'already_connected',
        'contacts were released on this introduction, so there is nothing left to withdraw. Use block_pair to stop future activity between these two cards.')
    }
    guardState('withdraw_request', facts, now)

    recordCanonicalEvidence(write)
    // Not a refusal. Every reachable reason to refuse was checked above, so a failure here
    // is an INVARIANT VIOLATION rather than a caller error and becomes a logged 500 through
    // the pipeline's boundary instead of pretending the caller did something wrong.
    if (!withdrawAuthorization({ introId, actorKey, operation: 'request_intro', withdrawnBy: write.writeRef })) {
      throw new Error(`withdraw_request found no live request_intro row after its checks passed: ${introId}`)
    }
    // ONE ATOMIC TERMINAL OPERATION, per the closure ruling. Permitted in `connecting` now,
    // so the cascade is the normal path rather than defence in depth: the actor's own
    // unreleased contact authorization goes with the withdrawal, and every unfinished
    // continuation is cancelled. All of it is in the transaction that reserved the nonce.
    const alsoContact = withdrawAuthorization({ introId, actorKey, operation: 'share_contact', withdrawnBy: write.writeRef })
    if (alsoContact) {
      blankOwnContact(facts, actorKey)
      withdrawArtifacts(introId, actorKey, 'share_contact')
    }
    const closed = closeUnfinishedContinuations(introId)
    const state = materializeStatus(introId, now)
    return {
      intro_id: introId, state,
      contact_authorization_withdrawn: alsoContact,
      continuations_closed: closed,
      bridged_from_legacy: antecedent!.evidence_id === PRE_2A_ANTECEDENT,
    }
  },
}))

// ── POST /withdraw-interest ───────────────────────────────────────────────

router.post('/withdraw-interest', canonicalWriteRoute({
  operations: ['withdraw_interest'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    const introId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key
    const facts = factsForWrite(introId)
    requireParty(facts, actorKey, 'target', 'only the target may withdraw its own interest')

    // Read the release inside this transaction, which is what makes the race in
    // section 14.2 answerable. Once contacts are released Mingle never pretends they
    // can be unshared.
    // A concurrent final contact release that commits first makes the intro `connected`, and
    // the guard below then refuses this withdrawal atomically, so nothing changes. If this
    // commits first, the later release is refused by the terminal guard. Exactly one of the
    // two wins. A released contact is never retracted by anything.
    if (isReleased(introId)) {
      refuseWrite(409, 'already_connected',
        'contacts were released on this introduction, so there is nothing left to withdraw. Use block_pair to stop future activity between these two cards.')
    }
    guardState('withdraw_interest', facts, now)
    // Read before writing, so every refusal precedes every side effect. The guard above
    // already implies a live interest, because mutual interest is what `interested` means, so
    // this is the specific answer for a caller whose act is already done.
    const interest = authorizationOf(introId, actorKey, 'express_interest')
    if (interest === null || interest.live !== 1) {
      refuseWrite(409, 'already_withdrawn', 'this interest was already withdrawn')
    }
    if (!withdrawAuthorization({ introId, actorKey, operation: 'express_interest', withdrawnBy: write.writeRef })) {
      throw new Error(`withdraw_interest found no live express_interest row after its checks passed: ${introId}`)
    }
    // ONE ATOMIC TERMINAL OPERATION, per the closure ruling. This cascade used to be
    // unreachable defence in depth, because the guard refused the act in `connecting` and a
    // live share_contact IS a live continuation. The ruling permits the act in `connecting`,
    // so it is now the normal path: the actor's own unreleased contact authorization goes
    // with the withdrawal, and every unfinished continuation is cancelled, in the transaction
    // that reserved the nonce.
    //
    // The invariant it protects is unchanged and is why it was written before it could fire:
    // a live contact authorization under a withdrawn interest would let the other side's
    // share complete a connection this actor had backed out of.
    const alsoContact = withdrawAuthorization({ introId, actorKey, operation: 'share_contact', withdrawnBy: write.writeRef })
    if (alsoContact) {
      blankOwnContact(facts, actorKey)
      withdrawArtifacts(introId, actorKey, 'share_contact')
    }
    const closed = closeUnfinishedContinuations(introId)
    recordCanonicalEvidence(write)
    const state = materializeStatus(introId, now)
    return { intro_id: introId, state, contact_authorization_withdrawn: alsoContact, continuations_closed: closed }
  },
}))

// ── POST /withdraw-contact ────────────────────────────────────────────────

router.post('/withdraw-contact', canonicalWriteRoute({
  operations: ['withdraw_contact'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    const introId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key
    const facts = factsForWrite(introId)
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
    // Reachable, and it is the answer for a party who is in a connecting intro because the
    // OTHER side shared. Read first, so the refusal precedes every write.
    const mine = authorizationOf(introId, actorKey, 'share_contact')
    if (mine === null || mine.live !== 1) {
      refuseWrite(409, 'no_contact_authorization', 'this key holds no live contact authorization on this introduction')
    }
    if (!withdrawAuthorization({ introId, actorKey, operation: 'share_contact', withdrawnBy: write.writeRef })) {
      throw new Error(`withdraw_contact found no live share_contact row after its checks passed: ${introId}`)
    }
    blankOwnContact(facts, actorKey)
    const artifacts = withdrawArtifacts(introId, actorKey, 'share_contact')
    recordCanonicalEvidence(write)
    // The state is recomputed, not assigned. If another continuation is live it stays
    // connecting. If the withdrawn contact was the only one it regresses to `interested`,
    // and the deadline is 30 days from the LATER of the interest authorization and this
    // withdrawal, per the closed TTL ruling. So withdrawing your own contact line never
    // expires an introduction that was alive a moment before, which is what it used to do
    // whenever the interest was more than 30 days old. connection-state.ts carries the
    // reasoning and tests/intro-expiry.test.ts carries the regression.
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
    const facts = factsForWrite(introId)
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
