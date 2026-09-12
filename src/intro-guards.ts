// ══════════════════════════════════════════════════════════════
// The guards every intro write runs, canonical or adapted
// ══════════════════════════════════════════════════════════════
// Three small functions, in one module so the canonical routes and the legacy adapters
// cannot drift apart on who may act and in which state. They all raise WriteRefusal,
// so they are only ever called from inside a canonical write transaction, where a
// refusal rolls everything back.

import { refuseWrite } from './write-pipeline.js'
import { introFacts, bridgePre2AIntro } from './connection-facts.js'
import { deriveIntroState, isWriteAllowedInState, guardRefusal } from './connection-state.js'
import type { IntroFacts, IntroState, Operation } from './connection-state.js'

/** Load the facts for one intro for a WRITE, bridging a pre-2A history first, or refuse.
 *
 *  It writes, and the name says so. An intro created before this build has no authorization
 *  rows, so the derivation would answer `requested` however far that intro had actually
 *  progressed, and a write would then be admitted against a state the intro is not in. Two
 *  independent reviewers reached the same defect from opposite ends: a canonical
 *  express_interest or decline on an already accepted pre-2A intro succeeded and destroyed
 *  it, and a legacy accept on one left a pair that could never connect on the canonical
 *  lane.
 *
 *  So the bridge runs before the facts are read, once per intro, inside the write's own
 *  transaction. Only a `pending` pre-2A intro is bridgeable. Anything else has a history the
 *  legacy column records and the facts do not, and this REFUSES rather than guessing at it,
 *  because a guess is how a finished connection gets reopened. */
export function factsForWrite(introId: string): IntroFacts {
  const bridged = bridgePre2AIntro(introId)
  if (bridged === 'not_bridgeable') {
    refuseWrite(409, 'legacy_intro_not_upgradable',
      'this introduction predates signed writes and has already progressed past a request, so it stays on the path it started on')
  }
  const facts = introFacts(introId)
  if (facts === null) refuseWrite(404, 'intro_not_found', 'no such introduction')
  return facts as IntroFacts
}

/** A read-only load, for a caller that is not about to write. */
export function factsOrRefuse(introId: string): IntroFacts {
  const facts = introFacts(introId)
  if (facts === null) refuseWrite(404, 'intro_not_found', 'no such introduction')
  return facts as IntroFacts
}

/** The standing state guard, run against the derivation rather than against any stored
 *  column, with the refusal code the 104 cell matrix decided for this pair. */
export function guardState(operation: Operation, facts: IntroFacts, now: Date): IntroState {
  const state = deriveIntroState(facts, now)
  if (!isWriteAllowedInState(operation, state)) {
    const r = guardRefusal(operation, state)
    refuseWrite(409, r.code, r.error)
  }
  return state
}

export type PartyRequirement = 'requester' | 'target' | 'either'

/** `message` names what the caller was trying to do, because "only the requester may
 *  act here" is less useful than naming the act. The CODE is what a client branches on
 *  and it never varies. */
export function requireParty(facts: IntroFacts, actorKey: string, want: PartyRequirement, message?: string): void {
  const isFrom = actorKey === facts.from_key
  const isTo = actorKey === facts.to_key
  if (want === 'requester' && !isFrom) refuseWrite(403, 'not_the_requester', message ?? 'only the requester may act here')
  if (want === 'target' && !isTo) refuseWrite(403, 'not_the_target', message ?? 'only the intro target may act here')
  if (want === 'either' && !isFrom && !isTo) refuseWrite(403, 'not_a_party', message ?? 'only a party to this introduction may act on it')
}
