// ══════════════════════════════════════════════════════════════
// The guards every intro write runs, canonical or adapted
// ══════════════════════════════════════════════════════════════
// Three small functions, in one module so the canonical routes and the legacy adapters
// cannot drift apart on who may act and in which state. They all raise WriteRefusal,
// so they are only ever called from inside a canonical write transaction, where a
// refusal rolls everything back.

import { refuseWrite } from './write-pipeline.js'
import { introFacts } from './connection-facts.js'
import { deriveIntroState, isWriteAllowedInState, guardRefusal } from './connection-state.js'
import type { IntroFacts, IntroState, Operation } from './connection-state.js'

/** Load the facts for one intro, or refuse. */
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
