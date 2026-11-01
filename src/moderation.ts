// Operator moderation: hide a card, or every card of a key, from the network
// without touching the signed revocation_status. Only an operator with shell access
// to the server runs this (scripts/moderate.mjs). There is no HTTP route.
//
// Hidden means: out of search, the event wall, matching, intros and fit, refused for
// new publish, renew and replace, and shown as hidden (reason withheld) on fetch. The
// owner can still withdraw or delete the card. Evidence is never deleted here.

import * as v3db from './v3-db.js'
import * as matchesDb from './matches-db.js'
import { recordCardEvent } from './card-events.js'

export type ModerationTarget = 'card' | 'subject'

export function hideFromNetwork(targetType: ModerationTarget, target: string, reason: string, actor: string): { newly_hidden: boolean; cards: number } {
  if (!reason.trim() || !actor.trim()) throw new Error('reason and actor are required')
  const cards = v3db.cardIdsForTarget(targetType, target)
  const newly_hidden = v3db.setHidden(targetType, target, reason, actor)
  for (const c of cards) {
    v3db.removeFromIndex(c.card_id)
    matchesDb.deleteMatchArtifacts(c.card_id)
    if (newly_hidden) recordCardEvent('card_hidden', c.card_id, c.subject_key, { target_type: targetType, reason, actor })
  }
  return { newly_hidden, cards: cards.length }
}

/** Lifts the hide. Search and the wall see the cards again at once. The semantic
 *  index entry and matches removed by the hide are not rebuilt here, so the result
 *  names how many live cards need a re-embed. */
export function unhideFromNetwork(targetType: ModerationTarget, target: string, actor: string): { cleared: boolean; reembed_needed: number } {
  const cards = v3db.cardIdsForTarget(targetType, target)
  const cleared = v3db.clearHidden(targetType, target)
  let reembed_needed = 0
  for (const c of cards) {
    if (cleared) recordCardEvent('card_unhidden', c.card_id, c.subject_key, { target_type: targetType, actor })
    if (v3db.isCardMatchable(c.card_id)) reembed_needed++
  }
  return { cleared, reembed_needed }
}
