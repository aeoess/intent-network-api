// ══════════════════════════════════════════════════════════════
// Closing unfinished continuation state when an introduction is withdrawn
// ══════════════════════════════════════════════════════════════
// The closure ruling makes a withdrawal from `connecting` ONE ATOMIC TERMINAL
// OPERATION. Part of that is that unfinished continuation state does not survive the
// introduction it belonged to, so a reader is never shown a live looking fit exchange,
// handshake or plan on an introduction that is over.
//
// WHY THIS IS NOT REDUNDANT with the terminal state guard. The guard already refuses
// every later write on a withdrawn intro, so nothing can ADVANCE. What it does not do is
// change what a READ surface shows: an exchange still reads `answering`, a handshake
// still reads `requested`, and a half approved plan still reads as awaiting one
// signature. Each of those is a sentence about a live conversation, and the conversation
// is over.
//
// WHAT IS AND IS NOT TOUCHED, and the line is the same in all three: UNFINISHED state is
// cancelled and FINISHED state is a fact and is left exactly as it is.
//
//   a sealed exchange record          left alone, it is signed and re-servable
//   a committed handshake             left alone, the evaluation happened
//   a finalized First Step plan       left alone, both keys approved one digest
//   an already released contact       never retracted, anywhere, by anything
//
// Everything here is synchronous and expects to be called INSIDE the canonical write
// transaction, so a refusal anywhere in that transaction rolls all of it back.

import * as fitDb from './fit-db.js'
import * as handshakeDb from './fit-handshake-db.js'
import * as firstStepDb from './fit-firststep-db.js'

export interface ClosedContinuations {
  /** The exchange id that was cancelled, or null when there was nothing unfinished. */
  exchange: string | null
  /** True when an unfinished handshake was cancelled. */
  handshake: boolean
  /** True when an unfinished plan's approvals were cleared. */
  first_step: boolean
}

/** Cancel every unfinished continuation on one intro. Idempotent: a second call finds
 *  nothing unfinished and reports nothing closed. */
export function closeUnfinishedContinuations(introId: string): ClosedContinuations {
  const ex = fitDb.exchangeForIntro(introId)
  const exchange = ex !== null && fitDb.cancelExchange(ex.id) ? ex.id : null
  return {
    exchange,
    handshake: handshakeDb.cancelHandshake(introId),
    first_step: firstStepDb.cancelUnfinished(introId),
  }
}

/** Did this intro carry any unfinished continuation at all? A read, for a caller that
 *  wants to say whether a withdrawal closed anything without performing it. */
export function hasUnfinishedContinuations(introId: string): boolean {
  const ex = fitDb.exchangeForIntro(introId)
  if (ex !== null && ex.state !== 'closed' && ex.state !== 'cancelled') return true
  const hs = handshakeDb.getHandshake(introId)
  if (hs !== null && (hs.state === 'open' || hs.state === 'requested')) return true
  const fs = firstStepDb.getFirstStep(introId)
  return fs !== null && !firstStepDb.isFinalized(fs) && (fs.a_approved === 1 || fs.b_approved === 1)
}
