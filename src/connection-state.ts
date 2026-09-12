// ══════════════════════════════════════════════════════════════
// deriveIntroState: the lifecycle is a projection, not a column
// ══════════════════════════════════════════════════════════════
// One function computes the state of an intro from durable facts, every time it
// is asked. Nothing stores a state, nothing transitions one, and no action
// assigns one. An action writes facts and the state is what those facts imply.
//
// v3_intros.status is a COMPATIBILITY MATERIALIZATION written from this function
// so a published 3.2.x client keeps working. Nothing in the new code path reads
// it, nothing branches on it, and a test proves it cannot override a durable
// fact.
//
// Pure. No database access, no clock of its own: `now` is a parameter, which is
// what makes the whole lifecycle testable as a table before any wire format
// exists, and what stops a read from accidentally depending on wall time.
//
// Terminal facts are decided by the write transaction, never arbitrated here. The
// routes refuse a terminal write that would contradict an earlier one, and the
// ordering below is a backstop for a row that should not exist rather than a
// mechanism anything depends on.

export type IntroState =
  | 'requested'
  | 'interested'
  | 'connecting'
  | 'connected'
  | 'declined'
  | 'withdrawn'
  | 'blocked'
  | 'expired'

export const INTRO_STATES: readonly IntroState[] = [
  'requested', 'interested', 'connecting', 'connected', 'declined', 'withdrawn', 'blocked', 'expired',
] as const

/** The thirteen product actions, plus fit_round2, which ruling 12 gave envelope
 *  treatment. fit_round2 is not a product action and produces no state, but it is
 *  a signed act on a live connection so it counts as a continuation. */
export const OPERATIONS = [
  'request_intro', 'withdraw_request', 'express_interest', 'decline', 'block_pair',
  'withdraw_interest', 'share_contact', 'withdraw_contact', 'fit_request', 'fit_commit',
  'release_exact', 'first_step_propose', 'first_step_approve',
] as const
export type Operation = typeof OPERATIONS[number] | 'fit_round2'

/** A continuation is a signed act on a live connection. The first one moves the
 *  pair to connecting, and each accepted one sets a new expiry from its own time. */
export const CONTINUATIONS: readonly Operation[] = [
  'share_contact', 'fit_request', 'fit_commit', 'fit_round2', 'release_exact',
  'first_step_propose', 'first_step_approve',
] as const

/** Explicit terminal facts. Withdrawal is not here: it is the absence of a live
 *  request or interest authorization on a row that once had one, so it needs no
 *  fact of its own. */
export const TERMINAL_FACTS: readonly Operation[] = ['decline', 'block_pair'] as const

// ── TTLs, decided ─────────────────────────────────────────────────────────

export const TTL_REQUESTED_DAYS = 14
export const TTL_INTERESTED_DAYS = 30
export const TTL_CONNECTING_DAYS = 30
const DAY_MS = 24 * 3600 * 1000

// ── The facts the derivation reads, and nothing else ──────────────────────

export interface AuthFact {
  operation: Operation
  actor_key: string
  subject: string
  live: boolean
  created_at: string
  evidence: 'canonical' | 'legacy_unbound'
  /** When an accepted signed withdrawal took this authorization out of live, or null.
   *
   *  Not a column. It is the recorded_at of the evidence row for the withdrawing act,
   *  resolved through withdrawn_by, so the only thing that can set it is an accepted
   *  signed write. A sweep, a read, a poll and an email have no evidence row to point
   *  at and therefore cannot produce a value here at all. */
  withdrawn_at?: string | null
}

export interface IntroFacts {
  intro_id: string
  /** The intro row's own created_at, which is the basis for the requested TTL. */
  created_at: string
  from_key: string
  to_key: string
  authorizations: AuthFact[]
  /** A connection_release row exists. This is what `connected` means. */
  released: boolean
}

function find(facts: IntroFacts, operation: Operation, actorKey?: string): AuthFact | undefined {
  return facts.authorizations.find(a => a.operation === operation && (actorKey === undefined || a.actor_key === actorKey))
}

function liveContinuations(facts: IntroFacts): AuthFact[] {
  return facts.authorizations.filter(a => a.live && (CONTINUATIONS as readonly string[]).includes(a.operation))
}

/** The requester's request authorization and the target's interest authorization
 *  are both live. Required for every continuation and for `interested`. */
export function hasMutualInterest(facts: IntroFacts): boolean {
  const req = find(facts, 'request_intro')
  const interest = find(facts, 'express_interest')
  return !!req && req.live && !!interest && interest.live
}

/** A withdrawal is a row that exists and is no longer live. A row that never
 *  existed is not a withdrawal, it is an act that never happened. */
function isWithdrawn(facts: IntroFacts): boolean {
  const req = find(facts, 'request_intro')
  const interest = find(facts, 'express_interest')
  return (!!req && !req.live) || (!!interest && !interest.live)
}

// ── Expiry, derived ───────────────────────────────────────────────────────
// Derived from the created_at of authorization rows, never stored. That is what
// makes the renewal rule structural rather than a discipline: the only way to move
// a deadline is to insert a continuation authorization, and the only way to do
// that is to present a valid canonical envelope for a continuation. A read writes
// no row. A poll writes no row. A notification writes no row. A background sweep
// writes no row. There is no last_activity_at column to touch, because a column
// like that is exactly what gets touched by accident.
//
// An accepted continuation sets a NEW expiry from the continuation's own time. It
// never adds to the previous expiry, so a long-running connection cannot
// accumulate an unbounded window.
//
// THE INTERESTED BASIS, per the closed ruling. When the last live continuation is
// explicitly withdrawn by an accepted signed action and mutual interest remains, the
// basis is the LATER of the interest authorization and that withdrawal's accepted
// time. The reason is that expiry measures inactivity and a withdrawal is activity: a
// pair demonstrably acting on day 35 should not be killed outright because their
// interest is from day 1. Without this, withdrawing your own contact line, which is
// the safest act a user can take, expires the introduction at a clock where it was
// alive a moment before.
//
// Only an ACCEPTED SIGNED withdrawal moves it. A continuation that lapses passively is
// still live, so it is still the basis and nothing moves at all. Sweeps, reads,
// polling, email delivery and background jobs write no evidence row, so they cannot
// produce a withdrawn_at and cannot refresh anything.

function withdrawnContinuationBasis(facts: IntroFacts): number {
  let latest = 0
  for (const a of facts.authorizations) {
    if (a.live) continue
    if (!(CONTINUATIONS as readonly string[]).includes(a.operation)) continue
    if (typeof a.withdrawn_at !== 'string' || a.withdrawn_at.length === 0) continue
    const t = Date.parse(a.withdrawn_at)
    if (Number.isNaN(t)) continue
    if (t > latest) latest = t
  }
  return latest
}

export function expiryOf(facts: IntroFacts): string | null {
  if (facts.released) return null // connected has no lifecycle expiry
  const cont = liveContinuations(facts)
  if (cont.length > 0) {
    const latest = cont.reduce((a, b) => (Date.parse(a.created_at) >= Date.parse(b.created_at) ? a : b))
    return new Date(Date.parse(latest.created_at) + TTL_CONNECTING_DAYS * DAY_MS).toISOString()
  }
  const interest = find(facts, 'express_interest')
  if (interest && interest.live) {
    const basis = Math.max(Date.parse(interest.created_at), withdrawnContinuationBasis(facts))
    return new Date(basis + TTL_INTERESTED_DAYS * DAY_MS).toISOString()
  }
  return new Date(Date.parse(facts.created_at) + TTL_REQUESTED_DAYS * DAY_MS).toISOString()
}

export function isExpired(facts: IntroFacts, now: Date): boolean {
  const at = expiryOf(facts)
  if (at === null) return false
  return now.getTime() >= Date.parse(at)
}

// ── The derivation ────────────────────────────────────────────────────────

/** Total over any fact set, including an empty one. First match wins.
 *
 *  1 released                -> connected   (historical, never later expired)
 *  2 explicit terminal fact  -> declined | blocked
 *  3 withdrawal              -> withdrawn
 *  4 past derived expiry     -> expired
 *  5 mutual interest + live continuation -> connecting
 *  6 mutual interest         -> interested
 *  7 otherwise               -> requested
 */
export function deriveIntroState(facts: IntroFacts, now: Date = new Date()): IntroState {
  if (facts.released) return 'connected'

  const declined = find(facts, 'decline')
  if (declined && declined.live) return 'declined'
  const blocked = find(facts, 'block_pair')
  if (blocked && blocked.live) return 'blocked'

  if (isWithdrawn(facts)) return 'withdrawn'

  if (isExpired(facts, now)) return 'expired'

  if (hasMutualInterest(facts)) {
    return liveContinuations(facts).length > 0 ? 'connecting' : 'interested'
  }
  return 'requested'
}

/** The value v3_intros.status is materialized to, for a published 3.2.x client.
 *
 *  `expired` is the one lossy cell. IntroStatus at intros-db.ts:15 has no
 *  `expired` member, so materializing one would hand an old client a string its
 *  own type does not admit. `withdrawn` keeps it inside its vocabulary and loses
 *  the distinction between a lapse and a retraction ON THE LEGACY COLUMN ONLY.
 *  deriveIntroState still answers `expired`, and the evidence record shows no
 *  withdrawal authorization, so the distinction is recoverable by anything that
 *  looks past the column. */
export function materializedStatus(state: IntroState): 'pending' | 'accepted' | 'declined' | 'withdrawn' | 'blocked' {
  switch (state) {
    case 'requested': return 'pending'
    case 'interested':
    case 'connecting':
    case 'connected': return 'accepted'
    case 'declined': return 'declined'
    case 'blocked': return 'blocked'
    case 'withdrawn':
    case 'expired': return 'withdrawn'
  }
}

// ── The standing state guards ─────────────────────────────────────────────
// Two rules the per action sections do not repeat, encoded once so a route cannot
// forget one:
//   every continuation requires mutual interest
//   no action writes on a terminal intro, except block_pair
//
// The matrix of thirteen operations against eight states is 104 cells, which is
// the cheapest way to find a route that forgot a guard.

const TERMINAL_STATES: readonly IntroState[] = ['declined', 'withdrawn', 'blocked', 'expired'] as const

export function isTerminalState(state: IntroState): boolean {
  return (TERMINAL_STATES as readonly string[]).includes(state)
}

/** May this operation be written against an intro currently in this state?
 *
 *  `request_intro` is a create, so for any EXISTING intro the answer is no: a
 *  second request for the same pair is a new intro or a refusal, never a write
 *  against this one. */
export function isWriteAllowedInState(operation: Operation, state: IntroState): boolean {
  // block_pair stays available everywhere, including after a connection, because
  // blocking future pair activity is useful once contacts have been exchanged.
  // After a release it writes only the pair block and no intro level fact, which
  // is what keeps `connected` from being rewritten.
  if (operation === 'block_pair') return true

  if (isTerminalState(state)) return false

  switch (operation) {
    case 'request_intro': return false
    case 'withdraw_request': return state === 'requested' || state === 'interested'
    case 'express_interest': return state === 'requested'
    case 'decline': return state === 'requested'
    case 'withdraw_interest': return state === 'interested'
    case 'share_contact': return state === 'interested' || state === 'connecting'
    case 'withdraw_contact': return state === 'connecting'
    case 'fit_request':
    case 'fit_commit':
    case 'fit_round2':
    case 'release_exact':
    case 'first_step_propose':
    case 'first_step_approve':
      return state === 'interested' || state === 'connecting' || state === 'connected'
  }
}

/** The refusal code a route answers when a guard rejects. Distinct codes because
 *  the caller's remedy differs: an in-progress connection is a different problem
 *  from a finished one. */
export function guardRefusal(operation: Operation, state: IntroState): { code: string; error: string } {
  if (isTerminalState(state)) {
    return { code: 'intro_terminal', error: `this introduction is ${state} and accepts no further ${operation}` }
  }
  if ((operation === 'withdraw_request' || operation === 'withdraw_interest') && (state === 'connecting' || state === 'connected')) {
    return { code: 'connection_in_progress', error: 'this connection is already in progress, so withdraw the contact rather than the interest' }
  }
  if (operation === 'withdraw_contact' && state === 'connected') {
    return { code: 'contact_already_released', error: 'contacts were released, and Mingle does not pretend a released contact can be unshared' }
  }
  return { code: 'wrong_state', error: `${operation} does not apply to an introduction that is ${state}` }
}

// ── pending_actions ───────────────────────────────────────────────────────

export type Side = 'requester' | 'target'

export function sideOf(facts: IntroFacts, actorKey: string): Side | null {
  if (actorKey === facts.from_key) return 'requester'
  if (actorKey === facts.to_key) return 'target'
  return null
}

/** One owner-side projection, derived from the state and the facts, never stored.
 *
 *  Three rules: it never offers an action the state guards would refuse, it never
 *  offers withdraw_contact once a release row exists, and it never offers a
 *  withdrawal of request or interest while a continuation is live. */
export function pendingActions(facts: IntroFacts, actorKey: string, now: Date = new Date()): Operation[] {
  const side = sideOf(facts, actorKey)
  if (side === null) return []
  const state = deriveIntroState(facts, now)
  if (isTerminalState(state)) return []

  const out: Operation[] = []
  const push = (op: Operation) => { if (isWriteAllowedInState(op, state)) out.push(op) }

  if (state === 'requested') {
    if (side === 'target') { push('express_interest'); push('decline') }
    else push('withdraw_request')
  } else {
    // interested, connecting or connected
    const mine = facts.authorizations.find(a => a.operation === 'share_contact' && a.actor_key === actorKey && a.live)
    if (!facts.released && !mine) push('share_contact')
    if (!facts.released && mine) push('withdraw_contact')
    if (side === 'requester') push('withdraw_request')
    else push('withdraw_interest')
    push('fit_request')
    push('first_step_propose')
  }
  push('block_pair')
  return out
}
