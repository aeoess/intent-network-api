// ══════════════════════════════════════════════════════════════
// The two checks every legacy adapter runs, in one place
// ══════════════════════════════════════════════════════════════
// Anti-downgrade first, then the cutoff. Both answer 426 client_upgrade_required with
// the same user text, because the caller's remedy is identical: update. Two codes for
// one remedy would be noise in a client that has to handle both anyway.
//
// They are distinguished in the INTERNAL LOG, where the distinction is actually
// useful. Anti-downgrade records `downgrade prevention` and the cutoff records the
// window closing. The response bodies are identical, so the log is the only place the
// difference exists, and a test asserts the reason on each path.
//
// Order matters. Anti-downgrade is about this actor's own history and applies inside
// the window as well as after it, so a caller who has already used canonical
// authorization is refused whether the window is open or not. Checking the cutoff
// first would make the same request produce a different log reason depending on the
// date, for no gain.
//
// Nothing here writes. It is a predicate, called before any side effect, which is what
// lets an adapter satisfy the rule that no row, email or logged payload precedes a
// passed authorization check.

import { legacyWindowClosed } from './db.js'
import { resolveAuthMode } from './write-db.js'
import { isPre2AIntro } from './connection-facts.js'

/** The one refusal both checks answer with. */
export const LEGACY_REFUSAL = {
  status: 426,
  code: 'client_upgrade_required',
  error: 'Update Mingle to continue this connection.',
} as const

export type LegacyRefusalReason = 'downgrade prevention' | 'legacy write window closed'

export interface LegacyGateResult {
  status: number
  code: string
  error: string
  logReason: LegacyRefusalReason
}

export interface LegacyGateArgs {
  /** The resource this legacy act touches, for the anti-downgrade lookup. */
  resourceType: string
  resourceId: string
  actorKey: string
  /** The intro this act belongs to, when there is one. A pre-2A intro is exempt from
   *  the cutoff, because the decision is that it stays on the old path until terminal
   *  or expired. Omit for a create, which has no intro yet and cannot be
   *  grandfathered. */
  introId?: string
  now?: Date
}

/** Run both checks. Returns null when the legacy act may proceed. */
export function checkLegacyWrite(args: LegacyGateArgs): LegacyGateResult | null {
  // 1. Anti-downgrade. Per actor, per resource, canonical absorbing. A row exists only
  // for a key that has actually signed something, so this never refuses a counterparty
  // who has done nothing.
  if (resolveAuthMode(args.resourceType, args.resourceId, args.actorKey) === 'canonical') {
    return { ...LEGACY_REFUSAL, logReason: 'downgrade prevention' }
  }

  // 2. The cutoff. Unstamped means the window is OPEN: nothing derives the cutoff from
  // deploy time, build time or a first request, so an unset marker can only ever mean
  // "not yet", never "already".
  if (legacyWindowClosed(args.now ?? new Date())) {
    if (args.introId !== undefined && isPre2AIntro(args.introId)) return null
    return { ...LEGACY_REFUSAL, logReason: 'legacy write window closed' }
  }
  return null
}

/** A legacy CREATE runs the cutoff only.
 *
 *  Anti-downgrade is per actor per resource, and a create's resource does not exist
 *  yet: there is no intro and no request_id to have a mode row for. So the check is
 *  structurally a no-op here rather than something skipped by choice, and saying that
 *  in its own function is clearer than passing an empty resource id to the other one
 *  and letting the lookup miss. */
export function checkLegacyCreate(args: { actorKey: string; now?: Date }): LegacyGateResult | null {
  void args.actorKey
  if (legacyWindowClosed(args.now ?? new Date())) {
    return { ...LEGACY_REFUSAL, logReason: 'legacy write window closed' }
  }
  return null
}

/** Log the refusal and answer it. The log carries the reason, the operation and the
 *  resource, and never the request payload. */
export function refuseLegacy(res: { status: (n: number) => any }, operation: string, resourceId: string, gate: LegacyGateResult): void {
  console.warn(`[legacy write] refused ${operation} on ${resourceId}: ${gate.logReason}`)
  res.status(gate.status).json({ code: gate.code, error: gate.error })
}
