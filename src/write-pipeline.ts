// ══════════════════════════════════════════════════════════════
// One Express chain for every canonical write
// ══════════════════════════════════════════════════════════════
// The canonical processing order, and where each numbered step lives:
//
//    1 parse                          write-envelope.ts
//    2 reject shape, null, nonce,     write-envelope.ts
//      timestamps, operation, resource
//    3 recompute payload digest       write-envelope.ts
//    4 verify envelope signature      write-envelope.ts
//    5 acting key relation to the     HERE, via the handler's `authorize`
//      resource and the action
//    6 freshness and replay           freshness HERE, replay in write-tx.ts
//    7 verify the private opening     HERE
//    8 authorization, state,          INSIDE the transaction, see below
//      compatibility, anti-downgrade
//    9 one transaction                write-tx.ts
//   10 derive state                   connection-state.ts
//   11 warranted receipt claims       step 13
//   12 persist for idempotent resend  write-tx.ts
//   13 respond                        HERE
//
// A documented safe equivalent for step 8. The order as written puts authorization,
// state and anti-downgrade before the transaction. This runs them INSIDE it, which
// is strictly safer rather than a relaxation: a state check outside the transaction
// is a read-then-write race, and between reading "this intro is interested" and
// writing a fact another request can change it. Running them inside removes the
// window entirely, and it still satisfies the rule that no business side effect
// precedes an authorization check, because the transaction rolls back and nothing
// survives a refusal. The nonce is reserved first inside that transaction, so a
// refusal also leaves the nonce usable.
//
// No side effect of any kind happens before every check has passed. Email and other
// non transactional effects run only after the transaction has committed, from the
// route, never from the handler.

import type { Request, Response } from 'express'
import { checkRateLimit } from './db.js'
import { verifyWriteBody, checkFreshness, verifyOpening } from './write-envelope.js'
import type { VerifiedWrite } from './write-envelope.js'
import { runCanonicalWrite, WriteRefusal } from './write-tx.js'
import { resolveAuthMode, recordAuthMode } from './write-db.js'
import type { Operation } from './connection-state.js'

/** Its own rate limit action name, checked against the 33 already stored so it
 *  cannot share a counter with an existing route. */
export const WRITE_RATE_ACTION = 'write_canonical'
export const WRITE_RATE_LIMIT = 120

export interface CanonicalContext {
  write: VerifiedWrite
  /** The clock, passed down so a handler never reads wall time itself. */
  now: Date
}

export interface CanonicalRoute<T> {
  /** Which operations this route accepts. An envelope naming anything else is
   *  refused before the handler is reached, so one route cannot be driven with
   *  another route's operation. */
  operations: readonly Operation[]
  /** Runs INSIDE the transaction, after the nonce is reserved. Throw WriteRefusal
   *  to refuse with a code and roll everything back. */
  handler: (ctx: CanonicalContext) => T
  /** Non transactional effects, after a successful commit only. Never throws into
   *  the response: a lost email must not undo a committed connection. */
  afterCommit?: (ctx: CanonicalContext, result: T) => void | Promise<void>
}

function refuse(res: Response, status: number, code: string, error: string): void {
  res.status(status).json({ code, error })
}

/** Build the Express handler for one canonical write route. */
export function canonicalWriteRoute<T>(route: CanonicalRoute<T>) {
  return async (req: Request, res: Response): Promise<void> => {
    // Express 4 does not catch a rejection from an async handler, so an unexpected
    // throw would leave the request hanging with no response at all rather than
    // failing. Found while implementing: a primary key violation inside a handler
    // hung the client forever. Everything below runs inside this boundary, and an
    // unexpected error becomes a 500 with a code.
    try {
      await runRoute(route, req, res)
    } catch (e) {
      console.error(`[canonical write] unhandled error on ${(req as any).path}:`, (e as Error)?.stack ?? e)
      if (!(res as any).headersSent) {
        res.status(500).json({ code: 'write_failed', error: 'the write could not be completed' })
      }
    }
  }
}

async function runRoute<T>(route: CanonicalRoute<T>, req: Request, res: Response): Promise<void> {
  {
    // Rate limit first, on the transport, before any parsing. Keyed on the client
    // like every other route in this repo.
    const key = `write:${req.ip || 'anon'}`
    if (!checkRateLimit(key, WRITE_RATE_ACTION, WRITE_RATE_LIMIT).allowed) {
      refuse(res, 429, 'rate_limited', 'Rate limit exceeded')
      return
    }

    // 1 to 4: parse, shape, payload gate, digest, signature.
    const parsed = verifyWriteBody(req.body)
    if (parsed.ok !== true) {
      const p = parsed as { status: number; code: string; error: string }
      refuse(res, p.status, p.code, p.error)
      return
    }
    const write = parsed.write

    if (!route.operations.includes(write.envelope.operation)) {
      refuse(res, 400, 'operation_not_on_this_route',
        `${write.envelope.operation} is not accepted here`)
      return
    }

    // 6a: freshness. After the signature, so a caller who cannot sign learns
    // nothing about the server's clock tolerance.
    const stale = checkFreshness(write.envelope, new Date())
    if (stale !== null) {
      const s = stale as unknown as { status: number; code: string; error: string }
      refuse(res, s.status, s.code, s.error)
      return
    }

    // 7: the private opening recomputes to the commitment in the signed payload.
    // Before the transaction, because it is pure arithmetic on the request and
    // needs no database state.
    const opening = verifyOpening(write)
    if (opening !== null) {
      const o = opening as unknown as { status: number; code: string; error: string }
      refuse(res, o.status, o.code, o.error)
      return
    }

    const ctx: CanonicalContext = { write, now: new Date() }

    // 8 and 9: authorization, state and anti-downgrade inside the transaction that
    // also reserves the nonce and writes the facts.
    const outcome = runCanonicalWrite(write, () => {
      // Anti-downgrade, in the direction this lane cares about: a canonical write
      // is always allowed, and recording it makes the resource canonical for this
      // actor so a later legacy write on the same resource is refused by the
      // adapter. Canonical is absorbing.
      recordAuthMode(write.envelope.resource.type, write.envelope.resource.id, write.envelope.actor_key, 'canonical')
      return route.handler(ctx)
    })

    if (outcome.ok !== true) {
      const o = outcome as { status: number; code: string; error: string }
      refuse(res, o.status, o.code, o.error)
      return
    }

    // 13: respond. An idempotent resend gets the stored answer and the same status.
    res.status(outcome.kind === 'idempotent' ? 200 : 201).json({
      ...(outcome.result as object),
      write_ref: write.writeRef,
      idempotent: outcome.kind === 'idempotent',
    })

    // Non transactional effects, after the response and only on a real commit.
    if (outcome.kind === 'committed' && route.afterCommit) {
      try { await route.afterCommit(ctx, outcome.result) } catch { /* never affects a committed write */ }
    }
  }
}

/** The refusal an adapter answers when a legacy body arrives from an actor who has
 *  already used canonical authorization on this resource.
 *
 *  Same status and same user text as the cutoff refusal, deliberately: the caller's
 *  remedy is identical, which is to update, so two codes to handle would be noise.
 *  The distinction lives in the internal log reason, where it is actually useful. */
export const DOWNGRADE_REFUSAL = {
  status: 426,
  code: 'client_upgrade_required',
  error: 'Update Mingle to continue this connection.',
  logReason: 'downgrade prevention',
} as const

/** Would a legacy write on this resource by this actor be a downgrade? */
export function isDowngrade(resourceType: string, resourceId: string, actorKey: string): boolean {
  return resolveAuthMode(resourceType, resourceId, actorKey) === 'canonical'
}

/** Raise from inside a transaction body. Exported so an adapter and a canonical
 *  handler refuse identically. */
export function refuseWrite(status: number, code: string, error: string): never {
  throw new WriteRefusal(status, code, error)
}
