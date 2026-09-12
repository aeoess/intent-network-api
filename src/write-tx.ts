// ══════════════════════════════════════════════════════════════
// The one transaction every canonical write runs inside
// ══════════════════════════════════════════════════════════════
// Reserve the nonce, mutate durable facts, persist the result. One transaction,
// so a failure anywhere leaves no nonce reservation, no fact and no receipt.
//
// The claim is a bare INSERT whose primary key conflict means "already claimed",
// which is the atomic first-writer-wins pattern notify-db.ts:135-140 already uses
// for outbound mail. checkRateLimit at db.ts:309-332 is the WRONG template and is
// worth naming so nobody copies it: it SELECTs and then INSERTs with no
// transaction, and for a counter a lost race merely undercounts, while for a nonce
// the gap between the read and the write IS the replay window.
//
// Why the reservation and the result are written in the SAME transaction. If the
// reservation committed first and the result later, a concurrent replay could find
// a reservation with no result and would have to guess whether the work happened.
// Writing both together means a surviving row always carries its answer, so
// `status` only ever holds 'committed': every refusal path rolls the whole
// transaction back, including the claim, so the nonce stays usable and a refusal
// costs the caller nothing.
//
// Concurrency. Inside one process better-sqlite3 is synchronous and the handler
// contains no await between the claim and the mutation, so nothing interleaves.
// Across processes SQLite serializes write transactions: the second blocks on the
// write lock (busy_timeout 5000 at db.ts:35), then its INSERT hits the primary key,
// it reads the committed row and returns the stored result. One mutation, two
// identical answers.

import { getDb } from './db.js'
import type { VerifiedWrite } from './write-envelope.js'

/** A business or authorization refusal raised from inside the transaction body.
 *  Throwing rolls the transaction back, which is the point: the refusal is decided
 *  inside the same transaction as the facts it is deciding about. */
export class WriteRefusal extends Error {
  readonly status: number
  readonly code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'WriteRefusal'
    this.status = status
    this.code = code
  }
}

class IdempotentReplay extends Error {
  readonly resultJson: string | null
  constructor(resultJson: string | null) {
    super('idempotent replay')
    this.name = 'IdempotentReplay'
    this.resultJson = resultJson
  }
}

class ReplayConflict extends Error {
  constructor(readonly storedWriteRef: string) {
    super('replay conflict')
    this.name = 'ReplayConflict'
  }
}

export type WriteOutcome<T> =
  | { ok: true; kind: 'committed' | 'idempotent'; result: T }
  | { ok: false; status: number; code: string; error: string }

export interface NonceRow {
  actor_key: string
  nonce: string
  write_ref: string
  operation: string
  resource_type: string
  resource_id: string
  issued_at: string
  first_seen_at: string
  status: string
  result_json: string | null
}

export function nonceRow(actorKey: string, nonce: string): NonceRow | null {
  return (getDb().prepare('SELECT * FROM write_nonces WHERE actor_key = ? AND nonce = ?')
    .get(actorKey, nonce) as NonceRow) ?? null
}

/** Run a canonical write. `body` does the authorization checks that need the
 *  database, mutates the durable facts, and returns the response payload.
 *
 *  Everything `body` does is inside the transaction, so no side effect of any kind
 *  survives a refusal. Side effects that cannot be transactional, email above all,
 *  belong AFTER this returns committed. */
export function runCanonicalWrite<T>(write: VerifiedWrite, body: () => T): WriteOutcome<T> {
  const { envelope, writeRef } = write
  try {
    const result = getDb().transaction((): T => {
      // ── Reserve. A conflict is the whole replay story. ──
      try {
        getDb().prepare(`
          INSERT INTO write_nonces
            (actor_key, nonce, write_ref, operation, resource_type, resource_id, issued_at, status)
          VALUES (?, ?, ?, ?, ?, ?, ?, 'committed')
        `).run(envelope.actor_key, envelope.nonce, writeRef, envelope.operation,
          envelope.resource.type, envelope.resource.id, envelope.issued_at)
      } catch {
        const existing = nonceRow(envelope.actor_key, envelope.nonce)
        if (existing === null) throw new Error('nonce claim failed without a stored row')
        if (existing.write_ref === writeRef) throw new IdempotentReplay(existing.result_json)
        throw new ReplayConflict(existing.write_ref)
      }

      const out = body()

      // Written before commit, so a concurrent replay never sees a reservation
      // without its answer.
      getDb().prepare('UPDATE write_nonces SET result_json = ? WHERE actor_key = ? AND nonce = ?')
        .run(JSON.stringify(out ?? null), envelope.actor_key, envelope.nonce)
      return out
    })()
    return { ok: true, kind: 'committed', result }
  } catch (e) {
    if (e instanceof IdempotentReplay) {
      return { ok: true, kind: 'idempotent', result: (e.resultJson === null ? null : JSON.parse(e.resultJson)) as T }
    }
    if (e instanceof ReplayConflict) {
      return {
        ok: false, status: 409, code: 'replay_conflict',
        error: 'this nonce was already used for a different write. A nonce is never reused across two different acts.',
      }
    }
    if (e instanceof WriteRefusal) {
      return { ok: false, status: e.status, code: e.code, error: e.message }
    }
    throw e
  }
}
