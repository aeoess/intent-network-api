// ══════════════════════════════════════════════════════════════
// Reading and writing the durable facts deriveIntroState projects over
// ══════════════════════════════════════════════════════════════
// connection-state.ts is pure and knows nothing about storage. This module is the
// only place that turns rows into an IntroFacts and an accepted write into rows.
// Keeping the two apart is what lets the whole lifecycle be tested as a table
// before any database exists, and it is why no route assembles facts by hand.
//
// Everything here is synchronous and expects to be called INSIDE the canonical
// write transaction. Nothing opens a transaction of its own, because a nested
// better-sqlite3 transaction becomes a SAVEPOINT and a caller that wanted one
// atomic unit would get two.
//
// The materialization is one function, called last by every canonical write. It
// reads the facts the transaction just wrote, derives the state, and writes the
// mapped value into v3_intros.status. Per action status assignment would be
// thirteen chances to disagree with the derivation. One derived write is zero.

import type { Database } from 'better-sqlite3'
import { getDb, SQL_NOW_ISO, getSchemaMarker, MINGLE_2A_MARKER_KEY } from './db.js'
import type { AuthEvidence } from './write-db.js'
import {
  deriveIntroState, materializedStatus, expiryOf, pendingActions,
} from './connection-state.js'
import type { IntroFacts, IntroState, Operation } from './connection-state.js'

function d(): Database {
  return getDb()
}

export interface AuthorizationRow {
  intro_id: string
  actor_key: string
  operation: string
  subject: string
  evidence_id: string
  evidence: AuthEvidence
  live: number
  withdrawn_by: string | null
  created_at: string
}

// ── Reading ───────────────────────────────────────────────────────────────

export function isReleased(introId: string): boolean {
  return !!d().prepare('SELECT 1 FROM connection_release WHERE intro_id = ?').get(introId)
}

export function authorizationsFor(introId: string): AuthorizationRow[] {
  return d().prepare(
    'SELECT * FROM connection_authorizations WHERE intro_id = ? ORDER BY created_at, operation, actor_key, subject',
  ).all(introId) as AuthorizationRow[]
}

/** The actor's own authorization for one operation, live or not. `subject` carries
 *  the dimension for release_exact and is empty for everything else. */
export function authorizationOf(introId: string, actorKey: string, operation: Operation, subject = ''): AuthorizationRow | null {
  return (d().prepare(
    'SELECT * FROM connection_authorizations WHERE intro_id = ? AND actor_key = ? AND operation = ? AND subject = ?',
  ).get(introId, actorKey, operation, subject) as AuthorizationRow) ?? null
}

/** The fact set for one intro, or null if no such intro.
 *
 *  This is the ONLY reader the derivation is given. It deliberately does not read
 *  v3_intros.status: the column is an output of the derivation and feeding it back
 *  in would make the projection depend on its own materialization. */
export function introFacts(introId: string): IntroFacts | null {
  const row = d().prepare('SELECT id, created_at, from_key, to_key FROM v3_intros WHERE id = ?').get(introId) as
    { id: string; created_at: string; from_key: string; to_key: string } | undefined
  if (row === undefined) return null
  return {
    intro_id: row.id,
    created_at: row.created_at,
    from_key: row.from_key,
    to_key: row.to_key,
    authorizations: authorizationsFor(introId).map(a => ({
      operation: a.operation as Operation,
      actor_key: a.actor_key,
      subject: a.subject,
      live: a.live === 1,
      created_at: a.created_at,
      evidence: a.evidence,
    })),
    released: isReleased(introId),
  }
}

/** The derived state, or null if no such intro. Never reads the status column. */
export function stateOf(introId: string, now: Date = new Date()): IntroState | null {
  const facts = introFacts(introId)
  return facts === null ? null : deriveIntroState(facts, now)
}

/** The owner side projection for one party: state, derived expiry, pending actions.
 *  Nothing here is stored. */
export function introProjection(introId: string, actorKey: string, now: Date = new Date()): {
  state: IntroState
  expires_at: string | null
  pending_actions: Operation[]
} | null {
  const facts = introFacts(introId)
  if (facts === null) return null
  return {
    state: deriveIntroState(facts, now),
    expires_at: expiryOf(facts),
    pending_actions: pendingActions(facts, actorKey, now),
  }
}

// ── Writing ───────────────────────────────────────────────────────────────

/** Record an authorization, or bring a withdrawn one back to life.
 *
 *  An upsert rather than an insert, because of the share, withdraw, share again
 *  sequence. The withdrawal flips `live` rather than deleting the row, so a plain
 *  insert would hit the primary key and that principal could never share again.
 *
 *  `created_at` is refreshed on revival, because the derived connecting window
 *  measures the most recent live continuation and a revived authorization is a new
 *  signed act with its own time. */
export function recordAuthorization(args: {
  introId: string
  actorKey: string
  operation: Operation
  subject?: string
  evidenceId: string
  evidence: AuthEvidence
}): void {
  d().prepare(`
    INSERT INTO connection_authorizations
      (intro_id, actor_key, operation, subject, evidence_id, evidence, live, withdrawn_by)
    VALUES (?, ?, ?, ?, ?, ?, 1, NULL)
    ON CONFLICT(intro_id, actor_key, operation, subject) DO UPDATE SET
      live = 1,
      withdrawn_by = NULL,
      evidence_id = excluded.evidence_id,
      evidence = excluded.evidence,
      created_at = ${SQL_NOW_ISO}
  `).run(args.introId, args.actorKey, args.operation, args.subject ?? '', args.evidenceId, args.evidence)
}

/** Stop treating one authorization as live. Returns false when there was no live
 *  row to withdraw, which the caller turns into a state refusal rather than
 *  silently succeeding. */
export function withdrawAuthorization(args: {
  introId: string
  actorKey: string
  operation: Operation
  subject?: string
  withdrawnBy: string
}): boolean {
  const r = d().prepare(`
    UPDATE connection_authorizations SET live = 0, withdrawn_by = ?
    WHERE intro_id = ? AND actor_key = ? AND operation = ? AND subject = ? AND live = 1
  `).run(args.withdrawnBy, args.introId, args.actorKey, args.operation, args.subject ?? '')
  return r.changes === 1
}

/** Claim the release for one intro. Returns true for the transaction that wrote it and
 *  false for one that found it already written.
 *
 *  A bare INSERT whose primary key conflict means "another transaction released", which
 *  is the notify-db.ts:135-140 pattern. The exactly once property rests on the primary
 *  key and NOT on the ordering: if both sides somehow read before either wrote, both
 *  attempt the insert, the loser catches the conflict and still commits its own
 *  authorization. A SELECT then INSERT would have a window between them that is exactly
 *  the double release. */
export function claimRelease(introId: string, aWriteRef: string | null, bWriteRef: string | null): boolean {
  try {
    d().prepare('INSERT INTO connection_release (intro_id, a_write_ref, b_write_ref) VALUES (?, ?, ?)')
      .run(introId, aWriteRef, bWriteRef)
    return true
  } catch {
    return false
  }
}

/** The bound field list of the signature behind one authorization, or null when there is no
 *  such authorization.
 *
 *  What a receipt renderer asks for: the list is the warrant, and a clause is emitted only
 *  when the field it names is in it. */
export function boundFieldsOfAuthorization(introId: string, actorKey: string, operation: Operation, subject = ''): string[] | null {
  const row = d().prepare(`
    SELECT e.bound_fields_json AS bound FROM connection_authorizations a
    JOIN write_evidence e ON e.evidence_id = a.evidence_id
    WHERE a.intro_id = ? AND a.actor_key = ? AND a.operation = ? AND a.subject = ?
  `).get(introId, actorKey, operation, subject) as { bound: string } | undefined
  if (row === undefined) return null
  try {
    const parsed = JSON.parse(row.bound)
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : []
  } catch {
    return []
  }
}

/** The write_ref of the envelope behind one authorization, or null when the act was
 *  legacy and had no envelope. Used to name the two acts a release rests on. */
export function writeRefOfAuthorization(introId: string, actorKey: string, operation: Operation, subject = ''): string | null {
  const row = d().prepare(`
    SELECT e.write_ref AS write_ref FROM connection_authorizations a
    JOIN write_evidence e ON e.evidence_id = a.evidence_id
    WHERE a.intro_id = ? AND a.actor_key = ? AND a.operation = ? AND a.subject = ?
  `).get(introId, actorKey, operation, subject) as { write_ref: string | null } | undefined
  return row?.write_ref ?? null
}

/** Mark every private artifact this actor authored for one operation on this intro
 *  as withdrawn. A no-op until share_contact writes artifacts, and correct then. */
export function withdrawArtifacts(introId: string, authorKey: string, operation: Operation): number {
  return d().prepare(
    'UPDATE private_artifacts SET withdrawn = 1 WHERE intro_id = ? AND author_key = ? AND operation = ? AND withdrawn = 0',
  ).run(introId, authorKey, operation).changes
}

// ── The grandfathering bridge ─────────────────────────────────────────────

/** Does this intro carry any authorization row at all? */
export function hasAuthorizations(introId: string): boolean {
  return !!d().prepare('SELECT 1 FROM connection_authorizations WHERE intro_id = ? LIMIT 1').get(introId)
}

/** Was this intro created before this build's write subsystem existed?
 *
 *  The grandfathering predicate. A pre-2A intro was authorized entirely on the legacy
 *  path, and the decision is that it stays there until terminal or expired, so it is
 *  exempt from the legacy write cutoff. An unstamped marker means nothing is
 *  grandfathered, which is the safe direction: it can only ever refuse an exemption,
 *  never grant one. */
export function isPre2AIntro(introId: string): boolean {
  const marker = getSchemaMarker(MINGLE_2A_MARKER_KEY)
  if (marker === null) return false
  const row = d().prepare('SELECT created_at FROM v3_intros WHERE id = ?').get(introId) as
    { created_at: string } | undefined
  if (row === undefined) return false
  return Date.parse(row.created_at) < Date.parse(marker)
}

/** Is this intro a pre-2A row whose legacy request is still open?
 *
 *  THE ONE PLACE the canonical lane reads v3_intros.status, and the conditions are
 *  narrow on purpose:
 *
 *    the intro predates mingle_2a_deployed_at, so it was authorized before the write
 *    subsystem existed, AND it carries no authorization row at all
 *
 *  Under those two conditions the legacy column is the only record of the request
 *  the requester is retracting, so it is read as a legacy fact and never as a
 *  lifecycle state. From the moment the legacy adapters land, every legacy act
 *  writes a legacy_unbound authorization row, so a post-2A intro always has a
 *  canonical antecedent to read instead and this bridge cannot fire for it.
 *
 *  The marker gate is what stops this becoming a general back door: a caller cannot
 *  reach it by deleting rows, because an intro created after the marker fails the
 *  first condition whatever its rows say.
 *
 *  deriveIntroState is untouched by this. Nothing synthesizes facts from the column,
 *  because a derivation that read its own materialization back in would make the
 *  column authoritative by the back door, which is exactly what 14.3 forbids. */
export function grandfatheredRequestOpen(introId: string): boolean {
  if (!isPre2AIntro(introId)) return false
  if (hasAuthorizations(introId)) return false
  const row = d().prepare('SELECT status FROM v3_intros WHERE id = ?').get(introId) as
    { status: string } | undefined
  return row !== undefined && row.status === 'pending'
}

/** Is this intro complete on the legacy lane: accepted with both contact columns?
 *
 *  The legacy lane's notion of a finished connection, the same three term predicate
 *  as isComplete at intros-db.ts:129. A pre-2A completed intro has no
 *  connection_release row, because the release row only exists for connections the
 *  canonical lane made, so a rule that asked only about the release row would treat
 *  a finished legacy connection as unfinished. */
export function legacyComplete(introId: string): boolean {
  const row = d().prepare('SELECT status, from_contact, to_contact FROM v3_intros WHERE id = ?').get(introId) as
    { status: string; from_contact: string | null; to_contact: string | null } | undefined
  if (row === undefined) return false
  return row.status === 'accepted' && !!row.from_contact && !!row.to_contact
}

/** Have contacts been exchanged on this intro, on either lane? The condition the
 *  block_pair branch turns on. */
export function contactsExchanged(introId: string): boolean {
  return isReleased(introId) || legacyComplete(introId)
}

// ── The compatibility materialization ─────────────────────────────────────

/** Write v3_intros.status from the derivation. Called LAST by every canonical
 *  write, after that write's own facts, and inside the same transaction.
 *
 *  Returns the derived state so a route can answer with it without deriving twice.
 *
 *  The column has no authority over anything. If it and deriveIntroState ever
 *  disagree the column is wrong by definition, which is why it is written from the
 *  derivation and never assigned by an action. */
export function materializeStatus(introId: string, now: Date = new Date()): IntroState {
  const facts = introFacts(introId)
  if (facts === null) throw new Error(`materializeStatus called for an intro that does not exist: ${introId}`)
  const state = deriveIntroState(facts, now)
  d().prepare('UPDATE v3_intros SET status = ? WHERE id = ?').run(materializedStatus(state), introId)
  return state
}

// ── The expiry sweep ──────────────────────────────────────────────────────

/** The shortest TTL, which is what makes the candidate filter both sound and complete.
 *
 *  Every expiry basis is at or after the intro's own created_at: `requested` measures from
 *  it directly, `interested` from an authorization inserted no earlier, and `connecting`
 *  from a continuation inserted later still. So the EARLIEST any intro can expire is
 *  created_at plus 14 days, and an intro younger than that cannot be expired whatever its
 *  facts say. That argument is why the filter can be one comparison rather than a scan. */
const SHORTEST_TTL_DAYS = 14

/** Bring v3_intros.status into line for rows that expired without anyone writing to them.
 *
 *  THE SWEEP WRITES NOTHING EXCEPT THE MATERIALIZATION. It does not compute or store an
 *  expiry, because deriveIntroState already answers `expired` for any row past its derived
 *  deadline. What it exists for is the legacy reader: a row that lapsed with no write would
 *  otherwise keep showing `pending` or `accepted` to a 3.2.x client forever. If the
 *  materialization were dropped, this could be dropped with it.
 *
 *  It writes no authorization row, so it cannot move a deadline. That is the point of
 *  deriving expiry rather than storing it: a background job that touched a
 *  last_activity_at column is exactly the accident the design removes the column to prevent.
 *
 *  Returns the ids it materialized, so a caller can log a count rather than guess at one. */
export function sweepExpiredIntros(now: Date = new Date()): string[] {
  const earliest = new Date(now.getTime() - SHORTEST_TTL_DAYS * 24 * 3600 * 1000).toISOString()
  // The comparison is ISO string against ISO string, both in the shape SQL_NOW_ISO writes.
  // Comparing against datetime('now') instead would be lexically broken, because 'T' > ' '
  // makes such a comparison always true, which is the live bug db.ts:20-25 documents. This
  // binds a parameter rather than calling a SQL clock at all.
  const candidates = d().prepare(`
    SELECT id FROM v3_intros
    WHERE status IN ('pending', 'accepted') AND created_at < ?
    ORDER BY created_at
  `).all(earliest) as { id: string }[]

  const swept: string[] = []
  for (const { id } of candidates) {
    const facts = introFacts(id)
    if (facts === null) continue
    if (deriveIntroState(facts, now) !== 'expired') continue
    // One derived write, through the same function every canonical write uses, so the sweep
    // cannot disagree with the derivation about what the column should say.
    materializeStatus(id, now)
    swept.push(id)
  }
  return swept
}
