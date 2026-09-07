// ══════════════════════════════════════════════════════════════
// Mingle - append-only card event log (additive)
// ══════════════════════════════════════════════════════════════
// Every consequential transition a card goes through writes one row here and
// nothing ever updates or deletes one. That is the point: the stats surface and
// any later review read history from this table rather than from mutable
// counters, so a number can be traced back to the events that produced it.
//
// This is an event log, not an audit ledger. It is not a tamper-evident record
// and it does not claim to be one: rows carry no hash chain and no signature,
// and a writer with database access can rewrite history without leaving a
// trace. Do not cite it as proof of what happened; cite it as the server's own
// account of what it did.
//
// TRANSACTIONALITY. Event insertion is NOT transactional with every state
// change it records. Two shapes exist and the difference matters when reading
// a count:
//
//   In-transaction (event and state change commit or roll back together):
//     - legacy card expiry in db.ts purgeExpired, via recordCardEventStrict
//       inside the same better-sqlite3 transaction as the DELETE.
//
//   Best-effort, NOT in a transaction with the change (every other site):
//     - card_published, card_renewed, card_server_copy_deleted and the four
//       revocation verbs (v3-routes.ts)
//     - card_expired from the v3 sweep (v3-db.ts) - the events are written
//       after the UPDATE commits
//     - embedding_stored / embedding_failed, match_notified /
//       match_notify_skipped (v3-routes.ts)
//     - matching_started, match_created, match_removed, match_dismissed
//       (matches-db.ts)
//     - digest_read (match-routes.ts)
//     - intro_requested / intro_accepted / intro_declined (intros-routes.ts)
//     - handshake_requested / handshake_committed, first_step_proposed /
//       first_step_approved (fit-v4-routes.ts)
//     - handshake_closed (fit-routes.ts)
//
// At those sites recordCardEvent swallows its own failure, so a lost event
// leaves the state change standing. That is deliberate - a publish must not
// fail because a log line could not be written - but it means an event count
// is a floor, not a guarantee. recordCardEventStrict is the opposite: it
// throws, so a caller inside a transaction rolls the state change back with it.
//
// There is deliberately no update or delete statement in this module, and a
// test greps src/ to keep it that way.

import type { Database } from 'better-sqlite3'
import { getDb } from './db.js'

let initialized = false

export function initCardEventsSchema(): void {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS card_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      card_id TEXT,
      subject_key TEXT,
      event TEXT NOT NULL,
      detail_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_card_events_card ON card_events(card_id);
    CREATE INDEX IF NOT EXISTS idx_card_events_event ON card_events(event);
  `)
  initialized = true
}

function d(): Database {
  if (!initialized) initCardEventsSchema()
  return getDb()
}

/** The transitions this log records. Listing them as a closed set keeps a
 *  typo from silently creating a new event name that no stats query counts. */
export const CARD_EVENTS = [
  'card_published',
  'card_renewed',
  'card_expired',
  'card_withdrawn',
  'card_superseded',
  'card_authority_revoked',
  'card_stopped_new_matches',
  'card_server_copy_deleted',
  'embedding_stored',
  'embedding_failed',
  'matching_started',
  'match_created',
  'match_removed',
  'match_dismissed',
  'match_notified',
  'match_notify_skipped',
  'digest_read',
  'handshake_requested',
  'handshake_committed',
  'handshake_closed',
  'intro_requested',
  'intro_accepted',
  'intro_declined',
  'first_step_proposed',
  'first_step_approved',
] as const

export type CardEvent = typeof CARD_EVENTS[number]

/** Create the table if it does not exist yet. Callers that need to write an
 *  event inside their own transaction must call this first: the lazy creation
 *  in d() would otherwise run DDL from inside that transaction. */
export function ensureCardEventsSchema(): void {
  if (!initialized) initCardEventsSchema()
}

/** Append one event. Insert-only, and never throws into the caller's response.
 *  Use this everywhere except inside a transaction the event must share. */
export function recordCardEvent(
  event: CardEvent,
  cardId: string | null,
  subjectKey: string | null,
  detail?: Record<string, unknown>,
): void {
  try {
    d().prepare('INSERT INTO card_events (card_id, subject_key, event, detail_json) VALUES (?, ?, ?, ?)')
      .run(cardId, subjectKey, event, detail ? JSON.stringify(detail) : null)
  } catch (e) {
    console.error('[card-events] failed to record', event, (e as Error).message)
  }
}

/** Append one event on an explicit connection and THROW on failure, so a caller
 *  running inside a transaction rolls its own state change back rather than
 *  committing a change the log does not record. The connection is passed in
 *  rather than fetched, so this module never reaches back into db.ts on the
 *  transactional path. */
export function recordCardEventStrict(
  conn: Database,
  event: CardEvent,
  cardId: string | null,
  subjectKey: string | null,
  detail?: Record<string, unknown>,
): void {
  conn.prepare('INSERT INTO card_events (card_id, subject_key, event, detail_json) VALUES (?, ?, ?, ?)')
    .run(cardId, subjectKey, event, detail ? JSON.stringify(detail) : null)
}

// ── Read helpers (stats, tests, review) ────────────────────────────────────

export function countEvents(event: CardEvent): number {
  return (d().prepare('SELECT COUNT(*) AS n FROM card_events WHERE event = ?').get(event) as any).n
}

export interface CardEventRow {
  id: number
  at: string
  card_id: string | null
  subject_key: string | null
  event: string
  detail_json: string | null
}

export function eventsForCard(cardId: string): CardEventRow[] {
  return d().prepare('SELECT * FROM card_events WHERE card_id = ? ORDER BY id').all(cardId) as any[]
}

export function recentEvents(limit = 50): CardEventRow[] {
  return d().prepare('SELECT * FROM card_events ORDER BY id DESC LIMIT ?').all(limit) as any[]
}
