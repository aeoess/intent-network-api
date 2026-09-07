// ══════════════════════════════════════════════════════════════
// Mingle - append-only card event ledger (additive)
// ══════════════════════════════════════════════════════════════
// Every consequential transition a card goes through writes one row here and
// nothing ever updates or deletes one. That is the point: the stats surface and
// any later audit read history from this table rather than from mutable
// counters, so a number can be traced back to the events that produced it.
//
// recordCardEvent never throws into a caller. An event that cannot be written
// is a lost line in a log; a publish or a match that fails because the log
// failed would be a far worse outcome, so the write is wrapped the way
// finalizePublish wraps its embedding and match work.
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

/** The transitions this ledger records. Listing them as a closed set keeps a
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

/** Append one event. Insert-only, and never throws into the caller's response. */
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

// ── Read helpers (stats, tests, audit) ────────────────────────────────────

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
