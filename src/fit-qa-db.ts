// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - adaptive question answers (additive)
// ══════════════════════════════════════════════════════════════
// One answer per (intro, dimension, answerer). A drafted counterparty answer is
// stored as BOTH its raw human-visible text and the airlock's structured
// extraction; the extraction is what any policy-bearing planner may read, the
// raw is only ever shown to the human. Ledger answers pull an approved v3
// disclosure sentence verbatim. Skips are not_answered, never negative evidence.

import type { Database } from 'better-sqlite3'
import { getDb } from './db.js'

let initialized = false

export type QaMode = 'ledger' | 'drafted' | 'skip'

export function initQaSchema(): void {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS v4_fit_qa (
      intro_id TEXT NOT NULL,
      dimension TEXT NOT NULL,
      answerer_key TEXT NOT NULL,
      mode TEXT NOT NULL,
      text TEXT,
      extraction_json TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (intro_id, dimension, answerer_key)
    );
    CREATE TABLE IF NOT EXISTS v4_fit_qa_round2 (
      intro_id TEXT NOT NULL,
      requester_key TEXT NOT NULL,
      dimension TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (intro_id, requester_key, dimension)
    );
  `)
  initialized = true
}

function d(): Database {
  if (!initialized) initQaSchema()
  return getDb()
}

export interface QaRow {
  intro_id: string
  dimension: string
  answerer_key: string
  mode: QaMode
  text: string | null
  extraction_json: string | null
  created_at: string
}

export function upsertQa(a: { intro_id: string; dimension: string; answerer_key: string; mode: QaMode; text?: string | null; extraction_json?: string | null }): void {
  d().prepare(`INSERT INTO v4_fit_qa (intro_id, dimension, answerer_key, mode, text, extraction_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    ON CONFLICT(intro_id, dimension, answerer_key) DO UPDATE SET mode = excluded.mode, text = excluded.text, extraction_json = excluded.extraction_json, created_at = excluded.created_at`)
    .run(a.intro_id, a.dimension, a.answerer_key, a.mode, a.text ?? null, a.extraction_json ?? null)
}

export function qaForIntro(introId: string): QaRow[] {
  return d().prepare('SELECT * FROM v4_fit_qa WHERE intro_id = ?').all(introId) as QaRow[]
}

/** Dimensions any party has answered with a real (non-skip) answer, used to
 *  drop them from the unresolved set. */
export function settledDimensions(introId: string): Set<string> {
  const rows = d().prepare("SELECT DISTINCT dimension FROM v4_fit_qa WHERE intro_id = ? AND mode != 'skip'").all(introId) as any[]
  return new Set(rows.map(r => r.dimension))
}

export function addRound2(introId: string, requesterKey: string, dimension: string): void {
  d().prepare('INSERT OR IGNORE INTO v4_fit_qa_round2 (intro_id, requester_key, dimension) VALUES (?, ?, ?)').run(introId, requesterKey, dimension)
}
export function round2ForIntro(introId: string): { requester_key: string; dimension: string; created_at: string }[] {
  return d().prepare('SELECT requester_key, dimension, created_at FROM v4_fit_qa_round2 WHERE intro_id = ?').all(introId) as any[]
}
