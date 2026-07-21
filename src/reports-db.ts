// ══════════════════════════════════════════════════════════════
// Mingle v3 abuse reports - storage (additive)
// ══════════════════════════════════════════════════════════════
// A minimal report row so a human or agent can flag a card. Reasons are capped
// and URL-free (checked at the route), which keeps the store from becoming a
// link-injection channel. No route lists reports; they exist for the operator.

import type { Database } from 'better-sqlite3'
import { getDb } from './db.js'

let initialized = false

export function initReportsSchema(): void {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS v3_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      card_id TEXT NOT NULL,
      reason TEXT NOT NULL,
      reporter_ip TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_v3_reports_card ON v3_reports(card_id);
  `)
  initialized = true
}

function d(): Database {
  if (!initialized) initReportsSchema()
  return getDb()
}

export function insertReport(cardId: string, reason: string, reporterIp: string | null): number {
  const res = d().prepare('INSERT INTO v3_reports (card_id, reason, reporter_ip) VALUES (?, ?, ?)').run(cardId, reason, reporterIp)
  return Number(res.lastInsertRowid)
}

export function reportCount(cardId: string): number {
  return (d().prepare('SELECT COUNT(*) AS n FROM v3_reports WHERE card_id = ?').get(cardId) as any).n
}
