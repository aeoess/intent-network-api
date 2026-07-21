// ══════════════════════════════════════════════════════════════
// Mingle email notifications - storage (additive)
// ══════════════════════════════════════════════════════════════
// A subscription table keyed by subject_key and an email-send log for
// dedupe and the per-recipient daily cap. Email addresses live ONLY here.
// They never appear in a card, page, search result, or receipt, and there is
// no route that lists them. The tables sit beside the live schema; nothing
// existing is altered.

import type { Database } from 'better-sqlite3'
import { getDb } from './db.js'

let initialized = false

export function initNotifySchema(): void {
  const dd = getDb()
  dd.exec(`
    CREATE TABLE IF NOT EXISTS notifications (
      subject_key TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      verified INTEGER NOT NULL DEFAULT 0,
      verify_token TEXT NOT NULL,
      unsub_token TEXT NOT NULL,
      prefs_json TEXT NOT NULL DEFAULT '{"intro_request":true,"intro_accepted":true,"weekly_digest":false}',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_verify ON notifications(verify_token);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_unsub ON notifications(unsub_token);

    CREATE TABLE IF NOT EXISTS email_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject_key TEXT NOT NULL,
      intro_id TEXT NOT NULL,
      type TEXT NOT NULL,
      sent_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      UNIQUE (subject_key, intro_id, type)
    );
    CREATE INDEX IF NOT EXISTS idx_email_log_recipient_day ON email_log(subject_key, sent_at);
  `)
  initialized = true
}

function d(): Database {
  if (!initialized) initNotifySchema()
  return getDb()
}

export interface NotifPrefs { intro_request: boolean; intro_accepted: boolean; weekly_digest: boolean }
export interface Subscription {
  subject_key: string
  email: string
  verified: boolean
  verify_token: string
  unsub_token: string
  prefs: NotifPrefs
}

function rowToSub(row: any): Subscription {
  const parsed = JSON.parse(row.prefs_json) as Partial<NotifPrefs>
  return {
    subject_key: row.subject_key, email: row.email, verified: !!row.verified,
    verify_token: row.verify_token, unsub_token: row.unsub_token,
    // weekly_digest defaults off for any row stored before the pref existed.
    prefs: {
      intro_request: parsed.intro_request !== false,
      intro_accepted: parsed.intro_accepted !== false,
      weekly_digest: parsed.weekly_digest === true,
    },
  }
}

/** Verified subscribers who opted into the weekly digest. Emails live only in
 *  this table; this is the sole reader for the weekly job. */
export function weeklyDigestSubscribers(): Subscription[] {
  const rows = d().prepare("SELECT * FROM notifications WHERE verified = 1 AND json_extract(prefs_json, '$.weekly_digest') = 1").all() as any[]
  return rows.map(rowToSub)
}

/** Upsert a subscription as UNVERIFIED with fresh tokens. Changing the email
 *  resets verification, so a confirmation is always required for a new address. */
export function upsertSubscription(subjectKey: string, email: string, verifyToken: string, unsubToken: string, prefs: NotifPrefs): void {
  d().prepare(`
    INSERT INTO notifications (subject_key, email, verified, verify_token, unsub_token, prefs_json, updated_at)
    VALUES (?, ?, 0, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    ON CONFLICT(subject_key) DO UPDATE SET
      email = excluded.email,
      verified = CASE WHEN notifications.email = excluded.email THEN notifications.verified ELSE 0 END,
      verify_token = excluded.verify_token,
      prefs_json = excluded.prefs_json,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
  `).run(subjectKey, email, verifyToken, unsubToken, JSON.stringify(prefs))
}

export function getSubscription(subjectKey: string): Subscription | null {
  const row = d().prepare('SELECT * FROM notifications WHERE subject_key = ?').get(subjectKey) as any
  return row ? rowToSub(row) : null
}

export function confirmByToken(token: string): Subscription | null {
  const row = d().prepare('SELECT * FROM notifications WHERE verify_token = ?').get(token) as any
  if (!row) return null
  d().prepare('UPDATE notifications SET verified = 1, updated_at = strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\') WHERE subject_key = ?').run(row.subject_key)
  return rowToSub({ ...row, verified: 1 })
}

export function deleteSubscription(subjectKey: string): boolean {
  return d().prepare('DELETE FROM notifications WHERE subject_key = ?').run(subjectKey).changes > 0
}

export function deleteByUnsubToken(token: string): boolean {
  return d().prepare('DELETE FROM notifications WHERE unsub_token = ?').run(token).changes > 0
}

// ── dedupe + daily cap ────────────────────────────────────────────────────

const DAILY_CAP = 10

/** Reserve an email send. Returns false when this exact (recipient, intro_id,
 *  type) already went out (dedupe) or, for non-direct mail, the recipient hit
 *  the daily cap. Direct-action mail (a person acted on something they joined)
 *  skips the cap but still dedupes. On true the row is recorded, so callers
 *  should only send after a true. */
export function reserveSend(subjectKey: string, introId: string, type: string, direct = false): { ok: boolean; reason?: string } {
  if (!direct) {
    const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString()
    const count = (d().prepare('SELECT COUNT(*) AS n FROM email_log WHERE subject_key = ? AND sent_at > ?').get(subjectKey, since) as any).n
    if (count >= DAILY_CAP) return { ok: false, reason: 'daily_cap' }
  }
  try {
    d().prepare('INSERT INTO email_log (subject_key, intro_id, type) VALUES (?, ?, ?)').run(subjectKey, introId, type)
    return { ok: true }
  } catch {
    return { ok: false, reason: 'duplicate' }
  }
}
