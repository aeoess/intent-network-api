// ══════════════════════════════════════════════════════════════
// Intent Network API — Database Layer
// ══════════════════════════════════════════════════════════════
// SQLite with WAL mode. Cards, intros, rate limits.
// Ed25519 public keys are the identity — no accounts needed.

import Database from 'better-sqlite3'
import { join } from 'node:path'
import type { IntentCard, IntroRequest, IntroResponse, RelevanceMatch } from 'agent-passport-system'

const DB_PATH = process.env.DB_PATH || join(process.cwd(), 'data', 'intent-network.db')

let db: Database.Database

export function getDb(): Database.Database {
  if (!db) {
    db = new Database(DB_PATH)
    db.pragma('journal_mode = WAL')
    db.pragma('busy_timeout = 5000')
    db.pragma('synchronous = NORMAL')
    db.pragma('foreign_keys = ON')
    initSchema()
  }
  return db
}

function initSchema(): void {
  const d = db

  // ── Schema ──
  d.exec(`
    CREATE TABLE IF NOT EXISTS cards (
      card_id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      principal_alias TEXT NOT NULL,
      card_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_cards_agent ON cards(agent_id);
    CREATE INDEX IF NOT EXISTS idx_cards_pubkey ON cards(public_key);
    CREATE INDEX IF NOT EXISTS idx_cards_expires ON cards(expires_at);

    CREATE TABLE IF NOT EXISTS intros (
      intro_id TEXT PRIMARY KEY,
      requested_by TEXT NOT NULL,
      target_agent_id TEXT NOT NULL,
      match_id TEXT NOT NULL,
      message TEXT NOT NULL,
      fields_to_disclose TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'pending',
      response_json TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_intros_requested ON intros(requested_by);
    CREATE INDEX IF NOT EXISTS idx_intros_target ON intros(target_agent_id);
    CREATE INDEX IF NOT EXISTS idx_intros_status ON intros(status);

    CREATE TABLE IF NOT EXISTS rate_limits (
      public_key TEXT NOT NULL,
      action TEXT NOT NULL,
      window_start TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 1,
      PRIMARY KEY (public_key, action, window_start)
    );

    CREATE TABLE IF NOT EXISTS network_stats (
      stat_key TEXT PRIMARY KEY,
      stat_value INTEGER NOT NULL DEFAULT 0
    );

    INSERT OR IGNORE INTO network_stats (stat_key, stat_value) VALUES
      ('total_cards_published', 0),
      ('total_matches_computed', 0),
      ('total_intros_requested', 0),
      ('total_intros_approved', 0),
      ('total_intros_declined', 0);
  `)
}

// ══════════════════════════════════════
// Card Operations
// ══════════════════════════════════════

export function publishCard(card: IntentCard): { published: boolean; error?: string } {
  const d = getDb()
  // Remove expired cards first
  purgeExpired()

  // Check if agent already has a card (one card per agent)
  const existing = d.prepare('SELECT card_id FROM cards WHERE agent_id = ?').get(card.agentId) as any
  if (existing) {
    // Update existing card
    d.prepare(`
      UPDATE cards SET card_json = ?, principal_alias = ?, expires_at = ?, updated_at = datetime('now')
      WHERE agent_id = ?
    `).run(JSON.stringify(card), card.principalAlias, card.expiresAt, card.agentId)
    return { published: true }
  }

  d.prepare(`
    INSERT INTO cards (card_id, agent_id, public_key, principal_alias, card_json, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(card.cardId, card.agentId, card.publicKey, card.principalAlias, JSON.stringify(card), card.createdAt, card.expiresAt)

  incrementStat('total_cards_published')
  return { published: true }
}

export function getCard(agentId: string): IntentCard | null {
  const d = getDb()
  purgeExpired()
  const row = d.prepare('SELECT card_json FROM cards WHERE agent_id = ? AND expires_at > datetime(\'now\')').get(agentId) as any
  return row ? JSON.parse(row.card_json) : null
}

export function removeCard(cardId: string, agentId: string): boolean {
  const d = getDb()
  const result = d.prepare('DELETE FROM cards WHERE card_id = ? AND agent_id = ?').run(cardId, agentId)
  return result.changes > 0
}

export function getAllActiveCards(): IntentCard[] {
  const d = getDb()
  purgeExpired()
  const rows = d.prepare('SELECT card_json FROM cards WHERE expires_at > datetime(\'now\')').all() as any[]
  return rows.map(r => JSON.parse(r.card_json))
}

export function getCardCount(): number {
  const d = getDb()
  return (d.prepare('SELECT COUNT(*) as count FROM cards WHERE expires_at > datetime(\'now\')').get() as any).count
}

// ══════════════════════════════════════
// Intro Operations
// ══════════════════════════════════════

export function createIntro(intro: IntroRequest): { created: boolean; error?: string } {
  const d = getDb()
  try {
    d.prepare(`
      INSERT INTO intros (intro_id, requested_by, target_agent_id, match_id, message, fields_to_disclose, status, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(intro.introId, intro.requestedBy, intro.targetAgentId, intro.matchId, intro.message,
      JSON.stringify(intro.fieldsToDisclose), intro.status, intro.createdAt, intro.expiresAt)
    incrementStat('total_intros_requested')
    return { created: true }
  } catch (e: any) {
    return { created: false, error: e.message }
  }
}

export function getIntro(introId: string): IntroRequest | null {
  const d = getDb()
  const row = d.prepare('SELECT * FROM intros WHERE intro_id = ?').get(introId) as any
  if (!row) return null
  return {
    introId: row.intro_id,
    requestedBy: row.requested_by,
    targetAgentId: row.target_agent_id,
    matchId: row.match_id,
    message: row.message,
    fieldsToDisclose: JSON.parse(row.fields_to_disclose),
    status: row.status,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    signature: '',
  }
}

export function updateIntroStatus(introId: string, status: string, responseJson?: string): boolean {
  const d = getDb()
  const result = d.prepare(`
    UPDATE intros SET status = ?, response_json = ?, updated_at = datetime('now') WHERE intro_id = ?
  `).run(status, responseJson || null, introId)
  if (result.changes > 0) {
    if (status === 'approved') incrementStat('total_intros_approved')
    if (status === 'declined') incrementStat('total_intros_declined')
  }
  return result.changes > 0
}

export function getIntrosForAgent(agentId: string): { sent: IntroRequest[]; received: IntroRequest[] } {
  const d = getDb()
  const sent = d.prepare('SELECT * FROM intros WHERE requested_by = ? AND status = \'pending\'').all(agentId) as any[]
  const received = d.prepare('SELECT * FROM intros WHERE target_agent_id = ? AND status = \'pending\'').all(agentId) as any[]

  const mapRow = (row: any): IntroRequest => ({
    introId: row.intro_id,
    requestedBy: row.requested_by,
    targetAgentId: row.target_agent_id,
    matchId: row.match_id,
    message: row.message,
    fieldsToDisclose: JSON.parse(row.fields_to_disclose),
    status: row.status,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    signature: '',
  })
  return { sent: sent.map(mapRow), received: received.map(mapRow) }
}

// ══════════════════════════════════════
// Rate Limiting
// ══════════════════════════════════════

export function checkRateLimit(publicKey: string, action: string, maxPerHour: number): { allowed: boolean; remaining: number } {
  const d = getDb()
  const windowStart = new Date()
  windowStart.setMinutes(0, 0, 0)
  const window = windowStart.toISOString()

  const row = d.prepare(
    'SELECT count FROM rate_limits WHERE public_key = ? AND action = ? AND window_start = ?'
  ).get(publicKey, action, window) as any

  const current = row?.count || 0
  if (current >= maxPerHour) {
    return { allowed: false, remaining: 0 }
  }

  // Upsert
  d.prepare(`
    INSERT INTO rate_limits (public_key, action, window_start, count)
    VALUES (?, ?, ?, 1)
    ON CONFLICT(public_key, action, window_start) DO UPDATE SET count = count + 1
  `).run(publicKey, action, window)

  return { allowed: true, remaining: maxPerHour - current - 1 }
}

// ══════════════════════════════════════
// Utilities
// ══════════════════════════════════════

export function purgeExpired(): number {
  const d = getDb()
  const cards = d.prepare('DELETE FROM cards WHERE expires_at <= datetime(\'now\')').run()
  const intros = d.prepare('UPDATE intros SET status = \'expired\' WHERE status = \'pending\' AND expires_at <= datetime(\'now\')').run()
  // Clean old rate limit windows (older than 2 hours)
  const cutoff = new Date(Date.now() - 2 * 3600 * 1000).toISOString()
  d.prepare('DELETE FROM rate_limits WHERE window_start < ?').run(cutoff)
  return cards.changes + intros.changes
}

function incrementStat(key: string): void {
  const d = getDb()
  d.prepare('UPDATE network_stats SET stat_value = stat_value + 1 WHERE stat_key = ?').run(key)
}

export function getNetworkStats(): Record<string, number> {
  const d = getDb()
  const rows = d.prepare('SELECT stat_key, stat_value FROM network_stats').all() as any[]
  const stats: Record<string, number> = {}
  for (const row of rows) stats[row.stat_key] = row.stat_value
  stats.active_cards = getCardCount()
  stats.pending_intros = (d.prepare('SELECT COUNT(*) as c FROM intros WHERE status = \'pending\'').get() as any).c
  return stats
}

export function closeDb(): void {
  if (db) db.close()
}
