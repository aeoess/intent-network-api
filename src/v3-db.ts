// ══════════════════════════════════════════════════════════════
// Mingle v3 - Additive storage
// ══════════════════════════════════════════════════════════════
// New tables beside the live cards/intros/embeddings tables. Nothing in the
// existing schema is altered; the 48h IntentCard path is untouched. The v3
// semantic index reuses the same MiniLM embed pipeline but its vectors live
// in a separate vec table so 48h matching never sees v3 rows.

import type { Database } from 'better-sqlite3'
import { getDb, SQL_NOW_ISO } from './db.js'
import type { RevocationStatus, V3Card } from './v3-cards.js'
import { networkVisibleView } from './v3-cards.js'

let initialized = false

export function initV3Schema(): void {
  const d = getDb()
  d.exec(`
    CREATE TABLE IF NOT EXISTS v3_cards (
      card_id TEXT PRIMARY KEY,
      card_type TEXT NOT NULL,
      subject_key TEXT NOT NULL,
      card_hash TEXT NOT NULL,
      card_json TEXT NOT NULL,
      headline TEXT NOT NULL,
      intents_json TEXT NOT NULL,
      event_ref_id TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      revocation_status TEXT NOT NULL DEFAULT 'active',
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_v3_cards_subject ON v3_cards(subject_key);
    CREATE INDEX IF NOT EXISTS idx_v3_cards_type ON v3_cards(card_type);
    CREATE INDEX IF NOT EXISTS idx_v3_cards_expires ON v3_cards(expires_at);
    CREATE INDEX IF NOT EXISTS idx_v3_cards_event ON v3_cards(event_ref_id);

    CREATE VIRTUAL TABLE IF NOT EXISTS v3_embeddings USING vec0(
      embedding float[384]
    );
    CREATE TABLE IF NOT EXISTS v3_embedding_cards (
      rowid_ref INTEGER PRIMARY KEY,
      card_id TEXT NOT NULL
    );
  `)
  initialized = true
}

function d(): Database {
  if (!initialized) initV3Schema()
  return getDb()
}

export interface StoredV3Card {
  card_id: string
  card: V3Card
  revocation_status: RevocationStatus
  expires_at: string
}

export function insertV3Card(cardId: string, card: V3Card, cardHash: string): void {
  d().prepare(`
    INSERT INTO v3_cards (card_id, card_type, subject_key, card_hash, card_json, headline, intents_json, event_ref_id, created_at, expires_at, revocation_status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    cardId, card.card_type, card.subject_key, cardHash, JSON.stringify(card),
    card.headline, JSON.stringify(card.intents), card.event_ref?.event_id ?? null,
    card.created_at, card.expires_at, card.revocation_status,
  )
}

export function getV3Card(cardId: string): StoredV3Card | null {
  const row = d().prepare('SELECT card_id, card_json, revocation_status, expires_at FROM v3_cards WHERE card_id = ?').get(cardId) as any
  if (!row) return null
  const card = JSON.parse(row.card_json) as V3Card
  card.revocation_status = row.revocation_status
  return { card_id: row.card_id, card, revocation_status: row.revocation_status, expires_at: row.expires_at }
}

export function setRevocationStatus(cardId: string, subjectKey: string, status: RevocationStatus): boolean {
  const res = d().prepare(`
    UPDATE v3_cards SET revocation_status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE card_id = ? AND subject_key = ?
  `).run(status, cardId, subjectKey)
  return res.changes > 0
}

export function deleteV3Card(cardId: string, subjectKey: string): boolean {
  const owned = d().prepare('SELECT 1 FROM v3_cards WHERE card_id = ? AND subject_key = ?').get(cardId, subjectKey)
  if (!owned) return false
  removeFromIndex(cardId)
  // The row itself flips to deleted rather than vanishing, so every stored
  // copy can show its status on open (spec: status shown on every fetch).
  d().prepare(`
    UPDATE v3_cards SET revocation_status = 'deleted', card_json = json_object('card_type', card_type, 'deleted', 1),
      headline = '[deleted]', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE card_id = ?
  `).run(cardId)
  return true
}

// ── Semantic index (separate from the 48h pipeline) ──────────────────────

export function storeV3Embedding(cardId: string, vector: Float32Array): void {
  const res = d().prepare('INSERT INTO v3_embeddings (embedding) VALUES (?)').run(Buffer.from(vector.buffer, vector.byteOffset, vector.byteLength))
  d().prepare('INSERT INTO v3_embedding_cards (rowid_ref, card_id) VALUES (?, ?)').run(res.lastInsertRowid, cardId)
}

export function removeFromIndex(cardId: string): void {
  const rows = d().prepare('SELECT rowid_ref FROM v3_embedding_cards WHERE card_id = ?').all(cardId) as any[]
  for (const r of rows) d().prepare('DELETE FROM v3_embeddings WHERE rowid = ?').run(r.rowid_ref)
  d().prepare('DELETE FROM v3_embedding_cards WHERE card_id = ?').run(cardId)
}

export function semanticSearchV3(queryVec: Float32Array, limit: number): { card_id: string; distance: number }[] {
  const rows = d().prepare(`
    SELECT c.card_id AS card_id, e.distance AS distance
    FROM v3_embeddings e
    JOIN v3_embedding_cards c ON c.rowid_ref = e.rowid
    WHERE e.embedding MATCH ? AND e.k = ?
    ORDER BY e.distance
  `).all(Buffer.from(queryVec.buffer, queryVec.byteOffset, queryVec.byteLength), limit * 3) as any[]
  return rows.map(r => ({ card_id: r.card_id, distance: r.distance }))
}

// ── Explicit-field search with visibility filtering ──────────────────────

export interface V3SearchFilters {
  card_type?: string
  intents?: string[]
  topics?: string[]
  engagement?: string
  location?: string
  event_ref?: string
}

const SEARCH_CAP = 50

export function searchV3Cards(filters: V3SearchFilters, semanticIds?: string[], limit = 20): Record<string, unknown>[] {
  const cap = Math.min(limit, SEARCH_CAP)
  const where: string[] = [
    `expires_at > ${SQL_NOW_ISO}`,
    `revocation_status IN ('active')`,
  ]
  const params: unknown[] = []
  if (filters.card_type) { where.push('card_type = ?'); params.push(filters.card_type) }
  if (filters.event_ref) { where.push('event_ref_id = ?'); params.push(filters.event_ref) }
  const rows = d().prepare(`SELECT card_id, card_json, revocation_status FROM v3_cards WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT 500`).all(...params) as any[]

  const results: Record<string, unknown>[] = []
  for (const row of rows) {
    const card = JSON.parse(row.card_json) as V3Card
    card.revocation_status = row.revocation_status
    if (semanticIds && !semanticIds.includes(row.card_id)) continue
    if (filters.intents?.length && !filters.intents.some(i => card.intents.includes(i))) continue
    if (filters.topics?.length) {
      const cardTopics = [...card.seeking, ...card.offering].flatMap(e => e.topics ?? [])
      if (!filters.topics.some(t => cardTopics.some(ct => ct.toLowerCase().includes(t.toLowerCase())))) continue
    }
    if (filters.engagement) {
      const engagements = card.seeking.map(s => s.engagement).filter(Boolean) as string[]
      const prefEngagement = card.preferences.filter(p => p.key === 'engagement').map(p => p.value)
      if (![...engagements, ...prefEngagement].some(e => e.toLowerCase().includes(filters.engagement!.toLowerCase()))) continue
    }
    if (filters.location) {
      const locPrefs = card.preferences.filter(p => p.key === 'location').map(p => p.value)
      if (!locPrefs.some(l => l.toLowerCase().includes(filters.location!.toLowerCase()))) continue
    }
    results.push(networkVisibleView({ ...card, card_id: row.card_id }))
    if (results.length >= cap) break
  }
  return results
}

// ── Expiry sweep with index removal ──────────────────────────────────────

export function sweepExpiredV3Cards(): { swept: number } {
  const expired = d().prepare(`SELECT card_id FROM v3_cards WHERE expires_at <= ${SQL_NOW_ISO} AND revocation_status != 'deleted'`).all() as any[]
  for (const row of expired) removeFromIndex(row.card_id)
  const res = d().prepare(`
    UPDATE v3_cards SET revocation_status = CASE WHEN revocation_status = 'active' THEN 'withdrawn' ELSE revocation_status END,
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE expires_at <= ${SQL_NOW_ISO} AND revocation_status = 'active'
  `).run()
  return { swept: res.changes }
}

export function v3CardCount(): number {
  return (d().prepare(`SELECT COUNT(*) AS n FROM v3_cards WHERE expires_at > ${SQL_NOW_ISO} AND revocation_status = 'active'`).get() as any).n
}
