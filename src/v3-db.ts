// ══════════════════════════════════════════════════════════════
// Mingle v3 - Additive storage
// ══════════════════════════════════════════════════════════════
// New tables beside the live cards/intros/embeddings tables. Nothing in the
// existing schema is altered; the 48h IntentCard path is untouched. The v3
// semantic index reuses the same MiniLM embed pipeline but its vectors live
// in a separate vec table so 48h matching never sees v3 rows.

import type { Database } from 'better-sqlite3'
import { createHash } from 'node:crypto'
import { getDb, getSchemaMarker, SQL_NOW_ISO, V3_2_MARKER_KEY } from './db.js'
import type { RevocationStatus, V3Card } from './v3-cards.js'
import { networkVisibleView } from './v3-cards.js'
import { recordCardEvent } from './card-events.js'
import { pageFairness, words, overlap, SIMILAR, NEAR_DUPLICATES_PER_PAGE } from './page-fairness.js'
import { networkVisibleText } from './v3-cards.js'

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

    -- Operator moderation, kept apart from the signed revocation_status so hiding a
    -- card never pretends its owner withdrew it. target_type 'card' hides one card,
    -- 'subject' hides every card of a key, including ones published later.
    CREATE TABLE IF NOT EXISTS v3_moderation (
      target_type TEXT NOT NULL CHECK (target_type IN ('card', 'subject')),
      target TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'hidden' CHECK (status IN ('hidden')),
      reason TEXT NOT NULL,
      actor TEXT NOT NULL,
      at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (target_type, target)
    );
  `)
  ensureCardHashUnique(d)
  ensureReceivedAt(d)
  initialized = true
}

/** received_at is the server's own clock when the row was stored. created_at is
 *  signed by the client and bounded at write time, received_at is what the server
 *  saw. Added as a nullable column, so rows from before it, and rows written by
 *  older code after a rollback, read as null. */
function ensureReceivedAt(db: Database): void {
  const cols = db.prepare('PRAGMA table_info(v3_cards)').all() as { name: string }[]
  if (!cols.some(c => c.name === 'received_at')) db.exec('ALTER TABLE v3_cards ADD COLUMN received_at TEXT')
  // A salted hash of the publishing client address, server side only and never
  // returned. Search uses it to fold near identical cards from one source.
  if (!cols.some(c => c.name === 'source_hash')) db.exec('ALTER TABLE v3_cards ADD COLUMN source_hash TEXT')
}

const SOURCE_SALT = process.env.MINGLE_SOURCE_SALT ?? 'mingle-source-v1'
/** The stored form of a publishing address. Loopback (the operator) stores nothing. */
export function sourceHashOf(ip: string | undefined): string | null {
  if (!ip || ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return null
  return createHash('sha256').update(SOURCE_SALT + ':' + ip).digest('hex').slice(0, 32)
}

/** One stored row per (subject_key, card_hash). The route checks already refuse a
 *  repeat, and the index makes the database refuse it too, so a second process
 *  or a future async gap between check and insert cannot store the same signed
 *  card twice. If old duplicate rows exist the index cannot be built, so this
 *  logs and leaves the route checks as the only guard rather than failing boot. */
function ensureCardHashUnique(db: Database): void {
  const dup = db.prepare('SELECT 1 FROM v3_cards GROUP BY subject_key, card_hash HAVING COUNT(*) > 1 LIMIT 1').get()
  if (dup) {
    console.warn('[v3] duplicate (subject_key, card_hash) rows exist, unique index not created')
    return
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_v3_cards_subject_hash ON v3_cards(subject_key, card_hash)')
}

function d(): Database {
  if (!initialized) initV3Schema()
  return getDb()
}

/** SQL condition: the v3_cards row is not hidden by the operator, neither the card
 *  itself nor its subject key. Every network-facing read (search, the event wall,
 *  matching, counts) adds it. Queries using it must name the table v3_cards. */
const NOT_HIDDEN = `NOT EXISTS (SELECT 1 FROM v3_moderation m WHERE (m.target_type = 'card' AND m.target = v3_cards.card_id) OR (m.target_type = 'subject' AND m.target = v3_cards.subject_key))`

/** True when this card repeats, in nearly the same words, at least
 *  NEAR_DUPLICATES_PER_PAGE earlier live cards from the same publishing source. Matching
 *  skips such a card: on 2026-11-01 a test showed 60 near identical cards from one source
 *  creating 1,500 matches against real cards. "Earlier" (created_at, then card_id) keeps
 *  the hourly recompute deterministic, so the first copies match like any card and the
 *  repeats never do. A card with no stored source is never a repeat. */
export function isNearDuplicateRepeat(cardId: string): boolean {
  const me = d().prepare('SELECT card_id, source_hash, created_at, card_json FROM v3_cards WHERE card_id = ?').get(cardId) as any
  if (!me?.source_hash) return false
  const mine = words(networkVisibleText(JSON.parse(me.card_json) as V3Card))
  const earlier = d().prepare(
    `SELECT card_json FROM v3_cards WHERE source_hash = ? AND card_id != ? AND revocation_status = 'active' AND expires_at > ${SQL_NOW_ISO}
       AND (created_at < ? OR (created_at = ? AND card_id < ?)) ORDER BY created_at DESC LIMIT 200`,
  ).all(me.source_hash, cardId, me.created_at, me.created_at, cardId) as any[]
  let similar = 0
  for (const r of earlier) {
    if (overlap(words(networkVisibleText(JSON.parse(r.card_json) as V3Card)), mine) >= SIMILAR && ++similar >= NEAR_DUPLICATES_PER_PAGE) return true
  }
  return false
}

/** Every live card that is a near duplicate repeat, by the rule above, computed per
 *  source group in one pass and cached for 10 seconds, so the hourly recompute of all
 *  cards does not redo the comparison for every candidate. */
let repeatCache: { at: number; ids: Set<string> } | null = null
export function nearDuplicateRepeatIds(nowMs = Date.now()): Set<string> {
  if (repeatCache && nowMs - repeatCache.at < 10_000) return repeatCache.ids
  const rows = d().prepare(
    `SELECT card_id, source_hash, created_at, card_json FROM v3_cards WHERE source_hash IS NOT NULL AND revocation_status = 'active' AND expires_at > ${SQL_NOW_ISO}
       ORDER BY source_hash, created_at, card_id`,
  ).all() as any[]
  const ids = new Set<string>()
  let group: { id: string; w: Set<string> }[] = []
  let src: string | null = null
  for (const r of rows) {
    if (r.source_hash !== src) { group = []; src = r.source_hash }
    const w = words(networkVisibleText(JSON.parse(r.card_json) as V3Card))
    let similar = 0
    for (const g of group) if (overlap(g.w, w) >= SIMILAR && ++similar >= NEAR_DUPLICATES_PER_PAGE) break
    if (similar >= NEAR_DUPLICATES_PER_PAGE) ids.add(r.card_id)
    group.push({ id: r.card_id, w })
  }
  repeatCache = { at: nowMs, ids }
  return ids
}
export function clearNearDuplicateCache(): void { repeatCache = null }

/** True when the operator hid this card or its subject key. */
export function isHidden(cardId: string, subjectKey: string): boolean {
  return !!d().prepare(
    `SELECT 1 FROM v3_moderation WHERE (target_type = 'card' AND target = ?) OR (target_type = 'subject' AND target = ?)`,
  ).get(cardId, subjectKey)
}

/** True when the operator hid every card of this subject key. */
export function isSubjectHidden(subjectKey: string): boolean {
  return !!d().prepare(`SELECT 1 FROM v3_moderation WHERE target_type = 'subject' AND target = ?`).get(subjectKey)
}

export interface ModerationRow { target_type: 'card' | 'subject'; target: string; status: 'hidden'; reason: string; actor: string; at: string }

export function setHidden(targetType: 'card' | 'subject', target: string, reason: string, actor: string): boolean {
  const res = d().prepare(`INSERT OR IGNORE INTO v3_moderation (target_type, target, reason, actor) VALUES (?, ?, ?, ?)`).run(targetType, target, reason, actor)
  return res.changes === 1
}

export function clearHidden(targetType: 'card' | 'subject', target: string): boolean {
  return d().prepare(`DELETE FROM v3_moderation WHERE target_type = ? AND target = ?`).run(targetType, target).changes === 1
}

export function listModeration(): ModerationRow[] {
  return d().prepare(`SELECT * FROM v3_moderation ORDER BY at`).all() as ModerationRow[]
}

/** Card ids a moderation target covers: the card, or every stored card of the key. */
export function cardIdsForTarget(targetType: 'card' | 'subject', target: string): { card_id: string; subject_key: string }[] {
  return (targetType === 'card'
    ? d().prepare('SELECT card_id, subject_key FROM v3_cards WHERE card_id = ?').all(target)
    : d().prepare('SELECT card_id, subject_key FROM v3_cards WHERE subject_key = ?').all(target)) as any[]
}

export interface StoredV3Card {
  card_id: string
  card: V3Card
  revocation_status: RevocationStatus
  expires_at: string
  /** Hidden by the operator (the card or its key). Separate from revocation_status. */
  moderated: boolean
}

export function insertV3Card(cardId: string, card: V3Card, cardHash: string, sourceHash: string | null = null): void {
  d().prepare(`
    INSERT INTO v3_cards (card_id, card_type, subject_key, card_hash, card_json, headline, intents_json, event_ref_id, created_at, expires_at, revocation_status, received_at, source_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?)
  `).run(
    cardId, card.card_type, card.subject_key, cardHash, JSON.stringify(card),
    card.headline, JSON.stringify(card.intents), card.event_ref?.event_id ?? null,
    card.created_at, card.expires_at, card.revocation_status, sourceHash,
  )
}

export function getV3Card(cardId: string): StoredV3Card | null {
  const row = d().prepare('SELECT card_id, card_json, revocation_status, expires_at FROM v3_cards WHERE card_id = ?').get(cardId) as any
  if (!row) return null
  const card = JSON.parse(row.card_json) as V3Card
  card.revocation_status = row.revocation_status
  return { card_id: row.card_id, card, revocation_status: row.revocation_status, expires_at: row.expires_at, moderated: isHidden(row.card_id, card.subject_key ?? '') }
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
const MAX_SCAN = 2000

/** The JS-side filter predicate (intents, topics, engagement, location, event)
 *  shared by the wall search and the paginated agent search. It decides on the
 *  network-visible view, the same content the result shows. Deciding on the full
 *  card let a search for a hidden topic or event reveal which cards hold it by
 *  whether they came back. */
function passesJsFilters(stored: V3Card, filters: V3SearchFilters): boolean {
  const card = networkVisibleView(stored as any) as Partial<V3Card>
  const intents = card.intents ?? []
  const seeking = card.seeking ?? []
  const offering = card.offering ?? []
  const preferences = card.preferences ?? []
  if (filters.event_ref && card.event_ref?.event_id !== filters.event_ref) return false
  if (filters.intents?.length && !filters.intents.some(i => intents.includes(i))) return false
  if (filters.topics?.length) {
    const cardTopics = [...seeking, ...offering].flatMap(e => e.topics ?? [])
    if (!filters.topics.some(t => cardTopics.some(ct => ct.toLowerCase().includes(t.toLowerCase())))) return false
  }
  if (filters.engagement) {
    const engagements = seeking.map(s => s.engagement).filter(Boolean) as string[]
    const prefEngagement = preferences.filter(p => p.key === 'engagement').map(p => p.value)
    if (![...engagements, ...prefEngagement].some(e => e.toLowerCase().includes(filters.engagement!.toLowerCase()))) return false
  }
  if (filters.location) {
    const locPrefs = preferences.filter(p => p.key === 'location').map(p => p.value)
    if (!locPrefs.some(l => l.toLowerCase().includes(filters.location!.toLowerCase()))) return false
  }
  return true
}

/** Semantic search is one ranked window. Rows follow the order of semanticIds
 *  (nearest first, as the vector index returned them), are filtered by the
 *  explicit fields, and are cut at the limit. There is no cursor for it. */
function semanticWindow(filters: V3SearchFilters, semanticIds: string[], limit: number, createdAfter?: string): Record<string, unknown>[] {
  const ids = [...new Set(semanticIds)]
  if (ids.length === 0) return []
  const where: string[] = [`expires_at > ${SQL_NOW_ISO}`, `revocation_status = 'active'`, NOT_HIDDEN, `card_id IN (${ids.map(() => '?').join(', ')})`]
  const params: unknown[] = [...ids]
  if (filters.card_type) { where.push('card_type = ?'); params.push(filters.card_type) }
  if (filters.event_ref) { where.push('event_ref_id = ?'); params.push(filters.event_ref) }
  if (createdAfter) { where.push('created_at > ?'); params.push(createdAfter) }
  const rows = d().prepare(`SELECT card_id, subject_key, source_hash, card_json FROM v3_cards WHERE ${where.join(' AND ')}`).all(...params) as any[]
  const byId = new Map(rows.map(r => [r.card_id as string, r]))

  const results: Record<string, unknown>[] = []
  const fair = pageFairness()
  for (const id of ids) {
    const row = byId.get(id)
    if (!row) continue
    const card = JSON.parse(row.card_json) as V3Card
    card.revocation_status = 'active'
    if (!passesJsFilters(card, filters)) continue
    if (!fair.admit(row.subject_key, row.source_hash, card)) continue
    results.push(networkVisibleView({ ...card, card_id: row.card_id }))
    if (results.length >= limit) break
  }
  return results
}

export function searchV3Cards(filters: V3SearchFilters, semanticIds?: string[], limit = 20): Record<string, unknown>[] {
  const cap = Math.min(limit, SEARCH_CAP)
  if (semanticIds) return semanticWindow(filters, semanticIds, cap)
  const where: string[] = [`expires_at > ${SQL_NOW_ISO}`, `revocation_status = 'active'`, NOT_HIDDEN]
  const params: unknown[] = []
  if (filters.card_type) { where.push('card_type = ?'); params.push(filters.card_type) }
  if (filters.event_ref) { where.push('event_ref_id = ?'); params.push(filters.event_ref) }
  const rows = d().prepare(`SELECT card_id, subject_key, source_hash, card_json FROM v3_cards WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT 500`).all(...params) as any[]

  const results: Record<string, unknown>[] = []
  const fair = pageFairness()
  for (const row of rows) {
    const card = JSON.parse(row.card_json) as V3Card
    card.revocation_status = 'active'
    if (!passesJsFilters(card, filters)) continue
    if (!fair.admit(row.subject_key, row.source_hash, card)) continue
    results.push(networkVisibleView({ ...card, card_id: row.card_id }))
    if (results.length >= cap) break
  }
  return results
}

export interface PageCursor { created_at: string; card_id: string }
export interface PageOpts { semanticIds?: string[]; limit?: number; createdAfter?: string; cursor?: PageCursor }

/** Stable keyset pagination for third-party agents. Orders by (created_at,
 *  card_id) DESC, and the cursor is the last returned item, so pages never skip
 *  or repeat. next_cursor is null when the page did not fill (no more results
 *  within the scan window). With semanticIds it is one ranked window instead:
 *  distance order, cut at the limit, next_cursor always null. A cursor cannot
 *  be combined with semanticIds. */
export function searchV3CardsPaged(filters: V3SearchFilters, opts: PageOpts = {}): { results: Record<string, unknown>[]; next_cursor: PageCursor | null; folded?: number } {
  const limit = Math.min(Math.max(1, opts.limit ?? 20), SEARCH_CAP)
  if (opts.semanticIds) {
    if (opts.cursor) throw new Error('a cursor cannot be combined with a semantic search')
    return { results: semanticWindow(filters, opts.semanticIds, limit, opts.createdAfter), next_cursor: null }
  }
  const where: string[] = [`expires_at > ${SQL_NOW_ISO}`, `revocation_status = 'active'`, NOT_HIDDEN]
  const params: unknown[] = []
  if (filters.card_type) { where.push('card_type = ?'); params.push(filters.card_type) }
  if (filters.event_ref) { where.push('event_ref_id = ?'); params.push(filters.event_ref) }
  if (opts.createdAfter) { where.push('created_at > ?'); params.push(opts.createdAfter) }
  if (opts.cursor) {
    where.push('(created_at < ? OR (created_at = ? AND card_id < ?))')
    params.push(opts.cursor.created_at, opts.cursor.created_at, opts.cursor.card_id)
  }
  const rows = d().prepare(
    `SELECT card_id, subject_key, source_hash, card_json, created_at FROM v3_cards WHERE ${where.join(' AND ')} ORDER BY created_at DESC, card_id DESC LIMIT ?`,
  ).all(...params, MAX_SCAN) as any[]

  const results: Record<string, unknown>[] = []
  let last: PageCursor | null = null
  // Folded cards sit behind the cursor and are not shown again in this run of pages.
  const fair = pageFairness()
  for (const row of rows) {
    const card = JSON.parse(row.card_json) as V3Card
    card.revocation_status = 'active'
    if (!passesJsFilters(card, filters)) continue
    if (!fair.admit(row.subject_key, row.source_hash, card)) continue
    results.push(networkVisibleView({ ...card, card_id: row.card_id }))
    last = { created_at: row.created_at, card_id: row.card_id }
    if (results.length >= limit) break
  }
  return { results, next_cursor: results.length >= limit ? last : null, folded: fair.folded }
}

// ── Expiry sweep with index removal ──────────────────────────────────────

export function sweepExpiredV3Cards(): { swept: number } {
  const expired = d().prepare(`SELECT card_id FROM v3_cards WHERE expires_at <= ${SQL_NOW_ISO} AND revocation_status != 'deleted'`).all() as any[]
  for (const row of expired) removeFromIndex(row.card_id)
  // Which rows the sweep is about to move, captured before the UPDATE so each
  // one can be named in the ledger. A card that lapsed is 'expired'; only the
  // principal's own signed verb produces 'withdrawn'.
  const moving = d().prepare(
    `SELECT card_id, subject_key, expires_at FROM v3_cards WHERE expires_at <= ${SQL_NOW_ISO} AND revocation_status = 'active'`,
  ).all() as any[]
  const res = d().prepare(`
    UPDATE v3_cards SET revocation_status = 'expired',
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE expires_at <= ${SQL_NOW_ISO} AND revocation_status = 'active'
  `).run()
  for (const row of moving) recordCardEvent('card_expired', row.card_id, row.subject_key, { expires_at: row.expires_at })
  return { swept: res.changes }
}

export function v3CardCount(): number {
  return (d().prepare(`SELECT COUNT(*) AS n FROM v3_cards WHERE expires_at > ${SQL_NOW_ISO} AND revocation_status = 'active' AND ${NOT_HIDDEN}`).get() as any).n
}

// ── Helpers for the match engine, digest, idempotency, and renew ──────────

/** Active, unexpired cards for pairwise match computation. Only 'active'
 *  status participates; 'stopped_new_matches' and every terminal status do not. */
export function listActiveCardsForMatching(cap = 500): { card_id: string; card: V3Card }[] {
  const rows = d().prepare(
    `SELECT card_id, card_json FROM v3_cards WHERE expires_at > ${SQL_NOW_ISO} AND revocation_status = 'active' AND ${NOT_HIDDEN} ORDER BY created_at DESC LIMIT ?`,
  ).all(cap) as any[]
  return rows.map(r => ({ card_id: r.card_id, card: JSON.parse(r.card_json) as V3Card }))
}

/** The active, unexpired card_ids a subject owns (a subject may hold several). */
export function activeCardIdsForSubject(subjectKey: string): string[] {
  const rows = d().prepare(
    `SELECT card_id FROM v3_cards WHERE subject_key = ? AND expires_at > ${SQL_NOW_ISO} AND revocation_status = 'active' ORDER BY created_at DESC`,
  ).all(subjectKey) as any[]
  return rows.map(r => r.card_id)
}

/** True when a card is currently matchable (active and unexpired). Used as the
 *  read-time safety filter so a withdrawn or expired counterpart never leaks
 *  through a stale match row. */
export function isCardMatchable(cardId: string): boolean {
  return !!d().prepare(
    `SELECT 1 FROM v3_cards WHERE card_id = ? AND expires_at > ${SQL_NOW_ISO} AND revocation_status = 'active' AND ${NOT_HIDDEN}`,
  ).get(cardId)
}

/** For idempotency: an existing live card of this subject carrying this exact
 *  content hash, if any. */
export function findActiveCardByHash(subjectKey: string, cardHash: string): { card_id: string; expires_at: string; revocation_status: string } | null {
  const row = d().prepare(
    `SELECT card_id, expires_at, revocation_status FROM v3_cards WHERE subject_key = ? AND card_hash = ? AND expires_at > ${SQL_NOW_ISO} AND revocation_status = 'active' ORDER BY created_at DESC LIMIT 1`,
  ).get(subjectKey, cardHash) as any
  return row ?? null
}

/** Where this exact signed content stands for this subject, across every stored
 *  status. 'active' is a live card with this hash (an idempotent retry). 'retired'
 *  is any earlier card with this hash that is no longer live (withdrawn, deleted,
 *  superseded, revoked, stopped, expired, or past expiry and not yet swept).
 *  Publishing, renewing to, or replacing with that exact signed card again would
 *  undo the owner's own takedown, so every write path refuses 'retired'. */
export type HashStanding =
  | { kind: 'none' }
  | { kind: 'active'; card_id: string; expires_at: string; revocation_status: string }
  | { kind: 'retired'; card_id: string; revocation_status: string }

export function cardHashStanding(subjectKey: string, cardHash: string): HashStanding {
  const row = d().prepare(
    `SELECT card_id, expires_at, revocation_status, (expires_at > ${SQL_NOW_ISO}) AS live FROM v3_cards WHERE subject_key = ? AND card_hash = ? ORDER BY created_at DESC LIMIT 1`,
  ).get(subjectKey, cardHash) as any
  if (!row) return { kind: 'none' }
  if (row.revocation_status === 'active' && row.live) {
    return { kind: 'active', card_id: row.card_id, expires_at: row.expires_at, revocation_status: row.revocation_status }
  }
  return { kind: 'retired', card_id: row.card_id, revocation_status: row.revocation_status === 'active' ? 'expired' : row.revocation_status }
}

/** Supersede a card only if it is still active and unexpired, in one statement.
 *  Renew and replace call this inside the transaction that inserts the successor,
 *  so a takedown that committed first makes the whole renew or replace roll back,
 *  and two successors of one card cannot both commit. */
export function supersedeIfActive(cardId: string, subjectKey: string): boolean {
  const res = d().prepare(`
    UPDATE v3_cards SET revocation_status = 'superseded', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
    WHERE card_id = ? AND subject_key = ? AND revocation_status = 'active' AND expires_at > ${SQL_NOW_ISO}
  `).run(cardId, subjectKey)
  return res.changes === 1
}

/** True when an insert failed on the (subject_key, card_hash) unique index, so a
 *  concurrent writer stored the same signed content first. */
export function isCardHashConflict(e: unknown): boolean {
  return (e as { code?: string })?.code === 'SQLITE_CONSTRAINT_UNIQUE'
}

/** The card's stored content (for renew's identical-content check). */
export function getV3CardContent(cardId: string): V3Card | null {
  const row = d().prepare('SELECT card_json FROM v3_cards WHERE card_id = ?').get(cardId) as any
  return row ? (JSON.parse(row.card_json) as V3Card) : null
}

// ── Supersession links (renew), additive table ───────────────────────────

let supersedeInit = false
function ensureSupersede(): Database {
  const dd = d()
  if (!supersedeInit) {
    dd.exec(`CREATE TABLE IF NOT EXISTS v3_supersessions (
      old_card_id TEXT PRIMARY KEY,
      new_card_id TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_v3_superseded_by ON v3_supersessions(new_card_id);`)
    supersedeInit = true
  }
  return dd
}
export function recordSupersession(oldCardId: string, newCardId: string): void {
  ensureSupersede().prepare('INSERT OR REPLACE INTO v3_supersessions (old_card_id, new_card_id) VALUES (?, ?)').run(oldCardId, newCardId)
}
export function getSupersededBy(oldCardId: string): string | null {
  const row = ensureSupersede().prepare('SELECT new_card_id FROM v3_supersessions WHERE old_card_id = ?').get(oldCardId) as any
  return row?.new_card_id ?? null
}
export function getSupersedes(newCardId: string): string | null {
  const row = ensureSupersede().prepare('SELECT old_card_id FROM v3_supersessions WHERE new_card_id = ?').get(newCardId) as any
  return row?.old_card_id ?? null
}

// ── Live counts for GET /api/stats (Part 3) ──────────────────────────────
// Every number here is a query against the v3 tables at read time. Nothing is
// a stored counter, so nothing can drift from the rows it claims to describe.

export interface V3CardCounts {
  cards_lifetime: number
  cards_active: number
  cards_hidden: number
  cards_expired: number
  cards_withdrawn: number
  cards_deleted: number
  cards_legacy_status_ambiguous: number
  subjects_lifetime: number
  subjects_active: number
}

/** The moment protocol 3.2.0 first opened this database, before which the expiry
 *  sweep wrote 'withdrawn' for a card that had merely lapsed. It is written once
 *  into schema_markers on first start and never overwritten, so it survives
 *  restarts, redeploys and process moves - nothing about it depends on an
 *  environment variable staying set, or on anyone remembering to set it.
 *
 *  Rows whose status was last written before the marker cannot be told apart
 *  from a real withdrawal, so they are counted but never reinterpreted. */
export function v32DeployMarker(): string | null {
  return getSchemaMarker(V3_2_MARKER_KEY)
}

export function v3CardCounts(): V3CardCounts {
  const dd = d()
  const one = (sql: string, ...params: unknown[]): number => (dd.prepare(sql).get(...params) as any).n
  const marker = v32DeployMarker()
  return {
    cards_lifetime: one('SELECT COUNT(*) AS n FROM v3_cards'),
    cards_active: one(`SELECT COUNT(*) AS n FROM v3_cards WHERE expires_at > ${SQL_NOW_ISO} AND revocation_status = 'active' AND ${NOT_HIDDEN}`),
    // Active by status but hidden by the operator. Not part of cards_active.
    cards_hidden: one(`SELECT COUNT(*) AS n FROM v3_cards WHERE expires_at > ${SQL_NOW_ISO} AND revocation_status = 'active' AND NOT (${NOT_HIDDEN})`),
    // Expired counts the sweep's own status AND rows that have passed their
    // expiry but no sweep has reached yet: both are expired in fact.
    cards_expired: one(`SELECT COUNT(*) AS n FROM v3_cards WHERE revocation_status = 'expired' OR (revocation_status = 'active' AND expires_at <= ${SQL_NOW_ISO})`),
    // Ambiguous rows stay counted here, as they always were: nothing is moved.
    cards_withdrawn: one("SELECT COUNT(*) AS n FROM v3_cards WHERE revocation_status = 'withdrawn'"),
    cards_deleted: one("SELECT COUNT(*) AS n FROM v3_cards WHERE revocation_status = 'deleted'"),
    // A subset of cards_withdrawn, never a bucket added on top: the withdrawn
    // rows whose status was last written before 3.2.0, when the sweep and the
    // withdraw verb produced the same value.
    //
    // The test is updated_at, not created_at, and that is the whole point: every
    // path that changes revocation_status stamps updated_at (setRevocationStatus
    // for the withdraw verb, deleteV3Card, and the sweep), so a long-lived card
    // withdrawn AFTER the deploy carries a post-marker updated_at and is
    // correctly left out. Under created_at it would have been counted.
    //
    // Still an upper bound, not a census: a principal who genuinely withdrew a
    // card before the marker is counted too, because nothing in the row can
    // distinguish that from the sweep's doing. With no marker recorded the count
    // is 0 rather than a guess. The old sweep could only write 'withdrawn' after the
    // card had lapsed, so a row is ambiguous only if it was already expired at the
    // moment it became withdrawn (expires_at <= updated_at). A withdrawal written
    // before expiry was the principal's own, however long ago the card has since lapsed.
    cards_legacy_status_ambiguous: marker === null ? 0 : one(
      `SELECT COUNT(*) AS n FROM v3_cards WHERE revocation_status = 'withdrawn' AND updated_at < ? AND expires_at <= updated_at`,
      marker,
    ),
    subjects_lifetime: one('SELECT COUNT(DISTINCT subject_key) AS n FROM v3_cards'),
    subjects_active: one(`SELECT COUNT(DISTINCT subject_key) AS n FROM v3_cards WHERE expires_at > ${SQL_NOW_ISO} AND revocation_status = 'active' AND ${NOT_HIDDEN}`),
  }
}
