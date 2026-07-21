// ══════════════════════════════════════════════════════════════
// Mingle v3 match engine - storage + recompute orchestration (additive)
// ══════════════════════════════════════════════════════════════
// One row per unordered card pair, keyed with card_a < card_b so a pair is
// stored once. seen_/dismissed_ flags are per side (a = owner of card_a). The
// overlap_json holds only the overlap map (intents, agreed fields, each side's
// own quoted snippets); no score is ever stored. Card vectors live in a small
// additive table so the hourly sweep can score similarity without re-embedding.
//
// Read paths filter to counterparts that are currently active and unexpired, so
// a stale row for a withdrawn card can never surface a counterpart that has left
// the network.

import type { Database } from 'better-sqlite3'
import { getDb } from './db.js'
import * as v3db from './v3-db.js'
import { cosineSimilarity } from './embeddings.js'
import { computeOverlap, overlapCount, type OverlapMap, type AgreedField } from './matches.js'

let initialized = false

export function initMatchesSchema(): void {
  const dd = getDb()
  dd.exec(`
    CREATE TABLE IF NOT EXISTS v3_matches (
      card_a TEXT NOT NULL,
      card_b TEXT NOT NULL,
      computed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      overlap_json TEXT NOT NULL,
      seen_a INTEGER NOT NULL DEFAULT 0,
      seen_b INTEGER NOT NULL DEFAULT 0,
      dismissed_a INTEGER NOT NULL DEFAULT 0,
      dismissed_b INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (card_a, card_b)
    );
    CREATE INDEX IF NOT EXISTS idx_v3_matches_a ON v3_matches(card_a);
    CREATE INDEX IF NOT EXISTS idx_v3_matches_b ON v3_matches(card_b);

    CREATE TABLE IF NOT EXISTS v3_match_vectors (
      card_id TEXT PRIMARY KEY,
      vec BLOB NOT NULL
    );

    CREATE TABLE IF NOT EXISTS v3_digest_checks (
      subject_key TEXT PRIMARY KEY,
      last_check TEXT NOT NULL
    );
  `)
  initialized = true
}

function d(): Database {
  if (!initialized) initMatchesSchema()
  return getDb()
}

const nowExpr = "strftime('%Y-%m-%dT%H:%M:%fZ','now')"
const order = (x: string, y: string): [string, string] => (x < y ? [x, y] : [y, x])

// ── Vectors ───────────────────────────────────────────────────────────────

export function storeMatchVector(cardId: string, vec: Float32Array): void {
  d().prepare('INSERT OR REPLACE INTO v3_match_vectors (card_id, vec) VALUES (?, ?)').run(
    cardId, Buffer.from(vec.buffer, vec.byteOffset, vec.byteLength),
  )
}

export function getMatchVector(cardId: string): Float32Array | null {
  const row = d().prepare('SELECT vec FROM v3_match_vectors WHERE card_id = ?').get(cardId) as any
  if (!row) return null
  const buf: Buffer = row.vec
  // Copy into a fresh, aligned ArrayBuffer before viewing as float32.
  return new Float32Array(new Uint8Array(buf).buffer)
}

function cosOf(a: Float32Array | null, b: Float32Array | null): number | null {
  if (!a || !b || a.length !== b.length) return null
  return cosineSimilarity(a, b)
}

// ── Pair upsert / delete ──────────────────────────────────────────────────

function upsertMatch(x: string, y: string, overlap: OverlapMap): void {
  const [a, b] = order(x, y)
  const json = JSON.stringify(overlap)
  const existing = d().prepare('SELECT overlap_json FROM v3_matches WHERE card_a = ? AND card_b = ?').get(a, b) as any
  if (existing) {
    // An unchanged overlap keeps its original computed_at (first-seen), so a
    // re-sweep never re-dates a match and "new since last check" stays honest.
    if (existing.overlap_json === json) return
    d().prepare(`UPDATE v3_matches SET overlap_json = ?, computed_at = ${nowExpr} WHERE card_a = ? AND card_b = ?`).run(json, a, b)
    return
  }
  d().prepare(`INSERT INTO v3_matches (card_a, card_b, overlap_json, computed_at) VALUES (?, ?, ?, ${nowExpr})`).run(a, b, json)
}

function deletePair(x: string, y: string): void {
  const [a, b] = order(x, y)
  d().prepare('DELETE FROM v3_matches WHERE card_a = ? AND card_b = ?').run(a, b)
}

function deleteMatchRowsForCard(cardId: string): void {
  d().prepare('DELETE FROM v3_matches WHERE card_a = ? OR card_b = ?').run(cardId, cardId)
}

/** Full cleanup when a card leaves the network (verb or delete). */
export function deleteMatchArtifacts(cardId: string): void {
  deleteMatchRowsForCard(cardId)
  d().prepare('DELETE FROM v3_match_vectors WHERE card_id = ?').run(cardId)
}

// ── Recompute ──────────────────────────────────────────────────────────────

/** Recompute every pair touching one card. Upserts pairs that clear the
 *  threshold, deletes pairs that no longer do. Returns the live match count. */
export function recomputeMatchesForCard(cardId: string): number {
  const stored = v3db.getV3Card(cardId)
  if (!stored || stored.revocation_status !== 'active' || Date.parse(stored.expires_at) <= Date.now()) {
    deleteMatchRowsForCard(cardId)
    return 0
  }
  const myVec = getMatchVector(cardId)
  const candidates = v3db.listActiveCardsForMatching(500)
  let n = 0
  for (const cand of candidates) {
    if (cand.card_id === cardId) continue
    const cos = myVec ? cosOf(myVec, getMatchVector(cand.card_id)) : null
    const [aId] = order(cardId, cand.card_id)
    const aCard = aId === cardId ? stored.card : cand.card
    const bCard = aId === cardId ? cand.card : stored.card
    const overlap = computeOverlap(aCard, bCard, cos)
    if (overlap) { upsertMatch(cardId, cand.card_id, overlap); n++ }
    else deletePair(cardId, cand.card_id)
  }
  return n
}

/** Hourly sweep: recompute across the active set, then prune orphans. */
export function recomputeAllMatches(cap = 500): { cards: number; pairs: number } {
  const active = v3db.listActiveCardsForMatching(cap)
  let pairs = 0
  for (const c of active) pairs += recomputeMatchesForCard(c.card_id)
  pruneInactiveMatches()
  return { cards: active.length, pairs }
}

/** Drop match rows and vectors for cards that are no longer active. */
export function pruneInactiveMatches(): void {
  const rows = d().prepare('SELECT DISTINCT card_a AS id FROM v3_matches UNION SELECT DISTINCT card_b FROM v3_matches').all() as any[]
  for (const r of rows) {
    if (!v3db.isCardMatchable(r.id)) deleteMatchRowsForCard(r.id)
  }
  const vecs = d().prepare('SELECT card_id FROM v3_match_vectors').all() as any[]
  for (const v of vecs) {
    if (!v3db.isCardMatchable(v.card_id)) d().prepare('DELETE FROM v3_match_vectors WHERE card_id = ?').run(v.card_id)
  }
}

// ── Owner-perspective reads ────────────────────────────────────────────────

export interface OwnerMatch {
  card_id: string          // the owner's card this match belongs to
  other_card_id: string    // the counterpart card
  computed_at: string
  matched_intents: string[]
  agreed_fields: AgreedField[]
  counterpart_snippets: string[]  // the counterpart's own quoted words
  overlap_count: number
  seen: boolean
  dismissed: boolean
}

function rowToOwnerMatch(row: any, ownerCardId: string): OwnerMatch | null {
  const iAmA = row.card_a === ownerCardId
  const otherId = iAmA ? row.card_b : row.card_a
  // Read-time safety: only surface counterparts still active on the network.
  if (!v3db.isCardMatchable(otherId)) return null
  const overlap = JSON.parse(row.overlap_json) as OverlapMap
  return {
    card_id: ownerCardId,
    other_card_id: otherId,
    computed_at: row.computed_at,
    matched_intents: overlap.matched_intents,
    agreed_fields: overlap.agreed_fields,
    counterpart_snippets: iAmA ? overlap.b_snippets : overlap.a_snippets,
    overlap_count: overlapCount(overlap),
    seen: iAmA ? !!row.seen_a : !!row.seen_b,
    dismissed: iAmA ? !!row.dismissed_a : !!row.dismissed_b,
  }
}

/** All live, non-dismissed matches for one of the owner's cards. */
export function ownerMatches(ownerCardId: string): OwnerMatch[] {
  const rows = d().prepare('SELECT * FROM v3_matches WHERE card_a = ? OR card_b = ?').all(ownerCardId, ownerCardId) as any[]
  const out: OwnerMatch[] = []
  for (const row of rows) {
    const iAmA = row.card_a === ownerCardId
    if (iAmA ? row.dismissed_a : row.dismissed_b) continue
    const m = rowToOwnerMatch(row, ownerCardId)
    if (m) out.push(m)
  }
  return out
}

/** New matches for a subject's cards since an ISO timestamp (recency window),
 *  dismissed ones excluded, counterpart still active. */
export function newMatchesForCardsSince(ownerCardIds: string[], sinceIso: string | null): OwnerMatch[] {
  const out: OwnerMatch[] = []
  for (const cardId of ownerCardIds) {
    for (const m of ownerMatches(cardId)) {
      if (!sinceIso || m.computed_at > sinceIso) out.push(m)
    }
  }
  return out
}

export function markSeenForCard(cardId: string): void {
  d().prepare('UPDATE v3_matches SET seen_a = 1 WHERE card_a = ?').run(cardId)
  d().prepare('UPDATE v3_matches SET seen_b = 1 WHERE card_b = ?').run(cardId)
}

/** Dismiss a match from the owner's side ONLY. The other side is untouched and
 *  never learns of it. Returns true when a row was updated. */
export function dismissMatch(ownerCardId: string, otherCardId: string): boolean {
  const [a, b] = order(ownerCardId, otherCardId)
  const col = ownerCardId === a ? 'dismissed_a' : 'dismissed_b'
  const res = d().prepare(`UPDATE v3_matches SET ${col} = 1 WHERE card_a = ? AND card_b = ?`).run(a, b)
  return res.changes > 0
}

// ── Digest since-tracking (per subject_key) ────────────────────────────────

export function getLastDigestCheck(subjectKey: string): string | null {
  const row = d().prepare('SELECT last_check FROM v3_digest_checks WHERE subject_key = ?').get(subjectKey) as any
  return row?.last_check ?? null
}

export function stampDigestCheck(subjectKey: string): void {
  d().prepare(`INSERT INTO v3_digest_checks (subject_key, last_check) VALUES (?, ${nowExpr})
    ON CONFLICT(subject_key) DO UPDATE SET last_check = ${nowExpr}`).run(subjectKey)
}

/** Test/introspection helper: raw stored flags for a pair. */
export function rawMatchRow(x: string, y: string): any {
  const [a, b] = order(x, y)
  return d().prepare('SELECT * FROM v3_matches WHERE card_a = ? AND card_b = ?').get(a, b)
}
