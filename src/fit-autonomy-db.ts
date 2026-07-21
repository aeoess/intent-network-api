// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - graduated autonomy scopes + legible activity (additive)
// ══════════════════════════════════════════════════════════════
// Autonomy is per-dimension, per-purpose, and time-limited, never one toggle. A
// scope authorizes only specific tiers: overlap disclosure (state 3) and, if
// enabled, bucket disclosure (state 4). Exact (state 5) is NEVER autonomous, a
// high-sensitivity dimension ALWAYS needs a per-match human tap, and a pause
// halts every automatic disclosure at once. Every automatic action writes an
// activity row so the session pulse can show a truthful "while you were away".

import type { Database } from 'better-sqlite3'
import { createHash } from 'node:crypto'
import { canonicalize } from 'agent-passport-system'
import { getDb } from './db.js'
import { POLICY_INTENTS, DIMENSION_NAMES, DISCLOSURE_RANK, type DisclosureState } from './fit-schema.js'

let initialized = false

// These categories are always forbidden from autonomous handling, whatever the
// scope says. The seeded schema has no dimension in them, so this is a standing
// guard against future or euphemistic dimensions.
export const ALWAYS_FORBIDDEN = ['health', 'family', 'politics', 'finance', 'third_party']

export function initAutonomySchema(): void {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS v4_fit_autonomy (
      card_id TEXT PRIMARY KEY,
      subject_key TEXT NOT NULL,
      version INTEGER NOT NULL,
      scope_hash TEXT NOT NULL,
      scope_json TEXT NOT NULL,
      paused INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE IF NOT EXISTS v4_fit_activity (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject_key TEXT NOT NULL,
      intro_id TEXT NOT NULL,
      action TEXT NOT NULL,
      dimension TEXT,
      counterparty_key TEXT,
      autonomous INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_v4_activity_subject ON v4_fit_activity(subject_key, created_at);
  `)
  initialized = true
}

function d(): Database {
  if (!initialized) initAutonomySchema()
  return getDb()
}

export interface AutonomyScope {
  intents: string[]
  dimensions: string[]
  auto_reveal_overlap: boolean
  reveal_bucket_on_reciprocity: boolean
  ask_before_exact: boolean
  forbidden_categories: string[]
  expiry: string
}

const isIso = (s: unknown): s is string => typeof s === 'string' && !Number.isNaN(Date.parse(s))

export function validateScope(scope: unknown): { ok: boolean; error?: string; scope?: AutonomyScope } {
  const s = scope as any
  if (!s || typeof s !== 'object') return { ok: false, error: 'scope object required' }
  if (!Array.isArray(s.intents) || s.intents.length === 0) return { ok: false, error: 'scope.intents required' }
  for (const it of s.intents) if (!(POLICY_INTENTS as readonly string[]).includes(it)) return { ok: false, error: `scope.intents contains "${it}" (work is excluded)` }
  if (!Array.isArray(s.dimensions) || s.dimensions.length === 0) return { ok: false, error: 'scope.dimensions required' }
  for (const dim of s.dimensions) if (!DIMENSION_NAMES.includes(dim)) return { ok: false, error: `scope.dimensions contains unknown "${dim}"` }
  if (typeof s.auto_reveal_overlap !== 'boolean' || typeof s.reveal_bucket_on_reciprocity !== 'boolean') return { ok: false, error: 'auto_reveal_overlap and reveal_bucket_on_reciprocity must be booleans' }
  if (!isIso(s.expiry)) return { ok: false, error: 'scope.expiry must be ISO' }
  // ask_before_exact defaults true; the always-forbidden categories are merged in.
  const forbidden = Array.from(new Set([...(Array.isArray(s.forbidden_categories) ? s.forbidden_categories : []), ...ALWAYS_FORBIDDEN]))
  const normalized: AutonomyScope = {
    intents: s.intents, dimensions: s.dimensions,
    auto_reveal_overlap: s.auto_reveal_overlap, reveal_bucket_on_reciprocity: s.reveal_bucket_on_reciprocity,
    ask_before_exact: s.ask_before_exact !== false, forbidden_categories: forbidden, expiry: s.expiry,
  }
  return { ok: true, scope: normalized }
}

export function scopeHash(scope: AutonomyScope): string {
  const normalized = {
    intents: [...scope.intents].sort(), dimensions: [...scope.dimensions].sort(),
    auto_reveal_overlap: scope.auto_reveal_overlap, reveal_bucket_on_reciprocity: scope.reveal_bucket_on_reciprocity,
    ask_before_exact: scope.ask_before_exact, forbidden_categories: [...scope.forbidden_categories].sort(), expiry: scope.expiry,
  }
  return createHash('sha256').update(canonicalize(normalized), 'utf8').digest('hex')
}

export interface StoredScope { card_id: string; version: number; scope_hash: string; scope: AutonomyScope; paused: boolean }

export function getScope(cardId: string): StoredScope | null {
  const row = d().prepare('SELECT * FROM v4_fit_autonomy WHERE card_id = ?').get(cardId) as any
  if (!row) return null
  return { card_id: cardId, version: row.version, scope_hash: row.scope_hash, scope: JSON.parse(row.scope_json), paused: !!row.paused }
}

export function setScope(cardId: string, subjectKey: string, scope: AutonomyScope): { version: number; scope_hash: string } {
  const hash = scopeHash(scope)
  const cur = (d().prepare('SELECT version FROM v4_fit_autonomy WHERE card_id = ?').get(cardId) as any)?.version ?? 0
  const version = cur + 1
  d().prepare(`INSERT INTO v4_fit_autonomy (card_id, subject_key, version, scope_hash, scope_json, paused, updated_at)
    VALUES (?, ?, ?, ?, ?, 0, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    ON CONFLICT(card_id) DO UPDATE SET subject_key = excluded.subject_key, version = excluded.version, scope_hash = excluded.scope_hash, scope_json = excluded.scope_json, paused = 0, updated_at = excluded.updated_at`)
    .run(cardId, subjectKey, version, hash, JSON.stringify(scope))
  return { version, scope_hash: hash }
}

export function setPaused(cardId: string, paused: boolean): boolean {
  return d().prepare(`UPDATE v4_fit_autonomy SET paused = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE card_id = ?`).run(paused ? 1 : 0, cardId).changes > 0
}

/**
 * Whether an autonomous disclosure of one dimension at an effective level is
 * permitted by the owner's scope. Fail-closed: no scope, expired, paused,
 * high-sensitivity, exact, or out-of-scope all return false.
 */
export function autonomyPermitsDisclosure(cardId: string, intent: string, dimension: string, effLevel: DisclosureState | 'not_disclosed', sensitivity: string, now = Date.now()): boolean {
  const stored = getScope(cardId)
  if (!stored) return false
  if (stored.paused) return false
  if (Date.parse(stored.scope.expiry) <= now) return false
  const s = stored.scope
  if (!s.intents.includes(intent)) return false
  if (!s.dimensions.includes(dimension)) return false
  if (s.forbidden_categories.includes(dimension)) return false
  if (sensitivity === 'high') return false                 // high-sensitivity always per-match
  if (effLevel === 'not_disclosed') return true            // nothing leaves (T1)
  const rank = DISCLOSURE_RANK[effLevel as DisclosureState]
  if (rank <= 2) return true                                // testable: predicate ran, nothing disclosed
  if (rank === 3) return s.auto_reveal_overlap              // overlap (T2)
  if (rank === 4) return s.reveal_bucket_on_reciprocity     // bucket (T3)
  return false                                              // reveal_exact (5) is NEVER autonomous
}

// ── Activity (the "while you were away" ledger) ───────────────────────────

export function recordActivity(subjectKey: string, introId: string, action: string, dimension: string | null, counterpartyKey: string | null, autonomous: boolean): void {
  d().prepare('INSERT INTO v4_fit_activity (subject_key, intro_id, action, dimension, counterparty_key, autonomous) VALUES (?, ?, ?, ?, ?, ?)')
    .run(subjectKey, introId, action, dimension, counterpartyKey, autonomous ? 1 : 0)
}

export interface ActivityRow { intro_id: string; action: string; dimension: string | null; counterparty_key: string | null; autonomous: number; created_at: string }

export function activityFor(subjectKey: string, sinceIso?: string): ActivityRow[] {
  if (sinceIso) return d().prepare('SELECT intro_id, action, dimension, counterparty_key, autonomous, created_at FROM v4_fit_activity WHERE subject_key = ? AND created_at > ? ORDER BY created_at').all(subjectKey, sinceIso) as ActivityRow[]
  return d().prepare('SELECT intro_id, action, dimension, counterparty_key, autonomous, created_at FROM v4_fit_activity WHERE subject_key = ? ORDER BY created_at DESC LIMIT 200').all(subjectKey) as ActivityRow[]
}

/** The legible summary: cards evaluated, overlaps disclosed to whom on which
 *  dimensions, bucket count, and exact count (should be 0 unless a human tapped). */
export function whileAwaySummary(subjectKey: string, sinceIso?: string): Record<string, unknown> {
  const rows = activityFor(subjectKey, sinceIso)
  const cards = new Set<string>()
  const overlapPeople = new Set<string>()
  const overlapDims = new Set<string>()
  let buckets = 0, exacts = 0
  for (const r of rows) {
    if (r.action === 'evaluated') cards.add(r.intro_id)
    if (r.action === 'overlap_disclosed') { if (r.counterparty_key) overlapPeople.add(r.counterparty_key); if (r.dimension) overlapDims.add(r.dimension) }
    if (r.action === 'bucket_disclosed') buckets++
    if (r.action === 'exact_released') exacts++
  }
  return {
    cards_evaluated: cards.size,
    overlaps_disclosed_to: overlapPeople.size,
    overlap_dimensions: [...overlapDims].sort(),
    buckets_disclosed: buckets,
    exact_values_released: exacts,
  }
}
