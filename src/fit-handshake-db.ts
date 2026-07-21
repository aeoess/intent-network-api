// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - bilateral predicate handshake storage (additive)
// ══════════════════════════════════════════════════════════════
// One handshake per accepted intro. The reciprocity gate lives in the state
// machine: a manifest is stored PENDING (state 'requested') and nothing is
// evaluated until the counterparty commits to the same dimensions with matching
// reciprocity (state 'committed'). The anti-narrowing budget is keyed by the
// unordered PRINCIPAL pair plus dimension, so the same private value cannot be
// binary-searched across different cards or threads between the same two people.

import type { Database } from 'better-sqlite3'
import { getDb } from './db.js'

let initialized = false

// Lifetime evaluations allowed for one (principal-pair, dimension) before the
// dimension is refused, which caps binary-search narrowing.
export const QUERY_BUDGET_MAX = 3

export function initHandshakeSchema(): void {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS v4_fit_handshakes (
      intro_id TEXT PRIMARY KEY,
      card_a TEXT NOT NULL, card_b TEXT NOT NULL,
      key_a TEXT NOT NULL, key_b TEXT NOT NULL,
      intent TEXT NOT NULL,
      state TEXT NOT NULL DEFAULT 'open',
      requester_key TEXT,
      requested_json TEXT,
      req_reciprocal_json TEXT,
      req_policy_hash TEXT,
      committer_key TEXT,
      accept_json TEXT,
      com_reciprocal_json TEXT,
      com_policy_hash TEXT,
      query_budget INTEGER,
      result_json TEXT,
      receipt TEXT,
      receipt_digest TEXT,
      receipt_content_json TEXT,
      released_exacts_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      expires_at TEXT NOT NULL,
      committed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS v4_fit_query_budget (
      pair_key TEXT NOT NULL,
      dimension TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (pair_key, dimension)
    );
  `)
  initialized = true
}

function d(): Database {
  if (!initialized) initHandshakeSchema()
  return getDb()
}

export function principalPairKey(a: string, b: string): string {
  return [a, b].sort().join(' ')
}

export interface HandshakeRow {
  intro_id: string
  card_a: string; card_b: string; key_a: string; key_b: string
  intent: string
  state: 'open' | 'requested' | 'committed'
  requester_key: string | null
  requested_json: string | null
  req_reciprocal_json: string | null
  req_policy_hash: string | null
  committer_key: string | null
  accept_json: string | null
  com_reciprocal_json: string | null
  com_policy_hash: string | null
  query_budget: number | null
  result_json: string | null
  receipt: string | null
  receipt_digest: string | null
  receipt_content_json: string | null
  released_exacts_json: string
  created_at: string
  expires_at: string
  committed_at: string | null
}

export function createHandshake(args: { intro_id: string; card_a: string; card_b: string; key_a: string; key_b: string; intent: string; expires_at: string }): void {
  d().prepare(`INSERT OR IGNORE INTO v4_fit_handshakes (intro_id, card_a, card_b, key_a, key_b, intent, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(args.intro_id, args.card_a, args.card_b, args.key_a, args.key_b, args.intent, args.expires_at)
}

export function getHandshake(introId: string): HandshakeRow | null {
  return (d().prepare('SELECT * FROM v4_fit_handshakes WHERE intro_id = ?').get(introId) as any) ?? null
}

export function existsHandshakeForIntro(introId: string): boolean {
  return !!d().prepare('SELECT 1 FROM v4_fit_handshakes WHERE intro_id = ?').get(introId)
}

export function setRequest(introId: string, requesterKey: string, requested: string[], reciprocal: string[], policyHash: string, queryBudget: number): void {
  d().prepare(`UPDATE v4_fit_handshakes SET state = 'requested', requester_key = ?, requested_json = ?, req_reciprocal_json = ?, req_policy_hash = ?, query_budget = ? WHERE intro_id = ?`)
    .run(requesterKey, JSON.stringify(requested), JSON.stringify(reciprocal), policyHash, queryBudget, introId)
}

export function setCommitResult(introId: string, committerKey: string, accept: string[], reciprocal: string[], policyHash: string, resultJson: string, receipt: string, receiptDigest: string, receiptContentJson: string): void {
  d().prepare(`UPDATE v4_fit_handshakes SET state = 'committed', committer_key = ?, accept_json = ?, com_reciprocal_json = ?, com_policy_hash = ?, result_json = ?, receipt = ?, receipt_digest = ?, receipt_content_json = ?, committed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE intro_id = ?`)
    .run(committerKey, JSON.stringify(accept), JSON.stringify(reciprocal), policyHash, resultJson, receipt, receiptDigest, receiptContentJson, introId)
}

export function releaseExact(introId: string, dimension: string, ownerKey: string): void {
  const row = getHandshake(introId)
  if (!row) return
  const released = JSON.parse(row.released_exacts_json || '{}')
  released[dimension] = ownerKey
  d().prepare('UPDATE v4_fit_handshakes SET released_exacts_json = ? WHERE intro_id = ?').run(JSON.stringify(released), introId)
}

// ── Anti-narrowing query budget ────────────────────────────────────────────

/** Consume one unit of budget for (principal pair, dimension). Returns
 *  {allowed:false} when the lifetime cap is already reached (the dimension must
 *  then be refused, not re-evaluated). */
export function budgetConsume(pairKey: string, dimension: string): { allowed: boolean; count: number } {
  const dd = d()
  const row = dd.prepare('SELECT count FROM v4_fit_query_budget WHERE pair_key = ? AND dimension = ?').get(pairKey, dimension) as any
  const count = row?.count ?? 0
  if (count >= QUERY_BUDGET_MAX) return { allowed: false, count }
  dd.prepare(`INSERT INTO v4_fit_query_budget (pair_key, dimension, count, updated_at) VALUES (?, ?, 1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    ON CONFLICT(pair_key, dimension) DO UPDATE SET count = count + 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')`).run(pairKey, dimension)
  return { allowed: true, count: count + 1 }
}

export function budgetPeek(pairKey: string, dimension: string): number {
  const row = d().prepare('SELECT count FROM v4_fit_query_budget WHERE pair_key = ? AND dimension = ?').get(pairKey, dimension) as any
  return row?.count ?? 0
}
