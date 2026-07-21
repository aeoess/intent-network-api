// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - Fit Policy storage + validation (additive)
// ══════════════════════════════════════════════════════════════
// A private, per-card Fit Policy: a set of typed dimensions, each with a value
// and five independent disclosure controls. Stored signed, versioned, and
// supersedable, approved as a whole set by its content hash (like the ledger and
// the card). Old versions are retained by hash so a receipt that bound a policy
// hash stays verifiable. Values are private; only the schema is public.

import type { Database } from 'better-sqlite3'
import { createHash } from 'node:crypto'
import { canonicalize } from 'agent-passport-system'
import { getDb } from './db.js'
import {
  DIMENSIONS, DIMENSION_SCHEMA_VERSION, DISCLOSURE_STATES, SENSITIVITIES, IMPORTANCES,
  POLICY_INTENTS, validateDimensionValue, type DisclosureState, type Sensitivity, type Importance,
} from './fit-schema.js'

let initialized = false

export function initFitPolicySchema(): void {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS v4_fit_policies (
      card_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      subject_key TEXT NOT NULL,
      policy_hash TEXT NOT NULL,
      schema_version INTEGER NOT NULL,
      policy_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (card_id, version)
    );
    CREATE INDEX IF NOT EXISTS idx_v4_pol_hash ON v4_fit_policies(policy_hash);

    CREATE TABLE IF NOT EXISTS v4_fit_policy_meta (
      card_id TEXT PRIMARY KEY,
      subject_key TEXT NOT NULL,
      current_version INTEGER NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
  `)
  initialized = true
}

function d(): Database {
  if (!initialized) initFitPolicySchema()
  return getDb()
}

export interface PolicyDimension {
  dimension: string
  value: unknown
  sensitivity: Sensitivity
  disclosure_state: DisclosureState
  allowed_intents: string[]
  expires_at: string
  importance: Importance
}

export interface FitPolicy {
  card_id: string
  version: number
  policy_hash: string
  schema_version: number
  dimensions: PolicyDimension[]
}

const isIso = (s: unknown): s is string => typeof s === 'string' && !Number.isNaN(Date.parse(s))

/** Validate a proposed dimension set against the public schema. Types only:
 *  open-ended text values are impossible because every dimension is typed. */
export function validatePolicyDimensions(dims: unknown): { ok: boolean; error?: string; dimensions?: PolicyDimension[] } {
  if (!Array.isArray(dims) || dims.length === 0) return { ok: false, error: 'dimensions must be a non-empty array' }
  if (dims.length > Object.keys(DIMENSIONS).length) return { ok: false, error: 'too many dimensions' }
  const seen = new Set<string>()
  for (const raw of dims) {
    const dd = raw as any
    if (typeof dd?.dimension !== 'string' || !DIMENSIONS[dd.dimension]) return { ok: false, error: `unknown dimension "${dd?.dimension}"` }
    if (seen.has(dd.dimension)) return { ok: false, error: `duplicate dimension "${dd.dimension}"` }
    seen.add(dd.dimension)
    const valueErr = validateDimensionValue(dd.dimension, dd.value)
    if (valueErr) return { ok: false, error: valueErr }
    if (!SENSITIVITIES.includes(dd.sensitivity)) return { ok: false, error: `${dd.dimension}.sensitivity invalid` }
    if (!DISCLOSURE_STATES.includes(dd.disclosure_state)) return { ok: false, error: `${dd.dimension}.disclosure_state invalid` }
    if (!IMPORTANCES.includes(dd.importance)) return { ok: false, error: `${dd.dimension}.importance invalid` }
    if (!Array.isArray(dd.allowed_intents) || dd.allowed_intents.length === 0) return { ok: false, error: `${dd.dimension}.allowed_intents required` }
    for (const it of dd.allowed_intents) {
      if (!(POLICY_INTENTS as readonly string[]).includes(it)) return { ok: false, error: `${dd.dimension}.allowed_intents contains "${it}" (work is excluded; must be one of ${POLICY_INTENTS.join(', ')})` }
    }
    if (!isIso(dd.expires_at)) return { ok: false, error: `${dd.dimension}.expires_at must be ISO` }
  }
  return { ok: true, dimensions: dims as PolicyDimension[] }
}

/** Canonical hash of the normalized dimension set (approval binds this). */
export function policyHash(dimensions: PolicyDimension[]): string {
  const normalized = [...dimensions]
    .map(x => ({ dimension: x.dimension, value: x.value, sensitivity: x.sensitivity, disclosure_state: x.disclosure_state, allowed_intents: [...x.allowed_intents].sort(), expires_at: x.expires_at, importance: x.importance }))
    .sort((a, b) => a.dimension.localeCompare(b.dimension))
  return createHash('sha256').update(canonicalize(normalized), 'utf8').digest('hex')
}

export function getCurrentPolicy(cardId: string): FitPolicy | null {
  const meta = d().prepare('SELECT current_version FROM v4_fit_policy_meta WHERE card_id = ?').get(cardId) as any
  if (!meta) return null
  const row = d().prepare('SELECT * FROM v4_fit_policies WHERE card_id = ? AND version = ?').get(cardId, meta.current_version) as any
  if (!row) return null
  return { card_id: cardId, version: row.version, policy_hash: row.policy_hash, schema_version: row.schema_version, dimensions: JSON.parse(row.policy_json) }
}

export function hasPolicy(cardId: string): boolean {
  return !!d().prepare('SELECT 1 FROM v4_fit_policy_meta WHERE card_id = ?').get(cardId)
}

/** A retained policy version by its hash (for receipt verification). */
export function getPolicyByHash(cardId: string, hash: string): FitPolicy | null {
  const row = d().prepare('SELECT * FROM v4_fit_policies WHERE card_id = ? AND policy_hash = ? ORDER BY version DESC LIMIT 1').get(cardId, hash) as any
  if (!row) return null
  return { card_id: cardId, version: row.version, policy_hash: row.policy_hash, schema_version: row.schema_version, dimensions: JSON.parse(row.policy_json) }
}

/** Store a new approved policy version. Returns the new version and hash. */
export function setPolicy(cardId: string, subjectKey: string, dimensions: PolicyDimension[]): { version: number; policy_hash: string } {
  const hash = policyHash(dimensions)
  const dd = d()
  const tx = dd.transaction(() => {
    const cur = (dd.prepare('SELECT current_version FROM v4_fit_policy_meta WHERE card_id = ?').get(cardId) as any)?.current_version ?? 0
    const version = cur + 1
    dd.prepare('INSERT INTO v4_fit_policies (card_id, version, subject_key, policy_hash, schema_version, policy_json) VALUES (?, ?, ?, ?, ?, ?)')
      .run(cardId, version, subjectKey, hash, DIMENSION_SCHEMA_VERSION, JSON.stringify(dimensions))
    dd.prepare(`INSERT INTO v4_fit_policy_meta (card_id, subject_key, current_version, updated_at) VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
      ON CONFLICT(card_id) DO UPDATE SET current_version = excluded.current_version, subject_key = excluded.subject_key, updated_at = excluded.updated_at`).run(cardId, subjectKey, version)
    return { version, policy_hash: hash }
  })
  return tx()
}

/** The dimensions of a policy that apply to a given intent (allowed_intents),
 *  excluding any that have expired. */
export function dimensionsForIntent(policy: FitPolicy, intent: string, now = Date.now()): PolicyDimension[] {
  return policy.dimensions.filter(x => x.allowed_intents.includes(intent) && Date.parse(x.expires_at) > now)
}
