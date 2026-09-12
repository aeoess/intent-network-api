// ══════════════════════════════════════════════════════════════
// mingle-write-v1 storage: nonces, evidence, authorizations, artifacts
// ══════════════════════════════════════════════════════════════
// Nine tables, one module, because they are one subsystem and a canonical write
// touches most of them inside a single transaction. Splitting them would spread
// one transaction across nine files.
//
// All additive. Nothing here alters an existing table, and nothing can: at this
// revision the repo has no ALTER TABLE, no PRAGMA user_version and no migrations
// list, and `CREATE TABLE IF NOT EXISTS` is a no op on an existing table, so a
// column added to an existing literal would silently never appear on a deployed
// database. New tables are free. New columns on old tables are not.
//
// Created EAGERLY at boot, never lazily on first use. The established lazy
// `init*Schema()` pattern would put DDL inside whatever transaction happens to
// touch the table first, and v3-routes.ts:231 already demonstrates that shape
// reaching CREATE TABLE at v3-db.ts:322 inside a transaction. A nonce table whose
// creation can be rolled back with a failed business write is worse than none.
//
// Every timestamp uses SQL_NOW_ISO. Comparing ISO strings against
// datetime('now') is lexically broken ('T' > ' ') and was a live always-true bug,
// documented at db.ts:20-25.

import type { Database } from 'better-sqlite3'
import { getDb, SQL_NOW_ISO } from './db.js'

export type AuthEvidence = 'canonical' | 'legacy_unbound'
export type AuthMode = 'canonical' | 'legacy_unbound'

/** Create every write-subsystem table. Idempotent, called at boot. */
export function initWriteSchema(): void {
  const d = getDb()
  d.exec(`
    -- Replay defense and idempotency. The claim is a bare INSERT whose primary
    -- key conflict means "already claimed", which is the atomic first-writer-wins
    -- pattern notify-db.ts:135-140 already uses. checkRateLimit is the WRONG
    -- template: it SELECTs then INSERTs with no transaction, and for a nonce the
    -- gap between the read and the write IS the replay window.
    CREATE TABLE IF NOT EXISTS write_nonces (
      actor_key     TEXT NOT NULL,
      nonce         TEXT NOT NULL,
      write_ref     TEXT NOT NULL,
      operation     TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      resource_id   TEXT NOT NULL,
      issued_at     TEXT NOT NULL,
      first_seen_at TEXT NOT NULL DEFAULT (${SQL_NOW_ISO}),
      status        TEXT NOT NULL,
      result_json   TEXT,
      PRIMARY KEY (actor_key, nonce)
    );
    CREATE INDEX IF NOT EXISTS idx_write_nonces_seen ON write_nonces(first_seen_at);
    CREATE INDEX IF NOT EXISTS idx_write_nonces_ref  ON write_nonces(write_ref);

    -- A create's second idempotency key. Nonce idempotency covers a byte
    -- identical retry. A client whose request timed out mints a fresh nonce and
    -- issued_at, so write_ref differs and uniqueness sees a new write. request_id
    -- is what stops that producing a second intro.
    CREATE TABLE IF NOT EXISTS write_create_map (
      request_id   TEXT PRIMARY KEY,
      actor_key    TEXT NOT NULL,
      operation    TEXT NOT NULL,
      created_type TEXT NOT NULL,
      created_id   TEXT NOT NULL,
      write_ref    TEXT NOT NULL,
      created_at   TEXT NOT NULL DEFAULT (${SQL_NOW_ISO})
    );
    CREATE INDEX IF NOT EXISTS idx_write_create_map_created ON write_create_map(created_type, created_id);

    -- The most important table here, because of bound_fields_json. That column
    -- names every semantic field the recorded signature actually covers, and a
    -- receipt renderer emits only clauses whose fields appear in it. That makes
    -- "a receipt never claims more than the evidence establishes" mechanical
    -- rather than a matter of care, which is what fit-v4-routes.ts:238 shows
    -- happens without it.
    CREATE TABLE IF NOT EXISTS write_evidence (
      evidence_id       TEXT PRIMARY KEY,
      write_ref         TEXT,
      actor_key         TEXT NOT NULL,
      operation         TEXT NOT NULL,
      resource_type     TEXT NOT NULL,
      resource_id       TEXT NOT NULL,
      evidence          TEXT NOT NULL,
      envelope_json     TEXT,
      signature         TEXT NOT NULL,
      payload_digest    TEXT,
      bound_fields_json TEXT NOT NULL,
      legacy_preimage   TEXT,
      recorded_at       TEXT NOT NULL DEFAULT (${SQL_NOW_ISO})
    );
    CREATE INDEX IF NOT EXISTS idx_write_evidence_resource ON write_evidence(resource_type, resource_id);
    CREATE INDEX IF NOT EXISTS idx_write_evidence_actor    ON write_evidence(actor_key);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_write_evidence_ref ON write_evidence(write_ref) WHERE write_ref IS NOT NULL;

    -- Anti-downgrade. (resource_type, resource_id, actor_key) -> mode, canonical
    -- absorbing. One row per signed write, for the SIGNER, never for a
    -- counterparty who has not written: a row written on someone else's behalf
    -- would assert a fact about an actor who has done nothing.
    CREATE TABLE IF NOT EXISTS write_auth_mode (
      resource_type TEXT NOT NULL,
      resource_id   TEXT NOT NULL,
      actor_key     TEXT NOT NULL,
      mode          TEXT NOT NULL,
      first_at      TEXT NOT NULL DEFAULT (${SQL_NOW_ISO}),
      PRIMARY KEY (resource_type, resource_id, actor_key)
    );

    -- The durable facts deriveIntroState reads. No state is stored here, only the
    -- authorizations a state is derived from. subject carries the dimension for
    -- release_exact and is empty for everything else, which is why the primary key
    -- has four parts: one actor can hold many live release_exact authorizations on
    -- one intro and exactly one share_contact.
    CREATE TABLE IF NOT EXISTS connection_authorizations (
      intro_id     TEXT NOT NULL,
      actor_key    TEXT NOT NULL,
      operation    TEXT NOT NULL,
      subject      TEXT NOT NULL DEFAULT '',
      evidence_id  TEXT NOT NULL,
      evidence     TEXT NOT NULL,
      live         INTEGER NOT NULL DEFAULT 1,
      withdrawn_by TEXT,
      created_at   TEXT NOT NULL DEFAULT (${SQL_NOW_ISO}),
      PRIMARY KEY (intro_id, actor_key, operation, subject)
    );
    CREATE INDEX IF NOT EXISTS idx_conn_auth_intro ON connection_authorizations(intro_id, live);

    -- One row per intro, ever. The primary key is the exactly-once mechanism, so
    -- the release does not depend on which transaction observes both
    -- authorizations first.
    CREATE TABLE IF NOT EXISTS connection_release (
      intro_id    TEXT PRIMARY KEY,
      released_at TEXT NOT NULL DEFAULT (${SQL_NOW_ISO}),
      a_write_ref TEXT,
      b_write_ref TEXT
    );

    -- opening_json is the only place in the schema that holds a private value.
    -- payload_json holds the signed payload, which is a commitment and no value,
    -- so the two are separate columns because they have different exposure rules
    -- and one column would lose that distinction at the first query.
    CREATE TABLE IF NOT EXISTS private_artifacts (
      artifact_id      TEXT PRIMARY KEY,
      intro_id         TEXT NOT NULL,
      operation        TEXT NOT NULL,
      subject          TEXT NOT NULL DEFAULT '',
      author_key       TEXT NOT NULL,
      recipient_key    TEXT NOT NULL,
      opening_json     TEXT NOT NULL,
      value_commitment TEXT NOT NULL,
      payload_json     TEXT NOT NULL,
      payload_digest   TEXT NOT NULL,
      envelope_json    TEXT NOT NULL,
      signature        TEXT NOT NULL,
      withdrawn        INTEGER NOT NULL DEFAULT 0,
      created_at       TEXT NOT NULL DEFAULT (${SQL_NOW_ISO})
    );
    CREATE INDEX IF NOT EXISTS idx_private_artifacts_recipient ON private_artifacts(recipient_key, intro_id);
    CREATE INDEX IF NOT EXISTS idx_private_artifacts_intro ON private_artifacts(intro_id, operation, subject);

    -- The salt is NOT here. The owner keeps policy, salt, commitment and the
    -- signed authorization. The server verifies the opening once at registration
    -- and then holds only the commitment, so it can state that a commitment was
    -- opened to it once and nothing more.
    CREATE TABLE IF NOT EXISTS policy_commitments (
      card_id       TEXT NOT NULL,
      commitment    TEXT NOT NULL,
      subject_key   TEXT NOT NULL,
      policy_hash   TEXT NOT NULL,
      version       INTEGER NOT NULL,
      registered_at TEXT NOT NULL DEFAULT (${SQL_NOW_ISO}),
      PRIMARY KEY (card_id, commitment)
    );

    -- issuer_key_id is inside content_json as well as in this column, so it is
    -- covered by receipt_digest and cannot be swapped after the fact.
    CREATE TABLE IF NOT EXISTS lifecycle_receipts (
      receipt_id     TEXT PRIMARY KEY,
      subject_type   TEXT NOT NULL,
      subject_id     TEXT NOT NULL,
      receipt_type   TEXT NOT NULL,
      content_json   TEXT NOT NULL,
      receipt_digest TEXT NOT NULL,
      receipt        TEXT NOT NULL,
      issuer_key_id  TEXT NOT NULL,
      rendered_at    TEXT NOT NULL DEFAULT (${SQL_NOW_ISO})
    );
    CREATE INDEX IF NOT EXISTS idx_lifecycle_receipts_subject ON lifecycle_receipts(subject_type, subject_id);
  `)
}

/** The nine tables this module owns, for the eager-creation test and for anyone
 *  auditing what 2B added. */
export const WRITE_TABLES = [
  'write_nonces',
  'write_create_map',
  'write_evidence',
  'write_auth_mode',
  'connection_authorizations',
  'connection_release',
  'private_artifacts',
  'policy_commitments',
  'lifecycle_receipts',
] as const

function d(): Database {
  return getDb()
}

// ── Anti-downgrade ────────────────────────────────────────────────────────

export interface AuthModeRow {
  resource_type: string
  resource_id: string
  actor_key: string
  mode: AuthMode
  first_at: string
}

/** Record the mode for the SIGNER of this write, and nobody else. Canonical is
 *  absorbing: once a row says canonical it never returns to legacy_unbound, so a
 *  legacy write is refused rather than recorded. */
export function recordAuthMode(resourceType: string, resourceId: string, actorKey: string, mode: AuthMode): void {
  d().prepare(`
    INSERT INTO write_auth_mode (resource_type, resource_id, actor_key, mode)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(resource_type, resource_id, actor_key) DO UPDATE SET
      mode = CASE WHEN write_auth_mode.mode = 'canonical' THEN 'canonical' ELSE excluded.mode END
  `).run(resourceType, resourceId, actorKey, mode)
}

export function authModeRow(resourceType: string, resourceId: string, actorKey: string): AuthModeRow | null {
  return (d().prepare('SELECT * FROM write_auth_mode WHERE resource_type = ? AND resource_id = ? AND actor_key = ?')
    .get(resourceType, resourceId, actorKey) as AuthModeRow) ?? null
}

/** The resolved mode binding this actor on this resource.
 *
 *  A create names `intro_request/<request_id>` because the intro does not exist
 *  yet, and a later act on the created intro names a different resource. Rather
 *  than pre-writing a row for a resource nobody has acted on, resolution walks
 *  back through write_create_map. Same protection, one row, and no fact asserted
 *  about anyone who has not written. */
export function resolveAuthMode(resourceType: string, resourceId: string, actorKey: string): AuthMode | null {
  const direct = authModeRow(resourceType, resourceId, actorKey)
  if (direct) return direct.mode
  if (resourceType === 'intro') {
    const created = d().prepare("SELECT request_id FROM write_create_map WHERE created_type = 'intro' AND created_id = ? AND actor_key = ?")
      .get(resourceId, actorKey) as { request_id: string } | undefined
    if (created) {
      const antecedent = authModeRow('intro_request', created.request_id, actorKey)
      if (antecedent) return antecedent.mode
    }
  }
  return null
}

// ── The create map ────────────────────────────────────────────────────────

export interface CreateMapRow {
  request_id: string
  actor_key: string
  operation: string
  created_type: string
  created_id: string
  write_ref: string
  created_at: string
}

/** First writer wins. A conflict means this request_id already created something,
 *  and the caller returns that instead of creating a second one. */
export function claimCreate(row: Omit<CreateMapRow, 'created_at'>): { claimed: boolean; existing: CreateMapRow | null } {
  try {
    d().prepare(`
      INSERT INTO write_create_map (request_id, actor_key, operation, created_type, created_id, write_ref)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(row.request_id, row.actor_key, row.operation, row.created_type, row.created_id, row.write_ref)
    return { claimed: true, existing: null }
  } catch {
    return { claimed: false, existing: createMapRow(row.request_id) }
  }
}

export function createMapRow(requestId: string): CreateMapRow | null {
  return (d().prepare('SELECT * FROM write_create_map WHERE request_id = ?').get(requestId) as CreateMapRow) ?? null
}

// ── Housekeeping ──────────────────────────────────────────────────────────

/** Retention is at least 24 hours, swept on first_seen_at rather than issued_at.
 *  Both satisfy the arithmetic that makes post-expiry replay impossible, and
 *  first_seen_at is the server's own clock while issued_at is the client's. */
export function purgeWriteNonces(retentionHours = 24): number {
  const cutoff = new Date(Date.now() - retentionHours * 3600 * 1000).toISOString()
  return d().prepare('DELETE FROM write_nonces WHERE first_seen_at < ?').run(cutoff).changes
}
