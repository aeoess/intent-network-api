// ══════════════════════════════════════════════════════════════
// The write subsystem schema, the markers, and the compatibility clock
// ══════════════════════════════════════════════════════════════
// Nine additive tables and three markers. The tests that matter most here are the
// two that are easy to skip:
//
//   1. Eager creation. A table created lazily on first use has its CREATE inside
//      whatever transaction touches it first, and that CREATE rolls back with a
//      failed business write. So: open a transaction, fail it, and assert every
//      table is still there.
//   2. legacy_write_cutoff_at is unstamped and inferred from nothing. An unset
//      cutoff must read as an OPEN window, because a fresh database has an empty
//      marker table and reading that as a past cutoff would refuse every legacy
//      client on day one.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPair } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-write-db-test-'))
process.env.DB_PATH = join(tmpDir, 'write.db')
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey
// The compatibility clock stays unset for this suite unless a case seeds it.
delete process.env.MINGLE_CANONICAL_MCP_RELEASED_AT

const db = await import('../src/db.js')
const w = await import('../src/write-db.js')

before(() => { db.getDb(); w.initWriteSchema() })
after(() => { db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })

function tableExists(name: string): boolean {
  return !!db.getDb().prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?").get(name)
}

// ── Schema ────────────────────────────────────────────────────────────────

test('WRITE SCHEMA: all nine tables exist and the list matches what was created', () => {
  assert.equal(w.WRITE_TABLES.length, 9)
  for (const t of w.WRITE_TABLES) assert.equal(tableExists(t), true, `${t} exists`)
})

test('WRITE SCHEMA: init is idempotent across repeated calls', () => {
  w.initWriteSchema()
  w.initWriteSchema()
  for (const t of w.WRITE_TABLES) assert.equal(tableExists(t), true)
})

test('WRITE SCHEMA: the tables are created eagerly, so a failed transaction cannot remove them', () => {
  // The test that justifies not using the lazy init*Schema pattern.
  assert.throws(() => {
    db.getDb().transaction(() => {
      db.getDb().prepare('INSERT INTO write_auth_mode (resource_type, resource_id, actor_key, mode) VALUES (?, ?, ?, ?)')
        .run('intro', 'roll-me-back', 'k', 'canonical')
      throw new Error('injected failure inside the transaction')
    })()
  }, /injected failure/)
  for (const t of w.WRITE_TABLES) assert.equal(tableExists(t), true, `${t} survived a rolled back transaction`)
  assert.equal(w.authModeRow('intro', 'roll-me-back', 'k'), null, 'and the row did not survive')
})

test('WRITE SCHEMA: a row round trips in every one of the nine tables', () => {
  const d = db.getDb()
  const now = '2026-09-12T00:00:00.000Z'
  d.prepare('INSERT INTO write_nonces (actor_key, nonce, write_ref, operation, resource_type, resource_id, issued_at, status) VALUES (?,?,?,?,?,?,?,?)')
    .run('k1', 'n1', 'r1', 'request_intro', 'intro_request', 'req1', now, 'committed')
  d.prepare('INSERT INTO write_create_map (request_id, actor_key, operation, created_type, created_id, write_ref) VALUES (?,?,?,?,?,?)')
    .run('req1', 'k1', 'request_intro', 'intro', 'intro-1', 'r1')
  d.prepare('INSERT INTO write_evidence (evidence_id, write_ref, actor_key, operation, resource_type, resource_id, evidence, signature, bound_fields_json) VALUES (?,?,?,?,?,?,?,?,?)')
    .run('e1', 'r1', 'k1', 'request_intro', 'intro_request', 'req1', 'canonical', 'sig', '["operation"]')
  w.recordAuthMode('intro', 'intro-1', 'k1', 'canonical')
  d.prepare('INSERT INTO connection_authorizations (intro_id, actor_key, operation, subject, evidence_id, evidence) VALUES (?,?,?,?,?,?)')
    .run('intro-1', 'k1', 'request_intro', '', 'e1', 'canonical')
  d.prepare('INSERT INTO connection_release (intro_id) VALUES (?)').run('intro-1')
  d.prepare('INSERT INTO private_artifacts (artifact_id, intro_id, operation, author_key, recipient_key, opening_json, value_commitment, payload_json, payload_digest, envelope_json, signature) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
    .run('a1', 'intro-1', 'share_contact', 'k1', 'k2', '{}', 'c', '{}', 'pd', '{}', 'sig')
  d.prepare('INSERT INTO policy_commitments (card_id, commitment, subject_key, policy_hash, version) VALUES (?,?,?,?,?)')
    .run('card-1', 'commit1', 'k1', 'ph', 1)
  d.prepare('INSERT INTO lifecycle_receipts (receipt_id, subject_type, subject_id, receipt_type, content_json, receipt_digest, receipt, issuer_key_id) VALUES (?,?,?,?,?,?,?,?)')
    .run('rc1', 'intro', 'intro-1', 'connection', '{}', 'rd', 'sig', 'mk1_x')

  for (const t of w.WRITE_TABLES) {
    const n = (d.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get() as any).n
    assert.ok(n >= 1, `${t} holds the row that was written`)
  }
  // Every default timestamp uses SQL_NOW_ISO, so it is comparable to the ISO
  // strings the app stores. datetime('now') would be lexically broken against
  // them, which was a live always-true bug.
  const seen = (d.prepare('SELECT first_seen_at FROM write_nonces WHERE nonce = ?').get('n1') as any).first_seen_at
  assert.match(seen, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
})

// ── Anti-downgrade ────────────────────────────────────────────────────────

test('AUTH MODE: canonical is absorbing and legacy never overwrites it', () => {
  w.recordAuthMode('intro', 'abs-1', 'kA', 'legacy_unbound')
  assert.equal(w.authModeRow('intro', 'abs-1', 'kA')!.mode, 'legacy_unbound')
  w.recordAuthMode('intro', 'abs-1', 'kA', 'canonical')
  assert.equal(w.authModeRow('intro', 'abs-1', 'kA')!.mode, 'canonical')
  w.recordAuthMode('intro', 'abs-1', 'kA', 'legacy_unbound')
  assert.equal(w.authModeRow('intro', 'abs-1', 'kA')!.mode, 'canonical', 'canonical absorbs')
})

test('AUTH MODE: exactly one row per signed write, and none for a counterparty', () => {
  w.recordAuthMode('intro', 'pair-1', 'kA', 'canonical')
  const rows = db.getDb().prepare('SELECT actor_key FROM write_auth_mode WHERE resource_id = ?').all('pair-1') as any[]
  assert.deepEqual(rows.map(r => r.actor_key), ['kA'],
    'the counterparty has written nothing, so no row asserts anything about them')
  assert.equal(w.resolveAuthMode('intro', 'pair-1', 'kB'), null, 'and the counterparty resolves to no mode')
})

test('AUTH MODE: a create propagates to the created intro by lookup, not by a pre-written row', () => {
  // request_intro names intro_request/<request_id> because the intro does not
  // exist yet. Acting legacy on the created intro must still be refused, and the
  // protection comes from walking write_create_map rather than from a row written
  // for a resource nobody had acted on.
  w.recordAuthMode('intro_request', 'req-prop', 'kP', 'canonical')
  w.claimCreate({ request_id: 'req-prop', actor_key: 'kP', operation: 'request_intro', created_type: 'intro', created_id: 'intro-prop', write_ref: 'wr-prop' })
  assert.equal(w.authModeRow('intro', 'intro-prop', 'kP'), null, 'no row was pre-written for the new intro')
  assert.equal(w.resolveAuthMode('intro', 'intro-prop', 'kP'), 'canonical', 'and it resolves canonical anyway')
  assert.equal(w.resolveAuthMode('intro', 'intro-prop', 'kOther'), null, 'for the signer only')
})

// ── The create map ────────────────────────────────────────────────────────

test('CREATE MAP: first writer wins and a repeat returns the existing row', () => {
  const first = w.claimCreate({ request_id: 'req-2', actor_key: 'k', operation: 'request_intro', created_type: 'intro', created_id: 'intro-2', write_ref: 'w2' })
  assert.equal(first.claimed, true)
  const again = w.claimCreate({ request_id: 'req-2', actor_key: 'k', operation: 'request_intro', created_type: 'intro', created_id: 'intro-DIFFERENT', write_ref: 'w3' })
  assert.equal(again.claimed, false, 'a second create under the same request_id is refused')
  assert.equal(again.existing!.created_id, 'intro-2', 'and the caller gets the id it already created')
})

// ── Markers ───────────────────────────────────────────────────────────────

test('MARKERS: the 2A deploy marker is stamped once and a restart leaves it alone', () => {
  const first = db.getSchemaMarker(db.MINGLE_2A_MARKER_KEY)
  assert.ok(first, 'stamped at schema init')
  db.stamp2ADeployMarkerOnce()
  db.stamp2ADeployMarkerOnce()
  assert.equal(db.getSchemaMarker(db.MINGLE_2A_MARKER_KEY), first, 'calling it again is what a restart looks like')
})

test('MARKERS: an unstamped key reads null, which is a real answer', () => {
  assert.equal(db.getSchemaMarker('no_such_marker'), null)
})

// ── The compatibility clock ───────────────────────────────────────────────

test('CUTOFF: unset means the legacy window is OPEN, never closed', () => {
  assert.equal(db.legacyWriteCutoffAt(), null, 'nothing has stamped it')
  assert.equal(db.legacyWindowClosed(), false,
    'an empty marker table is the state of a fresh database, and reading it as a past cutoff would refuse every legacy client on day one')
  assert.equal(db.legacyWindowClosed(new Date('2099-01-01T00:00:00.000Z')), false,
    'and no future date closes a window that was never opened')
})

test('CUTOFF: nothing derives it from deploy time, build time or a first request', () => {
  // Calling the stamp with no variable set must write nothing at all.
  db.stampCanonicalMcpReleaseOnce({})
  assert.equal(db.legacyWriteCutoffAt(), null)
  assert.equal(db.getSchemaMarker(db.CANONICAL_MCP_RELEASED_KEY), null)
})

test('CUTOFF: an explicit release instant seeds the marker, and the marker is the authority', () => {
  db.stampCanonicalMcpReleaseOnce({ MINGLE_CANONICAL_MCP_RELEASED_AT: '2026-10-01T00:00:00.000Z' })
  assert.equal(db.getSchemaMarker(db.CANONICAL_MCP_RELEASED_KEY), '2026-10-01T00:00:00.000Z')
  assert.equal(db.legacyWriteCutoffAt(), '2026-10-31T00:00:00.000Z', '30 days from the release')
  assert.equal(db.legacyWindowClosed(new Date('2026-10-30T00:00:00.000Z')), false)
  assert.equal(db.legacyWindowClosed(new Date('2026-10-31T00:00:00.001Z')), true)

  // A later or different variable cannot move a cutoff that is already recorded.
  db.stampCanonicalMcpReleaseOnce({ MINGLE_CANONICAL_MCP_RELEASED_AT: '2027-01-01T00:00:00.000Z' })
  assert.equal(db.legacyWriteCutoffAt(), '2026-10-31T00:00:00.000Z', 'INSERT OR IGNORE, so an early stamp is not recoverable and a late one is inert')
})

test('CUTOFF: an unparseable release instant throws rather than stamping something wrong', () => {
  assert.throws(() => db.stampCanonicalMcpReleaseOnce({ MINGLE_CANONICAL_MCP_RELEASED_AT: 'soon' }), /parseable/)
})

// ── Nonce retention ───────────────────────────────────────────────────────

test('NONCE RETENTION: the purge drops rows past 24 hours and keeps newer ones', () => {
  const d = db.getDb()
  const old = new Date(Date.now() - 25 * 3600 * 1000).toISOString()
  const fresh = new Date(Date.now() - 1 * 3600 * 1000).toISOString()
  d.prepare('INSERT INTO write_nonces (actor_key, nonce, write_ref, operation, resource_type, resource_id, issued_at, first_seen_at, status) VALUES (?,?,?,?,?,?,?,?,?)')
    .run('kR', 'old-nonce', 'r', 'decline', 'intro', 'i', old, old, 'committed')
  d.prepare('INSERT INTO write_nonces (actor_key, nonce, write_ref, operation, resource_type, resource_id, issued_at, first_seen_at, status) VALUES (?,?,?,?,?,?,?,?,?)')
    .run('kR', 'fresh-nonce', 'r', 'decline', 'intro', 'i', fresh, fresh, 'committed')
  const removed = w.purgeWriteNonces(24)
  assert.ok(removed >= 1)
  assert.equal(d.prepare('SELECT 1 FROM write_nonces WHERE nonce = ?').get('old-nonce'), undefined)
  assert.ok(d.prepare('SELECT 1 FROM write_nonces WHERE nonce = ?').get('fresh-nonce'), 'the fresh one stays')
})
