// ══════════════════════════════════════════════════════════════
// The root index capability field
// ══════════════════════════════════════════════════════════════
// One field a client reads to decide which lane to use. Two properties matter:
//
//   1  it is ALWAYS present, so a client can tell "this server does not know about
//      canonical writes" from "this server has not answered yet"
//   2  legacy_accepted is derived from the marker and never from an unset value. A missing
//      marker means the window is OPEN, because a fresh database has no marker and reading
//      that as a past cutoff would refuse every legacy client the moment the table is empty.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-cap-test-'))
process.env.DB_PATH = join(tmpDir, 'cap.db')
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => {
  db.getDb().prepare('DELETE FROM rate_limits').run()
  db.getDb().prepare('DELETE FROM schema_markers WHERE key = ?').run(db.LEGACY_WRITE_CUTOFF_KEY)
})

async function root(): Promise<any> {
  return (await fetch(`${base}/`)).json()
}
function setCutoff(at: string): void {
  db.getDb().prepare('INSERT OR REPLACE INTO schema_markers (key, value) VALUES (?, ?)')
    .run(db.LEGACY_WRITE_CUTOFF_KEY, at)
}

async function withV2<T>(value: string | undefined, fn: () => Promise<T>): Promise<T> {
  const previous = process.env.MINGLE_V2_ENABLED
  if (value === undefined) delete process.env.MINGLE_V2_ENABLED
  else process.env.MINGLE_V2_ENABLED = value
  try { return await fn() } finally {
    if (previous === undefined) delete process.env.MINGLE_V2_ENABLED
    else process.env.MINGLE_V2_ENABLED = previous
  }
}

test('CAPABILITY: the field is present with the v2 flag in every combination', async () => {
  for (const v2 of [undefined, '1', '0', 'true'] as const) {
    const body = await withV2(v2, root)
    assert.ok(body.write_authorization, `v2=${String(v2)}: the field is present`)
    assert.equal(body.write_authorization.domain, 'mingle-write-v1', `v2=${String(v2)}`)
    assert.equal(body.write_authorization.preferred, true, `v2=${String(v2)}`)
  }
  // It is orthogonal to v2: turning the legacy 48h surface on or off changes nothing here.
  const on = await withV2('1', root)
  const off = await withV2(undefined, root)
  assert.deepEqual(on.write_authorization, off.write_authorization)
  assert.equal('legacy_v2' in on, false, 'while legacy_v2 still appears only when v2 is off')
  assert.deepEqual(off.legacy_v2, { available: false })
})

test('CAPABILITY: a missing marker reports accepted true with a null cutoff', async () => {
  assert.equal(db.legacyWriteCutoffAt(), null, 'a fresh database has no marker')
  const body = await root()
  assert.equal(body.write_authorization.legacy_accepted, true,
    'null means the window is OPEN, never a cutoff in the past')
  assert.equal(body.write_authorization.legacy_cutoff_at, null)
  assert.equal(db.legacyWindowClosed(), false)
})

test('CAPABILITY: a future cutoff reports accepted true and names the instant', async () => {
  const at = new Date(Date.now() + 30 * 864e5).toISOString()
  setCutoff(at)
  const body = await root()
  assert.equal(body.write_authorization.legacy_accepted, true)
  assert.equal(body.write_authorization.legacy_cutoff_at, at,
    'so a client can warn its user before the window closes rather than after')
})

test('CAPABILITY: a past cutoff reports accepted false, and the cutoff read comes from the marker', async () => {
  const at = new Date(Date.now() - 1000).toISOString()
  setCutoff(at)
  const body = await root()
  assert.equal(body.write_authorization.legacy_accepted, false)
  assert.equal(body.write_authorization.legacy_cutoff_at, at)
  assert.equal(db.legacyWindowClosed(), true)

  // The marker is the authority, not the environment variable that seeds it. Changing the
  // variable after the marker exists does not move the answer.
  const previous = process.env.MINGLE_CANONICAL_MCP_RELEASED_AT
  process.env.MINGLE_CANONICAL_MCP_RELEASED_AT = new Date(Date.now() + 365 * 864e5).toISOString()
  try {
    db.stampCanonicalMcpReleaseOnce()
    const again = await root()
    assert.equal(again.write_authorization.legacy_cutoff_at, at,
      'INSERT OR IGNORE, so an early or repeated stamp cannot move a cutoff already recorded')
    assert.equal(again.write_authorization.legacy_accepted, false)
  } finally {
    if (previous === undefined) delete process.env.MINGLE_CANONICAL_MCP_RELEASED_AT
    else process.env.MINGLE_CANONICAL_MCP_RELEASED_AT = previous
  }
})

test('CAPABILITY: the boundary is inclusive on the closed side', async () => {
  // legacyWindowClosed is `now >= cutoff`, so the instant itself is closed rather than open.
  // Asserted because a half-open window is the kind of thing two implementations disagree on.
  const now = new Date()
  setCutoff(now.toISOString())
  assert.equal(db.legacyWindowClosed(now), true, 'at the cutoff instant the window is closed')
  assert.equal(db.legacyWindowClosed(new Date(now.getTime() - 1)), false, 'one millisecond before, open')
  const body = await root()
  assert.equal(body.write_authorization.legacy_accepted, false)
})
