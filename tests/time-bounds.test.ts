// Time bounds at write time: created_at at most 5 minutes ahead of server time and at
// most 24 hours old, a lifetime of at most 60 days, and received_at stored by the
// server. Synthetic keys and data only.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-time-test-'))
process.env.DB_PATH = join(tmpDir, 'time-test.db')

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const matchesDb = await import('../src/matches-db.js')
const v3db = await import('../src/v3-db.js')
const { timeBoundsError, MAX_TTL_DAYS } = await import('../src/v3-cards.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(resolve => { server = app.listen(0, '127.0.0.1', () => resolve()) })
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })

type Keys = { publicKey: string; privateKey: string }

function makeCard(keys: Keys, overrides: Record<string, unknown> = {}, createdOffsetMs = 0): Record<string, any> {
  const now = Date.now() + createdOffsetMs
  const card: Record<string, any> = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(now).toISOString(),
    expires_at: new Date(now + 21 * 24 * 3600 * 1000).toISOString(),
    headline: 'Engineer seeking collaborators on agent delegation',
    intents: ['collaborate'],
    seeking: [{ description: 'Collaborators on agent delegation and revocation', topics: ['delegation', 'revocation'], engagement: 'part_time' }],
    offering: [{ description: 'Experience building delegation verifiers', topics: ['delegation'], provenance: 'principal_statement' }],
    preferences: [], artifacts: [], event_ref: null, team_size_sought: null,
    visibility: { headline: 'network', seeking: 'network', offering: 'network' },
    composition: { agent_assisted: true, skill_version: 'mingle-composer-v1' },
    delegation_ref: null, revocation_status: 'active',
    ...overrides,
  }
  return seal(card, keys)
}

function seal(card: Record<string, any>, keys: Keys): Record<string, any> {
  delete card.signature; delete card.approval
  const card_hash = cardContentHash(card)
  card.approval = { card_hash, approved_at: new Date().toISOString(), principal_signature: sign(card_hash, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return card
}





const MIN = 60000, HOUR = 3600000, DAY = 86400000
async function post(path: string, body: unknown): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}
// makeCard sets expires_at = created_at + 21 days; this variant sets the lifetime.
function timed(keys: Keys, createdOffsetMs: number, ttlMs = 21 * DAY, headline = `Time bound ${createdOffsetMs} ${ttlMs}`): Record<string, any> {
  const card = makeCard(keys, { headline }, createdOffsetMs)
  card.expires_at = new Date(Date.parse(card.created_at) + ttlMs).toISOString()
  return seal(card, keys)
}

test('created_at more than 5 minutes ahead is refused, within 5 minutes is accepted', async () => {
  const k = generateKeyPair()
  const ahead = await post('/api/v3/cards', { card: timed(k, 6 * MIN) })
  assert.equal(ahead.status, 400, JSON.stringify(ahead.body))
  assert.match(ahead.body.error, /ahead of server time/)
  assert.equal((await post('/api/v3/cards', { card: timed(k, 4 * MIN) })).status, 201)
})

test('created_at more than 24 hours old is refused, a card signed an hour ago is accepted', async () => {
  const k = generateKeyPair()
  const old = await post('/api/v3/cards', { card: timed(k, -25 * HOUR) })
  assert.equal(old.status, 400, JSON.stringify(old.body))
  assert.match(old.body.error, /24 hours old/)
  // The 2026-10-31 probe batch was signed about 70 minutes before release. That alone is not refused.
  assert.equal((await post('/api/v3/cards', { card: timed(k, -70 * MIN) })).status, 201)
})

test('a lifetime over 60 days is refused, exactly 60 days is accepted', async () => {
  const k = generateKeyPair()
  const long = await post('/api/v3/cards', { card: timed(k, 0, 61 * DAY) })
  assert.equal(long.status, 400, JSON.stringify(long.body))
  assert.match(long.body.error, /at most 60 days/)
  assert.equal((await post('/api/v3/cards', { card: timed(k, 0, 60 * DAY) })).status, 201)
})

test('renew and replace apply the same bounds', async () => {
  const k = generateKeyPair()
  const p = await post('/api/v3/cards', { card: timed(k, 0, 21 * DAY, 'Bounds renew probe') })
  assert.equal(p.status, 201)
  const rn = await post(`/api/v3/cards/${p.body.card_id}/renew`, { card: timed(k, 10 * MIN, 21 * DAY, 'Bounds renew probe') })
  assert.equal(rn.status, 400, JSON.stringify(rn.body))
  const rp = await post(`/api/v3/cards/${p.body.card_id}/replace`, { card: timed(k, 1000, 90 * DAY, 'Bounds replace probe') })
  assert.equal(rp.status, 400, JSON.stringify(rp.body))
  assert.equal(v3db.getV3Card(p.body.card_id)?.revocation_status, 'active', 'refused writes change nothing')
})

test('the server stores its own received_at next to the signed created_at', async () => {
  const k = generateKeyPair()
  const before = Date.now()
  const p = await post('/api/v3/cards', { card: timed(k, -30 * MIN) })
  assert.equal(p.status, 201)
  const row = db.getDb().prepare('SELECT created_at, received_at FROM v3_cards WHERE card_id = ?').get(p.body.card_id) as any
  assert.ok(Date.parse(row.received_at) >= before - 1000 && Date.parse(row.received_at) <= Date.now() + 1000, row.received_at)
  assert.ok(Date.parse(row.received_at) - Date.parse(row.created_at) >= 29 * MIN, 'the two clocks are kept apart')
})

test('timeBoundsError boundaries', () => {
  const now = Date.parse('2026-11-01T06:00:00.000Z')
  const at = (c: number, ttl = 21 * DAY) => ({ created_at: new Date(now + c).toISOString(), expires_at: new Date(now + c + ttl).toISOString() })
  assert.equal(timeBoundsError(at(5 * MIN), now), null)
  assert.ok(timeBoundsError(at(5 * MIN + 1), now))
  assert.equal(timeBoundsError(at(-24 * HOUR), now), null)
  assert.ok(timeBoundsError(at(-24 * HOUR - 1), now))
  assert.equal(timeBoundsError(at(0, MAX_TTL_DAYS * DAY + MIN), now), null)
  assert.ok(timeBoundsError(at(0, MAX_TTL_DAYS * DAY + MIN + 1), now))
})
