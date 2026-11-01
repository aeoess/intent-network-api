// Address block and same-key intros: a blocked address cannot publish, search or
// request intros but can still GET, other addresses are unaffected, and an intro
// between two cards of one key is refused. Synthetic keys and data only.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-block-test-'))
process.env.DB_PATH = join(tmpDir, 'block-test.db')

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const matchesDb = await import('../src/matches-db.js')
const v3db = await import('../src/v3-db.js')
const blocks = await import('../src/source-blocks.js')

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





const BAD = { 'X-Forwarded-For': '203.0.113.9, 84.17.44.229' }
const OTHER = { 'X-Forwarded-For': '198.51.100.20, 84.17.44.229' }
async function req(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) })
  const text = await r.text(); let j: any = null; try { j = JSON.parse(text) } catch { /* html */ }
  return { status: r.status, body: j, text }
}
const intro = (keys: Keys, from: string, to: string, headers: Record<string, string> = {}) => {
  const nonce = `n-${Math.random().toString(16).slice(2)}`
  return req('POST', '/api/v3/intros/request', { from_card: from, to_card: to, purpose: 'collaborate', note: 'hi', public_key: keys.publicKey, nonce,
    signature: sign(`intro-request:${from}:${to}:collaborate:${nonce}`, keys.privateKey) }, headers)
}

test('a blocked address cannot write or search, can still GET, and other addresses are unaffected', async () => {
  const k = generateKeyPair()
  const before = await req('POST', '/api/v3/cards', { card: makeCard(k, { headline: 'Block control before' }) }, BAD)
  assert.equal(before.status, 201, 'control: the address can publish before the block')
  assert.equal(blocks.blockSource('203.0.113.9', 'probe source', 'operator-test'), true)
  const pub = await req('POST', '/api/v3/cards', { card: makeCard(generateKeyPair(), { headline: 'Block after' }) }, BAD)
  assert.equal(pub.status, 403, pub.text)
  assert.match(pub.body.error, /blocked by the operator/)
  assert.equal((await req('POST', '/api/v3/cards/search', { limit: 5 }, BAD)).status, 403, 'search is a POST and is blocked too')
  const other = await req('POST', '/api/v3/cards', { card: makeCard(generateKeyPair(), { headline: 'Other address' }) }, OTHER)
  assert.equal(other.status, 201, 'another client behind the same edge is unaffected')
  assert.equal((await intro(k, before.body.card_id, other.body.card_id, BAD)).status, 403, 'intro requests are writes')
  assert.equal((await req('GET', `/api/v3/cards/${before.body.card_id}`, undefined, BAD)).status, 200, 'GET stays open')
  assert.equal((await req('GET', '/health', undefined, BAD)).status, 200)
  assert.equal(blocks.unblockSource('203.0.113.9'), true)
  assert.equal((await req('POST', '/api/v3/cards', { card: makeCard(generateKeyPair(), { headline: 'Block lifted' }) }, BAD)).status, 201)
})

test('blocking needs an address, a reason and an actor, and blocking twice is a no-op', () => {
  assert.throws(() => blocks.blockSource('', 'r', 'a'))
  assert.throws(() => blocks.blockSource('203.0.113.50', ' ', 'a'))
  assert.equal(blocks.blockSource('203.0.113.50', 'r', 'a'), true)
  assert.equal(blocks.blockSource('203.0.113.50', 'r', 'a'), false)
  assert.ok(blocks.listBlockedSources().some(b => b.ip === '203.0.113.50'))
  blocks.unblockSource('203.0.113.50')
})

test('an intro between two cards of the same key is refused, to another key it goes through', async () => {
  const k = generateKeyPair()
  const a = await req('POST', '/api/v3/cards', { card: makeCard(k, { headline: 'Same key intro A' }) })
  const b = await req('POST', '/api/v3/cards', { card: makeCard(k, { headline: 'Same key intro B' }, 1000) })
  const self = await intro(k, a.body.card_id, b.body.card_id)
  assert.equal(self.status, 400, self.text)
  assert.match(self.body.error, /same key/)
  const c = await req('POST', '/api/v3/cards', { card: makeCard(generateKeyPair(), { headline: 'Same key intro other' }) })
  const ok = await intro(k, a.body.card_id, c.body.card_id)
  assert.ok(ok.status === 200 || ok.status === 201, ok.text)
})
