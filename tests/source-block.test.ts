// Scoped, temporary address restriction and same-key intros. A restricted address
// cannot publish, renew, replace, request intros or sign up for email, but can still
// search, fetch, withdraw and delete. Spoofed forwarding headers change nothing, the
// restriction expires on its own, and an intro between two cards of one key is
// refused. Synthetic keys and data only.

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





// Production shape: [anything the client sent], client address, edge address.
const REAL = '203.0.113.9'
const AS_REAL = { 'X-Forwarded-For': `${REAL}, 84.17.44.229` }
const SPOOF_AWAY = { 'X-Forwarded-For': `6.6.6.6, ${REAL}, 84.17.44.229` }
const FRAME_OTHER = { 'X-Forwarded-For': `${REAL}, 198.51.100.20, 84.17.44.229` }
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
const subscribe = (keys: Keys, email: string, headers: Record<string, string> = {}) => {
  const nonce = `s-${Math.random().toString(16).slice(2)}`
  return req('POST', '/api/v3/notifications/subscribe', { subject_key: keys.publicKey, email, nonce, signature: sign(`${email}:${nonce}`, keys.privateKey) }, headers)
}
const verb = (keys: Keys, id: string, name: string, headers: Record<string, string> = {}) =>
  req('POST', `/api/v3/cards/${id}/${name}`, { public_key: keys.publicKey, signature: sign(`${name}:${id}`, keys.privateKey) }, headers)

test('a restricted address cannot add to the network, and can still search, fetch, withdraw and delete', async () => {
  const k = generateKeyPair()
  const mine = await req('POST', '/api/v3/cards', { card: makeCard(k, { headline: 'Restriction owner card' }) }, AS_REAL)
  const other = await req('POST', '/api/v3/cards', { card: makeCard(generateKeyPair(), { headline: 'Restriction other card' }) }, OTHER)
  assert.deepEqual([mine.status, other.status], [201, 201], 'control: both publish before the restriction')
  blocks.restrictSource(REAL, 'probe source', 'operator-test')

  const pub = await req('POST', '/api/v3/cards', { card: makeCard(generateKeyPair(), { headline: 'Restriction new card' }) }, AS_REAL)
  assert.equal(pub.status, 403, pub.text)
  assert.match(pub.body.error, /paused by the operator until .*withdrawing or deleting your own cards still works/)
  assert.equal((await req('POST', `/api/v3/cards/${mine.body.card_id}/renew`, { card: makeCard(k, { headline: 'Restriction owner card' }, 1000) }, AS_REAL)).status, 403)
  assert.equal((await req('POST', `/api/v3/cards/${mine.body.card_id}/replace`, { card: makeCard(k, { headline: 'Restriction replaced' }, 2000) }, AS_REAL)).status, 403)
  assert.equal((await intro(k, mine.body.card_id, other.body.card_id, AS_REAL)).status, 403)
  assert.equal((await subscribe(k, 'restricted@aeoess-test.org', AS_REAL)).status, 403)

  assert.equal((await req('POST', '/api/v3/cards/search', { limit: 5 }, AS_REAL)).status, 200, 'search stays open')
  assert.equal((await req('GET', `/api/v3/cards/${mine.body.card_id}`, undefined, AS_REAL)).status, 200, 'fetch stays open')
  assert.equal((await verb(k, mine.body.card_id, 'withdraw', AS_REAL)).status, 200, 'the owner can still take the card down')
  assert.equal((await verb(k, mine.body.card_id, 'delete-server-copy', AS_REAL)).status, 200, 'and delete it')
  blocks.liftRestriction(REAL)
})

test('forwarding headers a client adds can neither escape a restriction nor put one on someone else', async () => {
  blocks.restrictSource(REAL, 'probe source', 'operator-test')
  const escape = await req('POST', '/api/v3/cards', { card: makeCard(generateKeyPair(), { headline: 'Spoof escape' }) }, SPOOF_AWAY)
  assert.equal(escape.status, 403, 'a fake leading address does not hide the real one')
  const framed = await req('POST', '/api/v3/cards', { card: makeCard(generateKeyPair(), { headline: 'Spoof frame' }) }, FRAME_OTHER)
  assert.equal(framed.status, 201, 'naming the restricted address in a header does not restrict the real client')
  blocks.liftRestriction(REAL)
})

test('a restriction expires on its own, can be narrowed to one scope, and needs a reason and an actor', async () => {
  const past = Date.now() - 25 * 3600 * 1000
  blocks.restrictSource(REAL, 'old', 'operator-test', { nowMs: past })
  assert.equal(blocks.isRestricted(REAL, 'publish'), false, 'a 24 hour restriction set 25 hours ago no longer applies')
  assert.equal((await req('POST', '/api/v3/cards', { card: makeCard(generateKeyPair(), { headline: 'After expiry' }) }, AS_REAL)).status, 201)

  blocks.restrictSource(REAL, 'subscribe only', 'operator-test', { scopes: ['subscribe'], hours: 1 })
  assert.equal(blocks.isRestricted(REAL, 'subscribe'), true)
  assert.equal(blocks.isRestricted(REAL, 'publish'), false)
  assert.equal((await req('POST', '/api/v3/cards', { card: makeCard(generateKeyPair(), { headline: 'Scope publish open' }) }, AS_REAL)).status, 201)
  blocks.liftRestriction(REAL)

  assert.throws(() => blocks.restrictSource('', 'r', 'a'))
  assert.throws(() => blocks.restrictSource(REAL, ' ', 'a'))
  assert.throws(() => blocks.restrictSource(REAL, 'r', 'a', { hours: 0 }))
  assert.throws(() => blocks.restrictSource(REAL, 'r', 'a', { scopes: ['search' as any] }))
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
