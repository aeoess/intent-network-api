// Replay guard: signed content that was taken down cannot come back through
// publish, renew or replace, concurrent identical writes store one row, and the
// database refuses a second row for the same (subject_key, card_hash).
// Synthetic keys and data only.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-replay-test-'))
process.env.DB_PATH = join(tmpDir, 'replay-test.db')

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const matchesDb = await import('../src/matches-db.js')
const v3db = await import('../src/v3-db.js')

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
  const card_hash = cardContentHash(card)
  card.approval = { card_hash, approved_at: new Date(now).toISOString(), principal_signature: sign(card_hash, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return card
}

async function publish(card: Record<string, any>, headers: Record<string, string> = {}): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}/api/v3/cards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify({ card }),
  })
  return { status: res.status, body: await res.json() }
}

async function withdraw(keys: Keys, cardId: string): Promise<number> {
  const res = await fetch(`${base}/api/v3/cards/${cardId}/withdraw`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: keys.publicKey, signature: sign(`withdraw:${cardId}`, keys.privateKey) }),
  })
  return res.status
}


async function post(path: string, body: unknown): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}/api/v3${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}
const renew = (oldId: string, card: Record<string, any>) => post(`/cards/${oldId}/renew`, { card })
const replace = (oldId: string, card: Record<string, any>) => post(`/cards/${oldId}/replace`, { card })
const verb = (keys: Keys, cardId: string, name: string) =>
  post(`/cards/${cardId}/${name}`, { public_key: keys.publicKey, signature: sign(`${name}:${cardId}`, keys.privateKey) })
const statusOf = async (cardId: string): Promise<string> =>
  (await fetch(`${base}/api/v3/cards/${cardId}`).then(r => r.json())).revocation_status
const rowsFor = (card: Record<string, any>): number =>
  (db.getDb().prepare('SELECT COUNT(*) n FROM v3_cards WHERE subject_key = ? AND card_hash = ?').get(card.subject_key, card.approval.card_hash) as any).n

test('renew cannot bring back the signed version it superseded', async () => {
  const keys = generateKeyPair()
  const v1 = makeCard(keys, { headline: 'Renew replay probe' })
  const p = await publish(v1)
  assert.equal(p.status, 201, JSON.stringify(p.body))
  const r = await renew(p.body.card_id, makeCard(keys, { headline: 'Renew replay probe' }, 1000))
  assert.equal(r.status, 201, JSON.stringify(r.body))
  const back = await renew(r.body.new_card_id, v1)
  assert.equal(back.status, 409, JSON.stringify(back.body))
  assert.equal(await statusOf(p.body.card_id), 'superseded')
  assert.equal(await statusOf(r.body.new_card_id), 'active')
  assert.equal(rowsFor(v1), 1)
})

test('renew with the live card itself is refused and stores no second row', async () => {
  const keys = generateKeyPair()
  const card = makeCard(keys, { headline: 'Renew identical probe' })
  const p = await publish(card)
  assert.equal(p.status, 201)
  const same = await renew(p.body.card_id, card)
  assert.equal(same.status, 409, JSON.stringify(same.body))
  assert.equal(await statusOf(p.body.card_id), 'active')
  assert.equal(rowsFor(card), 1)
})

test('replace cannot use a withdrawn card as the replacement', async () => {
  const keys = generateKeyPair()
  const gone = makeCard(keys, { headline: 'Replace replay withdrawn' })
  const g = await publish(gone)
  assert.equal(g.status, 201)
  assert.equal((await verb(keys, g.body.card_id, 'withdraw')).status, 200)
  const live = await publish(makeCard(keys, { headline: 'Replace replay live target' }, 1000))
  assert.equal(live.status, 201)
  const rep = await replace(live.body.card_id, gone)
  assert.equal(rep.status, 409, JSON.stringify(rep.body))
  assert.equal(rep.body.card_id, g.body.card_id)
  assert.equal(await statusOf(live.body.card_id), 'active', 'the refused replace changes nothing')
  assert.equal(await statusOf(g.body.card_id), 'withdrawn')
})

test('replace cannot swap back to the version it superseded', async () => {
  const keys = generateKeyPair()
  const a = makeCard(keys, { headline: 'Replace swap back A' })
  const pa = await publish(a)
  assert.equal(pa.status, 201)
  const rb = await replace(pa.body.card_id, makeCard(keys, { headline: 'Replace swap back B' }, 1000))
  assert.equal(rb.status, 201, JSON.stringify(rb.body))
  const back = await replace(rb.body.new_card_id, a)
  assert.equal(back.status, 409, JSON.stringify(back.body))
  assert.equal(await statusOf(pa.body.card_id), 'superseded')
  assert.equal(await statusOf(rb.body.new_card_id), 'active')
})

test('after delete-server-copy the signed card cannot be published again', async () => {
  const keys = generateKeyPair()
  const card = makeCard(keys, { headline: 'Delete then replay probe' })
  const p = await publish(card)
  assert.equal(p.status, 201)
  assert.equal((await verb(keys, p.body.card_id, 'delete-server-copy')).status, 200)
  const replay = await publish(card)
  assert.equal(replay.status, 409, JSON.stringify(replay.body))
  assert.equal(await statusOf(p.body.card_id), 'deleted')
  assert.equal(rowsFor(card), 1)
})

test('superseded, authority-revoked and stopped cards cannot be published again either', async () => {
  for (const name of ['supersede', 'revoke-authority', 'stop-new-matches']) {
    const keys = generateKeyPair()
    const card = makeCard(keys, { headline: `Verb replay probe ${name}` })
    const p = await publish(card)
    assert.equal(p.status, 201)
    assert.equal((await verb(keys, p.body.card_id, name)).status, 200, name)
    const replay = await publish(card)
    assert.equal(replay.status, 409, `${name}: ${JSON.stringify(replay.body)}`)
  }
})

test('a replayed withdrawn card stays withdrawn and generates no matches', async () => {
  const other = generateKeyPair()
  const counterpart = await publish(makeCard(other, { headline: 'Replay match counterpart' }))
  assert.equal(counterpart.status, 201)
  const keys = generateKeyPair()
  const card = makeCard(keys, { headline: 'Replay match probe' }, 1000)
  const p = await publish(card)
  assert.equal(p.status, 201)
  assert.equal((await verb(keys, p.body.card_id, 'withdraw')).status, 200)
  assert.equal((await publish(card)).status, 409)
  assert.equal(await statusOf(p.body.card_id), 'withdrawn')
  assert.equal(matchesDb.ownerMatches(p.body.card_id).length, 0)
  assert.equal(matchesDb.ownerMatches(counterpart.body.card_id).some((m: any) => m.other_card_id === p.body.card_id), false)
})

test('concurrent identical publishes store one card, concurrent replays all fail', async () => {
  // Four plus four stays under the per-key publish limit of 10 per hour.
  const keys = generateKeyPair()
  const card = makeCard(keys, { headline: 'Concurrent publish probe' })
  const results = await Promise.all(Array.from({ length: 4 }, () => publish(card)))
  const created = results.filter(r => r.status === 201)
  assert.equal(created.length, 1, JSON.stringify(results.map(r => r.status)))
  assert.ok(results.every(r => r.status === 201 || (r.status === 200 && r.body.idempotent === true)))
  assert.equal(new Set(results.map(r => r.body.card_id)).size, 1)
  assert.equal(rowsFor(card), 1)
  assert.equal((await verb(keys, created[0].body.card_id, 'withdraw')).status, 200)
  const replays = await Promise.all(Array.from({ length: 4 }, () => publish(card)))
  assert.deepEqual(replays.map(r => r.status), [409, 409, 409, 409])
  assert.equal(await statusOf(created[0].body.card_id), 'withdrawn')
})

test('the database refuses a second row for the same subject and card hash', () => {
  const keys = generateKeyPair()
  const card = makeCard(keys, { headline: 'Unique index probe' }) as any
  v3db.insertV3Card('v3-connection-unique-a', card, card.approval.card_hash)
  let caught: unknown = null
  try { v3db.insertV3Card('v3-connection-unique-b', card, card.approval.card_hash) } catch (e) { caught = e }
  assert.ok(caught, 'second insert must throw')
  assert.equal(v3db.isCardHashConflict(caught), true)
  // A different subject with the same hash value is a different row.
  const otherKey = generateKeyPair().publicKey
  v3db.insertV3Card('v3-connection-unique-c', { ...card, subject_key: otherKey }, card.approval.card_hash)
})
