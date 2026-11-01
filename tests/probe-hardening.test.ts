// Regression cases from the 2026-10-31 probe run against production: a signed card
// replayed after withdrawal, one key matching its own cards, and many free keys
// publishing from one source. Synthetic keys and data only.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-probe-test-'))
process.env.DB_PATH = join(tmpDir, 'probe-test.db')

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const matchesDb = await import('../src/matches-db.js')

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

test('fetching a card never returns its signature or approval, and still returns what clients read', async () => {
  const keys = generateKeyPair()
  const pub = await publish(makeCard(keys))
  assert.equal(pub.status, 201, JSON.stringify(pub.body))
  const fetched = await fetch(`${base}/api/v3/cards/${pub.body.card_id}`).then(r => r.json())
  assert.equal(fetched.card.signature, undefined)
  assert.equal(fetched.card.approval, undefined)
  assert.equal(fetched.card.subject_key, keys.publicKey, 'renew checks ownership with subject_key')
  assert.equal(fetched.card.headline, 'Engineer seeking collaborators on agent delegation')
  assert.equal(fetched.revocation_status, 'active')
})

test('a withdrawn card cannot be published again from its signed copy', async () => {
  const keys = generateKeyPair()
  const card = makeCard(keys)
  const first = await publish(card)
  assert.equal(first.status, 201)
  assert.equal(await withdraw(keys, first.body.card_id), 200)
  const replay = await publish(card)
  assert.equal(replay.status, 409, JSON.stringify(replay.body))
  assert.equal(replay.body.card_id, first.body.card_id)
  // Control: the owner can still publish the same words as a new card with new timestamps.
  const fresh = await publish(makeCard(keys, {}, 1000))
  assert.equal(fresh.status, 201, JSON.stringify(fresh.body))
})

test('publishing the identical live card twice stays idempotent', async () => {
  const keys = generateKeyPair()
  const card = makeCard(keys, { headline: 'Idempotency control card' })
  const a = await publish(card)
  const b = await publish(card)
  assert.equal(a.status, 201)
  assert.equal(b.status, 200)
  assert.equal(b.body.idempotent, true)
  assert.equal(b.body.card_id, a.body.card_id)
})

test('two cards of the same key never match each other, a different key still matches', async () => {
  const keys = generateKeyPair()
  const a = await publish(makeCard(keys, { headline: 'Self match probe one' }))
  const b = await publish(makeCard(keys, { headline: 'Self match probe two' }, 1000))
  assert.equal(a.status, 201); assert.equal(b.status, 201)
  const selfPair = matchesDb.ownerMatches(a.body.card_id).find((m: any) => m.other_card_id === b.body.card_id)
  assert.equal(selfPair, undefined, 'same-key cards must not match')
  const other = generateKeyPair()
  const c = await publish(makeCard(other, { headline: 'Self match control other key' }))
  assert.equal(c.status, 201)
  const cross = matchesDb.ownerMatches(c.body.card_id).find((m: any) => m.other_card_id === a.body.card_id)
  assert.ok(cross, 'cards of different keys with overlapping intents still match')
})

test('one source cannot publish past the per-source limit by rotating keys, and loopback is exempt', async () => {
  const limit = Number(process.env.MINGLE_PUBLISH_PER_SOURCE ?? 10)
  const src = { 'X-Forwarded-For': '203.0.113.77' }
  for (let i = 0; i < limit; i++) {
    const r = await publish(makeCard(generateKeyPair(), { headline: `Source limit probe ${i}` }), src)
    assert.equal(r.status, 201, `publish ${i}: ${JSON.stringify(r.body)}`)
  }
  const over = await publish(makeCard(generateKeyPair(), { headline: 'Source limit probe over' }), src)
  assert.equal(over.status, 429, JSON.stringify(over.body))
  // A different source is unaffected.
  const otherSrc = await publish(makeCard(generateKeyPair(), { headline: 'Source limit other source' }), { 'X-Forwarded-For': '198.51.100.4' })
  assert.equal(otherSrc.status, 201, JSON.stringify(otherSrc.body))
  // Loopback with no forwarded header is the operator and never hits the source cap.
  const local = await publish(makeCard(generateKeyPair(), { headline: 'Source limit loopback' }))
  assert.equal(local.status, 201, JSON.stringify(local.body))
})
