// ══════════════════════════════════════════════════════════════
// Mingle v4 private fit - Stage 1: Fit Policy (schema, storage, approval)
// ══════════════════════════════════════════════════════════════
// Values are typed and private; the schema is public. A policy is approved as a
// whole set by its content hash, is versioned/supersedable, and never lets the
// work intent carry a dimension.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-v4-test-'))
process.env.DB_PATH = join(tmpDir, 'v4.db')
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const { policyHash } = await import('../src/fit-policy-db.js')

let server: Server
let base: string

before(async () => {
  const app = createApp(); db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => { db.getDb().prepare('DELETE FROM rate_limits').run() })

function makeCard(headline: string, intents: string[]): { keys: any; card: any } {
  const keys = generateKeyPair()
  const now = Date.now()
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(now).toISOString(), expires_at: new Date(now + 21 * 864e5).toISOString(),
    headline, intents, seeking: [], offering: [{ description: 'x', provenance: 'principal_statement' }],
    preferences: [], artifacts: [], event_ref: null, team_size_sought: null,
    visibility: {}, composition: { agent_assisted: true, skill_version: 'v1' },
    delegation_ref: null, revocation_status: 'active',
  }
  const h = cardContentHash(card)
  card.approval = { card_hash: h, approved_at: new Date(now).toISOString(), principal_signature: sign(h, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return { keys, card }
}
async function publish(built: { card: any }): Promise<string> {
  const r = await (await fetch(`${base}/api/v3/cards`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card: built.card }) })).json()
  return r.card_id
}
const future = () => new Date(Date.now() + 30 * 864e5).toISOString()

function dim(dimension: string, value: any, disclosure_state = 'testable', importance = 'useful', allowed_intents = ['cofound']): any {
  return { dimension, value, sensitivity: 'low', disclosure_state, allowed_intents, expires_at: future(), importance }
}

async function setPolicy(who: any, cardId: string, dimensions: any[]): Promise<{ status: number; body: any }> {
  const approved_hash = policyHash(dimensions)
  const nonce = 'p' + Math.random().toString(16).slice(2)
  const body = { card_id: cardId, dimensions, approved_hash, public_key: who.keys.publicKey, nonce, signature: sign(`set-fit-policy:${cardId}:${approved_hash}:${nonce}`, who.keys.privateKey) }
  const res = await fetch(`${base}/api/v4/fit/policy`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}
async function getPolicy(who: any, cardId: string): Promise<any> {
  const nonce = 'g' + Math.random().toString(16).slice(2)
  const qs = new URLSearchParams({ card_id: cardId, public_key: who.keys.publicKey, nonce, signature: sign(`get-fit-policy:${cardId}:${nonce}`, who.keys.privateKey) })
  return (await fetch(`${base}/api/v4/fit/policy?${qs}`)).json()
}

test('a valid policy is stored, versioned, and readable by the owner', async () => {
  const alice = makeCard('Alice', ['cofound', 'collaborate'])
  const cardId = await publish(alice)
  const dims = [
    dim('weekly_commitment', { min: 20, max: 40 }),
    dim('cadence', 'mixed', 'reveal_overlap'),
    dim('role_spike', ['product', 'fundraising'], 'reveal_bucket'),
  ]
  const r = await setPolicy(alice, cardId, dims)
  assert.equal(r.status, 201, JSON.stringify(r.body))
  assert.equal(r.body.version, 1)
  assert.match(r.body.policy_hash, /^[0-9a-f]{64}$/)

  const got = await getPolicy(alice, cardId)
  assert.equal(got.version, 1)
  assert.equal(got.dimensions.length, 3)

  // Supersede: a second set bumps the version.
  const r2 = await setPolicy(alice, cardId, [dim('weekly_commitment', { min: 10, max: 20 })])
  assert.equal(r2.body.version, 2)
})

test('the work intent may never carry a dimension', async () => {
  const alice = makeCard('Alice', ['cofound', 'work'])
  const cardId = await publish(alice)
  const r = await setPolicy(alice, cardId, [dim('weekly_commitment', { min: 10, max: 20 }, 'testable', 'useful', ['cofound', 'work'])])
  assert.equal(r.status, 400)
  assert.match(r.body.error, /work is excluded/i)
})

test('an approval hash that does not match the dimensions is rejected', async () => {
  const alice = makeCard('Alice', ['cofound'])
  const cardId = await publish(alice)
  const dims = [dim('cadence', 'mixed')]
  const nonce = 'x'
  const wrongHash = createHash('sha256').update('nope').digest('hex')
  const body = { card_id: cardId, dimensions: dims, approved_hash: wrongHash, public_key: alice.keys.publicKey, nonce, signature: sign(`set-fit-policy:${cardId}:${wrongHash}:${nonce}`, alice.keys.privateKey) }
  const res = await fetch(`${base}/api/v4/fit/policy`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  assert.equal(res.status, 400)
})

test('unknown dimensions and bad enum values are rejected', async () => {
  const alice = makeCard('Alice', ['cofound'])
  const cardId = await publish(alice)
  assert.equal((await setPolicy(alice, cardId, [dim('made_up', 'x')])).status, 400)
  assert.equal((await setPolicy(alice, cardId, [dim('cadence', 'not_a_cadence')])).status, 400)
  assert.equal((await setPolicy(alice, cardId, [dim('role_spike', ['not_a_tag'])])).status, 400)
})

test('only the card owner can set or read a policy', async () => {
  const alice = makeCard('Alice', ['cofound']); const bob = makeCard('Bob', ['cofound'])
  const cardId = await publish(alice); await publish(bob)
  const r = await setPolicy(bob, cardId, [dim('cadence', 'mixed')])
  assert.equal(r.status, 403)
  const got = await getPolicy(bob, cardId)
  assert.equal(got.error ?? 'blocked', got.error)  // 403 body has error
})
