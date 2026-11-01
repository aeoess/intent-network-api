// Lifecycle races: a takedown that commits first always wins over a renew or
// replace, one card has at most one successor, verbs on a superseded card name
// the successor, and one key cannot hold two live copies of the same content.
// Synthetic keys and data only.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-race-test-'))
process.env.DB_PATH = join(tmpDir, 'race-test.db')

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



async function post(path: string, body: unknown): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}/api/v3${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}
const publish = (card: Record<string, any>) => post('/cards', { card })
const renew = (id: string, card: Record<string, any>) => post(`/cards/${id}/renew`, { card })
const replace = (id: string, card: Record<string, any>) => post(`/cards/${id}/replace`, { card })
const verb = (keys: Keys, id: string, name: string) => post(`/cards/${id}/${name}`, { public_key: keys.publicKey, signature: sign(`${name}:${id}`, keys.privateKey) })
const status = (id: string) => v3db.getV3Card(id)?.revocation_status
const liveFor = (keys: Keys) => v3db.activeCardIdsForSubject(keys.publicKey)
const TRIALS = 8

test('withdraw racing renew: exactly one wins, and a committed withdrawal never leaves a live successor', async () => {
  const outcomes = { withdraw_won: 0, renew_won: 0 }
  for (let i = 0; i < TRIALS; i++) {
    const keys = generateKeyPair()
    const p = await publish(makeCard(keys, { headline: `Race renew ${i}` }))
    assert.equal(p.status, 201, JSON.stringify(p.body))
    const id = p.body.card_id
    const [r, w] = await Promise.all([renew(id, makeCard(keys, { headline: `Race renew ${i}` }, 1000)), verb(keys, id, 'withdraw')])
    if (w.status === 200) {
      outcomes.withdraw_won++
      assert.equal(r.status, 409, `trial ${i}: renew must fail once withdraw committed: ${JSON.stringify(r.body)}`)
      assert.equal(status(id), 'withdrawn')
      assert.equal(v3db.getSupersededBy(id), null)
      assert.deepEqual(liveFor(keys), [])
    } else {
      outcomes.renew_won++
      assert.equal(r.status, 201, JSON.stringify(r.body))
      assert.equal(w.status, 409, JSON.stringify(w.body))
      assert.equal(w.body.superseded_by, r.body.new_card_id, 'the refused withdraw names the live successor')
      assert.equal(status(id), 'superseded')
      assert.deepEqual(liveFor(keys), [r.body.new_card_id])
    }
  }
  assert.equal(outcomes.withdraw_won + outcomes.renew_won, TRIALS)
})

test('withdraw racing replace: exactly one wins, and a committed withdrawal never leaves a live successor', async () => {
  for (let i = 0; i < TRIALS; i++) {
    const keys = generateKeyPair()
    const p = await publish(makeCard(keys, { headline: `Race replace ${i}` }))
    const id = p.body.card_id
    const [r, w] = await Promise.all([replace(id, makeCard(keys, { headline: `Race replace new ${i}` }, 1000)), verb(keys, id, 'withdraw')])
    if (w.status === 200) {
      assert.equal(r.status, 409, `trial ${i}: ${JSON.stringify(r.body)}`)
      assert.equal(status(id), 'withdrawn')
      assert.deepEqual(liveFor(keys), [])
    } else {
      assert.equal(r.status, 201, JSON.stringify(r.body))
      assert.equal(w.status, 409, JSON.stringify(w.body))
      assert.equal(w.body.superseded_by, r.body.new_card_id)
      assert.deepEqual(liveFor(keys), [r.body.new_card_id])
    }
  }
})

test('withdraw committed first: renew and replace store nothing', async () => {
  const keys = generateKeyPair()
  const p = await publish(makeCard(keys, { headline: 'Withdraw first' }))
  assert.equal((await verb(keys, p.body.card_id, 'withdraw')).status, 200)
  const renewCard = makeCard(keys, { headline: 'Withdraw first' }, 1000)
  const r = await renew(p.body.card_id, renewCard)
  assert.equal(r.status, 409, JSON.stringify(r.body))
  const rep = await replace(p.body.card_id, makeCard(keys, { headline: 'Withdraw first new' }, 2000))
  assert.equal(rep.status, 409, JSON.stringify(rep.body))
  assert.equal(v3db.cardHashStanding(keys.publicKey, renewCard.approval.card_hash).kind, 'none', 'no row was stored')
  assert.deepEqual(liveFor(keys), [])
  assert.equal(status(p.body.card_id), 'withdrawn')
})

test('two concurrent renewals of one card leave one successor', async () => {
  for (let i = 0; i < TRIALS; i++) {
    const keys = generateKeyPair()
    const p = await publish(makeCard(keys, { headline: `Double renew ${i}` }))
    const id = p.body.card_id
    const [a, b] = await Promise.all([
      renew(id, makeCard(keys, { headline: `Double renew ${i}` }, 1000)),
      renew(id, makeCard(keys, { headline: `Double renew ${i}` }, 2000)),
    ])
    assert.deepEqual([a.status, b.status].sort(), [201, 409], `trial ${i}: ${JSON.stringify([a.body, b.body])}`)
    const winner = a.status === 201 ? a.body.new_card_id : b.body.new_card_id
    assert.equal(v3db.getSupersededBy(id), winner)
    assert.deepEqual(liveFor(keys), [winner])
  }
})

test('two concurrent replacements with different content leave one successor', async () => {
  for (let i = 0; i < TRIALS; i++) {
    const keys = generateKeyPair()
    const p = await publish(makeCard(keys, { headline: `Double replace ${i}` }))
    const id = p.body.card_id
    const [a, b] = await Promise.all([
      replace(id, makeCard(keys, { headline: `Double replace A ${i}` }, 1000)),
      replace(id, makeCard(keys, { headline: `Double replace B ${i}` }, 2000)),
    ])
    assert.deepEqual([a.status, b.status].sort(), [201, 409], `trial ${i}: ${JSON.stringify([a.body, b.body])}`)
    const winner = a.status === 201 ? a.body.new_card_id : b.body.new_card_id
    assert.deepEqual(liveFor(keys), [winner])
  }
})

test('a renew racing a replace of the same card leaves one successor', async () => {
  const keys = generateKeyPair()
  const p = await publish(makeCard(keys, { headline: 'Renew vs replace' }))
  const [a, b] = await Promise.all([
    renew(p.body.card_id, makeCard(keys, { headline: 'Renew vs replace' }, 1000)),
    replace(p.body.card_id, makeCard(keys, { headline: 'Renew vs replace other' }, 2000)),
  ])
  assert.deepEqual([a.status, b.status].sort(), [201, 409], JSON.stringify([a.body, b.body]))
  assert.equal(liveFor(keys).length, 1)
})

test('the conditional supersede refuses a card that is no longer active', () => {
  const keys = generateKeyPair()
  const card = makeCard(keys, { headline: 'Conditional supersede unit' }) as any
  v3db.insertV3Card('v3-connection-cond-1', card, card.approval.card_hash)
  v3db.setRevocationStatus('v3-connection-cond-1', keys.publicKey, 'withdrawn')
  assert.equal(v3db.supersedeIfActive('v3-connection-cond-1', keys.publicKey), false)
  assert.equal(status('v3-connection-cond-1'), 'withdrawn', 'a withdrawal is never overwritten')
  const other = makeCard(keys, { headline: 'Conditional supersede unit two' }, 1000) as any
  v3db.insertV3Card('v3-connection-cond-2', other, other.approval.card_hash)
  assert.equal(v3db.supersedeIfActive('v3-connection-cond-2', generateKeyPair().publicKey), false, 'another key cannot supersede it')
  assert.equal(v3db.supersedeIfActive('v3-connection-cond-2', keys.publicKey), true)
})

test('one key cannot hold two live copies of the same content', async () => {
  // Production shape from 05:38 UTC: five cards, same words, each signed with new timestamps.
  const keys = generateKeyPair()
  const results = []
  for (let i = 0; i < 5; i++) results.push(await publish(makeCard(keys, { headline: 'Same words flood probe' }, i * 500)))
  assert.deepEqual(results.map(r => r.status), [201, 409, 409, 409, 409], JSON.stringify(results.map(r => r.body)))
  assert.equal(results[1].body.card_id, results[0].body.card_id, 'the refusal names the live card to renew')
  assert.deepEqual(liveFor(keys), [results[0].body.card_id])
  // Different words from the same key are still fine, and so are the same words from another key.
  assert.equal((await publish(makeCard(keys, { headline: 'Same words flood probe, different card' }, 9000))).status, 201)
  assert.equal((await publish(makeCard(generateKeyPair(), { headline: 'Same words flood probe' }))).status, 201)
  // After withdrawal the owner can publish those words again as a new card.
  assert.equal((await verb(keys, results[0].body.card_id, 'withdraw')).status, 200)
  assert.equal((await publish(makeCard(keys, { headline: 'Same words flood probe' }, 12000))).status, 201)
})
