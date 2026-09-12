// ══════════════════════════════════════════════════════════════
// The legacy v2 gate: MINGLE_V2_ENABLED
// ══════════════════════════════════════════════════════════════
// The legacy 48h IntentCard surface runs only when the flag is exactly "1".
// The flag is deliberately NOT set at module scope here, so this file's default
// is the production setting, which is off. Every case that needs it on sets it
// and puts the previous value back.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { createIntentCard, generateKeyPair } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-v2-gate-test-'))
process.env.DB_PATH = join(tmpDir, 'v2gate.db')

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')

let server: Server
let base: string

before(async () => {
  const app = createApp(); db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => { db.getDb().prepare('DELETE FROM rate_limits').run() })

const GATE_TEXT = 'This legacy Mingle interface is temporarily unavailable. Use the current Mingle tools.'

async function withV2(value: string | undefined, fn: () => Promise<void>): Promise<void> {
  const previous = process.env.MINGLE_V2_ENABLED
  if (value === undefined) delete process.env.MINGLE_V2_ENABLED
  else process.env.MINGLE_V2_ENABLED = value
  try {
    await fn()
  } finally {
    if (previous === undefined) delete process.env.MINGLE_V2_ENABLED
    else process.env.MINGLE_V2_ENABLED = previous
  }
}

async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; json: any }> {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let json: any = null
  try { json = await res.json() } catch { json = null }
  return { status: res.status, json }
}

function signedCard(agentId: string): { card: any; keys: any } {
  const keys = generateKeyPair()
  const card = createIntentCard({
    agentId, principalAlias: `${agentId} alias`,
    publicKey: keys.publicKey, privateKey: keys.privateKey,
    needs: [{ category: 'engineering', description: 'A backend engineer', priority: 'high', tags: ['rust'], visibility: 'public' }],
    offers: [{ category: 'funding', description: 'Seed investment', priority: 'medium', tags: ['seed'], visibility: 'public' }],
    openTo: ['introductions'], notOpenTo: [], ttlSeconds: 86400,
  })
  return { card, keys }
}

// The ten gated routes, each with a method and a realistic path.
const GATED: [string, string][] = [
  ['POST', '/api/cards'],
  ['GET', '/api/cards/some-agent'],
  ['DELETE', '/api/cards/some-card'],
  ['GET', '/api/matches/some-agent'],
  ['POST', '/api/matches/ghost'],
  ['POST', '/api/intros'],
  ['PUT', '/api/intros/some-intro'],
  ['GET', '/api/digest/some-agent'],
  ['POST', '/api/feedback/some-intro'],
  ['GET', '/api/trust/some-agent'],
]
const bodyFor = (method: string): unknown => (method === 'GET' || method === 'DELETE' ? undefined : {})

// The root index as it reads today, for the compatibility check with v2 on.
const TODAYS_ROOT = {
  name: 'AEOESS Intent Network API',
  version: '0.4.0',
  docs: 'https://aeoess.com/llms-full.txt',
  endpoints: {
    'POST /api/cards': 'Publish an IntentCard (signature verified)',
    'GET /api/cards/:agentId': "Get an agent's card",
    'DELETE /api/cards/:cardId': 'Remove a card (signature verified)',
    'GET /api/matches/:agentId': 'Get ranked matches',
    'POST /api/intros': 'Request an introduction (signature verified)',
    'PUT /api/intros/:introId': 'Respond to an intro (signature verified)',
    'GET /api/digest/:agentId': 'Personalized digest',
    'GET /api/stats': 'Network statistics',
  },
}

test('V2 GATE: the replay exploit is refused while v2 is off, and the card survives', async () => {
  const { card, keys } = signedCard('replay-victim')
  let stolen: any = null
  await withV2('1', async () => {
    const pub = await call('POST', '/api/cards', { ...card, publicKey: keys.publicKey })
    assert.equal(pub.status, 201, JSON.stringify(pub.json))
    const fetched = await call('GET', '/api/cards/replay-victim')
    assert.equal(fetched.status, 200)
    // The stored card comes back with its signature, which is what makes the
    // replay possible while v2 is on.
    assert.equal(fetched.json.card.signature, card.signature)
    stolen = fetched.json.card
  })
  await withV2(undefined, async () => {
    const del = await call('DELETE', `/api/cards/${stolen.cardId}`, stolen)
    assert.equal(del.status, 503, JSON.stringify(del.json))
    assert.deepEqual(del.json, { error: GATE_TEXT, code: 'v2_disabled' })
  })
  assert.notEqual(db.getCard('replay-victim'), null, 'the victim card is still in the database')
})

// SECURITY DEBT, documented on purpose and deliberately not part of the green
// contract. With v2 explicitly re-enabled this body succeeds, because
// requireSignature verifies the card against the key inside that same card, so
// a fetched card is a valid DELETE body for anyone. It is skipped so it neither
// codifies the defect as expected behavior nor breaks when requireSignature is
// repaired.
test.skip('SECURITY-DEBT: v2 replay succeeds when explicitly re-enabled', async () => {
  const { card, keys } = signedCard('replay-debt')
  await withV2('1', async () => {
    assert.equal((await call('POST', '/api/cards', { ...card, publicKey: keys.publicKey })).status, 201)
    const fetched = await call('GET', '/api/cards/replay-debt')
    const stolen = fetched.json.card
    // No key of the attacker's is involved anywhere. The victim's own card is
    // the whole proof of authorization.
    const del = await call('DELETE', `/api/cards/${stolen.cardId}`, stolen)
    assert.equal(del.status, 200, 'the replayed victim signature authorizes the delete')
    assert.equal(db.getCard('replay-debt'), null, 'the victim card is gone')
  })
})

test('V2 GATE: with the flag unset, each of the ten legacy routes answers 503 v2_disabled', async () => {
  await withV2(undefined, async () => {
    for (const [method, path] of GATED) {
      const r = await call(method, path, bodyFor(method))
      assert.equal(r.status, 503, `${method} ${path}`)
      assert.deepEqual(r.json, { error: GATE_TEXT, code: 'v2_disabled' }, `${method} ${path}`)
    }
  })
})

test('V2 GATE: feedback is refused with the flag unset even with the identify headers set', async () => {
  await withV2(undefined, async () => {
    const r = await call('POST', '/api/feedback/some-intro', { rating: 'useful' }, { 'X-Agent-Id': 'someone', 'X-Public-Key': 'some-key' })
    assert.equal(r.status, 503)
    assert.deepEqual(r.json, { error: GATE_TEXT, code: 'v2_disabled' })
  })
})

test('V2 GATE: resolve, challenge, stats, health and v3 all work with the flag unset', async () => {
  await withV2(undefined, async () => {
    assert.equal((await call('GET', '/api/resolve?did=did:aps:nobody')).status, 404, 'resolve is open and answers its own 404')
    assert.equal((await call('POST', '/api/challenge/create', {})).status, 400, 'challenge/create validates its body rather than being gated')
    assert.equal((await call('GET', '/api/stats')).status, 200, 'stats')
    assert.equal((await call('GET', '/health')).status, 200, 'health')
    assert.equal((await call('POST', '/api/v3/cards/search', { card_type: 'connection' })).status, 200, 'a v3 route')
  })
})

test('V2 GATE: only the exact value "1" turns legacy v2 on', async () => {
  for (const value of ['true', 'yes', '0', '']) {
    await withV2(value, async () => {
      const r = await call('GET', '/api/cards/some-agent')
      assert.equal(r.status, 503, `flag ${JSON.stringify(value)}`)
      assert.equal(r.json.code, 'v2_disabled')
    })
  }
})

test('V2 GATE: a refusal consumes no rate-limit quota and runs no verification', async () => {
  await withV2(undefined, async () => {
    for (const [method, path] of GATED) await call(method, path, bodyFor(method))
    // beforeEach truncates rate_limits, so every row here would be a refusal's.
    const n = (db.getDb().prepare('SELECT COUNT(*) AS n FROM rate_limits').get() as any).n
    assert.equal(n, 0, 'a refusal writes no rate-limit row')
  })
})

test('V2 GATE: the root index hides legacy v2 when off and is byte-identical when on', async () => {
  await withV2(undefined, async () => {
    const r = await call('GET', '/')
    assert.equal(r.status, 200)
    assert.deepEqual(r.json.legacy_v2, { available: false })
    assert.deepEqual(r.json.endpoints, { 'GET /api/stats': 'Network statistics' }, 'no legacy path is advertised')
  })
  await withV2('1', async () => {
    const res = await fetch(`${base}/`)
    assert.equal(res.status, 200)
    // Byte equality, not only deep equality, so a reordered key is a red test.
    assert.equal(await res.text(), JSON.stringify(TODAYS_ROOT), 'the root response is unchanged when v2 is on')
  })
})
