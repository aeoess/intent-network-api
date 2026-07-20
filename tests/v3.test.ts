// ══════════════════════════════════════════════════════════════
// Mingle v3 tests - schema, lint, hash binding, visibility, verbs
// ══════════════════════════════════════════════════════════════
// Same bootstrap as api.test.ts: in-process app, throwaway DB, real
// Ed25519 signatures. Embedding model intentionally cold; explicit-field
// search paths are exercised, the semantic query path is covered by its
// unavailable-model error contract.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-v3-test-'))
process.env.DB_PATH = join(tmpDir, 'v3-test.db')

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { validateV3Card, cardContentHash, findBannedContent } = await import('../src/v3-cards.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(resolve => { server = app.listen(0, '127.0.0.1', () => resolve()) })
  const addr = server.address() as { port: number }
  base = `http://127.0.0.1:${addr.port}`
})

after(() => {
  server?.close()
  db.closeDb()
  rmSync(tmpDir, { recursive: true, force: true })
})

// ── Fixtures ──
// Each card gets a fresh keypair so per-subject_key rate limits never cross
// tests. The keypair rides on the returned object for verb signing.

type Keyed = Record<string, any> & { __keys: { publicKey: string; privateKey: string } }

function makeCard(overrides: Record<string, unknown> = {}, opts: { expiresInMs?: number } = {}): Keyed {
  const keys = generateKeyPair()
  const now = Date.now()
  const card: Record<string, any> = {
    card_type: 'connection',
    subject_key: keys.publicKey,
    version: 1,
    created_at: new Date(now).toISOString(),
    expires_at: new Date(now + (opts.expiresInMs ?? 21 * 24 * 3600 * 1000)).toISOString(),
    headline: 'Protocol engineer seeking collaborators on agent identity',
    intents: ['collaborate', 'team_up'],
    seeking: [{ description: 'Collaborators on open agent-identity protocols', topics: ['agent identity', 'delegation'], engagement: 'part_time' }],
    offering: [{ description: 'I build TypeScript SDKs, shipped a delegation chain verifier', topics: ['typescript'], provenance: 'principal_statement' }],
    preferences: [{ key: 'communication', value: 'written context first' }, { key: 'location', value: 'remote, EU timezones' }],
    artifacts: [{
      claim: 'Author of the agent-passport-system npm package',
      source: 'artifact_link',
      method: 'link provided by principal, existence checkable',
      verified_fact: 'a package by this name exists at the given link',
      date: new Date(now).toISOString(),
    }],
    event_ref: null,
    team_size_sought: null,
    visibility: { headline: 'network', seeking: 'network', offering: 'network', preferences: 'intro_request', artifacts: 'network' },
    composition: { agent_assisted: true, skill_version: 'mingle-composer-v1' },
    delegation_ref: null,
    revocation_status: 'active',
    ...overrides,
  }
  const card_hash = cardContentHash(card)
  card.approval = {
    card_hash,
    approved_at: new Date(now).toISOString(),
    principal_signature: sign(card_hash, keys.privateKey),
  }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  card.__keys = keys
  return card as Keyed
}

async function publish(card: Keyed): Promise<{ status: number; body: any }> {
  const { __keys, ...wire } = card
  const res = await fetch(`${base}/api/v3/cards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ card: wire }),
  })
  return { status: res.status, body: await res.json() }
}

function signedVerbBody(card: Keyed, verb: string, cardId: string): string {
  return JSON.stringify({ public_key: card.__keys.publicKey, signature: sign(`${verb}:${cardId}`, card.__keys.privateKey) })
}

// ── Schema round-trip, both card types ──

test('connection card round-trips through validation', () => {
  const { __keys, ...card } = makeCard()
  const v = validateV3Card(card)
  assert.equal(v.valid, true, (v as any).error)
})

test('opportunity card with event fields round-trips and publishes', async () => {
  const card = makeCard({
    card_type: 'opportunity',
    headline: 'Hackathon team forming: agent-identity tooling',
    intents: ['team_up'],
    event_ref: { event_id: 'hackathon-vienna-2026', dates: '2026-09-12/2026-09-14' },
    team_size_sought: 4,
  })
  const { __keys, ...bare } = card
  const v = validateV3Card(bare)
  assert.equal(v.valid, true, (v as any).error)
  const { status, body } = await publish(card)
  assert.equal(status, 201, JSON.stringify(body))
  // event_ref is searchable as an explicit field
  const res = await fetch(`${base}/api/v3/cards/search`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ event_ref: 'hackathon-vienna-2026' }),
  })
  const found = await res.json()
  assert.ok((found.results as any[]).some(r => r.card_id === body.card_id))
})

// ── Banned-key rejection (invariants 1 and 2 at the type layer) ──

test('banned keys are rejected wherever they appear', () => {
  const cases: Record<string, unknown>[] = [
    { fitVector: [0.2, 0.9] },
    { assessment: 'strong candidate' },
    { hostile_notes: 'avoid' },
    { trust_tier: 2 },
    { extra: { nested: { score: 0.7 } } },
    { seeking: [{ description: 'x', rank: 1 }] },
    { preferences: [{ key: 'confidence', value: 'high' }] },
  ]
  for (const extra of cases) {
    const card = makeCard(extra as Record<string, unknown>)
    const v = validateV3Card(card)
    assert.equal(v.valid, false, `expected rejection for ${JSON.stringify(extra).slice(0, 60)}`)
    assert.match((v as any).error, /prohibited field content/)
  }
})

test('banned tokens as exact string values are rejected, prose is not', () => {
  assert.notEqual(findBannedContent({ kind: 'trust_tier' }), null)
  assert.notEqual(findBannedContent({ list: ['fit_vector'] }), null)
  assert.equal(findBannedContent({ text: 'we keep musical scores and ranked lists out of scope' }), null)
})

test('publish rejects a banned-key card at the API layer', async () => {
  const card = makeCard({ assessment: 'smuggled' })
  const { status, body } = await publish(card)
  assert.equal(status, 400)
  assert.match(body.error, /prohibited field content/)
})

// ── Hash approval binding (invariant 4) ──

test('publish rejects when approval.card_hash does not match content', async () => {
  const card = makeCard()
  card.headline = 'Edited after approval'
  // re-sign the card so ONLY the hash binding is stale
  const { signature, __keys, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), card.__keys.privateKey)
  const { status, body } = await publish(card)
  assert.equal(status, 403)
  assert.match(body.error, /card_hash does not match/)
})

test('publish rejects a bad approval signature', async () => {
  const card = makeCard()
  const other = generateKeyPair()
  card.approval.principal_signature = sign(card.approval.card_hash, other.privateKey)
  const { signature, __keys, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), card.__keys.privateKey)
  const { status, body } = await publish(card)
  assert.equal(status, 403)
  assert.match(body.error, /principal_signature/)
})

test('publish rejects a bad card signature', async () => {
  const card = makeCard()
  const other = generateKeyPair()
  const { signature, __keys, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), other.privateKey)
  const { status, body } = await publish(card)
  assert.equal(status, 403)
  assert.match(body.error, /card signature/)
})

test('a fully valid card publishes and fetch shows status', async () => {
  const { status, body } = await publish(makeCard())
  assert.equal(status, 201)
  assert.equal(body.published, true)
  const res = await fetch(`${base}/api/v3/cards/${body.card_id}`)
  const fetched = await res.json()
  assert.equal(fetched.revocation_status, 'active')
  assert.equal(fetched.card.headline.includes('Protocol engineer'), true)
})

// ── Visibility filtering ──

test('a private field never appears in search results', async () => {
  const card = makeCard({
    headline: 'Visibility probe card',
    visibility: { headline: 'network', seeking: 'network', offering: 'private', preferences: 'private', artifacts: 'intro_request' },
  })
  const pub = await publish(card)
  assert.equal(pub.status, 201)
  const res = await fetch(`${base}/api/v3/cards/search`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ card_type: 'connection', intents: ['collaborate'] }),
  })
  const body = await res.json()
  const probe = (body.results as any[]).find(r => r.headline === 'Visibility probe card')
  assert.ok(probe, 'probe card should appear in search')
  assert.equal(probe.offering, undefined, 'private offering must not appear')
  assert.equal(probe.preferences, undefined, 'private preferences must not appear')
  assert.equal(probe.artifacts, undefined, 'intro_request artifacts must not appear in network search')
  assert.ok(probe.seeking, 'network-visible seeking should appear')
})

// ── Expiry sweep including index removal ──

test('expired cards are swept and leave search', async () => {
  const card = makeCard({ headline: 'Short-lived sweep probe' }, { expiresInMs: 50 })
  const pub = await publish(card)
  assert.equal(pub.status, 201)
  await new Promise(r => setTimeout(r, 80))
  const sweep = await fetch(`${base}/api/v3/sweep`, { method: 'POST' }).then(r => r.json())
  assert.ok(sweep.swept >= 1, `expected at least one swept card, got ${sweep.swept}`)
  const res = await fetch(`${base}/api/v3/cards/search`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ card_type: 'connection' }),
  })
  const body = await res.json()
  assert.equal((body.results as any[]).some(r => r.headline === 'Short-lived sweep probe'), false)
  // status still shown on direct fetch after sweep
  const fetched = await fetch(`${base}/api/v3/cards/${pub.body.card_id}`).then(r => r.json())
  assert.equal(fetched.revocation_status, 'withdrawn')
})

// ── Revocation verbs (invariant 7) ──

test('every revocation verb transitions status correctly', async () => {
  const verbs: [string, string][] = [
    ['withdraw', 'withdrawn'],
    ['supersede', 'superseded'],
    ['revoke-authority', 'authority_revoked'],
    ['stop-new-matches', 'stopped_new_matches'],
  ]
  for (const [verb, expected] of verbs) {
    const card = makeCard({ headline: `Verb probe ${verb}` })
    const pub = await publish(card)
    assert.equal(pub.status, 201, JSON.stringify(pub.body))
    const res = await fetch(`${base}/api/v3/cards/${pub.body.card_id}/${verb}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: signedVerbBody(card, verb, pub.body.card_id),
    })
    const body = await res.json()
    assert.equal(res.status, 200, JSON.stringify(body))
    assert.equal(body.revocation_status, expected)
    const fetched = await fetch(`${base}/api/v3/cards/${pub.body.card_id}`).then(r => r.json())
    assert.equal(fetched.revocation_status, expected)
  }
})

test('delete-server-copy blanks content but keeps status visible', async () => {
  const card = makeCard({ headline: 'Delete probe' })
  const pub = await publish(card)
  const res = await fetch(`${base}/api/v3/cards/${pub.body.card_id}/delete-server-copy`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: signedVerbBody(card, 'delete-server-copy', pub.body.card_id),
  })
  assert.equal(res.status, 200)
  const fetched = await fetch(`${base}/api/v3/cards/${pub.body.card_id}`).then(r => r.json())
  assert.equal(fetched.revocation_status, 'deleted')
  assert.equal(fetched.card.headline ?? '[deleted]', '[deleted]')
})

test('a verb signed by a different key is refused', async () => {
  const pub = await publish(makeCard({ headline: 'Foreign key probe' }))
  const other = generateKeyPair()
  const res = await fetch(`${base}/api/v3/cards/${pub.body.card_id}/withdraw`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: other.publicKey, signature: sign(`withdraw:${pub.body.card_id}`, other.privateKey) }),
  })
  assert.equal(res.status, 403)
})

// ── No bulk endpoints (invariant 8) ──

test('the v3 router exposes no bulk-export or category-download route', async () => {
  const v3Routes = (await import('../src/v3-routes.js')).default as any
  const paths: string[] = []
  for (const layer of v3Routes.stack) {
    if (layer.route?.path) paths.push(layer.route.path)
  }
  assert.ok(paths.length >= 8, `router should expose its known routes, saw ${paths.length}`)
  for (const p of paths) {
    assert.doesNotMatch(p, /export|bulk|category|download|dump|all-cards/i, `route ${p} looks like a bulk endpoint`)
  }
  // And the search cap holds: ask for 10000, never receive more than 50.
  const res = await fetch(`${base}/api/v3/cards/search`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ limit: 10000 }),
  })
  const body = await res.json()
  assert.ok(body.count <= 50, `search must cap results, got ${body.count}`)
})
