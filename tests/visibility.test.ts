// Visibility: a field marked for anything narrower than 'network' never appears on
// an unauthenticated surface, a card that is no longer live shows its status only,
// and the full signed card is readable by its subject alone through owner-read.
// Synthetic keys and data only.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-visibility-test-'))
process.env.DB_PATH = join(tmpDir, 'visibility-test.db')

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


async function post(path: string, body: unknown): Promise<{ status: number; body: any; text: string }> {
  const res = await fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  const text = await res.text()
  let parsed: any = null
  try { parsed = JSON.parse(text) } catch { /* html or empty */ }
  return { status: res.status, body: parsed, text }
}
async function getText(path: string): Promise<{ status: number; text: string }> {
  const res = await fetch(`${base}${path}`)
  return { status: res.status, text: await res.text() }
}
const ownerRead = (keys: Keys, cardId: string, issuedAt = new Date().toISOString(), signedFor = cardId) =>
  post(`/api/v3/cards/${cardId}/owner-read`, { public_key: keys.publicKey, issued_at: issuedAt, signature: sign(`owner-read:${signedFor}:${issuedAt}`, keys.privateKey) })

const OFFER_MARK = 'OFFERMARK-7f3a91'
const SEEK_MARK = 'SEEKMARK-c40e2b'
const EVENT = 'visibility-probe-event'

function restrictedCard(keys: Keys, offset = 0): Record<string, any> {
  return makeCard(keys, {
    headline: 'Visibility probe card',
    seeking: [{ description: `Hidden seeking ${SEEK_MARK}`, topics: ['delegation'], engagement: 'part_time' }],
    offering: [{ description: `Hidden offering ${OFFER_MARK}`, topics: ['delegation'], provenance: 'principal_statement' }],
    event_ref: { event_id: EVENT },
    visibility: { headline: 'network', intents: 'network', event_ref: 'network', seeking: 'private', offering: 'intro_request' },
  }, offset)
}

test('restricted fields never appear on any unauthenticated surface', async () => {
  const keys = generateKeyPair()
  const p = await post('/api/v3/cards', { card: restrictedCard(keys) })
  assert.equal(p.status, 201, p.text)
  const id = p.body.card_id
  const surfaces: Array<[string, { status: number; text: string }]> = [
    ['GET /api/v3/cards/:id', await getText(`/api/v3/cards/${id}`)],
    ['POST /api/v3/cards/search intents', await post('/api/v3/cards/search', { intents: ['collaborate'], limit: 50 })],
    ['POST /api/v3/cards/search event_ref', await post('/api/v3/cards/search', { event_ref: EVENT })],
    ['GET /c/:id', await getText(`/c/${id}`)],
    ['GET /e/:event', await getText(`/e/${EVENT}`)],
    ['GET /api/v3/stats', await getText('/api/v3/stats')],
  ]
  for (const [name, r] of surfaces) {
    assert.ok(r.status < 500, `${name} returned ${r.status}`)
    assert.equal(r.text.includes(OFFER_MARK), false, `${name} leaked the intro_request field`)
    assert.equal(r.text.includes(SEEK_MARK), false, `${name} leaked the private field`)
  }
  // The card is still findable and shows its network-visible content.
  const g = JSON.parse(surfaces[0][1].text)
  assert.equal(g.projection, 'network_visible')
  assert.equal(g.card.headline, 'Visibility probe card')
  assert.equal(g.card.offering, undefined)
  assert.equal(g.card.seeking, undefined)
  assert.equal(g.card.signature, undefined)
  assert.equal(g.card.approval, undefined)
  assert.equal(g.card.subject_key, keys.publicKey)
  const search = JSON.parse(surfaces[1][1].text)
  assert.ok((search.results ?? []).some((c: any) => c.card_id === id), 'the card is still discoverable by its network-visible fields')
})

test('a card that is no longer live shows its status and none of its former content', async () => {
  const keys = generateKeyPair()
  const p = await post('/api/v3/cards', { card: makeCard(keys, { headline: 'Withdrawn content WDMARK-55aa' }) })
  assert.equal(p.status, 201, p.text)
  const w = await post(`/api/v3/cards/${p.body.card_id}/withdraw`, { public_key: keys.publicKey, signature: sign(`withdraw:${p.body.card_id}`, keys.privateKey) })
  assert.equal(w.status, 200, w.text)
  const g = await getText(`/api/v3/cards/${p.body.card_id}`)
  assert.equal(g.status, 200)
  assert.equal(g.text.includes('WDMARK-55aa'), false)
  const body = JSON.parse(g.text)
  assert.equal(body.revocation_status, 'withdrawn')
  assert.equal(body.projection, 'status_only')
  assert.equal((await getText(`/c/${p.body.card_id}`)).text.includes('WDMARK-55aa'), false)
})

test('owner-read returns the full signed card to its subject only, with a fresh signature', async () => {
  const keys = generateKeyPair()
  const p = await post('/api/v3/cards', { card: restrictedCard(keys, 1000) })
  assert.equal(p.status, 201, p.text)
  const id = p.body.card_id
  const ok = await ownerRead(keys, id)
  assert.equal(ok.status, 200, ok.text)
  assert.equal(ok.body.projection, 'owner_full')
  assert.ok(ok.text.includes(OFFER_MARK) && ok.text.includes(SEEK_MARK))
  assert.ok(ok.body.card.signature && ok.body.card.approval, 'the owner gets the envelope to verify')

  const stale = await ownerRead(keys, id, new Date(Date.now() - 10 * 60 * 1000).toISOString())
  assert.equal(stale.status, 401, stale.text)
  const future = await ownerRead(keys, id, new Date(Date.now() + 10 * 60 * 1000).toISOString())
  assert.equal(future.status, 401, future.text)
  const otherCard = await ownerRead(keys, id, new Date().toISOString(), 'v3-connection-some-other-card')
  assert.equal(otherCard.status, 403, otherCard.text)
  const stranger = generateKeyPair()
  const notOwner = await ownerRead(stranger, id)
  assert.equal(notOwner.status, 403, notOwner.text)
  // A stranger presenting the owner's public key with their own signature fails too.
  const iat = new Date().toISOString()
  const forged = await post(`/api/v3/cards/${id}/owner-read`, { public_key: keys.publicKey, issued_at: iat, signature: sign(`owner-read:${id}:${iat}`, stranger.privateKey) })
  assert.equal(forged.status, 403, forged.text)
  const missing = await post(`/api/v3/cards/${id}/owner-read`, { public_key: keys.publicKey })
  assert.equal(missing.status, 401, missing.text)
  for (const r of [stale, future, otherCard, notOwner, forged, missing]) {
    assert.equal(r.text.includes(OFFER_MARK), false)
  }
})

test('renew works from the owner-read card, and the public projection cannot stand in for it', async () => {
  const keys = generateKeyPair()
  const p = await post('/api/v3/cards', { card: restrictedCard(keys, 2000) })
  assert.equal(p.status, 201, p.text)
  const id = p.body.card_id

  // A client that reseals from the public projection loses the withheld fields, so
  // the server refuses it as changed content (this is what an old client hits).
  const pub = JSON.parse((await getText(`/api/v3/cards/${id}`)).text).card
  const fromPublic: Record<string, any> = { ...pub }
  delete fromPublic.card_id
  fromPublic.created_at = new Date(Date.now() + 3000).toISOString()
  fromPublic.expires_at = new Date(Date.now() + 3000 + 21 * 86400000).toISOString()
  fromPublic.revocation_status = 'active'
  const bad = await post(`/api/v3/cards/${id}/renew`, { card: seal(fromPublic, keys) })
  assert.ok(bad.status === 400, bad.text)

  const full = (await ownerRead(keys, id)).body.card
  const renewed: Record<string, any> = { ...full }
  renewed.created_at = new Date(Date.now() + 4000).toISOString()
  renewed.expires_at = new Date(Date.now() + 4000 + 21 * 86400000).toISOString()
  renewed.revocation_status = 'active'
  const good = await post(`/api/v3/cards/${id}/renew`, { card: seal(renewed, keys) })
  assert.equal(good.status, 201, good.text)
})
