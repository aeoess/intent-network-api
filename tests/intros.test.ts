// ══════════════════════════════════════════════════════════════
// Mingle v3 introductions - the consent loop, with a mock email transport
// ══════════════════════════════════════════════════════════════
// Real Ed25519-signed v3 cards published through /api/v3/cards, then the intro
// loop exercised end to end. The contact-never-until-complete property is the
// one that matters most, so it is checked at every stage.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-intros-test-'))
process.env.DB_PATH = join(tmpDir, 'intros.db')
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const email = await import('../src/notifications.js')
const notifyDb = await import('../src/notify-db.js')

let server: Server
let base: string
const sent: { to: string; subject: string; text: string }[] = []

before(async () => {
  const app = createApp(); db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { email.resetTransport(); server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => {
  sent.length = 0
  email.setTransport(async e => { sent.push(e); return { ok: true, id: 'mock' } })
  // The intro routes rate-limit by client IP; every test shares 127.0.0.1, so
  // clear the shared counter between tests (test-only, no production change).
  db.getDb().prepare('DELETE FROM rate_limits').run()
})

// ── Fixtures ──

function makeCard(headline: string, visibility: Record<string, string> = {}): any {
  const keys = generateKeyPair()
  const now = Date.now()
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(now).toISOString(), expires_at: new Date(now + 21 * 864e5).toISOString(),
    headline, intents: ['collaborate'],
    seeking: [{ description: 'x' }], offering: [{ description: 'y', provenance: 'principal_statement' }],
    preferences: [], artifacts: [], event_ref: null, team_size_sought: null,
    visibility, composition: { agent_assisted: true, skill_version: 'v1' },
    delegation_ref: null, revocation_status: 'active',
  }
  const h = cardContentHash(card)
  card.approval = { card_hash: h, approved_at: new Date(now).toISOString(), principal_signature: sign(h, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return { keys, card }
}

async function publish(built: any): Promise<string> {
  const r = await (await fetch(`${base}/api/v3/cards`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card: built.card }) })).json()
  return r.card_id
}

async function subscribeVerified(keys: any, addr: string): Promise<void> {
  const nonce = 's' + Math.random().toString(36).slice(2)
  await fetch(`${base}/api/v3/notifications/subscribe`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subject_key: keys.publicKey, email: addr, nonce, signature: sign(`${addr}:${nonce}`, keys.privateKey) }) })
  await fetch(`${base}/api/v3/notifications/confirm/${notifyDb.getSubscription(keys.publicKey)!.verify_token}`)
}

function reqBody(from: any, fromCard: string, toCard: string, purpose: string, note: string): any {
  const nonce = 'r' + Math.random().toString(36).slice(2)
  return { from_card: fromCard, to_card: toCard, purpose, note, public_key: from.keys.publicKey, nonce, signature: sign(`intro-request:${fromCard}:${toCard}:${purpose}:${nonce}`, from.keys.privateKey) }
}
async function request(from: any, fromCard: string, toCard: string, purpose = 'collaborate', note = ''): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}/api/v3/intros/request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(reqBody(from, fromCard, toCard, purpose, note)) })
  return { status: res.status, body: await res.json() }
}
function respondBody(who: any, id: string, action: string, contact?: string): any {
  const nonce = 'p' + Math.random().toString(36).slice(2)
  const b: any = { action, public_key: who.keys.publicKey, nonce, signature: sign(`intro-respond:${id}:${action}:${nonce}`, who.keys.privateKey) }
  if (contact !== undefined) b.contact = contact
  return b
}
async function respond(who: any, id: string, action: string, contact?: string): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}/api/v3/intros/${id}/respond`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(respondBody(who, id, action, contact)) })
  return { status: res.status, body: await res.json() }
}
async function complete(who: any, id: string, contact: string): Promise<{ status: number; body: any }> {
  const nonce = 'c' + Math.random().toString(36).slice(2)
  const b = { contact, public_key: who.keys.publicKey, nonce, signature: sign(`intro-complete:${id}:${nonce}`, who.keys.privateKey) }
  const res = await fetch(`${base}/api/v3/intros/${id}/complete`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
  return { status: res.status, body: await res.json() }
}
async function mine(who: any): Promise<any> {
  const nonce = 'm' + Math.random().toString(36).slice(2)
  const qs = new URLSearchParams({ public_key: who.keys.publicKey, nonce, signature: sign(`intro-mine:${nonce}`, who.keys.privateKey) })
  return (await fetch(`${base}/api/v3/intros/mine?${qs}`)).json()
}

// ── The full happy loop ──

test('the full loop: request, accept, complete, contacts released only at the end', async () => {
  const alice = makeCard('Alice the engineer'); const bob = makeCard('Bob the founder')
  const aCard = await publish(alice); const bCard = await publish(bob)
  await subscribeVerified(alice.keys, 'alice@example.com'); await subscribeVerified(bob.keys, 'bob@example.com')
  sent.length = 0

  // request
  const r = await request(alice, aCard, bCard, 'collaborate', 'love your protocol work')
  assert.equal(r.status, 201, JSON.stringify(r.body))
  const id = r.body.id
  assert.equal(sent.length, 1)
  assert.equal(sent[0].to, 'bob@example.com')
  assert.match(sent[0].subject, /wants to connect/i)
  assert.match(sent[0].text, /show my Mingle intros/)                 // fixed CTA
  assert.match(sent[0].text, /Replies to this address are not monitored/) // footer line

  // before acceptance, neither side sees a contact
  let am = await mine(alice); let bm = await mine(bob)
  assert.equal(am.intros[0].counterparty_contact, null)
  assert.equal(bm.intros[0].counterparty_contact, null)

  // Bob accepts with his contact
  const acc = await respond(bob, id, 'accept', 'bob@signal.example / @bobf')
  assert.equal(acc.status, 200, JSON.stringify(acc.body))

  // after accept but before complete, still no contact released to Alice
  am = await mine(alice)
  assert.equal(am.intros[0].counterparty_contact, null, 'contact must not release before completion')
  assert.equal(am.intros[0].awaiting, 'your_contact')

  sent.length = 0
  // Alice completes with her contact
  const done = await complete(alice, id, 'alice@telegram.example')
  assert.equal(done.status, 200, JSON.stringify(done.body))
  assert.equal(done.body.complete, true)

  // both emails now carry the OTHER party's contact
  assert.equal(sent.length, 2)
  const byTo = Object.fromEntries(sent.map(e => [e.to, e.text]))
  assert.match(byTo['alice@example.com'], /bob@signal\.example/)   // Alice learns Bob's contact
  assert.match(byTo['bob@example.com'], /alice@telegram\.example/) // Bob learns Alice's contact

  // mine now reveals the counterparty contact to each party
  am = await mine(alice); bm = await mine(bob)
  assert.equal(am.intros[0].counterparty_contact, 'bob@signal.example / @bobf')
  assert.equal(bm.intros[0].counterparty_contact, 'alice@telegram.example')
  assert.equal(am.intros[0].complete, true)
})

// ── Guards ──

test('one pending per card pair, in either direction', async () => {
  const a = makeCard('A'); const b = makeCard('B')
  const aCard = await publish(a); const bCard = await publish(b)
  assert.equal((await request(a, aCard, bCard)).status, 201)
  assert.equal((await request(a, aCard, bCard)).status, 409, 'second pending same direction')
  assert.equal((await request(b, bCard, aCard)).status, 409, 'pending reverse direction')
})

test('daily cap of 10 requests per key', async () => {
  const a = makeCard('capper'); const aCard = await publish(a)
  for (let i = 0; i < 10; i++) { const t = makeCard(`t${i}`); const tc = await publish(t); assert.equal((await request(a, aCard, tc)).status, 201) }
  const extra = makeCard('extra'); const ec = await publish(extra)
  assert.equal((await request(a, aCard, ec)).status, 429)
})

test('urls in the note are stripped at store and in responses', async () => {
  const a = makeCard('A'); const b = makeCard('B')
  const aCard = await publish(a); const bCard = await publish(b)
  const r = await request(a, aCard, bCard, 'collaborate', 'ping me at https://evil.example/x or bob.com right now')
  assert.equal(r.status, 201)
  assert.equal(r.body.note.includes('http'), false)
  assert.equal(r.body.note.includes('evil.example'), false)
  assert.equal(r.body.note.includes('bob.com'), false)
  assert.match(r.body.note, /\[link removed\]/)
  const bm = await mine(b)
  assert.equal(bm.intros[0].note.includes('evil.example'), false)
})

test('only the target may respond, only the requester may complete', async () => {
  const a = makeCard('A'); const b = makeCard('B'); const c = makeCard('C')
  const aCard = await publish(a); const bCard = await publish(b); await publish(c)
  const id = (await request(a, aCard, bCard)).body.id
  assert.equal((await respond(a, id, 'accept', 'x')).status, 403, 'requester cannot respond')
  assert.equal((await respond(c, id, 'accept', 'x')).status, 403, 'third party cannot respond')
  await respond(b, id, 'accept', 'bcontact')
  assert.equal((await complete(b, id, 'x')).status, 403, 'target cannot complete')
})

test('accept without a contact is rejected', async () => {
  const a = makeCard('A'); const b = makeCard('B')
  const aCard = await publish(a); const bCard = await publish(b)
  const id = (await request(a, aCard, bCard)).body.id
  const res = await fetch(`${base}/api/v3/intros/${id}/respond`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(respondBody(b, id, 'accept')) })
  assert.equal(res.status, 400)
})

test('decline_and_block prevents re-request in both directions', async () => {
  const a = makeCard('A'); const b = makeCard('B')
  const aCard = await publish(a); const bCard = await publish(b)
  const id = (await request(a, aCard, bCard)).body.id
  const r = await respond(b, id, 'decline_and_block')
  assert.equal(r.body.blocked, true)
  assert.equal((await request(a, aCard, bCard)).status, 403, 'blocked pair cannot re-request forward')
  assert.equal((await request(b, bCard, aCard)).status, 403, 'blocked pair cannot re-request reverse')
})

test('a from_card that does not belong to the signer is rejected', async () => {
  const a = makeCard('A'); const b = makeCard('B'); const imposter = makeCard('imp')
  const aCard = await publish(a); const bCard = await publish(b)
  // imposter signs with their own key but claims aCard as from_card
  const nonce = 'z'
  const body = { from_card: aCard, to_card: bCard, purpose: 'collaborate', note: '', public_key: imposter.keys.publicKey, nonce, signature: sign(`intro-request:${aCard}:${bCard}:collaborate:${nonce}`, imposter.keys.privateKey) }
  const res = await fetch(`${base}/api/v3/intros/request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  assert.equal(res.status, 403)
})

test('a request to a non-network-visible target is refused', async () => {
  const a = makeCard('A'); const hidden = makeCard('hidden', { headline: 'private' })
  const aCard = await publish(a); const hCard = await publish(hidden)
  assert.equal((await request(a, aCard, hCard)).status, 404)
})

test('mine requires a valid signature', async () => {
  const a = makeCard('A'); const other = generateKeyPair()
  const qs = new URLSearchParams({ public_key: a.keys.publicKey, nonce: 'n', signature: sign('intro-mine:n', other.privateKey) })
  const res = await fetch(`${base}/api/v3/intros/mine?${qs}`)
  assert.equal(res.status, 403)
})
