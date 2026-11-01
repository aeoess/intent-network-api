// Two-sided replay harness from the 2026-10-31 and 2026-11-01 probe run.
//
// LEGIT scenarios are things Mingle exists to do and must keep working: several cards
// per person, several people behind one office address, frequent search, renew and
// replace, taking data down while an address is restricted, an introduction between
// two people, and confirming one's own email.
// ABUSE scenarios reproduce what the probe client did and must stay contained: key
// rotation from one source, the same words published again and again, future dates,
// replay after withdrawal, reading hidden fields, self intros, email to chosen
// addresses, and guessed ids.
// Both sides run against the same server build. Each scenario uses its own client
// address so limits do not leak between scenarios. Synthetic keys and data only.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-harness-test-'))
process.env.DB_PATH = join(tmpDir, 'harness-test.db')
process.env.MINGLE_ALLOW_RESERVED_EMAIL_DOMAINS = '0'

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const matchesDb = await import('../src/matches-db.js')
const v3db = await import('../src/v3-db.js')
const blocks = await import('../src/source-blocks.js')
const email = await import('../src/notifications.js')

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





const sentMail: { to: string }[] = []
email.setTransport(async (e) => { sentMail.push(e); return { ok: true, id: 'mock' } })
let ipSeq = 10
const newSource = () => ({ 'X-Forwarded-For': `198.18.0.${ipSeq++}, 84.17.44.229` })
async function req(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const r = await fetch(`${base}${path}`, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) })
  const text = await r.text(); let j: any = null; try { j = JSON.parse(text) } catch { /* html */ }
  return { status: r.status, body: j, text }
}
const publish = (card: Record<string, any>, h: Record<string, string>) => req('POST', '/api/v3/cards', { card }, h)
const search = (filters: Record<string, unknown>, h: Record<string, string>, key?: string) => req('POST', '/api/v3/cards/search', { limit: 50, ...filters }, key ? { ...h, 'X-Public-Key': key } : h)
const verb = (k: Keys, id: string, name: string, h: Record<string, string>) => req('POST', `/api/v3/cards/${id}/${name}`, { public_key: k.publicKey, signature: sign(`${name}:${id}`, k.privateKey) }, h)
const intro = (k: Keys, from: string, to: string, h: Record<string, string>) => {
  const nonce = `n-${Math.random().toString(16).slice(2)}`
  return req('POST', '/api/v3/intros/request', { from_card: from, to_card: to, purpose: 'collaborate', note: 'hi', public_key: k.publicKey, nonce, signature: sign(`intro-request:${from}:${to}:collaborate:${nonce}`, k.privateKey) }, h)
}
const respond = (k: Keys, introId: string, action: string, h: Record<string, string>, contact?: string) => {
  const nonce = `r-${Math.random().toString(16).slice(2)}`
  return req('POST', `/api/v3/intros/${introId}/respond`, { action, public_key: k.publicKey, nonce, signature: sign(`intro-respond:${introId}:${action}:${nonce}`, k.privateKey), ...(contact ? { contact } : {}) }, h)
}
const subscribe = (k: Keys, addr: string, h: Record<string, string>) => {
  const nonce = `s-${Math.random().toString(16).slice(2)}`
  return req('POST', '/api/v3/notifications/subscribe', { subject_key: k.publicKey, email: addr, nonce, signature: sign(`${addr}:${nonce}`, k.privateKey) }, h)
}
const statuses = (rs: { status: number }[]) => rs.map(r => r.status)
const count = (rs: { status: number }[], s: number) => rs.filter(r => r.status === s).length

// ── LEGIT: must keep working ──────────────────────────────────────────────

test('LEGIT one person publishes 5 different cards', async () => {
  const h = newSource(); const k = generateKeyPair()
  const rs = []
  for (let i = 0; i < 5; i++) rs.push(await publish(makeCard(k, { headline: `Legit project card ${i}` }, i * 1000), h))
  assert.deepEqual(statuses(rs), [201, 201, 201, 201, 201])
})

test('LEGIT five people behind one office address publish 3 cards each', async () => {
  const h = newSource(); const rs = []
  for (let p = 0; p < 5; p++) {
    const k = generateKeyPair()
    for (let i = 0; i < 3; i++) rs.push(await publish(makeCard(k, { headline: `Office person ${p} card ${i}` }, i * 1000), h))
  }
  assert.equal(count(rs, 201), 15, JSON.stringify(statuses(rs)))
})

test('LEGIT an event wall: 25 people on one venue network publish one card each', async () => {
  const h = newSource(); const rs = []
  for (let p = 0; p < 25; p++) rs.push(await publish(makeCard(generateKeyPair(), { headline: `Event attendee ${p}`, event_ref: { event_id: 'harness-event' } }), h))
  assert.equal(count(rs, 201), 25, JSON.stringify(statuses(rs)))
})

test('LEGIT an agent searches 25 times in an hour without publishing', async () => {
  const h = newSource(); const k = generateKeyPair(); const rs = []
  for (let i = 0; i < 25; i++) rs.push(await search({ intents: ['collaborate'] }, h, k.publicKey))
  assert.equal(count(rs, 200), 25, JSON.stringify(statuses(rs)))
})

test('LEGIT an owner renews one card and replaces another', async () => {
  const h = newSource(); const k = generateKeyPair()
  const a = await publish(makeCard(k, { headline: 'Renew me' }), h)
  const b = await publish(makeCard(k, { headline: 'Replace me' }, 1000), h)
  const rn = await req('POST', `/api/v3/cards/${a.body.card_id}/renew`, { card: makeCard(k, { headline: 'Renew me' }, 2000) }, h)
  const rp = await req('POST', `/api/v3/cards/${b.body.card_id}/replace`, { card: makeCard(k, { headline: 'Replaced, new words' }, 3000) }, h)
  assert.deepEqual([rn.status, rp.status], [201, 201], JSON.stringify([rn.body, rp.body]))
})

test('LEGIT a person behind a restricted address can still withdraw and delete their card', async () => {
  const h = newSource(); const k = generateKeyPair()
  const a = await publish(makeCard(k, { headline: 'Take me down later' }), h)
  const b = await publish(makeCard(k, { headline: 'Delete me later' }, 1000), h)
  blocks.restrictSource(h['X-Forwarded-For'].split(',')[0], 'harness', 'harness')
  assert.equal((await verb(k, a.body.card_id, 'withdraw', h)).status, 200)
  assert.equal((await verb(k, b.body.card_id, 'delete-server-copy', h)).status, 200)
  assert.equal((await search({ intents: ['collaborate'] }, h)).status, 200, 'search stays open too')
})

test('LEGIT two different people: one requests an intro, the other accepts', async () => {
  const ha = newSource(); const hb = newSource()
  const ka = generateKeyPair(); const kb = generateKeyPair()
  const a = await publish(makeCard(ka, { headline: 'Requester person' }), ha)
  const b = await publish(makeCard(kb, { headline: 'Target person' }), hb)
  const r = await intro(ka, a.body.card_id, b.body.card_id, ha)
  assert.ok(r.status === 200 || r.status === 201, r.text)
  const id = r.body.intro_id ?? r.body.id
  const acc = await respond(kb, id, 'accept', hb, 'target-person@harness-mail.org')
  assert.ok(acc.status === 200 || acc.status === 201, acc.text)
})

test('LEGIT a person confirms their own email address', async () => {
  const h = newSource(); const k = generateKeyPair()
  const before = sentMail.length
  const r = await subscribe(k, 'person@harness-mail.org', h)
  assert.equal(r.status, 201, r.text)
  assert.equal(r.body.confirmation_sent, true)
  assert.equal(sentMail.length, before + 1)
})

// ── ABUSE: must stay contained ────────────────────────────────────────────

const SOURCE_CAP = Number(process.env.MINGLE_PUBLISH_PER_SOURCE ?? 60)

test('ABUSE a flood: one source rotates 25 fresh keys, 3 cards each, in one hour', async () => {
  const h = newSource(); const rs = []
  for (let p = 0; p < 25; p++) {
    const k = generateKeyPair()
    for (let i = 0; i < 3; i++) rs.push(await publish(makeCard(k, { headline: `Rotation probe ${p}.${i}` }, i * 1000), h))
  }
  assert.equal(count(rs, 201), SOURCE_CAP, `accepted ${count(rs, 201)} of ${rs.length}`)
  assert.equal(count(rs, 429), rs.length - SOURCE_CAP)
})

test('ABUSE one key publishes the same words 5 times with new timestamps', async () => {
  const h = newSource(); const k = generateKeyPair(); const rs = []
  for (let i = 0; i < 5; i++) rs.push(await publish(makeCard(k, { headline: 'Open-data release confirmed' }, i * 500), h))
  assert.deepEqual(statuses(rs), [201, 409, 409, 409, 409])
})

test('ABUSE a card dated 10 minutes ahead to sit on top of search', async () => {
  const h = newSource(); const k = generateKeyPair()
  const c = makeCard(k, { headline: 'Future dated' }, 10 * 60000)
  assert.equal((await publish(c, h)).status, 400)
})

test('ABUSE replay a withdrawn card, then race a renew against the withdraw', async () => {
  const h = newSource(); const k = generateKeyPair()
  const c = makeCard(k, { headline: 'Replay me' })
  const p = await publish(c, h)
  assert.equal((await verb(k, p.body.card_id, 'withdraw', h)).status, 200)
  assert.equal((await publish(c, h)).status, 409)
  const q = await publish(makeCard(k, { headline: 'Race me' }, 1000), h)
  const [rn, w] = await Promise.all([req('POST', `/api/v3/cards/${q.body.card_id}/renew`, { card: makeCard(k, { headline: 'Race me' }, 2000) }, h), verb(k, q.body.card_id, 'withdraw', h)])
  assert.ok((w.status === 200 && rn.status === 409) || (rn.status === 201 && w.status === 409), JSON.stringify([rn.status, w.status]))
})

test('ABUSE read a hidden field through search and fetch', async () => {
  const h = newSource(); const k = generateKeyPair()
  const p = await publish(makeCard(k, { headline: 'Hidden field holder', offering: [{ description: 'HARNESSMARK-hidden', topics: ['harnesshidden'], provenance: 'principal_statement' }], visibility: { headline: 'network', seeking: 'network', offering: 'private' } }), h)
  const s1 = await search({ topics: ['harnesshidden'] }, newSource())
  const f = await req('GET', `/api/v3/cards/${p.body.card_id}`, undefined, newSource())
  assert.equal(s1.text.includes('HARNESSMARK') || f.text.includes('HARNESSMARK'), false)
  assert.equal((s1.body.results ?? []).some((c: any) => c.card_id === p.body.card_id), false, 'the hidden topic does not find it either')
})

test('ABUSE an intro from one card of a key to another card of the same key', async () => {
  const h = newSource(); const k = generateKeyPair()
  const a = await publish(makeCard(k, { headline: 'Self intro A' }), h)
  const b = await publish(makeCard(k, { headline: 'Self intro B' }, 1000), h)
  assert.equal((await intro(k, a.body.card_id, b.body.card_id, h)).status, 400)
})

test('ABUSE one key makes Mingle email addresses it chooses', async () => {
  const h = newSource(); const k = generateKeyPair()
  const before = sentMail.length
  const addrs = ['desk@fermata.example', 'probe@example.org', 'a1@harness-mail.org', 'a2@harness-mail.org', 'a3@harness-mail.org', 'a4@harness-mail.org', 'a5@harness-mail.org']
  const rs = []
  for (const a of addrs) rs.push(await subscribe(k, a, h))
  assert.equal(sentMail.length - before, 3, `emails sent: ${sentMail.length - before}, statuses ${JSON.stringify(statuses(rs))}`)
  assert.deepEqual(statuses(rs).slice(0, 2), [429, 429], 'reserved test domains refused')
})

test('ABUSE withdraw, replace and respond on guessed ids change nothing', async () => {
  const h = newSource(); const k = generateKeyPair()
  const ids = ['card_gridstora_261013_5089', 'v3-connection-4c81de02', 'card_nonexistent_zzz']
  for (const id of ids) {
    assert.equal((await verb(k, id, 'withdraw', h)).status, 404)
    assert.equal((await req('POST', `/api/v3/cards/${id}/replace`, { card: makeCard(k, { headline: 'Guess' }) }, h)).status, 404)
  }
  assert.equal((await respond(k, 'intro_260510_97458', 'accept', h)).status, 404)
})

test('ABUSE a restricted source cannot publish, request intros or sign up for email', async () => {
  const h = newSource(); const k = generateKeyPair(); const other = generateKeyPair()
  const mine = await publish(makeCard(k, { headline: 'Before restriction' }), h)
  const theirs = await publish(makeCard(other, { headline: 'Restriction target' }), newSource())
  blocks.restrictSource(h['X-Forwarded-For'].split(',')[0], 'harness', 'harness')
  assert.equal((await publish(makeCard(generateKeyPair(), { headline: 'After restriction' }), h)).status, 403)
  assert.equal((await intro(k, mine.body.card_id, theirs.body.card_id, h)).status, 403)
  assert.equal((await subscribe(k, 'restricted@harness-mail.org', h)).status, 403)
})
