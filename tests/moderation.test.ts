// Operator moderation: a hidden card or key leaves search, the wall, matching,
// intros and counts, keeps its signed revocation_status, cannot publish, renew or
// replace, and can still be withdrawn by its owner. Synthetic keys and data only.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-moderation-test-'))
process.env.DB_PATH = join(tmpDir, 'moderation-test.db')

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const matchesDb = await import('../src/matches-db.js')
const v3db = await import('../src/v3-db.js')
const mod = await import('../src/moderation.js')

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
  let j: any = null; try { j = JSON.parse(text) } catch { /* html */ }
  return { status: res.status, body: j, text }
}
const getText = async (path: string) => { const r = await fetch(`${base}${path}`); return { status: r.status, text: await r.text() } }
const publish = (card: Record<string, any>) => post('/api/v3/cards', { card })
const verb = (keys: Keys, id: string, name: string) => post(`/api/v3/cards/${id}/${name}`, { public_key: keys.publicKey, signature: sign(`${name}:${id}`, keys.privateKey) })
const searchIds = async (filters: Record<string, unknown>) => ((await post('/api/v3/cards/search', { ...filters, limit: 50 })).body.results ?? []).map((c: any) => c.card_id)
const EVENT = 'moderation-wall-event'

test('hiding a key takes all its cards off the network without forging a withdrawal', async () => {
  const probe = generateKeyPair()
  const real = generateKeyPair()
  const p1 = await publish(makeCard(probe, { headline: 'Moderation probe one', event_ref: { event_id: EVENT } }))
  const p2 = await publish(makeCard(probe, { headline: 'Moderation probe two' }, 1000))
  const r1 = await publish(makeCard(real, { headline: 'Moderation real person', event_ref: { event_id: EVENT } }))
  assert.deepEqual([p1.status, p2.status, r1.status], [201, 201, 201])
  assert.ok((await searchIds({ intents: ['collaborate'] })).includes(p1.body.card_id), 'control: visible before the hide')
  assert.ok(matchesDb.ownerMatches(r1.body.card_id).some((m: any) => m.other_card_id === p1.body.card_id), 'control: matched before the hide')
  const before = v3db.v3CardCounts()

  const res = mod.hideFromNetwork('subject', probe.publicKey, 'probe traffic 2026-10-31', 'operator-test')
  assert.deepEqual(res, { newly_hidden: true, cards: 2 })

  const ids = await searchIds({ intents: ['collaborate'] })
  assert.equal(ids.includes(p1.body.card_id) || ids.includes(p2.body.card_id), false, 'out of search')
  assert.ok(ids.includes(r1.body.card_id), 'the real card stays')
  const wall = await getText(`/e/${EVENT}`)
  assert.equal(wall.text.includes('Moderation probe one'), false, 'off the event wall')
  assert.ok(wall.text.includes('Moderation real person'))
  assert.equal(matchesDb.ownerMatches(r1.body.card_id).some((m: any) => m.other_card_id === p1.body.card_id), false, 'out of matches')
  assert.equal(v3db.isCardMatchable(p1.body.card_id), false)
  const after = v3db.v3CardCounts()
  assert.equal(after.cards_active, before.cards_active - 2)
  assert.equal(after.cards_hidden, before.cards_hidden + 2)
  const stats = JSON.parse((await getText('/api/stats')).text)
  assert.equal(stats.v3.cards_active, after.cards_active, 'public stats still count active cards')
  assert.equal('cards_hidden' in stats.v3, false, 'but not how many the operator hid')

  const g = JSON.parse((await getText(`/api/v3/cards/${p1.body.card_id}`)).text)
  assert.equal(g.revocation_status, 'active', 'the signed status is not rewritten')
  assert.equal(g.moderation, 'hidden')
  assert.equal(g.projection, 'status_only')
  assert.equal(JSON.stringify(g).includes('Moderation probe one'), false)
  assert.equal(JSON.stringify(g).includes('probe traffic'), false, 'the reason is not published')
  assert.equal((await getText(`/c/${p1.body.card_id}`)).text.includes('Moderation probe one'), false)
  const events = db.getDb().prepare("SELECT COUNT(*) n FROM card_events WHERE event = 'card_hidden' AND subject_key = ?").get(probe.publicKey) as any
  assert.equal(events.n, 2)
})

test('a hidden key cannot publish, renew or replace, and the owner can still withdraw', async () => {
  const keys = generateKeyPair()
  const p = await publish(makeCard(keys, { headline: 'Hidden key writes' }))
  assert.equal(p.status, 201)
  mod.hideFromNetwork('subject', keys.publicKey, 'test', 'operator-test')
  const again = await publish(makeCard(keys, { headline: 'Hidden key new card' }, 1000))
  assert.equal(again.status, 403, again.text)
  assert.match(again.body.error, /hidden from the network by the operator/)
  const rn = await post(`/api/v3/cards/${p.body.card_id}/renew`, { card: makeCard(keys, { headline: 'Hidden key writes' }, 2000) })
  assert.equal(rn.status, 403, rn.text)
  const rp = await post(`/api/v3/cards/${p.body.card_id}/replace`, { card: makeCard(keys, { headline: 'Hidden key replacement' }, 3000) })
  assert.equal(rp.status, 403, rp.text)
  const w = await verb(keys, p.body.card_id, 'withdraw')
  assert.equal(w.status, 200, w.text)
  assert.equal(v3db.getV3Card(p.body.card_id)?.revocation_status, 'withdrawn')
})

test('hiding one card leaves the key\'s other cards alone and blocks renewing that card', async () => {
  const keys = generateKeyPair()
  const a = await publish(makeCard(keys, { headline: 'Single hide A' }))
  const b = await publish(makeCard(keys, { headline: 'Single hide B' }, 1000))
  mod.hideFromNetwork('card', a.body.card_id, 'test', 'operator-test')
  const ids = await searchIds({ intents: ['collaborate'] })
  assert.equal(ids.includes(a.body.card_id), false)
  assert.ok(ids.includes(b.body.card_id))
  const rn = await post(`/api/v3/cards/${a.body.card_id}/renew`, { card: makeCard(keys, { headline: 'Single hide A' }, 2000) })
  assert.equal(rn.status, 409, rn.text)
  const fresh = await publish(makeCard(keys, { headline: 'Single hide C' }, 3000))
  assert.equal(fresh.status, 201, 'the key itself is not hidden')
})

test('an intro to a hidden card is refused, and from a hidden card too', async () => {
  const me = generateKeyPair()
  const them = generateKeyPair()
  const mine = await publish(makeCard(me, { headline: 'Intro requester card' }))
  const theirs = await publish(makeCard(them, { headline: 'Intro hidden target' }))
  mod.hideFromNetwork('card', theirs.body.card_id, 'test', 'operator-test')
  const nonce = `n-${Date.now()}`
  const to = await post('/api/v3/intros/request', {
    from_card: mine.body.card_id, to_card: theirs.body.card_id, purpose: 'collaborate', note: 'hi', public_key: me.publicKey, nonce,
    signature: sign(`intro-request:${mine.body.card_id}:${theirs.body.card_id}:collaborate:${nonce}`, me.privateKey),
  })
  assert.equal(to.status, 404, to.text)
  assert.match(to.body.error, /target card is not available/)
  // Control: the same request shape to a card that is not hidden goes through.
  const ctrl = await publish(makeCard(generateKeyPair(), { headline: 'Intro control target' }))
  const nc = `nc-${Date.now()}`
  const ok = await post('/api/v3/intros/request', {
    from_card: mine.body.card_id, to_card: ctrl.body.card_id, purpose: 'collaborate', note: 'hi', public_key: me.publicKey, nonce: nc,
    signature: sign(`intro-request:${mine.body.card_id}:${ctrl.body.card_id}:collaborate:${nc}`, me.privateKey),
  })
  assert.ok(ok.status === 200 || ok.status === 201, `control intro: ${ok.text}`)
  mod.hideFromNetwork('card', mine.body.card_id, 'test', 'operator-test')
  const other = await publish(makeCard(generateKeyPair(), { headline: 'Intro live target' }))
  const nonce2 = `n2-${Date.now()}`
  const from = await post('/api/v3/intros/request', {
    from_card: mine.body.card_id, to_card: other.body.card_id, purpose: 'collaborate', note: 'hi', public_key: me.publicKey, nonce: nonce2,
    signature: sign(`intro-request:${mine.body.card_id}:${other.body.card_id}:collaborate:${nonce2}`, me.privateKey),
  })
  assert.equal(from.status, 400, from.text)
  assert.match(from.body.error, /from_card is not live/)
})

test('unhide brings cards back to search, and hiding needs a reason and an actor', async () => {
  const keys = generateKeyPair()
  const p = await publish(makeCard(keys, { headline: 'Unhide probe' }))
  mod.hideFromNetwork('subject', keys.publicKey, 'test', 'operator-test')
  assert.equal((await searchIds({ intents: ['collaborate'] })).includes(p.body.card_id), false)
  const u = mod.unhideFromNetwork('subject', keys.publicKey, 'operator-test')
  assert.deepEqual(u, { cleared: true, reembed_needed: 1 })
  assert.ok((await searchIds({ intents: ['collaborate'] })).includes(p.body.card_id))
  assert.throws(() => mod.hideFromNetwork('card', p.body.card_id, ' ', 'operator-test'))
  assert.throws(() => mod.hideFromNetwork('card', p.body.card_id, 'reason', ''))
  assert.equal(mod.hideFromNetwork('card', p.body.card_id, 'r', 'a').newly_hidden, true)
  assert.equal(mod.hideFromNetwork('card', p.body.card_id, 'r', 'a').newly_hidden, false, 'hiding twice is a no-op')
})
