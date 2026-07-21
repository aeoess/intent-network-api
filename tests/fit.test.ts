// ══════════════════════════════════════════════════════════════
// Mingle v3.6 fit exchange - isolation is the headline
// ══════════════════════════════════════════════════════════════
// The property that must hold: counterparty-authored answer text never enters a
// drafting context. It is checked two ways here: the drafting-context builder's
// input type carries no counterparty field, and the /draft endpoint output
// excludes the counterpart's answer even after they answered. The rest of the
// suite covers the ticket, commit-time invalidation, the gates, deterministic
// classification, the record digest, receipts, access control, and the sweep.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize, verify } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-fit-test-'))
process.env.DB_PATH = join(tmpDir, 'fit.db')
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const fitDb = await import('../src/fit-db.js')
const introsDb = await import('../src/intros-db.js')
const fitContext = await import('../src/fit-context.js')
const fitRecord = await import('../src/fit-record.js')
const serverKey = await import('../src/server-key.js')

let server: Server
let base: string

before(async () => {
  const app = createApp(); db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => { db.getDb().prepare('DELETE FROM rate_limits').run() })

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

// ── Fixtures ──

function makeCard(headline: string, intents: string[], seeking: any[] = []): { keys: any; card: any } {
  const keys = generateKeyPair()
  const now = Date.now()
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(now).toISOString(), expires_at: new Date(now + 21 * 864e5).toISOString(),
    headline, intents, seeking, offering: [{ description: 'things I offer', provenance: 'principal_statement' }],
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

// Create an exchange directly (both cards published) with a chosen intent.
async function makeExchange(intent = 'cofound', headlineB = 'Bob the rust engineer'): Promise<{ exId: string; alice: any; bob: any; aliceCard: string; bobCard: string }> {
  const alice = makeCard('Alice building an AI startup', [intent, 'collaborate'])
  const bob = makeCard(headlineB, [intent], [{ description: 'a technical cofounder role' }])
  const aliceCard = await publish(alice); const bobCard = await publish(bob)
  const exId = `fit-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`
  fitDb.createExchange({ id: exId, intro_id: `intro-${exId}`, card_a: aliceCard, card_b: bobCard, key_a: alice.keys.publicKey, key_b: bob.keys.publicKey, intent, expires_at: new Date(Date.now() + fitDb.FIT_WINDOW_MS).toISOString(), ledger_version_a: 0, ledger_version_b: 0 })
  return { exId, alice, bob, aliceCard, bobCard }
}

function ticket(exId: string, nonce: string, answers: any[], signWith: any): any {
  const hash = sha(canonicalize({ exchange_id: exId, nonce, answers }))
  return { answers, public_key: signWith.publicKey, nonce, signature: sign(hash, signWith.privateKey) }
}
async function submitAnswers(who: any, exId: string, answers: any[]): Promise<{ status: number; body: any }> {
  const nonce = 'n' + Math.random().toString(16).slice(2)
  const res = await fetch(`${base}/api/v3/fit/${exId}/answers`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(ticket(exId, nonce, answers, who.keys)) })
  return { status: res.status, body: await res.json() }
}
async function getFit(who: any, exId: string, path = ''): Promise<{ status: number; body: any }> {
  const nonce = 'g' + Math.random().toString(16).slice(2)
  const prefix = path === '/draft' ? 'fit-draft' : 'fit-get'
  const qs = new URLSearchParams({ public_key: who.keys.publicKey, nonce, signature: sign(`${prefix}:${exId}:${nonce}`, who.keys.privateKey) })
  const res = await fetch(`${base}/api/v3/fit/${exId}${path}?${qs}`)
  return { status: res.status, body: await res.json() }
}
async function setDisclosures(who: any, cardId: string, texts: string[]): Promise<any> {
  const approved_hash = sha(canonicalize(texts))
  const nonce = 'l' + Math.random().toString(16).slice(2)
  const body = { card_id: cardId, items: texts.map(t => ({ text: t })), approved_hash, public_key: who.keys.publicKey, nonce, signature: sign(`set-disclosures:${cardId}:${approved_hash}:${nonce}`, who.keys.privateKey) }
  const res = await fetch(`${base}/api/v3/fit/disclosures`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: res.status, body: await res.json() }
}
async function closeFit(who: any, exId: string): Promise<any> {
  const nonce = 'c' + Math.random().toString(16).slice(2)
  const body = { public_key: who.keys.publicKey, nonce, signature: sign(`fit-close:${exId}:${nonce}`, who.keys.privateKey) }
  return (await fetch(`${base}/api/v3/fit/${exId}/close`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json()
}

// ── ISOLATION (the headline) ──

test('the drafting-context builder cannot receive counterparty answer text', () => {
  // Type-level: the only inputs are own card, own ledger, questions.
  const ctx = fitContext.assembleDraftingContext({
    own_card_public: { headline: 'me' },
    own_ledger: [{ id: 'l1', text: 'I can commit 20 hours', position: 1 }],
    questions: [{ question_id: 'cofound-1', text: 'How many hours?' }],
  })
  assert.deepEqual(Object.keys(ctx).sort(), ['guidance', 'own_headline', 'own_ledger', 'questions'])
  // There is no field anywhere that could carry a counterparty answer.
  assert.equal(JSON.stringify(ctx).includes('COUNTERPARTY'), false)
})

test('a counterpart answer never appears in the drafting context, only in the human view', async () => {
  const { exId, alice, bob } = await makeExchange('cofound')
  const r = await submitAnswers(bob, exId, [{ question_id: 'cofound-1', mode: 'drafted', text: 'I can give twenty hours a week, COUNTERPARTYSECRET' }])
  assert.equal(r.status, 200, JSON.stringify(r.body))

  // Alice drafts: her drafting context must not contain Bob's answer.
  const draft = await getFit(alice, exId, '/draft')
  assert.equal(draft.status, 200)
  assert.equal(JSON.stringify(draft.body).includes('COUNTERPARTYSECRET'), false, 'Bob\'s answer must never enter Alice\'s drafting context')

  // The human view DOES carry it (as data), which is where it belongs.
  const human = await getFit(alice, exId)
  assert.equal(JSON.stringify(human.body).includes('COUNTERPARTYSECRET'), true, 'the human view shows the counterpart answer as data')
})

// ── Ticket semantics ──

test('a ticket whose answers do not match the signed hash is rejected', async () => {
  const { exId, alice } = await makeExchange()
  const nonce = 'x'
  const signedFor = [{ question_id: 'cofound-1', mode: 'skip' }]
  const posted = [{ question_id: 'cofound-2', mode: 'skip' }]  // different from what was signed
  const hash = sha(canonicalize({ exchange_id: exId, nonce, answers: signedFor }))
  const body = { answers: posted, public_key: alice.keys.publicKey, nonce, signature: sign(hash, alice.keys.privateKey) }
  const res = await fetch(`${base}/api/v3/fit/${exId}/answers`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  assert.equal(res.status, 403)
})

// ── Commit-time re-checks ──

test('a blocked pair cannot submit answers', async () => {
  const { exId, alice, aliceCard, bobCard } = await makeExchange()
  introsDb.addBlock(aliceCard, bobCard)
  const r = await submitAnswers(alice, exId, [{ question_id: 'cofound-1', mode: 'skip' }])
  assert.equal(r.status, 403)
})

test('ledger supersession invalidates an answer referencing the old item', async () => {
  const { exId, alice, aliceCard } = await makeExchange()
  const v1 = await setDisclosures(alice, aliceCard, ['I can commit twenty hours a week'])
  const ledgerId = v1.body.items[0].id
  // Supersede the ledger (new version; the old id is gone).
  await setDisclosures(alice, aliceCard, ['A completely different statement'])
  const r = await submitAnswers(alice, exId, [{ question_id: 'cofound-1', mode: 'ledger', ledger_id: ledgerId }])
  assert.equal(r.status, 409, JSON.stringify(r.body))
})

// ── Ledger deny-list ──

test('open-ended ledger items are rejected', async () => {
  const built = makeCard('someone', ['cofound']); const cardId = await publish(built)
  for (const bad of ['share anything relevant', 'use your judgment', 'tell them whatever']) {
    const r = await setDisclosures(built, cardId, [bad])
    assert.equal(r.status, 400, `should reject: ${bad}`)
  }
  const ok = await setDisclosures(built, cardId, ['I can commit twenty hours a week'])
  assert.equal(ok.status, 201)
})

// ── Work-intent prohibition ──

test('a work-intent intro opens no fit exchange', async () => {
  const alice = makeCard('Alice hiring', ['work']); const bob = makeCard('Bob for hire', ['work'])
  const aliceCard = await publish(alice); const bobCard = await publish(bob)
  // request + accept a work intro
  const reqNonce = 'r1'
  const reqBody = { from_card: aliceCard, to_card: bobCard, purpose: 'work', note: '', public_key: alice.keys.publicKey, nonce: reqNonce, signature: sign(`intro-request:${aliceCard}:${bobCard}:work:${reqNonce}`, alice.keys.privateKey) }
  const introId = (await (await fetch(`${base}/api/v3/intros/request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(reqBody) })).json()).id
  const accNonce = 'a1'
  const accBody = { action: 'accept', contact: 'bob@work.example', public_key: bob.keys.publicKey, nonce: accNonce, signature: sign(`intro-respond:${introId}:accept:${accNonce}`, bob.keys.privateKey) }
  const acc = await (await fetch(`${base}/api/v3/intros/${introId}/respond`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(accBody) })).json()
  assert.equal(acc.status ?? 'accepted', 'accepted')
  assert.equal(acc.fit_exchange, null, 'work intent must not open a fit exchange')
})

test('a cofound intro DOES open a fit exchange with a consent sheet', async () => {
  const alice = makeCard('Alice founder', ['cofound']); const bob = makeCard('Bob cofounder', ['cofound'])
  const aliceCard = await publish(alice); const bobCard = await publish(bob)
  const reqNonce = 'r2'
  const reqBody = { from_card: aliceCard, to_card: bobCard, purpose: 'cofound', note: '', public_key: alice.keys.publicKey, nonce: reqNonce, signature: sign(`intro-request:${aliceCard}:${bobCard}:cofound:${reqNonce}`, alice.keys.privateKey) }
  const introId = (await (await fetch(`${base}/api/v3/intros/request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(reqBody) })).json()).id
  const accNonce = 'a2'
  const accBody = { action: 'accept', contact: 'bob@x.example', public_key: bob.keys.publicKey, nonce: accNonce, signature: sign(`intro-respond:${introId}:accept:${accNonce}`, bob.keys.privateKey) }
  const acc = await (await fetch(`${base}/api/v3/intros/${introId}/respond`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(accBody) })).json()
  assert.ok(acc.fit_exchange, 'a fit exchange opened')
  assert.equal(acc.consent_sheet.purpose, 'cofound')
  assert.equal(acc.consent_sheet.bank_version, 1)
})

// ── Slot sanitization ──

test('public-card slots are sanitized of markup in questions', async () => {
  const { exId, alice } = await makeExchange('cofound', 'Founder <script>alert(1)</script> "loud"')
  const draft = await getFit(alice, exId, '/draft')
  const q4 = draft.body.drafting_context.questions.find((q: any) => q.question_id === 'cofound-4')
  assert.ok(q4)
  assert.equal(q4.text.includes('<script>'), false)
  assert.equal(q4.text.includes('<'), false)
  assert.equal(q4.text.includes('>'), false)
})

// ── Contact-data detection ──

test('contact data is caught, including spelled and cross-answer split forms', async () => {
  const { exId, alice } = await makeExchange()
  // spelled email in one answer
  assert.equal((await submitAnswers(alice, exId, [{ question_id: 'cofound-1', mode: 'drafted', text: 'reach me at john at example dot com' }])).status, 400)
  // split across two answers
  assert.equal((await submitAnswers(alice, exId, [
    { question_id: 'cofound-1', mode: 'drafted', text: 'my email is jane' },
    { question_id: 'cofound-2', mode: 'drafted', text: 'at example dot com' },
  ])).status, 400)
  // a clean answer passes
  assert.equal((await submitAnswers(alice, exId, [{ question_id: 'cofound-1', mode: 'drafted', text: 'I can commit twenty hours a week and want to own product' }])).status, 200)
})

test('a third-party allegation is rejected', async () => {
  const { exId, alice } = await makeExchange()
  const r = await submitAnswers(alice, exId, [{ question_id: 'cofound-6', mode: 'drafted', text: 'My last cofounder Bob committed fraud and was fired' }])
  assert.equal(r.status, 400)
})

// ── Custom question caps ──

test('custom questions are capped at two per party', async () => {
  const { exId, alice } = await makeExchange()
  const custom = async (qs: string[]) => {
    const nonce = 'cu' + Math.random().toString(16).slice(2)
    const body = { questions: qs.map(t => ({ text: t })), public_key: alice.keys.publicKey, nonce, signature: sign(`fit-custom:${exId}:${nonce}`, alice.keys.privateKey) }
    return fetch(`${base}/api/v3/fit/${exId}/custom`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  }
  assert.equal((await custom(['What is your timezone?', 'What is your stack?'])).status, 200)
  assert.equal((await custom(['One more question?'])).status, 400, 'over the cap')
})

// ── Deterministic classification ──

test('classification is deterministic and never infers from silence', () => {
  assert.equal(fitRecord.classify(undefined, false), 'not_answered')
  assert.equal(fitRecord.classify({ mode: 'skip' } as any, false), 'not_answered')
  assert.equal(fitRecord.classify({ mode: 'drafted' } as any, false), 'answered')
  assert.equal(fitRecord.classify({ mode: 'ledger' } as any, false), 'answered')
  assert.equal(fitRecord.classify({ mode: 'drafted' } as any, true), 'partially_answered')
})

// ── Record digest + receipt ──

test('the record digest is stable and its receipt verifies', async () => {
  const { exId, alice, bob } = await makeExchange()
  await submitAnswers(alice, exId, [{ question_id: 'cofound-1', mode: 'drafted', text: 'twenty hours a week' }, { question_id: 'cofound-2', mode: 'skip' }])
  await submitAnswers(bob, exId, [{ question_id: 'cofound-1', mode: 'drafted', text: 'thirty hours a week' }])

  const closed = await closeFit(alice, exId)
  assert.equal(closed.closed, true)
  const digest = closed.record_digest
  assert.match(digest, /^[0-9a-f]{64}$/)

  // Re-fetch: closing is idempotent and the digest is unchanged.
  const again = await getFit(alice, exId)
  assert.equal(again.body.record_digest, digest, 'digest is stable across reads')

  // Receipt verifies against the server key.
  assert.equal(serverKey.verifyReceipt(digest, again.body.receipt), true)
  assert.equal(verify(digest, again.body.receipt, again.body.server_public_key), true)
  // A different digest does not verify.
  assert.equal(serverKey.verifyReceipt('f'.repeat(64), again.body.receipt), false)
})

test('round2 without a fresh answer classifies as partially_answered', async () => {
  const { exId, alice, bob } = await makeExchange()
  await submitAnswers(alice, exId, [{ question_id: 'cofound-1', mode: 'drafted', text: 'twenty hours' }])
  // bob requests more on cofound-1 (targeting alice); alice does not re-answer.
  const nonce = 'r2q'
  await fetch(`${base}/api/v3/fit/${exId}/round2`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question_ids: ['cofound-1'], public_key: bob.keys.publicKey, nonce, signature: sign(`fit-round2:${exId}:${nonce}`, bob.keys.privateKey) }) })
  const closed = await closeFit(alice, exId)
  const entry = closed.record.entries.find((e: any) => e.question_id === 'cofound-1')
  const aliceSide = entry.by_a.key === alice.keys.publicKey ? entry.by_a : entry.by_b
  assert.equal(aliceSide.classification, 'partially_answered')
})

// ── Access control + sweep ──

test('only the two parties can read an exchange', async () => {
  const { exId } = await makeExchange()
  const stranger = { keys: generateKeyPair() }
  assert.equal((await getFit(stranger, exId)).status, 403)
  assert.equal((await getFit(stranger, exId, '/draft')).status, 403)
})

test('the 72h sweep closes an expired exchange', async () => {
  const { exId, alice } = await makeExchange()
  // Force the window into the past.
  db.getDb().prepare('UPDATE v3_fit_exchanges SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), exId)
  const swept = await (await fetch(`${base}/api/v3/fit/sweep`, { method: 'POST' })).json()
  assert.ok(swept.closed >= 1)
  const g = await getFit(alice, exId)
  assert.equal(g.body.state, 'closed')
  assert.ok(g.body.record)
})
