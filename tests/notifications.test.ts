// ══════════════════════════════════════════════════════════════
// Mingle email notification tests - mock transport, never the real API
// ══════════════════════════════════════════════════════════════
// A recorder transport captures every OutgoingEmail so tests assert on
// recipients, subjects, and bodies without any network call. The real Resend
// path is exercised only by the env-unset no-op check (transport reset,
// RESEND_API_KEY absent).

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize, createIntentCard } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-email-test-'))
process.env.DB_PATH = join(tmpDir, 'email.db')
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'
// The legacy intro tests below drive the v2 routes, which run only when
// MINGLE_V2_ENABLED is exactly "1".
process.env.MINGLE_V2_ENABLED = '1'

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const email = await import('../src/notifications.js')
const notifyDb = await import('../src/notify-db.js')

let server: Server
let base: string
const sent: { to: string; subject: string; text: string }[] = []

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(resolve => { server = app.listen(0, '127.0.0.1', () => resolve()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { email.resetTransport(); server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => {
  sent.length = 0
  email.setTransport(async (e) => { sent.push(e); return { ok: true, id: 'mock' } })
  // Notification routes rate-limit by client IP; every test shares 127.0.0.1,
  // so clear the shared counter between tests (test-only, no production change).
  db.getDb().prepare('DELETE FROM rate_limits').run()
})

// ── Subscribe / confirm ──

async function subscribe(keys: any, addr: string, prefs?: any): Promise<any> {
  const nonce = 'n' + Math.random().toString(36).slice(2)
  const body: any = { subject_key: keys.publicKey, email: addr, nonce, signature: sign(`${addr}:${nonce}`, keys.privateKey) }
  if (prefs) body.prefs = prefs
  return (await fetch(`${base}/api/v3/notifications/subscribe`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })).json()
}

test('subscribe stores unverified and sends exactly one confirmation', async () => {
  const keys = generateKeyPair()
  const r = await subscribe(keys, 'alice@example.com')
  assert.equal(r.subscribed, true)
  assert.equal(r.verified, false)
  assert.equal(sent.length, 1, 'exactly one confirmation email')
  assert.equal(sent[0].to, 'alice@example.com')
  assert.match(sent[0].subject, /Confirm/i)
  assert.match(sent[0].text, /\/api\/v3\/notifications\/confirm\//)
  const sub = notifyDb.getSubscription(keys.publicKey)!
  assert.equal(sub.verified, false)
})

test('a bad subscribe signature is refused', async () => {
  const keys = generateKeyPair()
  const other = generateKeyPair()
  const nonce = 'x'
  const body = { subject_key: keys.publicKey, email: 'x@example.com', nonce, signature: sign(`x@example.com:${nonce}`, other.privateKey) }
  const res = await fetch(`${base}/api/v3/notifications/subscribe`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  assert.equal(res.status, 403)
  assert.equal(sent.length, 0)
})

test('confirm flips verified', async () => {
  const keys = generateKeyPair()
  await subscribe(keys, 'bob@example.com')
  const token = notifyDb.getSubscription(keys.publicKey)!.verify_token
  const res = await fetch(`${base}/api/v3/notifications/confirm/${token}`)
  assert.equal(res.status, 200)
  assert.equal(notifyDb.getSubscription(keys.publicKey)!.verified, true)
})

// ── Signed status read (for the assistant's confirmation nudge) ──

async function status(keys: any, signer?: any): Promise<{ code: number; body: any }> {
  const nonce = 's' + Math.random().toString(36).slice(2)
  const qs = new URLSearchParams({ public_key: keys.publicKey, nonce, signature: sign(`notif-status:${nonce}`, (signer ?? keys).privateKey) })
  const res = await fetch(`${base}/api/v3/notifications/status?${qs}`)
  return { code: res.status, body: await res.json() }
}

// What a new subscription starts with. new_match is opt-in, like weekly_digest.
const NEW_SUB_PREFS = { intro_request: true, intro_accepted: true, weekly_digest: false, new_match: false }

test('status reports subscribed, verified and the effective prefs, gated by a valid signature', async () => {
  const keys = generateKeyPair()
  // before subscribing: not subscribed, so there are no prefs to report
  let s = await status(keys)
  assert.equal(s.code, 200)
  assert.deepEqual(s.body, { subscribed: false, verified: false, prefs: null })
  // after subscribing, before confirming: subscribed but unverified
  await subscribe(keys, 'status@example.com')
  s = await status(keys)
  assert.deepEqual(s.body, { subscribed: true, verified: false, prefs: NEW_SUB_PREFS })
  // after confirming: verified
  await fetch(`${base}/api/v3/notifications/confirm/${notifyDb.getSubscription(keys.publicKey)!.verify_token}`)
  s = await status(keys)
  assert.deepEqual(s.body, { subscribed: true, verified: true, prefs: NEW_SUB_PREFS })
  // a signature from another key is refused (no one else learns your status)
  const other = generateKeyPair()
  const bad = await status(keys, other)
  assert.equal(bad.code, 403)
})

// ── Preference merge: a named pref is set, an omitted pref keeps its value ──

test('a new subscription that does not name new_match stores it off, and the response carries all four prefs', async () => {
  const keys = generateKeyPair()
  const r = await subscribe(keys, 'defaults@example.com')
  assert.deepEqual(r.prefs, NEW_SUB_PREFS)
  assert.deepEqual(notifyDb.getSubscription(keys.publicKey)!.prefs, NEW_SUB_PREFS)
  const row = db.getDb().prepare('SELECT prefs_json FROM notifications WHERE subject_key = ?').get(keys.publicKey) as any
  assert.equal(JSON.parse(row.prefs_json).new_match, false, 'stored explicitly off, not merely absent')
})

test('a resubscribe that names only weekly_digest leaves every other pref as stored', async () => {
  const keys = generateKeyPair()
  await subscribe(keys, 'merge@example.com', { new_match: true, intro_request: false })
  const r = await subscribe(keys, 'merge@example.com', { weekly_digest: true })
  const expected = { intro_request: false, intro_accepted: true, weekly_digest: true, new_match: true }
  assert.deepEqual(r.prefs, expected, 'the subscribe response carries the effective prefs')
  assert.deepEqual(notifyDb.getSubscription(keys.publicKey)!.prefs, expected)
  assert.deepEqual((await status(keys)).body.prefs, expected, 'signed status shows the same four prefs')

  // The other direction: new_match stays off when a resubscribe does not name it.
  const off = generateKeyPair()
  await subscribe(off, 'stays-off@example.com')
  await subscribe(off, 'stays-off@example.com', { weekly_digest: true })
  assert.equal(notifyDb.getSubscription(off.publicKey)!.prefs.new_match, false)

  // A resubscribe that names nothing changes nothing.
  const same = await subscribe(keys, 'merge@example.com')
  assert.deepEqual(same.prefs, expected)
})

// A pref change is a resubscribe with the same address, so that path must not
// act like a new subscription.
test('a pref update on a confirmed address stays confirmed, says so, and sends no confirmation', async () => {
  const keys = generateKeyPair()
  await subscribe(keys, 'confirmed@example.com')
  await fetch(`${base}/api/v3/notifications/confirm/${notifyDb.getSubscription(keys.publicKey)!.verify_token}`)
  sent.length = 0
  const r = await subscribe(keys, 'confirmed@example.com', { new_match: true })
  assert.equal(r.verified, true, 'the response reports the stored state')
  assert.equal(r.confirmation_sent, false)
  assert.equal(sent.length, 0, 'no confirmation email for an address that is already confirmed')
  assert.deepEqual((await status(keys)).body, { subscribed: true, verified: true, prefs: { ...NEW_SUB_PREFS, new_match: true } })
})

test('changing the address still resets verification and sends one confirmation', async () => {
  const keys = generateKeyPair()
  await subscribe(keys, 'old-addr@example.com')
  await fetch(`${base}/api/v3/notifications/confirm/${notifyDb.getSubscription(keys.publicKey)!.verify_token}`)
  sent.length = 0
  const r = await subscribe(keys, 'new-addr@example.com')
  assert.equal(r.verified, false)
  assert.equal(r.confirmation_sent, true)
  assert.equal(sent.length, 1)
  assert.equal(sent[0].to, 'new-addr@example.com')
})

// ── Intro event emails ──

function publishIntentCard(agentId: string, alias: string): any {
  const keys = generateKeyPair()
  const card = createIntentCard({
    agentId, principalAlias: alias, publicKey: keys.publicKey, privateKey: keys.privateKey,
    needs: [{ category: 'eng', description: 'a backend engineer', priority: 'high', tags: ['x'], visibility: 'public' }],
    offers: [{ category: 'fund', description: 'seed funding', priority: 'medium', tags: ['y'], visibility: 'public' }],
    openTo: ['introductions'], notOpenTo: [], ttlSeconds: 86400,
  })
  return { keys, card }
}

async function publish(card: any): Promise<void> {
  await fetch(`${base}/api/cards`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(card) })
}

test('an intro request emails the verified target, network-visible fields only', async () => {
  const requester = publishIntentCard('req-agent', 'Requester Alias')
  const target = publishIntentCard('tgt-agent', 'Target Alias')
  await publish(requester.card); await publish(target.card)
  // target subscribes + confirms
  await subscribe(target.keys, 'target@example.com')
  const token = notifyDb.getSubscription(target.keys.publicKey)!.verify_token
  await fetch(`${base}/api/v3/notifications/confirm/${token}`)
  sent.length = 0

  // requester sends an intro to the target
  const introBody: any = {
    matchId: 'm1', targetAgentId: 'tgt-agent', message: 'I would love to collaborate on your protocol work',
    fieldsToDisclose: ['needs'], agentId: 'req-agent', publicKey: requester.keys.publicKey,
  }
  introBody.signature = sign(canonicalize(introBody), requester.keys.privateKey)
  const res = await fetch(`${base}/api/intros`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(introBody) })
  assert.equal(res.status, 201, JSON.stringify(await res.clone().json()))

  assert.equal(sent.length, 1, 'exactly one intro email')
  assert.equal(sent[0].to, 'target@example.com')
  assert.match(sent[0].subject, /wants to connect/i)
  assert.match(sent[0].text, /Requester Alias/)         // requester's network-visible headline
  assert.match(sent[0].text, /love to collaborate/)     // the stated purpose
  assert.equal(sent[0].text.includes('target@example.com'), false, 'the email must not echo the address in its body content beyond the To')
})

test('an unverified target never receives the intro email', async () => {
  const requester = publishIntentCard('req2', 'Req Two')
  const target = publishIntentCard('tgt2', 'Tgt Two')
  await publish(requester.card); await publish(target.card)
  await subscribe(target.keys, 'unverified@example.com')  // subscribed but NOT confirmed
  sent.length = 0
  const introBody: any = { matchId: 'm', targetAgentId: 'tgt2', message: 'hi', agentId: 'req2', publicKey: requester.keys.publicKey }
  introBody.signature = sign(canonicalize(introBody), requester.keys.privateKey)
  await fetch(`${base}/api/intros`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(introBody) })
  assert.equal(sent.length, 0, 'no email to an unverified address')
})

test('accepting an intro emails both sides', async () => {
  const requester = publishIntentCard('req3', 'Req Three')
  const target = publishIntentCard('tgt3', 'Tgt Three')
  await publish(requester.card); await publish(target.card)
  for (const [who, addr] of [[requester, 'r3@example.com'], [target, 't3@example.com']] as const) {
    await subscribe(who.keys, addr)
    await fetch(`${base}/api/v3/notifications/confirm/${notifyDb.getSubscription(who.keys.publicKey)!.verify_token}`)
  }
  // create the intro
  const introBody: any = { matchId: 'm', targetAgentId: 'tgt3', message: 'lets talk', agentId: 'req3', publicKey: requester.keys.publicKey }
  introBody.signature = sign(canonicalize(introBody), requester.keys.privateKey)
  const introId = (await (await fetch(`${base}/api/intros`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(introBody) })).json()).introId
  sent.length = 0
  // target approves (X-Agent-Id header identifies verifiedAgentId)
  const respondBody: any = { verdict: 'approve', agentId: 'tgt3', publicKey: target.keys.publicKey }
  respondBody.signature = sign(canonicalize(respondBody), target.keys.privateKey)
  const res = await fetch(`${base}/api/intros/${introId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(respondBody) })
  assert.equal(res.status, 200, JSON.stringify(await res.clone().json()))
  const recipients = sent.map(e => e.to).sort()
  assert.deepEqual(recipients, ['r3@example.com', 't3@example.com'])
  for (const e of sent) assert.match(e.subject, /accepted/i)
})

test('dedupe: the same intro event never emails twice', async () => {
  const target = generateKeyPair()
  notifyDb.upsertSubscription(target.publicKey, 'dedupe@example.com', 'vt', 'ut', { intro_request: true, intro_accepted: true })
  notifyDb.confirmByToken('vt')
  const first = await email.notifyIntroRequest({ recipientKey: target.publicKey, introId: 'introD', requesterHeadline: 'X', purpose: 'p', statusUrl: 'u' })
  const second = await email.notifyIntroRequest({ recipientKey: target.publicKey, introId: 'introD', requesterHeadline: 'X', purpose: 'p', statusUrl: 'u' })
  assert.equal(first.sent, true)
  assert.equal(second.sent, false)
  assert.equal(second.reason, 'duplicate')
})

// ── A failed send gives its dedupe reservation back ──

function verifiedTarget(tag: string): string {
  const keys = generateKeyPair()
  notifyDb.upsertSubscription(keys.publicKey, `${tag}@example.com`, `vt-${tag}`, `ut-${tag}`, { intro_request: true, intro_accepted: true, weekly_digest: false, new_match: false })
  notifyDb.confirmByToken(`vt-${tag}`)
  return keys.publicKey
}
const logRowsFor = (key: string, introId: string): number =>
  (db.getDb().prepare('SELECT COUNT(*) AS n FROM email_log WHERE subject_key = ? AND intro_id = ?').get(key, introId) as any).n

test('a transport failure releases the reservation, so a retry sends exactly once', async () => {
  const key = verifiedTarget('retry')
  const args = { recipientKey: key, introId: 'introRetry', requesterHeadline: 'X', purpose: 'p', statusUrl: 'u' }

  email.setTransport(async () => ({ ok: false, error: 'provider 503' }))
  const failed = await email.notifyIntroRequest(args)
  assert.equal(failed.sent, false)
  assert.equal(failed.reason, 'provider 503')
  assert.equal(logRowsFor(key, 'introRetry'), 0, 'the failed send left no reservation behind')

  email.setTransport(async e => { sent.push(e); return { ok: true, id: 'mock' } })
  const retried = await email.notifyIntroRequest(args)
  assert.equal(retried.sent, true, JSON.stringify(retried))
  const again = await email.notifyIntroRequest(args)
  assert.equal(again.reason, 'duplicate', 'after a real send the dedupe holds')
  assert.equal(sent.filter(e => e.to === 'retry@example.com').length, 1, 'exactly one email went out')
  assert.equal(logRowsFor(key, 'introRetry'), 1)
})

test('a transport that throws also releases the reservation', async () => {
  const key = verifiedTarget('throws')
  const args = { recipientKey: key, introId: 'introThrow', requesterHeadline: 'X', purpose: 'p', statusUrl: 'u' }
  email.setTransport(async () => { throw new Error('socket hang up') })
  const failed = await email.notifyIntroRequest(args)
  assert.equal(failed.sent, false)
  assert.equal(failed.reason, 'socket hang up')
  assert.equal(logRowsFor(key, 'introThrow'), 0)
  email.setTransport(async e => { sent.push(e); return { ok: true, id: 'mock' } })
  assert.equal((await email.notifyIntroRequest(args)).sent, true)
  assert.equal(sent.filter(e => e.to === 'throws@example.com').length, 1)
})

// ── Unsubscribe + delete-server-copy ──

test('signed unsubscribe deletes the row', async () => {
  const keys = generateKeyPair()
  await subscribe(keys, 'leaving@example.com')
  const nonce = 'u1'
  const body = { subject_key: keys.publicKey, nonce, signature: sign(`unsubscribe:${nonce}`, keys.privateKey) }
  const res = await fetch(`${base}/api/v3/notifications/unsubscribe`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  assert.equal(res.status, 200)
  assert.equal(notifyDb.getSubscription(keys.publicKey), null)
})

test('the tokened unsubscribe link needs no signature', async () => {
  const keys = generateKeyPair()
  await subscribe(keys, 'oneclick@example.com')
  const token = notifyDb.getSubscription(keys.publicKey)!.unsub_token
  const res = await fetch(`${base}/api/v3/notifications/unsubscribe/${token}`)
  assert.equal(res.status, 200)
  assert.equal(notifyDb.getSubscription(keys.publicKey), null)
})

// ── Env-unset no-op (the only path that touches the real transport code) ──

test('with no transport and no env, every path no-ops with zero errors', async () => {
  email.resetTransport()
  const savedKey = process.env.RESEND_API_KEY
  const savedFrom = process.env.MINGLE_FROM_EMAIL
  delete process.env.RESEND_API_KEY
  delete process.env.MINGLE_FROM_EMAIL
  try {
    assert.equal(email.isEmailEnabled(), false)
    const keys = generateKeyPair()
    // subscribe still stores, just sends nothing
    const r = await subscribe(keys, 'dark@example.com')
    assert.equal(r.subscribed, true)
    assert.equal(r.email_enabled, false)
    // notify helpers return disabled, never throw
    const res = await email.notifyIntroRequest({ recipientKey: keys.publicKey, introId: 'i', requesterHeadline: 'h', purpose: 'p', statusUrl: 'u' })
    assert.equal(res.sent, false)
    assert.equal(res.reason, 'disabled')
  } finally {
    if (savedKey !== undefined) process.env.RESEND_API_KEY = savedKey
    if (savedFrom !== undefined) process.env.MINGLE_FROM_EMAIL = savedFrom
  }
})
