// Confirmation email guard. On 2026-11-01 a probe client used notification sign-up to
// make Mingle email 28 addresses it chose. A sign-up now cannot reach a reserved test
// domain, one address gets at most 2 confirmations a day whoever asks, one key can name
// at most 3 addresses a day, a hidden key gets none, and a pref update on the same
// unconfirmed address saves without another email while the first link keeps working.
// Mock transport, synthetic keys, never the real mailer.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-confirm-test-'))
process.env.DB_PATH = join(tmpDir, 'confirm-test.db')
// This file tests the production rule, so the test-suite exception is off here.
process.env.MINGLE_ALLOW_RESERVED_EMAIL_DOMAINS = '0'

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const email = await import('../src/notifications.js')
const notifyDb = await import('../src/notify-db.js')
const mod = await import('../src/moderation.js')
const { isReservedDomain } = await import('../src/confirm-guard.js')

let server: Server
let base: string
const sent: { to: string; subject: string; text: string }[] = []
before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { email.resetTransport(); server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => {
  sent.length = 0
  email.setTransport(async (e) => { sent.push(e); return { ok: true, id: 'mock' } })
  db.getDb().prepare('DELETE FROM rate_limits').run()
})

type Keys = { publicKey: string; privateKey: string }
async function subscribe(keys: Keys, addr: string, prefs?: Record<string, boolean>) {
  const nonce = `n-${Math.random().toString(16).slice(2)}`
  const r = await fetch(`${base}/api/v3/notifications/subscribe`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject_key: keys.publicKey, email: addr, nonce, signature: sign(`${addr}:${nonce}`, keys.privateKey), prefs }),
  })
  return { status: r.status, body: await r.json() }
}

test('reserved test domains never get a confirmation and nothing is stored', async () => {
  for (const a of ['flora@duinrand.example', 'probe@example.org', 'x@example.com', 'y@sub.example.net', 'z@host.test', 'w@a.invalid', 'v@localhost']) {
    assert.equal(isReservedDomain(a), true, a)
  }
  for (const a of ['tima@aeoess.com', 'someone@gmail.com', 'data@provincie-noordholland.nl', 'me@notexample.com']) {
    assert.equal(isReservedDomain(a), false, a)
  }
  const k = generateKeyPair()
  const r = await subscribe(k, 'records@havenlicht.example')
  assert.equal(r.status, 429, JSON.stringify(r.body))
  assert.match(r.body.error, /reserved test domain/)
  assert.equal(sent.length, 0)
  assert.equal(notifyDb.getSubscription(k.publicKey), null)
})

test('a person confirming their own address works, and can ask once more', async () => {
  const k = generateKeyPair()
  const first = await subscribe(k, 'person@mingle-test.org')
  assert.equal(first.status, 201); assert.equal(first.body.confirmation_sent, true)
  const again = await subscribe(k, 'person@mingle-test.org')
  assert.equal(again.status, 201); assert.equal(again.body.confirmation_sent, true, 'one retry, for a mail that went to spam')
  assert.equal(sent.length, 2)
})

test('one address gets at most 2 confirmations a day, whoever asks', async () => {
  const victim = 'someone-else@mingle-test.org'
  assert.equal((await subscribe(generateKeyPair(), victim)).status, 201)
  assert.equal((await subscribe(generateKeyPair(), victim)).status, 201)
  const third = await subscribe(generateKeyPair(), victim)
  assert.equal(third.status, 429, JSON.stringify(third.body))
  assert.equal(sent.filter(e => e.to === victim).length, 2)
})

test('one key can name at most 3 different addresses a day', async () => {
  const k = generateKeyPair()
  for (let i = 0; i < 3; i++) assert.equal((await subscribe(k, `rotate${i}@mingle-test.org`)).status, 201, `address ${i}`)
  const fourth = await subscribe(k, 'rotate3@mingle-test.org')
  assert.equal(fourth.status, 429, JSON.stringify(fourth.body))
  assert.match(fourth.body.error, /at most 3 different addresses/)
  assert.equal(sent.length, 3)
})

test('a pref update on the same unconfirmed address saves without another email, and the first link still works', async () => {
  const k = generateKeyPair()
  const addr = 'prefs@mingle-test.org'
  await subscribe(k, addr); await subscribe(k, addr)
  const tokenBefore = notifyDb.getSubscription(k.publicKey)!.verify_token
  const upd = await subscribe(k, addr, { weekly_digest: true })
  assert.equal(upd.status, 201, JSON.stringify(upd.body))
  assert.equal(upd.body.confirmation_sent, false)
  assert.equal(upd.body.prefs.weekly_digest, true)
  assert.equal(sent.length, 2, 'no third email')
  assert.equal(notifyDb.getSubscription(k.publicKey)!.verify_token, tokenBefore, 'the link already sent stays valid')
  const confirm = await fetch(`${base}/api/v3/notifications/confirm/${tokenBefore}`)
  assert.equal(confirm.status, 200)
  assert.equal(notifyDb.getSubscription(k.publicKey)!.verified, true)
})

test('a key hidden by the operator cannot sign up for email', async () => {
  const k = generateKeyPair()
  mod.hideFromNetwork('subject', k.publicKey, 'test', 'operator-test')
  const r = await subscribe(k, 'hidden@mingle-test.org')
  assert.equal(r.status, 403, JSON.stringify(r.body))
  assert.equal(sent.length, 0)
})
