// Per key and address limits for intro inbox reads, intro requests and email sign-up.
// Each person on a shared address gets their own allowance, naming someone else's key
// from another address cannot spend that person's allowance, and the address as a
// whole still has a flood cap.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-keyed-test-'))
process.env.DB_PATH = join(tmpDir, 'keyed-test.db')
const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { INTRO_MINE_LIMIT } = await import('../src/keyed-limits.js')

let server: Server
let base: string
before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => { db.getDb().prepare('DELETE FROM rate_limits').run() })

const from = (ip: string) => ({ 'X-Forwarded-For': `${ip}, 84.17.44.229` })
const inbox = async (key: string, h: Record<string, string>) =>
  (await fetch(`${base}/api/v3/intros/mine?public_key=${encodeURIComponent(key)}&nonce=n1&signature=bad`, { headers: h })).status
const run = async (key: string, h: Record<string, string>, n: number) => { const s: number[] = []; for (let i = 0; i < n; i++) s.push(await inbox(key, h)); return s }

test('people on one address each get their own inbox allowance', async () => {
  const venue = from('198.18.5.1')
  for (let p = 0; p < 3; p++) {
    const s = await run(generateKeyPair().publicKey, venue, INTRO_MINE_LIMIT.perKey)
    assert.equal(s.filter(x => x === 429).length, 0, `person ${p}`)
  }
})

test('one key at one address is limited, and naming that key from elsewhere does not spend its allowance', async () => {
  const victim = generateKeyPair().publicKey
  const attacker = from('198.18.5.2')
  const used = await run(victim, attacker, INTRO_MINE_LIMIT.perKey + 2)
  assert.equal(used.filter(x => x === 429).length, 2, 'the attacker hits the limit for its own address')
  const own = await run(victim, from('198.18.5.3'), 3)
  assert.equal(own.filter(x => x === 429).length, 0, 'the real owner, on their own address, is unaffected')
})

test('an address flooding with many keys still hits the address cap', async () => {
  const flood = from('198.18.5.4')
  const s: number[] = []
  for (let i = 0; i < INTRO_MINE_LIMIT.perSource + 5; i++) s.push(await inbox(generateKeyPair().publicKey, flood))
  assert.equal(s.filter(x => x === 429).length, 5)
})

test('security.txt names the security contact and has not expired', async () => {
  const r = await fetch(`${base}/.well-known/security.txt`)
  assert.equal(r.status, 200)
  const text = await r.text()
  assert.match(text, /^Contact: mailto:security@aeoess\.com$/m)
  const exp = Date.parse(text.match(/^Expires: (.+)$/m)![1])
  assert.ok(exp > Date.now() && exp - Date.now() < 366 * 86400000, 'RFC 9116 wants an expiry within a year')
})
