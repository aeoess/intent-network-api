// SCRATCH probe: does the hourly sweep damage the grandfathered pre-2A row?
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPair, sign } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'zz-probe-'))
process.env.DB_PATH = join(tmpDir, 'probe.db')
const kp = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = kp.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = kp.publicKey

const { createApp } = await import('./src/app.js')
const db = await import('./src/db.js')
const facts = await import('./src/connection-facts.js')
const introsDb = await import('./src/intros-db.js')

const app = createApp()
db.getDb()
introsDb.initIntrosSchema()
const server = app.listen(0, '127.0.0.1')
await new Promise<void>(r => server.once('listening', () => r()))
const base = `http://127.0.0.1:${(server.address() as any).port}`

const DAY = 24 * 3600 * 1000
const alice = generateKeyPair()
const bob = generateKeyPair()

// The grandfathered production row, exactly as the old semantics left it:
// created BEFORE mingle_2a_deployed_at, accepted with the target's contact,
// completed with the requester's contact, and ZERO rows in the write subsystem
// because the write subsystem did not exist when it was written.
const createdAt = new Date(Date.now() - 40 * DAY).toISOString().replace('Z', 'Z')
const introId = 'intro-v3-1750000000000-deadbeef'
db.getDb().prepare(`
  INSERT INTO v3_intros (id, from_card, to_card, from_key, to_key, purpose, note, status, created_at, responded_at, from_contact, to_contact)
  VALUES (?, 'card-a', 'card-b', ?, ?, 'collaborate', 'the one real intro', 'accepted', ?, ?, 'alice@telegram.example', 'bob@signal.example')
`).run(introId, alice.publicKey, bob.publicKey, createdAt, new Date(Date.now() - 39 * DAY).toISOString())

console.log('marker mingle_2a_deployed_at =', db.getSchemaMarker(db.MINGLE_2A_MARKER_KEY))
console.log('intro created_at            =', createdAt)
console.log('isPre2AIntro                =', facts.isPre2AIntro(introId))
console.log('authorization rows          =',
  (db.getDb().prepare('SELECT COUNT(*) AS n FROM connection_authorizations WHERE intro_id = ?').get(introId) as any).n)
console.log('derived state               =', facts.stateOf(introId))

async function mine(k: { publicKey: string; privateKey: string }) {
  const nonce = 'm' + Math.random().toString(36).slice(2)
  const qs = new URLSearchParams({ public_key: k.publicKey, nonce, signature: sign(`intro-mine:${nonce}`, k.privateKey) })
  const j: any = await (await fetch(`${base}/api/v3/intros/mine?${qs}`)).json()
  return j.intros[0]
}

const beforeA = await mine(alice)
console.log('\n--- GET /mine as the requester, BEFORE the sweep ---')
console.log({ status: beforeA.status, complete: beforeA.complete, counterparty_contact: beforeA.counterparty_contact })

// Exactly what server.ts:75 runs once an hour.
const swept = facts.sweepExpiredIntros()
console.log('\nsweepExpiredIntros() returned:', swept)
console.log('v3_intros.status is now      :',
  (db.getDb().prepare('SELECT status FROM v3_intros WHERE id = ?').get(introId) as any).status)

const afterA = await mine(alice)
const afterB = await mine(bob)
console.log('\n--- GET /mine, AFTER the sweep ---')
console.log('requester:', { status: afterA.status, complete: afterA.complete, counterparty_contact: afterA.counterparty_contact })
console.log('target   :', { status: afterB.status, complete: afterB.complete, counterparty_contact: afterB.counterparty_contact })

server.close()
db.closeDb()
rmSync(tmpDir, { recursive: true, force: true })
