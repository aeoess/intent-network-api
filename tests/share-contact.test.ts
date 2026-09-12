// ══════════════════════════════════════════════════════════════
// share_contact, the release, and the private artifact
// ══════════════════════════════════════════════════════════════
// The action the lifecycle is built around, and the first private payload. What these
// tests are really about:
//
//   1  the contact is NEVER in the signed payload, so no copy of a signed payload is a
//      copy of the contact. Asserted by scanning the stored evidence row for the value.
//   2  the artifact verifies STANDALONE, all four checks, none of them needing a server
//      key, which is the property almost nothing in the repo satisfies today
//   3  the release is exactly once, and it rests on a primary key rather than on which
//      transaction observes both authorizations first
//   4  a mixed pair completes, each side recorded at its own strength, and no receipt
//      promotes the legacy half

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import type { Server } from 'node:http'
import Database from 'better-sqlite3'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-share-test-'))
const DB_FILE = join(tmpDir, 'share.db')
process.env.DB_PATH = DB_FILE
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'
delete process.env.MINGLE_FIT_ENABLED
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const env = await import('../src/write-envelope.js')
const facts = await import('../src/connection-facts.js')
const state = await import('../src/connection-state.js')
const introsDb = await import('../src/intros-db.js')
const artifacts = await import('../src/private-artifacts.js')
const evidence = await import('../src/write-evidence.js')
const email = await import('../src/notifications.js')
const notifyDb = await import('../src/notify-db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const { newNonce, jcs } = await import('../src/canonical-write.js')

let server: Server
let base: string
const sent: { to: string; subject: string; text: string }[] = []
let mailerThrows = false

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { email.resetTransport(); server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => {
  db.getDb().prepare('DELETE FROM rate_limits').run()
  sent.length = 0
  mailerThrows = false
  email.setTransport(async e => {
    if (mailerThrows) throw new Error('mail transport is down')
    sent.push(e)
    return { ok: true, id: 'mock' }
  })
})

// ── Fixtures ──────────────────────────────────────────────────────────────

function makeCard(headline: string): any {
  const keys = generateKeyPair()
  const now = Date.now()
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(now).toISOString(), expires_at: new Date(now + 21 * 864e5).toISOString(),
    headline, intents: ['collaborate'],
    seeking: [{ description: 'x' }], offering: [{ description: 'y', provenance: 'principal_statement' }],
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

async function publish(built: any): Promise<string> {
  const r = await (await fetch(`${base}/api/v3/cards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card: built.card }),
  })).json()
  assert.ok(r.card_id, `publish failed: ${JSON.stringify(r)}`)
  return r.card_id
}

async function subscribeVerified(keys: any, addr: string): Promise<void> {
  const nonce = 's' + randomBytes(4).toString('hex')
  await fetch(`${base}/api/v3/notifications/subscribe`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject_key: keys.publicKey, email: addr, nonce, signature: sign(`${addr}:${nonce}`, keys.privateKey) }),
  })
  await fetch(`${base}/api/v3/notifications/confirm/${notifyDb.getSubscription(keys.publicKey)!.verify_token}`)
}

async function post(path: string, body: unknown) {
  const res = await fetch(`${base}/api/v3/intros/${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  let json: any = null
  try { json = await res.json() } catch { /* none */ }
  return { status: res.status, json }
}

function signedBody(over: { operation: string; resource: any; payload?: any; keys: any; nonce?: string; opening?: any }) {
  const payload = over.payload ?? {}
  const built = env.buildEnvelope({
    operation: over.operation as any, actorKey: over.keys.publicKey, resource: over.resource,
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
    nonce: over.nonce ?? newNonce(), payload,
  })
  const body: Record<string, unknown> = {
    envelope: built.envelope, signature: sign(jcs(built.envelope), over.keys.privateKey), payload,
  }
  if (over.opening !== undefined) body.opening = over.opening
  return { body, built }
}

interface Live { introId: string; from: any; to: any; fromCard: string; toCard: string }

/** A canonical intro in `interested`: canonical request, canonical express_interest. */
async function interested(): Promise<Live> {
  const from = makeCard('requester ' + randomBytes(3).toString('hex'))
  const to = makeCard('target ' + randomBytes(3).toString('hex'))
  const fromCard = await publish(from)
  const toCard = await publish(to)
  const requestId = randomBytes(16).toString('hex')
  const req = await post('request', signedBody({
    operation: 'request_intro', resource: { type: 'intro_request', id: requestId },
    payload: { from_card: fromCard, to_card: toCard, purpose: 'collaborate', note: 'hello there' },
    keys: from.keys,
  }).body)
  assert.equal(req.status, 201, JSON.stringify(req.json))
  const introId = req.json.intro_id
  const interest = await post(`${introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: to.keys,
  }).body)
  assert.equal(interest.status, 201, JSON.stringify(interest.json))
  return { introId, from, to, fromCard, toCard }
}

/** A signed share_contact, with the commitment and the opening built the decided way. */
function shareBody(introId: string, keys: any, contact: string, over: { salt?: string; openingValue?: unknown; nonce?: string; omitOpening?: boolean } = {}) {
  const resource = { type: 'intro' as const, id: introId }
  const salt = over.salt ?? randomBytes(32).toString('base64url')
  const commitment = env.privateValueCommitment('share_contact', resource, salt, contact)
  const s = signedBody({
    operation: 'share_contact', resource, payload: { private_value_commitment: commitment },
    keys, nonce: over.nonce,
    opening: over.omitOpening ? undefined : { value: over.openingValue ?? contact, salt },
  })
  return { ...s, salt, commitment }
}

async function share(introId: string, keys: any, contact: string, over: Parameters<typeof shareBody>[3] = {}) {
  const s = shareBody(introId, keys, contact, over)
  return { ...(await post('share-contact', s.body)), built: s.built, salt: s.salt, commitment: s.commitment, body: s.body }
}

function introRow(id: string): any {
  return db.getDb().prepare('SELECT * FROM v3_intros WHERE id = ?').get(id)
}
function releaseRows(id: string): any[] {
  return db.getDb().prepare('SELECT * FROM connection_release WHERE intro_id = ?').all(id)
}
function artifactRows(id: string): any[] {
  return db.getDb().prepare('SELECT * FROM private_artifacts WHERE intro_id = ? ORDER BY created_at').all(id)
}

// ══════════════════════════════════════════════════════════════
// The first share, the second share, the release
// ══════════════════════════════════════════════════════════════

test('SHARE: the first share derives connecting, writes no release, and discloses nothing to the counterparty', async () => {
  const L = await interested()
  const r = await share(L.introId, L.from.keys, 'alice@example.com')
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.state, 'connecting')
  assert.equal(r.json.released, false)
  assert.equal(r.json.shared_by, 'requester')
  assert.equal(releaseRows(L.introId).length, 0)

  const row = introRow(L.introId)
  assert.equal(row.from_contact, 'alice@example.com', 'the sharer\'s own column')
  assert.equal(row.to_contact, null, 'and nothing on the other side')
  assert.equal(introsDb.isComplete(introsDb.getIntro(L.introId)!), false,
    'isComplete needs BOTH columns, so one share is never enough')

  // The counterparty's read surface shows nothing, because complete is false.
  const nonce = 'm' + randomBytes(4).toString('hex')
  const qs = new URLSearchParams({
    public_key: L.to.keys.publicKey, nonce, signature: sign(`intro-mine:${nonce}`, L.to.keys.privateKey),
  })
  const mine = await (await fetch(`${base}/api/v3/intros/mine?${qs}`)).json()
  const seen = mine.intros.find((x: any) => x.id === L.introId)
  assert.equal(seen.counterparty_contact, null, 'no contact reaches the counterparty before the release')
})

test('SHARE: the second share writes exactly one release row and derives connected', async () => {
  const L = await interested()
  await subscribeVerified(L.from.keys, 'req@example.com')
  await subscribeVerified(L.to.keys, 'tgt@example.com')

  assert.equal((await share(L.introId, L.from.keys, 'alice@example.com')).status, 201)
  const second = await share(L.introId, L.to.keys, 'bob@example.com')
  assert.equal(second.status, 201, JSON.stringify(second.json))
  assert.equal(second.json.released, true)
  assert.equal(second.json.state, 'connected')

  const rows = releaseRows(L.introId)
  assert.equal(rows.length, 1)
  assert.ok(rows[0].a_write_ref, 'the release names the requester\'s act')
  assert.ok(rows[0].b_write_ref, 'and the target\'s')
  assert.notEqual(rows[0].a_write_ref, rows[0].b_write_ref)

  assert.equal(facts.stateOf(L.introId), 'connected')
  assert.equal(introRow(L.introId).status, 'accepted', 'connected materializes accepted')
  assert.equal(introsDb.isComplete(introsDb.getIntro(L.introId)!), true,
    'all three isComplete terms now hold, which is what makes connected legible to an old client')

  // Both parties see the other's line, and neither sees anything a third party could.
  for (const [who, expected] of [[L.from, 'bob@example.com'], [L.to, 'alice@example.com']] as const) {
    const nonce = 'm' + randomBytes(4).toString('hex')
    const qs = new URLSearchParams({
      public_key: who.keys.publicKey, nonce, signature: sign(`intro-mine:${nonce}`, who.keys.privateKey),
    })
    const mine = await (await fetch(`${base}/api/v3/intros/mine?${qs}`)).json()
    assert.equal(mine.intros.find((x: any) => x.id === L.introId).counterparty_contact, expected)
  }
})

test('SHARE: the two release emails are attempted once each', async () => {
  const L = await interested()
  await subscribeVerified(L.from.keys, 'req2@example.com')
  await subscribeVerified(L.to.keys, 'tgt2@example.com')
  await share(L.introId, L.from.keys, 'alice2@example.com')
  sent.length = 0
  const second = await share(L.introId, L.to.keys, 'bob2@example.com')
  assert.equal(second.json.released, true)
  await new Promise(r => setTimeout(r, 60))

  const completed = sent.filter(e => e.subject === 'Your Mingle connection is complete')
  assert.equal(completed.length, 2, 'one each, and not two to one side')
  const addrs = completed.map(e => e.to).sort()
  assert.deepEqual(addrs, ['req2@example.com', 'tgt2@example.com'])
  assert.ok(completed.find(e => e.to === 'req2@example.com')!.text.includes('bob2@example.com'))
  assert.ok(completed.find(e => e.to === 'tgt2@example.com')!.text.includes('alice2@example.com'))
})

test('SHARE: a thrown mailer does not roll back the release', async () => {
  const L = await interested()
  await subscribeVerified(L.from.keys, 'req3@example.com')
  await subscribeVerified(L.to.keys, 'tgt3@example.com')
  await share(L.introId, L.from.keys, 'alice3@example.com')
  mailerThrows = true
  const second = await share(L.introId, L.to.keys, 'bob3@example.com')
  assert.equal(second.status, 201, 'the write committed before the mail was attempted')
  assert.equal(second.json.released, true)
  await new Promise(r => setTimeout(r, 60))
  assert.equal(releaseRows(L.introId).length, 1, 'the durable fact survives a lost email')
  assert.equal(facts.stateOf(L.introId), 'connected')
})

test('SHARE: a third share attempt is refused and writes no second release row', async () => {
  const L = await interested()
  await share(L.introId, L.from.keys, 'alice4@example.com')
  await share(L.introId, L.to.keys, 'bob4@example.com')
  assert.equal(releaseRows(L.introId).length, 1)

  const third = await share(L.introId, L.from.keys, 'alice-again@example.com')
  assert.equal(third.status, 409, JSON.stringify(third.json))
  // wrong_state rather than intro_terminal: `connected` is deliberately NOT a terminal
  // state, because block_pair and the continuations stay available on a live connection.
  // What refuses this is the matrix cell, share_contact applying only in interested and
  // connecting, and the message names the state so the answer is actionable.
  assert.equal(third.json.code, 'wrong_state', JSON.stringify(third.json))
  assert.equal(third.json.error, 'share_contact does not apply to an introduction that is connected')
  assert.equal(state.isTerminalState('connected'), false)
  assert.equal(releaseRows(L.introId).length, 1)
  assert.equal(introRow(L.introId).from_contact, 'alice4@example.com', 'and the stored line did not change')
})

test('SHARE: a byte identical resend returns the stored result and does not release twice', async () => {
  const L = await interested()
  await share(L.introId, L.from.keys, 'alice5@example.com')
  const s = shareBody(L.introId, L.to.keys, 'bob5@example.com')
  const first = await post('share-contact', s.body)
  assert.equal(first.status, 201)
  assert.equal(first.json.released, true)
  const again = await post('share-contact', s.body)
  assert.equal(again.status, 200)
  assert.equal(again.json.idempotent, true)
  assert.equal(again.json.released, true, 'the stored answer, which said released')
  assert.equal(releaseRows(L.introId).length, 1)
  assert.equal(artifactRows(L.introId).length, 2, 'and no third artifact')
})

test('SHARE: concurrent second shares, exactly one release row, and the loser still commits its authorization', async () => {
  // Inside one process better-sqlite3 is synchronous, so the race is only reachable with a
  // second connection. The property being demonstrated is that exactly-once rests on the
  // primary key and NOT on which transaction observes both authorizations first.
  const L = await interested()
  await share(L.introId, L.from.keys, 'alice6@example.com')
  await share(L.introId, L.to.keys, 'bob6@example.com')
  assert.equal(releaseRows(L.introId).length, 1)

  // Now drive the claim itself from two connections on a fresh intro, both believing they
  // observed two live authorizations.
  const M = await interested()
  await share(M.introId, M.from.keys, 'carol@example.com')
  const d = db.getDb()
  d.prepare(`INSERT INTO connection_authorizations (intro_id, actor_key, operation, subject, evidence_id, evidence)
             VALUES (?, ?, 'share_contact', '', 'ev-race', 'canonical')`).run(M.introId, M.to.keys.publicKey)
  const other = new Database(DB_FILE)
  try {
    const claim = (conn: any) => {
      try { conn.prepare('INSERT INTO connection_release (intro_id) VALUES (?)').run(M.introId); return true } catch { return false }
    }
    assert.equal(claim(d), true, 'the first claim wins')
    assert.equal(claim(other), false, 'and the second is refused by the primary key, not by a read')
    assert.equal(releaseRows(M.introId).length, 1)
    // The loser's own authorization is untouched, which is what "still commits its own
    // authorization" means: the conflict is caught, not propagated.
    const auths = db.getDb().prepare(
      "SELECT COUNT(*) AS n FROM connection_authorizations WHERE intro_id = ? AND operation = 'share_contact' AND live = 1",
    ).get(M.introId) as any
    assert.equal(auths.n, 2)
  } finally { other.close() }
})

// ══════════════════════════════════════════════════════════════
// withdraw_contact against the release
// ══════════════════════════════════════════════════════════════

test('SHARE: withdraw_contact after the release is 409 contact_already_released', async () => {
  const L = await interested()
  await share(L.introId, L.from.keys, 'alice7@example.com')
  await share(L.introId, L.to.keys, 'bob7@example.com')
  const r = await post('withdraw-contact', signedBody({
    operation: 'withdraw_contact', resource: { type: 'intro', id: L.introId }, keys: L.from.keys,
  }).body)
  assert.equal(r.status, 409)
  assert.equal(r.json.code, 'contact_already_released')
  assert.equal(introRow(L.introId).from_contact, 'alice7@example.com', 'nothing was unshared')
  assert.equal(artifactRows(L.introId).filter(a => a.withdrawn === 1).length, 0)
})

test('SHARE: withdraw_contact before the release removes only the caller\'s authorization and artifact', async () => {
  const L = await interested()
  await share(L.introId, L.from.keys, 'alice8@example.com')
  await share(L.introId, L.to.keys, 'bob8@example.com', { nonce: newNonce() })
  // Undo the release so this is the pre-release case with both sides having shared.
  db.getDb().prepare('DELETE FROM connection_release WHERE intro_id = ?').run(L.introId)

  const r = await post('withdraw-contact', signedBody({
    operation: 'withdraw_contact', resource: { type: 'intro', id: L.introId }, keys: L.from.keys,
  }).body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.artifacts_withdrawn, 1)

  const row = introRow(L.introId)
  assert.equal(row.from_contact, null, 'the caller\'s line is gone')
  assert.equal(row.to_contact, 'bob8@example.com', 'and the counterparty\'s stored contact is untouched')

  const mine = artifactRows(L.introId).filter(a => a.author_key === L.from.keys.publicKey)
  const theirs = artifactRows(L.introId).filter(a => a.author_key === L.to.keys.publicKey)
  assert.equal(mine[0].withdrawn, 1)
  assert.equal(theirs[0].withdrawn, 0, 'a withdrawal never reaches across')
  assert.equal(facts.stateOf(L.introId), 'connecting', 'the counterparty\'s share is still a live continuation')
})

test('SHARE: share, withdraw, share again succeeds, which a plain insert would have made impossible', async () => {
  const L = await interested()
  await share(L.introId, L.from.keys, 'first@example.com')
  assert.equal((await post('withdraw-contact', signedBody({
    operation: 'withdraw_contact', resource: { type: 'intro', id: L.introId }, keys: L.from.keys,
  }).body)).status, 201)

  const again = await share(L.introId, L.from.keys, 'second@example.com')
  assert.equal(again.status, 201, JSON.stringify(again.json))
  assert.equal(introRow(L.introId).from_contact, 'second@example.com', 'the new line, which may differ')

  const rows = artifactRows(L.introId).filter(a => a.author_key === L.from.keys.publicKey)
  assert.equal(rows.length, 2, 'the earlier artifact stays, marked withdrawn, so the sequence is legible')
  assert.equal(rows.filter(a => a.withdrawn === 1).length, 1)
  const evidenceCount = (db.getDb().prepare(
    "SELECT COUNT(*) AS n FROM write_evidence WHERE resource_id = ? AND operation = 'share_contact' AND actor_key = ?",
  ).get(L.introId, L.from.keys.publicKey) as any).n
  assert.equal(evidenceCount, 2, 'and both envelopes remain in write_evidence, which is append only')
})

// ══════════════════════════════════════════════════════════════
// The contact validation set
// ══════════════════════════════════════════════════════════════

test('SHARE: every rejected contact shape is refused with its own reason and stores nothing', async () => {
  const L = await interested()
  const before = {
    artifacts: artifactRows(L.introId).length,
    nonces: (db.getDb().prepare('SELECT COUNT(*) AS n FROM write_nonces').get() as any).n,
  }
  const cases: [string, string, string][] = [
    ['empty', '', 'contact_empty'],
    ['whitespace only', '   ', 'edge_whitespace'],
    ['leading space', ' alice@example.com', 'edge_whitespace'],
    ['trailing space', 'alice@example.com ', 'edge_whitespace'],
    ['201 characters', 'a'.repeat(201), 'contact_too_long'],
    ['a raw newline', 'alice@example.com\nBcc: someone', 'control_character'],
    ['a raw NUL', 'alice' + String.fromCharCode(0) + '@example.com', 'control_character'],
    ['a DEL', 'alice' + String.fromCharCode(0x7f) + '@example.com', 'control_character'],
  ]
  for (const [label, contact, code] of cases) {
    const r = await share(L.introId, L.from.keys, contact)
    assert.equal(r.status, 400, `${label}: ${JSON.stringify(r.json)}`)
    assert.equal(r.json.code, code, label)
  }
  assert.equal(artifactRows(L.introId).length, before.artifacts, 'no artifact')
  assert.equal((db.getDb().prepare('SELECT COUNT(*) AS n FROM write_nonces').get() as any).n, before.nonces,
    'and no nonce, so none of these cost the caller anything')
  assert.equal(introRow(L.introId).from_contact, null)

  // Exactly 200 is accepted, which pins the boundary rather than the direction.
  const ok = await share(L.introId, L.from.keys, 'b'.repeat(200))
  assert.equal(ok.status, 201)
  assert.equal(introRow(L.introId).from_contact, 'b'.repeat(200),
    'measured on the string as sent, and stored as sent: no trim, so no 201-with-a-space stored as 199')
})

// ══════════════════════════════════════════════════════════════
// The commitment, the opening, and what evidence holds
// ══════════════════════════════════════════════════════════════

test('COMMITMENT: a swapped value and a swapped salt are each refused with commitment_mismatch, before any write', async () => {
  const L = await interested()
  const before = artifactRows(L.introId).length

  const salt = randomBytes(32).toString('base64url')
  const swappedValue = await share(L.introId, L.from.keys, 'alice@example.com', {
    salt, openingValue: 'attacker@evil.example',
  })
  assert.equal(swappedValue.status, 400)
  assert.equal(swappedValue.json.code, 'commitment_mismatch',
    'a proxy that rewrites the value is caught before any write')

  // The true value with a different salt: the commitment in the payload was built with the
  // real salt, so recomputing with another one cannot reach it.
  const s = shareBody(L.introId, L.from.keys, 'alice@example.com', { salt })
  const wrongSalt = { ...s.body, opening: { value: 'alice@example.com', salt: randomBytes(32).toString('base64url') } }
  const r2 = await post('share-contact', wrongSalt)
  assert.equal(r2.status, 400)
  assert.equal(r2.json.code, 'commitment_mismatch')

  assert.equal(artifactRows(L.introId).length, before, 'and nothing was written on either path')
  assert.equal(introRow(L.introId).from_contact, null)
})

test('COMMITMENT: a missing opening and an opening where none belongs are each refused', async () => {
  const L = await interested()
  const missing = await share(L.introId, L.from.keys, 'alice@example.com', { omitOpening: true })
  assert.equal(missing.status, 400)
  assert.equal(missing.json.code, 'missing_opening')

  const unexpected = await post(`${L.introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: L.introId }, keys: L.to.keys,
    opening: { value: 'x', salt: randomBytes(32).toString('base64url') },
  }).body)
  assert.equal(unexpected.status, 400)
  assert.equal(unexpected.json.code, 'unexpected_opening')
})

test('COMMITMENT: the same value and salt under a different operation or intro gives a different commitment', async () => {
  const salt = randomBytes(32).toString('base64url')
  const value = 'alice@example.com'
  const here = { type: 'intro' as const, id: 'intro-v3-aaa' }
  const elsewhere = { type: 'intro' as const, id: 'intro-v3-bbb' }
  const a = env.privateValueCommitment('share_contact', here, salt, value)
  const b = env.privateValueCommitment('release_exact', here, salt, value)
  const c = env.privateValueCommitment('share_contact', elsewhere, salt, value)
  assert.notEqual(a, b, 'operation is inside the commitment preimage')
  assert.notEqual(a, c, 'and so is the resource')
  assert.notEqual(b, c)
  // So an artifact cannot be lifted between acts, independently of the envelope's binding.
  assert.equal(new Set([a, b, c]).size, 3)
})

test('EVIDENCE: the signed payload stored in write_evidence contains no contact string anywhere', async () => {
  // The test that the commitment construction actually keeps the value out of evidence.
  // It scans the whole stored row rather than the field it expects, because the point is
  // that NO column holds it.
  const L = await interested()
  const contact = 'very-distinctive-address-9f3a@example.com'
  const r = await share(L.introId, L.from.keys, contact)
  assert.equal(r.status, 201)

  const row = db.getDb().prepare('SELECT * FROM write_evidence WHERE write_ref = ?').get(r.built.writeRef) as any
  const blob = JSON.stringify(row)
  assert.equal(blob.includes(contact), false, 'the evidence row holds a commitment and no value')
  assert.equal(blob.includes(r.salt), false, 'and no salt, which is what makes the commitment non invertible')
  assert.equal(JSON.parse(row.envelope_json).payload_digest, row.payload_digest)
  assert.deepEqual(JSON.parse(row.bound_fields_json),
    ['operation', 'resource.id', 'payload.private_value_commitment'],
    'and the bound list names the commitment, never the contact')

  // The value lives in exactly one place, and that place is named as such.
  const art = artifactRows(L.introId)[0]
  assert.equal(JSON.parse(art.opening_json).value, contact)
  assert.equal(art.payload_json.includes(contact), false)
  // THE LIMIT, stated: the server holds the line in plain text. This is not end to end
  // encryption, and the test says so rather than letting the shape imply otherwise.
  assert.ok(art.opening_json.includes(contact))
})

test('EVIDENCE: the stored contact reproduces the commitment the principal signed', async () => {
  const L = await interested()
  const contact = 'byte-identical@example.com'
  const r = await share(L.introId, L.from.keys, contact)
  assert.equal(r.status, 201)

  const stored = introRow(L.introId).from_contact
  const art = artifactRows(L.introId)[0]
  const rebuilt = env.privateValueCommitment(
    'share_contact', { type: 'intro', id: L.introId },
    JSON.parse(art.opening_json).salt, stored,
  )
  assert.equal(rebuilt, r.commitment,
    'the column, the salt on disk and the signed commitment are one consistent set')
  assert.equal(rebuilt, JSON.parse(art.payload_json).private_value_commitment)
})

// ══════════════════════════════════════════════════════════════
// The artifact verifies standalone, and only two keys may read it
// ══════════════════════════════════════════════════════════════

test('ARTIFACT: the recipient verifies all four checks alone, with no server key', async () => {
  const L = await interested()
  const contact = 'standalone@example.com'
  assert.equal((await share(L.introId, L.from.keys, contact)).status, 201)

  const read = artifacts.readArtifact(artifactRows(L.introId)[0].artifact_id, L.to.keys.publicKey)
  assert.equal(read.ok, true, 'the recipient may read it')
  const standalone = artifacts.standaloneFrom((read as any).artifact)
  const author = L.from.keys.publicKey
  const v = artifacts.verifyArtifactStandalone(standalone, L.introId, author)
  assert.deepEqual(v, {
    ok: true, signature_verifies: true, payload_digest_matches: true,
    commitment_opens: true, resource_is_expected: true,
    author_is_expected: true, envelope_is_well_formed: true,
  }, 'six checks, and none of them touches the server key')
  assert.equal(standalone.opening.value, contact)

  // Each check fails on its own when its input is broken, so `ok` is not carried by one.
  const badSig = artifacts.verifyArtifactStandalone({ ...standalone, signature: 'ab'.repeat(64) }, L.introId, author)
  assert.equal(badSig.signature_verifies, false)
  assert.equal(badSig.ok, false)

  const badPayload = artifacts.verifyArtifactStandalone(
    { ...standalone, payload: { private_value_commitment: 'a'.repeat(64) } }, L.introId, author)
  assert.equal(badPayload.payload_digest_matches, false)
  assert.equal(badPayload.commitment_opens, false)

  const badOpening = artifacts.verifyArtifactStandalone(
    { ...standalone, opening: { value: 'someone-else@example.com', salt: standalone.opening.salt } }, L.introId, author)
  assert.equal(badOpening.signature_verifies, true, 'a signed act still happened')
  assert.equal(badOpening.payload_digest_matches, true)
  assert.equal(badOpening.commitment_opens, false,
    'which is exactly what step 3 adds: without it the recipient could not tell that the value it received is the value authorized')

  const wrongIntro = artifacts.verifyArtifactStandalone(standalone, 'intro-v3-someone-elses', author)
  assert.equal(wrongIntro.resource_is_expected, false)
  assert.equal(wrongIntro.ok, false)

  // THE CHECK A REVIEW ADDED. A stranger builds their own share_contact envelope over this
  // reader's intro id, commits to a value of their choosing, signs it with their OWN key and
  // hands it over. Every arithmetic check passes, because the forgery is internally
  // consistent. Only the author check says whose authorization it is.
  const mallory = generateKeyPair()
  const forgedSalt = randomBytes(32).toString('base64url')
  const forgedRes = { type: 'intro' as const, id: L.introId }
  const forgedCommitment = env.privateValueCommitment('share_contact', forgedRes, forgedSalt, 'mallory@evil.example')
  const forgedBuilt = env.buildEnvelope({
    operation: 'share_contact', actorKey: mallory.publicKey, resource: forgedRes,
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'), nonce: newNonce(),
    payload: { private_value_commitment: forgedCommitment },
  })
  const forged = {
    envelope: forgedBuilt.envelope,
    signature: sign(forgedBuilt.envelopeBytes, mallory.privateKey),
    payload: { private_value_commitment: forgedCommitment },
    opening: { value: 'mallory@evil.example', salt: forgedSalt },
  }
  const forgedResult = artifacts.verifyArtifactStandalone(forged, L.introId, author)
  assert.equal(forgedResult.signature_verifies, true, 'the forgery is internally consistent')
  assert.equal(forgedResult.payload_digest_matches, true)
  assert.equal(forgedResult.commitment_opens, true)
  assert.equal(forgedResult.resource_is_expected, true)
  assert.equal(forgedResult.author_is_expected, false, 'and this is the only check that catches it')
  assert.equal(forgedResult.ok, false)

  // And the two envelope rules the server applies, applied here too: a verifier weaker than
  // the server endorses what the server would refuse.
  const wrongDomain = artifacts.verifyArtifactStandalone(
    { ...standalone, envelope: { ...standalone.envelope, domain: 'some-other-protocol-v9' as any } }, L.introId, author)
  assert.equal(wrongDomain.envelope_is_well_formed, false)
  assert.equal(wrongDomain.ok, false)
  const extraField = artifacts.verifyArtifactStandalone(
    { ...standalone, envelope: { ...standalone.envelope, scope: 'read-only-do-not-honour' } as any }, L.introId, author)
  assert.equal(extraField.envelope_is_well_formed, false,
    'an extra signed field may narrow authority, and the server refuses one for exactly that reason')
  assert.equal(extraField.ok, false)
})

test('ARTIFACT: only the author and the recipient may read it, and a party to another intro may not', async () => {
  const L = await interested()
  assert.equal((await share(L.introId, L.from.keys, 'private@example.com')).status, 201)
  const id = artifactRows(L.introId)[0].artifact_id

  assert.equal(artifacts.readArtifact(id, L.from.keys.publicKey).ok, true, 'the author')
  assert.equal(artifacts.readArtifact(id, L.to.keys.publicKey).ok, true, 'and the recipient')

  // The negative case that is easy to forget: a real Mingle user with intros of their own,
  // which says nothing about this one.
  const stranger = await interested()
  const refused = artifacts.readArtifact(id, stranger.from.keys.publicKey)
  assert.equal(refused.ok, false)
  assert.equal((refused as any).code, 'artifact_unavailable')
  assert.equal(artifacts.readArtifact(id, generateKeyPair().publicKey).ok, false, 'and neither may a key with no intros')
  const missing = artifacts.readArtifact('pa_does_not_exist', L.to.keys.publicKey)
  assert.equal(missing.ok, false)
  // ONE answer for both, so a caller holding a guessed id cannot tell a real one from a
  // fabricated one by comparing refusals. The codes used to differ while the comment claimed
  // they did not.
  assert.deepEqual(refused, missing, 'not an existence oracle')
})

test('ARTIFACT: a withdrawn artifact is no longer readable', async () => {
  const L = await interested()
  assert.equal((await share(L.introId, L.from.keys, 'withdrawn@example.com')).status, 201)
  const id = artifactRows(L.introId)[0].artifact_id
  assert.equal(artifacts.readArtifact(id, L.to.keys.publicKey).ok, true)

  assert.equal((await post('withdraw-contact', signedBody({
    operation: 'withdraw_contact', resource: { type: 'intro', id: L.introId }, keys: L.from.keys,
  }).body)).status, 201)
  const after = artifacts.readArtifact(id, L.to.keys.publicKey)
  assert.equal(after.ok, false)
  assert.equal((after as any).code, 'artifact_withdrawn')
  assert.equal(artifacts.liveArtifactOf(L.introId, L.from.keys.publicKey, 'share_contact'), null)
})

// ══════════════════════════════════════════════════════════════
// A mixed pair completes
// ══════════════════════════════════════════════════════════════

test('MIXED: a canonical target and a legacy requester reach connected, each recorded at its own strength', async () => {
  const L = await interested()
  await subscribeVerified(L.from.keys, 'mixreq@example.com')
  await subscribeVerified(L.to.keys, 'mixtgt@example.com')
  // The target shares canonically.
  assert.equal((await share(L.introId, L.to.keys, 'canonical-target@example.com')).status, 201)
  assert.equal(facts.stateOf(L.introId), 'connecting')

  // The requester completes with the published 3.2.x shape. It never sent a canonical
  // envelope, so anti-downgrade has nothing to refuse: the intro was created canonically by
  // this same key, which IS a downgrade, so this pair cannot actually mix that way. Prove
  // that first, then build the mixable pair.
  const nonce = 'c' + randomBytes(4).toString('hex')
  const blocked = await fetch(`${base}/api/v3/intros/${L.introId}/complete`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contact: 'legacy-requester@example.com', public_key: L.from.keys.publicKey, nonce,
      signature: sign(`intro-complete:${L.introId}:${nonce}`, L.from.keys.privateKey),
    }),
  })
  assert.equal(blocked.status, 426, 'a key that created canonically cannot fall back on the intro it created')
  assert.equal((await blocked.json()).code, 'client_upgrade_required')

  // A legacy requester from the start, with a canonical target.
  const from = makeCard('legacy requester')
  const to = makeCard('canonical target')
  const fromCard = await publish(from)
  const toCard = await publish(to)
  const rq = 'n' + randomBytes(4).toString('hex')
  const created = await (await fetch(`${base}/api/v3/intros/request`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from_card: fromCard, to_card: toCard, purpose: 'collaborate', note: 'old client',
      public_key: from.keys.publicKey, nonce: rq,
      signature: sign(`intro-request:${fromCard}:${toCard}:collaborate:${rq}`, from.keys.privateKey),
    }),
  })).json()
  const introId = created.id

  // The target answers and shares canonically.
  assert.equal((await post(`${introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: to.keys,
  }).body)).status, 201)
  assert.equal((await share(introId, to.keys, 'newclient@example.com')).status, 201)
  assert.equal(facts.stateOf(introId), 'connecting')

  // And the legacy requester completes, which releases.
  const cn = 'c' + randomBytes(4).toString('hex')
  const done = await (await fetch(`${base}/api/v3/intros/${introId}/complete`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contact: 'oldclient@example.com', public_key: from.keys.publicKey, nonce: cn,
      signature: sign(`intro-complete:${introId}:${cn}`, from.keys.privateKey),
    }),
  })).json()
  assert.equal(done.complete, true)
  assert.equal(done.released, true, 'a mixed pair completes')
  assert.equal(facts.stateOf(introId), 'connected')
  assert.equal(releaseRows(introId).length, 1)

  // The two evidence rows describe each side at its own strength.
  const rows = db.getDb().prepare(
    "SELECT * FROM write_evidence WHERE resource_id = ? AND operation = 'share_contact'").all(introId) as any[]
  assert.equal(rows.length, 2)
  const canonical = rows.find(r => r.evidence === 'canonical')!
  const legacy = rows.find(r => r.evidence === 'legacy_unbound')!
  assert.deepEqual(JSON.parse(canonical.bound_fields_json),
    ['operation', 'resource.id', 'payload.private_value_commitment'])
  assert.deepEqual(JSON.parse(legacy.bound_fields_json), ['id'],
    'intro-complete:${id}:${nonce} covers the id and nothing else')
  assert.equal(evidence.covers(legacy, 'contact'), false, 'so no receipt promotes the legacy half')
  assert.equal(evidence.covers(canonical, 'payload.private_value_commitment'), true)
  assert.equal(legacy.payload_digest, null)
  assert.equal(canonical.payload_digest !== null, true)

  // Only the canonical side has an artifact, because only a canonical act has an opening.
  const arts = artifactRows(introId)
  assert.equal(arts.length, 1)
  assert.equal(arts[0].author_key, to.keys.publicKey)
})

test('MIXED: the column and the derivation agree on every intro this suite touched', async () => {
  const rows = db.getDb().prepare('SELECT DISTINCT intro_id FROM connection_authorizations').all() as { intro_id: string }[]
  assert.ok(rows.length > 10, `the suite wrote facts, found ${rows.length}`)
  for (const { intro_id } of rows) {
    const f = facts.introFacts(intro_id)
    if (f === null) continue
    const derived = state.deriveIntroState(f)
    assert.equal(introRow(intro_id).status, state.materializedStatus(derived), `${intro_id} derives ${derived}`)
  }
})
