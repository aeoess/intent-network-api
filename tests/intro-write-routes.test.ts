// ══════════════════════════════════════════════════════════════
// The four canonical actions with no legacy form, end to end
// ══════════════════════════════════════════════════════════════
// Real Ed25519 cards published through /api/v3/cards, a real intro created through
// the legacy /request route, then the canonical withdrawals and the block driven as
// signed mingle-write-v1 envelopes over HTTP.
//
// The canonical request_intro and express_interest routes land in the next step, so
// the authorizations those will write are seeded directly here. Seeding facts is not
// the same as inventing behavior: every assertion below is about what the canonical
// routes do with a fact set, and the fact set is exactly the row shape step 10 writes.
//
// Every fixture intro gets its OWN pair of fresh cards. hasPendingBetween at
// intros-db.ts:88-94 allows one pending intro per pair in either direction, so a
// shared pair would make the fixtures fight each other and the failure would look
// like a route bug.
//
// The read side assertions at the bottom are asserted against the SHAPE
// GET /api/v3/intros/mine returns, not against the published client, because the
// server owes a stable shape and not a particular client's rendering of it.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import Database from 'better-sqlite3'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-introwrite-test-'))
const DB_FILE = join(tmpDir, 'introwrite.db')
process.env.DB_PATH = DB_FILE
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'
// Fit stays off, which is the production setting. Nothing in this step touches fit.
delete process.env.MINGLE_FIT_ENABLED
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const wdb = await import('../src/write-db.js')
const env = await import('../src/write-envelope.js')
const facts = await import('../src/connection-facts.js')
const state = await import('../src/connection-state.js')
const introsDb = await import('../src/intros-db.js')
const routes = await import('../src/intro-write-routes.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const { newNonce, jcs } = await import('../src/canonical-write.js')

let server: Server
let base: string
/** An outsider who is never a party to anything, for the third party refusals. */
let OUT: any
let cardOut: string

before(async () => {
  const app = createApp()
  db.getDb()
  wdb.initWriteSchema()
  introsDb.initIntrosSchema()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
  OUT = makeCard('outsider headline')
  cardOut = await publish(OUT)
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => { db.getDb().prepare('DELETE FROM rate_limits').run() })

// ── Card and intro fixtures ───────────────────────────────────────────────

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

/** An intro through the legacy /request route, so from_key, to_key and created_at
 *  come from the real path rather than from a hand written row. */
async function legacyRequest(from: any, fromCard: string, toCard: string): Promise<{ status: number; json: any }> {
  const nonce = 'n' + Math.random().toString(36).slice(2)
  const purpose = 'collaborate'
  const res = await fetch(`${base}/api/v3/intros/request`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from_card: fromCard, to_card: toCard, purpose, note: 'hello',
      public_key: from.keys.publicKey, nonce,
      signature: sign(`intro-request:${fromCard}:${toCard}:${purpose}:${nonce}`, from.keys.privateKey),
    }),
  })
  return { status: res.status, json: await res.json().catch(() => null) }
}

function seedAuth(introId: string, actorKey: string, operation: string, opts: { subject?: string; live?: boolean; evidence?: string } = {}): void {
  db.getDb().prepare(`
    INSERT INTO connection_authorizations (intro_id, actor_key, operation, subject, evidence_id, evidence, live)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(intro_id, actor_key, operation, subject) DO UPDATE SET live = excluded.live
  `).run(introId, actorKey, operation, opts.subject ?? '', 'ev-seed-' + Math.random().toString(36).slice(2),
    opts.evidence ?? 'canonical', opts.live === false ? 0 : 1)
}

type Seeded = 'bare' | 'requested' | 'interested' | 'connecting' | 'connected'

interface Fixture {
  id: string
  from: any
  to: any
  fromCard: string
  toCard: string
}

/** A fresh card pair, a real intro, and the authorization rows for one shape. */
async function intro(shape: Seeded): Promise<Fixture> {
  const from = makeCard('requester ' + Math.random().toString(36).slice(2))
  const to = makeCard('target ' + Math.random().toString(36).slice(2))
  const fromCard = await publish(from)
  const toCard = await publish(to)
  const r = await legacyRequest(from, fromCard, toCard)
  assert.equal(r.status, 201, `fixture request failed: ${JSON.stringify(r.json)}`)
  const f: Fixture = { id: r.json.id as string, from, to, fromCard, toCard }
  if (shape === 'bare') return f

  seedAuth(f.id, from.keys.publicKey, 'request_intro')
  if (shape === 'requested') return f

  seedAuth(f.id, to.keys.publicKey, 'express_interest')
  if (shape === 'interested') {
    db.getDb().prepare("UPDATE v3_intros SET status = 'accepted' WHERE id = ?").run(f.id)
    return f
  }
  // connecting: the requester has shared a contact, which is one live continuation.
  seedAuth(f.id, from.keys.publicKey, 'share_contact')
  db.getDb().prepare("UPDATE v3_intros SET status = 'accepted', from_contact = 'a@example.com' WHERE id = ?").run(f.id)
  if (shape === 'connecting') return f

  // connected: both shared and the release row exists.
  seedAuth(f.id, to.keys.publicKey, 'share_contact')
  db.getDb().prepare("UPDATE v3_intros SET to_contact = 'b@example.com' WHERE id = ?").run(f.id)
  db.getDb().prepare('INSERT INTO connection_release (intro_id) VALUES (?)').run(f.id)
  return f
}

// ── Envelope fixtures ─────────────────────────────────────────────────────

interface Over {
  operation: any
  resource: any
  payload?: any
  nonce?: string
  issuedAt?: string
  keys: any
}

function signed(over: Over) {
  const keys = over.keys
  const payload = over.payload ?? {}
  const built = env.buildEnvelope({
    operation: over.operation, actorKey: keys.publicKey, resource: over.resource,
    issuedAt: over.issuedAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
    nonce: over.nonce ?? newNonce(), payload,
  })
  return {
    body: { envelope: built.envelope, signature: sign(jcs(built.envelope), keys.privateKey), payload },
    built,
  }
}

/** The common case: an intro-resource envelope for one operation. */
function forIntro(operation: string, introId: string, keys: any, nonce?: string) {
  return signed({ operation, resource: { type: 'intro', id: introId }, keys, nonce })
}

async function post(path: string, body: unknown) {
  const res = await fetch(`${base}/api/v3/intros/${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  let json: any = null
  try { json = await res.json() } catch { /* no body */ }
  return { status: res.status, json }
}

function statusOf(introId: string): string {
  return (db.getDb().prepare('SELECT status FROM v3_intros WHERE id = ?').get(introId) as any).status
}
function authRow(introId: string, actorKey: string, operation: string, subject = ''): any {
  return db.getDb().prepare('SELECT * FROM connection_authorizations WHERE intro_id = ? AND actor_key = ? AND operation = ? AND subject = ?')
    .get(introId, actorKey, operation, subject)
}
function counts() {
  const d = db.getDb()
  const one = (sql: string) => (d.prepare(sql).get() as any).n
  return {
    nonces: one('SELECT COUNT(*) AS n FROM write_nonces'),
    auths: one('SELECT COUNT(*) AS n FROM connection_authorizations'),
    evidence: one('SELECT COUNT(*) AS n FROM write_evidence'),
    blocks: one('SELECT COUNT(*) AS n FROM v3_intro_blocks'),
  }
}

// ══════════════════════════════════════════════════════════════
// withdraw_request
// ══════════════════════════════════════════════════════════════

test('WITHDRAW_REQUEST: the happy path withdraws the authorization, derives withdrawn and materializes the column', async () => {
  const f = await intro('requested')
  const { body, built } = forIntro('withdraw_request', f.id, f.from.keys)
  const r = await post('withdraw-request', body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.state, 'withdrawn')
  assert.equal(r.json.grandfathered, false)
  assert.equal(r.json.write_ref, built.writeRef)

  const row = authRow(f.id, f.from.keys.publicKey, 'request_intro')
  assert.equal(row.live, 0, 'the authorization is no longer live')
  assert.equal(row.withdrawn_by, built.writeRef, 'and names the act that withdrew it')
  assert.equal(statusOf(f.id), 'withdrawn', 'the compatibility column is materialized from the derivation')
  assert.equal(facts.stateOf(f.id), 'withdrawn', 'and the derivation is the authority')

  const ev = db.getDb().prepare('SELECT * FROM write_evidence WHERE write_ref = ?').get(built.writeRef) as any
  assert.equal(ev.evidence, 'canonical')
  assert.deepEqual(JSON.parse(ev.bound_fields_json), ['operation', 'resource.id'])
})

test('WITHDRAW_REQUEST: the target cannot withdraw the requester\'s request, and nothing is written', async () => {
  const f = await intro('requested')
  const before = counts()
  const r = await post('withdraw-request', forIntro('withdraw_request', f.id, f.to.keys).body)
  assert.equal(r.status, 403)
  assert.equal(r.json.code, 'not_the_requester')
  assert.deepEqual(counts(), before, 'a refusal rolls back the nonce as well as the facts')
  assert.equal(facts.stateOf(f.id), 'requested')
})

test('WITHDRAW_REQUEST: allowed from interested, refused once a continuation is live', async () => {
  const i = await intro('interested')
  const okr = await post('withdraw-request', forIntro('withdraw_request', i.id, i.from.keys).body)
  assert.equal(okr.status, 201, 'a target expressing interest does not commit the requester to anything')
  assert.equal(okr.json.state, 'withdrawn')

  const c = await intro('connecting')
  assert.equal(facts.stateOf(c.id), 'connecting')
  const refused = await post('withdraw-request', forIntro('withdraw_request', c.id, c.from.keys).body)
  assert.equal(refused.status, 409)
  assert.equal(refused.json.code, 'connection_in_progress')
  assert.equal(facts.stateOf(c.id), 'connecting', 'and the state did not move')
})

test('WITHDRAW_REQUEST: an identical resend returns the stored result, and a fresh envelope is already_withdrawn', async () => {
  const f = await intro('requested')
  const { body } = forIntro('withdraw_request', f.id, f.from.keys)
  const first = await post('withdraw-request', body)
  assert.equal(first.status, 201)
  const again = await post('withdraw-request', body)
  assert.equal(again.status, 200, 'a replay is not a second act')
  assert.equal(again.json.idempotent, true)
  assert.deepEqual(
    { state: again.json.state, intro_id: again.json.intro_id },
    { state: first.json.state, intro_id: first.json.intro_id },
    'the stored answer, field for field',
  )

  const fresh = await post('withdraw-request', forIntro('withdraw_request', f.id, f.from.keys).body)
  assert.equal(fresh.status, 409)
  assert.equal(fresh.json.code, 'already_withdrawn', 'a state answer, not a replay answer')
})

test('WITHDRAW_REQUEST: pending_actions is empty after the withdrawal, for both sides', async () => {
  const f = await intro('requested')
  await post('withdraw-request', forIntro('withdraw_request', f.id, f.from.keys).body)
  const facts0 = facts.introFacts(f.id)!
  assert.deepEqual(state.pendingActions(facts0, f.from.keys.publicKey), [], 'a terminal intro offers nothing')
  assert.deepEqual(state.pendingActions(facts0, f.to.keys.publicKey), [])
})

test('WITHDRAW_REQUEST: a pre-2A row with no authorization is withdrawn, and the backfilled row is labelled legacy_unbound', async () => {
  const f = await intro('bare')
  // Backdate behind the 2A marker, which is the only condition under which the
  // legacy column is read to decide a canonical write.
  const marker = db.getSchemaMarker(db.MINGLE_2A_MARKER_KEY)!
  const backdated = new Date(Date.parse(marker) - 60_000).toISOString()
  db.getDb().prepare('UPDATE v3_intros SET created_at = ? WHERE id = ?').run(backdated, f.id)

  const { body, built } = forIntro('withdraw_request', f.id, f.from.keys)
  const r = await post('withdraw-request', body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.grandfathered, true)
  assert.equal(r.json.state, 'withdrawn', 'which ends the grandfathered path cleanly')

  const row = authRow(f.id, f.from.keys.publicKey, 'request_intro')
  assert.equal(row.evidence, 'legacy_unbound',
    'the REQUEST was never canonically signed, so its row may never claim it was')
  assert.equal(row.live, 0)
  const ev = db.getDb().prepare('SELECT evidence FROM write_evidence WHERE write_ref = ?').get(built.writeRef) as any
  assert.equal(ev.evidence, 'canonical', 'while the withdrawal itself is canonical and says so in its own row')
})

test('WITHDRAW_REQUEST: a post-2A row with no authorization is refused rather than bridged', async () => {
  const f = await intro('bare')
  const before = counts()
  const r = await post('withdraw-request', forIntro('withdraw_request', f.id, f.from.keys).body)
  assert.equal(r.status, 409)
  assert.equal(r.json.code, 'no_open_request',
    'the bridge is gated on the marker, so it cannot be reached by an intro created under this build')
  assert.deepEqual(counts(), before)
})

test('WITHDRAW_REQUEST: an unknown intro is 404 and writes nothing', async () => {
  const before = counts()
  const r = await post('withdraw-request', forIntro('withdraw_request', 'intro-v3-nope', OUT.keys).body)
  assert.equal(r.status, 404)
  assert.equal(r.json.code, 'intro_not_found')
  assert.deepEqual(counts(), before)
})

// ── The live defect this action fixes ─────────────────────────────────────

test('WITHDRAW_REQUEST: request, withdraw, request again on the same pair succeeds', async () => {
  // hasPendingBetween at intros-db.ts:88-94 is bidirectional and unbounded, so before
  // this action one unanswered request stopped a pair from ever requesting again in
  // either direction, with no way out. This is that defect, as a regression test.
  const f = await intro('requested')
  const blocked = await legacyRequest(f.from, f.fromCard, f.toCard)
  assert.equal(blocked.status, 409, 'one pending request is one pending request, today and still')
  assert.equal(blocked.json.error, 'a pending intro already exists for this pair')
  const reverseBlocked = await legacyRequest(f.to, f.toCard, f.fromCard)
  assert.equal(reverseBlocked.status, 409, 'and the guard is bidirectional, which is the half that was worse')

  const w = await post('withdraw-request', forIntro('withdraw_request', f.id, f.from.keys).body)
  assert.equal(w.status, 201)
  assert.equal(statusOf(f.id), 'withdrawn', 'which is what makes the hasPendingBetween query stop matching')

  const third = await legacyRequest(f.from, f.fromCard, f.toCard)
  assert.equal(third.status, 201, 'the pair is no longer permanently stuck')
  assert.notEqual(third.json.id, f.id, 'and it is a new intro rather than a revived one')
})

// ══════════════════════════════════════════════════════════════
// withdraw_interest
// ══════════════════════════════════════════════════════════════

test('WITHDRAW_INTEREST: the happy path withdraws the interest and derives withdrawn', async () => {
  const f = await intro('interested')
  const { body, built } = forIntro('withdraw_interest', f.id, f.to.keys)
  const r = await post('withdraw-interest', body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.state, 'withdrawn')
  assert.equal(r.json.contact_authorization_withdrawn, false)
  const row = authRow(f.id, f.to.keys.publicKey, 'express_interest')
  assert.equal(row.live, 0)
  assert.equal(row.withdrawn_by, built.writeRef)
  assert.equal(statusOf(f.id), 'withdrawn')
})

test('WITHDRAW_INTEREST: only the target may withdraw its own interest', async () => {
  const f = await intro('interested')
  const before = counts()
  const r = await post('withdraw-interest', forIntro('withdraw_interest', f.id, f.from.keys).body)
  assert.equal(r.status, 403)
  assert.equal(r.json.code, 'not_the_target')
  assert.deepEqual(counts(), before)
})

test('WITHDRAW_INTEREST: refused in requested, because there is no interest yet', async () => {
  const f = await intro('requested')
  const r = await post('withdraw-interest', forIntro('withdraw_interest', f.id, f.to.keys).body)
  assert.equal(r.status, 409)
  assert.equal(r.json.code, 'wrong_state')
  assert.equal(facts.stateOf(f.id), 'requested')
})

test('WITHDRAW_INTEREST: a resend returns the stored result', async () => {
  const f = await intro('interested')
  const { body } = forIntro('withdraw_interest', f.id, f.to.keys)
  assert.equal((await post('withdraw-interest', body)).status, 201)
  const again = await post('withdraw-interest', body)
  assert.equal(again.status, 200)
  assert.equal(again.json.idempotent, true)
})

test('WITHDRAW_INTEREST: refused in connecting, where the remedy is to withdraw the contact first', async () => {
  // A contradiction inside the design, resolved here and recorded. Item 6 of
  // withdraw_interest says that if the target shared and no release happened, the
  // withdrawal "also needs the contact authorization gone, so the transaction sets
  // live = 0 on both rows". Section 14.4 rule 3 says the opposite: withdraw_interest
  // is refused in connecting with 409 connection_in_progress, and appears only in the
  // requested and interested rows.
  //
  // 14.4 wins, and not by seniority. A live share_contact IS a live continuation, so
  // the state whenever the target has shared is connecting, which means item 6's case
  // and 14.4's refusal describe the same situation. Allowing the cascade would let an
  // intro derive withdrawn by rule 3 while continuations are still live, so rule 5
  // could never be reached and the derivation would contradict its own facts. That is
  // the coherence item 2 means by "the guard section 14.1 relies on to keep branch 3
  // of the derivation safe".
  //
  // The product path is two narrow acts rather than one wide one, which is what
  // designing the thirteen independently produces.
  const f = await intro('connecting')
  seedAuth(f.id, f.to.keys.publicKey, 'share_contact')
  db.getDb().prepare("UPDATE v3_intros SET to_contact = 'b@example.com' WHERE id = ?").run(f.id)

  const refused = await post('withdraw-interest', forIntro('withdraw_interest', f.id, f.to.keys).body)
  assert.equal(refused.status, 409)
  assert.equal(refused.json.code, 'connection_in_progress')
  assert.equal(refused.json.error, 'this connection is already in progress, so withdraw the contact rather than the interest',
    'and the refusal says which act to send instead')

  // Act one: the contact. Only the withdrawer's own column is blanked.
  const one = await post('withdraw-contact', forIntro('withdraw_contact', f.id, f.to.keys).body)
  assert.equal(one.status, 201, JSON.stringify(one.json))
  const row = db.getDb().prepare('SELECT from_contact, to_contact FROM v3_intros WHERE id = ?').get(f.id) as any
  assert.equal(row.to_contact, null, 'the withdrawer\'s own contact is blanked')
  assert.equal(row.from_contact, 'a@example.com', 'and the counterparty\'s is not')
  assert.equal(one.json.state, 'connecting', 'the requester\'s contact is still a live continuation')

  // Act two: the requester withdraws theirs as well, so no continuation is live.
  assert.equal((await post('withdraw-contact', forIntro('withdraw_contact', f.id, f.from.keys).body)).status, 201)
  assert.equal(facts.stateOf(f.id), 'interested')

  // And now the interest can go.
  const two = await post('withdraw-interest', forIntro('withdraw_interest', f.id, f.to.keys).body)
  assert.equal(two.status, 201, JSON.stringify(two.json))
  assert.equal(two.json.state, 'withdrawn')
})

test('WITHDRAW_INTEREST: no accepted withdrawal ever leaves a live contact authorization behind', async () => {
  // The invariant item 6 was protecting, asserted directly rather than through the
  // cascade. It holds two ways: the guard refuses the withdrawal in connecting, and if
  // a future edit ever loosened that guard the cascade in the route would still take
  // the contact authorization with the interest. Either way a live contact
  // authorization under a withdrawn interest cannot exist, which is what stops the
  // other side completing a connection this actor backed out of.
  const rows = db.getDb().prepare(`
    SELECT i.intro_id, i.actor_key FROM connection_authorizations i
    WHERE i.operation = 'express_interest' AND i.live = 0
  `).all() as { intro_id: string; actor_key: string }[]
  assert.ok(rows.length > 0, 'the suite did withdraw interests')
  for (const r of rows) {
    const contact = authRow(r.intro_id, r.actor_key, 'share_contact')
    if (contact === undefined) continue
    assert.equal(contact.live, 0, `${r.intro_id} holds a live contact authorization under a withdrawn interest`)
  }
})

test('WITHDRAW_INTEREST: after a release it is contact_already_released, and writes nothing', async () => {
  const f = await intro('connected')
  const before = counts()
  const r = await post('withdraw-interest', forIntro('withdraw_interest', f.id, f.to.keys).body)
  assert.equal(r.status, 409)
  assert.equal(r.json.code, 'contact_already_released')
  assert.deepEqual(counts(), before)
  assert.equal(facts.stateOf(f.id), 'connected', 'Mingle does not pretend a released contact can be unshared')
})

// ══════════════════════════════════════════════════════════════
// withdraw_contact
// ══════════════════════════════════════════════════════════════

test('WITHDRAW_CONTACT: the happy path blanks only the actor\'s contact and the state regresses to interested', async () => {
  const f = await intro('connecting')
  assert.equal(facts.stateOf(f.id), 'connecting')
  const { body, built } = forIntro('withdraw_contact', f.id, f.from.keys)
  const r = await post('withdraw-contact', body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.state, 'interested',
    'the state is recomputed, not assigned: the withdrawn contact was the only live continuation')
  const row = authRow(f.id, f.from.keys.publicKey, 'share_contact')
  assert.equal(row.live, 0)
  assert.equal(row.withdrawn_by, built.writeRef)
  const intr = db.getDb().prepare('SELECT from_contact, status FROM v3_intros WHERE id = ?').get(f.id) as any
  assert.equal(intr.from_contact, null)
  assert.equal(intr.status, 'accepted', 'interested materializes accepted, so the old client keeps working')
})

test('WITHDRAW_CONTACT: the state stays connecting while another continuation is live', async () => {
  const f = await intro('connecting')
  seedAuth(f.id, f.from.keys.publicKey, 'fit_request')
  const r = await post('withdraw-contact', forIntro('withdraw_contact', f.id, f.from.keys).body)
  assert.equal(r.status, 201)
  assert.equal(r.json.state, 'connecting', 'a live fit authorization is still a live continuation')
})

test('WITHDRAW_CONTACT: a third party is refused, and so is a party holding no contact authorization', async () => {
  const f = await intro('connecting')
  const outsider = await post('withdraw-contact', forIntro('withdraw_contact', f.id, OUT.keys).body)
  assert.equal(outsider.status, 403)
  assert.equal(outsider.json.code, 'not_a_party')

  const target = await post('withdraw-contact', forIntro('withdraw_contact', f.id, f.to.keys).body)
  assert.equal(target.status, 409)
  assert.equal(target.json.code, 'no_contact_authorization',
    'a party who authorized no contact has nothing to withdraw')
})

test('WITHDRAW_CONTACT: refused in interested, where nothing has been shared', async () => {
  const f = await intro('interested')
  const r = await post('withdraw-contact', forIntro('withdraw_contact', f.id, f.from.keys).body)
  assert.equal(r.status, 409)
  assert.equal(r.json.code, 'wrong_state')
})

test('WITHDRAW_CONTACT: a resend returns the stored result', async () => {
  const f = await intro('connecting')
  const { body } = forIntro('withdraw_contact', f.id, f.from.keys)
  assert.equal((await post('withdraw-contact', body)).status, 201)
  const again = await post('withdraw-contact', body)
  assert.equal(again.status, 200)
  assert.equal(again.json.idempotent, true)
  assert.equal(again.json.state, 'interested', 'the stored answer')
})

test('WITHDRAW_CONTACT: 14.2 case B, the share commits first, so the withdrawal is refused and the nonce stays usable', async () => {
  const f = await intro('connected') // the release row is the "B shared first" outcome
  const shared = newNonce()
  const { body } = forIntro('withdraw_contact', f.id, f.from.keys, shared)
  const refused = await post('withdraw-contact', body)
  assert.equal(refused.status, 409)
  assert.equal(refused.json.code, 'contact_already_released')

  const n = (db.getDb().prepare('SELECT COUNT(*) AS n FROM write_nonces WHERE nonce = ?').get(shared) as any).n
  assert.equal(n, 0, 'the whole transaction rolled back including the reservation')

  // And the nonce is genuinely reusable, proven on a different intro where it commits.
  const other = await intro('connecting')
  const reuse = await post('withdraw-contact', forIntro('withdraw_contact', other.id, other.from.keys, shared).body)
  assert.equal(reuse.status, 201, 'a refusal costs the caller nothing, not even a nonce')
})

test('WITHDRAW_CONTACT: 14.2 case B, the withdrawal commits first, so the other side finds one live authorization and no release', async () => {
  const f = await intro('connecting')
  // The target shares too, so both are live and a release is now possible.
  seedAuth(f.id, f.to.keys.publicKey, 'share_contact')
  const w = await post('withdraw-contact', forIntro('withdraw_contact', f.id, f.from.keys).body)
  assert.equal(w.status, 201)

  const f0 = facts.introFacts(f.id)!
  const liveShares = f0.authorizations.filter(a => a.operation === 'share_contact' && a.live)
  assert.equal(liveShares.length, 1, 'so a transaction looking for two live authorizations finds one')
  assert.equal(facts.isReleased(f.id), false, 'and writes no release')
  assert.equal(state.deriveIntroState(f0), 'connecting', 'the target\'s own contact is still a live continuation')
})

test('WITHDRAW_CONTACT: the release row is exactly once under two connections racing it', async () => {
  // Inside one process better-sqlite3 is synchronous, so the race is only reachable
  // with a second connection to the same file. The exactly-once property rests on the
  // primary key and not on the ordering.
  const f = await intro('connecting')
  seedAuth(f.id, f.to.keys.publicKey, 'share_contact')
  const other = new Database(DB_FILE)
  try {
    const claim = (conn: any) => {
      try { conn.prepare('INSERT INTO connection_release (intro_id) VALUES (?)').run(f.id); return true } catch { return false }
    }
    assert.equal(claim(db.getDb()), true)
    assert.equal(claim(other), false, 'the loser is refused by the primary key, not by a read')
    const n = (db.getDb().prepare('SELECT COUNT(*) AS n FROM connection_release WHERE intro_id = ?').get(f.id) as any).n
    assert.equal(n, 1)
  } finally { other.close() }
})

// ══════════════════════════════════════════════════════════════
// block_pair
// ══════════════════════════════════════════════════════════════

function blockBody(f: Fixture, keys: any, over: { payload?: any; resourceId?: string; nonce?: string; cards?: [string, string] } = {}) {
  const [ca, cb] = over.cards ?? [f.fromCard, f.toCard]
  const [lo, hi] = [ca, cb].sort()
  return signed({
    operation: 'block_pair',
    resource: { type: 'card_pair', id: over.resourceId ?? env.cardPairResourceId(ca, cb) },
    payload: over.payload ?? { card_a: lo, card_b: hi, intro_id: f.id },
    keys, nonce: over.nonce,
  })
}

test('BLOCK_PAIR: before a release the intro ends blocked, the pair row exists, and the column materializes blocked', async () => {
  const f = await intro('interested')
  const r = await post('block-pair', blockBody(f, f.to.keys).body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.intro_ended, true)
  assert.equal(r.json.pair_blocked, true)
  assert.equal(r.json.state, 'blocked')
  assert.equal(introsDb.isBlocked(f.fromCard, f.toCard), true, 'the pair row exists under the unchanged storage key')
  assert.equal(statusOf(f.id), 'blocked')
  assert.equal(facts.stateOf(f.id), 'blocked')
  assert.equal(authRow(f.id, f.to.keys.publicKey, 'block_pair').live, 1, 'and the intro level terminal fact is written')

  // A new request between the same two cards is refused, in both directions.
  assert.equal((await legacyRequest(f.from, f.fromCard, f.toCard)).status, 403)
  const reversed = await legacyRequest(f.to, f.toCard, f.fromCard)
  assert.equal(reversed.status, 403, 'the storage key is unordered')
  assert.equal(reversed.json.error, 'this pair cannot be introduced')
})

test('BLOCK_PAIR: after a release the pair is blocked, NO intro level fact is written, and the intro stays connected', async () => {
  const f = await intro('connected')
  assert.equal(facts.stateOf(f.id), 'connected')

  const r = await post('block-pair', blockBody(f, f.to.keys).body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.intro_ended, false)
  assert.equal(r.json.pair_blocked, true)
  assert.equal(r.json.state, 'connected')
  assert.equal(introsDb.isBlocked(f.fromCard, f.toCard), true, 'the pair block is identical in both shapes')
  assert.equal(authRow(f.id, f.to.keys.publicKey, 'block_pair'), undefined,
    'rule 2 finds no blocked fact, so the derivation needs no exception and gets none')
  assert.equal(facts.stateOf(f.id), 'connected')
  assert.equal(statusOf(f.id), 'accepted', 'and the column is not rewritten either')
  assert.equal(introsDb.isComplete(introsDb.getIntro(f.id)!), true,
    'so the pair stays in the old client\'s completed list with its contacts')

  // Future pair activity is blocked, which is the point of blocking after a connection.
  const again = await legacyRequest(f.from, f.fromCard, f.toCard)
  assert.equal(again.status, 403)
  assert.equal(again.json.error, 'this pair cannot be introduced')
})

test('BLOCK_PAIR: a legacy complete intro with no release row is treated as connected, not reopened as blocked', async () => {
  // A pre-2A connection has no connection_release row, because that row only exists
  // for connections the canonical lane made. A branch that asked only about the
  // release row would end a finished legacy connection and flip isComplete to false,
  // dropping the pair out of the old client's completed list. contactsExchanged reads
  // both lanes, so it does not.
  const f = await intro('bare')
  db.getDb().prepare("UPDATE v3_intros SET status = 'accepted', from_contact = 'a@x.test', to_contact = 'b@x.test' WHERE id = ?").run(f.id)
  assert.equal(facts.isReleased(f.id), false)
  assert.equal(facts.legacyComplete(f.id), true)

  const r = await post('block-pair', blockBody(f, f.from.keys).body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.intro_ended, false)
  assert.equal(statusOf(f.id), 'accepted', 'the finished legacy connection keeps the value it earned')
  assert.equal(introsDb.isComplete(introsDb.getIntro(f.id)!), true)
  assert.equal(introsDb.isBlocked(f.fromCard, f.toCard), true, 'and the pair is still blocked')
})

test('BLOCK_PAIR: the approved review copy is returned byte exact', async () => {
  const f = await intro('interested')
  const r = await post('block-pair', blockBody(f, f.to.keys).body)
  assert.equal(r.status, 201)
  assert.equal(r.json.review_copy, "You won't be matched or introduced through these two cards again.")
  assert.equal(r.json.review_copy, routes.BLOCK_PAIR_REVIEW_COPY, 'one string, one home')
  // It names cards and not people, because a v3 card carries a 21 day TTL and the
  // block does not follow a person who publishes a new one.
  assert.ok(/\bcards\b/.test(r.json.review_copy))
  assert.ok(!/\bthem\b|\bthis person\b|\bthey\b/i.test(r.json.review_copy))
})

test('BLOCK_PAIR: the three server checks each refuse, and write nothing', async () => {
  const f = await intro('interested')
  const before = counts()

  // Check 1: the resource id does not recompute from the payload pair.
  const wrongId = await post('block-pair', blockBody(f, f.from.keys, { resourceId: 'a'.repeat(64) }).body)
  assert.equal(wrongId.status, 400)
  assert.equal(wrongId.json.code, 'resource_id_mismatch')

  // Check 2: the pair does not match the intro. The resource id is computed from the
  // listed cards, so check 1 passes and only check 2 catches this.
  const [lo, hi] = [f.fromCard, cardOut].sort()
  const wrongPair = await post('block-pair', blockBody(f, f.from.keys, {
    cards: [f.fromCard, cardOut], payload: { card_a: lo, card_b: hi, intro_id: f.id },
  }).body)
  assert.equal(wrongPair.status, 400)
  assert.equal(wrongPair.json.code, 'pair_not_in_intro',
    'a signature naming one intro must not authorize a block on any two cards the signer lists')

  // Check 3: the actor is not a party to the intro.
  const outsider = await post('block-pair', blockBody(f, OUT.keys).body)
  assert.equal(outsider.status, 403)
  assert.equal(outsider.json.code, 'not_a_party', 'nothing about a card pair identifies who may act on it')

  assert.deepEqual(counts(), before, 'and no refusal left a nonce, a fact, an evidence row or a block')
  assert.equal(introsDb.isBlocked(f.fromCard, f.toCard), false)
  assert.equal(introsDb.isBlocked(f.fromCard, cardOut), false)
})

test('BLOCK_PAIR: the payload must carry exactly the three fields, in sorted order', async () => {
  const f = await intro('interested')
  const [lo, hi] = [f.fromCard, f.toCard].sort()

  const extra = await post('block-pair', blockBody(f, f.from.keys, {
    payload: { card_a: lo, card_b: hi, intro_id: f.id, reason: 'rude' },
  }).body)
  assert.equal(extra.status, 400)
  assert.equal(extra.json.code, 'malformed_payload', 'an extra field inside the digest is an unexamined field')

  const unsorted = await post('block-pair', blockBody(f, f.from.keys, {
    payload: { card_a: hi, card_b: lo, intro_id: f.id },
  }).body)
  assert.equal(unsorted.status, 400)
  assert.equal(unsorted.json.code, 'malformed_payload')
  assert.equal(introsDb.isBlocked(f.fromCard, f.toCard), false)
})

test('BLOCK_PAIR: the requester may block too, and a resend returns the stored result', async () => {
  const f = await intro('interested')
  // Today only the target can block, because blocking exists only as the
  // decline_and_block branch at intros-routes.ts:141-146.
  const { body } = blockBody(f, f.from.keys)
  const first = await post('block-pair', body)
  assert.equal(first.status, 201, JSON.stringify(first.json))
  assert.equal(first.json.state, 'blocked')
  const again = await post('block-pair', body)
  assert.equal(again.status, 200)
  assert.equal(again.json.idempotent, true)
  const n = (db.getDb().prepare('SELECT COUNT(*) AS n FROM write_evidence WHERE resource_type = ? AND resource_id = ?')
    .get('card_pair', env.cardPairResourceId(f.fromCard, f.toCard)) as any).n
  assert.equal(n, 1, 'one signed act, one evidence row, even though the pair insert is idempotent')
})

// ══════════════════════════════════════════════════════════════
// The envelope pairs an operation with exactly one resource type
// ══════════════════════════════════════════════════════════════

test('RESOURCE TYPE: an operation may not name a resource type the design did not give it', async () => {
  const f = await intro('requested')
  const r = await post('withdraw-request', signed({
    operation: 'withdraw_request', resource: { type: 'card_pair', id: 'a'.repeat(64) }, keys: f.from.keys,
  }).body)
  assert.equal(r.status, 400)
  assert.equal(r.json.code, 'resource_type_mismatch')

  const b = await post('block-pair', signed({
    operation: 'block_pair', resource: { type: 'intro', id: f.id }, keys: f.from.keys,
    payload: { card_a: f.fromCard, card_b: f.toCard, intro_id: f.id },
  }).body)
  assert.equal(b.status, 400)
  assert.equal(b.json.code, 'resource_type_mismatch')
})

// ══════════════════════════════════════════════════════════════
// The read side the materialization exists for (section 14.3)
// ══════════════════════════════════════════════════════════════

async function mine(keys: any): Promise<any[]> {
  const nonce = 'm' + Math.random().toString(36).slice(2)
  const qs = new URLSearchParams({
    public_key: keys.publicKey, nonce, signature: sign(`intro-mine:${nonce}`, keys.privateKey),
  })
  const r = await (await fetch(`${base}/api/v3/intros/mine?${qs}`)).json()
  return r.intros
}

/** The three splits a 3.2.x client applies to /mine, at index.ts:1059-1067. */
function splits(rows: any[]) {
  return {
    incoming_pending: rows.filter(r => r.direction === 'incoming' && r.status === 'pending'),
    outgoing: rows.filter(r => r.direction === 'outgoing' && !r.complete),
    completed: rows.filter(r => r.complete),
  }
}

test('READ SIDE: a withdrawn intro leaves incoming_pending and lingers in outgoing carrying withdrawn', async () => {
  const f = await intro('requested')
  await post('withdraw-request', forIntro('withdraw_request', f.id, f.from.keys).body)

  const target = splits(await mine(f.to.keys))
  assert.equal(target.incoming_pending.find(r => r.id === f.id), undefined,
    'the incoming filter tests status === "pending", so a withdrawn intro correctly disappears')

  const requester = splits(await mine(f.from.keys))
  const row = requester.outgoing.find(r => r.id === f.id)
  assert.ok(row, 'the outgoing filter tests only !complete, so the terminal row lingers')
  assert.equal(row.status, 'withdrawn',
    'carrying a string the published client has no branch for and relays as is. Not a break, and not tidy')
})

test('READ SIDE: interested materializes accepted, which is what three unchanged predicates need', async () => {
  // The 2B plan's step 9 bullet says an interested intro "still reports status:
  // pending". That contradicts Output 1 section 14.3, whose mapping table gives
  // interested -> accepted, and the table is right for a concrete reason: isComplete
  // at intros-db.ts:129 is a THREE term conjunction requiring status === 'accepted',
  // so materializing 'pending' would mean a canonically connected pair could never
  // read as complete and the old client would never show a released contact. The
  // settled design wins over the plan's prose, and this test pins it.
  const f = await intro('interested')
  facts.materializeStatus(f.id)
  assert.equal(statusOf(f.id), 'accepted')
  assert.equal(facts.stateOf(f.id), 'interested', 'while the derivation still answers interested')

  const target = splits(await mine(f.to.keys))
  assert.equal(target.incoming_pending.find(r => r.id === f.id), undefined,
    'so the intro leaves the target\'s incoming list, which is what expressing interest means')
  const requester = splits(await mine(f.from.keys))
  const row = requester.outgoing.find(r => r.id === f.id)
  assert.equal(row.awaiting, 'your_contact', 'and the requester is told what they owe')
})

test('READ SIDE: in connecting with the requester\'s contact stored, awaiting is absent, which is the guidance degradation', async () => {
  const f = await intro('connecting')
  facts.materializeStatus(f.id)
  assert.equal(facts.stateOf(f.id), 'connecting')

  const requester = splits(await mine(f.from.keys))
  const row = requester.outgoing.find(r => r.id === f.id)
  assert.equal(row.awaiting, undefined,
    'awaiting at intros-routes.ts:210 keys on from_contact being absent, so once the requester has shared, the old client can no longer tell either side what is outstanding')
  assert.equal(row.status, 'accepted')
  assert.equal(row.counterparty_contact, null, 'and nothing is released before the release row exists')
})

test('READ SIDE: connected reads as complete with the contact released, all three isComplete terms holding', async () => {
  const f = await intro('connected')
  facts.materializeStatus(f.id)
  assert.equal(statusOf(f.id), 'accepted')
  assert.equal(facts.stateOf(f.id), 'connected')

  const requester = splits(await mine(f.from.keys))
  const row = requester.completed.find(r => r.id === f.id)
  assert.ok(row, 'isComplete needs status accepted and both contact columns, and all three hold')
  assert.equal(row.counterparty_contact, 'b@example.com')
})

test('READ SIDE: the column and the derivation agree after every canonical write in this suite', async () => {
  // The general rule from 14.3: if v3_intros.status and deriveIntroState ever
  // disagree, the column is wrong by definition. This walks every intro the suite
  // touched canonically and checks the pair, which is the only thing tying them
  // together.
  //
  // Strict, with no allowance for exceptions. The one case that writes no column, a
  // block after a connection, still agrees: the intro derives connected and the column
  // already holds accepted, which is what connected materializes to. So "does not
  // rewrite the column" and "the column agrees with the derivation" are both true at
  // once, and an allowance here would have hidden that rather than shown it.
  const rows = db.getDb().prepare('SELECT DISTINCT intro_id FROM connection_authorizations').all() as { intro_id: string }[]
  assert.ok(rows.length > 5, `the suite did write facts, found ${rows.length}`)
  let checked = 0
  for (const { intro_id } of rows) {
    const f0 = facts.introFacts(intro_id)
    assert.ok(f0 !== null, `${intro_id} has facts but no intro row`)
    const derived = state.deriveIntroState(f0!)
    assert.equal(statusOf(intro_id), state.materializedStatus(derived),
      `${intro_id} derives ${derived}, so the column should be ${state.materializedStatus(derived)}`)
    checked++
  }
  assert.equal(checked, rows.length)
})
