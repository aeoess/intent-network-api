// ══════════════════════════════════════════════════════════════
// Two lanes on one path: request_intro, express_interest, decline
// ══════════════════════════════════════════════════════════════
// The dispatch is a shape check, so both lanes are exercised against the SAME paths with
// the same cards. What the tests are really about:
//
//   1  the canonical lane refuses a note rather than repairing one, and the stored note
//      recomputes to the payload_digest the principal signed
//   2  the legacy lane behaves byte for byte as it did at 909ffe3, including the five
//      transforms on its note, and gains only a record of what its signature covered
//   3  one legacy accept means TWO authorizations in the new model, from one signature
//      whose bound_fields_json names neither of the things it did not cover
//   4  the cutoff and anti-downgrade answer identically and are distinguished only in
//      the internal log

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-canonlane-test-'))
process.env.DB_PATH = join(tmpDir, 'lane.db')
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'
// Fit off, which is production. The accept branch must behave the same either way, and
// tests/intros.test.ts already covers it with the flag on.
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
const evidence = await import('../src/write-evidence.js')
const gate = await import('../src/legacy-write-gate.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const { newNonce, jcs, sha256Hex } = await import('../src/canonical-write.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => {
  db.getDb().prepare('DELETE FROM rate_limits').run()
  clearCutoff()
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

interface Pair { from: any; to: any; fromCard: string; toCard: string }

/** A fresh pair of published cards. Fresh every time, because hasPendingBetween allows
 *  one pending intro per pair in either direction. */
async function pair(): Promise<Pair> {
  const from = makeCard('requester ' + randomBytes(3).toString('hex'))
  const to = makeCard('target ' + randomBytes(3).toString('hex'))
  return { from, to, fromCard: await publish(from), toCard: await publish(to) }
}

async function post(path: string, body: unknown) {
  const res = await fetch(`${base}/api/v3/intros/${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  let json: any = null
  try { json = await res.json() } catch { /* no body */ }
  return { status: res.status, json }
}

function newRequestId(): string { return randomBytes(16).toString('hex') }

function signedBody(over: {
  operation: string
  resource: any
  payload?: any
  keys: any
  nonce?: string
  issuedAt?: string
}) {
  const payload = over.payload ?? {}
  const built = env.buildEnvelope({
    operation: over.operation as any, actorKey: over.keys.publicKey, resource: over.resource,
    issuedAt: over.issuedAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
    nonce: over.nonce ?? newNonce(), payload,
  })
  return {
    body: { envelope: built.envelope, signature: sign(jcs(built.envelope), over.keys.privateKey), payload },
    built,
  }
}

/** A canonical request_intro. Returns the response and everything needed to assert on
 *  the exact signed bytes afterwards. */
async function canonicalRequest(p: Pair, over: { note?: string; purpose?: string; requestId?: string; nonce?: string } = {}) {
  const requestId = over.requestId ?? newRequestId()
  const payload = {
    from_card: p.fromCard, to_card: p.toCard,
    purpose: over.purpose ?? 'collaborate',
    note: over.note ?? 'compare notes on delegation chains',
  }
  const s = signedBody({
    operation: 'request_intro', resource: { type: 'intro_request', id: requestId },
    payload, keys: p.from.keys, nonce: over.nonce,
  })
  const r = await post('request', s.body)
  return { ...r, requestId, payload, built: s.built, body: s.body }
}

async function legacyRequest(p: Pair, note = 'hello'): Promise<{ status: number; json: any }> {
  const nonce = 'n' + randomBytes(4).toString('hex')
  const purpose = 'collaborate'
  const res = await fetch(`${base}/api/v3/intros/request`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from_card: p.fromCard, to_card: p.toCard, purpose, note,
      public_key: p.from.keys.publicKey, nonce,
      signature: sign(`intro-request:${p.fromCard}:${p.toCard}:${purpose}:${nonce}`, p.from.keys.privateKey),
    }),
  })
  return { status: res.status, json: await res.json().catch(() => null) }
}

async function legacyRespond(p: Pair, introId: string, action: string, contact?: string) {
  const nonce = 'r' + randomBytes(4).toString('hex')
  const body: any = {
    action, public_key: p.to.keys.publicKey, nonce,
    signature: sign(`intro-respond:${introId}:${action}:${nonce}`, p.to.keys.privateKey),
  }
  if (contact !== undefined) body.contact = contact
  const res = await fetch(`${base}/api/v3/intros/${introId}/respond`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  return { status: res.status, json: await res.json().catch(() => null) }
}

function introRow(id: string): any {
  return db.getDb().prepare('SELECT * FROM v3_intros WHERE id = ?').get(id)
}
function authRows(introId: string): any[] {
  return db.getDb().prepare('SELECT * FROM connection_authorizations WHERE intro_id = ? ORDER BY operation').all(introId)
}
function evidenceRows(introId: string): any[] {
  return db.getDb().prepare('SELECT * FROM write_evidence WHERE resource_type = ? AND resource_id = ? ORDER BY recorded_at, evidence_id')
    .all('intro', introId)
}
function setCutoff(at: string): void {
  db.getDb().prepare('INSERT OR REPLACE INTO schema_markers (key, value) VALUES (?, ?)').run(db.LEGACY_WRITE_CUTOFF_KEY, at)
}
function clearCutoff(): void {
  db.getDb().prepare('DELETE FROM schema_markers WHERE key = ?').run(db.LEGACY_WRITE_CUTOFF_KEY)
}
/** Capture what the legacy gate logs, which is the only place the two refusals differ. */
async function capturingWarnings<T>(fn: () => Promise<T>): Promise<{ result: T; lines: string[] }> {
  const lines: string[] = []
  const original = console.warn
  console.warn = (...args: unknown[]) => { lines.push(args.map(String).join(' ')) }
  try { return { result: await fn(), lines } } finally { console.warn = original }
}

// ══════════════════════════════════════════════════════════════
// request_intro, the canonical lane
// ══════════════════════════════════════════════════════════════

test('CANONICAL REQUEST: the happy path creates the intro and records what the signature covered', async () => {
  const p = await pair()
  const r = await canonicalRequest(p, { note: 'compare notes on delegation chains' })
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.created, true)
  assert.equal(r.json.state, 'requested')
  assert.equal(r.json.write_ref, r.built.writeRef)

  const row = introRow(r.json.intro_id)
  assert.equal(row.from_key, p.from.keys.publicKey)
  assert.equal(row.to_key, p.to.keys.publicKey, 'to_key comes from the target card, never from the client')
  assert.equal(row.status, 'pending', 'requested materializes pending')
  assert.equal(row.note, 'compare notes on delegation chains')

  const auths = authRows(r.json.intro_id)
  assert.equal(auths.length, 1)
  assert.equal(auths[0].operation, 'request_intro')
  assert.equal(auths[0].evidence, 'canonical')
  assert.equal(auths[0].live, 1)

  const ev = db.getDb().prepare('SELECT * FROM write_evidence WHERE write_ref = ?').get(r.built.writeRef) as any
  assert.equal(ev.evidence, 'canonical')
  assert.deepEqual(JSON.parse(ev.bound_fields_json),
    ['operation', 'resource.id', 'payload.from_card', 'payload.to_card', 'payload.purpose', 'payload.note'],
    'the note IS covered on this lane, which is the whole difference from legacy')

  // The mode row is on the intro_request resource, because the intro did not exist when
  // the envelope was signed. A later act on the created intro resolves through
  // write_create_map rather than through a pre-written row.
  const mode = db.getDb().prepare('SELECT * FROM write_auth_mode WHERE resource_type = ? AND resource_id = ?')
    .get('intro_request', r.requestId) as any
  assert.equal(mode.mode, 'canonical')
  assert.equal(mode.actor_key, p.from.keys.publicKey)
  const created = db.getDb().prepare('SELECT * FROM write_create_map WHERE request_id = ?').get(r.requestId) as any
  assert.equal(created.created_id, r.json.intro_id)
})

test('CANONICAL REQUEST: request_id stops a timed out retry creating a second intro', async () => {
  const p = await pair()
  const requestId = newRequestId()
  const first = await canonicalRequest(p, { requestId })
  assert.equal(first.status, 201)
  assert.equal(first.json.created, true)

  // A fresh nonce AND a fresh issued_at, which is exactly what a client does after a
  // timeout. write_ref therefore differs and nonce idempotency does not catch it.
  const retry = await canonicalRequest(p, { requestId })
  assert.notEqual(retry.built.writeRef, first.built.writeRef, 'a genuinely different signed act')
  assert.equal(retry.status, 201)
  assert.equal(retry.json.created, false, 'and yet no second intro')
  assert.equal(retry.json.intro_id, first.json.intro_id)

  const n = (db.getDb().prepare('SELECT COUNT(*) AS n FROM v3_intros WHERE from_card = ? AND to_card = ?')
    .get(p.fromCard, p.toCard) as any).n
  assert.equal(n, 1, 'which is the defect today: the id at intros-routes.ts:75 carries a fresh Date.now()')
})

test('CANONICAL REQUEST: a byte identical resend is an idempotent replay, not a create', async () => {
  const p = await pair()
  const first = await canonicalRequest(p)
  assert.equal(first.status, 201)
  const again = await post('request', first.body)
  assert.equal(again.status, 200)
  assert.equal(again.json.idempotent, true)
  assert.equal(again.json.intro_id, first.json.intro_id)
})

test('CANONICAL REQUEST: a request_id belonging to another key is refused', async () => {
  const p = await pair()
  const other = await pair()
  const requestId = newRequestId()
  assert.equal((await canonicalRequest(p, { requestId })).status, 201)
  const stolen = await canonicalRequest(other, { requestId })
  assert.equal(stolen.status, 409)
  assert.equal(stolen.json.code, 'request_id_taken')
})

test('CANONICAL REQUEST: the shape and authorization refusals each write nothing', async () => {
  const p = await pair()
  const before = (db.getDb().prepare('SELECT COUNT(*) AS n FROM v3_intros').get() as any).n

  const badId = await post('request', signedBody({
    operation: 'request_intro', resource: { type: 'intro_request', id: 'not-hex' },
    payload: { from_card: p.fromCard, to_card: p.toCard, purpose: 'collaborate', note: 'x' }, keys: p.from.keys,
  }).body)
  assert.equal(badId.json.code, 'malformed_request_id')

  const badPurpose = await canonicalRequest(p, { purpose: 'conquer' })
  assert.equal(badPurpose.status, 400)
  assert.equal(badPurpose.json.code, 'unknown_purpose')

  // Signed by a key that does not own from_card.
  const impostor = await pair()
  const notMine = await post('request', signedBody({
    operation: 'request_intro', resource: { type: 'intro_request', id: newRequestId() },
    payload: { from_card: p.fromCard, to_card: p.toCard, purpose: 'collaborate', note: 'x' },
    keys: impostor.from.keys,
  }).body)
  assert.equal(notMine.status, 403)
  assert.equal(notMine.json.code, 'card_not_the_signers')

  const extra = await post('request', signedBody({
    operation: 'request_intro', resource: { type: 'intro_request', id: newRequestId() },
    payload: { from_card: p.fromCard, to_card: p.toCard, purpose: 'collaborate', note: 'x', urgency: 'high' },
    keys: p.from.keys,
  }).body)
  assert.equal(extra.json.code, 'malformed_payload')

  assert.equal((db.getDb().prepare('SELECT COUNT(*) AS n FROM v3_intros').get() as any).n, before,
    'no refusal created an intro')
})

test('CANONICAL REQUEST: a blocked pair and an existing pending intro are both refused', async () => {
  const p = await pair()
  assert.equal((await canonicalRequest(p)).status, 201)
  const second = await canonicalRequest(p)
  assert.equal(second.status, 409)
  assert.equal(second.json.code, 'pending_intro_exists')

  const q = await pair()
  introsDb.addBlock(q.fromCard, q.toCard)
  const blocked = await canonicalRequest(q)
  assert.equal(blocked.status, 403)
  assert.equal(blocked.json.code, 'pair_blocked')
})

// ══════════════════════════════════════════════════════════════
// Invariant 4: refuse, never repair
// ══════════════════════════════════════════════════════════════

test('INVARIANT 4: a canonical note carrying a link is refused, and nothing is stored', async () => {
  const p = await pair()
  const before = (db.getDb().prepare('SELECT COUNT(*) AS n FROM v3_intros').get() as any).n
  for (const note of [
    'see https://evil.example/path',
    'find me at www.evil.example',
    'my site is evil.biz and it is great',
    'reach me on evil.com/x',
  ]) {
    const r = await canonicalRequest(p, { note })
    assert.equal(r.status, 400, `${note}: ${JSON.stringify(r.json)}`)
    assert.equal(r.json.code, 'note_contains_link')
  }
  assert.equal((db.getDb().prepare('SELECT COUNT(*) AS n FROM v3_intros').get() as any).n, before)

  // A LIMIT OF THE DETECTOR, recorded rather than fixed. The bare host alternative at
  // intros-db.ts:71 matches only a closed TLD list, so `evil.example` is not a link to it
  // and never was. Both lanes are equally blind to it, because both use the same regex:
  // the legacy lane stores it unchanged and the canonical lane accepts it. Widening the
  // list would change what the legacy lane rewrites, which is out of scope here.
  const bare = await canonicalRequest(p, { note: 'my site is evil.example' })
  assert.equal(bare.status, 201, 'accepted, because the detector does not consider this a link')
  assert.equal(introRow(bare.json.intro_id).note, 'my site is evil.example')
  const q = await pair()
  const viaLegacy = await legacyRequest(q, 'my site is evil.example')
  assert.equal(introRow(viaLegacy.json.id).note, 'my site is evil.example',
    'and the legacy lane does not rewrite it either, so the two lanes agree on this gap')
})

test('INVARIANT 4: edge whitespace, a control character and an over long note are each refused with their own reason', async () => {
  const p = await pair()
  const leading = await canonicalRequest(p, { note: ' padded' })
  assert.equal(leading.status, 400)
  assert.equal(leading.json.code, 'edge_whitespace', 'caught by the payload gate, before any schema check')

  const nul = await canonicalRequest(p, { note: 'a' + String.fromCharCode(0) + 'b' })
  assert.equal(nul.status, 400)
  assert.equal(nul.json.code, 'control_character',
    'text reaching a database column and an email body must not carry what intros-db.ts:78 carried')

  const del = await canonicalRequest(p, { note: 'a' + String.fromCharCode(0x7f) + 'b' })
  assert.equal(del.json.code, 'control_character')

  const long = await canonicalRequest(p, { note: 'x'.repeat(201) })
  assert.equal(long.status, 400)
  assert.equal(long.json.code, 'note_too_long', 'refused, not sliced to 200')
})

test('INVARIANT 4: the stored canonical note recomputes to the payload_digest the principal signed', async () => {
  // The mechanical form of invariant 4, and one of the three tests the plan names as
  // mattering most. It does not compare strings: it rebuilds the digest from the columns
  // that came back out of the database and checks it against the signed envelope.
  const p = await pair()
  const note = 'Saw your protocol work and want to compare notes'
  const r = await canonicalRequest(p, { note })
  assert.equal(r.status, 201, JSON.stringify(r.json))

  const row = introRow(r.json.intro_id)
  const rebuilt = sha256Hex(jcs({
    domain: env.PAYLOAD_DOMAIN,
    operation: 'request_intro',
    resource: { type: 'intro_request', id: r.requestId },
    payload: { from_card: row.from_card, to_card: row.to_card, purpose: row.purpose, note: row.note },
  }))
  assert.equal(rebuilt, r.built.payloadDigest,
    'the stored row reproduces the digest, so the bytes stored are the bytes signed')

  const ev = db.getDb().prepare('SELECT payload_digest, envelope_json FROM write_evidence WHERE write_ref = ?')
    .get(r.built.writeRef) as any
  assert.equal(ev.payload_digest, rebuilt)
  assert.equal(ev.envelope_json, r.built.envelopeBytes, 'and the exact signed bytes are retained verbatim')
})

test('INVARIANT 4: the same note through the legacy branch is rewritten, which is today\'s behavior and stays', async () => {
  // The pair of assertions that pins contradiction C2 as a test rather than as prose:
  // invariant 4 holds on one lane and not on the other, deliberately, because the legacy
  // signature does not cover the note either way.
  const p = await pair()
  const note = '  see https://evil.example/x   for   details  '
  const legacy = await legacyRequest(p, note)
  assert.equal(legacy.status, 201)
  const row = introRow(legacy.json.id)
  assert.notEqual(row.note, note, 'the legacy lane repairs')
  assert.equal(row.note, 'see [link removed] for details',
    'five transforms: link replacement, whitespace collapse, trim, the 200 slice and String() coercion')

  const ev = evidenceRows(legacy.json.id)
  assert.equal(ev.length, 1)
  assert.equal(ev[0].evidence, 'legacy_unbound')
  assert.deepEqual(JSON.parse(ev[0].bound_fields_json), ['from_card', 'to_card', 'purpose'],
    'and the note is absent from the bound list, so no receipt can name it')
  assert.equal(evidence.covers(ev[0], 'note'), false)
  assert.equal(ev[0].legacy_preimage, 'intro-request:${from_card}:${to_card}:${purpose}:${nonce}')
})

// ══════════════════════════════════════════════════════════════
// express_interest and decline, the canonical lane
// ══════════════════════════════════════════════════════════════

/** A canonical intro in `requested`, ready for the target to answer. */
async function requested(): Promise<{ p: Pair; introId: string }> {
  const p = await pair()
  const r = await canonicalRequest(p)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  return { p, introId: r.json.intro_id }
}

test('CANONICAL EXPRESS_INTEREST: stores no contact, writes one authorization, and materializes accepted', async () => {
  const { p, introId } = await requested()
  const s = signedBody({ operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: p.to.keys })
  const r = await post(`${introId}/respond`, s.body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.state, 'interested')
  assert.equal(r.json.contact_shared, false)

  const row = introRow(introId)
  assert.equal(row.status, 'accepted', 'which four unchanged predicates need')
  assert.equal(row.to_contact, null, 'and no contact is stored, because none was sent')
  assert.equal(row.from_contact, null)
  assert.ok(row.responded_at, 'responded_at is stamped without touching either contact column')

  const auths = authRows(introId).filter(a => a.actor_key === p.to.keys.publicKey)
  assert.equal(auths.length, 1, 'ONE authorization, where the legacy accept writes two')
  assert.equal(auths[0].operation, 'express_interest')
  assert.equal(auths[0].evidence, 'canonical')
  assert.equal(facts.stateOf(introId), 'interested')
})

test('CANONICAL EXPRESS_INTEREST: the four predicates that key on the column behave', async () => {
  const { p, introId } = await requested()
  await post(`${introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: p.to.keys,
  }).body)
  const row = introsDb.getIntro(introId)!

  assert.equal(introsDb.isComplete(row), false, 'not complete: accepted but no contacts yet')
  assert.equal(row.status, 'accepted', 'so the legacy complete guard at intros-routes.ts:165 passes')

  const nonce = 'm' + randomBytes(4).toString('hex')
  const qs = new URLSearchParams({
    public_key: p.from.keys.publicKey, nonce,
    signature: sign(`intro-mine:${nonce}`, p.from.keys.privateKey),
  })
  const mine = await (await fetch(`${base}/api/v3/intros/mine?${qs}`)).json()
  const seen = mine.intros.find((x: any) => x.id === introId)
  assert.equal(seen.awaiting, 'your_contact', 'the requester keeps the hint that tells them to share')
  assert.equal(seen.status, 'accepted')
  assert.equal(seen.counterparty_contact, null, 'and nothing is released')

  const tNonce = 'm' + randomBytes(4).toString('hex')
  const tqs = new URLSearchParams({
    public_key: p.to.keys.publicKey, nonce: tNonce,
    signature: sign(`intro-mine:${tNonce}`, p.to.keys.privateKey),
  })
  const theirs = await (await fetch(`${base}/api/v3/intros/mine?${tqs}`)).json()
  const incomingPending = theirs.intros.filter((x: any) => x.direction === 'incoming' && x.status === 'pending')
  assert.equal(incomingPending.find((x: any) => x.id === introId), undefined,
    'an intro the target already answered leaves the target\'s incoming list')
})

test('CANONICAL EXPRESS_INTEREST: only the target, only in requested, and a resend returns the stored result', async () => {
  const { p, introId } = await requested()
  const wrongActor = await post(`${introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: p.from.keys,
  }).body)
  assert.equal(wrongActor.status, 403)
  assert.equal(wrongActor.json.code, 'not_the_target')

  const s = signedBody({ operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: p.to.keys })
  assert.equal((await post(`${introId}/respond`, s.body)).status, 201)
  const replay = await post(`${introId}/respond`, s.body)
  assert.equal(replay.status, 200)
  assert.equal(replay.json.idempotent, true)

  // A fresh envelope for the same act is a state answer: the target has already answered.
  const fresh = await post(`${introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: p.to.keys,
  }).body)
  assert.equal(fresh.status, 409)
  assert.equal(fresh.json.code, 'wrong_state')
})

test('CANONICAL DECLINE: derives declined, materializes declined, and cannot follow an interest', async () => {
  const { p, introId } = await requested()
  const r = await post(`${introId}/respond`, signedBody({
    operation: 'decline', resource: { type: 'intro', id: introId }, keys: p.to.keys,
  }).body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.state, 'declined')
  assert.equal(introRow(introId).status, 'declined')
  assert.equal(facts.stateOf(introId), 'declined')

  const again = await post(`${introId}/respond`, signedBody({
    operation: 'decline', resource: { type: 'intro', id: introId }, keys: p.to.keys,
  }).body)
  assert.equal(again.status, 409)
  assert.equal(again.json.code, 'intro_terminal')

  // The other order: interest first, then a decline, which withdraw_interest exists for.
  const b = await requested()
  await post(`${b.introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: b.introId }, keys: b.p.to.keys,
  }).body)
  const late = await post(`${b.introId}/respond`, signedBody({
    operation: 'decline', resource: { type: 'intro', id: b.introId }, keys: b.p.to.keys,
  }).body)
  assert.equal(late.status, 409)
  assert.equal(late.json.code, 'wrong_state')
})

// ══════════════════════════════════════════════════════════════
// The dispatch itself
// ══════════════════════════════════════════════════════════════

test('DISPATCH: the envelope key chooses the lane, and a path that disagrees with the envelope is refused', async () => {
  const { p, introId } = await requested()
  const other = await requested()

  // The signed envelope names one intro and the path names another.
  const mismatch = await post(`${other.introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: p.to.keys,
  }).body)
  assert.equal(mismatch.status, 400)
  assert.equal(mismatch.json.code, 'path_resource_mismatch')
  assert.equal(authRows(introId).filter(a => a.operation === 'express_interest').length, 0, 'and nothing was written')
  assert.equal(authRows(other.introId).filter(a => a.operation === 'express_interest').length, 0)

  // A legacy body on the same path still reaches the legacy handler, unchanged.
  const legacy = await legacyRespond(p, introId, 'decline')
  assert.equal(legacy.status, 200)
  assert.deepEqual(legacy.json, { id: introId, status: 'declined' }, 'byte for byte the old response')
})

// ══════════════════════════════════════════════════════════════
// The legacy adapters, the four cases per action
// ══════════════════════════════════════════════════════════════

test('LEGACY ACCEPT (b): one signature, TWO authorizations, and a bound list naming neither the contact nor the sharing', async () => {
  // The single most important compatibility case in the design: an old client's one act
  // means two things in the new model.
  const p = await pair()
  const req = await legacyRequest(p)
  assert.equal(req.status, 201)
  const introId = req.json.id

  const r = await legacyRespond(p, introId, 'accept', 'alice@example.com')
  assert.equal(r.status, 200, JSON.stringify(r.json))
  assert.equal(r.json.status, 'accepted')
  assert.equal(r.json.awaiting, 'requester_contact', 'the old response shape, unchanged')

  const row = introRow(introId)
  assert.equal(row.status, 'accepted')
  assert.equal(row.to_contact, 'alice@example.com', 'today\'s path exactly: the contact is stored')

  const targetAuths = authRows(introId).filter(a => a.actor_key === p.to.keys.publicKey)
  assert.deepEqual(targetAuths.map(a => a.operation).sort(), ['express_interest', 'share_contact'])
  assert.ok(targetAuths.every(a => a.evidence === 'legacy_unbound'))
  assert.equal(new Set(targetAuths.map(a => a.evidence_id)).size, 1,
    'both point at ONE evidence row, because there was one signature')

  const ev = db.getDb().prepare('SELECT * FROM write_evidence WHERE evidence_id = ?').get(targetAuths[0].evidence_id) as any
  assert.deepEqual(JSON.parse(ev.bound_fields_json), ['id', 'action'],
    'the preimage is intro-respond:id:action:nonce and the contact is attached outside it at build/index.js:834-835')
  assert.equal(evidence.covers(ev, 'contact'), false, 'so no receipt may ever name the contact line stored with it')
  assert.equal(ev.write_ref, null, 'and there is no envelope, so no write_ref')
  assert.equal(ev.payload_digest, null)

  // The lifecycle still derives correctly from legacy facts alone.
  assert.equal(facts.stateOf(introId), 'connecting', 'one live share_contact is one live continuation')
  assert.equal(state.materializedStatus(facts.stateOf(introId)!), 'accepted', 'which agrees with the column')
})

test('LEGACY ACCEPT (a): a grandfathered row behaves exactly as at 909ffe3, asserted against the stored columns', async () => {
  const p = await pair()
  const req = await legacyRequest(p)
  const introId = req.json.id
  // Make it genuinely pre-2A: backdate it and remove every write subsystem row, which is
  // the state of a row that existed before this build opened the database.
  const marker = db.getSchemaMarker(db.MINGLE_2A_MARKER_KEY)!
  const d = db.getDb()
  d.prepare('UPDATE v3_intros SET created_at = ? WHERE id = ?').run(new Date(Date.parse(marker) - 864e5).toISOString(), introId)
  d.prepare('DELETE FROM connection_authorizations WHERE intro_id = ?').run(introId)
  d.prepare('DELETE FROM write_evidence WHERE resource_id = ?').run(introId)
  d.prepare('DELETE FROM write_auth_mode WHERE resource_id = ?').run(introId)
  assert.equal(facts.isPre2AIntro(introId), true)

  const r = await legacyRespond(p, introId, 'accept', 'grandfathered@example.com')
  assert.equal(r.status, 200, JSON.stringify(r.json))
  const row = introRow(introId)
  assert.equal(row.status, 'accepted', 'the column, not a derivation of facts it does not have')
  assert.equal(row.to_contact, 'grandfathered@example.com')
  assert.ok(row.responded_at)
  // And the derivation would answer something else, which is exactly why the legacy lane
  // does not materialize: it has no request_intro fact to derive mutual interest from.
  assert.notEqual(facts.stateOf(introId), 'connecting')
  assert.equal(row.status, 'accepted', 'the column is untouched by that disagreement')
})

test('LEGACY ACCEPT (d): after the cutoff it is 426 with the decided text, and the pre-2A row is exempt', async () => {
  const now = await pair()
  const reqNow = await legacyRequest(now)
  const modern = reqNow.json.id

  const old = await pair()
  const reqOld = await legacyRequest(old)
  const grandfathered = reqOld.json.id
  const marker = db.getSchemaMarker(db.MINGLE_2A_MARKER_KEY)!
  db.getDb().prepare('UPDATE v3_intros SET created_at = ? WHERE id = ?')
    .run(new Date(Date.parse(marker) - 864e5).toISOString(), grandfathered)

  setCutoff(new Date(Date.now() - 60_000).toISOString())
  const refused = await capturingWarnings(() => legacyRespond(now, modern, 'accept', 'a@example.com'))
  assert.equal(refused.result.status, 426)
  assert.deepEqual(refused.result.json, {
    code: 'client_upgrade_required', error: 'Update Mingle to continue this connection.',
  }, 'byte exact, and identical to the anti-downgrade body')
  assert.ok(refused.lines.some(l => l.includes('legacy write window closed')),
    'the log is the only place the two refusals differ')
  assert.equal(introRow(modern).status, 'pending', 'and nothing was written')

  const exempt = await legacyRespond(old, grandfathered, 'accept', 'b@example.com')
  assert.equal(exempt.status, 200, 'the grandfathered row stays on the old path until terminal or expired')
  assert.equal(introRow(grandfathered).to_contact, 'b@example.com')
})

test('LEGACY ACCEPT: an actor with a canonical mode row on this intro is 426 with reason downgrade prevention', async () => {
  const { p, introId } = await requested()
  // The target answers canonically, which records mode canonical for that key on that
  // intro. Its next legacy act on the same resource is a downgrade.
  assert.equal((await post(`${introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: p.to.keys,
  }).body)).status, 201)

  const refused = await capturingWarnings(() => legacyRespond(p, introId, 'accept', 'downgrade@example.com'))
  assert.equal(refused.result.status, 426)
  assert.equal(refused.result.json.code, 'client_upgrade_required')
  assert.equal(refused.result.json.error, 'Update Mingle to continue this connection.')
  assert.ok(refused.lines.some(l => l.includes('downgrade prevention')),
    'the internal log records which of the two refused it')
  assert.equal(introRow(introId).to_contact, null, 'and no contact was stored')

  // The counterparty is untouched: a mode row exists only for a key that actually signed.
  assert.equal(facts.stateOf(introId), 'interested')
})

test('LEGACY REQUEST: records one legacy_unbound authorization, and anti-downgrade cannot apply to a create', async () => {
  // One requester card and two targets, so the same key can create canonically once and
  // then send a legacy create. A create names a resource that does not exist yet, so there
  // is nothing for anti-downgrade to resolve against: the check is structurally a no-op
  // here rather than something skipped by choice.
  const from = makeCard('one requester')
  const fromCard = await publish(from)
  const t1 = makeCard('target one'); const t2 = makeCard('target two')
  const p1: Pair = { from, to: t1, fromCard, toCard: await publish(t1) }
  const p = { from, to: t2, fromCard, toCard: await publish(t2) } as Pair

  const canonical = await canonicalRequest(p1)
  assert.equal(canonical.status, 201, JSON.stringify(canonical.json))
  const modeRow = db.getDb().prepare('SELECT mode FROM write_auth_mode WHERE actor_key = ? AND resource_type = ?')
    .get(from.keys.publicKey, 'intro_request') as any
  assert.equal(modeRow.mode, 'canonical', 'this key does hold a canonical mode row')

  const r = await legacyRequest(p, 'plain note')
  assert.equal(r.status, 201, JSON.stringify(r.json))
  const auths = authRows(r.json.id)
  assert.equal(auths.length, 1)
  assert.equal(auths[0].operation, 'request_intro')
  assert.equal(auths[0].evidence, 'legacy_unbound')
  const mode = db.getDb().prepare('SELECT mode FROM write_auth_mode WHERE resource_type = ? AND resource_id = ? AND actor_key = ?')
    .get('intro', r.json.id, p.from.keys.publicKey) as any
  assert.equal(mode.mode, 'legacy_unbound')
  // No nonce was reserved: the published client's nonce is not unique by construction.
  const n = (db.getDb().prepare('SELECT COUNT(*) AS n FROM write_nonces WHERE resource_id = ?').get(r.json.id) as any).n
  assert.equal(n, 0)
})

test('LEGACY REQUEST: after the cutoff a create is 426, with the window reason', async () => {
  const p = await pair()
  setCutoff(new Date(Date.now() - 1000).toISOString())
  const before = (db.getDb().prepare('SELECT COUNT(*) AS n FROM v3_intros').get() as any).n
  const refused = await capturingWarnings(() => legacyRequest(p))
  assert.equal(refused.result.status, 426)
  assert.equal(refused.result.json.code, 'client_upgrade_required')
  assert.ok(refused.lines.some(l => l.includes('legacy write window closed')))
  assert.equal((db.getDb().prepare('SELECT COUNT(*) AS n FROM v3_intros').get() as any).n, before)

  // And the canonical lane is unaffected by the cutoff, which is the point of having one.
  clearCutoff()
  const q = await pair()
  setCutoff(new Date(Date.now() - 1000).toISOString())
  assert.equal((await canonicalRequest(q)).status, 201, 'the cutoff closes the legacy lane and nothing else')
})

test('LEGACY DECLINE: one authorization whose signature covers all of its semantics', async () => {
  const p = await pair()
  const introId = (await legacyRequest(p)).json.id
  const r = await legacyRespond(p, introId, 'decline')
  assert.equal(r.status, 200)
  assert.deepEqual(r.json, { id: introId, status: 'declined' })
  assert.equal(introRow(introId).status, 'declined')

  const targetAuths = authRows(introId).filter(a => a.actor_key === p.to.keys.publicKey)
  assert.equal(targetAuths.length, 1)
  assert.equal(targetAuths[0].operation, 'decline')
  assert.equal(targetAuths[0].evidence, 'legacy_unbound')
  const ev = db.getDb().prepare('SELECT * FROM write_evidence WHERE evidence_id = ?').get(targetAuths[0].evidence_id) as any
  assert.deepEqual(JSON.parse(ev.bound_fields_json), ['id', 'action'],
    'the intro id and the action are everything a decline has, so this is the one legacy act with no evidence gap')
  assert.equal(facts.stateOf(introId), 'declined', 'and the derivation agrees with the column')
})

test('LEGACY DECLINE_AND_BLOCK: two effects and two authorizations from one signature', async () => {
  const p = await pair()
  const introId = (await legacyRequest(p)).json.id
  const r = await legacyRespond(p, introId, 'decline_and_block')
  assert.equal(r.status, 200)
  assert.deepEqual(r.json, { id: introId, status: 'declined', blocked: true }, 'the old response shape')
  assert.equal(introsDb.isBlocked(p.fromCard, p.toCard), true)

  const targetAuths = authRows(introId).filter(a => a.actor_key === p.to.keys.publicKey)
  assert.deepEqual(targetAuths.map(a => a.operation).sort(), ['block_pair', 'decline'])
  assert.equal(new Set(targetAuths.map(a => a.evidence_id)).size, 1, 'from one signature')
  assert.ok(targetAuths.every(a => a.evidence === 'legacy_unbound'))
  // Rule 2 checks decline before block_pair, so the state is declined rather than blocked,
  // and the column says the same.
  assert.equal(facts.stateOf(introId), 'declined')
  assert.equal(introRow(introId).status, 'declined')
})

test('LEGACY: with no cutoff marker and with a future cutoff, every legacy route works', async () => {
  clearCutoff()
  const open = await pair()
  const a = await legacyRequest(open)
  assert.equal(a.status, 201, 'an unstamped cutoff means the window is OPEN, never closed')
  assert.equal((await legacyRespond(open, a.json.id, 'accept', 'x@example.com')).status, 200)

  setCutoff(new Date(Date.now() + 30 * 864e5).toISOString())
  const future = await pair()
  const b = await legacyRequest(future)
  assert.equal(b.status, 201)
  assert.equal((await legacyRespond(future, b.json.id, 'decline')).status, 200)
  assert.equal(db.legacyWindowClosed(), false)
})

// ══════════════════════════════════════════════════════════════
// The invariant that ties the two lanes together
// ══════════════════════════════════════════════════════════════

test('AGREEMENT: after every canonical write the column equals what the derivation materializes', async () => {
  const rows = db.getDb().prepare(`
    SELECT DISTINCT a.intro_id FROM connection_authorizations a
    WHERE a.evidence = 'canonical'
  `).all() as { intro_id: string }[]
  assert.ok(rows.length > 5, `the suite did write canonically, found ${rows.length}`)
  for (const { intro_id } of rows) {
    const f = facts.introFacts(intro_id)!
    const derived = state.deriveIntroState(f)
    assert.equal(introRow(intro_id).status, state.materializedStatus(derived),
      `${intro_id} derives ${derived}`)
  }
})

test('AGREEMENT: a mixed pair reaches the same place, and the two evidence rows differ in bound_fields_json', async () => {
  // An OLD requester and a NEW target, which puts both evidence rows on the same resource.
  // The other mix, a canonical requester and a legacy target, also works but its rows sit
  // under two resource identities, because a create names intro_request and every later
  // act names the intro. That is asserted separately below.
  const p = await pair()
  const introId = (await legacyRequest(p, 'old client note')).json.id
  const r = await post(`${introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: p.to.keys,
  }).body)
  assert.equal(r.status, 201, JSON.stringify(r.json))

  const rows = evidenceRows(introId)
  const canonical = rows.find(x => x.evidence === 'canonical')
  const legacy = rows.find(x => x.evidence === 'legacy_unbound')
  assert.ok(canonical && legacy, 'one row per lane, both on the intro')
  assert.notDeepEqual(JSON.parse(canonical.bound_fields_json), JSON.parse(legacy.bound_fields_json))
  assert.deepEqual(JSON.parse(legacy.bound_fields_json), ['from_card', 'to_card', 'purpose'])
  assert.equal(evidence.covers(legacy, 'note'), false, 'the old requester\'s note is unbound')
  assert.equal(canonical.payload_digest !== null, true, 'and the new target\'s act carries a digest')
  assert.equal(facts.stateOf(introId), 'interested', 'and the lifecycle reads both lanes as one fact set')
  assert.equal(introRow(introId).status, 'accepted')
})

test('AGREEMENT: a canonical create and a legacy response leave evidence under two resource identities', async () => {
  const { p, introId } = await requested()
  assert.equal((await legacyRespond(p, introId, 'accept', 'mixed@example.com')).status, 200)

  const onIntro = evidenceRows(introId)
  assert.equal(onIntro.length, 1, 'only the legacy response names the intro')
  assert.equal(onIntro[0].evidence, 'legacy_unbound')

  const created = db.getDb().prepare('SELECT request_id FROM write_create_map WHERE created_id = ?').get(introId) as any
  const onRequest = db.getDb().prepare('SELECT * FROM write_evidence WHERE resource_type = ? AND resource_id = ?')
    .all('intro_request', created.request_id) as any[]
  assert.equal(onRequest.length, 1, 'the create names intro_request, because the intro did not exist yet')
  assert.equal(onRequest[0].evidence, 'canonical')
  // And the two are linked, which is what makes anti-downgrade resolvable without
  // pre-writing a row for a resource nobody has acted on.
  const { resolveAuthMode } = await import('../src/write-db.js')
  assert.equal(resolveAuthMode('intro', introId, p.from.keys.publicKey), 'canonical',
    'resolved by walking write_create_map back to the create')
  assert.equal(facts.stateOf(introId), 'connecting')
})

test('GATE: the two refusals share a body and a status, and differ only in the reason', () => {
  assert.equal(gate.LEGACY_REFUSAL.status, 426)
  assert.equal(gate.LEGACY_REFUSAL.code, 'client_upgrade_required')
  assert.equal(gate.LEGACY_REFUSAL.error, 'Update Mingle to continue this connection.')
})
