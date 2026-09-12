// ══════════════════════════════════════════════════════════════
// The pre-2A bridge, and what the sweep may not touch
// ══════════════════════════════════════════════════════════════
// Two independent reviews found the same defect from opposite ends, and it was the most
// serious thing in the whole change: an intro created BEFORE this build has no authorization
// rows, so the derivation could see nothing but its age.
//
//   the hourly sweep read `expired` for a FINISHED legacy connection and materialized
//     `withdrawn` over it, so both parties lost a contact line they had already exchanged,
//     with no route able to put it back
//   a canonical express_interest or decline on an already accepted pre-2A intro passed the
//     state guard, because no facts meant `requested`, and re-stated the intro
//   a legacy accept on one left a pair whose requester could never share canonically, because
//     hasMutualInterest needs a request_intro row that nothing wrote
//
// The fix has two halves, and both are asserted here. The bridge translates a `pending` pre-2A
// intro into the one fact its own row proves, once, inside an act's transaction. Anything
// further along is REFUSED rather than guessed at. And the sweep materializes a factless intro
// only from `pending`, the one legacy value that carries nothing the derivation cannot see.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-pre2a-test-'))
process.env.DB_PATH = join(tmpDir, 'pre2a.db')
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
const { cardContentHash } = await import('../src/v3-cards.js')
const { newNonce, jcs } = await import('../src/canonical-write.js')

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

const rid = () => randomBytes(4).toString('hex')
const DAY = 864e5

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

async function post(url: string, body: unknown) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  let json: any = null
  try { json = await res.json() } catch { /* none */ }
  return { status: res.status, json }
}
async function publish(built: any): Promise<string> {
  const r = await post(`${base}/api/v3/cards`, { card: built.card })
  assert.ok(r.json.card_id, JSON.stringify(r.json))
  return r.json.card_id
}

const marker = () => db.getSchemaMarker(db.MINGLE_2A_MARKER_KEY)!
const preMarker = (days: number) => new Date(Date.parse(marker()) - days * DAY).toISOString()

interface Pre2A { id: string; from: any; to: any; fromCard: string; toCard: string }

/** A row exactly as it sits on disk from before this build: a real intro, backdated behind the
 *  2A marker, with every write subsystem row removed because the code that writes them did
 *  not exist yet. */
async function pre2A(status: string, fromContact: string | null, toContact: string | null, ageDays = 60): Promise<Pre2A> {
  const from = makeCard('requester ' + rid())
  const to = makeCard('target ' + rid())
  const fromCard = await publish(from)
  const toCard = await publish(to)
  const nonce = 'n' + rid()
  const req = await post(`${base}/api/v3/intros/request`, {
    from_card: fromCard, to_card: toCard, purpose: 'collaborate', note: 'old',
    public_key: from.keys.publicKey, nonce,
    signature: sign(`intro-request:${fromCard}:${toCard}:collaborate:${nonce}`, from.keys.privateKey),
  })
  assert.equal(req.status, 201, JSON.stringify(req.json))
  const id = req.json.id
  const d = db.getDb()
  d.prepare('UPDATE v3_intros SET created_at = ?, status = ?, from_contact = ?, to_contact = ? WHERE id = ?')
    .run(preMarker(ageDays), status, fromContact, toContact, id)
  d.prepare('DELETE FROM connection_authorizations WHERE intro_id = ?').run(id)
  d.prepare('DELETE FROM write_evidence WHERE resource_id = ?').run(id)
  d.prepare('DELETE FROM write_auth_mode WHERE resource_id = ?').run(id)
  assert.equal(facts.isPre2AIntro(id), true)
  assert.equal(facts.hasAuthorizations(id), false)
  return { id, from, to, fromCard, toCard }
}

function signedBody(over: { operation: string; resource: any; payload?: any; keys: any }) {
  const payload = over.payload ?? {}
  const built = env.buildEnvelope({
    operation: over.operation as any, actorKey: over.keys.publicKey, resource: over.resource,
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'), nonce: newNonce(), payload,
  })
  return { body: { envelope: built.envelope, signature: sign(jcs(built.envelope), over.keys.privateKey), payload }, built }
}
const statusOf = (id: string) => (db.getDb().prepare('SELECT status FROM v3_intros WHERE id = ?').get(id) as any).status

async function mine(keys: any): Promise<any[]> {
  const nonce = 'm' + rid()
  const qs = new URLSearchParams({
    public_key: keys.publicKey, nonce, signature: sign(`intro-mine:${nonce}`, keys.privateKey),
  })
  return (await (await fetch(`${base}/api/v3/intros/mine?${qs}`)).json()).intros
}

// ══════════════════════════════════════════════════════════════
// The sweep
// ══════════════════════════════════════════════════════════════

test('SWEEP: a FINISHED pre-2A connection is never materialized, and both parties keep their contact', async () => {
  // The most serious defect the review found. Before the fix, one hour after boot this row
  // became `withdrawn` with both contact columns still populated, isComplete flipped to false,
  // and GET /mine answered complete:false and counterparty_contact:null for BOTH parties.
  const p = await pre2A('accepted', 'requester@old.example', 'target@old.example')
  assert.equal(facts.legacyComplete(p.id), true)
  assert.equal(introsDb.isComplete(introsDb.getIntro(p.id)!), true)
  assert.equal(facts.stateOf(p.id), 'expired', 'the derivation still says expired, because it has no facts')

  const swept = facts.sweepExpiredIntros()
  assert.equal(swept.includes(p.id), false, 'and the sweep declines to write that answer down')
  assert.equal(statusOf(p.id), 'accepted')
  assert.equal(introsDb.isComplete(introsDb.getIntro(p.id)!), true)
  assert.equal(facts.contactsExchanged(p.id), true)

  for (const [who, expected] of [[p.from, 'target@old.example'], [p.to, 'requester@old.example']] as const) {
    const row = (await mine(who.keys)).find(x => x.id === p.id)
    assert.equal(row.complete, true, 'the connection still reads as complete')
    assert.equal(row.counterparty_contact, expected, 'and the contact they earned is still there')
    assert.equal(row.status, 'accepted')
  }
})

test('SWEEP: a pre-2A ACCEPTED but incomplete intro is left alone too', async () => {
  // The target accepted and shared before this build, and the requester never completed. Under the
  // old semantics that row had no expiry at all, and materializing `withdrawn` over it would
  // lose the `awaiting` hint the old client shows the requester.
  const p = await pre2A('accepted', null, 'target@old.example')
  assert.equal(facts.legacyComplete(p.id), false, 'not complete, so contactsExchanged alone would not protect it')
  assert.equal(facts.sweepExpiredIntros().includes(p.id), false)
  assert.equal(statusOf(p.id), 'accepted')
})

test('SWEEP: a pre-2A DECLINED or BLOCKED intro is left alone, and a pre-2A PENDING one is swept', async () => {
  for (const terminal of ['declined', 'blocked', 'withdrawn']) {
    const p = await pre2A(terminal, null, null)
    assert.equal(facts.sweepExpiredIntros().includes(p.id), false, terminal)
    assert.equal(statusOf(p.id), terminal, `${terminal} is not rewritten`)
  }
  // `pending` IS swept, because it is the one legacy value carrying nothing the derivation
  // cannot also see, and stopping a lapsed request showing in an old client's incoming list
  // forever is the whole reason the sweep exists.
  const pending = await pre2A('pending', null, null)
  assert.equal(facts.sweepExpiredIntros().includes(pending.id), true)
  assert.equal(statusOf(pending.id), 'withdrawn')
  const incoming = (await mine(pending.to.keys)).filter(x => x.direction === 'incoming' && x.status === 'pending')
  assert.equal(incoming.find(x => x.id === pending.id), undefined, 'and it leaves the incoming list')
})

test('SWEEP: a post-2A intro is unaffected by the new guard, because it has facts', async () => {
  // The guard must not protect a row the derivation CAN speak for, or a genuinely lapsed
  // canonical intro would never be materialized.
  const from = makeCard('post req'); const to = makeCard('post tgt')
  const fc = await publish(from); const tc = await publish(to)
  const nonce = 'n' + rid()
  const req = await post(`${base}/api/v3/intros/request`, {
    from_card: fc, to_card: tc, purpose: 'collaborate', note: 'x',
    public_key: from.keys.publicKey, nonce,
    signature: sign(`intro-request:${fc}:${tc}:collaborate:${nonce}`, from.keys.privateKey),
  })
  const id = req.json.id
  assert.equal(facts.hasAuthorizations(id), true, 'the legacy adapter wrote its request_intro row')
  db.getDb().prepare('UPDATE v3_intros SET created_at = ? WHERE id = ?')
    .run(new Date(Date.now() - 60 * DAY).toISOString(), id)
  db.getDb().prepare('UPDATE connection_authorizations SET created_at = ? WHERE intro_id = ?')
    .run(new Date(Date.now() - 60 * DAY).toISOString(), id)
  assert.equal(facts.stateOf(id), 'expired')
  assert.equal(facts.sweepExpiredIntros().includes(id), true, 'and it IS swept')
  assert.equal(statusOf(id), 'withdrawn')
})

// ══════════════════════════════════════════════════════════════
// The bridge, and the refusal
// ══════════════════════════════════════════════════════════════

test('BRIDGE: a pre-2A PENDING intro is bridged once, carrying the intro\'s own time and no evidence', async () => {
  const p = await pre2A('pending', null, null, 5)
  assert.equal(facts.bridgePre2AIntro(p.id), 'bridged')
  assert.equal(facts.bridgePre2AIntro(p.id), 'not_needed', 'idempotent: it has facts now')

  const row = db.getDb().prepare(
    "SELECT * FROM connection_authorizations WHERE intro_id = ? AND operation = 'request_intro'").get(p.id) as any
  assert.equal(row.actor_key, introsDb.getIntro(p.id)!.from_key, 'the REQUESTER\'s row, because they made the request')
  assert.equal(row.live, 1)
  assert.equal(row.evidence, 'legacy_unbound', 'it may never claim the request was canonically signed')
  assert.equal(row.evidence_id, facts.PRE_2A_ANTECEDENT)
  assert.equal(row.created_at, introsDb.getIntro(p.id)!.created_at,
    'the intro\'s own time, so the 14 day window measures from the real request')
  // The sentinel is not a real evidence row, so a receipt renderer finds no warrant and emits
  // no clause. That fails closed, which is the only acceptable direction.
  assert.equal(facts.boundFieldsOfAuthorization(p.id, row.actor_key, 'request_intro'), null)
  assert.equal(facts.stateOf(p.id), 'requested')
})

test('BRIDGE: anything past a request is NOT bridgeable, and the canonical lane refuses it', async () => {
  for (const [status, from, to] of [
    ['accepted', 'a@old.example', 'b@old.example'],
    ['accepted', null, 'b@old.example'],
    ['declined', null, null],
    ['blocked', null, null],
    ['withdrawn', null, null],
  ] as const) {
    const p = await pre2A(status, from, to, 5)
    assert.equal(facts.bridgePre2AIntro(p.id), 'not_bridgeable', status)

    // Both destructive canonical acts are refused, where before the fix both SUCCEEDED and
    // re-stated the intro.
    for (const operation of ['express_interest', 'decline'] as const) {
      const r = await post(`${base}/api/v3/intros/${p.id}/respond`, signedBody({
        operation, resource: { type: 'intro', id: p.id }, keys: p.to.keys,
      }).body)
      assert.equal(r.status, 409, `${status}/${operation}: ${JSON.stringify(r.json)}`)
      assert.equal(r.json.code, 'legacy_intro_not_upgradable', `${status}/${operation}`)
    }
    assert.equal(statusOf(p.id), status, `${status}: the column was not touched`)
    assert.equal(facts.hasAuthorizations(p.id), false, `${status}: and no fact was guessed at`)
    const row = introsDb.getIntro(p.id)!
    assert.equal(row.from_contact, from, `${status}: contacts untouched`)
    assert.equal(row.to_contact, to)
  }
})

test('BRIDGE: a LEGACY ACT\'s own row does not make a pre-2A intro bridgeable', async () => {
  // THE DEFECT THIS CLOSES, reproduced end to end before the fix.
  //
  // The bridge and the read projection both asked hasAuthorizations, meaning "does any row
  // exist". The legacy POST /:id/complete handler writes a share_contact row of its own. So a
  // pre-2A intro that a published client accepted and then completed ended up with exactly one
  // authorization row, no request_intro, and hasAuthorizations true. That answered
  // 'not_needed' instead of 'not_bridgeable', the derivation answered `requested` because
  // nothing recorded a request to have been answered, and the canonical decline the projection
  // then advertised returned 201 and set the column to `declined`, which is terminal. A
  // released connection, destroyed.
  //
  // The gate is now the request_intro ANTECEDENT, which is what every rule in the derivation
  // rests on, so no other row can stand in for it.
  const p = await pre2A('accepted', null, 'b@old.example', 5)

  // The requester completes on the legacy lane, exactly as a published 3.2.2 install does.
  const nonce = 'c' + rid()
  const comp = await post(`${base}/api/v3/intros/${p.id}/complete`, {
    contact: 'a@old.example', public_key: p.from.keys.publicKey, nonce,
    signature: sign(`intro-complete:${p.id}:${nonce}`, p.from.keys.privateKey),
  })
  assert.equal(comp.status, 200, JSON.stringify(comp.json))
  assert.equal(comp.json.complete, true, 'the legacy lane considers this connection finished')

  // Exactly one row, and it is not the antecedent.
  assert.equal(facts.hasAuthorizations(p.id), true, 'the legacy complete wrote its own row')
  assert.equal(facts.hasRequestAntecedent(p.id), false, 'and it is not a request_intro')
  assert.equal(facts.bridgePre2AIntro(p.id), 'not_bridgeable',
    'so the intro is still not bridgeable, which is what one row used to hide')

  // Both destructive canonical acts are refused.
  for (const operation of ['express_interest', 'decline'] as const) {
    const r = await post(`${base}/api/v3/intros/${p.id}/respond`, signedBody({
      operation, resource: { type: 'intro', id: p.id }, keys: p.to.keys,
    }).body)
    assert.equal(r.status, 409, `${operation}: ${JSON.stringify(r.json)}`)
    assert.equal(r.json.code, 'legacy_intro_not_upgradable', operation)
  }

  // And the connection is intact, on the column and on both contacts.
  assert.equal(statusOf(p.id), 'accepted', 'the released connection survived')
  const row = introsDb.getIntro(p.id)!
  assert.equal(row.from_contact, 'a@old.example')
  assert.equal(row.to_contact, 'b@old.example')
  assert.equal(introsDb.isComplete(row), true)

  // The read surface withholds the projection rather than serving a derivation over a fact set
  // that cannot describe this intro, while every field the published client reads is correct.
  for (const who of [p.from, p.to]) {
    const served = (await mine(who.keys)).find(r => r.id === p.id)
    assert.equal(served.state, null, 'no derived state for a row whose antecedent is absent')
    assert.deepEqual(served.pending_actions, [], 'and nothing is offered')
    assert.equal(served.expires_at, null)
    assert.equal(served.status, 'accepted', 'while the compatibility fields answer as they did')
    assert.equal(served.complete, true)
    assert.ok(served.counterparty_contact, 'and the released contact is still readable')
  }
})

test('BRIDGE: a legacy accept on a pre-2A pending intro leaves a pair that CAN complete canonically', async () => {
  // The defect this closes: with no request_intro antecedent, hasMutualInterest was false
  // forever, so the requester's canonical share_contact was refused wrong_state and the
  // connection could never be made on the canonical lane.
  const p = await pre2A('pending', null, null, 5)
  const an = 'a' + rid()
  const acc = await post(`${base}/api/v3/intros/${p.id}/respond`, {
    action: 'accept', contact: 'target@old.example', public_key: p.to.keys.publicKey, nonce: an,
    signature: sign(`intro-respond:${p.id}:accept:${an}`, p.to.keys.privateKey),
  })
  assert.equal(acc.status, 200, JSON.stringify(acc.json))
  assert.equal(statusOf(p.id), 'accepted', 'today\'s stored value, unchanged')
  assert.equal(facts.stateOf(p.id), 'connecting', 'and the facts now agree with it')
  assert.equal(state.materializedStatus(facts.stateOf(p.id)!), 'accepted')

  // The requester can now share canonically, and that completes the connection.
  const resource = { type: 'intro' as const, id: p.id }
  const salt = randomBytes(32).toString('base64url')
  const contact = 'requester@new.example'
  const commitment = env.privateValueCommitment('share_contact', resource, salt, contact)
  const s = signedBody({
    operation: 'share_contact', resource, payload: { private_value_commitment: commitment }, keys: p.from.keys,
  })
  const shared = await post(`${base}/api/v3/intros/share-contact`, { ...s.body, opening: { value: contact, salt } })
  assert.equal(shared.status, 201, JSON.stringify(shared.json))
  assert.equal(shared.json.released, true, 'the pair connects, which it could not before')
  assert.equal(shared.json.state, 'connected')
  assert.equal(introsDb.isComplete(introsDb.getIntro(p.id)!), true)
})

test('BRIDGE: withdraw_request on a pre-2A pending intro goes through ONE path now', async () => {
  const p = await pre2A('pending', null, null, 5)
  const r = await post(`${base}/api/v3/intros/withdraw-request`, signedBody({
    operation: 'withdraw_request', resource: { type: 'intro', id: p.id }, keys: p.from.keys,
  }).body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(r.json.state, 'withdrawn')
  assert.equal(r.json.bridged_from_legacy, true, 'and it reports that its antecedent was bridged')
  assert.equal(statusOf(p.id), 'withdrawn')
})

test('BRIDGE: the marker is the boundary, so a post-2A intro is never bridged', async () => {
  // The gate that stops this becoming a general back door. Deleting a post-2A intro's rows
  // does not make it bridgeable, because the marker check fails whatever its rows say.
  const from = makeCard('modern req'); const to = makeCard('modern tgt')
  const fc = await publish(from); const tc = await publish(to)
  const nonce = 'n' + rid()
  const req = await post(`${base}/api/v3/intros/request`, {
    from_card: fc, to_card: tc, purpose: 'collaborate', note: 'x',
    public_key: from.keys.publicKey, nonce,
    signature: sign(`intro-request:${fc}:${tc}:collaborate:${nonce}`, from.keys.privateKey),
  })
  const id = req.json.id
  db.getDb().prepare('DELETE FROM connection_authorizations WHERE intro_id = ?').run(id)
  assert.equal(facts.isPre2AIntro(id), false)
  assert.equal(facts.hasAuthorizations(id), false)
  assert.equal(facts.bridgePre2AIntro(id), 'not_needed', 'no bridge, because it is not a pre-2A row')
  // And withdraw_request then refuses, because there is genuinely nothing to withdraw.
  const r = await post(`${base}/api/v3/intros/withdraw-request`, signedBody({
    operation: 'withdraw_request', resource: { type: 'intro', id }, keys: from.keys,
  }).body)
  assert.equal(r.status, 409)
  assert.equal(r.json.code, 'no_open_request')
})
