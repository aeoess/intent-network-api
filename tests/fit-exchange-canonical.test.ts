// ══════════════════════════════════════════════════════════════
// The v3 fit exchange, canonical
// ══════════════════════════════════════════════════════════════
// DOUBLE GATE: every route here sits behind MINGLE_FIT_ENABLED as well as behind the
// canonical pipeline, and that flag is unset in production. This suite sets it
// explicitly and restores the prior value, so what it covers is code that does not run
// in production today and no other suite depends on it having been set.
//
// THE RESOURCE IS THE EXCHANGE. resource.type is fit_exchange and resource.id is the
// exchange id, which is also the :id in the path, so canonicalDispatch refuses a
// disagreement between the two rather than picking a winner. These acts record canonical
// evidence and an anti-downgrade mode for the exchange, and they deliberately write no
// connection_authorizations row: the exchange is not the intro, it has its own window
// and its own state machine, and the authorization table keys on the intro.
//
// The repairs this file exists for, route by route:
//   round2   question_ids was in no preimage at all, so one valid fit-round2 signature
//            authorized escalating whatever questions the holder chose
//   custom   not one character of the question text was signed, and the server stored
//            the post-gate cleaned output rather than the signed text
//   answers  the preimage already was a content hash over the answers, but the stored
//            text was the cleaned string, so the record could not be recomputed from it
//   close    the closer signed "close exchange X" and the server computed the digest
//            afterwards, so the signature never said "this is the record"

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-fitex-test-'))
process.env.DB_PATH = join(tmpDir, 'fitex.db')
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey
// Scoped locally and restored in teardown, so nothing in this file leaks a flag value
// and nothing outside it depends on one.
const flagBefore = process.env.MINGLE_FIT_ENABLED
process.env.MINGLE_FIT_ENABLED = '1'

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const env = await import('../src/write-envelope.js')
const fitDb = await import('../src/fit-db.js')
const introsDb = await import('../src/intros-db.js')
const evidence = await import('../src/write-evidence.js')
const wdb = await import('../src/write-db.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const { newNonce, jcs } = await import('../src/canonical-write.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  introsDb.initIntrosSchema()
  fitDb.initFitSchema()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => {
  server?.close()
  db.closeDb()
  rmSync(tmpDir, { recursive: true, force: true })
  if (flagBefore === undefined) delete process.env.MINGLE_FIT_ENABLED
  else process.env.MINGLE_FIT_ENABLED = flagBefore
})
beforeEach(() => { db.getDb().prepare('DELETE FROM rate_limits').run() })

// ── Fixtures ──────────────────────────────────────────────────────────────

const rid = () => randomBytes(4).toString('hex')
const INTENT = 'cofound'

function makeCard(headline: string): any {
  const keys = generateKeyPair()
  const now = Date.now()
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(now).toISOString(), expires_at: new Date(now + 21 * 864e5).toISOString(),
    headline, intents: [INTENT], seeking: [], offering: [{ description: 'x', provenance: 'principal_statement' }],
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
  assert.ok(r.card_id, JSON.stringify(r))
  return r.card_id
}

interface Exchange { id: string; introId: string; alice: any; bob: any; aliceCard: string; bobCard: string }

/** An open exchange between two published cards, built directly rather than through the
 *  intro accept path, so a failure here is about the exchange routes and nothing else. */
async function exchange(opts: { expiresAt?: string } = {}): Promise<Exchange> {
  const alice = makeCard('Alice ' + rid())
  const bob = makeCard('Bob ' + rid())
  const aliceCard = await publish(alice)
  const bobCard = await publish(bob)
  const introId = `intro-v3-fx-${rid()}`
  db.getDb().prepare(`
    INSERT INTO v3_intros (id, from_card, to_card, from_key, to_key, purpose, note, status)
    VALUES (?, ?, ?, ?, ?, ?, '', 'accepted')
  `).run(introId, aliceCard, bobCard, alice.keys.publicKey, bob.keys.publicKey, INTENT)
  const id = `fit-${Date.now()}-${rid()}`
  fitDb.createExchange({
    id, intro_id: introId, card_a: aliceCard, card_b: bobCard,
    key_a: alice.keys.publicKey, key_b: bob.keys.publicKey, intent: INTENT,
    expires_at: opts.expiresAt ?? new Date(Date.now() + fitDb.FIT_WINDOW_MS).toISOString(),
    ledger_version_a: fitDb.getLedgerVersion(aliceCard),
    ledger_version_b: fitDb.getLedgerVersion(bobCard),
  })
  return { id, introId, alice, bob, aliceCard, bobCard }
}

function signedBody(over: { operation: string; resourceId: string; payload: any; keys: any; nonce?: string; resourceType?: string }) {
  const resource = { type: over.resourceType ?? 'fit_exchange', id: over.resourceId }
  const built = env.buildEnvelope({
    operation: over.operation as any, actorKey: over.keys.publicKey, resource: resource as any,
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'),
    nonce: over.nonce ?? newNonce(), payload: over.payload,
  })
  return {
    body: { envelope: built.envelope, signature: sign(jcs(built.envelope), over.keys.privateKey), payload: over.payload },
    built,
  }
}

async function postJson(url: string, body: unknown) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  let json: any = null
  try { json = await res.json() } catch { /* none */ }
  return { status: res.status, json }
}

const exUrl = (id: string, tail: string) => `${base}/api/v3/fit/${id}${tail}`

/** A recorded act on this exchange, so a later act has something to name. Any evidence
 *  row will do: what the antecedent check cares about is the resource, not the operation. */
function antecedentFor(exchangeId: string, actorKey: string): string {
  const ref = randomBytes(32).toString('hex')
  db.getDb().prepare(`
    INSERT INTO write_evidence
      (evidence_id, write_ref, actor_key, operation, resource_type, resource_id,
       evidence, envelope_json, signature, payload_digest, bound_fields_json, legacy_preimage)
    VALUES (?, ?, ?, 'fit_exchange_answers', 'fit_exchange', ?, 'canonical', '{}', ?, NULL, '[]', NULL)
  `).run('ev-ant-' + rid(), ref, actorKey, exchangeId, 'a'.repeat(128))
  return ref
}

// ══════════════════════════════════════════════════════════════
// round2, canonical
// ══════════════════════════════════════════════════════════════

test('EXCHANGE ROUND2: the signed question ids are stored exactly, and nothing else is', async () => {
  const ex = await exchange()
  const ante = antecedentFor(ex.id, ex.bob.keys.publicKey)
  const ids = ['cofound-1', 'cofound-3']
  const { body, built } = signedBody({
    operation: 'fit_exchange_round2', resourceId: ex.id, keys: ex.bob.keys,
    payload: { question_ids: ids, antecedent_write_ref: ante },
  })
  const res = await postJson(exUrl(ex.id, '/round2'), body)
  assert.equal(res.status, 201, JSON.stringify(res.json))
  assert.deepEqual(res.json.round2, ids)
  assert.equal(res.json.write_ref, built.writeRef)

  const stored = fitDb.round2ForExchange(ex.id)
  assert.deepEqual(stored.map(r => r.question_id).sort(), ids, 'byte identical to the signed list')
  for (const r of stored) assert.equal(r.requester_key, ex.bob.keys.publicKey)
  assert.equal(fitDb.getExchange(ex.id)!.state, 'round2')

  // The evidence row names the question ids, because the envelope's payload_digest covers
  // them. That is the whole repair: the legacy preimage named nothing but the exchange.
  const row = evidence.evidenceByWriteRef(built.writeRef)!
  assert.equal(row.evidence, 'canonical')
  assert.equal(row.resource_type, 'fit_exchange')
  assert.equal(row.resource_id, ex.id)
  assert.deepEqual(evidence.boundFieldsOf(row),
    ['operation', 'resource.id', 'payload.question_ids', 'payload.antecedent_write_ref'])
  assert.equal(evidence.covers(row, 'payload.question_ids'), true)
  // And the exchange act writes no intro fact, because the exchange is not the intro.
  const auths = db.getDb().prepare('SELECT COUNT(*) AS n FROM connection_authorizations WHERE intro_id = ?').get(ex.introId) as any
  assert.equal(auths.n, 0)
  // The anti-downgrade mode IS recorded, against the exchange.
  assert.equal(wdb.resolveAuthMode('fit_exchange', ex.id, ex.bob.keys.publicKey), 'canonical')
})

test('EXCHANGE ROUND2: an unknown question id is refused and NOT ONE id is stored', async () => {
  // The partial write this repair removes. The old loop validated and inserted in one
  // pass, so an unknown third id answered 400 with the first two already stored, which is
  // a refusal after a write.
  const ex = await exchange()
  const ante = antecedentFor(ex.id, ex.bob.keys.publicKey)
  const { body } = signedBody({
    operation: 'fit_exchange_round2', resourceId: ex.id, keys: ex.bob.keys,
    payload: { question_ids: ['cofound-1', 'zzz-nonsense'], antecedent_write_ref: ante },
  })
  const res = await postJson(exUrl(ex.id, '/round2'), body)
  assert.equal(res.status, 400)
  assert.equal(res.json.code, 'unknown_question_id')
  assert.deepEqual(fitDb.round2ForExchange(ex.id), [], 'the valid id must not survive the refusal')
  assert.equal(fitDb.getExchange(ex.id)!.state, 'answering', 'and the state must not have moved')
})

test('EXCHANGE ROUND2: the LEGACY lane also refuses before writing, and records a weak row', async () => {
  const ex = await exchange()
  const nonce = 'r' + rid()
  const legacy = async (question_ids: unknown[]) => postJson(exUrl(ex.id, '/round2'), {
    question_ids, public_key: ex.bob.keys.publicKey, nonce: nonce + rid(),
    signature: sign(`fit-round2:${ex.id}:${nonce}`, ex.bob.keys.privateKey),
  })
  // The signature is over a fixed nonce while the body carries a fresh one, so it fails,
  // which proves the shape before the real call. Then the real one.
  assert.equal((await legacy(['cofound-1'])).status, 403)

  const good = await postJson(exUrl(ex.id, '/round2'), {
    question_ids: ['cofound-1', 'nope'], public_key: ex.bob.keys.publicKey, nonce,
    signature: sign(`fit-round2:${ex.id}:${nonce}`, ex.bob.keys.privateKey),
  })
  assert.equal(good.status, 400)
  assert.deepEqual(fitDb.round2ForExchange(ex.id), [], 'the legacy lane must not leave a partial write either')

  const n2 = 'r2' + rid()
  const ok = await postJson(exUrl(ex.id, '/round2'), {
    question_ids: ['cofound-2'], public_key: ex.bob.keys.publicKey, nonce: n2,
    signature: sign(`fit-round2:${ex.id}:${n2}`, ex.bob.keys.privateKey),
  })
  assert.equal(ok.status, 200, JSON.stringify(ok.json))
  const rows = evidence.evidenceForResource('fit_exchange', ex.id)
  assert.equal(rows.length, 1)
  assert.equal(rows[0].evidence, 'legacy_unbound')
  assert.equal(rows[0].write_ref, null, 'there is no envelope, so there is no write_ref')
  assert.deepEqual(evidence.boundFieldsOf(rows[0]), ['id'],
    'fit-round2:${id}:${nonce} covers the exchange id and not one character of question_ids')
  assert.equal(evidence.covers(rows[0], 'payload.question_ids'), false)
  assert.equal(rows[0].legacy_preimage, 'fit-round2:${id}:${nonce}')
})

test('EXCHANGE ROUND2: anti-downgrade, a canonical escalation closes the legacy form for that key', async () => {
  const ex = await exchange()
  const ante = antecedentFor(ex.id, ex.bob.keys.publicKey)
  const { body } = signedBody({
    operation: 'fit_exchange_round2', resourceId: ex.id, keys: ex.bob.keys,
    payload: { question_ids: ['cofound-1'], antecedent_write_ref: ante },
  })
  assert.equal((await postJson(exUrl(ex.id, '/round2'), body)).status, 201)

  const nonce = 'd' + rid()
  const back = await postJson(exUrl(ex.id, '/round2'), {
    question_ids: ['cofound-2'], public_key: ex.bob.keys.publicKey, nonce,
    signature: sign(`fit-round2:${ex.id}:${nonce}`, ex.bob.keys.privateKey),
  })
  assert.equal(back.status, 426)
  assert.equal(back.json.code, 'client_upgrade_required')
  assert.deepEqual(fitDb.round2ForExchange(ex.id).map(r => r.question_id), ['cofound-1'],
    'and the refused legacy call wrote nothing')

  // The OTHER party has signed nothing, so their legacy form still works. A row is written
  // for the signer and never for a counterparty who has not written.
  const n2 = 'd2' + rid()
  const other = await postJson(exUrl(ex.id, '/round2'), {
    question_ids: ['cofound-3'], public_key: ex.alice.keys.publicKey, nonce: n2,
    signature: sign(`fit-round2:${ex.id}:${n2}`, ex.alice.keys.privateKey),
  })
  assert.equal(other.status, 200, JSON.stringify(other.json))
})

test('EXCHANGE ROUND2: the signed list is never repaired after approval', async () => {
  const ex = await exchange()
  const ante = antecedentFor(ex.id, ex.bob.keys.publicKey)
  const bad: [string, unknown][] = [
    ['unsorted', ['cofound-3', 'cofound-1']],
    ['duplicated', ['cofound-1', 'cofound-1']],
    ['empty', []],
    ['not strings', [1, 2]],
    ['over the cap of three', ['cofound-1', 'cofound-2', 'cofound-3', 'cofound-4']],
  ]
  for (const [why, question_ids] of bad) {
    const { body } = signedBody({
      operation: 'fit_exchange_round2', resourceId: ex.id, keys: ex.bob.keys,
      payload: { question_ids, antecedent_write_ref: ante },
    })
    const res = await postJson(exUrl(ex.id, '/round2'), body)
    assert.equal(res.status, 400, why)
    assert.equal(res.json.code, 'malformed_payload', why)
  }
  assert.deepEqual(fitDb.round2ForExchange(ex.id), [])
})

test('EXCHANGE ROUND2: the antecedent must resolve, and must name THIS exchange', async () => {
  const ex = await exchange()
  const other = await exchange()
  const cases: [string, string, string][] = [
    ['a ref naming nothing', randomBytes(32).toString('hex'), 'unknown_antecedent'],
    ['a ref on another exchange', antecedentFor(other.id, other.bob.keys.publicKey), 'antecedent_other_resource'],
  ]
  for (const [why, ref, code] of cases) {
    const { body } = signedBody({
      operation: 'fit_exchange_round2', resourceId: ex.id, keys: ex.bob.keys,
      payload: { question_ids: ['cofound-1'], antecedent_write_ref: ref },
    })
    const res = await postJson(exUrl(ex.id, '/round2'), body)
    assert.equal(res.status, 400, why)
    assert.equal(res.json.code, code, why)
  }
  // A malformed ref dies in the payload gate rather than in the lookup.
  const { body } = signedBody({
    operation: 'fit_exchange_round2', resourceId: ex.id, keys: ex.bob.keys,
    payload: { question_ids: ['cofound-1'], antecedent_write_ref: 'NOTHEX' },
  })
  assert.equal((await postJson(exUrl(ex.id, '/round2'), body)).json.code, 'malformed_payload')
})

test('EXCHANGE ROUND2: the five exchange guards, each with its own code', async () => {
  const live = await exchange()
  const ante = antecedentFor(live.id, live.bob.keys.publicKey)
  const stranger = generateKeyPair()

  const call = (id: string, keys: any, ref = ante) => {
    const { body } = signedBody({
      operation: 'fit_exchange_round2', resourceId: id, keys,
      payload: { question_ids: ['cofound-1'], antecedent_write_ref: ref },
    })
    return postJson(exUrl(id, '/round2'), body)
  }

  // No such exchange. Existence is answered before anything about a party, and a resource
  // id that is well formed but names nothing is a 404 rather than a 403.
  const missing = await call('fit-does-not-exist', live.bob.keys)
  assert.equal(missing.status, 404)
  assert.equal(missing.json.code, 'exchange_not_found')

  // Not a party. Checked before any state is disclosed.
  const outsider = await call(live.id, stranger)
  assert.equal(outsider.status, 403)
  assert.equal(outsider.json.code, 'not_a_party')

  // Closed.
  const closed = await exchange()
  fitDb.setState(closed.id, 'closed')
  const onClosed = await call(closed.id, closed.bob.keys, antecedentFor(closed.id, closed.bob.keys.publicKey))
  assert.equal(onClosed.status, 409)
  assert.equal(onClosed.json.code, 'exchange_closed')

  // Past its 72 hour window.
  const stale = await exchange({ expiresAt: new Date(Date.now() - 1000).toISOString() })
  const onStale = await call(stale.id, stale.bob.keys, antecedentFor(stale.id, stale.bob.keys.publicKey))
  assert.equal(onStale.status, 409)
  assert.equal(onStale.json.code, 'exchange_expired')

  // Blocked pair.
  const blocked = await exchange()
  introsDb.addBlock(blocked.aliceCard, blocked.bobCard)
  const onBlocked = await call(blocked.id, blocked.bob.keys, antecedentFor(blocked.id, blocked.bob.keys.publicKey))
  assert.equal(onBlocked.status, 403)
  assert.equal(onBlocked.json.code, 'pair_blocked')

  // A withdrawn card.
  const withdrawn = await exchange()
  db.getDb().prepare("UPDATE v3_cards SET revocation_status = 'withdrawn' WHERE card_id = ?").run(withdrawn.aliceCard)
  const onWithdrawn = await call(withdrawn.id, withdrawn.bob.keys, antecedentFor(withdrawn.id, withdrawn.bob.keys.publicKey))
  assert.equal(onWithdrawn.status, 409)
  assert.equal(onWithdrawn.json.code, 'card_unavailable')
})

test('EXCHANGE ROUND2: the envelope and the path must name the same exchange', async () => {
  const ex = await exchange()
  const other = await exchange()
  const ante = antecedentFor(ex.id, ex.bob.keys.publicKey)
  const { body } = signedBody({
    operation: 'fit_exchange_round2', resourceId: ex.id, keys: ex.bob.keys,
    payload: { question_ids: ['cofound-1'], antecedent_write_ref: ante },
  })
  const res = await postJson(exUrl(other.id, '/round2'), body)
  assert.equal(res.status, 400)
  assert.equal(res.json.code, 'path_resource_mismatch')
})

test('EXCHANGE ROUND2: the operation must name a fit_exchange, and a replay returns the stored answer', async () => {
  const ex = await exchange()
  const ante = antecedentFor(ex.id, ex.bob.keys.publicKey)
  // An envelope naming an intro for an exchange operation dies in the envelope checks,
  // before any handler, because the resource type of an operation is fixed by the protocol.
  const wrongType = signedBody({
    operation: 'fit_exchange_round2', resourceId: ex.introId, keys: ex.bob.keys, resourceType: 'intro',
    payload: { question_ids: ['cofound-1'], antecedent_write_ref: ante },
  })
  const bad = await postJson(exUrl(ex.introId, '/round2'), wrongType.body)
  assert.equal(bad.status, 400)
  assert.equal(bad.json.code, 'resource_type_mismatch')

  // And the same envelope twice is one escalation, answered from the stored result.
  const { body } = signedBody({
    operation: 'fit_exchange_round2', resourceId: ex.id, keys: ex.bob.keys,
    payload: { question_ids: ['cofound-2'], antecedent_write_ref: ante },
  })
  const first = await postJson(exUrl(ex.id, '/round2'), body)
  assert.equal(first.status, 201)
  assert.equal(first.json.idempotent, false)
  const again = await postJson(exUrl(ex.id, '/round2'), body)
  assert.equal(again.status, 200)
  assert.equal(again.json.idempotent, true)
  assert.deepEqual(again.json.round2, ['cofound-2'])
  assert.equal(fitDb.round2ForExchange(ex.id).length, 1, 'one act, one row')
})
