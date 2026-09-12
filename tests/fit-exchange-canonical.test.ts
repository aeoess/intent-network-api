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
import { randomBytes, createHash } from 'node:crypto'
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

// ══════════════════════════════════════════════════════════════
// custom questions, canonical
// ══════════════════════════════════════════════════════════════

test('EXCHANGE CUSTOM: the signed text is stored byte identical, in the order signed', async () => {
  const ex = await exchange()
  const questions = ['What does your week actually look like right now?', 'Who else is already committed?']
  const { body, built } = signedBody({
    operation: 'fit_exchange_custom', resourceId: ex.id, keys: ex.alice.keys, payload: { questions },
  })
  const res = await postJson(exUrl(ex.id, '/custom'), body)
  assert.equal(res.status, 201, JSON.stringify(res.json))
  assert.equal(res.json.custom_ids.length, 2)

  const stored = fitDb.customForExchange(ex.id)
  assert.equal(stored.length, 2)
  // Order as signed, not sorted: these are sentences a human wrote and the sequence carries
  // meaning, which is why the text gate does not sort the way the id gate does.
  assert.deepEqual(stored.map(c => c.text), questions)
  for (const c of stored) assert.equal(c.asker_key, ex.alice.keys.publicKey)

  const row = evidence.evidenceByWriteRef(built.writeRef)!
  assert.deepEqual(evidence.boundFieldsOf(row), ['operation', 'resource.id', 'payload.questions'])
  assert.equal(evidence.covers(row, 'payload.questions'), true)
})

test('EXCHANGE CUSTOM: a link is refused rather than stripped, and ordinary prose is not', async () => {
  // The repair. The old handler ran stripUrls and stored the output, so the stored question
  // was not the question the principal signed. Repairing text after approval is the defect.
  const ex = await exchange()
  const { body } = signedBody({
    operation: 'fit_exchange_custom', resourceId: ex.id, keys: ex.alice.keys,
    payload: { questions: ['Have you read https://example.com/manifesto yet?'] },
  })
  const res = await postJson(exUrl(ex.id, '/custom'), body)
  assert.equal(res.status, 400, JSON.stringify(res.json))
  assert.equal(res.json.code, 'text_contains_link')
  assert.deepEqual(fitDb.customForExchange(ex.id), [], 'and nothing is stored in either form')

  // AND THE PART THAT MATTERS MORE. The predicate is containsUrl, not a comparison against
  // stripUrls' output, because stripUrls collapses whitespace too. Comparing against it
  // refused every one of these and blamed a link the text does not have.
  // A tab and a newline are refused EARLIER, by the payload gate, with control_character,
  // which is accurate. What the comparison got wrong is whitespace the payload gate allows:
  // a double space, a non-breaking space and an ideographic space.
  const ordinary = [
    'Three evenings a week  and most Saturdays.',
    'A non breaking\u00a0space.',
    'An ideographic\u3000space.',
  ]
  for (const q of ordinary) {
    const fresh = await exchange()
    const ok = signedBody({
      operation: 'fit_exchange_custom', resourceId: fresh.id, keys: fresh.alice.keys, payload: { questions: [q] },
    })
    const r = await postJson(exUrl(fresh.id, '/custom'), ok.body)
    assert.equal(r.status, 201, `${JSON.stringify(q)} was refused: ${JSON.stringify(r.json)}`)
    assert.deepEqual(fitDb.customForExchange(fresh.id).map(c => c.text), [q],
      'and stored byte identical, whitespace included')
  }
  // The gate's own refusals still stand, with their own codes.
  const withTab = await exchange()
  const tabbed = signedBody({
    operation: 'fit_exchange_custom', resourceId: withTab.id, keys: withTab.alice.keys,
    payload: { questions: ['A tab\tinside.'] },
  })
  assert.equal((await postJson(exUrl(withTab.id, '/custom'), tabbed.body)).json.code, 'control_character')

  // The legacy lane still cleans and stores, because that is what a published client
  // expects, and its evidence row says the text was never covered.
  const nonce = 'c' + rid()
  const legacy = await postJson(exUrl(ex.id, '/custom'), {
    questions: ['Have you read https://example.com/manifesto yet?'],
    public_key: ex.alice.keys.publicKey, nonce,
    signature: sign(`fit-custom:${ex.id}:${nonce}`, ex.alice.keys.privateKey),
  })
  assert.equal(legacy.status, 200, JSON.stringify(legacy.json))
  const stored = fitDb.customForExchange(ex.id)
  assert.equal(stored.length, 1)
  assert.equal(stored[0].text.includes('https://example.com'), false, 'the legacy path still cleans')
  const rows = evidence.evidenceForResource('fit_exchange', ex.id)
  assert.deepEqual(evidence.boundFieldsOf(rows[0]), ['id'])
  assert.equal(evidence.covers(rows[0], 'payload.questions'), false)
})

test('EXCHANGE CUSTOM: the post-gate still screens, and a refusal stores nothing', async () => {
  const ex = await exchange()
  const { body } = signedBody({
    operation: 'fit_exchange_custom', resourceId: ex.id, keys: ex.alice.keys,
    payload: { questions: ['Mail me at someone@example.com and we can talk'] },
  })
  const res = await postJson(exUrl(ex.id, '/custom'), body)
  assert.equal(res.status, 400)
  assert.equal(res.json.code, 'post_gate_refused')
  assert.match(String(res.json.error), /contact/)
  assert.deepEqual(fitDb.customForExchange(ex.id), [])
})

test('EXCHANGE CUSTOM: the per party cap counts what is already stored, on both lanes', async () => {
  const ex = await exchange()
  const one = signedBody({
    operation: 'fit_exchange_custom', resourceId: ex.id, keys: ex.alice.keys, payload: { questions: ['First question?'] },
  })
  assert.equal((await postJson(exUrl(ex.id, '/custom'), one.body)).status, 201)
  const two = signedBody({
    operation: 'fit_exchange_custom', resourceId: ex.id, keys: ex.alice.keys, payload: { questions: ['Second question?', 'Third question?'] },
  })
  const over = await postJson(exUrl(ex.id, '/custom'), two.body)
  assert.equal(over.status, 409)
  assert.equal(over.json.code, 'custom_cap_reached')
  assert.equal(fitDb.customForExchange(ex.id).length, 1, 'and the refusal wrote none of the two')

  // The other party has their own cap.
  const theirs = signedBody({
    operation: 'fit_exchange_custom', resourceId: ex.id, keys: ex.bob.keys, payload: { questions: ['Mine?', 'And mine?'] },
  })
  assert.equal((await postJson(exUrl(ex.id, '/custom'), theirs.body)).status, 201)
  assert.equal(fitDb.customForExchange(ex.id).length, 3)
})

test('EXCHANGE CUSTOM: an unknown payload field is refused rather than carried along', async () => {
  // A field inside payload_digest that the server ignores is a field the signature says the
  // principal asked for and the server did not honour.
  const ex = await exchange()
  const { body } = signedBody({
    operation: 'fit_exchange_custom', resourceId: ex.id, keys: ex.alice.keys,
    payload: { questions: ['Fine question?'], urgent: true },
  })
  const res = await postJson(exUrl(ex.id, '/custom'), body)
  assert.equal(res.status, 400)
  assert.equal(res.json.code, 'malformed_payload')
  assert.match(String(res.json.error), /unexpected payload field: urgent/)
})

// ══════════════════════════════════════════════════════════════
// answers, canonical
// ══════════════════════════════════════════════════════════════

/** Recompute the payload digest from what the DATABASE holds, the way a later reader would.
 *  This is the assertion the legacy lane cannot pass. */
function digestOfStoredAnswers(exchangeId: string, answererKey: string, operation: string): string {
  const rows = fitDb.answersForExchange(exchangeId)
    .filter(r => r.answerer_key === answererKey)
    .sort((a, b) => (a.question_id < b.question_id ? -1 : 1))
  const answers = rows.map(r => {
    if (r.mode === 'skip') return { question_id: r.question_id, mode: r.mode }
    if (r.mode === 'ledger') return { question_id: r.question_id, mode: r.mode, ledger_id: r.ledger_id, text: r.text }
    return { question_id: r.question_id, mode: r.mode, text: r.text }
  })
  return env.buildEnvelope({
    operation: operation as any, actorKey: answererKey,
    resource: { type: 'fit_exchange', id: exchangeId } as any,
    issuedAt: '2026-01-01T00:00:00.000Z', nonce: 'x'.repeat(22), payload: { answers },
  }).payloadDigest
}

async function setLedger(who: any, cardId: string, texts: string[]): Promise<any> {
  const approved_hash = fitDb.ledgerHash(texts)
  const nonce = 'l' + rid()
  const res = await fetch(`${base}/api/v3/fit/disclosures`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      card_id: cardId, items: texts.map(t => ({ text: t })), approved_hash,
      public_key: who.keys.publicKey, nonce,
      signature: sign(`set-disclosures:${cardId}:${approved_hash}:${nonce}`, who.keys.privateKey),
    }),
  })
  return { status: res.status, body: await res.json() }
}

test('EXCHANGE ANSWERS: the stored answer recomputes to the signed payload digest, in all three modes', async () => {
  // The assertion that fails on the legacy lane, and the whole reason this route is in the
  // gate: a drafted answer was stripUrls'd and a ledger answer became a server composed
  // sentence, so the record could not be recomputed from what the principal signed.
  const ex = await exchange()
  const ledgerSet = await setLedger(ex.bob, ex.bobCard, ['I have shipped two products to paying customers.'])
  assert.equal(ledgerSet.status, 201, JSON.stringify(ledgerSet.body))
  const ledgerId = ledgerSet.body.items[0].id
  const ledgerText = ledgerSet.body.items[0].text

  const answers = [
    { question_id: 'cofound-1', mode: 'drafted', text: 'Three evenings a week and most Saturdays.' },
    { question_id: 'cofound-2', mode: 'ledger', ledger_id: ledgerId, text: ledgerText },
    { question_id: 'cofound-3', mode: 'skip' },
  ]
  const { body, built } = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys, payload: { answers },
  })
  const res = await postJson(exUrl(ex.id, '/answers'), body)
  assert.equal(res.status, 201, JSON.stringify(res.json))
  assert.equal(res.json.answered, 3)

  assert.equal(digestOfStoredAnswers(ex.id, ex.bob.keys.publicKey, 'fit_exchange_answers'), built.payloadDigest,
    'the stored rows must rebuild the exact payload the principal signed')

  // The ledger answer is stored VERBATIM, with no server composed wrap around it.
  const rows = fitDb.answersForExchange(ex.id)
  const ledgerRow = rows.find(r => r.question_id === 'cofound-2')!
  assert.equal(ledgerRow.text, ledgerText)
  assert.equal(ledgerRow.text!.includes('Their approved brief states'), false,
    'a wrap is a sentence the principal did not sign attached to words they did')
  assert.equal(ledgerRow.ledger_id, ledgerId)
  assert.equal(rows.find(r => r.question_id === 'cofound-3')!.text, null, 'a skip stores no text')

  const row = evidence.evidenceByWriteRef(built.writeRef)!
  assert.deepEqual(evidence.boundFieldsOf(row), ['operation', 'resource.id', 'payload.answers'])
})

test('EXCHANGE ANSWERS: the LEGACY lane still cannot be recomputed, and its evidence says so', async () => {
  // Kept as it is on purpose: a published 3.2.2 client sends this shape and expects the
  // wrapped, cleaned storage. What changed is that the act is now RECORDED as weak.
  const ex = await exchange()
  const ledgerSet = await setLedger(ex.bob, ex.bobCard, ['I have shipped two products.'])
  const ledgerId = ledgerSet.body.items[0].id
  const nonce = 'a' + rid()
  const answers = [
    { question_id: 'cofound-1', mode: 'drafted', text: 'See https://example.com/me for the detail.' },
    { question_id: 'cofound-2', mode: 'ledger', ledger_id: ledgerId },
  ]
  const answersHash = createHash('sha256')
    .update(canonicalize({ exchange_id: ex.id, nonce, answers }), 'utf8').digest('hex')
  const res = await postJson(exUrl(ex.id, '/answers'), {
    answers, public_key: ex.bob.keys.publicKey, nonce,
    signature: sign(answersHash, ex.bob.keys.privateKey),
  })
  assert.equal(res.status, 200, JSON.stringify(res.json))

  const rows = fitDb.answersForExchange(ex.id)
  assert.equal(rows.find(r => r.question_id === 'cofound-1')!.text!.includes('https://example.com'), false,
    'the legacy lane still cleans')
  assert.ok(rows.find(r => r.question_id === 'cofound-2')!.text!.includes('Their approved brief states'),
    'and still wraps')
  assert.notEqual(digestOfStoredAnswers(ex.id, ex.bob.keys.publicKey, 'fit_exchange_answers'), answersHash,
    'so the stored record does not recompute to the signed hash, which is the gap')

  const ev = evidence.evidenceForResource('fit_exchange', ex.id)
  assert.equal(ev.length, 1)
  assert.equal(ev[0].evidence, 'legacy_unbound')
  assert.deepEqual(evidence.boundFieldsOf(ev[0]), ['exchange_id', 'answers_submitted'])
  assert.equal(evidence.covers(ev[0], 'payload.answers'), false,
    'the bound list names what ARRIVED and never the stored text')
})

test('EXCHANGE ANSWERS: a link is refused, and ordinary whitespace is stored verbatim', async () => {
  const ex = await exchange()
  const { body } = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys,
    payload: { answers: [{ question_id: 'cofound-1', mode: 'drafted', text: 'Read https://example.com/x first.' }] },
  })
  const res = await postJson(exUrl(ex.id, '/answers'), body)
  assert.equal(res.status, 400)
  assert.equal(res.json.code, 'text_contains_link')
  assert.deepEqual(fitDb.answersForExchange(ex.id), [])

  // Ordinary prose with collapsible whitespace is accepted and stored byte identical. A
  // comparison against stripUrls' output refused this, because stripUrls collapses
  // whitespace as well as removing links.
  const text = 'Three evenings a week  and\u00a0most Saturdays.'
  const ok = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys,
    payload: { answers: [{ question_id: 'cofound-1', mode: 'drafted', text }] },
  })
  const r = await postJson(exUrl(ex.id, '/answers'), ok.body)
  assert.equal(r.status, 201, JSON.stringify(r.json))
  assert.equal(fitDb.answersForExchange(ex.id).find(a => a.question_id === 'cofound-1')!.text, text)
  assert.equal(digestOfStoredAnswers(ex.id, ex.bob.keys.publicKey, 'fit_exchange_answers'), ok.built.payloadDigest,
    'and it still recomputes to the signed digest, which a collapsed string would not')
})

test('EXCHANGE ANSWERS: a ledger answer whose signed text is not the item text is refused', async () => {
  const ex = await exchange()
  const ledgerSet = await setLedger(ex.bob, ex.bobCard, ['I have shipped two products.'])
  const ledgerId = ledgerSet.body.items[0].id

  // A text of the signer's choosing attached to a real ledger id. This is the substitution
  // the old route made possible from the other direction: only the id was signed, so the
  // quoted words were warranted by nothing.
  const wrong = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys,
    payload: { answers: [{ question_id: 'cofound-1', mode: 'ledger', ledger_id: ledgerId, text: 'I have shipped nine products.' }] },
  })
  const res = await postJson(exUrl(ex.id, '/answers'), wrong.body)
  assert.equal(res.status, 409)
  assert.equal(res.json.code, 'ledger_text_mismatch')
  assert.deepEqual(fitDb.answersForExchange(ex.id), [])

  // And an id that names nothing live is its own refusal, so a superseded item is
  // distinguishable from a mismatched text.
  const gone = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys,
    payload: { answers: [{ question_id: 'cofound-1', mode: 'ledger', ledger_id: 'nosuchitem', text: 'anything' }] },
  })
  const res2 = await postJson(exUrl(ex.id, '/answers'), gone.body)
  assert.equal(res2.status, 409)
  assert.equal(res2.json.code, 'ledger_item_superseded')
})

test('EXCHANGE ANSWERS: the signed list must be sorted, unique and exactly shaped per mode', async () => {
  const ex = await exchange()
  const bad: [string, unknown][] = [
    ['unsorted', [{ question_id: 'cofound-2', mode: 'skip' }, { question_id: 'cofound-1', mode: 'skip' }]],
    ['duplicated', [{ question_id: 'cofound-1', mode: 'skip' }, { question_id: 'cofound-1', mode: 'skip' }]],
    ['empty', []],
    ['a skip carrying text', [{ question_id: 'cofound-1', mode: 'skip', text: 'x' }]],
    ['a drafted with no text', [{ question_id: 'cofound-1', mode: 'drafted' }]],
    ['a ledger with no ledger_id', [{ question_id: 'cofound-1', mode: 'ledger', text: 'x' }]],
    ['a ledger with no text', [{ question_id: 'cofound-1', mode: 'ledger', ledger_id: 'x' }]],
    ['an unknown mode', [{ question_id: 'cofound-1', mode: 'improvised', text: 'x' }]],
    ['an extra field', [{ question_id: 'cofound-1', mode: 'drafted', text: 'x', urgent: true }]],
    ['not an object', ['cofound-1']],
  ]
  for (const [why, answers] of bad) {
    const { body } = signedBody({
      operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys, payload: { answers },
    })
    const res = await postJson(exUrl(ex.id, '/answers'), body)
    assert.equal(res.status, 400, why)
    assert.equal(res.json.code, 'malformed_payload', `${why}: ${JSON.stringify(res.json)}`)
  }
  assert.deepEqual(fitDb.answersForExchange(ex.id), [])
})

test('EXCHANGE ANSWERS: a custom question is answerable only in drafted mode, and only by the other party', async () => {
  const ex = await exchange()
  const asked = signedBody({
    operation: 'fit_exchange_custom', resourceId: ex.id, keys: ex.alice.keys, payload: { questions: ['What is your runway?'] },
  })
  const askRes = await postJson(exUrl(ex.id, '/custom'), asked.body)
  assert.equal(askRes.status, 201)
  const customId = askRes.json.custom_ids[0]

  // Bob may answer it, in drafted mode.
  const ok = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys,
    payload: { answers: [{ question_id: customId, mode: 'drafted', text: 'About fourteen months.' }] },
  })
  assert.equal((await postJson(exUrl(ex.id, '/answers'), ok.body)).status, 201)

  // Not in skip mode.
  const skipped = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys,
    payload: { answers: [{ question_id: customId, mode: 'skip' }] },
  })
  const skipRes = await postJson(exUrl(ex.id, '/answers'), skipped.body)
  assert.equal(skipRes.status, 400)
  assert.equal(skipRes.json.code, 'custom_needs_drafted')

  // And Alice cannot answer her own question: it is not in her id set at all.
  const own = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.alice.keys,
    payload: { answers: [{ question_id: customId, mode: 'drafted', text: 'Mine to answer?' }] },
  })
  const ownRes = await postJson(exUrl(ex.id, '/answers'), own.body)
  assert.equal(ownRes.status, 400)
  assert.equal(ownRes.json.code, 'unknown_question_id')
})

// ══════════════════════════════════════════════════════════════
// close, canonical
// ══════════════════════════════════════════════════════════════

/** The digest of the record as it would be sealed right now, read from the API rather than
 *  computed in the test, because the point is that a closer can read it before signing. */
async function pendingDigest(ex: Exchange, who: any): Promise<string> {
  const nonce = 'g' + rid()
  const q = new URLSearchParams({
    public_key: who.keys.publicKey, nonce,
    signature: sign(`fit-get:${ex.id}:${nonce}`, who.keys.privateKey),
  })
  const body = await (await fetch(`${exUrl(ex.id, '')}?${q}`)).json()
  assert.ok(body.pending_record_digest, JSON.stringify(body))
  return body.pending_record_digest
}

test('EXCHANGE CLOSE: the closer signs the record digest, and the sealed record is that one', async () => {
  const ex = await exchange()
  const answers = [{ question_id: 'cofound-1', mode: 'drafted', text: 'Three evenings a week.' }]
  const ans = signedBody({ operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys, payload: { answers } })
  assert.equal((await postJson(exUrl(ex.id, '/answers'), ans.body)).status, 201)

  const digest = await pendingDigest(ex, ex.alice)
  const { body, built } = signedBody({
    operation: 'fit_exchange_close', resourceId: ex.id, keys: ex.alice.keys, payload: { record_digest: digest },
  })
  const res = await postJson(exUrl(ex.id, '/close'), body)
  assert.equal(res.status, 201, JSON.stringify(res.json))
  assert.equal(res.json.closed, true)
  assert.equal(res.json.record_digest, digest, 'the sealed digest is the one the closer signed')

  const row = fitDb.getExchange(ex.id)!
  assert.equal(row.state, 'closed')
  assert.equal(row.record_digest, digest)
  const ev = evidence.evidenceByWriteRef(built.writeRef)!
  assert.deepEqual(evidence.boundFieldsOf(ev), ['operation', 'resource.id', 'payload.record_digest'])
  assert.equal(evidence.covers(ev, 'payload.record_digest'), true)
})

test('EXCHANGE CLOSE: a record that changed between preview and close is refused', async () => {
  // The whole repair. The old route let the closer sign a route tag and computed the digest
  // afterwards, so whatever the record turned out to be was sealed under that signature.
  const ex = await exchange()
  const digest = await pendingDigest(ex, ex.alice)

  // Bob answers, which moves the record.
  const answers = [{ question_id: 'cofound-2', mode: 'drafted', text: 'Late evenings mostly.' }]
  const ans = signedBody({ operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys, payload: { answers } })
  assert.equal((await postJson(exUrl(ex.id, '/answers'), ans.body)).status, 201)
  const moved = await pendingDigest(ex, ex.alice)
  assert.notEqual(moved, digest, 'an answer moves the record, which is what makes the echo meaningful')

  const stale = signedBody({
    operation: 'fit_exchange_close', resourceId: ex.id, keys: ex.alice.keys, payload: { record_digest: digest },
  })
  const res = await postJson(exUrl(ex.id, '/close'), stale.body)
  assert.equal(res.status, 409)
  assert.equal(res.json.code, 'record_digest_stale')
  assert.match(String(res.json.error), new RegExp(moved), 'the refusal names the digest to sign instead')
  assert.equal(fitDb.getExchange(ex.id)!.state, 'answering', 'and nothing was sealed')

  // Signing the new one works.
  const fresh = signedBody({
    operation: 'fit_exchange_close', resourceId: ex.id, keys: ex.alice.keys, payload: { record_digest: moved },
  })
  assert.equal((await postJson(exUrl(ex.id, '/close'), fresh.body)).status, 201)
})

test('EXCHANGE CLOSE: it seals a record past the 72 hour window, because the sweep does too', async () => {
  // The one exchange act that may run on an expired exchange. Refusing a party what the
  // scheduled sweep does to them anyway would be perverse, and it is what the legacy close
  // route has always done, so this is a repair of the signature rather than a change.
  const ex = await exchange({ expiresAt: new Date(Date.now() - 1000).toISOString() })
  const digest = await pendingDigest(ex, ex.alice)
  const { body } = signedBody({
    operation: 'fit_exchange_close', resourceId: ex.id, keys: ex.alice.keys, payload: { record_digest: digest },
  })
  const res = await postJson(exUrl(ex.id, '/close'), body)
  assert.equal(res.status, 201, JSON.stringify(res.json))
  assert.equal(fitDb.getExchange(ex.id)!.state, 'closed')

  // And an act that ADDS to the exchange is still refused past the window.
  const ex2 = await exchange({ expiresAt: new Date(Date.now() - 1000).toISOString() })
  const ans = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex2.id, keys: ex2.bob.keys,
    payload: { answers: [{ question_id: 'cofound-1', mode: 'skip' }] },
  })
  const refused = await postJson(exUrl(ex2.id, '/answers'), ans.body)
  assert.equal(refused.status, 409)
  assert.equal(refused.json.code, 'exchange_expired')
})

test('EXCHANGE CLOSE: a second close is refused, and the record is not resealed', async () => {
  const ex = await exchange()
  const digest = await pendingDigest(ex, ex.alice)
  const first = signedBody({
    operation: 'fit_exchange_close', resourceId: ex.id, keys: ex.alice.keys, payload: { record_digest: digest },
  })
  assert.equal((await postJson(exUrl(ex.id, '/close'), first.body)).status, 201)
  // A replay of the SAME envelope is idempotent and returns the stored answer.
  const replay = await postJson(exUrl(ex.id, '/close'), first.body)
  assert.equal(replay.status, 200)
  assert.equal(replay.json.idempotent, true)
  // A different envelope on a closed exchange is refused, because the record already exists.
  const second = signedBody({
    operation: 'fit_exchange_close', resourceId: ex.id, keys: ex.bob.keys, payload: { record_digest: digest },
  })
  const res = await postJson(exUrl(ex.id, '/close'), second.body)
  assert.equal(res.status, 409)
  assert.equal(res.json.code, 'exchange_closed')
})

test('EXCHANGE CLOSE: the legacy lane still closes and is recorded as weak', async () => {
  const ex = await exchange()
  const nonce = 'lc' + rid()
  const res = await postJson(exUrl(ex.id, '/close'), {
    public_key: ex.alice.keys.publicKey, nonce,
    signature: sign(`fit-close:${ex.id}:${nonce}`, ex.alice.keys.privateKey),
  })
  assert.equal(res.status, 200, JSON.stringify(res.json))
  assert.equal(res.json.closed, true)
  const ev = evidence.evidenceForResource('fit_exchange', ex.id)
  assert.equal(ev.length, 1)
  assert.deepEqual(evidence.boundFieldsOf(ev[0]), ['id'])
  assert.equal(evidence.covers(ev[0], 'payload.record_digest'), false,
    'the digest the closer is attesting to appears in none of those bytes')
  assert.equal(ev[0].legacy_preimage, 'fit-close:${id}:${nonce}')
  // The card event landed, which is the check that splitting the seal from the events kept
  // the legacy path whole.
  const events = db.getDb().prepare(
    "SELECT COUNT(*) AS n FROM card_events WHERE event = 'handshake_closed'").get() as any
  assert.ok(events.n >= 2, 'one for each side')
})

// ══════════════════════════════════════════════════════════════
// What the antecedent proves, and what a rebuild from storage proves
// ══════════════════════════════════════════════════════════════

test('EXCHANGE ROUND2: the antecedent is reachable, because the read surface publishes the refs', async () => {
  // The defect this closes. The only refs that resolve are canonical write_refs, and the only
  // place one appeared was in the response to the party who made that write, so a party who
  // had not yet written canonically could not escalate at all. Escalating BEFORE answering is
  // the natural first move on this route.
  const ex = await exchange()
  const ans = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys,
    payload: { answers: [{ question_id: 'cofound-1', mode: 'drafted', text: 'Three evenings.' }] },
  })
  assert.equal((await postJson(exUrl(ex.id, '/answers'), ans.body)).status, 201)

  // Alice reads the exchange and finds Bob's act, without having written anything herself.
  const nonce = 'ga' + rid()
  const q = new URLSearchParams({
    public_key: ex.alice.keys.publicKey, nonce,
    signature: sign(`fit-get:${ex.id}:${nonce}`, ex.alice.keys.privateKey),
  })
  const view: any = await (await fetch(`${exUrl(ex.id, '')}?${q}`)).json()
  assert.ok(Array.isArray(view.canonical_acts), JSON.stringify(Object.keys(view)))
  assert.equal(view.canonical_acts.length, 1)
  assert.equal(view.canonical_acts[0].write_ref, ans.built.writeRef)
  assert.equal(view.canonical_acts[0].operation, 'fit_exchange_answers')
  assert.equal(view.canonical_acts[0].actor_key, ex.bob.keys.publicKey)

  // And it works as her antecedent, which is the whole point: a round two answers the
  // COUNTERPARTY's act, so naming theirs is the natural form and no actor check applies.
  const r2 = signedBody({
    operation: 'fit_exchange_round2', resourceId: ex.id, keys: ex.alice.keys,
    payload: { question_ids: ['cofound-1'], antecedent_write_ref: view.canonical_acts[0].write_ref },
  })
  assert.equal((await postJson(exUrl(ex.id, '/round2'), r2.body)).status, 201)
})

test('EXCHANGE ANSWERS: KNOWN LIMIT, a second write merges and the composite matches no signature', async () => {
  // The recompute property, stated exactly. ONE write by one party rebuilds to that write's
  // signed payload. A second write MERGES, because upsertAnswer is keyed on
  // (exchange, question, answerer), so the composite matches neither signature and nothing
  // stored says which write covered which answer.
  //
  // Not a regression: the old lane stored a cleaned string that matched nothing at all. What
  // IS true in every case is that the stored text is the signed text byte for byte, which is
  // what matrix row 39 complained about. Pinned here so the limit is known rather than
  // discovered, with per answer attribution recorded for 2C.
  const ex = await exchange()
  const first = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys,
    payload: { answers: [{ question_id: 'cofound-1', mode: 'drafted', text: 'Three evenings a week.' }] },
  })
  assert.equal((await postJson(exUrl(ex.id, '/answers'), first.body)).status, 201)
  assert.equal(digestOfStoredAnswers(ex.id, ex.bob.keys.publicKey, 'fit_exchange_answers'), first.built.payloadDigest,
    'one write rebuilds exactly')

  const second = signedBody({
    operation: 'fit_exchange_answers', resourceId: ex.id, keys: ex.bob.keys,
    payload: { answers: [{ question_id: 'cofound-2', mode: 'drafted', text: 'Mostly remote.' }] },
  })
  assert.equal((await postJson(exUrl(ex.id, '/answers'), second.body)).status, 201)
  const rebuilt = digestOfStoredAnswers(ex.id, ex.bob.keys.publicKey, 'fit_exchange_answers')
  assert.notEqual(rebuilt, first.built.payloadDigest)
  assert.notEqual(rebuilt, second.built.payloadDigest)
  // But every stored answer is still byte identical to the text its own signature covered.
  const rows = fitDb.answersForExchange(ex.id)
  assert.equal(rows.find(r => r.question_id === 'cofound-1')!.text, 'Three evenings a week.')
  assert.equal(rows.find(r => r.question_id === 'cofound-2')!.text, 'Mostly remote.')
  // And both acts are recorded, so a reader knows two signed writes happened even though the
  // rows do not say which covered which.
  const ev = evidence.evidenceForResource('fit_exchange', ex.id).filter(e => e.operation === 'fit_exchange_answers')
  assert.equal(ev.length, 2)
  assert.deepEqual(ev.map(e => e.write_ref).sort(), [first.built.writeRef, second.built.writeRef].sort())
})

test('EXCHANGE ROUND2: an act from outside the fit conversation is not an antecedent', async () => {
  // The antecedent used to accept any canonical act on the resource. On the v4 side that let
  // an express_interest write_ref, signed before any handshake existed, unblock an escalation.
  // On the exchange there are no lifecycle acts, so this drives the same check directly.
  const ex = await exchange()
  const ref = randomBytes(32).toString('hex')
  db.getDb().prepare(`
    INSERT INTO write_evidence
      (evidence_id, write_ref, actor_key, operation, resource_type, resource_id,
       evidence, envelope_json, signature, payload_digest, bound_fields_json, legacy_preimage)
    VALUES (?, ?, ?, 'share_contact', 'fit_exchange', ?, 'canonical', '{}', ?, NULL, '[]', NULL)
  `).run('ev-out-' + rid(), ref, ex.bob.keys.publicKey, ex.id, 'b'.repeat(128))
  const { body } = signedBody({
    operation: 'fit_exchange_round2', resourceId: ex.id, keys: ex.alice.keys,
    payload: { question_ids: ['cofound-1'], antecedent_write_ref: ref },
  })
  const res = await postJson(exUrl(ex.id, '/round2'), body)
  assert.equal(res.status, 400)
  assert.equal(res.json.code, 'antecedent_not_a_fit_act')
  assert.deepEqual(fitDb.round2ForExchange(ex.id), [])
})
