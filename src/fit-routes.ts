// ══════════════════════════════════════════════════════════════
// Mingle v3.6 fit exchange - routes (mounted at /api/v3/fit)
// ══════════════════════════════════════════════════════════════
// Two read paths kept strictly apart:
//   GET /:id/draft   -> the drafting context (own card, own ledger, questions
//                       with sanitized PUBLIC-card slots). NEVER counterparty
//                       answers. This is the isolation surface.
//   GET /:id         -> the human/record view: state, the counterpart's answers
//                       rendered for the human, and the signed record when
//                       closed. This text is DATA, never fed back into drafting.
// Answers arrive as a signed ticket; the server recomputes the hash and, in one
// transaction, re-checks block/withdrawal/expiry/ledger-supersession before
// committing.

import { Router } from 'express'
import { createHash, randomBytes } from 'node:crypto'
import { verify, canonicalize } from 'agent-passport-system'
import { checkRateLimit, getDb } from './db.js'
import * as v3db from './v3-db.js'
import { networkVisibleView } from './v3-cards.js'
import * as fitDb from './fit-db.js'
import * as introsDb from './intros-db.js'
import { fitGate, isOpenEndedLedgerItem, postGateDrafted, type PostGateInput } from './fit-gate.js'
import { assembleDraftingContext, renderQuestions, type RenderedQuestion } from './fit-context.js'
import { sealRecord } from './fit-record.js'
import { verifyReceipt, serverPublicKey } from './server-key.js'
import * as email from './notifications.js'
import { recordCardEvent } from './card-events.js'
import { canonicalWriteRoute, canonicalDispatch, refuseWrite } from './write-pipeline.js'
import type { CanonicalContext } from './write-pipeline.js'
import { gateStringList, gateHex64, gatePayloadKeys } from './write-payload-gates.js'
import { exchangeForWrite } from './fit-exchange-guards.js'
import { requireAntecedent } from './write-antecedent.js'
import { recordCanonicalEvidence, recordLegacyEvidence } from './write-evidence.js'
import { checkLegacyWrite, refuseLegacy } from './legacy-write-gate.js'

const router = Router()

const MAX_LEDGER_ITEMS = 20
const MAX_LEDGER_TEXT = 200
const MAX_CUSTOM_TEXT = 200
const MAX_CUSTOM_PER_ASKER = 2
const MAX_ROUND2 = 3

function checkSig(payload: string, signature: unknown, key: unknown): boolean {
  if (typeof signature !== 'string' || typeof key !== 'string') return false
  try { return verify(payload, signature, key) } catch { return false }
}

function rateLimited(action: string, limit: number) {
  return (req: any, res: any, next: any) => {
    if (!checkRateLimit(`fit:${req.ip || 'anon'}`, action, limit).allowed) { res.status(429).json({ error: 'Rate limit exceeded' }); return }
    next()
  }
}

class FitError extends Error { status: number; constructor(status: number, msg: string) { super(msg); this.status = status } }
const fail = (status: number, msg: string): never => { throw new FitError(status, msg) }

function cardActive(cardId: string): boolean {
  const c = v3db.getV3Card(cardId)
  return !!c && c.revocation_status === 'active' && Date.parse(c.expires_at) > Date.now()
}

/** Consent sheet for a party, per spec: what this exchange discloses and its limits. */
export function consentSheet(ex: fitDb.ExchangeRow, viewerKey: string): Record<string, unknown> {
  const cp = fitDb.counterpartOf(ex, viewerKey)
  const cpCard = cp ? v3db.getV3Card(cp.card) : null
  const handle = cpCard ? (networkVisibleView({ ...cpCard.card, card_id: cp!.card } as any) as any).headline ?? cp!.card : cp?.card
  const myLedgerVersion = viewerKey === ex.key_a ? ex.ledger_version_a : ex.ledger_version_b
  return {
    counterparty_handle: handle,
    purpose: ex.intent,
    bank_version: ex.bank_version,
    ledger_version_in_effect: myLedgerVersion,
    mode: 'drafted-and-approved (ledger answers are the autonomous tier)',
    limits: { window_hours: 72, round2_questions_max: MAX_ROUND2, custom_questions_max: MAX_CUSTOM_PER_ASKER, answer_chars_max: 800 },
    retention: 'Fit answers and records are currently retained on the server. Notification emails do not include fit answers or private fit values.',
  }
}

// ── POST /disclosures - set the ledger (exact-approval + signature) ────────

router.post('/disclosures', rateLimited('fit_disclose', 20), (req, res) => {
  const { card_id, items, approved_hash, public_key, nonce, signature } = req.body ?? {}
  if (typeof card_id !== 'string' || !Array.isArray(items) || typeof approved_hash !== 'string' || typeof nonce !== 'string') {
    res.status(400).json({ error: 'card_id, items, approved_hash, nonce required' }); return
  }
  if (!checkSig(`set-disclosures:${card_id}:${approved_hash}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const stored = v3db.getV3Card(card_id)
  if (!stored || stored.card.subject_key !== public_key) { res.status(403).json({ error: 'not the card subject' }); return }

  if (items.length > MAX_LEDGER_ITEMS) { res.status(400).json({ error: `too many items (max ${MAX_LEDGER_ITEMS})` }); return }
  const texts: string[] = []
  for (const it of items) {
    const text = typeof it === 'string' ? it : it?.text
    if (typeof text !== 'string' || text.trim().length === 0) { res.status(400).json({ error: 'each item needs text' }); return }
    if (text.length > MAX_LEDGER_TEXT) { res.status(400).json({ error: `item too long (max ${MAX_LEDGER_TEXT})` }); return }
    if (isOpenEndedLedgerItem(text)) { res.status(400).json({ error: `open-ended item rejected: "${text}". Ledger items are concrete statements, not permissions.` }); return }
    texts.push(text.trim())
  }
  if (fitDb.ledgerHash(texts) !== approved_hash) { res.status(400).json({ error: 'approved_hash does not match the items; re-approve the exact set' }); return }

  const result = fitDb.setLedger(card_id, public_key, texts)
  res.status(201).json({ card_id, version: result.version, ledger_hash: result.ledger_hash, items: result.items.map(i => ({ id: i.id, text: i.text })) })
})

// ── GET /disclosures - own ledger (signed) ────────────────────────────────

router.get('/disclosures', rateLimited('fit_get', 60), (req, res) => {
  const card_id = String(req.query.card_id ?? '')
  const public_key = String(req.query.public_key ?? '')
  const nonce = String(req.query.nonce ?? '')
  const signature = String(req.query.signature ?? '')
  if (!card_id || !nonce) { res.status(400).json({ error: 'card_id and nonce required' }); return }
  if (!checkSig(`get-disclosures:${card_id}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const stored = v3db.getV3Card(card_id)
  if (!stored || stored.card.subject_key !== public_key) { res.status(403).json({ error: 'not the card subject' }); return }
  res.json(fitDb.getLedger(card_id))
})

// ── Party auth for an exchange ────────────────────────────────────────────

function partyGuard(req: any, res: any, payloadPrefix: string): { ex: fitDb.ExchangeRow; key: string } | null {
  const id = String(req.params.id)
  const public_key = String(req.query.public_key ?? req.body?.public_key ?? '')
  const nonce = String(req.query.nonce ?? req.body?.nonce ?? '')
  const signature = req.query.signature ?? req.body?.signature
  if (!public_key || !nonce) { res.status(400).json({ error: 'public_key and nonce required' }); return null }
  if (!checkSig(`${payloadPrefix}:${id}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return null }
  const ex = fitDb.getExchange(id)
  if (!ex) { res.status(404).json({ error: 'exchange not found' }); return null }
  if (!fitDb.isParty(ex, public_key)) { res.status(403).json({ error: 'not a party to this exchange' }); return null }
  return { ex, key: public_key }
}

// ── GET /:id/draft - the drafting context (isolation surface) ─────────────
// Own card + own ledger + bank questions with sanitized PUBLIC-card slots.
// Counterparty answers and custom-question text are NOT here, by construction.

router.get('/:id/draft', rateLimited('fit_get', 60), (req, res) => {
  const g = partyGuard(req, res, 'fit-draft'); if (!g) return
  const { ex, key } = g
  const ownCardId = fitDb.ownCardOf(ex, key)!
  const cp = fitDb.counterpartOf(ex, key)!
  const ownStored = v3db.getV3Card(ownCardId)
  const cpStored = v3db.getV3Card(cp.card)
  if (!ownStored || !cpStored) { res.status(409).json({ error: 'a card in this exchange is no longer available' }); return }

  const bank = fitDb.getBank(ex.intent)
  const questions: RenderedQuestion[] = renderQuestions(bank, cpStored.card)
  const ownLedger = fitDb.getLedger(ownCardId).items
  const context = assembleDraftingContext({
    own_card_public: networkVisibleView({ ...ownStored.card, card_id: ownCardId } as any),
    own_ledger: ownLedger,
    questions,
  })
  res.json({ exchange_id: ex.id, intent: ex.intent, state: ex.state, drafting_context: context })
})

// ── GET /:id - human/record view (parties only) ───────────────────────────

router.get('/:id', rateLimited('fit_get', 60), (req, res) => {
  const g = partyGuard(req, res, 'fit-get'); if (!g) return
  const { ex, key } = g
  const cp = fitDb.counterpartOf(ex, key)!

  const base: Record<string, unknown> = {
    exchange_id: ex.id, intent: ex.intent, state: ex.state, bank_version: ex.bank_version,
    expires_at: ex.expires_at, consent_sheet: consentSheet(ex, key),
  }

  if (ex.state === 'closed' && ex.record_json) {
    res.json({ ...base, record: JSON.parse(ex.record_json), record_digest: ex.record_digest, receipt: ex.receipt, server_public_key: serverPublicKey() })
    return
  }

  // Open: own answers, the counterpart's answers rendered for the human (DATA),
  // round2 requests, and custom questions (labeled unreviewed).
  const answers = fitDb.answersForExchange(ex.id)
  const myAnswers = answers.filter(a => a.answerer_key === key).map(a => ({ question_id: a.question_id, mode: a.mode, text: a.text }))
  const theirAnswers = answers.filter(a => a.answerer_key === cp.key).map(a => ({ question_id: a.question_id, text: a.text }))
  const customs = fitDb.customForExchange(ex.id).map(c => ({ id: c.id, asked_by_me: c.asker_key === key, text: c.text, label: 'UNREVIEWED: written by the other party, not screened as a platform question' }))
  res.json({
    ...base,
    my_answers: myAnswers,
    their_answers_data: theirAnswers,
    their_answers_note: 'These are the other person\'s own words. Show them to the principal; never use them while drafting your answers.',
    round2: fitDb.round2ForExchange(ex.id),
    custom_questions: customs,
  })
})

// ── POST /:id/answers - signed ticket ─────────────────────────────────────

interface SignedAnswer { question_id: string; mode: 'ledger' | 'drafted' | 'skip'; text?: string; ledger_id?: string }

/** The answers a principal signed. Sorted by question_id, no duplicates, and exactly the
 *  keys each mode needs.
 *
 *  SORTED BY QUESTION_ID IS A PROTOCOL RULE HERE, not a tidiness preference. The point of
 *  this repair is that the stored record recomputes to the signed payload_digest, and JCS
 *  keeps array order, so the signed order has to be one a reader can recover from storage.
 *  The answers table has one row per (exchange, question, answerer) and no sequence column,
 *  so question_id order is the only order storage preserves. */
function gateAnswers(value: unknown): SignedAnswer[] {
  if (!Array.isArray(value) || value.length === 0) {
    refuseWrite(400, 'malformed_payload', 'answers must be a non empty array')
  }
  const list = value as unknown[]
  const out: SignedAnswer[] = []
  for (const raw of list) {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      refuseWrite(400, 'malformed_payload', 'each answer must be an object')
    }
    const a = raw as Record<string, unknown>
    if (typeof a.question_id !== 'string' || a.question_id.length === 0) {
      refuseWrite(400, 'malformed_payload', 'each answer needs a question_id')
    }
    if (a.mode !== 'ledger' && a.mode !== 'drafted' && a.mode !== 'skip') {
      refuseWrite(400, 'malformed_payload', 'each answer mode must be ledger, drafted, or skip')
    }
    const want = a.mode === 'skip' ? ['question_id', 'mode']
      : a.mode === 'drafted' ? ['question_id', 'mode', 'text']
      : ['question_id', 'mode', 'ledger_id', 'text']
    const have = Object.keys(a).sort()
    const wanted = [...want].sort()
    if (have.length !== wanted.length || have.some((k, i) => k !== wanted[i])) {
      refuseWrite(400, 'malformed_payload', `a ${a.mode} answer carries exactly ${want.join(', ')}`)
    }
    if (a.mode !== 'skip' && (typeof a.text !== 'string' || a.text.length === 0)) {
      refuseWrite(400, 'malformed_payload', 'text must be a non empty string')
    }
    if (a.mode === 'ledger' && (typeof a.ledger_id !== 'string' || a.ledger_id.length === 0)) {
      refuseWrite(400, 'malformed_payload', 'a ledger answer needs a ledger_id')
    }
    out.push(a as unknown as SignedAnswer)
  }
  for (let i = 1; i < out.length; i++) {
    if (out[i - 1].question_id === out[i].question_id) {
      refuseWrite(400, 'malformed_payload', `answers carries question_id ${out[i].question_id} twice`)
    }
    if (out[i - 1].question_id > out[i].question_id) {
      refuseWrite(400, 'malformed_payload', 'answers must be sorted by question_id, so the stored record recomputes to the signed digest')
    }
  }
  return out
}

const canonicalExchangeAnswers = canonicalWriteRoute({
  operations: ['fit_exchange_answers'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    gatePayloadKeys(write.payload, ['answers'])
    const exchangeId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key
    const ex = exchangeForWrite(exchangeId, actorKey, now)
    const ownCardId = fitDb.ownCardOf(ex, actorKey) as string
    const answers = gateAnswers(write.payload.answers)

    // Valid question ids for this answerer: the bank, plus custom questions the counterpart
    // addressed to them, which are answerable only in drafted mode.
    const bankIds = new Set(fitDb.getBank(ex.intent).map(q => q.question_id))
    const customForMe = new Map(fitDb.customForExchange(ex.id).filter(c => c.asker_key !== actorKey).map(c => [c.id, c]))
    for (const a of answers) {
      if (!bankIds.has(a.question_id) && !customForMe.has(a.question_id)) {
        refuseWrite(400, 'unknown_question_id', `unknown question_id ${a.question_id}`)
      }
      if (customForMe.has(a.question_id) && a.mode !== 'drafted') {
        refuseWrite(400, 'custom_needs_drafted', 'custom questions are answerable only in drafted mode')
      }
    }

    // The post-gate runs on every drafted text, as a batch, because it detects contact data
    // split across answers. A text it would REWRITE is refused rather than cleaned: the
    // whole repair is that the stored answer IS the signed answer, and a cleaned string is
    // neither what the principal approved nor something the digest covers.
    const drafted = answers.filter(a => a.mode === 'drafted')
    if (drafted.length > 0) {
      const gate = postGateDrafted(drafted.map(a => ({ question_id: a.question_id, text: a.text as string })))
      if (!gate.ok) {
        refuseWrite(400, 'post_gate_refused', gate.reason ?? 'the answer text was refused')
      }
      const cleaned = new Map((gate.cleaned ?? []).map(c => [c.question_id, c.text]))
      for (const a of drafted) {
        if (cleaned.get(a.question_id) !== a.text) {
          refuseWrite(400, 'text_not_stored_as_signed',
            `the answer to ${a.question_id} would be stored in a different form than the one you signed, so it is refused rather than rewritten. Remove any link and re-approve.`)
        }
      }
    }

    // A LEDGER ANSWER NOW BINDS THE TEXT. The matrix gap was that only ledger_id was signed
    // while the stored sentence quoted the item's text, so the quoted words were warranted
    // by nothing. The signed text must equal the live item's text exactly, and it is stored
    // verbatim with NO server composed wrap, because a wrap is a sentence the principal did
    // not sign attached to words they did.
    for (const a of answers) {
      if (a.mode !== 'ledger') continue
      const live = fitDb.ledgerItemLive(ownCardId, a.ledger_id as string)
      if (!live) {
        refuseWrite(409, 'ledger_item_superseded', `ledger item ${a.ledger_id} was superseded, so re-approve and re-answer`)
      }
      if ((live as { text: string }).text !== a.text) {
        refuseWrite(409, 'ledger_text_mismatch',
          `the signed text for ${a.question_id} is not the text of ledger item ${a.ledger_id}, so it is refused rather than replaced`)
      }
    }

    for (const a of answers) {
      fitDb.upsertAnswer({
        exchange_id: ex.id, question_id: a.question_id, answerer_key: actorKey, mode: a.mode,
        ledger_id: a.mode === 'ledger' ? (a.ledger_id as string) : null,
        text: a.mode === 'skip' ? null : (a.text as string),
      })
    }
    recordCanonicalEvidence(write)
    return { exchange_id: ex.id, answered: answers.length }
  },
})

router.post('/:id/answers', fitGate, canonicalDispatch(canonicalExchangeAnswers), rateLimited('fit_answer', 60), async (req, res) => {
  const id = String(req.params.id)
  const { answers, public_key, nonce, signature } = req.body ?? {}
  if (!Array.isArray(answers) || answers.length === 0 || typeof nonce !== 'string') { res.status(400).json({ error: 'answers and nonce required' }); return }

  // Ticket: signature is over sha256(canonical({exchange_id, nonce, answers})).
  const answersHash = createHash('sha256').update(canonicalize({ exchange_id: id, nonce, answers }), 'utf8').digest('hex')
  if (!checkSig(answersHash, signature, public_key)) { res.status(403).json({ error: 'ticket signature does not verify (answers, nonce, or exchange changed)' }); return }

  const ex = fitDb.getExchange(id)
  if (!ex) { res.status(404).json({ error: 'exchange not found' }); return }
  if (!fitDb.isParty(ex, public_key)) { res.status(403).json({ error: 'not a party to this exchange' }); return }
  const legacyGate = checkLegacyWrite({ resourceType: 'fit_exchange', resourceId: ex.id, actorKey: public_key, introId: ex.intro_id })
  if (legacyGate !== null) { refuseLegacy(res, 'fit_exchange_answers', ex.id, legacyGate); return }
  const ownCardId = fitDb.ownCardOf(ex, public_key)!

  // Valid question ids for this answerer: the bank, plus custom questions the
  // counterpart addressed to them (answerable only in drafted mode).
  const bankIds = new Set(fitDb.getBank(ex.intent).map(q => q.question_id))
  const customForMe = new Map(fitDb.customForExchange(ex.id).filter(c => c.asker_key !== public_key).map(c => [c.id, c]))

  // Post-gate the drafted texts as a batch (cross-answer detection).
  const drafted: PostGateInput[] = []
  for (const a of answers) {
    if (!['ledger', 'drafted', 'skip'].includes(a?.mode)) { res.status(400).json({ error: 'each answer mode must be ledger, drafted, or skip' }); return }
    if (!bankIds.has(a.question_id) && !customForMe.has(a.question_id)) { res.status(400).json({ error: `unknown question_id ${a.question_id}` }); return }
    if (customForMe.has(a.question_id) && a.mode !== 'drafted') { res.status(400).json({ error: 'custom questions are answerable only in drafted mode' }); return }
    if (a.mode === 'drafted') drafted.push({ question_id: a.question_id, text: String(a.text ?? '') })
  }
  let cleanedByQ = new Map<string, string>()
  if (drafted.length > 0) {
    const gate = postGateDrafted(drafted)
    if (!gate.ok) { res.status(400).json({ error: gate.reason, question_id: gate.question_id }); return }
    cleanedByQ = new Map((gate.cleaned ?? []).map(c => [c.question_id, c.text]))
  }

  // Commit-time atomic re-check + write.
  try {
    const tx = getDb().transaction(() => {
      if (ex.state === 'closed') fail(409, 'exchange is closed')
      if (Date.parse(ex.expires_at) <= Date.now()) fail(409, 'exchange window has expired')
      if (introsDb.isBlocked(ex.card_a, ex.card_b)) fail(403, 'this pair is blocked; the exchange is closed to new answers')
      if (!cardActive(ex.card_a) || !cardActive(ex.card_b)) fail(409, 'a card in this exchange has been withdrawn or superseded')

      for (const a of answers) {
        if (a.mode === 'skip') { fitDb.upsertAnswer({ exchange_id: id, question_id: a.question_id, answerer_key: public_key, mode: 'skip', text: null }); continue }
        if (a.mode === 'ledger') {
          if (typeof a.ledger_id !== 'string') fail(400, 'ledger mode requires ledger_id')
          const live = fitDb.ledgerItemLive(ownCardId, a.ledger_id)
          if (!live) fail(409, `ledger item ${a.ledger_id} was superseded; re-approve and re-answer`)
          fitDb.upsertAnswer({ exchange_id: id, question_id: a.question_id, answerer_key: public_key, mode: 'ledger', ledger_id: a.ledger_id, text: `Their approved brief states: "${live.text}"` })
          continue
        }
        // drafted
        const text = cleanedByQ.get(a.question_id)!
        fitDb.upsertAnswer({ exchange_id: id, question_id: a.question_id, answerer_key: public_key, mode: 'drafted', text })
      }
      // Inside the same transaction as the answers, so the record of the act and the act
      // commit together. Labelled legacy_unbound, and the bound list names the SUBMITTED
      // answers rather than the stored text, because this lane still cleans and still wraps.
      recordLegacyEvidence({
        actorKey: public_key, operation: 'fit_exchange_answers',
        resourceType: 'fit_exchange', resourceId: ex.id, signature: String(signature ?? ''),
      })
    })
    tx()
  } catch (e) {
    if (e instanceof FitError) { res.status(e.status).json({ error: e.message }); return }
    throw e
  }

  res.json({ ok: true, answered: answers.length })
})

// ══════════════════════════════════════════════════════════════
// The canonical lane for the v3 fit exchange
// ══════════════════════════════════════════════════════════════
// Each repaired route gains a canonical branch ahead of its legacy branch, on the path
// it already has, dispatched on the presence of an `envelope` key. A published 3.2.2
// client needs no change: its body simply never carries that key.
//
// The resource is the EXCHANGE, not the intro. resource.id is the exchange id, which is
// also the :id in the path, and canonicalDispatch refuses a disagreement between the two
// rather than picking a winner.
//
// These acts write no connection_authorizations row and are not intro continuations. The
// exchange has its own 72 hour window and its own state machine, and the authorization
// table keys on the intro, so recording an exchange act as an intro fact would either
// move an intro deadline from an act on a different resource or need a second key shape.
// What they do record is canonical evidence, which is what a later reader needs, and the
// pipeline records the anti-downgrade mode for (fit_exchange, id, actor).

/** The questions this actor may escalate: the bank for the intent plus every custom
 *  question on the exchange. Shared by both lanes so the two cannot disagree. */
function knownQuestionIds(ex: fitDb.ExchangeRow): Set<string> {
  const ids = new Set(fitDb.getBank(ex.intent).map(q => q.question_id))
  for (const c of fitDb.customForExchange(ex.id)) ids.add(c.id)
  return ids
}

// ── POST /:id/round2 - tell me more (<=3 questions) ───────────────────────

const canonicalExchangeRound2 = canonicalWriteRoute({
  operations: ['fit_exchange_round2'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    gatePayloadKeys(write.payload, ['question_ids', 'antecedent_write_ref'])
    const questionIds = gateStringList(write.payload.question_ids, 'question_ids', MAX_ROUND2)
    const antecedent = gateHex64(write.payload.antecedent_write_ref, 'antecedent_write_ref')
    const exchangeId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key

    const ex = exchangeForWrite(exchangeId, actorKey, now)
    requireAntecedent('fit_exchange', exchangeId, antecedent)
    // EVERY id is checked before the FIRST is written. The legacy loop below used to
    // validate and insert in one pass, so an unknown third id answered 400 with the first
    // two already stored, which is a refusal after a write.
    const known = knownQuestionIds(ex)
    for (const qid of questionIds) {
      if (!known.has(qid)) refuseWrite(400, 'unknown_question_id', `unknown question_id ${qid}`)
    }

    for (const qid of questionIds) fitDb.addRound2(ex.id, actorKey, qid)
    fitDb.setState(ex.id, 'round2')
    recordCanonicalEvidence(write)
    return { exchange_id: ex.id, state: 'round2', round2: questionIds }
  },
})

router.post('/:id/round2', fitGate, canonicalDispatch(canonicalExchangeRound2), rateLimited('fit_answer', 60), (req, res) => {
  const g = partyGuard(req, res, 'fit-round2'); if (!g) return
  const { ex, key } = g
  const { question_ids } = req.body ?? {}
  if (!Array.isArray(question_ids) || question_ids.length === 0 || question_ids.length > MAX_ROUND2) { res.status(400).json({ error: `question_ids required (1..${MAX_ROUND2})` }); return }
  if (ex.state === 'closed') { res.status(409).json({ error: 'exchange is closed' }); return }
  // Anti-downgrade first, then the cutoff. An actor who has already escalated on this
  // exchange with a signed envelope cannot go back to the weaker form.
  const gate = checkLegacyWrite({ resourceType: 'fit_exchange', resourceId: ex.id, actorKey: key, introId: ex.intro_id })
  if (gate !== null) { refuseLegacy(res, 'fit_exchange_round2', ex.id, gate); return }
  // Validate every id before writing any. The old loop did both in one pass.
  const known = knownQuestionIds(ex)
  for (const qid of question_ids) {
    if (!known.has(qid)) { res.status(400).json({ error: `unknown question_id ${qid}` }); return }
  }
  for (const qid of question_ids) fitDb.addRound2(ex.id, key, String(qid))
  fitDb.setState(ex.id, 'round2')
  // Labelled legacy_unbound, and the bound list names the exchange id and nothing else,
  // because fit-round2:${id}:${nonce} covers not one character of question_ids.
  recordLegacyEvidence({
    actorKey: key, operation: 'fit_exchange_round2',
    resourceType: 'fit_exchange', resourceId: ex.id,
    signature: String(req.query.signature ?? req.body?.signature ?? ''),
  })
  res.json({ ok: true, round2: question_ids })
})

// ── POST /:id/custom - ask up to 2 custom questions (post-gated) ───────────

/** The text list a principal signed. Order is theirs and is never sorted, which is the
 *  difference from a dimension or question id list: these are sentences a human wrote and
 *  the sequence carries meaning. */
function gateQuestionTexts(value: unknown, remaining: number): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    refuseWrite(400, 'malformed_payload', 'questions must be a non empty array')
  }
  const list = value as unknown[]
  if (!list.every(x => typeof x === 'string' && x.trim().length > 0)) {
    refuseWrite(400, 'malformed_payload', 'each question must be a non empty string')
  }
  const texts = list as string[]
  for (const t of texts) {
    if (t.length > MAX_CUSTOM_TEXT) {
      refuseWrite(400, 'malformed_payload', `a custom question is longer than ${MAX_CUSTOM_TEXT} characters`)
    }
  }
  if (texts.length > remaining) {
    refuseWrite(409, 'custom_cap_reached',
      `the custom question cap is ${MAX_CUSTOM_PER_ASKER} per party and ${remaining} remain`)
  }
  return texts
}

const canonicalExchangeCustom = canonicalWriteRoute({
  operations: ['fit_exchange_custom'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    gatePayloadKeys(write.payload, ['questions'])
    const exchangeId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key
    const ex = exchangeForWrite(exchangeId, actorKey, now)
    const remaining = MAX_CUSTOM_PER_ASKER - fitDb.customCountByAsker(ex.id, actorKey)
    const texts = gateQuestionTexts(write.payload.questions, remaining)

    // The post-gate still runs, because it is a safety screen on text a counterparty will
    // read and it is not negotiable. What changes is what happens when it would REWRITE
    // the text: the old handler stored the cleaned output, so the stored question was not
    // the question the principal signed and the record could not be recomputed from the
    // signature. Now a text that changes under the gate is REFUSED and the client is told
    // to re-approve, because repairing text after approval is the whole defect.
    const gate = postGateDrafted(texts.map((t, i) => ({ question_id: `custom-${i}`, text: t })))
    if (!gate.ok) refuseWrite(400, 'post_gate_refused', gate.reason ?? 'the question text was refused')
    const cleaned = gate.cleaned ?? []
    for (let i = 0; i < texts.length; i++) {
      if (cleaned[i]?.text !== texts[i]) {
        refuseWrite(400, 'text_not_stored_as_signed',
          'this question would be stored in a different form than the one you signed, so it is refused rather than rewritten. Remove any link and re-approve.')
      }
    }

    const ids: string[] = []
    for (const text of texts) {
      const cid = `fitq-${now.getTime()}-${randomBytes(3).toString('hex')}`
      fitDb.addCustom(cid, ex.id, actorKey, text)
      ids.push(cid)
    }
    recordCanonicalEvidence(write)
    return { exchange_id: ex.id, custom_ids: ids, questions: texts }
  },
})

router.post('/:id/custom', fitGate, canonicalDispatch(canonicalExchangeCustom), rateLimited('fit_answer', 30), (req, res) => {
  const g = partyGuard(req, res, 'fit-custom'); if (!g) return
  const { ex, key } = g
  const { questions } = req.body ?? {}
  if (ex.state === 'closed') { res.status(409).json({ error: 'exchange is closed' }); return }
  if (!Array.isArray(questions) || questions.length === 0) { res.status(400).json({ error: 'questions required' }); return }
  const existing = fitDb.customCountByAsker(ex.id, key)
  if (existing + questions.length > MAX_CUSTOM_PER_ASKER) { res.status(400).json({ error: `custom question cap is ${MAX_CUSTOM_PER_ASKER} per party` }); return }
  const gateResult = checkLegacyWrite({ resourceType: 'fit_exchange', resourceId: ex.id, actorKey: key, introId: ex.intro_id })
  if (gateResult !== null) { refuseLegacy(res, 'fit_exchange_custom', ex.id, gateResult); return }

  const texts: string[] = []
  for (const q of questions) {
    const text = typeof q === 'string' ? q : q?.text
    if (typeof text !== 'string' || text.trim().length === 0) { res.status(400).json({ error: 'each custom question needs text' }); return }
    if (text.length > MAX_CUSTOM_TEXT) { res.status(400).json({ error: `custom question too long (max ${MAX_CUSTOM_TEXT})` }); return }
    texts.push(text)
  }
  const gate = postGateDrafted(texts.map((t, i) => ({ question_id: `custom-${i}`, text: t })))
  if (!gate.ok) { res.status(400).json({ error: gate.reason }); return }
  const cleaned = gate.cleaned ?? []

  const ids: string[] = []
  for (const c of cleaned) {
    const cid = `fitq-${Date.now()}-${randomBytes(3).toString('hex')}`
    fitDb.addCustom(cid, ex.id, key, c.text)
    ids.push(cid)
  }
  // The legacy lane keeps storing the cleaned text, because that is what a published
  // 3.2.2 client expects and changing it would be a behaviour change on the old path. The
  // evidence row says so: the bound list names the exchange id and nothing else.
  recordLegacyEvidence({
    actorKey: key, operation: 'fit_exchange_custom',
    resourceType: 'fit_exchange', resourceId: ex.id,
    signature: String(req.query.signature ?? req.body?.signature ?? ''),
  })
  res.json({ ok: true, custom_ids: ids })
})

// ── POST /:id/close - assemble + sign the record ──────────────────────────

router.post('/:id/close', fitGate, rateLimited('fit_answer', 30), async (req, res) => {
  const g = partyGuard(req, res, 'fit-close'); if (!g) return
  const { ex } = g
  const out = closeExchangeNow(ex)
  try {
    await email.notifyFitRecordReady(ex.key_a, ex.id)
    await email.notifyFitRecordReady(ex.key_b, ex.id)
  } catch { /* record-ready email never blocks close */ }
  res.json({ closed: true, record: out.record, record_digest: out.digest, receipt: out.receipt, server_public_key: serverPublicKey() })
})

/** Assemble, sign, and persist the record for an exchange (idempotent). */
export function closeExchangeNow(ex: fitDb.ExchangeRow): { record: unknown; digest: string; receipt: string } {
  const fresh = fitDb.getExchange(ex.id)!
  if (fresh.state === 'closed' && fresh.record_json) {
    return { record: JSON.parse(fresh.record_json), digest: fresh.record_digest!, receipt: fresh.receipt! }
  }
  const bank = fitDb.getBank(fresh.intent)
  const answers = fitDb.answersForExchange(fresh.id)
  const round2s = fitDb.round2ForExchange(fresh.id)
  const customs = fitDb.customForExchange(fresh.id)
  const sealed = sealRecord(fresh, bank, answers, round2s, customs)
  fitDb.closeExchange(fresh.id, JSON.stringify(sealed.record), sealed.digest, sealed.receipt)
  // Recorded against both cards: a closed exchange is a fact for each side.
  recordCardEvent('handshake_closed', fresh.card_a, fresh.key_a, { exchange_id: fresh.id, intro_id: fresh.intro_id, intent: fresh.intent, record_digest: sealed.digest })
  recordCardEvent('handshake_closed', fresh.card_b, fresh.key_b, { exchange_id: fresh.id, intro_id: fresh.intro_id, intent: fresh.intent, record_digest: sealed.digest })
  return { record: sealed.record, digest: sealed.digest, receipt: sealed.receipt }
}

// ── Exchange creation on intro acceptance ────────────────────────────────
// Called from the intro accept handler. Opens an exchange only when the intro's
// purpose is a banked intent AND both cards list that intent. Returns the
// accepter's consent sheet, or null (the intro then proceeds to contact only).

export async function createFitExchangeForIntro(intro: introsDb.IntroRow): Promise<{ id: string; consent_sheet: Record<string, unknown> } | null> {
  const purpose = intro.purpose
  if (!fitDb.isBankedIntent(purpose)) return null
  const from = v3db.getV3Card(intro.from_card)
  const to = v3db.getV3Card(intro.to_card)
  if (!from || !to) return null
  if (from.revocation_status !== 'active' || to.revocation_status !== 'active') return null
  if (!Array.isArray(from.card.intents) || !from.card.intents.includes(purpose)) return null
  if (!Array.isArray(to.card.intents) || !to.card.intents.includes(purpose)) return null
  if (fitDb.existsActiveExchangeForIntro(intro.id)) return null

  const id = `fit-${Date.now()}-${randomBytes(4).toString('hex')}`
  const expires_at = new Date(Date.now() + fitDb.FIT_WINDOW_MS).toISOString()
  fitDb.createExchange({
    id, intro_id: intro.id, card_a: intro.from_card, card_b: intro.to_card,
    key_a: intro.from_key, key_b: intro.to_key, intent: purpose, expires_at,
    ledger_version_a: fitDb.getLedgerVersion(intro.from_card),
    ledger_version_b: fitDb.getLedgerVersion(intro.to_card),
  })
  const ex = fitDb.getExchange(id)!

  try {
    const fromHeadline = (networkVisibleView({ ...from.card, card_id: intro.from_card } as any) as any).headline ?? ''
    const toHeadline = (networkVisibleView({ ...to.card, card_id: intro.to_card } as any) as any).headline ?? ''
    await email.notifyFitStarted(intro.from_key, id, toHeadline, purpose)
    await email.notifyFitStarted(intro.to_key, id, fromHeadline, purpose)
  } catch { /* started email never blocks creation */ }

  return { id, consent_sheet: consentSheet(ex, intro.to_key) }
}

// ── 72h sweep ──────────────────────────────────────────────────────────────

export function sweepExpiredFitExchanges(): { closed: number } {
  const expired = fitDb.expiredOpenExchanges()
  for (const ex of expired) closeExchangeNow(ex)
  return { closed: expired.length }
}

// Exposed for tests and manual runs, rate limited per client. The scheduler in
// server.ts calls sweepExpiredFitExchanges directly, not this route.
//
// Behind fitGate as of step 18, which is CONTAINMENT and not repair: this route reads no
// body, no public key and no signature, so there is nothing to sign and it cannot be
// canonicalized at all. The release gate still counts it as unrepaired, deliberately,
// because a route that counts as contained while the flag is off would make the gate
// circular. Step 25 removes it.
router.post('/sweep', fitGate, rateLimited('fit_sweep', 6), (_req, res) => { res.json(sweepExpiredFitExchanges()) })

export { verifyReceipt }
export default router
