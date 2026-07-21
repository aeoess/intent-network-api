// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - routes (mounted at /api/v4/fit)
// ══════════════════════════════════════════════════════════════
// Stage 1: the private Fit Policy (set / get, owner-only, exact-set approval).
// Later stages add the bilateral predicate handshake. Everything here is signed
// by the acting key; a policy's values never leave the owner except through the
// handshake's mutually-authorized, canonical predicates.

import { Router } from 'express'
import { createHash } from 'node:crypto'
import { verify, canonicalize } from 'agent-passport-system'
import { checkRateLimit } from './db.js'
import * as v3db from './v3-db.js'
import * as policyDb from './fit-policy-db.js'
import * as handshakeDb from './fit-handshake-db.js'
import { selectEvaluableDimensions, evaluateHandshake, complementarityEntry, type OverlapEntry } from './fit-handshake.js'
import { POLICY_INTENTS, PREDICATE_VERSION, DISCLOSURE_RANK } from './fit-schema.js'
import { signReceipt, serverPublicKey, verifyReceipt } from './server-key.js'
import type { IntroRow } from './intros-db.js'
import * as qaDb from './fit-qa-db.js'
import * as autonomyDb from './fit-autonomy-db.js'
import { questionFor } from './fit-questions.js'
import { ledgerItemLive } from './fit-db.js'
import { postGateDrafted, type PostGateInput } from './fit-gate.js'
import { extract as airlockExtract, plan as airlockPlan } from './fit-airlock.js'

const router = Router()

const HANDSHAKE_WINDOW_MS = 72 * 3600 * 1000
const MAX_QUERY_BUDGET = 10

function checkSig(payload: string, signature: unknown, key: unknown): boolean {
  if (typeof signature !== 'string' || typeof key !== 'string') return false
  try { return verify(payload, signature, key) } catch { return false }
}

function rateLimited(action: string, limit: number) {
  return (req: any, res: any, next: any) => {
    if (!checkRateLimit(`fitv4:${req.ip || 'anon'}`, action, limit).allowed) { res.status(429).json({ error: 'Rate limit exceeded' }); return }
    next()
  }
}

function ownsCard(cardId: string, publicKey: string): boolean {
  const stored = v3db.getV3Card(cardId)
  return !!stored && stored.card.subject_key === publicKey
}

// ── POST /policy - set the Fit Policy (exact-set approval + signature) ─────

router.post('/policy', rateLimited('fitv4_policy', 20), (req, res) => {
  const { card_id, dimensions, approved_hash, public_key, nonce, signature } = req.body ?? {}
  if (typeof card_id !== 'string' || typeof approved_hash !== 'string' || typeof nonce !== 'string') {
    res.status(400).json({ error: 'card_id, dimensions, approved_hash, nonce required' }); return
  }
  if (!checkSig(`set-fit-policy:${card_id}:${approved_hash}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  if (!ownsCard(card_id, public_key)) { res.status(403).json({ error: 'not the card subject' }); return }

  const validation = policyDb.validatePolicyDimensions(dimensions)
  if (!validation.ok || !validation.dimensions) { res.status(400).json({ error: validation.error }); return }
  const dims = validation.dimensions
  if (policyDb.policyHash(dims) !== approved_hash) { res.status(400).json({ error: 'approved_hash does not match the dimensions; re-approve the exact set' }); return }

  const result = policyDb.setPolicy(card_id, public_key, dims)
  res.status(201).json({ card_id, version: result.version, policy_hash: result.policy_hash, dimensions: dims.length })
})

// ── GET /policy - own policy (signed) ─────────────────────────────────────

router.get('/policy', rateLimited('fitv4_get', 60), (req, res) => {
  const card_id = String(req.query.card_id ?? '')
  const public_key = String(req.query.public_key ?? '')
  const nonce = String(req.query.nonce ?? '')
  const signature = String(req.query.signature ?? '')
  if (!card_id || !nonce) { res.status(400).json({ error: 'card_id and nonce required' }); return }
  if (!checkSig(`get-fit-policy:${card_id}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  if (!ownsCard(card_id, public_key)) { res.status(403).json({ error: 'not the card subject' }); return }
  const policy = policyDb.getCurrentPolicy(card_id)
  res.json(policy ?? { card_id, version: 0, dimensions: [] })
})

// ══════════════════════════════════════════════════════════════
// Bilateral predicate handshake
// ══════════════════════════════════════════════════════════════

/** Open a v4 handshake for an accepted intro when BOTH cards carry a v4 policy
 *  with at least one dimension for the shared (banked) intent. Returns null so
 *  the caller falls back to the v3 exchange. Work is never banked, so a work
 *  intro never opens a handshake. */
export function openV4HandshakeForIntro(intro: IntroRow): { id: string; mode: 'v4' } | null {
  const intent = intro.purpose
  if (!(POLICY_INTENTS as readonly string[]).includes(intent)) return null
  if (!policyDb.hasPolicy(intro.from_card) || !policyDb.hasPolicy(intro.to_card)) return null
  const pa = policyDb.getCurrentPolicy(intro.from_card)
  const pb = policyDb.getCurrentPolicy(intro.to_card)
  if (!pa || !pb) return null
  if (policyDb.dimensionsForIntent(pa, intent).length === 0 || policyDb.dimensionsForIntent(pb, intent).length === 0) return null
  if (handshakeDb.existsHandshakeForIntro(intro.id)) return null
  handshakeDb.createHandshake({
    intro_id: intro.id, card_a: intro.from_card, card_b: intro.to_card,
    key_a: intro.from_key, key_b: intro.to_key, intent,
    expires_at: new Date(Date.now() + HANDSHAKE_WINDOW_MS).toISOString(),
  })
  return { id: intro.id, mode: 'v4' }
}

function cardOfKey(hs: handshakeDb.HandshakeRow, key: string): string | null {
  if (key === hs.key_a) return hs.card_a
  if (key === hs.key_b) return hs.card_b
  return null
}
function otherKey(hs: handshakeDb.HandshakeRow, key: string): string {
  return key === hs.key_a ? hs.key_b : hs.key_a
}
function isParty(hs: handshakeDb.HandshakeRow, key: string): boolean {
  return key === hs.key_a || key === hs.key_b
}
function dimMapFor(cardId: string, hash: string, intent: string): Map<string, policyDb.PolicyDimension> {
  const pol = policyDb.getPolicyByHash(cardId, hash)
  const m = new Map<string, policyDb.PolicyDimension>()
  if (!pol) return m
  for (const dd of policyDb.dimensionsForIntent(pol, intent)) m.set(dd.dimension, dd)
  return m
}
function levelName(a: policyDb.PolicyDimension, b: policyDb.PolicyDimension): string {
  const eff = Math.min(DISCLOSURE_RANK[a.disclosure_state], DISCLOSURE_RANK[b.disclosure_state])
  return (['', 'local_only', 'testable', 'reveal_overlap', 'reveal_bucket', 'reveal_exact'])[eff]
}

// ── POST /:introId/request - the signed Fit Request Manifest ──────────────

router.post('/:introId/request', rateLimited('fitv4_hs', 30), (req, res) => {
  const introId = String(req.params.introId)
  const { requested_dimensions, reciprocal_offer, predicate_version, policy_hash, query_budget, public_key, nonce, signature } = req.body ?? {}
  if (!Array.isArray(requested_dimensions) || requested_dimensions.length === 0 || typeof nonce !== 'string') { res.status(400).json({ error: 'requested_dimensions and nonce required' }); return }
  if (!checkSig(`fit-request:${introId}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }
  if (hs.state !== 'open') { res.status(409).json({ error: `handshake already ${hs.state}` }); return }
  if (predicate_version !== undefined && predicate_version !== PREDICATE_VERSION) { res.status(400).json({ error: `predicate_version must be ${PREDICATE_VERSION}` }); return }

  const card = cardOfKey(hs, public_key)!
  const pol = policyDb.getCurrentPolicy(card)
  if (!pol || pol.policy_hash !== policy_hash) { res.status(400).json({ error: 'policy_hash must match your current policy' }); return }
  const permitted = new Set(policyDb.dimensionsForIntent(pol, hs.intent).map(x => x.dimension))
  for (const dim of requested_dimensions) {
    if (!permitted.has(dim)) { res.status(400).json({ error: `dimension "${dim}" is not in your policy for intent ${hs.intent}` }); return }
  }
  const reciprocal = Array.isArray(reciprocal_offer) ? reciprocal_offer : requested_dimensions
  const budget = Math.min(Math.max(1, Number(query_budget) || 3), MAX_QUERY_BUDGET)
  handshakeDb.setRequest(introId, public_key, requested_dimensions, reciprocal, policy_hash, budget)
  res.status(201).json({ state: 'requested', requested_dimensions, note: 'Nothing is evaluated until the counterparty commits to the same dimensions with matching reciprocity.' })
})

// ── POST /:introId/commit - reciprocity gate; evaluate on mutual commit ───

router.post('/:introId/commit', rateLimited('fitv4_hs', 30), (req, res) => {
  const introId = String(req.params.introId)
  const { accept_dimensions, reciprocal_offer, policy_hash, public_key, nonce, signature } = req.body ?? {}
  if (!Array.isArray(accept_dimensions) || typeof nonce !== 'string') { res.status(400).json({ error: 'accept_dimensions and nonce required' }); return }
  if (!checkSig(`fit-commit:${introId}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }
  if (hs.state !== 'requested') { res.status(409).json({ error: `handshake is ${hs.state}, not awaiting a commit` }); return }
  if (public_key === hs.requester_key) { res.status(403).json({ error: 'the requester cannot also commit; the counterparty commits' }); return }
  if (Date.parse(hs.expires_at) <= Date.now()) { res.status(409).json({ error: 'handshake window expired' }); return }

  const committerCard = cardOfKey(hs, public_key)!
  const comPol = policyDb.getCurrentPolicy(committerCard)
  if (!comPol || comPol.policy_hash !== policy_hash) { res.status(400).json({ error: 'policy_hash must match your current policy' }); return }
  const comPermitted = new Set(policyDb.dimensionsForIntent(comPol, hs.intent).map(x => x.dimension))
  for (const dim of accept_dimensions) {
    if (!comPermitted.has(dim)) { res.status(400).json({ error: `dimension "${dim}" is not in your policy for intent ${hs.intent}` }); return }
  }

  const requesterCard = cardOfKey(hs, hs.requester_key!)!
  const policyReq = dimMapFor(requesterCard, hs.req_policy_hash!, hs.intent)
  const policyCom = dimMapFor(committerCard, policy_hash, hs.intent)
  const requested: string[] = JSON.parse(hs.requested_json || '[]')
  const reqReciprocal: string[] = JSON.parse(hs.req_reciprocal_json || '[]')
  const comReciprocal: string[] = Array.isArray(reciprocal_offer) ? reciprocal_offer : accept_dimensions

  const dims = selectEvaluableDimensions(requested, accept_dimensions, reqReciprocal, comReciprocal, policyReq, policyCom)

  // Anti-narrowing: consume budget per (principal pair, dimension). A dimension
  // over its lifetime cap is refused, not re-evaluated.
  const pairKey = handshakeDb.principalPairKey(hs.key_a, hs.key_b)
  const budgetBlocked = new Set<string>()
  for (const dim of dims) {
    if (!handshakeDb.budgetConsume(pairKey, dim).allowed) budgetBlocked.add(dim)
  }

  // Graduated autonomy: when the committer commits autonomously (under a standing
  // scope, no fresh human tap), every disclosed dimension must fall within the
  // scope's tier. Anything above it, or high-sensitivity, or exact, is refused
  // and must be committed by a human. A pause halts all autonomous commits.
  const autonomous = req.body?.autonomous === true
  if (autonomous) {
    for (const dim of dims) {
      const a = policyReq.get(dim), b = policyCom.get(dim)
      if (!a || !b || budgetBlocked.has(dim)) continue
      const eff = levelName(a, b) as any
      if (!autonomyDb.autonomyPermitsDisclosure(committerCard, hs.intent, dim, eff, b.sensitivity)) {
        res.status(403).json({ error: `dimension "${dim}" is outside your autonomy scope (or too sensitive, or exact); commit it without autonomous:true so the principal approves it` }); return
      }
    }
  }

  const facts = evaluateHandshake(dims, policyReq, policyCom, budgetBlocked)
  const compl = complementarityEntry(dims, policyReq, policyCom)
  const overlap_map = compl ? [...facts, compl] : facts

  // Legible activity: record what the committer's agent disclosed, so a truthful
  // "while you were away" summary can be shown later.
  autonomyDb.recordActivity(public_key, introId, 'evaluated', null, otherKey(hs, public_key), autonomous)
  for (const e of overlap_map) {
    if (e.dimension === 'complementarity') continue
    if (e.result === 'overlap') autonomyDb.recordActivity(public_key, introId, 'overlap_disclosed', e.dimension, otherKey(hs, public_key), autonomous)
    else if (e.result === 'bucket' || e.result === 'exact_available') autonomyDb.recordActivity(public_key, introId, 'bucket_disclosed', e.dimension, otherKey(hs, public_key), autonomous)
  }

  // Receipt: binds both policy hashes, requested predicates, purpose, each
  // authorized disclosure level, outcome, expiry. Attests authorization only.
  const disclosures = dims.filter(d => policyReq.get(d) && policyCom.get(d)).map(d => ({ dimension: d, level: levelName(policyReq.get(d)!, policyCom.get(d)!) }))
  const receiptContent = {
    intro_id: introId, purpose: hs.intent, predicate_version: PREDICATE_VERSION,
    policy_hash_a: hs.req_policy_hash, policy_hash_b: policy_hash,
    requested_predicates: dims,
    disclosures,
    outcome: overlap_map.map((e: OverlapEntry) => ({ dimension: e.dimension, result: e.result })),
    expiry: hs.expires_at,
    proves: 'Each party authorized the listed dimensions at the listed disclosure levels under their stated policy hash, for the stated purpose. This attests authorization, not the truth of any value.',
  }
  const receiptDigest = createHash('sha256').update(canonicalize(receiptContent), 'utf8').digest('hex')
  const receipt = signReceipt(receiptDigest)

  handshakeDb.setCommitResult(introId, public_key, accept_dimensions, comReciprocal, policy_hash, JSON.stringify(overlap_map), receipt, receiptDigest, JSON.stringify(receiptContent))
  res.json({ state: 'committed', overlap_map, receipt, receipt_digest: receiptDigest, receipt_content: receiptContent, server_public_key: serverPublicKey() })
})

// ── GET /:introId (parties only) ──────────────────────────────────────────

router.get('/:introId', rateLimited('fitv4_get', 60), (req, res) => {
  const introId = String(req.params.introId)
  const public_key = String(req.query.public_key ?? '')
  const nonce = String(req.query.nonce ?? '')
  const signature = String(req.query.signature ?? '')
  if (!public_key || !nonce) { res.status(400).json({ error: 'public_key and nonce required' }); return }
  if (!checkSig(`fit-hs-get:${introId}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }

  const base: Record<string, unknown> = { intro_id: introId, intent: hs.intent, state: hs.state, expires_at: hs.expires_at }
  if (hs.state !== 'committed' || !hs.result_json) { res.json(base); return }

  // Merge any human-tap-released exact values into the map for the two parties.
  const released = JSON.parse(hs.released_exacts_json || '{}') as Record<string, string>
  const map = JSON.parse(hs.result_json) as OverlapEntry[]
  const requesterCard = cardOfKey(hs, hs.requester_key!)!
  const committerCard = cardOfKey(hs, hs.committer_key!)!
  const polReq = dimMapFor(requesterCard, hs.req_policy_hash!, hs.intent)
  const polCom = dimMapFor(committerCard, hs.com_policy_hash!, hs.intent)
  const withExacts = map.map(e => {
    if (released[e.dimension]) {
      return { ...e, exact_a: polReq.get(e.dimension)?.value, exact_b: polCom.get(e.dimension)?.value }
    }
    return e
  })
  res.json({ ...base, overlap_map: withExacts, receipt: hs.receipt, receipt_digest: hs.receipt_digest, receipt_content: hs.receipt_content_json ? JSON.parse(hs.receipt_content_json) : undefined, server_public_key: serverPublicKey() })
})

// ── POST /:introId/reveal - human-tap exact release (state 5) ──────────────

router.post('/:introId/reveal', rateLimited('fitv4_hs', 30), (req, res) => {
  const introId = String(req.params.introId)
  const { dimension, public_key, nonce, signature } = req.body ?? {}
  if (typeof dimension !== 'string' || typeof nonce !== 'string') { res.status(400).json({ error: 'dimension and nonce required' }); return }
  if (!checkSig(`fit-reveal:${introId}:${dimension}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }
  if (hs.state !== 'committed') { res.status(409).json({ error: 'handshake is not committed' }); return }

  // Only reveal-exact dimensions the owner authorized may be released, by the owner.
  const ownerCard = cardOfKey(hs, public_key)!
  const ownerHash = public_key === hs.requester_key ? hs.req_policy_hash! : hs.com_policy_hash!
  const ownMap = dimMapFor(ownerCard, ownerHash, hs.intent)
  const own = ownMap.get(dimension)
  if (!own || own.disclosure_state !== 'reveal_exact') { res.status(403).json({ error: 'this dimension is not authorized for exact release by you' }); return }
  handshakeDb.releaseExact(introId, dimension, public_key)
  autonomyDb.recordActivity(public_key, introId, 'exact_released', dimension, otherKey(hs, public_key), false)
  res.json({ revealed: dimension })
})

// ══════════════════════════════════════════════════════════════
// Stage 6: graduated autonomy scopes + legible "while away" activity
// ══════════════════════════════════════════════════════════════

// ── POST /autonomy - set a scoped standing authorization (exact-approved) ──

router.post('/autonomy', rateLimited('fitv4_policy', 20), (req, res) => {
  const { card_id, scope, approved_hash, public_key, nonce, signature } = req.body ?? {}
  if (typeof card_id !== 'string' || typeof approved_hash !== 'string' || typeof nonce !== 'string') { res.status(400).json({ error: 'card_id, scope, approved_hash, nonce required' }); return }
  if (!checkSig(`set-fit-autonomy:${card_id}:${approved_hash}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  if (!ownsCard(card_id, public_key)) { res.status(403).json({ error: 'not the card subject' }); return }
  const v = autonomyDb.validateScope(scope)
  if (!v.ok || !v.scope) { res.status(400).json({ error: v.error }); return }
  if (autonomyDb.scopeHash(v.scope) !== approved_hash) { res.status(400).json({ error: 'approved_hash does not match the scope; re-approve the exact scope' }); return }
  const result = autonomyDb.setScope(card_id, public_key, v.scope)
  res.status(201).json({ card_id, version: result.version, scope_hash: result.scope_hash, forbidden_categories: v.scope.forbidden_categories })
})

// ── POST /autonomy/pause - halt (or resume) all autonomous disclosure ─────

router.post('/autonomy/pause', rateLimited('fitv4_policy', 30), (req, res) => {
  const { card_id, paused, public_key, nonce, signature } = req.body ?? {}
  if (typeof card_id !== 'string' || typeof paused !== 'boolean' || typeof nonce !== 'string') { res.status(400).json({ error: 'card_id, paused, nonce required' }); return }
  if (!checkSig(`fit-autonomy-pause:${card_id}:${paused}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  if (!ownsCard(card_id, public_key)) { res.status(403).json({ error: 'not the card subject' }); return }
  autonomyDb.setPaused(card_id, paused)
  res.json({ card_id, paused })
})

// ── GET /autonomy/activity - the "while you were away" summary (signed) ────

router.get('/autonomy/activity', rateLimited('fitv4_get', 60), (req, res) => {
  const card_id = String(req.query.card_id ?? '')
  const public_key = String(req.query.public_key ?? '')
  const nonce = String(req.query.nonce ?? '')
  const signature = String(req.query.signature ?? '')
  const since = typeof req.query.since === 'string' ? req.query.since : undefined
  if (!card_id || !nonce) { res.status(400).json({ error: 'card_id and nonce required' }); return }
  if (!checkSig(`fit-autonomy-activity:${card_id}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  if (!ownsCard(card_id, public_key)) { res.status(403).json({ error: 'not the card subject' }); return }
  res.json({ card_id, summary: autonomyDb.whileAwaySummary(public_key, since), activity: autonomyDb.activityFor(public_key, since) })
})

// ══════════════════════════════════════════════════════════════
// Stage 5: adaptive question selection, routed through the airlock
// ══════════════════════════════════════════════════════════════

/** Unresolved = union of both sides' essential/useful dimensions for the intent,
 *  minus dimensions the handshake overlap map already settled and minus any
 *  already answered. Capped to 4, only dimensions with a canonical question. */
function unresolvedQuestions(hs: handshakeDb.HandshakeRow): { dimension: string; question: string }[] {
  const important = new Set<string>()
  for (const cardId of [hs.card_a, hs.card_b]) {
    const pol = policyDb.getCurrentPolicy(cardId)
    if (!pol) continue
    for (const dd of policyDb.dimensionsForIntent(pol, hs.intent)) {
      if (dd.importance === 'essential' || dd.importance === 'useful') important.add(dd.dimension)
    }
  }
  const settled = new Set<string>()
  if (hs.result_json) {
    for (const e of JSON.parse(hs.result_json) as OverlapEntry[]) {
      if (e.result === 'overlap' || e.result === 'bucket' || e.result === 'exact_available') settled.add(e.dimension)
    }
  }
  for (const dim of qaDb.settledDimensions(hs.intro_id)) settled.add(dim)
  return [...important].filter(dim => !settled.has(dim) && questionFor(dim)).sort().slice(0, 4).map(dim => ({ dimension: dim, question: questionFor(dim)! }))
}

// ── POST /:introId/questions ──────────────────────────────────────────────

router.post('/:introId/questions', rateLimited('fitv4_hs', 60), (req, res) => {
  const introId = String(req.params.introId)
  const { public_key, nonce, signature } = req.body ?? {}
  if (typeof nonce !== 'string') { res.status(400).json({ error: 'nonce required' }); return }
  if (!checkSig(`fit-questions:${introId}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }
  res.json({ questions: unresolvedQuestions(hs), note: 'These are the unresolved dimensions, capped at four. Questions are canonical renderings; the counterpart never authors them.' })
})

// ── POST /:introId/answers (signed ticket; drafted routes through the airlock) ─

router.post('/:introId/answers', rateLimited('fitv4_hs', 60), (req, res) => {
  const introId = String(req.params.introId)
  const { answers, public_key, nonce, signature } = req.body ?? {}
  if (!Array.isArray(answers) || answers.length === 0 || typeof nonce !== 'string') { res.status(400).json({ error: 'answers and nonce required' }); return }
  const answersHash = createHash('sha256').update(canonicalize({ intro_id: introId, nonce, answers }), 'utf8').digest('hex')
  if (!checkSig(answersHash, signature, public_key)) { res.status(403).json({ error: 'ticket signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }
  const ownCard = cardOfKey(hs, public_key)!
  const pol = policyDb.getCurrentPolicy(ownCard)
  const permitted = new Set((pol ? policyDb.dimensionsForIntent(pol, hs.intent) : []).map(x => x.dimension))

  for (const a of answers) {
    if (!['ledger', 'drafted', 'skip'].includes(a?.mode)) { res.status(400).json({ error: 'each answer mode must be ledger, drafted, or skip' }); return }
    if (!questionFor(a.dimension) || !permitted.has(a.dimension)) { res.status(400).json({ error: `dimension "${a.dimension}" is not an askable dimension in your policy for this intent` }); return }
  }
  // Post-gate the drafted texts as a batch (same deterministic checks as v3).
  const drafted: PostGateInput[] = answers.filter((a: any) => a.mode === 'drafted').map((a: any) => ({ question_id: a.dimension, text: String(a.text ?? '') }))
  const cleaned = new Map<string, string>()
  if (drafted.length > 0) {
    const gate = postGateDrafted(drafted)
    if (!gate.ok) { res.status(400).json({ error: gate.reason, dimension: gate.question_id }); return }
    for (const c of gate.cleaned ?? []) cleaned.set(c.question_id, c.text)
  }

  for (const a of answers) {
    if (a.mode === 'skip') { qaDb.upsertQa({ intro_id: introId, dimension: a.dimension, answerer_key: public_key, mode: 'skip', text: null }); continue }
    if (a.mode === 'ledger') {
      const item = ledgerItemLive(ownCard, String(a.ledger_id))
      if (!item) { res.status(409).json({ error: `ledger item ${a.ledger_id} was superseded; re-approve and re-answer` }); return }
      qaDb.upsertQa({ intro_id: introId, dimension: a.dimension, answerer_key: public_key, mode: 'ledger', text: `Their approved brief states: "${item.text}"` })
      continue
    }
    // drafted: store the raw (human view) AND the airlock extraction (structured).
    // The extractor sees ONLY {answer, question, schema}; its output carries no
    // free text from the answer, so nothing crosses into a policy-bearing planner.
    const raw = cleaned.get(a.dimension)!
    const extraction = airlockExtract({ answer: raw, question: questionFor(a.dimension)!, schema: { dimension: a.dimension } })
    qaDb.upsertQa({ intro_id: introId, dimension: a.dimension, answerer_key: public_key, mode: 'drafted', text: raw, extraction_json: JSON.stringify(extraction) })
  }
  res.json({ ok: true, answered: answers.length })
})

// ── POST /:introId/round2 ──────────────────────────────────────────────────

router.post('/:introId/round2', rateLimited('fitv4_hs', 30), (req, res) => {
  const introId = String(req.params.introId)
  const { dimension_ids, public_key, nonce, signature } = req.body ?? {}
  if (!Array.isArray(dimension_ids) || dimension_ids.length === 0 || dimension_ids.length > 3 || typeof nonce !== 'string') { res.status(400).json({ error: 'dimension_ids required (1..3)' }); return }
  if (!checkSig(`fit-qa-round2:${introId}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }
  for (const dim of dimension_ids) { if (questionFor(dim)) qaDb.addRound2(introId, public_key, String(dim)) }
  res.json({ ok: true, round2: dimension_ids })
})

// ── GET /:introId/qa - the extractive record (parties only) ───────────────

router.get('/:introId/qa', rateLimited('fitv4_get', 60), (req, res) => {
  const introId = String(req.params.introId)
  const public_key = String(req.query.public_key ?? '')
  const nonce = String(req.query.nonce ?? '')
  const signature = String(req.query.signature ?? '')
  if (!public_key || !nonce) { res.status(400).json({ error: 'public_key and nonce required' }); return }
  if (!checkSig(`fit-qa-get:${introId}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }

  const rows = qaDb.qaForIntro(introId)
  const round2 = qaDb.round2ForIntro(introId)
  const viewerPol = policyDb.getCurrentPolicy(cardOfKey(hs, public_key)!)
  const viewerDims = new Map((viewerPol ? policyDb.dimensionsForIntent(viewerPol, hs.intent) : []).map(x => [x.dimension, x]))

  const byDimension = new Map<string, any>()
  for (const r of rows) {
    if (!byDimension.has(r.dimension)) byDimension.set(r.dimension, { dimension: r.dimension, question: questionFor(r.dimension), answers: [] })
    const round2Pending = round2.some(x => x.dimension === r.dimension && x.requester_key !== r.answerer_key) && r.mode === 'skip'
    const classification = r.mode === 'skip' ? (round2Pending ? 'partially_answered' : 'not_answered') : 'answered'
    const extraction = r.extraction_json ? JSON.parse(r.extraction_json) : undefined
    // A planner hint uses ONLY the extraction (never the raw text) plus the
    // viewer's own policy for this dimension: this is where plan() runs.
    let plan_hint
    if (extraction && r.answerer_key !== public_key && viewerDims.has(r.dimension)) {
      const vd = viewerDims.get(r.dimension)!
      plan_hint = airlockPlan(extraction, { disclosure_state: vd.disclosure_state, importance: vd.importance, sensitivity: vd.sensitivity })
    }
    byDimension.get(r.dimension).answers.push({
      answerer_key: r.answerer_key,
      mode: r.mode,
      raw_text: r.text,          // the human view; may contain the counterpart's own words
      extraction,                // the structured, secretless signal
      classification,
      plan_hint,
    })
  }
  res.json({
    intro_id: introId,
    record: [...byDimension.values()],
    note: 'raw_text is for the human to read; only the extraction (never raw_text) is used by any planner. Refusal or silence is never negative.',
  })
})

export { verifyReceipt }
export default router
