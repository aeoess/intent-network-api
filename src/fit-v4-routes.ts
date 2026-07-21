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

  const facts = evaluateHandshake(dims, policyReq, policyCom, budgetBlocked)
  const compl = complementarityEntry(dims, policyReq, policyCom)
  const overlap_map = compl ? [...facts, compl] : facts

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
  res.json({ revealed: dimension })
})

export { verifyReceipt }
export default router
