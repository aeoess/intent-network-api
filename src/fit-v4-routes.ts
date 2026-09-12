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
import { checkRateLimit, getDb } from './db.js'
import * as v3db from './v3-db.js'
import * as policyDb from './fit-policy-db.js'
import * as handshakeDb from './fit-handshake-db.js'
import { selectEvaluableDimensions, evaluateHandshake, complementarityEntry, type OverlapEntry } from './fit-handshake.js'
import { POLICY_INTENTS, PREDICATE_VERSION, DISCLOSURE_RANK } from './fit-schema.js'
import { signReceipt, serverPublicKey, verifyReceipt } from './server-key.js'
import type { IntroRow } from './intros-db.js'
import * as qaDb from './fit-qa-db.js'
import * as autonomyDb from './fit-autonomy-db.js'
import * as firstStepDb from './fit-firststep-db.js'
import * as email from './notifications.js'
import { questionFor } from './fit-questions.js'
import { ledgerItemLive } from './fit-db.js'
import { fitGate, postGateDrafted, type PostGateInput } from './fit-gate.js'
import { extract as airlockExtract, plan as airlockPlan } from './fit-airlock.js'
import { asyncRoute } from './async-route.js'
import { recordCardEvent } from './card-events.js'
import * as introsDb from './intros-db.js'
import { jcs } from './canonical-write.js'
import { canonicalWriteRoute, canonicalDispatch, refuseWrite } from './write-pipeline.js'
import type { CanonicalContext } from './write-pipeline.js'
import { recordCanonicalEvidence, recordLegacyEvidence } from './write-evidence.js'
import { recordAuthMode } from './write-db.js'
import { recordAuthorization, materializeStatus, writeRefOfAuthorization, boundFieldsOfAuthorization } from './connection-facts.js'
import { factsForWrite, guardState, requireParty } from './intro-guards.js'
import { checkLegacyWrite, refuseLegacy } from './legacy-write-gate.js'
import { writeArtifact } from './private-artifacts.js'
import { policyHashForCommitment, commitmentIsCurrent, registerPolicyCommitment, commitmentForPolicyHash } from './policy-commitment.js'
import { renderFitHandshake, warrantList } from './receipt-render.js'
import { boundFieldsFor } from './write-evidence.js'

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

// ── POST /policy/commitment - register a salted commitment to your policy ──
// The owner computes commitment = SHA-256(JCS({domain, salt, policy: normalized})) over
// the policy the server already holds, and sends the commitment and the salt. The server
// verifies the opening once and then keeps ONLY the commitment, so the strongest thing it
// can say afterwards is that a commitment was opened to it once.
//
// The policy body is not resent, because the server has it and a resent body could differ
// from the stored one. So the only secret crossing the wire is the salt, and it is dropped
// after the check.

router.post('/policy/commitment', rateLimited('fitv4_policy', 20), (req, res) => {
  const { card_id, commitment, salt, public_key, nonce, signature } = req.body ?? {}
  if (typeof card_id !== 'string' || typeof commitment !== 'string' || typeof nonce !== 'string') {
    res.status(400).json({ error: 'card_id, commitment, salt, nonce required' }); return
  }
  // The commitment is inside the preimage, so a proxy cannot register a different one.
  if (!checkSig(`register-policy-commitment:${card_id}:${commitment}:${nonce}`, signature, public_key)) {
    res.status(403).json({ error: 'signature does not verify' }); return
  }
  if (!ownsCard(card_id, public_key)) { res.status(403).json({ error: 'not the card subject' }); return }

  const result = registerPolicyCommitment({ cardId: card_id, subjectKey: public_key, commitment, salt })
  if (result.ok !== true) {
    const r = result as { code: string; error: string }
    res.status(400).json({ code: r.code, error: r.error }); return
  }
  const okResult = result as { ok: true; row: { policy_hash: string; version: number }; already: boolean }
  res.status(okResult.already ? 200 : 201).json({
    card_id, commitment, version: okResult.row.version, already_registered: okResult.already,
    note: 'The salt is not stored. Keep it: it is what lets you open this commitment later.',
  })
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

// ══════════════════════════════════════════════════════════════
// The canonical lane for the five fit actions
// ══════════════════════════════════════════════════════════════
// Each of the five gains a canonical branch ahead of its legacy branch, on the path it
// already has, dispatched on the presence of an `envelope` key.
//
// DOUBLE GATE. These routes sit behind MINGLE_FIT_ENABLED as well as behind the new
// pipeline, and that flag is unset in production. So this is code that does not run in
// production, and its tests set the flag explicitly. The legacy fit adapters are in
// practice a compatibility window for a surface that is off.
//
// Three repairs land here, each already justified:
//   reciprocal_offer and query_budget become REQUIRED in a canonical payload, so the
//     defaulting at fit-v4-routes.ts:153-154 cannot run on that lane
//   fit_commit carries request_write_ref, so a commit names the request it answers
//   first_step_approve moves its digest comparison and its write into one transaction

const HEX64_RE = /^[0-9a-f]{64}$/

/** How a shared helper refuses, so the two lanes can answer in their own idiom. */
export type Refuse = (status: number, code: string, error: string) => never

class LegacyFitRefusal extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
    this.name = 'LegacyFitRefusal'
  }
}
const legacyRefuse: Refuse = (status, _code, error) => { throw new LegacyFitRefusal(status, error) }

/** A dimension list a principal signed: non empty, sorted by code unit, no duplicates.
 *  Sorting it here would be a repair after approval, so an unsorted list is refused. */
function gateDimensionList(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    refuseWrite(400, 'malformed_payload', `${field} must be a non empty array`)
  }
  const list = value as unknown[]
  if (!list.every(x => typeof x === 'string' && x.length > 0)) {
    refuseWrite(400, 'malformed_payload', `${field} must contain only non empty strings`)
  }
  const strings = list as string[]
  for (let i = 1; i < strings.length; i++) {
    if (strings[i - 1] === strings[i]) refuseWrite(400, 'malformed_payload', `${field} contains a duplicate`)
    if (strings[i - 1] > strings[i]) refuseWrite(400, 'malformed_payload', `${field} must be sorted by code unit`)
  }
  return strings
}

function gateHex64(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64_RE.test(value)) {
    refuseWrite(400, 'malformed_payload', `${field} must be 64 lowercase hex characters`)
  }
  return value as string
}

/** Exactly these keys, plus optionally these. A field inside payload_digest that the
 *  server ignores is a field the signature says the principal asked for and the server
 *  did not honour, so an unknown one is refused rather than dropped. */
function gatePayloadKeys(payload: Record<string, unknown>, required: string[], optional: string[] = []): void {
  const present = Object.keys(payload)
  for (const k of required) {
    if (!present.includes(k)) refuseWrite(400, 'malformed_payload', `payload is missing ${k}`)
  }
  const allowed = new Set([...required, ...optional])
  const extra = present.filter(k => !allowed.has(k))
  if (extra.length > 0) refuseWrite(400, 'malformed_payload', `unexpected payload field: ${extra.join(', ')}`)
}

/** The actor's card and policy, resolved THROUGH the signed commitment rather than
 *  through a policy_hash the client sent in the clear.
 *
 *  An unregistered commitment resolves to nothing and is refused. That is what makes
 *  policy_commitment a check rather than an opaque string copied into a receipt. */
function resolvePolicy(hs: handshakeDb.HandshakeRow, actorKey: string, commitment: string): {
  card: string
  policyHash: string
  policy: policyDb.FitPolicy
} {
  const card = cardOfKey(hs, actorKey)
  if (!card) refuseWrite(403, 'not_a_party', 'not a party to this handshake')
  const resolved = policyHashForCommitment(card as string, commitment)
  if (resolved === null) {
    refuseWrite(400, 'policy_commitment_unknown',
      'this policy commitment was never registered for your card, so the server cannot resolve it')
  }
  if (!commitmentIsCurrent(card as string, commitment)) {
    refuseWrite(400, 'policy_commitment_stale',
      'this commitment names an older policy version; register a commitment to your current policy')
  }
  const policy = policyDb.getPolicyByHash(card as string, resolved as string)
  if (policy === null) refuseWrite(400, 'policy_commitment_unknown', 'the committed policy version is no longer retained')
  return { card: card as string, policyHash: resolved as string, policy: policy as policyDb.FitPolicy }
}

/** The actor's policy as the HANDSHAKE committed it, resolved through the signed commitment.
 *
 *  For an act that discloses a value the handshake already evaluated, the current policy is
 *  the wrong version to authorize against: the disclosure decisions were made against the
 *  committed one, and a read surface serves the committed one. */
function resolvePolicyAtCommit(hs: handshakeDb.HandshakeRow, actorKey: string, commitment: string): {
  card: string
  policyHash: string
  policy: policyDb.FitPolicy
} {
  const card = cardOfKey(hs, actorKey)
  if (!card) refuseWrite(403, 'not_a_party', 'not a party to this handshake')
  const committed = actorKey === hs.requester_key ? hs.req_policy_hash : hs.com_policy_hash
  if (!committed) {
    refuseWrite(409, 'handshake_wrong_state', 'this handshake has no committed policy version for you')
  }
  const resolved = policyHashForCommitment(card as string, commitment)
  if (resolved === null) {
    refuseWrite(400, 'policy_commitment_unknown',
      'this policy commitment was never registered for your card, so the server cannot resolve it')
  }
  if (resolved !== committed) {
    refuseWrite(409, 'policy_commitment_not_committed',
      'this commitment names a policy version other than the one this handshake was committed under, and the disclosure was authorized against that one')
  }
  const policy = policyDb.getPolicyByHash(card as string, committed as string)
  if (policy === null) refuseWrite(400, 'policy_commitment_unknown', 'the committed policy version is no longer retained')
  return { card: card as string, policyHash: committed as string, policy: policy as policyDb.FitPolicy }
}

/** Every canonical fit act shares these: the intro accepts a continuation in its current
 *  state, the handshake exists, and the actor is a party to both. */
function fitPreamble(ctx: CanonicalContext, wantHandshakeState: handshakeDb.HandshakeRow['state'] | null): {
  hs: handshakeDb.HandshakeRow
  introId: string
  actorKey: string
} {
  const introId = ctx.write.envelope.resource.id
  const actorKey = ctx.write.envelope.actor_key
  const facts = factsForWrite(introId)
  requireParty(facts, actorKey, 'either', 'only a party to this introduction may act on it')
  guardState(ctx.write.envelope.operation, facts, ctx.now)

  const hs = handshakeDb.getHandshake(introId)
  if (!hs) refuseWrite(404, 'no_handshake', 'no handshake for this intro')
  const row = hs as handshakeDb.HandshakeRow
  if (!isParty(row, actorKey)) refuseWrite(403, 'not_a_party', 'not a party to this handshake')
  if (wantHandshakeState !== null && row.state !== wantHandshakeState) {
    refuseWrite(409, 'handshake_wrong_state', `handshake is ${row.state}, not ${wantHandshakeState}`)
  }
  return { hs: row, introId, actorKey }
}

export interface EvaluationResult {
  overlapMap: OverlapEntry[]
  receipt: string
  receiptDigest: string
  receiptContent: Record<string, unknown>
}

/** The evaluation, the activity ledger and the receipt, shared by both lanes.
 *
 *  Extracted rather than duplicated. Two copies of a predicate evaluation would be two
 *  places for the disclosure rules to drift, and the drift would show as one lane
 *  disclosing more than the other. Only the refusal mechanism differs, and each lane
 *  supplies its own. */
function evaluateAndReceipt(args: {
  hs: handshakeDb.HandshakeRow
  actorKey: string
  introId: string
  committerCard: string
  comPolicyHash: string
  accept: string[]
  comReciprocal: string[]
  autonomous: boolean
  /** Which lane this commit arrived on. The commit's own evidence row does not exist yet
   *  when the receipt is rendered, so the bound field list is computed from the same
   *  function the recorder uses rather than read back from a row that is not there. */
  commitEvidenceKind: 'canonical' | 'legacy_unbound'
  refuse: Refuse
}): EvaluationResult {
  const { hs, actorKey, introId, committerCard, comPolicyHash, accept, comReciprocal, autonomous, refuse } = args
  const requestEvidence = boundFieldsOfAuthorization(introId, hs.requester_key!, 'fit_request')
  const commitEvidence = boundFieldsFor('fit_commit', args.commitEvidenceKind)
  const requesterCard = cardOfKey(hs, hs.requester_key!)!
  const policyReq = dimMapFor(requesterCard, hs.req_policy_hash!, hs.intent)
  const policyCom = dimMapFor(committerCard, comPolicyHash, hs.intent)
  const requested: string[] = JSON.parse(hs.requested_json || '[]')
  const reqReciprocal: string[] = JSON.parse(hs.req_reciprocal_json || '[]')

  const dims = selectEvaluableDimensions(requested, accept, reqReciprocal, comReciprocal, policyReq, policyCom)

  // Anti-narrowing: consume budget per (principal pair, dimension). A dimension over its
  // lifetime cap is refused, not re-evaluated.
  const pairKey = handshakeDb.principalPairKey(hs.key_a, hs.key_b)
  const budgetBlocked = new Set<string>()
  for (const dim of dims) {
    if (!handshakeDb.budgetConsume(pairKey, dim).allowed) budgetBlocked.add(dim)
  }

  // Graduated autonomy: when the committer commits under a standing scope with no fresh
  // human tap, every disclosed dimension must fall within the scope's tier. Anything
  // above it, or high-sensitivity, or exact, is refused and must be committed by a human.
  if (autonomous) {
    for (const dim of dims) {
      const a = policyReq.get(dim), b = policyCom.get(dim)
      if (!a || !b || budgetBlocked.has(dim)) continue
      const eff = levelName(a, b) as any
      if (!autonomyDb.autonomyPermitsDisclosure(committerCard, hs.intent, dim, eff, b.sensitivity)) {
        refuse(403, 'outside_autonomy_scope',
          `dimension "${dim}" is outside your autonomy scope (or too sensitive, or exact); commit it without autonomous:true so the principal approves it`)
      }
    }
  }

  const facts = evaluateHandshake(dims, policyReq, policyCom, budgetBlocked)
  const compl = complementarityEntry(dims, policyReq, policyCom)
  const overlapMap = compl ? [...facts, compl] : facts

  // Legible activity: record what the committer's agent disclosed, so a truthful
  // "while you were away" summary can be shown later.
  autonomyDb.recordActivity(actorKey, introId, 'evaluated', null, otherKey(hs, actorKey), autonomous)
  for (const e of overlapMap) {
    if (e.dimension === 'complementarity') continue
    if (e.result === 'overlap') autonomyDb.recordActivity(actorKey, introId, 'overlap_disclosed', e.dimension, otherKey(hs, actorKey), autonomous)
    else if (e.result === 'bucket' || e.result === 'exact_available') autonomyDb.recordActivity(actorKey, introId, 'bucket_disclosed', e.dimension, otherKey(hs, actorKey), autonomous)
  }

  // ── The receipt, reshaped ──
  //
  // TWO POLICY HASHES LEAVE. policyHash at fit-policy-db.ts:96-101 is an unsalted SHA-256
  // over the normalized dimension set, and that set includes the private `value` of every
  // dimension. The domains are small enough to enumerate offline: the widest dimension enum
  // is 7 values, disclosure_state 5, sensitivity 3, importance 4, allowed_intents draws from
  // 5, the tag sets from 16, and weekly_commitment is a pair of integers in 0 to 168. The
  // only high entropy field is expires_at. So anyone holding a policy hash who can bound
  // expires_at recovers the whole private dimension set, and today those hashes are returned
  // to both parties and stored. The salted commitments replace them, and the deterministic
  // hash stays internal for version lookup.
  //
  // A commitment is resolved back from (card, policy_hash), because the handshake stores the
  // hash and no column can be added to it at this revision. An owner who never registered a
  // commitment has none to name, and the field is then null rather than silently falling
  // back to the hash: a receipt that degrades to the enumerable value on a missing
  // registration would be the whole problem again.
  const commitmentA = commitmentForPolicyHash(requesterCard, hs.req_policy_hash!)
  const commitmentB = commitmentForPolicyHash(committerCard, comPolicyHash)

  const disclosures = dims.filter(dd => policyReq.get(dd) && policyCom.get(dd))
    .map(dd => ({ dimension: dd, level: levelName(policyReq.get(dd)!, policyCom.get(dd)!) }))

  // `proves` is no longer a hand written sentence. It is rendered from the two evidence
  // rows, so a clause appears only when the field it names is inside that row's
  // bound_fields_json. Four of today's six content clauses are warranted by nothing, and
  // this is what stops a seventh being added by someone editing a string.
  const rendered = renderFitHandshake({
    request: requestEvidence, commit: commitEvidence, standingScope: autonomous,
  })
  // The keys are OMITTED when there is no registered commitment, never set to null. The APS
  // canonicalize deletes null-valued members, so a null would be dropped from the digest and
  // a receipt carrying `policy_commitment_a: null` would digest identically to one with the
  // key absent. Omitting says the same thing and says it in the bytes.
  const commitmentFields: Record<string, string> = {}
  if (commitmentA !== null) commitmentFields.policy_commitment_a = commitmentA
  if (commitmentB !== null) commitmentFields.policy_commitment_b = commitmentB

  const receiptContent = {
    intro_id: introId, purpose: hs.intent, predicate_version: PREDICATE_VERSION,
    ...commitmentFields,
    requested_predicates: dims,
    disclosures,
    outcome: overlapMap.map((e: OverlapEntry) => ({ dimension: e.dimension, result: e.result })),
    expiry: hs.expires_at,
    proves: rendered.sentences.join(' '),
    warrants: { request: warrantList(requestEvidence), commit: warrantList(commitEvidence) },
  }
  const receiptDigest = createHash('sha256').update(canonicalize(receiptContent), 'utf8').digest('hex')
  return { overlapMap, receipt: signReceipt(receiptDigest), receiptDigest, receiptContent }
}

// ── fit_request, canonical ────────────────────────────────────────────────

const canonicalFitRequest = canonicalWriteRoute({
  operations: ['fit_request'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    gatePayloadKeys(write.payload,
      ['requested_dimensions', 'reciprocal_offer', 'predicate_version', 'policy_commitment', 'query_budget'])

    const requested = gateDimensionList(write.payload.requested_dimensions, 'requested_dimensions')
    // NOT defaulted. fit-v4-routes.ts:153 falls back to requested_dimensions AFTER
    // verification and :154 coerces, floors and clamps the budget, so both end up inside a
    // receipt as fields no principal signed.
    const reciprocal = gateDimensionList(write.payload.reciprocal_offer, 'reciprocal_offer')
    const commitment = gateHex64(write.payload.policy_commitment, 'policy_commitment')
    if (write.payload.predicate_version !== PREDICATE_VERSION) {
      refuseWrite(400, 'malformed_payload', `predicate_version must be ${PREDICATE_VERSION}`)
    }
    const budget = write.payload.query_budget
    if (typeof budget !== 'number' || !Number.isInteger(budget) || budget < 1 || budget > MAX_QUERY_BUDGET) {
      refuseWrite(400, 'malformed_payload', `query_budget must be an integer from 1 to ${MAX_QUERY_BUDGET}`)
    }

    // A GAP IN THE CANONICAL LANE, closed here. Today the handshake is opened as a side
    // effect of the legacy accept at intros-routes.ts:120, and canonical express_interest
    // deliberately does none of that: it writes one authorization and a timestamp, as
    // decided. So on the canonical lane nothing would ever open a handshake and fit_request
    // would answer no_handshake forever.
    //
    // Opening it here rather than widening express_interest keeps express_interest minimal
    // as decided, and it matches what section 14.1 already says: the first fit action is
    // what moves the pair to connecting. The predicate is unchanged, so a pair that could
    // not open a handshake through the legacy accept cannot open one through this either.
    const introIdEarly = write.envelope.resource.id
    if (!handshakeDb.existsHandshakeForIntro(introIdEarly)) {
      const row = introsDb.getIntro(introIdEarly)
      if (row === null) refuseWrite(404, 'intro_not_found', 'no such introduction')
      if (openV4HandshakeForIntro(row as IntroRow) === null) {
        refuseWrite(409, 'no_handshake_possible',
          'a fit handshake needs both cards to carry a Fit Policy for this intro\'s intent')
      }
    }

    const { hs, introId, actorKey } = fitPreamble(ctx, 'open')
    const resolved = resolvePolicy(hs, actorKey, commitment)
    const permitted = new Set(policyDb.dimensionsForIntent(resolved.policy, hs.intent).map(x => x.dimension))
    for (const dim of requested) {
      if (!permitted.has(dim)) {
        refuseWrite(400, 'dimension_not_in_policy', `dimension "${dim}" is not in your policy for intent ${hs.intent}`)
      }
    }

    handshakeDb.setRequest(introId, actorKey, requested, reciprocal, resolved.policyHash, budget as number)
    const evidenceId = recordCanonicalEvidence(write)
    recordAuthorization({ introId, actorKey, operation: 'fit_request', evidenceId, evidence: 'canonical' })
    recordCardEvent('handshake_requested', resolved.card, actorKey,
      { intro_id: introId, intent: hs.intent, dimensions: requested.length, canonical: true })
    const state = materializeStatus(introId, now)
    return {
      intro_id: introId, state, handshake_state: 'requested',
      requested_dimensions: requested, reciprocal_offer: reciprocal, query_budget: budget,
      note: 'Nothing is evaluated until the counterparty commits to the same dimensions with matching reciprocity.',
    }
  },
})

// ── fit_commit, canonical ─────────────────────────────────────────────────

const canonicalFitCommit = canonicalWriteRoute({
  operations: ['fit_commit'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    gatePayloadKeys(write.payload,
      ['accept_dimensions', 'reciprocal_offer', 'policy_commitment', 'request_write_ref'],
      ['standing_scope_commitment'])
    const accept = gateDimensionList(write.payload.accept_dimensions, 'accept_dimensions')
    const comReciprocal = gateDimensionList(write.payload.reciprocal_offer, 'reciprocal_offer')
    const commitment = gateHex64(write.payload.policy_commitment, 'policy_commitment')
    const requestRef = gateHex64(write.payload.request_write_ref, 'request_write_ref')

    const { hs, introId, actorKey } = fitPreamble(ctx, 'requested')
    // The role check, which is what makes this action's actor distinct from fit_request's.
    if (actorKey === hs.requester_key) {
      refuseWrite(403, 'requester_cannot_commit', 'the requester cannot also commit; the counterparty commits')
    }
    if (Date.parse(hs.expires_at) <= now.getTime()) {
      refuseWrite(409, 'handshake_expired', 'handshake window expired')
    }

    // request_write_ref names the exact fit_request envelope this commit answers, so a
    // commit cannot be applied to a different request than the one the principal saw.
    // Today nothing ties the two acts together beyond the intro id and the stored state.
    const answeredRef = writeRefOfAuthorization(introId, hs.requester_key!, 'fit_request')
    if (answeredRef === null) {
      refuseWrite(409, 'request_not_canonical',
        'the request on this handshake was not canonically signed, so there is no write_ref to answer')
    }
    if (answeredRef !== requestRef) {
      refuseWrite(409, 'request_write_ref_mismatch', 'request_write_ref does not name the request on this handshake')
    }

    const resolved = resolvePolicy(hs, actorKey, commitment)
    const comPermitted = new Set(policyDb.dimensionsForIntent(resolved.policy, hs.intent).map(x => x.dimension))
    for (const dim of accept) {
      if (!comPermitted.has(dim)) {
        refuseWrite(400, 'dimension_not_in_policy', `dimension "${dim}" is not in your policy for intent ${hs.intent}`)
      }
    }

    // A SIGNED scope reference, not an unsigned boolean. Today `autonomous` is a body field
    // the server reads and it alone decides whether the graduated checks run, and no
    // published client even sends it. Here the field is inside payload_digest and it must
    // name a scope the principal actually signed.
    const scopeCommitment = write.payload.standing_scope_commitment
    let autonomous = false
    if (scopeCommitment !== undefined) {
      const named = gateHex64(scopeCommitment, 'standing_scope_commitment')
      const scope = autonomyDb.getScope(resolved.card)
      if (scope === null || scope.scope_hash !== named) {
        refuseWrite(400, 'standing_scope_unknown',
          'standing_scope_commitment does not name a standing scope registered for your card')
      }
      const stored = scope as autonomyDb.StoredScope
      if (stored.paused) {
        refuseWrite(403, 'autonomy_paused', 'autonomous commits are paused for this card')
      }
      // The scope's OWN applicability, checked here rather than only inside the per-dimension
      // loop. That loop is skipped entirely when nothing is mutually evaluable or when every
      // dimension is budget-blocked, and the receipt would then carry "authorized under
      // standing scope S" for a scope that had expired years ago or was registered for a
      // different intent. A clause about how an act was authorized must not rest on a check
      // that a particular input shape skips.
      if (Date.parse(stored.scope.expiry) <= now.getTime()) {
        refuseWrite(403, 'standing_scope_expired', 'that standing scope has expired, so this act needs individual approval')
      }
      if (!stored.scope.intents.includes(hs.intent)) {
        refuseWrite(403, 'standing_scope_wrong_intent',
          `that standing scope does not cover the intent ${hs.intent}, so this act needs individual approval`)
      }
      autonomous = true
    }

    const evaluated = evaluateAndReceipt({
      hs, actorKey, introId, committerCard: resolved.card, comPolicyHash: resolved.policyHash,
      accept, comReciprocal, autonomous, commitEvidenceKind: 'canonical', refuse: refuseWrite,
    })
    handshakeDb.setCommitResult(introId, actorKey, accept, comReciprocal, resolved.policyHash,
      JSON.stringify(evaluated.overlapMap), evaluated.receipt, evaluated.receiptDigest,
      JSON.stringify(evaluated.receiptContent))
    const evidenceId = recordCanonicalEvidence(write)
    recordAuthorization({ introId, actorKey, operation: 'fit_commit', evidenceId, evidence: 'canonical' })
    recordCardEvent('handshake_committed', resolved.card, actorKey,
      { intro_id: introId, intent: hs.intent, dimensions: accept.length, receipt_digest: evaluated.receiptDigest, canonical: true })
    const state = materializeStatus(introId, now)
    return {
      intro_id: introId, state, handshake_state: 'committed',
      overlap_map: evaluated.overlapMap, receipt: evaluated.receipt,
      receipt_digest: evaluated.receiptDigest, receipt_content: evaluated.receiptContent,
      server_public_key: serverPublicKey(),
      authorized_under_standing_scope: autonomous,
    }
  },
})

// ── release_exact, canonical ──────────────────────────────────────────────

const canonicalReleaseExact = canonicalWriteRoute({
  operations: ['release_exact'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    gatePayloadKeys(write.payload, ['dimension', 'policy_commitment', 'private_value_commitment'])
    const dimension = write.payload.dimension
    if (typeof dimension !== 'string' || dimension.length === 0) {
      refuseWrite(400, 'malformed_payload', 'dimension must be a non empty string')
    }
    const commitment = gateHex64(write.payload.policy_commitment, 'policy_commitment')
    gateHex64(write.payload.private_value_commitment, 'private_value_commitment')
    const dim = dimension as string

    const { hs, introId, actorKey } = fitPreamble(ctx, 'committed')
    // THE COMMIT-TIME VERSION, not the current one. resolvePolicy pins to whatever policy is
    // in force now, and GET /:introId discloses the value from hs.req_policy_hash or
    // hs.com_policy_hash, the version the handshake was EVALUATED under. Pinning the two
    // halves to different versions meant the value disclosed was not the value the signature
    // named: an owner could edit a dimension from testable to reveal_exact after a commit
    // that had authorized no disclosure of it, sign a release of the new value, and have the
    // counterparty handed the old one. The handshake's disclosure decisions were made against
    // the committed versions, so the authorization has to be too.
    const resolved = resolvePolicyAtCommit(hs, actorKey, commitment)

    // CHECK ONE already ran, in step 7 of the pipeline: the opening recomputed to
    // private_value_commitment. So by here the value is the value the principal committed
    // to, and the remaining question is whether the policy permits releasing it.
    //
    // CHECK TWO, and the direction is the point. The signed commitment is the
    // AUTHORIZATION and the stored policy is the PERMISSION, so a mismatch is an error and
    // never a substitution. Today the value is pinned instead: dimMapFor at
    // fit-v4-routes.ts:304 returns whatever the stored policy holds at the moment the
    // request lands, so a policy edited between commit and reveal changes what the same
    // signature releases.
    const own = new Map(policyDb.dimensionsForIntent(resolved.policy, hs.intent).map(x => [x.dimension, x]))
      .get(dim)
    if (!own || own.disclosure_state !== 'reveal_exact') {
      refuseWrite(403, 'dimension_not_releasable', 'this dimension is not authorized for exact release by you')
    }
    const opened = write.opening!.value
    if (jcs(opened) !== jcs((own as policyDb.PolicyDimension).value)) {
      refuseWrite(409, 'value_not_in_policy',
        'the value you signed is not the value your stored policy holds for this dimension; re-read your policy and re-approve')
    }

    const added = handshakeDb.releaseExact(introId, dim, actorKey)
    if (added) autonomyDb.recordActivity(actorKey, introId, 'exact_released', dim, otherKey(hs, actorKey), false)
    const evidenceId = recordCanonicalEvidence(write)
    // `subject` carries the dimension, which is why that column exists: one actor can hold
    // many live release_exact authorizations on one intro and exactly one share_contact.
    recordAuthorization({ introId, actorKey, operation: 'release_exact', subject: dim, evidenceId, evidence: 'canonical' })
    writeArtifact({ write, introId, recipientKey: otherKey(hs, actorKey), subject: dim })
    const state = materializeStatus(introId, now)
    // Release is one way. There is no withdraw_release and there must not be, by the same
    // decision that governs contacts.
    return { intro_id: introId, state, revealed: dim, added }
  },
})

// ── first_step_propose, canonical ─────────────────────────────────────────

const canonicalFirstStepPropose = canonicalWriteRoute({
  operations: ['first_step_propose'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    // The payload IS the half, field for field, in the shape validateHalf accepts. So
    // payload_digest covers every text field and the expiry, where today the preimage is
    // fit-firststep:${introId}:${nonce} and the entire half is unbound.
    //
    // The key gate runs FIRST, because validateHalf copies seven known keys into a fresh
    // object and ignores the rest. Without this, an eighth field would be covered by
    // payload_digest, accepted with a 201, and silently dropped, so the counterparty would
    // approve a merged digest from which the principal's signed clause had vanished. That is
    // exactly the case gatePayloadKeys exists to refuse everywhere else.
    gatePayloadKeys(write.payload,
      ['purpose', 'next_action', 'meeting_length', 'agenda', 'each_wants', 'boundaries', 'expiry'])
    const v = firstStepDb.validateHalf(write.payload)
    if (!v.ok || !v.half) refuseWrite(400, 'malformed_half', v.error ?? 'invalid half')
    const gate = postGateDrafted((v.texts ?? []).map((t, i) => ({ question_id: String(i), text: t })))
    if (!gate.ok) refuseWrite(400, 'content_refused', `first-step content refused: ${gate.reason}`)
    // The URL strip is computed at fit-v4-routes.ts:525 and then DISCARDED, so URLs survive
    // there where the sibling answers route strips them. On this lane a half whose text
    // changes under stripUrls is refused rather than quietly kept, because the client
    // showed and signed these exact bytes.
    for (const t of v.texts ?? []) {
      if (introsDb.containsUrl(t)) {
        refuseWrite(400, 'half_contains_link', 'a First Step half may not contain a link, and Mingle does not rewrite one for you')
      }
    }

    const { hs, introId, actorKey } = fitPreamble(ctx, null)
    // proposeHalf resets both approvals whenever either half changes, which is the right
    // behavior and is kept.
    firstStepDb.proposeHalf(introId, actorKey === hs.key_a, actorKey, v.half)
    const evidenceId = recordCanonicalEvidence(write)
    recordAuthorization({ introId, actorKey, operation: 'first_step_propose', evidenceId, evidence: 'canonical' })
    recordCardEvent('first_step_proposed', cardOfKey(hs, actorKey), actorKey, { intro_id: introId, canonical: true })
    const row = firstStepDb.getFirstStep(introId)!
    const state = materializeStatus(introId, now)
    return {
      intro_id: introId, state, proposed: true,
      both_proposed: !!row.half_a_json && !!row.half_b_json,
      shared_digest: firstStepDb.sharedDigest(row),
    }
  },
  afterCommit: async ctx => {
    const introId = ctx.write.envelope.resource.id
    const hs = handshakeDb.getHandshake(introId)
    if (!hs) return
    await email.notifyFirstStepProposed(otherKey(hs, ctx.write.envelope.actor_key), introId)
  },
})

// ── first_step_approve, canonical ─────────────────────────────────────────

const canonicalFirstStepApprove = canonicalWriteRoute({
  operations: ['first_step_approve'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    gatePayloadKeys(write.payload, ['approved_digest'])
    const approvedDigest = gateHex64(write.payload.approved_digest, 'approved_digest')

    const { hs, introId, actorKey } = fitPreamble(ctx, null)
    // The read, the compare and the write are all inside this transaction. Lines 550 to 553
    // of the legacy branch read the digest, compare, then write with no transaction and no
    // await between them. That is safe today only because Node is single threaded and
    // better-sqlite3 is synchronous, so nothing interleaves inside one process. It stops
    // being safe the moment two processes share the database file.
    const row = firstStepDb.getFirstStep(introId)
    if (!row || !row.half_a_json || !row.half_b_json) {
      refuseWrite(409, 'halves_incomplete', 'both sides must propose a half before either can approve the shared artifact')
    }
    const digest = firstStepDb.sharedDigest(row!)
    if (digest !== approvedDigest) {
      refuseWrite(409, 'digest_changed',
        'approved_digest does not match the current shared artifact; re-read and re-approve')
    }
    firstStepDb.approve(introId, actorKey === hs.key_a)
    const fresh = firstStepDb.getFirstStep(introId)!
    const finalized = firstStepDb.isFinalized(fresh)
    const evidenceId = recordCanonicalEvidence(write)
    recordAuthorization({ introId, actorKey, operation: 'first_step_approve', evidenceId, evidence: 'canonical' })
    recordCardEvent('first_step_approved', cardOfKey(hs, actorKey), actorKey,
      { intro_id: introId, approved_digest: approvedDigest, finalized, canonical: true })
    const state = materializeStatus(introId, now)
    return { intro_id: introId, state, approved: true, finalized }
  },
})

// ── POST /:introId/request - the signed Fit Request Manifest ──────────────

router.post('/:introId/request', fitGate, canonicalDispatch(canonicalFitRequest), rateLimited('fitv4_hs', 30), (req, res) => {
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
  const legacyGate = checkLegacyWrite({ resourceType: 'intro', resourceId: introId, actorKey: public_key, introId })
  if (legacyGate !== null) { refuseLegacy(res, 'fit_request', introId, legacyGate); return }

  // Today's defaulting, unchanged: the reciprocal offer falls back to
  // requested_dimensions after verification and the budget is coerced, floored and clamped.
  // Both are fields no principal signed, which is exactly what bound_fields_json records
  // by naming only intro_id.
  const reciprocal = Array.isArray(reciprocal_offer) ? reciprocal_offer : requested_dimensions
  const budget = Math.min(Math.max(1, Number(query_budget) || 3), MAX_QUERY_BUDGET)
  getDb().transaction(() => {
    handshakeDb.setRequest(introId, public_key, requested_dimensions, reciprocal, policy_hash, budget)
    const evidenceId = recordLegacyEvidence({
      actorKey: public_key, operation: 'fit_request', resourceType: 'intro', resourceId: introId, signature,
    })
    recordAuthorization({ introId, actorKey: public_key, operation: 'fit_request', evidenceId, evidence: 'legacy_unbound' })
    recordAuthMode('intro', introId, public_key, 'legacy_unbound')
  })()
  // Outside the transaction, for the reason card-events.ts documents: it swallows its own
  // failures and it reaches a lazy CREATE TABLE on the first call in a process.
  recordCardEvent('handshake_requested', card, public_key, { intro_id: introId, intent: hs.intent, dimensions: requested_dimensions.length })
  res.status(201).json({ state: 'requested', requested_dimensions, note: 'Nothing is evaluated until the counterparty commits to the same dimensions with matching reciprocity.' })
})

// ── POST /:introId/commit - reciprocity gate; evaluate on mutual commit ───

router.post('/:introId/commit', fitGate, canonicalDispatch(canonicalFitCommit), rateLimited('fitv4_hs', 30), (req, res) => {
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

  const comReciprocal: string[] = Array.isArray(reciprocal_offer) ? reciprocal_offer : accept_dimensions

  // The cutoff and anti-downgrade, after every authorization check so an unauthorized
  // caller learns nothing about either.
  const gate = checkLegacyWrite({ resourceType: 'intro', resourceId: introId, actorKey: public_key, introId })
  if (gate !== null) { refuseLegacy(res, 'fit_commit', introId, gate); return }

  // The evaluation, the activity ledger and the receipt now come from one shared
  // function, called with exactly what this branch computed before: the reciprocal
  // fallback to accept_dimensions, and the unsigned `autonomous` boolean. So this lane's
  // behavior is unchanged, and the two lanes cannot drift on the disclosure rules.
  let evaluated: EvaluationResult
  try {
    evaluated = evaluateAndReceipt({
      hs, actorKey: public_key, introId, committerCard, comPolicyHash: policy_hash,
      accept: accept_dimensions, comReciprocal, autonomous: req.body?.autonomous === true,
      commitEvidenceKind: 'legacy_unbound', refuse: legacyRefuse,
    })
  } catch (e) {
    if (e instanceof LegacyFitRefusal) { res.status(e.status).json({ error: e.message }); return }
    throw e
  }

  getDb().transaction(() => {
    handshakeDb.setCommitResult(introId, public_key, accept_dimensions, comReciprocal, policy_hash,
      JSON.stringify(evaluated.overlapMap), evaluated.receipt, evaluated.receiptDigest,
      JSON.stringify(evaluated.receiptContent))
    const evidenceId = recordLegacyEvidence({
      actorKey: public_key, operation: 'fit_commit', resourceType: 'intro', resourceId: introId, signature,
    })
    // bound_fields_json is ["intro_id"] and nothing else. The preimage is
    // fit-commit:${introId}:${nonce}, so the dimensions, the reciprocal offer and the
    // policy hash are all unbound, and no receipt may name them as authorized content.
    // Whether the act was autonomous is established by nothing at all on this lane.
    recordAuthorization({ introId, actorKey: public_key, operation: 'fit_commit', evidenceId, evidence: 'legacy_unbound' })
    recordAuthMode('intro', introId, public_key, 'legacy_unbound')
  })()
  recordCardEvent('handshake_committed', committerCard, public_key,
    { intro_id: introId, intent: hs.intent, dimensions: accept_dimensions.length, receipt_digest: evaluated.receiptDigest })
  res.json({
    state: 'committed', overlap_map: evaluated.overlapMap, receipt: evaluated.receipt,
    receipt_digest: evaluated.receiptDigest, receipt_content: evaluated.receiptContent,
    server_public_key: serverPublicKey(),
  })
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

  // Merge human-tap-released exact values into the map for the two parties.
  // Each side's value appears only once that side has released it. Exposure
  // follows the roles (requester_key, committer_key), never the order of the
  // stored release set, so a first release by the committer never shows the
  // requester's value.
  const released = handshakeDb.parseReleased(hs.released_exacts_json)
  const map = JSON.parse(hs.result_json) as OverlapEntry[]
  const requesterCard = cardOfKey(hs, hs.requester_key!)!
  const committerCard = cardOfKey(hs, hs.committer_key!)!
  const polReq = dimMapFor(requesterCard, hs.req_policy_hash!, hs.intent)
  const polCom = dimMapFor(committerCard, hs.com_policy_hash!, hs.intent)
  const withExacts = map.map(e => {
    const releasers = handshakeDb.releasersFor(released, e.dimension)
    const requesterReleased = !!hs.requester_key && releasers.includes(hs.requester_key)
    const committerReleased = !!hs.committer_key && releasers.includes(hs.committer_key)
    if (!requesterReleased && !committerReleased) return e
    return {
      ...e,
      ...(requesterReleased ? { exact_a: polReq.get(e.dimension)?.value } : {}),
      ...(committerReleased ? { exact_b: polCom.get(e.dimension)?.value } : {}),
    }
  })
  res.json({ ...base, overlap_map: withExacts, receipt: hs.receipt, receipt_digest: hs.receipt_digest, receipt_content: hs.receipt_content_json ? JSON.parse(hs.receipt_content_json) : undefined, server_public_key: serverPublicKey() })
})

// ── POST /:introId/reveal - human-tap exact release (state 5) ──────────────

router.post('/:introId/reveal', fitGate, canonicalDispatch(canonicalReleaseExact), rateLimited('fitv4_hs', 30), (req, res) => {
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

  const legacyGate = checkLegacyWrite({ resourceType: 'intro', resourceId: introId, actorKey: public_key, introId })
  if (legacyGate !== null) { refuseLegacy(res, 'release_exact', introId, legacyGate); return }

  // The release and its ledger row commit together or not at all, so a failed
  // ledger write never leaves a release the ledger does not show. Only the
  // caller's own release is recorded, and only the first time. A repeat tap
  // discloses nothing new.
  getDb().transaction(() => {
    if (handshakeDb.releaseExact(introId, dimension, public_key)) {
      autonomyDb.recordActivity(public_key, introId, 'exact_released', dimension, otherKey(hs, public_key), false)
    }
    const evidenceId = recordLegacyEvidence({
      actorKey: public_key, operation: 'release_exact', resourceType: 'intro', resourceId: introId, signature,
    })
    // The strongest of the five legacy fit preimages, because it binds the dimension:
    // fit-reveal:${introId}:${dimension}:${nonce}, so bound_fields_json is
    // ["intro_id","dimension"]. It still omits the value and the policy the value is read
    // from, so the value released is whichever one dimMapFor returns when the request
    // lands. No artifact is written, because a legacy act has no opening to write.
    recordAuthorization({ introId, actorKey: public_key, operation: 'release_exact', subject: dimension, evidenceId, evidence: 'legacy_unbound' })
    // Keyed on the intro and not the dimension, which is coarser than the action: an actor
    // who released one dimension canonically cannot release a second by the legacy route.
    // Stricter than necessary and the right direction, because the alternative is a per
    // dimension mode table that lets one actor hold two authorization strengths on one intro.
    recordAuthMode('intro', introId, public_key, 'legacy_unbound')
  })()
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

router.post('/:introId/questions', fitGate, rateLimited('fitv4_hs', 60), (req, res) => {
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

router.post('/:introId/answers', fitGate, rateLimited('fitv4_hs', 60), (req, res) => {
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

router.post('/:introId/round2', fitGate, rateLimited('fitv4_hs', 30), (req, res) => {
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

// ══════════════════════════════════════════════════════════════
// Stage 7: First Step artifact (mutual exact-approval)
// ══════════════════════════════════════════════════════════════

// ── POST /:introId/first-step - propose your own half ─────────────────────

router.post('/:introId/first-step', fitGate, canonicalDispatch(canonicalFirstStepPropose), rateLimited('fitv4_hs', 30), asyncRoute(async (req, res) => {
  const introId = String(req.params.introId)
  const { half, public_key, nonce, signature } = req.body ?? {}
  if (typeof nonce !== 'string') { res.status(400).json({ error: 'nonce required' }); return }
  if (!checkSig(`fit-firststep:${introId}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }

  const v = firstStepDb.validateHalf(half)
  if (!v.ok || !v.half) { res.status(400).json({ error: v.error }); return }
  const gate = postGateDrafted((v.texts ?? []).map((t, i) => ({ question_id: String(i), text: t })))
  if (!gate.ok) { res.status(400).json({ error: `first-step content refused: ${gate.reason}` }); return }

  const legacyGate = checkLegacyWrite({ resourceType: 'intro', resourceId: introId, actorKey: public_key, introId })
  if (legacyGate !== null) { refuseLegacy(res, 'first_step_propose', introId, legacyGate); return }

  const isA = public_key === hs.key_a
  getDb().transaction(() => {
    firstStepDb.proposeHalf(introId, isA, public_key, v.half!)
    const evidenceId = recordLegacyEvidence({
      actorKey: public_key, operation: 'first_step_propose', resourceType: 'intro', resourceId: introId, signature,
    })
    // bound_fields_json is ["intro_id"]. The preimage is fit-firststep:${introId}:${nonce},
    // so no receipt may name any field of the half. The discarded URL strip at :525 stays
    // discarded here, because tightening a legacy route gains no evidence.
    recordAuthorization({ introId, actorKey: public_key, operation: 'first_step_propose', evidenceId, evidence: 'legacy_unbound' })
    recordAuthMode('intro', introId, public_key, 'legacy_unbound')
  })()
  recordCardEvent('first_step_proposed', cardOfKey(hs, public_key), public_key, { intro_id: introId })
  try { await email.notifyFirstStepProposed(otherKey(hs, public_key), introId) } catch { /* email never blocks proposal */ }

  const row = firstStepDb.getFirstStep(introId)!
  res.status(201).json({ proposed: true, both_proposed: !!row.half_a_json && !!row.half_b_json, shared_digest: firstStepDb.sharedDigest(row) })
}))

// ── POST /:introId/first-step/approve - approve the merged shared artifact ─

router.post('/:introId/first-step/approve', fitGate, canonicalDispatch(canonicalFirstStepApprove), rateLimited('fitv4_hs', 30), (req, res) => {
  const introId = String(req.params.introId)
  const { approved_digest, public_key, nonce, signature } = req.body ?? {}
  if (typeof approved_digest !== 'string' || typeof nonce !== 'string') { res.status(400).json({ error: 'approved_digest and nonce required' }); return }
  if (!checkSig(`fit-firststep-approve:${introId}:${approved_digest}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }

  const legacyGate = checkLegacyWrite({ resourceType: 'intro', resourceId: introId, actorKey: public_key, introId })
  if (legacyGate !== null) { refuseLegacy(res, 'first_step_approve', introId, legacyGate); return }

  // The read, the compare and the write in one transaction, closing the same read compare
  // write race the canonical branch closes. Today lines 550 to 553 do all three with no
  // transaction between them, which is safe only while one process owns the database file.
  // The refusals keep their exact status codes and messages, so the response is unchanged.
  const outcome = getDb().transaction((): { status: number; body: Record<string, unknown> } => {
    const row = firstStepDb.getFirstStep(introId)
    if (!row || !row.half_a_json || !row.half_b_json) {
      return { status: 409, body: { error: 'both sides must propose a half before either can approve the shared artifact' } }
    }
    const digest = firstStepDb.sharedDigest(row)
    if (digest !== approved_digest) {
      return { status: 400, body: { error: 'approved_digest does not match the current shared artifact; re-read and re-approve' } }
    }
    firstStepDb.approve(introId, public_key === hs.key_a)
    const fresh = firstStepDb.getFirstStep(introId)!
    const finalized = firstStepDb.isFinalized(fresh)
    const evidenceId = recordLegacyEvidence({
      actorKey: public_key, operation: 'first_step_approve', resourceType: 'intro', resourceId: introId, signature,
    })
    // The one fit action whose legacy signature covers its whole semantic content:
    // fit-firststep-approve:${introId}:${digest}:${nonce} binds the digest, so
    // bound_fields_json is ["intro_id","approved_digest"] and this legacy evidence is as
    // strong as its canonical counterpart for the approval clause.
    recordAuthorization({ introId, actorKey: public_key, operation: 'first_step_approve', evidenceId, evidence: 'legacy_unbound' })
    recordAuthMode('intro', introId, public_key, 'legacy_unbound')
    recordCardEvent('first_step_approved', cardOfKey(hs, public_key), public_key, { intro_id: introId, approved_digest, finalized })
    return { status: 200, body: { approved: true, finalized } }
  })()
  res.status(outcome.status).json(outcome.body)
})

// ── GET /:introId/first-step (parties only) ───────────────────────────────

router.get('/:introId/first-step', rateLimited('fitv4_get', 60), (req, res) => {
  const introId = String(req.params.introId)
  const public_key = String(req.query.public_key ?? '')
  const nonce = String(req.query.nonce ?? '')
  const signature = String(req.query.signature ?? '')
  if (!public_key || !nonce) { res.status(400).json({ error: 'public_key and nonce required' }); return }
  if (!checkSig(`fit-firststep-get:${introId}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  const hs = handshakeDb.getHandshake(introId)
  if (!hs) { res.status(404).json({ error: 'no handshake for this intro' }); return }
  if (!isParty(hs, public_key)) { res.status(403).json({ error: 'not a party to this handshake' }); return }
  const row = firstStepDb.getFirstStep(introId)
  if (!row) { res.json({ intro_id: introId, proposed: false }); return }
  res.json({
    intro_id: introId,
    half_a: row.half_a_json ? JSON.parse(row.half_a_json) : null,
    half_b: row.half_b_json ? JSON.parse(row.half_b_json) : null,
    a_approved: row.a_approved === 1,
    b_approved: row.b_approved === 1,
    finalized: firstStepDb.isFinalized(row),
    shared_digest: firstStepDb.sharedDigest(row),
  })
})

export { verifyReceipt }
export default router
