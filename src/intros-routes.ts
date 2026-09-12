// ══════════════════════════════════════════════════════════════
// Mingle v3 introductions - routes (mounted at /api/v3/intros)
// ══════════════════════════════════════════════════════════════
// The essential loop: request, mutual accept, complete. Contacts are released
// only when the intro is complete (both sides supplied a contact line), and
// only to the two parties (in GET /mine and the acceptance email). No third
// party ever sees a contact. Every write is signed by the acting key.
//
// TWO LANES ON THREE OF THESE PATHS. A body carrying an `envelope` key is a canonical
// mingle-write-v1 write and goes to the canonical handler. A body without one is the
// published 3.2.x shape and goes to the legacy handler below, byte for byte as it
// behaved at 909ffe3. The dispatch is a shape check and not a header, so an old client
// needs no change to keep working.
//
// The legacy branch is deliberately NOT tightened. Its note is rewritten by stripUrls
// exactly as today, because the note is unbound by that signature either way, so
// refusing it would break a working client and gain no evidence. What the adapter adds
// is a record: one evidence row labelled legacy_unbound whose bound_fields_json names
// only what the old preimage covered, and the authorization rows that act implies.
//
// The legacy branch also never calls the materialization. It writes v3_intros.status
// directly, as today. A pre-2A intro has no authorization rows to derive from, so
// materializing there would answer `requested` for an intro its own column correctly
// calls accepted, and the grandfathered row must behave exactly as it did.

import { Router } from 'express'
import { randomBytes } from 'node:crypto'
import { verify } from 'agent-passport-system'
import { checkRateLimit, getDb } from './db.js'
import * as introsDb from './intros-db.js'
import * as v3db from './v3-db.js'
import { networkVisibleView } from './v3-cards.js'
import * as email from './notifications.js'
import { createFitExchangeForIntro } from './fit-routes.js'
import { openV4HandshakeForIntro } from './fit-v4-routes.js'
import { fitEnabled, FIT_DISABLED_TEXT } from './fit-gate.js'
import { recordCardEvent } from './card-events.js'
import { asyncRoute } from './async-route.js'
import { canonicalWriteRoute, canonicalDispatch, refuseWrite } from './write-pipeline.js'
import type { CanonicalContext } from './write-pipeline.js'
import { recordCanonicalEvidence, recordLegacyEvidence } from './write-evidence.js'
import { recordAuthMode, createMapRow, claimCreate } from './write-db.js'
import {
  recordAuthorization, materializeStatus, stateOf, authorizationOf,
  claimRelease, writeRefOfAuthorization, bridgePre2AIntro,
  introProjection, hasAuthorizations,
} from './connection-facts.js'
import { writeArtifact } from './private-artifacts.js'
import { factsForWrite, guardState, requireParty } from './intro-guards.js'
import { checkLegacyWrite, checkLegacyCreate, refuseLegacy } from './legacy-write-gate.js'

const router = Router()
const MAX_NOTE = 200
const MAX_CONTACT = 200

function rateLimited(action: string, limit: number) {
  return (req: any, res: any, next: any) => {
    if (!checkRateLimit(`intro:${req.ip || 'anon'}`, action, limit).allowed) { res.status(429).json({ error: 'Rate limit exceeded' }); return }
    next()
  }
}

function checkSig(payload: string, signature: unknown, key: unknown): boolean {
  if (typeof signature !== 'string' || typeof key !== 'string') return false
  try { return verify(payload, signature, key) } catch { return false }
}

/** Network-visible headline of a live card, or null if the card is not
 *  discoverable (headline not network-visible) or not active. */
function liveNetworkHeadline(cardId: string): { key: string; headline: string } | null {
  const stored = v3db.getV3Card(cardId)
  if (!stored) return null
  if (stored.revocation_status !== 'active') return null
  if (Date.parse(stored.expires_at) <= Date.now()) return null
  const view = networkVisibleView({ ...stored.card, card_id: cardId }) as any
  if (typeof view.headline !== 'string' || view.headline.length === 0) return null
  return { key: stored.card.subject_key, headline: view.headline }
}

// ── POST /request, the canonical lane ─────────────────────────────────────

/** request_id is minted by the client from a CSPRNG, 16 bytes as hex, and is signed.
 *  It is the create's second idempotency key. */
const REQUEST_ID_RE = /^[0-9a-f]{32}$/

/** Refuse rather than repair, which is invariant 4. The client produces the final note
 *  bytes, shows those bytes, then signs those bytes, so any repair here would store
 *  something the principal never approved.
 *
 *  Three of the four rules are already enforced by the payload gate before this runs:
 *  control characters U+0000 to U+001F and U+007F, and leading or trailing whitespace.
 *  This adds the two that need the note's own schema. */
function gateCanonicalNote(note: unknown): string {
  if (typeof note !== 'string') refuseWrite(400, 'malformed_payload', 'note must be a string')
  const n = note as string
  if (n.length > MAX_NOTE) refuseWrite(400, 'note_too_long', `note is longer than ${MAX_NOTE} characters`)
  // The existing detector at intros-db.ts:71 as a predicate. match-routes.ts:196 already
  // uses the same detector this way for a report reason, so the pattern is the repo's
  // own rather than a new invention.
  if (introsDb.containsUrl(n)) {
    refuseWrite(400, 'note_contains_link', 'a note may not contain a link, and Mingle does not rewrite one for you')
  }
  return n
}

const canonicalRequestIntro = canonicalWriteRoute({
  operations: ['request_intro'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    const requestId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key
    if (!REQUEST_ID_RE.test(requestId)) {
      refuseWrite(400, 'malformed_request_id', 'resource.id must be 16 CSPRNG bytes as 32 lowercase hex characters')
    }

    // The create's second idempotency key, checked first. Nonce idempotency covers a
    // byte identical retry, and a client whose request timed out mints a fresh nonce and
    // issued_at, so write_ref differs and the nonce store sees a new write. request_id
    // is what stops that producing a second intro, which is today's behavior: the id at
    // intros-routes.ts:75 carries a fresh Date.now() every time.
    const already = createMapRow(requestId)
    if (already !== null) {
      if (already.actor_key !== actorKey) {
        refuseWrite(409, 'request_id_taken', 'this request id was already used by a different key')
      }
      const row = introsDb.getIntro(already.created_id)
      return {
        intro_id: already.created_id, created: false,
        state: stateOf(already.created_id), purpose: row?.purpose ?? null, note: row?.note ?? null,
      }
    }

    // Payload shape. Exactly the four semantic fields, which is what today's destructure
    // at intros-routes.ts:53 names minus the transport fields.
    const keys = Object.keys(write.payload).sort().join(',')
    if (keys !== 'from_card,note,purpose,to_card') {
      refuseWrite(400, 'malformed_payload', 'request_intro payload carries exactly from_card, to_card, purpose and note')
    }
    const fromCard = write.payload.from_card
    const toCard = write.payload.to_card
    const purpose = write.payload.purpose
    if (typeof fromCard !== 'string' || typeof toCard !== 'string') {
      refuseWrite(400, 'malformed_payload', 'from_card and to_card must be strings')
    }
    if (!(introsDb.INTRO_PURPOSES as readonly unknown[]).includes(purpose)) {
      refuseWrite(400, 'unknown_purpose', `purpose must be one of ${introsDb.INTRO_PURPOSES.join(', ')}`)
    }
    if (fromCard === toCard) refuseWrite(400, 'malformed_payload', 'cannot request an intro to your own card')
    const note = gateCanonicalNote(write.payload.note)

    // The same authorization checks the legacy lane runs, in the same order, now INSIDE
    // the transaction. Today they are a read then write race: the guards at
    // intros-db.ts:88-101 and the insert at intros-routes.ts:76 have no transaction
    // around them, so two concurrent requests can both pass hasPendingBetween and both
    // insert. Running them here closes that window.
    const fromStored = v3db.getV3Card(fromCard as string)
    if (!fromStored || fromStored.card.subject_key !== actorKey) {
      refuseWrite(403, 'card_not_the_signers', 'from_card does not belong to the signer')
    }
    if (fromStored!.revocation_status !== 'active' || Date.parse(fromStored!.expires_at) <= now.getTime()) {
      refuseWrite(400, 'card_not_live', 'from_card is not live')
    }
    const target = liveNetworkHeadline(toCard as string)
    if (!target) refuseWrite(404, 'target_unavailable', 'target card is not available or not network-visible')
    if (introsDb.isBlocked(fromCard as string, toCard as string)) {
      refuseWrite(403, 'pair_blocked', 'this pair cannot be introduced')
    }
    if (introsDb.hasPendingBetween(fromCard as string, toCard as string)) {
      refuseWrite(409, 'pending_intro_exists', 'a pending intro already exists for this pair')
    }
    if (!introsDb.underDailyCap(actorKey)) {
      refuseWrite(429, 'daily_cap_reached', 'daily intro request cap reached')
    }

    const introId = `intro-v3-${now.getTime()}-${randomBytes(4).toString('hex')}`
    // Claimed before the insert, so a lost race cannot leave a second intro behind.
    const claim = claimCreate({
      request_id: requestId, actor_key: actorKey, operation: 'request_intro',
      created_type: 'intro', created_id: introId, write_ref: write.writeRef,
    })
    // Not a refusal. createMapRow was read at the top of this transaction and found nothing,
    // and SQLite serializes write transactions, so no other writer can have claimed it in
    // between. A failure here is an invariant violation and belongs in the log as a 500.
    if (!claim.claimed) {
      throw new Error(`request_id ${requestId} was claimed between the read and the claim inside one transaction`)
    }

    // The note is stored byte identical to the signed bytes. No stripUrls, no slice, no
    // trim, no String() coercion. That is the whole difference between the lanes, and a
    // test recomputes payload_digest from the stored row to prove it.
    introsDb.insertIntro({
      id: introId, from_card: fromCard as string, to_card: toCard as string,
      from_key: actorKey, to_key: target!.key,
      purpose: purpose as introsDb.IntroPurpose, note,
    })
    const evidenceId = recordCanonicalEvidence(write)
    recordAuthorization({ introId, actorKey, operation: 'request_intro', evidenceId, evidence: 'canonical' })
    recordCardEvent('intro_requested', fromCard as string, actorKey, { intro_id: introId, to_card: toCard, purpose })
    const state = materializeStatus(introId, now)
    return { intro_id: introId, created: true, state, purpose, note }
  },
  afterCommit: async (ctx, result) => {
    const r = result as { intro_id: string; created: boolean; note: string; purpose: string }
    if (!r.created) return
    const row = introsDb.getIntro(r.intro_id)
    if (row === null) return
    const fromHeadline = liveNetworkHeadline(row.from_card)?.headline ?? ''
    await email.notifyIntroRequest({
      recipientKey: row.to_key, introId: r.intro_id, requesterHeadline: fromHeadline,
      purpose: r.note || r.purpose, statusUrl: '',
    })
  },
})

// ── POST /request ─────────────────────────────────────────────────────────

router.post('/request', canonicalDispatch(canonicalRequestIntro), rateLimited('intro_request', 20), asyncRoute(async (req, res) => {
  const { from_card, to_card, purpose, note, public_key, nonce, signature } = req.body ?? {}
  if (typeof from_card !== 'string' || typeof to_card !== 'string' || typeof nonce !== 'string') {
    res.status(400).json({ error: 'from_card, to_card, nonce required' }); return
  }
  if (!introsDb.INTRO_PURPOSES.includes(purpose)) { res.status(400).json({ error: `purpose must be one of ${introsDb.INTRO_PURPOSES.join(', ')}` }); return }
  if (from_card === to_card) { res.status(400).json({ error: 'cannot request an intro to your own card' }); return }
  if (!checkSig(`intro-request:${from_card}:${to_card}:${purpose}:${nonce}`, signature, public_key)) {
    res.status(403).json({ error: 'signature does not verify' }); return
  }

  const fromStored = v3db.getV3Card(from_card)
  if (!fromStored || fromStored.card.subject_key !== public_key) { res.status(403).json({ error: 'from_card does not belong to the signer' }); return }
  if (fromStored.revocation_status !== 'active' || Date.parse(fromStored.expires_at) <= Date.now()) { res.status(400).json({ error: 'from_card is not live' }); return }

  const target = liveNetworkHeadline(to_card)
  if (!target) { res.status(404).json({ error: 'target card is not available or not network-visible' }); return }

  if (introsDb.isBlocked(from_card, to_card)) { res.status(403).json({ error: 'this pair cannot be introduced' }); return }
  if (introsDb.hasPendingBetween(from_card, to_card)) { res.status(409).json({ error: 'a pending intro already exists for this pair' }); return }
  if (!introsDb.underDailyCap(public_key)) { res.status(429).json({ error: 'daily intro request cap reached' }); return }

  // The cutoff, after every authorization check so an unauthorized caller learns nothing
  // about the window. Anti-downgrade cannot apply to a create, which has no resource yet.
  const createGate = checkLegacyCreate({ actorKey: public_key })
  if (createGate !== null) { refuseLegacy(res, 'request_intro', `${from_card}:${to_card}`, createGate); return }

  const cleanNote = introsDb.stripUrls(String(note ?? '')).slice(0, MAX_NOTE)
  const id = `intro-v3-${Date.now()}-${randomBytes(4).toString('hex')}`
  // Today's five transforms on the note stay exactly as they are. The note is unbound by
  // this signature either way, so refusing it would break a working client for no gain
  // in evidence, and bound_fields_json below is where that gap is recorded instead.
  //
  // One transaction around the group, which today's code does not have. No stored value
  // and no response changes: what changes is that a failure halfway leaves neither an
  // intro without its authorization nor an authorization without its intro.
  getDb().transaction(() => {
    introsDb.insertIntro({ id, from_card, to_card, from_key: public_key, to_key: target.key, purpose, note: cleanNote })
    const evidenceId = recordLegacyEvidence({
      actorKey: public_key, operation: 'request_intro', resourceType: 'intro', resourceId: id, signature,
    })
    recordAuthorization({ introId: id, actorKey: public_key, operation: 'request_intro', evidenceId, evidence: 'legacy_unbound' })
    // No nonce reservation: the published client's nonce is not unique by construction
    // (five Math.random sites at build/index.js), so refusing a repeat would change
    // behavior for a working client inside the compatibility window.
    recordAuthMode('intro', id, public_key, 'legacy_unbound')
  })()
  // OUTSIDE the transaction. card-events.ts documents that an intro event is written outside
  // the transaction it records, and recordCardEvent reaches a lazy CREATE TABLE on the first
  // call in a process, which is precisely the shape step 3 refused to put inside a business
  // transaction. It also swallows its own failures, so it never belonged in an atomic group.
  recordCardEvent('intro_requested', from_card, public_key, { intro_id: id, to_card, purpose })

  // Email the target, if subscribed and verified. Dark and instant when
  // unconfigured; never breaks the request.
  try {
    const fromHeadline = liveNetworkHeadline(from_card)?.headline ?? ''
    await email.notifyIntroRequest({ recipientKey: target.key, introId: id, requesterHeadline: fromHeadline, purpose: cleanNote || purpose, statusUrl: '' })
  } catch { /* notification failure never affects the request */ }

  res.status(201).json({ id, status: 'pending', purpose, note: cleanNote })
}))

// ── POST /:id/respond, the canonical lane ─────────────────────────────────
// express_interest and decline, the target's two answers to a request, and exactly one
// of them applies. The operation name carries the choice, so no `action` field is needed
// inside the payload: today that choice rides in an `action` field which IS inside the
// preimage at intros-routes.ts:98, the one thing the legacy route gets right.

const canonicalRespond = canonicalWriteRoute({
  operations: ['express_interest', 'decline'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    const introId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key
    const operation = write.envelope.operation
    if (Object.keys(write.payload).length !== 0) {
      refuseWrite(400, 'malformed_payload', `${operation} carries an empty payload`)
    }
    const facts = factsForWrite(introId)
    requireParty(facts, actorKey, 'target', 'only the intro target may respond')
    // The state guard, not the status column. Both operations require `requested`, which
    // mirrors today's guard at intros-routes.ts:100 refusing a response unless the intro
    // is pending, without depending on the column to say so.
    guardState(operation, facts, now)

    const row = introsDb.getIntro(introId)!
    const evidenceId = recordCanonicalEvidence(write)
    recordAuthorization({ introId, actorKey, operation, evidenceId, evidence: 'canonical' })
    introsDb.markResponded(introId)
    // The materialization writes the column. express_interest derives `interested`, which
    // maps to 'accepted', and that value is load bearing: isComplete at
    // intros-db.ts:129, the complete guard at :165, `awaiting` at :210 and the client's
    // incoming_pending filter all key on it. What differs from today's accept is only
    // what accompanies it. No contact is stored, because none was sent.
    const state = materializeStatus(introId, now)
    recordCardEvent(
      operation === 'decline' ? 'intro_declined' : 'intro_accepted', row.to_card, actorKey,
      { intro_id: introId, from_card: row.from_card, purpose: row.purpose, canonical: true },
    )
    return { intro_id: introId, state, contact_shared: false }
  },
  afterCommit: async (ctx, result) => {
    if (ctx.write.envelope.operation !== 'express_interest') return
    const r = result as { intro_id: string }
    const row = introsDb.getIntro(r.intro_id)
    if (row === null) return
    // The requester is told there is interest. No contact line is in this email, because
    // interest shares nothing: it is released only when both sides sign a share_contact.
    const toHeadline = liveNetworkHeadline(row.to_card)?.headline ?? ''
    await email.notifyIntroAccepted({
      recipientKey: row.from_key, introId: r.intro_id,
      counterpartyHeadline: toHeadline, counterpartyContact: '',
    })
  },
})

// ── POST /:id/respond {action, contact?} ──────────────────────────────────

router.post('/:id/respond', canonicalDispatch(canonicalRespond), rateLimited('intro_respond', 30), asyncRoute(async (req, res) => {
  const id = String(req.params.id)
  const { action, contact, public_key, nonce, signature } = req.body ?? {}
  if (!['accept', 'decline', 'decline_and_block'].includes(action)) { res.status(400).json({ error: 'action must be accept, decline, or decline_and_block' }); return }
  if (typeof nonce !== 'string') { res.status(400).json({ error: 'nonce required' }); return }
  const intro = introsDb.getIntro(id)
  if (!intro) { res.status(404).json({ error: 'intro not found' }); return }
  if (!checkSig(`intro-respond:${id}:${action}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  if (intro.to_key !== public_key) { res.status(403).json({ error: 'only the intro target may respond' }); return }
  // Anti-downgrade then the cutoff, after the signature and the party check so an
  // unauthorized caller learns nothing about either, and BEFORE the state check. Whether
  // this lane may be used at all is a more fundamental answer than what state the
  // resource is in: a caller who must update cannot act on the state answer either way,
  // so handing it one would be noise. A pre-2A intro is exempt from the cutoff and keeps
  // working on the old path until terminal or expired.
  const gate = checkLegacyWrite({ resourceType: 'intro', resourceId: id, actorKey: public_key, introId: id })
  if (gate !== null) { refuseLegacy(res, `respond:${action}`, id, gate); return }

  if (intro.status !== 'pending') { res.status(409).json({ error: `intro already ${intro.status}` }); return }

  // Bridge a pre-2A history into facts before writing any. Without it, a legacy accept on an
  // intro created before this build leaves the target's two authorizations with no
  // request_intro antecedent, so hasMutualInterest is false forever: the requester's
  // canonical share_contact is then refused `wrong_state` and the pair can never connect on
  // the canonical lane. The status check above already established `pending`, which is the
  // only bridgeable value, so this cannot refuse here.
  bridgePre2AIntro(id)

  if (action === 'accept') {
    if (typeof contact !== 'string' || contact.trim().length === 0) { res.status(400).json({ error: 'accept requires a contact line' }); return }
    if (contact.length > MAX_CONTACT) { res.status(400).json({ error: `contact too long (max ${MAX_CONTACT})` }); return }
    // THE MOST IMPORTANT COMPATIBILITY CASE IN THE DESIGN: one legacy act means two
    // things in the new model. The old client has only one accept, and it carries a
    // contact, so the adapter records TWO authorizations from ONE signature,
    // express_interest and share_contact, both legacy_unbound, both pointing at the same
    // evidence row. That row's bound_fields_json names only `id` and `action`, because
    // the preimage is intro-respond:${id}:${action}:${nonce} and the contact is attached
    // outside it at build/index.js:834-835. So no receipt can ever say this signature
    // covered the contact line stored with it.
    getDb().transaction(() => {
      const evidenceId = recordLegacyEvidence({
        actorKey: public_key, operation: 'express_interest', resourceType: 'intro', resourceId: id, signature,
      })
      introsDb.respondIntro(id, 'accepted', contact.trim())
      recordAuthorization({ introId: id, actorKey: public_key, operation: 'express_interest', evidenceId, evidence: 'legacy_unbound' })
      recordAuthorization({ introId: id, actorKey: public_key, operation: 'share_contact', evidenceId, evidence: 'legacy_unbound' })
      recordAuthMode('intro', id, public_key, 'legacy_unbound')
    })()
    recordCardEvent('intro_accepted', intro.to_card, public_key, { intro_id: id, from_card: intro.from_card, purpose: intro.purpose })
    // If both cards share a banked intent, open a structured fit exchange and
    // return the accepter's consent sheet; otherwise the intro proceeds straight
    // to the existing contact-completion flow, unchanged.
    // Prefer the v4 predicate handshake when both cards carry a Fit Policy for
    // the shared intent; otherwise fall back to the v3 question-bank exchange,
    // unchanged. Work never opens either (it is not a policy intent).
    // Structured fit opens only while it is enabled. With the flag off the
    // acceptance, the stored contact and the acceptance email are unchanged,
    // and the response says fit is unavailable.
    const fitOn = fitEnabled()
    let handshake: { id: string; mode: 'v4' } | null = null
    let fit: { id: string; consent_sheet: Record<string, unknown> } | null = null
    if (fitOn) {
      try { handshake = openV4HandshakeForIntro(intro) } catch { /* never blocks accept */ }
      if (!handshake) {
        try { fit = await createFitExchangeForIntro(intro) } catch { /* never blocks accept */ }
      }
    }
    // Tell the requester now. The accepter's contact line is not in this email.
    // It is released only when the requester completes with their own contact.
    try {
      const toHeadline = liveNetworkHeadline(intro.to_card)?.headline ?? ''
      await email.notifyIntroAccepted({ recipientKey: intro.from_key, introId: id, counterpartyHeadline: toHeadline, counterpartyContact: '' })
    } catch { /* notification failure never affects accept */ }
    res.json({
      id, status: 'accepted', awaiting: 'requester_contact',
      fit_handshake: handshake?.id ?? null,
      fit_mode: handshake ? 'v4' : (fit ? 'v3' : null),
      fit_exchange: fit?.id ?? null,
      consent_sheet: fit?.consent_sheet ?? null,
      ...(fitOn ? {} : { fit: { available: false, note: FIT_DISABLED_TEXT } }),
    })
    return
  }
  if (action === 'decline_and_block') {
    // Two effects from one signature, recorded as two authorizations against one
    // evidence row. A canonical client sends two envelopes instead, which is a real
    // behavior change and the price of designing the thirteen independently.
    getDb().transaction(() => {
      const evidenceId = recordLegacyEvidence({
        actorKey: public_key, operation: 'decline', resourceType: 'intro', resourceId: id, signature,
      })
      introsDb.respondIntro(id, 'declined', null)
      introsDb.addBlock(intro.from_card, intro.to_card)
      recordAuthorization({ introId: id, actorKey: public_key, operation: 'decline', evidenceId, evidence: 'legacy_unbound' })
      recordAuthorization({ introId: id, actorKey: public_key, operation: 'block_pair', evidenceId, evidence: 'legacy_unbound' })
      recordAuthMode('intro', id, public_key, 'legacy_unbound')
    })()
    recordCardEvent('intro_declined', intro.to_card, public_key, { intro_id: id, from_card: intro.from_card, blocked: true })
    res.json({ id, status: 'declined', blocked: true })
    return
  }
  // A decline is the one legacy act whose signature covers all of its semantics: the
  // preimage carries both the intro id and the action, and those are the only two
  // semantic fields the operation has. So its evidence claim is identical to the
  // canonical one, which is true of no other action.
  getDb().transaction(() => {
    const evidenceId = recordLegacyEvidence({
      actorKey: public_key, operation: 'decline', resourceType: 'intro', resourceId: id, signature,
    })
    introsDb.respondIntro(id, 'declined', null)
    recordAuthorization({ introId: id, actorKey: public_key, operation: 'decline', evidenceId, evidence: 'legacy_unbound' })
    recordAuthMode('intro', id, public_key, 'legacy_unbound')
  })()
  recordCardEvent('intro_declined', intro.to_card, public_key, { intro_id: id, from_card: intro.from_card, blocked: false })
  res.json({ id, status: 'declined' })
}))

// ── POST /share-contact, the canonical lane ───────────────────────────────
// Symmetric by decision, which is the change from today: the target shares at accept
// time (intros-routes.ts:105) and the requester shares at complete time (:168), two
// different routes with two different preimages and two different guards. One operation
// replaces both, and the actor is whichever party signed.
//
// The contact is never in the signed payload. The payload carries a commitment, and the value
// travels in the opening beside it. So no copy of a signed payload is a copy of the
// contact, and the payload is safe to store in evidence and to reference in a shared
// receipt. What it is NOT is end to end encrypted: the server stores the opening.

/** The contact rules. Rejection, never repair, measured on the string as sent.
 *
 *  The gate in the pipeline already refused a control character, a lone surrogate and
 *  leading or trailing whitespace inside the opening, so this adds only what needs the
 *  operation's own schema. The control character rule earns its place: a contact line is
 *  interpolated raw into a plain text email body at notifications.ts:95, with no escaping
 *  and no newline handling, so a contact carrying a newline can add lines to a message
 *  somebody else reads. */
function gateContact(value: unknown): string {
  if (typeof value !== 'string') refuseWrite(400, 'malformed_opening', 'the contact line must be a string')
  const v = value as string
  if (v.length === 0) refuseWrite(400, 'contact_empty', 'a contact line is required, and an empty one is refused rather than dropped')
  // Today both routes measure the UNTRIMMED string at intros-routes.ts:104 and :159 and
  // store the trimmed one, so a 201 character string with a trailing space is refused
  // while a 200 character one with a trailing space is stored as 199. Here the string as
  // sent is the string stored, so one measurement answers both questions.
  if (v.length > MAX_CONTACT) refuseWrite(400, 'contact_too_long', `contact is longer than ${MAX_CONTACT} characters`)
  return v
}

const canonicalShareContact = canonicalWriteRoute({
  operations: ['share_contact'],
  handler: (ctx: CanonicalContext) => {
    const { write, now } = ctx
    const introId = write.envelope.resource.id
    const actorKey = write.envelope.actor_key

    const keys = Object.keys(write.payload)
    if (keys.length !== 1 || keys[0] !== 'private_value_commitment') {
      refuseWrite(400, 'malformed_payload', 'share_contact carries exactly private_value_commitment')
    }
    // The opening recomputed to the commitment in step 7 of the pipeline, before this ran,
    // so by here the value is the value the principal committed to.
    const contact = gateContact(write.opening!.value)

    const facts = factsForWrite(introId)
    requireParty(facts, actorKey, 'either', 'only a party to this introduction may share a contact')
    guardState('share_contact', facts, now)

    // A live authorization already exists, so this is a second share with a fresh
    // envelope. A byte identical resend never reaches here: the nonce store answers it.
    const existing = authorizationOf(introId, actorKey, 'share_contact')
    if (existing !== null && existing.live === 1) {
      refuseWrite(409, 'contact_already_shared', 'this key has already authorized a contact line on this introduction')
    }

    const row = introsDb.getIntro(introId)!
    const isRequester = actorKey === row.from_key
    const recipientKey = isRequester ? row.to_key : row.from_key

    const evidenceId = recordCanonicalEvidence(write)
    // An UPSERT, not an insert. After a withdrawal the row still exists with live = 0,
    // because the withdrawal flips a column rather than deleting a row, so a plain insert
    // would make withdraw_contact a permanent dead end for that principal. Evidence rows
    // are append only, so the withdrawn authorization's history survives regardless.
    recordAuthorization({ introId, actorKey, operation: 'share_contact', evidenceId, evidence: 'canonical' })
    writeArtifact({ write, introId, recipientKey })
    // The column the legacy reader needs. isComplete at intros-db.ts:129 is a three term
    // conjunction, so this write alone is never enough: the status came from
    // express_interest and the two columns come from the two shares.
    getDb().prepare(`UPDATE v3_intros SET ${isRequester ? 'from_contact' : 'to_contact'} = ? WHERE id = ?`)
      .run(contact, introId)

    // Now, and only now, look for the other side. At the time the FIRST share reads this,
    // the other row is absent, so it writes no release. The second share sees both and
    // claims it.
    const other = authorizationOf(introId, recipientKey, 'share_contact')
    let released = false
    if (other !== null && other.live === 1) {
      released = claimRelease(
        introId,
        writeRefOfAuthorization(introId, row.from_key, 'share_contact'),
        writeRefOfAuthorization(introId, row.to_key, 'share_contact'),
      )
    }
    const state = materializeStatus(introId, now)
    // The release effect, answered to the acting party in the same call that caused it.
    // Read AFTER the column write above, so the second sharer sees the first sharer's line.
    //
    // This discloses nothing the caller cannot already read: the release happened, GET /mine
    // answers this exact value to this exact key from here on, and the notification mails it.
    // Withholding it only forced a second round trip that would return the same string, and
    // a tool that says both contacts are now available while handing back null is a tool that
    // has to lie or poll. Gated on `released`, and on this caller being a party, which
    // requireParty settled above.
    const releasedRow = released ? introsDb.getIntro(introId) : null
    const counterpartyContact = releasedRow === null
      ? null
      : (isRequester ? releasedRow.to_contact : releasedRow.from_contact) ?? null
    return {
      intro_id: introId, state, released, shared_by: isRequester ? 'requester' : 'target',
      counterparty_contact: counterpartyContact,
    }
  },
  afterCommit: async (ctx, result) => {
    const r = result as { intro_id: string; released: boolean }
    if (!r.released) return
    const row = introsDb.getIntro(r.intro_id)
    if (row === null) return
    // The release effect: each party learns the other's line. After the commit and best
    // effort, as today, so a thrown mailer cannot undo a connection that happened. A crash
    // between the commit and the send loses the email and the release row is the durable
    // fact, which is already true of every mail call in this repo.
    const fromHeadline = liveNetworkHeadline(row.from_card)?.headline ?? ''
    const toHeadline = liveNetworkHeadline(row.to_card)?.headline ?? ''
    const attempts = [
      email.notifyIntroCompleted({
        recipientKey: row.from_key, introId: r.intro_id,
        counterpartyHeadline: toHeadline, counterpartyContact: row.to_contact ?? '',
      }),
      email.notifyIntroCompleted({
        recipientKey: row.to_key, introId: r.intro_id,
        counterpartyHeadline: fromHeadline, counterpartyContact: row.from_contact ?? '',
      }),
    ]
    // Settled rather than awaited in sequence, so one failing side does not skip the other.
    await Promise.allSettled(attempts)
  },
})

router.post('/share-contact', canonicalShareContact)

// ── POST /:id/complete {contact} ──────────────────────────────────────────

router.post('/:id/complete', rateLimited('intro_complete', 30), asyncRoute(async (req, res) => {
  const id = String(req.params.id)
  const { contact, public_key, nonce, signature } = req.body ?? {}
  if (typeof contact !== 'string' || contact.trim().length === 0) { res.status(400).json({ error: 'contact line required' }); return }
  if (contact.length > MAX_CONTACT) { res.status(400).json({ error: `contact too long (max ${MAX_CONTACT})` }); return }
  if (typeof nonce !== 'string') { res.status(400).json({ error: 'nonce required' }); return }
  const intro = introsDb.getIntro(id)
  if (!intro) { res.status(404).json({ error: 'intro not found' }); return }
  if (!checkSig(`intro-complete:${id}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  if (intro.from_key !== public_key) { res.status(403).json({ error: 'only the requester may complete' }); return }
  // Anti-downgrade then the cutoff, before the state checks for the reason given on
  // /respond. THIS is where anti-downgrade actually bites: a requester who created the
  // intro canonically holds a mode row on `intro_request/<request_id>`, and
  // resolveAuthMode walks write_create_map back to it, so the legacy completion of a
  // canonically created intro is refused without any row having been pre-written for a
  // resource nobody had acted on.
  const gate = checkLegacyWrite({ resourceType: 'intro', resourceId: id, actorKey: public_key, introId: id })
  if (gate !== null) { refuseLegacy(res, 'share_contact', id, gate); return }

  if (intro.status !== 'accepted') { res.status(409).json({ error: 'intro is not accepted' }); return }
  if (intro.from_contact) { res.status(409).json({ error: 'intro already complete' }); return }

  // A pre-2A intro reaching here is `accepted`, which is NOT bridgeable, so no bridge is
  // attempted and no fact is guessed at. The completion still works, on the legacy lane,
  // exactly as it did before: the column is this intro's truth and the legacy lane never
  // materializes over it.

  // One transaction around the group. The contact column, the authorization, the evidence
  // and the release either all land or none do. Today the single UPDATE is alone, so there
  // was nothing to be atomic with.
  const released = getDb().transaction((): boolean => {
    introsDb.completeIntro(id, contact.trim())
    const evidenceId = recordLegacyEvidence({
      actorKey: public_key, operation: 'share_contact', resourceType: 'intro', resourceId: id, signature,
    })
    // bound_fields_json omits `contact`, because the preimage is intro-complete:${id}:${nonce}
    // and the contact is attached outside it at build/index.js. This is the action where
    // today's gap is worst: the first ever complete for an intro accepts ANY contact the
    // holder of that one signature supplies, and the canonical lane closes it by covering
    // the value through payload_digest.
    recordAuthorization({ introId: id, actorKey: public_key, operation: 'share_contact', evidenceId, evidence: 'legacy_unbound' })
    recordAuthMode('intro', id, public_key, 'legacy_unbound')
    // The release, on the same rule the canonical lane uses: both sides hold a live
    // share_contact authorization. A mixed pair reaches it too, each side at its own
    // strength, and no receipt promotes the legacy half.
    const other = authorizationOf(id, intro.to_key, 'share_contact')
    if (other === null || other.live !== 1) return false
    return claimRelease(
      id,
      writeRefOfAuthorization(id, intro.from_key, 'share_contact'),
      writeRefOfAuthorization(id, intro.to_key, 'share_contact'),
    )
  })()
  const final = introsDb.getIntro(id)!

  // The release emails, gated on the intro actually being complete rather than fired
  // unconditionally. Today's accept always stored a contact, so the two were the same
  // thing. A canonical target who expressed interest without sharing makes them differ,
  // and an ungated send would mail "How to reach them:" with nothing after it.
  if (introsDb.isComplete(final)) {
    try {
      const fromHeadline = liveNetworkHeadline(intro.from_card)?.headline ?? ''
      const toHeadline = liveNetworkHeadline(intro.to_card)?.headline ?? ''
      // requester learns the target's contact; target learns the requester's.
      await email.notifyIntroCompleted({ recipientKey: intro.from_key, introId: id, counterpartyHeadline: toHeadline, counterpartyContact: final.to_contact ?? '' })
      await email.notifyIntroCompleted({ recipientKey: intro.to_key, introId: id, counterpartyHeadline: fromHeadline, counterpartyContact: final.from_contact ?? '' })
    } catch { /* notification failure never affects completion */ }
  }

  // `complete` reports the intro's ACTUAL state rather than a constant. On a pure legacy flow
  // both contact columns are set and this stays true, so the published client sees no change.
  // A canonical target who expressed interest without sharing makes it differ, and the old
  // value claimed completion while the very next GET /mine answered complete:false, which a
  // client cannot reconcile because a retry is refused as already complete.
  res.json({ id, status: 'accepted', complete: introsDb.isComplete(final), released })
}))

// ── GET /mine (signed) ────────────────────────────────────────────────────
// Signed via query params so a GET can carry the caller's proof.
//
// THE OWNER SIDE PROJECTION IS SERVED HERE, and this is the only place it is served.
// `state`, `expires_at` and `pending_actions` come from introProjection, which derives
// them from the durable facts for THIS caller and stores nothing. Before this the
// derivation existed and no HTTP surface answered with it, so a client that wanted to
// know what a principal could do next had to re-derive the six ordered rules itself.
// Two clients that both guessed would eventually disagree with each other and with the
// guards that actually refuse a write, which is the disagreement this closes.
//
// EVERY FIELD THE PUBLISHED CLIENT READS IS UNCHANGED. `status`, `complete`, `awaiting`
// and `counterparty_contact` keep their exact meaning and position, because 3.2.2 filters
// on `status === 'pending'` and on `complete`. The three new members are additive, which
// is the only kind of change a read surface with a published reader can carry.
//
// A ROW THE DERIVATION CANNOT SEE REPORTS NOTHING RATHER THAN GUESSING. A pre-2A intro
// whose column says `accepted` has no authorization facts, so the derivation would answer
// `requested` and the pending list would offer actions the guards refuse. Those rows carry
// state: null and an empty pending list, on the same line the bridge draws: only `pending`
// is bridgeable, and everything else refuses rather than guessing.

router.get('/mine', rateLimited('intro_mine', 60), (req, res) => {
  const public_key = String(req.query.public_key ?? '')
  const nonce = String(req.query.nonce ?? '')
  const signature = String(req.query.signature ?? '')
  if (!public_key || !nonce) { res.status(400).json({ error: 'public_key and nonce required' }); return }
  if (!checkSig(`intro-mine:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }

  const rows = introsDb.introsForKey(public_key)
  const out = rows.map(r => {
    const complete = introsDb.isComplete(r)
    const iAmFrom = r.from_key === public_key
    // The counterparty contact is released ONLY when complete, and only to the
    // two parties (this row already belongs to the caller).
    const counterpartyContact = complete ? (iAmFrom ? r.to_contact : r.from_contact) : null
    // Derived per caller, never stored, and never for a row whose facts are absent.
    const projection = hasAuthorizations(r.id) ? introProjection(r.id, public_key) : null
    return {
      id: r.id,
      direction: iAmFrom ? 'outgoing' : 'incoming',
      from_card: r.from_card, to_card: r.to_card,
      purpose: r.purpose, note: r.note, status: r.status,
      complete,
      created_at: r.created_at, responded_at: r.responded_at,
      counterparty_contact: counterpartyContact,
      awaiting: r.status === 'accepted' && !r.from_contact ? (iAmFrom ? 'your_contact' : 'their_contact') : undefined,
      state: projection?.state ?? null,
      expires_at: projection?.expires_at ?? null,
      pending_actions: projection?.pending_actions ?? [],
    }
  })
  res.json({ count: out.length, intros: out })
})

export default router
