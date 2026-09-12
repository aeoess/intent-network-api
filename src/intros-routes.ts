// ══════════════════════════════════════════════════════════════
// Mingle v3 introductions - routes (mounted at /api/v3/intros)
// ══════════════════════════════════════════════════════════════
// The essential loop: request, mutual accept, complete. Contacts are released
// only when the intro is complete (both sides supplied a contact line), and
// only to the two parties (in GET /mine and the acceptance email). No third
// party ever sees a contact. Every write is signed by the acting key.
//
// TWO LANES ON THREE OF THESE PATHS. A body carrying an `envelope` key is a canonical
// mingle-write-v1 write and goes to the canonical handler; a body without one is the
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
import { recordAuthorization, materializeStatus, stateOf } from './connection-facts.js'
import { factsOrRefuse, guardState, requireParty } from './intro-guards.js'
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
    // byte identical retry; a client whose request timed out mints a fresh nonce and
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
    if (!claim.claimed) refuseWrite(409, 'request_id_taken', 'this request id was claimed concurrently')

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
    recordCardEvent('intro_requested', from_card, public_key, { intro_id: id, to_card, purpose })
  })()

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
    const facts = factsOrRefuse(introId)
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
      recordCardEvent('intro_accepted', intro.to_card, public_key, { intro_id: id, from_card: intro.from_card, purpose: intro.purpose })
    })()
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
      recordCardEvent('intro_declined', intro.to_card, public_key, { intro_id: id, from_card: intro.from_card, blocked: true })
    })()
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
    recordCardEvent('intro_declined', intro.to_card, public_key, { intro_id: id, from_card: intro.from_card, blocked: false })
  })()
  res.json({ id, status: 'declined' })
}))

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
  if (intro.status !== 'accepted') { res.status(409).json({ error: 'intro is not accepted' }); return }
  if (intro.from_contact) { res.status(409).json({ error: 'intro already complete' }); return }

  introsDb.completeIntro(id, contact.trim())
  const final = introsDb.getIntro(id)!

  // Now complete: release each party's contact to the other, by email. This is
  // its own delivery type, so the acceptance email the requester already got
  // does not dedupe it away.
  try {
    const fromHeadline = liveNetworkHeadline(intro.from_card)?.headline ?? ''
    const toHeadline = liveNetworkHeadline(intro.to_card)?.headline ?? ''
    // requester learns the target's contact; target learns the requester's.
    await email.notifyIntroCompleted({ recipientKey: intro.from_key, introId: id, counterpartyHeadline: toHeadline, counterpartyContact: final.to_contact ?? '' })
    await email.notifyIntroCompleted({ recipientKey: intro.to_key, introId: id, counterpartyHeadline: fromHeadline, counterpartyContact: final.from_contact ?? '' })
  } catch { /* notification failure never affects completion */ }

  res.json({ id, status: 'accepted', complete: true })
}))

// ── GET /mine (signed) ────────────────────────────────────────────────────
// Signed via query params so a GET can carry the caller's proof.

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
    return {
      id: r.id,
      direction: iAmFrom ? 'outgoing' : 'incoming',
      from_card: r.from_card, to_card: r.to_card,
      purpose: r.purpose, note: r.note, status: r.status,
      complete,
      created_at: r.created_at, responded_at: r.responded_at,
      counterparty_contact: counterpartyContact,
      awaiting: r.status === 'accepted' && !r.from_contact ? (iAmFrom ? 'your_contact' : 'their_contact') : undefined,
    }
  })
  res.json({ count: out.length, intros: out })
})

export default router
