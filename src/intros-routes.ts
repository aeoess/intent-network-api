// ══════════════════════════════════════════════════════════════
// Mingle v3 introductions - routes (mounted at /api/v3/intros)
// ══════════════════════════════════════════════════════════════
// The essential loop: request, mutual accept, complete. Contacts are released
// only when the intro is complete (both sides supplied a contact line), and
// only to the two parties (in GET /mine and the acceptance email). No third
// party ever sees a contact. Every write is signed by the acting key.

import { Router } from 'express'
import { randomBytes } from 'node:crypto'
import { verify } from 'agent-passport-system'
import { checkRateLimit } from './db.js'
import * as introsDb from './intros-db.js'
import * as v3db from './v3-db.js'
import { networkVisibleView } from './v3-cards.js'
import * as email from './notifications.js'

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

// ── POST /request ─────────────────────────────────────────────────────────

router.post('/request', rateLimited('intro_request', 20), async (req, res) => {
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

  const cleanNote = introsDb.stripUrls(String(note ?? '')).slice(0, MAX_NOTE)
  const id = `intro-v3-${Date.now()}-${randomBytes(4).toString('hex')}`
  introsDb.insertIntro({ id, from_card, to_card, from_key: public_key, to_key: target.key, purpose, note: cleanNote })

  // Email the target, if subscribed and verified. Dark and instant when
  // unconfigured; never breaks the request.
  try {
    const fromHeadline = liveNetworkHeadline(from_card)?.headline ?? ''
    await email.notifyIntroRequest({ recipientKey: target.key, introId: id, requesterHeadline: fromHeadline, purpose: cleanNote || purpose, statusUrl: '' })
  } catch { /* notification failure never affects the request */ }

  res.status(201).json({ id, status: 'pending', purpose, note: cleanNote })
})

// ── POST /:id/respond {action, contact?} ──────────────────────────────────

router.post('/:id/respond', rateLimited('intro_respond', 30), (req, res) => {
  const id = String(req.params.id)
  const { action, contact, public_key, nonce, signature } = req.body ?? {}
  if (!['accept', 'decline', 'decline_and_block'].includes(action)) { res.status(400).json({ error: 'action must be accept, decline, or decline_and_block' }); return }
  if (typeof nonce !== 'string') { res.status(400).json({ error: 'nonce required' }); return }
  const intro = introsDb.getIntro(id)
  if (!intro) { res.status(404).json({ error: 'intro not found' }); return }
  if (!checkSig(`intro-respond:${id}:${action}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  if (intro.to_key !== public_key) { res.status(403).json({ error: 'only the intro target may respond' }); return }
  if (intro.status !== 'pending') { res.status(409).json({ error: `intro already ${intro.status}` }); return }

  if (action === 'accept') {
    if (typeof contact !== 'string' || contact.trim().length === 0) { res.status(400).json({ error: 'accept requires a contact line' }); return }
    if (contact.length > MAX_CONTACT) { res.status(400).json({ error: `contact too long (max ${MAX_CONTACT})` }); return }
    introsDb.respondIntro(id, 'accepted', contact.trim())
    res.json({ id, status: 'accepted', awaiting: 'requester_contact' })
    return
  }
  if (action === 'decline_and_block') {
    introsDb.respondIntro(id, 'declined', null)
    introsDb.addBlock(intro.from_card, intro.to_card)
    res.json({ id, status: 'declined', blocked: true })
    return
  }
  introsDb.respondIntro(id, 'declined', null)
  res.json({ id, status: 'declined' })
})

// ── POST /:id/complete {contact} ──────────────────────────────────────────

router.post('/:id/complete', rateLimited('intro_complete', 30), async (req, res) => {
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

  // Now complete: release each party's contact to the other, by email.
  try {
    const fromHeadline = liveNetworkHeadline(intro.from_card)?.headline ?? ''
    const toHeadline = liveNetworkHeadline(intro.to_card)?.headline ?? ''
    // requester learns the target's contact; target learns the requester's.
    await email.notifyIntroAccepted({ recipientKey: intro.from_key, introId: id, counterpartyHeadline: toHeadline, counterpartyContact: final.to_contact ?? '' })
    await email.notifyIntroAccepted({ recipientKey: intro.to_key, introId: id, counterpartyHeadline: fromHeadline, counterpartyContact: final.from_contact ?? '' })
  } catch { /* notification failure never affects completion */ }

  res.json({ id, status: 'accepted', complete: true })
})

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
