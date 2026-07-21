// ══════════════════════════════════════════════════════════════
// Mingle v3 - Routes (additive, mounted at /api/v3)
// ══════════════════════════════════════════════════════════════
// Publish verifies BOTH the Ed25519 card signature and the exact-content
// hash binding in approval (invariant 4). Search returns network-visible
// fields only. Revocation verbs transition status; status appears on every
// fetch. No bulk-export or category-download endpoint exists on this router,
// and a test asserts that (invariant 8).

import { Router } from 'express'
import { createHash, randomBytes } from 'node:crypto'
import { verify, canonicalize } from 'agent-passport-system'
import { cardContentHash, canonicalCardContent, validateV3Card } from './v3-cards.js'
import type { RevocationStatus, V3Card } from './v3-cards.js'
import * as v3db from './v3-db.js'
import * as notifyDb from './notify-db.js'
import * as matchesDb from './matches-db.js'
import * as email from './notifications.js'
import { embed } from './embeddings.js'
import { networkVisibleText } from './v3-cards.js'
import { checkRateLimit } from './db.js'

const router = Router()

const LIMITS = { publish: 10, search: 30, verb: 30, renew: 10 }

/** Store the semantic index vector, compute owner-only matches, and ping the
 *  operator. Shared by publish and renew. Never throws into the response. */
async function finalizePublish(cardId: string, card: V3Card): Promise<void> {
  try {
    const text = networkVisibleText(card)
    if (text.length > 0) {
      const vec = await embed(text)
      if (vec) { v3db.storeV3Embedding(cardId, vec); matchesDb.storeMatchVector(cardId, vec) }
    }
  } catch (e) {
    console.error('[v3] embedding failed (card still published):', (e as Error).message)
  }
  try { matchesDb.recomputeMatchesForCard(cardId) } catch (e) { console.error('[v3] match compute failed:', (e as Error).message) }
  try { await email.notifyAdmin('New Mingle card', `${card.headline} (${cardId})`) } catch { /* admin ping never affects publish */ }
}

/** Content identical except the volatile fields (timestamps, approval,
 *  signature, status). Used by renew to enforce identical-content re-signing. */
function sameContentExceptTimestamps(a: Record<string, any>, b: Record<string, any>): boolean {
  const strip = (c: Record<string, any>): string => {
    const { created_at, expires_at, approval, signature, revocation_status, ...rest } = c
    return canonicalize(rest)
  }
  return strip(a) === strip(b)
}

function rateLimited(action: keyof typeof LIMITS, keyOf: (req: any) => string) {
  return (req: any, res: any, next: any) => {
    const check = checkRateLimit(keyOf(req) || req.ip || 'anonymous', `v3_${action}`, LIMITS[action])
    if (!check.allowed) { res.status(429).json({ error: 'Rate limit exceeded', retryAfterSeconds: 3600 }); return }
    next()
  }
}

/** Verify the card signature (over the canonical card without signature) and
 *  the approval binding (approval.card_hash equals the recomputed content
 *  hash; approval.principal_signature is the subject key's Ed25519 signature
 *  over that hash). One key model in P1: subject_key signs both. */
function verifyCardCrypto(card: Record<string, any>): { ok: true } | { ok: false; error: string } {
  const recomputed = cardContentHash(card)
  if (card.approval.card_hash !== recomputed) {
    return { ok: false, error: `approval.card_hash does not match the card content (expected ${recomputed})` }
  }
  try {
    if (!verify(card.approval.card_hash, card.approval.principal_signature, card.subject_key)) {
      return { ok: false, error: 'approval.principal_signature does not verify under subject_key' }
    }
  } catch (e: any) {
    return { ok: false, error: `approval signature verification failed: ${e.message}` }
  }
  try {
    const { signature, ...unsigned } = card
    if (!signature || !verify(canonicalize(unsigned), signature, card.subject_key)) {
      return { ok: false, error: 'card signature does not verify under subject_key' }
    }
  } catch (e: any) {
    return { ok: false, error: `card signature verification failed: ${e.message}` }
  }
  return { ok: true }
}

// ── POST /api/v3/cards - publish (signature + hash binding) ──────────────

router.post('/cards', rateLimited('publish', req => String(req.body?.card?.subject_key ?? '')), async (req, res) => {
  const card = req.body?.card
  const validation = validateV3Card(card)
  if ('error' in validation) { res.status(400).json({ error: validation.error }); return }

  const crypto = verifyCardCrypto(card)
  if ('error' in crypto) { res.status(403).json({ error: crypto.error }); return }

  if (Date.parse(card.expires_at) <= Date.now()) { res.status(400).json({ error: 'card is already expired' }); return }
  if (card.revocation_status !== 'active') { res.status(400).json({ error: 'a new card must be published with revocation_status active' }); return }

  // Idempotency: byte-identical content already live for this subject returns
  // that card, not a duplicate. (The content hash covers timestamps too, so an
  // identical hash means a genuinely identical card.)
  const dup = v3db.findActiveCardByHash(card.subject_key, card.approval.card_hash)
  if (dup) {
    res.status(200).json({ published: true, idempotent: true, card_id: dup.card_id, card_hash: card.approval.card_hash, expires_at: dup.expires_at, revocation_status: dup.revocation_status })
    return
  }

  const cardId = `v3-${card.card_type}-${Date.now()}-${randomBytes(4).toString('hex')}`
  v3db.insertV3Card(cardId, card, card.approval.card_hash)
  await finalizePublish(cardId, card)

  res.status(201).json({ published: true, card_id: cardId, card_hash: card.approval.card_hash, expires_at: card.expires_at, revocation_status: card.revocation_status })
})

// ── POST /api/v3/cards/:cardId/renew - re-sign identical content, fresh TTL ─
// The client rebuilds the same card with new timestamps, re-approves the hash,
// and signs it, exactly like publishing. Renew verifies it is the same subject
// and the same content, publishes the fresh card, and supersedes the old one.

router.post('/cards/:cardId/renew', rateLimited('renew', req => String(req.body?.card?.subject_key ?? '')), async (req, res) => {
  const oldId = String(req.params.cardId)
  const card = req.body?.card
  const validation = validateV3Card(card)
  if ('error' in validation) { res.status(400).json({ error: validation.error }); return }
  const crypto = verifyCardCrypto(card)
  if ('error' in crypto) { res.status(403).json({ error: crypto.error }); return }
  if (Date.parse(card.expires_at) <= Date.now()) { res.status(400).json({ error: 'renewed card is already expired' }); return }
  if (card.revocation_status !== 'active') { res.status(400).json({ error: 'a renewed card must be active' }); return }

  const old = v3db.getV3Card(oldId)
  if (!old) { res.status(404).json({ error: 'card to renew not found' }); return }
  if (old.card.subject_key !== card.subject_key) { res.status(403).json({ error: 'not the card subject' }); return }
  if (old.revocation_status !== 'active') { res.status(409).json({ error: `only an active card can be renewed (this one is ${old.revocation_status})` }); return }
  if (!sameContentExceptTimestamps(old.card, card)) {
    res.status(400).json({ error: 'renew requires identical content; use compose and publish to change a card' }); return
  }

  const newId = `v3-${card.card_type}-${Date.now()}-${randomBytes(4).toString('hex')}`
  v3db.insertV3Card(newId, card, card.approval.card_hash)
  await finalizePublish(newId, card)

  // Supersede the old version and clean its index + match artifacts.
  v3db.setRevocationStatus(oldId, card.subject_key, 'superseded')
  v3db.removeFromIndex(oldId)
  matchesDb.deleteMatchArtifacts(oldId)
  v3db.recordSupersession(oldId, newId)

  res.status(201).json({ renewed: true, new_card_id: newId, superseded: oldId, card_hash: card.approval.card_hash, expires_at: card.expires_at })
})

// ── GET /api/v3/cards/:cardId - fetch, status always shown ───────────────

router.get('/cards/:cardId', (req, res) => {
  const cardId = String(req.params.cardId)
  const stored = v3db.getV3Card(cardId)
  if (!stored) { res.status(404).json({ error: 'card not found' }); return }
  // Surface the supersession chain so a renewed card and its predecessor link.
  const superseded_by = v3db.getSupersededBy(cardId)
  const supersedes = v3db.getSupersedes(cardId)
  res.json({ card_id: stored.card_id, revocation_status: stored.revocation_status, expires_at: stored.expires_at, card: stored.card, superseded_by, supersedes })
})

// ── POST /api/v3/cards/search - explicit fields + semantic, filtered ─────

router.post('/cards/search', rateLimited('search', req => String(req.headers['x-public-key'] ?? '')), async (req, res) => {
  const { card_type, intents, topics, engagement, location, event_ref, query, limit, created_after, cursor } = req.body ?? {}

  let decodedCursor: v3db.PageCursor | undefined
  if (typeof cursor === 'string' && cursor.length > 0) {
    try {
      const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'))
      if (typeof parsed?.created_at !== 'string' || typeof parsed?.card_id !== 'string') throw new Error('shape')
      decodedCursor = { created_at: parsed.created_at, card_id: parsed.card_id }
    } catch { res.status(400).json({ error: 'invalid cursor' }); return }
  }
  if (created_after !== undefined && typeof created_after !== 'string') { res.status(400).json({ error: 'created_after must be an ISO string' }); return }

  let semanticIds: string[] | undefined
  if (typeof query === 'string' && query.trim().length > 0) {
    try {
      const vec = await embed(query.trim())
      if (!vec) { res.status(500).json({ error: 'semantic search unavailable: embedding model not ready' }); return }
      const hits = v3db.semanticSearchV3(vec, Math.min(Number(limit) || 20, 50))
      semanticIds = hits.map(h => h.card_id)
    } catch (e) {
      res.status(500).json({ error: 'semantic search unavailable: ' + (e as Error).message })
      return
    }
  }
  const { results, next_cursor } = v3db.searchV3CardsPaged(
    { card_type, intents, topics, engagement, location, event_ref },
    { semanticIds, limit: Number(limit) || 20, createdAfter: created_after, cursor: decodedCursor },
  )
  const encoded = next_cursor ? Buffer.from(JSON.stringify(next_cursor)).toString('base64url') : null
  res.json({ count: results.length, results, next_cursor: encoded })
})

// ── Revocation verbs (invariant 7) ───────────────────────────────────────
// Each verb requires an Ed25519 signature by the card's subject key over
// `${verb}:${card_id}`, proving the principal's agent authorized this exact
// transition on this exact card.

const VERB_STATUS: Record<string, RevocationStatus> = {
  'withdraw': 'withdrawn',
  'supersede': 'superseded',
  'revoke-authority': 'authority_revoked',
  'stop-new-matches': 'stopped_new_matches',
}

function requireVerbSignature(req: any, res: any, cardId: string, verb: string): string | null {
  const { signature, public_key } = req.body ?? {}
  if (!signature || !public_key) { res.status(401).json({ error: 'signature and public_key required' }); return null }
  const stored = v3db.getV3Card(cardId)
  if (!stored) { res.status(404).json({ error: 'card not found' }); return null }
  if (stored.card.subject_key !== public_key) { res.status(403).json({ error: 'not the card subject' }); return null }
  try {
    if (!verify(`${verb}:${cardId}`, signature, public_key)) { res.status(403).json({ error: 'verb signature does not verify' }); return null }
  } catch (e: any) {
    res.status(403).json({ error: `verb signature verification failed: ${e.message}` }); return null
  }
  return public_key
}

for (const [verb, status] of Object.entries(VERB_STATUS)) {
  router.post(`/cards/:cardId/${verb}`, rateLimited('verb', req => String(req.body?.public_key ?? '')), (req, res) => {
    const cardId = String(req.params.cardId)
    const key = requireVerbSignature(req, res, cardId, verb)
    if (!key) return
    v3db.setRevocationStatus(cardId, key, status)
    if (verb !== 'supersede') v3db.removeFromIndex(cardId)
    // A card that is no longer active must not keep generating matches.
    if (status !== 'active') matchesDb.deleteMatchArtifacts(cardId)
    res.json({ card_id: cardId, revocation_status: status })
  })
}

router.post('/cards/:cardId/delete-server-copy', rateLimited('verb', req => String(req.body?.public_key ?? '')), (req, res) => {
  const cardId = String(req.params.cardId)
  const key = requireVerbSignature(req, res, cardId, 'delete-server-copy')
  if (!key) return
  v3db.deleteV3Card(cardId, key)
  matchesDb.deleteMatchArtifacts(cardId)
  // Deleting the server copy also removes the principal's notification email.
  notifyDb.deleteSubscription(key)
  res.json({ card_id: cardId, revocation_status: 'deleted' })
})

// ── POST /api/v3/sweep - expiry sweep including index removal ────────────
// Operationally invoked by a scheduler; exposed for tests and manual runs.

router.post('/sweep', (_req, res) => {
  res.json(v3db.sweepExpiredV3Cards())
})

router.get('/stats', (_req, res) => {
  res.json({ active_v3_cards: v3db.v3CardCount(), protocol: 'mingle-v3-p1' })
})

export default router
