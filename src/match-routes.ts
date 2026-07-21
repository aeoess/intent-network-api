// ══════════════════════════════════════════════════════════════
// Mingle v3 - digest, dismiss, report, API index (mounted at /api/v3)
// ══════════════════════════════════════════════════════════════
// The digest is each owner reading the results of their own standing query:
// signed by their subject_key, it returns overlap maps for their cards, a
// pending-intro count, and an expiry countdown. Nothing here exposes a numeric
// score, and match results are owner-only. Dismiss flips the caller's side of a
// match only. Report is an unsigned, rate-limited, URL-free abuse channel.

import { Router } from 'express'
import { verify } from 'agent-passport-system'
import { checkRateLimit } from './db.js'
import * as v3db from './v3-db.js'
import * as matchesDb from './matches-db.js'
import * as introsDb from './intros-db.js'
import * as reportsDb from './reports-db.js'
import * as email from './notifications.js'

const router = Router()

const PROTOCOL = { name: 'mingle-v3', version: '3.1.0' }
const RATE_LIMIT_CEILING = 600

function checkSig(payload: string, signature: unknown, key: unknown): boolean {
  if (typeof signature !== 'string' || typeof key !== 'string') return false
  try { return verify(payload, signature, key) } catch { return false }
}

function rateLimited(action: string, limit: number) {
  return (req: any, res: any, next: any) => {
    if (!checkRateLimit(`v3m:${req.ip || 'anon'}`, action, limit).allowed) { res.status(429).json({ error: 'Rate limit exceeded' }); return }
    next()
  }
}

/** Sets X-RateLimit-* on every v3 response. Informational (a generous ceiling):
 *  it never blocks, so it cannot change existing enforcement or break callers.
 *  Mount this at /api/v3 before the routers. */
export function v3RateHeaders(req: any, res: any, next: any): void {
  const key = String(req.headers['x-public-key'] || req.ip || 'anon')
  const { remaining } = checkRateLimit(`v3req:${key}`, 'v3_req', RATE_LIMIT_CEILING)
  const windowStart = new Date(); windowStart.setMinutes(0, 0, 0)
  const reset = Math.floor((windowStart.getTime() + 3600 * 1000) / 1000)
  res.setHeader('X-RateLimit-Limit', String(RATE_LIMIT_CEILING))
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, remaining)))
  res.setHeader('X-RateLimit-Reset', String(reset))
  next()
}

// ── GET /api/v3 - endpoint index for third-party agents ───────────────────

router.get('/', (_req, res) => {
  res.json({
    protocol: PROTOCOL.name,
    version: PROTOCOL.version,
    docs: 'PROTOCOL.md',
    endpoints: {
      'POST /api/v3/cards': 'Publish a signed card (idempotent on identical content)',
      'GET /api/v3/cards/:cardId': 'Fetch a card; status and supersession links always shown',
      'POST /api/v3/cards/search': 'Explicit-field + semantic search; supports created_after, cursor, limit',
      'POST /api/v3/cards/:cardId/renew': 'Re-sign identical content with a fresh expiry, superseding the old card',
      'POST /api/v3/cards/:cardId/withdraw|supersede|revoke-authority|stop-new-matches|delete-server-copy': 'Signed revocation verbs',
      'GET /api/v3/digest': 'Signed. Your new matches, pending intros, and expiry countdown',
      'POST /api/v3/matches/dismiss': 'Signed. Dismiss one match from your side only',
      'POST /api/v3/report': 'Report a card (reason <= 200 chars, no URLs)',
      'GET /api/v3/intros/mine': 'Signed. Your introductions',
      'GET /api/v3/notifications/status': 'Signed. Your notification subscription status',
    },
    limits: { window: 'hour', header: 'X-RateLimit-Limit / -Remaining / -Reset' },
    doctrine: 'Mingle transports; it never evaluates. Results carry no scores; matching runs each owner\'s own query and returns to that owner only.',
  })
})

// ── GET /api/v3/digest (signed) ───────────────────────────────────────────

const EXPIRY_SOON_DAYS = 3

router.get('/digest', rateLimited('v3_digest', 60), (req, res) => {
  const public_key = String(req.query.public_key ?? '')
  const nonce = String(req.query.nonce ?? '')
  const signature = String(req.query.signature ?? '')
  if (!public_key || !nonce) { res.status(400).json({ error: 'public_key and nonce required' }); return }
  if (!checkSig(`digest:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }

  const cardIds = v3db.activeCardIdsForSubject(public_key)
  const since = matchesDb.getLastDigestCheck(public_key)

  const newMatches = matchesDb.newMatchesForCardsSince(cardIds, since)
    .sort((a, b) => (a.computed_at < b.computed_at ? 1 : -1))
    .map(m => ({
      card_id: m.card_id,
      other_card_id: m.other_card_id,
      computed_at: m.computed_at,
      matched_intents: m.matched_intents,
      agreed_fields: m.agreed_fields,
      counterpart_snippets: m.counterpart_snippets,
      overlap_count: m.overlap_count,
    }))

  const now = Date.now()
  const card_expiry: { card_id: string; expires_at: string; days_left: number }[] = []
  for (const id of cardIds) {
    const c = v3db.getV3Card(id)
    if (!c) continue
    const msLeft = Date.parse(c.expires_at) - now
    const daysLeft = Math.ceil(msLeft / (24 * 3600 * 1000))
    if (daysLeft <= EXPIRY_SOON_DAYS) card_expiry.push({ card_id: id, expires_at: c.expires_at, days_left: daysLeft })
  }

  const pending_intros = introsDb.pendingIncomingCount(public_key)

  // Reading the digest advances the seen window for these cards.
  for (const id of cardIds) matchesDb.markSeenForCard(id)
  matchesDb.stampDigestCheck(public_key)

  res.json({
    protocol: PROTOCOL.name,
    new_match_count: newMatches.length,
    ordering: 'recency',   // most-recent overlap first; overlap_count is also present per match
    new_matches: newMatches,
    pending_intros,
    card_expiry,
    previous_check: since,
  })
})

// ── POST /api/v3/matches/dismiss (signed) ─────────────────────────────────

router.post('/matches/dismiss', rateLimited('v3_dismiss', 60), (req, res) => {
  const { card_id, other_card_id, public_key, nonce, signature } = req.body ?? {}
  if (typeof card_id !== 'string' || typeof other_card_id !== 'string' || typeof nonce !== 'string') {
    res.status(400).json({ error: 'card_id, other_card_id, nonce required' }); return
  }
  if (!checkSig(`dismiss:${card_id}:${other_card_id}:${nonce}`, signature, public_key)) { res.status(403).json({ error: 'signature does not verify' }); return }

  // The caller must own card_id.
  const stored = v3db.getV3Card(card_id)
  if (!stored || stored.card.subject_key !== public_key) { res.status(403).json({ error: 'not the owner of card_id' }); return }

  const dismissed = matchesDb.dismissMatch(card_id, other_card_id)
  res.json({ dismissed, card_id, other_card_id })
})

// ── POST /api/v3/report ───────────────────────────────────────────────────

const MAX_REASON = 200

router.post('/report', rateLimited('v3_report', 20), async (req, res) => {
  const { card_id, reason } = req.body ?? {}
  if (typeof card_id !== 'string' || card_id.length === 0) { res.status(400).json({ error: 'card_id required' }); return }
  if (typeof reason !== 'string' || reason.trim().length === 0) { res.status(400).json({ error: 'reason required' }); return }
  if (reason.length > MAX_REASON) { res.status(400).json({ error: `reason too long (max ${MAX_REASON})` }); return }
  // No URLs: reuse the intro note URL detector. A changed string means a link
  // was present, so the report is refused rather than stored with a link in it.
  if (introsDb.stripUrls(reason) !== reason) { res.status(400).json({ error: 'reason may not contain URLs' }); return }
  if (!v3db.getV3Card(card_id)) { res.status(404).json({ error: 'card not found' }); return }

  const id = reportsDb.insertReport(card_id, reason.trim(), req.ip ?? null)
  try { await email.notifyAdmin('Mingle card reported', `card ${card_id}\nreason: ${reason.trim()}`) } catch { /* ping never blocks a report */ }
  res.status(201).json({ reported: true, id })
})

export default router
