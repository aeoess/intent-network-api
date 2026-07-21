// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - routes (mounted at /api/v4/fit)
// ══════════════════════════════════════════════════════════════
// Stage 1: the private Fit Policy (set / get, owner-only, exact-set approval).
// Later stages add the bilateral predicate handshake. Everything here is signed
// by the acting key; a policy's values never leave the owner except through the
// handshake's mutually-authorized, canonical predicates.

import { Router } from 'express'
import { verify } from 'agent-passport-system'
import { checkRateLimit } from './db.js'
import * as v3db from './v3-db.js'
import * as policyDb from './fit-policy-db.js'

const router = Router()

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

export default router
