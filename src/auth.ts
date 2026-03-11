// ══════════════════════════════════════════════════════════════
// Intent Network API — Auth Middleware
// ══════════════════════════════════════════════════════════════
// Ed25519 signature verification. No passwords, no tokens.
// If you can sign with the key, you own the identity.

import type { Request, Response, NextFunction } from 'express'
import { verify, canonicalize } from 'agent-passport-system'

export interface AuthenticatedRequest extends Request {
  verifiedPublicKey?: string
  verifiedAgentId?: string
}

/**
 * Verify that the request body contains a valid Ed25519 signature.
 * Expects: { ...data, signature: string, publicKey: string }
 * The signature must be over canonicalize(data without signature).
 */
export function requireSignature(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const { signature, publicKey, ...data } = req.body

  if (!signature || !publicKey) {
    res.status(401).json({ error: 'Missing signature or publicKey' })
    return
  }

  try {
    // For IntentCards, the card itself has a signature field
    // We verify using the card's own signature
    const card = req.body.card || req.body
    const cardSig = card.signature
    const cardPubKey = card.publicKey || publicKey

    if (!cardSig || !cardPubKey) {
      res.status(401).json({ error: 'Card missing signature or publicKey' })
      return
    }

    // Build the unsigned version for verification
    const unsigned = { ...card }
    delete unsigned.signature

    const canonical = canonicalize(unsigned)
    const valid = verify(canonical, cardSig, cardPubKey)

    if (!valid) {
      res.status(403).json({ error: 'Invalid signature. The Ed25519 signature does not match the public key.' })
      return
    }

    req.verifiedPublicKey = cardPubKey
    req.verifiedAgentId = card.agentId
    next()
  } catch (e: any) {
    res.status(403).json({ error: `Signature verification failed: ${e.message}` })
  }
}

/**
 * Lighter auth: just verify that the requester can sign a challenge.
 * Used for read operations where we need to confirm identity.
 * Checks X-Agent-Id and X-Public-Key headers.
 */
export function identifyAgent(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
  req.verifiedAgentId = String(req.headers['x-agent-id'] || '') || undefined
  req.verifiedPublicKey = String(req.headers['x-public-key'] || '') || undefined
  next()
}
