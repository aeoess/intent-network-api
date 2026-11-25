// Test-only builder for a signed 48h IntentCard.
//
// agent-passport-system 8.x no longer exports createIntentCard. This produces
// the same card the 1.x SDK did (dist/src/core/intent-network.js in 1.13.0):
// same members, same defaults, same cardId shape, signed over the APS
// canonicalize of the card without its signature. A client on the 1.x SDK
// still builds cards this way, so the tests keep exercising what clients send.
//
// Not named *.test.ts, so the test glob does not run it as a suite.

import { randomUUID } from 'node:crypto'
import { sign, canonicalize } from 'agent-passport-system'
import type { IntentCard, IntentItem } from 'agent-passport-system'

export interface CreateIntentCardOptions {
  agentId: string
  principalAlias: string
  publicKey: string
  privateKey: string
  needs: IntentItem[]
  offers: IntentItem[]
  openTo?: string[]
  notOpenTo?: string[]
  approvalRequired?: string[]
  autonomy?: IntentCard['autonomy']
  ttlSeconds?: number
}

export function createIntentCard(opts: CreateIntentCardOptions): IntentCard {
  const now = new Date()
  const ttl = opts.ttlSeconds ?? 86400
  const unsigned = {
    cardId: `card_${randomUUID().slice(0, 12)}`,
    agentId: opts.agentId,
    principalAlias: opts.principalAlias,
    publicKey: opts.publicKey,
    needs: opts.needs,
    offers: opts.offers,
    openTo: opts.openTo ?? [],
    notOpenTo: opts.notOpenTo ?? [],
    approvalRequired: opts.approvalRequired ?? ['disclose-budget', 'share-contact'],
    autonomy: opts.autonomy ?? 'propose-intros',
    ttlSeconds: ttl,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
  }
  const signature = sign(canonicalize(unsigned), opts.privateKey)
  return { ...unsigned, signature }
}
