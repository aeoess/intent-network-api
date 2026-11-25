// ══════════════════════════════════════════════════════════════
// 48h IntentCard checks
// ══════════════════════════════════════════════════════════════
// agent-passport-system 2.0 moved the IntentNetwork helpers out of the SDK. In
// 8.1.1 verifyIntentCard and isCardExpired are not exported from the package
// root at all, and the internal module only throws.
// These are the two this API calls, kept here with the behaviour of the 1.x SDK
// (dist/src/core/intent-network.js in 1.13.0), so the preimage does not
// change and a valid expiry gives the same answer. An unparseable expiry now
// counts as expired. A card signed with an admissible key by a 1.x client keeps
// verifying. Key material that 8.x refuses and 1.x accepted, such as a
// small-order public key (GHSA-72cm-hhw9-f66f), no longer verifies, on purpose.
//
// The preimage is the card without its signature member, under the APS
// canonicalize (sorted keys, null and undefined object members removed). The
// key is card.publicKey. Only the primitives move: sign, verify and canonicalize
// still come from the SDK, which produces byte-identical signatures and canonical
// strings across 1.x and 8.x for the inputs tested in tests/sdk-compat.test.ts.

import { verify, canonicalize } from 'agent-passport-system'
import type { IntentCard } from 'agent-passport-system'

export function verifyIntentCard(card: IntentCard): boolean {
  const { signature, ...unsigned } = card
  return verify(canonicalize(unsigned), signature, card.publicKey)
}

/** True when expiresAt is before now, or cannot be read as a time. The 1.x SDK
 *  treated an unparseable expiresAt as not expired, because an Invalid Date
 *  compares false, so a card with a garbage expiry was accepted and never
 *  expired. That is the invalid-timestamp class in GHSA-r2fw-x6mg-f6h8, so this
 *  fails closed instead. A valid expiresAt gives the same answer as before. */
export function isCardExpired(card: IntentCard): boolean {
  const at = Date.parse(String(card.expiresAt))
  return Number.isNaN(at) || at < Date.now()
}
