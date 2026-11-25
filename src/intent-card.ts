// ══════════════════════════════════════════════════════════════
// 48h IntentCard checks
// ══════════════════════════════════════════════════════════════
// agent-passport-system 2.0 moved the IntentNetwork helpers out of the SDK. In
// 8.1.1 verifyIntentCard and isCardExpired are not exported from the package
// root at all, and the internal module only throws.
// These are the two this API calls, kept here with the behaviour of the 1.x SDK
// (dist/src/core/intent-network.js in 1.13.0), so the preimage and the expiry
// rule do not change. A card signed with an admissible key by a 1.x client keeps
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

/** True when expiresAt is before now. An unparseable expiresAt is not expired,
 *  as in the 1.x SDK, because an Invalid Date compares false. */
export function isCardExpired(card: IntentCard): boolean {
  return new Date(card.expiresAt) < new Date()
}
