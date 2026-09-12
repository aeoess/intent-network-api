import {
  deriveIntroState, expiryOf, isWriteAllowedInState, pendingActions, materializedStatus,
} from './src/connection-state.js'
import type { IntroFacts, AuthFact } from './src/connection-state.js'

const T0 = Date.parse('2026-01-01T00:00:00.000Z')
const day = (n: number) => new Date(T0 + n * 86400_000)
const iso = (n: number) => day(n).toISOString()

function a(operation: string, actor: string, createdDay: number, live = true): AuthFact {
  return { operation: operation as any, actor_key: actor, subject: '', live, created_at: iso(createdDay), evidence: 'canonical' }
}

const REQ = 'key-requester'
const TGT = 'key-target'

// ══════════════════════════════════════════════════════════════
// B: withdraw_contact in `connecting` derives `expired`, not `interested`
// ══════════════════════════════════════════════════════════════
{
  const before: IntroFacts = {
    intro_id: 'i-B', created_at: iso(0), from_key: REQ, to_key: TGT, released: false,
    authorizations: [
      a('request_intro', REQ, 0),
      a('express_interest', TGT, 1),
      a('share_contact', TGT, 29),
    ],
  }
  const now = day(35)
  console.log('== FINDING B ==')
  console.log(' before withdraw_contact: state =', deriveIntroState(before, now), ' expiry =', expiryOf(before))
  console.log('   withdraw_contact allowed in that state?', isWriteAllowedInState('withdraw_contact', deriveIntroState(before, now)))
  const after: IntroFacts = {
    ...before,
    authorizations: [
      a('request_intro', REQ, 0),
      a('express_interest', TGT, 1),
      a('share_contact', TGT, 29, false), // withdraw_contact flips live
    ],
  }
  console.log(' after  withdraw_contact: state =', deriveIntroState(after, now), ' expiry =', expiryOf(after))
  console.log('   route comment promises "regresses to interested"; materialized column =', materializedStatus(deriveIntroState(after, now)))
  console.log('   pending_actions requester =', pendingActions(after, REQ, now))
  console.log('   pending_actions target    =', pendingActions(after, TGT, now))
}

// ══════════════════════════════════════════════════════════════
// A (derivation half): a completed legacy connection derives `expired`
// ══════════════════════════════════════════════════════════════
{
  const legacyComplete: IntroFacts = {
    intro_id: 'i-A', created_at: iso(0), from_key: REQ, to_key: TGT,
    authorizations: [],          // pre-2A: the write subsystem did not exist
    released: false,             // connection_release only exists for canonical-lane releases
  }
  const now = day(60)
  console.log('\n== FINDING A (derivation half) ==')
  console.log(' facts: status=accepted, from_contact + to_contact both set, zero authorization rows')
  console.log(' state =', deriveIntroState(legacyComplete, now), ' expiry =', expiryOf(legacyComplete))
  console.log(' materialized column would be =', materializedStatus(deriveIntroState(legacyComplete, now)))
}

// ══════════════════════════════════════════════════════════════
// C: a pre-2A intro whose target accepted post-2A derives `requested`
// ══════════════════════════════════════════════════════════════
{
  // The legacy /respond accept adapter (intros-routes.ts:364-368) writes express_interest
  // AND share_contact for the TARGET, and correctly writes no row for the requester.
  // On a pre-2A intro the requester has no request_intro row and nothing ever backfills one.
  const facts: IntroFacts = {
    intro_id: 'i-C', created_at: iso(0), from_key: REQ, to_key: TGT, released: false,
    authorizations: [
      { ...a('express_interest', TGT, 10), evidence: 'legacy_unbound' },
      { ...a('share_contact', TGT, 10), evidence: 'legacy_unbound' },
    ],
  }
  const now = day(12)
  const state = deriveIntroState(facts, now)
  console.log('\n== FINDING C ==')
  console.log(' facts: live express_interest + live share_contact by the target, no request_intro row')
  console.log(' state =', state, ' expiry =', expiryOf(facts))
  console.log(' materialized column =', materializedStatus(state), '  (v3_intros.status is "accepted" before this)')
  console.log(' requester may canonically share_contact?', isWriteAllowedInState('share_contact', state))
  console.log(' target may canonically decline?         ', isWriteAllowedInState('decline', state))
  console.log(' target may re-express_interest?         ', isWriteAllowedInState('express_interest', state))
  console.log(' pending_actions requester =', pendingActions(facts, REQ, now))
  console.log(' pending_actions target    =', pendingActions(facts, TGT, now))
}
