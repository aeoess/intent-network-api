// ══════════════════════════════════════════════════════════════
// deriveIntroState, the derived expiry, the guards, pending_actions
// ══════════════════════════════════════════════════════════════
// This is where the lifecycle is actually specified. The module is pure and takes
// its clock as a parameter, so every case is a table row rather than a scenario
// with a server in it.
//
// The assertions that carry the most weight:
//   the materialized status cannot override a durable fact, in both directions
//   a release row is historical and never becomes expired
//   a continuation sets a new expiry from its own time, and a read moves nothing
//   the 104 cell guard matrix, which is how a route that forgot a guard is found

import { test } from 'node:test'
import assert from 'node:assert/strict'

const s = await import('../src/connection-state.js')
type AuthFact = import('../src/connection-state.js').AuthFact
type IntroFacts = import('../src/connection-state.js').IntroFacts
type Operation = import('../src/connection-state.js').Operation
type IntroState = import('../src/connection-state.js').IntroState

const T0 = '2026-09-01T00:00:00.000Z'
const REQ = 'key-requester'
const TGT = 'key-target'

const at = (isoDays: number) => new Date(Date.parse(T0) + isoDays * 24 * 3600 * 1000).toISOString()

function facts(over: Partial<IntroFacts> = {}): IntroFacts {
  return {
    intro_id: 'intro-test-1',
    created_at: T0,
    from_key: REQ,
    to_key: TGT,
    authorizations: [],
    released: false,
    ...over,
  }
}
function auth(operation: Operation, actor_key: string, over: Partial<AuthFact> = {}): AuthFact {
  return { operation, actor_key, subject: '', live: true, created_at: T0, evidence: 'canonical', ...over }
}

const requested = () => facts({ authorizations: [auth('request_intro', REQ)] })
const interested = () => facts({ authorizations: [auth('request_intro', REQ), auth('express_interest', TGT)] })
const connecting = (op: Operation = 'share_contact', actor = REQ, created = T0) =>
  facts({ authorizations: [auth('request_intro', REQ), auth('express_interest', TGT), auth(op, actor, { created_at: created })] })
const connected = () => facts({
  authorizations: [auth('request_intro', REQ), auth('express_interest', TGT), auth('share_contact', REQ), auth('share_contact', TGT)],
  released: true,
})

// ── The eight states, each by its own path ────────────────────────────────

test('DERIVE: each of the eight states is reached by its own fact set', () => {
  const table: [string, IntroFacts, IntroState][] = [
    ['no facts at all', facts(), 'requested'],
    ['request only', requested(), 'requested'],
    ['mutual interest, no continuation', interested(), 'interested'],
    ['mutual interest plus a continuation', connecting(), 'connecting'],
    ['a release row', connected(), 'connected'],
    ['a live decline fact', facts({ authorizations: [auth('request_intro', REQ), auth('decline', TGT)] }), 'declined'],
    ['a live block fact', facts({ authorizations: [auth('request_intro', REQ), auth('block_pair', TGT)] }), 'blocked'],
    ['request withdrawn', facts({ authorizations: [auth('request_intro', REQ, { live: false })] }), 'withdrawn'],
  ]
  for (const [label, f, want] of table) {
    assert.equal(s.deriveIntroState(f, new Date(T0)), want, label)
  }
  assert.equal(s.INTRO_STATES.length, 8)
})

test('DERIVE: the function is total over an empty fact set and answers requested', () => {
  assert.equal(s.deriveIntroState(facts({ authorizations: [] }), new Date(T0)), 'requested')
})

test('DERIVE: interest withdrawn after having been expressed is withdrawn, not requested', () => {
  // A row that never existed is not a withdrawal. A row that exists and is no
  // longer live is. That distinction is the whole reason withdrawal needs no
  // terminal fact of its own.
  const never = facts({ authorizations: [auth('request_intro', REQ)] })
  assert.equal(s.deriveIntroState(never, new Date(T0)), 'requested')
  const withdrew = facts({ authorizations: [auth('request_intro', REQ), auth('express_interest', TGT, { live: false })] })
  assert.equal(s.deriveIntroState(withdrew, new Date(T0)), 'withdrawn')
})

// ── connected is historical ───────────────────────────────────────────────

test('DERIVE: a release row is historical and outranks every later fact', () => {
  const base = connected()
  const withDecline = { ...base, authorizations: [...base.authorizations, auth('decline', TGT)] }
  assert.equal(s.deriveIntroState(withDecline, new Date(T0)), 'connected', 'a decline does not unmake a released connection')
  const withBlock = { ...base, authorizations: [...base.authorizations, auth('block_pair', TGT)] }
  assert.equal(s.deriveIntroState(withBlock, new Date(T0)), 'connected', 'nor does a block')
  const withWithdrawal = { ...base, authorizations: base.authorizations.map(a => a.operation === 'express_interest' ? { ...a, live: false } : a) }
  assert.equal(s.deriveIntroState(withWithdrawal, new Date(T0)), 'connected', 'nor a later withdrawal')
})

test('DERIVE: connected never becomes expired, at any distance', () => {
  assert.equal(s.expiryOf(connected()), null, 'no lifecycle expiry once released')
  assert.equal(s.deriveIntroState(connected(), new Date('2099-01-01T00:00:00.000Z')), 'connected')
  assert.equal(s.isExpired(connected(), new Date('2099-01-01T00:00:00.000Z')), false)
})

test('DERIVE: a block after a release writes no intro level fact, which is what the write does', () => {
  // The conditional write is in the route. Here the pair that pins it: with a
  // release and NO blocked fact the state is connected, and with a blocked fact
  // and no release it is blocked.
  assert.equal(s.deriveIntroState(connected(), new Date(T0)), 'connected')
  const blockedBefore = facts({ authorizations: [auth('request_intro', REQ), auth('express_interest', TGT), auth('block_pair', REQ)] })
  assert.equal(s.deriveIntroState(blockedBefore, new Date(T0)), 'blocked')
})

// ── Terminal precedence ───────────────────────────────────────────────────

test('DERIVE: declined beats expired', () => {
  const f = facts({ authorizations: [auth('request_intro', REQ), auth('decline', TGT)] })
  assert.equal(s.deriveIntroState(f, new Date(at(400))), 'declined', 'a declined intro long past its TTL still reads declined')
})

test('DERIVE: withdrawn beats expired', () => {
  const f = facts({ authorizations: [auth('request_intro', REQ, { live: false })] })
  assert.equal(s.deriveIntroState(f, new Date(at(400))), 'withdrawn')
})

// ── Mutual interest is required ───────────────────────────────────────────

test('DERIVE: a continuation with no live interest derives requested, not connecting', () => {
  // Every continuation route requires mutual interest before it accepts a write,
  // so this fact set should not arise. If it does, the truthful answer is that the
  // pair never expressed interest.
  const f = facts({ authorizations: [auth('request_intro', REQ), auth('share_contact', REQ)] })
  assert.equal(s.hasMutualInterest(f), false)
  assert.equal(s.deriveIntroState(f, new Date(T0)), 'requested')
})

test('DERIVE: a continuation with a withdrawn interest derives withdrawn', () => {
  const f = facts({ authorizations: [auth('request_intro', REQ), auth('express_interest', TGT, { live: false }), auth('share_contact', REQ)] })
  assert.equal(s.deriveIntroState(f, new Date(T0)), 'withdrawn')
})

// ── withdraw_contact recomputes from facts ────────────────────────────────

test('DERIVE: withdraw_contact with another live continuation stays connecting', () => {
  const f = facts({
    authorizations: [
      auth('request_intro', REQ), auth('express_interest', TGT),
      auth('share_contact', REQ, { live: false }),
      auth('fit_request', REQ),
    ],
  })
  assert.equal(s.deriveIntroState(f, new Date(T0)), 'connecting', 'the fit continuation is still live')
})

test('DERIVE: withdraw_contact with no other live continuation falls back to interested', () => {
  // The recompute-from-facts answer. There is no sticky connecting, because there
  // is no sticky anything.
  const f = facts({
    authorizations: [auth('request_intro', REQ), auth('express_interest', TGT), auth('share_contact', REQ, { live: false })],
  })
  assert.equal(s.deriveIntroState(f, new Date(T0)), 'interested')
})

// ── Expiry, derived ───────────────────────────────────────────────────────

test('EXPIRY: requested is 14 days from the intro created_at, both sides of the boundary', () => {
  const f = requested()
  assert.equal(s.expiryOf(f), at(14))
  assert.equal(s.deriveIntroState(f, new Date(Date.parse(at(14)) - 1000)), 'requested')
  assert.equal(s.deriveIntroState(f, new Date(Date.parse(at(14)) + 1000)), 'expired')
})

test('EXPIRY: interested is 30 days from the interest authorization, not from the intro', () => {
  const f = facts({ authorizations: [auth('request_intro', REQ), auth('express_interest', TGT, { created_at: at(10) })] })
  assert.equal(s.expiryOf(f), at(40), 'the basis is the interest, so day 10 plus 30')
  assert.equal(s.deriveIntroState(f, new Date(at(39))), 'interested')
  assert.equal(s.deriveIntroState(f, new Date(at(41))), 'expired')
})

test('EXPIRY: connecting is 30 days from the MOST RECENT live continuation', () => {
  const f = facts({
    authorizations: [
      auth('request_intro', REQ), auth('express_interest', TGT, { created_at: at(1) }),
      auth('share_contact', REQ, { created_at: at(5) }),
      auth('fit_request', REQ, { created_at: at(20) }),
    ],
  })
  assert.equal(s.expiryOf(f), at(50), 'day 20 plus 30, not day 5 plus 30')
  assert.equal(s.deriveIntroState(f, new Date(at(49))), 'connecting')
  assert.equal(s.deriveIntroState(f, new Date(at(51))), 'expired')
})

test('EXPIRY: an accepted continuation sets a new window from its own time and never adds to the old one', () => {
  const day29 = facts({
    authorizations: [auth('request_intro', REQ), auth('express_interest', TGT), auth('share_contact', REQ, { created_at: at(29) })],
  })
  assert.equal(s.expiryOf(day29), at(59), 'day 29 plus 30, which is a new window and not 30 added to an existing one')
  // A second continuation at day 40 moves it to day 70, again from its own time.
  const day40 = facts({
    authorizations: [...day29.authorizations, auth('fit_commit', TGT, { created_at: at(40) })],
  })
  assert.equal(s.expiryOf(day40), at(70))
})

test('EXPIRY: reading the facts a thousand times moves nothing', () => {
  const f = connecting('share_contact', REQ, at(5))
  const before = s.expiryOf(f)
  for (let i = 0; i < 1000; i++) { s.deriveIntroState(f, new Date(at(10 + i / 1000))); s.expiryOf(f) }
  assert.equal(s.expiryOf(f), before,
    'the deadline is derived from a row created_at, so nothing but a new row can move it')
})

test('EXPIRY: a withdrawn continuation moves the basis backward and cannot resurrect a lapsed intro', () => {
  const f = facts({
    authorizations: [
      auth('request_intro', REQ), auth('express_interest', TGT, { created_at: at(1) }),
      auth('share_contact', REQ, { created_at: at(40), live: false }),
    ],
  })
  // The only continuation is withdrawn, so the basis falls back to the interest.
  assert.equal(s.expiryOf(f), at(31))
  assert.equal(s.deriveIntroState(f, new Date(at(35))), 'expired')
})

// ── The materialized status cannot override a durable fact ────────────────

test('MATERIALIZATION: the mapping covers all eight states and stays inside IntroStatus', () => {
  const allowed = new Set(['pending', 'accepted', 'declined', 'withdrawn', 'blocked'])
  for (const st of s.INTRO_STATES) {
    assert.ok(allowed.has(s.materializedStatus(st)), `${st} materializes to a value IntroStatus admits`)
  }
  assert.equal(s.materializedStatus('expired'), 'withdrawn',
    'the one lossy cell: IntroStatus has no expired member, so the legacy column loses lapse versus retraction')
})

test('MATERIALIZATION: a status of accepted cannot make an intro with no interest fact derive past requested', () => {
  // The column is an output of the derivation, never an input. This is the
  // direction that would be a live bug if anything read it.
  const f = facts({ authorizations: [auth('request_intro', REQ)] })
  assert.equal(s.deriveIntroState(f, new Date(T0)), 'requested',
    'no interest fact, so no amount of status accepted makes this interested')
  assert.equal(s.materializedStatus(s.deriveIntroState(f, new Date(T0))), 'pending')
})

test('MATERIALIZATION: a released pair derives connected regardless of what a status column says', () => {
  const f = connected()
  assert.equal(s.deriveIntroState(f, new Date(T0)), 'connected')
  assert.equal(s.materializedStatus('connected'), 'accepted')
  // And the derivation reads no status at all: IntroFacts has no such field.
  assert.equal(Object.prototype.hasOwnProperty.call(f, 'status'), false)
})

// ── The 104 cell guard matrix ─────────────────────────────────────────────

test('GUARDS: the full matrix of TWENTY operations against eight states', () => {
  // It was thirteen by thirteen product actions when the vocabulary was thirteen. The
  // vocabulary is now twenty, so 56 of the 160 cells isWriteAllowedInState answers were
  // asserted nowhere, including every cell the non-intro early return decides. The file's own
  // comment calls this matrix "how a route that forgot a guard is found", so it has to cover
  // every operation the function accepts rather than the subset it used to.
  const expected: Record<string, IntroState[]> = {
    request_intro: [],
    withdraw_request: ['requested', 'interested'],
    express_interest: ['requested'],
    decline: ['requested'],
    block_pair: [...s.INTRO_STATES],
    withdraw_interest: ['interested'],
    share_contact: ['interested', 'connecting'],
    withdraw_contact: ['connecting'],
    fit_request: ['interested', 'connecting', 'connected'],
    fit_commit: ['interested', 'connecting', 'connected'],
    release_exact: ['interested', 'connecting', 'connected'],
    first_step_propose: ['interested', 'connecting', 'connected'],
    first_step_approve: ['interested', 'connecting', 'connected'],
    // The protocol sub-actions. fit_round2 and fit_answers name an INTRO and are
    // continuations, so they sit with the other fit acts. The five whose resource is a fit
    // exchange or a card name no intro at all, so there is no intro state in which they may
    // be written and every one of their cells is a refusal.
    fit_round2: ['interested', 'connecting', 'connected'],
    fit_answers: ['interested', 'connecting', 'connected'],
    fit_exchange_round2: [],
    fit_exchange_custom: [],
    fit_exchange_answers: [],
    fit_exchange_close: [],
    autonomy_pause: [],
  }
  const ALL_OPERATIONS = [...s.OPERATIONS, ...s.PROTOCOL_OPERATIONS]
  assert.equal(ALL_OPERATIONS.length, 20)
  assert.deepEqual(Object.keys(expected).sort(), [...ALL_OPERATIONS].sort(),
    'every operation the vocabulary has must have a row here, and nothing else may')
  let cells = 0
  for (const op of ALL_OPERATIONS) {
    for (const st of s.INTRO_STATES) {
      cells++
      const want = expected[op].includes(st)
      assert.equal(s.isWriteAllowedInState(op, st), want, `${op} in ${st} should be ${want ? 'allowed' : 'refused'}`)
    }
  }
  assert.equal(cells, 160, 'twenty operations against eight states')
  // And the five non-intro operations are refused in EVERY state, which is the early return
  // being a decision rather than a missing switch case returning undefined.
  for (const op of s.NON_INTRO_OPERATIONS) {
    for (const st of s.INTRO_STATES) {
      assert.equal(s.isWriteAllowedInState(op, st), false, `${op} in ${st}`)
      assert.equal(typeof s.isWriteAllowedInState(op, st), 'boolean')
    }
  }
})

test('GUARDS: every continuation requires mutual interest, so none is allowed in requested', () => {
  for (const op of s.CONTINUATIONS) {
    assert.equal(s.isWriteAllowedInState(op, 'requested'), false, `${op} refused in requested`)
  }
})

test('GUARDS: no action writes on a terminal intro except block_pair', () => {
  for (const st of ['declined', 'withdrawn', 'blocked', 'expired'] as IntroState[]) {
    for (const op of [...s.OPERATIONS, ...s.PROTOCOL_OPERATIONS]) {
      const want = op === 'block_pair'
      assert.equal(s.isWriteAllowedInState(op, st), want, `${op} in ${st}`)
    }
  }
})

test('GUARDS: each refusal carries a code whose remedy differs', () => {
  assert.equal(s.guardRefusal('withdraw_request', 'connecting').code, 'connection_in_progress')
  assert.equal(s.guardRefusal('withdraw_contact', 'connected').code, 'contact_already_released')
  assert.equal(s.guardRefusal('express_interest', 'declined').code, 'intro_terminal')
  assert.equal(s.guardRefusal('express_interest', 'connecting').code, 'wrong_state')
})

// ── pending_actions ───────────────────────────────────────────────────────

test('PENDING: requested offers the target a response and the requester a withdrawal', () => {
  const f = requested()
  assert.deepEqual(s.pendingActions(f, TGT, new Date(T0)), ['express_interest', 'decline', 'block_pair'])
  assert.deepEqual(s.pendingActions(f, REQ, new Date(T0)), ['withdraw_request', 'block_pair'])
})

test('PENDING: interested offers a contact to both sides', () => {
  const f = interested()
  const forReq = s.pendingActions(f, REQ, new Date(T0))
  assert.ok(forReq.includes('share_contact'))
  assert.ok(forReq.includes('withdraw_request'))
  const forTgt = s.pendingActions(f, TGT, new Date(T0))
  assert.ok(forTgt.includes('share_contact'))
  assert.ok(forTgt.includes('withdraw_interest'))
})

test('PENDING: the side that has shared is offered a withdrawal, not a second share', () => {
  const f = connecting('share_contact', REQ)
  const mine = s.pendingActions(f, REQ, new Date(T0))
  assert.equal(mine.includes('share_contact'), false, 'already shared')
  assert.ok(mine.includes('withdraw_contact'))
  const theirs = s.pendingActions(f, TGT, new Date(T0))
  assert.ok(theirs.includes('share_contact'), 'the other side has not')
  assert.equal(theirs.includes('withdraw_contact'), false)
})

test('PENDING: connected offers no contact action at all, and never withdraw_contact', () => {
  const out = s.pendingActions(connected(), REQ, new Date(T0))
  assert.equal(out.includes('withdraw_contact'), false, 'a released contact cannot be unshared')
  assert.equal(out.includes('share_contact'), false)
  assert.equal(out.includes('withdraw_request'), false, 'and a connection in progress is not withdrawn by retracting the request')
  assert.ok(out.includes('block_pair'), 'blocking future pair activity stays available')
})

test('PENDING: every terminal state offers nothing, and a stranger gets nothing', () => {
  for (const f of [
    facts({ authorizations: [auth('request_intro', REQ), auth('decline', TGT)] }),
    facts({ authorizations: [auth('request_intro', REQ, { live: false })] }),
    facts({ authorizations: [auth('request_intro', REQ), auth('block_pair', TGT)] }),
  ]) {
    assert.deepEqual(s.pendingActions(f, REQ, new Date(T0)), [])
    assert.deepEqual(s.pendingActions(f, TGT, new Date(T0)), [])
  }
  assert.deepEqual(s.pendingActions(requested(), 'key-stranger', new Date(T0)), [], 'not a party')
})

test('PENDING: it never offers an action the guard matrix would refuse', () => {
  // The negative assertion that makes the projection trustworthy rather than a
  // second, drifting copy of the rules.
  const sets = [requested(), interested(), connecting(), connected(),
    facts({ authorizations: [auth('request_intro', REQ), auth('decline', TGT)] })]
  for (const f of sets) {
    const state = s.deriveIntroState(f, new Date(T0))
    for (const actor of [REQ, TGT]) {
      for (const op of s.pendingActions(f, actor, new Date(T0))) {
        assert.equal(s.isWriteAllowedInState(op, state), true, `${op} offered in ${state} must pass the guard`)
      }
    }
  }
})
