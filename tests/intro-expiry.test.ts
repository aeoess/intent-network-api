// ══════════════════════════════════════════════════════════════
// Derived expiry, the renewal rule, and the sweep
// ══════════════════════════════════════════════════════════════
// EXPIRY IS NEVER STORED. It is derived from the created_at of authorization rows, and the
// clock is a parameter, which is why every boundary here is exact rather than approximate.
//
// That derivation is what makes the renewal rule structural rather than a discipline: the
// ONLY way to move a deadline is to insert a continuation authorization, and the only way
// to do that is to present a valid canonical envelope. A read writes no row. A poll writes
// no row. A notification writes no row. The sweep writes no row. There is no
// last_activity_at column to touch, because a column like that is exactly what gets
// touched by accident.
//
// The pair of tests that says this out loud: a signed continuation at day 29 moves the
// deadline to day 59, and the same intro read a thousand times in between does not move it
// at all.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { generateKeyPair } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-expiry-test-'))
process.env.DB_PATH = join(tmpDir, 'expiry.db')
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey

const db = await import('../src/db.js')
const wdb = await import('../src/write-db.js')
const introsDb = await import('../src/intros-db.js')
const facts = await import('../src/connection-facts.js')
const state = await import('../src/connection-state.js')

before(() => { db.getDb(); wdb.initWriteSchema(); introsDb.initIntrosSchema() })
after(() => { db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })

const DAY = 24 * 3600 * 1000
const iso = (t: number) => new Date(t).toISOString()
const T0 = Date.parse('2026-01-01T00:00:00.000Z')
const rid = () => randomBytes(4).toString('hex')

/** An intro row with an explicit created_at, and nothing else. */
function makeIntro(createdAt: number, status = 'pending'): { id: string; fromKey: string; toKey: string } {
  const id = `intro-v3-exp-${rid()}`
  const fromKey = 'a'.repeat(63) + rid()[0]
  const toKey = 'b'.repeat(63) + rid()[0]
  db.getDb().prepare(`
    INSERT INTO v3_intros (id, from_card, to_card, from_key, to_key, purpose, note, status, created_at)
    VALUES (?, ?, ?, ?, ?, 'collaborate', '', ?, ?)
  `).run(id, 'card-' + rid(), 'card-' + rid(), fromKey, toKey, status, iso(createdAt))
  return { id, fromKey, toKey }
}

function addAuth(introId: string, actorKey: string, operation: string, createdAt: number, opts: { subject?: string; live?: boolean } = {}): void {
  db.getDb().prepare(`
    INSERT INTO connection_authorizations (intro_id, actor_key, operation, subject, evidence_id, evidence, live, created_at)
    VALUES (?, ?, ?, ?, ?, 'canonical', ?, ?)
    ON CONFLICT(intro_id, actor_key, operation, subject) DO UPDATE SET live = excluded.live, created_at = excluded.created_at
  `).run(introId, actorKey, operation, opts.subject ?? '', 'ev-' + rid(), opts.live === false ? 0 : 1, iso(createdAt))
}

function statusOf(id: string): string {
  return (db.getDb().prepare('SELECT status FROM v3_intros WHERE id = ?').get(id) as any).status
}

// ══════════════════════════════════════════════════════════════
// One case per boundary, with the clock passed in
// ══════════════════════════════════════════════════════════════

test('EXPIRY: a requested intro derives requested at 14 days minus one second and expired one second later', () => {
  const i = makeIntro(T0)
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  const f = facts.introFacts(i.id)!

  assert.equal(state.expiryOf(f), iso(T0 + 14 * DAY), 'the deadline is the intro\'s own created_at plus 14 days')
  assert.equal(state.deriveIntroState(f, new Date(T0 + 14 * DAY - 1000)), 'requested')
  assert.equal(state.deriveIntroState(f, new Date(T0 + 14 * DAY + 1000)), 'expired')
  // The boundary itself is expired, because isExpired is `now >= deadline`.
  assert.equal(state.deriveIntroState(f, new Date(T0 + 14 * DAY)), 'expired')
})

test('EXPIRY: an interested intro measures 30 days from the interest authorization, not from the intro', () => {
  const i = makeIntro(T0)
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  // Interest arrives on day 10, which is inside the 14 day requested window.
  addAuth(i.id, i.toKey, 'express_interest', T0 + 10 * DAY)
  const f = facts.introFacts(i.id)!

  assert.equal(state.expiryOf(f), iso(T0 + 40 * DAY), 'day 10 plus 30, not day 0 plus 30')
  assert.equal(state.deriveIntroState(f, new Date(T0 + 40 * DAY - 1000)), 'interested')
  assert.equal(state.deriveIntroState(f, new Date(T0 + 40 * DAY + 1000)), 'expired')
  // And expressing interest ENDS the 14 day window by making rule 6 rather than rule 7 the
  // matching branch, so day 20 is alive where a requested intro would be long gone.
  assert.equal(state.deriveIntroState(f, new Date(T0 + 20 * DAY)), 'interested')
})

test('EXPIRY: a connecting intro measures 30 days from the MOST RECENT live continuation', () => {
  const i = makeIntro(T0)
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  addAuth(i.id, i.toKey, 'express_interest', T0 + 1 * DAY)
  addAuth(i.id, i.fromKey, 'share_contact', T0 + 2 * DAY)
  const f = facts.introFacts(i.id)!
  assert.equal(state.expiryOf(f), iso(T0 + 32 * DAY))
  assert.equal(state.deriveIntroState(f, new Date(T0 + 32 * DAY - 1000)), 'connecting')
  assert.equal(state.deriveIntroState(f, new Date(T0 + 32 * DAY + 1000)), 'expired')
})

test('EXPIRY: a connecting intro whose LAST continuation was 31 days ago expires, even with an earlier one inside the window', () => {
  // The case that pins the basis as the most recent continuation rather than any of them.
  // The earlier continuation is more recent than 31 days from the interest, so a design that
  // measured from the interest, or from the first continuation, would answer connecting.
  const i = makeIntro(T0)
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  addAuth(i.id, i.toKey, 'express_interest', T0 + 20 * DAY)
  addAuth(i.id, i.fromKey, 'share_contact', T0 + 25 * DAY)
  addAuth(i.id, i.toKey, 'fit_request', T0 + 30 * DAY)
  const f = facts.introFacts(i.id)!

  assert.equal(state.expiryOf(f), iso(T0 + 60 * DAY), 'day 30 is the most recent, so day 60 is the deadline')
  const at61 = new Date(T0 + 61 * DAY)
  assert.equal(state.deriveIntroState(f, at61), 'expired')
  // And the sanity check that makes the case meaningful: measuring from the interest would
  // have given day 50, which is also past, so use a clock where the two answers differ.
  const at55 = new Date(T0 + 55 * DAY)
  assert.equal(state.deriveIntroState(f, at55), 'connecting',
    'day 55 is past interest plus 30 and inside continuation plus 30, and the continuation wins')
})

test('EXPIRY: a withdrawn continuation moves the basis BACKWARD, which is the one case the deadline comes closer', () => {
  const i = makeIntro(T0)
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  addAuth(i.id, i.toKey, 'express_interest', T0 + 1 * DAY)
  addAuth(i.id, i.fromKey, 'share_contact', T0 + 20 * DAY)
  let f = facts.introFacts(i.id)!
  assert.equal(state.expiryOf(f), iso(T0 + 50 * DAY))

  // Withdraw it. The window measures live activity, and there is now less of it.
  addAuth(i.id, i.fromKey, 'share_contact', T0 + 20 * DAY, { live: false })
  f = facts.introFacts(i.id)!
  assert.equal(state.expiryOf(f), iso(T0 + 31 * DAY), 'back to the interest authorization plus 30')
  assert.equal(state.deriveIntroState(f, new Date(T0 + 40 * DAY)), 'expired',
    'so a clock that was inside the old window is outside the new one')
})

test('EXPIRY: a released connection has no lifecycle expiry, at a year or at ten', () => {
  const i = makeIntro(T0, 'accepted')
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  addAuth(i.id, i.toKey, 'express_interest', T0 + 1 * DAY)
  addAuth(i.id, i.fromKey, 'share_contact', T0 + 2 * DAY)
  addAuth(i.id, i.toKey, 'share_contact', T0 + 2 * DAY)
  db.getDb().prepare('INSERT INTO connection_release (intro_id) VALUES (?)').run(i.id)
  const f = facts.introFacts(i.id)!

  assert.equal(state.expiryOf(f), null, 'connected is historical and is never later expired')
  assert.equal(state.deriveIntroState(f, new Date(T0 + 365 * DAY)), 'connected')
  assert.equal(state.deriveIntroState(f, new Date(T0 + 3650 * DAY)), 'connected')
})

test('EXPIRY: the grandfathered row expires on the same rule as everything else', () => {
  // "Until terminal or expired" requires that a pre-2A row lapse too, so the rule is one
  // rule and there is no production-id specific code anywhere.
  const marker = db.getSchemaMarker(db.MINGLE_2A_MARKER_KEY)!
  const before2A = Date.parse(marker) - 400 * DAY
  const i = makeIntro(before2A)
  addAuth(i.id, i.fromKey, 'request_intro', before2A)
  assert.equal(facts.isPre2AIntro(i.id), true)
  const f = facts.introFacts(i.id)!
  assert.equal(state.expiryOf(f), iso(before2A + 14 * DAY))
  assert.equal(state.deriveIntroState(f, new Date(before2A + 13 * DAY)), 'requested')
  assert.equal(state.deriveIntroState(f, new Date(before2A + 15 * DAY)), 'expired')
})

// ══════════════════════════════════════════════════════════════
// The renewal rule, as a pair
// ══════════════════════════════════════════════════════════════

test('RENEWAL: a signed continuation at day 29 moves the deadline to day 59', () => {
  const i = makeIntro(T0)
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  addAuth(i.id, i.toKey, 'express_interest', T0)
  assert.equal(state.expiryOf(facts.introFacts(i.id)!), iso(T0 + 30 * DAY))

  addAuth(i.id, i.fromKey, 'share_contact', T0 + 29 * DAY)
  assert.equal(state.expiryOf(facts.introFacts(i.id)!), iso(T0 + 59 * DAY),
    'a NEW expiry from the continuation\'s own time, never an addition to the previous one')

  // And it never accumulates: a second continuation one day later sets day 60, not day 89.
  addAuth(i.id, i.toKey, 'share_contact', T0 + 30 * DAY)
  assert.equal(state.expiryOf(facts.introFacts(i.id)!), iso(T0 + 60 * DAY),
    'so a long running connection cannot build an unbounded window')
})

test('RENEWAL: the same intro read a thousand times does not move the deadline at all', () => {
  const i = makeIntro(T0)
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  addAuth(i.id, i.toKey, 'express_interest', T0 + 5 * DAY)
  const deadline = state.expiryOf(facts.introFacts(i.id)!)
  assert.equal(deadline, iso(T0 + 35 * DAY))

  for (let n = 0; n < 1000; n++) {
    const f = facts.introFacts(i.id)!
    assert.equal(state.expiryOf(f), deadline)
    // Every read surface, not only the fact reader: the state, the projection and the
    // pending action list all go through the same derivation.
    state.deriveIntroState(f, new Date(T0 + 10 * DAY))
    facts.introProjection(i.id, i.fromKey, new Date(T0 + 10 * DAY))
    facts.stateOf(i.id, new Date(T0 + 10 * DAY))
  }
  assert.equal(state.expiryOf(facts.introFacts(i.id)!), deadline,
    'a read writes no row, so there is nothing that could have moved it')

  // And the sweep does not move it either, which is the one background job that looks at
  // every row.
  facts.sweepExpiredIntros(new Date(T0 + 10 * DAY))
  assert.equal(state.expiryOf(facts.introFacts(i.id)!), deadline)
  const rows = (db.getDb().prepare(
    'SELECT COUNT(*) AS n FROM connection_authorizations WHERE intro_id = ?').get(i.id) as any).n
  assert.equal(rows, 2, 'and the sweep inserted no authorization row, so it cannot renew anything')
})

test('EXPIRY: KNOWN GAP, withdrawing the last continuation past a stale interest expires the intro', () => {
  // Found by a review and deliberately NOT changed, because the TTL rule it rests on is settled
  // architecture and this is a gap in that rule rather than a defect in its implementation.
  //
  // The two design sentences diverge here. Item 6 of withdraw_contact says the basis "moves
  // backward to whatever live continuation remains, or to the express_interest authorization if
  // none does". The same item also says that if the withdrawn contact was the only connecting
  // class authorization, "the state regresses to interested". When the interest is more than 30
  // days old those give DIFFERENT answers, and the design does not address the case: its only
  // statement about the direction is that a withdrawal "cannot resurrect an already lapsed
  // intro", which is about an intro that had already expired, not one the withdrawal expires.
  //
  // The product consequence is real: a pair demonstrably active six days ago is killed outright
  // by one party rescinding their own contact line, which punishes the safest act a user can
  // take. My recommendation is in the handoff. Pinned here so the behavior is KNOWN rather than
  // discovered, and so a later ruling changes a red test rather than a silent answer.
  const i = makeIntro(T0)
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  addAuth(i.id, i.toKey, 'express_interest', T0 + 1 * DAY)
  addAuth(i.id, i.toKey, 'share_contact', T0 + 29 * DAY)
  const at35 = new Date(T0 + 35 * DAY)

  const before = facts.introFacts(i.id)!
  assert.equal(state.deriveIntroState(before, at35), 'connecting')
  assert.equal(state.expiryOf(before), iso(T0 + 59 * DAY), 'the signed continuation bought until day 59')
  assert.equal(state.isWriteAllowedInState('withdraw_contact', 'connecting'), true, 'so the guard admits the write')

  addAuth(i.id, i.toKey, 'share_contact', T0 + 29 * DAY, { live: false })
  const after = facts.introFacts(i.id)!
  assert.equal(state.expiryOf(after), iso(T0 + 31 * DAY), 'the basis falls back to the interest, which is already past')
  assert.equal(state.deriveIntroState(after, at35), 'expired',
    'so the intro expires as a RESULT of the withdrawal, at a clock where it was alive before it')
  assert.deepEqual(state.pendingActions(after, i.fromKey, at35), [], 'and the pair has nothing left but a block')
  assert.equal(state.materializedStatus('expired'), 'withdrawn')
})

// ══════════════════════════════════════════════════════════════
// The sweep
// ══════════════════════════════════════════════════════════════

test('SWEEP: it materializes a lapsed row and leaves a live one alone', () => {
  const lapsed = makeIntro(T0)
  addAuth(lapsed.id, lapsed.fromKey, 'request_intro', T0)
  const live = makeIntro(T0 + 100 * DAY)
  addAuth(live.id, live.fromKey, 'request_intro', T0 + 100 * DAY)

  const now = new Date(T0 + 101 * DAY)
  const swept = facts.sweepExpiredIntros(now)
  assert.ok(swept.includes(lapsed.id), 'the lapsed row is materialized')
  assert.equal(swept.includes(live.id), false, 'and the live one is not touched')
  assert.equal(statusOf(lapsed.id), 'withdrawn',
    'expired is the one lossy cell: IntroStatus has no expired member, so it maps to withdrawn')
  assert.equal(statusOf(live.id), 'pending')
  // The derivation still answers `expired`, so the distinction is recoverable by anything
  // that looks past the column.
  assert.equal(state.deriveIntroState(facts.introFacts(lapsed.id)!, now), 'expired')
})

test('SWEEP: it is idempotent, and a second pass reports nothing', () => {
  const i = makeIntro(T0)
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  const now = new Date(T0 + 50 * DAY)
  const first = facts.sweepExpiredIntros(now)
  assert.ok(first.includes(i.id))
  const second = facts.sweepExpiredIntros(now)
  assert.equal(second.includes(i.id), false,
    'the row now reads withdrawn, so the candidate filter no longer selects it')
})

test('SWEEP: it writes NOTHING except the status column', () => {
  const i = makeIntro(T0)
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  const d = db.getDb()
  const counts = () => ({
    auths: (d.prepare('SELECT COUNT(*) AS n FROM connection_authorizations').get() as any).n,
    nonces: (d.prepare('SELECT COUNT(*) AS n FROM write_nonces').get() as any).n,
    evidence: (d.prepare('SELECT COUNT(*) AS n FROM write_evidence').get() as any).n,
    releases: (d.prepare('SELECT COUNT(*) AS n FROM connection_release').get() as any).n,
    artifacts: (d.prepare('SELECT COUNT(*) AS n FROM private_artifacts').get() as any).n,
    receipts: (d.prepare('SELECT COUNT(*) AS n FROM lifecycle_receipts').get() as any).n,
  })
  const before = counts()
  const swept = facts.sweepExpiredIntros(new Date(T0 + 50 * DAY))
  assert.ok(swept.length > 0, 'it did do something')
  assert.deepEqual(counts(), before, 'and that something was the column and nothing else')
})

test('SWEEP: the candidate filter actually filters, which is the clock bug db.ts:20-25 documents', () => {
  // Comparing an ISO string against SQLite's datetime('now') is lexically broken, because
  // 'T' > ' ' makes such a comparison always true. This proves the filter selects a strict
  // subset rather than everything: a row inside the shortest TTL is not even a candidate.
  const young = makeIntro(T0 + 200 * DAY)
  addAuth(young.id, young.fromKey, 'request_intro', T0 + 200 * DAY)
  const old = makeIntro(T0 + 100 * DAY)
  addAuth(old.id, old.fromKey, 'request_intro', T0 + 100 * DAY)

  const now = new Date(T0 + 201 * DAY)
  const earliest = iso(now.getTime() - 14 * DAY)
  const candidates = db.getDb().prepare(`
    SELECT id FROM v3_intros WHERE status IN ('pending', 'accepted') AND created_at < ?
  `).all(earliest) as { id: string }[]
  const ids = candidates.map(c => c.id)
  assert.equal(ids.includes(old.id), true, 'a row older than the shortest TTL is a candidate')
  assert.equal(ids.includes(young.id), false,
    'and one younger is not, so the comparison is doing work rather than passing everything')

  // The broken form, shown failing, so the reason for the rule lives in the test rather
  // than only in a comment. The bug bites exactly when the DATE parts are equal: position 11
  // then decides, and an ISO string has 'T' (0x54) where datetime('now') has a space (0x20),
  // so the ISO string always compares LARGER and "is this in the future" is always yes.
  const todayMidnight = new Date().toISOString().slice(0, 10) + 'T00:00:00.000Z'
  const past = makeIntro(Date.parse(todayMidnight))
  const brokenFuture = db.getDb().prepare(
    "SELECT COUNT(*) AS n FROM v3_intros WHERE id = ? AND created_at > datetime('now')").get(past.id) as any
  assert.equal(brokenFuture.n, 1,
    "a row from midnight today reads as being in the FUTURE, because 'T' > ' ' decides once the dates match")
  const soundFuture = db.getDb().prepare(
    'SELECT COUNT(*) AS n FROM v3_intros WHERE id = ? AND created_at > ?').get(past.id, new Date().toISOString()) as any
  assert.equal(soundFuture.n, 0, 'while an ISO parameter compares against an ISO column correctly')
  // Which is why nothing in the write subsystem calls a SQL clock in a comparison: it either
  // binds a parameter, as the sweep does, or writes with SQL_NOW_ISO.
  const usesSqlClock = db.getDb().prepare(
    "SELECT COUNT(*) AS n FROM v3_intros WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ','now')").get() as any
  assert.ok(usesSqlClock.n > 0, 'and SQL_NOW_ISO is the form that does work in a comparison')

  // The sweep itself, which uses the sound form, selects exactly the expired subset.
  const swept = facts.sweepExpiredIntros(now)
  assert.equal(swept.includes(old.id), true)
  assert.equal(swept.includes(young.id), false)
})

test('SWEEP: the shortest TTL bound is sound, so nothing expired is ever missed', () => {
  // The filter rests on one argument: every expiry basis is at or after the intro's own
  // created_at, so the earliest any intro can expire is created_at plus 14 days. This walks
  // the three bases and checks that claim directly.
  const now = new Date(T0 + 500 * DAY)
  for (const build of [
    (i: ReturnType<typeof makeIntro>) => { addAuth(i.id, i.fromKey, 'request_intro', T0) },
    (i: ReturnType<typeof makeIntro>) => {
      addAuth(i.id, i.fromKey, 'request_intro', T0)
      addAuth(i.id, i.toKey, 'express_interest', T0 + 3 * DAY)
    },
    (i: ReturnType<typeof makeIntro>) => {
      addAuth(i.id, i.fromKey, 'request_intro', T0)
      addAuth(i.id, i.toKey, 'express_interest', T0 + 3 * DAY)
      addAuth(i.id, i.fromKey, 'share_contact', T0 + 9 * DAY)
    },
  ]) {
    const i = makeIntro(T0)
    build(i)
    const deadline = state.expiryOf(facts.introFacts(i.id)!)!
    assert.ok(Date.parse(deadline) >= T0 + 14 * DAY,
      `a basis produced ${deadline}, earlier than created_at plus 14 days, which would break the filter`)
    assert.equal(state.deriveIntroState(facts.introFacts(i.id)!, now), 'expired')
    assert.ok(facts.sweepExpiredIntros(now).includes(i.id), 'and the sweep finds it')
  }
})

test('SWEEP: a terminal row is never a candidate, so a decline is not rewritten as withdrawn', () => {
  const i = makeIntro(T0, 'declined')
  addAuth(i.id, i.fromKey, 'request_intro', T0)
  addAuth(i.id, i.toKey, 'decline', T0 + 1 * DAY)
  const swept = facts.sweepExpiredIntros(new Date(T0 + 500 * DAY))
  assert.equal(swept.includes(i.id), false, "the filter reads status IN ('pending','accepted')")
  assert.equal(statusOf(i.id), 'declined')
  // And the derivation agrees: rule 2 sits above rule 4, so a terminal fact outranks expiry.
  assert.equal(state.deriveIntroState(facts.introFacts(i.id)!, new Date(T0 + 500 * DAY)), 'declined')
})
