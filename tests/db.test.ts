// ══════════════════════════════════════════════════════════════
// DB layer tests — cards, intros, rate limits, embeddings, trust
// ══════════════════════════════════════════════════════════════
// Runs against a throwaway SQLite file in a fresh temp directory.
// DB_PATH is set BEFORE the first getDb() call (db.ts resolves it
// lazily), so this never touches data/intent-network.db or the
// live Railway service.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const tmpDir = mkdtempSync(join(tmpdir(), 'intent-net-db-test-'))
process.env.DB_PATH = join(tmpDir, 'test.db')

const db = await import('../src/db.js')
const cardEvents = await import('../src/card-events.js')

function makeCard(agentId: string, opts: { expiresInMs?: number, publicKey?: string, needs?: any[], offers?: any[] } = {}) {
  const now = Date.now()
  return {
    cardId: `card-${agentId}-${now}`,
    agentId,
    principalAlias: `${agentId} alias`,
    publicKey: opts.publicKey || `pk-${agentId}`,
    needs: opts.needs ?? [{ category: 'engineering', description: `need of ${agentId}`, priority: 'high', tags: [], visibility: 'public' }],
    offers: opts.offers ?? [{ category: 'funding', description: `offer of ${agentId}`, priority: 'medium', tags: [], visibility: 'public' }],
    openTo: ['introductions'],
    notOpenTo: [],
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + (opts.expiresInMs ?? 3600_000)).toISOString(),
    signature: 'unit-test-signature',
  } as any
}

// Unit-length basis vectors: e(i) . e(i) = 1, e(i) . e(j) = 0
function basisVec(i: number, dim = 8): Float32Array {
  const v = new Float32Array(dim)
  v[i] = 1
  return v
}

before(() => {
  db.getDb() // opens the temp DB, creates schema
})

after(() => {
  db.closeDb()
  rmSync(tmpDir, { recursive: true, force: true })
})

test('DB file is the temp file, not the repo data dir', () => {
  const file = (db.getDb() as any).name as string
  assert.equal(file, join(tmpDir, 'test.db'))
  assert.ok(!file.includes('data/intent-network.db'))
})

test('publishCard + getCard round-trips the full card', () => {
  const card = makeCard('alice')
  const result = db.publishCard(card)
  assert.equal(result.published, true)

  const fetched = db.getCard('alice')
  assert.ok(fetched, 'card should be retrievable')
  assert.equal(fetched!.cardId, card.cardId)
  assert.equal(fetched!.agentId, 'alice')
  assert.equal((fetched!.needs![0] as any).description, 'need of alice')
  assert.equal((fetched!.offers![0] as any).description, 'offer of alice')
  assert.equal(db.getCardCount(), 1)
})

test('re-publishing for the same agent updates in place (one card per agent)', () => {
  const updated = makeCard('alice', { needs: [{ category: 'x', description: 'UPDATED need', priority: 'high', tags: [], visibility: 'public' }] })
  db.publishCard(updated)
  assert.equal(db.getCardCount(), 1, 'still exactly one card for alice')
  const fetched = db.getCard('alice')
  assert.equal((fetched!.needs![0] as any).description, 'UPDATED need')
})

test('expired cards are deleted, and their disappearance is recorded', () => {
  const stale = makeCard('ghost-agent', { expiresInMs: -60_000 }) // already expired
  // Insert directly (publishCard purges first, so raw insert)
  db.getDb().prepare(`
    INSERT INTO cards (card_id, agent_id, public_key, principal_alias, card_json, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(stale.cardId, stale.agentId, stale.publicKey, stale.principalAlias, JSON.stringify(stale), stale.createdAt, stale.expiresAt)

  assert.equal(db.getCard('ghost-agent'), null, 'expired card must not be returned')
  db.purgeExpired()
  const row = db.getDb().prepare('SELECT COUNT(*) as c FROM cards WHERE agent_id = ?').get('ghost-agent') as any
  assert.equal(row.c, 0, 'the 48h body was published under an ephemeral promise and must be deleted')

  // Deleted, but no longer silently: exactly one event says so.
  const evs = cardEvents.eventsForCard(stale.cardId).filter(e => e.event === 'card_expired')
  assert.equal(evs.length, 1, 'exactly one card_expired event per deleted row')
  assert.equal(evs[0].subject_key, 'ghost-agent', 'the event records agent_id as the subject')
  const detail = JSON.parse(evs[0].detail_json!)
  assert.equal(detail.expires_at, stale.expiresAt, 'the event records when it lapsed')

  // The event must not smuggle the body back in.
  assert.deepEqual(Object.keys(detail), ['expires_at'], 'the event carries nothing but the expiry timestamp')
  const raw = JSON.stringify(evs[0])
  assert.equal(raw.includes(stale.principalAlias), false, 'no principal alias in the event')
  assert.equal(raw.includes('card_json'), false, 'no card body in the event')
  for (const need of stale.needs ?? []) {
    assert.equal(raw.includes(need.description), false, 'no card content in the event')
  }
})

test('a broken event log cannot keep an expired card body alive', () => {
  const stale = makeCard('doomed-agent', { expiresInMs: -60_000 })
  db.getDb().prepare(`
    INSERT INTO cards (card_id, agent_id, public_key, principal_alias, card_json, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(stale.cardId, stale.agentId, stale.publicKey, stale.principalAlias, JSON.stringify(stale), stale.createdAt, stale.expiresAt)

  // Break the event log the way a real breakage behaves: every insert into
  // card_events aborts. A trigger is used rather than dropping the table so the
  // failure cannot be routed around by a CREATE TABLE IF NOT EXISTS on the way
  // in - the table is present and writing to it still fails.
  db.getDb().exec('CREATE TABLE IF NOT EXISTS card_events (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, card_id TEXT, subject_key TEXT, event TEXT, detail_json TEXT)')
  db.getDb().exec("CREATE TRIGGER card_events_broken BEFORE INSERT ON card_events BEGIN SELECT RAISE(ABORT, 'event log is down'); END")
  let threw: unknown = null
  try {
    db.purgeExpired()
  } catch (e) {
    threw = e
  } finally {
    db.getDb().exec('DROP TRIGGER IF EXISTS card_events_broken')
  }

  // The invariant that matters most, asserted first: a broken log must never
  // be able to retain content the principal was promised would disappear.
  const remaining = db.getDb().prepare('SELECT COUNT(*) as c FROM cards WHERE agent_id = ?').get('doomed-agent') as any
  assert.equal(remaining.c, 0, 'a broken event log must NOT retain the expired card body')
  assert.equal(db.getCard('doomed-agent'), null)
  assert.equal(threw, null, 'purgeExpired must not throw when the event log is broken')

  // And the body is gone from the database entirely, not merely hidden.
  const anywhere = db.getDb().prepare("SELECT COUNT(*) as c FROM cards WHERE card_json LIKE ?").get(`%${stale.needs[0].description}%`) as any
  assert.equal(anywhere.c, 0, 'no card body may survive a logging failure')
  const inLog = db.getDb().prepare('SELECT COUNT(*) as c FROM card_events WHERE card_id = ?').get(stale.cardId) as any
  assert.equal(inLog.c, 0, 'the event genuinely did not get written, so this is the failure path')
})

test('the purge deletes only what has lapsed, once, and leaves live cards alone', () => {
  const live = makeCard('kept-agent')
  db.publishCard(live)
  const stale = makeCard('lapsed-agent', { expiresInMs: -60_000 })
  db.getDb().prepare(`
    INSERT INTO cards (card_id, agent_id, public_key, principal_alias, card_json, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(stale.cardId, stale.agentId, stale.publicKey, stale.principalAlias, JSON.stringify(stale), stale.createdAt, stale.expiresAt)

  const before = (db.getDb().prepare('SELECT COUNT(*) as c FROM cards').get() as any).c
  db.purgeExpired(); db.purgeExpired()   // second run has nothing left to do
  const after = (db.getDb().prepare('SELECT COUNT(*) as c FROM cards').get() as any).c
  assert.equal(after, before - 1, 'the lapsed row goes, the live one stays')
  assert.ok(db.getCard('kept-agent'), 'a live card is untouched by the purge')

  // One event, not two: the second purge found nothing to record.
  const evs = cardEvents.eventsForCard(stale.cardId).filter(e => e.event === 'card_expired')
  assert.equal(evs.length, 1, 'a re-run must not record the same expiry twice')

  // The explicit user delete path is untouched and still removes a live row.
  assert.equal(db.removeCard(live.cardId, live.publicKey), true)
  assert.equal((db.getDb().prepare('SELECT COUNT(*) as c FROM cards').get() as any).c, after - 1)
})

test('removeCard requires the owning public key', () => {
  const card = makeCard('bob')
  db.publishCard(card)
  assert.equal(db.removeCard(card.cardId, 'pk-of-somebody-else'), false, 'wrong key must not delete')
  assert.ok(db.getCard('bob'), 'card still present after failed delete')
  assert.equal(db.removeCard(card.cardId, card.publicKey), true, 'owner key deletes')
  assert.equal(db.getCard('bob'), null)
})

test('checkRateLimit allows up to the limit then blocks within the window', () => {
  const key = 'pk-ratelimit-test'
  for (let i = 0; i < 3; i++) {
    const check = db.checkRateLimit(key, 'unit-action', 3)
    assert.equal(check.allowed, true, `call ${i + 1} of 3 should be allowed`)
    assert.equal(check.remaining, 3 - i - 1)
  }
  const blocked = db.checkRateLimit(key, 'unit-action', 3)
  assert.equal(blocked.allowed, false, '4th call must be blocked')
  assert.equal(blocked.remaining, 0)
})

test('intro lifecycle: create, fetch, respond, stats', () => {
  const intro = {
    introId: 'intro-test-1',
    requestedBy: 'alice',
    targetAgentId: 'carol',
    matchId: 'match-1',
    message: 'hello carol',
    fieldsToDisclose: ['needs'],
    status: 'pending',
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    signature: '',
  } as any

  assert.equal(db.createIntro(intro).created, true)
  assert.equal(db.createIntro(intro).created, false, 'duplicate introId must fail')

  const fetched = db.getIntro('intro-test-1')
  assert.ok(fetched)
  assert.equal(fetched!.requestedBy, 'alice')
  assert.equal(fetched!.targetAgentId, 'carol')
  assert.equal(fetched!.status, 'pending')
  assert.deepEqual(fetched!.fieldsToDisclose, ['needs'])

  const forCarol = db.getIntrosForAgent('carol')
  assert.equal(forCarol.received.length, 1)
  const forAlice = db.getIntrosForAgent('alice')
  assert.equal(forAlice.sent.length, 1)

  assert.equal(db.updateIntroStatus('intro-test-1', 'approved', JSON.stringify({ verdict: 'approve' })), true)
  assert.equal(db.getIntro('intro-test-1')!.status, 'approved')
  assert.equal(db.getIntrosForAgent('carol').received.length, 0, 'approved intro no longer pending')

  const stats = db.getNetworkStats()
  assert.equal(stats.total_intros_requested, 1)
  assert.equal(stats.total_intros_approved, 1)
})

const embedCards = new Map<string, any>()

test('embeddings: semanticSearch matches offers to needs with mutual bonus', () => {
  // dave needs e0 and offers e1; erin offers e0 and needs e1 → mutual match
  // frank only offers e0 → one-directional match
  // gina offers e2 (orthogonal) → below 0.3 threshold, no match
  for (const agent of ['dave', 'erin', 'frank', 'gina']) {
    const card = makeCard(agent)
    embedCards.set(agent, card)
    db.publishCard(card)
  }

  // card_embeddings.card_id has a FOREIGN KEY to cards(card_id)
  db.storeEmbeddings(embedCards.get('erin').cardId, 'erin', [
    { type: 'offer', text: 'erin offer', vector: basisVec(0) },
    { type: 'need', text: 'erin need', vector: basisVec(1) },
  ])
  db.storeEmbeddings(embedCards.get('frank').cardId, 'frank', [
    { type: 'offer', text: 'frank offer', vector: basisVec(0) },
  ])
  db.storeEmbeddings(embedCards.get('gina').cardId, 'gina', [
    { type: 'offer', text: 'gina offer', vector: basisVec(2) },
  ])

  assert.equal(db.hasEmbeddings('erin'), true)
  assert.equal(db.hasEmbeddings('dave'), false)
  assert.equal(db.getEmbeddingCount(), 4)

  const offersForNeeds = db.searchOffersForNeeds([basisVec(0)], 'dave')
  const offerAgents = offersForNeeds.map(m => m.agentId).sort()
  assert.deepEqual(offerAgents, ['erin', 'frank'], 'gina (orthogonal) must be excluded')
  assert.ok(offersForNeeds.every(m => m.score > 0.99), 'identical vectors score ~1')

  const results = db.semanticSearch([basisVec(0)], [basisVec(1)], 'dave')
  const erin = results.find(r => r.agentId === 'erin')
  const frank = results.find(r => r.agentId === 'frank')
  assert.ok(erin, 'erin matches')
  assert.equal(erin!.mutual, true, 'erin matches in both directions')
  assert.equal(erin!.score, 1, 'mutual bonus caps at 1.0')
  assert.equal(erin!.needMatch, 'erin offer')
  assert.equal(erin!.offerMatch, 'erin need')
  assert.ok(frank, 'frank matches one direction')
  assert.equal(frank!.mutual, false)
  assert.equal(results[0].agentId, 'erin', 'mutual match ranks first')
  assert.ok(!results.some(r => r.agentId === 'gina'))
  assert.ok(!results.some(r => r.agentId === 'dave'), 'self is excluded')
})

test('storeEmbeddings replaces prior embeddings for the same card/agent', () => {
  db.storeEmbeddings(embedCards.get('frank').cardId, 'frank', [
    { type: 'offer', text: 'frank offer v2', vector: basisVec(3) },
  ])
  const results = db.searchOffersForNeeds([basisVec(3)], 'nobody')
  const frank = results.filter(m => m.agentId === 'frank')
  assert.equal(frank.length, 1)
  assert.equal(frank[0].offerText, 'frank offer v2')
  // Old e0 offer for frank is gone
  const old = db.searchOffersForNeeds([basisVec(0)], 'dave').filter(m => m.agentId === 'frank')
  assert.equal(old.length, 0)
})

test('trust signals: profile counters feed response/acceptance rates', () => {
  db.ensureProfile('pk-trusty', 'trusty')
  db.ensureProfile('pk-trusty', 'trusty') // idempotent
  db.incrementProfile('pk-trusty', 'total_intros_received')
  db.incrementProfile('pk-trusty', 'total_intros_received')
  db.incrementProfile('pk-trusty', 'total_intros_accepted')

  const trust = db.getTrustSignals('trusty')
  assert.equal(trust.responseRate, 50, '1 responded of 2 received')
  assert.equal(trust.acceptanceRate, 100)
  assert.equal(trust.trustLevel, 'new', 'zero-age identity stays "new"')
  assert.equal(trust.linkedProofs, 0)

  const unknown = db.getTrustSignals('never-seen-agent')
  assert.equal(unknown.trustLevel, 'new')
  assert.equal(unknown.identityAge, 0)
})

test('network stats reflect publishes and active cards', () => {
  const stats = db.getNetworkStats()
  assert.ok(stats.total_cards_published >= 2, 'alice + bob + embedding agents were published')
  assert.equal(typeof stats.active_cards, 'number')
  assert.equal(typeof stats.pending_intros, 'number')
  assert.equal(stats.active_cards, db.getCardCount())
})
