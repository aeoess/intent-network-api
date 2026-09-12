// ══════════════════════════════════════════════════════════════
// Intent Network API Server
// ══════════════════════════════════════════════════════════════
// Persistent backend for the AEOESS Intent Network.
// Stores IntentCards, runs matching, handles intro protocol.
// Auth: Ed25519 signatures. No passwords, no OAuth.
//
// Start: npm start (production) or npm run dev (watch mode)
// Config: PORT, DB_PATH env vars
//
// App construction (middleware + routes) lives in app.ts so tests
// can build the app without binding a port. This file owns the
// runtime side effects: DB init, purge interval, listen, signals.
// ══════════════════════════════════════════════════════════════

import { createApp } from './app.js'
import { getDb, purgeExpired, closeDb, stampCanonicalMcpReleaseOnce } from './db.js'
import { initWriteSchema, purgeWriteNonces } from './write-db.js'
import { sweepExpiredIntros } from './connection-facts.js'
import { warmupModel } from './embeddings.js'
import { sweepExpiredFitExchanges } from './fit-routes.js'
import { sweepExpiredV3Cards } from './v3-db.js'
import { recomputeAllMatches } from './matches-db.js'
import { runWeeklyDigest } from './weekly.js'
import { assertReceiptKeyConfigured } from './server-key.js'

const PORT = parseInt(process.env.PORT || '3100')

// ── Receipt key, before anything else ──
// A receipt signed by a key this process invented stops verifying at the next
// restart, silently, which makes every server observation worthless as evidence.
// So the key is a startup requirement rather than a runtime fallback: refuse to
// serve, and say which variable is wrong, instead of booting into a state where
// receipts look fine and are not.
try {
  const key = assertReceiptKeyConfigured()
  console.log(`[receipt key] issuer ${key.issuerKeyId}`)
} catch (e) {
  console.error(`[receipt key] refusing to start: ${(e as Error).message}`)
  process.exit(1)
}

const app = createApp()

// ── Initialize DB and start ──
getDb() // Ensures schema is created
// Eagerly, at boot, never lazily on first use. A lazily created table's CREATE
// can land inside whatever transaction touches it first and be rolled back with a
// failed business write, and a nonce table that sometimes does not exist is worse
// than none. v3-routes.ts:231 already shows that shape reaching DDL inside a
// transaction.
initWriteSchema()
// The compatibility clock. A no op unless MINGLE_CANONICAL_MCP_RELEASED_AT names
// an explicit instant, and nothing here infers one from deploy or build time.
stampCanonicalMcpReleaseOnce()

// Purge expired cards every 5 minutes
setInterval(() => { purgeExpired() }, 5 * 60 * 1000)

// Close fit exchanges past their 72h window (assembles and signs the record).
setInterval(() => {
  try { sweepExpiredFitExchanges() } catch (e) { console.error('[fit sweep]', (e as Error).message) }
}, 30 * 60 * 1000)
// Hourly: sweep expired v3 cards, then recompute the match graph over the
// active set (catches new complements as cards join and prunes departed ones).
setInterval(() => {
  try { sweepExpiredV3Cards() } catch (e) { console.error('[v3 sweep]', (e as Error).message) }
  try { recomputeAllMatches() } catch (e) { console.error('[match sweep]', (e as Error).message) }
  // The intro lifecycle sweep. It writes NOTHING except v3_intros.status, from the
  // derivation, for rows that lapsed without anyone writing to them. It stores no expiry
  // and inserts no authorization, so it cannot move a deadline: that is the whole reason
  // expiry is derived from authorization timestamps rather than kept in a column a
  // background job could touch by accident.
  try {
    const swept = sweepExpiredIntros()
    if (swept.length > 0) console.log(`[intro sweep] materialized ${swept.length} expired intro(s)`)
  } catch (e) { console.error('[intro sweep]', (e as Error).message) }
  // Nonce retention is at least 24 hours, which is what makes post-expiry replay
  // impossible: the freshness window is 10 minutes, so a nonce row always outlives every
  // envelope that could carry it.
  try { purgeWriteNonces() } catch (e) { console.error('[nonce purge]', (e as Error).message) }
}, 60 * 60 * 1000)

// Weekly digest. The week key dedupes, so at most one email per subscriber per
// week even though the timer is coarse.
setInterval(() => { runWeeklyDigest().catch(e => console.error('[weekly digest]', (e as Error).message)) }, 7 * 24 * 60 * 60 * 1000)

app.listen(PORT, () => {
  console.log(`Intent Network API running on port ${PORT}`)
  console.log(`Database: ${process.env.DB_PATH || 'data/intent-network.db'}`)
  console.log(`Endpoints: http://localhost:${PORT}/`)
  // Warm up embedding model in background (don't block startup)
  warmupModel().catch(e => console.error('[embeddings] Warmup failed:', e.message))
})

// ── Graceful shutdown ──
process.on('SIGINT', () => { closeDb(); process.exit(0) })
process.on('SIGTERM', () => { closeDb(); process.exit(0) })

export default app
