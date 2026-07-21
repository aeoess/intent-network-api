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
import { getDb, purgeExpired, closeDb } from './db.js'
import { warmupModel } from './embeddings.js'
import { sweepExpiredV3Cards } from './v3-db.js'
import { recomputeAllMatches } from './matches-db.js'
import { runWeeklyDigest } from './weekly.js'

const PORT = parseInt(process.env.PORT || '3100')
const app = createApp()

// ── Initialize DB and start ──
getDb() // Ensures schema is created

// Purge expired cards every 5 minutes
setInterval(() => { purgeExpired() }, 5 * 60 * 1000)

// Hourly: sweep expired v3 cards, then recompute the match graph over the
// active set (catches new complements as cards join and prunes departed ones).
setInterval(() => {
  try { sweepExpiredV3Cards() } catch (e) { console.error('[v3 sweep]', (e as Error).message) }
  try { recomputeAllMatches() } catch (e) { console.error('[match sweep]', (e as Error).message) }
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
