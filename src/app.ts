// ══════════════════════════════════════════════════════════════
// Intent Network API — App Factory
// ══════════════════════════════════════════════════════════════
// Builds the Express app (middleware + routes) WITHOUT binding a
// port or opening the database. server.ts wires the side effects
// (getDb, purge interval, listen); tests import createApp() and
// run the same app against an ephemeral port + temp DB_PATH.
// Extracted verbatim from server.ts — no behavior change.

import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import routes from './routes.js'
import v3Routes from './v3-routes.js'
import v3Pages from './v3-pages.js'
import notifyRoutes from './notify-routes.js'
import introsRoutes from './intros-routes.js'
import introWriteRoutes from './intro-write-routes.js'
import fitRoutes from './fit-routes.js'
import fitV4Routes from './fit-v4-routes.js'
import matchRoutes, { v3RateHeaders } from './match-routes.js'
import { v2Enabled, V2_INDEX_KEYS } from './v2-gate.js'
import { initWriteSchema } from './write-db.js'
import { legacyWindowClosed, legacyWriteCutoffAt } from './db.js'
import { WRITE_DOMAIN } from './write-envelope.js'

export function createApp() {
  // The write subsystem tables, created here as well as at server boot. server.ts is not
  // the only thing that builds this app: a test, a script or a future worker can, and
  // before this call the legacy adapters on the intro routes would hit "no such table:
  // write_evidence" the first time a 3.2.x client responded to an intro. Idempotent, and
  // outside any transaction, which is the whole reason it is not lazy on first use.
  initWriteSchema()
  const app = express()

  // ── Middleware ──
  app.use(helmet())
  app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'X-Agent-Id', 'X-Public-Key'],
  }))
  app.use((express as any).json({ limit: '100kb' }))

  // ── Routes ──
  app.use('/api', routes)
  // Informational X-RateLimit-* headers on every v3 response (never blocks).
  app.use('/api/v3', v3RateHeaders)
  // Mingle v3 (additive; the 48h IntentCard routes above are untouched)
  app.use('/api/v3', v3Routes)
  // Mingle v3 match engine surfaces: index, digest, dismiss, report
  app.use('/api/v3', matchRoutes)
  // Mingle v3 P1.5 read surfaces: /c/:cardId, /e/:eventRef, /join
  app.use('/', v3Pages)
  // Mingle email notifications (consent + confirm + unsubscribe)
  app.use('/api/v3/notifications', notifyRoutes)
  // Mingle v3 introductions (request, respond, complete, mine)
  app.use('/api/v3/intros', introsRoutes)
  // The canonical mingle-write-v1 actions that have no legacy form. Mounted BEFORE
  // nothing and AFTER the legacy router, because the paths are disjoint: these are
  // fixed words and the legacy router's only parameterized paths are /:id/respond
  // and /:id/complete, which no path here matches.
  app.use('/api/v3/intros', introWriteRoutes)
  // Mingle v3.6 structured fit exchange (disclosures, draft, answers, close)
  app.use('/api/v3/fit', fitRoutes)
  // Mingle v4 private fit (policy, predicate handshake)
  app.use('/api/v4/fit', fitV4Routes)

  // ── Health check ──
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: '0.4.0', uptime: process.uptime() })
  })

  // ── Root ──
  app.get('/', (_req, res) => {
    const endpoints: Record<string, string> = {
      'POST /api/cards': 'Publish an IntentCard (signature verified)',
      'GET /api/cards/:agentId': 'Get an agent\'s card',
      'DELETE /api/cards/:cardId': 'Remove a card (signature verified)',
      'GET /api/matches/:agentId': 'Get ranked matches',
      'POST /api/intros': 'Request an introduction (signature verified)',
      'PUT /api/intros/:introId': 'Respond to an intro (signature verified)',
      'GET /api/digest/:agentId': 'Personalized digest',
      'GET /api/stats': 'Network statistics',
    }
    const body: Record<string, unknown> = {
      name: 'AEOESS Intent Network API',
      version: '0.4.0',
      docs: 'https://aeoess.com/llms-full.txt',
      endpoints,
    }
    // With legacy v2 off the index advertises none of it, so a half-live product
    // cannot be discovered and invoked. With v2 on this response is unchanged.
    if (!v2Enabled()) {
      for (const key of V2_INDEX_KEYS) delete endpoints[key]
      body.legacy_v2 = { available: false }
    }
    // The capability a client reads to decide which lane to use. Always present, because a
    // client has to be able to tell "this server does not know about canonical writes" from
    // "this server has not answered yet", and an absent field cannot make that distinction.
    //
    // `legacy_accepted` is derived from the marker and NEVER from an unset value. A null
    // cutoff means the window is open, because a fresh database has no marker and reading
    // that as a cutoff in the past would refuse every legacy client the moment the table is
    // empty.
    body.write_authorization = {
      domain: WRITE_DOMAIN,
      preferred: true,
      legacy_accepted: !legacyWindowClosed(),
      legacy_cutoff_at: legacyWriteCutoffAt(),
    }
    res.json(body)
  })

  return app
}
