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
import fitRoutes from './fit-routes.js'
import fitV4Routes from './fit-v4-routes.js'
import matchRoutes, { v3RateHeaders } from './match-routes.js'
import { v2Enabled, V2_INDEX_KEYS } from './v2-gate.js'

export function createApp() {
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
    res.json(body)
  })

  return app
}
