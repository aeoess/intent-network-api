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
  // Mingle v3 (additive; the 48h IntentCard routes above are untouched)
  app.use('/api/v3', v3Routes)
  // Mingle v3 P1.5 read surfaces: /c/:cardId, /e/:eventRef, /join
  app.use('/', v3Pages)

  // ── Health check ──
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', version: '0.4.0', uptime: process.uptime() })
  })

  // ── Root ──
  app.get('/', (_req, res) => {
    res.json({
      name: 'AEOESS Intent Network API',
      version: '0.4.0',
      docs: 'https://aeoess.com/llms-full.txt',
      endpoints: {
        'POST /api/cards': 'Publish an IntentCard (signature verified)',
        'GET /api/cards/:agentId': 'Get an agent\'s card',
        'DELETE /api/cards/:cardId': 'Remove a card (signature verified)',
        'GET /api/matches/:agentId': 'Get ranked matches',
        'POST /api/intros': 'Request an introduction (signature verified)',
        'PUT /api/intros/:introId': 'Respond to an intro (signature verified)',
        'GET /api/digest/:agentId': 'Personalized digest',
        'GET /api/stats': 'Network statistics',
      },
    })
  })

  return app
}
