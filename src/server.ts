// ══════════════════════════════════════════════════════════════
// Intent Network API Server
// ══════════════════════════════════════════════════════════════
// Persistent backend for the AEOESS Intent Network.
// Stores IntentCards, runs matching, handles intro protocol.
// Auth: Ed25519 signatures. No passwords, no OAuth.
//
// Start: npm start (production) or npm run dev (watch mode)
// Config: PORT, DB_PATH env vars
// ══════════════════════════════════════════════════════════════

import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import routes from './routes.js'
import { getDb, purgeExpired, closeDb } from './db.js'

const PORT = parseInt(process.env.PORT || '3100')
const app = express()

// ── Middleware ──
app.use(helmet())
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-Agent-Id', 'X-Public-Key'],
}))
app.use(express.json({ limit: '100kb' }))

// ── Routes ──
app.use('/api', routes)

// ── Health check ──
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: '0.1.0', uptime: process.uptime() })
})

// ── Root ──
app.get('/', (_req, res) => {
  res.json({
    name: 'AEOESS Intent Network API',
    version: '0.1.0',
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

// ── Initialize DB and start ──
getDb() // Ensures schema is created

// Purge expired cards every 5 minutes
setInterval(() => { purgeExpired() }, 5 * 60 * 1000)

app.listen(PORT, () => {
  console.log(`Intent Network API running on port ${PORT}`)
  console.log(`Database: ${process.env.DB_PATH || 'data/intent-network.db'}`)
  console.log(`Endpoints: http://localhost:${PORT}/`)
})

// ── Graceful shutdown ──
process.on('SIGINT', () => { closeDb(); process.exit(0) })
process.on('SIGTERM', () => { closeDb(); process.exit(0) })

export default app
