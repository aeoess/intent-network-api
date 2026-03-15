// migrate-embeddings.mjs — Embed all existing cards for Phase 1B semantic matching
// Run: cd /Users/clawrot/intent-network-api && node migrate-embeddings.mjs

import Database from 'better-sqlite3'
import * as sqliteVec from 'sqlite-vec'
import { pipeline } from '@xenova/transformers'

const DB_PATH = 'data/intent-network.db'
const db = new Database(DB_PATH)
sqliteVec.load(db)

// Ensure embeddings table exists
db.exec(`
  CREATE TABLE IF NOT EXISTS card_embeddings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    item_type TEXT NOT NULL,
    item_text TEXT NOT NULL,
    embedding BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_emb_card ON card_embeddings(card_id);
  CREATE INDEX IF NOT EXISTS idx_emb_agent ON card_embeddings(agent_id);
  CREATE INDEX IF NOT EXISTS idx_emb_type ON card_embeddings(item_type);
`)

console.log('Loading embedding model...')
const embedder = await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2')
console.log('Model loaded.')

// Get all active cards
const cards = db.prepare("SELECT card_id, agent_id, card_json FROM cards WHERE expires_at > datetime('now')").all()
console.log(`Found ${cards.length} active cards to embed.`)

// Clear existing embeddings
db.prepare('DELETE FROM card_embeddings').run()
console.log('Cleared old embeddings.')

const insert = db.prepare('INSERT INTO card_embeddings (card_id, agent_id, item_type, item_text, embedding) VALUES (?, ?, ?, ?, ?)')
let embedded = 0
let skipped = 0

for (const row of cards) {
  const card = JSON.parse(row.card_json)
  const needs = (card.needs || []).map(n => typeof n === 'string' ? n : n.description || '')
  const offers = (card.offers || []).map(o => typeof o === 'string' ? o : o.description || '')

  // Concatenate category+tags for old v1 cards that only have structured data
  const enrichedNeeds = needs.map(n => {
    if (!n && card.needs) {
      const orig = card.needs.find(x => (x.description || '') === n)
      if (orig) return [orig.category, orig.description, ...(orig.tags || [])].filter(Boolean).join(' ')
    }
    return n
  }).filter(t => t && t.length > 3)

  const enrichedOffers = offers.map(o => {
    if (!o && card.offers) {
      const orig = card.offers.find(x => (x.description || '') === o)
      if (orig) return [orig.category, orig.description, ...(orig.tags || [])].filter(Boolean).join(' ')
    }
    return o
  }).filter(t => t && t.length > 3)

  if (enrichedNeeds.length === 0 && enrichedOffers.length === 0) {
    skipped++
    continue
  }

  // Embed each need and offer
  for (const text of enrichedNeeds) {
    const result = await embedder(text, { pooling: 'mean', normalize: true })
    const buf = Buffer.from(new Float32Array(result.data).buffer)
    insert.run(row.card_id, row.agent_id, 'need', text, buf)
  }
  for (const text of enrichedOffers) {
    const result = await embedder(text, { pooling: 'mean', normalize: true })
    const buf = Buffer.from(new Float32Array(result.data).buffer)
    insert.run(row.card_id, row.agent_id, 'offer', text, buf)
  }

  embedded++
  if (embedded % 20 === 0) process.stdout.write(`${embedded}...`)
}

console.log(`\n\nDone! Embedded ${embedded} cards, skipped ${skipped}.`)
const total = db.prepare('SELECT COUNT(*) as cnt FROM card_embeddings').get()
console.log(`Total embedding rows: ${total.cnt}`)
db.close()
