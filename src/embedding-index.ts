// ══════════════════════════════════════════════════════════════
// Indexing of cards that were published while the model was loading
// ══════════════════════════════════════════════════════════════
//
// A card is embedded when it is published. If the model is still loading at
// that moment, embed() returns null, the card gets an `embedding_failed`
// event, and nothing used to go back to it, so a query search never returned
// it. This pass runs once the model is ready and embeds those cards.
//
// It writes only the two index rows a publish would have written. It does not
// change a card's content, status, expiry or visibility, it does not compute
// matches (the hourly sweep does that from the stored match vector) and it
// sends no notification.

import { embed, warmupModel } from './embeddings.js'
import * as v3db from './v3-db.js'
import * as matchesDb from './matches-db.js'
import { networkVisibleText } from './v3-cards.js'
import type { V3Card } from './v3-cards.js'
import { recordCardEvent } from './card-events.js'

export interface IndexPassResult {
  indexed: number
  /** Cards that were taken down, hidden or already indexed by the time their
   *  vector was ready, or that have no network visible text. */
  skipped: number
  /** Matchable cards still without a vector after this pass. */
  remaining: number
}

/** Embed up to `limit` live cards that have no row in the semantic index.
 *  Safe to run again: a card that has a row is never selected. */
export async function indexMissingEmbeddings(limit = 500): Promise<IndexPassResult> {
  const rows = v3db.listMatchableCardsWithoutEmbedding(limit)
  let indexed = 0
  let skipped = 0
  for (const row of rows) {
    let card: V3Card
    try { card = JSON.parse(row.card_json) as V3Card } catch { skipped++; continue }
    // The same text a publish embeds, built from the network visible fields only.
    const text = networkVisibleText(card)
    if (text.length === 0) { skipped++; continue }
    const vec = await embed(text)
    if (!vec) break
    // Rechecked after the await. The card may have been withdrawn, hidden or
    // expired, or a renew may have indexed it, while the vector was computed.
    // The check and the two writes below run without an await between them.
    if (!v3db.isCardMatchable(row.card_id) || v3db.hasV3Embedding(row.card_id)) { skipped++; continue }
    v3db.storeV3Embedding(row.card_id, vec)
    matchesDb.storeMatchVector(row.card_id, vec)
    recordCardEvent('embedding_stored', row.card_id, row.subject_key, { dims: vec.length, source: 'index_pass' })
    indexed++
  }
  return { indexed, skipped, remaining: v3db.countMatchableCardsWithoutEmbedding() }
}

/** Server startup. Loads the model in the background and, once it is ready,
 *  indexes the cards that missed it. Never rejects. */
export async function startEmbeddings(): Promise<IndexPassResult | null> {
  const ready = await warmupModel()
  if (!ready) return null
  try {
    const r = await indexMissingEmbeddings()
    console.log(`[embeddings] Index pass: ${r.indexed} indexed, ${r.skipped} skipped, ${r.remaining} still without a vector`)
    return r
  } catch (e) {
    console.error('[embeddings] Index pass failed:', (e as Error).message)
    return null
  }
}
