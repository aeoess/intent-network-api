// ══════════════════════════════════════════════════════════════
// Indexing of cards that were published while the model was loading
// ══════════════════════════════════════════════════════════════
//
// A card is embedded when it is published. If the model is still loading at
// that moment, embed() returns null, the card gets an `embedding_failed`
// event, and nothing used to go back to it, so a query search never returned
// it. This pass runs once the model is ready and embeds those cards.
//
// A card has two vectors: a row in the semantic index, which query search
// reads, and a row in v3_match_vectors, which the hourly match sweep reads.
// The pass selects a card missing either one and adds only what is missing.
//
// It does not change a card's content, status, expiry or visibility, it does
// not compute matches (the hourly sweep does that from the stored match
// vector) and it sends no notification.

import { getDb } from './db.js'
import { embed, warmupModel } from './embeddings.js'
import * as v3db from './v3-db.js'
import * as matchesDb from './matches-db.js'
import { networkVisibleText } from './v3-cards.js'
import type { V3Card } from './v3-cards.js'
import { recordCardEvent } from './card-events.js'

export type StoreVectorsResult = 'stored' | 'already_indexed' | 'not_current'

/** Store the vectors computed from `text` for a card, in one transaction.
 *
 *  The card must still be live and unhidden, and its network visible text, read
 *  again inside the transaction, must still be `text`. A vector computed from
 *  text the card no longer shows is never written. Either both missing rows are
 *  written or neither is, so a failure leaves the card selectable by the next
 *  pass. A row that already exists is kept. */
export function storeCardVectors(cardId: string, text: string, vec: Float32Array): StoreVectorsResult {
  matchesDb.initMatchesSchema()
  return getDb().transaction((): StoreVectorsResult => {
    if (!v3db.isCardMatchable(cardId)) return 'not_current'
    const current = v3db.getV3CardContent(cardId)
    if (!current || networkVisibleText(current) !== text) return 'not_current'
    const hasSemantic = v3db.hasV3Embedding(cardId)
    const hasMatch = matchesDb.getMatchVector(cardId) !== null
    if (hasSemantic && hasMatch) return 'already_indexed'
    if (!hasSemantic) v3db.storeV3Embedding(cardId, vec)
    if (!hasMatch) matchesDb.storeMatchVector(cardId, vec)
    return 'stored'
  })()
}

export interface IndexPassResult {
  indexed: number
  /** Cards whose content, status or visibility changed while their vector was
   *  computed, cards another writer indexed first, and cards with no network
   *  visible text. */
  skipped: number
  /** Cards whose write failed. Nothing was written for them. */
  failed: number
  /** True when the pass stopped at its limit with cards left to embed. */
  limit_reached: boolean
  /** Live cards still missing a vector after this pass, including cards with no
   *  network visible text, which never get one. */
  remaining: number
}

const PAGE = 100

/** Embed up to `limit` live cards that are missing a vector. Cards skipped
 *  without an embedding (no visible text, unreadable content) do not count
 *  against the limit, and the scan moves past them, so they cannot hold back
 *  later cards. Safe to run again. */
export async function indexMissingEmbeddings(limit = 500): Promise<IndexPassResult> {
  matchesDb.initMatchesSchema()
  let indexed = 0
  let skipped = 0
  let failed = 0
  let embedded = 0
  let limitReached = false
  let after: { created_at: string; card_id: string } | undefined
  scan: for (;;) {
    const page = v3db.listCardsMissingVectors(PAGE, after)
    if (page.length === 0) break
    for (const row of page) {
      if (embedded >= limit) { limitReached = true; break scan }
      after = { created_at: row.created_at, card_id: row.card_id }
      let card: V3Card
      try { card = JSON.parse(row.card_json) as V3Card } catch { skipped++; continue }
      // The same text a publish embeds, built from the network visible fields only.
      const text = networkVisibleText(card)
      if (text.length === 0) { skipped++; continue }
      embedded++
      const vec = await embed(text)
      if (!vec) break scan
      let result: StoreVectorsResult
      try {
        result = storeCardVectors(row.card_id, text, vec)
      } catch (e) {
        failed++
        console.error(`[embeddings] Index pass could not store vectors for ${row.card_id}:`, (e as Error).message)
        continue
      }
      if (result === 'stored') {
        indexed++
        recordCardEvent('embedding_stored', row.card_id, row.subject_key, { dims: vec.length, source: 'index_pass' })
      } else {
        skipped++
      }
    }
  }
  return { indexed, skipped, failed, limit_reached: limitReached, remaining: v3db.countCardsMissingVectors() }
}

/** Server startup. Loads the model in the background and, once it is ready,
 *  indexes the cards that missed it. Never rejects. */
export async function startEmbeddings(): Promise<IndexPassResult | null> {
  const ready = await warmupModel()
  if (!ready) return null
  try {
    const r = await indexMissingEmbeddings()
    console.log(
      `[embeddings] Index pass: ${r.indexed} indexed, ${r.skipped} skipped, ${r.failed} failed, ` +
        `${r.remaining} live cards still missing a vector` +
        (r.limit_reached ? ' (stopped at the per-start limit, the rest are indexed on a later start)' : ''),
    )
    return r
  } catch (e) {
    console.error('[embeddings] Index pass failed:', (e as Error).message)
    return null
  }
}
