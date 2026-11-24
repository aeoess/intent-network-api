// ══════════════════════════════════════════════════════════════
// Intent Network API — Embedding Module
// Uses all-MiniLM-L6-v2 via @xenova/transformers for semantic matching
// ══════════════════════════════════════════════════════════════

import { pipeline } from '@xenova/transformers'

let embedder: any = null
/** The one warmup for this process. Every caller gets the same promise, so
 *  overlapping calls start one model load, not several. */
let warmup: Promise<boolean> | null = null
let loadModel: () => Promise<any> = () => pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2')

/**
 * Load the embedding model in the background, once per process.
 *
 * Resolves true when the model is ready and false when loading failed. It
 * never rejects. Nothing on a request path waits for it: until it resolves,
 * embed() returns null and the caller records that, so a slow or stalled
 * load never holds a publish or a search open.
 *
 * The two log lines are relied on by the mingle-mcp end to end suite, which
 * reads this process's output to know when the model is ready.
 */
export function warmupModel(): Promise<boolean> {
  if (warmup) return warmup
  const t = Date.now()
  console.log('[embeddings] Loading all-MiniLM-L6-v2...')
  warmup = loadModel().then(
    e => {
      embedder = e
      console.log(`[embeddings] Model ready in ${Date.now() - t}ms`)
      return true
    },
    err => {
      console.error('[embeddings] Warmup failed:', (err as Error)?.message ?? String(err))
      return false
    },
  )
  return warmup
}

/** Tests only. Replaces the model loader and forgets any earlier warmup, so a
 *  test can control when, and whether, the model becomes ready. */
export function setModelLoaderForTests(loader: () => Promise<any>): void {
  embedder = null
  warmup = null
  loadModel = loader
}

/**
 * Embed a text string into a 384-dim float32 vector.
 * Returns null if model isn't loaded yet.
 */
export async function embed(text: string): Promise<Float32Array | null> {
  if (!embedder) return null
  const result = await embedder(text, { pooling: 'mean', normalize: true })
  return new Float32Array(result.data)
}

/**
 * Embed multiple texts efficiently.
 * Returns array of 384-dim vectors in same order as input.
 */
export async function embedBatch(texts: string[]): Promise<Float32Array[]> {
  if (!embedder) return []
  const results: Float32Array[] = []
  for (const text of texts) {
    const result = await embedder(text, { pooling: 'mean', normalize: true })
    results.push(new Float32Array(result.data))
  }
  return results
}

/**
 * Cosine similarity between two vectors.
 * Vectors are already normalized by the model, so dot product = cosine sim.
 */
export function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  let dot = 0
  for (let i = 0; i < a.length; i++) dot += a[i] * b[i]
  return dot
}

export const EMBEDDING_DIM = 384
