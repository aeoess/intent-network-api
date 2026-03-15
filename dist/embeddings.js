// ══════════════════════════════════════════════════════════════
// Intent Network API — Embedding Module
// Uses all-MiniLM-L6-v2 via @xenova/transformers for semantic matching
// ══════════════════════════════════════════════════════════════
import { pipeline } from '@xenova/transformers';
let embedder = null;
let warming = false;
/**
 * Warm up the embedding model at server startup.
 * Call this once — subsequent calls are no-ops.
 */
export async function warmupModel() {
    if (embedder || warming)
        return;
    warming = true;
    const t = Date.now();
    console.log('[embeddings] Loading all-MiniLM-L6-v2...');
    embedder = await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2');
    console.log(`[embeddings] Model ready in ${Date.now() - t}ms`);
}
/**
 * Embed a text string into a 384-dim float32 vector.
 * Returns null if model isn't loaded yet.
 */
export async function embed(text) {
    if (!embedder)
        return null;
    const result = await embedder(text, { pooling: 'mean', normalize: true });
    return new Float32Array(result.data);
}
/**
 * Embed multiple texts efficiently.
 * Returns array of 384-dim vectors in same order as input.
 */
export async function embedBatch(texts) {
    if (!embedder)
        return [];
    const results = [];
    for (const text of texts) {
        const result = await embedder(text, { pooling: 'mean', normalize: true });
        results.push(new Float32Array(result.data));
    }
    return results;
}
/**
 * Cosine similarity between two vectors.
 * Vectors are already normalized by the model, so dot product = cosine sim.
 */
export function cosineSimilarity(a, b) {
    let dot = 0;
    for (let i = 0; i < a.length; i++)
        dot += a[i] * b[i];
    return dot;
}
export const EMBEDDING_DIM = 384;
//# sourceMappingURL=embeddings.js.map