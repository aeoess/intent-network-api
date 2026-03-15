/**
 * Warm up the embedding model at server startup.
 * Call this once — subsequent calls are no-ops.
 */
export declare function warmupModel(): Promise<void>;
/**
 * Embed a text string into a 384-dim float32 vector.
 * Returns null if model isn't loaded yet.
 */
export declare function embed(text: string): Promise<Float32Array | null>;
/**
 * Embed multiple texts efficiently.
 * Returns array of 384-dim vectors in same order as input.
 */
export declare function embedBatch(texts: string[]): Promise<Float32Array[]>;
/**
 * Cosine similarity between two vectors.
 * Vectors are already normalized by the model, so dot product = cosine sim.
 */
export declare function cosineSimilarity(a: Float32Array, b: Float32Array): number;
export declare const EMBEDDING_DIM = 384;
