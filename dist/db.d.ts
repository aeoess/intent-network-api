import Database from 'better-sqlite3';
import type { IntentCard, IntroRequest } from 'agent-passport-system';
export declare function getDb(): Database.Database;
export declare function publishCard(card: IntentCard): {
    published: boolean;
    error?: string;
};
export declare function getCard(agentId: string): IntentCard | null;
export declare function removeCard(cardId: string, publicKey: string): boolean;
export declare function getAllActiveCards(): IntentCard[];
export declare function getCardCount(): number;
export declare function createIntro(intro: IntroRequest): {
    created: boolean;
    error?: string;
};
export declare function getIntro(introId: string): IntroRequest | null;
export declare function updateIntroStatus(introId: string, status: string, responseJson?: string): boolean;
export declare function getIntrosForAgent(agentId: string): {
    sent: IntroRequest[];
    received: IntroRequest[];
};
export declare function checkRateLimit(publicKey: string, action: string, maxPerHour: number): {
    allowed: boolean;
    remaining: number;
};
export declare function purgeExpired(): number;
export declare function getNetworkStats(): Record<string, number>;
export declare function closeDb(): void;
/**
 * Store embeddings for a card's needs and offers.
 * Deletes previous embeddings for this card first (upsert).
 */
export declare function storeEmbeddings(cardId: string, agentId: string, items: {
    type: 'need' | 'offer';
    text: string;
    vector: Float32Array;
}[]): void;
/**
 * Cross-vector search: find cards where their OFFERS match my NEEDS.
 * Returns top N agent_ids with best cosine similarity.
 */
export declare function searchOffersForNeeds(needVectors: Float32Array[], excludeAgentId: string, limit?: number): {
    agentId: string;
    score: number;
    offerText: string;
    needIdx: number;
}[];
/**
 * Cross-vector search: find cards where their NEEDS match my OFFERS.
 */
export declare function searchNeedsForOffers(offerVectors: Float32Array[], excludeAgentId: string, limit?: number): {
    agentId: string;
    score: number;
    needText: string;
    offerIdx: number;
}[];
/**
 * Combined semantic search: finds matches in both directions.
 * Returns top N candidates with combined scores and mutual bonus.
 */
export declare function semanticSearch(needVectors: Float32Array[], offerVectors: Float32Array[], agentId: string, limit?: number): {
    agentId: string;
    score: number;
    mutual: boolean;
    needMatch: string | null;
    offerMatch: string | null;
}[];
/**
 * Check if a card has embeddings stored.
 */
export declare function hasEmbeddings(agentId: string): boolean;
export declare function getEmbeddingCount(): number;
