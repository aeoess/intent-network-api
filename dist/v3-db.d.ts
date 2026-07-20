import type { RevocationStatus, V3Card } from './v3-cards.js';
export declare function initV3Schema(): void;
export interface StoredV3Card {
    card_id: string;
    card: V3Card;
    revocation_status: RevocationStatus;
    expires_at: string;
}
export declare function insertV3Card(cardId: string, card: V3Card, cardHash: string): void;
export declare function getV3Card(cardId: string): StoredV3Card | null;
export declare function setRevocationStatus(cardId: string, subjectKey: string, status: RevocationStatus): boolean;
export declare function deleteV3Card(cardId: string, subjectKey: string): boolean;
export declare function storeV3Embedding(cardId: string, vector: Float32Array): void;
export declare function removeFromIndex(cardId: string): void;
export declare function semanticSearchV3(queryVec: Float32Array, limit: number): {
    card_id: string;
    distance: number;
}[];
export interface V3SearchFilters {
    card_type?: string;
    intents?: string[];
    topics?: string[];
    engagement?: string;
    location?: string;
    event_ref?: string;
}
export declare function searchV3Cards(filters: V3SearchFilters, semanticIds?: string[], limit?: number): Record<string, unknown>[];
export declare function sweepExpiredV3Cards(): {
    swept: number;
};
export declare function v3CardCount(): number;
