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
