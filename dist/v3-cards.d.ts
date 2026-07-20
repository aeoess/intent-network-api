export declare const CARD_TYPES: readonly ["connection", "opportunity"];
export declare const INTENTS: readonly ["meet", "collaborate", "team_up", "work", "advise", "mentor", "cofound"];
export declare const EVIDENCE_SOURCES: readonly ["principal_statement", "artifact_link", "subject_binding", "third_party_attestation"];
export declare const VISIBILITY_LEVELS: readonly ["private", "network", "intro_request", "mutual_intro", "thread_only"];
export declare const REVOCATION_STATUSES: readonly ["active", "stopped_new_matches", "superseded", "withdrawn", "authority_revoked", "deleted"];
export declare const DEFAULT_TTL_DAYS = 21;
export type CardType = typeof CARD_TYPES[number];
export type RevocationStatus = typeof REVOCATION_STATUSES[number];
export interface EvidenceRecord {
    claim: string;
    source: typeof EVIDENCE_SOURCES[number];
    method: string;
    verified_fact: string;
    date: string;
}
export interface SeekingEntry {
    description: string;
    topics?: string[];
    engagement?: string;
}
export interface OfferingEntry {
    description: string;
    topics?: string[];
    provenance: 'principal_statement';
}
export interface PreferenceEntry {
    key: string;
    value: string;
}
export interface V3Card {
    card_type: CardType;
    subject_key: string;
    version: 1;
    created_at: string;
    expires_at: string;
    headline: string;
    intents: string[];
    seeking: SeekingEntry[];
    offering: OfferingEntry[];
    preferences: PreferenceEntry[];
    artifacts: EvidenceRecord[];
    event_ref?: {
        event_id: string;
        dates?: string;
    } | null;
    team_size_sought?: number | null;
    visibility: Record<string, typeof VISIBILITY_LEVELS[number]>;
    composition: {
        agent_assisted: boolean;
        skill_version: string;
    };
    delegation_ref?: string | null;
    approval: {
        card_hash: string;
        approved_at: string;
        principal_signature: string;
    };
    revocation_status: RevocationStatus;
    signature?: string;
}
export declare function findBannedContent(value: unknown, path?: string): string | null;
export declare function canonicalCardContent(card: Record<string, unknown>): string;
export declare function cardContentHash(card: Record<string, unknown>): string;
export declare function validateV3Card(card: unknown): {
    valid: true;
    card: V3Card;
} | {
    valid: false;
    error: string;
};
export declare function networkVisibleView(card: V3Card & {
    card_id?: string;
}): Record<string, unknown>;
/** The text the semantic index sees: network-visible free text only. */
export declare function networkVisibleText(card: V3Card): string;
