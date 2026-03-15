// ══════════════════════════════════════════════════════════════
// Intent Network API — Database Layer
// ══════════════════════════════════════════════════════════════
// SQLite with WAL mode. Cards, intros, rate limits.
// Ed25519 public keys are the identity — no accounts needed.
import Database from 'better-sqlite3';
import * as sqliteVec from 'sqlite-vec';
import { join } from 'node:path';
const DB_PATH = process.env.DB_PATH || join(process.cwd(), 'data', 'intent-network.db');
let db;
export function getDb() {
    if (!db) {
        db = new Database(DB_PATH);
        sqliteVec.load(db);
        db.pragma('journal_mode = WAL');
        db.pragma('busy_timeout = 5000');
        db.pragma('synchronous = NORMAL');
        db.pragma('foreign_keys = ON');
        initSchema();
    }
    return db;
}
function initSchema() {
    const d = db;
    // ── Schema ──
    d.exec(`
    CREATE TABLE IF NOT EXISTS cards (
      card_id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      public_key TEXT NOT NULL,
      principal_alias TEXT NOT NULL,
      card_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_cards_agent ON cards(agent_id);
    CREATE INDEX IF NOT EXISTS idx_cards_pubkey ON cards(public_key);
    CREATE INDEX IF NOT EXISTS idx_cards_expires ON cards(expires_at);

    CREATE TABLE IF NOT EXISTS intros (
      intro_id TEXT PRIMARY KEY,
      requested_by TEXT NOT NULL,
      target_agent_id TEXT NOT NULL,
      match_id TEXT NOT NULL,
      message TEXT NOT NULL,
      fields_to_disclose TEXT NOT NULL DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'pending',
      response_json TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_intros_requested ON intros(requested_by);
    CREATE INDEX IF NOT EXISTS idx_intros_target ON intros(target_agent_id);
    CREATE INDEX IF NOT EXISTS idx_intros_status ON intros(status);

    CREATE TABLE IF NOT EXISTS rate_limits (
      public_key TEXT NOT NULL,
      action TEXT NOT NULL,
      window_start TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 1,
      PRIMARY KEY (public_key, action, window_start)
    );

    CREATE TABLE IF NOT EXISTS network_stats (
      stat_key TEXT PRIMARY KEY,
      stat_value INTEGER NOT NULL DEFAULT 0
    );

    INSERT OR IGNORE INTO network_stats (stat_key, stat_value) VALUES
      ('total_cards_published', 0),
      ('total_matches_computed', 0),
      ('total_intros_requested', 0),
      ('total_intros_approved', 0),
      ('total_intros_declined', 0);
  `);
    // ── Embeddings table (Phase 1B) ──
    d.exec(`
    CREATE TABLE IF NOT EXISTS card_embeddings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      card_id TEXT NOT NULL,
      agent_id TEXT NOT NULL,
      item_type TEXT NOT NULL,
      item_text TEXT NOT NULL,
      embedding BLOB NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (card_id) REFERENCES cards(card_id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_emb_card ON card_embeddings(card_id);
    CREATE INDEX IF NOT EXISTS idx_emb_agent ON card_embeddings(agent_id);
    CREATE INDEX IF NOT EXISTS idx_emb_type ON card_embeddings(item_type);
  `);
    // ── Phase 4: Trust signals + feedback ──
    d.exec(`
    CREATE TABLE IF NOT EXISTS identity_profiles (
      public_key TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      first_seen TEXT NOT NULL DEFAULT (datetime('now')),
      total_cards_published INTEGER NOT NULL DEFAULT 0,
      total_intros_sent INTEGER NOT NULL DEFAULT 0,
      total_intros_received INTEGER NOT NULL DEFAULT 0,
      total_intros_accepted INTEGER NOT NULL DEFAULT 0,
      total_intros_declined INTEGER NOT NULL DEFAULT 0,
      total_feedback_useful INTEGER NOT NULL DEFAULT 0,
      total_feedback_neutral INTEGER NOT NULL DEFAULT 0,
      total_feedback_not_useful INTEGER NOT NULL DEFAULT 0,
      github_url TEXT,
      website_url TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_ip_agent ON identity_profiles(agent_id);

    CREATE TABLE IF NOT EXISTS intro_feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      intro_id TEXT NOT NULL,
      from_agent TEXT NOT NULL,
      rating TEXT NOT NULL CHECK(rating IN ('useful', 'neutral', 'not_useful')),
      comment TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(intro_id, from_agent)
    );
  `);
}
// ══════════════════════════════════════
// Card Operations
// ══════════════════════════════════════
export function publishCard(card) {
    const d = getDb();
    // Remove expired cards first
    purgeExpired();
    // Check if agent already has a card (one card per agent)
    const existing = d.prepare('SELECT card_id FROM cards WHERE agent_id = ?').get(card.agentId);
    if (existing) {
        // Update existing card
        d.prepare(`
      UPDATE cards SET card_json = ?, principal_alias = ?, expires_at = ?, updated_at = datetime('now')
      WHERE agent_id = ?
    `).run(JSON.stringify(card), card.principalAlias, card.expiresAt, card.agentId);
        return { published: true };
    }
    d.prepare(`
    INSERT INTO cards (card_id, agent_id, public_key, principal_alias, card_json, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(card.cardId, card.agentId, card.publicKey, card.principalAlias, JSON.stringify(card), card.createdAt, card.expiresAt);
    incrementStat('total_cards_published');
    return { published: true };
}
export function getCard(agentId) {
    const d = getDb();
    purgeExpired();
    const row = d.prepare('SELECT card_json FROM cards WHERE agent_id = ? AND expires_at > datetime(\'now\')').get(agentId);
    return row ? JSON.parse(row.card_json) : null;
}
export function removeCard(cardId, publicKey) {
    // NW-006: Use public_key (cryptographically verified) not agent_id (self-reported)
    const d = getDb();
    const result = d.prepare('DELETE FROM cards WHERE card_id = ? AND public_key = ?').run(cardId, publicKey);
    return result.changes > 0;
}
export function getAllActiveCards() {
    const d = getDb();
    purgeExpired();
    const rows = d.prepare('SELECT card_json FROM cards WHERE expires_at > datetime(\'now\')').all();
    return rows.map(r => JSON.parse(r.card_json));
}
export function getCardCount() {
    const d = getDb();
    return d.prepare('SELECT COUNT(*) as count FROM cards WHERE expires_at > datetime(\'now\')').get().count;
}
// ══════════════════════════════════════
// Intro Operations
// ══════════════════════════════════════
export function createIntro(intro) {
    const d = getDb();
    try {
        d.prepare(`
      INSERT INTO intros (intro_id, requested_by, target_agent_id, match_id, message, fields_to_disclose, status, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(intro.introId, intro.requestedBy, intro.targetAgentId, intro.matchId, intro.message, JSON.stringify(intro.fieldsToDisclose), intro.status, intro.createdAt, intro.expiresAt);
        incrementStat('total_intros_requested');
        return { created: true };
    }
    catch (e) {
        return { created: false, error: e.message };
    }
}
export function getIntro(introId) {
    const d = getDb();
    const row = d.prepare('SELECT * FROM intros WHERE intro_id = ?').get(introId);
    if (!row)
        return null;
    return {
        introId: row.intro_id,
        requestedBy: row.requested_by,
        targetAgentId: row.target_agent_id,
        matchId: row.match_id,
        message: row.message,
        fieldsToDisclose: JSON.parse(row.fields_to_disclose),
        status: row.status,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        signature: '',
    };
}
export function updateIntroStatus(introId, status, responseJson) {
    const d = getDb();
    const result = d.prepare(`
    UPDATE intros SET status = ?, response_json = ?, updated_at = datetime('now') WHERE intro_id = ?
  `).run(status, responseJson || null, introId);
    if (result.changes > 0) {
        if (status === 'approved')
            incrementStat('total_intros_approved');
        if (status === 'declined')
            incrementStat('total_intros_declined');
    }
    return result.changes > 0;
}
export function getIntrosForAgent(agentId) {
    const d = getDb();
    const sent = d.prepare('SELECT * FROM intros WHERE requested_by = ? AND status = \'pending\'').all(agentId);
    const received = d.prepare('SELECT * FROM intros WHERE target_agent_id = ? AND status = \'pending\'').all(agentId);
    const mapRow = (row) => ({
        introId: row.intro_id,
        requestedBy: row.requested_by,
        targetAgentId: row.target_agent_id,
        matchId: row.match_id,
        message: row.message,
        fieldsToDisclose: JSON.parse(row.fields_to_disclose),
        status: row.status,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        signature: '',
    });
    return { sent: sent.map(mapRow), received: received.map(mapRow) };
}
// ══════════════════════════════════════
// Rate Limiting
// ══════════════════════════════════════
export function checkRateLimit(publicKey, action, maxPerHour) {
    const d = getDb();
    const windowStart = new Date();
    windowStart.setMinutes(0, 0, 0);
    const window = windowStart.toISOString();
    const row = d.prepare('SELECT count FROM rate_limits WHERE public_key = ? AND action = ? AND window_start = ?').get(publicKey, action, window);
    const current = row?.count || 0;
    if (current >= maxPerHour) {
        return { allowed: false, remaining: 0 };
    }
    // Upsert
    d.prepare(`
    INSERT INTO rate_limits (public_key, action, window_start, count)
    VALUES (?, ?, ?, 1)
    ON CONFLICT(public_key, action, window_start) DO UPDATE SET count = count + 1
  `).run(publicKey, action, window);
    return { allowed: true, remaining: maxPerHour - current - 1 };
}
// ══════════════════════════════════════
// Utilities
// ══════════════════════════════════════
export function purgeExpired() {
    const d = getDb();
    const cards = d.prepare('DELETE FROM cards WHERE expires_at <= datetime(\'now\')').run();
    const intros = d.prepare('UPDATE intros SET status = \'expired\' WHERE status = \'pending\' AND expires_at <= datetime(\'now\')').run();
    // Clean old rate limit windows (older than 2 hours)
    const cutoff = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
    d.prepare('DELETE FROM rate_limits WHERE window_start < ?').run(cutoff);
    return cards.changes + intros.changes;
}
function incrementStat(key) {
    const d = getDb();
    d.prepare('UPDATE network_stats SET stat_value = stat_value + 1 WHERE stat_key = ?').run(key);
}
export function getNetworkStats() {
    const d = getDb();
    const rows = d.prepare('SELECT stat_key, stat_value FROM network_stats').all();
    const stats = {};
    for (const row of rows)
        stats[row.stat_key] = row.stat_value;
    stats.active_cards = getCardCount();
    stats.pending_intros = d.prepare('SELECT COUNT(*) as c FROM intros WHERE status = \'pending\'').get().c;
    return stats;
}
export function closeDb() {
    if (db)
        db.close();
}
// ══════════════════════════════════════
// Embedding Operations (Phase 1B)
// ══════════════════════════════════════
/**
 * Store embeddings for a card's needs and offers.
 * Deletes previous embeddings for this card first (upsert).
 */
export function storeEmbeddings(cardId, agentId, items) {
    const d = getDb();
    // Clear old embeddings for this card
    d.prepare('DELETE FROM card_embeddings WHERE card_id = ?').run(cardId);
    // Also clear by agent_id for upserted cards that got a new card_id
    d.prepare('DELETE FROM card_embeddings WHERE agent_id = ?').run(agentId);
    const insert = d.prepare('INSERT INTO card_embeddings (card_id, agent_id, item_type, item_text, embedding) VALUES (?, ?, ?, ?, ?)');
    for (const item of items) {
        const buf = Buffer.from(item.vector.buffer);
        insert.run(cardId, agentId, item.type, item.text, buf);
    }
}
/**
 * Cross-vector search: find cards where their OFFERS match my NEEDS.
 * Returns top N agent_ids with best cosine similarity.
 */
export function searchOffersForNeeds(needVectors, excludeAgentId, limit = 15) {
    const d = getDb();
    // Get all offer embeddings for active cards
    const offers = d.prepare(`
    SELECT ce.agent_id, ce.item_text, ce.embedding
    FROM card_embeddings ce
    JOIN cards c ON ce.agent_id = c.agent_id
    WHERE ce.item_type = 'offer'
    AND c.expires_at > datetime('now')
    AND ce.agent_id != ?
  `).all(excludeAgentId);
    const matches = [];
    for (let ni = 0; ni < needVectors.length; ni++) {
        const needVec = needVectors[ni];
        for (const offer of offers) {
            const offerVec = new Float32Array(offer.embedding.buffer, offer.embedding.byteOffset, offer.embedding.byteLength / 4);
            // Dot product = cosine sim (vectors are normalized)
            let dot = 0;
            for (let i = 0; i < needVec.length; i++)
                dot += needVec[i] * offerVec[i];
            if (dot > 0.3) {
                matches.push({ agentId: offer.agent_id, score: dot, offerText: offer.item_text, needIdx: ni });
            }
        }
    }
    // Dedupe by agentId (keep best score), sort desc
    const best = new Map();
    for (const m of matches) {
        const existing = best.get(m.agentId);
        if (!existing || m.score > existing.score)
            best.set(m.agentId, m);
    }
    return Array.from(best.values()).sort((a, b) => b.score - a.score).slice(0, limit);
}
/**
 * Cross-vector search: find cards where their NEEDS match my OFFERS.
 */
export function searchNeedsForOffers(offerVectors, excludeAgentId, limit = 15) {
    const d = getDb();
    const needs = d.prepare(`
    SELECT ce.agent_id, ce.item_text, ce.embedding
    FROM card_embeddings ce
    JOIN cards c ON ce.agent_id = c.agent_id
    WHERE ce.item_type = 'need'
    AND c.expires_at > datetime('now')
    AND ce.agent_id != ?
  `).all(excludeAgentId);
    const matches = [];
    for (let oi = 0; oi < offerVectors.length; oi++) {
        const offerVec = offerVectors[oi];
        for (const need of needs) {
            const needVec = new Float32Array(need.embedding.buffer, need.embedding.byteOffset, need.embedding.byteLength / 4);
            let dot = 0;
            for (let i = 0; i < offerVec.length; i++)
                dot += offerVec[i] * needVec[i];
            if (dot > 0.3) {
                matches.push({ agentId: need.agent_id, score: dot, needText: need.item_text, offerIdx: oi });
            }
        }
    }
    const best = new Map();
    for (const m of matches) {
        const existing = best.get(m.agentId);
        if (!existing || m.score > existing.score)
            best.set(m.agentId, m);
    }
    return Array.from(best.values()).sort((a, b) => b.score - a.score).slice(0, limit);
}
/**
 * Combined semantic search: finds matches in both directions.
 * Returns top N candidates with combined scores and mutual bonus.
 */
export function semanticSearch(needVectors, offerVectors, agentId, limit = 15) {
    const offersForMyNeeds = searchOffersForNeeds(needVectors, agentId, 50);
    const needsForMyOffers = searchNeedsForOffers(offerVectors, agentId, 50);
    // Merge: agents appearing in both get a mutual bonus
    const combined = new Map();
    for (const m of offersForMyNeeds) {
        combined.set(m.agentId, { score: m.score, mutual: false, needMatch: m.offerText, offerMatch: null });
    }
    for (const m of needsForMyOffers) {
        const existing = combined.get(m.agentId);
        if (existing) {
            existing.mutual = true;
            existing.score = Math.min(1.0, (existing.score + m.score) / 2 + 0.15); // mutual bonus
            existing.offerMatch = m.needText;
        }
        else {
            combined.set(m.agentId, { score: m.score, mutual: false, needMatch: null, offerMatch: m.needText });
        }
    }
    return Array.from(combined.entries())
        .map(([agentId, data]) => ({ agentId, ...data }))
        .sort((a, b) => b.score - a.score)
        .slice(0, limit);
}
/**
 * Check if a card has embeddings stored.
 */
export function hasEmbeddings(agentId) {
    const d = getDb();
    const row = d.prepare('SELECT COUNT(*) as cnt FROM card_embeddings WHERE agent_id = ?').get(agentId);
    return row.cnt > 0;
}
export function getEmbeddingCount() {
    const d = getDb();
    return d.prepare('SELECT COUNT(*) as cnt FROM card_embeddings').get().cnt;
}
// ══════════════════════════════════════
// Phase 4: Trust Signals + Feedback
// ══════════════════════════════════════
/** Ensure an identity profile exists. Called on every card publish. */
export function ensureProfile(publicKey, agentId) {
    const d = getDb();
    const existing = d.prepare('SELECT public_key FROM identity_profiles WHERE public_key = ?').get(publicKey);
    if (!existing) {
        d.prepare('INSERT INTO identity_profiles (public_key, agent_id) VALUES (?, ?)').run(publicKey, agentId);
    }
}
/** Increment a profile counter. */
export function incrementProfile(publicKey, field) {
    const d = getDb();
    d.prepare(`UPDATE identity_profiles SET ${field} = ${field} + 1, updated_at = datetime('now') WHERE public_key = ?`).run(publicKey);
}
/** Get trust signals for an agent. */
export function getTrustSignals(agentId) {
    const d = getDb();
    const profile = d.prepare('SELECT * FROM identity_profiles WHERE agent_id = ?').get(agentId);
    if (!profile)
        return { identityAge: 0, responseRate: 0, acceptanceRate: 0, trustLevel: 'new' };
    const ageDays = Math.floor((Date.now() - new Date(profile.first_seen).getTime()) / 86400000);
    const totalReceived = profile.total_intros_received || 0;
    const totalResponded = (profile.total_intros_accepted || 0) + (profile.total_intros_declined || 0);
    const responseRate = totalReceived > 0 ? Math.round((totalResponded / totalReceived) * 100) : 0;
    const acceptanceRate = totalResponded > 0 ? Math.round((profile.total_intros_accepted / totalResponded) * 100) : 0;
    // Trust level based on age + activity
    let trustLevel = 'new';
    if (ageDays >= 1 && profile.total_intros_accepted >= 1)
        trustLevel = 'established';
    if (ageDays >= 7 && profile.total_intros_accepted >= 3 && responseRate >= 50)
        trustLevel = 'trusted';
    if (ageDays >= 30 && profile.total_intros_accepted >= 10 && responseRate >= 70)
        trustLevel = 'veteran';
    return {
        identityAge: ageDays,
        responseRate,
        acceptanceRate,
        totalPublished: profile.total_cards_published,
        totalIntrosSent: profile.total_intros_sent,
        totalIntrosAccepted: profile.total_intros_accepted,
        feedbackUseful: profile.total_feedback_useful,
        feedbackNotUseful: profile.total_feedback_not_useful,
        trustLevel,
        githubUrl: profile.github_url,
        websiteUrl: profile.website_url,
        linkedProofs: [profile.github_url, profile.website_url].filter(Boolean).length,
    };
}
/** Submit feedback for a completed intro. */
export function submitFeedback(introId, fromAgent, rating, comment) {
    const d = getDb();
    try {
        d.prepare('INSERT OR REPLACE INTO intro_feedback (intro_id, from_agent, rating, comment) VALUES (?, ?, ?, ?)').run(introId, fromAgent, rating, comment || null);
        // Update the other party's profile
        const intro = d.prepare('SELECT requested_by, target_agent_id FROM intros WHERE intro_id = ?').get(introId);
        if (intro) {
            const otherAgent = fromAgent === intro.requested_by ? intro.target_agent_id : intro.requested_by;
            const otherCard = d.prepare('SELECT public_key FROM cards WHERE agent_id = ?').get(otherAgent);
            if (otherCard) {
                if (rating === 'useful')
                    incrementProfile(otherCard.public_key, 'total_feedback_useful');
                else if (rating === 'not_useful')
                    incrementProfile(otherCard.public_key, 'total_feedback_not_useful');
                else
                    incrementProfile(otherCard.public_key, 'total_feedback_neutral');
            }
        }
        return true;
    }
    catch {
        return false;
    }
}
/** Update linked proofs for an identity. */
export function updateLinkedProofs(publicKey, githubUrl, websiteUrl) {
    const d = getDb();
    const updates = [];
    const params = [];
    if (githubUrl !== undefined) {
        updates.push('github_url = ?');
        params.push(githubUrl || null);
    }
    if (websiteUrl !== undefined) {
        updates.push('website_url = ?');
        params.push(websiteUrl || null);
    }
    if (updates.length > 0) {
        updates.push("updated_at = datetime('now')");
        params.push(publicKey);
        d.prepare(`UPDATE identity_profiles SET ${updates.join(', ')} WHERE public_key = ?`).run(...params);
    }
}
//# sourceMappingURL=db.js.map