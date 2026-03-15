// ══════════════════════════════════════════════════════════════
// Intent Network API — Routes
// ══════════════════════════════════════════════════════════════
import { Router } from 'express';
import { requireSignature, identifyAgent } from './auth.js';
import * as db from './db.js';
import { embedBatch } from './embeddings.js';
import { verifyIntentCard, isCardExpired, } from 'agent-passport-system';
const router = Router();
// ── Rate limit config ──
const LIMITS = {
    publish: 10, // cards per hour
    search: 30, // searches per hour
    intro: 10, // intro requests per hour
    digest: 30, // digests per hour
};
function rateLimit(action, limit) {
    return (req, res, next) => {
        // Check per-key rate limit
        const key = req.verifiedPublicKey || String(req.headers['x-public-key'] || '') || req.ip || 'anonymous';
        const check = db.checkRateLimit(key, action, limit);
        if (!check.allowed) {
            res.status(429).json({ error: 'Rate limit exceeded', retryAfterSeconds: 3600 });
            return;
        }
        // Also check per-IP rate limit (prevents key rotation bypass)
        const ip = req.ip || req.socket?.remoteAddress || 'unknown';
        const ipLimit = limit * 5; // IP limit is 5x per-key limit
        const ipCheck = db.checkRateLimit(`ip:${ip}`, action, ipLimit);
        if (!ipCheck.allowed) {
            res.status(429).json({ error: 'IP rate limit exceeded', retryAfterSeconds: 3600 });
            return;
        }
        res.setHeader('X-RateLimit-Remaining', Math.min(check.remaining, ipCheck.remaining));
        next();
    };
}
// ══════════════════════════════════════
// POST /api/cards — Publish IntentCard
// ══════════════════════════════════════
router.post('/cards', requireSignature, rateLimit('publish', LIMITS.publish), async (req, res) => {
    const card = req.body.card || req.body;
    // Validate the card structure
    if (!card.cardId || !card.agentId || !card.publicKey) {
        res.status(400).json({ error: 'Invalid card: missing cardId, agentId, or publicKey' });
        return;
    }
    if ((!card.needs || card.needs.length === 0) && (!card.offers || card.offers.length === 0)) {
        res.status(400).json({ error: 'Card must have at least one need or offer' });
        return;
    }
    // Field-level size constraints — prevent bloat and injection payloads
    const MAX_ITEMS = 10;
    const MAX_FIELD_LEN = 1000;
    if (card.agentId.length > 200) {
        res.status(400).json({ error: 'agentId too long (max 200)' });
        return;
    }
    if ((card.needs?.length || 0) > MAX_ITEMS) {
        res.status(400).json({ error: `Too many needs (max ${MAX_ITEMS})` });
        return;
    }
    if ((card.offers?.length || 0) > MAX_ITEMS) {
        res.status(400).json({ error: `Too many offers (max ${MAX_ITEMS})` });
        return;
    }
    for (const item of [...(card.needs || []), ...(card.offers || [])]) {
        const desc = typeof item === 'string' ? item : item?.description || '';
        if (desc.length > MAX_FIELD_LEN) {
            res.status(400).json({ error: `Field too long (max ${MAX_FIELD_LEN} chars)` });
            return;
        }
    }
    // Verify card signature
    if (!verifyIntentCard(card)) {
        res.status(403).json({ error: 'Card signature verification failed' });
        return;
    }
    // Check if already expired
    if (isCardExpired(card)) {
        res.status(400).json({ error: 'Card is already expired' });
        return;
    }
    // Default principalAlias to agentId if not provided
    if (!card.principalAlias) {
        card.principalAlias = card.agentId;
    }
    const result = db.publishCard(card);
    if (!result.published) {
        res.status(500).json({ error: result.error });
        return;
    }
    // Phase 4: Track identity profile
    db.ensureProfile(card.publicKey, card.agentId);
    db.incrementProfile(card.publicKey, 'total_cards_published');
    // ── Phase 1B: Embed needs and offers for semantic matching ──
    let topMatches = [];
    try {
        const needTexts = (card.needs || []).map((n) => typeof n === 'string' ? n : n.description || '');
        const offerTexts = (card.offers || []).map((o) => typeof o === 'string' ? o : o.description || '');
        const contextText = card.context || '';
        // Embed all texts
        const allTexts = [
            ...needTexts.map((t) => contextText ? `${t} ${contextText}` : t),
            ...offerTexts.map((t) => contextText ? `${t} ${contextText}` : t),
        ];
        const vectors = await embedBatch(allTexts.filter((t) => t.length > 0));
        // Store embeddings
        const items = [];
        let vi = 0;
        for (const t of needTexts) {
            if (t) {
                items.push({ type: 'need', text: t, vector: vectors[vi++] });
            }
        }
        for (const t of offerTexts) {
            if (t) {
                items.push({ type: 'offer', text: t, vector: vectors[vi++] });
            }
        }
        if (items.length > 0) {
            db.storeEmbeddings(card.cardId, card.agentId, items);
            // Return top 3 matches inline
            const needVecs = items.filter(i => i.type === 'need').map(i => i.vector);
            const offerVecs = items.filter(i => i.type === 'offer').map(i => i.vector);
            if (needVecs.length > 0 || offerVecs.length > 0) {
                const matches = db.semanticSearch(needVecs, offerVecs, card.agentId, 3);
                topMatches = matches.map(m => ({
                    agentId: m.agentId,
                    score: Math.round(m.score * 100) / 100,
                    mutual: m.mutual,
                    needMatch: m.needMatch,
                    offerMatch: m.offerMatch,
                }));
            }
        }
    }
    catch (e) {
        console.error('[embeddings] Failed to embed card:', e.message);
    }
    res.status(201).json({
        published: true,
        cardId: card.cardId,
        agentId: card.agentId,
        expiresAt: card.expiresAt,
        networkSize: db.getCardCount(),
        topMatches,
        matchingVersion: topMatches.length > 0 ? 'semantic-v1' : 'pending-embeddings',
        embeddingsStored: topMatches.length > 0 || db.hasEmbeddings(card.agentId),
    });
});
// ══════════════════════════════════════
// GET /api/cards/:agentId — Get card
// ══════════════════════════════════════
router.get('/cards/:agentId', (req, res) => {
    const card = db.getCard(String(req.params.agentId));
    if (!card) {
        res.status(404).json({ error: 'No active card for this agent' });
        return;
    }
    res.json({ card });
});
// ══════════════════════════════════════
// DELETE /api/cards/:cardId — Remove card
// ══════════════════════════════════════
router.delete('/cards/:cardId', requireSignature, (req, res) => {
    // NW-006: Use verifiedPublicKey (cryptographically proven) for ownership check
    const removed = db.removeCard(String(req.params.cardId), req.verifiedPublicKey || '');
    if (!removed) {
        res.status(404).json({ error: 'Card not found or not owned by you' });
        return;
    }
    res.json({ removed: true, cardId: String(req.params.cardId) });
});
// ══════════════════════════════════════
// GET /api/matches/:agentId — Ranked matches
// ══════════════════════════════════════
router.get('/matches/:agentId', identifyAgent, rateLimit('search', LIMITS.search), async (req, res) => {
    const agentId = String(req.params.agentId);
    const myCard = db.getCard(agentId);
    if (!myCard) {
        res.status(404).json({ error: 'No active card. Publish a card first.' });
        return;
    }
    const maxResults = Math.min(parseInt(String(req.query.max || '15')), 50);
    const minScore = parseFloat(String(req.query.minScore || '0.3'));
    // Semantic matching via embeddings
    if (db.hasEmbeddings(agentId)) {
        try {
            const needTexts = (myCard.needs || []).map((n) => typeof n === 'string' ? n : n.description || '');
            const offerTexts = (myCard.offers || []).map((o) => typeof o === 'string' ? o : o.description || '');
            const needVecs = await embedBatch(needTexts.filter((t) => t));
            const offerVecs = await embedBatch(offerTexts.filter((t) => t));
            const matches = db.semanticSearch(needVecs, offerVecs, agentId, maxResults)
                .filter(m => m.score >= minScore);
            // Enrich with card info + trust signals
            const enriched = matches.map(m => {
                const card = db.getCard(m.agentId);
                const trust = db.getTrustSignals(m.agentId);
                return {
                    matchId: `match_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
                    agentId: m.agentId,
                    name: card?.principalAlias || m.agentId,
                    score: Math.round(m.score * 100) / 100,
                    mutual: m.mutual,
                    needMatch: m.needMatch,
                    offerMatch: m.offerMatch,
                    source: card?.source || 'organic',
                    trust: { level: trust.trustLevel, age: trust.identityAge, responseRate: trust.responseRate, linkedProofs: trust.linkedProofs },
                    matchingVersion: 'semantic-v1',
                };
            });
            res.json({ agentId, matchCount: enriched.length, totalCandidates: db.getCardCount() - 1, matches: enriched });
            return;
        }
        catch (e) {
            console.error('[matches] Semantic search failed, falling back:', e.message);
        }
    }
    // Fallback: old matching (for cards without embeddings)
    res.json({ agentId, matchCount: 0, totalCandidates: db.getCardCount() - 1, matches: [], matchingVersion: 'pending-embeddings' });
});
// ══════════════════════════════════════
// POST /api/matches/ghost — Ghost mode: search without a published card
// ══════════════════════════════════════
router.post('/matches/ghost', rateLimit('search', LIMITS.search), async (req, res) => {
    const { needs, offers } = req.body || {};
    if ((!needs || needs.length === 0) && (!offers || offers.length === 0)) {
        res.status(400).json({ error: 'Provide at least one need or offer to search' });
        return;
    }
    const maxResults = Math.min(parseInt(String(req.query?.max || '15')), 50);
    const needTexts = (needs || []).map((n) => typeof n === 'string' ? n : n.description || '');
    const offerTexts = (offers || []).map((o) => typeof o === 'string' ? o : o.description || '');
    try {
        const needVecs = await embedBatch(needTexts.filter((t) => t));
        const offerVecs = await embedBatch(offerTexts.filter((t) => t));
        const matches = db.semanticSearch(needVecs, offerVecs, '__ghost__', maxResults)
            .map(m => {
            const card = db.getCard(m.agentId);
            return {
                agentId: m.agentId,
                name: card?.principalAlias || m.agentId,
                score: Math.round(m.score * 100) / 100,
                mutual: m.mutual,
                needMatch: m.needMatch,
                offerMatch: m.offerMatch,
                source: card?.source || 'organic',
            };
        });
        res.json({ ghost: true, matchCount: matches.length, totalCandidates: db.getCardCount(), matches });
    }
    catch (e) {
        res.status(500).json({ error: 'Matching failed: ' + e.message });
    }
});
// ══════════════════════════════════════
// POST /api/intros — Request introduction
// ══════════════════════════════════════
router.post('/intros', requireSignature, rateLimit('intro', LIMITS.intro), (req, res) => {
    const { matchId, targetAgentId, message, fieldsToDisclose } = req.body;
    const requestedBy = req.verifiedAgentId;
    if (!requestedBy || !targetAgentId || !matchId || !message) {
        res.status(400).json({ error: 'Missing required fields: matchId, targetAgentId, message' });
        return;
    }
    // Verify target has an active card
    const targetCard = db.getCard(targetAgentId);
    if (!targetCard) {
        res.status(404).json({ error: 'Target agent has no active card' });
        return;
    }
    const introId = `intro-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const intro = {
        introId,
        requestedBy,
        targetAgentId,
        matchId,
        message,
        fieldsToDisclose: fieldsToDisclose || ['needs', 'offers'],
        status: 'pending',
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString(),
        signature: req.body.signature || '',
    };
    const result = db.createIntro(intro);
    if (!result.created) {
        res.status(500).json({ error: result.error });
        return;
    }
    // Phase 4: Track intro stats
    if (req.verifiedPublicKey)
        db.incrementProfile(req.verifiedPublicKey, 'total_intros_sent');
    // Track target's received count
    const targetProfile = db.getCard(targetAgentId);
    if (targetProfile?.publicKey)
        db.incrementProfile(targetProfile.publicKey, 'total_intros_received');
    res.status(201).json({ introId, status: 'pending', targetAgentId });
});
// ══════════════════════════════════════
// PUT /api/intros/:introId — Respond to intro
// ══════════════════════════════════════
router.put('/intros/:introId', requireSignature, (req, res) => {
    const intro = db.getIntro(String(req.params.introId));
    if (!intro) {
        res.status(404).json({ error: 'Intro not found' });
        return;
    }
    if (intro.targetAgentId !== req.verifiedAgentId) {
        res.status(403).json({ error: 'Only the target agent can respond to this intro' });
        return;
    }
    if (intro.status !== 'pending') {
        res.status(400).json({ error: `Intro already ${intro.status}` });
        return;
    }
    const { verdict, message: responseMessage, disclosedFields } = req.body;
    if (!verdict || !['approve', 'decline'].includes(verdict)) {
        res.status(400).json({ error: 'verdict must be "approve" or "decline"' });
        return;
    }
    const responseJson = JSON.stringify({ verdict, message: responseMessage, disclosedFields, respondedAt: new Date().toISOString() });
    db.updateIntroStatus(String(req.params.introId), verdict === 'approve' ? 'approved' : 'declined', responseJson);
    // Phase 4: Track accepted/declined on requester's profile
    const introRecord = db.getDb().prepare('SELECT requested_by FROM intros WHERE intro_id = ?').get(String(req.params.introId));
    if (introRecord) {
        const requesterCard = db.getCard(introRecord.requested_by);
        if (requesterCard?.publicKey) {
            db.incrementProfile(requesterCard.publicKey, verdict === 'approve' ? 'total_intros_accepted' : 'total_intros_declined');
        }
    }
    res.json({ introId: String(req.params.introId), status: verdict === 'approve' ? 'approved' : 'declined' });
});
// ══════════════════════════════════════
// GET /api/digest/:agentId — Personalized digest
// ══════════════════════════════════════
router.get('/digest/:agentId', identifyAgent, rateLimit('digest', LIMITS.digest), async (req, res) => {
    const agentId = String(req.params.agentId);
    const myCard = db.getCard(agentId);
    // Get matches via semantic search
    let semanticMatches = [];
    if (myCard && db.hasEmbeddings(agentId)) {
        try {
            const needTexts = (myCard.needs || []).map((n) => typeof n === 'string' ? n : n.description || '');
            const offerTexts = (myCard.offers || []).map((o) => typeof o === 'string' ? o : o.description || '');
            const needVecs = await embedBatch(needTexts.filter((t) => t));
            const offerVecs = await embedBatch(offerTexts.filter((t) => t));
            semanticMatches = db.semanticSearch(needVecs, offerVecs, agentId, 10)
                .map(m => {
                const card = db.getCard(m.agentId);
                return { agentId: m.agentId, name: card?.principalAlias || m.agentId, score: Math.round(m.score * 100) / 100, mutual: m.mutual, needMatch: m.needMatch, offerMatch: m.offerMatch, source: card?.source || 'organic' };
            });
        }
        catch (e) {
            console.error('[digest] Semantic match failed:', e.message);
        }
    }
    // Get intros
    const intros = db.getIntrosForAgent(agentId);
    // Build summary
    const parts = [];
    if (semanticMatches.length > 0)
        parts.push(`${semanticMatches.length} relevant match${semanticMatches.length > 1 ? 'es' : ''}`);
    if (intros.sent.length > 0)
        parts.push(`${intros.sent.length} intro${intros.sent.length > 1 ? 's' : ''} pending response`);
    if (intros.received.length > 0)
        parts.push(`${intros.received.length} intro${intros.received.length > 1 ? 's' : ''} for you to review`);
    const summary = parts.length > 0 ? parts.join(', ') : 'Nothing new right now';
    res.json({
        agentId,
        generatedAt: new Date().toISOString(),
        summary,
        matches: semanticMatches,
        introsPending: intros.sent,
        introsReceived: intros.received,
        hasCard: !!myCard,
        networkSize: db.getCardCount(),
    });
});
// ══════════════════════════════════════
// GET /api/resolve — Cross-protocol identity resolution
// Implements the APS side of the AIP↔APS bridge spec
// ══════════════════════════════════════
router.get('/resolve', async (req, res) => {
    const did = String(req.query.did || '');
    if (!did) {
        res.status(400).json({ error: 'Missing ?did= query parameter. Usage: /api/resolve?did=did:aps:agentId or did:aip:suffix' });
        return;
    }
    // ── Cross-protocol proxy: did:aip → forward to AIP service ──
    const aipMatch = did.match(/^did:aip:(.+)$/);
    if (aipMatch) {
        try {
            const aipUrl = `https://aip-service.fly.dev/resolve/${did}`;
            const aipRes = await fetch(aipUrl);
            if (!aipRes.ok) {
                res.status(aipRes.status).json({ error: `AIP service returned ${aipRes.status}`, did, proxied_to: aipUrl });
                return;
            }
            const aipData = await aipRes.json();
            // Return with bridge metadata
            res.json({
                ...aipData,
                resolved_via: 'aps-bridge',
                source_protocol: 'aip',
                bridge_note: 'Resolved via APS→AIP cross-protocol bridge at api.aeoess.com',
                resolved_at: new Date().toISOString(),
            });
            return;
        }
        catch (err) {
            res.status(502).json({ error: `Failed to reach AIP service: ${err.message}`, did });
            return;
        }
    }
    // Support did:aps:<agentId> format
    const apsMatch = did.match(/^did:aps:(.+)$/);
    // Also support raw agentId lookup
    const agentId = apsMatch ? apsMatch[1] : did;
    const card = db.getCard(agentId);
    if (!card) {
        res.status(404).json({ error: `Identity not found: ${did}` });
        return;
    }
    // Return unified bridge response format (hex-encoded public key)
    const pubKeyHex = Buffer.from(card.publicKey, 'base64').toString('hex');
    res.json({
        did: `did:aps:${card.agentId}`,
        source_protocol: 'aps',
        public_key: pubKeyHex,
        public_key_type: 'Ed25519VerificationKey2020',
        trust_summary: {
            behavioral: null,
        },
        challenge_endpoint: `https://${req.get('host')}/api/challenge/create`,
        resolved_at: new Date().toISOString(),
        card_summary: {
            needs: card.needs?.map((n) => n.description || n) || [],
            offers: card.offers?.map((o) => o.description || o) || [],
            expiresAt: card.expiresAt,
        },
    });
});
// ══════════════════════════════════════
// POST /api/challenge/create — Challenge-response verification
// ══════════════════════════════════════
router.post('/challenge/create', (req, res) => {
    const { did, nonce } = req.body;
    if (!did || !nonce) {
        res.status(400).json({ error: 'Missing did or nonce' });
        return;
    }
    const apsMatch = did.match(/^did:aps:(.+)$/);
    const agentId = apsMatch ? apsMatch[1] : did;
    const card = db.getCard(agentId);
    if (!card) {
        res.status(404).json({ error: `Identity not found: ${did}` });
        return;
    }
    const pubKeyHex = Buffer.from(card.publicKey, 'base64').toString('hex');
    res.json({
        did: `did:aps:${card.agentId}`,
        public_key: pubKeyHex,
        public_key_type: 'Ed25519VerificationKey2020',
        challenge_nonce: nonce,
        message: 'Use the public key to verify Ed25519 signatures from this agent.',
    });
});
// ══════════════════════════════════════
// GET /api/stats — Public network stats
// ══════════════════════════════════════
router.get('/stats', (_req, res) => {
    const stats = db.getNetworkStats();
    res.json({
        ...stats,
        version: '0.1.0',
        protocol: 'agent-passport-system',
        uptime: process.uptime(),
    });
});
// ══════════════════════════════════════
// GET /api/health — Detailed health check
// ══════════════════════════════════════
router.get('/health', (_req, res) => {
    const stats = db.getNetworkStats();
    const d = db.getDb();
    const uniqueKeys = d.prepare('SELECT COUNT(DISTINCT public_key) as cnt FROM cards WHERE expires_at > datetime(\'now\')').get()?.cnt || 0;
    const lastCard = d.prepare('SELECT created_at FROM cards ORDER BY created_at DESC LIMIT 1').get()?.created_at || null;
    const embCount = db.getEmbeddingCount();
    res.json({
        status: 'ok',
        activeCards: stats.active_cards,
        activeUsers: uniqueKeys,
        totalPublished: stats.total_cards_published,
        totalIntrosApproved: stats.total_intros_approved,
        pendingIntros: stats.pending_intros,
        lastCardPublished: lastCard,
        embeddingsStored: embCount,
        uptime: Math.round(process.uptime()),
        version: '0.4.0',
    });
});
// ══════════════════════════════════════
// POST /api/feedback/:introId — Submit intro feedback
// ══════════════════════════════════════
router.post('/feedback/:introId', identifyAgent, (req, res) => {
    const { rating, comment } = req.body || {};
    if (!rating || !['useful', 'neutral', 'not_useful'].includes(rating)) {
        res.status(400).json({ error: 'Rating must be useful, neutral, or not_useful' });
        return;
    }
    const agentId = req.verifiedAgentId;
    if (!agentId) {
        res.status(401).json({ error: 'Missing agent identity' });
        return;
    }
    const ok = db.submitFeedback(String(req.params.introId), agentId, rating, comment);
    if (!ok) {
        res.status(500).json({ error: 'Failed to submit feedback' });
        return;
    }
    res.json({ submitted: true, introId: String(req.params.introId), rating });
});
// ══════════════════════════════════════
// GET /api/trust/:agentId — Trust signals
// ══════════════════════════════════════
router.get('/trust/:agentId', (req, res) => {
    const trust = db.getTrustSignals(String(req.params.agentId));
    res.json({ agentId: String(req.params.agentId), ...trust });
});
export default router;
//# sourceMappingURL=routes.js.map