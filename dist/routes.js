// ══════════════════════════════════════════════════════════════
// Intent Network API — Routes
// ══════════════════════════════════════════════════════════════
import { Router } from 'express';
import { requireSignature, identifyAgent } from './auth.js';
import * as db from './db.js';
import { computeRelevance, verifyIntentCard, isCardExpired, } from 'agent-passport-system';
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
        const key = req.verifiedPublicKey || String(req.headers['x-public-key'] || '') || req.ip || 'anonymous';
        const check = db.checkRateLimit(key, action, limit);
        if (!check.allowed) {
            res.status(429).json({ error: 'Rate limit exceeded', retryAfterSeconds: 3600 });
            return;
        }
        res.setHeader('X-RateLimit-Remaining', check.remaining);
        next();
    };
}
// ══════════════════════════════════════
// POST /api/cards — Publish IntentCard
// ══════════════════════════════════════
router.post('/cards', requireSignature, rateLimit('publish', LIMITS.publish), (req, res) => {
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
    const result = db.publishCard(card);
    if (!result.published) {
        res.status(500).json({ error: result.error });
        return;
    }
    res.status(201).json({
        published: true,
        cardId: card.cardId,
        agentId: card.agentId,
        expiresAt: card.expiresAt,
        networkSize: db.getCardCount(),
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
    const removed = db.removeCard(String(req.params.cardId), req.verifiedAgentId || '');
    if (!removed) {
        res.status(404).json({ error: 'Card not found or not owned by you' });
        return;
    }
    res.json({ removed: true, cardId: String(req.params.cardId) });
});
// ══════════════════════════════════════
// GET /api/matches/:agentId — Ranked matches
// ══════════════════════════════════════
router.get('/matches/:agentId', identifyAgent, rateLimit('search', LIMITS.search), (req, res) => {
    const agentId = String(req.params.agentId);
    const myCard = db.getCard(agentId);
    if (!myCard) {
        res.status(404).json({ error: 'No active card. Publish a card first.' });
        return;
    }
    const allCards = db.getAllActiveCards();
    const matches = [];
    for (const other of allCards) {
        if (other.agentId === agentId)
            continue;
        const match = computeRelevance(myCard, other);
        if (match && match.score > 0) {
            matches.push(match);
        }
    }
    // Sort by score descending
    matches.sort((a, b) => b.score - a.score);
    const maxResults = Math.min(parseInt(String(req.query.max || '10')), 50);
    const minScore = parseFloat(String(req.query.minScore || '0'));
    const filtered = matches.filter(m => m.score >= minScore).slice(0, maxResults);
    res.json({
        agentId,
        matchCount: filtered.length,
        totalCandidates: allCards.length - 1,
        matches: filtered,
    });
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
    res.json({ introId: String(req.params.introId), status: verdict === 'approve' ? 'approved' : 'declined' });
});
// ══════════════════════════════════════
// GET /api/digest/:agentId — Personalized digest
// ══════════════════════════════════════
router.get('/digest/:agentId', identifyAgent, rateLimit('digest', LIMITS.digest), (req, res) => {
    const agentId = String(req.params.agentId);
    const myCard = db.getCard(agentId);
    // Get matches
    let matches = [];
    if (myCard) {
        const allCards = db.getAllActiveCards();
        for (const other of allCards) {
            if (other.agentId === agentId)
                continue;
            const match = computeRelevance(myCard, other);
            if (match && match.score > 0)
                matches.push(match);
        }
        matches.sort((a, b) => b.score - a.score);
        matches = matches.slice(0, 10);
    }
    // Get intros
    const intros = db.getIntrosForAgent(agentId);
    // Build summary
    const parts = [];
    if (matches.length > 0)
        parts.push(`${matches.length} relevant match${matches.length > 1 ? 'es' : ''}`);
    if (intros.sent.length > 0)
        parts.push(`${intros.sent.length} intro${intros.sent.length > 1 ? 's' : ''} pending response`);
    if (intros.received.length > 0)
        parts.push(`${intros.received.length} intro${intros.received.length > 1 ? 's' : ''} for you to review`);
    const summary = parts.length > 0 ? parts.join(', ') : 'Nothing new right now';
    res.json({
        agentId,
        generatedAt: new Date().toISOString(),
        summary,
        matches,
        introsPending: intros.sent,
        introsReceived: intros.received,
        hasCard: !!myCard,
        networkSize: db.getCardCount(),
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
export default router;
//# sourceMappingURL=routes.js.map