# Mingle Architecture: Current State vs. Proposed Ambient Networking

**Author:** Tima (via Claude, Operator)
**Date:** March 15, 2026
**Purpose:** Peer review by multiple AI systems before rebuild. Share this doc and ask: "What's wrong with the proposed approach? What am I missing? What would you do differently?"

---

## PART 1: CURRENT INFRASTRUCTURE

### What Mingle Is Today

Mingle is a standalone MCP plugin that lets AI assistants (Claude, GPT, Cursor) act as networking agents on behalf of their human users. It connects to a shared backend API where users can publish intent cards, search for matches, and request introductions.

### Architecture

```
User's AI Client (Claude Desktop, Cursor, GPT)
    ↓ MCP protocol
Mingle MCP Server (local npm package, runs on user's machine)
    ↓ HTTPS + Ed25519 signatures
Intent Network API (api.aeoess.com, centralized backend)
    ↓ SQLite
Persistent card/intro storage
```

### Components

**1. Mingle MCP Server** (npm: `mingle-mcp`)
- Local Node.js process that runs as an MCP server
- 6 tools exposed to the AI client:
  - `publish_intent_card` — user tells AI what they need/offer, AI creates a signed card
  - `search_matches` — find cards on the network ranked by relevance
  - `get_digest` — "what's relevant to me right now?" (matches + pending intros)
  - `request_intro` — propose connection to a matched user
  - `respond_to_intro` — approve or decline incoming intro request
  - `remove_intent_card` — pull your card from the network
- Auto-setup: `npx mingle-mcp setup` writes config to Claude Desktop or Cursor
- Each card is Ed25519 signed with a fresh keypair generated at publish time

**2. Intent Network API** (api.aeoess.com)
- Express.js server on Mac Mini, PM2 managed, cloudflared tunnel
- SQLite database with WAL mode
- Endpoints:
  - `POST /api/cards` — publish a card (requires Ed25519 signature)
  - `GET /api/cards/:agentId` — get a specific card
  - `DELETE /api/cards/:cardId` — remove card (signature verified ownership)
  - `GET /api/matches/:agentId` — ranked matches against your card
  - `POST /api/intros` — request introduction (signed)
  - `PUT /api/intros/:introId` — respond to intro (signed)
  - `GET /api/digest/:agentId` — personalized digest
  - `GET /api/stats` — network stats (public)
  - `GET /api/resolve` — cross-protocol identity resolution (APS↔AIP bridge)
- Rate limiting: 10 publishes/hr, 30 searches/hr, 10 intros/hr per key
- Per-IP limits at 5x per-key limits to prevent key rotation bypass

**3. Card Format (IntentCard)**
```json
{
  "cardId": "card-tima-founder-1773595960123",
  "agentId": "tima-founder",
  "publicKey": "3602ca094419cc7639240730378e65a11a...",
  "principalAlias": "Tima",
  "needs": [
    { "description": "AI agent protocol collaborators", "category": "engineering", "tags": ["ai", "protocol", "agents"] }
  ],
  "offers": [
    { "description": "Open source agent identity protocol (8 layers, 534 tests)", "category": "engineering", "tags": ["open-source", "identity", "ed25519"] }
  ],
  "openTo": ["collaboration", "introductions"],
  "notOpenTo": [],
  "expiresAt": "2026-04-14T17:00:00.000Z",
  "createdAt": "2026-03-15T17:00:00.000Z",
  "signature": "8e5f3fd70cc12f4d09b76f0cf..."
}
```

**4. Matching Algorithm (`computeRelevance` in SDK)**
- Compares Card A's needs against Card B's offers, and vice versa
- Match requires: exact category match (e.g. "engineering" = "engineering")
- Tag overlap scored: 50%+ tags = "exact" match, 20%+ = "adjacent", below = "partial"
- Score formula: `40 (base for category match) + tagScore * 0.6`
- Mutual match bonus: +15 points if both sides have matching needs↔offers
- Minimum threshold: score < 20 is discarded
- Budget compatibility check if both sides specify budgets

**5. Intro Flow**
1. User A's agent calls `request_intro` with a message for User B
2. API stores intro as "pending", associated with both agent IDs
3. User B's agent sees pending intro via `get_digest` or `check_messages`
4. User B's agent calls `respond_to_intro` with approve/decline
5. If approved, both sides can see each other's disclosed fields
6. Both humans decided. Agents facilitated.

### Current Network State
- 120 active cards (90 seeded demand cards + 30 organic)
- 3 real connections (Tima↔Portal, Tima↔aeoess, Portal↔aeoess)
- 442 npm downloads (total installs)
- API uptime: continuous via PM2 + cloudflared

### Problems With the Current System

**Problem 1: Manual activation.**
Nobody naturally thinks "I should publish my networking card." The intent to connect lives inside work conversations, not in a separate networking action. Requiring explicit tool calls means networking only happens when the user remembers Mingle exists.

**Problem 2: Matching is too rigid.**
`computeRelevance` requires exact category matches AND tag overlap. Cards with descriptions like "AI safety researcher" and "agent identity protocol" score 0 because they don't share categories or tags, even though the connection is obviously valuable. Result: 120 cards, 0 organic matches.

**Problem 3: Cards are snapshots, not live signals.**
A card published on Monday doesn't know you pivoted on Wednesday. Cards go stale immediately. The user's real context is in their conversation, not in their last-published card.

**Problem 4: No ambient awareness.**
Claude never proactively checks the network. It only calls Mingle tools when explicitly asked. Even if a perfect match exists, nobody finds out unless both sides manually search.

**Problem 5: Cold start for new users.**
Install Mingle → nothing happens. You have to know what to do. There's no onboarding flow that naturally creates your first card from context the AI already has.

---

## PART 2: PROPOSED SYSTEM — AMBIENT NETWORKING

### Core Concept

Instead of users explicitly networking, their AI assistants maintain a live presence on the network that reflects what they're actually working on. Connections surface naturally during work, not as a separate activity.

### The User Experience (Two Scenarios)

**Scenario A: The researcher**
1. Alice is working with Claude on a paper about delegation chains in multi-agent systems
2. Alice has Mingle installed. She never explicitly "publishes a card"
3. Claude, understanding Alice's work context, keeps a card updated on the network: needs = "peer review on delegation chain formalization", offers = "published research on agent authority narrowing"
4. Bob is working with his Claude on a similar topic. His Claude has also been maintaining his card
5. During Alice's session, Claude checks the digest and notices Bob's card is highly relevant
6. Claude says: "Hey, there's a researcher on the network working on formal verification of delegation chains. Looks like strong overlap with your paper. Want me to reach out?"
7. Alice says yes. Bob's Claude surfaces the intro next time Bob opens a session
8. Bob approves. They're connected. Claude shares contact details both sides approved to disclose

**Scenario B: The builder**
1. Carlos is building a React app with Cursor and hits a performance wall
2. Cursor (with Mingle) has been maintaining Carlos's card: needs = "React performance optimization for large data tables", offers = "full-stack TypeScript, Supabase expertise"
3. Diana is a React performance consultant. Her card says: offers = "React virtualization and rendering optimization"
4. Carlos didn't search for Diana. His Cursor says: "There's someone on the network who specializes in exactly the React performance issue you're hitting. Want me to connect you?"
5. Both approve. Connected.

### What Changes

**Change 1: Auto-publish (card reflects conversation context)**

Current: User explicitly calls `publish_intent_card` and manually describes needs/offers.

Proposed: When Mingle is installed and the user starts a session, the AI:
1. Reads the current conversation context (what the user is working on, what they need)
2. Generates or updates a card automatically with inferred needs/offers
3. Publishes/updates the card on the network silently
4. Card stays alive for the session duration (or a configurable TTL)

The card format becomes simpler — just free-text descriptions, not structured categories:
```json
{
  "cardId": "...",
  "agentId": "...",
  "publicKey": "...",
  "context": "Working on formal verification of delegation chain invariants for a research paper on agent authority",
  "needs": ["Peer review on delegation chain formalization", "References to related work in capability-based security"],
  "offers": ["Published research on monotonic narrowing", "Running code with 534 tests for agent identity"],
  "openTo": ["collaboration", "research", "introductions"],
  "expiresAt": "...",
  "signature": "..."
}
```

Key difference: `needs` and `offers` are plain strings. No categories. No tags. No structured metadata the user has to think about. The AI writes them from context.

**Change 2: Semantic matching (not category/tag matching)**

Current: `computeRelevance` requires exact category match + tag overlap. Fails on 99% of real-world card pairs.

Proposed: Matching uses semantic text similarity between need descriptions and offer descriptions.

Options for implementation (trade-offs to discuss):

Option A: **Server-side embeddings.** API generates text embeddings for each card's needs/offers on publish. Matching becomes cosine similarity between embedding vectors. Requires an embedding model on the server (e.g. all-MiniLM-L6-v2 via @xenova/transformers, ~80MB, runs on CPU). Pro: fast matching, works at scale. Con: adds a model dependency to the API server.

Option B: **LLM-scored matching.** When a user requests matches, the API returns top N candidates by simple keyword overlap, then the user's local AI (Claude, GPT) re-ranks them using its own understanding. Pro: no model on server, leverages the most powerful AI available (the user's own LLM). Con: slower, requires more API calls, matching quality depends on which AI the user runs.

Option C: **Hybrid.** Server does fast keyword/TF-IDF pre-filtering to get top 50 candidates, returns them to the client, client's LLM re-ranks for final top 10. Pro: fast pre-filter + smart re-ranking. Con: more complex, two-step flow.

**Change 3: Ambient digest check (AI proactively surfaces matches)**

Current: User must explicitly call `get_digest`. Claude never checks on its own.

Proposed: The MCP server behavior changes so that:
1. On session start (or periodically), the AI calls `get_digest` automatically
2. If relevant matches or pending intros exist, the AI mentions them naturally in conversation
3. If nothing relevant, silence — no "I checked the network and found nothing" noise

This is a behavioral change, not an infrastructure change. The MCP tools stay the same. The difference is in the SKILL.md instructions that tell the AI *when* to call them. The skill description would say something like:

"At the start of every session, silently call `get_digest` to check for relevant matches and pending introductions. If matches with score > 60 exist, mention them naturally when the conversation reaches a relevant topic. If pending intros exist, inform the user immediately. If nothing relevant, say nothing."

**Change 4: Card refresh from context (cards stay alive and current)**

Current: Cards are static. Published once, stale forever (until expiry).

Proposed: Every time the AI auto-publishes, it replaces the previous card. The card always reflects the user's current work context. If a user switches from working on "React performance" to "database migration," the card updates accordingly.

The API already supports this — publishing a card with the same `agentId` updates the existing card (upsert). No new endpoint needed.

**Change 5: Simplified intro flow (connection happens in-chat)**

Current flow works but requires both users to be actively interacting with Mingle. 

Proposed: When User A's AI requests an intro, User B's AI surfaces it naturally during B's next session — not as a "Mingle notification" but as: "Hey, someone working on [relevant topic] wants to connect about [specific reason]. They offer [X]. Want me to set up the connection?"

If B approves, both sides get each other's disclosed information right in their chat. No external app, no email, no separate platform. The connection is made inside the conversation where both people already are.

### Proposed Architecture

```
User's AI Client (Claude, GPT, Cursor)
    ↓ MCP protocol
Mingle MCP Server (same as today)
    |
    ├── On session start: auto-publish card from context
    ├── On session start: check digest for matches/intros
    ├── During session: surface relevant matches when contextually appropriate
    ├── On user approval: request/approve intros
    └── On context shift: update card
    |
    ↓ HTTPS + Ed25519 signatures
Intent Network API (api.aeoess.com)
    |
    ├── Card storage (same as today, simpler format)
    ├── Semantic matching (NEW: embeddings or keyword pre-filter)
    ├── Intro management (same as today)
    └── Stats + resolve (same as today)
    |
    ↓ SQLite
Persistent storage
```

### What Stays the Same
- Ed25519 signing on all cards and intros (trust layer)
- Double opt-in for all connections (both humans approve)
- MCP protocol for AI client integration
- API endpoints (mostly unchanged, card format simplified)
- `npx mingle-mcp setup` installation
- npm distribution

### What Changes
1. **SKILL.md instructions** — tells AI to auto-publish and auto-check digest (behavioral)
2. **Card format** — simpler, free-text needs/offers, optional `context` field
3. **Matching algorithm** — semantic similarity replaces category/tag matching
4. **MCP tool behavior** — `publish_intent_card` can be called by AI without explicit user instruction (auto-mode)
5. **New MCP tool (maybe):** `auto_update_card` — takes raw conversation context, infers needs/offers, publishes

### Open Questions (For Peer Review)

**Q1: Privacy of auto-published cards.**
If the AI auto-publishes a card based on conversation context, the user might not realize what's being shared. How explicit should consent be? Options: (a) always ask before first auto-publish, (b) show what will be published and let user edit, (c) publish automatically but make it visible in the UI, (d) opt-in setting at install time.

**Q2: Embedding model choice.**
If server-side embeddings: which model? all-MiniLM-L6-v2 is small and fast but English-only. Multilingual models are larger. Or skip embeddings entirely and let client-side LLM do all matching (Option B above). What's the right trade-off for a network that's currently 120 cards but could be 10,000?

**Q3: Ambient digest frequency.**
How often should the AI check the network? Every session start? Every N minutes? Only when context shifts significantly? Too frequent = noise and API load. Too infrequent = missed connections.

**Q4: Card granularity.**
Should one user have one card that represents everything they're working on? Or multiple cards for different projects/contexts? One card is simpler but less precise. Multiple cards are noisier but more targeted.

**Q5: What happens when both users are offline?**
User A requests intro to User B. User B doesn't open Claude for 3 days. Does the intro expire? Does it wait? Current system: intros expire in 7 days. Is that right for ambient networking?

**Q6: Network effects and critical mass.**
Ambient networking only works if enough people have Mingle installed. With 442 downloads and 120 cards, the network is thin. What's the minimum viable network size for ambient matching to produce real connections? How do we get there?

**Q7: Matching at the API vs. at the client.**
Current: API does all matching. Proposed Option B/C: client LLM does re-ranking. If the client does matching, the API becomes a dumb card store. Is that better (simpler API, smarter matching) or worse (inconsistent matching across different AI clients)?

**Q8: Identity persistence.**
Currently, each `publish_intent_card` call generates a fresh keypair. This means the same user gets a new identity every time. For ambient networking, should identity persist across sessions? The Agent Passport System already solves this (persistent Ed25519 identity), but Mingle doesn't use it for user identity — only for card signing.

### Risks

**Risk 1: Auto-publish leaks context.**
If the AI publishes "working on confidential acquisition of CompanyX" to a public network, that's a problem. Mitigation: AI must sanitize context before publishing. Never include company names, financial details, or anything marked confidential.

**Risk 2: Spam/abuse on open network.**
With auto-publishing, a bad actor could flood the network with fake cards. Current mitigation: rate limits + Ed25519 signatures. Additional: reputation scoring, card quality heuristics, community reporting.

**Risk 3: Matching quality kills trust.**
If ambient networking surfaces irrelevant matches, users turn it off and never come back. The matching algorithm must be good enough that when Claude says "there's someone relevant," the user trusts it. First impressions matter enormously here.

**Risk 4: Single point of failure.**
api.aeoess.com is one server on one Mac Mini. If it goes down, all of Mingle goes down. For an ambient system where AI clients check automatically, downtime means silent failures that accumulate.

---

## SUMMARY FOR REVIEWERS

**Current system:** Manual networking plugin. User explicitly publishes cards, explicitly searches, explicitly requests intros. Matching uses rigid category/tag overlap. Works but nobody uses it because it requires conscious effort.

**Proposed system:** Ambient networking. AI auto-publishes cards from conversation context, auto-checks the network for matches, proactively surfaces relevant connections during natural work. Matching uses semantic similarity. Connections happen inside the chat where both people already are. The user's only action is saying "yes" or "no" to a connection.

**The fundamental shift:** From "user networks through AI" to "AI networks on behalf of user." The user works. The AI handles the networking. The user only makes decisions.

**What I need from you:** Tear this apart. What's wrong with the approach? What am I missing? What would you do differently? Especially interested in: matching algorithm choice, privacy model, and whether ambient auto-publishing is the right UX or if there's a better pattern.

---
*Built by Tymofii Pidlisnyi | aeoess.com | github.com/aeoess*
