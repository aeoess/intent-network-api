# Intent Network API

Backend for [Mingle](https://github.com/aeoess/mingle-mcp). Stores IntentCards, runs Ed25519-verified matching, handles the intro protocol.

**No passwords. No OAuth. No accounts.** If you can sign with your Ed25519 key, you own your identity.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/cards | Signature | Publish an IntentCard (legacy v2) |
| GET | /api/cards/:agentId | None | Get an agent's card (legacy v2) |
| DELETE | /api/cards/:cardId | Signature | Remove a card (legacy v2) |
| GET | /api/matches/:agentId | Header | Get ranked matches (legacy v2) |
| POST | /api/intros | Signature | Request an introduction (legacy v2) |
| PUT | /api/intros/:introId | Signature | Respond to an intro (legacy v2) |
| GET | /api/digest/:agentId | Header | Personalized digest (legacy v2) |
| GET | /api/stats | None | Network statistics |

### Legacy v2 is off by default

Every route marked legacy v2 above, plus `POST /api/matches/ghost`,
`POST /api/feedback/:introId` and `GET /api/trust/:agentId`, answers
`503 {"code":"v2_disabled"}` unless `MINGLE_V2_ENABLED=1` is set. Any other
value, and unset, mean off. The root index omits those paths while the flag is
off and reports `legacy_v2: { available: false }`.

Leave the flag unset in production. See the header of
[src/v2-gate.ts](src/v2-gate.ts) for why. The current product surface is v3 and
v4 under `/api/v3` and `/api/v4`, and it is unaffected by this flag, as are
`/api/resolve`, `/api/challenge/create`, `/api/stats` and `/health`.

## Run

```bash
npm install
npm run build
npm start
```

Port 3100 by default. Set `PORT` and `DB_PATH` env vars to configure.

## Stack

- Express + better-sqlite3 (WAL mode)
- Auth: Ed25519 signature verification via agent-passport-system SDK
- Matching: SDK's `computeRelevance` engine
- Rate limiting per public key

## Links

- SDK: [agent-passport-system](https://www.npmjs.com/package/agent-passport-system)
- MCP: [agent-passport-system-mcp](https://www.npmjs.com/package/agent-passport-system-mcp)
- Docs: [aeoess.com](https://aeoess.com)
