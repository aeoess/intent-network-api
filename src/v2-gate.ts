// ══════════════════════════════════════════════════════════════
// Legacy v2 availability flag (MINGLE_V2_ENABLED)
// ══════════════════════════════════════════════════════════════
// The legacy 48h IntentCard product (cards, matches, intros, digest, feedback,
// trust) runs only when the flag is exactly "1". Any other value, and unset,
// mean off, which is the safe default.
//
// Why it is off. Legacy v2 authorization semantics (requireSignature and
// identifyAgent in auth.ts) are not safe to expose, and the interface is
// disabled by default while that model is retired. MINGLE_V2_ENABLED=1 is
// intended only for compatibility testing until then. This gate is
// containment, not a repair.
//
// The flag is read per request, never at import, so nothing has to restart for a
// change to take effect and a test can set it per case.

export function v2Enabled(): boolean {
  return process.env.MINGLE_V2_ENABLED === '1'
}

/** The one user-facing sentence for every gated legacy route. Approved copy. */
export const V2_DISABLED_TEXT = 'This legacy Mingle interface is temporarily unavailable. Use the current Mingle tools.'

/** Per-route middleware. It is the FIRST middleware on each gated route, ahead
 *  of auth and rate limiting, so a refusal runs no signature verification and
 *  costs the caller no quota. */
export function v2Gate(_req: unknown, res: any, next: () => void): void {
  if (!v2Enabled()) { res.status(503).json({ error: V2_DISABLED_TEXT, code: 'v2_disabled' }); return }
  next()
}

/** The legacy paths the root index may advertise. With v2 off the index omits
 *  every one of them and says so once, so a half-live product cannot be
 *  discovered and invoked. */
export const V2_INDEX_KEYS = [
  'POST /api/cards',
  'GET /api/cards/:agentId',
  'DELETE /api/cards/:cardId',
  'GET /api/matches/:agentId',
  'POST /api/matches/ghost',
  'POST /api/intros',
  'PUT /api/intros/:introId',
  'GET /api/digest/:agentId',
  'POST /api/feedback/:introId',
  'GET /api/trust/:agentId',
]
