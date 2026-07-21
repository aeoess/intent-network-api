// ══════════════════════════════════════════════════════════════
// Mingle v3 weekly digest job
// ══════════════════════════════════════════════════════════════
// At most one email per verified, opted-in subscriber per week: up to three new
// matches rendered as the counterpart's own stated words, a count, and an
// expiry heads-up. Emails come only from the notification table, the send goes
// through the injectable transport (mocked in tests), and the week key doubles
// as the dedupe id so a re-run never double-sends. Dark and silent when email
// is unconfigured.

import * as notifyDb from './notify-db.js'
import * as matchesDb from './matches-db.js'
import * as v3db from './v3-db.js'
import * as email from './notifications.js'

const DAY = 24 * 3600 * 1000
const EXPIRY_SOON_DAYS = 3
const MAX_LINES = 3

/** Stable per-week identifier from whole epoch weeks. Passed in so tests are
 *  deterministic and the module never calls Date.now() implicitly. */
export function weekKey(now: number): string {
  return `weekly-${Math.floor(now / (7 * DAY))}`
}

export async function runWeeklyDigest(now: number = Date.now()): Promise<{ considered: number; sent: number }> {
  const subs = notifyDb.weeklyDigestSubscribers()
  const wk = weekKey(now)
  const since = new Date(now - 7 * DAY).toISOString()
  let sent = 0

  for (const sub of subs) {
    const cardIds = v3db.activeCardIdsForSubject(sub.subject_key)
    if (cardIds.length === 0) continue

    // New matches this week, deduped by counterpart card, most recent first.
    const matches = matchesDb.newMatchesForCardsSince(cardIds, since)
    const seen = new Set<string>()
    const unique = matches.filter(m => (seen.has(m.other_card_id) ? false : (seen.add(m.other_card_id), true)))
    unique.sort((a, b) => (a.computed_at < b.computed_at ? 1 : -1))
    const matchLines = unique
      .slice(0, MAX_LINES)
      .map(m => m.counterpart_snippets[0] ?? m.matched_intents.join(', '))
      .filter(Boolean)

    let expiring = 0
    for (const cardId of cardIds) {
      const c = v3db.getV3Card(cardId)
      if (c && Date.parse(c.expires_at) - now <= EXPIRY_SOON_DAYS * DAY) expiring++
    }

    // Nothing worth an email this week.
    if (unique.length === 0 && expiring === 0) continue

    const res = await email.notifyWeeklyDigest({
      recipientKey: sub.subject_key,
      weekKey: wk,
      payload: { matchLines, newMatchCount: unique.length, expiringCardCount: expiring },
    })
    if (res.sent) sent++
  }
  return { considered: subs.length, sent }
}
