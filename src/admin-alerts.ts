// Admin alerts for new cards, with a cap. Every publish used to send one email,
// so a burst of probe cards became dozens of messages. Now the first few in an
// hour go out one by one, the rest are held and sent as one summary when the hour
// turns over (the hourly timer in server.ts calls flush). Reports of a card are not
// routed here: they stay immediate.
//
// The state is in memory. A restart drops held lines, which loses a summary but
// never a card: every publish is recorded in card_events regardless.

import * as email from './notifications.js'

type Send = (subject: string, text: string) => Promise<unknown>

export const ALERTS_PER_HOUR = 3
const WINDOW_MS = 60 * 60 * 1000
const SUMMARY_LINES = 20

export class AdminAlerts {
  private windowStart = 0
  private sentInWindow = 0
  private held: string[] = []
  constructor(private send: Send = email.notifyAdmin, private now: () => number = Date.now) {}

  /** Alert on a new card, or hold it for the summary once the hour's cap is used. */
  async newCard(cardId: string, headline: string, subjectKey: string): Promise<'sent' | 'held' | 'skipped'> {
    const t = this.now()
    if (t - this.windowStart >= WINDOW_MS) {
      await this.flush()
      this.windowStart = t
      this.sentInWindow = 0
    }
    const line = `${headline} (${cardId}, key ${subjectKey.slice(0, 10)})`
    if (this.sentInWindow < ALERTS_PER_HOUR) {
      const r = await this.send('New Mingle card', line) as { sent?: boolean; reason?: string } | undefined
      // No admin address or email off: nothing went out, so nothing counts against the cap.
      if (r && r.sent === false && (r.reason === 'no_admin' || r.reason === 'disabled')) return 'skipped'
      this.sentInWindow++
      return 'sent'
    }
    this.held.push(line)
    return 'held'
  }

  /** Send one summary of the held cards, if any. */
  async flush(): Promise<number> {
    if (this.held.length === 0) return 0
    const lines = this.held
    this.held = []
    const shown = lines.slice(0, SUMMARY_LINES)
    const more = lines.length - shown.length
    const text = `${lines.length} more new cards after the first ${ALERTS_PER_HOUR} this hour.\n\n${shown.join('\n')}${more > 0 ? `\n\n...and ${more} more, see card_events.` : ''}`
    await this.send(`Mingle: ${lines.length} more new cards`, text)
    return lines.length
  }
}

export const adminAlerts = new AdminAlerts()
