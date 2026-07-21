// ══════════════════════════════════════════════════════════════
// Mingle email notifications - transport, templates, send logic
// ══════════════════════════════════════════════════════════════
// Email is notification plumbing, never card data. The bodies carry only what
// the recipient could already see (a network-visible headline plus a stated
// purpose), never anything from a card's private fields.
//
// Sending goes through Resend's HTTP API. If RESEND_API_KEY or
// unset the module no-ops silently, so the feature stays
// dark with zero errors until an operator configures it. Tests inject a mock
// transport so the real API is never called.

import * as notifyDb from './notify-db.js'

export interface OutgoingEmail { to: string; subject: string; text: string }
export type Transport = (email: OutgoingEmail) => Promise<{ ok: boolean; id?: string; error?: string }>

// ── Transport (injectable) ────────────────────────────────────────────────
// The default transport reads env at call time. Tests call setTransport with a
// recorder. resetTransport restores the default.

let transport: Transport | null = null

export function setTransport(t: Transport): void { transport = t }
export function resetTransport(): void { transport = null }

/** True when the feature is configured to actually send. */
// Sender defaults to mingle@aeoess.com (domain already verified in Resend);
// MINGLE_FROM_EMAIL overrides it. Only RESEND_API_KEY is required to go live.
const FROM_EMAIL = process.env.MINGLE_FROM_EMAIL || 'Mingle <mingle@aeoess.com>'

export function isEmailEnabled(): boolean {
  return transport !== null || !!process.env.RESEND_API_KEY
}

async function resendTransport(email: OutgoingEmail): Promise<{ ok: boolean; id?: string; error?: string }> {
  const key = process.env.RESEND_API_KEY
  const from = FROM_EMAIL
  if (!key) return { ok: false, error: 'not_configured' }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to: email.to, subject: email.subject, text: email.text }),
    })
    if (!res.ok) return { ok: false, error: `resend_${res.status}` }
    const body = await res.json() as { id?: string }
    return { ok: true, id: body.id }
  } catch (e) {
    return { ok: false, error: (e as Error).message }
  }
}

async function send(email: OutgoingEmail): Promise<{ ok: boolean; id?: string; error?: string }> {
  const t = transport ?? (process.env.RESEND_API_KEY ? resendTransport : null)
  if (!t) return { ok: false, error: 'disabled' }
  return t(email)
}

// ── Links ─────────────────────────────────────────────────────────────────

function baseUrl(): string {
  return (process.env.MINGLE_PUBLIC_URL || 'https://api.aeoess.com').replace(/\/$/, '')
}
export function confirmUrl(token: string): string { return `${baseUrl()}/api/v3/notifications/confirm/${token}` }
export function unsubUrl(token: string): string { return `${baseUrl()}/api/v3/notifications/unsubscribe/${token}` }

// ── Templates (plain text, no images, no tracking) ────────────────────────

const FOOTER = (unsubToken: string): string =>
  `\n\n---\nMingle notifications. This message contains only what you could already see. Replies to this address are not monitored. To stop these emails, open: ${unsubUrl(unsubToken)}`

export function confirmEmail(to: string, verifyToken: string, unsubToken: string): OutgoingEmail {
  return {
    to,
    subject: 'Confirm your Mingle notification email',
    text: `You (or your assistant) asked Mingle to email you when someone wants to connect.\n\nConfirm this address to turn notifications on: ${confirmUrl(verifyToken)}\n\nIf this was not you, ignore this email and nothing happens.${FOOTER(unsubToken)}`,
  }
}

export function introRequestEmail(to: string, requesterHeadline: string, purpose: string, _statusUrl: string, unsubToken: string): OutgoingEmail {
  return {
    to,
    subject: 'Someone wants to connect on Mingle',
    text: `Someone on the Mingle network asked to connect with you.\n\nThey describe themselves as: ${requesterHeadline || '(no headline provided)'}\nWhy they reached out: ${purpose || '(no note provided)'}\n\nOpen your assistant and say: show my Mingle intros.\nNothing about you is shared unless you approve.${FOOTER(unsubToken)}`,
  }
}

export function introAcceptedEmail(to: string, counterpartyHeadline: string, counterpartyContact: string, unsubToken: string): OutgoingEmail {
  // With a contact line (v3 complete intro) the connection is ready to act on;
  // without one (legacy 48h path) the wording stays as it was.
  const lead = counterpartyContact
    ? 'An introduction on Mingle is complete. Both sides shared a way to connect.'
    : 'An introduction on Mingle was accepted.'
  const contactLine = counterpartyContact ? `\nHow to reach them: ${counterpartyContact}` : ''
  return {
    to,
    subject: 'Your introduction was accepted on Mingle',
    text: `${lead}\n\nThe other side: ${counterpartyHeadline || '(no headline provided)'}${contactLine}\n\nOpen your assistant and say: show my Mingle intros.${FOOTER(unsubToken)}`,
  }
}

// ── Fit exchange templates (v3.6) ─────────────────────────────────────────
// Content-free by design: the started email names only the counterpart's public
// headline and the purpose; the record-ready email carries nothing at all.

export function fitStartedEmail(to: string, counterpartHeadline: string, purpose: string, unsubToken: string): OutgoingEmail {
  return {
    to,
    subject: 'Someone\'s agent wants to talk to yours on Mingle',
    text: `An introduction you are part of opened a structured fit exchange about: ${purpose}.\n\nThe other side: ${counterpartHeadline || '(no headline provided)'}\n\nOpen your assistant and say: show my Mingle fit exchanges. Your assistant drafts each answer from your own words and approved notes; you approve before anything is shared.${FOOTER(unsubToken)}`,
  }
}

export function fitRecordReadyEmail(to: string, unsubToken: string): OutgoingEmail {
  return {
    to,
    subject: 'Your Mingle fit record is ready',
    text: `A fit exchange you were part of has closed and its record is ready.\n\nOpen your assistant and say: show my Mingle fit record.${FOOTER(unsubToken)}`,
  }
}

export function firstStepEmail(to: string, unsubToken: string): OutgoingEmail {
  return {
    to,
    subject: 'A Mingle first-step plan is ready',
    text: `The other side proposed a first-step plan for a connection you are part of.\n\nOpen your assistant and say: show my Mingle first step.${FOOTER(unsubToken)}`,
  }
}

// ── High-level send helpers, verified + prefs + dedupe + cap gated ────────

interface IntroRequestArgs { recipientKey: string; introId: string; requesterHeadline: string; purpose: string; statusUrl: string }

export async function notifyIntroRequest(a: IntroRequestArgs): Promise<{ sent: boolean; reason?: string }> {
  return dispatch(a.recipientKey, a.introId, 'intro_request', 'intro_request', sub =>
    introRequestEmail(sub.email, a.requesterHeadline, a.purpose, a.statusUrl, sub.unsub_token))
}

interface IntroAcceptedArgs { recipientKey: string; introId: string; counterpartyHeadline: string; counterpartyContact?: string }

export async function notifyIntroAccepted(a: IntroAcceptedArgs): Promise<{ sent: boolean; reason?: string }> {
  return dispatch(a.recipientKey, a.introId, 'intro_accepted', 'intro_accepted', sub =>
    introAcceptedEmail(sub.email, a.counterpartyHeadline, a.counterpartyContact ?? '', sub.unsub_token))
}

/** Fit-started and record-ready are direct-action emails (a person acted in an
 *  exchange they joined), so they are not held back by the non-direct daily cap.
 *  They still require verification, a live pref, and dedupe. */
export async function notifyFitStarted(recipientKey: string, exchangeId: string, counterpartHeadline: string, purpose: string): Promise<{ sent: boolean; reason?: string }> {
  return dispatch(recipientKey, `fit-start:${exchangeId}`, 'fit_started', 'intro_request', sub =>
    fitStartedEmail(sub.email, counterpartHeadline, purpose, sub.unsub_token), true)
}

export async function notifyFitRecordReady(recipientKey: string, exchangeId: string): Promise<{ sent: boolean; reason?: string }> {
  return dispatch(recipientKey, `fit-record:${exchangeId}`, 'fit_record', 'intro_accepted', sub =>
    fitRecordReadyEmail(sub.email, sub.unsub_token), true)
}

/** First-step proposal notice. Content-free, and NON-direct: it counts toward
 *  the one-per-day cap (not an urgent action, just a nudge). */
export async function notifyFirstStepProposed(recipientKey: string, introId: string): Promise<{ sent: boolean; reason?: string }> {
  return dispatch(recipientKey, `first-step:${introId}`, 'first_step', 'intro_accepted', sub =>
    firstStepEmail(sub.email, sub.unsub_token), false)
}

async function dispatch(
  recipientKey: string,
  introId: string,
  type: string,
  prefKey: keyof notifyDb.NotifPrefs,
  build: (sub: notifyDb.Subscription) => OutgoingEmail,
  direct = false,
): Promise<{ sent: boolean; reason?: string }> {
  if (!isEmailEnabled()) return { sent: false, reason: 'disabled' }
  const sub = notifyDb.getSubscription(recipientKey)
  if (!sub) return { sent: false, reason: 'not_subscribed' }
  if (!sub.verified) return { sent: false, reason: 'unverified' }
  if (!sub.prefs[prefKey]) return { sent: false, reason: 'pref_off' }
  const reserve = notifyDb.reserveSend(recipientKey, introId, type, direct)
  if (!reserve.ok) return { sent: false, reason: reserve.reason }
  const result = await send(build(sub))
  return { sent: result.ok, reason: result.ok ? undefined : result.error }
}

/** The confirmation email is the ONLY message an unverified address ever gets,
 *  sent directly at subscribe time (not through the verified-gated dispatch). */
export async function sendConfirmation(email: string, verifyToken: string, unsubToken: string): Promise<{ sent: boolean; reason?: string }> {
  if (!isEmailEnabled()) return { sent: false, reason: 'disabled' }
  const result = await send(confirmEmail(email, verifyToken, unsubToken))
  return { sent: result.ok, reason: result.ok ? undefined : result.error }
}


export interface WeeklyDigestPayload { matchLines: string[]; newMatchCount: number; expiringCardCount: number }

export function weeklyDigestEmail(to: string, payload: WeeklyDigestPayload, unsubToken: string): OutgoingEmail {
  const lines: string[] = []
  lines.push('Here is your weekly Mingle summary.')
  lines.push('')
  if (payload.newMatchCount > 0) {
    lines.push(`New cards relevant to what yours is seeking: ${payload.newMatchCount}.`)
    for (const l of payload.matchLines.slice(0, 3)) lines.push(`- ${l}`)
  } else {
    lines.push('No new relevant cards this week.')
  }
  if (payload.expiringCardCount > 0) {
    lines.push('')
    lines.push(`Heads up: ${payload.expiringCardCount} of your cards expire within a few days. Renew if you still want to appear.`)
  }
  lines.push('')
  lines.push('Open your assistant and say: show my Mingle digest.')
  return { to, subject: 'Your weekly Mingle summary', text: lines.join('\n') + FOOTER(unsubToken) }
}

interface WeeklyDigestArgs { recipientKey: string; weekKey: string; payload: WeeklyDigestPayload }

export async function notifyWeeklyDigest(a: WeeklyDigestArgs): Promise<{ sent: boolean; reason?: string }> {
  // weekKey doubles as the dedupe id, so a subscriber gets at most one weekly
  // email per week even if the job runs more than once.
  return dispatch(a.recipientKey, a.weekKey, 'weekly_digest', 'weekly_digest', sub =>
    weeklyDigestEmail(sub.email, a.payload, sub.unsub_token))
}

/** Operator ping to ADMIN_NOTIFY_EMAIL. Not a subscriber flow: no verification,
 *  no prefs, no dedupe. Dark and silent when the env var is unset. */
export async function notifyAdmin(subject: string, text: string): Promise<{ sent: boolean; reason?: string }> {
  const to = process.env.ADMIN_NOTIFY_EMAIL
  if (!to) return { sent: false, reason: 'no_admin' }
  if (!isEmailEnabled()) return { sent: false, reason: 'disabled' }
  const result = await send({ to, subject, text })
  return { sent: result.ok, reason: result.ok ? undefined : result.error }
}