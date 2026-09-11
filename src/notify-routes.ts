// ══════════════════════════════════════════════════════════════
// Mingle email notifications - consent routes (mounted at /api/v3/notifications)
// ══════════════════════════════════════════════════════════════
// subscribe (signed) stores an unverified address and sends a confirmation.
// confirm/:token (GET) flips verified. unsubscribe (signed POST, or GET the
// tokened link) deletes the row. No route lists or enumerates addresses.

import { Router } from 'express'
import { randomBytes } from 'node:crypto'
import { verify } from 'agent-passport-system'
import { checkRateLimit } from './db.js'
import * as notifyDb from './notify-db.js'
import * as email from './notifications.js'

const router = Router()

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
// What a new subscription starts with. The kinds of mail added after the first
// two (the weekly digest, new matches) start off, so nobody receives a kind of
// email they never chose.
const NEW_SUBSCRIPTION_PREFS: notifyDb.NotifPrefs = { intro_request: true, intro_accepted: true, weekly_digest: false, new_match: false }
const PREF_KEYS = Object.keys(NEW_SUBSCRIPTION_PREFS) as (keyof notifyDb.NotifPrefs)[]

function rateLimited(action: string, limit: number) {
  return (req: any, res: any, next: any) => {
    const key = `notif:${req.ip || 'anon'}`
    if (!checkRateLimit(key, action, limit).allowed) { res.status(429).json({ error: 'Rate limit exceeded' }); return }
    next()
  }
}

// ── POST /subscribe {subject_key, email, nonce, signature, prefs?} ────────
// signature is over `${email}:${nonce}` by subject_key.

router.post('/subscribe', rateLimited('notif_subscribe', 10), async (req, res) => {
  const { subject_key, email: addr, nonce, signature, prefs } = req.body ?? {}
  if (typeof subject_key !== 'string' || typeof addr !== 'string' || typeof nonce !== 'string' || typeof signature !== 'string') {
    res.status(400).json({ error: 'subject_key, email, nonce, signature required' }); return
  }
  if (addr.length > 254 || !EMAIL_RE.test(addr)) { res.status(400).json({ error: 'invalid email' }); return }
  try {
    if (!verify(`${addr}:${nonce}`, signature, subject_key)) { res.status(403).json({ error: 'signature does not verify under subject_key' }); return }
  } catch (e: any) {
    res.status(403).json({ error: `signature verification failed: ${e.message}` }); return
  }
  // Merge, never reset. A pref the request names is set. A pref it omits keeps
  // what is stored, or the new-subscription default when nothing is stored yet.
  // upsertSubscription writes the whole object, so the merge has to happen here.
  const existing = notifyDb.getSubscription(subject_key)
  const effective: notifyDb.NotifPrefs = { ...(existing?.prefs ?? NEW_SUBSCRIPTION_PREFS) }
  for (const k of PREF_KEYS) {
    if (prefs && typeof prefs === 'object' && prefs[k] !== undefined) effective[k] = !!prefs[k]
  }
  const verifyToken = randomBytes(24).toString('hex')
  const unsubToken = existing?.unsub_token ?? randomBytes(24).toString('hex')
  notifyDb.upsertSubscription(subject_key, addr, verifyToken, unsubToken, effective)
  // upsertSubscription keeps a confirmed row confirmed when the address is
  // unchanged. That call is only a pref update, so it gets no new confirmation
  // email, and the response reports the stored state. The confirmation is the
  // only email an unverified address receives.
  const verified = notifyDb.getSubscription(subject_key)?.verified ?? false
  const sent = verified ? { sent: false } : await email.sendConfirmation(addr, verifyToken, unsubToken)
  res.status(201).json({ subscribed: true, verified, confirmation_sent: sent.sent, email_enabled: email.isEmailEnabled(), prefs: effective })
})

// ── GET /confirm/:token ───────────────────────────────────────────────────

router.get('/confirm/:token', rateLimited('notif_confirm', 60), (req, res) => {
  const sub = notifyDb.confirmByToken(String(req.params.token))
  if (!sub) { res.status(404).type('text/plain').send('This confirmation link is not valid.'); return }
  res.type('text/plain').send('Your Mingle notification email is confirmed. You can close this tab.')
})

// ── POST /unsubscribe {subject_key, nonce, signature} ─────────────────────

router.post('/unsubscribe', rateLimited('notif_unsub', 20), (req, res) => {
  const { subject_key, nonce, signature } = req.body ?? {}
  if (typeof subject_key !== 'string' || typeof nonce !== 'string' || typeof signature !== 'string') {
    res.status(400).json({ error: 'subject_key, nonce, signature required' }); return
  }
  try {
    if (!verify(`unsubscribe:${nonce}`, signature, subject_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  } catch (e: any) {
    res.status(403).json({ error: `signature verification failed: ${e.message}` }); return
  }
  notifyDb.deleteSubscription(subject_key)
  res.json({ unsubscribed: true })
})

// ── GET /unsubscribe/:token (one-click, no signature needed to leave) ─────

router.get('/unsubscribe/:token', rateLimited('notif_unsub', 60), (req, res) => {
  notifyDb.deleteByUnsubToken(String(req.params.token))
  res.type('text/plain').send('You are unsubscribed from Mingle notification emails.')
})

// ── GET /status (signed) ──────────────────────────────────────────────────
// Lets the principal's own assistant learn whether their address is subscribed
// and confirmed, so it can nudge once if a confirmation link is still unclicked.
// Signed by subject_key over `notif-status:${nonce}`; reveals nothing to anyone
// who cannot sign for the key, and never returns the address itself.

router.get('/status', rateLimited('notif_status', 60), (req, res) => {
  const subject_key = String(req.query.public_key ?? '')
  const nonce = String(req.query.nonce ?? '')
  const signature = String(req.query.signature ?? '')
  if (!subject_key || !nonce) { res.status(400).json({ error: 'public_key and nonce required' }); return }
  try {
    if (!verify(`notif-status:${nonce}`, signature, subject_key)) { res.status(403).json({ error: 'signature does not verify' }); return }
  } catch (e: any) {
    res.status(403).json({ error: `signature verification failed: ${e.message}` }); return
  }
  const sub = notifyDb.getSubscription(subject_key)
  // prefs is the effective four-pref object, or null when there is no subscription.
  res.json({ subscribed: !!sub, verified: !!sub?.verified, prefs: sub ? sub.prefs : null })
})

export default router
