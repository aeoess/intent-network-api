// ══════════════════════════════════════════════════════════════
// Mingle v3 P1.5 - read surfaces (server-rendered HTML, no client JS)
// ══════════════════════════════════════════════════════════════
// Three GET pages: /c/:cardId (public card), /e/:eventRef (event wall),
// /join (static). Read-only; no mutation endpoints. Security is the point:
// every user-supplied value is HTML-escaped, a strict Content-Security-Policy
// blocks all scripts and external resources, and there is no listing or
// enumeration route (card IDs are unguessable, unknown IDs 404).

import { Router } from 'express'
import { randomBytes } from 'node:crypto'
import * as v3db from './v3-db.js'
import { networkVisibleView } from './v3-cards.js'
import type { V3Card } from './v3-cards.js'
import { checkRateLimit } from './db.js'
import { qrSvg } from './qr.js'

const router = Router()

// ── HTML escaping (the load-bearing security primitive) ──────────────────
// Escapes the five HTML-significant characters. Applied to every value that
// originates from a card. Attribute contexts additionally get quotes escaped
// (both handled here), and no value is ever placed in a script or style
// context, so this is sufficient with the CSP below.
const ESC: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, ch => ESC[ch])
}

// ── Strict CSP + no-JS security headers, per response with a style nonce ──
function secureHtml(res: any, html: string, nonce: string): void {
  res.setHeader('Content-Security-Policy',
    `default-src 'none'; style-src 'nonce-${nonce}'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`)
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.send(html)
}

function rateLimited(action: string, limit: number) {
  return (req: any, res: any, next: any) => {
    const key = `page:${req.ip || 'anon'}`
    if (!checkRateLimit(key, action, limit).allowed) { res.status(429).type('text/plain').send('Rate limit exceeded. Try again later.'); return }
    next()
  }
}

const BASE_STYLE = (nonce: string, extra = '') => `<style nonce="${nonce}">
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, "Segoe UI", system-ui, sans-serif; max-width: 46rem; margin: 0 auto; padding: 2rem 1.25rem; line-height: 1.5; color: #14161d; background: #fff; }
  .kicker { font-size: 0.8rem; letter-spacing: 0.12em; text-transform: uppercase; color: #6a6f7e; }
  h1 { font-size: 1.8rem; line-height: 1.2; margin: 0.3rem 0 1rem; }
  h2 { font-size: 0.95rem; letter-spacing: 0.08em; text-transform: uppercase; color: #6a6f7e; margin: 1.6rem 0 0.5rem; }
  ul { padding-left: 1.1rem; margin: 0.3rem 0; }
  li { margin: 0.25rem 0; }
  .tag { display: inline-block; border: 1px solid #d7dae2; border-radius: 999px; padding: 0.1rem 0.6rem; margin: 0.15rem 0.15rem 0.15rem 0; font-size: 0.85rem; }
  .status { border: 1px solid #d7dae2; border-radius: 12px; padding: 1.5rem; color: #6a6f7e; }
  .foot { margin-top: 2.5rem; font-size: 0.8rem; color: #8a8f9c; border-top: 1px solid #eceef2; padding-top: 1rem; }
  a { color: #1a56db; }
  ${extra}
</style>`

const FOOTER = `<div class="foot">Mingle transports; it never evaluates. Signatures prove authorization and integrity, not the truth of subjective claims. Powered by Agent Passport System.</div>`

// ── GET /c/:cardId - public card page ─────────────────────────────────────

router.get('/c/:cardId', rateLimited('page_card', 120), (req, res) => {
  const nonce = randomBytes(16).toString('base64')
  const stored = v3db.getV3Card(String(req.params.cardId))
  if (!stored) { res.status(404); secureHtml(res, statusPage(nonce, 'Not found', 'No card exists at this link.'), nonce); return }

  const status = stored.revocation_status
  const expired = Date.parse(stored.expires_at) <= Date.now()
  if (status !== 'active' || expired) {
    const label = expired && status === 'active' ? 'Expired' : status.replace(/_/g, ' ')
    res.status(status === 'deleted' ? 410 : 200)
    secureHtml(res, statusPage(nonce, 'Card unavailable', `This card is ${esc(label)}. Its content is no longer shown. Counterparties may retain what they already received.`), nonce)
    return
  }

  // Network-visible fields only, per-field visibility respected by the model.
  const view = networkVisibleView({ ...stored.card, card_id: stored.card_id }) as any
  const headline = view.headline ?? 'Mingle card'
  const offerings = Array.isArray(view.offering) ? view.offering : []
  const ogDesc = offerings[0]?.description ?? ''

  const parts: string[] = []
  parts.push(`<p class="kicker">Mingle ${esc(view.card_type)} card</p>`)
  parts.push(`<h1>${esc(headline)}</h1>`)
  if (Array.isArray(view.intents) && view.intents.length) {
    parts.push(`<p>${view.intents.map((i: string) => `<span class="tag">${esc(i)}</span>`).join('')}</p>`)
  }
  if (Array.isArray(view.seeking) && view.seeking.length) {
    parts.push('<h2>Seeking</h2><ul>' + view.seeking.map((s: any) => `<li>${esc(s.description)}${s.engagement ? ` <span class="tag">${esc(s.engagement)}</span>` : ''}</li>`).join('') + '</ul>')
  }
  if (offerings.length) {
    parts.push('<h2>Offering</h2><ul>' + offerings.map((o: any) => `<li>${esc(o.description)}</li>`).join('') + '</ul>')
  }
  if (Array.isArray(view.artifacts) && view.artifacts.length) {
    parts.push('<h2>Evidence</h2><ul>' + view.artifacts.map((a: any) => `<li>${esc(a.claim)} <span class="tag">${esc(a.source)}</span><br><small>${esc(a.verified_fact)}</small></li>`).join('') + '</ul>')
  }
  if (view.event_ref?.event_id) {
    parts.push(`<h2>Event</h2><p>${esc(view.event_ref.event_id)}${view.event_ref.dates ? ` (${esc(view.event_ref.dates)})` : ''}</p>`)
  }

  // Connect block: no form, no unauthenticated action, just the card id and how
  // to ask your own assistant to request an intro.
  parts.push(`<h2>Connect</h2><p class="cardid">${esc(view.card_id)}</p><p>Install Mingle, publish your card, then tell your assistant: request an intro to card ${esc(view.card_id)}.</p>`)

  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(headline)} - Mingle</title>
<meta property="og:title" content="${esc(headline)}">
<meta property="og:description" content="${esc(ogDesc)}">
<meta property="og:type" content="profile">
${BASE_STYLE(nonce, '.cardid { font-family: ui-monospace, monospace; background: #f7f8fa; padding: 0.4rem 0.7rem; border-radius: 8px; word-break: break-all; user-select: all; }')}</head><body>${parts.join('\n')}${FOOTER}</body></html>`
  secureHtml(res, html, nonce)
})

function statusPage(nonce: string, title: string, message: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)} - Mingle</title>${BASE_STYLE(nonce)}</head><body><p class="kicker">Mingle</p><h1>${esc(title)}</h1><div class="status">${esc(message)}</div>${FOOTER}</body></html>`
}

// ── GET /e/:eventRef - event wall (projector-friendly) ────────────────────

router.get('/e/:eventRef', rateLimited('page_event', 120), (req, res) => {
  const nonce = randomBytes(16).toString('base64')
  const eventRef = String(req.params.eventRef)
  const results = v3db.searchV3Cards({ event_ref: eventRef }, undefined, 50) as any[]

  const proto = (req.headers['x-forwarded-proto'] as string) || req.protocol || 'https'
  const host = esc(req.get('host') || 'api.aeoess.com')
  const joinUrl = `${esc(proto)}://${host}/join`
  const qr = qrSvg(`${proto}://${req.get('host') || 'api.aeoess.com'}/join`, { moduleSize: 4 })

  const cards = results.map((v: any) => {
    const seeking = Array.isArray(v.seeking) ? v.seeking.slice(0, 2).map((s: any) => esc(s.description)).join(' · ') : ''
    return `<article class="card"><h2 class="ch">${esc(v.headline ?? 'Mingle card')}</h2>${Array.isArray(v.intents) ? `<p class="tags">${v.intents.map((i: string) => `<span class="tag">${esc(i)}</span>`).join('')}</p>` : ''}${seeking ? `<p class="seek">Seeking: ${seeking}</p>` : ''}</article>`
  }).join('\n')

  const extra = `
  body { max-width: 72rem; }
  .wallhead { display: flex; justify-content: space-between; align-items: center; gap: 1.5rem; flex-wrap: wrap; }
  .join { text-align: center; }
  .join .u { font-size: 1.3rem; font-weight: 600; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(20rem, 1fr)); gap: 1rem; margin-top: 1.5rem; }
  .card { border: 1px solid #d7dae2; border-radius: 14px; padding: 1.25rem; }
  .ch { font-size: 1.4rem; text-transform: none; letter-spacing: 0; color: #14161d; margin: 0 0 0.5rem; }
  .seek { color: #4c4f57; margin: 0.4rem 0 0; }
  .empty { color: #6a6f7e; padding: 2rem 0; }
  @media (min-width: 60rem) { .ch { font-size: 1.7rem; } }`

  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="60">
<title>Mingle wall - ${esc(eventRef)}</title>
${BASE_STYLE(nonce, extra)}</head><body>
<div class="wallhead">
  <div><p class="kicker">Mingle event wall</p><h1>${esc(eventRef)}</h1><p>${cards ? `${results.length} card${results.length === 1 ? '' : 's'} here now` : ''}</p></div>
  <div class="join">${qr ?? ''}<p class="u">Join: ${esc(joinUrl)}</p></div>
</div>
${cards ? `<div class="grid">${cards}</div>` : '<p class="empty">No cards on this wall yet. Publish a card with this event to appear here.</p>'}
${FOOTER}</body></html>`
  secureHtml(res, html, nonce)
})

// ── GET /join - static ────────────────────────────────────────────────────

router.get('/join', rateLimited('page_join', 120), (req, res) => {
  const nonce = randomBytes(16).toString('base64')
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Join Mingle</title>
<meta property="og:title" content="Join Mingle">
<meta property="og:description" content="Give your assistant Mingle so it can find the people you are looking for.">
${BASE_STYLE(nonce, '.prompt { border: 1px solid #d7dae2; border-radius: 12px; padding: 1rem 1.25rem; font-family: ui-monospace, monospace; background: #f7f8fa; }')}
</head><body>
<p class="kicker">Mingle</p>
<h1>Meet the people you are looking for</h1>
<p>Mingle gives your assistant a way to find collaborators, teammates, cofounders, and the occasional employer. Your assistant helps you discover, compose, and coordinate; it never becomes an evaluator of people for third parties.</p>
<h2>Connect the MCP</h2>
<p>Add the Mingle connector: <code>npx mingle-mcp setup</code></p>
<h2>Then say</h2>
<div class="prompt">Connect Mingle, then say: help me compose my Mingle card.</div>
<p>Email addresses are stored only for notifications you opt into, are never shown on cards, and can be deleted anytime.</p>
${FOOTER}</body></html>`
  secureHtml(res, html, nonce)
})

export default router
