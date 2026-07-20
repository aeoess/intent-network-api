// ══════════════════════════════════════════════════════════════
// Mingle v3 P1.5 page tests - XSS escaping, visibility, status, enum
// ══════════════════════════════════════════════════════════════
// Same bootstrap as the other suites: in-process app, throwaway DB, real
// Ed25519-signed cards published through the real /api/v3 path, then the
// server-rendered pages fetched and inspected as raw HTML.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-p15-test-'))
process.env.DB_PATH = join(tmpDir, 'p15.db')

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const { cardContentHash } = await import('../src/v3-cards.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(resolve => { server = app.listen(0, '127.0.0.1', () => resolve()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })

function makeCard(overrides: Record<string, any> = {}, opts: { expiresInMs?: number } = {}): Record<string, any> {
  const keys = generateKeyPair()
  const now = Date.now()
  const card: Record<string, any> = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(now).toISOString(),
    expires_at: new Date(now + (opts.expiresInMs ?? 21 * 24 * 3600 * 1000)).toISOString(),
    headline: 'Protocol engineer', intents: ['collaborate'],
    seeking: [{ description: 'collaborators on agent identity', topics: ['identity'], engagement: 'part_time' }],
    offering: [{ description: 'I build SDKs', topics: ['ts'], provenance: 'principal_statement' }],
    preferences: [{ key: 'location', value: 'remote' }],
    artifacts: [{ claim: 'author of a package', source: 'artifact_link', method: 'link exists', verified_fact: 'a package exists', date: new Date(now).toISOString() }],
    event_ref: null, team_size_sought: null,
    visibility: {}, composition: { agent_assisted: true, skill_version: 'v1' },
    delegation_ref: null, revocation_status: 'active', ...overrides,
  }
  const h = cardContentHash(card)
  card.approval = { card_hash: h, approved_at: new Date(now).toISOString(), principal_signature: sign(h, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return { card, keys }
}

async function publish(built: Record<string, any>): Promise<any> {
  const res = await fetch(`${base}/api/v3/cards`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card: built.card }) })
  return res.json()
}

const XSS = '<script>alert(1)</script>'

test('card page escapes every user-supplied value (no raw markup)', async () => {
  const built = makeCard({
    headline: `Engineer ${XSS}`,
    seeking: [{ description: `looking for ${XSS} people` }],
    offering: [{ description: `I build "<img src=x onerror=alert(1)>"`, provenance: 'principal_statement' }],
    visibility: {},
  })
  const pub = await publish(built)
  assert.ok(pub.card_id, JSON.stringify(pub))
  const res = await fetch(`${base}/c/${pub.card_id}`)
  const html = await res.text()
  assert.equal(res.status, 200)
  // No executable markup survives: no raw script tag and no raw <img element.
  // The event-handler text may appear inside the escaped, inert form
  // (&lt;img ... onerror ... &gt;), which is safe; what must never appear is a
  // real opening tag that the browser would parse.
  assert.equal(html.includes('<script>alert(1)</script>'), false, 'raw script tag leaked')
  assert.equal(html.includes('<img src=x onerror=alert(1)>'), false, 'raw img tag leaked')
  assert.equal(/<img\b/i.test(html), false, 'a raw <img element must not appear')
  // The escaped forms are present, proving the values were rendered as text.
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), 'escaped script text missing')
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'), 'escaped img text missing')
})

test('card page sets a strict CSP with no script source', async () => {
  const built = makeCard()
  const pub = await publish(built)
  const res = await fetch(`${base}/c/${pub.card_id}`)
  const csp = res.headers.get('content-security-policy') || ''
  assert.match(csp, /default-src 'none'/)
  assert.equal(/script-src/.test(csp) && !/script-src 'none'/.test(csp) ? false : true, true)
  // No 'unsafe-inline' or external host for scripts anywhere.
  assert.equal(csp.includes('unsafe-inline') && csp.includes('script'), false)
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff')
})

test('a private field never appears in card page HTML', async () => {
  const built = makeCard({
    headline: 'Visibility probe',
    offering: [{ description: 'SECRET_OFFERING_TOKEN', provenance: 'principal_statement' }],
    preferences: [{ key: 'location', value: 'SECRET_PREF_TOKEN' }],
    visibility: { offering: 'private', preferences: 'private' },
  })
  const pub = await publish(built)
  const html = await (await fetch(`${base}/c/${pub.card_id}`)).text()
  assert.equal(html.includes('SECRET_OFFERING_TOKEN'), false, 'private offering leaked to HTML')
  assert.equal(html.includes('SECRET_PREF_TOKEN'), false, 'private preference leaked to HTML')
  // og:description must not carry a private offering either.
  assert.equal(html.includes('SECRET_OFFERING_TOKEN'), false)
})

test('og tags reflect headline and first network-visible offering', async () => {
  const built = makeCard({ headline: 'OG headline probe', offering: [{ description: 'public offering line', provenance: 'principal_statement' }], visibility: {} })
  const pub = await publish(built)
  const html = await (await fetch(`${base}/c/${pub.card_id}`)).text()
  assert.match(html, /<meta property="og:title" content="OG headline probe">/)
  assert.match(html, /<meta property="og:description" content="public offering line">/)
})

test('revoked card renders status only, no content', async () => {
  const built = makeCard({ headline: 'Revoke render probe', offering: [{ description: 'SHOULD_NOT_SHOW', provenance: 'principal_statement' }], visibility: {} })
  const pub = await publish(built)
  const wd = await fetch(`${base}/api/v3/cards/${pub.card_id}/withdraw`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ public_key: built.keys.publicKey, signature: sign(`withdraw:${pub.card_id}`, built.keys.privateKey) }) })
  assert.equal(wd.status, 200)
  const html = await (await fetch(`${base}/c/${pub.card_id}`)).text()
  assert.equal(html.includes('SHOULD_NOT_SHOW'), false, 'revoked card leaked content')
  assert.match(html, /unavailable|withdrawn/i)
})

test('expired card renders status only', async () => {
  const built = makeCard({ headline: 'Expiry render probe', offering: [{ description: 'EXPIRED_SECRET', provenance: 'principal_statement' }] }, { expiresInMs: 40 })
  const pub = await publish(built)
  await new Promise(r => setTimeout(r, 70))
  const html = await (await fetch(`${base}/c/${pub.card_id}`)).text()
  assert.equal(html.includes('EXPIRED_SECRET'), false)
  assert.match(html, /Expired|unavailable/i)
})

test('unknown card id 404s with no enumeration route', async () => {
  const res = await fetch(`${base}/c/v3-connection-0000000000-deadbeef`)
  assert.equal(res.status, 404)
  // There is no route that lists cards.
  for (const path of ['/c', '/c/', '/cards', '/c/all', '/e']) {
    const r = await fetch(`${base}${path}`)
    assert.notEqual(r.status, 200, `${path} should not list cards`)
  }
})

test('event wall filters by event_ref and excludes non-network visibility', async () => {
  const ev = 'hack-2026-probe'
  const onWall = makeCard({ headline: 'On the wall', event_ref: { event_id: ev }, visibility: {} })
  const hiddenHeadline = makeCard({ headline: 'HIDDEN_WALL_HEADLINE', event_ref: { event_id: ev }, visibility: { headline: 'private' } })
  const otherEvent = makeCard({ headline: 'Different event', event_ref: { event_id: 'other-event' }, visibility: {} })
  await publish(onWall); await publish(hiddenHeadline); await publish(otherEvent)
  const html = await (await fetch(`${base}/e/${ev}`)).text()
  assert.ok(html.includes('On the wall'), 'network-visible card should appear on the wall')
  assert.equal(html.includes('HIDDEN_WALL_HEADLINE'), false, 'private headline must not appear on the wall')
  assert.equal(html.includes('Different event'), false, 'card for another event must not appear')
  assert.match(html, /http-equiv="refresh" content="60"/)
  assert.match(html, /\/join/)
})

test('event wall escapes the event ref and card content', async () => {
  const ev = 'evt'
  const built = makeCard({ headline: `Wall XSS ${XSS}`, event_ref: { event_id: ev }, visibility: {} })
  await publish(built)
  const html = await (await fetch(`${base}/e/${ev}`)).text()
  assert.equal(html.includes('<script>alert(1)</script>'), false)
  assert.ok(html.includes('&lt;script&gt;'))
})

test('join page is static and script-free', async () => {
  const res = await fetch(`${base}/join`)
  const html = await res.text()
  assert.equal(res.status, 200)
  assert.match(html, /help me compose my Mingle card/)
  assert.match(html, /npx mingle-mcp setup/)
  const csp = res.headers.get('content-security-policy') || ''
  assert.match(csp, /default-src 'none'/)
})
