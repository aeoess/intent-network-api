// v3 activation smoke: two compatible cards through the REAL publish endpoint
// against a running server, following the tests/smoke.ts fetch pattern.
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'
import { cardContentHash } from '../src/v3-cards.js'

const API = process.env.API || 'http://localhost:3100'

function build(opts: any, keys: any): any {
  const at = Date.now()
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(at).toISOString(), expires_at: new Date(at + 21 * 864e5).toISOString(),
    headline: opts.headline, intents: ['collaborate', 'team_up'],
    seeking: opts.seeking, offering: opts.offering.map((o: any) => ({ ...o, provenance: 'principal_statement' })),
    preferences: [{ key: 'engagement', value: 'part_time' }, { key: 'location', value: 'remote' }],
    artifacts: [], event_ref: null, team_size_sought: null,
    visibility: {}, composition: { agent_assisted: true, skill_version: 'v1' },
    delegation_ref: null, revocation_status: 'active',
  }
  const h = cardContentHash(card)
  card.approval = { card_hash: h, approved_at: new Date(at).toISOString(), principal_signature: sign(h, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return card
}

const ka = generateKeyPair(), kb = generateKeyPair()
const a = build({ headline: 'Smoke A seeks a rust protocol engineer',
  seeking: [{ description: 'a rust protocol engineer', topics: ['rust', 'protocols'] }],
  offering: [{ description: 'seed funding for developer tools', topics: ['funding'] }] }, ka)
const b = build({ headline: 'Smoke B offers rust, seeks seed',
  seeking: [{ description: 'seed funding for developer tools', topics: ['funding'] }],
  offering: [{ description: 'a rust protocol engineer, 8 years', topics: ['rust', 'protocols'] }] }, kb)

async function post(path: string, body: any) {
  const r = await fetch(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { status: r.status, body: await r.json() }
}

const pa = await post('/api/v3/cards', { card: a })
console.log('PUBLISH A:', pa.status, JSON.stringify(pa.body))
const pb = await post('/api/v3/cards', { card: b })
console.log('PUBLISH B:', pb.status, JSON.stringify(pb.body))

const nonce = `smoke-${Date.now()}`
const qs = new URLSearchParams({ public_key: ka.publicKey, nonce, signature: sign(`matches-pending:${nonce}`, ka.privateKey) })
const pending = await fetch(`${API}/api/v3/matches/pending?${qs}`).then(r => r.json())
console.log('PENDING (side A):', JSON.stringify(pending, null, 2))

const stats = await fetch(`${API}/api/stats`).then(r => r.json())
console.log('STATS v3:', JSON.stringify(stats.v3, null, 2))
console.log('STATS legacy_v2:', JSON.stringify(stats.legacy_v2))
console.log('CARD_IDS:', pa.body.card_id, pb.body.card_id)

// ── Intro loop through the real endpoints, so the intro ledger hooks fire ──
const n1 = `intro-${Date.now()}`
const introReq = await post('/api/v3/intros/request', {
  from_card: pa.body.card_id, to_card: pb.body.card_id, purpose: 'collaborate',
  note: 'overlapping on rust protocol work', public_key: ka.publicKey, nonce: n1,
  signature: sign(`intro-request:${pa.body.card_id}:${pb.body.card_id}:collaborate:${n1}`, ka.privateKey),
})
console.log('INTRO REQUEST:', introReq.status, JSON.stringify(introReq.body))

const n2 = `resp-${Date.now()}`
const introResp = await post(`/api/v3/intros/${introReq.body.id}/respond`, {
  action: 'accept', contact: 'smoke-b@example.test', public_key: kb.publicKey, nonce: n2,
  signature: sign(`intro-respond:${introReq.body.id}:accept:${n2}`, kb.privateKey),
})
console.log('INTRO ACCEPT:', introResp.status, JSON.stringify(introResp.body))

const stats2 = await fetch(`${API}/api/stats`).then(r => r.json())
console.log('STATS v3 AFTER INTRO:', JSON.stringify(stats2.v3, null, 2))
