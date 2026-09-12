// ══════════════════════════════════════════════════════════════
// The cutoff and anti-downgrade, across every legacy route
// ══════════════════════════════════════════════════════════════
// The last step, because it is the only one that can refuse a working client. What is being
// held down:
//
//   1  ALL EIGHT legacy mutation routes run both checks, driven as a matrix rather than one
//      route at a time, so a route that forgot the gate is a red test and not an omission
//      somebody has to notice
//   2  the two refusals share a status and a body byte for byte, and are distinguished ONLY
//      in the internal log, which the tests capture
//   3  anti-downgrade is per actor and per resource: the counterparty on the same intro is
//      unaffected, and no row exists for a key that has not written
//   4  the grandfathered row is exempt from the cutoff and keeps working
//
// The eight routes cover all thirteen product actions, because /respond multiplexes
// express_interest, decline and block_pair.

import { test, before, after, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-cutoff-test-'))
process.env.DB_PATH = join(tmpDir, 'cutoff.db')
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'
process.env.MINGLE_FIT_ENABLED = '1'
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const env = await import('../src/write-envelope.js')
const facts = await import('../src/connection-facts.js')
const wdb = await import('../src/write-db.js')
const policyDb = await import('../src/fit-policy-db.js')
const firstStepDb = await import('../src/fit-firststep-db.js')
const commitments = await import('../src/policy-commitment.js')
const gate = await import('../src/legacy-write-gate.js')
const { cardContentHash } = await import('../src/v3-cards.js')
const { newNonce, jcs } = await import('../src/canonical-write.js')

let server: Server
let base: string

before(async () => {
  const app = createApp()
  db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })
beforeEach(() => {
  db.getDb().prepare('DELETE FROM rate_limits').run()
  clearCutoff()
})

// ── Fixtures ──────────────────────────────────────────────────────────────

const rid = () => randomBytes(4).toString('hex')
const future = () => new Date(Date.now() + 30 * 864e5).toISOString()
const DECIDED_BODY = { code: 'client_upgrade_required', error: 'Update Mingle to continue this connection.' }

function setCutoff(at: string): void {
  db.getDb().prepare('INSERT OR REPLACE INTO schema_markers (key, value) VALUES (?, ?)')
    .run(db.LEGACY_WRITE_CUTOFF_KEY, at)
}
function clearCutoff(): void {
  db.getDb().prepare('DELETE FROM schema_markers WHERE key = ?').run(db.LEGACY_WRITE_CUTOFF_KEY)
}
const PAST = () => new Date(Date.now() - 1000).toISOString()
const FUTURE = () => new Date(Date.now() + 30 * 864e5).toISOString()

async function capturingWarnings<T>(fn: () => Promise<T>): Promise<{ result: T; lines: string[] }> {
  const lines: string[] = []
  const original = console.warn
  console.warn = (...args: unknown[]) => { lines.push(args.map(String).join(' ')) }
  try { return { result: await fn(), lines } } finally { console.warn = original }
}

function makeCard(headline: string, intents: string[]): any {
  const keys = generateKeyPair()
  const now = Date.now()
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(now).toISOString(), expires_at: new Date(now + 21 * 864e5).toISOString(),
    headline, intents, seeking: [], offering: [{ description: 'x', provenance: 'principal_statement' }],
    preferences: [], artifacts: [], event_ref: null, team_size_sought: null,
    visibility: {}, composition: { agent_assisted: true, skill_version: 'v1' },
    delegation_ref: null, revocation_status: 'active',
  }
  const h = cardContentHash(card)
  card.approval = { card_hash: h, approved_at: new Date(now).toISOString(), principal_signature: sign(h, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return { keys, card }
}

async function post(url: string, body: unknown) {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  let json: any = null
  try { json = await res.json() } catch { /* none */ }
  return { status: res.status, json }
}

async function publish(built: any): Promise<string> {
  const r = await post(`${base}/api/v3/cards`, { card: built.card })
  assert.ok(r.json.card_id, JSON.stringify(r.json))
  return r.json.card_id
}

function dim(dimension: string, value: any, disclosure_state = 'testable'): any {
  return {
    dimension, value, sensitivity: 'low', disclosure_state,
    allowed_intents: ['cofound'], expires_at: future(), importance: 'useful',
  }
}

async function setPolicy(who: any, cardId: string, dimensions: any[]): Promise<void> {
  const approved_hash = policyDb.policyHash(dimensions)
  const nonce = 'p' + rid()
  const r = await post(`${base}/api/v4/fit/policy`, {
    card_id: cardId, dimensions, approved_hash, public_key: who.keys.publicKey, nonce,
    signature: sign(`set-fit-policy:${cardId}:${approved_hash}:${nonce}`, who.keys.privateKey),
  })
  assert.equal(r.status, 201, JSON.stringify(r.json))
}

const DIMS_A = [
  dim('cadence', 'mixed', 'reveal_overlap'),
  dim('weekly_commitment', { min: 20, max: 40 }, 'reveal_exact'),
  dim('role_spike', ['product'], 'reveal_exact'),
]
const DIMS_B = [
  dim('cadence', 'mixed', 'reveal_overlap'),
  dim('weekly_commitment', { min: 10, max: 30 }, 'reveal_exact'),
  dim('role_spike', ['fundraising'], 'reveal_exact'),
]

interface Scene {
  introId: string
  alice: any
  bob: any
  aliceCard: string
  bobCard: string
}

/** An entirely legacy scene: a legacy intro request, a legacy accept (which opens the v4
 *  handshake), and both cards carrying a Fit Policy. Nothing canonical anywhere, so nothing
 *  here is a downgrade and only the cutoff can refuse. */
async function legacyScene(opts: { accept?: boolean; fit?: boolean; fitRequest?: boolean } = {}): Promise<Scene> {
  const alice = makeCard('Alice C' + rid(), ['cofound', 'collaborate'])
  const bob = makeCard('Bob C' + rid(), ['cofound'])
  const aliceCard = await publish(alice)
  const bobCard = await publish(bob)
  await setPolicy(alice, aliceCard, DIMS_A)
  await setPolicy(bob, bobCard, DIMS_B)

  const rn = 'ri' + rid()
  const req = await post(`${base}/api/v3/intros/request`, {
    from_card: aliceCard, to_card: bobCard, purpose: 'cofound', note: 'old client',
    public_key: alice.keys.publicKey, nonce: rn,
    signature: sign(`intro-request:${aliceCard}:${bobCard}:cofound:${rn}`, alice.keys.privateKey),
  })
  assert.equal(req.status, 201, JSON.stringify(req.json))
  const introId = req.json.id

  if (opts.accept !== false) {
    const an = 'ai' + rid()
    const acc = await post(`${base}/api/v3/intros/${introId}/respond`, {
      action: 'accept', contact: 'x@e.example', public_key: bob.keys.publicKey, nonce: an,
      signature: sign(`intro-respond:${introId}:accept:${an}`, bob.keys.privateKey),
    })
    assert.equal(acc.status, 200, JSON.stringify(acc.json))
  }
  if (opts.fit || opts.fitRequest) {
    const fn = 'fq' + rid()
    const fr = await post(`${base}/api/v4/fit/${introId}/request`, {
      requested_dimensions: ['cadence'], reciprocal_offer: ['cadence'], predicate_version: 1,
      policy_hash: policyDb.policyHash(DIMS_A), query_budget: 3,
      public_key: alice.keys.publicKey, nonce: fn,
      signature: sign(`fit-request:${introId}:${fn}`, alice.keys.privateKey),
    })
    assert.equal(fr.status, 201, JSON.stringify(fr.json))
  }
  if (opts.fit) {
    const cn = 'fc' + rid()
    const fc = await post(`${base}/api/v4/fit/${introId}/commit`, {
      accept_dimensions: ['cadence'], reciprocal_offer: ['cadence'],
      policy_hash: policyDb.policyHash(DIMS_B),
      public_key: bob.keys.publicKey, nonce: cn,
      signature: sign(`fit-commit:${introId}:${cn}`, bob.keys.privateKey),
    })
    assert.equal(fc.status, 200, JSON.stringify(fc.json))
  }
  return { introId, alice, bob, aliceCard, bobCard }
}

const HALF = () => ({
  purpose: 'compare notes', next_action: 'a call', meeting_length: '30m',
  agenda: ['scope'], each_wants: 'clarity', boundaries: ['no recruiting'], expiry: future(),
})

/** THE MATRIX. One entry per legacy mutation route, each a closure that sends the published
 *  3.2.x shape. Every one must be refused under a past cutoff and must work without one. */
interface Lane {
  action: string
  /** Build a scene this route can act on, and send the legacy call. */
  send: (s: Scene) => Promise<{ status: number; json: any }>
  /** What the scene needs before this route is reachable. */
  needs: { accept?: boolean; fit?: boolean; fitRequest?: boolean }
  /** Extra legacy setup that must happen while the window is OPEN. */
  prepare?: (s: Scene) => Promise<void>
  /** The status a successful legacy call answers. */
  ok: number
}

const LANES: Lane[] = [
  {
    action: 'request_intro', needs: { accept: false }, ok: 201,
    // A create: its own fresh pair, because the scene's pair already has a pending intro.
    send: async () => {
      const alice = makeCard('Alice R' + rid(), ['cofound'])
      const bob = makeCard('Bob R' + rid(), ['cofound'])
      const ac = await publish(alice); const bc = await publish(bob)
      const n = 'ri' + rid()
      return post(`${base}/api/v3/intros/request`, {
        from_card: ac, to_card: bc, purpose: 'cofound', note: 'x',
        public_key: alice.keys.publicKey, nonce: n,
        signature: sign(`intro-request:${ac}:${bc}:cofound:${n}`, alice.keys.privateKey),
      })
    },
  },
  {
    action: 'express_interest (accept)', needs: { accept: false }, ok: 200,
    send: async s => {
      const n = 'ai' + rid()
      return post(`${base}/api/v3/intros/${s.introId}/respond`, {
        action: 'accept', contact: 'y@e.example', public_key: s.bob.keys.publicKey, nonce: n,
        signature: sign(`intro-respond:${s.introId}:accept:${n}`, s.bob.keys.privateKey),
      })
    },
  },
  {
    action: 'decline', needs: { accept: false }, ok: 200,
    send: async s => {
      const n = 'di' + rid()
      return post(`${base}/api/v3/intros/${s.introId}/respond`, {
        action: 'decline', public_key: s.bob.keys.publicKey, nonce: n,
        signature: sign(`intro-respond:${s.introId}:decline:${n}`, s.bob.keys.privateKey),
      })
    },
  },
  {
    action: 'block_pair (decline_and_block)', needs: { accept: false }, ok: 200,
    send: async s => {
      const n = 'bi' + rid()
      return post(`${base}/api/v3/intros/${s.introId}/respond`, {
        action: 'decline_and_block', public_key: s.bob.keys.publicKey, nonce: n,
        signature: sign(`intro-respond:${s.introId}:decline_and_block:${n}`, s.bob.keys.privateKey),
      })
    },
  },
  {
    action: 'share_contact (complete)', needs: { accept: true }, ok: 200,
    send: async s => {
      const n = 'ci' + rid()
      return post(`${base}/api/v3/intros/${s.introId}/complete`, {
        contact: 'z@e.example', public_key: s.alice.keys.publicKey, nonce: n,
        signature: sign(`intro-complete:${s.introId}:${n}`, s.alice.keys.privateKey),
      })
    },
  },
  {
    action: 'fit_request', needs: { accept: true }, ok: 201,
    send: async s => {
      const n = 'fq' + rid()
      return post(`${base}/api/v4/fit/${s.introId}/request`, {
        requested_dimensions: ['cadence'], reciprocal_offer: ['cadence'], predicate_version: 1,
        policy_hash: policyDb.policyHash(DIMS_A), query_budget: 3,
        public_key: s.alice.keys.publicKey, nonce: n,
        signature: sign(`fit-request:${s.introId}:${n}`, s.alice.keys.privateKey),
      })
    },
  },
  {
    // The request is part of the scene, so it is sent while the window is open and the commit
    // is the only act under test. Building it inside send() would mean the cutoff refused the
    // request and the commit then answered 409 about the handshake state instead.
    action: 'fit_commit', needs: { accept: true, fitRequest: true }, ok: 200,
    send: async s => {
      const n = 'fc' + rid()
      return post(`${base}/api/v4/fit/${s.introId}/commit`, {
        accept_dimensions: ['cadence'], reciprocal_offer: ['cadence'],
        policy_hash: policyDb.policyHash(DIMS_B),
        public_key: s.bob.keys.publicKey, nonce: n,
        signature: sign(`fit-commit:${s.introId}:${n}`, s.bob.keys.privateKey),
      })
    },
  },
  {
    action: 'release_exact', needs: { accept: true, fit: true }, ok: 200,
    send: async s => {
      const n = 'fv' + rid()
      return post(`${base}/api/v4/fit/${s.introId}/reveal`, {
        dimension: 'weekly_commitment', public_key: s.alice.keys.publicKey, nonce: n,
        signature: sign(`fit-reveal:${s.introId}:weekly_commitment:${n}`, s.alice.keys.privateKey),
      })
    },
  },
  {
    action: 'first_step_propose', needs: { accept: true, fit: true }, ok: 201,
    send: async s => {
      const n = 'fs' + rid()
      return post(`${base}/api/v4/fit/${s.introId}/first-step`, {
        half: HALF(), public_key: s.alice.keys.publicKey, nonce: n,
        signature: sign(`fit-firststep:${s.introId}:${n}`, s.alice.keys.privateKey),
      })
    },
  },
  {
    // Both halves are proposed by prepare(), while the window is open, so the approve is the
    // only act the cutoff is being asked about.
    action: 'first_step_approve', needs: { accept: true, fit: true }, ok: 200,
    prepare: async s => {
      for (const who of [s.alice, s.bob]) {
        const pn = 'fs' + rid()
        const r = await post(`${base}/api/v4/fit/${s.introId}/first-step`, {
          half: HALF(), public_key: who.keys.publicKey, nonce: pn,
          signature: sign(`fit-firststep:${s.introId}:${pn}`, who.keys.privateKey),
        })
        assert.equal(r.status, 201, JSON.stringify(r.json))
      }
    },
    send: async s => {
      const digest = firstStepDb.sharedDigest(firstStepDb.getFirstStep(s.introId)!)
      const n = 'fa' + rid()
      return post(`${base}/api/v4/fit/${s.introId}/first-step/approve`, {
        approved_digest: digest, public_key: s.alice.keys.publicKey, nonce: n,
        signature: sign(`fit-firststep-approve:${s.introId}:${digest}:${n}`, s.alice.keys.privateKey),
      })
    },
  },
]

// ══════════════════════════════════════════════════════════════
// The matrix: no marker, a future cutoff, a past cutoff
// ══════════════════════════════════════════════════════════════

test('CUTOFF: with no marker, every legacy route works', async () => {
  clearCutoff()
  assert.equal(db.legacyWriteCutoffAt(), null)
  for (const lane of LANES) {
    const scene = await legacyScene(lane.needs)
    if (lane.prepare) await lane.prepare(scene)
    const r = await lane.send(scene)
    assert.equal(r.status, lane.ok, `${lane.action}: ${JSON.stringify(r.json)}`)
  }
})

test('CUTOFF: with a future cutoff, every legacy route still works', async () => {
  setCutoff(FUTURE())
  assert.equal(db.legacyWindowClosed(), false)
  for (const lane of LANES) {
    const scene = await legacyScene(lane.needs)
    if (lane.prepare) await lane.prepare(scene)
    const r = await lane.send(scene)
    assert.equal(r.status, lane.ok, `${lane.action}: ${JSON.stringify(r.json)}`)
  }
})

test('CUTOFF: with a past cutoff, every legacy route answers 426 with the decided text byte exact', async () => {
  // The scenes are built with the window OPEN, because building them is itself a sequence of
  // legacy calls. Then the cutoff closes and the act under test is sent.
  const prepared: [Lane, Scene][] = []
  clearCutoff()
  for (const lane of LANES) {
    const scene = await legacyScene(lane.needs)
    if (lane.prepare) await lane.prepare(scene)
    prepared.push([lane, scene])
  }

  setCutoff(PAST())
  assert.equal(db.legacyWindowClosed(), true)
  for (const [lane, scene] of prepared) {
    const { result, lines } = await capturingWarnings(() => lane.send(scene))
    assert.equal(result.status, 426, `${lane.action}: ${JSON.stringify(result.json)}`)
    assert.deepEqual(result.json, DECIDED_BODY, `${lane.action}: byte exact`)
    assert.ok(lines.some(l => l.includes('legacy write window closed')),
      `${lane.action}: the log names the window, which is the only place the two refusals differ`)
    assert.equal(lines.some(l => l.includes('downgrade prevention')), false, `${lane.action}: and not the other reason`)
  }
  assert.equal(prepared.length, 10, 'all ten legacy acts across the eight routes were driven')
})

test('CUTOFF: the grandfathered row is exempt and keeps working after the cutoff', async () => {
  const scene = await legacyScene({ accept: false })
  // Both scenes are built while the window is open, because building one is itself a legacy
  // call. Only the acts under test are sent after it closes.
  const modern = await legacyScene({ accept: false })
  const marker = db.getSchemaMarker(db.MINGLE_2A_MARKER_KEY)!
  db.getDb().prepare('UPDATE v3_intros SET created_at = ? WHERE id = ?')
    .run(new Date(Date.parse(marker) - 864e5).toISOString(), scene.introId)
  assert.equal(facts.isPre2AIntro(scene.introId), true)

  setCutoff(PAST())
  const n = 'ga' + rid()
  const r = await post(`${base}/api/v3/intros/${scene.introId}/respond`, {
    action: 'accept', contact: 'grand@e.example', public_key: scene.bob.keys.publicKey, nonce: n,
    signature: sign(`intro-respond:${scene.introId}:accept:${n}`, scene.bob.keys.privateKey),
  })
  assert.equal(r.status, 200, `the grandfathered row stays on the old path until terminal or expired: ${JSON.stringify(r.json)}`)

  // And a row created under THIS build, on the same date, is not exempt.
  assert.equal(facts.isPre2AIntro(modern.introId), false)
  const m = 'ma' + rid()
  const refused = await post(`${base}/api/v3/intros/${modern.introId}/respond`, {
    action: 'accept', contact: 'modern@e.example', public_key: modern.bob.keys.publicKey, nonce: m,
    signature: sign(`intro-respond:${modern.introId}:accept:${m}`, modern.bob.keys.privateKey),
  })
  assert.equal(refused.status, 426)
})

test('CUTOFF: a create cannot be grandfathered, because it has no intro yet', async () => {
  // checkLegacyCreate runs the cutoff only, in its own named function, because a create's
  // resource does not exist yet and there is nothing for anti-downgrade to resolve against.
  setCutoff(PAST())
  const alice = makeCard('Alice N' + rid(), ['cofound'])
  const bob = makeCard('Bob N' + rid(), ['cofound'])
  const ac = await publish(alice); const bc = await publish(bob)
  const n = 'ri' + rid()
  const r = await post(`${base}/api/v3/intros/request`, {
    from_card: ac, to_card: bc, purpose: 'cofound', note: 'x',
    public_key: alice.keys.publicKey, nonce: n,
    signature: sign(`intro-request:${ac}:${bc}:cofound:${n}`, alice.keys.privateKey),
  })
  assert.equal(r.status, 426, 'a new request after the cutoff is a new client\'s job')
  assert.equal(gate.checkLegacyCreate({ actorKey: alice.keys.publicKey }) !== null, true)
})

// ══════════════════════════════════════════════════════════════
// Anti-downgrade
// ══════════════════════════════════════════════════════════════

function signedBody(over: { operation: string; resource: any; payload?: any; keys: any }) {
  const payload = over.payload ?? {}
  const built = env.buildEnvelope({
    operation: over.operation as any, actorKey: over.keys.publicKey, resource: over.resource,
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'), nonce: newNonce(), payload,
  })
  return { body: { envelope: built.envelope, signature: sign(jcs(built.envelope), over.keys.privateKey), payload }, built }
}

test('DOWNGRADE: a canonical actor sending legacy on the same resource is 426, both before and after the cutoff', async () => {
  for (const cutoff of [null, PAST()] as const) {
    const scene = await legacyScene({ accept: false })
    clearCutoff()
    // The target answers canonically, which records mode canonical for that key on that intro.
    const canonical = await post(`${base}/api/v3/intros/${scene.introId}/respond`, signedBody({
      operation: 'express_interest', resource: { type: 'intro', id: scene.introId }, keys: scene.bob.keys,
    }).body)
    assert.equal(canonical.status, 201, JSON.stringify(canonical.json))
    if (cutoff !== null) setCutoff(cutoff)

    // The target's legacy act is the accept on /respond. Only the requester may complete, so
    // using /complete here would have been refused on the party check instead.
    const { result, lines } = await capturingWarnings(async () => {
      const n = 'dg' + rid()
      return post(`${base}/api/v3/intros/${scene.introId}/respond`, {
        action: 'accept', contact: 'downgrade@e.example', public_key: scene.bob.keys.publicKey, nonce: n,
        signature: sign(`intro-respond:${scene.introId}:accept:${n}`, scene.bob.keys.privateKey),
      })
    })
    assert.equal(result.status, 426, `cutoff=${String(cutoff)}: ${JSON.stringify(result.json)}`)
    assert.deepEqual(result.json, DECIDED_BODY, 'the same body as the cutoff refusal, because the remedy is the same')
    assert.ok(lines.some(l => l.includes('downgrade prevention')),
      `cutoff=${String(cutoff)}: anti-downgrade runs FIRST, so the log says downgrade even after the cutoff`)
    assert.equal(lines.some(l => l.includes('legacy write window closed')), false)
    clearCutoff()
  }
})

test('DOWNGRADE: exactly one mode row per signed write, and none for a key that has not written', async () => {
  const scene = await legacyScene({ accept: false })
  const before = db.getDb().prepare(
    'SELECT * FROM write_auth_mode WHERE resource_type = ? AND resource_id = ?').all('intro', scene.introId) as any[]
  // The legacy request wrote one row, for its signer only.
  assert.equal(before.length, 1)
  assert.equal(before[0].actor_key, scene.alice.keys.publicKey)
  assert.equal(before[0].mode, 'legacy_unbound')
  assert.equal(facts.stateOf(scene.introId), 'requested')

  // THE RULING that removed the pre-authorized row: no row exists for the counterparty, who
  // has done nothing. A row written on someone else's behalf would assert a fact about an
  // actor who has not acted.
  assert.equal(wdb.authModeRow('intro', scene.introId, scene.bob.keys.publicKey), null)
  assert.equal(wdb.resolveAuthMode('intro', scene.introId, scene.bob.keys.publicKey), null)

  // The target now writes canonically. One row appears, for the target.
  assert.equal((await post(`${base}/api/v3/intros/${scene.introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: scene.introId }, keys: scene.bob.keys,
  }).body)).status, 201)
  const after = db.getDb().prepare(
    'SELECT * FROM write_auth_mode WHERE resource_type = ? AND resource_id = ? ORDER BY actor_key').all('intro', scene.introId) as any[]
  assert.equal(after.length, 2, 'one per signer, and never more')
  assert.equal(wdb.resolveAuthMode('intro', scene.introId, scene.bob.keys.publicKey), 'canonical')

  // And the requester is UNAFFECTED, which is the per actor per resource property: it may
  // still use the legacy lane.
  assert.equal(wdb.resolveAuthMode('intro', scene.introId, scene.alice.keys.publicKey), 'legacy_unbound')
  const n = 'cc' + rid()
  const stillLegacy = await post(`${base}/api/v3/intros/${scene.introId}/complete`, {
    contact: 'requester@e.example', public_key: scene.alice.keys.publicKey, nonce: n,
    signature: sign(`intro-complete:${scene.introId}:${n}`, scene.alice.keys.privateKey),
  })
  assert.equal(stillLegacy.status, 200, 'the counterparty on the same intro is untouched')
})

test('DOWNGRADE: canonical is absorbing, so a second canonical write does not weaken the row', async () => {
  const scene = await legacyScene({ accept: false })
  assert.equal((await post(`${base}/api/v3/intros/${scene.introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: scene.introId }, keys: scene.bob.keys,
  }).body)).status, 201)
  assert.equal(wdb.resolveAuthMode('intro', scene.introId, scene.bob.keys.publicKey), 'canonical')
  // Recording legacy_unbound for a key already canonical must not move it back. The refusal
  // is what a route does, and the absorbing update is what the table guarantees if one slips.
  wdb.recordAuthMode('intro', scene.introId, scene.bob.keys.publicKey, 'legacy_unbound')
  assert.equal(wdb.resolveAuthMode('intro', scene.introId, scene.bob.keys.publicKey), 'canonical',
    'canonical is absorbing, so the table cannot be walked backwards')
})

test('DOWNGRADE: an actor who created canonically and then sends legacy is refused, resolved through write_create_map', async () => {
  // The one row model. The create names intro_request/<request_id>, because the intro did not
  // exist when the envelope was signed, so resolution walks BACK through write_create_map
  // rather than pre-writing a row for a resource nobody has acted on.
  const alice = makeCard('Alice M' + rid(), ['cofound'])
  const bob = makeCard('Bob M' + rid(), ['cofound'])
  const aliceCard = await publish(alice)
  const bobCard = await publish(bob)
  const requestId = randomBytes(16).toString('hex')
  const created = await post(`${base}/api/v3/intros/request`, signedBody({
    operation: 'request_intro', resource: { type: 'intro_request', id: requestId },
    payload: { from_card: aliceCard, to_card: bobCard, purpose: 'cofound', note: 'new client' },
    keys: alice.keys,
  }).body)
  assert.equal(created.status, 201, JSON.stringify(created.json))
  const introId = created.json.intro_id

  // No direct row on the intro for the creator.
  assert.equal(wdb.authModeRow('intro', introId, alice.keys.publicKey), null,
    'no row is pre-written for a resource nobody has acted on')
  // And yet the mode resolves, by walking the create map.
  assert.equal(wdb.resolveAuthMode('intro', introId, alice.keys.publicKey), 'canonical')
  assert.equal(wdb.authModeRow('intro_request', requestId, alice.keys.publicKey)!.mode, 'canonical')

  // So the legacy completion of a canonically created intro is refused.
  assert.equal((await post(`${base}/api/v3/intros/${introId}/respond`, signedBody({
    operation: 'express_interest', resource: { type: 'intro', id: introId }, keys: bob.keys,
  }).body)).status, 201)
  const { result, lines } = await capturingWarnings(async () => {
    const n = 'mc' + rid()
    return post(`${base}/api/v3/intros/${introId}/complete`, {
      contact: 'fallback@e.example', public_key: alice.keys.publicKey, nonce: n,
      signature: sign(`intro-complete:${introId}:${n}`, alice.keys.privateKey),
    })
  })
  assert.equal(result.status, 426, JSON.stringify(result.json))
  assert.ok(lines.some(l => l.includes('downgrade prevention')))
  // Nothing was written by the refused call.
  const row = db.getDb().prepare('SELECT from_contact FROM v3_intros WHERE id = ?').get(introId) as any
  assert.equal(row.from_contact, null)
})

test('DOWNGRADE: release_exact\'s mode key is coarser than the action, deliberately', async () => {
  // The subject on release_exact is the dimension, so anti-downgrade keyed on (actor, intro)
  // means an actor who released one dimension canonically cannot release a second by the
  // legacy route. Stricter than necessary and the right direction: the alternative is a per
  // dimension mode table that lets one actor hold two authorization strengths on one intro.
  const scene = await legacyScene({ accept: true, fit: true })
  const commitDims = DIMS_A
  const salt = randomBytes(32).toString('base64url')
  const commitment = commitments.policyCommitment(salt, commitDims as any)
  const cn = 'pc' + rid()
  assert.equal((await post(`${base}/api/v4/fit/policy/commitment`, {
    card_id: scene.aliceCard, commitment, salt, public_key: scene.alice.keys.publicKey, nonce: cn,
    signature: sign(`register-policy-commitment:${scene.aliceCard}:${commitment}:${cn}`, scene.alice.keys.privateKey),
  })).status, 201)

  // A canonical release of ONE dimension.
  const resource = { type: 'intro' as const, id: scene.introId }
  const value = { min: 20, max: 40 }
  const valueSalt = randomBytes(32).toString('base64url')
  const vc = env.privateValueCommitment('release_exact', resource, valueSalt, value)
  const built = env.buildEnvelope({
    operation: 'release_exact', actorKey: scene.alice.keys.publicKey, resource,
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z'), nonce: newNonce(),
    payload: { dimension: 'weekly_commitment', policy_commitment: commitment, private_value_commitment: vc },
  })
  const canonical = await post(`${base}/api/v4/fit/${scene.introId}/reveal`, {
    envelope: built.envelope, signature: sign(jcs(built.envelope), scene.alice.keys.privateKey),
    payload: { dimension: 'weekly_commitment', policy_commitment: commitment, private_value_commitment: vc },
    opening: { value, salt: valueSalt },
  })
  assert.equal(canonical.status, 201, JSON.stringify(canonical.json))

  // Now a legacy reveal of a DIFFERENT dimension by the same actor. Refused, because the mode
  // key does not carry the dimension.
  // role_spike is reveal_exact too. A dimension the policy does not authorize for exact
  // release would be refused on that check BEFORE the gate, which is the right order, so this
  // has to be a dimension the actor genuinely could release.
  const n = 'lr' + rid()
  const refused = await post(`${base}/api/v4/fit/${scene.introId}/reveal`, {
    dimension: 'role_spike', public_key: scene.alice.keys.publicKey, nonce: n,
    signature: sign(`fit-reveal:${scene.introId}:role_spike:${n}`, scene.alice.keys.privateKey),
  })
  assert.equal(refused.status, 426, 'coarser than the action, and the right direction')
  // While the counterparty, who has written nothing canonical, is unaffected.
  assert.equal(wdb.resolveAuthMode('intro', scene.introId, scene.bob.keys.publicKey), 'legacy_unbound')
})

test('GATE: the two refusals are the same status and body, and differ only in the log reason', () => {
  assert.equal(gate.LEGACY_REFUSAL.status, 426)
  assert.deepEqual({ code: gate.LEGACY_REFUSAL.code, error: gate.LEGACY_REFUSAL.error }, DECIDED_BODY)
  // Both reasons exist and are distinct, and neither leaks into the response.
  const reasons = new Set(['downgrade prevention', 'legacy write window closed'])
  assert.equal(reasons.size, 2)
  for (const r of reasons) {
    assert.equal(gate.LEGACY_REFUSAL.error.includes(r), false, 'the reason never reaches the caller')
  }
})
