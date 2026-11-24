// Cards published while the embedding model is loading.
//
// The server loads the model in the background after it starts listening. A
// card published before the model is ready got no vector, and nothing went
// back to it, so a query search never returned it. These tests control when
// the model becomes ready with a fake loader and check that such a card is
// indexed once it is, without any change to the card itself.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import type { Server } from 'node:http'
import { generateKeyPair, sign, canonicalize } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-embedding-warmup-test-'))
process.env.DB_PATH = join(tmpDir, 'warmup.db')
process.env.MINGLE_PUBLIC_URL = 'https://mingle.test'
delete process.env.ADMIN_NOTIFY_EMAIL

const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const v3db = await import('../src/v3-db.js')
const embeddings = await import('../src/embeddings.js')
const index = await import('../src/embedding-index.js')
const mod = await import('../src/moderation.js')
const matchesDb = await import('../src/matches-db.js')
const email = await import('../src/notifications.js')
const { cardContentHash } = await import('../src/v3-cards.js')

let server: Server
let base: string

before(async () => {
  const app = createApp(); db.getDb()
  email.setTransport(async () => ({ ok: true, id: 'mock' }))
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { email.resetTransport(); server?.close(); db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })

/** A stand-in for the model: a stable 384 dimension vector from the words of
 *  the text, so texts that share words are close. `onEmbed` lets a test act
 *  while a vector is being computed. */
let onEmbed: (text: string) => void = () => {}
const fakeModel = async (text: string) => {
  onEmbed(text)
  const v = new Float32Array(384)
  for (const w of text.toLowerCase().split(/\W+/).filter(Boolean)) {
    v[createHash('sha256').update(w).digest()[0]! % 384] += 1
  }
  const n = Math.hypot(...v) || 1
  for (let i = 0; i < v.length; i++) v[i] = v[i]! / n
  return { data: v }
}

function deferred<T>() {
  let resolve!: (v: T) => void
  let reject!: (e: unknown) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

function buildCard(headline: string, offering: string, keys = generateKeyPair()): { keys: any; card: any } {
  const at = Date.now()
  const card: any = {
    card_type: 'connection', subject_key: keys.publicKey, version: 1,
    created_at: new Date(at).toISOString(), expires_at: new Date(at + 21 * 864e5).toISOString(),
    headline, intents: ['collaborate'],
    seeking: [], offering: [{ description: offering, topics: [], provenance: 'principal_statement' }],
    preferences: [], artifacts: [], event_ref: null, team_size_sought: null,
    visibility: {}, composition: { agent_assisted: true, skill_version: 'v1' },
    delegation_ref: null, revocation_status: 'active',
  }
  const h = cardContentHash(card)
  card.approval = { card_hash: h, approved_at: new Date(at).toISOString(), principal_signature: sign(h, keys.privateKey) }
  const { signature, ...unsigned } = card
  card.signature = sign(canonicalize(unsigned), keys.privateKey)
  return { keys, card }
}

async function publish(headline: string, offering: string): Promise<{ id: string; keys: any }> {
  const { keys, card } = buildCard(headline, offering)
  const res = await fetch(`${base}/api/v3/cards`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ card }) })
  const body = await res.json()
  assert.equal(res.status, 201, JSON.stringify(body))
  return { id: body.card_id, keys }
}

async function withdraw(id: string, keys: any): Promise<void> {
  const res = await fetch(`${base}/api/v3/cards/${id}/withdraw`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ public_key: keys.publicKey, signature: sign(`withdraw:${id}`, keys.privateKey) }),
  })
  assert.equal(res.status, 200, JSON.stringify(await res.json()))
}

async function search(query: string): Promise<{ status: number; ids: string[] }> {
  db.getDb().prepare('DELETE FROM rate_limits').run()
  const res = await fetch(`${base}/api/v3/cards/search`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query }) })
  const body = await res.json()
  return { status: res.status, ids: (body.results ?? []).map((r: any) => r.card_id) }
}

function row(id: string): unknown {
  return db.getDb().prepare('SELECT card_json, revocation_status, expires_at, card_hash FROM v3_cards WHERE card_id = ?').get(id)
}

test('a card published while the model loads becomes searchable once it is ready, without renewal', async () => {
  const model = deferred<any>()
  let loads = 0
  embeddings.setModelLoaderForTests(() => { loads++; return model.promise })
  const started = index.startEmbeddings()

  // Publishing does not wait for the model.
  const early = await publish('Tide pool ecologist', 'marine field surveys along the coast')
  assert.equal(v3db.hasV3Embedding(early.id), false, 'no vector while the model is loading')
  assert.equal((await search('marine field surveys')).status, 500, 'a query search is refused while loading')

  // Three cards that must not be indexed, and one that will be withdrawn while
  // its vector is being computed.
  const hidden = await publish('Glacier photographer', 'ice field photography')
  mod.hideFromNetwork('card', hidden.id, 'test', 'operator-test')
  const withdrawn = await publish('Desert botanist', 'cactus surveys')
  await withdraw(withdrawn.id, withdrawn.keys)
  const expired = await publish('Volcano guide', 'lava field walks')
  db.getDb().prepare(`UPDATE v3_cards SET expires_at = '2000-01-01T00:00:00.000Z' WHERE card_id = ?`).run(expired.id)
  const racing = await publish('Cave diver', 'underwater cave mapping')
  onEmbed = text => {
    if (text.includes('Cave diver')) {
      db.getDb().prepare(`UPDATE v3_cards SET revocation_status = 'withdrawn' WHERE card_id = ?`).run(racing.id)
    }
  }
  const before = [hidden, withdrawn, expired].map(c => row(c.id))
  const racingBefore = row(racing.id) as any

  // A second warmup call joins the first.
  const again = embeddings.warmupModel()
  model.resolve(fakeModel)
  assert.equal(await again, true)
  const result = await started
  onEmbed = () => {}
  assert.equal(loads, 1, 'one model load for overlapping warmup calls')
  assert.deepEqual(result, { indexed: 1, skipped: 1, remaining: 0 })

  assert.equal(v3db.hasV3Embedding(early.id), true)
  assert.ok(matchesDb.getMatchVector(early.id), 'the hourly sweep gets a vector to match with')
  const found = await search('marine field surveys')
  assert.equal(found.status, 200)
  assert.ok(found.ids.includes(early.id), `the early card is found: ${JSON.stringify(found.ids)}`)

  for (const c of [hidden, withdrawn, expired, racing]) {
    assert.equal(v3db.hasV3Embedding(c.id), false, `${c.id} stays out of the index`)
    assert.equal(found.ids.includes(c.id), false)
  }
  assert.deepEqual([hidden, withdrawn, expired].map(c => row(c.id)), before, 'no card row was changed')
  // The racing card changed only by the test's own withdrawal during the pass.
  assert.deepEqual(row(racing.id), { ...racingBefore, revocation_status: 'withdrawn' })

  // Running the pass again indexes nothing and adds no second index row.
  assert.deepEqual(await index.indexMissingEmbeddings(), { indexed: 0, skipped: 0, remaining: 0 })
  const rows = db.getDb().prepare('SELECT COUNT(*) AS n FROM v3_embedding_cards WHERE card_id = ?').get(early.id) as any
  assert.equal(rows.n, 1)
})

test('a card published after the model is ready is indexed at publish, and the pass leaves it alone', async () => {
  const later = await publish('Orchard keeper', 'apple grafting workshops')
  assert.equal(v3db.hasV3Embedding(later.id), true)
  assert.equal((await index.indexMissingEmbeddings()).indexed, 0)
})

test('a model that fails to load: the pass does not run, publishing still works, and the cause is logged', async () => {
  const logged: string[] = []
  const orig = console.error
  console.error = (...a: unknown[]) => { logged.push(a.join(' ')) }
  try {
    embeddings.setModelLoaderForTests(() => Promise.reject(new Error('no network')))
    assert.equal(await index.startEmbeddings(), null)
  } finally {
    console.error = orig
  }
  assert.ok(logged.some(l => l.includes('[embeddings] Warmup failed: no network')), JSON.stringify(logged))
  const card = await publish('Bridge inspector', 'steel truss inspections')
  assert.equal(v3db.hasV3Embedding(card.id), false)
  assert.equal(await embeddings.embed('anything'), null)
})

test('a model that never loads holds no request open', async () => {
  embeddings.setModelLoaderForTests(() => new Promise(() => {}))
  void index.startEmbeddings()
  const t = Date.now()
  await publish('Night sky guide', 'telescope evenings')
  assert.equal((await search('telescope')).status, 500)
  assert.ok(Date.now() - t < 5000, 'publish and search answered without waiting for the model')
})
