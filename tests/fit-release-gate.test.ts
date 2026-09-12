// ══════════════════════════════════════════════════════════════
// The structured fit release gate
// ══════════════════════════════════════════════════════════════
// MINGLE_FIT_ENABLED stays unset until a TEST proves the surface is repaired. This is
// that test, and it is the scoreboard for steps 18 to 25: each of them flips exactly one
// enumerated route from unrepaired to canonical or removed, so the count here moves
// rather than a claim in a document.
//
// Three things make it a gate rather than theatre, and each has its own case below:
//
//   1  it ENUMERATES from the live router stack, so a mutation route added to either fit
//      router with nobody remembering to classify it fails
//   2  it fails LOUDLY on an unparseable or empty manifest rather than passing vacuously
//   3  being behind fitGate satisfies NOTHING, because otherwise the gate is circular:
//      every route would count as contained while the flag is off, which is exactly the
//      state the gate exists to decide whether to leave
//
// THE FLAG IS NOT MUTATED HERE. The evaluator is pure and takes the flag as a parameter,
// so this file asserts the verdict under BOTH values in one run, deterministically, and
// no test in the suite depends on another having enabled fit. The suite is also run twice
// under the two real environment values for the handoff, and this file behaves the same
// either way.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPair } from 'agent-passport-system'

// A temp database and an injected receipt key, because createApp() opens the write schema
// and a receipt key is a startup requirement with no fallback.
const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-gate-test-'))
process.env.DB_PATH = join(tmpDir, 'gate.db')
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey
// The flag's value must not matter to anything in this file. Recorded, restored, never
// read by an assertion.
const flagBefore = process.env.MINGLE_FIT_ENABLED

const gate = await import('../src/fit-release-gate.js')
const pipeline = await import('../src/write-pipeline.js')
const fitGateMod = await import('../src/fit-gate.js')
const evidence = await import('../src/write-evidence.js')
const env = await import('../src/write-envelope.js')
const { createApp } = await import('../src/app.js')
const db = await import('../src/db.js')
const expressMod = (await import('express')).default

process.on('exit', () => {
  if (flagBefore === undefined) delete process.env.MINGLE_FIT_ENABLED
  else process.env.MINGLE_FIT_ENABLED = flagBefore
  try { db.closeDb() } catch { /* the app may never have opened it */ }
  rmSync(tmpDir, { recursive: true, force: true })
})

const manifest = JSON.parse(
  readFileSync(new URL('../fixtures/mingle-fit-release-gate.json', import.meta.url), 'utf8'),
)

const app = createApp()
let server: import('node:http').Server
let base = ''
before(async () => {
  db.getDb()
  await new Promise<void>(r => { server = app.listen(0, '127.0.0.1', () => r()) })
  base = `http://127.0.0.1:${(server.address() as any).port}`
})
after(() => { server?.close() })

const registered = gate.enumerateFitMutationRoutes(app, {
  canonicalOperationsOf: pipeline.canonicalOperationsOf,
  fitGate: fitGateMod.fitGate,
})
// null for an operation the protocol does not have, so the evaluator can tell "unfinished"
// from "the manifest names something that does not exist".
const KNOWN_OPERATIONS = new Set<string>(env.ENVELOPE_OPERATIONS as unknown as string[])
const boundFields = (op: string) => KNOWN_OPERATIONS.has(op) ? evidence.boundFieldsFor(op as any, 'canonical') : null
const evaluate = (fitEnabled: boolean) => gate.evaluateReleaseGate({ manifest, registered, fitEnabled, boundFields })

// ══════════════════════════════════════════════════════════════
// 1. The enumeration is independent of the manifest and of the flag
// ══════════════════════════════════════════════════════════════

test('GATE: the enumeration reads the live router stack and finds both fit mounts', () => {
  assert.ok(registered.length >= 12,
    `only ${registered.length} structured fit mutation routes enumerated, which is fewer than the matrix classified`)
  for (const mount of gate.FIT_MOUNTS) {
    assert.ok(registered.some(r => r.route.startsWith(mount + '/')), `${mount} contributed no route`)
  }
  // Every enumerated route is a mutation on a fit mount, and no read leaked in.
  for (const r of registered) {
    assert.equal(r.method, r.method.toUpperCase())
    assert.equal(['GET', 'HEAD', 'OPTIONS'].includes(r.method), false, `${r.route} is a read method`)
    assert.ok(gate.FIT_MOUNTS.some(m => r.route.startsWith(m + '/')), `${r.route} is not on a fit mount`)
  }
  // The reads that DO exist on these routers are absent, which is what makes the count
  // meaningful rather than "every route".
  assert.equal(registered.some(r => r.route === '/api/v4/fit/:introId/qa'), false)
  assert.equal(registered.some(r => r.route === '/api/v3/fit/:id/draft'), false)
})

test('GATE: the mount decoder returns null rather than guessing, and the enumerator then throws', () => {
  // The mount path is recoverable only from the layer's regexp: Express sets layer.path
  // during matching. So the decoder is load bearing and a silent wrong answer would be a
  // gate that enumerates the wrong surface.
  assert.equal(gate.mountPrefixOf({ regexp: { source: '^\\/api\\/v3\\/fit\\/?(?=\\/|$)' } }), '/api/v3/fit')
  assert.equal(gate.mountPrefixOf({ regexp: { source: '^\\/?(?=\\/|$)', fast_slash: true } }), '')
  assert.equal(gate.mountPrefixOf({ regexp: { source: 'something else' } }), null)
  assert.equal(gate.mountPrefixOf({}), null)
  assert.equal(gate.mountPrefixOf(null), null)
  assert.throws(() => gate.enumerateFitMutationRoutes({}, { canonicalOperationsOf: () => null, fitGate: null }),
    /no router stack/)
  // An undecodable mount OUTSIDE the fit surface is skipped, because it could be anything and
  // is none of this gate's business. The missing fit mount is then what fails, loudly.
  assert.throws(() => gate.enumerateFitMutationRoutes(
    { _router: { stack: [{ handle: { stack: [] }, regexp: { source: 'undecodable' } }] } },
    { canonicalOperationsOf: () => null, fitGate: null }), /is not mounted/)
  // An undecodable mount INSIDE the fit surface is fatal on its own terms, because it could
  // carry a mutation route nobody can see.
  const fitMount = (inner: unknown[]) => ({
    handle: { stack: inner }, regexp: { source: '^\\/api\\/v3\\/fit\\/?(?=\\/|$)' },
  })
  const v4Mount = { handle: { stack: [] }, regexp: { source: '^\\/api\\/v4\\/fit\\/?(?=\\/|$)' } }
  assert.throws(() => gate.enumerateFitMutationRoutes(
    { _router: { stack: [fitMount([{ handle: { stack: [] }, regexp: { source: 'undecodable' } }]), v4Mount] } },
    { canonicalOperationsOf: () => null, fitGate: null }), /could not be decoded/)
  // A stack with neither fit mount is a loud failure rather than an empty pass.
  assert.throws(() => gate.enumerateFitMutationRoutes(
    { _router: { stack: [{ handle: { stack: [] }, regexp: { source: '^\\/api\\/v3\\/cards\\/?(?=\\/|$)' } }] } },
    { canonicalOperationsOf: () => null, fitGate: null }), /is not mounted/)
  // And a route path Express recorded as something other than a string is fatal rather than
  // discarded, which is how an array of paths used to vanish.
  assert.throws(() => gate.enumerateFitMutationRoutes(
    { _router: { stack: [fitMount([{ route: { path: 42, methods: { post: true }, stack: [] } }]), v4Mount] } },
    { canonicalOperationsOf: () => null, fitGate: null }), /cannot read/)
})

test('GATE: the four registration forms that used to vanish are now enumerated', () => {
  // Each of these was silently skipped, with no throw and no unlisted_mutation_route, so a
  // mutation route registered any of these four ordinary ways was live and invisible to the
  // gate. Built from real Express routers rather than from hand written layer shapes, because
  // the point is what Express actually records.
  const build = (make: (fit: any, app: any) => void): string[] => {
    const fit = expressMod.Router()
    const app = expressMod()
    make(fit, app)
    app.use('/api/v3/fit', fit)
    app.use('/api/v4/fit', expressMod.Router())
    return gate.enumerateFitMutationRoutes(app, {
      canonicalOperationsOf: pipeline.canonicalOperationsOf, fitGate: fitGateMod.fitGate,
    }).map(r => `${r.method} ${r.route}`)
  }
  const nested = expressMod.Router()
  nested.post('/:id/seal', (_q: any, res: any) => res.json({}))
  assert.deepEqual(build(fit => { fit.use('/exchange', nested) }), ['POST /api/v3/fit/exchange/:id/seal'],
    'a sub-router mounted inside a fit router')
  const deeper = expressMod.Router()
  deeper.post('/:id/nuke', (_q: any, res: any) => res.json({}))
  assert.deepEqual(build((_f, app) => { app.use('/api/v3/fit/exchange', deeper) }), ['POST /api/v3/fit/exchange/:id/nuke'],
    'a mount one level deeper than the fit mount')
  const cased = expressMod.Router()
  cased.post('/x/nuke', (_q: any, res: any) => res.json({}))
  assert.deepEqual(build((_f, app) => { app.use('/API/v3/FIT', cased) }), ['POST /API/v3/FIT/x/nuke'],
    'Express routes case insensitively, so a cased mount serves the same requests')
  assert.deepEqual(build(fit => { fit.post(['/:id/answers', '/:id/answer'], (_q: any, res: any) => res.json({})) }),
    ['POST /api/v3/fit/:id/answers', 'POST /api/v3/fit/:id/answer'],
    'one declaration registering two paths')
  // router.all records the pseudo method _all, enumerated so it fails as unlisted.
  assert.deepEqual(build(fit => { fit.all('/:id/allof', (_q: any, res: any) => res.json({})) }),
    ['_ALL /api/v3/fit/:id/allof'])
})

test('GATE: a duplicate registration is fatal, because Express runs the first and a lookup keeps the last', () => {
  const dup = [...registered, { method: 'POST', route: '/api/v3/fit/:id/answers', canonicalOperations: null, behindFitGate: true }]
  for (const fitEnabled of [false, true]) {
    const v = gate.evaluateReleaseGate({ manifest, registered: dup, fitEnabled, boundFields })
    assert.equal(v.ok, false, `flag ${fitEnabled}`)
    assert.equal(v.problems.some(p => p.kind === 'duplicate_registration'), true, JSON.stringify(v.problems))
  }
})

test('GATE: the manifest cannot be weakened, widened or renamed while staying green', () => {
  // Three ways the gate could have been made to accept a partial repair, each now fatal.
  const weaker = { ...manifest, gate: manifest.gate.map((e: any) =>
    e.semantic_fields ? { ...e, semantic_fields: [e.semantic_fields[0]] } : e) }
  const w = gate.evaluateReleaseGate({ manifest: weaker, registered, fitEnabled: true, boundFields })
  assert.equal(w.ok, false, 'a manifest that names fewer semantic fields than the operation binds')
  assert.equal(w.problems.some(p => p.kind === 'semantic_fields_drift'), true, JSON.stringify(w.problems))

  const wider = registered.map(r => r.route === '/api/v4/fit/:introId/answers'
    ? { ...r, canonicalOperations: ['fit_answers', 'fit_round2'] } : r)
  const x = gate.evaluateReleaseGate({ manifest, registered: wider, fitEnabled: true, boundFields })
  assert.equal(x.ok, false, 'a route that also accepts an operation the manifest never named')
  assert.equal(x.problems.some(p => p.kind === 'operation_set_wider'), true, JSON.stringify(x.problems))

  const renamed = { ...manifest, gate: manifest.gate.map((e: any) =>
    e.route === '/api/v3/fit/:id/custom' ? { ...e, operation: 'not_an_operation' } : e) }
  const y = gate.evaluateReleaseGate({ manifest: renamed, registered, fitEnabled: true, boundFields })
  assert.equal(y.ok, false, 'a manifest naming an operation the protocol does not have')
  assert.equal(y.problems.some(p => p.kind === 'unknown_operation'), true, JSON.stringify(y.problems))

  const moved = {
    ...manifest,
    gate: manifest.gate.filter((e: any) => e.route !== '/api/v3/fit/:id/custom'),
    outside_gate: [...manifest.outside_gate, {
      method: 'POST', route: '/api/v3/fit/:id/custom', matrix_row: '41', verdict: 'NO',
      reason: 'a plausible sentence that is more than twenty characters long',
    }],
  }
  const z = gate.evaluateReleaseGate({ manifest: moved, registered, fitEnabled: false, boundFields })
  assert.equal(z.ok, false, 'a PARTIAL or NO row cannot sit outside the gate')
  assert.equal(z.problems.some(p => p.kind === 'outside_gate_not_yes'), true, JSON.stringify(z.problems))
})

// ══════════════════════════════════════════════════════════════
// 2. The live verdict, under BOTH flag values
// ══════════════════════════════════════════════════════════════

test('GATE: the manifest and the application agree exactly, whatever the flag says', () => {
  for (const fitEnabled of [false, true]) {
    const v = evaluate(fitEnabled)
    assert.deepEqual(v.problems, [],
      `set agreement or manifest shape failed, which is fatal under both flag values:\n${gate.formatGateReport(v)}`)
  }
})

test('GATE: THE RATCHET, every entry is satisfied under BOTH flag values', () => {
  // The gate is green, so from here its job changes. While work remained, the flag-unset
  // verdict was the assertion and the flag-at-"1" verdict was expected to be red. Now that
  // all twelve are satisfied, BOTH verdicts must be asserted true, or the suite cannot tell
  // 12 of 12 from 11 of 12: a route that lost its canonical branch would leave one shortfall,
  // which the flag-unset verdict tolerates by design, and CI would stay green on the exact
  // regression this gate exists to catch.
  for (const fitEnabled of [false, true]) {
    const v = evaluate(fitEnabled)
    assert.equal(v.ok, true, `flag ${fitEnabled}:\n${gate.formatGateReport(v)}`)
    assert.deepEqual(v.shortfalls, [], `flag ${fitEnabled}: a shortfall is now a regression`)
    assert.deepEqual(v.problems, [])
    assert.equal(v.statuses.filter(s => s.satisfied).length, v.statuses.length,
      `flag ${fitEnabled}: every entry must have reached its disposition`)
  }
  // And the ratchet is not vacuous: degrade one route and the flag-at-"1" verdict goes red.
  const degraded = registered.map(r => r.route === '/api/v3/fit/:id/close' ? { ...r, canonicalOperations: null } : r)
  const after = gate.evaluateReleaseGate({ manifest, registered: degraded, fitEnabled: true, boundFields })
  assert.equal(after.ok, false, 'losing a canonical branch must fail the enabled verdict')
  assert.equal(after.shortfalls.length, 1)
})

test('GATE: with the flag unset the report names every route and its status', () => {
  const v = evaluate(false)
  assert.equal(v.ok, true, gate.formatGateReport(v))
  assert.equal(v.statuses.length, manifest.gate.length, 'one status row per gate entry')
  // The report is what the handoff records, so it must actually name each route and its
  // matrix row rather than summarising.
  const report = gate.formatGateReport(v)
  for (const s of v.statuses) assert.ok(report.includes(`${s.method} ${s.route}`), `${s.route} is missing from the report`)
  console.log(report)
})

test('GATE: with the flag at "1" the verdict is exactly whether every entry is satisfied', () => {
  const v = evaluate(true)
  const unsatisfied = v.statuses.filter(s => !s.satisfied)
  assert.equal(v.ok, unsatisfied.length === 0,
    'the enabled verdict must be nothing other than "every entry reached its disposition"')
  assert.equal(v.shortfalls.length > 0, unsatisfied.length > 0)
  // The header always, so a run log carries the verdict under BOTH flag values, plus the
  // shortfalls while any remain. The flag-unset case already printed every route, so this
  // does not repeat them.
  const lines = gate.formatGateReport(v).split('\n')
  console.log([lines[0], ...lines.filter(l => l.startsWith('     '))].join('\n'))
})

// ══════════════════════════════════════════════════════════════
// 3. The evaluator itself, including a synthetic unfinished entry
// ══════════════════════════════════════════════════════════════

const REG = (over: Partial<import('../src/fit-release-gate.js').RegisteredRoute> = {}) => ({
  method: 'POST', route: '/api/v4/fit/:introId/synthetic',
  canonicalOperations: ['synthetic_op'], behindFitGate: false, ...over,
})
const ENTRY = (over: Partial<import('../src/fit-release-gate.js').GateEntry> = {}) => ({
  method: 'POST', route: '/api/v4/fit/:introId/synthetic', matrix_row: '99', verdict: 'NO' as const,
  disposition: 'canonical' as const, operation: 'synthetic_op', semantic_fields: ['payload.thing'], ...over,
})
const MAN = (gateArr: unknown[], outside: unknown[] = []) => ({ manifest: 'test', gate: gateArr, outside_gate: outside })
const covers = (fields: string[]) => () => fields

test('GATE: a synthetic UNFINISHED entry passes with the flag unset and fails with the flag at "1"', () => {
  // The proof that the gate does what it exists for: an enabled incomplete surface fails.
  // Driven through the same evaluator the live gate uses, not a parallel copy of it.
  const unfinished = {
    manifest: MAN([ENTRY()]),
    registered: [REG({ canonicalOperations: null })],
    boundFields: covers(['payload.thing']),
  }
  const off = gate.evaluateReleaseGate({ ...unfinished, fitEnabled: false })
  assert.equal(off.ok, true, 'unfinished entries are allowed while the flag is unset')
  assert.equal(off.shortfalls.length, 1)
  assert.equal(off.shortfalls[0].kind, 'not_canonical')

  const on = gate.evaluateReleaseGate({ ...unfinished, fitEnabled: true })
  assert.equal(on.ok, false, 'and the same state with the flag at "1" is red')
  assert.deepEqual(on.problems, [], 'as a shortfall rather than as a broken gate')
})

test('GATE: the three ways a canonical entry can fall short', () => {
  const cases: [string, any, any, string[]][] = [
    ['not_canonical', [ENTRY()], [REG({ canonicalOperations: null })], ['payload.thing']],
    ['operation_not_accepted', [ENTRY()], [REG({ canonicalOperations: ['other_op'] })], ['payload.thing']],
    ['semantic_field_unbound', [ENTRY()], [REG()], ['operation', 'resource.id']],
  ]
  for (const [kind, gateArr, reg, covered] of cases) {
    const v = gate.evaluateReleaseGate({ manifest: MAN(gateArr), registered: reg, fitEnabled: true, boundFields: covers(covered) })
    assert.equal(v.ok, false, kind)
    assert.deepEqual(v.problems, [], `${kind} is a shortfall, not a broken gate`)
    assert.equal(v.shortfalls.length, 1)
    assert.equal(v.shortfalls[0].kind, kind)
    assert.equal(v.statuses[0].satisfied, false)
  }
  // And the satisfied case, so the three above are not vacuous.
  const good = gate.evaluateReleaseGate({ manifest: MAN([ENTRY()]), registered: [REG()], fitEnabled: true, boundFields: covers(['payload.thing', 'operation']) })
  assert.equal(good.ok, true)
  assert.equal(good.statuses[0].satisfied, true)
})

test('GATE: being behind fitGate satisfies NOTHING, which is what stops the gate being circular', () => {
  const v = gate.evaluateReleaseGate({
    manifest: MAN([ENTRY()]),
    registered: [REG({ canonicalOperations: null, behindFitGate: true })],
    fitEnabled: true, boundFields: covers(['payload.thing']),
  })
  assert.equal(v.ok, false, 'containment is not repair')
  assert.equal(v.shortfalls[0].kind, 'not_canonical')
  assert.equal(v.statuses[0].behindFitGate, true, 'it is reported, and it is not a condition')
  assert.equal(v.statuses[0].satisfied, false)
})

test('GATE: an unlisted registered mutation route fails under BOTH flag values', () => {
  // The reason the enumeration exists. A thirteenth route added next year lands in neither
  // half of the manifest and holds the flag down without anyone remembering to add it.
  for (const fitEnabled of [false, true]) {
    const v = gate.evaluateReleaseGate({
      manifest: MAN([ENTRY()]),
      registered: [REG(), REG({ route: '/api/v4/fit/:introId/brand-new' })],
      fitEnabled, boundFields: covers(['payload.thing']),
    })
    assert.equal(v.ok, false, `flag ${fitEnabled}: an unlisted mutation route must fail`)
    assert.equal(v.problems.some(p => p.kind === 'unlisted_mutation_route' && p.route.includes('brand-new')), true)
  }
  // A DELETE on a path that is already listed for POST is a different route, not the same one.
  const byMethod = gate.evaluateReleaseGate({
    manifest: MAN([ENTRY()]),
    registered: [REG(), REG({ method: 'DELETE' })],
    fitEnabled: false, boundFields: covers(['payload.thing']),
  })
  assert.equal(byMethod.problems.some(p => p.kind === 'unlisted_mutation_route' && p.route.startsWith('DELETE')), true)
})

test('GATE: a listed route missing from the application fails unless its disposition is removal', () => {
  const canonicalGone = gate.evaluateReleaseGate({
    manifest: MAN([ENTRY()]), registered: [], fitEnabled: false, boundFields: covers(['payload.thing']),
  })
  assert.equal(canonicalGone.ok, false, 'a route required to be canonical that is not registered at all')
  assert.equal(canonicalGone.problems[0].kind, 'manifest_route_missing')

  const removedGone = gate.evaluateReleaseGate({
    manifest: MAN([ENTRY({ disposition: 'removed', operation: undefined, semantic_fields: undefined })]),
    registered: [], fitEnabled: true, boundFields: covers([]),
  })
  assert.equal(removedGone.ok, true, 'and removal is satisfied precisely by being gone')
  assert.equal(removedGone.statuses[0].satisfied, true)

  const removedStillThere = gate.evaluateReleaseGate({
    manifest: MAN([ENTRY({ disposition: 'removed', operation: undefined, semantic_fields: undefined })]),
    registered: [REG({ canonicalOperations: null })], fitEnabled: true, boundFields: covers([]),
  })
  assert.equal(removedStillThere.ok, false)
  assert.equal(removedStillThere.shortfalls[0].kind, 'not_removed')

  // An outside_gate route that has vanished is a stale manifest, which is fatal too.
  const staleOutside = gate.evaluateReleaseGate({
    manifest: MAN([ENTRY()], [{ method: 'POST', route: '/api/v4/fit/gone', matrix_row: '1', verdict: 'YES', reason: 'because' }]),
    registered: [REG()], fitEnabled: false, boundFields: covers(['payload.thing']),
  })
  assert.equal(staleOutside.ok, false)
  assert.equal(staleOutside.problems[0].kind, 'manifest_route_missing')
})

test('GATE: it fails LOUDLY on a manifest it cannot parse or that enumerates zero rows', () => {
  // A gate that silently matches nothing is worse than no gate, so each of these is fatal
  // under both flag values rather than an allowed unfinished state.
  for (const fitEnabled of [false, true]) {
    for (const bad of [null, undefined, 42, 'a string', {}, { gate: [] }, { gate: 'no', outside_gate: [] }, { gate: [], outside_gate: [] }]) {
      const v = gate.evaluateReleaseGate({ manifest: bad, registered: [], fitEnabled, boundFields: covers([]) })
      assert.equal(v.ok, false, `${JSON.stringify(bad)} must not pass`)
      assert.ok(['manifest_unparseable', 'manifest_empty'].includes(v.problems[0].kind), JSON.stringify(v.problems))
    }
  }
})

test('GATE: a malformed or duplicated entry is fatal, so the manifest cannot rot quietly', () => {
  const badEntries: [string, any][] = [
    ['no matrix row', ENTRY({ matrix_row: '' })],
    ['a verdict the matrix never gives', ENTRY({ verdict: 'YES' as any })],
    ['a disposition that is neither', ENTRY({ disposition: 'contained' as any })],
    ['canonical with no operation', ENTRY({ operation: undefined })],
    ['canonical with no semantic fields', ENTRY({ semantic_fields: [] })],
    ['a relative route', ENTRY({ route: 'api/v4/fit/x' })],
  ]
  for (const [why, entry] of badEntries) {
    const v = gate.evaluateReleaseGate({ manifest: MAN([entry]), registered: [], fitEnabled: false, boundFields: covers(['payload.thing']) })
    assert.equal(v.ok, false, why)
    assert.equal(v.problems.some(p => p.kind === 'manifest_entry_malformed'), true, why)
  }
  const dup = gate.evaluateReleaseGate({ manifest: MAN([ENTRY(), ENTRY()]), registered: [REG()], fitEnabled: false, boundFields: covers(['payload.thing']) })
  assert.equal(dup.problems.some(p => p.kind === 'manifest_duplicate'), true)
  const both = gate.evaluateReleaseGate({
    manifest: MAN([ENTRY()], [{ method: 'POST', route: ENTRY().route, matrix_row: '1', verdict: 'YES', reason: 'because' }]),
    registered: [REG()], fitEnabled: false, boundFields: covers(['payload.thing']),
  })
  assert.equal(both.problems.some(p => p.kind === 'manifest_duplicate'), true,
    'a route cannot be both inside and outside the gate')
})

// ══════════════════════════════════════════════════════════════
// 3b. The canonical lane is REACHABLE, not merely present
// ══════════════════════════════════════════════════════════════

test('GATE: every canonical route actually answers from the canonical pipeline', async () => {
  // The enumeration can only see that SOME layer in a route's chain carries the canonical
  // tag. It cannot see control flow, so a chain like (legacyHandler, canonicalDispatch(...))
  // would report canonical while the legacy handler answered every request. This closes that
  // gap behaviourally: a body carrying an `envelope` key must come back with a refusal only
  // the canonical pipeline produces.
  //
  // The flag is set locally and restored, because these routes sit behind fitGate and the
  // point is to reach the handler behind it.
  const before = process.env.MINGLE_FIT_ENABLED
  process.env.MINGLE_FIT_ENABLED = '1'
  try {
    // Codes only verifyWriteBody and canonicalDispatch produce. No legacy fit branch answers
    // any of them, and none of them is a fitGate or an anti-downgrade refusal.
    const CANONICAL_CODES = ['path_resource_mismatch', 'missing_signature', 'malformed_body', 'unknown_envelope_domain']
    const canonicalEntries = manifest.gate.filter((e: any) => e.disposition === 'canonical')
    assert.equal(canonicalEntries.length, 11)
    for (const e of canonicalEntries) {
      const path = e.route.replace(':introId', 'intro-nosuch').replace(':id', 'fit-nosuch')
      const res = await fetch(base + path, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ envelope: {} }),
      })
      const body: any = await res.json()
      assert.equal(typeof body.code, 'string', `${path} answered without a code: ${JSON.stringify(body)}`)
      assert.ok(CANONICAL_CODES.includes(body.code),
        `${path} answered ${body.code}, which the canonical pipeline does not produce, so the canonical lane may not be reachable`)
    }
    // And the control: the SAME routes with a body carrying no envelope key reach their legacy
    // branch instead, which answers something else. Otherwise the assertion above would pass
    // for a route that refused everything.
    const legacy = await fetch(`${base}/api/v3/fit/fit-nosuch/round2`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
    })
    const legacyBody: any = await legacy.json()
    assert.equal(CANONICAL_CODES.includes(legacyBody.code), false,
      `a body with no envelope key reached the canonical pipeline: ${JSON.stringify(legacyBody)}`)
  } finally {
    if (before === undefined) delete process.env.MINGLE_FIT_ENABLED
    else process.env.MINGLE_FIT_ENABLED = before
  }
})

// ══════════════════════════════════════════════════════════════
// 4. The manifest against the matrix it was built from
// ══════════════════════════════════════════════════════════════

test('GATE: the twelve rows in the gate are EXACTLY these twelve', () => {
  // Written out as literals, deliberately duplicating the manifest, exactly as the golden
  // copy test duplicates the approved sentences. Counting twelve entries is not enough: a row
  // can be retired from the gate by moving it into outside_gate with a plausible reason and
  // moving an already-canonical YES row in, and every other check still passes. This is the
  // check that makes that a visible diff in a test rather than a quiet edit to one file.
  const expected = [
    ['POST', '/api/v3/fit/:id/answers', '39', 'PARTIAL', 'canonical'],
    ['POST', '/api/v3/fit/:id/round2', '40', 'NO', 'canonical'],
    ['POST', '/api/v3/fit/:id/custom', '41', 'NO', 'canonical'],
    ['POST', '/api/v3/fit/:id/close', '42', 'PARTIAL', 'canonical'],
    ['POST', '/api/v3/fit/sweep', '43', 'PARTIAL', 'removed'],
    ['POST', '/api/v4/fit/:introId/request', '28', 'NO', 'canonical'],
    ['POST', '/api/v4/fit/:introId/commit', '29', 'NO', 'canonical'],
    ['POST', '/api/v4/fit/:introId/reveal', '30', 'PARTIAL', 'canonical'],
    ['POST', '/api/v4/fit/autonomy/pause', '32', 'PARTIAL', 'canonical'],
    ['POST', '/api/v4/fit/:introId/answers', '34', 'PARTIAL', 'canonical'],
    ['POST', '/api/v4/fit/:introId/round2', '35', 'NO', 'canonical'],
    ['POST', '/api/v4/fit/:introId/first-step', '36', 'NO', 'canonical'],
  ]
  const actual = manifest.gate.map((e: any) => [e.method, e.route, e.matrix_row, e.verdict, e.disposition])
  assert.deepEqual([...actual].sort(), [...expected].sort(),
    'the gate covers a different set of matrix rows than the twelve the matrix classified PARTIAL or NO')
  // And no outside_gate entry claims a verdict the gate covers, which is the evaluator's
  // half of the same rule.
  for (const e of manifest.outside_gate) {
    assert.equal(['NO', 'PARTIAL'].includes(e.verdict), false, `${e.route} claims ${e.verdict} and sits outside the gate`)
  }
})

test('GATE: every gate entry carries a matrix row, a verdict and a named gap', () => {
  // The manifest is the checked-in projection of a document this repository cannot read,
  // so each entry has to carry enough to be checked against it by hand.
  assert.equal(manifest.gate.length, 12, 'the matrix classified twelve structured fit mutation rows as PARTIAL or NO')
  const ranks = new Set<number>()
  for (const e of manifest.gate) {
    assert.match(e.matrix_row, /^\d+$/, `${e.route} must name its matrix row`)
    assert.ok(['NO', 'PARTIAL'].includes(e.verdict))
    assert.ok(typeof e.gap === 'string' && e.gap.length > 20, `${e.route} must say what the gap was`)
    assert.equal(typeof e.matrix_rank, 'number')
    assert.equal(ranks.has(e.matrix_rank), false, `Summary (a) rank ${e.matrix_rank} is used twice`)
    ranks.add(e.matrix_rank)
  }
  assert.equal(manifest.gate.filter((e: any) => e.disposition === 'removed').length, 1,
    'exactly one row cannot be canonicalized at all, which is the sweep')
  for (const e of manifest.outside_gate) {
    assert.ok(typeof e.reason === 'string' && e.reason.length > 20, `${e.route} must say why it is outside`)
  }
})
