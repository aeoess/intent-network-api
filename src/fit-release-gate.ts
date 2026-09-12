// ══════════════════════════════════════════════════════════════
// The structured fit release gate, executable
// ══════════════════════════════════════════════════════════════
// MINGLE_FIT_ENABLED stays unset until a TEST proves the surface is repaired, not
// until someone reads a list and agrees. This module is that test's machinery, in
// two halves that are deliberately separate:
//
//   enumerateFitMutationRoutes(app)   what the application ACTUALLY registers
//   evaluateReleaseGate({...})        a pure verdict over that plus the manifest
//
// THE MANIFEST IS CHECKED IN. The signed-write matrix is the normative source for
// building it, and it lives outside this repository, so no test here may read it: a
// suite that depends on a file in a private directory is a suite that fails on any
// other machine. The manifest is the checked-in projection of those rows, each entry
// naming its matrix row, its original verdict and the disposition it must reach.
//
// THE ENUMERATION IS INDEPENDENT OF THE MANIFEST, and that is the whole mechanism.
// A hard coded list of twelve routes is a list someone forgets to extend. This walks
// the live Express router stack, so a thirteenth mutation route added to either fit
// router next year appears here with nobody remembering to add it, lands in neither
// half of the manifest, and fails the gate. Exact set agreement in both directions:
// an unlisted registered route fails, and a listed route that has vanished fails
// unless its required disposition was removal.
//
// WHAT SATISFIES AN ENTRY. Exactly two dispositions:
//
//   canonical  the route is registered, its handler chain accepts a mingle-write-v1
//              envelope for the named operation, and that operation's bound field
//              list covers every semantic field the manifest names
//   removed    the declaration is gone from the router
//
// BEING BEHIND fitGate SATISFIES NOTHING. If it did the gate would be circular:
// every route would count as unreachable while the flag is off, which is exactly the
// state the gate exists to decide whether to leave. `behindFitGate` is reported for
// the handoff and is never a condition.
//
// HARD PROBLEMS AGAINST SHORTFALLS. A gate that silently matches nothing is worse
// than no gate, so an unparseable manifest, an empty one, a malformed entry, an
// unlisted registered route and a listed route that has disappeared are HARD: they
// fail whatever the flag says, because each one means the gate has stopped measuring
// rather than that the work is unfinished. A route that is simply not canonical yet
// is a SHORTFALL: allowed while the flag is unset, fatal the moment it is "1".
//
// Pure. No filesystem, no environment read, no Express import. The caller supplies
// the app, the manifest, the flag and the bound field lookup, which is what lets a
// unit test drive a synthetic unfinished entry through the same evaluator the live
// gate uses.

import { readFileSync } from 'node:fs'

export type Verdict = 'NO' | 'PARTIAL'
export type Disposition = 'canonical' | 'removed'

export interface GateEntry {
  method: string
  route: string
  /** Which row of the signed-write matrix this is, so a reader can go and check. */
  matrix_row: string
  /** Its rank in Summary (a), which is how the matrix orders the same rows. */
  matrix_rank?: number
  verdict: Verdict
  disposition: Disposition
  /** The mingle-write-v1 operation the repaired route accepts. Required for
   *  `canonical`, meaningless for `removed`. */
  operation?: string
  /** The semantic fields that operation's signature must cover. Duplicated from
   *  CANONICAL_BOUND on purpose: the duplication IS the check, exactly as the golden
   *  copy test duplicates the approved sentences. */
  semantic_fields?: string[]
}

export interface OutsideEntry {
  method: string
  route: string
  /** A matrix row, or the string that says it postdates the matrix. */
  matrix_row: string
  verdict: string
  reason: string
}

export interface ReleaseManifest {
  manifest: string
  gate: GateEntry[]
  outside_gate: OutsideEntry[]
}

export interface RegisteredRoute {
  /** Upper case, so 'POST' and 'post' cannot be two routes. */
  method: string
  /** The full path including the mount prefix, as Express has it. */
  route: string
  /** The operations this route's chain accepts under mingle-write-v1, or null. */
  canonicalOperations: readonly string[] | null
  /** Reported, never a condition. See the header. */
  behindFitGate: boolean
}

export type ProblemKind =
  | 'manifest_unparseable'
  | 'manifest_empty'
  | 'manifest_entry_malformed'
  | 'manifest_duplicate'
  | 'unlisted_mutation_route'
  | 'manifest_route_missing'
  | 'unknown_operation'
  | 'semantic_fields_drift'
  | 'operation_set_wider'
  | 'duplicate_registration'
  | 'outside_gate_not_yes'

export type ShortfallKind =
  | 'not_canonical'
  | 'operation_not_accepted'
  | 'semantic_field_unbound'
  | 'not_removed'

export interface GateFinding {
  kind: ProblemKind | ShortfallKind
  route: string
  detail: string
}

export interface RouteStatus {
  method: string
  route: string
  matrix_row: string
  verdict: Verdict
  disposition: Disposition
  registered: boolean
  behindFitGate: boolean
  operations: readonly string[] | null
  satisfied: boolean
}

export interface GateVerdict {
  ok: boolean
  /** Failures that mean the gate has stopped measuring. Fatal whatever the flag says. */
  problems: GateFinding[]
  /** Unfinished work. Allowed while the flag is unset, fatal when it is "1". */
  shortfalls: GateFinding[]
  /** One row per gate entry, for the handoff and for a human reading a failure. */
  statuses: RouteStatus[]
  fitEnabled: boolean
}

function key(method: string, route: string): string {
  return `${method.toUpperCase()} ${route}`
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(x => typeof x === 'string' && x.length > 0)
}

/** The verdict. Pure over its four inputs. */
export function evaluateReleaseGate(args: {
  manifest: unknown
  registered: readonly RegisteredRoute[]
  fitEnabled: boolean
  /** What a canonical signature for this operation covers, or null when there is no
   *  such operation. Injected rather than imported so a unit test can drive a synthetic
   *  operation through this evaluator rather than through a parallel copy of it.
   *
   *  Null matters: an operation the protocol does not have is a manifest that names
   *  something that does not exist, which is the gate having stopped measuring rather
   *  than work being unfinished, so it is a hard problem. */
  boundFields: (operation: string) => readonly string[] | null
}): GateVerdict {
  const problems: GateFinding[] = []
  const shortfalls: GateFinding[] = []
  const statuses: RouteStatus[] = []
  const empty: GateVerdict = { ok: false, problems, shortfalls, statuses, fitEnabled: args.fitEnabled }

  const m = args.manifest as ReleaseManifest | null
  if (m === null || typeof m !== 'object' || !Array.isArray(m.gate) || !Array.isArray(m.outside_gate)) {
    problems.push({ kind: 'manifest_unparseable', route: '(manifest)', detail: 'the manifest must be an object carrying a gate array and an outside_gate array' })
    return empty
  }
  if (m.gate.length === 0) {
    problems.push({ kind: 'manifest_empty', route: '(manifest)', detail: 'the gate enumerates zero routes, which would pass vacuously' })
    return empty
  }

  // ── Every entry well formed, and no route listed twice anywhere ──
  const seen = new Set<string>()
  for (const e of m.gate) {
    const at = e && typeof e === 'object' ? key(String(e.method), String(e.route)) : '(unnamed entry)'
    const bad = (detail: string) => problems.push({ kind: 'manifest_entry_malformed', route: at, detail })
    if (!e || typeof e !== 'object') { bad('entry is not an object'); continue }
    if (typeof e.method !== 'string' || e.method.length === 0) bad('method is required')
    if (typeof e.route !== 'string' || !e.route.startsWith('/')) bad('route must be an absolute path')
    if (typeof e.matrix_row !== 'string' || e.matrix_row.length === 0) bad('matrix_row is required, so a reader can check the classification')
    if (e.verdict !== 'NO' && e.verdict !== 'PARTIAL') bad('verdict must be the matrix verdict, NO or PARTIAL')
    if (e.disposition !== 'canonical' && e.disposition !== 'removed') bad('disposition must be canonical or removed')
    if (e.disposition === 'canonical') {
      if (typeof e.operation !== 'string' || e.operation.length === 0) bad('a canonical disposition must name its operation')
      if (!isStringArray(e.semantic_fields) || e.semantic_fields.length === 0) {
        bad('a canonical disposition must name the semantic fields its signature has to cover')
      }
    }
    if (seen.has(at)) problems.push({ kind: 'manifest_duplicate', route: at, detail: 'listed more than once, so its required disposition is ambiguous' })
    seen.add(at)
  }
  for (const e of m.outside_gate) {
    const at = e && typeof e === 'object' ? key(String(e.method), String(e.route)) : '(unnamed entry)'
    if (!e || typeof e !== 'object' || typeof e.method !== 'string' || typeof e.route !== 'string' || !e.route.startsWith('/')) {
      problems.push({ kind: 'manifest_entry_malformed', route: at, detail: 'an outside_gate entry needs a method and an absolute route' })
      continue
    }
    if (typeof e.reason !== 'string' || e.reason.length === 0) {
      problems.push({ kind: 'manifest_entry_malformed', route: at, detail: 'an outside_gate entry must say why it is outside the gate' })
    }
    if (typeof e.verdict !== 'string' || e.verdict.length === 0) {
      problems.push({ kind: 'manifest_entry_malformed', route: at, detail: 'an outside_gate entry must carry the verdict that puts it outside' })
    }
    // THE ROW CANNOT BE MOVED OUT OF THE GATE. Without this, a PARTIAL or NO row could be
    // retired from the gate by editing one array into the other and writing a plausible
    // reason, and the count would still be twelve. The gate covers exactly the rows the
    // matrix classified PARTIAL or NO, so a row that claims to be outside must claim a
    // verdict that is neither.
    if (e.verdict === 'NO' || e.verdict === 'PARTIAL') {
      problems.push({ kind: 'outside_gate_not_yes', route: at,
        detail: `claims verdict ${e.verdict}, which is exactly what the gate covers, so it cannot sit outside it` })
    }
    if (seen.has(at)) problems.push({ kind: 'manifest_duplicate', route: at, detail: 'listed in both halves of the manifest' })
    seen.add(at)
  }
  if (problems.length > 0) return empty

  // ── Exact set agreement, in both directions ──
  //
  // A Map would collapse two declarations of the same method and path and keep the LAST,
  // while Express runs the FIRST. So the duplicate is refused before any map is built,
  // rather than silently resolved in the optimistic direction.
  const byKey = new Map<string, RegisteredRoute>()
  for (const r of args.registered) {
    const at = key(r.method, r.route)
    if (byKey.has(at)) {
      problems.push({ kind: 'duplicate_registration', route: at,
        detail: 'registered more than once, and Express runs the FIRST while a lookup would keep the last, so the gate cannot say which chain answers' })
      continue
    }
    byKey.set(at, r)
  }
  if (problems.length > 0) return empty
  for (const [at] of byKey) {
    if (!seen.has(at)) {
      problems.push({ kind: 'unlisted_mutation_route', route: at,
        detail: 'a structured fit mutation route the application registers that the manifest does not list. Classify it and give it a disposition.' })
    }
  }
  for (const e of m.outside_gate) {
    if (!byKey.has(key(e.method, e.route))) {
      problems.push({ kind: 'manifest_route_missing', route: key(e.method, e.route),
        detail: 'listed as outside the gate but the application does not register it, so the manifest is stale' })
    }
  }

  // ── Each gate entry against reality ──
  for (const e of m.gate) {
    const at = key(e.method, e.route)
    const live = byKey.get(at) ?? null
    let satisfied = false
    if (e.disposition === 'removed') {
      satisfied = live === null
      if (!satisfied) {
        shortfalls.push({ kind: 'not_removed', route: at, detail: 'required disposition is removal and the declaration is still registered' })
      }
    } else if (live === null) {
      problems.push({ kind: 'manifest_route_missing', route: at,
        detail: 'required disposition is canonical and the application does not register it at all' })
    } else if (args.boundFields(e.operation as string) === null) {
      problems.push({ kind: 'unknown_operation', route: at,
        detail: `the manifest names operation ${e.operation}, which the protocol does not have` })
    } else if (live.canonicalOperations === null) {
      shortfalls.push({ kind: 'not_canonical', route: at, detail: 'the handler chain accepts no mingle-write-v1 envelope' })
    } else if (!live.canonicalOperations.includes(e.operation as string)) {
      shortfalls.push({ kind: 'operation_not_accepted', route: at,
        detail: `accepts ${live.canonicalOperations.join(', ') || 'nothing'} rather than the required ${e.operation}` })
    } else if (live.canonicalOperations.length !== 1) {
      // A SUPERSET IS NOT A MATCH. A route that also accepts a second operation accepts one
      // the manifest never named and whose semantic fields were therefore never checked,
      // which is the gate having stopped measuring rather than unfinished work.
      problems.push({ kind: 'operation_set_wider', route: at,
        detail: `accepts ${live.canonicalOperations.join(', ')} while the manifest names only ${e.operation}, so the others are unaudited` })
    } else {
      // EQUALITY, NOT A SUBSET. The manifest's semantic_fields must be exactly the payload
      // part of that operation's bound list. A subset check would let someone weaken the
      // manifest and keep the gate green, and the whole point of duplicating the list here
      // is that the duplication IS the check.
      const covered = args.boundFields(e.operation as string) as readonly string[]
      const payloadPart = covered.filter(f => f.startsWith('payload.'))
      const declared = [...(e.semantic_fields ?? [])]
      const same = payloadPart.length === declared.length
        && [...payloadPart].sort().every((f, i) => f === [...declared].sort()[i])
      const missing = declared.filter(f => !covered.includes(f))
      if (missing.length > 0) {
        shortfalls.push({ kind: 'semantic_field_unbound', route: at,
          detail: `${e.operation} does not bind ${missing.join(', ')}` })
      } else if (!same) {
        problems.push({ kind: 'semantic_fields_drift', route: at,
          detail: `the manifest names [${declared.join(', ')}] and ${e.operation} binds [${payloadPart.join(', ')}], so one of the two has drifted` })
      } else {
        satisfied = true
      }
    }
    statuses.push({
      method: e.method.toUpperCase(), route: e.route, matrix_row: e.matrix_row,
      verdict: e.verdict, disposition: e.disposition,
      registered: live !== null, behindFitGate: live?.behindFitGate ?? false,
      operations: live?.canonicalOperations ?? null, satisfied,
    })
  }

  const ok = problems.length === 0 && (!args.fitEnabled || shortfalls.length === 0)
  return { ok, problems, shortfalls, statuses, fitEnabled: args.fitEnabled }
}

// ── Enumerating what the application registers ────────────────────────────

/** The two mounts that carry the structured fit surface. Both must be found or the
 *  enumeration throws, because an enumeration that quietly finds one is a gate that
 *  passes half the surface without saying so.
 *
 *  Matched as a case insensitive PREFIX rather than by equality. Express routes case
 *  insensitively, so `/API/v3/FIT` serves the same requests as `/api/v3/fit`, and a mount
 *  one level deeper such as `/api/v3/fit/exchange` is still the fit surface. Both forms
 *  were silently skipped by an equality test. */
export const FIT_MOUNTS = ['/api/v3/fit', '/api/v4/fit'] as const

function isFitPath(path: string): boolean {
  const lower = path.toLowerCase()
  return FIT_MOUNTS.some(m => lower === m || lower.startsWith(m + '/'))
}

/** A mutation is anything that is not a read. GET is the only read method on these
 *  routers, and stating it this way rather than listing POST means a PUT or a DELETE
 *  added later is enumerated rather than skipped. */
const READ_METHODS = new Set(['get', 'head', 'options'])

const MOUNT_SUFFIX = '\\/?(?=\\/|$)'

/** Decode the path an Express 4 mount layer was registered under.
 *
 *  Express keeps no plain copy of it: `layer.path` is set during matching only, so the
 *  regexp source is the only durable record. Returns null rather than guessing, and the
 *  caller turns null into a loud failure. */
export function mountPrefixOf(layer: unknown): string | null {
  const re = (layer as { regexp?: { source?: string; fast_slash?: boolean } } | null)?.regexp
  if (!re || typeof re.source !== 'string') return null
  if (re.fast_slash === true) return ''
  let src = re.source
  if (!src.startsWith('^')) return null
  src = src.slice(1)
  if (!src.endsWith(MOUNT_SUFFIX)) return null
  src = src.slice(0, -MOUNT_SUFFIX.length)
  const path = src.replace(/\\\//g, '/')
  return /^(\/[A-Za-z0-9_.~-]+)+$/.test(path) ? path : null
}

/** Is this stack layer a mounted router rather than a route or a plain middleware? */
function routerOf(layer: unknown): unknown[] | null {
  const inner = (layer as { handle?: { stack?: unknown[] } } | null)?.handle?.stack
  return Array.isArray(inner) ? inner : null
}

/** Every structured fit mutation route the app actually registers.
 *
 *  Independent of MINGLE_FIT_ENABLED by construction: fitGate is per-route middleware,
 *  so both fit routers are mounted whatever the flag says, and this reads the same
 *  stack either way. A test asserts the two enumerations are identical.
 *
 *  WHAT IT PROVES AND WHAT IT DOES NOT. It proves that a route is registered, and that
 *  SOME layer in its chain carries the canonical tag. It does NOT prove that the tagged
 *  layer runs before a layer that could answer first, because an Express chain's control
 *  flow is not readable from the stack. That gap is closed by a behavioural test beside
 *  this one, which sends an envelope shaped body to every canonical route and requires a
 *  canonical pipeline refusal code, so the lane is proved reachable rather than present. */
export function enumerateFitMutationRoutes(app: unknown, opts: {
  canonicalOperationsOf: (handle: unknown) => readonly string[] | null
  fitGate: unknown
}): RegisteredRoute[] {
  const stack = (app as { _router?: { stack?: unknown[] } })?._router?.stack
  if (!Array.isArray(stack)) {
    throw new Error('release gate: the app exposes no router stack, so nothing can be enumerated')
  }
  const found: RegisteredRoute[] = []
  const mountsSeen = new Set<string>()

  /** Walk one router's stack, composing the prefix. Recursive, because a sub-router
   *  mounted inside a fit router carries routes that are just as reachable and were
   *  invisible to a single level walk. */
  const walk = (layers: unknown[], prefix: string, inFit: boolean, depth: number): void => {
    if (depth > 8) throw new Error('release gate: router nesting deeper than 8, which this walk refuses rather than truncates')
    for (const layer of layers as any[]) {
      const inner = routerOf(layer)
      if (inner !== null) {
        const own = mountPrefixOf(layer)
        if (own === null) {
          // Inside the fit surface an undecodable mount is fatal, because it could carry
          // anything. Outside it, a mount this gate does not care about is skipped.
          if (inFit) throw new Error(`release gate: a router mounted inside the fit surface could not be decoded from ${String(layer?.regexp)}`)
          const guess = mountPrefixOf(layer)
          if (guess === null) continue
        }
        const full = prefix + (own ?? '')
        const fit = inFit || isFitPath(full)
        if (fit) {
          for (const m of FIT_MOUNTS) if (full.toLowerCase().startsWith(m)) mountsSeen.add(m)
        }
        walk(inner, full, fit, depth + 1)
        continue
      }
      const route = layer?.route
      if (!route) continue
      if (!inFit) continue
      // route.path is a string for the ordinary form and an ARRAY when one declaration
      // registers several paths. Both are reachable, so both are enumerated.
      const paths: unknown[] = Array.isArray(route.path) ? route.path : [route.path]
      const chain: any[] = Array.isArray(route.stack) ? route.stack : []
      let operations: readonly string[] | null = null
      let behindFitGate = false
      for (const step of chain) {
        const ops = opts.canonicalOperationsOf(step?.handle)
        if (ops !== null && ops.length > 0) operations = ops
        if (step?.handle === opts.fitGate) behindFitGate = true
      }
      for (const p of paths) {
        if (typeof p !== 'string') {
          throw new Error(`release gate: a route inside the fit surface has a path this walk cannot read: ${String(p)}`)
        }
        for (const method of Object.keys(route.methods ?? {})) {
          if (READ_METHODS.has(method.toLowerCase())) continue
          // `router.all` records the pseudo method `_all`, which is enumerated as `_ALL` so
          // it fails as unlisted rather than passing unseen. A fit mutation registered that
          // way has to be classified like any other.
          found.push({
            method: method.toUpperCase(),
            route: prefix + (mountPrefixOf(layer) ?? '') + p,
            canonicalOperations: operations,
            behindFitGate,
          })
        }
      }
    }
  }
  walk(stack, '', false, 0)

  for (const mount of FIT_MOUNTS) {
    if (!mountsSeen.has(mount)) {
      throw new Error(`release gate: ${mount} is not mounted, so the enumeration would cover only part of the fit surface`)
    }
  }
  return found
}

/** Load the checked-in manifest. Only the boot gate and the tests call this: the
 *  evaluator itself takes the manifest as an argument and touches no filesystem. */
export function loadReleaseManifest(): unknown {
  const url = new URL('../fixtures/mingle-fit-release-gate.json', import.meta.url)
  return JSON.parse(readFileSync(url, 'utf8'))
}

/** A one line status per gate entry, for a handoff or a failure message. */
export function formatGateReport(v: GateVerdict): string {
  const lines = v.statuses.map(s => {
    const mark = s.satisfied ? 'OK  ' : 'TODO'
    const how = s.disposition === 'removed'
      ? (s.registered ? 'still registered' : 'removed')
      : (s.operations === null ? 'no envelope' : `canonical as ${s.operations.join(', ')}`)
    return `${mark} ${s.method} ${s.route} [matrix ${s.matrix_row}, ${s.verdict}] wants ${s.disposition}, is ${how}${s.behindFitGate ? ', behind fitGate' : ''}`
  })
  const head = `release gate: ${v.ok ? 'GREEN' : 'RED'} with MINGLE_FIT_ENABLED ${v.fitEnabled ? '"1"' : 'unset'}, `
    + `${v.statuses.filter(s => s.satisfied).length}/${v.statuses.length} satisfied, `
    + `${v.problems.length} problem(s), ${v.shortfalls.length} shortfall(s)`
  const detail = [...v.problems, ...v.shortfalls].map(f => `     ${f.kind}: ${f.route}, ${f.detail}`)
  return [head, ...lines, ...detail].join('\n')
}
