// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - dimension schema + predicate grammar (PUBLIC protocol)
// ══════════════════════════════════════════════════════════════
// Public/private boundary: the dimension SCHEMA and the predicate GRAMMAR here
// are protocol (public). A person's dimension VALUES and their Fit Policy are
// private and live only in signed, owner-controlled storage. Predicates are
// CANONICAL: fixed buckets and fixed overlap rules, never a threshold chosen by
// the requester. That is what makes the handshake anti-narrowing.

export const DIMENSION_SCHEMA_VERSION = 1
export const PREDICATE_VERSION = 1

export const DISCLOSURE_STATES = ['local_only', 'testable', 'reveal_overlap', 'reveal_bucket', 'reveal_exact'] as const
export type DisclosureState = typeof DISCLOSURE_STATES[number]
// Numeric order for the strict reveal ordering (overlap < bucket < exact).
export const DISCLOSURE_RANK: Record<DisclosureState, number> = {
  local_only: 1, testable: 2, reveal_overlap: 3, reveal_bucket: 4, reveal_exact: 5,
}

export const SENSITIVITIES = ['low', 'moderate', 'high'] as const
export type Sensitivity = typeof SENSITIVITIES[number]

export const IMPORTANCES = ['essential', 'useful', 'optional', 'do_not_ask'] as const
export type Importance = typeof IMPORTANCES[number]

// Banked intents that may carry a fit policy. WORK IS EXCLUDED, always.
export const POLICY_INTENTS = ['cofound', 'team_up', 'collaborate', 'meet', 'advise'] as const
export type PolicyIntent = typeof POLICY_INTENTS[number]

// A small, fixed role-tag taxonomy (public) for role_spike / role_antiportfolio.
export const ROLE_TAGS = [
  'frontend', 'backend', 'infra', 'ml', 'data', 'mobile', 'design', 'product',
  'research', 'security', 'sales', 'marketing', 'ops', 'fundraising', 'legal', 'bizdev',
] as const

type Kind = 'hours_range' | 'enum' | 'timezone' | 'tag_set'

interface DimensionDef {
  kind: Kind
  values?: readonly string[]     // for enum
  sensitivity: Sensitivity       // default sensitivity (a policy may raise it)
}

// The canonical dimension set (schema v1).
export const DIMENSIONS: Record<string, DimensionDef> = {
  weekly_commitment: { kind: 'hours_range', sensitivity: 'moderate' },
  start_window: { kind: 'enum', values: ['now', 'within_month', 'within_quarter', 'flexible'], sensitivity: 'low' },
  time_horizon: { kind: 'enum', values: ['weeks', 'months', 'long_term'], sensitivity: 'low' },
  timezone: { kind: 'timezone', sensitivity: 'low' },
  cadence: { kind: 'enum', values: ['async_first', 'mixed', 'daily_sync'], sensitivity: 'low' },
  project_stage: { kind: 'enum', values: ['exploring', 'validating', 'building', 'scaling'], sensitivity: 'low' },
  relationship_shape: { kind: 'enum', values: ['brainstorm', 'recurring_collab', 'co_owner', 'short_project', 'mentor', 'peer', 'accountability'], sensitivity: 'low' },
  role_spike: { kind: 'tag_set', sensitivity: 'low' },
  role_antiportfolio: { kind: 'tag_set', sensitivity: 'moderate' },
  decision_model: { kind: 'enum', values: ['separated_ownership', 'consensus', 'single_dm', 'context_dependent'], sensitivity: 'moderate' },
}
export const DIMENSION_NAMES = Object.keys(DIMENSIONS)

// ── Value validation (types only; no free text) ───────────────────────────

export function validateDimensionValue(dimension: string, value: unknown): string | null {
  const def = DIMENSIONS[dimension]
  if (!def) return `unknown dimension "${dimension}"`
  switch (def.kind) {
    case 'hours_range': {
      const v = value as any
      if (!v || typeof v.min !== 'number' || typeof v.max !== 'number') return `${dimension} needs {min, max} hours`
      if (v.min < 0 || v.max > 168 || v.min > v.max) return `${dimension} range out of bounds`
      return null
    }
    case 'enum':
      return typeof value === 'string' && def.values!.includes(value) ? null : `${dimension} must be one of ${def.values!.join(', ')}`
    case 'timezone': {
      const v = value as any
      if (!v || typeof v.zone !== 'string' || v.zone.length === 0 || v.zone.length > 40) return `${dimension} needs a zone string`
      if (v.sync_overlap_needed !== undefined && typeof v.sync_overlap_needed !== 'boolean' && !(v.sync_overlap_needed && typeof v.sync_overlap_needed.min === 'number')) {
        return `${dimension}.sync_overlap_needed must be a bool or {min,max}`
      }
      return null
    }
    case 'tag_set': {
      if (!Array.isArray(value) || value.length === 0 || value.length > 8) return `${dimension} must be 1..8 tags`
      for (const t of value) if (!(ROLE_TAGS as readonly string[]).includes(t)) return `${dimension} tag "${t}" is not in the taxonomy`
      return null
    }
  }
}

// ── Canonical predicates + buckets (the public grammar) ───────────────────
// Each returns a small, coarse fact. Overlap functions return a boolean or the
// string 'needs_discussion'. Bucket functions return a coarse label, never the
// exact value.

const HOUR_BUCKETS: [number, number, string][] = [[0, 9, '<10'], [10, 20, '10-20'], [21, 40, '21-40'], [41, 168, '40+']]
function hoursBucket(h: number): string { return (HOUR_BUCKETS.find(([lo, hi]) => h >= lo && h <= hi) ?? [0, 0, '?'])[2] }

const STAGE_ORDER = ['exploring', 'validating', 'building', 'scaling']

/** Overlap fact for a dimension given both sides' values. Canonical, fixed. */
export function overlapFact(dimension: string, a: any, b: any): boolean | 'needs_discussion' {
  switch (dimension) {
    case 'weekly_commitment':
      return a.max >= b.min && b.max >= a.min          // ranges intersect
    case 'start_window': {
      const flex = (x: string) => x === 'flexible'
      return a === b || flex(a) || flex(b)
    }
    case 'time_horizon':
      return a === b ? true : 'needs_discussion'
    case 'timezone': {
      // Compatible when neither requires sync, or the zones are equal.
      const needSync = (x: any) => x.sync_overlap_needed === true || (x.sync_overlap_needed && typeof x.sync_overlap_needed === 'object')
      if (!needSync(a) && !needSync(b)) return true
      return a.zone === b.zone ? true : 'needs_discussion'
    }
    case 'cadence':
      return a === b ? true : (a === 'mixed' || b === 'mixed')
    case 'project_stage': {
      const d = Math.abs(STAGE_ORDER.indexOf(a) - STAGE_ORDER.indexOf(b))
      return d <= 1
    }
    case 'relationship_shape':
      return a === b ? true : 'needs_discussion'
    case 'decision_model':
      return a === b ? true : (a === 'context_dependent' || b === 'context_dependent' ? true : 'needs_discussion')
    case 'role_spike':
      return arraysIntersect(a, b)
    case 'role_antiportfolio':
      return arraysIntersect(a, b)
    default:
      return 'needs_discussion'
  }
}

/** Coarse bucket for a dimension value (state 4). Never the exact value. */
export function bucketFact(dimension: string, value: any): string {
  const def = DIMENSIONS[dimension]
  if (!def) return '?'
  switch (def.kind) {
    case 'hours_range': return `${hoursBucket(value.min)}..${hoursBucket(value.max)}`
    case 'enum': return String(value)
    case 'timezone': return String(value.zone).slice(0, 3).toUpperCase()  // coarse region prefix
    case 'tag_set': return `${(value as string[]).length} tags`
    default: return '?'
  }
}

/** The complementarity fact (H): A is strong in what B listed as anti-portfolio
 *  and vice versa. Owner-only overlap fact, never a score or a sort key. */
export function complementarityFact(aSpike: string[] | undefined, aAnti: string[] | undefined, bSpike: string[] | undefined, bAnti: string[] | undefined): boolean {
  const aCoversB = arraysIntersect(aSpike ?? [], bAnti ?? [])
  const bCoversA = arraysIntersect(bSpike ?? [], aAnti ?? [])
  return aCoversB && bCoversA
}

function arraysIntersect(a: string[], b: string[]): boolean {
  const s = new Set(a)
  for (const x of b) if (s.has(x)) return true
  return false
}

// ── Euphemism screening (consequential-eligibility prohibition) ───────────
// Purpose, policy, and answers are screened for eligibility euphemisms. Purpose
// is an enum so it cannot carry one; this catches free-text surfaces.
const EUPHEMISMS = [
  'candidate fit', 'founder screening', 'tenant compatibility', 'background check',
  'credit check', 'employment screening', 'hiring decision', 'eligibility', 'screening',
]
export function hasEuphemism(text: string): boolean {
  const t = String(text ?? '').toLowerCase()
  return EUPHEMISMS.some(e => t.includes(e))
}
