// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - handshake evaluation (pure)
// ══════════════════════════════════════════════════════════════
// The predicate grammar (overlap/bucket/complementarity) lives in fit-schema.ts
// and is consumed here unchanged. This module does three things, all pure:
//   - reciprocity intersection: the evaluable set is what BOTH sides committed;
//   - disclosure-state reveal ordering: the disclosed fact for a dimension is
//     bounded by the LOWER of the two sides' disclosure states (testable reveals
//     nothing, overlap -> bucket -> exact strictly);
//   - anti-accumulation: only essential/useful dimensions, capped, distinct
//     facts, never a score or a count.

import { overlapFact, bucketFact, complementarityFact, DISCLOSURE_RANK } from './fit-schema.js'
import type { PolicyDimension } from './fit-policy-db.js'

export const OVERLAP_MAP_CAP = 6

export interface OverlapEntry {
  dimension: string
  result: 'overlap' | 'bucket' | 'exact_available' | 'not_disclosed' | 'not_checked' | 'budget_exhausted'
  overlap?: boolean | 'needs_discussion'
  bucket_a?: string
  bucket_b?: string
  exact_available?: boolean
}

/** The mutually-committed, reciprocal, important dimension set, capped. A
 *  dimension qualifies only when: both sides requested/accepted it, both offered
 *  it reciprocally, both hold it in policy for the intent, and it is
 *  essential/useful on at least one side. Deterministic order; capped to 6. */
export function selectEvaluableDimensions(
  requested: string[], accept: string[], reqReciprocal: string[], comReciprocal: string[],
  policyA: Map<string, PolicyDimension>, policyB: Map<string, PolicyDimension>,
): string[] {
  const req = new Set(requested), acc = new Set(accept), rr = new Set(reqReciprocal), cr = new Set(comReciprocal)
  const out: string[] = []
  for (const dim of new Set(requested)) {
    if (!acc.has(dim) || !rr.has(dim) || !cr.has(dim)) continue        // reciprocity: both committed + both offered
    const a = policyA.get(dim), b = policyB.get(dim)
    if (!a || !b) continue                                            // both must hold it for the intent
    const important = ['essential', 'useful'].includes(a.importance) || ['essential', 'useful'].includes(b.importance)
    if (!important) continue                                          // anti-accumulation: only what matters to someone
    out.push(dim)
  }
  out.sort()
  return out.slice(0, OVERLAP_MAP_CAP)
}

/**
 * Evaluate each mutually-committed dimension. The disclosed fact is bounded by
 * the LOWER disclosure state of the two sides. local_only never participates;
 * testable participates but reveals nothing; overlap/bucket/exact strictly.
 */
export function evaluateHandshake(
  dimensions: string[],
  policyA: Map<string, PolicyDimension>,
  policyB: Map<string, PolicyDimension>,
  budgetBlocked: Set<string>,
): OverlapEntry[] {
  const facts: OverlapEntry[] = []
  for (const dim of dimensions) {
    if (budgetBlocked.has(dim)) { facts.push({ dimension: dim, result: 'budget_exhausted' }); continue }
    const a = policyA.get(dim), b = policyB.get(dim)
    if (!a || !b) { facts.push({ dimension: dim, result: 'not_checked' }); continue }
    const rankA = DISCLOSURE_RANK[a.disclosure_state], rankB = DISCLOSURE_RANK[b.disclosure_state]
    if (rankA < 2 || rankB < 2) { facts.push({ dimension: dim, result: 'not_checked' }); continue }  // local_only excluded
    const eff = Math.min(rankA, rankB)
    if (eff < 3) { facts.push({ dimension: dim, result: 'not_disclosed' }); continue }               // testable reveals nothing
    const overlap = overlapFact(dim, a.value, b.value)
    if (eff === 3) { facts.push({ dimension: dim, result: 'overlap', overlap }); continue }
    const entry: OverlapEntry = { dimension: dim, result: eff === 5 ? 'exact_available' : 'bucket', overlap, bucket_a: bucketFact(dim, a.value), bucket_b: bucketFact(dim, b.value) }
    if (eff === 5) entry.exact_available = true
    facts.push(entry)
  }
  return facts
}

/** The complementarity fact (H), emitted only when role_spike AND
 *  role_antiportfolio are both evaluable at overlap level or higher on both
 *  sides. A distinct fact, never a score or a sort key. */
export function complementarityEntry(dimensions: string[], policyA: Map<string, PolicyDimension>, policyB: Map<string, PolicyDimension>): OverlapEntry | null {
  if (!dimensions.includes('role_spike') || !dimensions.includes('role_antiportfolio')) return null
  for (const name of ['role_spike', 'role_antiportfolio']) {
    const a = policyA.get(name), b = policyB.get(name)
    if (!a || !b) return null
    if (Math.min(DISCLOSURE_RANK[a.disclosure_state], DISCLOSURE_RANK[b.disclosure_state]) < 3) return null
  }
  const compl = complementarityFact(
    policyA.get('role_spike')!.value as string[], policyA.get('role_antiportfolio')!.value as string[],
    policyB.get('role_spike')!.value as string[], policyB.get('role_antiportfolio')!.value as string[],
  )
  return { dimension: 'complementarity', result: 'overlap', overlap: compl }
}
