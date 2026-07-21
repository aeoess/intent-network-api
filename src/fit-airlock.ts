// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - the semantic airlock (secretless extractor + private planner)
// ══════════════════════════════════════════════════════════════
// This is an AIRLOCK, not a firewall: it reduces attack surface, it is not a
// guarantee against hostile language. The property it enforces structurally:
// counterparty-authored answer text is read ONLY by the extractor, whose input
// type is exactly {answer, question, schema} and NOTHING ELSE (no owner card, no
// policy, no ledger, no tools, no memory, no network). The extractor emits a
// schema-bounded result with no free text from the answer. The private planner,
// which holds the policy, receives ONLY that validated extraction, never the raw
// answer. The human always sees the raw answer beside the extraction.

import { DIMENSIONS, ROLE_TAGS } from './fit-schema.js'

// ── The extractor's world: exactly these three fields. Adding an owner-data
//    field here would be the thing the airlock exists to prevent. ──
export interface ExtractionSchema { dimension: string }
export interface AirlockInput {
  answer: string
  question: string
  schema: ExtractionSchema
}

export type ExtractStatus = 'answered' | 'partially' | 'unclear' | 'not_answered'
export interface AirlockExtraction {
  dimension: string
  status: ExtractStatus
  value_bucket?: string        // a canonical bucket/enum only, never free text
  conditions: string[]         // from a fixed vocabulary, never free text
}

const CONDITION_VOCAB: [RegExp, string][] = [
  [/\bif\b|\bdepends\b|\bconditional\b|\bprovided that\b/, 'conditional'],
  [/\bmaybe\b|\bnot sure\b|\bunsure\b|\bpossibly\b|\bmight\b|\bperhaps\b/, 'uncertain'],
  [/\blater\b|\beventually\b|\bdown the line\b/, 'deferred'],
]

function detectConditions(lower: string): string[] {
  const out: string[] = []
  for (const [re, tag] of CONDITION_VOCAB) if (re.test(lower)) out.push(tag)
  return out
}

const HOUR_BUCKETS: [number, number, string][] = [[0, 9, '<10'], [10, 20, '10-20'], [21, 40, '21-40'], [41, 168, '40+']]
function hoursBucket(n: number): string { return (HOUR_BUCKETS.find(([lo, hi]) => n >= lo && n <= hi) ?? [0, 0, '?'])[2] }

/**
 * Extract a schema-bounded state from ONE counterparty answer. Deterministic and
 * secretless: the only inputs are the answer, its question, and the extraction
 * schema (public). The output carries NO text from the answer, only a canonical
 * bucket, a fixed status, and fixed-vocabulary conditions. This is what makes a
 * marker string in the answer unable to cross into any private-data context.
 */
export function extract(input: AirlockInput): AirlockExtraction {
  const dimension = input.schema?.dimension
  const def = DIMENSIONS[dimension]
  const lower = String(input.answer ?? '').toLowerCase()
  const conditions = detectConditions(lower)

  if (!def || lower.trim().length === 0) return { dimension, status: 'not_answered', conditions }

  let value_bucket: string | undefined
  let matched = false
  switch (def.kind) {
    case 'enum': {
      const hit = def.values!.find(v => lower.includes(v.replace(/_/g, ' ')) || lower.includes(v))
      if (hit) { value_bucket = hit; matched = true }
      break
    }
    case 'hours_range': {
      const m = lower.match(/\b(\d{1,3})\b/)
      if (m) { value_bucket = hoursBucket(Number(m[1])); matched = true }
      break
    }
    case 'tag_set': {
      const hits = (ROLE_TAGS as readonly string[]).filter(t => lower.includes(t))
      if (hits.length) { value_bucket = `${hits.length} tags`; matched = true }
      break
    }
    case 'timezone': {
      if (/\butc\b|\bgmt\b|\best\b|\bpst\b|\bcet\b|[a-z]+\/[a-z]+/.test(lower)) { value_bucket = 'zone_stated'; matched = true }
      break
    }
  }

  let status: ExtractStatus
  if (matched && conditions.length === 0) status = 'answered'
  else if (matched) status = 'partially'
  else status = 'unclear'
  return { dimension, status, value_bucket, conditions }
}

// ── The private planner: holds policy, never the raw answer ────────────────

export type PlannerAction = 'resolved' | 'clarify' | 'escalate_to_human'
export interface PlannerPolicyView { disclosure_state: string; importance: string; sensitivity: string }
export interface PlannerDecision { action: PlannerAction; requires_human: boolean; reason: string }

/**
 * Decide what to do with a dimension given ONLY the validated extraction and the
 * owner's policy view for that dimension. There is deliberately no parameter for
 * the raw answer: the planner cannot receive it. Any status other than a clean
 * "answered", or any condition, forces human confirmation; a high-sensitivity
 * dimension always escalates even on a clean answer.
 */
export function plan(extraction: AirlockExtraction, ownDim: PlannerPolicyView): PlannerDecision {
  if (extraction.status !== 'answered' || extraction.conditions.length > 0) {
    return { action: 'escalate_to_human', requires_human: true, reason: 'extraction is not a clean answer or carries conditions' }
  }
  if (ownDim.sensitivity === 'high') {
    return { action: 'escalate_to_human', requires_human: true, reason: 'high-sensitivity dimension requires per-match human approval' }
  }
  return { action: 'resolved', requires_human: false, reason: 'clean extraction; any disclosure still obeys disclosure_state and mutual reciprocity' }
}
