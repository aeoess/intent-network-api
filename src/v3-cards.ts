// ══════════════════════════════════════════════════════════════
// Mingle v3 - Card schema, banned-field lint, canonical hashing
// ══════════════════════════════════════════════════════════════
// ConnectionCard v1 and OpportunityCard v1 per MINGLE-V3-SPEC "Cards".
// Additive beside the live 48h IntentCard path, which is untouched.
//
// Invariants enforced here at the type layer:
//   1/2: the banned class (fitVector, assessment, hostile_notes, confidence,
//        trust_tier, score, rank) is rejected wherever it appears in a v3
//        card, as a key or as an exact string value. The live 48h IntentCard
//        keeps its existing shape (it carries a confidence field); this lint
//        applies to v3 cards only.
//   4:   publish binds the exact content hash (canonical serialize + sha256).
//   5:   every evidence record states claim, source, method, verified_fact.

import { createHash } from 'node:crypto'
import { canonicalize } from 'agent-passport-system'

export const CARD_TYPES = ['connection', 'opportunity'] as const
export const INTENTS = ['meet', 'collaborate', 'team_up', 'work', 'advise', 'mentor', 'cofound'] as const
export const EVIDENCE_SOURCES = ['principal_statement', 'artifact_link', 'subject_binding', 'third_party_attestation'] as const
export const VISIBILITY_LEVELS = ['private', 'network', 'intro_request', 'mutual_intro', 'thread_only'] as const
export const REVOCATION_STATUSES = ['active', 'stopped_new_matches', 'superseded', 'withdrawn', 'authority_revoked', 'deleted'] as const

export const DEFAULT_TTL_DAYS = 21

export type CardType = typeof CARD_TYPES[number]
export type RevocationStatus = typeof REVOCATION_STATUSES[number]

export interface EvidenceRecord {
  claim: string
  source: typeof EVIDENCE_SOURCES[number]
  method: string
  verified_fact: string
  date: string
}

export interface SeekingEntry {
  description: string
  topics?: string[]
  engagement?: string
}

export interface OfferingEntry {
  description: string
  topics?: string[]
  provenance: 'principal_statement'
}

export interface PreferenceEntry {
  key: string
  value: string
}

export interface V3Card {
  card_type: CardType
  subject_key: string
  version: 1
  created_at: string
  expires_at: string
  headline: string
  intents: string[]
  seeking: SeekingEntry[]
  offering: OfferingEntry[]
  preferences: PreferenceEntry[]
  artifacts: EvidenceRecord[]
  event_ref?: { event_id: string; dates?: string } | null
  team_size_sought?: number | null
  visibility: Record<string, typeof VISIBILITY_LEVELS[number]>
  composition: { agent_assisted: boolean; skill_version: string }
  delegation_ref?: string | null
  approval: { card_hash: string; approved_at: string; principal_signature: string }
  revocation_status: RevocationStatus
  signature?: string
}

// ── Banned-field lint (invariants 1 and 2 at the type layer) ─────────────
// Normalized key match: lowercase with separators stripped, so fitVector,
// fit_vector and FIT-VECTOR all hit. String values are rejected on an exact
// normalized token match, which catches enum smuggling ({"kind":"trust_tier"})
// without rejecting prose that merely contains an overlapping word.

const BANNED_TOKENS = ['fitvector', 'assessment', 'hostilenotes', 'confidence', 'trusttier', 'score', 'rank']
const normalizeToken = (s: string): string => s.toLowerCase().replace(/[_\-\s]/g, '')

export function findBannedContent(value: unknown, path = 'card'): string | null {
  if (typeof value === 'string') {
    return BANNED_TOKENS.includes(normalizeToken(value)) ? `${path} = "${value}"` : null
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const hit = findBannedContent(value[i], `${path}[${i}]`)
      if (hit) return hit
    }
    return null
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (BANNED_TOKENS.includes(normalizeToken(k))) return `${path}.${k} (banned key)`
      const hit = findBannedContent(v, `${path}.${k}`)
      if (hit) return hit
    }
  }
  return null
}

// ── Canonical serialization and content hash (invariant 4) ───────────────
// The approval token is sha256 over the canonical form of the card without
// signature, approval, or revocation_status: the approval binds the CONTENT
// the principal saw; server-side status transitions must not invalidate it.

export function canonicalCardContent(card: Record<string, unknown>): string {
  const { signature, approval, revocation_status, ...content } = card
  return canonicalize(content)
}

export function cardContentHash(card: Record<string, unknown>): string {
  return createHash('sha256').update(canonicalCardContent(card), 'utf8').digest('hex')
}

// ── Validation ────────────────────────────────────────────────────────────

const MAX_HEADLINE = 200
const MAX_ITEMS = 10
const MAX_TEXT = 1000
const isIso = (s: unknown): s is string => typeof s === 'string' && !Number.isNaN(Date.parse(s))

export function validateV3Card(card: unknown): { valid: true; card: V3Card } | { valid: false; error: string } {
  const bad = (error: string): { valid: false; error: string } => ({ valid: false, error })
  if (!card || typeof card !== 'object' || Array.isArray(card)) return bad('card must be an object')
  const c = card as Record<string, any>

  const banned = findBannedContent(c)
  if (banned) return bad(`prohibited field content: ${banned}. Assessment, scoring, and trust-tier data may not appear in a card.`)

  if (!CARD_TYPES.includes(c.card_type)) return bad(`card_type must be one of ${CARD_TYPES.join(', ')}`)
  if (typeof c.subject_key !== 'string' || c.subject_key.length === 0 || c.subject_key.length > 200) return bad('subject_key required')
  if (c.version !== 1) return bad('version must be 1')
  if (!isIso(c.created_at) || !isIso(c.expires_at)) return bad('created_at and expires_at must be ISO timestamps')
  if (Date.parse(c.expires_at) <= Date.parse(c.created_at)) return bad('expires_at must be after created_at')
  if (typeof c.headline !== 'string' || c.headline.length === 0 || c.headline.length > MAX_HEADLINE) return bad(`headline required (max ${MAX_HEADLINE} chars)`)

  if (!Array.isArray(c.intents) || c.intents.length === 0) return bad('intents must be a non-empty array')
  for (const intent of c.intents) {
    if (!INTENTS.includes(intent)) return bad(`unknown intent "${intent}" (allowed: ${INTENTS.join(', ')})`)
  }

  for (const [field, max] of [['seeking', MAX_ITEMS], ['offering', MAX_ITEMS], ['preferences', MAX_ITEMS], ['artifacts', MAX_ITEMS]] as const) {
    if (!Array.isArray(c[field])) return bad(`${field} must be an array`)
    if (c[field].length > max) return bad(`too many ${field} entries (max ${max})`)
  }
  for (const s of c.seeking) {
    if (typeof s?.description !== 'string' || s.description.length === 0 || s.description.length > MAX_TEXT) return bad('every seeking entry needs a description (max 1000 chars)')
  }
  for (const o of c.offering) {
    if (typeof o?.description !== 'string' || o.description.length === 0 || o.description.length > MAX_TEXT) return bad('every offering entry needs a description (max 1000 chars)')
    if (o.provenance !== 'principal_statement') return bad('offering.provenance must be principal_statement')
  }
  for (const p of c.preferences) {
    if (typeof p?.key !== 'string' || typeof p?.value !== 'string') return bad('preferences must be explicit {key, value} pairs')
  }
  for (const a of c.artifacts) {
    if (typeof a?.claim !== 'string' || a.claim.length === 0) return bad('every evidence record needs its exact claim')
    if (!EVIDENCE_SOURCES.includes(a?.source)) return bad(`evidence source must be one of ${EVIDENCE_SOURCES.join(', ')}`)
    if (typeof a?.method !== 'string' || typeof a?.verified_fact !== 'string' || !isIso(a?.date)) return bad('every evidence record needs method, verified_fact, and date')
  }

  if (c.event_ref != null) {
    if (typeof c.event_ref?.event_id !== 'string' || c.event_ref.event_id.length === 0) return bad('event_ref needs event_id')
  }
  if (c.team_size_sought != null && (!Number.isInteger(c.team_size_sought) || c.team_size_sought < 1 || c.team_size_sought > 100)) {
    return bad('team_size_sought must be an integer 1..100')
  }

  if (!c.visibility || typeof c.visibility !== 'object' || Array.isArray(c.visibility)) return bad('visibility map required')
  for (const [field, level] of Object.entries(c.visibility)) {
    if (!VISIBILITY_LEVELS.includes(level as any)) return bad(`visibility.${field} must be one of ${VISIBILITY_LEVELS.join(', ')}`)
  }

  if (typeof c.composition?.agent_assisted !== 'boolean' || typeof c.composition?.skill_version !== 'string') {
    return bad('composition {agent_assisted, skill_version} required')
  }
  if (c.delegation_ref != null && typeof c.delegation_ref !== 'string') return bad('delegation_ref must be a string when present')

  if (typeof c.approval?.card_hash !== 'string' || !/^[0-9a-f]{64}$/.test(c.approval.card_hash)) return bad('approval.card_hash must be a sha256 hex string')
  if (!isIso(c.approval?.approved_at)) return bad('approval.approved_at must be an ISO timestamp')
  if (typeof c.approval?.principal_signature !== 'string' || c.approval.principal_signature.length === 0) return bad('approval.principal_signature required')

  if (!REVOCATION_STATUSES.includes(c.revocation_status)) return bad(`revocation_status must be one of ${REVOCATION_STATUSES.join(', ')}`)

  return { valid: true, card: c as V3Card }
}

// ── Visibility filtering ──────────────────────────────────────────────────
// Search results carry network-visible fields only. Structural fields that
// carry no principal content (type, timestamps, status) always pass; content
// fields default to network-visible when unlisted, and any stricter level
// removes them from search results.

const ALWAYS_VISIBLE = new Set(['card_type', 'version', 'created_at', 'expires_at', 'revocation_status', 'composition'])
const CONTENT_FIELDS = ['headline', 'intents', 'seeking', 'offering', 'preferences', 'artifacts', 'event_ref', 'team_size_sought']

export function networkVisibleView(card: V3Card & { card_id?: string }): Record<string, unknown> {
  const out: Record<string, unknown> = { card_id: card.card_id }
  for (const f of ALWAYS_VISIBLE) out[f] = (card as any)[f]
  for (const f of CONTENT_FIELDS) {
    const level = card.visibility[f] ?? 'network'
    if (level === 'network') out[f] = (card as any)[f]
  }
  return out
}

/** The text the semantic index sees: network-visible free text only. */
export function networkVisibleText(card: V3Card): string {
  const view = networkVisibleView(card as any)
  const parts: string[] = []
  if (typeof view.headline === 'string') parts.push(view.headline)
  for (const s of (view.seeking as SeekingEntry[] | undefined) ?? []) parts.push(s.description, ...(s.topics ?? []))
  for (const o of (view.offering as OfferingEntry[] | undefined) ?? []) parts.push(o.description, ...(o.topics ?? []))
  return parts.filter(Boolean).join(' ')
}
