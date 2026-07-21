// ══════════════════════════════════════════════════════════════
// Mingle v3 match engine - overlap computation (pure)
// ══════════════════════════════════════════════════════════════
// Doctrine (MINGLE-V3-SPEC invariant 2 + the match adjudication): a card's
// seeking section is a standing query authored by its owner. Matching runs each
// owner's own query continuously; results go only to the card owner. The
// artifact is an OVERLAP MAP, never a score: matched intents, agreed stated
// fields, and short quoted snippets of the counterpart's own network-visible
// words. A numeric score is computed transiently to gate inclusion and is then
// discarded; it is never stored or exposed anywhere.
//
// Everything here reads network-visible content only (networkVisibleView), so a
// private field can neither create a match nor appear in a snippet shown to the
// counterpart.

import { networkVisibleView, type V3Card, type SeekingEntry, type OfferingEntry } from './v3-cards.js'

export interface AgreedField { field: string; value: string }

/** The stored overlap for a pair. a_snippets are card_a's own words (shown to
 *  card_b's owner) and b_snippets are card_b's own words (shown to card_a's
 *  owner). matched_intents and agreed_fields are symmetric. No score. */
export interface OverlapMap {
  matched_intents: string[]
  agreed_fields: AgreedField[]
  a_snippets: string[]
  b_snippets: string[]
}

const SNIPPET_MAX = 160
const MAX_SNIPPETS = 3
const MATCH_THRESHOLD = 3

const clip = (s: string): string => (s.length > SNIPPET_MAX ? s.slice(0, SNIPPET_MAX).trimEnd() + '...' : s)

// A small stopword set so token overlap reflects real subject words, not glue.
const STOP = new Set([
  'the', 'and', 'for', 'with', 'who', 'are', 'you', 'your', 'our', 'that', 'this',
  'from', 'have', 'has', 'had', 'into', 'not', 'but', 'all', 'any', 'can', 'get',
  'want', 'looking', 'seeking', 'offer', 'offering', 'need', 'needs', 'help',
  'work', 'working', 'someone', 'people', 'build', 'building', 'make', 'making',
  'good', 'great', 'love', 'like', 'able', 'both', 'more', 'about', 'they', 'them',
])

function tokenSet(strings: string[]): Set<string> {
  const out = new Set<string>()
  for (const s of strings) {
    for (const t of s.toLowerCase().split(/[^a-z0-9]+/)) {
      if (t.length >= 3 && !STOP.has(t)) out.add(t)
    }
  }
  return out
}

function overlaps(a: Set<string>, b: Set<string>): boolean {
  for (const t of a) if (b.has(t)) return true
  return false
}

function view(card: V3Card): Record<string, any> {
  return networkVisibleView(card as any) as Record<string, any>
}

function visibleIntents(v: Record<string, any>): string[] {
  return Array.isArray(v.intents) ? v.intents.filter((i: unknown): i is string => typeof i === 'string') : []
}

function snippets(v: Record<string, any>): string[] {
  const out: string[] = []
  if (typeof v.headline === 'string' && v.headline.trim()) out.push(clip(v.headline.trim()))
  for (const s of (v.seeking as SeekingEntry[] | undefined) ?? []) {
    if (s?.description?.trim()) out.push(clip(s.description.trim()))
  }
  for (const o of (v.offering as OfferingEntry[] | undefined) ?? []) {
    if (o?.description?.trim()) out.push(clip(o.description.trim()))
  }
  return out.slice(0, MAX_SNIPPETS)
}

function seekingTokens(v: Record<string, any>): Set<string> {
  const parts: string[] = []
  for (const s of (v.seeking as SeekingEntry[] | undefined) ?? []) {
    if (s?.description) parts.push(s.description)
    for (const t of s?.topics ?? []) parts.push(t)
  }
  return tokenSet(parts)
}

function offeringTokens(v: Record<string, any>): Set<string> {
  const parts: string[] = []
  for (const o of (v.offering as OfferingEntry[] | undefined) ?? []) {
    if (o?.description) parts.push(o.description)
    for (const t of o?.topics ?? []) parts.push(t)
  }
  return tokenSet(parts)
}

/** Stated-field agreements: same event, same declared location, same engagement.
 *  Only explicit, self-declared values, never inferred. */
function agreedFields(a: V3Card, b: V3Card): AgreedField[] {
  const out: AgreedField[] = []

  if (a.event_ref?.event_id && b.event_ref?.event_id && a.event_ref.event_id === b.event_ref.event_id) {
    out.push({ field: 'event_ref', value: a.event_ref.event_id })
  }

  const prefValues = (card: V3Card, key: string): string[] =>
    card.preferences.filter(p => p.key === key).map(p => p.value.trim()).filter(Boolean)
  const engagementValues = (card: V3Card): string[] => [
    ...prefValues(card, 'engagement'),
    ...card.seeking.map(s => s.engagement?.trim()).filter((e): e is string => !!e),
  ]

  for (const [field, aVals, bVals] of [
    ['location', prefValues(a, 'location'), prefValues(b, 'location')],
    ['engagement', engagementValues(a), engagementValues(b)],
  ] as const) {
    const shared = aVals.find(av => bVals.some(bv => bv.toLowerCase() === av.toLowerCase()))
    if (shared) out.push({ field, value: shared })
  }
  return out
}

/**
 * Compute the overlap map for an ordered pair (cardA is the canonically-first
 * card_id). cos is the cosine similarity of the two network-visible texts, or
 * null when no embedding is available. Returns null when the pair does not
 * clear the inclusion threshold. The score is local and never returned.
 */
export function computeOverlap(cardA: V3Card, cardB: V3Card, cos: number | null): OverlapMap | null {
  const va = view(cardA)
  const vb = view(cardB)

  const intentsA = new Set(visibleIntents(va))
  const matched_intents = visibleIntents(vb).filter(i => intentsA.has(i))
  const agreed_fields = agreedFields(cardA, cardB)

  const aWantsB = overlaps(seekingTokens(va), offeringTokens(vb))
  const bWantsA = overlaps(seekingTokens(vb), offeringTokens(va))

  let score = 0
  if (matched_intents.length > 0) score += 2
  score += agreed_fields.length
  if (aWantsB && bWantsA) score += 2
  else if (aWantsB || bWantsA) score += 1
  if (cos != null) {
    if (cos >= 0.55) score += 2
    else if (cos >= 0.40) score += 1
  }

  if (score < MATCH_THRESHOLD) return null

  return {
    matched_intents,
    agreed_fields,
    a_snippets: snippets(va),
    b_snippets: snippets(vb),
  }
}

/** Count of concrete overlap signals, used for the overlap-count ordering. */
export function overlapCount(map: OverlapMap): number {
  return map.matched_intents.length + map.agreed_fields.length
}

export const MATCH_INTERNALS = { MATCH_THRESHOLD, SNIPPET_MAX } as const
