// ══════════════════════════════════════════════════════════════
// Mingle v3.6 fit exchange - the isolation surface (pure)
// ══════════════════════════════════════════════════════════════
// THE headline safety property lives here: counterparty-authored ANSWER text can
// never enter a drafting/generation context. It is enforced by construction, not
// by policy: DraftingContextInput has exactly three fields (your own public
// card, your own approved ledger items, and the platform questions with
// sanitized PUBLIC-card slots). There is deliberately no field, anywhere in this
// type, for counterparty answers. The counterpart's answers reach the human and
// the record through entirely separate read paths.

import type { V3Card } from './v3-cards.js'
import { networkVisibleView } from './v3-cards.js'
import { sanitizeSlot } from './fit-gate.js'
import type { LedgerItem, BankQuestion } from './fit-db.js'

/** A question whose public-card slots are already substituted and sanitized. */
export interface RenderedQuestion { question_id: string; text: string }

/** The ONLY inputs a drafting context may contain. No counterparty answers. */
export interface DraftingContextInput {
  own_card_public: Record<string, unknown>
  own_ledger: LedgerItem[]
  questions: RenderedQuestion[]
}

export interface DraftingContext {
  own_headline: string
  own_ledger: LedgerItem[]
  questions: RenderedQuestion[]
  guidance: string
}

/** Substitute {their_headline}/{their_seeking} from the counterpart's PUBLIC
 *  card only, sanitized. Deterministic string replacement; public card fields
 *  are allowed in drafting context, counterparty ANSWERS are not. */
export function renderQuestion(template: string, counterpartPublic: Record<string, any>): string {
  const headline = sanitizeSlot(typeof counterpartPublic.headline === 'string' ? counterpartPublic.headline : '')
  const firstSeeking = Array.isArray(counterpartPublic.seeking) && counterpartPublic.seeking[0]?.description
    ? sanitizeSlot(String(counterpartPublic.seeking[0].description))
    : ''
  return template
    .replace(/\{their_headline\}/g, headline || 'their card')
    .replace(/\{their_seeking\}/g, firstSeeking || 'what they are seeking')
}

export function renderQuestions(bank: BankQuestion[], counterpartCard: V3Card): RenderedQuestion[] {
  const pub = networkVisibleView(counterpartCard as any) as Record<string, any>
  return bank.map(q => ({ question_id: q.question_id, text: renderQuestion(q.template, pub) }))
}

/**
 * Assemble the drafting context. The input type makes counterparty answer text
 * unrepresentable; this function only reads own card, own ledger, and the
 * questions. It is the single sanctioned builder of anything an assistant may
 * use to draft a fit answer.
 */
export function assembleDraftingContext(input: DraftingContextInput): DraftingContext {
  const own = input.own_card_public as Record<string, any>
  return {
    own_headline: typeof own.headline === 'string' ? own.headline : '',
    own_ledger: input.own_ledger,
    questions: input.questions,
    guidance: 'Draft each answer from the principal\'s own words and approved disclosure items only. The counterpart\'s answers are not part of this context; do not request or use them while drafting.',
  }
}
