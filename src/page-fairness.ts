// Fairness inside one page of search results. On 2026-11-01 a test showed that one
// source spreading 60 near identical cards over 20 keys filled the whole first page of
// an event search, because results are ordered newest first.
//
// Two rules, applied while a page is built, in the normal order:
//   at most PAGE_PER_KEY cards of one key on a page
//   a source may show at most NEAR_DUPLICATES_PER_PAGE cards on a page whose wording is
//     nearly the same as each other (word overlap at or above SIMILAR); further ones are
//     folded out of that page
// Measured 2026-11-01: the flood cards overlapped 1.00 with each other, templated event
// attendees 0.76 to 0.81, different real people in one field 0.04 to 0.10. So an event,
// even one where many attendees use the same wording, stays whole.
// Similar cards from different networks are never folded. Cards with no stored source
// (older rows, the operator) are only subject to the per-key rule. Nothing here scores
// or ranks a person: it only decides which of the cards that match a query share one
// page. The response reports how many cards were folded out.

import { networkVisibleText } from './v3-cards.js'
import type { V3Card } from './v3-cards.js'

export const PAGE_PER_KEY = 3
export const SIMILAR = 0.9
export const NEAR_DUPLICATES_PER_PAGE = 3

const words = (t: string) => new Set(t.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(w => w.length >= 3))
function overlap(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0
  let both = 0
  for (const w of a) if (b.has(w)) both++
  return both / (a.size + b.size - both)
}

export function pageFairness() {
  const perKey = new Map<string, number>()
  const shownBySource = new Map<string, Set<string>[]>()
  let folded = 0
  return {
    /** True if this card may join the page. */
    admit(subjectKey: string, sourceHash: string | null, card: V3Card): boolean {
      const k = perKey.get(subjectKey) ?? 0
      if (k >= PAGE_PER_KEY) { folded++; return false }
      if (sourceHash) {
        const mine = words(networkVisibleText(card))
        const shown = shownBySource.get(sourceHash) ?? []
        if (shown.filter(s => overlap(s, mine) >= SIMILAR).length >= NEAR_DUPLICATES_PER_PAGE) { folded++; return false }
        shown.push(mine)
        shownBySource.set(sourceHash, shown)
      }
      perKey.set(subjectKey, k + 1)
      return true
    },
    get folded() { return folded },
  }
}
