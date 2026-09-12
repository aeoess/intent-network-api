// ══════════════════════════════════════════════════════════════
// The receipt renderer: approved text, and no clause without warrant
// ══════════════════════════════════════════════════════════════
// Every sentence a receipt can contain is a constant in this file, taken from the approved
// copy. A wording change is therefore one diff in one place, and a golden test holds each
// string to the character so the approved copy is load bearing rather than aspirational.
//
// THE MECHANISM, and it is the whole point of the module: a clause is emitted only when the
// field it names appears in that evidence row's bound_fields_json. So "a receipt never
// claims more authorization than principal-signed evidence establishes" is arithmetic over
// a stored list rather than a matter of care.
//
// That is the difference between this and fit-v4-routes.ts:238, where a server-signed
// sentence names dimensions, disclosure levels, a policy hash and a purpose, and four of
// its six content clauses are warranted by nothing.
//
// Mixed strength needs no special case. The two sides of one intro have two evidence rows,
// so one receipt carries two strengths by reading each row's own list. A sentence that
// averages two strengths is a sentence that overclaims about the weaker one.
//
// Nothing here reads a server key, signs anything, or touches the network. It turns rows
// into strings.

import { covers, boundFieldsOf } from './write-evidence.js'
import type { EvidenceRow } from './write-evidence.js'

// ── The approved sentences ────────────────────────────────────────────────
// Verbatim. Do not rephrase, do not reflow, do not add a clause. The golden test compares
// character for character, so an edit here is a deliberate copy change and shows as one.

export const SENTENCES = {
  /** 2.1 request_intro, canonical. */
  request_canonical: 'Acting key K authorized an introduction request to card T for purpose P, with the exact note recorded here. Mingle recorded it at R.',
  /** 2.2 request_intro, legacy. The second sentence is the edit and is not optional. */
  request_legacy: 'Acting key K authorized an introduction request to card T for purpose P. The note stored with it was not covered by that signature.',

  /** 3.1 the connection, both sides canonical. */
  connection_canonical: 'Mingle observed valid contact-sharing authorizations from both acting keys and released each counterparty\'s contact after both authorizations existed.',
  /** 3.2 the connection, one side legacy. */
  connection_mixed: 'Mingle released each counterparty\'s contact after both sides authorized sharing. Key A\'s authorization covered the exact contact line it shared. Key B\'s authorization did not cover the contact line stored for B.',
  /** 3.6 always allowed on a connection receipt. */
  connection_held: 'Neither contact was released until both authorizations existed. Before that, each contact was held and shown to no one.',
  /** 3.7 required wherever a contact appears. */
  contact_irrevocable: 'Mingle cannot withdraw a contact line once it has been released.',

  /** 9.1 the mixed connection receipt, three paragraphs. */
  mixed_para_1: 'Mingle released each counterparty\'s contact after both sides authorized sharing.',
  mixed_para_2: 'Key A\'s authorization covered the exact contact line A shared, committed to as C. The line itself is not in this receipt.',
  mixed_para_3: 'Key B authorized a response on this introduction using an earlier version of Mingle. That signature did not cover the contact line stored for B, so Mingle cannot show that the line it released for B is the line B intended.',
  /** 9.4 allowed wherever a legacy side appears. */
  legacy_side_present: 'This introduction includes a side that authorized with an earlier version of Mingle. Evidence for that side covers less than evidence for the current version.',

  /** 5.2 the v4 handshake receipt, canonical. Replaces fit-v4-routes.ts:238. */
  fit_canonical: 'Acting keys A and B authorized the listed fit operations under the listed policy commitments. Mingle evaluated predicate version V and produced the listed outcome. This attests authorization, not the truth of any value.',
  /** 5.3 required wherever a standing scope applied. The second sentence is not optional. */
  fit_standing_scope: 'This act was authorized under standing scope S. It was not individually approved.',
  /** 5.4 the v4 handshake receipt, legacy. Blunt on purpose. */
  fit_legacy: 'Acting keys A and B each sent a signed fit message naming this introduction. Those signatures did not cover the dimensions, the reciprocal offer, the policy hash or the budget. Mingle evaluated predicate version V from the values it stored and produced the listed outcome.',
  /** 5.7 the disclosure model, stated to the reader. */
  fit_commitment_disclosure: 'The policy commitments in this receipt hide the policy behind them. Either owner may later disclose their policy and salt to an auditor or counterparty of their choosing.',

  /** 6.1 the First Step record, both halves canonical. */
  first_step_canonical: 'Key A authorized half A. Key B authorized half B. Both keys approved merged digest D.',
  /** 6.2 the First Step record when a half was proposed under a legacy signature. */
  first_step_mixed: 'Both keys approved merged digest D, which is the digest of the two halves recorded here. Neither proposal signature covered the text of its half.',
  /** 6.5 always allowed on a First Step record. */
  first_step_finality: 'The plan is final only when both keys have approved the same merged digest. Changing either half clears both approvals.',

  /** 8.1a the shared receipt line for a contact release. */
  share_contact_shared: 'Acting key K authorized the release of a contact line on this introduction, committed to as C. The line itself is held for the counterparty and is not in this receipt. Mingle recorded the authorization at R.',
  /** 8.1c what the recipient may be told. */
  share_contact_recipient: 'This contact line was signed by the other side\'s acting key. You can check that signature yourself, without trusting Mingle.',
  /** 8.1d the limit, required wherever the artifact is described. */
  artifact_plaintext_limit: 'Mingle holds the contact line in plain text on its server. This is not end to end encryption.',
} as const

export type SentenceKey = keyof typeof SENTENCES

/** The sentences the NEVER list forbids, held here so a test can assert no rendered
 *  receipt contains one. Each is a real NOT-ALLOWED entry from the approved list. */
export const FORBIDDEN_SENTENCES: readonly string[] = [
  // 3.3, 3.4, 3.5
  'Both parties agreed to connect.',
  'Each side approved sharing their contact with the other.',
  'Mingle connected A and B.',
  // 5.1, the sentence being replaced, and 5.5, 5.6
  'Each party authorized the listed dimensions at the listed disclosure levels under their stated policy hash, for the stated purpose.',
  'A and B are a good fit.',
  'The listed dimensions matched.',
  // 6.3, 6.4, 6.6
  'A and B agreed to the plan.',
  'A and B will meet as described.',
  'The approval covers the plan as shown to each principal.',
  // 9.2, 9.3
  'Both sides authorized the release of their exact contact lines.',
  'B used an older client, so this evidence is weaker.',
  // 8.1b
  'The contact line is D.',
] as const

// ── The predicate every clause passes through ─────────────────────────────

/** A warrant is either a stored evidence row or the bound field list that row will carry.
 *
 *  Both forms exist because of one real ordering: the fit receipt is assembled as part of
 *  the commit, so the commit's own evidence row does not exist yet when the sentence is
 *  rendered. The list is then computed by boundFieldsFor, the SAME function the recorder
 *  uses, so the rendered sentence and the row that lands cannot disagree. */
export type Warrant = EvidenceRow | readonly string[] | null | undefined

function isRow(w: Warrant): w is EvidenceRow {
  return !!w && !Array.isArray(w) && typeof (w as EvidenceRow).bound_fields_json === 'string'
}

/** Is every one of these fields covered by the signature this warrant records?
 *
 *  Fails closed on an unparseable list and on a missing warrant, because an absent warrant
 *  is not a weak warrant. */
export function warrants(w: Warrant, fields: readonly string[]): boolean {
  if (!w) return false
  if (isRow(w)) return fields.every(f => covers(w, f))
  const list = w as readonly string[]
  return fields.every(f => list.includes(f))
}

export interface RenderedReceipt {
  /** The sentences, in order, each already approved text. */
  sentences: string[]
  /** Which approved constants were used, for a test and for an audit trail. */
  keys: SentenceKey[]
  /** Set when any side of the act was legacy, so a reader is told once. */
  mixed: boolean
}

function build(pairs: [SentenceKey, boolean][]): RenderedReceipt {
  const keys = pairs.filter(([, on]) => on).map(([k]) => k)
  return { sentences: keys.map(k => SENTENCES[k]), keys, mixed: keys.some(k => String(k).includes('legacy') || String(k).includes('mixed')) }
}

// ── The three records ─────────────────────────────────────────────────────

/** The connection record, from the two share_contact evidence rows.
 *
 *  `a` is the requester's row and `b` the target's. Either may be null, which is the
 *  not-yet-shared case, and a receipt is then not rendered at all. */
export function renderConnection(a: Warrant, b: Warrant): RenderedReceipt {
  const aBound = warrants(a, ['payload.private_value_commitment'])
  const bBound = warrants(b, ['payload.private_value_commitment'])
  if (aBound && bBound) {
    return build([
      ['connection_canonical', true],
      ['connection_held', true],
      ['contact_irrevocable', true],
    ])
  }
  // The three paragraph form. It states a limit on Mingle's own knowledge rather than a
  // suspicion about the weaker side, which is what makes it honest.
  return build([
    ['mixed_para_1', true],
    ['mixed_para_2', aBound || bBound],
    ['mixed_para_3', !(aBound && bBound)],
    ['legacy_side_present', true],
    ['contact_irrevocable', true],
  ])
}

/** The v4 handshake record, from the fit_request and fit_commit evidence rows. */
export function renderFitHandshake(args: {
  request: Warrant
  commit: Warrant
  standingScope: boolean
}): RenderedReceipt {
  // The canonical sentence needs BOTH sides' dimension lists bound and both policy
  // commitments bound. One canonical side is not enough, because the sentence names both.
  const requestBound = warrants(args.request, [
    'payload.requested_dimensions', 'payload.reciprocal_offer', 'payload.predicate_version', 'payload.policy_commitment',
  ])
  const commitBound = warrants(args.commit, [
    'payload.accept_dimensions', 'payload.reciprocal_offer', 'payload.policy_commitment', 'payload.request_write_ref',
  ])
  const canonical = requestBound && commitBound
  return build([
    ['fit_canonical', canonical],
    ['fit_commitment_disclosure', canonical],
    ['fit_legacy', !canonical],
    ['legacy_side_present', !canonical],
    // 5.3 is required wherever a scope applied, and only a canonical commit can establish
    // one: on the legacy lane whether the act was autonomous is established by nothing.
    ['fit_standing_scope', args.standingScope && commitBound],
  ])
}

/** The First Step record, from the two propose rows and the two approve rows. */
export function renderFirstStep(args: {
  proposeA: Warrant
  proposeB: Warrant
  approveA: Warrant
  approveB: Warrant
}): RenderedReceipt {
  const halfFields = ['payload.purpose', 'payload.next_action', 'payload.meeting_length',
    'payload.agenda', 'payload.each_wants', 'payload.boundaries', 'payload.expiry']
  const bothHalves = warrants(args.proposeA, halfFields) && warrants(args.proposeB, halfFields)
  // The approval clause stands on its own even when neither half was bound, because
  // fit-firststep-approve:${introId}:${digest}:${nonce} binds the digest. It is the one
  // legacy preimage that covers its whole semantic content.
  const bothApproved =
    (warrants(args.approveA, ['payload.approved_digest']) || warrants(args.approveA, ['approved_digest']))
    && (warrants(args.approveB, ['payload.approved_digest']) || warrants(args.approveB, ['approved_digest']))
  return build([
    ['first_step_canonical', bothHalves && bothApproved],
    ['first_step_mixed', !bothHalves && bothApproved],
    ['legacy_side_present', !bothHalves],
    ['first_step_finality', true],
  ])
}

/** The intro request record, from its one evidence row. */
export function renderIntroRequest(row: Warrant): RenderedReceipt {
  const bound = warrants(row, ['payload.to_card', 'payload.purpose', 'payload.note'])
  return build([
    ['request_canonical', bound],
    ['request_legacy', !bound],
  ])
}

/** Every field a row's signature covers, for a surface that wants to show the warrant
 *  rather than the conclusion. */
export function warrantList(w: Warrant): string[] {
  if (!w) return []
  return isRow(w) ? boundFieldsOf(w) : [...(w as readonly string[])]
}
