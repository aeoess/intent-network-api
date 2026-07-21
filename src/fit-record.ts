// ══════════════════════════════════════════════════════════════
// Mingle v3.6 fit exchange - record assembly (deterministic)
// ══════════════════════════════════════════════════════════════
// On close the record is assembled mechanically: per question, both sides'
// answers verbatim plus a four-state classification. Classification is
// deterministic and never a model judgment; refusal or silence is not_answered,
// never annotated as negative evidence. The record binds a stable content digest
// that the server signs.

import { createHash } from 'node:crypto'
import { canonicalize } from 'agent-passport-system'
import type { ExchangeRow, AnswerRow, BankQuestion } from './fit-db.js'
import { signReceipt, serverPublicKey } from './server-key.js'

export type Classification = 'answered' | 'partially_answered' | 'unclear' | 'not_answered'

interface Round2Row { requester_key: string; question_id: string; created_at: string }
interface CustomRow { id: string; asker_key: string; text: string; created_at: string }

/** Deterministic per-(question, side) state. round2Pending overrides to
 *  partially; skip/absent is not_answered; ledger/drafted is answered. */
export function classify(answer: AnswerRow | undefined, round2Pending: boolean): Classification {
  if (round2Pending) return 'partially_answered'
  if (!answer || answer.mode === 'skip') return 'not_answered'
  return 'answered'
}

function round2Pending(sideKey: string, questionId: string, round2s: Round2Row[], answers: AnswerRow[]): boolean {
  // A round2 targeting sideKey is one requested by the OTHER party on this question.
  const reqs = round2s.filter(r => r.question_id === questionId && r.requester_key !== sideKey)
  if (reqs.length === 0) return false
  const latestReq = reqs.map(r => r.created_at).sort().slice(-1)[0]
  const ans = answers.find(a => a.question_id === questionId && a.answerer_key === sideKey)
  if (!ans) return true
  return ans.created_at <= latestReq
}

export interface SideAnswer { key: string; text: string | null; mode: string; classification: Classification }
export interface RecordEntry {
  question_id: string
  question_text: string
  kind: 'bank' | 'custom'
  asker_key?: string
  by_a: SideAnswer
  by_b: SideAnswer
}

export interface FitRecord {
  exchange_id: string
  intent: string
  bank_version: number
  key_a: string
  key_b: string
  entries: RecordEntry[]
}

function sideAnswer(key: string, answer: AnswerRow | undefined, r2: boolean): SideAnswer {
  return { key, text: answer?.text ?? null, mode: answer?.mode ?? 'none', classification: classify(answer, r2) }
}

/** Build the record content (no timestamps, so the digest is reproducible). */
export function assembleRecord(ex: ExchangeRow, bank: BankQuestion[], answers: AnswerRow[], round2s: Round2Row[], customs: CustomRow[]): FitRecord {
  const find = (qid: string, key: string) => answers.find(a => a.question_id === qid && a.answerer_key === key)

  const entries: RecordEntry[] = bank.map(q => ({
    question_id: q.question_id,
    question_text: q.template,
    kind: 'bank' as const,
    by_a: sideAnswer(ex.key_a, find(q.question_id, ex.key_a), round2Pending(ex.key_a, q.question_id, round2s, answers)),
    by_b: sideAnswer(ex.key_b, find(q.question_id, ex.key_b), round2Pending(ex.key_b, q.question_id, round2s, answers)),
  }))

  // Custom questions: the asker's side is marked as the asker (not an answer);
  // only the counterpart answers, in drafted mode.
  for (const c of customs) {
    const answererKey = c.asker_key === ex.key_a ? ex.key_b : ex.key_a
    const answererAns = find(c.id, answererKey)
    const askerSide: SideAnswer = { key: c.asker_key, text: null, mode: 'asked', classification: 'not_answered' }
    const answerSide = sideAnswer(answererKey, answererAns, false)
    entries.push({
      question_id: c.id,
      question_text: c.text,
      kind: 'custom',
      asker_key: c.asker_key,
      by_a: ex.key_a === c.asker_key ? askerSide : answerSide,
      by_b: ex.key_b === c.asker_key ? askerSide : answerSide,
    })
  }

  return { exchange_id: ex.id, intent: ex.intent, bank_version: ex.bank_version, key_a: ex.key_a, key_b: ex.key_b, entries }
}

export function recordDigest(record: FitRecord): string {
  return createHash('sha256').update(canonicalize(record as any), 'utf8').digest('hex')
}

/** Assemble, digest, and sign a record. Returns everything needed to store and
 *  to let a party verify the receipt. */
export function sealRecord(ex: ExchangeRow, bank: BankQuestion[], answers: AnswerRow[], round2s: Round2Row[], customs: CustomRow[]): {
  record: FitRecord; digest: string; receipt: string; server_public_key: string
} {
  const record = assembleRecord(ex, bank, answers, round2s, customs)
  const digest = recordDigest(record)
  return { record, digest, receipt: signReceipt(digest), server_public_key: serverPublicKey() }
}
