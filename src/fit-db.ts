// ══════════════════════════════════════════════════════════════
// Mingle v3.6 fit exchange - storage + seeded question banks (additive)
// ══════════════════════════════════════════════════════════════
// Structured fit exchange between an intro's two parties. The disclosure ledger
// holds discrete, individually approved claims (never an open-ended permission).
// Question banks are versioned and seeded once. Answers are one per (exchange,
// question, answerer). Nothing here alters an existing table.

import type { Database } from 'better-sqlite3'
import { createHash, randomBytes } from 'node:crypto'
import { canonicalize } from 'agent-passport-system'
import { getDb } from './db.js'

let initialized = false

export const BANKED_INTENTS = ['cofound', 'team_up', 'collaborate', 'meet', 'advise'] as const
export const BANK_VERSION = 1
export const FIT_WINDOW_MS = 72 * 3600 * 1000

export type FitState = 'answering' | 'round2' | 'closed'
export type AnswerMode = 'ledger' | 'drafted' | 'skip'

// ── The seeded banks (bank_version 1), verbatim from the spec ─────────────
// {their_headline} and {their_seeking} are slots filled from the counterpart's
// PUBLIC card at render time (deterministic, sanitized). 'work' has no bank.
const BANK_SEED: Record<string, string[]> = {
  cofound: [
    'What weekly hour commitment can you make for the next six months?',
    'What is your runway or income situation, in whatever terms you are comfortable sharing?',
    'How do you want decisions split between cofounders?',
    'Your counterpart\'s card says "{their_headline}". What part of that do you want to own?',
    'What is your equity philosophy in one sentence?',
    'Have you cofounded before, and what happened?',
    'Where do you work from and what timezone overlap do you need?',
    'What would make you walk away in month three?',
  ],
  team_up: [
    'What role do you want on this team?',
    'How many hours can you give during the event window?',
    'What stack or tools are you fastest in?',
    'Their card mentions "{their_seeking}". How do you complement that?',
    'What does a win look like for you at this event?',
    'Do you want to keep working together after the event if it goes well?',
  ],
  collaborate: [
    'What stage is your project at right now?',
    'What cadence of collaboration works for you?',
    'What part do you want a collaborator to own?',
    'Their card says "{their_headline}". Where do you see the overlap?',
    'What have you already tried that did not work?',
    'How do you want credit and ownership handled?',
  ],
  meet: [
    'What are you hoping to get out of connecting?',
    'What are you working on right now, in your own words?',
    'What kind of people do you learn the most from?',
    'Their card says "{their_headline}". What made you want to talk?',
  ],
  advise: [
    'What decision are you facing where advice would help?',
    'What has your advisor experience been so far, either side?',
    'What cadence and format do you want?',
    'What expertise from their card drew you?',
  ],
}

export function initFitSchema(): void {
  const dd = getDb()
  dd.exec(`
    CREATE TABLE IF NOT EXISTS v3_disclosure_ledger (
      id TEXT PRIMARY KEY,
      card_id TEXT NOT NULL,
      subject_key TEXT NOT NULL,
      text TEXT NOT NULL,
      position INTEGER NOT NULL,
      ledger_version INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_ledger_card ON v3_disclosure_ledger(card_id, ledger_version);

    CREATE TABLE IF NOT EXISTS v3_ledger_meta (
      card_id TEXT PRIMARY KEY,
      subject_key TEXT NOT NULL,
      version INTEGER NOT NULL,
      ledger_hash TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );

    CREATE TABLE IF NOT EXISTS v3_fit_question_banks (
      intent TEXT NOT NULL,
      bank_version INTEGER NOT NULL,
      question_id TEXT NOT NULL,
      position INTEGER NOT NULL,
      template TEXT NOT NULL,
      PRIMARY KEY (intent, bank_version, question_id)
    );

    CREATE TABLE IF NOT EXISTS v3_fit_exchanges (
      id TEXT PRIMARY KEY,
      intro_id TEXT NOT NULL,
      card_a TEXT NOT NULL,
      card_b TEXT NOT NULL,
      key_a TEXT NOT NULL,
      key_b TEXT NOT NULL,
      intent TEXT NOT NULL,
      bank_version INTEGER NOT NULL,
      ledger_version_a INTEGER NOT NULL DEFAULT 0,
      ledger_version_b INTEGER NOT NULL DEFAULT 0,
      state TEXT NOT NULL DEFAULT 'answering',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      expires_at TEXT NOT NULL,
      closed_at TEXT,
      record_json TEXT,
      record_digest TEXT,
      receipt TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_fit_ex_keys ON v3_fit_exchanges(key_a, key_b);
    CREATE INDEX IF NOT EXISTS idx_fit_ex_state ON v3_fit_exchanges(state, expires_at);

    CREATE TABLE IF NOT EXISTS v3_fit_answers (
      exchange_id TEXT NOT NULL,
      question_id TEXT NOT NULL,
      answerer_key TEXT NOT NULL,
      mode TEXT NOT NULL,
      ledger_id TEXT,
      text TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (exchange_id, question_id, answerer_key)
    );

    CREATE TABLE IF NOT EXISTS v3_fit_round2 (
      exchange_id TEXT NOT NULL,
      requester_key TEXT NOT NULL,
      question_id TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      PRIMARY KEY (exchange_id, requester_key, question_id)
    );

    CREATE TABLE IF NOT EXISTS v3_fit_custom (
      id TEXT PRIMARY KEY,
      exchange_id TEXT NOT NULL,
      asker_key TEXT NOT NULL,
      text TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_fit_custom_ex ON v3_fit_custom(exchange_id);
  `)
  seedBanks()
  initialized = true
}

function seedBanks(): void {
  const dd = getDb()
  const ins = dd.prepare('INSERT OR IGNORE INTO v3_fit_question_banks (intent, bank_version, question_id, position, template) VALUES (?, ?, ?, ?, ?)')
  for (const [intent, questions] of Object.entries(BANK_SEED)) {
    questions.forEach((template, i) => ins.run(intent, BANK_VERSION, `${intent}-${i + 1}`, i + 1, template))
  }
}

function d(): Database {
  if (!initialized) initFitSchema()
  return getDb()
}

export function isBankedIntent(intent: string): intent is typeof BANKED_INTENTS[number] {
  return (BANKED_INTENTS as readonly string[]).includes(intent)
}

// ── Question banks ─────────────────────────────────────────────────────────

export interface BankQuestion { question_id: string; position: number; template: string }

export function getBank(intent: string, bankVersion = BANK_VERSION): BankQuestion[] {
  return d().prepare('SELECT question_id, position, template FROM v3_fit_question_banks WHERE intent = ? AND bank_version = ? ORDER BY position').all(intent, bankVersion) as BankQuestion[]
}

// ── Disclosure ledger ──────────────────────────────────────────────────────

export interface LedgerItem { id: string; text: string; position: number }

/** Canonical hash of a ledger item text list (approval binds this). */
export function ledgerHash(texts: string[]): string {
  return createHash('sha256').update(canonicalize(texts), 'utf8').digest('hex')
}

export function getLedger(cardId: string): { version: number; items: LedgerItem[] } {
  const meta = d().prepare('SELECT version FROM v3_ledger_meta WHERE card_id = ?').get(cardId) as any
  const version = meta?.version ?? 0
  if (!version) return { version: 0, items: [] }
  const items = d().prepare('SELECT id, text, position FROM v3_disclosure_ledger WHERE card_id = ? AND ledger_version = ? ORDER BY position').all(cardId, version) as LedgerItem[]
  return { version, items }
}

export function getLedgerVersion(cardId: string): number {
  const meta = d().prepare('SELECT version FROM v3_ledger_meta WHERE card_id = ?').get(cardId) as any
  return meta?.version ?? 0
}

/** True when this ledger item id is present in the card's CURRENT version. */
export function ledgerItemLive(cardId: string, ledgerId: string): { text: string } | null {
  const version = getLedgerVersion(cardId)
  if (!version) return null
  const row = d().prepare('SELECT text FROM v3_disclosure_ledger WHERE id = ? AND card_id = ? AND ledger_version = ?').get(ledgerId, cardId, version) as any
  return row ? { text: row.text } : null
}

/** Replace a card's ledger with a new approved set. Returns the stored items and
 *  the new version. Item ids are assigned here and returned to the caller. */
export function setLedger(cardId: string, subjectKey: string, texts: string[]): { version: number; items: LedgerItem[]; ledger_hash: string } {
  const dd = d()
  const tx = dd.transaction(() => {
    const cur = (dd.prepare('SELECT version FROM v3_ledger_meta WHERE card_id = ?').get(cardId) as any)?.version ?? 0
    const version = cur + 1
    const items: LedgerItem[] = texts.map((text, i) => ({ id: `led-${version}-${i + 1}-${randomBytes(5).toString('hex')}`, text, position: i + 1 }))
    const ins = dd.prepare('INSERT INTO v3_disclosure_ledger (id, card_id, subject_key, text, position, ledger_version) VALUES (?, ?, ?, ?, ?, ?)')
    for (const it of items) ins.run(it.id, cardId, subjectKey, it.text, it.position, version)
    const lh = ledgerHash(texts)
    dd.prepare(`INSERT INTO v3_ledger_meta (card_id, subject_key, version, ledger_hash, updated_at) VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
      ON CONFLICT(card_id) DO UPDATE SET version = excluded.version, ledger_hash = excluded.ledger_hash, subject_key = excluded.subject_key, updated_at = excluded.updated_at`).run(cardId, subjectKey, version, lh)
    return { version, items, ledger_hash: lh }
  })
  return tx()
}

// ── Exchanges ──────────────────────────────────────────────────────────────

export interface ExchangeRow {
  id: string
  intro_id: string
  card_a: string; card_b: string
  key_a: string; key_b: string
  intent: string
  bank_version: number
  ledger_version_a: number; ledger_version_b: number
  state: FitState
  created_at: string
  expires_at: string
  closed_at: string | null
  record_json: string | null
  record_digest: string | null
  receipt: string | null
}

export function createExchange(args: {
  id: string; intro_id: string; card_a: string; card_b: string; key_a: string; key_b: string;
  intent: string; expires_at: string; ledger_version_a: number; ledger_version_b: number
}): void {
  d().prepare(`INSERT INTO v3_fit_exchanges (id, intro_id, card_a, card_b, key_a, key_b, intent, bank_version, ledger_version_a, ledger_version_b, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    args.id, args.intro_id, args.card_a, args.card_b, args.key_a, args.key_b, args.intent, BANK_VERSION, args.ledger_version_a, args.ledger_version_b, args.expires_at,
  )
}

export function getExchange(id: string): ExchangeRow | null {
  const row = d().prepare('SELECT * FROM v3_fit_exchanges WHERE id = ?').get(id) as any
  return row ?? null
}

export function existsActiveExchangeForIntro(introId: string): boolean {
  return !!d().prepare("SELECT 1 FROM v3_fit_exchanges WHERE intro_id = ?").get(introId)
}

/** The counterpart card and key for a party in an exchange, or null if the key
 *  is not a party. */
export function counterpartOf(ex: ExchangeRow, key: string): { card: string; key: string } | null {
  if (key === ex.key_a) return { card: ex.card_b, key: ex.key_b }
  if (key === ex.key_b) return { card: ex.card_a, key: ex.key_a }
  return null
}
export function ownCardOf(ex: ExchangeRow, key: string): string | null {
  if (key === ex.key_a) return ex.card_a
  if (key === ex.key_b) return ex.card_b
  return null
}
export function isParty(ex: ExchangeRow, key: string): boolean {
  return key === ex.key_a || key === ex.key_b
}

export function setState(id: string, state: FitState): void {
  d().prepare('UPDATE v3_fit_exchanges SET state = ? WHERE id = ?').run(state, id)
}

export function closeExchange(id: string, recordJson: string, recordDigest: string, receipt: string): void {
  d().prepare(`UPDATE v3_fit_exchanges SET state = 'closed', closed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), record_json = ?, record_digest = ?, receipt = ? WHERE id = ?`)
    .run(recordJson, recordDigest, receipt, id)
}

export function expiredOpenExchanges(): ExchangeRow[] {
  return d().prepare(`SELECT * FROM v3_fit_exchanges WHERE state != 'closed' AND expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')`).all() as ExchangeRow[]
}

// ── Answers ────────────────────────────────────────────────────────────────

export interface AnswerRow {
  exchange_id: string; question_id: string; answerer_key: string
  mode: AnswerMode; ledger_id: string | null; text: string | null; created_at: string
}

export function upsertAnswer(a: { exchange_id: string; question_id: string; answerer_key: string; mode: AnswerMode; ledger_id?: string | null; text?: string | null }): void {
  d().prepare(`INSERT INTO v3_fit_answers (exchange_id, question_id, answerer_key, mode, ledger_id, text, created_at)
    VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    ON CONFLICT(exchange_id, question_id, answerer_key) DO UPDATE SET mode = excluded.mode, ledger_id = excluded.ledger_id, text = excluded.text, created_at = excluded.created_at`)
    .run(a.exchange_id, a.question_id, a.answerer_key, a.mode, a.ledger_id ?? null, a.text ?? null)
}

export function answersForExchange(exchangeId: string): AnswerRow[] {
  return d().prepare('SELECT * FROM v3_fit_answers WHERE exchange_id = ?').all(exchangeId) as AnswerRow[]
}

export function answersByKey(exchangeId: string, key: string): AnswerRow[] {
  return d().prepare('SELECT * FROM v3_fit_answers WHERE exchange_id = ? AND answerer_key = ?').all(exchangeId, key) as AnswerRow[]
}

// ── Round2 + custom ──────────────────────────────────────────────────────

export function addRound2(exchangeId: string, requesterKey: string, questionId: string): void {
  d().prepare('INSERT OR IGNORE INTO v3_fit_round2 (exchange_id, requester_key, question_id) VALUES (?, ?, ?)').run(exchangeId, requesterKey, questionId)
}
export function round2ForExchange(exchangeId: string): { requester_key: string; question_id: string; created_at: string }[] {
  return d().prepare('SELECT requester_key, question_id, created_at FROM v3_fit_round2 WHERE exchange_id = ?').all(exchangeId) as any[]
}

export function addCustom(id: string, exchangeId: string, askerKey: string, text: string): void {
  d().prepare('INSERT INTO v3_fit_custom (id, exchange_id, asker_key, text) VALUES (?, ?, ?, ?)').run(id, exchangeId, askerKey, text)
}
export function customForExchange(exchangeId: string): { id: string; asker_key: string; text: string; created_at: string }[] {
  return d().prepare('SELECT id, asker_key, text, created_at FROM v3_fit_custom WHERE exchange_id = ? ORDER BY created_at').all(exchangeId) as any[]
}
export function customCountByAsker(exchangeId: string, askerKey: string): number {
  return (d().prepare('SELECT COUNT(*) AS n FROM v3_fit_custom WHERE exchange_id = ? AND asker_key = ?').get(exchangeId, askerKey) as any).n
}
export function getCustom(exchangeId: string, customId: string): { asker_key: string; text: string } | null {
  const row = d().prepare('SELECT asker_key, text FROM v3_fit_custom WHERE exchange_id = ? AND id = ?').get(exchangeId, customId) as any
  return row ?? null
}
