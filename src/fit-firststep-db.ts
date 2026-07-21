// ══════════════════════════════════════════════════════════════
// Mingle v4 fit - First Step artifact (additive)
// ══════════════════════════════════════════════════════════════
// After fit, each side drafts (from its own approved material) half of a
// proposed first conversation. The shared artifact is the two halves together,
// and it is final only when BOTH humans exact-approve the same merged content,
// mirroring the contact-line mutual-approval pattern. Neither half is sent as
// final on its own.

import type { Database } from 'better-sqlite3'
import { createHash } from 'node:crypto'
import { canonicalize } from 'agent-passport-system'
import { getDb } from './db.js'
import { hasEuphemism } from './fit-schema.js'

let initialized = false

export function initFirstStepSchema(): void {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS v4_fit_first_step (
      intro_id TEXT PRIMARY KEY,
      half_a_key TEXT, half_a_json TEXT, a_approved INTEGER NOT NULL DEFAULT 0,
      half_b_key TEXT, half_b_json TEXT, b_approved INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
  `)
  initialized = true
}

function d(): Database {
  if (!initialized) initFirstStepSchema()
  return getDb()
}

export interface FirstStepHalf {
  purpose: string
  next_action: string
  meeting_length: string
  agenda: string[]
  each_wants: string
  boundaries: string[]
  expiry: string
}

const isIso = (s: unknown): s is string => typeof s === 'string' && !Number.isNaN(Date.parse(s))
const isStr = (s: unknown, max: number): s is string => typeof s === 'string' && s.length > 0 && s.length <= max

/** Validate a proposed half. Returns the free-text fields so the route can run
 *  them through the shared post-gate (contact-data/URL/allegation). */
export function validateHalf(half: unknown): { ok: boolean; error?: string; half?: FirstStepHalf; texts?: string[] } {
  const h = half as any
  if (!h || typeof h !== 'object') return { ok: false, error: 'first-step half required' }
  if (!isStr(h.purpose, 200)) return { ok: false, error: 'purpose required (max 200)' }
  if (!isStr(h.next_action, 200)) return { ok: false, error: 'next_action required (max 200)' }
  if (!isStr(h.meeting_length, 40)) return { ok: false, error: 'meeting_length required (max 40)' }
  if (!isStr(h.each_wants, 300)) return { ok: false, error: 'each_wants required (max 300)' }
  if (!Array.isArray(h.agenda) || h.agenda.length > 5 || h.agenda.some((x: any) => !isStr(x, 200))) return { ok: false, error: 'agenda must be up to 5 short items' }
  if (!Array.isArray(h.boundaries) || h.boundaries.length > 5 || h.boundaries.some((x: any) => !isStr(x, 200))) return { ok: false, error: 'boundaries must be up to 5 short items' }
  if (!isIso(h.expiry)) return { ok: false, error: 'expiry must be ISO' }
  const texts = [h.purpose, h.next_action, h.each_wants, ...h.agenda, ...h.boundaries]
  if (texts.some((t: string) => hasEuphemism(t))) return { ok: false, error: 'first-step content may not use consequential-eligibility language' }
  const clean: FirstStepHalf = { purpose: h.purpose, next_action: h.next_action, meeting_length: h.meeting_length, agenda: h.agenda, each_wants: h.each_wants, boundaries: h.boundaries, expiry: h.expiry }
  return { ok: true, half: clean, texts }
}

export interface FirstStepRow {
  intro_id: string
  half_a_key: string | null; half_a_json: string | null; a_approved: number
  half_b_key: string | null; half_b_json: string | null; b_approved: number
}

export function getFirstStep(introId: string): FirstStepRow | null {
  return (d().prepare('SELECT * FROM v4_fit_first_step WHERE intro_id = ?').get(introId) as any) ?? null
}

/** Store (or replace) a side's half. Proposing again resets that side's approval
 *  and the counterparty's approval, since the shared content changed. */
export function proposeHalf(introId: string, isA: boolean, key: string, half: FirstStepHalf): void {
  const dd = d()
  dd.prepare('INSERT OR IGNORE INTO v4_fit_first_step (intro_id) VALUES (?)').run(introId)
  if (isA) {
    dd.prepare(`UPDATE v4_fit_first_step SET half_a_key = ?, half_a_json = ?, a_approved = 0, b_approved = 0, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE intro_id = ?`).run(key, JSON.stringify(half), introId)
  } else {
    dd.prepare(`UPDATE v4_fit_first_step SET half_b_key = ?, half_b_json = ?, a_approved = 0, b_approved = 0, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE intro_id = ?`).run(key, JSON.stringify(half), introId)
  }
}

/** Digest of the merged shared artifact (both halves). Approval binds this. */
export function sharedDigest(row: FirstStepRow): string | null {
  if (!row.half_a_json || !row.half_b_json) return null
  const shared = { a: JSON.parse(row.half_a_json), b: JSON.parse(row.half_b_json) }
  return createHash('sha256').update(canonicalize(shared), 'utf8').digest('hex')
}

export function approve(introId: string, isA: boolean): void {
  const col = isA ? 'a_approved' : 'b_approved'
  d().prepare(`UPDATE v4_fit_first_step SET ${col} = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE intro_id = ?`).run(introId)
}

export function isFinalized(row: FirstStepRow): boolean {
  return !!row.half_a_json && !!row.half_b_json && row.a_approved === 1 && row.b_approved === 1
}
