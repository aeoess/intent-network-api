// Limits on notification confirmation emails. Each sign-up makes Mingle send one
// email to an address the caller names. On 2026-11-01 the probe client used that to
// send 28 confirmation emails to addresses it chose: 23 on reserved test domains that
// can never receive mail (they bounce and cost the sending domain reputation), and 5
// to real-looking addresses of other people, one of them delivered.
//
// Keys are free, so no per-key limit bounds this on its own. Every confirmation is
// reserved in one transaction that checks, in order:
//   reserved test domain              refused
//   same address within 10 minutes    held (prefs saved, no email, old link valid)
//   same address twice in 24 hours    held for the same key, refused for another key
//   one key, 3 addresses in 24 hours  refused
//   one client address, across keys   MINGLE_CONFIRMS_PER_SOURCE_PER_DAY (10)
//   whole service, per hour           MINGLE_CONFIRMS_PER_HOUR (30)
// and only then writes the reservation, before the mail provider is called. A send
// that fails gives its reservation back. Loopback is the operator and skips the
// per-source limit only. Publishing a card never depends on any of this.
// Addresses are stored only as a hash here.

import { createHash } from 'node:crypto'
import { getDb } from './db.js'

export const CONFIRMS_PER_ADDRESS_PER_DAY = 2
export const ADDRESSES_PER_KEY_PER_DAY = 3
export const RESEND_COOLDOWN_MS = 10 * 60 * 1000
export const confirmsPerSourcePerDay = () => Number(process.env.MINGLE_CONFIRMS_PER_SOURCE_PER_DAY ?? 10)
export const confirmsPerHour = () => Number(process.env.MINGLE_CONFIRMS_PER_HOUR ?? 30)

let ready = false
function d() {
  const db = getDb()
  if (!ready) {
    db.exec(`CREATE TABLE IF NOT EXISTS v3_confirm_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      subject_key TEXT NOT NULL,
      addr_hash TEXT NOT NULL,
      ip TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_confirm_log_addr ON v3_confirm_log(addr_hash, at);
    CREATE INDEX IF NOT EXISTS idx_confirm_log_key ON v3_confirm_log(subject_key, at);
    CREATE INDEX IF NOT EXISTS idx_confirm_log_ip ON v3_confirm_log(ip, at);
    CREATE INDEX IF NOT EXISTS idx_confirm_log_at ON v3_confirm_log(at);
    CREATE TABLE IF NOT EXISTS v3_confirm_allowances (
      ip TEXT PRIMARY KEY,
      per_day INTEGER NOT NULL,
      reason TEXT NOT NULL,
      actor TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );`)
    ready = true
  }
  return db
}

// An operator allowance raises the daily per-address limit for one client address,
// for example an event on venue wifi where many attendees sign up for email. It has a
// reason, an actor and an expiry (24 hours unless set), and stops applying on its own.
// Inside its own per-day cap, that address is not held to the service-wide hourly budget.
export function allowSourceEmail(ip: string, perDay: number, reason: string, actor: string, opts: { hours?: number; nowMs?: number } = {}) {
  const hours = opts.hours ?? 24
  if (!ip.trim() || !reason.trim() || !actor.trim()) throw new Error('ip, reason and actor are required')
  if (!(perDay > 0 && perDay <= 1000)) throw new Error('per_day must be between 1 and 1000')
  if (!(hours > 0 && hours <= 24 * 14)) throw new Error('hours must be between 0 and 336')
  const now = opts.nowMs ?? Date.now()
  d().prepare(`INSERT INTO v3_confirm_allowances (ip, per_day, reason, actor, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET per_day = excluded.per_day, reason = excluded.reason, actor = excluded.actor, created_at = excluded.created_at, expires_at = excluded.expires_at`)
    .run(ip.trim(), perDay, reason, actor, new Date(now).toISOString(), new Date(now + hours * 3600 * 1000).toISOString())
  return activeAllowance(ip.trim(), now)
}
export function activeAllowance(ip: string | undefined, nowMs = Date.now()): { ip: string; per_day: number; reason: string; actor: string; expires_at: string } | null {
  if (!ip) return null
  return (d().prepare('SELECT ip, per_day, reason, actor, expires_at FROM v3_confirm_allowances WHERE ip = ? AND expires_at > ?').get(ip, new Date(nowMs).toISOString()) as any) ?? null
}
export function liftAllowance(ip: string): boolean {
  return d().prepare('DELETE FROM v3_confirm_allowances WHERE ip = ?').run(ip.trim()).changes === 1
}
export function listAllowances() {
  return d().prepare('SELECT * FROM v3_confirm_allowances ORDER BY created_at').all()
}

const hashAddr = (addr: string) => createHash('sha256').update(addr.trim().toLowerCase()).digest('hex')
const isLoopback = (ip?: string) => !ip || ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1'

/** RFC 2606 and RFC 6761 names that can never receive mail. */
export function isReservedDomain(addr: string): boolean {
  const domain = addr.trim().toLowerCase().split('@').pop() ?? ''
  if (/\.(example|test|invalid|localhost)$/.test(domain) || ['example', 'test', 'invalid', 'localhost'].includes(domain)) return true
  return /(^|\.)example\.(com|net|org)$/.test(domain)
}

export type ConfirmDecision =
  | { ok: true; id: number }
  | { ok: false; hold: true; reason: string }
  | { ok: false; hold: false; reason: string }

/** Check every limit and reserve one confirmation, atomically. A 'hold' means the
 *  same key asked again for the same address: save its prefs, send nothing. */
export function reserveConfirm(subjectKey: string, addr: string, ip: string | undefined, nowMs = Date.now()): ConfirmDecision {
  const allowReserved = process.env.MINGLE_ALLOW_RESERVED_EMAIL_DOMAINS === '1'
  if (!allowReserved && isReservedDomain(addr)) return { ok: false, hold: false, reason: 'this address is on a reserved test domain that cannot receive mail' }
  const db = d()
  const h = hashAddr(addr)
  const day = new Date(nowMs - 24 * 3600 * 1000).toISOString()
  const hour = new Date(nowMs - 3600 * 1000).toISOString()
  const cool = new Date(nowMs - RESEND_COOLDOWN_MS).toISOString()
  const n = (sql: string, ...p: unknown[]) => (db.prepare(sql).get(...p) as any).n as number
  return db.transaction((): ConfirmDecision => {
    const sameKeyAddr = n('SELECT COUNT(*) n FROM v3_confirm_log WHERE addr_hash = ? AND subject_key = ? AND at > ?', h, subjectKey, day) > 0
    if (n('SELECT COUNT(*) n FROM v3_confirm_log WHERE addr_hash = ? AND at > ?', h, cool) > 0) {
      return sameKeyAddr ? { ok: false, hold: true, reason: 'cooldown' } : { ok: false, hold: false, reason: 'a confirmation was just sent to this address; use the link in that email' }
    }
    if (n('SELECT COUNT(*) n FROM v3_confirm_log WHERE addr_hash = ? AND at > ?', h, day) >= CONFIRMS_PER_ADDRESS_PER_DAY) {
      return sameKeyAddr ? { ok: false, hold: true, reason: 'address_daily' } : { ok: false, hold: false, reason: 'this address already got its confirmations for today; use the link in that email' }
    }
    const named = db.prepare('SELECT DISTINCT addr_hash FROM v3_confirm_log WHERE subject_key = ? AND at > ?').all(subjectKey, day) as { addr_hash: string }[]
    if (named.length >= ADDRESSES_PER_KEY_PER_DAY && !named.some(r => r.addr_hash === h)) {
      return { ok: false, hold: false, reason: `one key can ask for confirmation of at most ${ADDRESSES_PER_KEY_PER_DAY} different addresses per 24 hours` }
    }
    const allowance = activeAllowance(ip, nowMs)
    const perSource = Math.max(confirmsPerSourcePerDay(), allowance?.per_day ?? 0)
    if (!isLoopback(ip) && n('SELECT COUNT(*) n FROM v3_confirm_log WHERE ip = ? AND at > ?', ip, day) >= perSource) {
      return { ok: false, hold: false, reason: 'too many confirmation emails requested from this network address today' }
    }
    // An address with an operator allowance is bounded by that allowance instead of the
    // service-wide hourly budget, which an event alone could otherwise use up.
    if (!allowance && n('SELECT COUNT(*) n FROM v3_confirm_log WHERE at > ?', hour) >= confirmsPerHour()) {
      return { ok: false, hold: false, reason: 'Mingle is sending too many confirmation emails right now; try again in an hour' }
    }
    const r = db.prepare('INSERT INTO v3_confirm_log (at, subject_key, addr_hash, ip) VALUES (?, ?, ?, ?)').run(new Date(nowMs).toISOString(), subjectKey, h, ip ?? null)
    return { ok: true, id: Number(r.lastInsertRowid) }
  })()
}

/** A send that did not happen gives its reservation back. */
export function releaseConfirm(id: number): void {
  d().prepare('DELETE FROM v3_confirm_log WHERE id = ?').run(id)
}

/** True once the hourly service budget is used up, for the admin alert. */
export function hourlyBudgetUsed(nowMs = Date.now()): boolean {
  return (d().prepare('SELECT COUNT(*) n FROM v3_confirm_log WHERE at > ?').get(new Date(nowMs - 3600 * 1000).toISOString()) as any).n >= confirmsPerHour()
}
