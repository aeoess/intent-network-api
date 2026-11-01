// Limits on notification confirmation emails. Each sign-up makes Mingle send one
// email to an address the caller names. On 2026-11-01 the probe client used that to
// send 28 confirmation emails to addresses it chose: 23 on reserved test domains that
// can never receive mail (they bounce and cost the sending domain reputation), and 5
// to real-looking addresses of other people, one of them delivered.
//
// The guard refuses reserved domains outright, sends at most one confirmation to an
// address at most twice per 24 hours whoever asks, and lets one key name at most 3 different
// addresses per 24 hours. A real person confirming their own address once is never
// affected. Addresses are stored only as a hash here.

import { createHash } from 'node:crypto'
import { getDb } from './db.js'

// Two, so a person whose first confirmation landed in spam can ask once more.
export const CONFIRMS_PER_ADDRESS_PER_DAY = 2
export const ADDRESSES_PER_KEY_PER_DAY = 3

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
    CREATE INDEX IF NOT EXISTS idx_confirm_log_key ON v3_confirm_log(subject_key, at);`)
    ready = true
  }
  return db
}

const hashAddr = (addr: string) => createHash('sha256').update(addr.trim().toLowerCase()).digest('hex')

/** RFC 2606 and RFC 6761 names that can never receive mail. */
export function isReservedDomain(addr: string): boolean {
  const domain = addr.trim().toLowerCase().split('@').pop() ?? ''
  if (/\.(example|test|invalid|localhost)$/.test(domain) || ['example', 'test', 'invalid', 'localhost'].includes(domain)) return true
  return /(^|\.)example\.(com|net|org)$/.test(domain)
}

/** Why a confirmation to this address may not be sent now, or null if it may. */
export function confirmRefusal(subjectKey: string, addr: string, nowMs = Date.now()): string | null {
  // The test suite sends to example.com through a mock mailer, so it sets this
  // explicitly. Production never sets it.
  const allowReserved = process.env.MINGLE_ALLOW_RESERVED_EMAIL_DOMAINS === '1'
  if (!allowReserved && isReservedDomain(addr)) return 'this address is on a reserved test domain that cannot receive mail'
  const since = new Date(nowMs - 24 * 3600 * 1000).toISOString()
  const h = hashAddr(addr)
  const toAddr = (d().prepare('SELECT COUNT(*) n FROM v3_confirm_log WHERE addr_hash = ? AND at > ?').get(h, since) as any).n
  if (toAddr >= CONFIRMS_PER_ADDRESS_PER_DAY) return 'a confirmation was already sent to this address in the last 24 hours; use the link in that email'
  const named = d().prepare('SELECT DISTINCT addr_hash FROM v3_confirm_log WHERE subject_key = ? AND at > ?').all(subjectKey, since) as { addr_hash: string }[]
  if (named.length >= ADDRESSES_PER_KEY_PER_DAY && !named.some(r => r.addr_hash === h)) return `one key can ask for confirmation of at most ${ADDRESSES_PER_KEY_PER_DAY} different addresses per 24 hours`
  return null
}

export function recordConfirm(subjectKey: string, addr: string, ip: string | undefined, nowMs = Date.now()): void {
  d().prepare('INSERT INTO v3_confirm_log (at, subject_key, addr_hash, ip) VALUES (?, ?, ?, ?)').run(new Date(nowMs).toISOString(), subjectKey, hashAddr(addr), ip ?? null)
}
