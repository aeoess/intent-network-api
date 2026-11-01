// Operator block on writes from one network address. Keys are free, so hiding a key
// stops that key only; on 2026-11-01 the same address came back with a new key within
// hours. A blocked address can still GET (card fetch, pages, health), but every POST,
// PUT, PATCH or DELETE under /api gets a plain 403. That includes search, which is a
// POST. Set only by an operator with shell
// access (scripts/moderate.mjs). The address is req.ip, which is the client address
// because app.ts trusts exactly the two proxy hops in front of the app.

import { getDb } from './db.js'

let ready = false
function d() {
  const db = getDb()
  if (!ready) {
    db.exec(`CREATE TABLE IF NOT EXISTS v3_blocked_sources (
      ip TEXT PRIMARY KEY,
      reason TEXT NOT NULL,
      actor TEXT NOT NULL,
      at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    )`)
    ready = true
  }
  return db
}

export function isSourceBlocked(ip: string | undefined): boolean {
  if (!ip) return false
  return !!d().prepare('SELECT 1 FROM v3_blocked_sources WHERE ip = ?').get(ip)
}

export function blockSource(ip: string, reason: string, actor: string): boolean {
  if (!ip.trim() || !reason.trim() || !actor.trim()) throw new Error('ip, reason and actor are required')
  return d().prepare('INSERT OR IGNORE INTO v3_blocked_sources (ip, reason, actor) VALUES (?, ?, ?)').run(ip.trim(), reason, actor).changes === 1
}

export function unblockSource(ip: string): boolean {
  return d().prepare('DELETE FROM v3_blocked_sources WHERE ip = ?').run(ip.trim()).changes === 1
}

export function listBlockedSources(): { ip: string; reason: string; actor: string; at: string }[] {
  return d().prepare('SELECT * FROM v3_blocked_sources ORDER BY at').all() as any[]
}

const WRITE_METHODS = new Set(['POST', 'PUT', 'DELETE', 'PATCH'])

/** Express middleware: refuse writes under /api from a blocked address. */
export function blockedSourceWrites(req: any, res: any, next: any): void {
  if (WRITE_METHODS.has(req.method) && String(req.path).startsWith('/api') && isSourceBlocked(req.ip)) {
    res.status(403).json({ error: 'writes from this network address are blocked by the operator' })
    return
  }
  next()
}
