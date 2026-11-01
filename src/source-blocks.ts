// Operator restriction on new writes from one network address, scoped and temporary.
//
// Keys are free, so hiding a key stops that key only. On 2026-11-01 the same address
// came back with a new key within hours. A restriction refuses only the operations
// that add something to the network or send mail:
//   publish        new cards, renew, replace
//   intro_request  new intro requests
//   subscribe      notification sign-ups (each one sends a confirmation email)
// Everything else stays open on purpose: search, card fetch, pages, withdraw, delete,
// revoke, stop, owner-read, and managing intros that already exist. A person behind a
// restricted address can always take their own data down.
//
// Every restriction carries a reason, an actor and an expiry (24 hours unless set),
// and expired rows stop applying without anyone removing them. The address is req.ip,
// the client address behind the two proxy hops app.ts trusts. Set only by an operator
// with shell access (scripts/moderate.mjs).

import { getDb } from './db.js'

export const RESTRICTION_SCOPES = ['publish', 'intro_request', 'subscribe'] as const
export type RestrictionScope = typeof RESTRICTION_SCOPES[number]
export const DEFAULT_RESTRICTION_HOURS = 24

let ready = false
function d() {
  const db = getDb()
  if (!ready) {
    db.exec(`CREATE TABLE IF NOT EXISTS v3_source_restrictions (
      ip TEXT PRIMARY KEY,
      scopes TEXT NOT NULL,
      reason TEXT NOT NULL,
      actor TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      expires_at TEXT NOT NULL
    )`)
    ready = true
  }
  return db
}

export interface Restriction { ip: string; scopes: RestrictionScope[]; reason: string; actor: string; created_at: string; expires_at: string }

function rowToRestriction(r: any): Restriction {
  return { ...r, scopes: String(r.scopes).split(',') as RestrictionScope[] }
}

/** The live restriction on an address, if any (expired rows do not count). */
export function activeRestriction(ip: string | undefined, nowMs = Date.now()): Restriction | null {
  if (!ip) return null
  const r = d().prepare('SELECT * FROM v3_source_restrictions WHERE ip = ? AND expires_at > ?').get(ip, new Date(nowMs).toISOString())
  return r ? rowToRestriction(r) : null
}

export function isRestricted(ip: string | undefined, scope: RestrictionScope, nowMs = Date.now()): boolean {
  return !!activeRestriction(ip, nowMs)?.scopes.includes(scope)
}

export function restrictSource(ip: string, reason: string, actor: string, opts: { hours?: number; scopes?: RestrictionScope[]; nowMs?: number } = {}): Restriction {
  const scopes = opts.scopes ?? [...RESTRICTION_SCOPES]
  const hours = opts.hours ?? DEFAULT_RESTRICTION_HOURS
  if (!ip.trim() || !reason.trim() || !actor.trim()) throw new Error('ip, reason and actor are required')
  if (!(hours > 0 && hours <= 24 * 30)) throw new Error('hours must be between 0 and 720')
  if (scopes.length === 0 || scopes.some(s => !RESTRICTION_SCOPES.includes(s))) throw new Error(`scopes must be among ${RESTRICTION_SCOPES.join(', ')}`)
  const now = opts.nowMs ?? Date.now()
  const expires = new Date(now + hours * 3600 * 1000).toISOString()
  d().prepare(`INSERT INTO v3_source_restrictions (ip, scopes, reason, actor, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET scopes = excluded.scopes, reason = excluded.reason, actor = excluded.actor, created_at = excluded.created_at, expires_at = excluded.expires_at`)
    .run(ip.trim(), scopes.join(','), reason, actor, new Date(now).toISOString(), expires)
  return activeRestriction(ip.trim(), now)!
}

export function liftRestriction(ip: string): boolean {
  return d().prepare('DELETE FROM v3_source_restrictions WHERE ip = ?').run(ip.trim()).changes === 1
}

export function listRestrictions(): Restriction[] {
  return (d().prepare('SELECT * FROM v3_source_restrictions ORDER BY created_at').all() as any[]).map(rowToRestriction)
}

/** Route middleware: refuse this one operation from a restricted address. */
export function unlessRestricted(scope: RestrictionScope) {
  return (req: any, res: any, next: any): void => {
    const r = activeRestriction(req.ip)
    if (r?.scopes.includes(scope)) {
      res.status(403).json({ error: `new ${scope.replace('_', ' ')} operations from this network address are paused by the operator until ${r.expires_at}; withdrawing or deleting your own cards still works` })
      return
    }
    next()
  }
}
