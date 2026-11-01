// Limits for signed operations that many people may run from one network address,
// such as an event on venue wifi. Each person gets their own allowance, keyed by the
// signing key the request names together with the client address, and the address as
// a whole has a much larger cap that only a flood reaches.
//
// Why key plus address and not key alone: the limit runs before the signature is
// checked, so a request can name someone else's public key. Pairing the key with the
// sender's address means such requests spend the sender's own allowance, never the
// named person's. Loopback is the operator and skips the address cap.

import { checkRateLimit } from './db.js'

const isLoopback = (ip?: string) => !ip || ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1'

export interface KeyedLimit { action: string; perKey: number; perSource: number; keyOf: (req: any) => string | undefined }

export const INTRO_REQUEST_LIMIT: Omit<KeyedLimit, 'keyOf'> = { action: 'intro_request', perKey: 20, perSource: 200 }
export const INTRO_MINE_LIMIT: Omit<KeyedLimit, 'keyOf'> = { action: 'intro_mine', perKey: 60, perSource: 600 }
export const SUBSCRIBE_LIMIT: Omit<KeyedLimit, 'keyOf'> = { action: 'notif_subscribe', perKey: 10, perSource: 100 }

export function keyedLimit(l: KeyedLimit) {
  return (req: any, res: any, next: any): void => {
    const ip = req.ip || 'anon'
    const key = String(l.keyOf(req) ?? '').slice(0, 200)
    if (!isLoopback(req.ip) && !checkRateLimit(`src:${ip}`, `${l.action}_src`, l.perSource).allowed) {
      res.status(429).json({ error: 'Rate limit exceeded for this network address' }); return
    }
    if (!checkRateLimit(`k:${key}:${ip}`, l.action, l.perKey).allowed) {
      res.status(429).json({ error: 'Rate limit exceeded' }); return
    }
    next()
  }
}
