// ══════════════════════════════════════════════════════════════
// The guards every v3 fit exchange write runs, canonical or adapted
// ══════════════════════════════════════════════════════════════
// The v3 fit exchange is its OWN resource. It has two parties, a 72 hour window, a
// state machine of its own, and it belongs to an intro without being one. So the
// intro guards in intro-guards.ts are the wrong question for it and these are the
// right one.
//
// Everything here reads and nothing writes, which is what lets a handler run all of
// it before its first side effect. Each check raises WriteRefusal, so it is only
// called from inside a canonical write transaction, where a refusal rolls everything
// back including the nonce reservation.
//
// The five conditions are the same five the legacy handlers already re-check at commit
// time, in the same order, taken from fit-routes.ts and gathered here so the two lanes
// cannot drift apart on which of them applies to which act.

import { refuseWrite } from './write-pipeline.js'
import * as fitDb from './fit-db.js'
import * as v3db from './v3-db.js'
import * as introsDb from './intros-db.js'

function cardActive(cardId: string, now: Date): boolean {
  const c = v3db.getV3Card(cardId)
  return !!c && c.revocation_status === 'active' && Date.parse(c.expires_at) > now.getTime()
}

/** Load an exchange for a WRITE by this actor, or refuse.
 *
 *  Existence first, then authorization, then state, so nothing about the exchange's
 *  state is disclosed to a caller who is not a party to it. */
export function exchangeForWrite(exchangeId: string, actorKey: string, now: Date): fitDb.ExchangeRow {
  const ex = fitDb.getExchange(exchangeId)
  if (!ex) refuseWrite(404, 'exchange_not_found', 'no such fit exchange')
  const row = ex as fitDb.ExchangeRow
  if (!fitDb.isParty(row, actorKey)) refuseWrite(403, 'not_a_party', 'not a party to this exchange')
  if (row.state === 'closed') refuseWrite(409, 'exchange_closed', 'this exchange is closed and accepts no further writes')
  if (Date.parse(row.expires_at) <= now.getTime()) refuseWrite(409, 'exchange_expired', 'this exchange window has expired')
  if (introsDb.isBlocked(row.card_a, row.card_b)) {
    refuseWrite(403, 'pair_blocked', 'this pair is blocked, so the exchange is closed to new writes')
  }
  if (!cardActive(row.card_a, now) || !cardActive(row.card_b, now)) {
    refuseWrite(409, 'card_unavailable', 'a card in this exchange has been withdrawn, superseded or expired')
  }
  return row
}
