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
import { evidenceByWriteRef } from './write-evidence.js'

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

/** The act this one follows must be a real recorded act on the SAME resource.
 *
 *  What an antecedent reference buys, given that resource.id is already inside the
 *  signed envelope: it says WHICH state of the conversation the signer was answering.
 *  Without it one signature over a set of question ids stands for the same escalation
 *  at any later point in the exchange, and the signer cannot tell those apart.
 *
 *  Checked by resolution rather than accepted as an opaque string, because an opaque
 *  string copied into evidence is a field that looks like a check and is not. */
export function requireAntecedent(resourceType: string, resourceId: string, writeRef: string): void {
  const row = evidenceByWriteRef(writeRef)
  if (row === null) {
    refuseWrite(400, 'unknown_antecedent',
      'antecedent_write_ref names no write this server recorded')
  }
  const ev = row as { resource_type: string; resource_id: string }
  if (ev.resource_type !== resourceType || ev.resource_id !== resourceId) {
    refuseWrite(400, 'antecedent_other_resource',
      'antecedent_write_ref names an act on a different resource, so it cannot place this one in a conversation')
  }
}
