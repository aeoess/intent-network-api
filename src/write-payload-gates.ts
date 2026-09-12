// ══════════════════════════════════════════════════════════════
// The payload gates every canonical handler runs, in one place
// ══════════════════════════════════════════════════════════════
// Three small checks, shared rather than duplicated. They were local to
// fit-v4-routes.ts while only the v4 handlers needed them. The v3 fit exchange
// handlers need exactly the same rules, and two copies of "an unknown payload key is
// refused rather than dropped" is two places for that rule to drift, which would show
// as one lane accepting a field the other refuses.
//
// Every one of them raises WriteRefusal, so they are only ever called from inside a
// canonical write transaction, where a refusal rolls everything back.

import { refuseWrite } from './write-pipeline.js'

const HEX64_RE = /^[0-9a-f]{64}$/

/** A string list a principal signed: non empty, sorted by code unit, no duplicates,
 *  optionally capped.
 *
 *  Sorting it here would be a repair AFTER approval, so an unsorted list is refused
 *  instead. The principal signed an order and the server does not get to improve it. */
export function gateStringList(value: unknown, field: string, max?: number): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    refuseWrite(400, 'malformed_payload', `${field} must be a non empty array`)
  }
  const list = value as unknown[]
  if (!list.every(x => typeof x === 'string' && x.length > 0)) {
    refuseWrite(400, 'malformed_payload', `${field} must contain only non empty strings`)
  }
  const strings = list as string[]
  if (max !== undefined && strings.length > max) {
    refuseWrite(400, 'malformed_payload', `${field} carries ${strings.length} entries and the cap is ${max}`)
  }
  for (let i = 1; i < strings.length; i++) {
    if (strings[i - 1] === strings[i]) refuseWrite(400, 'malformed_payload', `${field} contains a duplicate`)
    if (strings[i - 1] > strings[i]) refuseWrite(400, 'malformed_payload', `${field} must be sorted by code unit`)
  }
  return strings
}

export function gateHex64(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64_RE.test(value)) {
    refuseWrite(400, 'malformed_payload', `${field} must be 64 lowercase hex characters`)
  }
  return value as string
}

/** Exactly these keys, plus optionally these. A field inside payload_digest that the
 *  server ignores is a field the signature says the principal asked for and the server
 *  did not honour, so an unknown one is refused rather than dropped. */
export function gatePayloadKeys(payload: Record<string, unknown>, required: string[], optional: string[] = []): void {
  const present = Object.keys(payload)
  for (const k of required) {
    if (!present.includes(k)) refuseWrite(400, 'malformed_payload', `payload is missing ${k}`)
  }
  const allowed = new Set([...required, ...optional])
  const extra = present.filter(k => !allowed.has(k))
  if (extra.length > 0) refuseWrite(400, 'malformed_payload', `unexpected payload field: ${extra.join(', ')}`)
}
