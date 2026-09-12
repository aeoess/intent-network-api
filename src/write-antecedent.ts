// ══════════════════════════════════════════════════════════════
// antecedent_write_ref: the act this one follows
// ══════════════════════════════════════════════════════════════
// Its own module because it is resource generic. A v3 exchange act names a prior act on
// that exchange and a v4 round two names a prior act on that intro, and the check is the
// same either way, so it belongs to neither module's guards.
//
// WHAT IT BUYS, given that resource.id is already inside the signed envelope: it says
// WHICH state of the conversation the signer was answering. Without it one signature over
// a set of ids stands for the same escalation at any later point in that conversation, and
// the signer has no way to tell those apart.
//
// Checked by RESOLUTION rather than accepted as an opaque string, because an opaque string
// copied into evidence is a field that looks like a check and is not.

import { refuseWrite } from './write-pipeline.js'
import { evidenceByWriteRef } from './write-evidence.js'

export function requireAntecedent(resourceType: string, resourceId: string, writeRef: string): void {
  const row = evidenceByWriteRef(writeRef)
  if (row === null) {
    refuseWrite(400, 'unknown_antecedent', 'antecedent_write_ref names no write this server recorded')
  }
  const ev = row as { resource_type: string; resource_id: string }
  if (ev.resource_type !== resourceType || ev.resource_id !== resourceId) {
    refuseWrite(400, 'antecedent_other_resource',
      'antecedent_write_ref names an act on a different resource, so it cannot place this one in a conversation')
  }
}
