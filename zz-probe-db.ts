import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
process.env.DB_PATH = join(mkdtempSync(join(tmpdir(), 'zzprobe-')), 'p.db')

const db = await import('./src/db.js')
const introsDb = await import('./src/intros-db.js')
const writeDb = await import('./src/write-db.js')
const facts = await import('./src/connection-facts.js')

introsDb.initIntrosSchema()
writeDb.initWriteSchema()
const d = db.getDb()

const day = (n: number) => new Date(Date.now() - n * 86400_000).toISOString()

function seed(id: string, status: string, createdDaysAgo: number, fromContact: string | null, toContact: string | null) {
  d.prepare(`INSERT INTO v3_intros (id, from_card, to_card, from_key, to_key, purpose, note, status, created_at, from_contact, to_contact)
             VALUES (?,?,?,?,?,'work','',?,?,?,?)`)
    .run(id, `card-${id}-a`, `card-${id}-b`, `key-${id}-req`, `key-${id}-tgt`, status, day(createdDaysAgo), fromContact, toContact)
}

const st = (id: string) => (d.prepare('SELECT status FROM v3_intros WHERE id = ?').get(id) as any).status

// ══════════════════════════════════════════════════════════════
// A: the sweep flips a COMPLETED pre-2A connection from accepted to withdrawn
// ══════════════════════════════════════════════════════════════
console.log('== FINDING A (durable half) ==')
seed('L1', 'accepted', 60, 'requester@example.com', 'target@example.com')
console.log(' seeded: status =', st('L1'), '| both contact columns set | zero authorization rows | created 60d ago')
console.log(' isReleased        =', facts.isReleased('L1'))
console.log(' legacyComplete    =', facts.legacyComplete('L1'))
console.log(' contactsExchanged =', facts.contactsExchanged('L1'))
console.log(' stateOf           =', facts.stateOf('L1'))
const swept = facts.sweepExpiredIntros()
console.log(' sweepExpiredIntros() returned', swept)
console.log(' AFTER SWEEP: status =', st('L1'))
console.log('   from_contact/to_contact still =', d.prepare('SELECT from_contact, to_contact FROM v3_intros WHERE id = ?').get('L1'))
console.log('   legacyComplete    =', facts.legacyComplete('L1'), '  <- was true')
console.log('   contactsExchanged =', facts.contactsExchanged('L1'), '  <- was true')
console.log(' sweep is idempotent-destructive: second run =', facts.sweepExpiredIntros())

// ══════════════════════════════════════════════════════════════
// C: materializeStatus resets a legacy 'accepted' intro back to 'pending'
// ══════════════════════════════════════════════════════════════
console.log('\n== FINDING C (durable half) ==')
// A pre-2A intro: created before the 2A marker, so no request_intro row exists.
db.stamp2ADeployMarkerOnce()
seed('L2', 'pending', 40, null, null)
console.log(' isPre2AIntro(L2) =', facts.isPre2AIntro('L2'), ' (marker =', db.getSchemaMarker(db.MINGLE_2A_MARKER_KEY), ')')
console.log(' grandfatheredRequestOpen before the accept =', facts.grandfatheredRequestOpen('L2'))
// The legacy /respond accept adapter, verbatim in effect (intros-routes.ts:364-368):
d.prepare(`INSERT INTO write_evidence (evidence_id, actor_key, operation, resource_type, resource_id, evidence, signature, bound_fields_json)
           VALUES ('ev-L2','key-L2-tgt','express_interest','intro','L2','legacy_unbound','sig','["operation","resource.id"]')`).run()
d.prepare("UPDATE v3_intros SET status = 'accepted', to_contact = 'target@example.com' WHERE id = 'L2'").run()
facts.recordAuthorization({ introId: 'L2', actorKey: 'key-L2-tgt', operation: 'express_interest', evidenceId: 'ev-L2', evidence: 'legacy_unbound' })
facts.recordAuthorization({ introId: 'L2', actorKey: 'key-L2-tgt', operation: 'share_contact', evidenceId: 'ev-L2', evidence: 'legacy_unbound' })
console.log(' after the legacy accept: status =', st('L2'), '| stateOf =', facts.stateOf('L2'))
console.log(' grandfatheredRequestOpen after the accept =', facts.grandfatheredRequestOpen('L2'), ' (so canonical withdraw_request is refused no_open_request)')
console.log(' introProjection(requester) =', JSON.stringify(facts.introProjection('L2', 'key-L2-req')))
// Any canonical write on this intro ends with materializeStatus. The target
// re-expressing interest is admitted by the guard matrix in state `requested`.
const state = facts.materializeStatus('L2')
console.log(' materializeStatus() derived', state, '-> status is now', st('L2'), ' <- was accepted')
console.log('   to_contact still =', (d.prepare('SELECT to_contact FROM v3_intros WHERE id = ?').get('L2') as any).to_contact)
console.log('   hasPendingBetween now sees it as pending again:',
  introsDb.hasPendingBetween('card-L2-a', 'card-L2-b'))
