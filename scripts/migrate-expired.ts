// ══════════════════════════════════════════════════════════════
// One-time migration: rows the old sweep marked 'withdrawn' -> 'expired'
// ══════════════════════════════════════════════════════════════
// Before this pass the expiry sweep wrote 'withdrawn', so a card that simply
// lapsed is indistinguishable from one the principal deliberately pulled. The
// one signal left in the row is updated_at: the sweep can only touch a row whose
// expires_at has already passed, so it always stamps updated_at AFTER
// expires_at, while a principal withdrawing a live card stamps it BEFORE.
//
// Blind spot, stated rather than hidden: a principal who withdrew a card that
// had ALREADY lapsed also has updated_at > expires_at and is moved. Nothing in
// the row can tell those apart. Going forward the card_events ledger records
// which verb ran, so this ambiguity does not recur.
//
// Dry run by default. Pass --apply to write.
//   DB_PATH=/path/to.db npx tsx scripts/migrate-expired.ts
//   DB_PATH=/path/to.db npx tsx scripts/migrate-expired.ts --apply

import { getDb, closeDb } from '../src/db.js'
import { initV3Schema, migrateSweptWithdrawnToExpired } from '../src/v3-db.js'

const apply = process.argv.includes('--apply')

getDb()
initV3Schema()

const before = getDb().prepare('SELECT revocation_status, COUNT(*) AS n FROM v3_cards GROUP BY 1 ORDER BY 1').all()
console.log('DB_PATH:', process.env.DB_PATH ?? '(default data/intent-network.db)')
console.log('before:', JSON.stringify(before))

const result = migrateSweptWithdrawnToExpired({ dryRun: !apply })
console.log(apply ? 'APPLIED' : 'DRY RUN')
console.log('  moved to expired  :', result.moved)
console.log('  kept withdrawn    :', result.kept_withdrawn)
console.log('  moved card_ids    :', JSON.stringify(result.moved_card_ids))
console.log('  kept  card_ids    :', JSON.stringify(result.kept_card_ids))

const after = getDb().prepare('SELECT revocation_status, COUNT(*) AS n FROM v3_cards GROUP BY 1 ORDER BY 1').all()
console.log('after:', JSON.stringify(after))
if (!apply) console.log('\nNothing was written. Re-run with --apply to migrate.')
closeDb()
