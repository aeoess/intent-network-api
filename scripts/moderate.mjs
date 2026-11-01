// Operator moderation, run on the server with shell access. Dry run unless --apply.
//
//   node scripts/moderate.mjs list
//   node scripts/moderate.mjs hide subject <subject_key> "<reason>" <actor> [--apply]
//   node scripts/moderate.mjs hide card <card_id> "<reason>" <actor> [--apply]
//   node scripts/moderate.mjs unhide subject|card <target> <actor> [--apply]
//
// Uses the built server code in dist/, so run it after a build (the deployed image
// has one). Preserve evidence before hiding: this never deletes cards, but it does
// remove the hidden cards' index entries and matches.

const [cmd, type, target, a3, a4] = process.argv.slice(2)
const apply = process.argv.includes('--apply')
const v3db = await import('../dist/v3-db.js')
const mod = await import('../dist/moderation.js')
const blocks = await import('../dist/source-blocks.js')

// Address blocks:
//   node scripts/moderate.mjs list-sources
//   node scripts/moderate.mjs block-source <ip> "<reason>" <actor> [--apply]
//   node scripts/moderate.mjs unblock-source <ip> [--apply]
if (cmd === 'list-sources') { console.log(JSON.stringify(blocks.listBlockedSources(), null, 1)); process.exit(0) }
if (cmd === 'block-source' || cmd === 'unblock-source') {
  const ip = type
  if (!ip) { console.error('usage: block-source <ip> "<reason>" <actor> [--apply] | unblock-source <ip> [--apply]'); process.exit(2) }
  if (!apply) { console.log(JSON.stringify({ dry_run: true, cmd, ip, currently_blocked: blocks.isSourceBlocked(ip) }, null, 1)); process.exit(0) }
  const changed = cmd === 'block-source' ? blocks.blockSource(ip, target ?? '', a3 ?? '') : blocks.unblockSource(ip)
  console.log(JSON.stringify({ applied: true, cmd, ip, changed }, null, 1))
  process.exit(0)
}

if (cmd === 'list') {
  console.log(JSON.stringify(v3db.listModeration(), null, 1))
  process.exit(0)
}
if (!['hide', 'unhide'].includes(cmd) || !['card', 'subject'].includes(type) || !target) {
  console.error('usage: list | hide card|subject <target> "<reason>" <actor> [--apply] | unhide card|subject <target> <actor> [--apply]')
  process.exit(2)
}
const cards = v3db.cardIdsForTarget(type, target)
const plan = { cmd, type, target, cards: cards.length, card_ids: cards.map(c => c.card_id) }
if (!apply) {
  console.log(JSON.stringify({ dry_run: true, ...plan }, null, 1))
  process.exit(0)
}
const result = cmd === 'hide' ? mod.hideFromNetwork(type, target, a3 ?? '', a4 ?? '') : mod.unhideFromNetwork(type, target, a3 ?? '')
console.log(JSON.stringify({ applied: true, ...plan, result }, null, 1))
