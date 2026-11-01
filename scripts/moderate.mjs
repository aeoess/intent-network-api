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

// Address restrictions (new publish, renew, replace, intro requests, email sign-up only):
//   node scripts/moderate.mjs list-sources
//   node scripts/moderate.mjs restrict-source <ip> "<reason>" <actor> [hours] [--apply]
//   node scripts/moderate.mjs lift-source <ip> [--apply]
if (cmd === 'list-sources') { console.log(JSON.stringify(blocks.listRestrictions(), null, 1)); process.exit(0) }
if (cmd === 'restrict-source' || cmd === 'lift-source') {
  const ip = type
  if (!ip) { console.error('usage: restrict-source <ip> "<reason>" <actor> [hours] [--apply] | lift-source <ip> [--apply]'); process.exit(2) }
  const hours = a4 && a4 !== '--apply' ? Number(a4) : undefined
  if (!apply) { console.log(JSON.stringify({ dry_run: true, cmd, ip, hours: hours ?? blocks.DEFAULT_RESTRICTION_HOURS, current: blocks.activeRestriction(ip) }, null, 1)); process.exit(0) }
  const result = cmd === 'restrict-source' ? blocks.restrictSource(ip, target ?? '', a3 ?? '', { hours }) : blocks.liftRestriction(ip)
  console.log(JSON.stringify({ applied: true, cmd, ip, result }, null, 1))
  process.exit(0)
}

// Email allowance for one address (an event on shared wifi):
//   node scripts/moderate.mjs allow-source-email <ip> <per_day> "<reason>" <actor> [hours] [--apply]
//   node scripts/moderate.mjs lift-source-email <ip> [--apply]
//   node scripts/moderate.mjs list-email-allowances
const guard = await import('../dist/confirm-guard.js')
if (cmd === 'list-email-allowances') { console.log(JSON.stringify(guard.listAllowances(), null, 1)); process.exit(0) }
if (cmd === 'allow-source-email' || cmd === 'lift-source-email') {
  const ip = type
  if (!ip) { console.error('usage: allow-source-email <ip> <per_day> "<reason>" <actor> [hours] [--apply] | lift-source-email <ip> [--apply]'); process.exit(2) }
  const rest = process.argv.slice(2).filter(x => x !== '--apply')
  const perDay = Number(rest[2]); const reason = rest[3] ?? ''; const actor = rest[4] ?? ''; const hours = rest[5] ? Number(rest[5]) : undefined
  if (!apply) { console.log(JSON.stringify({ dry_run: true, cmd, ip, per_day: perDay, hours: hours ?? 24, current: guard.activeAllowance(ip) }, null, 1)); process.exit(0) }
  const result = cmd === 'allow-source-email' ? guard.allowSourceEmail(ip, perDay, reason, actor, { hours }) : guard.liftAllowance(ip)
  console.log(JSON.stringify({ applied: true, cmd, ip, result }, null, 1))
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
