#!/usr/bin/env node
// ══════════════════════════════════════════════════════════════
// Pre-deploy preflight. Run it BEFORE the API deploy, on the commit being deployed.
// ══════════════════════════════════════════════════════════════
// Every check here is about the thing being shipped, not about production: nothing in this
// file makes a network call or touches a live database, so it is safe to run anywhere and it
// can be run again as often as you like.
//
// It exits non-zero on the first hard failure and prints what to do about it. A zero exit is
// the local half of Gate A. The other half is scripts/probe-production.mjs, which runs AFTER
// the deploy against the deployed URL.
//
//   node scripts/preflight-deploy.mjs
//   node scripts/preflight-deploy.mjs --base <git ref>   (default: the last release tag or 909ffe3)
//
// WHY EACH CHECK EXISTS, because a checklist nobody understands gets skipped:
//
//  1 RECEIPT KEYS. A receipt signed by a key the process invented stops verifying at the next
//    restart, silently, which makes every server observation worthless as evidence. The
//    server already refuses to boot without a usable pair, so this check is about catching it
//    on the machine you are deploying from rather than in a crash loop.
//
//  2 ADDITIVE SCHEMA ONLY. This revision has no migrations list, no PRAGMA user_version and
//    no ALTER TABLE anywhere. CREATE TABLE IF NOT EXISTS is a NO-OP against a database that
//    already has the table, so a column added to an existing CREATE TABLE would never appear
//    on the deployed database and every read of it would answer undefined. New TABLES are
//    free. New COLUMNS on existing tables are not, and that asymmetry is invisible in a diff
//    unless something looks for it.
//
//  3 BOTH CONTAINMENT FLAGS UNSET. MINGLE_FIT_ENABLED and MINGLE_V2_ENABLED are containment,
//    not configuration. Neither has ever been set in production and neither is being turned
//    on by this deploy.
//
//  4 NO CUTOFF ACTIVATION. MINGLE_CANONICAL_MCP_RELEASED_AT seeds the 30 day compatibility
//    clock, and the clock starts at the npm publication of the canonical MCP, which has not
//    happened at API deploy time. Setting it here would start the window before any client
//    could possibly have it, and the marker is INSERT OR IGNORE, so a wrong stamp cannot be
//    corrected by stamping again.

import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const repo = new URL('..', import.meta.url).pathname
const argBase = process.argv.indexOf('--base')
const BASE = argBase > -1 ? process.argv[argBase + 1] : '909ffe3'

let failed = 0
const ok = m => console.log(`  ok    ${m}`)
const bad = (m, fix) => { failed++; console.log(`  FAIL  ${m}`); if (fix) console.log(`        fix: ${fix}`) }
const note = m => console.log(`        ${m}`)

function git(...args) {
  return execFileSync('git', args, { cwd: repo, encoding: 'utf8' })
}

// ── 1. Receipt keys present and matching ──────────────────────────────────
console.log('\n1. receipt keys')
{
  const priv = process.env.MINGLE_RECEIPT_PRIVKEY
  const pub = process.env.MINGLE_RECEIPT_PUBKEY
  if (!priv || !pub) {
    bad('MINGLE_RECEIPT_PRIVKEY and MINGLE_RECEIPT_PUBKEY are not both set in this shell',
      'export both from the deployment secret store, then re-run. The server refuses to boot without them.')
    note('Checked in THIS shell. If your platform injects them at runtime, run this with the same values.')
  } else {
    // publicKeyFromPrivate is the export the server itself uses at server-key.ts:118. Naming
    // a function that does not exist would have failed here with a message about the wrong
    // thing, which is the worst failure a preflight can have.
    const { publicKeyFromPrivate } = await import('agent-passport-system')
    let derived = null
    try { derived = publicKeyFromPrivate(priv) } catch (e) { bad(`MINGLE_RECEIPT_PRIVKEY is not a usable Ed25519 private key: ${e.message}`) }
    if (derived !== null) {
      if (derived !== pub) {
        bad(`MINGLE_RECEIPT_PUBKEY does not match the key derived from the private key. Derived ${derived}, configured ${pub}`,
          'a mismatch issues receipts that verify against neither key. Fix the pair before deploying.')
      } else {
        ok(`the pair matches, issuer key ${derived.slice(0, 16)}...`)
      }
    }
    const retired = process.env.MINGLE_RECEIPT_RETIRED_PUBKEYS ?? ''
    if (retired.trim() === '') ok('no retired keys configured')
    else {
      const entries = retired.split(',').map(s => s.trim()).filter(Boolean)
      for (const e of entries) {
        const [key, at] = e.split('@')
        if (!/^[0-9a-f]{64}$/.test(key ?? '')) bad(`retired entry ${e.slice(0, 20)}... is not 64 lowercase hex`)
        else if (!at || Number.isNaN(Date.parse(at))) bad(`retired entry for ${key.slice(0, 16)} carries no parseable retired_at`)
        else ok(`retired key ${key.slice(0, 16)}... bounded at ${at}`)
      }
    }
  }
}

// ── 2. Additive schema only ───────────────────────────────────────────────
console.log(`\n2. schema is additive (${BASE}..HEAD)`)
{
  let diff = ''
  try { diff = git('diff', '-U0', `${BASE}..HEAD`, '--', 'src/') } catch (e) {
    bad(`cannot diff ${BASE}..HEAD: ${e.message}`, `pass --base <ref> naming the currently deployed commit`)
  }

  // No ALTER TABLE anywhere in the tree, added or otherwise.
  const srcFiles = readdirSync(join(repo, 'src')).filter(f => f.endsWith('.ts'))
  // Comments are stripped FIRST. Several files carry a comment explaining that this revision
  // has no ALTER TABLE, and a scan that matched those would fail on its own documentation.
  const stripComments = t => t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
  const alters = []
  for (const f of srcFiles) {
    const body = stripComments(readFileSync(join(repo, 'src', f), 'utf8'))
    if (/ALTER\s+TABLE/i.test(body)) alters.push(f)
  }
  if (alters.length > 0) {
    bad(`ALTER TABLE appears in ${alters.join(', ')}`,
      'this revision has no migration runner, so an ALTER never runs against a deployed database. Use a new table.')
  } else ok('no ALTER TABLE anywhere in src/')

  // Added lines inside a CREATE TABLE body that look like a column declaration. A new table
  // brings its own columns, so only additions to a table that ALREADY EXISTS at BASE matter.
  let baseSrc = ''
  try {
    for (const f of git('ls-tree', '--name-only', `${BASE}`, 'src/').trim().split('\n')) {
      if (f.endsWith('.ts')) baseSrc += stripComments(git('show', `${BASE}:${f}`))
    }
  } catch { /* a base without src/ means everything is new */ }
  let headSrc = ''
  for (const f of srcFiles) headSrc += stripComments(readFileSync(join(repo, 'src', f), 'utf8'))

  // Every table named by a real CREATE TABLE, comments already stripped. The prose in this
  // repo says CREATE TABLE IF NOT EXISTS often enough that an unanchored scan would invent
  // tables called `is`, `on` and `IF` and then report them as new.
  const tablesIn = sql => {
    const found = new Set()
    for (const m of sql.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\(/gi)) found.add(m[1])
    return found
  }
  const existingTables = tablesIn(baseSrc)
  const columnsOf = (sql, table) => {
    for (const m of sql.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\(([\s\S]*?)\n\s*\)/gi)) {
      if (m[1] !== table) continue
      return new Set(m[2].split('\n')
        .map(l => l.trim())
        .filter(l => /^[a-z_][a-z0-9_]*\s+(TEXT|INTEGER|REAL|BLOB|NUMERIC)/i.test(l))
        .map(l => l.split(/\s+/)[0]))
    }
    return null
  }
  // A table whose columns cannot be read is REPORTED, never skipped quietly. A skip is how a
  // check like this becomes vacuous: the regex stops matching, every table becomes unreadable,
  // and the deploy is told there is no drift because nothing was looked at.
  let drift = 0
  let compared = 0
  const unreadable = []
  for (const table of existingTables) {
    const before = columnsOf(baseSrc, table)
    const after = columnsOf(headSrc, table)
    if (before === null || after === null) { unreadable.push(table); continue }
    compared++
    const added = [...after].filter(c => !before.has(c))
    if (added.length > 0) {
      drift++
      bad(`table ${table} gained column(s) ${added.join(', ')} since ${BASE}`,
        'CREATE TABLE IF NOT EXISTS is a no-op on a database that has the table, so this column will never exist in production. Put the data in a new table instead.')
    }
  }
  if (drift === 0) ok(`no new column on any of the ${compared} pre-existing tables whose columns were compared`)
  if (unreadable.length > 0) {
    bad(`could not read the column list for ${unreadable.length} pre-existing table(s): ${unreadable.join(', ')}`,
      'the comparison above did NOT cover them. Fix the parse or check those tables by hand before deploying.')
  }

  // A new table is fine, and worth printing so the deploy knows what appears on first boot.
  const newTables = [...tablesIn(headSrc)].filter(t => !existingTables.has(t))
  if (newTables.length > 0) ok(`new tables, created on first boot: ${newTables.join(', ')}`)
  else ok('no new tables')
}

// ── 3. Both containment flags unset ───────────────────────────────────────
console.log('\n3. containment flags')
for (const flag of ['MINGLE_FIT_ENABLED', 'MINGLE_V2_ENABLED']) {
  const v = process.env[flag]
  if (v === undefined || v === '') ok(`${flag} unset`)
  else if (v === '1') bad(`${flag} is "1", which TURNS THE SURFACE ON`, `unset ${flag}. It is containment, and this deploy does not lift it.`)
  else bad(`${flag} is set to ${JSON.stringify(v)}`, `unset it. Any value other than "1" means off, but a set value is a configuration nobody decided.`)
}

// ── 4. No cutoff activation ───────────────────────────────────────────────
console.log('\n4. the compatibility clock is not being started')
{
  const at = process.env.MINGLE_CANONICAL_MCP_RELEASED_AT
  if (at === undefined || at === '') {
    ok('MINGLE_CANONICAL_MCP_RELEASED_AT unset, so no cutoff is stamped by this deploy')
    note('The clock starts at the npm publication of the canonical MCP, which has not happened yet.')
    note('The marker is INSERT OR IGNORE: a wrong stamp cannot be corrected by stamping again.')
  } else {
    bad(`MINGLE_CANONICAL_MCP_RELEASED_AT is set to ${JSON.stringify(at)}`,
      'unset it. This deploy precedes the MCP publication, so any instant here starts the 30 day window before a single client could have the new version.')
  }
}

// ── 5. The build and the suites, so a deploy cannot ship a red tree ───────
console.log('\n5. the tree itself')
{
  const status = git('status', '--short').trim()
  if (status === '') ok('working tree clean')
  else bad(`working tree is not clean:\n${status.split('\n').map(l => '        ' + l).join('\n')}`, 'commit or stash before deploying, so the deployed commit is the reviewed one')
  const head = git('rev-parse', 'HEAD').trim()
  ok(`HEAD ${head}`)
  note('Run these two before deploying, and read the exit codes rather than the output:')
  note('  npx tsc --noEmit')
  note('  npm test')
  note('  MINGLE_FIT_ENABLED=1 MINGLE_V2_ENABLED=1 npm test    (the flags are scoped to this command)')
}

console.log(`\n${failed === 0 ? 'PREFLIGHT OK' : `PREFLIGHT FAILED with ${failed} problem(s)`}`)
process.exit(failed === 0 ? 0 : 1)
