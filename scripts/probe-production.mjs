#!/usr/bin/env node
// ══════════════════════════════════════════════════════════════
// Post-deploy production probes. READ ONLY, and that is enforced by what it sends.
// ══════════════════════════════════════════════════════════════
// Run AFTER the API deploy, against the deployed URL. Nothing here creates, changes or
// deletes anything: every request is either a GET, or a POST whose body is deliberately
// unsignable so the server refuses it before any write. Running it twice changes nothing,
// and running it a hundred times changes nothing.
//
//   node scripts/probe-production.mjs --url https://api.aeoess.com
//
// The live intro check is separate because it reads the database rather than the HTTP
// surface, and it is the one check that needs a path only the operator has:
//
//   node scripts/probe-production.mjs --db /path/to/prod.db --snapshot before.json   (BEFORE the deploy)
//   node scripts/probe-production.mjs --db /path/to/prod.db --compare  before.json   (AFTER the deploy)
//
// WHAT EACH PROBE IS FOR:
//
//  1 CURRENT V3. The product surface answers. This is the smoke test, and it is first because
//    every probe after it is meaningless if the deploy did not come up.
//
//  2 THE CAPABILITY FIELD. The root index must advertise write_authorization with
//    domain mingle-write-v1, legacy_accepted true and legacy_cutoff_at null. That triple is
//    how a client learns, before it writes anything, that canonical writes are available and
//    that the legacy window is still open. legacy_cutoff_at MUST be null after this deploy:
//    a non-null value means something stamped the clock, and the marker is INSERT OR IGNORE,
//    so it cannot be corrected by stamping again.
//
//  3 GRANDFATHERED LEGACY CLIENT. A published 3.2.x install must still be able to change a
//    connection. Probed WITHOUT writing: a legacy-shaped body with an unusable signature must
//    be refused for the signature, not for the window. A 403 proves the lane is open and
//    reachable. A 426 would prove it is closed, which at this point would be a defect.
//
//  4 BOTH CONTAINMENTS. The v2 surface and the fit surface must each answer with their own
//    refusal and their own approved sentence, and the root index must advertise neither.
//
//  5 RECEIPT KEY TRUST, READ ONLY. Every receipt ever issued names the key that signed it,
//    and a verifier resolves that id against the configured trusted set. If a receipt names
//    an id the set does not hold, that receipt stops verifying and the evidence it carries is
//    worthless. Checked against the database, because the id lives on the receipt row and the
//    server publishes no key material.

const argOf = name => {
  const i = process.argv.indexOf(name)
  return i > -1 ? process.argv[i + 1] : undefined
}
const URL_ = (argOf('--url') ?? '').replace(/\/$/, '')
const DB = argOf('--db')
const SNAPSHOT = argOf('--snapshot')
const COMPARE = argOf('--compare')

let failed = 0
const ok = m => console.log(`  ok    ${m}`)
const bad = (m, why) => { failed++; console.log(`  FAIL  ${m}`); if (why) console.log(`        ${why}`) }
const note = m => console.log(`        ${m}`)

async function get(path) {
  const res = await fetch(`${URL_}${path}`)
  let body = null
  try { body = await res.json() } catch { body = null }
  return { status: res.status, body }
}

/** A POST whose body cannot possibly authorize anything. Used to ask a route whether it is
 *  reachable without asking it to do something. */
async function unsignablePost(path, body) {
  const res = await fetch(`${URL_}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  })
  let out = null
  try { out = await res.json() } catch { out = null }
  return { status: res.status, body: out }
}

if (URL_ !== '') {
  // ── 1. Current v3 ───────────────────────────────────────────────────────
  console.log(`\n1. the deploy is up and serving v3 (${URL_})`)
  {
    const health = await get('/health')
    if (health.status === 200) ok('/health 200')
    else bad(`/health answered ${health.status}`, 'the deploy is not serving. Stop here and look at the logs.')

    const v3 = await get('/api/v3/')
    if (v3.status === 200) ok('/api/v3/ 200')
    else bad(`/api/v3/ answered ${v3.status}`)

    const search = await unsignablePost('/api/v3/cards/search', { limit: 1 })
    if (search.status === 200) ok('the card search answers, so the read path works end to end')
    else bad(`POST /api/v3/cards/search answered ${search.status}`, JSON.stringify(search.body))
  }

  // ── 2. The capability field ──────────────────────────────────────────────
  console.log('\n2. the capability field on the root index')
  {
    const root = await get('/')
    const cap = root.body?.write_authorization
    if (!cap) {
      bad('the root index carries no write_authorization field',
        'a client cannot learn that canonical writes exist, so every 3.2.x install stays on the legacy lane with no warning before the cutoff.')
    } else {
      if (cap.domain === 'mingle-write-v1') ok('domain mingle-write-v1')
      else bad(`domain is ${JSON.stringify(cap.domain)}, expected mingle-write-v1`)
      if (cap.preferred === true) ok('preferred true')
      else bad(`preferred is ${JSON.stringify(cap.preferred)}`)
      if (cap.legacy_accepted === true) ok('legacy_accepted true, so published clients still work')
      else bad(`legacy_accepted is ${JSON.stringify(cap.legacy_accepted)}`, 'the legacy window has closed, which must not be true at this deploy.')
      if (cap.legacy_cutoff_at === null) ok('legacy_cutoff_at null, so the clock has not been started')
      else bad(`legacy_cutoff_at is ${JSON.stringify(cap.legacy_cutoff_at)}`,
        'something stamped the compatibility clock. The marker is INSERT OR IGNORE, so it cannot be corrected by stamping again. Escalate before publishing the MCP.')
    }
  }

  // ── 3. Grandfathered legacy client ───────────────────────────────────────
  console.log('\n3. a published 3.2.x client can still change a connection')
  {
    // The exact body shape mingle-mcp 3.2.2 sends, with a signature that cannot verify. The
    // server must refuse it for the SIGNATURE. A 426 here would mean the window is closed.
    const probe = await unsignablePost('/api/v3/intros/request', {
      from_card: 'probe-not-a-card', to_card: 'probe-not-a-card-either', purpose: 'meet',
      note: 'A read only probe. This body cannot authorize anything.',
      public_key: '0'.repeat(64), nonce: 'probe-nonce', signature: '0'.repeat(128),
    })
    if (probe.status === 426 || probe.body?.code === 'client_upgrade_required') {
      bad('the legacy lane answered client_upgrade_required',
        'the 30 day window is closed for this shape, so every published 3.2.x install is already cut off. This must not be true before the MCP is published.')
    } else if (probe.status === 403 || probe.status === 401) {
      ok(`the legacy lane is reachable and refused the probe for its signature (${probe.status})`)
      note('Nothing was created: the signature cannot verify, so the handler refused before any write.')
    } else if (probe.status === 400 || probe.status === 404) {
      ok(`the legacy lane is reachable and refused the probe on its shape (${probe.status})`)
      note(`answer: ${JSON.stringify(probe.body)}`)
      note('Not a 426, which is the part that matters: the window is open.')
    } else {
      bad(`the legacy lane answered ${probe.status}: ${JSON.stringify(probe.body)}`,
        'expected a refusal for the signature or the shape. Anything else needs reading before the MCP is published.')
    }
  }

  // ── 4. Both containments ────────────────────────────────────────────────
  console.log('\n4. both containments hold')
  {
    const v2 = await unsignablePost('/api/feedback/probe-not-an-intro', { rating: 'useful' })
    if (v2.status === 503 && v2.body?.code === 'v2_disabled') {
      ok('the v2 surface refuses with v2_disabled')
      if (v2.body.error === 'This legacy Mingle interface is temporarily unavailable. Use the current Mingle tools.') {
        ok('and with its approved sentence, byte exact')
      } else bad(`the v2 sentence has drifted: ${JSON.stringify(v2.body.error)}`)
    } else bad(`POST /api/feedback answered ${v2.status} ${JSON.stringify(v2.body)}`, 'expected 503 v2_disabled. A live v2 surface exposes the authorization model this flag contains.')

    const fit = await unsignablePost('/api/v4/fit/probe-not-an-intro/request', {})
    if (fit.status === 503) {
      ok('the fit surface refuses')
      if (fit.body?.error === 'Agent fit is temporarily unavailable. You can still continue the introduction directly.') {
        ok('and with its approved sentence, byte exact')
      } else note(`fit answer: ${JSON.stringify(fit.body)}`)
    } else bad(`POST /api/v4/fit/.../request answered ${fit.status} ${JSON.stringify(fit.body)}`, 'expected 503. MINGLE_FIT_ENABLED must not be set.')

    // The index must say the legacy product is unavailable AND must not list any of it. The
    // routes probed here are the ones the index literal actually contains, so this can fail:
    // with the flag on they all appear. (V2_INDEX_KEYS also names /api/feedback/:introId,
    // /api/trust/:agentId and /api/matches/ghost, which the literal never carries, so those
    // three deletions are dead code and probing for them would prove nothing.)
    const root = await get('/')
    const endpoints = Object.keys(root.body?.endpoints ?? {})
    const shouldBeAbsent = [
      'POST /api/cards', 'GET /api/cards/:agentId', 'DELETE /api/cards/:cardId',
      'GET /api/matches/:agentId', 'POST /api/intros', 'PUT /api/intros/:introId',
      'GET /api/digest/:agentId',
    ]
    const leaked = shouldBeAbsent.filter(k => endpoints.includes(k))
    if (leaked.length > 0) {
      bad(`the root index advertises ${leaked.length} contained route(s): ${leaked.join(', ')}`,
        'MINGLE_V2_ENABLED is set, so a half live product is discoverable. Unset it.')
    } else ok(`the root index advertises none of the ${shouldBeAbsent.length} contained routes`)
    if (root.body?.legacy_v2?.available === false) ok('and says legacy_v2 available false')
    else bad(`legacy_v2 is ${JSON.stringify(root.body?.legacy_v2)}, expected { available: false }`)
  }

} else {
  note('no --url given, so the HTTP probes were skipped')
}

// ── 5. Receipt key trust, and 6. the live intro, read once ────────────────
// The one check that reads the database. It is READ ONLY: the connection is opened readonly,
// so a stray write would throw rather than land.
//
// WHY A SNAPSHOT AND A COMPARE rather than one read. "Nothing changed" is only checkable
// against what it was before, and the values are specific to whatever is live at the time, so
// this does not hard code them. Take the snapshot BEFORE the deploy, compare AFTER.
if (DB) {
  const { default: Database } = await import('better-sqlite3')
  const db = new Database(DB, { readonly: true })
  // Several tables in this schema are created on FIRST USE rather than at boot, so a database
  // that has served nothing yet legitimately has no v3_intros. A probe that threw on that
  // would be unrunnable on a fresh deploy, which is exactly when it is most wanted.
  const has = table =>
    db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table) !== undefined
  try {
    // ── 5. Every receipt still resolves to a trusted key ──────────────────
    console.log('\n5. every receipt names a key the server still trusts')
    {
      const { createHash } = await import('node:crypto')
      const deriveIssuerKeyId = pk => 'mk1_' + createHash('sha256').update(pk, 'utf8').digest('hex').slice(0, 32)
      const trusted = new Set()
      if (process.env.MINGLE_RECEIPT_PUBKEY) trusted.add(deriveIssuerKeyId(process.env.MINGLE_RECEIPT_PUBKEY))
      for (const entry of (process.env.MINGLE_RECEIPT_RETIRED_PUBKEYS ?? '').split(',')) {
        const key = entry.trim().split('@')[0]
        if (/^[0-9a-f]{64}$/.test(key)) trusted.add(deriveIssuerKeyId(key))
      }
      const issuers = has('lifecycle_receipts')
        ? db.prepare('SELECT issuer_key_id, COUNT(*) AS n FROM lifecycle_receipts GROUP BY issuer_key_id').all()
        : []
      if (issuers.length === 0) {
        ok('no receipts have been issued yet, so there is nothing that could stop verifying')
      } else if (trusted.size === 0) {
        bad(`${issuers.length} distinct issuer(s) on record and no receipt key in this shell to check them against`,
          'export MINGLE_RECEIPT_PUBKEY (and MINGLE_RECEIPT_RETIRED_PUBKEYS if any) with the deployed values, then re-run.')
      } else {
        for (const row of issuers) {
          if (trusted.has(row.issuer_key_id)) ok(`${row.n} receipt(s) under ${row.issuer_key_id}, which is trusted`)
          else bad(`${row.n} receipt(s) under ${row.issuer_key_id}, which is NOT in the trusted set`,
            'those receipts no longer verify. Add the retired public key to MINGLE_RECEIPT_RETIRED_PUBKEYS with its retirement instant rather than deleting anything.')
        }
      }
    }

    // ── 6. The live introduction ──────────────────────────────────────────
    console.log('\n6. the live introduction, read once')
    if (!has('v3_intros')) {
      ok('this database has no v3_intros table yet, so there is no introduction to read')
      note('The table is created on first use, not at boot. A production database that has')
      note('served an introduction has it, so this branch means a fresh or wrong database.')
    } else {
    const rows = db.prepare(`
      SELECT id, status, from_contact IS NOT NULL AS has_from_contact,
             to_contact IS NOT NULL AS has_to_contact, created_at, responded_at
      FROM v3_intros ORDER BY created_at, id
    `).all()
    const auth = db.prepare('SELECT intro_id, COUNT(*) AS n FROM connection_authorizations GROUP BY intro_id').all()
    const authBy = Object.fromEntries(auth.map(a => [a.intro_id, a.n]))
    const snapshot = rows.map(r => ({ ...r, authorizations: authBy[r.id] ?? 0 }))
    console.log(`        ${snapshot.length} intro row(s):`)
    for (const r of snapshot) {
      console.log(`        ${r.id}  status=${r.status}  from_contact=${!!r.has_from_contact}  to_contact=${!!r.has_to_contact}  authorizations=${r.authorizations}`)
    }

    if (SNAPSHOT) {
      const { writeFileSync } = await import('node:fs')
      writeFileSync(SNAPSHOT, JSON.stringify(snapshot, null, 2) + '\n')
      ok(`snapshot written to ${SNAPSHOT}. Run again with --compare ${SNAPSHOT} after the deploy.`)
    } else if (COMPARE) {
      const { readFileSync } = await import('node:fs')
      const before = JSON.parse(readFileSync(COMPARE, 'utf8'))
      const key = r => `${r.id}|${r.status}|${!!r.has_from_contact}|${!!r.has_to_contact}|${r.responded_at ?? ''}`
      const beforeKeys = before.map(key).sort()
      const afterKeys = snapshot.map(key).sort()
      if (JSON.stringify(beforeKeys) === JSON.stringify(afterKeys)) {
        ok('every live introduction is exactly as it was before the deploy')
        note('Nothing migrated it and nothing swept it. The deploy is additive for existing rows.')
      } else {
        bad('a live introduction changed across the deploy')
        for (const k of afterKeys.filter(k => !beforeKeys.includes(k))) console.log(`        after only:  ${k}`)
        for (const k of beforeKeys.filter(k => !afterKeys.includes(k))) console.log(`        before only: ${k}`)
        note('An existing row must not be rewritten by a deploy. Escalate before anything else.')
      }
      // Authorization rows may only be ADDED, and only by a principal acting. A row that lost
      // authorizations across a deploy would mean something deleted evidence.
      for (const r of snapshot) {
        const was = before.find(b => b.id === r.id)
        if (was && r.authorizations < was.authorizations) {
          bad(`${r.id} lost authorization rows (${was.authorizations} -> ${r.authorizations})`,
            'authorization rows are append only and a withdrawal flips a column rather than deleting one. Losing one means evidence was deleted.')
        }
      }
    } else {
      note('Pass --snapshot <file> before the deploy, then --compare <file> after it.')
    }
    }
  } finally { db.close() }
} else {
  note('\nno --db given, so the live introduction check was skipped')
}

console.log(`\n${failed === 0 ? 'PROBES OK' : `PROBES FAILED with ${failed} problem(s)`}`)
process.exit(failed === 0 ? 0 : 1)
