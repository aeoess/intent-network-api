#!/usr/bin/env node
// ══════════════════════════════════════════════════════════════
// Post-deploy production probes. No business write, and here is exactly what it does touch.
// ══════════════════════════════════════════════════════════════
// Run AFTER the API deploy, against the deployed URL.
//
// WHAT IT DOES NOT DO: it creates, changes or deletes no card, no introduction, no
// authorization, no receipt and no subscription. Every request is a GET, or a POST whose body
// cannot authorize anything, so each one is refused before any handler writes.
//
// WHAT IT DOES TOUCH, because a script that claims to touch nothing and then writes is worse
// than one that says so:
//   - `rate_limits` counter rows, three or four per run. Every /api/v3 request passes a limiter
//     that upserts a counter before the handler refuses. Keyed per hour and per IP.
//   - On a database that has never served a v3 card read, the first `cards/search` creates the
//     v3 card and embedding tables, which this build creates lazily on first use.
// Neither is business state and neither is reversible in the sense that matters, because
// neither carries anything. An earlier version of this script also posted to the legacy intro
// request route, which consumed the 20 per hour `intro_request` bucket shared with real 3.2.x
// clients behind the same address: enough runs in one clock hour turned this script red for a
// reason unrelated to the deploy. That probe is gone, see probe 3.
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
//  3 GRANDFATHERED LEGACY CLIENT, answered from the capability field and NOT by a write probe.
//    The earlier version posted an unsignable legacy body and read the refusal. That could not
//    work: every legacy route checks the signature BEFORE the window, deliberately, so an
//    unauthorized caller learns nothing about the window. Verified against a server with the
//    window fully closed, where the probe still reported the lane open. It also accepted a 404
//    as proof of reachability, so a server with no such route at all passed.
//    `legacy_accepted` in probe 2 is the authoritative answer, and it is the same answer the
//    server gives its own clients. The write-level property, that a real 3.2.x body is accepted
//    and creates a real introduction, cannot be checked read-only against production: it is
//    driven end to end against a local API in mingle-mcp's e2e suite instead.
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

/** A GET that reports a dead endpoint rather than throwing an undici stack at the operator. */
async function get(path) {
  let res
  try {
    res = await fetch(`${URL_}${path}`, { signal: AbortSignal.timeout(20000) })
  } catch (e) {
    return { status: 0, body: null, unreachable: e.message }
  }
  let body = null
  try { body = await res.json() } catch { body = null }
  return { status: res.status, body }
}

/** A POST whose body cannot possibly authorize anything. Used to ask a route whether it is
 *  reachable without asking it to do something. */
async function unsignablePost(path, body) {
  let res
  try {
    res = await fetch(`${URL_}${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(20000),
    })
  } catch (e) {
    return { status: 0, body: null, unreachable: e.message }
  }
  let out = null
  try { out = await res.json() } catch { out = null }
  return { status: res.status, body: out }
}

if (URL_ !== '') {
  // ── 1. Current v3 ───────────────────────────────────────────────────────
  console.log(`\n1. the deploy is up and serving v3 (${URL_})`)
  {
    const health = await get('/health')
    if (health.unreachable) {
      bad(`${URL_} is not reachable: ${health.unreachable}`,
        'nothing below can run. Check the URL, the deploy and the network, then re-run.')
      console.log('\nPROBES FAILED: the endpoint did not answer at all')
      process.exit(1)
    }
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
    // Probe 2 already read the authoritative answer. This states what it means, and does not
    // attempt a write probe: every legacy route checks the signature before the window, so an
    // unsignable body cannot observe the window and the old probe reported the lane open even
    // against a server that had closed it.
    const cap = (await get('/')).body?.write_authorization
    if (cap?.legacy_accepted === true && cap?.legacy_cutoff_at === null) {
      ok('the window is open and unstamped, so every published 3.2.x install can still change a connection')
      note('This is the same answer the server gives its own clients, and the only one available')
      note('read-only: a legacy route refuses an unsigned body for the signature, before the window,')
      note('so no probe can observe the window without a real signature and a real write.')
      note('The write-level property is covered end to end against a local API by')
      note('mingle-mcp/test/e2e-two-principals.test.ts, which posts a real 3.2.2 body and')
      note('asserts a real introduction comes back with every field that client reads.')
    } else if (cap?.legacy_accepted === false) {
      bad('legacy_accepted is false, so every published 3.2.x install is already cut off',
        'this must not be true before the MCP is published. Check whether the clock was stamped.')
    } else {
      bad(`the capability field does not answer the window: ${JSON.stringify(cap)}`,
        'without it a client cannot tell a server that has not answered from one that does not know about canonical writes.')
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

    // bad(), not note(). This branch used note() for the sentence, so replacing the approved fit
    // text with anything at all still printed PROBES OK. The v2 branch above always checked its
    // sentence, so one of the two claims the commit made was unenforced.
    const fit = await unsignablePost('/api/v4/fit/probe-not-an-intro/request', {})
    if (fit.status === 503) {
      ok('the fit surface refuses')
      if (fit.body?.error === 'Agent fit is temporarily unavailable. You can still continue the introduction directly.') {
        ok('and with its approved sentence, byte exact')
      } else {
        bad(`the fit sentence has drifted: ${JSON.stringify(fit.body?.error)}`,
          'it is approved copy and a person reads it. Restore it byte for byte.')
      }
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
    // GUARDED. The currently deployed commit has no write subsystem at all, so production's
    // database has v3_intros and NOT connection_authorizations. The documented pre-deploy
    // snapshot crashed on this line with a raw SqliteError and wrote no snapshot file, which
    // meant the "nothing changed across the deploy" check could not be performed on the one
    // deploy it was written for.
    const auth = has('connection_authorizations')
      ? db.prepare('SELECT intro_id, COUNT(*) AS n FROM connection_authorizations GROUP BY intro_id').all()
      : []
    if (!has('connection_authorizations')) {
      note('this database has no connection_authorizations table, which is expected BEFORE the deploy')
    }
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
      // COMPARED BY ID, over the rows that existed BEFORE.
      //
      // A sorted set comparison of every row reported a new introduction, which is a person
      // using the product during the deploy window, as "a live introduction changed across the
      // deploy, an existing row must not be rewritten, escalate before anything else". Verified:
      // inserting one new row produced exactly that false escalation. The same happened when an
      // existing introduction legitimately progressed. What this check is for is a MIGRATION
      // touching a row nobody acted on, so it compares each pre-existing id against itself and
      // reports new and progressed rows as activity.
      const state = r => `status=${r.status} from_contact=${!!r.has_from_contact} to_contact=${!!r.has_to_contact} responded_at=${r.responded_at ?? 'null'}`
      const byId = new Map(snapshot.map(r => [r.id, r]))
      const changed = []
      const gone = []
      for (const was of before) {
        const now = byId.get(was.id)
        if (now === undefined) { gone.push(was.id); continue }
        if (state(now) !== state(was)) changed.push({ id: was.id, was: state(was), now: state(now) })
      }
      const added = snapshot.filter(r => !before.some(b => b.id === r.id)).map(r => r.id)

      if (gone.length > 0) {
        bad(`${gone.length} introduction(s) present before the deploy are GONE: ${gone.join(', ')}`,
          'nothing in this build deletes an introduction row. Escalate before anything else.')
      }
      if (changed.length === 0 && gone.length === 0) {
        ok(`all ${before.length} pre-existing introduction(s) are exactly as they were`)
        note('Nothing migrated one and nothing swept one.')
      } else if (changed.length > 0) {
        // A CHANGE IS NOT AUTOMATICALLY A FAULT. A person acting during the window changes a
        // row legitimately. It is reported for a human to read rather than called an escalation.
        note(`${changed.length} pre-existing introduction(s) changed state during the window:`)
        for (const c of changed) {
          console.log(`        ${c.id}`)
          console.log(`          before: ${c.was}`)
          console.log(`          after:  ${c.now}`)
        }
        note('Each of these is either somebody acting during the deploy window, which is normal,')
        note('or a migration that rewrote a row, which nothing in this build does. Read them and')
        note('decide. A row that moved ALONG the lifecycle is activity. A row that moved backwards,')
        note('or lost a contact, is not.')
      }
      if (added.length > 0) {
        ok(`${added.length} introduction(s) were created during the window, which is people using it`)
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
