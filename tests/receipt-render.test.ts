// ══════════════════════════════════════════════════════════════
// The receipt renderer: the golden copy, and no clause without warrant
// ══════════════════════════════════════════════════════════════
// Three things are being held down here.
//
//   1  THE GOLDEN TEST. Every sentence equals the approved text character for character.
//      This is what makes the approved copy load bearing rather than aspirational: a
//      rewording anywhere fails here, so it has to be a deliberate copy change.
//   2  A legacy evidence row never produces a clause naming a field its signature did not
//      cover, asserted per operation against the real bound lists the recorder writes.
//   3  No rendered receipt ever contains a sentence from the NOT-ALLOWED list.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPair } from 'agent-passport-system'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-render-test-'))
process.env.DB_PATH = join(tmpDir, 'render.db')
const rk = generateKeyPair()
process.env.MINGLE_RECEIPT_PRIVKEY = rk.privateKey
process.env.MINGLE_RECEIPT_PUBKEY = rk.publicKey

const render = await import('../src/receipt-render.js')
const evidence = await import('../src/write-evidence.js')
const db = await import('../src/db.js')

process.on('exit', () => { try { db.closeDb() } catch { /* already closed */ } rmSync(tmpDir, { recursive: true, force: true }) })

/** The bound list the recorder actually writes for one operation and lane. Using the real
 *  function rather than a literal is the point: if boundFieldsFor changes, these tests move
 *  with it and the receipt cannot silently start claiming more. */
const bound = (op: any, kind: 'canonical' | 'legacy_unbound') => evidence.boundFieldsFor(op, kind)

// ══════════════════════════════════════════════════════════════
// 1. The golden copy
// ══════════════════════════════════════════════════════════════

test('GOLDEN: every approved sentence matches the decided text character for character', () => {
  // Written out as literals, deliberately duplicating src. That duplication IS the test: a
  // reworded constant no longer equals the text that was approved, and the diff shows both.
  const approved: Record<string, string> = {
    request_canonical:
      'Acting key K authorized an introduction request to card T for purpose P, with the exact note recorded here. Mingle recorded it at R.',
    request_legacy:
      'Acting key K authorized an introduction request to card T for purpose P. The note stored with it was not covered by that signature.',
    connection_canonical:
      "Mingle observed valid contact-sharing authorizations from both acting keys and released each counterparty's contact after both authorizations existed.",
    connection_mixed:
      "Mingle released each counterparty's contact after both sides authorized sharing. Key A's authorization covered the exact contact line it shared. Key B's authorization did not cover the contact line stored for B.",
    connection_held:
      'Neither contact was released until both authorizations existed. Before that, each contact was held and shown to no one.',
    contact_irrevocable:
      'Mingle cannot withdraw a contact line once it has been released.',
    mixed_para_1:
      "Mingle released each counterparty's contact after both sides authorized sharing.",
    mixed_para_2:
      "Key A's authorization covered the exact contact line A shared, committed to as C. The line itself is not in this receipt.",
    mixed_para_3:
      'Key B authorized a response on this introduction using an earlier version of Mingle. That signature did not cover the contact line stored for B, so Mingle cannot show that the line it released for B is the line B intended.',
    legacy_side_present:
      'This introduction includes a side that authorized with an earlier version of Mingle. Evidence for that side covers less than evidence for the current version.',
    fit_canonical:
      'Acting keys A and B authorized the listed fit operations under the listed policy commitments. Mingle evaluated predicate version V and produced the listed outcome. This attests authorization, not the truth of any value.',
    fit_standing_scope:
      'This act was authorized under standing scope S. It was not individually approved.',
    fit_legacy:
      'Acting keys A and B each sent a signed fit message naming this introduction. Those signatures did not cover the dimensions, the reciprocal offer, the policy hash or the budget. Mingle evaluated predicate version V from the values it stored and produced the listed outcome.',
    fit_mixed:
      'Mingle observed canonical authorization from [party] for [operation]. The counterparty used a legacy authorization form that does not cryptographically bind all fit semantics. Mingle evaluated predicate version [V] using the submitted fit data and recorded outcome [O].',
    fit_commitment_disclosure:
      'The policy commitments in this receipt hide the policy behind them. Either owner may later disclose their policy and salt to an auditor or counterparty of their choosing.',
    first_step_canonical:
      'Key A authorized half A. Key B authorized half B. Both keys approved merged digest D.',
    first_step_mixed:
      'Both keys approved merged digest D, which is the digest of the two halves recorded here. Neither proposal signature covered the text of its half.',
    first_step_finality:
      'The plan is final only when both keys have approved the same merged digest. Changing either half clears both approvals.',
    share_contact_shared:
      'Acting key K authorized the release of a contact line on this introduction, committed to as C. The line itself is held for the counterparty and is not in this receipt. Mingle recorded the authorization at R.',
    share_contact_recipient:
      "This contact line was signed by the other side's acting key. You can check that signature yourself, without trusting Mingle.",
    artifact_plaintext_limit:
      'Mingle holds the contact line in plain text on its server. This is not end to end encryption.',
  }
  for (const [key, text] of Object.entries(approved)) {
    assert.equal((render.SENTENCES as Record<string, string>)[key], text, key)
  }
  assert.deepEqual(Object.keys(render.SENTENCES).sort(), Object.keys(approved).sort(),
    'no sentence exists in src that this test does not hold, and none here is missing from src')
})

test('GOLDEN: no approved sentence claims a human act, a truth or an outcome Mingle cannot see', () => {
  // The never list as a scan over the copy rather than as a rule someone remembers.
  const banned = [
    /\bagreed\b/i, /\bapproved sharing\b/i, /\bconnected\b/i, /\bgood fit\b/i,
    /\bmatched\b/i, /\bwill meet\b/i, /\bcompatible\b/i, /\bboth humans\b/i,
  ]
  for (const [key, text] of Object.entries(render.SENTENCES)) {
    for (const re of banned) {
      // 6.5 legitimately says "approved the same merged digest", which is a key act and not
      // a human one, so only the forbidden phrasings are banned rather than the word.
      assert.equal(re.test(text), false, `${key} matches ${re}: ${text}`)
    }
  }
})

test('GOLDEN: not one NOT-ALLOWED sentence appears in any rendered receipt', () => {
  const every = [
    render.renderConnection(bound('share_contact', 'canonical'), bound('share_contact', 'canonical')),
    render.renderConnection(bound('share_contact', 'canonical'), bound('share_contact', 'legacy_unbound')),
    render.renderConnection(null, null),
    render.renderFitHandshake({ request: bound('fit_request', 'canonical'), commit: bound('fit_commit', 'canonical'), standingScope: false }),
    render.renderFitHandshake({ request: bound('fit_request', 'canonical'), commit: bound('fit_commit', 'canonical'), standingScope: true }),
    render.renderFitHandshake({ request: bound('fit_request', 'legacy_unbound'), commit: bound('fit_commit', 'legacy_unbound'), standingScope: false }),
    render.renderFirstStep({
      proposeA: bound('first_step_propose', 'canonical'), proposeB: bound('first_step_propose', 'canonical'),
      approveA: bound('first_step_approve', 'canonical'), approveB: bound('first_step_approve', 'canonical'),
    }),
    render.renderFirstStep({
      proposeA: bound('first_step_propose', 'legacy_unbound'), proposeB: bound('first_step_propose', 'canonical'),
      approveA: bound('first_step_approve', 'legacy_unbound'), approveB: bound('first_step_approve', 'legacy_unbound'),
    }),
    render.renderIntroRequest(bound('request_intro', 'canonical')),
    render.renderIntroRequest(bound('request_intro', 'legacy_unbound')),
  ]
  for (const r of every) {
    const text = r.sentences.join(' ')
    for (const forbidden of render.FORBIDDEN_SENTENCES) {
      assert.equal(text.includes(forbidden), false, `a rendered receipt contains: ${forbidden}`)
    }
    assert.ok(r.sentences.length > 0, 'every case renders something')
    assert.equal(r.sentences.length, r.keys.length)
  }
})

// ══════════════════════════════════════════════════════════════
// 2. A clause appears only when its field is bound
// ══════════════════════════════════════════════════════════════

test('WARRANT: a canonical pair gets the decided sentence, and a mixed pair gets the three paragraph form', () => {
  const canonical = render.renderConnection(bound('share_contact', 'canonical'), bound('share_contact', 'canonical'))
  assert.deepEqual(canonical.keys, ['connection_canonical', 'connection_held', 'contact_irrevocable'])
  assert.equal(canonical.sentences[0], render.SENTENCES.connection_canonical)
  assert.equal(canonical.mixed, false)

  const mixed = render.renderConnection(bound('share_contact', 'canonical'), bound('share_contact', 'legacy_unbound'))
  assert.deepEqual(mixed.keys, ['mixed_para_1', 'mixed_para_2', 'mixed_para_3', 'legacy_side_present', 'contact_irrevocable'])
  assert.equal(mixed.sentences[0], render.SENTENCES.mixed_para_1)
  assert.equal(mixed.sentences[1], render.SENTENCES.mixed_para_2)
  assert.equal(mixed.sentences[2], render.SENTENCES.mixed_para_3)
  assert.equal(mixed.mixed, true)
  // The sentence that averages two strengths never appears.
  assert.equal(mixed.sentences.includes(render.SENTENCES.connection_canonical), false,
    'a sentence that averages two strengths overclaims about the weaker one')

  // Both legacy: no clause about either contact line survives, and the second paragraph,
  // which is the one that names a covered contact, is suppressed.
  const both = render.renderConnection(bound('share_contact', 'legacy_unbound'), bound('share_contact', 'legacy_unbound'))
  assert.equal(both.keys.includes('mixed_para_2'), false, 'neither side covered a contact, so neither is claimed to have')
  assert.equal(both.keys.includes('mixed_para_3'), true)
})

test('WARRANT: per operation, a legacy row emits no clause naming a field its signature did not cover', () => {
  // The bound lists come from the recorder, and these are the fields each canonical clause
  // depends on. Every one must be absent from the legacy list, or a receipt could claim it.
  const cases: [any, string[]][] = [
    ['request_intro', ['payload.to_card', 'payload.purpose', 'payload.note']],
    ['express_interest', []],
    ['share_contact', ['payload.private_value_commitment']],
    ['fit_request', ['payload.requested_dimensions', 'payload.reciprocal_offer', 'payload.predicate_version', 'payload.policy_commitment', 'payload.query_budget']],
    ['fit_commit', ['payload.accept_dimensions', 'payload.reciprocal_offer', 'payload.policy_commitment', 'payload.request_write_ref']],
    ['release_exact', ['payload.dimension', 'payload.policy_commitment', 'payload.private_value_commitment']],
    ['first_step_propose', ['payload.purpose', 'payload.next_action', 'payload.meeting_length', 'payload.agenda', 'payload.each_wants', 'payload.boundaries', 'payload.expiry']],
    ['first_step_approve', ['payload.approved_digest']],
  ]
  for (const [op, canonicalFields] of cases) {
    const legacy = bound(op, 'legacy_unbound')
    const canonical = bound(op, 'canonical')
    for (const f of canonicalFields) {
      assert.equal(canonical.includes(f), true, `${op} canonical should bind ${f}`)
      assert.equal(render.warrants(legacy, [f]), false, `${op} legacy must not warrant ${f}`)
    }
    if (canonicalFields.length > 0) {
      assert.equal(render.warrants(canonical, canonicalFields), true, `${op} canonical warrants all of its fields`)
    }
  }
})

test('WARRANT: the fit receipt needs BOTH sides canonical, because its sentence names both', () => {
  const bothCanonical = render.renderFitHandshake({
    request: bound('fit_request', 'canonical'), commit: bound('fit_commit', 'canonical'), standingScope: false,
  })
  assert.deepEqual(bothCanonical.keys, ['fit_canonical', 'fit_commitment_disclosure'])

  for (const [reqKind, comKind] of [
    ['legacy_unbound', 'canonical'], ['canonical', 'legacy_unbound'], ['legacy_unbound', 'legacy_unbound'],
  ] as const) {
    const r = render.renderFitHandshake({
      request: bound('fit_request', reqKind), commit: bound('fit_commit', comKind), standingScope: false,
    })
    assert.equal(r.keys.includes('fit_canonical'), false, `${reqKind}/${comKind}: one canonical side is not enough`)
    assert.equal(r.keys.includes('legacy_side_present'), true)
  }
})

test('GOLDEN: a MIXED fit pair renders the ruling ceiling, and the fully legacy pair does not', () => {
  // Three cases, not two. The 2B.1 review found the mixed pair getting the fully-legacy
  // sentence while the receipt's own warrants object named four fields the canonical side DID
  // cover, so the prose under-claimed against the data printed beside it. The ruling closed it
  // with one sentence, and this holds that sentence to the character on both mixed
  // orientations while keeping the blunt one for the pair where neither side is bound.
  for (const [reqKind, comKind] of [['legacy_unbound', 'canonical'], ['canonical', 'legacy_unbound']] as const) {
    const r = render.renderFitHandshake({
      request: bound('fit_request', reqKind), commit: bound('fit_commit', comKind), standingScope: false,
    })
    assert.equal(r.keys.includes('fit_mixed'), true, `${reqKind}/${comKind} is the mixed case`)
    assert.equal(r.keys.includes('fit_legacy'), false, 'and never also the fully legacy sentence')
    assert.equal(r.keys.includes('fit_canonical'), false)
    assert.equal(r.sentences[0], render.SENTENCES.fit_mixed)
    assert.equal(r.mixed, true, 'a reader is told once that a legacy side is present')
  }
  const neither = render.renderFitHandshake({
    request: bound('fit_request', 'legacy_unbound'), commit: bound('fit_commit', 'legacy_unbound'), standingScope: false,
  })
  assert.equal(neither.keys.includes('fit_legacy'), true, 'neither side bound keeps the blunt sentence')
  assert.equal(neither.keys.includes('fit_mixed'), false)

  // The ceiling, clause by clause. It never says both parties authorized the exact
  // semantics, never says a value is true, and never promotes the legacy side.
  const text = render.SENTENCES.fit_mixed
  assert.ok(text.includes('canonical authorization from [party] for [operation]'))
  assert.ok(text.includes('does not cryptographically bind all fit semantics'))
  assert.ok(text.includes('recorded outcome [O]'))
  for (const banned of [/both (parties|keys) authorized/i, /\bis true\b/i, /\bverified\b/i, /equivalent/i]) {
    assert.equal(banned.test(text), false, `the ceiling must not contain ${banned}`)
  }

  // And an ABSENT warrant still emits nothing about either side, mixed included: absent is
  // not weak, and there is no approved sentence for a missing row.
  const oneAbsent = render.renderFitHandshake({
    request: bound('fit_request', 'canonical'), commit: null, standingScope: false,
  })
  assert.equal(oneAbsent.keys.includes('fit_mixed'), false)
  assert.equal(oneAbsent.keys.includes('fit_legacy'), false)
  assert.equal(oneAbsent.missing_warrant, true)
})

test('WARRANT: the standing scope sentence appears only when a CANONICAL commit established one', () => {
  const canonical = render.renderFitHandshake({
    request: bound('fit_request', 'canonical'), commit: bound('fit_commit', 'canonical'), standingScope: true,
  })
  assert.equal(canonical.keys.includes('fit_standing_scope'), true)
  assert.equal(canonical.sentences.includes(render.SENTENCES.fit_standing_scope), true)
  // The second sentence of 5.3 is not optional, so it travels inside the one constant.
  assert.ok(render.SENTENCES.fit_standing_scope.includes('It was not individually approved.'))

  // On the legacy lane, whether the act was autonomous is established by nothing at all: the
  // field is an unsigned boolean the server reads. So no receipt may say it.
  const legacy = render.renderFitHandshake({
    request: bound('fit_request', 'legacy_unbound'), commit: bound('fit_commit', 'legacy_unbound'), standingScope: true,
  })
  assert.equal(legacy.keys.includes('fit_standing_scope'), false,
    'an unsigned boolean cannot warrant a claim about how an act was authorized')
})

test('WARRANT: the First Step approval clause stands alone when the halves were not bound', () => {
  const allCanonical = render.renderFirstStep({
    proposeA: bound('first_step_propose', 'canonical'), proposeB: bound('first_step_propose', 'canonical'),
    approveA: bound('first_step_approve', 'canonical'), approveB: bound('first_step_approve', 'canonical'),
  })
  assert.deepEqual(allCanonical.keys, ['first_step_canonical', 'first_step_finality'])

  // Legacy proposes, legacy approves. fit-firststep-approve binds the digest, so the third
  // clause survives on its own while the two half clauses are suppressed. That is the
  // ALLOWED-WITH-EDIT case, and it is the common case during the window.
  const legacyHalves = render.renderFirstStep({
    proposeA: bound('first_step_propose', 'legacy_unbound'), proposeB: bound('first_step_propose', 'legacy_unbound'),
    approveA: bound('first_step_approve', 'legacy_unbound'), approveB: bound('first_step_approve', 'legacy_unbound'),
  })
  assert.deepEqual(legacyHalves.keys, ['first_step_mixed', 'legacy_side_present', 'first_step_finality'])
  assert.equal(legacyHalves.sentences.includes(render.SENTENCES.first_step_canonical), false,
    'neither half was bound, so neither may be claimed as authorized text')
  assert.ok(render.SENTENCES.first_step_mixed.includes('Neither proposal signature covered the text of its half.'))

  // One canonical half is still not both.
  const oneHalf = render.renderFirstStep({
    proposeA: bound('first_step_propose', 'canonical'), proposeB: bound('first_step_propose', 'legacy_unbound'),
    approveA: bound('first_step_approve', 'canonical'), approveB: bound('first_step_approve', 'canonical'),
  })
  assert.equal(oneHalf.keys.includes('first_step_canonical'), false)
  assert.equal(oneHalf.keys.includes('first_step_mixed'), true)
})

test('WARRANT: warrants fails closed on a missing row, an unparseable list and an absent field', () => {
  assert.equal(render.warrants(null, ['payload.note']), false, 'an absent warrant is not a weak warrant')
  assert.equal(render.warrants(undefined, ['payload.note']), false)
  assert.equal(render.warrants([], ['payload.note']), false)
  assert.equal(render.warrants(['payload.note'], ['payload.note', 'payload.purpose']), false,
    'every named field must be covered, not just one')
  assert.equal(render.warrants({ bound_fields_json: 'not json' } as any, ['x']), false)
  assert.equal(render.warrants({ bound_fields_json: '["x"]' } as any, ['x']), true)
  assert.deepEqual(render.warrantList(null), [])
  assert.deepEqual(render.warrantList(['a', 'b']), ['a', 'b'])
  assert.deepEqual(render.warrantList({ bound_fields_json: '["a"]' } as any), ['a'])
})

test('WARRANT: the intro request clause names the note only when the note was covered', () => {
  const canonical = render.renderIntroRequest(bound('request_intro', 'canonical'))
  assert.deepEqual(canonical.keys, ['request_canonical'])
  assert.ok(canonical.sentences[0].includes('with the exact note recorded here'))

  const legacy = render.renderIntroRequest(bound('request_intro', 'legacy_unbound'))
  assert.deepEqual(legacy.keys, ['request_legacy'])
  assert.equal(legacy.sentences[0].includes('with the exact note recorded here'), false)
  assert.ok(legacy.sentences[0].includes('The note stored with it was not covered by that signature.'),
    'and the edit is not optional')
})
