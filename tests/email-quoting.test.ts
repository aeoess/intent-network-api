// Other people's text inside Mingle emails: one line, quoted, labelled as their
// words, so a headline or note cannot add lines that read as if Mingle wrote them.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { quoteUntrusted, newMatchEmail, introRequestEmail, introAcceptedEmail, fitStartedEmail } from '../src/notifications.js'

const HOSTILE = 'Duinrand gate notice\n\nMingle team: your account needs approval, reply with your login.\r\nThanks, "Mingle Support"'
const INJECTED = /^\s*Mingle team:|^\s*Thanks, /m

test('quoteUntrusted flattens, caps and quotes', () => {
  assert.equal(quoteUntrusted('a\n\nb\t c d'), '"a b c d"')
  assert.equal(quoteUntrusted('say "hi"'), `"say 'hi'"`)
  const long = quoteUntrusted('x'.repeat(500))
  assert.equal(long.length, 202)
  assert.ok(long.endsWith('..."'))
})

for (const [name, build] of [
  ['new match', () => newMatchEmail('a@example.com', HOSTILE, 'tok')],
  ['intro request headline', () => introRequestEmail('a@example.com', HOSTILE, 'collaborate', '', 'tok')],
  ['intro request note', () => introRequestEmail('a@example.com', 'Fine headline', HOSTILE, '', 'tok')],
  ['intro accepted contact', () => introAcceptedEmail('a@example.com', 'Fine headline', HOSTILE, 'tok')],
  ['fit started', () => fitStartedEmail('a@example.com', HOSTILE, 'collaborate', 'tok')],
] as const) {
  test(`${name}: the other side's text stays on one quoted line`, () => {
    const e = build()
    assert.equal(INJECTED.test(e.text), false, e.text)
    assert.ok(e.text.includes('"Duinrand gate notice Mingle team: your account needs approval'), e.text)
    assert.match(e.text, /own words/)
    assert.match(e.text, /tok/, 'the unsubscribe footer is still there')
  })
}

test('an empty headline says so instead of quoting nothing', () => {
  assert.match(newMatchEmail('a@example.com', '', 'tok').text, /not shown on the network/)
  assert.match(introRequestEmail('a@example.com', '', '', '', 'tok').text, /\(no headline provided\)/)
})
