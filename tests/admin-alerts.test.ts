// Admin alerts: at most ALERTS_PER_HOUR single emails per hour, the rest held and
// sent as one summary on flush or when the next hour starts.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { AdminAlerts, ALERTS_PER_HOUR } from '../src/admin-alerts.js'

function rig() {
  const sent: Array<{ subject: string; text: string }> = []
  let t = Date.parse('2026-11-01T05:38:27.000Z')
  const a = new AdminAlerts(async (subject, text) => { sent.push({ subject, text }) }, () => t)
  return { a, sent, advance: (ms: number) => { t += ms } }
}

test('a burst sends the first few alerts and holds the rest for one summary', async () => {
  const { a, sent } = rig()
  const results = []
  for (let i = 0; i < 8; i++) results.push(await a.newCard(`v3-connection-${i}`, `Burst card ${i}`, 'abcdef0123456789'))
  assert.deepEqual(results, [...Array(ALERTS_PER_HOUR).fill('sent'), ...Array(8 - ALERTS_PER_HOUR).fill('held')])
  assert.equal(sent.length, ALERTS_PER_HOUR)
  assert.match(sent[0].text, /key abcdef0123/)
  assert.equal(await a.flush(), 8 - ALERTS_PER_HOUR)
  assert.equal(sent.length, ALERTS_PER_HOUR + 1)
  assert.match(sent.at(-1)!.subject, /5 more new cards/)
  assert.match(sent.at(-1)!.text, /Burst card 7/)
  assert.equal(await a.flush(), 0, 'nothing held, nothing sent')
  assert.equal(sent.length, ALERTS_PER_HOUR + 1)
})

test('the next hour flushes what was held and starts a fresh allowance', async () => {
  const { a, sent, advance } = rig()
  for (let i = 0; i < ALERTS_PER_HOUR + 2; i++) await a.newCard(`c${i}`, `H1 card ${i}`, 'k1')
  advance(61 * 60 * 1000)
  assert.equal(await a.newCard('c-next', 'H2 card', 'k2'), 'sent')
  const subjects = sent.map(s => s.subject)
  assert.equal(subjects.filter(s => s === 'New Mingle card').length, ALERTS_PER_HOUR + 1)
  assert.equal(subjects.filter(s => /more new cards/.test(s)).length, 1, 'one summary for the held two')
})

test('a long burst caps the summary at 20 lines and says how many more', async () => {
  const { a, sent } = rig()
  for (let i = 0; i < ALERTS_PER_HOUR + 30; i++) await a.newCard(`c${i}`, `Long ${i}`, 'k')
  await a.flush()
  const summary = sent.at(-1)!.text
  assert.equal(summary.split('\n').filter(l => l.startsWith('Long ')).length, 20)
  assert.match(summary, /and 10 more/)
})

test('when no admin address is set nothing is sent and nothing uses up the cap', async () => {
  let calls = 0
  const a = new AdminAlerts(async () => { calls++; return { sent: false, reason: 'no_admin' } }, () => Date.now())
  for (let i = 0; i < 10; i++) assert.equal(await a.newCard(`c${i}`, 'h', 'k'), 'skipped')
  assert.equal(await a.flush(), 0)
  assert.equal(calls, 10)
})
