// The rate limiter's sliding window: a burst across an hour boundary is held to
// about the limit, the old fixed-window allowance is restored as the previous hour
// fades, and nothing the fixed window refused is now allowed.

import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const tmpDir = mkdtempSync(join(tmpdir(), 'mingle-rate-test-'))
process.env.DB_PATH = join(tmpDir, 'rate-test.db')
const db = await import('../src/db.js')
after(() => { db.closeDb(); rmSync(tmpDir, { recursive: true, force: true }) })

const H = Date.parse('2026-11-01T06:00:00.000Z')
const MIN = 60000
const burst = (key: string, n: number, at: number) => Array.from({ length: n }, () => db.checkRateLimit(key, 'test', 10, at).allowed).filter(Boolean).length

test('a burst at 05:59 and another at 06:00 is held to the limit, not twice it', () => {
  assert.equal(burst('k1', 10, H - MIN), 10)
  // The weighted estimate rounds in the caller's favour by at most one request.
  assert.ok(burst('k1', 10, H + 1000) <= 1, 'the fixed window would have allowed 10 more here')
})

test('the allowance comes back as the previous hour fades', () => {
  assert.equal(burst('k2', 10, H - 30 * MIN), 10)
  // 30 minutes into the next hour, half of the previous 10 still counts.
  assert.equal(burst('k2', 10, H + 30 * MIN), 5)
  // A full hour later only the current bucket counts again.
  assert.equal(burst('k3', 10, H + 59 * MIN), 10)
})

test('within one hour the limit is exactly as before', () => {
  assert.equal(burst('k4', 15, H + 10 * MIN), 10)
})
