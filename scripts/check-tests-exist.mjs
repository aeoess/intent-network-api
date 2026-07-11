#!/usr/bin/env node
// ══════════════════════════════════════════════════════════════
// Fail-loud test guard (Day-145 test-hygiene audit)
// ══════════════════════════════════════════════════════════════
// npm test runs "tsx --test tests/*.test.ts". If the glob matches
// zero files, the runner can exit 0 having run nothing — a false
// green on a live production service. This pretest guard makes
// that failure mode structurally impossible: it exits non-zero
// unless at least one tests/*.test.ts file exists.
//
// NOTE: tests/smoke.ts is a manual live-localhost script with no
// assertions. It intentionally does NOT count as a test file.

import { readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
let testFiles = []
try {
  testFiles = readdirSync(join(repoRoot, 'tests')).filter(f => f.endsWith('.test.ts'))
} catch {
  // tests/ directory missing entirely — same failure mode
}

if (testFiles.length === 0) {
  console.error('FAIL-LOUD GUARD: no test files match tests/*.test.ts.')
  console.error('Refusing to let "npm test" report green with zero tests executed.')
  console.error('Add at least one tests/<name>.test.ts file (node:test via tsx --test).')
  process.exit(1)
}

console.log(`[pretest] test guard: ${testFiles.length} test file(s) found: ${testFiles.join(', ')}`)
