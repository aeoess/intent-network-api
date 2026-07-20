// ══════════════════════════════════════════════════════════════
// Minimal QR encoder (byte mode, ECC level M) - self-contained, no deps
// ══════════════════════════════════════════════════════════════
// Written from ISO/IEC 18004 (QR Code) so the event-wall page can render a
// join QR without adding a runtime dependency to the live server. Byte mode,
// error-correction level M, automatic version selection (1 through 10), full
// mask evaluation. Returns an inline SVG string, or null on any failure so the
// caller can fall back to the plain URL.
//
// This is a fresh implementation; scan it once against a phone before the
// projector wall goes live (recorded in the handoff).

// ── GF(256) tables, primitive polynomial 0x11d ───────────────────────────
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(function initGf() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();
const gfMul = (a: number, b: number): number => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

function rsGenerator(degree: number): number[] {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= gfMul(poly[j], EXP[i]);
      next[j + 1] ^= poly[j];
    }
    poly = next;
  }
  return poly;
}

function rsEncode(data: number[], ecLen: number): number[] {
  const gen = rsGenerator(ecLen);
  const res = new Array(ecLen).fill(0);
  for (const d of data) {
    const factor = d ^ res[0];
    res.shift();
    res.push(0);
    for (let j = 0; j < ecLen; j++) res[j] ^= gfMul(gen[j], factor);
  }
  return res;
}

// ── Version parameters for ECC level M (data codewords, ec per block, blocks)
// [totalDataCodewords, ecCodewordsPerBlock, blocks group1, blocks group2] per
// ISO/IEC 18004 Table 9 (level M), versions 1..10.
interface VerParam { version: number; ecPerBlock: number; g1Blocks: number; g1Words: number; g2Blocks: number; g2Words: number }
const M_PARAMS: VerParam[] = [
  { version: 1, ecPerBlock: 10, g1Blocks: 1, g1Words: 16, g2Blocks: 0, g2Words: 0 },
  { version: 2, ecPerBlock: 16, g1Blocks: 1, g1Words: 28, g2Blocks: 0, g2Words: 0 },
  { version: 3, ecPerBlock: 26, g1Blocks: 1, g1Words: 44, g2Blocks: 0, g2Words: 0 },
  { version: 4, ecPerBlock: 18, g1Blocks: 2, g1Words: 32, g2Blocks: 0, g2Words: 0 },
  { version: 5, ecPerBlock: 24, g1Blocks: 2, g1Words: 43, g2Blocks: 0, g2Words: 0 },
  { version: 6, ecPerBlock: 16, g1Blocks: 4, g1Words: 27, g2Blocks: 0, g2Words: 0 },
  { version: 7, ecPerBlock: 18, g1Blocks: 4, g1Words: 31, g2Blocks: 0, g2Words: 0 },
  { version: 8, ecPerBlock: 22, g1Blocks: 2, g1Words: 38, g2Blocks: 2, g2Words: 39 },
  { version: 9, ecPerBlock: 22, g1Blocks: 3, g1Words: 36, g2Blocks: 2, g2Words: 37 },
  { version: 10, ecPerBlock: 26, g1Blocks: 4, g1Words: 43, g2Blocks: 1, g2Words: 44 },
];
const dataCapacity = (p: VerParam): number => p.g1Blocks * p.g1Words + p.g2Blocks * p.g2Words;
const ALIGN_POS: Record<number, number[]> = { 1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50] };

// ── Bit buffer ────────────────────────────────────────────────────────────
class Bits {
  bits: number[] = [];
  push(val: number, len: number): void { for (let i = len - 1; i >= 0; i--) this.bits.push((val >> i) & 1); }
}

function buildCodewords(text: string): { words: number[]; param: VerParam } | null {
  const data = Array.from(new TextEncoder().encode(text));
  for (const p of M_PARAMS) {
    const cap = dataCapacity(p);
    const countBits = p.version < 10 ? 8 : 16;
    const b = new Bits();
    b.push(0b0100, 4);            // byte mode
    b.push(data.length, countBits);
    for (const d of data) b.push(d, 8);
    const totalBits = cap * 8;
    if (b.bits.length + 4 <= totalBits) b.push(0, Math.min(4, totalBits - b.bits.length)); // terminator
    while (b.bits.length % 8 !== 0) b.bits.push(0);
    const words: number[] = [];
    for (let i = 0; i < b.bits.length; i += 8) { let v = 0; for (let j = 0; j < 8; j++) v = (v << 1) | b.bits[i + j]; words.push(v); }
    const pads = [0xec, 0x11];
    let pi = 0;
    while (words.length < cap) { words.push(pads[pi % 2]); pi++; }
    if (words.length > cap) continue;
    // Split into blocks, compute EC, interleave.
    const blocks: { data: number[]; ec: number[] }[] = [];
    let off = 0;
    for (let g = 0; g < 2; g++) {
      const n = g === 0 ? p.g1Blocks : p.g2Blocks;
      const w = g === 0 ? p.g1Words : p.g2Words;
      for (let k = 0; k < n; k++) { const d = words.slice(off, off + w); off += w; blocks.push({ data: d, ec: rsEncode(d, p.ecPerBlock) }); }
    }
    const maxData = Math.max(...blocks.map(bl => bl.data.length));
    const out: number[] = [];
    for (let i = 0; i < maxData; i++) for (const bl of blocks) if (i < bl.data.length) out.push(bl.data[i]);
    for (let i = 0; i < p.ecPerBlock; i++) for (const bl of blocks) out.push(bl.ec[i]);
    return { words: out, param: p };
  }
  return null;
}

// ── Matrix placement ──────────────────────────────────────────────────────
type Grid = { size: number; mods: Int8Array; fn: Uint8Array };
const idx = (g: Grid, r: number, c: number): number => r * g.size + c;
function newGrid(version: number): Grid { const size = version * 4 + 17; return { size, mods: new Int8Array(size * size).fill(-1), fn: new Uint8Array(size * size) }; }
function setFn(g: Grid, r: number, c: number, v: number): void { g.mods[idx(g, r, c)] = v; g.fn[idx(g, r, c)] = 1; }

function placeFinder(g: Grid, r: number, c: number): void {
  for (let dr = -1; dr <= 7; dr++) for (let dc = -1; dc <= 7; dc++) {
    const rr = r + dr, cc = c + dc;
    if (rr < 0 || rr >= g.size || cc < 0 || cc >= g.size) continue;
    const inRing = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
    const dark = inRing && ((dr === 0 || dr === 6 || dc === 0 || dc === 6) || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
    setFn(g, rr, cc, dark ? 1 : 0);
  }
}

function buildFunctionPatterns(g: Grid, version: number): void {
  placeFinder(g, 0, 0); placeFinder(g, 0, g.size - 7); placeFinder(g, g.size - 7, 0);
  for (let i = 8; i < g.size - 8; i++) { const v = i % 2 === 0 ? 1 : 0; setFn(g, 6, i, v); setFn(g, i, 6, v); }
  const pos = ALIGN_POS[version];
  for (const r of pos) for (const c of pos) {
    if ((r <= 8 && c <= 8) || (r <= 8 && c >= g.size - 9) || (r >= g.size - 9 && c <= 8)) continue;
    for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) {
      const dark = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
      setFn(g, r + dr, c + dc, dark ? 1 : 0);
    }
  }
  setFn(g, g.size - 8, 8, 1); // dark module
  // reserve format info areas (filled later)
  for (let i = 0; i < 9; i++) { if (i !== 6) { setFn(g, 8, i, 0); setFn(g, i, 8, 0); } }
  for (let i = 0; i < 8; i++) { setFn(g, 8, g.size - 1 - i, 0); setFn(g, g.size - 1 - i, 8, 0); }
}

function placeData(g: Grid, words: number[]): void {
  const bits: number[] = [];
  for (const w of words) for (let i = 7; i >= 0; i--) bits.push((w >> i) & 1);
  let bi = 0, up = true;
  for (let col = g.size - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (let i = 0; i < g.size; i++) {
      const row = up ? g.size - 1 - i : i;
      for (const c of [col, col - 1]) {
        if (g.fn[idx(g, row, c)]) continue;
        g.mods[idx(g, row, c)] = bi < bits.length ? bits[bi++] : 0;
      }
    }
    up = !up;
  }
}

const MASKS: ((r: number, c: number) => boolean)[] = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

function applyMask(g: Grid, mask: number): Grid {
  const out: Grid = { size: g.size, mods: g.mods.slice(), fn: g.fn };
  for (let r = 0; r < g.size; r++) for (let c = 0; c < g.size; c++) {
    if (g.fn[idx(g, r, c)]) continue;
    if (MASKS[mask](r, c)) out.mods[idx(out, r, c)] ^= 1;
  }
  return out;
}

function formatBits(mask: number): number {
  // ECC level M = 0b00; combined with mask, BCH(15,5), XOR 0x5412.
  const data = (0b00 << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9 & 1) ? 0x537 : 0);
  return ((data << 10) | rem) ^ 0x5412;
}

function placeFormat(g: Grid, mask: number): void {
  const bits = formatBits(mask);
  for (let i = 0; i <= 5; i++) { const b = (bits >> i) & 1; g.mods[idx(g, 8, i)] = b; g.fn[idx(g, 8, i)] = 1; }
  g.mods[idx(g, 8, 7)] = (bits >> 6) & 1; g.fn[idx(g, 8, 7)] = 1;
  g.mods[idx(g, 8, 8)] = (bits >> 7) & 1; g.fn[idx(g, 8, 8)] = 1;
  g.mods[idx(g, 7, 8)] = (bits >> 8) & 1; g.fn[idx(g, 7, 8)] = 1;
  for (let i = 9; i <= 14; i++) { const b = (bits >> i) & 1; g.mods[idx(g, 14 - i, 8)] = b; g.fn[idx(g, 14 - i, 8)] = 1; }
  for (let i = 0; i <= 7; i++) { const b = (bits >> i) & 1; g.mods[idx(g, g.size - 1 - i, 8)] = b; g.fn[idx(g, g.size - 1 - i, 8)] = 1; }
  for (let i = 8; i <= 14; i++) { const b = (bits >> i) & 1; g.mods[idx(g, 8, g.size - 15 + i)] = b; g.fn[idx(g, 8, g.size - 15 + i)] = 1; }
}

function penalty(g: Grid): number {
  let p = 0;
  const at = (r: number, c: number) => g.mods[idx(g, r, c)];
  for (let r = 0; r < g.size; r++) { let run = 1; for (let c = 1; c < g.size; c++) { if (at(r, c) === at(r, c - 1)) { run++; if (run === 5) p += 3; else if (run > 5) p++; } else run = 1; } }
  for (let c = 0; c < g.size; c++) { let run = 1; for (let r = 1; r < g.size; r++) { if (at(r, c) === at(r - 1, c)) { run++; if (run === 5) p += 3; else if (run > 5) p++; } else run = 1; } }
  for (let r = 0; r < g.size - 1; r++) for (let c = 0; c < g.size - 1; c++) if (at(r, c) === at(r, c + 1) && at(r, c) === at(r + 1, c) && at(r, c) === at(r + 1, c + 1)) p += 3;
  let dark = 0; for (let i = 0; i < g.size * g.size; i++) dark += g.mods[i];
  const ratio = Math.abs(Math.round((dark * 100) / (g.size * g.size)) - 50) / 5;
  p += Math.floor(ratio) * 10;
  return p;
}

/** Encode text to an inline SVG QR, or null on failure (caller uses fallback). */
export function qrSvg(text: string, opts: { moduleSize?: number; quiet?: number } = {}): string | null {
  try {
    const built = buildCodewords(text);
    if (!built) return null;
    const base = newGrid(built.param.version);
    buildFunctionPatterns(base, built.param.version);
    placeData(base, built.words);
    let best: Grid | null = null; let bestPenalty = Infinity;
    for (let m = 0; m < 8; m++) {
      const masked = applyMask(base, m);
      placeFormat(masked, m);
      const pen = penalty(masked);
      if (pen < bestPenalty) { bestPenalty = pen; best = masked; }
    }
    if (!best) return null;
    const g = best;
    const ms = opts.moduleSize ?? 6;
    const quiet = opts.quiet ?? 4;
    const dim = (g.size + quiet * 2) * ms;
    const rects: string[] = [];
    for (let r = 0; r < g.size; r++) for (let c = 0; c < g.size; c++) {
      if (g.mods[idx(g, r, c)] === 1) rects.push(`<rect x="${(c + quiet) * ms}" y="${(r + quiet) * ms}" width="${ms}" height="${ms}"/>`);
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" width="${dim}" height="${dim}" viewBox="0 0 ${dim} ${dim}" role="img" aria-label="QR code for the join link"><rect width="${dim}" height="${dim}" fill="#fff"/><g fill="#000">${rects.join('')}</g></svg>`;
  } catch {
    return null;
  }
}
