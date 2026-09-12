// scratch probe: payload gate coverage of OBJECT KEYS and depth boundary
import { checkCanonicalPayload, jcs, sha256Hex } from './src/canonical-write.js'

function show(name: string, payload: unknown) {
  const r = checkCanonicalPayload(payload)
  let canon = '(threw)'
  let err = ''
  try { canon = jcs(payload) } catch (e: any) { err = e?.constructor?.name + ': ' + e?.message }
  console.log(`${name}\n  gate: ${JSON.stringify(r)}\n  jcs : ${err || JSON.stringify(canon)}\n`)
}

console.log('=== control characters / whitespace / lone surrogates in KEYS ===')
show('newline inside a key', { 'no\nte': 'hi' })
show('DEL inside a key', { 'note': 'hi' })
show('leading space in a key', { ' note': 'hi' })
show('lone high surrogate as a key', { '\ud800': 'hi' })
show('lone low surrogate as a key', { '\udc00': 'hi' })

console.log('=== the same in VALUES, for contrast ===')
show('newline inside a value', { note: 'a\nb' })
show('lone surrogate inside a value', { note: '\ud800' })

console.log('=== depth boundary ===')
function nest(levels: number): any {
  let v: any = 'leaf'
  for (let i = 0; i < levels; i++) v = { a: v }
  return v
}
for (const n of [11, 12, 13, 14]) {
  console.log(`object nesting levels=${n} ->`, JSON.stringify(checkCanonicalPayload(nest(n))))
}

console.log('=== arrays count toward depth too ===')
function nestArr(levels: number): any {
  let v: any = 'leaf'
  for (let i = 0; i < levels; i++) v = [v]
  return v
}
for (const n of [11, 12, 13]) {
  console.log(`array nesting levels=${n} ->`, JSON.stringify(checkCanonicalPayload(nestArr(n))))
}

console.log('=== __proto__ as a JSON key ===')
const pp = JSON.parse('{"__proto__":{"x":1},"b":2}')
show('__proto__ own key', pp)
console.log('  Object.keys:', Object.keys(pp), ' proto still Object.prototype:', Object.getPrototypeOf(pp) === Object.prototype)

console.log('=== does sha256Hex collapse anything jcs emits? ===')
console.log('  sha256 of a raw lone surrogate string:', sha256Hex('\ud800'), '\n  sha256 of U+FFFD          :', sha256Hex('�'))
