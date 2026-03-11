import { createIntentCard, generateKeyPair } from 'agent-passport-system'

const keysA = generateKeyPair()
const keysB = generateKeyPair()

const cardA = createIntentCard({
  agentId: 'alice-agent', principalAlias: 'Alice (Founder)',
  publicKey: keysA.publicKey, privateKey: keysA.privateKey,
  needs: [{ category: 'engineering', description: 'Senior Rust backend engineer', priority: 'high', tags: ['rust', 'protocols', 'backend'], visibility: 'public' }],
  offers: [{ category: 'funding', description: 'Seed investment for dev tools', priority: 'medium', tags: ['seed', 'devtools'], visibility: 'public' }],
  openTo: ['introductions', 'partnerships'], notOpenTo: ['cold-sales'],
  ttlSeconds: 86400,
})

const cardB = createIntentCard({
  agentId: 'bob-agent', principalAlias: 'Bob (Engineer)',
  publicKey: keysB.publicKey, privateKey: keysB.privateKey,
  needs: [{ category: 'funding', description: 'Seed funding for dev tools startup', priority: 'high', tags: ['seed', 'devtools'], visibility: 'public' }],
  offers: [{ category: 'engineering', description: 'Senior Rust engineer, 8yr protocol exp', priority: 'high', tags: ['rust', 'protocols', 'backend'], visibility: 'public' }],
  openTo: ['introductions', 'contracts'], notOpenTo: [],
  ttlSeconds: 86400,
})

const API = 'http://localhost:3100'

async function test() {
  // Publish Alice
  let res = await fetch(`${API}/api/cards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...cardA, publicKey: keysA.publicKey, signature: cardA.signature }),
  })
  console.log('Alice publish:', await res.json())

  // Publish Bob
  res = await fetch(`${API}/api/cards`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...cardB, publicKey: keysB.publicKey, signature: cardB.signature }),
  })
  console.log('Bob publish:', await res.json())

  // Alice matches
  res = await fetch(`${API}/api/matches/alice-agent`, { headers: { 'X-Agent-Id': 'alice-agent' } })
  const matches = await res.json()
  console.log(`\nAlice found ${matches.matchCount} match(es):`)
  for (const m of matches.matches) {
    console.log(`  → ${m.agentB} (score: ${m.score}, mutual: ${m.mutual})`)
    for (const nom of m.needOfferMatches) {
      console.log(`    ${nom.needFrom} needs "${nom.need.category}" ↔ ${nom.offerFrom} offers "${nom.offer.category}" (${nom.matchType})`)
    }
  }

  // Alice digest
  res = await fetch(`${API}/api/digest/alice-agent`, { headers: { 'X-Agent-Id': 'alice-agent' } })
  const digest = await res.json()
  console.log(`\nAlice digest: "${digest.summary}"`)
  console.log(`Network size: ${digest.networkSize} cards`)

  // Stats
  res = await fetch(`${API}/api/stats`)
  const stats = await res.json()
  console.log(`\nNetwork stats:`, stats)
}

test().catch(console.error)
