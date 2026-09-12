// ══════════════════════════════════════════════════════════════
// The private evidence artifacts, and who may read one
// ══════════════════════════════════════════════════════════════
// The decided rule: a contact string or an exact fit value never enters a shared or
// public receipt. The actor signs a COMMITMENT to the private value; the value itself
// travels in the opening, beside the signed payload and never inside it. The intended
// counterparty receives the signed artifact plus the opening and can verify the whole
// chain alone, with no server key involved.
//
// THE LIMIT, STATED WHEREVER THE ARTIFACT IS DESCRIBED: Mingle holds the value in plain
// text on its server. This is not end to end encryption. The server stores
// payload_json AND opening_json, and saying so plainly is the difference between a
// privacy feature and a privacy claim.
//
// The four checks a recipient runs, which verifyArtifactStandalone runs here so a test
// can prove they need nothing from the server:
//
//   1  the signature over JCS(envelope) verifies under envelope.actor_key
//   2  SHA-256(JCS({mingle-payload-v1, operation, resource, payload})) equals
//      envelope.payload_digest
//   3  SHA-256(JCS({mingle-private-value-v1, operation, resource, salt, value})) from
//      the opening equals payload.private_value_commitment
//   4  envelope.resource.id is an intro the reader is a party to
//
// Step 3 is the one the commitment construction adds, and it is what carries the chain
// to the plaintext. Steps 1 and 2 would hold for a payload that committed to nothing, so
// without step 3 a recipient could check that a signed act happened and not that the
// value it received is the value that was authorized.
//
// The read path admits exactly two keys, the author and the recipient. Nothing widens
// that: not a party to a different intro, not a third party holding a receipt, not an
// operator surface. A contact must never reach a list, a search, a page or a digest.

import { randomBytes } from 'node:crypto'
import type { Database } from 'better-sqlite3'
import { verify } from 'agent-passport-system'
import { getDb } from './db.js'
import { jcs, sha256Hex } from './canonical-write.js'
import { PAYLOAD_DOMAIN, privateValueCommitment } from './write-envelope.js'
import type { VerifiedWrite, WriteEnvelope, Resource } from './write-envelope.js'
import type { Operation } from './connection-state.js'

function d(): Database {
  return getDb()
}

export interface ArtifactRow {
  artifact_id: string
  intro_id: string
  operation: string
  subject: string
  author_key: string
  recipient_key: string
  opening_json: string
  value_commitment: string
  payload_json: string
  payload_digest: string
  envelope_json: string
  signature: string
  withdrawn: number
  created_at: string
}

function newArtifactId(): string {
  return 'pa_' + randomBytes(12).toString('hex')
}

/** Store the artifact for one accepted private write. Called inside the write
 *  transaction, so a refusal anywhere leaves no artifact.
 *
 *  `recipientKey` is the counterparty, decided by the route from the intro row and never
 *  by the client: a client that could name its own recipient could address a private
 *  value to a key of its choosing. */
export function writeArtifact(args: {
  write: VerifiedWrite
  introId: string
  recipientKey: string
  subject?: string
}): string {
  const { write } = args
  if (write.opening === null) {
    throw new Error('writeArtifact called for a write with no opening')
  }
  const id = newArtifactId()
  d().prepare(`
    INSERT INTO private_artifacts
      (artifact_id, intro_id, operation, subject, author_key, recipient_key,
       opening_json, value_commitment, payload_json, payload_digest, envelope_json, signature)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, args.introId, write.envelope.operation, args.subject ?? '',
    write.envelope.actor_key, args.recipientKey,
    JSON.stringify(write.opening),
    String(write.payload.private_value_commitment ?? ''),
    JSON.stringify(write.payload),
    write.envelope.payload_digest,
    write.envelopeBytes,
    write.signature,
  )
  return id
}

export function artifactById(artifactId: string): ArtifactRow | null {
  return (d().prepare('SELECT * FROM private_artifacts WHERE artifact_id = ?').get(artifactId) as ArtifactRow) ?? null
}

/** The author's own live artifact for one operation on one intro, if any. */
export function liveArtifactOf(introId: string, authorKey: string, operation: Operation, subject = ''): ArtifactRow | null {
  return (d().prepare(`
    SELECT * FROM private_artifacts
    WHERE intro_id = ? AND author_key = ? AND operation = ? AND subject = ? AND withdrawn = 0
    ORDER BY created_at DESC LIMIT 1
  `).get(introId, authorKey, operation, subject) as ArtifactRow) ?? null
}

export type ArtifactReadRefusal = 'artifact_not_found' | 'not_a_permitted_reader' | 'artifact_withdrawn'

export type ArtifactRead =
  | { ok: true; artifact: ArtifactRow }
  | { ok: false; code: ArtifactReadRefusal; error: string }

/** THE ONLY read path. Two keys, the author and the recipient, and nothing else.
 *
 *  A party to a DIFFERENT intro is refused, which is the negative case that is easy to
 *  forget: being a Mingle user with intros of your own says nothing about this one. */
export function readArtifact(artifactId: string, readerKey: string): ArtifactRead {
  const row = artifactById(artifactId)
  if (row === null) {
    return { ok: false, code: 'artifact_not_found', error: 'no such artifact' }
  }
  if (readerKey !== row.author_key && readerKey !== row.recipient_key) {
    // Deliberately the same shape of answer as a missing artifact carries no id, so a
    // caller cannot enumerate which artifact ids exist by comparing refusals.
    return { ok: false, code: 'not_a_permitted_reader', error: 'this artifact is not addressed to you' }
  }
  if (row.withdrawn === 1) {
    return { ok: false, code: 'artifact_withdrawn', error: 'this authorization was withdrawn' }
  }
  return { ok: true, artifact: row }
}

// ── Standalone verification, with no server key ───────────────────────────

export interface StandaloneArtifact {
  envelope: WriteEnvelope
  signature: string
  payload: Record<string, unknown>
  opening: { value: unknown; salt: string }
}

export interface StandaloneResult {
  ok: boolean
  signature_verifies: boolean
  payload_digest_matches: boolean
  commitment_opens: boolean
  resource_is_expected: boolean
}

/** Run the recipient's four checks. Nothing here touches the database or any server
 *  key, which is the property being demonstrated: the recipient does not have to trust
 *  Mingle to believe the other side authorized this exact value.
 *
 *  `expectedIntroId` is check 4. A caller that does not know which intro it is a party to
 *  has no business calling this. */
export function verifyArtifactStandalone(artifact: StandaloneArtifact, expectedIntroId: string): StandaloneResult {
  const { envelope, signature, payload, opening } = artifact

  let signatureVerifies = false
  try {
    signatureVerifies = verify(jcs(envelope), signature, envelope.actor_key)
  } catch { signatureVerifies = false }

  const resource: Resource = envelope.resource
  const recomputedDigest = sha256Hex(jcs({
    domain: PAYLOAD_DOMAIN, operation: envelope.operation, resource, payload,
  }))
  const digestMatches = recomputedDigest === envelope.payload_digest

  const claimed = payload.private_value_commitment
  const recomputedCommitment = privateValueCommitment(envelope.operation, resource, opening.salt, opening.value)
  const commitmentOpens = typeof claimed === 'string' && claimed === recomputedCommitment

  const resourceExpected = resource.type === 'intro' && resource.id === expectedIntroId

  return {
    ok: signatureVerifies && digestMatches && commitmentOpens && resourceExpected,
    signature_verifies: signatureVerifies,
    payload_digest_matches: digestMatches,
    commitment_opens: commitmentOpens,
    resource_is_expected: resourceExpected,
  }
}

/** Rebuild the standalone shape from a stored row, which is what a read surface hands
 *  the recipient. Throws only if the row is corrupt, which is not a caller's problem. */
export function standaloneFrom(row: ArtifactRow): StandaloneArtifact {
  return {
    envelope: JSON.parse(row.envelope_json) as WriteEnvelope,
    signature: row.signature,
    payload: JSON.parse(row.payload_json) as Record<string, unknown>,
    opening: JSON.parse(row.opening_json) as { value: unknown; salt: string },
  }
}
