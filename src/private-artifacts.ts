// ══════════════════════════════════════════════════════════════
// The private evidence artifacts, and who may read one
// ══════════════════════════════════════════════════════════════
// The decided rule: a contact string or an exact fit value never enters a shared or
// public receipt. The actor signs a COMMITMENT to the private value, and the value itself
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
import { PAYLOAD_DOMAIN, WRITE_DOMAIN, ENVELOPE_FIELDS, privateValueCommitment } from './write-envelope.js'
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

/** `artifact_unavailable` covers BOTH "no such artifact" and "not addressed to you", with one
 *  message, because two distinct answers are an existence oracle: a caller holding a guessed
 *  id could tell a real one from a fabricated one by comparing refusals. The comment used to
 *  claim they were indistinguishable while the codes differed.
 *
 *  `artifact_withdrawn` stays separate because only a PERMITTED reader can reach it, so it
 *  tells a stranger nothing. */
export type ArtifactReadRefusal = 'artifact_unavailable' | 'artifact_withdrawn'

export type ArtifactRead =
  | { ok: true; artifact: ArtifactRow }
  | { ok: false; code: ArtifactReadRefusal; error: string }

/** THE ONLY read path. Two keys, the author and the recipient, and nothing else.
 *
 *  A party to a DIFFERENT intro is refused, which is the negative case that is easy to
 *  forget: being a Mingle user with intros of your own says nothing about this one. */
export function readArtifact(artifactId: string, readerKey: string): ArtifactRead {
  const row = artifactById(artifactId)
  const unavailable = { ok: false as const, code: 'artifact_unavailable' as const, error: 'no artifact is available to you under that id' }
  // One answer for both, so a caller cannot learn that an id exists by comparing refusals.
  if (row === null) return unavailable
  if (readerKey !== row.author_key && readerKey !== row.recipient_key) return unavailable
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
  /** Is the signer the key the reader expected? WITHOUT this, `ok` means only that SOMEBODY
   *  signed something that opens to this value. */
  author_is_expected: boolean
  /** Is this a mingle-write-v1 envelope carrying exactly the seven envelope fields? */
  envelope_is_well_formed: boolean
}

/** Run the recipient's checks. Nothing here touches the database or any server key, which is
 *  the property being demonstrated: the recipient does not have to trust Mingle to believe
 *  the other side authorized this exact value.
 *
 *  `expectedAuthorKey` and the two envelope checks are NOT decoration. Without the author
 *  check, a stranger could build their own share_contact envelope over the reader's intro id,
 *  commit to a value of their choosing, sign it with their OWN key, and this function would
 *  answer ok:true, byte for byte the same object as for the legitimate artifact. The four
 *  arithmetic checks establish that a signature, a digest and a commitment agree with each
 *  other. Only the author check establishes WHOSE authorization it is.
 *
 *  The domain and unknown-field checks mirror verifyWriteBody. An envelope carrying an extra
 *  signed field is refused on the server precisely because such a field may narrow authority,
 *  and a recipient verifier that accepted it would grant more than the signer asked for while
 *  the signature said otherwise. A verifier weaker than the server is a verifier that
 *  endorses what the server would refuse. */
export function verifyArtifactStandalone(
  artifact: StandaloneArtifact,
  expectedIntroId: string,
  expectedAuthorKey: string,
): StandaloneResult {
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

  const resourceExpected = resource !== undefined && resource !== null
    && resource.type === 'intro' && resource.id === expectedIntroId
  const authorExpected = typeof expectedAuthorKey === 'string' && expectedAuthorKey.length > 0
    && envelope.actor_key === expectedAuthorKey

  const keys = envelope === null || typeof envelope !== 'object' ? [] : Object.keys(envelope)
  const wellFormed = envelope?.domain === WRITE_DOMAIN
    && keys.length === ENVELOPE_FIELDS.length
    && ENVELOPE_FIELDS.every(f => keys.includes(f))

  return {
    ok: signatureVerifies && digestMatches && commitmentOpens && resourceExpected
      && authorExpected && wellFormed,
    signature_verifies: signatureVerifies,
    payload_digest_matches: digestMatches,
    commitment_opens: commitmentOpens,
    resource_is_expected: resourceExpected,
    author_is_expected: authorExpected,
    envelope_is_well_formed: wellFormed,
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
