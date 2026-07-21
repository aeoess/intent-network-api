// ══════════════════════════════════════════════════════════════
// Mingle server receipt key
// ══════════════════════════════════════════════════════════════
// The server signs fit-record digests so a party can verify the record they hold
// is the one the server closed. The key comes from env when set
// (MINGLE_RECEIPT_PUBKEY / MINGLE_RECEIPT_PRIVKEY, for persistence across
// restarts); otherwise an ephemeral pair is generated for this process, which is
// enough for tests and for verifying a receipt within a running instance.

import { generateKeyPair, sign, verify } from 'agent-passport-system'

let kp: { publicKey: string; privateKey: string } | null = null

function keypair(): { publicKey: string; privateKey: string } {
  if (!kp) {
    const publicKey = process.env.MINGLE_RECEIPT_PUBKEY
    const privateKey = process.env.MINGLE_RECEIPT_PRIVKEY
    kp = publicKey && privateKey ? { publicKey, privateKey } : generateKeyPair()
  }
  return kp
}

export function serverPublicKey(): string { return keypair().publicKey }
export function signReceipt(digest: string): string { return sign(digest, keypair().privateKey) }
export function verifyReceipt(digest: string, receipt: string): boolean {
  try { return verify(digest, receipt, keypair().publicKey) } catch { return false }
}
