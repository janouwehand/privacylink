export interface CreateChallenge {
  version: number;
  challengeId: string;
  nonce: string;
  difficultyBits: number;
  expiresAt: number;
  signature: string;
}

export type CreateProofChallenge = Pick<CreateChallenge, 'challengeId' | 'nonce' | 'difficultyBits'>;

/** Solves the API's signed SHA-256 create challenge in a browser-compatible runtime. */
export async function solveCreateProof(challenge: CreateProofChallenge, isCancelled: () => boolean = () => false): Promise<string> {
  const encoder = new TextEncoder();
  const maxCounter = 0xffffffffffffffffn;
  for (let counter = 0n; counter <= maxCounter; counter++) {
    if (isCancelled()) throw new Error('Proof calculation cancelled');
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(`PrivacyLink-Create-PoW-v1:${challenge.challengeId}:${challenge.nonce}:${counter}`)));
    let zeroBits = 0;
    for (const byte of digest) {
      if (byte === 0) { zeroBits += 8; continue; }
      zeroBits += Math.clz32(byte) - 24;
      break;
    }
    if (zeroBits >= challenge.difficultyBits) return counter.toString();
    if ((counter & 2047n) === 2047n) await new Promise(resolve => setTimeout(resolve, 0));
  }
  throw new Error('Proof counter exhausted');
}
