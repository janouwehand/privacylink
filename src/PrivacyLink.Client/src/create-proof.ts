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
  return solveCounter(challenge.difficultyBits, counter => `PrivacyLink-Create-PoW-v1:${challenge.challengeId}:${challenge.nonce}:${counter}`, isCancelled);
}

/** Solves a secret- and operation-bound open challenge and returns its proof header. */
export async function solveOpenProof(
  challenge: CreateChallenge,
  secretId: string,
  action: 'open' | 'unlock' | `file-open:${string}`,
  isCancelled: () => boolean = () => false
): Promise<string> {
  const counter = await solveCounter(challenge.difficultyBits,
    value => `PrivacyLink-Open-PoW-v1:${challenge.challengeId}:${secretId}:${action}:${challenge.nonce}:${value}`, isCancelled);
  return `${challenge.challengeId}.${challenge.nonce}.${challenge.difficultyBits}.${challenge.expiresAt}.${challenge.signature}.${counter}`;
}

async function solveCounter(difficultyBits: number, proofText: (counter: bigint) => string, isCancelled: () => boolean): Promise<string> {
  const encoder = new TextEncoder();
  const maxCounter = 0xffffffffffffffffn;
  for (let counter = 0n; counter <= maxCounter; counter++) {
    if (isCancelled()) throw new Error('Proof calculation cancelled');
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(proofText(counter))));
    let zeroBits = 0;
    for (const byte of digest) {
      if (byte === 0) { zeroBits += 8; continue; }
      zeroBits += Math.clz32(byte) - 24;
      break;
    }
    if (zeroBits >= difficultyBits) return counter.toString();
    if ((counter & 2047n) === 2047n) await new Promise(resolve => setTimeout(resolve, 0));
  }
  throw new Error('Proof counter exhausted');
}
