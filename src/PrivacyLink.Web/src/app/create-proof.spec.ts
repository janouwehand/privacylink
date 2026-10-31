import { describe, expect, it } from 'vitest';
import { solveCreateProof } from '../../../PrivacyLink.Client/src';

describe('create proof', () => {
  it('returns a decimal counter whose challenge digest meets the requested difficulty', async () => {
    const challenge = { challengeId: 'challenge-id', nonce: 'challenge-nonce', difficultyBits: 8 };
    const counter = await solveCreateProof(challenge);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`PrivacyLink-Create-PoW-v1:${challenge.challengeId}:${challenge.nonce}:${counter}`)));

    expect(counter).toMatch(/^\d+$/);
    expect(digest[0]).toBe(0);
  });

  it('supports cancellation without coupling the core solver to a Worker API', async () => {
    await expect(solveCreateProof({ challengeId: 'challenge-id', nonce: 'challenge-nonce', difficultyBits: 24 }, () => true))
      .rejects.toThrow('Proof calculation cancelled');
  });
});
