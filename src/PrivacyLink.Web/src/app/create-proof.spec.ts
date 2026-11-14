import { describe, expect, it } from 'vitest';
import { solveCreateProof, solveOpenProof } from '../../../PrivacyLink.Client/src';

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

  it('includes the secret and operation in a recipient proof', async () => {
    const challenge = { version: 1, challengeId: 'AAAAAAAAAAAAAAAAAAAAAA', nonce: 'BBBBBBBBBBBBBBBBBBBBBB', difficultyBits: 1, expiresAt: 1791747900, signature: 'signature' };
    const header = await solveOpenProof(challenge, 'CCCCCCCCCCCCCCCCCCCCCC', 'unlock');
    const [id, nonce, bits, expiry, signature, counter] = header.split('.');
    expect([id, nonce, bits, expiry, signature]).toEqual([challenge.challengeId, challenge.nonce, '1', '1791747900', challenge.signature]);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`PrivacyLink-Open-PoW-v1:${id}:CCCCCCCCCCCCCCCCCCCCCC:unlock:${nonce}:${counter}`)));
    expect(digest[0]! & 0x80).toBe(0);
  });
});
