import { describe, expect, it } from 'vitest';
import { decodeCanonical, decryptFile, decryptFileName, decryptMessage, derivePasswordToken, encodeBase64Url, encryptFile } from './secret-crypto';

describe('protocol compatibility vectors', () => {
  it('decrypts the independently generated Unicode message vector and derives its access-code token', async () => {
    const clientKey = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
    const message = {
      nonce: 'AAECAwQFBgcICQoL',
      ciphertext: 'eCoRy-1UcSZNzQHtQaxmQL40KbCxBvlruAaU6SbzoDN_avX60k5xeS-dGRsq05J0tT6F-X9WUQ3oCnA'
    };

    await expect(decryptMessage({ protocolVersion: 1, message, files: [] }, clientKey))
      .resolves.toBe('Compatibility vector: café, e\u0301, 🧪 🔐');
    await expect(derivePasswordToken('päss🔐', clientKey))
      .resolves.toBe('uTqZqeHaUMYKkSjlyxGC882t8st29B9dXdNOo9PI9vc');
  });
});

describe('file encryption metadata', () => {
  it('authenticates file metadata and reconstructs the filename', async () => {
    const clientKey = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
    const plaintext = new TextEncoder().encode('encrypted file contents');
    const file = new File([plaintext], 'Quarterly report.PDF', { type: 'application/pdf' });
    const encrypted = await encryptFile(file, decodeCanonical(clientKey, 32));

    expect(encrypted.extension).toBe('.pdf');
    expect(await decryptFileName(encrypted, clientKey)).toBe('Quarterly report.pdf');
    expect(new TextDecoder().decode(await decryptFile(encrypted, clientKey))).toBe('encrypted file contents');

    const alternateId = encodeBase64Url(new Uint8Array(16).fill(1));
    await expect(decryptFileName({ ...encrypted, id: alternateId }, clientKey)).rejects.toThrow();
    await expect(decryptFile({ ...encrypted, id: alternateId }, clientKey)).rejects.toThrow();
    await expect(decryptFileName({ ...encrypted, extension: '.txt' }, clientKey)).rejects.toThrow();
    await expect(decryptFile({ ...encrypted, extension: '.txt' }, clientKey)).rejects.toThrow();
    const changedMimeType = { ...encrypted, mimeType: 'application/octet-stream' };
    await expect(decryptFileName(changedMimeType, clientKey)).rejects.toThrow();
    await expect(decryptFile(changedMimeType, clientKey)).rejects.toThrow();
    const changedSize = { ...encrypted, size: encrypted.size + 1 };
    await expect(decryptFileName(changedSize, clientKey)).rejects.toThrow();
    await expect(decryptFile(changedSize, clientKey)).rejects.toThrow();
  });
});

describe('canonical base64url encoding', () => {
  it('rejects non-canonical unused tail bits and invalid lengths', () => {
    expect(decodeCanonical('AA')).toEqual(new Uint8Array([0]));
    expect(decodeCanonical('AAA')).toEqual(new Uint8Array([0, 0]));
    expect(() => decodeCanonical('AB')).toThrow('invalid canonical encoding');
    expect(() => decodeCanonical('AAB')).toThrow('invalid canonical encoding');
    expect(() => decodeCanonical('A')).toThrow('invalid base64url');
  });

  it('round-trips a moderate payload through bounded Base64 chunks', () => {
    const bytes = Uint8Array.from({ length: 1024 * 1024 + 17 }, (_, index) => index % 251);
    const encoded = encodeBase64Url(bytes);
    expect(decodeCanonical(encoded, bytes.length)).toEqual(bytes);
  });
});
