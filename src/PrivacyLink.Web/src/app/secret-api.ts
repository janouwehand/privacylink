import { Inject, Injectable, InjectionToken } from '@angular/core';
import type { CreateChallenge } from '../../../PrivacyLink.Client/src';
import { getSecretCryptoWorkerClient } from './secret-crypto-worker-client';
import { EncryptedFile, EncryptedFileMetadata, EncryptedMessage, EncryptedPayload, OpenedFile } from './secret-crypto';

export class SecretApiError extends Error {
  constructor(readonly status: number, readonly retryAfterSeconds: number | null = null, readonly code: string | null = null) { super(`HTTP ${status}`); }
}

/** Empty for the same-origin website; the extension supplies its fixed API origin. */
export const PRIVACYLINK_API_ORIGIN = new InjectionToken<string>('PRIVACYLINK_API_ORIGIN', { providedIn: 'root', factory: () => '' });

async function apiError(response: Response): Promise<SecretApiError> {
  const retryAfter = Number.parseInt(response.headers.get('Retry-After') ?? '', 10);
  let code: string | null = null;
  try { code = (await response.json() as { code?: string }).code ?? null; } catch { /* A generic response is sufficient. */ }
  return new SecretApiError(response.status, Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null, code);
}

async function responseJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw await apiError(response);
  }
  return response.json() as Promise<T>;
}

async function responseArrayBuffer(response: Response): Promise<ArrayBuffer> {
  if (!response.ok) {
    throw await apiError(response);
  }
  return response.arrayBuffer();
}

function delay(milliseconds: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

@Injectable({ providedIn: 'root' })
export class SecretApi {
  constructor(@Inject(PRIVACYLINK_API_ORIGIN) private readonly apiOrigin = '') {}
  private fetchApi(input: RequestInfo | URL, init?: RequestInit): Promise<Response> { const value = typeof input === 'string' && input.startsWith('/api/') ? this.apiOrigin + input : input; return fetch(value, init); }
  private static pathPart(value: string): string { return encodeURIComponent(value); }
  getFileUploadPolicy(): Promise<{ maxFiles: number; maxTotalFileBytes: number; allowedFileExtensions: string[] }> {
    return this.fetchApi('/api/v1/capabilities', { cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson(response));
  }
  getCreateChallenge(): Promise<CreateChallenge> {
    return this.fetchApi('/api/v1/secrets/create-challenge', { cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson<CreateChallenge>(response));
  }
  async getOpenProof(id: string, action: 'open' | 'unlock' | 'file-open', fileId?: string, signal?: AbortSignal): Promise<string> {
    const secretPath = `/api/v1/secrets/${SecretApi.pathPart(id)}`;
    const challengePath = action === 'file-open'
      ? `${secretPath}/files/${SecretApi.pathPart(fileId ?? '')}/open-challenge`
      : `${secretPath}/${action}-challenge`;
    const response = await this.fetchApi(challengePath, { cache: 'no-store', referrerPolicy: 'no-referrer', signal });
    const challenge = await responseJson<CreateChallenge>(response);
    return getSecretCryptoWorkerClient().solveOpenProof(challenge, id, action === 'file-open' ? `file-open:${fileId ?? ''}` : action, signal);
  }
  create(request: { protocolVersion: 1; expiry: '1d' | '7d' | '14d'; message: EncryptedMessage | null; files: EncryptedFile[]; password?: string; emailAddress?: string; oneTimeOpen?: boolean }, proof: string): Promise<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }> {
    return this.fetchApi('/api/v1/secrets', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-PrivacyLink-Proof': proof }, body: JSON.stringify(request), cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }>(response));
  }
  createSerialized(body: ArrayBuffer, proof: string): Promise<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }> {
    return this.fetchApi('/api/v1/secrets', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-PrivacyLink-Proof': proof }, body, cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }>(response));
  }
  revoke(id: string, revokeToken: string): Promise<void> {
    return this.fetchApi(`/api/v1/secrets/${SecretApi.pathPart(id)}/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ revokeToken }), cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => {
      // Revocation is idempotent from History's perspective: 404 means the secret is already absent.
      if (!response.ok && response.status !== 404) throw new Error(`HTTP ${response.status}`);
    });
  }
  getMetadata(id: string): Promise<{ exists: boolean; protocolVersion: number; expiresAt: string; passwordProtected: boolean; hasMessage: boolean; fileCount: number; files: EncryptedFileMetadata[]; emailVerificationRequired?: boolean; maskedEmailAddress?: string | null; oneTimeOpen?: boolean; oneTimeOpened?: boolean }> {
    return this.fetchApi(`/api/v1/secrets/${SecretApi.pathPart(id)}`, { cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson(response));
  }
  requestEmailCode(id: string): Promise<{ code: string }> {
    return this.fetchApi(`/api/v1/secrets/${SecretApi.pathPart(id)}/email-verification/request`, { method: 'POST', credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson(response));
  }
  async verifyEmailCode(id: string, code: string): Promise<void> {
    const response = await this.fetchApi(`/api/v1/secrets/${SecretApi.pathPart(id)}/email-verification/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
      credentials: 'same-origin',
      cache: 'no-store',
      referrerPolicy: 'no-referrer'
    });
    if (!response.ok) throw await apiError(response);
  }
  async open(id: string, proof?: string): Promise<EncryptedPayload> {
    const proofHeader = proof ?? await this.getOpenProof(id, 'open');
    return this.fetchApi(`/api/v1/secrets/${SecretApi.pathPart(id)}/open`, { method: 'POST', headers: { 'X-PrivacyLink-Proof': proofHeader }, cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson<EncryptedPayload>(response));
  }
  async openRaw(id: string, proof?: string): Promise<ArrayBuffer> {
    const proofHeader = proof ?? await this.getOpenProof(id, 'open');
    return this.fetchApi(`/api/v1/secrets/${SecretApi.pathPart(id)}/open`, { method: 'POST', headers: { 'X-PrivacyLink-Proof': proofHeader }, cache: 'no-store', referrerPolicy: 'no-referrer' }).then(responseArrayBuffer);
  }
  unlock(id: string, password: string, proofProvider?: () => Promise<string>): Promise<EncryptedPayload> {
    return this.unlockWithRetry(id, password, response => responseJson<EncryptedPayload>(response), proofProvider);
  }

  unlockRaw(id: string, password: string, proofProvider?: () => Promise<string>): Promise<ArrayBuffer> {
    return this.unlockWithRetry(id, password, responseArrayBuffer, proofProvider);
  }

  private async unlockWithRetry<T>(id: string, password: string, readResponse: (response: Response) => Promise<T>, proofProvider?: () => Promise<string>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const proof = await (proofProvider?.() ?? this.getOpenProof(id, 'unlock'));
      const response = await this.fetchApi(`/api/v1/secrets/${SecretApi.pathPart(id)}/unlock`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-PrivacyLink-Proof': proof }, body: JSON.stringify({ password }), cache: 'no-store', referrerPolicy: 'no-referrer' });
      if (response.status === 503 && attempt < 2) {
        const retryAfter = Number.parseInt(response.headers.get('Retry-After') ?? '', 10);
        const backoff = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : Math.min(1000 * 2 ** attempt, 4000);
        await delay(Math.min(backoff, 5000) + Math.floor(Math.random() * 250));
        continue;
      }
      return readResponse(response);
    }
  }
  async openFile(id: string, fileId: string): Promise<{ protocolVersion: number; file: OpenedFile }> {
    const proof = await this.getOpenProof(id, 'file-open', fileId);
    return this.fetchApi(`/api/v1/secrets/${SecretApi.pathPart(id)}/files/${SecretApi.pathPart(fileId)}/open`, { method: 'POST', headers: { 'X-PrivacyLink-Proof': proof }, cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson(response));
  }
  async openFileRaw(id: string, fileId: string): Promise<ArrayBuffer> {
    const proof = await this.getOpenProof(id, 'file-open', fileId);
    return this.fetchApi(`/api/v1/secrets/${SecretApi.pathPart(id)}/files/${SecretApi.pathPart(fileId)}/open`, { method: 'POST', headers: { 'X-PrivacyLink-Proof': proof }, cache: 'no-store', referrerPolicy: 'no-referrer' }).then(responseArrayBuffer);
  }
}
