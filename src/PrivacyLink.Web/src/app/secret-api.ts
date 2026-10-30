import { Injectable } from '@angular/core';
import type { CreateChallenge } from '../../../PrivacyLink.Client/src';
import { EncryptedFile, EncryptedFileMetadata, EncryptedMessage, EncryptedPayload, OpenedFile } from './secret-crypto';

export class SecretApiError extends Error {
  constructor(readonly status: number, readonly retryAfterSeconds: number | null = null, readonly code: string | null = null) { super(`HTTP ${status}`); }
}

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
  private static pathPart(value: string): string { return encodeURIComponent(value); }
  getFileUploadPolicy(): Promise<{ maxFiles: number; maxTotalFileBytes: number; allowedFileExtensions: string[] }> {
    return fetch('/api/v1/capabilities', { cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson(response));
  }
  getCreateChallenge(): Promise<CreateChallenge> {
    return fetch('/api/v1/secrets/create-challenge', { cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson<CreateChallenge>(response));
  }
  create(request: { protocolVersion: 1; expiry: '1d' | '7d' | '14d'; message: EncryptedMessage | null; files: EncryptedFile[]; password?: string; emailAddress?: string }, proof: string): Promise<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }> {
    return fetch('/api/v1/secrets', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-PrivacyLink-Proof': proof }, body: JSON.stringify(request), cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }>(response));
  }
  createSerialized(body: ArrayBuffer, proof: string): Promise<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }> {
    return fetch('/api/v1/secrets', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-PrivacyLink-Proof': proof }, body, cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }>(response));
  }
  revoke(id: string, revokeToken: string): Promise<void> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ revokeToken }), cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => {
      // Revocation is idempotent from History's perspective: 404 means the secret is already absent.
      if (!response.ok && response.status !== 404) throw new Error(`HTTP ${response.status}`);
    });
  }
  getMetadata(id: string): Promise<{ exists: boolean; protocolVersion: number; expiresAt: string; passwordProtected: boolean; hasMessage: boolean; fileCount: number; files: EncryptedFileMetadata[]; emailVerificationRequired?: boolean; maskedEmailAddress?: string | null }> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}`, { cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson(response));
  }
  requestEmailCode(id: string): Promise<{ code: string }> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/email-verification/request`, { method: 'POST', credentials: 'same-origin', cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson(response));
  }
  async verifyEmailCode(id: string, code: string): Promise<void> {
    const response = await fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/email-verification/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
      credentials: 'same-origin',
      cache: 'no-store',
      referrerPolicy: 'no-referrer'
    });
    if (!response.ok) throw await apiError(response);
  }
  open(id: string): Promise<EncryptedPayload> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/open`, { method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson<EncryptedPayload>(response));
  }
  openRaw(id: string): Promise<ArrayBuffer> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/open`, { method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer' }).then(responseArrayBuffer);
  }
  unlock(id: string, password: string): Promise<EncryptedPayload> {
    return this.unlockWithRetry(id, password, response => responseJson<EncryptedPayload>(response));
  }

  unlockRaw(id: string, password: string): Promise<ArrayBuffer> {
    return this.unlockWithRetry(id, password, responseArrayBuffer);
  }

  private async unlockWithRetry<T>(id: string, password: string, readResponse: (response: Response) => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const response = await fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/unlock`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }), cache: 'no-store', referrerPolicy: 'no-referrer' });
      if (response.status === 503 && attempt < 2) {
        const retryAfter = Number.parseInt(response.headers.get('Retry-After') ?? '', 10);
        const backoff = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : Math.min(1000 * 2 ** attempt, 4000);
        await delay(Math.min(backoff, 5000) + Math.floor(Math.random() * 250));
        continue;
      }
      return readResponse(response);
    }
  }
  openFile(id: string, fileId: string): Promise<{ protocolVersion: number; file: OpenedFile }> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/files/${SecretApi.pathPart(fileId)}/open`, { method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson(response));
  }
  openFileRaw(id: string, fileId: string): Promise<ArrayBuffer> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/files/${SecretApi.pathPart(fileId)}/open`, { method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer' }).then(responseArrayBuffer);
  }
}
