import { Injectable } from '@angular/core';
import { EncryptedFile, EncryptedFileMetadata, EncryptedMessage, EncryptedPayload, OpenedFile } from './secret-crypto';

export class SecretApiError extends Error {
  constructor(readonly status: number, readonly retryAfterSeconds: number | null = null) { super(`HTTP ${status}`); }
}

async function responseJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const retryAfter = Number.parseInt(response.headers.get('Retry-After') ?? '', 10);
    throw new SecretApiError(response.status, Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null);
  }
  return response.json() as Promise<T>;
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
  create(request: { protocolVersion: 1; expiry: '1d' | '7d' | '14d'; message: EncryptedMessage | null; files: EncryptedFile[]; password?: string }): Promise<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }> {
    return fetch('/api/v1/secrets', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request), cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }>(response));
  }
  revoke(id: string, revokeToken: string): Promise<void> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ revokeToken }), cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => {
      // Revocation is idempotent from History's perspective: 404 means the secret is already absent.
      if (!response.ok && response.status !== 404) throw new Error(`HTTP ${response.status}`);
    });
  }
  getMetadata(id: string): Promise<{ exists: boolean; protocolVersion: number; expiresAt: string; passwordProtected: boolean; hasMessage: boolean; fileCount: number; files: EncryptedFileMetadata[] }> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}`, { cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson(response));
  }
  open(id: string): Promise<EncryptedPayload> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/open`, { method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson<EncryptedPayload>(response));
  }
  unlock(id: string, password: string): Promise<EncryptedPayload> {
    return this.unlockWithRetry(id, password);
  }

  private async unlockWithRetry(id: string, password: string): Promise<EncryptedPayload> {
    for (let attempt = 0; ; attempt++) {
      const response = await fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/unlock`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }), cache: 'no-store', referrerPolicy: 'no-referrer' });
      if (response.status === 503 && attempt < 2) {
        const retryAfter = Number.parseInt(response.headers.get('Retry-After') ?? '', 10);
        const backoff = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : Math.min(1000 * 2 ** attempt, 4000);
        await delay(Math.min(backoff, 5000) + Math.floor(Math.random() * 250));
        continue;
      }
      return responseJson<EncryptedPayload>(response);
    }
  }
  openFile(id: string, fileId: string): Promise<{ protocolVersion: number; file: OpenedFile }> {
    return fetch(`/api/v1/secrets/${SecretApi.pathPart(id)}/files/${SecretApi.pathPart(fileId)}/open`, { method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer' }).then(response => responseJson(response));
  }
}
