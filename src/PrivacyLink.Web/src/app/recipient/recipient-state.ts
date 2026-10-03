import { DOCUMENT } from '@angular/common';
import { computed, inject, Injectable, signal } from '@angular/core';
import { SecretApi, SecretApiError } from '../secret-api';
import { decodeCanonical, decryptFile, decryptFileName, decryptMessage, derivePasswordToken } from '../secret-crypto';
import { LanguageState } from '../language-state';
import type { EncryptedPayload } from '../secret-crypto';
import type { TranslatableError } from '../translations';

@Injectable()
export class RecipientState {
  private readonly api = inject(SecretApi);
  private readonly language = inject(LanguageState);
  private readonly document = inject(DOCUMENT);

  readonly unlockPassword = signal('');
  readonly metadataFiles = signal<{ id: string; name: string; extension: string; mimeType: string; size: number }[]>([]);
  readonly metadataFileCount = signal(0);
  readonly busy = signal(false);
  readonly loadingMetadata = signal(false);
  readonly metadataReady = signal(false);
  readonly opened = signal(false);
  readonly openedMessage = signal('');
  readonly expiresAt = signal('');
  readonly passwordProtected = signal(false);
  readonly openedPayload = signal<EncryptedPayload | null>(null);
  readonly error = signal<TranslatableError[]>([]);
  readonly lockoutSeconds = signal(0);
  readonly errorText = computed(() => this.error().map(error => this.language.translateError(error)).join(' '));

  private recipientId = '';
  private recipientKey = '';
  private metadataRequestId = 0;
  private lockoutTimer: ReturnType<typeof setInterval> | undefined;

  setError(error: TranslatableError): void { this.error.set([error]); }
  clearError(): void { this.error.set([]); }
  updateUnlockPassword(event: Event): void { this.unlockPassword.set((event.target as HTMLInputElement).value); }
  formatFileSize(bytes: number): string { return this.language.formatFileSize(bytes); }

  initialize(id: string | null, key: string): void {
    const requestId = ++this.metadataRequestId;
    this.clearRecipientData();
    this.clearError();
    if (!id) { this.setError({ key: 'invalidLink' }); return; }
    try {
      decodeCanonical(id, 16);
      decodeCanonical(key, 32);
      this.recipientId = id;
      this.recipientKey = key;
    } catch {
      this.setError({ key: 'invalidLink' });
      return;
    }

    this.loadingMetadata.set(true);
    void this.api.getMetadata(id).then(async metadata => {
      if (requestId !== this.metadataRequestId) return;
      if (!metadata.exists || metadata.protocolVersion !== 1 || (!metadata.hasMessage && metadata.fileCount === 0)) {
        throw new Error('unsupported protocol');
      }
      const files = metadata.passwordProtected
        ? []
        : await Promise.all(metadata.files.map(async file => ({ ...file, name: await decryptFileName(file, key) })));
      if (requestId !== this.metadataRequestId) return;
      this.passwordProtected.set(metadata.passwordProtected);
      this.expiresAt.set(metadata.expiresAt);
      this.metadataFiles.set(files);
      this.metadataFileCount.set(metadata.fileCount);
      this.metadataReady.set(true);
    }).catch(() => {
      if (requestId === this.metadataRequestId) this.setError({ key: 'unavailable' });
    }).finally(() => {
      if (requestId === this.metadataRequestId) this.loadingMetadata.set(false);
    });
  }

  leave(): void {
    this.metadataRequestId++;
    this.clearLockout();
    this.clearRecipientData();
    this.clearError();
  }

  private clearRecipientData(): void {
    this.clearLockout();
    this.recipientId = '';
    this.recipientKey = '';
    this.unlockPassword.set('');
    this.metadataReady.set(false);
    this.loadingMetadata.set(false);
    this.metadataFiles.set([]);
    this.metadataFileCount.set(0);
    this.opened.set(false);
    this.openedMessage.set('');
    this.openedPayload.set(null);
    this.passwordProtected.set(false);
    this.expiresAt.set('');
    this.busy.set(false);
  }

  async open(): Promise<void> {
    if (this.busy() || !this.metadataReady() || this.lockoutSeconds() > 0) return;
    const requestId = this.metadataRequestId;
    this.busy.set(true);
    this.clearError();
    try {
      const payload = this.passwordProtected()
        ? await this.api.unlock(this.recipientId, await derivePasswordToken(this.unlockPassword(), this.recipientKey))
        : await this.api.open(this.recipientId);
      if (requestId !== this.metadataRequestId) return;
      const files = this.passwordProtected()
        ? await Promise.all(payload.files.map(async file => ({ ...file, name: await decryptFileName(file, this.recipientKey) })))
        : this.metadataFiles();
      const message = payload.message ? await decryptMessage(payload, this.recipientKey) : '';
      if (requestId !== this.metadataRequestId) return;
      this.openedPayload.set(payload);
      this.metadataFiles.set(files);
      this.openedMessage.set(message);
      this.opened.set(true);
    } catch (error) {
      if (requestId === this.metadataRequestId) {
        if (error instanceof SecretApiError && error.status === 429) {
          this.setError({ key: 'rateLimited' });
          this.startLockout(error.retryAfterSeconds);
        } else if (error instanceof SecretApiError && error.status === 503) {
          this.setError({ key: 'temporarilyUnavailable' });
        } else if (this.passwordProtected() && error instanceof SecretApiError && error.status === 403) {
          this.setError({ key: 'incorrectPassword' });
        } else {
          this.setError({ key: 'decryptFailure' });
        }
      }
    } finally {
      if (requestId === this.metadataRequestId) {
        this.unlockPassword.set('');
        this.busy.set(false);
      }
    }
  }

  private startLockout(seconds: number | null): void {
    this.clearLockout();
    if (!seconds) return;
    this.lockoutSeconds.set(seconds);
    this.lockoutTimer = setInterval(() => {
      const remaining = this.lockoutSeconds() - 1;
      this.lockoutSeconds.set(Math.max(remaining, 0));
      if (remaining <= 0) this.clearLockout();
    }, 1000);
  }

  private clearLockout(): void {
    if (this.lockoutTimer !== undefined) clearInterval(this.lockoutTimer);
    this.lockoutTimer = undefined;
    this.lockoutSeconds.set(0);
  }

  countdownText(): string {
    const totalSeconds = this.lockoutSeconds();
    const minutes = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
    const seconds = (totalSeconds % 60).toString().padStart(2, '0');
    return `${minutes}:${seconds}`;
  }

  async download(file: { id: string; name: string; extension: string; mimeType: string }): Promise<void> {
    const requestId = this.metadataRequestId;
    try {
      const opened = this.passwordProtected()
        ? this.openedPayload()?.files.find(item => item.id === file.id)
        : (await this.api.openFile(this.recipientId, file.id)).file;
      if (!opened) throw new Error('missing file');
      const name = await decryptFileName(opened, this.recipientKey);
      const data = await decryptFile(opened, this.recipientKey);
      if (requestId !== this.metadataRequestId) return;
      const url = URL.createObjectURL(new Blob([data.buffer as ArrayBuffer], { type: file.mimeType || 'application/octet-stream' }));
      const anchor = this.document.createElement('a');
      anchor.href = url;
      anchor.download = name.replace(/[\\/:\0]/g, '_');
      anchor.click();
      URL.revokeObjectURL(url);
    } catch {
      if (requestId === this.metadataRequestId) this.setError({ key: 'decryptFailure' });
    }
  }
}
