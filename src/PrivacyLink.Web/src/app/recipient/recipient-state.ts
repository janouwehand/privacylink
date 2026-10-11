import { DOCUMENT } from '@angular/common';
import { computed, inject, Injectable, signal } from '@angular/core';
import { SecretApi, SecretApiError } from '../secret-api';
import { decodeCanonical, derivePasswordToken } from '../secret-crypto';
import { LanguageState } from '../language-state';
import type { TranslatableError } from '../translations';
import { WorkProgressState } from '../work-progress-state';
import { getSecretCryptoWorkerClient } from '../secret-crypto-worker-client';

@Injectable()
export class RecipientState {
  private readonly api = inject(SecretApi);
  private readonly language = inject(LanguageState);
  private readonly document = inject(DOCUMENT);
  private readonly workProgress = inject(WorkProgressState);

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
  readonly error = signal<TranslatableError[]>([]);
  readonly lockoutSeconds = signal(0);
  readonly errorText = computed(() => this.error().map(error => this.language.translateError(error)).join(' '));

  private recipientId = '';
  private recipientKey = '';
  private cachedFilesToken: string | undefined;
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
      let files: { id: string; name: string; extension: string; mimeType: string; size: number }[] = [];
      if (!metadata.passwordProtected && metadata.files.length) {
        this.workProgress.begin('open', metadata.files.map((_, index) => this.language.t('workFileNumber', { number: index + 1 })));
        this.workProgress.setStage('processing');
        const worker = getSecretCryptoWorkerClient();
        for (let index = 0; index < metadata.files.length; index++) {
          this.workProgress.setFileStatus(index, 'processing');
          const file = metadata.files[index]!;
          const name = await worker.decryptFileName(file, key, undefined, file.extension);
          files.push({ ...file, name });
          this.workProgress.setFileName(index, name);
          this.workProgress.setFileStatus(index, 'done');
        }
      }
      if (requestId !== this.metadataRequestId) return;
      this.passwordProtected.set(metadata.passwordProtected);
      this.expiresAt.set(metadata.expiresAt);
      this.metadataFiles.set(files);
      this.metadataFileCount.set(metadata.fileCount);
      this.metadataReady.set(true);
    }).catch(() => {
      if (requestId === this.metadataRequestId) this.setError({ key: 'unavailable' });
    }).finally(() => {
      if (requestId === this.metadataRequestId) {
        this.loadingMetadata.set(false);
        this.workProgress.finish();
      }
    });
  }

  leave(): void {
    this.metadataRequestId++;
    this.workProgress.finish();
    this.clearLockout();
    this.clearRecipientData();
    this.clearError();
  }

  private clearRecipientData(): void {
    this.clearCachedFilePayload();
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
    this.passwordProtected.set(false);
    this.expiresAt.set('');
    this.busy.set(false);
  }

  async open(): Promise<void> {
    if (this.busy() || !this.metadataReady() || this.lockoutSeconds() > 0) return;
    const requestId = this.metadataRequestId;
    this.busy.set(true);
    this.workProgress.begin('open', this.passwordProtected() ? [] : this.metadataFiles().map(file => file.name));
    this.workProgress.setStage('fetching');
    this.clearError();
    try {
      let files = this.metadataFiles();
      let message = '';
      const rawResponse = this.passwordProtected()
        ? await this.api.unlockRaw(this.recipientId, await derivePasswordToken(this.unlockPassword(), this.recipientKey))
        : await this.api.openRaw(this.recipientId);
      if (requestId !== this.metadataRequestId) return;
      this.workProgress.setStage('processing');
      const worker = getSecretCryptoWorkerClient();
      const opened = await worker.decryptOpenSecretResponse(rawResponse, this.recipientKey, progress => {
        if (!this.workProgress.files().length && progress.total > 0) {
          this.workProgress.setFiles(Array.from({ length: progress.total }, (_, index) => this.language.t('workFileNumber', { number: index + 1 })));
        }
        for (let index = 0; index < progress.current - 1; index++) this.workProgress.setFileStatus(index, 'done');
        if (progress.current <= progress.total) this.workProgress.setFileStatus(progress.current - 1, 'processing');
      });
      if (requestId !== this.metadataRequestId) {
        void getSecretCryptoWorkerClient().clearCachedFiles(opened.token);
        return;
      }
      if (opened.files.length) {
        this.cachedFilesToken = opened.token;
        files = opened.files;
      } else {
        void worker.clearCachedFiles(opened.token);
        if (this.passwordProtected() && this.metadataFileCount() > 0) throw new Error('missing protected file payload');
        if (!this.passwordProtected()) files = this.metadataFiles();
      }
      this.workProgress.setFiles(files.map(file => file.name));
      files.forEach((_, index) => this.workProgress.setFileStatus(index, 'done'));
      message = opened.message ?? '';
      if (requestId !== this.metadataRequestId) return;
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
      this.workProgress.finish();
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
    if (this.workProgress.active()) return;
    const requestId = this.metadataRequestId;
    this.workProgress.begin('download', [file.name]);
    this.workProgress.setFileStatus(0, 'processing');
    try {
      const worker = getSecretCryptoWorkerClient();
      let opened;
      if (this.passwordProtected()) {
        if (!this.cachedFilesToken) throw new Error('missing file payload');
        this.workProgress.setStage('processing');
        opened = await worker.decryptCachedFile(this.cachedFilesToken, file.id, this.recipientKey, undefined, file.name);
      } else {
        this.workProgress.setStage('fetching');
        const response = await this.api.openFileRaw(this.recipientId, file.id);
        this.workProgress.setStage('processing');
        opened = await worker.decryptOpenFileResponse(response, this.recipientKey);
      }
      if (requestId !== this.metadataRequestId) return;
      this.workProgress.setFileStatus(0, 'done');
      const url = URL.createObjectURL(new Blob([opened.data], { type: opened.mimeType || file.mimeType || 'application/octet-stream' }));
      const anchor = this.document.createElement('a');
      anchor.href = url;
      anchor.download = opened.filename.replace(/[\\/:\0]/g, '_');
      anchor.click();
      URL.revokeObjectURL(url);
    } catch {
      if (requestId === this.metadataRequestId) this.setError({ key: 'decryptFailure' });
    } finally {
      this.workProgress.finish();
    }
  }

  private clearCachedFilePayload(): void {
    if (!this.cachedFilesToken) return;
    const token = this.cachedFilesToken;
    this.cachedFilesToken = undefined;
    void getSecretCryptoWorkerClient().clearCachedFiles(token).catch(() => undefined);
  }
}
