import { DOCUMENT } from '@angular/common';
import { computed, inject, Injectable, signal } from '@angular/core';
import { SecretApi, SecretApiError } from '../secret-api';
import { decodeCanonical, derivePasswordToken } from '../secret-crypto';
import { LanguageState } from '../language-state';
import type { TranslatableError } from '../translations';
import { WorkProgressState } from '../work-progress-state';
import { getSecretCryptoWorkerClient } from '../secret-crypto-worker-client';

const EMAIL_VERIFICATION_SESSION_MS = 30 * 60 * 1000;
const EMAIL_CODE_REQUEST_COOLDOWN_SECONDS = 60;

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
  readonly emailVerificationRequired = signal(false);
  readonly maskedEmailAddress = signal('');
  readonly emailCodeRequested = signal(false);
  readonly emailCode = signal('');
  readonly emailVerificationBusy = signal(false);
  readonly emailVerified = signal(false);
  readonly emailCodeCooldownSeconds = signal(0);
  readonly error = signal<TranslatableError[]>([]);
  readonly lockoutSeconds = signal(0);
  readonly errorText = computed(() => this.error().map(error => this.language.translateError(error)).join(' '));

  private recipientId = '';
  private recipientKey = '';
  private cachedFilesToken: string | undefined;
  private metadataRequestId = 0;
  private lockoutTimer: ReturnType<typeof setInterval> | undefined;
  private emailCodeCooldownTimer: ReturnType<typeof setInterval> | undefined;

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
      const emailVerificationRequired = metadata.emailVerificationRequired === true;
      this.emailVerificationRequired.set(emailVerificationRequired);
      this.maskedEmailAddress.set(metadata.maskedEmailAddress ?? '');
      this.emailVerified.set(emailVerificationRequired && this.hasEmailVerificationSession(id));
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
    this.clearEmailCodeCooldown();
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
    this.emailVerificationRequired.set(false);
    this.maskedEmailAddress.set('');
    this.emailCodeRequested.set(false);
    this.emailCode.set('');
    this.emailVerificationBusy.set(false);
    this.emailVerified.set(false);
    this.expiresAt.set('');
    this.busy.set(false);
  }

  async open(): Promise<void> {
    if (this.busy() || !this.metadataReady() || this.lockoutSeconds() > 0) return;
    if (this.emailVerificationRequired() && !this.emailVerified()) return;
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
        } else if (error instanceof SecretApiError && error.status === 403 && error.code === 'email_verification_required') {
          this.resetEmailVerificationSession();
          this.setError({ key: 'emailVerificationRequired' });
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

  async requestEmailCode(): Promise<void> {
    if (this.emailVerificationBusy() || this.emailCodeCooldownSeconds() > 0 || !this.emailVerificationRequired() || !this.recipientId) return;
    const requestId = this.metadataRequestId;
    const recipientId = this.recipientId;
    this.emailVerificationBusy.set(true);
    this.clearError();
    try {
      await this.api.requestEmailCode(recipientId);
      if (requestId !== this.metadataRequestId || recipientId !== this.recipientId) return;
      this.emailCode.set('');
      this.emailCodeRequested.set(true);
      this.startEmailCodeCooldown();
    } catch (error) {
      if (requestId === this.metadataRequestId && recipientId === this.recipientId) {
        this.setError({ key: error instanceof SecretApiError && error.status === 429 ? 'emailVerificationRateLimited' : 'temporarilyUnavailable' });
      }
    } finally {
      if (requestId === this.metadataRequestId && recipientId === this.recipientId) this.emailVerificationBusy.set(false);
    }
  }

  updateEmailCode(event: Event): void {
    const input = event.target as HTMLInputElement;
    const code = input.value.replace(/\D/g, '').slice(0, 6);
    input.value = code;
    this.emailCode.set(code);
  }

  canVerifyEmailCode(): boolean { return /^\d{6}$/.test(this.emailCode()); }

  async verifyEmailCode(): Promise<void> {
    if (this.emailVerificationBusy() || !this.emailCodeRequested() || !this.canVerifyEmailCode() || !this.recipientId) return;
    const requestId = this.metadataRequestId;
    const recipientId = this.recipientId;
    const code = this.emailCode();
    this.emailVerificationBusy.set(true);
    this.clearError();
    try {
      await this.api.verifyEmailCode(recipientId, code);
      if (requestId !== this.metadataRequestId || recipientId !== this.recipientId) return;
      this.emailVerified.set(true);
      this.emailCodeRequested.set(false);
      this.emailCode.set('');
      this.clearEmailCodeCooldown();
      this.saveEmailVerificationSession(recipientId);
    } catch (error) {
      if (requestId === this.metadataRequestId && recipientId === this.recipientId) {
        this.setError({ key: error instanceof SecretApiError && error.status === 429 ? 'emailVerificationRateLimited' : error instanceof SecretApiError && error.status === 400 ? 'invalidEmailCode' : 'temporarilyUnavailable' });
      }
    } finally {
      if (requestId === this.metadataRequestId && recipientId === this.recipientId) this.emailVerificationBusy.set(false);
    }
  }

  private emailVerificationSessionKey(id: string): string { return `privacylink.email-verification.${id}`; }

  private hasEmailVerificationSession(id: string): boolean {
    try {
      const storage = this.document.defaultView?.localStorage;
      const expiresAt = Number(storage?.getItem(this.emailVerificationSessionKey(id)));
      if (Number.isFinite(expiresAt) && expiresAt > Date.now()) return true;
      storage?.removeItem(this.emailVerificationSessionKey(id));
    } catch { /* Browser storage is only a UI hint; the server cookie remains authoritative. */ }
    return false;
  }

  private saveEmailVerificationSession(id: string): void {
    try { this.document.defaultView?.localStorage.setItem(this.emailVerificationSessionKey(id), String(Date.now() + EMAIL_VERIFICATION_SESSION_MS)); }
    catch { /* The HttpOnly server cookie remains authoritative when storage is unavailable. */ }
  }

  private resetEmailVerificationSession(): void {
    this.emailVerified.set(false);
    this.emailCodeRequested.set(false);
    this.emailCode.set('');
    try { this.document.defaultView?.localStorage.removeItem(this.emailVerificationSessionKey(this.recipientId)); }
    catch { /* Ignore unavailable browser storage. */ }
  }

  private startEmailCodeCooldown(): void {
    this.clearEmailCodeCooldown();
    this.emailCodeCooldownSeconds.set(EMAIL_CODE_REQUEST_COOLDOWN_SECONDS);
    this.emailCodeCooldownTimer = setInterval(() => {
      const remaining = this.emailCodeCooldownSeconds() - 1;
      this.emailCodeCooldownSeconds.set(Math.max(remaining, 0));
      if (remaining <= 0) this.clearEmailCodeCooldown();
    }, 1000);
  }

  private clearEmailCodeCooldown(): void {
    if (this.emailCodeCooldownTimer !== undefined) clearInterval(this.emailCodeCooldownTimer);
    this.emailCodeCooldownTimer = undefined;
    this.emailCodeCooldownSeconds.set(0);
  }

  emailCodeCountdownText(): string {
    const totalSeconds = this.emailCodeCooldownSeconds();
    const minutes = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
    const seconds = (totalSeconds % 60).toString().padStart(2, '0');
    return `${minutes}:${seconds}`;
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
