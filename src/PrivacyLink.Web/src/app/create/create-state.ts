import { computed, inject, Injectable, signal } from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { AppState } from '../app-state';
import { LinkSharingState } from '../link-sharing-state';
import { LanguageState } from '../language-state';
import { SecretApi, SecretApiError } from '../secret-api';
import { decodeCanonical, derivePasswordToken, encryptMessage } from '../secret-crypto';
import { SecretHistoryStore } from '../secret-history-store';
import { WorkProgressState } from '../work-progress-state';
import { getSecretCryptoWorkerClient } from '../secret-crypto-worker-client';
import type { TranslatableError } from '../translations';

type Expiry = '1d' | '7d' | '14d';
type FilePolicy = { maxFiles: number; maxTotalFileBytes: number; allowedFileExtensions: string[] };
type CreateChallenge = { version: number; challengeId: string; nonce: string; difficultyBits: number; expiresAt: number; signature: string };

const MAX_MESSAGE_CHARACTERS = 20000;
const MAX_MESSAGE_BYTES = MAX_MESSAGE_CHARACTERS * 4;
const CREATE_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const CREATE_CHALLENGE_SAFETY_MARGIN_MS = 5 * 1000;

@Injectable({ providedIn: 'root' })
export class CreateState {
  private readonly app = inject(AppState);
  private readonly api = inject(SecretApi);
  private readonly history = inject(SecretHistoryStore);
  private readonly language = inject(LanguageState);
  private readonly sharing = inject(LinkSharingState);
  private readonly workProgress = inject(WorkProgressState);
  private readonly document = inject(DOCUMENT);
  private linkCopiedTimeout: ReturnType<typeof setTimeout> | undefined;
  private passwordCopiedTimeout: ReturnType<typeof setTimeout> | undefined;
  private resultAccessCodeCopiedTimeout: ReturnType<typeof setTimeout> | undefined;
  private preparedProof: { header: string; monotonicDeadline: number } | undefined;
  private proofController: AbortController | undefined;
  private proofTask: Promise<void> | undefined;
  private proofTimer: ReturnType<typeof setTimeout> | undefined;
  private proofFailureCount = 0;
  private visibilityListenerRegistered = false;

  readonly message = signal('');
  readonly password = signal('');
  readonly passwordDraft = signal('');
  readonly resultAccessCode = signal('');
  readonly passwordCopied = signal(false);
  readonly resultAccessCodeCopied = signal(false);
  readonly messageBytes = computed(() => new TextEncoder().encode(this.message()).length);
  readonly messageCharacters = computed(() => Array.from(this.message()).length);
  readonly formattedMessageCharacters = computed(() => this.language.formatNumber(this.messageCharacters()));
  readonly formattedMessageLimit = computed(() => this.language.formatNumber(MAX_MESSAGE_CHARACTERS));
  readonly selectedFiles = signal<File[]>([]);
  readonly filePolicy = signal<FilePolicy | null>(null);
  readonly fileAccept = computed(() => this.filePolicy()?.allowedFileExtensions.join(',') ?? null);
  readonly isDragging = signal(false);
  readonly expiry = signal<Expiry>('7d');
  readonly emailVerificationEnabled = signal(false);
  readonly recipientEmail = signal('');
  readonly busy = signal(false);
  readonly proofCalculating = signal(false);
  readonly shareLink = signal('');
  readonly expiresAt = signal('');
  readonly copied = signal(false);
  readonly error = signal<TranslatableError[]>([]);
  readonly errorText = computed(() => this.error().map(error => this.language.translateError(error)).join(' '));
  readonly passwordGeneratorOpen = signal(false);
  readonly emptyMessageDialogOpen = signal(false);
  readonly historyStorageWarning: SecretHistoryStore['saveFailed'] = this.history.saveFailed;
  readonly historyWarning = signal<'saveFailed' | null>(null);
  readonly canShare = this.sharing.canShare;

  initialize(): void {
    this.clearError();
    if (!this.filePolicy()) void this.api.getFileUploadPolicy().then(policy => this.filePolicy.set(policy)).catch(() => {
      /* Backend validation remains authoritative if policy loading fails. */
    });
    if (!this.visibilityListenerRegistered) {
      this.document.addEventListener('visibilitychange', this.handleVisibilityChange);
      this.visibilityListenerRegistered = true;
    }
    if (!this.document.hidden) void this.prepareProof().catch(() => {});
  }

  private readonly handleVisibilityChange = (): void => {
    if (this.document.hidden) this.cancelProofCalculation();
    else this.checkProofFreshness();
  };

  private checkProofFreshness(): void {
    if (this.document.hidden || this.app.mode() !== 'create') return;
    if (!this.hasProofLifetime(60)) void this.prepareProof().catch(() => {});
    this.scheduleProofRefresh();
  }

  private hasProofLifetime(seconds: number): boolean {
    return !!this.preparedProof && this.preparedProof.monotonicDeadline > performance.now() + seconds * 1000;
  }

  private scheduleProofRefresh(): void {
    if (this.proofTimer) clearTimeout(this.proofTimer);
    this.proofTimer = undefined;
    if (this.document.hidden || this.app.mode() !== 'create' || !this.preparedProof) return;
    const delayMs = Math.max(0, this.preparedProof.monotonicDeadline - performance.now() - 60_000);
    this.proofTimer = setTimeout(() => {
      this.proofTimer = undefined;
      if (!this.document.hidden && this.app.mode() === 'create') void this.prepareProof().catch(() => {});
    }, delayMs);
  }

  private cancelProofCalculation(): void {
    this.proofController?.abort();
    this.proofController = undefined;
    this.proofTask = undefined;
    this.proofCalculating.set(false);
    if (this.proofTimer) clearTimeout(this.proofTimer);
    this.proofTimer = undefined;
  }

  private async prepareProof(force = false): Promise<void> {
    if (this.document.hidden || this.app.mode() !== 'create') return;
    if (!force && this.hasProofLifetime(60)) { this.scheduleProofRefresh(); return; }
    if (this.proofTask) {
      if (this.busy() && this.workProgress.active()) this.workProgress.setStage('preparing');
      return this.proofTask;
    }
    const controller = new AbortController();
    this.proofController = controller;
    this.proofCalculating.set(true);
    if (this.busy() && this.workProgress.active()) this.workProgress.setStage('preparing');
    let task!: Promise<void>;
    task = (async () => {
      try {
        const challengeRequestStartedAt = performance.now();
        const challenge: CreateChallenge = await this.api.getCreateChallenge();
        if (controller.signal.aborted || this.document.hidden) return;
        // The server issues challenges with a fixed five-minute TTL. Start the
        // client deadline before the request so latency and second truncation are
        // accounted for without relying on the local wall clock.
        const monotonicDeadline = challengeRequestStartedAt + CREATE_CHALLENGE_TTL_MS - CREATE_CHALLENGE_SAFETY_MARGIN_MS;
        const counter = await getSecretCryptoWorkerClient().solveCreateProof(challenge, controller.signal);
        if (controller.signal.aborted || this.document.hidden) return;
        this.preparedProof = {
          header: `${challenge.challengeId}.${challenge.nonce}.${challenge.difficultyBits}.${challenge.expiresAt}.${challenge.signature}.${counter}`,
          monotonicDeadline
        };
        this.proofFailureCount = 0;
        this.scheduleProofRefresh();
      } catch (error) {
        this.proofFailureCount++;
        throw error;
      } finally {
        const isCurrentCalculation = this.proofController === controller;
        if (isCurrentCalculation) this.proofController = undefined;
        if (this.proofTask === task) this.proofTask = undefined;
        if (isCurrentCalculation) this.proofCalculating.set(false);
        if (this.busy() && this.workProgress.active()) this.workProgress.setStage('processing');
        if (this.proofFailureCount > 0 && this.preparedProof && !this.document.hidden && this.app.mode() === 'create') this.scheduleProofRetry();
      }
    })();
    this.proofTask = task;
    return task;
  }

  private scheduleProofRetry(): void {
    if (this.proofTimer) clearTimeout(this.proofTimer);
    this.proofTimer = setTimeout(() => {
      this.proofTimer = undefined;
      if (!this.document.hidden && this.app.mode() === 'create') void this.prepareProof().catch(() => {});
    }, Math.min(60, this.proofFailureCount * 15) * 1000);
  }

  private async takeProof(): Promise<string> {
    const existingProof = this.preparedProof;
    if (existingProof && existingProof.monotonicDeadline > performance.now() + 5_000) {
      const existing = existingProof.header;
      if (existingProof.monotonicDeadline <= performance.now() + 60_000) void this.prepareProof();
      return existing;
    }
    if (this.preparedProof) this.preparedProof = undefined;
    if (!this.proofTask) void this.prepareProof(true);
    else if (this.busy() && this.workProgress.active()) this.workProgress.setStage('preparing');
    await this.proofTask;
    const prepared = this.preparedProof as { header: string; monotonicDeadline: number } | undefined;
    if (!prepared || !this.hasProofLifetime(0)) throw new Error('Proof unavailable');
    return prepared.header;
  }

  private async submitWithProof<T>(send: (proof: string) => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const proof = await this.takeProof();
      if (this.preparedProof?.header === proof) this.preparedProof = undefined;
      try {
        return await send(proof);
      } catch (error) {
        if (!(error instanceof SecretApiError) || error.status !== 403 || error.code !== 'proof_required' || attempt > 0) throw error;
        await this.prepareProof(true);
      }
    }
  }

  private stopProof(): void {
    this.cancelProofCalculation();
    this.preparedProof = undefined;
  }

  onPageExit(): void {
    this.clearResultAccessCode();
    this.stopProof();
    if (this.visibilityListenerRegistered) {
      this.document.removeEventListener('visibilitychange', this.handleVisibilityChange);
      this.visibilityListenerRegistered = false;
    }
  }

  setError(error: TranslatableError): void { this.error.set([error]); }
  clearError(): void { this.error.set([]); }
  closeEmptyMessageDialog(): void { this.emptyMessageDialogOpen.set(false); }

  fileLimitHint(): string {
    const policy = this.filePolicy();
    const maxFiles = policy?.maxFiles ?? 15;
    const maxTotal = this.language.formatFileSize(policy?.maxTotalFileBytes ?? 75 * 1024 * 1024);
    return this.language.t('fileLimitHint', { maxFiles, maxTotal });
  }

  fileCountLimit(): number { return this.filePolicy()?.maxFiles ?? 15; }

  fileUsageSummary(): string {
    const totalBytes = this.selectedFiles().reduce((total, file) => total + file.size, 0);
    const maxBytes = this.filePolicy()?.maxTotalFileBytes ?? 75 * 1024 * 1024;
    return this.language.t('fileUsageSummary', {
      selected: this.selectedFiles().length,
      maxFiles: this.fileCountLimit(),
      usedSize: this.language.formatNumber(totalBytes / (1024 * 1024), 2),
      maxSize: this.language.formatNumber(maxBytes / (1024 * 1024), 2)
    });
  }

  updateMessage(event: Event): void {
    const textarea = event.target as HTMLTextAreaElement;
    const characters = Array.from(textarea.value);
    if (characters.length > MAX_MESSAGE_CHARACTERS) {
      const limited = characters.slice(0, MAX_MESSAGE_CHARACTERS).join('');
      textarea.value = limited;
      const caret = Math.min(textarea.selectionStart, limited.length);
      textarea.setSelectionRange(caret, caret);
      this.message.set(limited);
    } else {
      this.message.set(textarea.value);
    }
    this.clearError();
  }

  updatePassword(event: Event): void {
    this.passwordDraft.set((event.target as HTMLInputElement).value);
    this.passwordCopied.set(false);
  }

  setRecipientEmail(email: string): void { this.recipientEmail.set(email); }
  enableEmailVerification(): void { this.emailVerificationEnabled.set(true); }
  removeEmailVerification(): void {
    this.emailVerificationEnabled.set(false);
    this.recipientEmail.set('');
  }

  openPasswordSetup(): void {
    this.passwordDraft.set(this.password());
    this.passwordCopied.set(false);
  }

  savePasswordSetup(): void {
    this.password.set(this.passwordDraft());
    this.passwordDraft.set('');
    this.passwordCopied.set(false);
  }

  cancelPasswordSetup(): void {
    this.passwordDraft.set('');
    this.passwordCopied.set(false);
  }

  removePassword(): void {
    this.password.set('');
    this.cancelPasswordSetup();
  }

  openPasswordGenerator(): void { this.passwordGeneratorOpen.set(true); }

  closePasswordGenerator(): void { this.passwordGeneratorOpen.set(false); }

  useGeneratedPassword(password: string): void {
    this.passwordDraft.set(password);
    this.passwordCopied.set(false);
    this.clearError();
    this.passwordGeneratorOpen.set(false);
  }

  async copyPassword(): Promise<void> {
    if (!this.passwordDraft()) return;
    if (await this.sharing.copy(this.passwordDraft())) {
      this.passwordCopied.set(true);
      if (this.passwordCopiedTimeout) clearTimeout(this.passwordCopiedTimeout);
      this.passwordCopiedTimeout = setTimeout(() => this.passwordCopied.set(false), 1200);
    } else {
      this.setError({ key: 'clipboardFailure' });
    }
  }

  updateExpiry(event: Event): void { this.expiry.set((event.target as HTMLSelectElement).value as Expiry); }
  updateFiles(event: Event): void {
    const input = event.target as HTMLInputElement;
    this.setFiles(input.files, true);
    input.value = '';
  }
  onDragEnter(event: DragEvent): void { event.preventDefault(); if (!this.busy()) this.isDragging.set(true); }
  onDragOver(event: DragEvent): void { event.preventDefault(); if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy'; if (!this.busy()) this.isDragging.set(true); }
  onDragLeave(event: DragEvent): void { event.preventDefault(); this.isDragging.set(false); }
  onDrop(event: DragEvent): void { event.preventDefault(); this.isDragging.set(false); if (!this.busy()) this.setFiles(event.dataTransfer?.files ?? null, true); }

  private setFiles(files: FileList | null, append = false): void {
    const incoming = Array.from(files ?? []);
    const policy = this.filePolicy();
    const current = append ? this.selectedFiles() : [];
    const invalid = policy ? incoming.filter(file => !policy.allowedFileExtensions.includes(this.fileExtension(file))) : [];
    const valid = policy ? incoming.filter(file => policy.allowedFileExtensions.includes(this.fileExtension(file))) : incoming;
    const knownFiles = new Set(current.map(file => this.fileIdentity(file)));
    const unique = valid.filter(file => {
      const identity = this.fileIdentity(file);
      if (knownFiles.has(identity)) return false;
      knownFiles.add(identity);
      return true;
    });
    const maxFiles = policy?.maxFiles ?? 15;
    const available = Math.max(0, maxFiles - current.length);
    const overCount = unique.slice(available);
    const candidates = unique.slice(0, available);
    const maxBytes = policy?.maxTotalFileBytes ?? Number.MAX_SAFE_INTEGER;
    let totalBytes = current.reduce((total, file) => total + file.size, 0);
    const accepted: File[] = [];
    const tooLarge: File[] = [];
    for (const file of candidates) {
      if (totalBytes + file.size > maxBytes) tooLarge.push(file);
      else { accepted.push(file); totalBytes += file.size; }
    }
    this.selectedFiles.set([...current, ...accepted]);
    const messages: TranslatableError[] = [];
    if (invalid.length) messages.push({ key: 'unsupportedFileType', params: { files: invalid.map(file => file.name).join(', ') } });
    if (overCount.length) messages.push({ key: 'tooManyFiles', params: { max: maxFiles } });
    if (tooLarge.length) messages.push({ key: 'filesTooLarge', params: { sizeInBytes: maxBytes } });
    this.error.set(messages);
  }

  private fileExtension(file: File): string {
    const dot = file.name.lastIndexOf('.');
    return dot >= 0 ? file.name.slice(dot).toLowerCase() : '';
  }

  private fileIdentity(file: File): string {
    return `${file.name}\0${file.size}\0${file.lastModified}\0${file.type}`;
  }

  formatFileSize(bytes: number): string { return this.language.formatFileSize(bytes); }
  removeFile(index: number): void { if (this.busy()) return; this.selectedFiles.update(files => files.filter((_, fileIndex) => fileIndex !== index)); this.clearError(); }
  selectLink(event: FocusEvent): void { (event.target as HTMLInputElement).select(); }

  async create(): Promise<void> {
    if (this.busy()) return;
    this.clearError();
    if (!this.message().trim() && this.selectedFiles().length === 0) { this.emptyMessageDialogOpen.set(true); return; }
    if (this.messageCharacters() > MAX_MESSAGE_CHARACTERS || this.messageBytes() > MAX_MESSAGE_BYTES) {
      this.setError({ key: 'tooLarge', params: { max: MAX_MESSAGE_CHARACTERS } });
      return;
    }
    this.busy.set(true);
    const filesToEncrypt = this.selectedFiles();
    this.workProgress.begin('create', filesToEncrypt.map(file => file.name));
    try {
      this.historyWarning.set(null);
      await this.history.whenReady();
      const encrypted = await encryptMessage(this.message());
      const clientKey = decodeCanonical(encrypted.clientKey, 32);
      const requestWithoutFiles = {
        protocolVersion: 1,
        expiry: this.expiry(),
        message: this.message().trim() ? encrypted.message : null,
        ...(this.emailVerificationEnabled() ? { emailAddress: this.recipientEmail() } : {}),
        ...(this.password() ? { password: await derivePasswordToken(this.password(), encrypted.clientKey) } : {})
      } as const;
      const created = filesToEncrypt.length
        ? await this.createFilesWithWorker(requestWithoutFiles, filesToEncrypt, clientKey)
        : await this.submitWithProof(proof => this.api.create({ ...requestWithoutFiles, files: [] }, proof));
      decodeCanonical(created.id, 16);
      this.shareLink.set(`${this.document.location.origin}/s/${created.id}#${encrypted.clientKey}`);
      this.expiresAt.set(created.expiresAt);
      this.clearLinkCopiedFeedback();
      this.resultAccessCode.set(this.password());
      this.resultAccessCodeCopied.set(false);
      if (!await this.history.add({
          id: created.id,
          createdAt: new Date().toISOString(),
          link: this.shareLink(),
          expiresAt: created.expiresAt,
          password: this.password(),
          revokeToken: created.revokeToken
        })) this.historyWarning.set('saveFailed');
      this.app.activateResult();
      this.message.set('');
      this.selectedFiles.set([]);
      this.password.set('');
      this.passwordDraft.set('');
      this.emailVerificationEnabled.set(false);
      this.recipientEmail.set('');
      this.passwordCopied.set(false);
      this.stopProof();
    } catch (error) {
      this.setError({ key: error instanceof SecretApiError && error.status === 429 ? 'creationRateLimited' : 'failure' });
    } finally {
      this.busy.set(false);
      this.workProgress.finish();
      if (this.app.mode() === 'create' && !this.document.hidden) void this.prepareProof().catch(() => {});
    }
  }

  private async createFilesWithWorker(
    request: { protocolVersion: 1; expiry: Expiry; message: { nonce: string; ciphertext: string } | null; password?: string; emailAddress?: string },
    files: File[],
    clientKey: Uint8Array
  ): Promise<{ id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string }> {
    const body = await getSecretCryptoWorkerClient().encryptFilesAndSerialize(request, files, clientKey, progress => {
      if (progress.phase === 'encoding' && !progress.filename) {
        files.forEach((_, index) => this.workProgress.setFileStatus(index, 'done'));
        return;
      }
      for (let index = 0; index < progress.current - 1; index++) this.workProgress.setFileStatus(index, 'done');
      if (progress.current <= files.length) this.workProgress.setFileStatus(progress.current - 1, 'processing');
    });
    files.forEach((_, index) => this.workProgress.setFileStatus(index, 'done'));
    this.workProgress.setStage('uploading');
    return this.submitWithProof(proof => this.api.createSerialized(body, proof));
  }

  async copy(): Promise<void> {
    if (await this.sharing.copy(this.shareLink())) {
      this.copied.set(true);
      if (this.linkCopiedTimeout) clearTimeout(this.linkCopiedTimeout);
      this.linkCopiedTimeout = setTimeout(() => this.copied.set(false), 1000);
    } else this.setError({ key: 'clipboardFailure' });
  }

  private clearLinkCopiedFeedback(): void {
    if (this.linkCopiedTimeout) clearTimeout(this.linkCopiedTimeout);
    this.linkCopiedTimeout = undefined;
    this.copied.set(false);
  }

  share(url = this.shareLink()): void { void this.sharing.share(url); }
  async copyResultAccessCode(): Promise<void> {
    if (!this.resultAccessCode()) return;
    if (await this.sharing.copy(this.resultAccessCode())) {
      this.resultAccessCodeCopied.set(true);
      if (this.resultAccessCodeCopiedTimeout) clearTimeout(this.resultAccessCodeCopiedTimeout);
      this.resultAccessCodeCopiedTimeout = setTimeout(() => this.resultAccessCodeCopied.set(false), 1000);
    } else this.setError({ key: 'clipboardFailure' });
  }

  private clearResultAccessCode(): void {
    if (this.resultAccessCodeCopiedTimeout) clearTimeout(this.resultAccessCodeCopiedTimeout);
    this.resultAccessCodeCopiedTimeout = undefined;
    this.resultAccessCode.set('');
    this.resultAccessCodeCopied.set(false);
  }

  reset(): void {
    this.app.activatePage('create');
    this.clearResultAccessCode();
    this.clearLinkCopiedFeedback();
    this.shareLink.set('');
    this.clearError();
    this.password.set('');
    this.passwordDraft.set('');
    this.emailVerificationEnabled.set(false);
    this.recipientEmail.set('');
    this.passwordCopied.set(false);
  }
}
