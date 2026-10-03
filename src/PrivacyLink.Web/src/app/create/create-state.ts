import { computed, inject, Injectable, signal } from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { AppState } from '../app-state';
import { LinkSharingState } from '../link-sharing-state';
import { LanguageState } from '../language-state';
import { SecretApi } from '../secret-api';
import { decodeCanonical, derivePasswordToken, encryptFile, encryptMessage } from '../secret-crypto';
import { SecretHistoryStore } from '../secret-history-store';
import type { TranslatableError } from '../translations';

type Expiry = '1d' | '7d' | '14d';
type FilePolicy = { maxFiles: number; maxTotalFileBytes: number; allowedFileExtensions: string[] };

const MAX_MESSAGE_CHARACTERS = 20000;
const MAX_MESSAGE_BYTES = MAX_MESSAGE_CHARACTERS * 4;

@Injectable({ providedIn: 'root' })
export class CreateState {
  private readonly app = inject(AppState);
  private readonly api = inject(SecretApi);
  private readonly history = inject(SecretHistoryStore);
  private readonly language = inject(LanguageState);
  private readonly sharing = inject(LinkSharingState);
  private readonly document = inject(DOCUMENT);
  private passwordCopiedTimeout: ReturnType<typeof setTimeout> | undefined;

  readonly message = signal('');
  readonly password = signal('');
  readonly passwordVisible = signal(false);
  readonly passwordCopied = signal(false);
  readonly passwordCopyAcknowledged = signal(false);
  readonly messageBytes = computed(() => new TextEncoder().encode(this.message()).length);
  readonly messageCharacters = computed(() => Array.from(this.message()).length);
  readonly formattedMessageCharacters = computed(() => this.language.formatNumber(this.messageCharacters()));
  readonly formattedMessageLimit = computed(() => this.language.formatNumber(MAX_MESSAGE_CHARACTERS));
  readonly selectedFiles = signal<File[]>([]);
  readonly filePolicy = signal<FilePolicy | null>(null);
  readonly fileAccept = computed(() => this.filePolicy()?.allowedFileExtensions.join(',') ?? null);
  readonly isDragging = signal(false);
  readonly expiry = signal<Expiry>('7d');
  readonly busy = signal(false);
  readonly shareLink = signal('');
  readonly expiresAt = signal('');
  readonly copied = signal(false);
  readonly error = signal<TranslatableError[]>([]);
  readonly errorText = computed(() => this.error().map(error => this.language.translateError(error)).join(' '));
  readonly passwordCopyDialogOpen = signal(false);
  readonly passwordGeneratorOpen = signal(false);
  readonly emptyMessageDialogOpen = signal(false);
  readonly historyStorageWarning: SecretHistoryStore['saveFailed'] = this.history.saveFailed;
  readonly canShare = this.sharing.canShare;

  initialize(): void {
    this.clearError();
    if (this.filePolicy()) return;
    void this.api.getFileUploadPolicy().then(policy => this.filePolicy.set(policy)).catch(() => {
      /* Backend validation remains authoritative if policy loading fails. */
    });
  }

  setError(error: TranslatableError): void { this.error.set([error]); }
  clearError(): void { this.error.set([]); }
  closeEmptyMessageDialog(): void { this.emptyMessageDialogOpen.set(false); }

  fileLimitHint(): string {
    const policy = this.filePolicy();
    const maxFiles = policy?.maxFiles ?? 10;
    const maxTotal = this.language.formatFileSize(policy?.maxTotalFileBytes ?? 25 * 1024 * 1024);
    return this.language.t('fileLimitHint', { maxFiles, maxTotal });
  }

  fileCountLimit(): number { return this.filePolicy()?.maxFiles ?? 10; }

  fileUsageSummary(): string {
    const totalBytes = this.selectedFiles().reduce((total, file) => total + file.size, 0);
    const maxBytes = this.filePolicy()?.maxTotalFileBytes ?? 25 * 1024 * 1024;
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
    this.password.set((event.target as HTMLInputElement).value);
    this.passwordCopied.set(false);
    this.passwordCopyAcknowledged.set(false);
  }

  togglePasswordVisibility(): void { this.passwordVisible.update(visible => !visible); }

  openPasswordGenerator(): void { this.passwordGeneratorOpen.set(true); }

  closePasswordGenerator(): void { this.passwordGeneratorOpen.set(false); }

  useGeneratedPassword(password: string): void {
    this.password.set(password);
    this.passwordCopied.set(false);
    this.passwordCopyAcknowledged.set(false);
    this.clearError();
    this.passwordGeneratorOpen.set(false);
  }

  async copyPassword(): Promise<void> {
    if (!this.password()) return;
    if (await this.sharing.copy(this.password())) {
      this.passwordCopied.set(true);
      this.passwordCopyAcknowledged.set(true);
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
    const maxFiles = policy?.maxFiles ?? 10;
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

  async create(skipConfirmation = false): Promise<void> {
    if (this.busy()) return;
    this.clearError();
    if (!this.message().trim() && this.selectedFiles().length === 0) { this.emptyMessageDialogOpen.set(true); return; }
    if (this.messageCharacters() > MAX_MESSAGE_CHARACTERS || this.messageBytes() > MAX_MESSAGE_BYTES) {
      this.setError({ key: 'tooLarge', params: { max: MAX_MESSAGE_CHARACTERS } });
      return;
    }
    if (!skipConfirmation && this.password() && !this.passwordCopyAcknowledged()) {
      this.passwordCopyDialogOpen.set(true);
      return;
    }

    this.busy.set(true);
    try {
      const encrypted = await encryptMessage(this.message());
      const files = await Promise.all(this.selectedFiles().map(file => encryptFile(file, decodeCanonical(encrypted.clientKey, 32))));
      const created = await this.api.create({
        protocolVersion: 1,
        expiry: this.expiry(),
        message: this.message().trim() ? encrypted.message : null,
        files,
        ...(this.password() ? { password: await derivePasswordToken(this.password(), encrypted.clientKey) } : {})
      });
      decodeCanonical(created.id, 16);
      this.shareLink.set(`${this.document.location.origin}/s/${created.id}#${encrypted.clientKey}`);
      this.expiresAt.set(created.expiresAt);
      this.history.add({
        id: created.id,
        createdAt: new Date().toISOString(),
        link: this.shareLink(),
        expiresAt: created.expiresAt,
        password: this.password(),
        revokeToken: created.revokeToken
      });
      this.app.activateResult();
      this.message.set('');
      this.selectedFiles.set([]);
      this.password.set('');
      this.passwordVisible.set(false);
      this.passwordCopied.set(false);
      this.passwordCopyAcknowledged.set(false);
    } catch {
      this.setError({ key: 'failure' });
    } finally {
      this.busy.set(false);
    }
  }

  async copy(): Promise<void> {
    if (await this.sharing.copy(this.shareLink())) this.copied.set(true);
    else this.setError({ key: 'clipboardFailure' });
  }

  share(url = this.shareLink()): void { void this.sharing.share(url); }
  cancelPasswordCopy(): void { this.passwordCopyDialogOpen.set(false); }
  continueWithoutCopying(): void { this.passwordCopyDialogOpen.set(false); void this.create(true); }

  reset(): void {
    this.app.activatePage('create');
    this.shareLink.set('');
    this.clearError();
    this.copied.set(false);
    this.password.set('');
    this.passwordVisible.set(false);
    this.passwordCopied.set(false);
    this.passwordCopyAcknowledged.set(false);
  }
}
