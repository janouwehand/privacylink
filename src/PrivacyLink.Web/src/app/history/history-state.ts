import { computed, inject, Injectable, signal, Signal } from '@angular/core';
import { Router } from '@angular/router';
import { LinkSharingState } from '../link-sharing-state';
import { SecretApi } from '../secret-api';
import { HistoryVaultError, SecretHistoryEntry, SecretHistoryStore } from '../secret-history-store';

@Injectable({ providedIn: 'root' })
export class HistoryState {
  private readonly api = inject(SecretApi);
  private readonly router = inject(Router);
  private readonly store = inject(SecretHistoryStore);
  private readonly sharing = inject(LinkSharingState);

  readonly secretHistory: SecretHistoryStore['entries'];
  readonly historyStorageWarning: SecretHistoryStore['saveFailed'];
  readonly historyEnabled: SecretHistoryStore['enabled'];
  readonly historyUnlocked: SecretHistoryStore['unlocked'];
  readonly historyLocked: SecretHistoryStore['locked'];
  readonly legacyCleanupFailed: SecretHistoryStore['legacyCleanupFailed'];
  readonly vaultError: SecretHistoryStore['error'];
  readonly historyAvailable: Signal<boolean>;
  readonly vaultBusy = signal(false);
  readonly unlockHistoryDialogOpen = signal(false);
  readonly resetVaultDialogOpen = signal(false);
  readonly unlockPassphrase = signal('');
  readonly resetPassphrase = signal('');
  readonly resetPassphraseConfirmation = signal('');
  readonly unlockPassphraseValid = computed(() => Array.from(this.unlockPassphrase()).length >= 12);
  readonly resetPassphraseValid = computed(() => Array.from(this.resetPassphrase()).length >= 12
    && this.resetPassphrase() === this.resetPassphraseConfirmation());
  readonly resetVaultError = signal<HistoryVaultError | null>(null);
  readonly disableHistoryDialogOpen = signal(false);
  readonly visibleHistoryPasswords = signal<Set<string>>(new Set());
  readonly historyCopiedId = signal('');
  readonly historyCopyFailed = signal(false);
  readonly historyRevokeFailed = signal(false);
  readonly historyRevokingId = signal('');
  readonly pendingHistoryAction = signal<{ entry: SecretHistoryEntry; action: 'forget' | 'revoke' } | null>(null);
  readonly historyActionDialogOpen = signal(false);
  readonly clearHistoryDialogOpen = signal(false);
  readonly canShare = this.sharing.canShare;
  private historyCopiedTimeout: ReturnType<typeof setTimeout> | undefined;
  private navigateToHistoryAfterUnlock = false;

  constructor() {
    this.secretHistory = this.store.entries;
    this.historyStorageWarning = this.store.saveFailed;
    this.historyEnabled = this.store.enabled;
    this.historyUnlocked = this.store.unlocked;
    this.historyLocked = this.store.locked;
    this.legacyCleanupFailed = this.store.legacyCleanupFailed;
    this.vaultError = this.store.error;
    this.historyAvailable = computed(() => this.store.enabled() || this.store.legacyCleanupFailed() || this.store.entries().length > 0);
  }

  toggleHistoryPassword(id: string): void {
    this.visibleHistoryPasswords.update(visible => {
      const updated = new Set(visible);
      if (updated.has(id)) updated.delete(id); else updated.add(id);
      return updated;
    });
  }

  async copyHistoryValue(entry: SecretHistoryEntry, field: 'link' | 'password'): Promise<void> {
    const value = entry[field];
    if (!value) return;
    if (await this.sharing.copy(value)) {
      const copiedKey = `${entry.id}:${field}`;
      this.historyCopiedId.set(copiedKey);
      this.historyCopyFailed.set(false);
      if (this.historyCopiedTimeout) clearTimeout(this.historyCopiedTimeout);
      this.historyCopiedTimeout = setTimeout(() => {
        if (this.historyCopiedId() === copiedKey) this.historyCopiedId.set('');
      }, 1200);
    } else {
      this.historyCopiedId.set('');
      this.historyCopyFailed.set(true);
    }
  }

  openHistoryLink(entry: SecretHistoryEntry): void { this.sharing.openInNewTab(entry.link); }
  share(url: string): void { void this.sharing.share(url); }

  requestHistoryAction(entry: SecretHistoryEntry, action: 'forget' | 'revoke'): void {
    if (this.historyRevokingId() || (action === 'revoke' && !entry.revokeToken)) return;
    this.pendingHistoryAction.set({ entry, action });
    this.historyActionDialogOpen.set(true);
  }

  cancelHistoryAction(): void {
    this.pendingHistoryAction.set(null);
    this.historyActionDialogOpen.set(false);
  }

  onHistoryActionDialogClosed(): void { this.pendingHistoryAction.set(null); this.historyActionDialogOpen.set(false); }

  confirmHistoryAction(): void {
    const pending = this.pendingHistoryAction();
    if (!pending) return;
    this.historyActionDialogOpen.set(false);
    this.pendingHistoryAction.set(null);
    if (pending.action === 'revoke') void this.revokeHistoryEntry(pending.entry);
    else void this.removeHistoryEntryLocally(pending.entry);
  }

  openClearHistoryDialog(): void { this.clearHistoryDialogOpen.set(true); }
  closeClearHistoryDialog(): void { this.clearHistoryDialogOpen.set(false); }

  async confirmClearHistory(): Promise<void> {
    await this.store.clear();
    this.visibleHistoryPasswords.set(new Set());
    this.historyCopiedId.set('');
    this.historyCopyFailed.set(false);
    this.historyRevokeFailed.set(false);
    this.closeClearHistoryDialog();
  }

  private async removeHistoryEntryLocally(entry: SecretHistoryEntry): Promise<void> {
    this.visibleHistoryPasswords.update(visible => {
      const next = new Set(visible);
      next.delete(entry.id);
      return next;
    });
    await this.store.remove(entry.id);
  }

  private async revokeHistoryEntry(entry: SecretHistoryEntry): Promise<void> {
    if (!entry.revokeToken || this.historyRevokingId()) return;
    this.historyRevokeFailed.set(false);
    this.historyRevokingId.set(entry.id);
    try {
      await this.api.revoke(entry.id, entry.revokeToken);
      await this.removeHistoryEntryLocally(entry);
    } catch {
      this.historyRevokeFailed.set(true);
    } finally {
      this.historyRevokingId.set('');
    }
  }

  requestUnlockHistory(navigateToHistoryAfterUnlock = false): void {
    if (this.vaultBusy() || !this.historyLocked()) return;
    this.unlockPassphrase.set('');
    this.store.error.set(null);
    this.navigateToHistoryAfterUnlock = navigateToHistoryAfterUnlock;
    this.unlockHistoryDialogOpen.set(true);
  }

  closeUnlockHistoryDialog(): void {
    if (this.vaultBusy()) return;
    this.unlockHistoryDialogOpen.set(false);
    this.clearUnlockState();
  }

  onUnlockHistoryDialogClosed(): void {
    this.unlockHistoryDialogOpen.set(false);
    this.clearUnlockState();
  }

  preventUnlockHistoryCancel(event: Event): void {
    if (this.vaultBusy()) event.preventDefault();
  }

  requestResetVaultFromUnlockDialog(): void {
    if (this.vaultBusy()) return;
    this.unlockHistoryDialogOpen.set(false);
    this.clearUnlockState();
    this.requestResetVault();
  }

  async unlockHistory(): Promise<void> {
    if (!this.unlockPassphraseValid() || this.vaultBusy()) return;
    const passphrase = this.unlockPassphrase();
    this.unlockPassphrase.set('');
    this.vaultBusy.set(true);
    try {
      if (!await this.store.unlock(passphrase)) return;
      const navigateToHistory = this.navigateToHistoryAfterUnlock;
      this.navigateToHistoryAfterUnlock = false;
      this.unlockHistoryDialogOpen.set(false);
      if (navigateToHistory) await this.router.navigateByUrl('/history');
    } finally {
      this.vaultBusy.set(false);
    }
  }

  updateUnlockPassphrase(event: Event): void { this.unlockPassphrase.set((event.target as HTMLInputElement).value); }
  updateResetPassphrase(event: Event): void { this.resetPassphrase.set((event.target as HTMLInputElement).value); }
  updateResetPassphraseConfirmation(event: Event): void { this.resetPassphraseConfirmation.set((event.target as HTMLInputElement).value); }

  retryLegacyCleanup(): void { this.store.retryLegacyCleanup(); }

  requestResetVault(): void {
    if (this.vaultBusy()) return;
    this.resetVaultError.set(null);
    this.resetPassphrase.set('');
    this.resetPassphraseConfirmation.set('');
    this.resetVaultDialogOpen.set(true);
  }

  private clearUnlockState(): void {
    this.unlockPassphrase.set('');
    this.store.error.set(null);
    this.navigateToHistoryAfterUnlock = false;
  }
  closeResetVaultDialog(): void {
    if (this.vaultBusy()) return;
    this.resetVaultDialogOpen.set(false);
    this.resetPassphrase.set('');
    this.resetPassphraseConfirmation.set('');
    this.resetVaultError.set(null);
  }
  preventResetVaultCancel(event: Event): void {
    if (this.vaultBusy()) event.preventDefault();
  }
  async confirmResetVault(): Promise<void> {
    if (!this.resetPassphraseValid()) return;
    this.vaultBusy.set(true);
    try {
      const reset = await this.store.reset(this.resetPassphrase());
      if (reset) {
        this.vaultBusy.set(false);
        this.closeResetVaultDialog();
      }
      else this.resetVaultError.set(this.store.error());
    } finally { this.vaultBusy.set(false); }
  }

  requestDisableHistory(): void { this.disableHistoryDialogOpen.set(true); }
  closeDisableHistoryDialog(): void { this.disableHistoryDialogOpen.set(false); }
  async confirmDisableHistory(): Promise<void> {
    this.closeDisableHistoryDialog();
    this.vaultBusy.set(true);
    try { await this.store.disable(); } finally { this.vaultBusy.set(false); }
  }
}
