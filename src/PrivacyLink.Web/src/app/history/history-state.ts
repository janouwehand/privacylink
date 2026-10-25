import { inject, Injectable, signal } from '@angular/core';
import { Router } from '@angular/router';
import { LinkSharingState } from '../link-sharing-state';
import { SecretApi } from '../secret-api';
import { SecretHistoryEntry, SecretHistoryStore } from '../secret-history-store';

@Injectable({ providedIn: 'root' })
export class HistoryState {
  private readonly api = inject(SecretApi);
  private readonly router = inject(Router);
  private readonly store = inject(SecretHistoryStore);
  private readonly sharing = inject(LinkSharingState);

  readonly secretHistory: SecretHistoryStore['entries'];
  readonly historyStorageWarning: SecretHistoryStore['saveFailed'];
  readonly expiryCleanupFailed: SecretHistoryStore['expiryCleanupFailed'];
  readonly storeUnavailable: SecretHistoryStore['unavailableEntries'];
  readonly visibleHistoryPasswords = signal<Set<string>>(new Set());
  readonly historyCopiedId = signal('');
  readonly historyCopyFailed = signal(false);
  readonly historyRevokeFailed = signal(false);
  readonly historyRevokingId = signal('');
  readonly pendingHistoryAction = signal<{ entry: SecretHistoryEntry; action: 'forget' | 'revoke' } | null>(null);
  readonly historyActionDialogOpen = signal(false);
  readonly clearHistoryDialogOpen = signal(false);
  readonly editingLabelId = signal('');
  readonly labelDraft = signal('');
  readonly canShare = this.sharing.canShare;

  private historyCopiedTimeout: ReturnType<typeof setTimeout> | undefined;

  constructor() {
    this.secretHistory = this.store.entries;
    this.historyStorageWarning = this.store.saveFailed;
    this.expiryCleanupFailed = this.store.expiryCleanupFailed;
    this.storeUnavailable = this.store.unavailableEntries;
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
      const copiedKey = entry.id + ':' + field;
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
    if (!await this.store.clear()) return;
    this.visibleHistoryPasswords.set(new Set());
    this.historyCopiedId.set('');
    this.historyCopyFailed.set(false);
    this.historyRevokeFailed.set(false);
    this.closeClearHistoryDialog();
  }

  editLabel(entry: SecretHistoryEntry): void {
    this.editingLabelId.set(entry.id);
    this.labelDraft.set(entry.givenLabel ?? '');
  }

  cancelLabelEdit(): void {
    this.editingLabelId.set('');
    this.labelDraft.set('');
  }

  updateLabelDraft(event: Event): void { this.labelDraft.set((event.target as HTMLInputElement).value); }

  async saveLabel(entry: SecretHistoryEntry): Promise<void> {
    if (!await this.store.updateLabel(entry.id, this.labelDraft())) return;
    this.cancelLabelEdit();
  }

  async navigateToHistory(): Promise<void> { await this.router.navigateByUrl('/history'); }

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
}
