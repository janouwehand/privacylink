import { AfterViewInit, Component, ElementRef, computed, effect, inject, signal, ViewChild } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';
import { AppState } from './app-state';
import { CreateState } from './create/create-state';
import { HistoryState } from './history/history-state';
import { LanguageState } from './language-state';
import { PasswordGenerator } from './password-generator/password-generator';
import { APP_VERSION } from './app-version';
import { WorkProgressState } from './work-progress-state';

@Component({
  selector: 'app-root',
  imports: [RouterLink, RouterOutlet, PasswordGenerator],
  templateUrl: './app.html'
})
export class App implements AfterViewInit {
  protected readonly appVersion = APP_VERSION;
  protected readonly app = inject(AppState);
  protected readonly create = inject(CreateState);
  protected readonly history = inject(HistoryState);
  protected readonly language = inject(LanguageState);
  protected readonly workProgress = inject(WorkProgressState);
  protected readonly historyPassphrase = signal('');
  protected readonly historyPassphraseConfirmation = signal('');
  protected readonly historyPassphraseValid = computed(() => Array.from(this.historyPassphrase()).length >= 12
    && this.historyPassphrase() === this.historyPassphraseConfirmation());

  @ViewChild('passwordCopyDialog') private passwordCopyDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('emptyMessageDialog') private emptyMessageDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('historyActionDialog') private historyActionDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('clearHistoryDialog') private clearHistoryDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('historyLockedDialog') private historyLockedDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('historyOptInDialog') private historyOptInDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('unlockHistoryDialog') private unlockHistoryDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('resetVaultDialog') private resetVaultDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('disableHistoryDialog') private disableHistoryDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('passwordGeneratorDialog') private passwordGeneratorDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('workProgressDialog') private workProgressDialog?: ElementRef<HTMLDialogElement>;

  constructor() {
    effect(() => this.syncDialog(this.passwordCopyDialog?.nativeElement, this.create.passwordCopyDialogOpen()));
    effect(() => this.syncDialog(this.emptyMessageDialog?.nativeElement, this.create.emptyMessageDialogOpen()));
    effect(() => this.syncDialog(this.historyActionDialog?.nativeElement, this.history.historyActionDialogOpen()));
    effect(() => this.syncDialog(this.clearHistoryDialog?.nativeElement, this.history.clearHistoryDialogOpen()));
    effect(() => this.syncDialog(this.historyLockedDialog?.nativeElement, this.create.historyLockedDialogOpen()));
    effect(() => this.syncHistoryVaultDialogs(this.history.unlockHistoryDialogOpen(), this.history.resetVaultDialogOpen()));
    effect(() => this.syncDialog(this.disableHistoryDialog?.nativeElement, this.history.disableHistoryDialogOpen()));
    effect(() => this.syncDialog(this.passwordGeneratorDialog?.nativeElement, this.create.passwordGeneratorOpen()));
    effect(() => this.syncDialog(this.workProgressDialog?.nativeElement, this.workProgress.visible()));
  }

  ngAfterViewInit(): void {
    this.syncDialog(this.passwordCopyDialog?.nativeElement, this.create.passwordCopyDialogOpen());
    this.syncDialog(this.emptyMessageDialog?.nativeElement, this.create.emptyMessageDialogOpen());
    this.syncDialog(this.historyActionDialog?.nativeElement, this.history.historyActionDialogOpen());
    this.syncDialog(this.clearHistoryDialog?.nativeElement, this.history.clearHistoryDialogOpen());
    this.syncDialog(this.historyLockedDialog?.nativeElement, this.create.historyLockedDialogOpen());
    this.syncDialog(this.historyOptInDialog?.nativeElement, false);
    this.syncHistoryVaultDialogs(this.history.unlockHistoryDialogOpen(), this.history.resetVaultDialogOpen());
    this.syncDialog(this.disableHistoryDialog?.nativeElement, this.history.disableHistoryDialogOpen());
    this.syncDialog(this.passwordGeneratorDialog?.nativeElement, this.create.passwordGeneratorOpen());
    this.syncDialog(this.workProgressDialog?.nativeElement, this.workProgress.visible());
  }

  private syncDialog(dialog: HTMLDialogElement | undefined, shouldOpen: boolean): void {
    if (!dialog) return;
    if (shouldOpen && !dialog.open) dialog.showModal();
    else if (!shouldOpen && dialog.open) dialog.close();
  }

  openHistoryOptInDialog(): void {
    if (this.create.historySetupBusy() || this.history.historyEnabled()) return;
    this.create.historySetupError.set(null);
    this.historyPassphrase.set('');
    this.historyPassphraseConfirmation.set('');
    const dialog = this.historyOptInDialog?.nativeElement;
    if (dialog && !dialog.open) dialog.showModal();
  }

  closeHistoryOptInDialog(): void {
    if (this.create.historySetupBusy()) return;
    this.historyOptInDialog?.nativeElement.close();
  }

  onHistoryOptInDialogClosed(): void {
    this.historyPassphrase.set('');
    this.historyPassphraseConfirmation.set('');
  }

  preventHistoryOptInCancel(event: Event): void {
    if (this.create.historySetupBusy()) event.preventDefault();
  }

  async enableHistory(): Promise<void> {
    if (!this.historyPassphraseValid() || this.create.historySetupBusy()) return;
    if (await this.create.enableHistory(this.historyPassphrase())) {
      if (this.app.mode() === 'result') this.create.historyEnabledFromResult.set(true);
      this.closeHistoryOptInDialog();
    }
    else {
      this.historyPassphrase.set('');
      this.historyPassphraseConfirmation.set('');
    }
  }

  updateHistoryPassphrase(event: Event): void { this.historyPassphrase.set((event.target as HTMLInputElement).value); }
  updateHistoryPassphraseConfirmation(event: Event): void { this.historyPassphraseConfirmation.set((event.target as HTMLInputElement).value); }

  private syncHistoryVaultDialogs(unlockOpen: boolean, resetOpen: boolean): void {
    const unlockDialog = this.unlockHistoryDialog?.nativeElement;
    const resetDialog = this.resetVaultDialog?.nativeElement;
    if (resetOpen) {
      if (unlockDialog?.open) unlockDialog.close();
      this.syncDialog(resetDialog, true);
      return;
    }
    this.syncDialog(resetDialog, false);
    this.syncDialog(unlockDialog, unlockOpen);
  }
}
