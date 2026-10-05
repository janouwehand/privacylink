import { AfterViewInit, Component, ElementRef, effect, inject, ViewChild } from '@angular/core';
import { RouterLink, RouterOutlet } from '@angular/router';
import { AppState } from './app-state';
import { CreateState } from './create/create-state';
import { HistoryState } from './history/history-state';
import { LanguageState } from './language-state';
import { PasswordGenerator } from './password-generator/password-generator';
import { APP_VERSION } from './app-version';

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

  @ViewChild('passwordCopyDialog') private passwordCopyDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('emptyMessageDialog') private emptyMessageDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('historyActionDialog') private historyActionDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('clearHistoryDialog') private clearHistoryDialog?: ElementRef<HTMLDialogElement>;
  @ViewChild('passwordGeneratorDialog') private passwordGeneratorDialog?: ElementRef<HTMLDialogElement>;

  constructor() {
    effect(() => this.syncDialog(this.passwordCopyDialog?.nativeElement, this.create.passwordCopyDialogOpen()));
    effect(() => this.syncDialog(this.emptyMessageDialog?.nativeElement, this.create.emptyMessageDialogOpen()));
    effect(() => this.syncDialog(this.historyActionDialog?.nativeElement, this.history.historyActionDialogOpen()));
    effect(() => this.syncDialog(this.clearHistoryDialog?.nativeElement, this.history.clearHistoryDialogOpen()));
    effect(() => this.syncDialog(this.passwordGeneratorDialog?.nativeElement, this.create.passwordGeneratorOpen()));
  }

  ngAfterViewInit(): void {
    this.syncDialog(this.passwordCopyDialog?.nativeElement, this.create.passwordCopyDialogOpen());
    this.syncDialog(this.emptyMessageDialog?.nativeElement, this.create.emptyMessageDialogOpen());
    this.syncDialog(this.historyActionDialog?.nativeElement, this.history.historyActionDialogOpen());
    this.syncDialog(this.clearHistoryDialog?.nativeElement, this.history.clearHistoryDialogOpen());
    this.syncDialog(this.passwordGeneratorDialog?.nativeElement, this.create.passwordGeneratorOpen());
  }

  private syncDialog(dialog: HTMLDialogElement | undefined, shouldOpen: boolean): void {
    if (!dialog) return;
    if (shouldOpen && !dialog.open) dialog.showModal();
    else if (!shouldOpen && dialog.open) dialog.close();
  }
}
