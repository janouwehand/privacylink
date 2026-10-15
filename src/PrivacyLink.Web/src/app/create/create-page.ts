import { AfterViewInit, Component, ElementRef, inject, OnDestroy, signal, ViewChild } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AppState } from '../app-state';
import { LanguageState } from '../language-state';
import { CreateState } from './create-state';

@Component({
  selector: 'app-create-page',
  imports: [DatePipe, RouterLink],
  templateUrl: './create-page.html'
})
export class CreatePage implements AfterViewInit, OnDestroy {
  protected readonly app = inject(AppState);
  protected readonly create = inject(CreateState);
  protected readonly language = inject(LanguageState);
  protected readonly emailDraft = signal('');

  @ViewChild('emailVerificationDialog') private emailVerificationDialog?: ElementRef<HTMLDialogElement>;

  constructor() {
    this.app.activatePage('create');
    this.create.initialize();
  }

  ngAfterViewInit(): void {
    if (this.app.mode() === 'create') document.getElementById('message')?.focus();
  }

  ngOnDestroy(): void { this.create.onPageExit(); }

  openEmailVerificationDialog(): void {
    this.emailDraft.set(this.create.recipientEmail());
    const dialog = this.emailVerificationDialog?.nativeElement;
    if (dialog && !dialog.open) dialog.showModal();
  }

  closeEmailVerificationDialog(): void {
    this.emailVerificationDialog?.nativeElement.close();
  }

  updateEmailDraft(event: Event): void {
    this.emailDraft.set((event.target as HTMLInputElement).value);
  }

  saveEmailVerification(event: SubmitEvent): void {
    event.preventDefault();
    const form = event.currentTarget as HTMLFormElement;
    if (!form.reportValidity()) return;
    this.create.setRecipientEmail(this.emailDraft().trim());
    this.create.enableEmailVerification();
    this.closeEmailVerificationDialog();
  }

  removeEmailVerification(): void { this.create.removeEmailVerification(); }
}
