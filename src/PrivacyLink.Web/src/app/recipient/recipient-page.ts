import { AfterViewInit, Component, DestroyRef, ElementRef, inject, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { DatePipe } from '@angular/common';
import { ActivatedRoute, CanDeactivateFn } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { combineLatest } from 'rxjs';
import { AppState } from '../app-state';
import { LanguageState } from '../language-state';
import { RecipientState } from './recipient-state';

@Component({
  selector: 'app-recipient-page',
  imports: [DatePipe],
  providers: [RecipientState],
  templateUrl: './recipient-page.html'
})
export class RecipientPage implements OnInit, AfterViewInit, OnDestroy {
  protected readonly app = inject(AppState);
  protected readonly language = inject(LanguageState);
  protected readonly recipient = inject(RecipientState);
  private readonly route = inject(ActivatedRoute);
  private readonly destroyRef = inject(DestroyRef);

  private unlockPasswordInput?: ElementRef<HTMLInputElement>;

  @ViewChild('unlockPasswordInput')
  set unlockPasswordInputElement(input: ElementRef<HTMLInputElement> | undefined) {
    this.unlockPasswordInput = input;
    input?.nativeElement.focus();
  }

  @ViewChild('emailCodeInput')
  set emailCodeInputElement(input: ElementRef<HTMLInputElement> | undefined) {
    if (input) queueMicrotask(() => input.nativeElement.focus());
  }

  @ViewChild('openedPageTitle')
  set openedPageTitle(title: ElementRef<HTMLHeadingElement> | undefined) {
    title?.nativeElement.focus();
  }

  @ViewChild('unavailablePageTitle')
  set unavailablePageTitle(title: ElementRef<HTMLHeadingElement> | undefined) {
    title?.nativeElement.focus();
  }

  ngOnInit(): void {
    window.addEventListener('beforeunload', this.handleBeforeUnload);
    combineLatest([this.route.paramMap, this.route.fragment])
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(([params, fragment]) => {
        this.app.activatePage('recipient');
        this.recipient.initialize(params.get('id'), fragment ?? '');
      });
  }

  canLeaveRecipient(): boolean {
    return !this.recipient.oneTimeOpen() || !this.recipient.opened() || window.confirm(this.language.t('oneTimeLeaveConfirm'));
  }

  private readonly handleBeforeUnload = (event: BeforeUnloadEvent): void => {
    if (!this.recipient.oneTimeOpen() || !this.recipient.opened()) return;
    event.preventDefault();
    event.returnValue = '';
  };

  ngAfterViewInit(): void { document.getElementById('page-title')?.focus(); }

  async openRecipient(): Promise<void> {
    await this.recipient.open();
    if (this.recipient.error().some(error => error.key === 'incorrectPassword')) {
      this.unlockPasswordInput?.nativeElement.focus();
    }
  }

  async verifyEmailCode(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    await this.recipient.verifyEmailCode();
  }

  ngOnDestroy(): void { window.removeEventListener('beforeunload', this.handleBeforeUnload); this.recipient.leave(); }
}

export const recipientLeaveGuard: CanDeactivateFn<RecipientPage> = component => component.canLeaveRecipient();
