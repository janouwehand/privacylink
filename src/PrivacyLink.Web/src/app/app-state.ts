import { effect, inject, Injectable, signal } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { LanguageState } from './language-state';
import type { TranslationKey } from './translations';

export type AppMode = 'create' | 'result' | 'recipient' | 'history' | 'security' | 'statistics' | 'security-details' | 'password-generator' | 'not-found';

const PAGE_TITLE_KEYS: Record<AppMode, TranslationKey> = {
  create: 'appTitle',
  result: 'pageTitleResult',
  recipient: 'pageTitleRecipient',
  history: 'pageTitleHistory',
  security: 'pageTitleSecurity',
  statistics: 'pageTitleStatistics',
  'security-details': 'pageTitleSecurityDetails',
  'password-generator': 'pageTitlePasswordGenerator',
  'not-found': 'pageTitleNotFound'
};

@Injectable({ providedIn: 'root' })
export class AppState {
  readonly mode = signal<AppMode>('create');

  private readonly language = inject(LanguageState);
  private readonly title = inject(Title);

  constructor() {
    effect(() => this.title.setTitle(this.language.t(PAGE_TITLE_KEYS[this.mode()])));
  }

  activatePage(mode: Exclude<AppMode, 'result'>): void {
    this.mode.set(mode);
  }

  activateResult(): void {
    this.mode.set('result');
  }
}
