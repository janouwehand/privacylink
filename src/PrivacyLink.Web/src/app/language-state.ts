import { DOCUMENT, registerLocaleData } from '@angular/common';
import localeNl from '@angular/common/locales/nl';
import { inject, Injectable, signal } from '@angular/core';
import { translate } from './translations';
import type { Language, TranslationArguments, TranslationKey, TranslatableError } from './translations';

const LANGUAGE_STORAGE_KEY = 'privacylink.language';

function initialLanguage(): Language {
  try {
    const stored = globalThis.localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (stored === 'nl' || stored === 'en') return stored;
  } catch { /* Fall back to the browser language when storage is unavailable. */ }
  return navigator.language.toLowerCase().startsWith('nl') ? 'nl' : 'en';
}

registerLocaleData(localeNl);

@Injectable({ providedIn: 'root' })
export class LanguageState {
  readonly lang = signal<Language>(initialLanguage());
  readonly dateLocale = () => this.lang() === 'nl' ? 'nl' : 'en-US';

  private readonly document = inject(DOCUMENT);

  constructor() {
    this.document.documentElement.lang = this.lang();
  }

  t<K extends TranslationKey>(key: K, ...args: TranslationArguments<K>): string {
    return translate(this.lang(), key, ...args);
  }

  setLanguage(lang: Language): void {
    this.lang.set(lang);
    this.document.documentElement.lang = lang;
    try { globalThis.localStorage.setItem(LANGUAGE_STORAGE_KEY, lang); } catch { /* Keep the selected language for this page. */ }
  }

  formatNumber(value: number, maximumFractionDigits?: number): string {
    return new Intl.NumberFormat(this.lang(), { maximumFractionDigits }).format(value);
  }

  formatFileSize(bytes: number): string {
    const unit = bytes >= 1024 * 1024 ? 'MiB' : 'KiB';
    const value = bytes / (unit === 'MiB' ? 1024 * 1024 : 1024);
    return `${this.formatNumber(value, unit === 'MiB' ? 2 : 1)} ${unit}`;
  }

  translateError(error: TranslatableError): string {
    switch (error.key) {
      case 'tooLarge': return this.t('tooLarge', error.params);
      case 'unsupportedFileType': return this.t('unsupportedFileType', error.params);
      case 'tooManyFiles': return this.t('tooManyFiles', error.params);
      case 'filesTooLarge': return this.t('filesTooLarge', { size: this.formatFileSize(error.params.sizeInBytes) });
      default: return this.t(error.key);
    }
  }
}
