import { DOCUMENT, registerLocaleData } from '@angular/common';
import localeNl from '@angular/common/locales/nl';
import { inject, Injectable, InjectionToken, signal } from '@angular/core';
import { translate } from './translations';
import type { Language, TranslationArguments, TranslationKey, TranslatableError } from './translations';

const LANGUAGE_STORAGE_KEY = 'privacylink.language';

export interface LanguageStorageAdapter {
  get(key: string): string | null;
  set(key: string, value: string): void;
}

export const LANGUAGE_STORAGE_ADAPTER = new InjectionToken<LanguageStorageAdapter>('LANGUAGE_STORAGE_ADAPTER', {
  providedIn: 'root',
  factory: () => ({ get: key => globalThis.localStorage.getItem(key), set: (key, value) => globalThis.localStorage.setItem(key, value) })
});

function initialLanguage(storage: LanguageStorageAdapter): Language {
  try {
    const stored = storage.get(LANGUAGE_STORAGE_KEY);
    if (stored === 'nl' || stored === 'en') return stored;
  } catch { /* Fall back to the browser language when storage is unavailable. */ }
  return navigator.language.toLowerCase().startsWith('nl') ? 'nl' : 'en';
}

registerLocaleData(localeNl);

@Injectable({ providedIn: 'root' })
export class LanguageState {
  private readonly storage = inject(LANGUAGE_STORAGE_ADAPTER);
  readonly lang = signal<Language>(initialLanguage(this.storage));
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
    try { this.storage.set(LANGUAGE_STORAGE_KEY, lang); } catch { /* Keep the selected language for this page. */ }
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
