import { Component, EventEmitter, Input, Output, computed, inject, signal } from '@angular/core';
import { LinkSharingState } from '../link-sharing-state';
import { LanguageState } from '../language-state';

type GeneratorType = 'password' | 'pin';
type GeneratorSettings = {
  type: GeneratorType;
  pinLength: number;
  passwordLength: number;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
};

const SETTINGS_KEY = 'privacylink.passwordGeneratorSettings';
const DEFAULT_SETTINGS: GeneratorSettings = {
  type: 'pin',
  pinLength: 6,
  passwordLength: 16,
  numbers: true,
  symbols: false,
  excludeAmbiguous: true
};

function loadSettings(): GeneratorSettings {
  try {
    const stored: unknown = JSON.parse(globalThis.localStorage.getItem(SETTINGS_KEY) ?? 'null');
    if (!stored || typeof stored !== 'object') return { ...DEFAULT_SETTINGS };
    const settings = stored as Partial<GeneratorSettings>;
    return {
      type: settings.type === 'password' ? 'password' : 'pin',
      pinLength: Number.isInteger(settings.pinLength) ? Math.max(4, Math.min(12, settings.pinLength!)) : DEFAULT_SETTINGS.pinLength,
      passwordLength: Number.isInteger(settings.passwordLength) ? Math.max(8, Math.min(64, settings.passwordLength!)) : DEFAULT_SETTINGS.passwordLength,
      numbers: typeof settings.numbers === 'boolean' ? settings.numbers : DEFAULT_SETTINGS.numbers,
      symbols: typeof settings.symbols === 'boolean' ? settings.symbols : DEFAULT_SETTINGS.symbols,
      excludeAmbiguous: typeof settings.excludeAmbiguous === 'boolean' ? settings.excludeAmbiguous : DEFAULT_SETTINGS.excludeAmbiguous
    };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

const CHARACTER_GROUPS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?'
} as const;

const UNAMBIGUOUS_GROUPS = {
  uppercase: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  lowercase: 'abcdefghijkmnpqrstuvwxyz',
  numbers: '23456789',
  symbols: CHARACTER_GROUPS.symbols
} as const;

@Component({
  selector: 'app-password-generator',
  templateUrl: './password-generator.html'
})
export class PasswordGenerator {
  @Input() context: 'dialog' | 'page' = 'page';
  @Output() readonly usePassword = new EventEmitter<string>();
  @Output() readonly close = new EventEmitter<void>();

  protected readonly language = inject(LanguageState);
  private readonly sharing = inject(LinkSharingState);
  private copiedTimeout: ReturnType<typeof setTimeout> | undefined;

  private readonly initialSettings = loadSettings();
  readonly type = signal<GeneratorType>(this.initialSettings.type);
  readonly pinLength = signal(this.initialSettings.pinLength);
  readonly passwordLength = signal(this.initialSettings.passwordLength);
  readonly length = computed(() => this.type() === 'pin' ? this.pinLength() : this.passwordLength());
  readonly numbers = signal(true);
  readonly symbols = signal(this.initialSettings.symbols);
  readonly excludeAmbiguous = signal(this.initialSettings.excludeAmbiguous);
  readonly value = signal('');
  readonly copied = signal(false);
  readonly copyFailed = signal(false);

  constructor() {
    this.numbers.set(this.initialSettings.numbers);
    this.generate();
  }

  setType(type: GeneratorType): void {
    if (this.type() === type) return;
    this.type.set(type);
    this.saveSettings();
    this.generate();
  }

  updateLength(event: Event): void {
    const value = Number((event.target as HTMLInputElement).value);
    if (this.type() === 'pin') this.pinLength.set(value);
    else this.passwordLength.set(value);
    this.saveSettings();
    this.generate();
  }

  toggleOption(option: 'numbers' | 'symbols' | 'excludeAmbiguous'): void {
    if (this.type() === 'pin') return;
    this[option].update(value => !value);
    this.saveSettings();
    this.generate();
  }

  generate(): void {
    const selectedGroups: (keyof typeof CHARACTER_GROUPS)[] = this.type() === 'pin'
      ? ['numbers']
      : ['uppercase', 'lowercase', ...(this.numbers() ? ['numbers' as const] : []), ...(this.symbols() ? ['symbols' as const] : [])];
    const sourceGroups = this.type() === 'pin' || this.excludeAmbiguous() ? UNAMBIGUOUS_GROUPS : CHARACTER_GROUPS;
    const groups = selectedGroups.map(group => sourceGroups[group]);
    const alphabet = groups.join('');
    const chars = groups.map(group => group[this.randomIndex(group.length)]);
    while (chars.length < this.length()) chars.push(alphabet[this.randomIndex(alphabet.length)]);
    for (let index = chars.length - 1; index > 0; index--) {
      const swap = this.randomIndex(index + 1);
      [chars[index], chars[swap]] = [chars[swap], chars[index]];
    }
    this.value.set(chars.join(''));
    this.copied.set(false);
    this.copyFailed.set(false);
  }

  async copy(): Promise<void> {
    const success = await this.sharing.copy(this.value());
    this.copied.set(success);
    this.copyFailed.set(!success);
    if (this.copiedTimeout) clearTimeout(this.copiedTimeout);
    if (success) this.copiedTimeout = setTimeout(() => this.copied.set(false), 1200);
  }

  accept(): void { this.usePassword.emit(this.value()); }

  private randomIndex(max: number): number {
    const limit = Math.floor(0x100000000 / max) * max;
    const random = new Uint32Array(1);
    do { crypto.getRandomValues(random); } while (random[0] >= limit);
    return random[0] % max;
  }

  private saveSettings(): void {
    try {
      const settings: GeneratorSettings = {
        type: this.type(),
        pinLength: this.pinLength(),
        passwordLength: this.passwordLength(),
        numbers: this.numbers(),
        symbols: this.symbols(),
        excludeAmbiguous: this.excludeAmbiguous()
      };
      globalThis.localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    } catch {
      // Keep the generator usable when browser storage is unavailable.
    }
  }
}
