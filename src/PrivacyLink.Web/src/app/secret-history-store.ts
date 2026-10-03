import { InjectionToken, Injectable, inject, signal } from '@angular/core';

export type SecretHistoryEntry = {
  id: string;
  createdAt: string;
  link: string;
  expiresAt: string;
  password: string;
  revokeToken?: string;
};

export interface SecretHistoryStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export const SECRET_HISTORY_STORAGE = new InjectionToken<SecretHistoryStorage>('SECRET_HISTORY_STORAGE', {
  providedIn: 'root',
  factory: () => ({
    getItem: key => globalThis.localStorage.getItem(key),
    setItem: (key, value) => globalThis.localStorage.setItem(key, value)
  })
});

const STORAGE_KEY = 'privacylink.secret-history.v1';

@Injectable({ providedIn: 'root' })
export class SecretHistoryStore {
  private readonly storage = inject(SECRET_HISTORY_STORAGE);
  readonly saveFailed = signal(false);
  private readonly mutableEntries = signal<SecretHistoryEntry[]>(this.load());
  private expiryCleanupTimeout: ReturnType<typeof setTimeout> | undefined;

  readonly entries = this.mutableEntries.asReadonly();

  constructor() { this.scheduleExpiryCleanup(); }

  add(entry: SecretHistoryEntry): boolean {
    const updated = [entry, ...this.activeEntries()];
    this.mutableEntries.set(updated);
    const saved = this.persist(updated);
    this.scheduleExpiryCleanup();
    return saved;
  }

  remove(id: string): boolean {
    const updated = this.activeEntries().filter(entry => entry.id !== id);
    this.mutableEntries.set(updated);
    const saved = this.persist(updated);
    this.scheduleExpiryCleanup();
    return saved;
  }

  clear(): boolean {
    this.mutableEntries.set([]);
    if (this.expiryCleanupTimeout) clearTimeout(this.expiryCleanupTimeout);
    this.expiryCleanupTimeout = undefined;
    return this.persist([]);
  }

  pruneExpired(): boolean {
    const active = this.activeEntries();
    if (active.length === this.mutableEntries().length) return false;
    this.mutableEntries.set(active);
    this.persist(active);
    this.scheduleExpiryCleanup();
    return true;
  }

  private activeEntries(): SecretHistoryEntry[] {
    return this.mutableEntries().filter(entry => Date.parse(entry.expiresAt) > Date.now());
  }

  private scheduleExpiryCleanup(): void {
    if (this.expiryCleanupTimeout) clearTimeout(this.expiryCleanupTimeout);
    const nearestExpiry = Math.min(...this.mutableEntries().map(entry => Date.parse(entry.expiresAt)));
    if (!Number.isFinite(nearestExpiry)) return;
    const delay = Math.min(Math.max(0, nearestExpiry - Date.now()), 2_147_000_000);
    this.expiryCleanupTimeout = setTimeout(() => {
      this.pruneExpired();
      this.scheduleExpiryCleanup();
    }, delay);
  }

  private load(): SecretHistoryEntry[] {
    try {
      const stored: unknown = JSON.parse(this.storage.getItem(STORAGE_KEY) ?? '[]');
      if (!Array.isArray(stored)) return [];
      const validEntries = stored.filter((item): item is SecretHistoryEntry => !!item && typeof item === 'object'
        && typeof item.id === 'string' && typeof item.createdAt === 'string' && typeof item.link === 'string'
        && typeof item.expiresAt === 'string' && Number.isFinite(Date.parse(item.expiresAt))
        && typeof item.password === 'string' && (item.revokeToken === undefined || typeof item.revokeToken === 'string'));
      const activeEntries = validEntries.filter(entry => Date.parse(entry.expiresAt) > Date.now());
      if (activeEntries.length !== stored.length) {
        try {
          this.storage.setItem(STORAGE_KEY, JSON.stringify(activeEntries));
        } catch {
          this.saveFailed.set(true);
        }
      }
      return activeEntries;
    } catch {
      return [];
    }
  }

  private persist(entries: SecretHistoryEntry[]): boolean {
    try {
      this.storage.setItem(STORAGE_KEY, JSON.stringify(entries));
      this.saveFailed.set(false);
      return true;
    } catch {
      this.saveFailed.set(true);
      return false;
    }
  }
}
