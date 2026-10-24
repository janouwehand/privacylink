import { DestroyRef, InjectionToken, Injectable, computed, inject, signal } from '@angular/core';
import { argon2id } from 'hash-wasm';

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
  removeItem(key: string): void;
}

export const SECRET_HISTORY_STORAGE = new InjectionToken<SecretHistoryStorage>('SECRET_HISTORY_STORAGE', {
  providedIn: 'root',
  factory: () => ({
    getItem: key => globalThis.localStorage.getItem(key),
    setItem: (key, value) => globalThis.localStorage.setItem(key, value),
    removeItem: key => globalThis.localStorage.removeItem(key)
  })
});

export type HistoryVaultError = 'tooShort' | 'failed' | 'incorrect' | 'storage';

const CIPHERTEXT_KEY = 'privacylink.secret-history.v3';
const VAULT_LOCK_NAME = 'privacylink:sender-history:v3';
const LEGACY_KEYS = [
  'privacylink.secret-history.v1',
  'privacylink.secret-history.v2',
  'privacylink.secret-history.credential.v2'
] as const;
const VAULT_AAD_ENTRY_PREFIX = 'privacylink:sender-history:entry:v3:';
// OWASP's minimum Argon2id profile; persisted parameters must match these values before any derivation runs.
const ARGON2_VERSION = 19;
const ARGON2_MEMORY_KIB = 19_456;
const ARGON2_ITERATIONS = 2;
const ARGON2_PARALLELISM = 1;
const SALT_BYTES = 16;

type KdfParameters = {
  algorithm: 'argon2id';
  version: 19;
  memoryKiB: 19456;
  iterations: 2;
  parallelism: 1;
  salt: string;
};
type EncryptedEntry = { expiresAt: string; iv: string; ciphertext: string };
type VaultCheck = { iv: string; ciphertext: string };
type CiphertextEnvelope = { version: 3; kdf: KdfParameters; check: VaultCheck; entries: EncryptedEntry[] };
const VAULT_CHECK_TEXT = 'PrivacyLink sender history vault check v3';

/** Owns the complete local history boundary: plaintext only lives in this process while unlocked. */
@Injectable({ providedIn: 'root' })
export class SecretHistoryStore {
  private readonly storage = inject(SECRET_HISTORY_STORAGE);
  private readonly destroyRef = inject(DestroyRef);
  private readonly mutableEntries = signal<SecretHistoryEntry[]>([]);
  private readonly vaultPresent = signal(this.readVaultPresence());
  private vaultIdentity = this.readVaultIdentity();
  private key: CryptoKey | undefined;
  private kdf: KdfParameters | undefined;
  private expiryCleanupTimeout: ReturnType<typeof setTimeout> | undefined;
  private vaultGeneration = 0;
  private mutationQueue: Promise<void> = Promise.resolve();
  private readonly onStorageChange = (event: StorageEvent): void => {
    if (event.key !== CIPHERTEXT_KEY && event.key !== null) return;
    const raw = this.readVaultValue();
    const nextIdentity = raw === null ? undefined : this.parseVaultIdentity(raw);
    const present = raw !== null;
    if (nextIdentity === this.vaultIdentity && present === this.vaultPresent()) return;
    this.invalidateForExternalVaultChange(raw);
    this.scheduleExpiryCleanup();
  };

  readonly entries = this.mutableEntries.asReadonly();
  readonly enabled = computed(() => this.vaultPresent());
  readonly unlocked = signal(false);
  readonly locked = computed(() => this.enabled() && !this.unlocked());
  readonly legacyCleanupFailed = signal(false);
  readonly saveFailed = signal(false);
  readonly error = signal<HistoryVaultError | null>(null);

  constructor() {
    if (typeof window !== 'undefined') {
      window.addEventListener('storage', this.onStorageChange);
      this.destroyRef.onDestroy(() => window.removeEventListener('storage', this.onStorageChange));
    }
    this.retryLegacyCleanup();
    void this.pruneExpiredCiphertextWhileLocked();
    this.scheduleExpiryCleanup();
  }

  async enable(passphrase: string): Promise<boolean> {
    this.error.set(null);
    if (this.enabled()) return this.unlocked() || this.unlock(passphrase);
    if (!isValidPassphrase(passphrase)) {
      this.error.set('tooShort');
      return false;
    }
    const generation = ++this.vaultGeneration;

    try {
      const kdf = createKdfParameters();
      const key = await deriveVaultKey(passphrase, kdf);
      const envelope = await encryptEntries([], key, kdf);
      return await this.withVaultLock(() => {
        if (this.vaultGeneration !== generation) return false;
        const current = this.storage.getItem(CIPHERTEXT_KEY);
        if (current !== null) {
          this.invalidateForExternalVaultChange(current);
          throw new HistoryVaultFailure('storage');
        }
        this.writeVaultEnvelope(envelope);
        this.setUnlockedVault(envelope, key, []);
        this.saveFailed.set(!this.retryLegacyCleanup());
        this.scheduleExpiryCleanup();
        return true;
      });
    } catch (error) {
      this.setFailure(error);
      return false;
    }
  }

  async unlock(passphrase: string): Promise<boolean> {
    this.error.set(null);
    if (!this.enabled()) return false;
    const generation = this.vaultGeneration;
    try {
      const rawEnvelope = this.storage.getItem(CIPHERTEXT_KEY);
      if (!rawEnvelope) throw new HistoryVaultFailure('incorrect');
      const envelope = parseEnvelope(rawEnvelope);
      const identity = getVaultIdentity(envelope);
      const key = await deriveVaultKey(passphrase, envelope.kdf);
      const entries = await decryptEntries(envelope, key);
      const active = entries.filter(entry => isUnexpired(entry));
      const cleanedEnvelope = active.length === entries.length ? undefined : await encryptEntries(active, key, envelope.kdf);
      if (!cleanedEnvelope) {
        const current = this.storage.getItem(CIPHERTEXT_KEY);
        const currentIdentity = current === null ? undefined : this.parseVaultIdentity(current);
        if (generation !== this.vaultGeneration) return false;
        if (currentIdentity !== identity) {
          this.invalidateForExternalVaultChange(current);
          return false;
        }
        this.finishUnlock(envelope, key, active, true);
        return true;
      }

      try {
        const saved = await this.withVaultLock(() => {
          if (generation !== this.vaultGeneration) return false;
          const current = this.storage.getItem(CIPHERTEXT_KEY);
          const currentIdentity = current === null ? undefined : this.parseVaultIdentity(current);
          if (currentIdentity !== identity) {
            this.invalidateForExternalVaultChange(current);
            return false;
          }
          try { this.writeVaultEnvelope(cleanedEnvelope); }
          catch { return null; }
          this.finishUnlock(cleanedEnvelope, key, active, true);
          return true;
        });
        if (saved !== null) return saved;
      } catch {
        // A lock failure must not block reading the vault; skip the optional expiry write.
      }

      const current = this.storage.getItem(CIPHERTEXT_KEY);
      const currentIdentity = current === null ? undefined : this.parseVaultIdentity(current);
      if (generation !== this.vaultGeneration) return false;
      if (currentIdentity !== identity) {
        this.invalidateForExternalVaultChange(current);
        return false;
      }
      this.finishUnlock(envelope, key, active, false);
      return true;
    } catch (error) {
      this.setFailure(error instanceof HistoryVaultFailure ? error : new HistoryVaultFailure('incorrect'));
      return false;
    }
  }

  async add(entry: SecretHistoryEntry): Promise<boolean> {
    const generation = this.vaultGeneration;
    return this.serializeMutation(async () => {
      if (!this.isCurrentUnlockedVault(generation)) return false;
      const key = this.key!;
      const kdf = this.kdf!;
      const updated = [entry, ...this.activeEntries()];
      if (!await this.persist(updated, key, kdf, generation) || !this.isCurrentUnlockedVault(generation)) return false;
      this.mutableEntries.set(updated);
      this.scheduleExpiryCleanup();
      return true;
    });
  }

  async remove(id: string): Promise<boolean> {
    const generation = this.vaultGeneration;
    return this.serializeMutation(async () => {
      if (!this.isCurrentUnlockedVault(generation)) return false;
      const key = this.key!;
      const kdf = this.kdf!;
      const updated = this.activeEntries().filter(entry => entry.id !== id);
      if (!await this.persist(updated, key, kdf, generation) || !this.isCurrentUnlockedVault(generation)) return false;
      this.mutableEntries.set(updated);
      this.scheduleExpiryCleanup();
      return true;
    });
  }

  async clear(): Promise<boolean> {
    const generation = this.vaultGeneration;
    return this.serializeMutation(async () => {
      if (!this.isCurrentUnlockedVault(generation)) return false;
      const key = this.key!;
      const kdf = this.kdf!;
      if (!await this.persist([], key, kdf, generation) || !this.isCurrentUnlockedVault(generation)) return false;
      this.mutableEntries.set([]);
      if (this.expiryCleanupTimeout) clearTimeout(this.expiryCleanupTimeout);
      this.expiryCleanupTimeout = undefined;
      return true;
    });
  }

  async pruneExpired(): Promise<boolean> {
    const generation = this.vaultGeneration;
    return this.serializeMutation(async () => {
      if (!this.isCurrentUnlockedVault(generation)) return false;
      const active = this.activeEntries();
      if (active.length === this.mutableEntries().length) return false;
      const key = this.key!;
      const kdf = this.kdf!;
      if (!await this.persist(active, key, kdf, generation) || !this.isCurrentUnlockedVault(generation)) return false;
      this.mutableEntries.set(active);
      return true;
    });
  }

  retryLegacyCleanup(): boolean {
    try {
      for (const key of LEGACY_KEYS) this.storage.removeItem(key);
      this.legacyCleanupFailed.set(false);
      this.saveFailed.set(false);
      return true;
    } catch {
      this.legacyCleanupFailed.set(true);
      this.saveFailed.set(true);
      return false;
    }
  }

  /** Caller must obtain explicit confirmation: this permanently erases the old vault and starts empty. */
  async reset(passphrase: string): Promise<boolean> {
    this.error.set(null);
    if (!isValidPassphrase(passphrase)) {
      this.error.set('tooShort');
      return false;
    }
    const generation = ++this.vaultGeneration;
    try {
      const kdf = createKdfParameters();
      const key = await deriveVaultKey(passphrase, kdf);
      const envelope = await encryptEntries([], key, kdf);
      return await this.withVaultLock(() => {
        if (generation !== this.vaultGeneration) return false;
        // Invalidate mutations that began while the replacement vault was being prepared.
        this.vaultGeneration++;
        this.writeVaultEnvelope(envelope);
        this.setUnlockedVault(envelope, key, []);
        const cleanupSaved = this.retryLegacyCleanup();
        this.saveFailed.set(!cleanupSaved);
        this.scheduleExpiryCleanup();
        return true;
      });
    } catch (error) {
      this.setFailure(error);
      return false;
    }
  }

  async disable(): Promise<boolean> {
    const generation = ++this.vaultGeneration;
    try {
      return await this.withVaultLock(() => {
        if (generation !== this.vaultGeneration) return false;
        this.storage.removeItem(CIPHERTEXT_KEY);
        for (const key of LEGACY_KEYS) this.storage.removeItem(key);
        this.clearUnlockedVault(false);
        this.legacyCleanupFailed.set(false);
        this.saveFailed.set(false);
        return true;
      });
    } catch {
      this.saveFailed.set(true);
      this.error.set('storage');
      return false;
    }
  }

  private readVaultPresence(): boolean {
    try { return this.storage.getItem(CIPHERTEXT_KEY) !== null; }
    catch { return false; }
  }

  private readVaultValue(): string | null {
    try { return this.storage.getItem(CIPHERTEXT_KEY); }
    catch { return null; }
  }

  private readVaultIdentity(): string | undefined {
    const raw = this.readVaultValue();
    return raw === null ? undefined : this.parseVaultIdentity(raw);
  }

  private parseVaultIdentity(raw: string): string | undefined {
    try { return getVaultIdentity(parseEnvelope(raw)); }
    catch { return undefined; }
  }

  private invalidateForExternalVaultChange(raw: string | null): void {
    this.vaultGeneration++;
    this.vaultIdentity = raw === null ? undefined : this.parseVaultIdentity(raw);
    this.vaultPresent.set(raw !== null);
    this.key = undefined;
    this.kdf = undefined;
    this.unlocked.set(false);
    this.mutableEntries.set([]);
    this.error.set(null);
    if (this.expiryCleanupTimeout) clearTimeout(this.expiryCleanupTimeout);
    this.expiryCleanupTimeout = undefined;
  }

  private setUnlockedVault(envelope: CiphertextEnvelope, key: CryptoKey, entries: SecretHistoryEntry[]): void {
    this.vaultIdentity = getVaultIdentity(envelope);
    this.vaultPresent.set(true);
    this.kdf = envelope.kdf;
    this.key = key;
    this.mutableEntries.set(entries);
    this.unlocked.set(true);
  }

  private finishUnlock(envelope: CiphertextEnvelope, key: CryptoKey, entries: SecretHistoryEntry[], cleanupSaved: boolean): void {
    this.setUnlockedVault(envelope, key, entries);
    this.saveFailed.set(!cleanupSaved || this.legacyCleanupFailed());
    this.scheduleExpiryCleanup();
  }

  private clearUnlockedVault(present: boolean): void {
    this.vaultIdentity = present ? this.readVaultIdentity() : undefined;
    this.vaultPresent.set(present);
    this.kdf = undefined;
    this.key = undefined;
    this.unlocked.set(false);
    this.mutableEntries.set([]);
    if (this.expiryCleanupTimeout) clearTimeout(this.expiryCleanupTimeout);
    this.expiryCleanupTimeout = undefined;
  }

  private activeEntries(): SecretHistoryEntry[] {
    return this.mutableEntries().filter(isUnexpired);
  }

  private scheduleExpiryCleanup(retryDelayMs = 0): void {
    if (this.expiryCleanupTimeout) clearTimeout(this.expiryCleanupTimeout);
    const expiryTimes = this.unlocked()
      ? this.mutableEntries().map(entry => Date.parse(entry.expiresAt))
      : this.readPersistedExpiryMetadata();
    const nearestExpiry = Math.min(...expiryTimes);
    if (!Number.isFinite(nearestExpiry) && retryDelayMs === 0) return;
    const delay = retryDelayMs > 0 ? retryDelayMs : Math.min(Math.max(0, nearestExpiry - Date.now()), 2_147_000_000);
    this.expiryCleanupTimeout = setTimeout(() => {
      this.expiryCleanupTimeout = undefined;
      if (!this.unlocked()) {
        void this.pruneExpiredCiphertextWhileLocked().then(pruned => this.scheduleExpiryCleanup(pruned ? 0 : 60_000));
        return;
      }
      const hadExpiredEntries = this.mutableEntries().some(entry => !isUnexpired(entry));
      void this.pruneExpired().then(pruned => this.scheduleExpiryCleanup(hadExpiredEntries && !pruned ? 60_000 : 0));
    }, delay);
  }

  private readPersistedExpiryMetadata(): number[] {
    try {
      const raw = this.storage.getItem(CIPHERTEXT_KEY);
      if (!raw) return [];
      const envelope = parseEnvelope(raw);
      return envelope.entries.map(entry => Date.parse(entry.expiresAt));
    } catch {
      return [];
    }
  }

  private async pruneExpiredCiphertextWhileLocked(): Promise<boolean> {
    try {
      const raw = this.storage.getItem(CIPHERTEXT_KEY);
      if (!raw) return true;
      const envelope = parseEnvelope(raw);
      if (envelope.entries.every(entry => Date.parse(entry.expiresAt) > Date.now())) return true;
      return await this.withVaultLock(() => {
        const current = this.storage.getItem(CIPHERTEXT_KEY);
        if (!current) return true;
        const latestEnvelope = parseEnvelope(current);
        const active = latestEnvelope.entries.filter(entry => Date.parse(entry.expiresAt) > Date.now());
        if (active.length === latestEnvelope.entries.length) return true;
        this.writeVaultEnvelope({ ...latestEnvelope, entries: active } satisfies CiphertextEnvelope);
        return true;
      });
    } catch {
      this.saveFailed.set(true);
      return false;
    }
  }

  private serializeMutation<T>(mutation: () => Promise<T>): Promise<T> {
    const result = this.mutationQueue.then(mutation, mutation);
    this.mutationQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  private isCurrentUnlockedVault(generation: number): boolean {
    return generation === this.vaultGeneration && this.unlocked() && !!this.key && !!this.kdf && !!this.vaultIdentity;
  }

  private async persist(entries: SecretHistoryEntry[], key: CryptoKey, kdf: KdfParameters, generation: number): Promise<boolean> {
    const expectedIdentity = this.vaultIdentity;
    if (!expectedIdentity) return false;
    try {
      const envelope = await encryptEntries(entries, key, kdf);
      return await this.withVaultLock(() => {
        if (generation !== this.vaultGeneration || expectedIdentity !== this.vaultIdentity) return false;
        const raw = this.storage.getItem(CIPHERTEXT_KEY);
        const currentIdentity = raw === null ? undefined : this.parseVaultIdentity(raw);
        if (currentIdentity !== expectedIdentity) {
          this.invalidateForExternalVaultChange(raw);
          return false;
        }
        this.writeVaultEnvelope(envelope);
        this.vaultIdentity = getVaultIdentity(envelope);
        this.saveFailed.set(this.legacyCleanupFailed());
        return true;
      });
    } catch {
      this.saveFailed.set(true);
      return false;
    }
  }

  private withVaultLock<T>(operation: () => T | Promise<T>): Promise<T> {
    if (typeof navigator === 'undefined' || !navigator.locks) {
      return Promise.reject(new HistoryVaultFailure('storage'));
    }
    return navigator.locks.request(VAULT_LOCK_NAME, { mode: 'exclusive' }, () => operation());
  }

  private writeVaultEnvelope(envelope: CiphertextEnvelope): void {
    try { this.storage.setItem(CIPHERTEXT_KEY, JSON.stringify(envelope)); }
    catch { throw new HistoryVaultFailure('storage'); }
  }

  private setFailure(error: unknown): void {
    this.error.set(error instanceof HistoryVaultFailure ? error.reason : 'failed');
    if (error instanceof HistoryVaultFailure && error.reason === 'storage') this.saveFailed.set(true);
  }
}

class HistoryVaultFailure extends Error {
  constructor(readonly reason: HistoryVaultError) { super(reason); }
}

function createKdfParameters(): KdfParameters {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  return {
    algorithm: 'argon2id',
    version: ARGON2_VERSION,
    memoryKiB: ARGON2_MEMORY_KIB,
    iterations: ARGON2_ITERATIONS,
    parallelism: ARGON2_PARALLELISM,
    salt: encodeBase64Url(salt)
  };
}

function isValidPassphrase(passphrase: string): boolean {
  return Array.from(passphrase).length >= 12;
}

async function deriveVaultKey(passphrase: string, kdf: KdfParameters): Promise<CryptoKey> {
  const passwordBytes = new TextEncoder().encode(passphrase);
  const salt = decodeBase64Url(kdf.salt);
  let derivedBytes: Uint8Array | undefined;
  try {
    if (salt.byteLength !== SALT_BYTES) throw new HistoryVaultFailure('incorrect');
    derivedBytes = await argon2id({
      password: passwordBytes,
      salt,
      parallelism: kdf.parallelism,
      iterations: kdf.iterations,
      memorySize: kdf.memoryKiB,
      hashLength: 32,
      outputType: 'binary'
    });
    return await crypto.subtle.importKey('raw', arrayBuffer(derivedBytes), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  } finally {
    passwordBytes.fill(0);
    salt.fill(0);
    derivedBytes?.fill(0);
  }
}

async function encryptEntries(entries: SecretHistoryEntry[], key: CryptoKey, kdf: KdfParameters): Promise<CiphertextEnvelope> {
  return {
    version: 3,
    kdf,
    check: await encryptVaultCheck(key, kdf),
    entries: await Promise.all(entries.map(entry => encryptEntry(entry, key, kdf)))
  };
}

async function encryptVaultCheck(key: CryptoKey, kdf: KdfParameters): Promise<VaultCheck> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: arrayBuffer(iv), additionalData: arrayBuffer(vaultCheckAdditionalData(kdf)) }, key, arrayBuffer(new TextEncoder().encode(VAULT_CHECK_TEXT)));
  return { iv: encodeBase64Url(iv), ciphertext: encodeBase64Url(new Uint8Array(ciphertext)) };
}

async function verifyVaultCheck(envelope: CiphertextEnvelope, key: CryptoKey): Promise<void> {
  try {
    const plaintext = await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv: arrayBuffer(decodeBase64Url(envelope.check.iv)),
      additionalData: arrayBuffer(vaultCheckAdditionalData(envelope.kdf))
    }, key, arrayBuffer(decodeBase64Url(envelope.check.ciphertext)));
    if (new TextDecoder().decode(plaintext) !== VAULT_CHECK_TEXT) throw new HistoryVaultFailure('incorrect');
  } catch {
    throw new HistoryVaultFailure('incorrect');
  }
}

async function encryptEntry(entry: SecretHistoryEntry, key: CryptoKey, kdf: KdfParameters): Promise<EncryptedEntry> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = entryAdditionalData(entry.expiresAt, kdf);
  const plaintext = new TextEncoder().encode(JSON.stringify(entry));
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: arrayBuffer(iv), additionalData: arrayBuffer(aad) }, key, arrayBuffer(plaintext));
    return { expiresAt: entry.expiresAt, iv: encodeBase64Url(iv), ciphertext: encodeBase64Url(new Uint8Array(ciphertext)) };
  } finally { plaintext.fill(0); }
}

async function decryptEntries(envelope: CiphertextEnvelope, key: CryptoKey): Promise<SecretHistoryEntry[]> {
  await verifyVaultCheck(envelope, key);
  return Promise.all(envelope.entries.map(async record => {
    let plaintext: ArrayBuffer | undefined;
    try {
      plaintext = await crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv: arrayBuffer(decodeBase64Url(record.iv)),
        additionalData: arrayBuffer(entryAdditionalData(record.expiresAt, envelope.kdf))
      }, key, arrayBuffer(decodeBase64Url(record.ciphertext)));
      const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
      if (!isHistoryEntry(parsed) || parsed.expiresAt !== record.expiresAt) throw new HistoryVaultFailure('incorrect');
      return parsed;
    } catch {
      throw new HistoryVaultFailure('incorrect');
    } finally { if (plaintext) new Uint8Array(plaintext).fill(0); }
  }));
}

function parseEnvelope(raw: string): CiphertextEnvelope {
  const value: unknown = JSON.parse(raw);
  if (!value || typeof value !== 'object') throw new HistoryVaultFailure('incorrect');
  const envelope = value as Partial<CiphertextEnvelope>;
  if (envelope.version !== 3 || !isKdfParameters(envelope.kdf) || !isVaultCheck(envelope.check)
    || !Array.isArray(envelope.entries) || !envelope.entries.every(isEncryptedEntry)) {
    throw new HistoryVaultFailure('incorrect');
  }
  return envelope as CiphertextEnvelope;
}

function entryAdditionalData(expiresAt: string, kdf: KdfParameters): Uint8Array {
  return new TextEncoder().encode(VAULT_AAD_ENTRY_PREFIX + JSON.stringify(kdf) + ':' + expiresAt);
}

function vaultCheckAdditionalData(kdf: KdfParameters): Uint8Array {
  return new TextEncoder().encode('privacylink:sender-history:vault-check:v3:' + JSON.stringify(kdf));
}

function isKdfParameters(value: unknown): value is KdfParameters {
  if (!value || typeof value !== 'object') return false;
  const kdf = value as Partial<KdfParameters>;
  if (kdf.algorithm !== 'argon2id' || kdf.version !== ARGON2_VERSION || kdf.memoryKiB !== ARGON2_MEMORY_KIB
    || kdf.iterations !== ARGON2_ITERATIONS || kdf.parallelism !== ARGON2_PARALLELISM || typeof kdf.salt !== 'string') return false;
  try { return decodeBase64Url(kdf.salt).byteLength === SALT_BYTES; }
  catch { return false; }
}

function isEncryptedEntry(value: unknown): value is EncryptedEntry {
  if (!value || typeof value !== 'object') return false;
  const record = value as Partial<EncryptedEntry>;
  return typeof record.expiresAt === 'string' && Number.isFinite(Date.parse(record.expiresAt))
    && typeof record.iv === 'string' && typeof record.ciphertext === 'string';
}

function isVaultCheck(value: unknown): value is VaultCheck {
  if (!value || typeof value !== 'object') return false;
  const check = value as Partial<VaultCheck>;
  return typeof check.iv === 'string' && typeof check.ciphertext === 'string';
}

function isHistoryEntry(item: unknown): item is SecretHistoryEntry {
  if (!item || typeof item !== 'object') return false;
  const entry = item as Partial<SecretHistoryEntry>;
  return typeof entry.id === 'string' && typeof entry.createdAt === 'string' && typeof entry.link === 'string'
    && typeof entry.expiresAt === 'string' && Number.isFinite(Date.parse(entry.expiresAt)) && typeof entry.password === 'string'
    && (entry.revokeToken === undefined || typeof entry.revokeToken === 'string');
}

function isUnexpired(entry: SecretHistoryEntry): boolean { return Date.parse(entry.expiresAt) > Date.now(); }

function getVaultIdentity(envelope: CiphertextEnvelope): string {
  const { algorithm, version, memoryKiB, iterations, parallelism, salt } = envelope.kdf;
  return JSON.stringify([algorithm, version, memoryKiB, iterations, parallelism, salt]);
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(normalized);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
