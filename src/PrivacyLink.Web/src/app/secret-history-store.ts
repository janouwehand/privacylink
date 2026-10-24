import { InjectionToken, Injectable, computed, inject, signal } from '@angular/core';
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
  private readonly mutableEntries = signal<SecretHistoryEntry[]>([]);
  private readonly vaultPresent = signal(this.readVaultPresence());
  private key: CryptoKey | undefined;
  private kdf: KdfParameters | undefined;
  private expiryCleanupTimeout: ReturnType<typeof setTimeout> | undefined;

  readonly entries = this.mutableEntries.asReadonly();
  readonly enabled = computed(() => this.vaultPresent());
  readonly unlocked = signal(false);
  readonly locked = computed(() => this.enabled() && !this.unlocked());
  readonly legacyCleanupFailed = signal(false);
  readonly saveFailed = signal(false);
  readonly error = signal<HistoryVaultError | null>(null);

  constructor() {
    this.retryLegacyCleanup();
    this.pruneExpiredCiphertextWhileLocked();
    this.scheduleExpiryCleanup();
  }

  async enable(passphrase: string): Promise<boolean> {
    this.error.set(null);
    if (this.enabled()) return this.unlocked() || this.unlock(passphrase);
    if (!isValidPassphrase(passphrase)) {
      this.error.set('tooShort');
      return false;
    }

    try {
      const kdf = createKdfParameters();
      const key = await deriveVaultKey(passphrase, kdf);
      const envelope = await encryptEntries([], key, kdf);
      try {
        this.storage.setItem(CIPHERTEXT_KEY, JSON.stringify(envelope));
      } catch {
        throw new HistoryVaultFailure('storage');
      }
      this.vaultPresent.set(true);
      this.kdf = kdf;
      this.key = key;
      this.mutableEntries.set([]);
      this.unlocked.set(true);
      this.saveFailed.set(!this.retryLegacyCleanup());
      this.scheduleExpiryCleanup();
      return true;
    } catch (error) {
      this.setFailure(error);
      return false;
    }
  }

  async unlock(passphrase: string): Promise<boolean> {
    this.error.set(null);
    if (!this.enabled()) return false;
    try {
      const rawEnvelope = this.storage.getItem(CIPHERTEXT_KEY);
      if (!rawEnvelope) throw new HistoryVaultFailure('incorrect');
      const envelope = parseEnvelope(rawEnvelope);
      const key = await deriveVaultKey(passphrase, envelope.kdf);
      const entries = await decryptEntries(envelope, key);
      const active = entries.filter(entry => isUnexpired(entry));
      const cleanupSaved = active.length === entries.length || await this.persist(active, key, envelope.kdf);
      this.kdf = envelope.kdf;
      this.key = key;
      this.mutableEntries.set(active);
      this.unlocked.set(true);
      this.saveFailed.set(!cleanupSaved || this.legacyCleanupFailed());
      this.scheduleExpiryCleanup();
      return true;
    } catch (error) {
      this.setFailure(error instanceof HistoryVaultFailure ? error : new HistoryVaultFailure('incorrect'));
      return false;
    }
  }

  async add(entry: SecretHistoryEntry): Promise<boolean> {
    if (!this.unlocked() || !this.key || !this.kdf) return false;
    const updated = [entry, ...this.activeEntries()];
    if (!await this.persist(updated, this.key, this.kdf)) return false;
    this.mutableEntries.set(updated);
    this.scheduleExpiryCleanup();
    return true;
  }

  async remove(id: string): Promise<boolean> {
    if (!this.unlocked() || !this.key || !this.kdf) return false;
    const updated = this.activeEntries().filter(entry => entry.id !== id);
    if (!await this.persist(updated, this.key, this.kdf)) return false;
    this.mutableEntries.set(updated);
    this.scheduleExpiryCleanup();
    return true;
  }

  async clear(): Promise<boolean> {
    if (!this.unlocked() || !this.key || !this.kdf) return false;
    if (!await this.persist([], this.key, this.kdf)) return false;
    this.mutableEntries.set([]);
    if (this.expiryCleanupTimeout) clearTimeout(this.expiryCleanupTimeout);
    this.expiryCleanupTimeout = undefined;
    return true;
  }

  async pruneExpired(): Promise<boolean> {
    const active = this.activeEntries();
    if (active.length === this.mutableEntries().length) return false;
    if (!this.key || !this.kdf || !await this.persist(active, this.key, this.kdf)) return false;
    this.mutableEntries.set(active);
    return true;
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
    try {
      const kdf = createKdfParameters();
      const key = await deriveVaultKey(passphrase, kdf);
      const envelope = await encryptEntries([], key, kdf);
      this.storage.setItem(CIPHERTEXT_KEY, JSON.stringify(envelope));
      this.vaultPresent.set(true);
      this.kdf = kdf;
      this.key = key;
      this.mutableEntries.set([]);
      this.unlocked.set(true);
      const cleanupSaved = this.retryLegacyCleanup();
      this.saveFailed.set(!cleanupSaved);
      this.scheduleExpiryCleanup();
      return true;
    } catch (error) {
      this.setFailure(error);
      return false;
    }
  }

  async disable(): Promise<boolean> {
    try {
      this.storage.removeItem(CIPHERTEXT_KEY);
      for (const key of LEGACY_KEYS) this.storage.removeItem(key);
      this.vaultPresent.set(false);
      this.kdf = undefined;
      this.key = undefined;
      this.unlocked.set(false);
      this.mutableEntries.set([]);
      this.legacyCleanupFailed.set(false);
      this.saveFailed.set(false);
      if (this.expiryCleanupTimeout) clearTimeout(this.expiryCleanupTimeout);
      this.expiryCleanupTimeout = undefined;
      return true;
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
        const pruned = this.pruneExpiredCiphertextWhileLocked();
        this.scheduleExpiryCleanup(pruned ? 0 : 60_000);
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

  private pruneExpiredCiphertextWhileLocked(): boolean {
    try {
      const raw = this.storage.getItem(CIPHERTEXT_KEY);
      if (!raw) return true;
      const envelope = parseEnvelope(raw);
      const active = envelope.entries.filter(entry => Date.parse(entry.expiresAt) > Date.now());
      if (active.length === envelope.entries.length) return true;
      this.storage.setItem(CIPHERTEXT_KEY, JSON.stringify({ ...envelope, entries: active } satisfies CiphertextEnvelope));
      return true;
    } catch {
      this.saveFailed.set(true);
      return false;
    }
  }

  private async persist(entries: SecretHistoryEntry[], key: CryptoKey, kdf: KdfParameters): Promise<boolean> {
    try {
      this.storage.setItem(CIPHERTEXT_KEY, JSON.stringify(await encryptEntries(entries, key, kdf)));
      this.saveFailed.set(this.legacyCleanupFailed());
      return true;
    } catch {
      this.saveFailed.set(true);
      return false;
    }
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
