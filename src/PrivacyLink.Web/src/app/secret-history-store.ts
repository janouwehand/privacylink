import { DestroyRef, InjectionToken, Injectable, inject, signal } from '@angular/core';

export type SecretHistoryEntry = {
  id: string;
  createdAt: string;
  link: string;
  expiresAt: string;
  password: string;
  revokeToken?: string;
  givenLabel?: string;
};

export type EncryptedHistoryRecord = {
  id: string;
  version: 1;
  createdAt: string;
  expiresAt: string;
  iv: ArrayBuffer;
  ciphertext: ArrayBuffer;
};

export interface SecretHistoryStorage {
  getKey(): Promise<CryptoKey | undefined>;
  getKeyId(): Promise<string | undefined>;
  getEpoch(): Promise<number>;
  putKeyIfAbsent(candidate: CryptoKey, candidateId: string): Promise<boolean>;
  getEntries(): Promise<EncryptedHistoryRecord[]>;
  addEntryIfCurrent(entry: EncryptedHistoryRecord, keyId: string, epoch: number): Promise<boolean>;
  replaceEntryIfCurrent(entry: EncryptedHistoryRecord, expectedCiphertext: ArrayBuffer, keyId: string, epoch: number): Promise<boolean>;
  deleteEntryIfCurrent(id: string, expectedCiphertext: ArrayBuffer): Promise<boolean>;
  clearEntries(): Promise<number>;
}

export const SECRET_HISTORY_STORAGE = new InjectionToken<SecretHistoryStorage>('SECRET_HISTORY_STORAGE', {
  providedIn: 'root',
  factory: () => new IndexedDbSecretHistoryStorage()
});

const DATABASE_NAME = 'privacylink.sender-history.v1';
const DATABASE_VERSION = 1;
const ENTRIES_STORE = 'entries';
const METADATA_STORE = 'metadata';
const ENCRYPTION_KEY = 'encryptionKey';
const ENCRYPTION_KEY_ID = 'encryptionKeyId';
const HISTORY_EPOCH = 'historyEpoch';
const MUTATION_LOCK_NAME = 'privacylink:sender-history:v1';

export type HistoryVaultError = 'storage' | 'unavailable';

class IndexedDbSecretHistoryStorage implements SecretHistoryStorage {
  private database?: Promise<IDBDatabase>;

  async getKey(): Promise<CryptoKey | undefined> {
    const value = await this.getMetadata(ENCRYPTION_KEY);
    return isUsableKey(value) ? value : undefined;
  }

  async getKeyId(): Promise<string | undefined> {
    const value = await this.getMetadata(ENCRYPTION_KEY_ID);
    return typeof value === 'string' ? value : undefined;
  }

  async getEpoch(): Promise<number> {
    const value = await this.getMetadata(HISTORY_EPOCH);
    return typeof value === 'number' && Number.isSafeInteger(value) ? value : 0;
  }

  async putKeyIfAbsent(candidate: CryptoKey, candidateId: string): Promise<boolean> {
    const database = await this.openDatabase();
    return new Promise((resolve, reject) => {
      const transaction = database.transaction([ENTRIES_STORE, METADATA_STORE], 'readwrite');
      const metadata = transaction.objectStore(METADATA_STORE);
      const entries = transaction.objectStore(ENTRIES_STORE);
      let key: unknown;
      let keyId: unknown;
      let recordCount: number | undefined;
      let result = false;
      let failed = false;
      const finish = () => {
        if (isUsableKey(key) && typeof keyId === 'string') { result = true; return; }
        if (recordCount !== 0) { failed = true; transaction.abort(); return; }
        metadata.put(candidate, ENCRYPTION_KEY);
        metadata.put(candidateId, ENCRYPTION_KEY_ID);
        result = true;
      };
      let remaining = 3;
      const done = () => { if (--remaining === 0) finish(); };
      metadata.get(ENCRYPTION_KEY).onsuccess = event => { key = (event.target as IDBRequest).result; done(); };
      metadata.get(ENCRYPTION_KEY_ID).onsuccess = event => { keyId = (event.target as IDBRequest).result; done(); };
      entries.count().onsuccess = event => { recordCount = (event.target as IDBRequest<number>).result; done(); };
      transaction.oncomplete = () => resolve(result);
      transaction.onerror = () => reject(transaction.error ?? new Error('History key transaction failed'));
      transaction.onabort = () => failed ? resolve(false) : reject(transaction.error ?? new Error('History key transaction aborted'));
    });
  }

  async getEntries(): Promise<EncryptedHistoryRecord[]> {
    const database = await this.openDatabase();
    return this.request<EncryptedHistoryRecord[]>(database.transaction(ENTRIES_STORE, 'readonly').objectStore(ENTRIES_STORE).getAll());
  }

  async addEntryIfCurrent(entry: EncryptedHistoryRecord, keyId: string, epoch: number): Promise<boolean> {
    const database = await this.openDatabase();
    return this.guardedEntryWrite(database, entry, keyId, epoch);
  }

  async replaceEntryIfCurrent(entry: EncryptedHistoryRecord, expectedCiphertext: ArrayBuffer, keyId: string, epoch: number): Promise<boolean> {
    const database = await this.openDatabase();
    return this.guardedEntryWrite(database, entry, keyId, epoch, expectedCiphertext);
  }

  async deleteEntryIfCurrent(id: string, expectedCiphertext: ArrayBuffer): Promise<boolean> {
    const database = await this.openDatabase();
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(ENTRIES_STORE, 'readwrite');
      const store = transaction.objectStore(ENTRIES_STORE);
      let result = false;
      store.get(id).onsuccess = event => {
        const record = (event.target as IDBRequest<EncryptedHistoryRecord | undefined>).result;
        if (record && equalBytes(record.ciphertext, expectedCiphertext)) {
          store.delete(id);
          result = true;
        }
      };
      transaction.oncomplete = () => resolve(result);
      transaction.onerror = () => reject(transaction.error ?? new Error('Could not remove sender history entry'));
      transaction.onabort = () => reject(transaction.error ?? new Error('Could not remove sender history entry'));
    });
  }

  async clearEntries(): Promise<number> {
    const database = await this.openDatabase();
    return new Promise((resolve, reject) => {
      const transaction = database.transaction([ENTRIES_STORE, METADATA_STORE], 'readwrite');
      const entries = transaction.objectStore(ENTRIES_STORE);
      const metadata = transaction.objectStore(METADATA_STORE);
      let nextEpoch = 1;
      entries.clear();
      metadata.get(HISTORY_EPOCH).onsuccess = event => {
        const previous = (event.target as IDBRequest).result;
        nextEpoch = (typeof previous === 'number' && Number.isSafeInteger(previous) ? previous : 0) + 1;
        metadata.put(nextEpoch, HISTORY_EPOCH);
      };
      transaction.oncomplete = () => resolve(nextEpoch);
      transaction.onerror = () => reject(transaction.error ?? new Error('Could not clear sender history'));
      transaction.onabort = () => reject(transaction.error ?? new Error('Could not clear sender history'));
    });
  }

  private async guardedEntryWrite(database: IDBDatabase, entry: EncryptedHistoryRecord, keyId: string, epoch: number, expectedCiphertext?: ArrayBuffer): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const transaction = database.transaction([ENTRIES_STORE, METADATA_STORE], 'readwrite');
      const metadata = transaction.objectStore(METADATA_STORE);
      const entries = transaction.objectStore(ENTRIES_STORE);
      let key: unknown;
      let storedKeyId: unknown;
      let storedEpoch: unknown;
      let accepted = false;
      let remaining = 3;
      const finish = () => {
        if (!isUsableKey(key) || storedKeyId !== keyId || (typeof storedEpoch === 'number' ? storedEpoch : 0) !== epoch) return;
        const save = () => {
          entries.put(entry);
          accepted = true;
        };
        if (expectedCiphertext === undefined) {
          entries.get(entry.id).onsuccess = event => {
            if ((event.target as IDBRequest).result === undefined) save();
          };
        } else {
          entries.get(entry.id).onsuccess = event => {
            const existing = (event.target as IDBRequest<EncryptedHistoryRecord | undefined>).result;
            if (existing && equalBytes(existing.ciphertext, expectedCiphertext)) save();
          };
        }
      };
      const done = () => { if (--remaining === 0) finish(); };
      metadata.get(ENCRYPTION_KEY).onsuccess = event => { key = (event.target as IDBRequest).result; done(); };
      metadata.get(ENCRYPTION_KEY_ID).onsuccess = event => { storedKeyId = (event.target as IDBRequest).result; done(); };
      metadata.get(HISTORY_EPOCH).onsuccess = event => { storedEpoch = (event.target as IDBRequest).result; done(); };
      transaction.oncomplete = () => resolve(accepted);
      transaction.onerror = () => reject(transaction.error ?? new Error('Could not save sender history entry'));
      transaction.onabort = () => reject(transaction.error ?? new Error('Could not save sender history entry'));
    });
  }

  private async getMetadata(key: string): Promise<unknown> {
    const database = await this.openDatabase();
    return this.request(database.transaction(METADATA_STORE, 'readonly').objectStore(METADATA_STORE).get(key));
  }

  private openDatabase(): Promise<IDBDatabase> {
    if (this.database) return this.database;
    if (typeof indexedDB === 'undefined') return Promise.reject(new Error('IndexedDB is unavailable'));
    this.database = new Promise((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(ENTRIES_STORE)) database.createObjectStore(ENTRIES_STORE, { keyPath: 'id' });
        if (!database.objectStoreNames.contains(METADATA_STORE)) database.createObjectStore(METADATA_STORE);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('Could not open sender history'));
      request.onblocked = () => reject(new Error('Sender history database is blocked'));
    });
    return this.database;
  }

  private request<T = void>(request: IDBRequest): Promise<T> {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result as T);
      request.onerror = () => reject(request.error ?? new Error('Sender history request failed'));
    });
  }

}

/** Owns encrypted, browser-local sender history and its asynchronous IndexedDB lifecycle. */
@Injectable({ providedIn: 'root' })
export class SecretHistoryStore {
  private readonly storage = inject(SECRET_HISTORY_STORAGE);
  private readonly destroyRef = inject(DestroyRef);
  private readonly mutableEntries = signal<SecretHistoryEntry[]>([]);
  private readonly unavailable = signal(0);
  private key?: CryptoKey;
  private keyId?: string;
  private epoch = 0;
  private generation = 0;
  private refreshVersion = 0;
  private expiryCleanupTimeout: ReturnType<typeof setTimeout> | undefined;
  private mutationQueue: Promise<void> = Promise.resolve();
  private channel?: BroadcastChannel;

  readonly entries = this.mutableEntries.asReadonly();
  readonly initialized = signal(false);
  readonly unavailableEntries = this.unavailable.asReadonly();
  readonly locked = signal(false);
  readonly unlocked = signal(true);
  readonly error = signal<HistoryVaultError | null>(null);
  readonly saveFailed = signal(false);

  private readonly ready = this.initialize();

  constructor() {
    if (typeof BroadcastChannel !== 'undefined') {
      this.channel = new BroadcastChannel('privacylink:sender-history:v1');
      this.channel.onmessage = () => { void this.refresh(); };
      this.destroyRef.onDestroy(() => this.channel?.close());
    }
  }

  async add(entry: SecretHistoryEntry): Promise<boolean> {
    return this.mutate(async (key, keyId, epoch) => {
      if (!isHistoryEntry(entry)) throw new Error('Invalid history entry');
      const encrypted = await encryptEntry(entry, key);
      return this.storage.addEntryIfCurrent(encrypted, keyId, epoch);
    });
  }

  async updateLabel(id: string, label: string | undefined): Promise<boolean> {
    return this.mutate(async (key, keyId, epoch) => {
      const records = await this.storage.getEntries();
      const record = records.find(item => item.id === id);
      if (!record) return false;
      const entry = await decryptEntry(record, key);
      const trimmedLabel = label?.trim();
      const updated = { ...entry };
      if (trimmedLabel) updated.givenLabel = trimmedLabel;
      else delete updated.givenLabel;
      const replacement = await encryptEntry(updated, key);
      return this.storage.replaceEntryIfCurrent(replacement, record.ciphertext, keyId, epoch);
    });
  }

  async remove(id: string): Promise<boolean> {
    return this.mutate(async (_key, _keyId, _epoch) => {
      const record = (await this.storage.getEntries()).find(item => item.id === id);
      return record ? this.storage.deleteEntryIfCurrent(id, record.ciphertext) : false;
    });
  }

  async clear(): Promise<boolean> {
    await this.ready;
    this.generation++;
    this.refreshVersion++;
    return this.withMutationLock(async () => {
      try {
        this.epoch = await this.storage.clearEntries();
        this.mutableEntries.set([]);
        this.unavailable.set(0);
        this.error.set(null);
        this.saveFailed.set(false);
        this.cancelExpiryCleanup();
        this.broadcast();
        return true;
      } catch {
        this.saveFailed.set(true);
        this.error.set('storage');
        return false;
      }
    });
  }

  async pruneExpired(): Promise<boolean> {
    await this.ready;
    return this.withMutationLock(async () => {
      try {
        const snapshotEpoch = await this.storage.getEpoch();
        const records = await this.storage.getEntries();
        const key = await this.storage.getKey();
        const keyId = await this.storage.getKeyId();
        if (key && keyId) {
          this.key = key;
          this.keyId = keyId;
          this.epoch = snapshotEpoch;
          await this.refreshEntries(key, records, ++this.refreshVersion, this.generation, snapshotEpoch, keyId);
        }
        return true;
      } catch {
        this.saveFailed.set(true);
        this.error.set('storage');
        return false;
      }
    });
  }

  whenReady(): Promise<void> { return this.ready; }

  private async initialize(): Promise<void> {
    await this.withMutationLock(async () => {
      try {
        const snapshotEpoch = await this.storage.getEpoch();
        const records = await this.storage.getEntries();
        let key = await this.storage.getKey();
        let keyId = await this.storage.getKeyId();
        if ((!key || !keyId) && records.length > 0) {
          this.unavailable.set(records.length);
          this.error.set('unavailable');
          this.saveFailed.set(true);
          this.scheduleExpiryCleanup(records);
          return;
        }
        if (!key || !keyId) {
          const material = await this.createKeyMaterial();
          if (!await this.storage.putKeyIfAbsent(material.key, material.id)) {
            this.unavailable.set(records.length);
            this.error.set('unavailable');
            this.saveFailed.set(true);
            return;
          }
          key = await this.storage.getKey();
          keyId = await this.storage.getKeyId();
        }
        if (!key || !keyId) throw new Error('History key is unavailable');
        this.keyId = keyId;
        this.epoch = snapshotEpoch;
        this.key = key;
        await this.refreshEntries(key, records, ++this.refreshVersion, this.generation, snapshotEpoch, keyId);
      } catch {
        this.saveFailed.set(true);
        this.error.set('storage');
      } finally {
        this.initialized.set(true);
      }
    });
  }

  private async refresh(): Promise<void> {
    await this.ready;
    const refreshVersion = ++this.refreshVersion;
    const currentGeneration = this.generation;
    try {
      const snapshotEpoch = await this.storage.getEpoch();
      const records = await this.storage.getEntries();
      let key = await this.storage.getKey();
      let keyId = await this.storage.getKeyId();
      if ((!key || !keyId) && records.length > 0) {
        if (refreshVersion !== this.refreshVersion || currentGeneration !== this.generation) return;
        this.generation++;
        this.key = undefined;
        this.keyId = undefined;
        this.unavailable.set(records.length);
        this.error.set('unavailable');
        this.saveFailed.set(true);
        return;
      }
      if (!key || !keyId) {
        const material = await this.createKeyMaterial();
        if (!await this.storage.putKeyIfAbsent(material.key, material.id)) return;
        key = await this.storage.getKey();
        keyId = await this.storage.getKeyId();
      }
      if (!key || !keyId || refreshVersion !== this.refreshVersion || currentGeneration !== this.generation) return;
      this.epoch = snapshotEpoch;
      this.key = key;
      this.keyId = keyId;
      await this.refreshEntries(key, records, refreshVersion, currentGeneration, snapshotEpoch, keyId);
    } catch {
      this.saveFailed.set(true);
      this.error.set('storage');
    }
  }

  private async refreshEntries(
    key: CryptoKey,
    records: EncryptedHistoryRecord[],
    refreshVersion: number,
    generation: number,
    snapshotEpoch: number,
    snapshotKeyId: string
  ): Promise<void> {
    const entries: SecretHistoryEntry[] = [];
    let unavailable = 0;
    await Promise.all(records.map(async record => {
      if (!isStoredEntry(record)) { unavailable++; return; }
      try {
        const entry = await decryptEntry(record, key);
        if (isUnexpired(entry.expiresAt)) entries.push(entry);
        else await this.storage.deleteEntryIfCurrent(record.id, record.ciphertext).catch(() => false);
      }
      catch { unavailable++; }
    }));
    entries.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    if (refreshVersion !== this.refreshVersion || generation !== this.generation) return;
    const [currentKeyId, currentEpoch] = await Promise.all([
      this.storage.getKeyId(), this.storage.getEpoch()
    ]);
    if (refreshVersion !== this.refreshVersion || generation !== this.generation) return;
    if (currentKeyId !== snapshotKeyId || currentEpoch !== snapshotEpoch) {
      void this.refresh();
      return;
    }
    this.mutableEntries.set(entries);
    this.unavailable.set(unavailable);
    if (unavailable) this.error.set('unavailable');
    else if (this.error() === 'unavailable') this.error.set(null);
    this.scheduleExpiryCleanup(records);
  }

  private async mutate<T>(operation: (key: CryptoKey, keyId: string, epoch: number) => Promise<T>): Promise<T | false> {
    await this.ready;
    const generation = this.generation;
    return this.withMutationLock(async () => {
      try {
        if (generation !== this.generation) return false;
        const snapshotEpoch = await this.storage.getEpoch();
        let key = await this.storage.getKey();
        let keyId = await this.storage.getKeyId();
        const records = await this.storage.getEntries();
        if ((!key || !keyId) && records.length > 0) {
          this.unavailable.set(records.length);
          this.error.set('unavailable');
          this.saveFailed.set(true);
          return false;
        }
        if (!key || !keyId) {
          const material = await this.createKeyMaterial();
          if (!await this.storage.putKeyIfAbsent(material.key, material.id)) return false;
          key = await this.storage.getKey();
          keyId = await this.storage.getKeyId();
        }
        if (!key || !keyId) return false;
        this.keyId = keyId;
        this.epoch = snapshotEpoch;
        const result = await operation(key, keyId, this.epoch);
        if (generation !== this.generation) return false;
        this.key = key;
        await this.refreshEntries(key, await this.storage.getEntries(), ++this.refreshVersion, generation, snapshotEpoch, keyId);
        this.saveFailed.set(false);
        this.error.set(this.unavailable() ? 'unavailable' : null);
        this.broadcast();
        return result;
      } catch {
        this.saveFailed.set(true);
        this.error.set('storage');
        return false;
      }
    });
  }

  private async createKeyMaterial(): Promise<{ key: CryptoKey; id: string }> {
    if (!globalThis.crypto?.subtle) throw new Error('Web Crypto is unavailable');
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    if (!isUsableKey(key)) throw new Error('Could not create a sender history key');
    const id = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
    return { key, id };
  }

  private withMutationLock<T>(operation: () => Promise<T>): Promise<T> {
    const run = (): Promise<T> => {
      if (typeof navigator !== 'undefined' && navigator.locks) {
        return navigator.locks.request(MUTATION_LOCK_NAME, { mode: 'exclusive' }, operation);
      }
      return operation();
    };
    const result = this.mutationQueue.then(run, run);
    this.mutationQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  private scheduleExpiryCleanup(records: EncryptedHistoryRecord[]): void {
    this.cancelExpiryCleanup();
    const nearestExpiry = Math.min(...records.filter(isStoredEntry)
      .map(record => Date.parse(record.expiresAt)).filter(value => Number.isFinite(value) && value > Date.now()));
    if (!Number.isFinite(nearestExpiry)) return;
    const delay = Math.min(Math.max(0, nearestExpiry - Date.now()), 2_147_000_000);
    this.expiryCleanupTimeout = setTimeout(() => {
      this.expiryCleanupTimeout = undefined;
      void this.pruneExpired().then(result => {
        if (!result) this.saveFailed.set(true);
        void this.refresh();
      });
    }, delay);
  }

  private cancelExpiryCleanup(): void {
    if (this.expiryCleanupTimeout) clearTimeout(this.expiryCleanupTimeout);
    this.expiryCleanupTimeout = undefined;
  }

  private broadcast(): void {
    this.channel?.postMessage('changed');
  }
}

async function encryptEntry(entry: SecretHistoryEntry, key: CryptoKey): Promise<EncryptedHistoryRecord> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = { ...entry };
  if (!payload.givenLabel?.trim()) delete payload.givenLabel;
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: additionalData({ ...entry, version: 1 }) },
      key,
      toArrayBuffer(plaintext)
    );
    return {
      id: entry.id,
      version: 1,
      createdAt: entry.createdAt,
      expiresAt: entry.expiresAt,
      iv: toArrayBuffer(iv),
      ciphertext: toArrayBuffer(new Uint8Array(ciphertext))
    };
  } finally {
    plaintext.fill(0);
  }
}

async function decryptEntry(record: EncryptedHistoryRecord, key: CryptoKey): Promise<SecretHistoryEntry> {
  if (!isStoredEntry(record)) throw new Error('Invalid stored history entry');
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: record.iv, additionalData: additionalData(record) },
    key,
    record.ciphertext
  );
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
    if (!isHistoryEntry(parsed)
      || parsed.id !== record.id
      || parsed.createdAt !== record.createdAt
      || parsed.expiresAt !== record.expiresAt) throw new Error('History entry metadata did not match');
    return parsed;
  } finally {
    new Uint8Array(plaintext).fill(0);
  }
}

function additionalData(record: Pick<EncryptedHistoryRecord, 'id' | 'version' | 'createdAt' | 'expiresAt'>): ArrayBuffer {
  return toArrayBuffer(new TextEncoder().encode(JSON.stringify([DATABASE_NAME, record.version, record.id, record.createdAt, record.expiresAt])));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function equalBytes(left: ArrayBuffer, right: ArrayBuffer): boolean {
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function isUsableKey(value: unknown): value is CryptoKey {
  if (!value || typeof value !== 'object') return false;
  const key = value as CryptoKey;
  return key.type === 'secret' && key.extractable === false && key.algorithm?.name === 'AES-GCM'
    && (key.algorithm as AesKeyAlgorithm).length === 256 && key.usages.includes('encrypt') && key.usages.includes('decrypt');
}

function isStoredEntry(value: unknown): value is EncryptedHistoryRecord {
  if (!value || typeof value !== 'object') return false;
  const entry = value as Partial<EncryptedHistoryRecord>;
  return typeof entry.id === 'string' && entry.id.length > 0 && entry.version === 1
    && typeof entry.createdAt === 'string' && Number.isFinite(Date.parse(entry.createdAt))
    && typeof entry.expiresAt === 'string' && Number.isFinite(Date.parse(entry.expiresAt))
    && entry.iv instanceof ArrayBuffer && entry.iv.byteLength === 12
    && entry.ciphertext instanceof ArrayBuffer && entry.ciphertext.byteLength >= 16;
}

function isHistoryEntry(value: unknown): value is SecretHistoryEntry {
  if (!value || typeof value !== 'object') return false;
  const entry = value as Partial<SecretHistoryEntry>;
  return typeof entry.id === 'string' && entry.id.length > 0
    && typeof entry.createdAt === 'string' && Number.isFinite(Date.parse(entry.createdAt))
    && typeof entry.link === 'string' && typeof entry.expiresAt === 'string'
    && Number.isFinite(Date.parse(entry.expiresAt)) && typeof entry.password === 'string'
    && (entry.revokeToken === undefined || typeof entry.revokeToken === 'string')
    && (entry.givenLabel === undefined || typeof entry.givenLabel === 'string');
}

function isUnexpired(expiresAt: string): boolean {
  return Date.parse(expiresAt) > Date.now();
}
