import { createEnvironmentInjector, EnvironmentInjector } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { vi } from 'vitest';
import { installTestWebLocks } from '../../test-utils/web-locks';
import { MemoryHistoryStorage } from '../../test-utils/memory-history-storage';
import { SECRET_HISTORY_STORAGE, SecretHistoryStorage, SecretHistoryStore } from './secret-history-store';

function entry(id: string, label?: string) {
  return {
    id,
    createdAt: '2026-10-24T07:00:00.000Z',
    link: 'https://example.test/s/secret#client-key-never-plaintext',
    expiresAt: '2030-01-01T00:00:00.000Z',
    password: 'private-password-never-plaintext',
    revokeToken: 'private-revoke-token-never-plaintext',
    ...(label ? { givenLabel: label } : {})
  };
}

describe('SecretHistoryStore', () => {
  let storage: MemoryHistoryStorage;
  let restoreWebLocks: (() => void) | undefined;
  let childInjectors: EnvironmentInjector[] = [];

  async function configure(): Promise<void> {
    TestBed.resetTestingModule();
    await TestBed.configureTestingModule({
      providers: [{ provide: SECRET_HISTORY_STORAGE, useValue: storage }]
    }).compileComponents();
  }

  async function createStore(): Promise<SecretHistoryStore> {
    await configure();
    const store = TestBed.inject(SecretHistoryStore);
    await store.whenReady();
    return store;
  }

  async function createIndependentStores(count: number): Promise<SecretHistoryStore[]> {
    await configure();
    const parent = TestBed.inject(EnvironmentInjector);
    const stores = Array.from({ length: count }, () => {
      const injector = createEnvironmentInjector([SecretHistoryStore], parent);
      childInjectors.push(injector);
      return injector.get(SecretHistoryStore);
    });
    await Promise.all(stores.map(store => store.whenReady()));
    return stores;
  }

  beforeEach(() => {
    restoreWebLocks = installTestWebLocks();
    storage = new MemoryHistoryStorage();
  });

  afterEach(() => {
    restoreWebLocks?.();
    for (const injector of childInjectors) injector.destroy();
    childInjectors = [];
    TestBed.resetTestingModule();
    vi.restoreAllMocks();
  });

  it('enables automatic saving by default and creates a non-extractable AES-256 key', async () => {
    const store = await createStore();
    const key = storage.metadata.get('encryptionKey') as CryptoKey;

    expect(store.entries()).toEqual([]);
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    expect(key.usages).toEqual(['encrypt', 'decrypt']);
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
  });

  it('encrypts every secret-bearing field separately and reuses the persisted CryptoKey', async () => {
    const first = await createStore();
    const saved = entry('secret-one', 'Payroll');
    expect(await first.add(saved)).toBe(true);

    const record = storage.records.get(saved.id)!;
    expect(storage.records.size).toBe(1);
    expect(record).toMatchObject({
      id: saved.id,
      version: 1,
      createdAt: saved.createdAt,
      expiresAt: saved.expiresAt
    });
    expect(Object.keys(record).sort()).toEqual(['ciphertext', 'createdAt', 'expiresAt', 'id', 'iv', 'version']);
    const persisted = JSON.stringify({
      id: record.id,
      version: record.version,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      iv: Array.from(new Uint8Array(record.iv)),
      ciphertext: Array.from(new Uint8Array(record.ciphertext))
    });
    for (const secret of [saved.link, saved.password, saved.revokeToken!, saved.givenLabel!]) {
      expect(persisted).not.toContain(secret);
    }
    expect(storage.metadata.get('encryptionKey')).toBeDefined();
    expect(JSON.stringify([...storage.metadata.keys()])).not.toContain('passphrase');

    const originalKey = storage.metadata.get('encryptionKey');
    const restored = await createStore();
    expect(storage.metadata.get('encryptionKey')).toBe(originalKey);
    expect(restored.entries()).toEqual([saved]);
  });

  it('does not read, migrate, or delete any old history data', async () => {
    localStorage.setItem('privacylink.secret-history.v1', 'old plaintext');
    localStorage.setItem('privacylink.secret-history.v2', 'old ciphertext');
    localStorage.setItem('privacylink.secret-history.v3', 'old vault');
    localStorage.setItem('privacylink.secret-history.credential.v2', 'old credential');

    const store = await createStore();

    expect(store.entries()).toEqual([]);
    expect(localStorage.getItem('privacylink.secret-history.v1')).toBe('old plaintext');
    expect(localStorage.getItem('privacylink.secret-history.v2')).toBe('old ciphertext');
    expect(localStorage.getItem('privacylink.secret-history.v3')).toBe('old vault');
    expect(localStorage.getItem('privacylink.secret-history.credential.v2')).toBe('old credential');
  });

  it('isolates a tampered record while restoring other readable entries', async () => {
    const store = await createStore();
    await store.add(entry('good-secret'));
    await store.add(entry('damaged-secret'));
    const damaged = storage.records.get('damaged-secret')!;
    const bytes = new Uint8Array(damaged.ciphertext.slice(0));
    bytes[0] ^= 0xff;
    storage.records.set('damaged-secret', { ...damaged, ciphertext: bytes.buffer });

    const restored = await createStore();

    expect(restored.entries()).toEqual([entry('good-secret')]);
    expect(restored.unavailableEntries()).toBe(1);
    expect(restored.error()).toBe('unavailable');
    expect(storage.records.has('damaged-secret')).toBe(true);
  });

  it('keeps a tampered expired record unavailable instead of deleting it', async () => {
    const store = await createStore();
    await store.add(entry('tampered-expiry'));
    const record = storage.records.get('tampered-expiry')!;
    storage.records.set(record.id, { ...record, expiresAt: new Date(Date.now() - 1_000).toISOString() });

    const restored = await createStore();

    expect(restored.entries()).toEqual([]);
    expect(restored.unavailableEntries()).toBe(1);
    expect(restored.error()).toBe('unavailable');
    expect(storage.records.has('tampered-expiry')).toBe(true);
  });

  it('does not replace missing key material while records remain and allows deliberate erasure', async () => {
    const store = await createStore();
    await store.add(entry('secret-one'));
    storage.metadata.delete('encryptionKey');

    const restored = await createStore();

    expect(restored.entries()).toEqual([]);
    expect(restored.unavailableEntries()).toBe(1);
    expect(storage.metadata.has('encryptionKey')).toBe(false);
    expect(await restored.add(entry('secret-two'))).toBe(false);
    expect(storage.records.size).toBe(1);
    expect(await restored.clear()).toBe(true);
    expect(storage.records.size).toBe(0);
    expect(storage.metadata.has('encryptionKey')).toBe(false);
  });

  it('cleans up expired records without changing server data', async () => {
    const store = await createStore();
    const now = Date.parse('2030-01-01T00:00:00.000Z');
    const dateNow = vi.spyOn(Date, 'now').mockReturnValue(now - 10_000);
    try {
      await store.add({ ...entry('expired-secret'), expiresAt: new Date(now).toISOString() });
      await store.add({ ...entry('active-secret'), expiresAt: new Date(now + 60_000).toISOString() });
      dateNow.mockReturnValue(now + 1);
      expect(await store.pruneExpired()).toBe(true);
      expect(store.entries()).toEqual([{ ...entry('active-secret'), expiresAt: new Date(now + 60_000).toISOString() }]);
      expect(storage.records.has('expired-secret')).toBe(false);
      expect(storage.records.has('active-secret')).toBe(true);
    } finally {
      dateNow.mockRestore();
    }
  });

  it('warns and retries when deleting an expired record temporarily fails', async () => {
    const store = await createStore();
    vi.useFakeTimers();
    try {
      storage.failNextDelete = true;

      expect(await store.add({ ...entry('expired-secret'), expiresAt: new Date(Date.now() - 1_000).toISOString() })).toBe(true);
      expect(store.entries()).toEqual([]);
      expect(store.expiryCleanupFailed()).toBe(true);
      expect(storage.records.has('expired-secret')).toBe(true);
      expect(storage.deleteCalls).toBe(1);

      await vi.advanceTimersByTimeAsync(60_000);
      vi.useRealTimers();

      await vi.waitFor(() => {
        expect(storage.deleteCalls).toBe(2);
        expect(storage.records.has('expired-secret')).toBe(false);
        expect(store.expiryCleanupFailed()).toBe(false);
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it('clears records but keeps saving enabled and the local key', async () => {
    const store = await createStore();
    await store.add(entry('secret-one'));
    const key = storage.metadata.get('encryptionKey');

    expect(await store.clear()).toBe(true);
    expect(store.entries()).toEqual([]);
    expect(storage.records.size).toBe(0);
    expect(storage.metadata.get('encryptionKey')).toBe(key);
  });

  it('preserves concurrent writes from independent store instances', async () => {
    const [first, second] = await createIndependentStores(2);
    await Promise.all([
      first.add(entry('secret-one')),
      second.add(entry('secret-two'))
    ]);

    const reloaded = await createStore();
    expect(reloaded.entries()).toHaveLength(2);
    expect(reloaded.entries().map(item => item.id).sort()).toEqual(['secret-one', 'secret-two']);
    expect(storage.records.size).toBe(2);
  });

  it('rejects a paused add racing clear when Web Locks are unavailable', async () => {
    const [addingTab, clearingTab] = await createIndependentStores(2);
    const lockDescriptor = Object.getOwnPropertyDescriptor(navigator, 'locks');
    Object.defineProperty(navigator, 'locks', { configurable: true, value: undefined });
    try {
      const pause = storage.pauseNextAdd();
      const pendingAdd = addingTab.add(entry('racing-clear'));
      await pause.started;

      expect(await clearingTab.clear()).toBe(true);
      pause.release();
      expect(await pendingAdd).toBe(false);
      expect(storage.records.size).toBe(0);
    } finally {
      if (lockDescriptor) Object.defineProperty(navigator, 'locks', lockDescriptor);
      else Reflect.deleteProperty(navigator, 'locks');
    }
  });

  it('does not let an out-of-order refresh repopulate entries after clear', async () => {
    const store = await createStore();
    await store.add(entry('stale-refresh'));
    const pause = storage.pauseNextEntriesRead();
    const pendingRefresh = (store as unknown as { refresh(): Promise<void> }).refresh();
    await pause.started;

    expect(await store.clear()).toBe(true);
    pause.release();
    await pendingRefresh;

    expect(store.entries()).toEqual([]);
    expect(storage.records.size).toBe(0);
  });

  it('does not publish a stale snapshot when another tab clears during refresh', async () => {
    const broadcastDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'BroadcastChannel');
    Object.defineProperty(globalThis, 'BroadcastChannel', { configurable: true, value: undefined });
    try {
      const [refreshingTab, clearingTab] = await createIndependentStores(2);
      await clearingTab.add(entry('cross-tab-stale-refresh'));
      expect(refreshingTab.entries()).toEqual([]);

      const pause = storage.pauseNextEntriesRead();
      const pendingRefresh = (refreshingTab as unknown as { refresh(): Promise<void> }).refresh();
      await pause.started;

      expect(await clearingTab.clear()).toBe(true);
      pause.release();
      await pendingRefresh;

      expect(refreshingTab.entries()).toEqual([]);
      expect(storage.records.size).toBe(0);
    } finally {
      if (broadcastDescriptor) Object.defineProperty(globalThis, 'BroadcastChannel', broadcastDescriptor);
      else Reflect.deleteProperty(globalThis, 'BroadcastChannel');
    }
  });

  it('reports persistence failures without exposing an entry as saved', async () => {
    const store = await createStore();
    storage.failWrites = true;

    expect(await store.add(entry('secret-one'))).toBe(false);
    expect(store.entries()).toEqual([]);
    expect(store.saveFailed()).toBe(true);
    expect(storage.records.size).toBe(0);
  });
});
