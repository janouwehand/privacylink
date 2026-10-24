import { createEnvironmentInjector, EnvironmentInjector } from '@angular/core';
import { TestBed as AngularTestBed } from '@angular/core/testing';
import { vi } from 'vitest';
import { SECRET_HISTORY_STORAGE, SecretHistoryStorage, SecretHistoryStore } from './secret-history-store';
import { installTestWebLocks } from '../../test-utils/web-locks';

const LEGACY_KEY = 'privacylink.secret-history.v1';
const OLD_CIPHERTEXT_KEY = 'privacylink.secret-history.v2';
const OLD_CREDENTIAL_KEY = 'privacylink.secret-history.credential.v2';
const CIPHERTEXT_KEY = 'privacylink.secret-history.v3';
const PASSPHRASE = 'violet lantern river meadow';

function entry() {
  return {
    id: 'AAAAAAAAAAAAAAAAAAAAAA',
    createdAt: '2026-10-24T07:00:00.000Z',
    link: 'https://example.test/s/secret#client-key-never-plaintext',
    expiresAt: '2030-01-01T00:00:00.000Z',
    password: 'private-password-never-plaintext',
    revokeToken: 'private-revoke-token-never-plaintext'
  };
}

describe('SecretHistoryStore', () => {
  let values: Map<string, string>;
  let storage: SecretHistoryStorage;
  let restoreWebLocks: (() => void) | undefined;
  let childInjectors: EnvironmentInjector[] = [];

  async function createStore(): Promise<SecretHistoryStore> {
    AngularTestBed.resetTestingModule();
    await AngularTestBed.configureTestingModule({
      providers: [{ provide: SECRET_HISTORY_STORAGE, useValue: storage }]
    }).compileComponents();
    return AngularTestBed.inject(SecretHistoryStore);
  }

  async function createIndependentStores(count: number): Promise<SecretHistoryStore[]> {
    AngularTestBed.resetTestingModule();
    await AngularTestBed.configureTestingModule({
      providers: [{ provide: SECRET_HISTORY_STORAGE, useValue: storage }]
    }).compileComponents();
    const parent = AngularTestBed.inject(EnvironmentInjector);
    return Array.from({ length: count }, () => {
      const injector = createEnvironmentInjector([SecretHistoryStore], parent);
      childInjectors.push(injector);
      return injector.get(SecretHistoryStore);
    });
  }

  function dispatchStorageEvent(): void {
    window.dispatchEvent(new StorageEvent('storage', {
      key: CIPHERTEXT_KEY,
      newValue: values.get(CIPHERTEXT_KEY) ?? null
    }));
  }

  beforeEach(() => {
    restoreWebLocks = installTestWebLocks();
    values = new Map();
    storage = {
      getItem: key => values.get(key) ?? null,
      setItem: (key, value) => { values.set(key, value); },
      removeItem: key => { values.delete(key); }
    };
  });

  afterEach(() => {
    restoreWebLocks?.();
    for (const injector of childInjectors) injector.destroy();
    childInjectors = [];
    AngularTestBed.resetTestingModule();
  });

  it('keeps sender history disabled and writes nothing by default', async () => {
    const store = await createStore();
    expect(store.enabled()).toBe(false);
    expect(store.entries()).toEqual([]);
    expect(values.size).toBe(0);
  });

  it('derives the vault key from the passphrase and restores only with the correct passphrase', async () => {
    const store = await createStore();
    expect(await store.enable(PASSPHRASE)).toBe(true);
    expect(await store.add(entry())).toBe(true);

    const persisted = [...values.values()].join('\n');
    expect(persisted).not.toContain(PASSPHRASE);
    expect(persisted).not.toContain('PrivacyLink sender history vault check v3');
    expect(persisted).not.toContain(entry().link);
    expect(persisted).not.toContain(entry().password);
    expect(persisted).not.toContain(entry().revokeToken);
    const envelope = JSON.parse(values.get(CIPHERTEXT_KEY)!);
    expect(envelope.version).toBe(3);
    expect(envelope.kdf).toMatchObject({ algorithm: 'argon2id', version: 19, memoryKiB: 19456, iterations: 2, parallelism: 1 });
    expect(envelope.kdf.salt).toHaveLength(22);

    const restored = await createStore();
    expect(await restored.unlock(PASSPHRASE)).toBe(true);
    expect(restored.entries()).toEqual([entry()]);

    const wrong = await createStore();
    expect(await wrong.unlock('amber forest cloud bridge')).toBe(false);
    expect(wrong.entries()).toEqual([]);
    expect(wrong.error()).toBe('incorrect');
  });

  it('uses the exact Unicode passphrase input without normalization', async () => {
    const passphrase = 'caf\u00e9 Meadow \u{1F331} River';
    const store = await createStore();
    expect(await store.enable(passphrase)).toBe(true);
    expect(await store.add(entry())).toBe(true);

    const decomposedInput = await createStore();
    expect(decomposedInput).not.toBe(store);
    expect(decomposedInput.unlocked()).toBe(false);
    expect(await decomposedInput.unlock(passphrase.normalize('NFD'))).toBe(false);
    const restored = await createStore();
    expect(await restored.unlock(passphrase)).toBe(true);
  });

  it('rejects modified ciphertext and does not reveal entries', async () => {
    const store = await createStore();
    await store.enable(PASSPHRASE);
    await store.add(entry());
    const envelope = JSON.parse(values.get(CIPHERTEXT_KEY)!);
    const original = envelope.entries[0].ciphertext as string;
    envelope.entries[0].ciphertext = (original.startsWith('A') ? 'B' : 'A') + original.slice(1);
    values.set(CIPHERTEXT_KEY, JSON.stringify(envelope));

    const tampered = await createStore();
    expect(await tampered.unlock(PASSPHRASE)).toBe(false);
    expect(tampered.entries()).toEqual([]);
    expect(tampered.error()).toBe('incorrect');
  });

  it('requires at least 12 characters before creating a vault', async () => {
    const store = await createStore();
    expect(await store.enable('short word')).toBe(false);
    expect(store.error()).toBe('tooShort');
    expect(values.has(CIPHERTEXT_KEY)).toBe(false);
  });

  it('deletes old plaintext and passkey vault data without restoring it', async () => {
    values.set(LEGACY_KEY, JSON.stringify([entry()]));
    values.set(OLD_CIPHERTEXT_KEY, 'old passkey ciphertext');
    values.set(OLD_CREDENTIAL_KEY, 'old passkey credential');
    const store = await createStore();
    expect(values.has(LEGACY_KEY)).toBe(false);
    expect(values.has(OLD_CIPHERTEXT_KEY)).toBe(false);
    expect(values.has(OLD_CREDENTIAL_KEY)).toBe(false);
    expect(store.entries()).toEqual([]);
    expect(store.enabled()).toBe(false);
    expect(values.has(CIPHERTEXT_KEY)).toBe(false);
  });

  it('removes expired per-entry ciphertext while locked and keeps active entries recoverable', async () => {
    const now = Date.parse('2030-01-01T00:00:00.000Z');
    const dateNow = vi.spyOn(Date, 'now').mockReturnValue(now);
    try {
      const store = await createStore();
      await store.enable(PASSPHRASE);
      const expired = { ...entry(), id: 'expired', expiresAt: new Date(now + 60_000).toISOString() };
      const active = { ...entry(), id: 'active', expiresAt: new Date(now + 3_600_000).toISOString() };
      await store.add(expired);
      await store.add(active);
      const originalRecords = JSON.parse(values.get(CIPHERTEXT_KEY)!).entries;
      expect(originalRecords).toHaveLength(2);

      dateNow.mockReturnValue(now + 120_000);
      const locked = await createStore();
      expect(locked.unlocked()).toBe(false);
      const prunedEnvelope = JSON.parse(values.get(CIPHERTEXT_KEY)!);
      expect(prunedEnvelope.entries).toHaveLength(1);
      expect(prunedEnvelope.entries[0].expiresAt).toBe(active.expiresAt);
      expect(await locked.unlock(PASSPHRASE)).toBe(true);
      expect(locked.entries()).toEqual([active]);
    } finally {
      dateNow.mockRestore();
    }
  });

  it('resets to an empty vault with a new passphrase and clears all previous history', async () => {
    const store = await createStore();
    await store.enable(PASSPHRASE);
    await store.add(entry());

    expect(await store.reset('different violet river meadow')).toBe(true);
    expect(store.entries()).toEqual([]);
    const locked = await createStore();
    expect(await locked.unlock('different violet river meadow')).toBe(true);
    expect(locked.entries()).toEqual([]);
    const oldPassphrase = await createStore();
    expect(await oldPassphrase.unlock(PASSPHRASE)).toBe(false);
  });

  it('erases ciphertext and old credential metadata when history is disabled', async () => {
    const store = await createStore();
    await store.enable(PASSPHRASE);
    await store.add(entry());
    values.set(OLD_CREDENTIAL_KEY, 'obsolete');
    expect(await store.disable()).toBe(true);
    expect(store.enabled()).toBe(false);
    expect(store.entries()).toEqual([]);
    expect(values.has(CIPHERTEXT_KEY)).toBe(false);
    expect(values.has(OLD_CREDENTIAL_KEY)).toBe(false);
  });

  it.each(['reset', 'disable'] as const)('rejects stale writes when another tab %s the vault', async action => {
    const [staleWriter, otherTab, eventOnlyTab] = await createIndependentStores(3);
    expect(await staleWriter.enable(PASSPHRASE)).toBe(true);
    expect(await staleWriter.add(entry())).toBe(true);
    dispatchStorageEvent();
    expect(await otherTab.unlock(PASSPHRASE)).toBe(true);
    expect(await eventOnlyTab.unlock(PASSPHRASE)).toBe(true);

    if (action === 'reset') {
      const oldSalt = JSON.parse(values.get(CIPHERTEXT_KEY)!).kdf.salt;
      const replacementPassphrase = 'different violet river meadow';
      expect(await otherTab.reset(replacementPassphrase)).toBe(true);
      const replacement = values.get(CIPHERTEXT_KEY)!;
      expect(JSON.parse(replacement).kdf.salt).not.toBe(oldSalt);

      // The persisted identity check protects the gap before the browser dispatches `storage`.
      expect(await staleWriter.add({ ...entry(), id: 'stale-after-reset' })).toBe(false);
      expect(values.get(CIPHERTEXT_KEY)).toBe(replacement);

      dispatchStorageEvent();
      expect(eventOnlyTab.unlocked()).toBe(false);
      expect(eventOnlyTab.entries()).toEqual([]);
      expect(await eventOnlyTab.add({ ...entry(), id: 'stale-after-event' })).toBe(false);
      expect(values.get(CIPHERTEXT_KEY)).toBe(replacement);
      expect(await eventOnlyTab.unlock(replacementPassphrase)).toBe(true);
      expect(eventOnlyTab.entries()).toEqual([]);
    } else {
      expect(await otherTab.disable()).toBe(true);
      dispatchStorageEvent();
      expect(staleWriter.enabled()).toBe(false);
      expect(staleWriter.unlocked()).toBe(false);
      expect(staleWriter.entries()).toEqual([]);
      expect(await staleWriter.add({ ...entry(), id: 'stale-after-disable' })).toBe(false);
      expect(values.has(CIPHERTEXT_KEY)).toBe(false);
    }
  });
});
