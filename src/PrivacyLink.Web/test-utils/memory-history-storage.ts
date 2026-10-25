import { EncryptedHistoryRecord, SecretHistoryStorage } from '../src/app/secret-history-store';

export class MemoryHistoryStorage implements SecretHistoryStorage {
  readonly metadata = new Map<string, unknown>();
  readonly records = new Map<string, EncryptedHistoryRecord>();
  failWrites = false;
  private pendingAddGate?: { started: () => void; wait: Promise<void>; release: () => void };
  private pendingEntriesGate?: { started: () => void; wait: Promise<void>; release: () => void };

  async getPreference(): Promise<boolean | undefined> {
    const value = this.metadata.get('savingEnabled');
    return typeof value === 'boolean' ? value : undefined;
  }

  async setPreference(enabled: boolean): Promise<void> {
    this.metadata.set('savingEnabled', enabled);
  }

  async getKey(): Promise<CryptoKey | undefined> {
    const value = this.metadata.get('encryptionKey');
    return isCryptoKey(value) ? value : undefined;
  }

  async getKeyId(): Promise<string | undefined> {
    const value = this.metadata.get('encryptionKeyId');
    return typeof value === 'string' ? value : undefined;
  }

  async getEpoch(): Promise<number> {
    const value = this.metadata.get('historyEpoch');
    return typeof value === 'number' ? value : 0;
  }

  async putKeyIfAbsent(candidate: CryptoKey, candidateId: string): Promise<boolean> {
    if (this.metadata.get('savingEnabled') === false) return false;
    const current = this.metadata.get('encryptionKey');
    const currentId = await this.getKeyId();
    if (isCryptoKey(current) && currentId) return true;
    if (this.records.size > 0) return false;
    this.metadata.set('encryptionKey', candidate);
    this.metadata.set('encryptionKeyId', candidateId);
    return true;
  }

  async enableWithKey(candidate: CryptoKey, candidateId: string): Promise<boolean> {
    const current = this.metadata.get('encryptionKey');
    const currentId = await this.getKeyId();
    if (isCryptoKey(current) && currentId) {
      this.metadata.set('savingEnabled', true);
      return true;
    }
    if (this.records.size > 0) return false;
    this.metadata.set('encryptionKey', candidate);
    this.metadata.set('encryptionKeyId', candidateId);
    this.metadata.set('savingEnabled', true);
    return true;
  }

  async getEntries(): Promise<EncryptedHistoryRecord[]> {
    const snapshot = [...this.records.values()];
    if (this.pendingEntriesGate) {
      const gate = this.pendingEntriesGate;
      this.pendingEntriesGate = undefined;
      gate.started();
      await gate.wait;
    }
    return snapshot;
  }

  async addEntryIfCurrent(entry: EncryptedHistoryRecord, keyId: string, epoch: number): Promise<boolean> {
    if (this.pendingAddGate) {
      const gate = this.pendingAddGate;
      this.pendingAddGate = undefined;
      gate.started();
      await gate.wait;
    }
    if (this.failWrites) throw new Error('Storage unavailable');
    if (this.metadata.get('savingEnabled') === false || !isCryptoKey(this.metadata.get('encryptionKey'))
      || this.metadata.get('encryptionKeyId') !== keyId
      || (typeof this.metadata.get('historyEpoch') === 'number' ? this.metadata.get('historyEpoch') : 0) !== epoch
      || this.records.has(entry.id)) return false;
    this.records.set(entry.id, entry);
    return true;
  }

  async replaceEntryIfCurrent(entry: EncryptedHistoryRecord, expectedCiphertext: ArrayBuffer, keyId: string, epoch: number): Promise<boolean> {
    if (this.failWrites) throw new Error('Storage unavailable');
    const current = this.records.get(entry.id);
    if (this.metadata.get('savingEnabled') === false || !isCryptoKey(this.metadata.get('encryptionKey'))
      || this.metadata.get('encryptionKeyId') !== keyId
      || (typeof this.metadata.get('historyEpoch') === 'number' ? this.metadata.get('historyEpoch') : 0) !== epoch
      || !current || !equalBytes(current.ciphertext, expectedCiphertext)) return false;
    this.records.set(entry.id, entry);
    return true;
  }

  async deleteEntryIfCurrent(id: string, expectedCiphertext: ArrayBuffer): Promise<boolean> {
    const current = this.records.get(id);
    if (!current || !equalBytes(current.ciphertext, expectedCiphertext)) return false;
    return this.records.delete(id);
  }

  async clearEntries(): Promise<number> {
    this.records.clear();
    const epoch = (typeof this.metadata.get('historyEpoch') === 'number' ? this.metadata.get('historyEpoch') as number : 0) + 1;
    this.metadata.set('historyEpoch', epoch);
    return epoch;
  }

  async disable(): Promise<number> {
    this.records.clear();
    this.metadata.delete('encryptionKey');
    this.metadata.delete('encryptionKeyId');
    this.metadata.set('savingEnabled', false);
    const epoch = (typeof this.metadata.get('historyEpoch') === 'number' ? this.metadata.get('historyEpoch') as number : 0) + 1;
    this.metadata.set('historyEpoch', epoch);
    return epoch;
  }

  pauseNextAdd(): { started: Promise<void>; release: () => void } {
    return this.pause('add');
  }

  pauseNextEntriesRead(): { started: Promise<void>; release: () => void } {
    return this.pause('entries');
  }

  private pause(kind: 'add' | 'entries'): { started: Promise<void>; release: () => void } {
    let signalStarted!: () => void;
    let release!: () => void;
    const started = new Promise<void>(resolve => { signalStarted = resolve; });
    const wait = new Promise<void>(resolve => { release = resolve; });
    const gate = { started: signalStarted, wait, release };
    if (kind === 'add') this.pendingAddGate = gate;
    else this.pendingEntriesGate = gate;
    return { started, release };
  }
}

function equalBytes(left: ArrayBuffer, right: ArrayBuffer): boolean {
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function isCryptoKey(value: unknown): value is CryptoKey {
  if (!value || typeof value !== 'object') return false;
  const key = value as CryptoKey;
  return key.type === 'secret' && key.algorithm?.name === 'AES-GCM';
}
