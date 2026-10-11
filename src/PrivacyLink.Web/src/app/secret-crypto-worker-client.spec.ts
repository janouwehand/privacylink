import { describe, expect, it, vi } from 'vitest';
import { SecretCryptoWorkerClient } from './secret-crypto-worker-client';

type WorkerRequest = { id: number; operation: string; payload: unknown; clientKey: string | Uint8Array; filename?: string };

class FakeWorker extends EventTarget {
  readonly requests: WorkerRequest[] = [];
  readonly transfers: Transferable[][] = [];
  terminated = false;

  postMessage(message: WorkerRequest, transfer: Transferable[] = []): void {
    this.requests.push(message);
    this.transfers.push(transfer);
  }

  terminate(): void {
    this.terminated = true;
  }

  emit(data: unknown): void {
    this.dispatchEvent(new MessageEvent('message', { data }));
  }

  fail(message = 'worker failed'): void {
    this.dispatchEvent(new ErrorEvent('error', { message }));
  }
}

describe('SecretCryptoWorkerClient', () => {
  it('creates its worker lazily, reuses it, and reports operation and file progress', async () => {
    const worker = new FakeWorker();
    const factory = vi.fn(() => worker as unknown as Worker);
    const client = new SecretCryptoWorkerClient(factory);
    expect(factory).not.toHaveBeenCalled();

    const onProgress = vi.fn();
    const file = new File(['content'], 'notes.txt', { type: 'text/plain' });
    const operation = client.encryptFile(file, new Uint8Array(32), onProgress);
    expect(factory).toHaveBeenCalledOnce();
    expect(worker.requests[0]?.operation).toBe('encryptFile');
    expect(worker.requests[0]?.filename).toBe('notes.txt');

    worker.emit({ id: 1, type: 'progress', current: 1, total: 1, phase: 'encoding' });
    worker.emit({ id: 1, type: 'result', result: { id: 'file-id' } });
    await expect(operation).resolves.toEqual({ id: 'file-id' });
    expect(onProgress).toHaveBeenCalledWith({ current: 1, total: 1, filename: 'notes.txt', phase: 'encoding' });

    const decrypt = client.decryptFile({ id: 'file-id', extension: '.txt', nonce: 'nonce', ciphertext: 'cipher' }, 'key', onProgress, 'notes.txt');
    expect(factory).toHaveBeenCalledOnce();
    worker.emit({ id: 2, type: 'result', result: new Uint8Array([1, 2, 3]) });
    await expect(decrypt).resolves.toEqual(new Uint8Array([1, 2, 3]));
    client.dispose();
    expect(worker.terminated).toBe(true);
  });

  it('rejects a pending operation when the worker reports an error', async () => {
    const worker = new FakeWorker();
    const client = new SecretCryptoWorkerClient(() => worker as unknown as Worker);
    const operation = client.decryptFileName({
      id: 'file-id', extension: '.txt', nameNonce: 'nonce', nameCiphertext: 'cipher', mimeType: 'text/plain', size: 1,
    }, 'key');

    worker.emit({ id: 1, type: 'error', error: 'invalid ciphertext' });
    await expect(operation).rejects.toThrow('invalid ciphertext');
    client.dispose();
  });

  it('requests worker-side create request serialization as transferable bytes', async () => {
    const worker = new FakeWorker();
    const client = new SecretCryptoWorkerClient(() => worker as unknown as Worker);
    const request = { protocolVersion: 1, files: [{ ciphertext: 'large-base64-payload' }] };
    const operation = client.serializeCreateRequest(request);
    expect(worker.requests[0]?.operation).toBe('serializeCreateRequest');
    expect(worker.requests[0]?.payload).toBe(request);

    const serialized = new TextEncoder().encode(JSON.stringify(request)).buffer;
    worker.emit({ id: 1, type: 'result', result: serialized });
    await expect(operation).resolves.toEqual(serialized);
    client.dispose();
  });

  it('uses one request to encrypt a file batch and transfer raw open responses into the worker', async () => {
    const worker = new FakeWorker();
    const client = new SecretCryptoWorkerClient(() => worker as unknown as Worker);
    const files = [new File(['first'], 'first.txt'), new File(['second'], 'second.txt')];
    const request = { protocolVersion: 1, message: null };
    const progress = vi.fn();
    const create = client.encryptFilesAndSerialize(request, files, new Uint8Array(32), progress);
    expect(worker.requests[0]?.operation).toBe('encryptFilesAndSerialize');
    worker.emit({ id: 1, type: 'progress', current: 2, total: 2, filename: 'second.txt', phase: 'encrypting' });
    const createBody = new ArrayBuffer(4);
    worker.emit({ id: 1, type: 'result', result: createBody });
    await expect(create).resolves.toBe(createBody);
    expect(progress).toHaveBeenCalledWith({ current: 2, total: 2, filename: 'second.txt', phase: 'encrypting' });

    const rawJson = new ArrayBuffer(8);
    const decrypt = client.decryptOpenSecretResponse(rawJson, 'client-key');
    expect(worker.requests[1]?.operation).toBe('decryptOpenSecretResponse');
    expect(worker.transfers[1]).toEqual([rawJson]);
    const opened = { token: 'opaque', message: 'message', files: [] };
    worker.emit({ id: 2, type: 'result', result: opened });
    await expect(decrypt).resolves.toEqual(opened);
    client.dispose();
  });

  it('rejects all pending operations and replaces a failed worker', async () => {
    const firstWorker = new FakeWorker();
    const secondWorker = new FakeWorker();
    const factory = vi.fn().mockReturnValueOnce(firstWorker as unknown as Worker).mockReturnValueOnce(secondWorker as unknown as Worker);
    const client = new SecretCryptoWorkerClient(factory);
    const operation = client.decryptFileName({
      id: 'file-id', extension: '.txt', nameNonce: 'nonce', nameCiphertext: 'cipher', mimeType: 'text/plain', size: 1,
    }, 'key');

    firstWorker.fail('worker crashed');
    await expect(operation).rejects.toThrow('worker crashed');
    const nextOperation = client.decryptFileName({
      id: 'file-id', extension: '.txt', nameNonce: 'nonce', nameCiphertext: 'cipher', mimeType: 'text/plain', size: 1,
    }, 'key');
    expect(factory).toHaveBeenCalledTimes(2);
    secondWorker.emit({ id: 2, type: 'result', result: 'notes.txt' });
    await expect(nextOperation).resolves.toBe('notes.txt');
    client.dispose();
  });
});
