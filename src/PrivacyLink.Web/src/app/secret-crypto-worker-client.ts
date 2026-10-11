import type { decryptFile, EncryptedFile, EncryptedFileMetadata, FileCryptoPhase } from './secret-crypto';

export interface SecretCryptoProgress {
  current: number;
  total: number;
  filename?: string;
  phase: FileCryptoPhase;
}

export type SecretCryptoProgressCallback = (progress: SecretCryptoProgress) => void;

export interface DecryptedFileResult { filename: string; mimeType: string; data: ArrayBuffer }
export interface DecryptedSecretFile { id: string; extension: string; name: string; mimeType: string; size: number }
export interface DecryptedSecretResponse { token: string; message: string | null; files: DecryptedSecretFile[] }

type Operation = 'encryptFile' | 'decryptFile' | 'decryptFileName' | 'serializeCreateRequest' | 'encryptFilesAndSerialize' | 'decryptOpenFileResponse' | 'decryptOpenSecretResponse' | 'decryptCachedFile' | 'clearCachedFiles' | 'solveCreateProof' | 'cancelProof';
interface RequestMessage {
  id: number;
  operation: Operation;
  payload: unknown;
  clientKey: string | Uint8Array;
  filename?: string;
}
type ResponseMessage =
  | { id: number; type: 'progress'; current: number; total: number; phase: FileCryptoPhase; filename?: string }
  | { id: number; type: 'result'; result: unknown }
  | { id: number; type: 'error'; error: string };

interface PendingOperation {
  resolve(value: unknown): void;
  reject(error: Error): void;
  onProgress?: SecretCryptoProgressCallback;
  filename?: string;
}

type WorkerFactory = () => Worker;

/** A reusable worker client. Constructing it is safe in non-browser contexts; the worker starts on first use. */
export class SecretCryptoWorkerClient {
  private worker?: Worker;
  private nextId = 0;
  private readonly pending = new Map<number, PendingOperation>();

  constructor(private readonly workerFactory: WorkerFactory = () => new Worker(new URL('./secret-crypto.worker', import.meta.url), { type: 'module' })) {}

  encryptFile(file: File, clientKey: Uint8Array, onProgress?: SecretCryptoProgressCallback): Promise<EncryptedFile> {
    return this.request<EncryptedFile>('encryptFile', file, clientKey, onProgress, file.name);
  }

  decryptFile(
    payload: Parameters<typeof decryptFile>[0],
    clientKey: string,
    onProgress?: SecretCryptoProgressCallback,
    filename?: string,
  ): Promise<Uint8Array> {
    return this.request<Uint8Array>('decryptFile', payload, clientKey, onProgress, filename);
  }

  decryptFileName(
    metadata: EncryptedFileMetadata,
    clientKey: string,
    onProgress?: SecretCryptoProgressCallback,
    filename?: string,
  ): Promise<string> {
    return this.request<string>('decryptFileName', metadata, clientKey, onProgress, filename ?? metadata.extension);
  }

  serializeCreateRequest<T>(request: T, onProgress?: SecretCryptoProgressCallback): Promise<ArrayBuffer> {
    return this.request<ArrayBuffer>('serializeCreateRequest', request, '', onProgress);
  }

  encryptFilesAndSerialize<T extends object>(
    requestWithoutFiles: T,
    files: File[],
    clientKey: Uint8Array,
    onProgress?: SecretCryptoProgressCallback,
  ): Promise<ArrayBuffer> {
    return this.request<ArrayBuffer>('encryptFilesAndSerialize', { request: requestWithoutFiles, files }, clientKey, onProgress);
  }

  decryptOpenFileResponse(rawJson: ArrayBuffer, clientKey: string, onProgress?: SecretCryptoProgressCallback): Promise<DecryptedFileResult> {
    return this.request<DecryptedFileResult>('decryptOpenFileResponse', rawJson, clientKey, onProgress, undefined, [rawJson]);
  }

  decryptOpenSecretResponse(rawJson: ArrayBuffer, clientKey: string, onProgress?: SecretCryptoProgressCallback): Promise<DecryptedSecretResponse> {
    return this.request<DecryptedSecretResponse>('decryptOpenSecretResponse', rawJson, clientKey, onProgress, undefined, [rawJson]);
  }

  decryptCachedFile(token: string, fileId: string, clientKey: string, onProgress?: SecretCryptoProgressCallback, filename?: string): Promise<DecryptedFileResult> {
    return this.request<DecryptedFileResult>('decryptCachedFile', { token, fileId }, clientKey, onProgress, filename);
  }

  clearCachedFiles(token: string): Promise<void> {
    return this.request<void>('clearCachedFiles', token, '');
  }

  solveCreateProof(challenge: { challengeId: string; nonce: string; difficultyBits: number }, signal?: AbortSignal): Promise<string> {
    return this.request<string>('solveCreateProof', challenge, '', undefined, undefined, [], signal);
  }

  dispose(): void {
    this.worker?.removeEventListener('message', this.handleMessage);
    this.worker?.removeEventListener('error', this.handleWorkerError);
    this.worker?.removeEventListener('messageerror', this.handleWorkerError);
    this.worker?.terminate();
    this.worker = undefined;
    this.failPending(new Error('File crypto worker was disposed'));
  }

  private request<T>(operation: Operation, payload: unknown, clientKey: string | Uint8Array, onProgress?: SecretCryptoProgressCallback, filename?: string, transfer: Transferable[] = [], signal?: AbortSignal): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      if (signal?.aborted) { reject(new DOMException('Operation cancelled', 'AbortError')); return; }
      let worker: Worker;
      try {
        worker = this.getWorker();
      } catch (error) {
        reject(error instanceof Error ? error : new Error('Could not start file crypto worker'));
        return;
      }

      const id = ++this.nextId;
      const onAbort = (): void => {
        if (!this.pending.delete(id)) return;
        worker.postMessage({ id, operation: 'cancelProof', payload: id, clientKey: '' } satisfies RequestMessage);
        reject(new DOMException('Operation cancelled', 'AbortError'));
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      const settleResolve = (value: unknown): void => { signal?.removeEventListener('abort', onAbort); resolve(value as T); };
      const settleReject = (error: Error): void => { signal?.removeEventListener('abort', onAbort); reject(error); };
      this.pending.set(id, { resolve: settleResolve, reject: settleReject, onProgress, filename });
      const message: RequestMessage = {
        id,
        operation,
        payload,
        clientKey: clientKey instanceof Uint8Array ? clientKey.slice() : clientKey,
        filename,
      };
      try {
        worker.postMessage(message, transfer);
      } catch (error) {
        this.pending.delete(id);
        signal?.removeEventListener('abort', onAbort);
        reject(error instanceof Error ? error : new Error('Could not send file operation to worker'));
      }
    });
  }

  private getWorker(): Worker {
    if (!this.worker) {
      const worker = this.workerFactory();
      worker.addEventListener('message', this.handleMessage);
      worker.addEventListener('error', this.handleWorkerError);
      worker.addEventListener('messageerror', this.handleWorkerError);
      this.worker = worker;
    }
    return this.worker;
  }

  private readonly handleMessage = (event: MessageEvent<ResponseMessage>): void => {
    const message = event.data;
    const pending = this.pending.get(message.id);
    if (!pending) return;

    if (message.type === 'progress') {
      try {
        pending.onProgress?.({ current: message.current, total: message.total, filename: message.filename ?? pending.filename, phase: message.phase });
      } catch {
        // A UI progress callback should not cancel or corrupt the cryptographic operation.
      }
      return;
    }

    this.pending.delete(message.id);
    if (message.type === 'error') pending.reject(new Error(message.error));
    else pending.resolve(message.result);
  };

  private readonly handleWorkerError = (event: Event): void => {
    const message = 'message' in event && typeof event.message === 'string' ? event.message : '';
    const error = new Error(message || 'File crypto worker failed');
    this.failPending(error);
    this.worker?.removeEventListener('message', this.handleMessage);
    this.worker?.removeEventListener('error', this.handleWorkerError);
    this.worker?.removeEventListener('messageerror', this.handleWorkerError);
    this.worker?.terminate();
    this.worker = undefined;
  };

  private failPending(error: Error): void {
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }
}

let sharedClient: SecretCryptoWorkerClient | undefined;

/** Returns the application-wide client, preserving one lazily-created Worker across operations. */
export function getSecretCryptoWorkerClient(): SecretCryptoWorkerClient {
  sharedClient ??= new SecretCryptoWorkerClient();
  return sharedClient;
}
