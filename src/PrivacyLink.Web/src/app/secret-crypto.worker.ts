import { decryptFile, decryptFileName, decryptMessage, encodeBase64Url, encryptFile, EncryptedFile, EncryptedFileMetadata, EncryptedPayload, FileCryptoPhase, OpenedFile, solveCreateProof } from '../../../PrivacyLink.Client/src';

type Operation = 'encryptFile' | 'decryptFile' | 'decryptFileName' | 'serializeCreateRequest' | 'encryptFilesAndSerialize' | 'decryptOpenFileResponse' | 'decryptOpenSecretResponse' | 'decryptCachedFile' | 'clearCachedFiles' | 'solveCreateProof' | 'cancelProof';
interface RequestMessage {
  id: number;
  operation: Operation;
  payload: unknown;
  clientKey: string | Uint8Array;
  filename?: string;
}
interface ProgressMessage { id: number; type: 'progress'; current: number; total: number; phase: FileCryptoPhase; filename?: string }
interface ResultMessage { id: number; type: 'result'; result: unknown }
interface ErrorMessage { id: number; type: 'error'; error: string }
type ResponseMessage = ProgressMessage | ResultMessage | ErrorMessage;
interface CachedSecret { files: Map<string, { opened: OpenedFile; filename: string }> }

const workerScope = globalThis as unknown as {
  onmessage: ((event: MessageEvent<RequestMessage>) => void) | null;
  postMessage(message: ResponseMessage, transfer?: Transferable[]): void;
};
const cachedSecrets = new Map<string, CachedSecret>();
const cancelledProofs = new Set<number>();

async function processRequest(data: RequestMessage): Promise<void> {
  const { id, operation, payload, clientKey, filename } = data;
  let current = 1;
  let total = 1;
  let progressFilename = filename;
  const reportProgress = (phase: FileCryptoPhase): void => {
    workerScope.postMessage({ id, type: 'progress', current, total, phase, filename: progressFilename });
  };

  try {
    let result: unknown;
    switch (operation) {
      case 'solveCreateProof': {
        const challenge = payload as { challengeId: string; nonce: string; difficultyBits: number };
        result = await solveCreateProof(challenge, () => cancelledProofs.has(id));
        break;
      }
      case 'encryptFile':
        result = await encryptFile(payload as File, clientKey as Uint8Array, reportProgress);
        break;
      case 'decryptFile':
        result = await decryptFile(payload as Parameters<typeof decryptFile>[0], clientKey as string, reportProgress);
        break;
      case 'decryptFileName':
        result = await decryptFileName(payload as EncryptedFileMetadata, clientKey as string, reportProgress);
        break;
      case 'serializeCreateRequest':
        reportProgress('encoding');
        result = new TextEncoder().encode(JSON.stringify(payload)).buffer;
        break;
      case 'encryptFilesAndSerialize': {
        const input = payload as { request: Record<string, unknown>; files: File[] };
        const encryptedFiles: EncryptedFile[] = [];
        total = Math.max(1, input.files.length);
        for (let index = 0; index < input.files.length; index++) {
          current = index + 1;
          const file = input.files[index]!;
          progressFilename = file.name;
          encryptedFiles.push(await encryptFile(file, clientKey as Uint8Array, reportProgress));
        }
        current = total;
        progressFilename = undefined;
        reportProgress('encoding');
        result = new TextEncoder().encode(JSON.stringify({ ...input.request, files: encryptedFiles })).buffer;
        break;
      }
      case 'decryptOpenFileResponse': {
        const response = JSON.parse(new TextDecoder().decode(payload as ArrayBuffer)) as { protocolVersion: number; file: OpenedFile };
        if (response.protocolVersion !== 1) throw new Error('unsupported protocol');
        progressFilename = response.file.extension;
        const name = await decryptFileName(response.file, clientKey as string, reportProgress);
        progressFilename = name;
        const plaintext = await decryptFile(response.file, clientKey as string, reportProgress);
        result = { filename: name, mimeType: response.file.mimeType, data: plaintext.buffer };
        break;
      }
      case 'decryptOpenSecretResponse': {
        const opened = JSON.parse(new TextDecoder().decode(payload as ArrayBuffer)) as EncryptedPayload;
        if (opened.protocolVersion !== 1) throw new Error('unsupported protocol');
        const message = opened.message ? await decryptMessage(opened, clientKey as string) : null;
        const token = encodeBase64Url(crypto.getRandomValues(new Uint8Array(24)));
        const files = new Map<string, { opened: OpenedFile; filename: string }>();
        const metadata: Array<{ id: string; extension: string; name: string; mimeType: string; size: number }> = [];
        total = Math.max(1, opened.files.length);
        for (let index = 0; index < opened.files.length; index++) {
          current = index + 1;
          const file = opened.files[index]!;
          progressFilename = file.extension;
          const name = await decryptFileName(file, clientKey as string, reportProgress);
          files.set(file.id, { opened: file, filename: name });
          metadata.push({ id: file.id, extension: file.extension, name, mimeType: file.mimeType, size: file.size });
          progressFilename = name;
        }
        cachedSecrets.set(token, { files });
        result = { token, message, files: metadata };
        break;
      }
      case 'decryptCachedFile': {
        const input = payload as { token: string; fileId: string };
        const cached = cachedSecrets.get(input.token)?.files.get(input.fileId);
        if (!cached) throw new Error('cached file is unavailable');
        progressFilename = filename ?? cached.filename;
        const plaintext = await decryptFile(cached.opened, clientKey as string, reportProgress);
        result = { filename: filename ?? cached.filename, mimeType: cached.opened.mimeType, data: plaintext.buffer };
        break;
      }
      case 'clearCachedFiles':
        cachedSecrets.delete(payload as string);
        result = undefined;
        break;
    }

    if (result instanceof Uint8Array) {
      workerScope.postMessage({ id, type: 'result', result }, [result.buffer]);
    } else if (result instanceof ArrayBuffer) {
      workerScope.postMessage({ id, type: 'result', result }, [result]);
    } else if (typeof result === 'object' && result !== null && 'data' in result && result.data instanceof ArrayBuffer) {
      workerScope.postMessage({ id, type: 'result', result }, [result.data]);
    } else {
      workerScope.postMessage({ id, type: 'result', result });
    }
  } catch (error) {
    workerScope.postMessage({ id, type: 'error', error: error instanceof Error ? error.message : 'File operation failed' });
  } finally {
    cancelledProofs.delete(id);
  }
}

// File operations are serialized to bound memory use when callers submit a batch concurrently.
let queuedOperations = Promise.resolve();
workerScope.onmessage = ({ data }) => {
  if (data.operation === 'cancelProof') { cancelledProofs.add(data.payload as number); return; }
  queuedOperations = queuedOperations.then(() => processRequest(data));
};

