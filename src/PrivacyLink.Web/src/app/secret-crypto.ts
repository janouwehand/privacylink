export interface EncryptedMessage { nonce: string; ciphertext: string }
export interface EncryptedFile { id: string; extension: string; nameNonce: string; nameCiphertext: string; mimeType: string; size: number; nonce: string; ciphertext: string }
export interface EncryptedFileMetadata { id: string; extension: string; nameNonce: string; nameCiphertext: string; mimeType: string; size: number }
export interface OpenedFile extends EncryptedFileMetadata { nonce: string; ciphertext: string }
export interface EncryptedPayload { protocolVersion: number; message: EncryptedMessage | null; files: OpenedFile[] }

const info = new TextEncoder().encode('privacylink-message-v1');
const aad = new TextEncoder().encode('privacylink:message:v1');
const salt = new Uint8Array(32);

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function decodeCanonical(value: string, expectedBytes?: number): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid base64url');
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
  const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
  if (encodeBase64Url(bytes) !== value || (expectedBytes !== undefined && bytes.length !== expectedBytes)) throw new Error('invalid canonical encoding');
  return bytes;
}

export async function derivePasswordToken(password: string, clientKey: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const token = await crypto.subtle.sign('HMAC', key, decodeCanonical(clientKey, 32) as BufferSource);
  return encodeBase64Url(new Uint8Array(token));
}

async function deriveKey(clientKey: Uint8Array, purpose: Uint8Array = info): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', clientKey as BufferSource, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: salt as BufferSource, info: purpose as BufferSource }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function encryptFile(file: File, clientKey: Uint8Array): Promise<EncryptedFile> {
  const idBytes = crypto.getRandomValues(new Uint8Array(16));
  const id = encodeBase64Url(idBytes);
  const dot = file.name.lastIndexOf('.');
  const rawExtension = dot >= 0 ? file.name.slice(dot) : '';
  const extension = rawExtension.toLowerCase();
  const stem = dot >= 0 ? file.name.slice(0, dot) : file.name;
  if (!/^\.[a-z0-9]{1,15}$/.test(extension)) throw new Error('invalid extension');
  const encodedId = encodeBase64Url(idBytes);
  const encoder = new TextEncoder();
  const nameNonce = crypto.getRandomValues(new Uint8Array(12));
  const nameKey = await deriveKey(clientKey, encoder.encode(`privacylink-filename:${encodedId}:${extension}`));
  const nameCiphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nameNonce, additionalData: encoder.encode(`privacylink:filename:${encodedId}:${extension}`), tagLength: 128 }, nameKey, encoder.encode(stem)));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(clientKey, new TextEncoder().encode(`privacylink-file:${id}`));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: encoder.encode(`privacylink:file:${id}:${extension}`), tagLength: 128 }, key, await file.arrayBuffer()));
  return { id, extension, nameNonce: encodeBase64Url(nameNonce), nameCiphertext: encodeBase64Url(nameCiphertext), mimeType: file.type || 'application/octet-stream', size: file.size, nonce: encodeBase64Url(nonce), ciphertext: encodeBase64Url(ciphertext) };
}

export async function decryptFile(payload: { id: string; extension: string; nonce: string; ciphertext: string }, clientKey: string): Promise<Uint8Array> {
  const idBytes = decodeCanonical(payload.id, 16);
  const id = encodeBase64Url(idBytes);
  if (!/^\.[a-z0-9]{1,15}$/.test(payload.extension)) throw new Error('invalid extension');
  const key = await deriveKey(decodeCanonical(clientKey, 32), new TextEncoder().encode(`privacylink-file:${id}`));
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decodeCanonical(payload.nonce, 12) as BufferSource, additionalData: new TextEncoder().encode(`privacylink:file:${id}:${payload.extension}`), tagLength: 128 }, key, decodeCanonical(payload.ciphertext) as BufferSource);
  return new Uint8Array(plaintext);
}

export async function decryptFileName(metadata: EncryptedFileMetadata, clientKey: string): Promise<string> {
  const id = encodeBase64Url(decodeCanonical(metadata.id, 16));
  if (!/^\.[a-z0-9]{1,15}$/.test(metadata.extension)) throw new Error('invalid extension');
  const encoder = new TextEncoder();
  const key = await deriveKey(decodeCanonical(clientKey, 32), encoder.encode(`privacylink-filename:${id}:${metadata.extension}`));
  const stem = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decodeCanonical(metadata.nameNonce, 12) as BufferSource, additionalData: encoder.encode(`privacylink:filename:${id}:${metadata.extension}`), tagLength: 128 }, key, decodeCanonical(metadata.nameCiphertext) as BufferSource);
  const decoded = new TextDecoder('utf-8', { fatal: true }).decode(stem);
  if (decoded.includes('/') || decoded.includes('\\') || decoded.includes(':') || /[\0-\x1f]/.test(decoded) || decoded.endsWith(' ') || decoded.endsWith('.')) throw new Error('invalid filename');
  return `${decoded}${metadata.extension}`;
}

export async function encryptMessage(message: string): Promise<{ clientKey: string; message: EncryptedMessage }> {
  const clientKey = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(clientKey);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, new TextEncoder().encode(message)));
  return { clientKey: encodeBase64Url(clientKey), message: { nonce: encodeBase64Url(nonce), ciphertext: encodeBase64Url(ciphertext) } };
}

export async function decryptMessage(payload: EncryptedPayload, clientKey: string): Promise<string> {
  if (payload.protocolVersion !== 1) throw new Error('unsupported protocol');
  if (!payload.message) throw new Error('missing message');
  const key = await deriveKey(decodeCanonical(clientKey, 32));
  const nonce = decodeCanonical(payload.message.nonce, 12);
  const ciphertext = decodeCanonical(payload.message.ciphertext);
  if (ciphertext.length < 17) throw new Error('invalid ciphertext');
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: 128 }, key, ciphertext as BufferSource);
  return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
}
