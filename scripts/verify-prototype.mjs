#!/usr/bin/env node
// Independent HTTP/protocol smoke test. No dependencies; Node 24+.
// Run: node scripts/verify-prototype.mjs [http://localhost:5080]
// Uses disposable random content. Never print messages, keys, IDs or full URLs.

import assert from 'node:assert/strict';
import { randomBytes, webcrypto } from 'node:crypto';

const base = new URL(process.argv[2] ?? 'http://localhost:5080');
if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) {
  throw new Error('Expected a plain HTTP(S) API base URL');
}
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const fromB64 = value => Buffer.from(value, 'base64url');
const info = encoder.encode('privacylink-message-v1');
const aad = encoder.encode('privacylink:message:v1');
const zeroSalt = new Uint8Array(32);
let checks = 0;

function canonical(value, size) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value) &&
    fromB64(value).length === size && b64(fromB64(value)) === value;
}

function headers(response) {
  assert.match(response.headers.get('cache-control') ?? '', /\bno-store\b/i);
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
}

async function request(path, method = 'GET', value, extraHeaders = {}) {
  const options = { method, headers: { ...extraHeaders }, redirect: 'manual' };
  if (value !== undefined) {
    options.headers['content-type'] = 'application/json';
    options.body = JSON.stringify(value);
  }
  const response = await fetch(new URL(path, base), options);
  headers(response);
  const raw = await response.text();
  let json;
  try { json = raw ? JSON.parse(raw) : undefined; } catch { throw new Error(`Non-JSON response: HTTP ${response.status}`); }
  return { response, json, raw };
}

function expectStatus(actual, status, label) {
  assert.equal(actual.response.status, status, `${label}: unexpected HTTP status`);
  checks++;
}

async function expectRejected(path, method, value, status, label, extraHeaders = {}) {
  const result = await request(path, method, value, extraHeaders);
  expectStatus(result, status, label);
  if (result.json !== undefined) assert.equal(typeof result.json.code, 'string', `${label}: error code`);
  return result;
}

async function derive(keyBytes) {
  const hkdf = await webcrypto.subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveKey']);
  return webcrypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: zeroSalt, info }, hkdf,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function decrypt(key, message, overrides = {}) {
  const nonce = overrides.nonce ?? fromB64(message.nonce);
  const ciphertext = overrides.ciphertext ?? fromB64(message.ciphertext);
  const additionalData = overrides.aad ?? aad;
  const plaintext = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128 }, key, ciphertext);
  return decoder.decode(plaintext);
}

async function main() {
  const secret = `verification-${b64(randomBytes(18))}`;
  const clientKey = randomBytes(32);
  const nonce = randomBytes(12);
  const key = await derive(clientKey);
  const ciphertext = new Uint8Array(await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, encoder.encode(secret)));
  const create = { protocolVersion: 1, expiry: '7d', message: { nonce: b64(nonce), ciphertext: b64(ciphertext) }, files: [] };
  assert(canonical(b64(clientKey), 32));
  assert(canonical(create.message.nonce, 12));
  assert(!canonical(`${b64(clientKey)}=`, 32), 'padded client key accepted');
  assert(!canonical(`${create.message.nonce}=`, 12), 'padded nonce accepted');
  assert(!canonical('*', 32), 'malformed client key accepted');
  assert(!JSON.stringify(create).includes(secret));
  assert(!JSON.stringify(create).includes(b64(clientKey)));
  checks += 7;

  const created = await request('/api/v1/secrets', 'POST', create);
  expectStatus(created, 201, 'create');
  assert(canonical(created.json?.id, 16), 'noncanonical secret ID');
  assert.equal(created.json.passwordProtected, false);
  assert(Number.isFinite(Date.parse(created.json.expiresAt)), 'invalid expiry timestamp');
  checks += 3;
  const id = created.json.id;
  assert(!`/api/v1/secrets/${id}`.includes(b64(clientKey)));
  checks++;

  const meta = await request(`/api/v1/secrets/${id}`);
  expectStatus(meta, 200, 'metadata');
  assert.deepEqual(meta.json.files, []);
  assert.equal(meta.json.protocolVersion, 1);
  assert.equal(meta.json.hasMessage, true);
  assert.equal(meta.json.passwordProtected, false);
  assert(!meta.raw.includes(create.message.ciphertext), 'metadata disclosed ciphertext');
  checks += 5;

  for (let i = 0; i < 2; i++) {
    const opened = await request(`/api/v1/secrets/${id}/open`, 'POST');
    expectStatus(opened, 200, 'open');
    assert.equal(opened.json.protocolVersion, 1);
    assert.equal(opened.json.message.nonce, create.message.nonce);
    assert.equal(opened.json.message.ciphertext, create.message.ciphertext);
    assert.equal(await decrypt(key, opened.json.message), secret);
    checks += 4;
  }

  const wrongKey = await derive(randomBytes(32));
  await assert.rejects(decrypt(wrongKey, create.message), 'wrong key accepted');
  const modified = Uint8Array.from(ciphertext);
  modified[0] ^= 1;
  await assert.rejects(decrypt(key, create.message, { ciphertext: modified }), 'tampered ciphertext accepted');
  const changedNonce = Uint8Array.from(nonce);
  changedNonce[0] ^= 1;
  await assert.rejects(decrypt(key, create.message, { nonce: changedNonce }), 'wrong nonce accepted');
  await assert.rejects(decrypt(key, create.message, { aad: encoder.encode('wrong-context') }), 'wrong AAD accepted');
  checks += 4;

  const unknownId = b64(randomBytes(16));
  await expectRejected(`/api/v1/secrets/${unknownId}`, 'GET', undefined, 404, 'unknown metadata');
  await expectRejected(`/api/v1/secrets/${unknownId}/open`, 'POST', undefined, 404, 'unknown open');
  await expectRejected('/api/v1/secrets', 'POST', { ...create, expiry: '2d' }, 400, 'invalid expiry');
  await expectRejected('/api/v1/secrets', 'POST', { ...create, protocolVersion: 2 }, 400, 'invalid version');
  await expectRejected('/api/v1/secrets', 'POST', { ...create, message: { ...create.message, nonce: b64(randomBytes(8)) } }, 400, 'invalid nonce');
  await expectRejected('/api/v1/secrets', 'POST', { ...create, extra: true }, 400, 'unknown field');
  await expectRejected('/api/v1/secrets', 'POST', { ...create, files: [{}] }, 400, 'invalid file');
  await expectRejected('/api/v1/secrets', 'POST', { ...create, password: '' }, 400, 'invalid password');
  const sameOrigin = await request('/api/v1/secrets', 'POST', create, { origin: base.origin });
  expectStatus(sameOrigin, 201, 'same-origin create');
  await expectRejected('/api/v1/secrets', 'POST', create, 403, 'foreign origin', { origin: 'https://foreign.invalid' });
  await expectRejected('/api/v1/secrets', 'POST', create, 403, 'cross-site fetch', { 'sec-fetch-site': 'cross-site' });
  await expectRejected(`/api/v1/secrets/${id}/open`, 'POST', { unexpected: true }, 400, 'open with body');
  const wrongMedia = await fetch(new URL('/api/v1/secrets', base), {
    method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'not JSON', redirect: 'manual'
  });
  headers(wrongMedia);
  expectStatus({ response: wrongMedia }, 415, 'unsupported media type');
  await expectRejected('/api/v1/secrets', 'POST', {
    ...create, message: { ...create.message, ciphertext: b64(randomBytes(262145 + 16)) }
  }, 413, 'oversized decoded message');
  const oversizedRaw = await fetch(new URL('/api/v1/secrets', base), {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: ' '.repeat(384 * 1024 + 1), redirect: 'manual'
  });
  headers(oversizedRaw);
  expectStatus({ response: oversizedRaw }, 413, 'oversized raw request');

  console.log(`PASS: ${checks} protocol assertions against ${base.origin}`);
}

main().catch(error => {
  // Deliberately avoid raw response bodies and assertion values, which can contain secrets.
  const safe = error?.cause?.code === 'ECONNREFUSED' ? 'API is not listening' :
    error?.name === 'AssertionError' ? error.message.split(':')[0] :
    error?.message?.startsWith('Non-JSON response') ? error.message : 'request or verification failed';
  console.error(`FAIL: ${safe}. Start the API, then run node scripts/verify-prototype.mjs [base-url].`);
  process.exitCode = 1;
});
