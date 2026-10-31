import assert from 'node:assert/strict';
import test from 'node:test';
import { createChromeWebStoreClient, runChromeWebStoreCommand } from './chrome-web-store.mjs';

const testEnvironment = {
  CWS_EXTENSION_ID: 'test-item-id',
  CWS_PUBLISHER_ID: 'test-publisher-id',
  CWS_OAUTH_CLIENT_ID: 'test-client-id',
  CWS_OAUTH_CLIENT_SECRET: 'test-client-secret',
  CWS_OAUTH_REFRESH_TOKEN: 'test-refresh-token'
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function clientWith(fetchImpl, options = {}) {
  const logs = [];
  const waits = [];
  const client = createChromeWebStoreClient({
    fetchImpl,
    env: testEnvironment,
    readFileImpl: async () => Buffer.from('test-signed-crx-bytes'),
    log: message => logs.push(message),
    sleep: async milliseconds => waits.push(milliseconds),
    now: () => 0,
    ...options
  });
  return { client, logs, waits };
}

test('refreshes an OAuth token and uploads the signed CRX as a raw Web Store v2 package', async () => {
  const calls = [];
  const { client, logs } = clientWith(async (url, init) => {
    calls.push({ url, init });
    if (url === 'https://oauth2.googleapis.com/token') return jsonResponse({ access_token: 'test-access-token' });
    return jsonResponse({ itemId: 'test-item-id', crxVersion: '0.1.0', uploadState: 'SUCCEEDED' });
  });

  await client.upload('signed-extension.crx');

  assert.equal(calls.length, 2);
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.deepEqual(Object.fromEntries(calls[0].init.body), {
    client_id: 'test-client-id',
    client_secret: 'test-client-secret',
    refresh_token: 'test-refresh-token',
    grant_type: 'refresh_token'
  });
  assert.equal(calls[1].url, 'https://chromewebstore.googleapis.com/upload/v2/publishers/test-publisher-id/items/test-item-id:upload');
  assert.equal(calls[1].init.method, 'POST');
  assert.equal(calls[1].init.headers.Authorization, 'Bearer test-access-token');
  assert.equal(calls[1].init.headers['X-Goog-Upload-Protocol'], 'raw');
  assert.equal(calls[1].init.headers['X-Goog-Upload-File-Name'], 'signed-extension.crx');
  assert.equal(calls[1].init.headers['Content-Type'], 'application/octet-stream');
  assert.deepEqual(calls[1].init.body, Buffer.from('test-signed-crx-bytes'));
  assert.deepEqual(logs, ['Chrome Web Store accepted the signed CRX upload (upload state SUCCEEDED).']);
});

test('polls an asynchronous upload until fetchStatus confirms SUCCEEDED', async () => {
  const calls = [];
  const { client, waits } = clientWith(async (url, init) => {
    calls.push({ url, init });
    if (url === 'https://oauth2.googleapis.com/token') return jsonResponse({ access_token: 'test-access-token' });
    if (url.includes(':upload')) return jsonResponse({ uploadState: 'IN_PROGRESS' });
    return jsonResponse({ lastAsyncUploadState: 'SUCCEEDED' });
  });

  await client.upload('signed-extension.crx');

  assert.equal(calls.length, 3);
  assert.equal(calls[2].url, 'https://chromewebstore.googleapis.com/v2/publishers/test-publisher-id/items/test-item-id:fetchStatus');
  assert.equal(calls[2].init.method, 'GET');
  assert.deepEqual(waits, [5000]);
});

test('reports a rejected upload state distinctly and does not continue polling', async () => {
  const errors = [];
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    if (url === 'https://oauth2.googleapis.com/token') return jsonResponse({ access_token: 'test-access-token' });
    return jsonResponse({ uploadState: 'FAILED' });
  };

  const result = await runChromeWebStoreCommand(['upload', 'signed-extension.crx'], {
    fetchImpl,
    env: testEnvironment,
    readFileImpl: async () => Buffer.from('test-signed-crx-bytes'),
    errorLog: message => errors.push(message)
  });

  assert.equal(result, 1);
  assert.equal(calls.length, 2);
  assert.deepEqual(errors, ['Chrome Web Store upload failed: Store rejected the CRX upload (state FAILED)']);
});

test('reports non-2xx OAuth and Store API responses as upload failures', async t => {
  await t.test('OAuth refresh HTTP error', async () => {
    const errors = [];
    const result = await runChromeWebStoreCommand(['upload', 'signed-extension.crx'], {
      fetchImpl: async () => jsonResponse({ error: 'invalid_grant' }, 401),
      env: testEnvironment,
      errorLog: message => errors.push(message)
    });
    assert.equal(result, 1);
    assert.match(errors[0], /^Chrome Web Store upload failed: OAuth token refresh returned HTTP 401:/);
  });

  await t.test('Store upload HTTP error', async () => {
    const errors = [];
    let call = 0;
    const result = await runChromeWebStoreCommand(['upload', 'signed-extension.crx'], {
      fetchImpl: async () => ++call === 1
        ? jsonResponse({ access_token: 'test-access-token' })
        : jsonResponse({ error: { message: 'package invalid' } }, 422),
      env: testEnvironment,
      readFileImpl: async () => Buffer.from('test-signed-crx-bytes'),
      errorLog: message => errors.push(message)
    });
    assert.equal(result, 1);
    assert.match(errors[0], /^Chrome Web Store upload failed: Store API returned HTTP 422:/);
  });
});

test('accepts a submission request while leaving Store review status separate', async () => {
  const calls = [];
  const { client, logs } = clientWith(async (url, init) => {
    calls.push({ url, init });
    return url === 'https://oauth2.googleapis.com/token'
      ? jsonResponse({ access_token: 'test-access-token' })
      : jsonResponse({ state: 'PENDING_REVIEW' });
  });

  await client.submit();

  assert.equal(calls.length, 2);
  assert.equal(calls[1].url, 'https://chromewebstore.googleapis.com/v2/publishers/test-publisher-id/items/test-item-id:publish');
  assert.equal(calls[1].init.method, 'POST');
  assert.equal(calls[1].init.headers.Authorization, 'Bearer test-access-token');
  assert.equal(calls[1].init.body, undefined);
  assert.match(logs[0], /reports request acceptance only/);
  assert.doesNotMatch(logs[0], /was published/i);
});

test('reports a rejected Store submission as a submission failure', async () => {
  const errors = [];
  let call = 0;
  const result = await runChromeWebStoreCommand(['submit'], {
    fetchImpl: async () => ++call === 1
      ? jsonResponse({ access_token: 'test-access-token' })
      : jsonResponse({ state: 'REJECTED' }),
    env: testEnvironment,
    errorLog: message => errors.push(message)
  });

  assert.equal(result, 1);
  assert.equal(call, 2);
  assert.deepEqual(errors, ['Chrome Web Store submission failed: Store did not confirm submission acceptance (state REJECTED)']);
});

test('importing the client does not issue requests', async () => {
  let requestCount = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    requestCount++;
    throw new Error('Import unexpectedly attempted a network request.');
  };
  try {
    const imported = await import(`./chrome-web-store.mjs?import-probe=${Date.now()}`);
    assert.equal(typeof imported.createChromeWebStoreClient, 'function');
    assert.equal(typeof imported.runChromeWebStoreCommand, 'function');
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(requestCount, 0);
});
