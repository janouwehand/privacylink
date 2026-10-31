import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const CWS_UPLOAD_STATE = Object.freeze({
  succeeded: 'SUCCEEDED',
  legacySucceeded: 'SUCCESS',
  inProgress: ['IN_PROGRESS', 'UPLOAD_IN_PROGRESS'],
  failed: ['FAILED', 'FAILURE', 'UPLOAD_FAILED']
});

const CWS_SUBMISSION_STATES = new Set(['PENDING_REVIEW', 'STAGED', 'PUBLISHED', 'PUBLISHED_TO_TESTERS']);

function defaultSleep(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

export function createChromeWebStoreClient({
  fetchImpl = globalThis.fetch,
  readFileImpl = readFile,
  env = process.env,
  log = console.log,
  sleep = defaultSleep,
  now = () => Date.now()
} = {}) {
  const sensitiveValues = [env.CWS_OAUTH_CLIENT_SECRET, env.CWS_OAUTH_REFRESH_TOKEN].filter(Boolean);

  function redact(value) {
    return sensitiveValues.reduce((redacted, secret) => redacted.replaceAll(secret, '[redacted]'), value);
  }

  function required(name) {
    const value = env[name];
    if (!value?.trim()) throw new Error(`required protected environment secret ${name} is missing`);
    return value.trim();
  }

  function endpoint(prefix, publisherId, extensionId, method) {
    const apiPrefix = prefix ? `${prefix}/` : '';
    return `https://chromewebstore.googleapis.com/${apiPrefix}v2/publishers/${encodeURIComponent(publisherId)}/items/${encodeURIComponent(extensionId)}:${method}`;
  }

  async function getAccessToken() {
    const body = new URLSearchParams({
      client_id: required('CWS_OAUTH_CLIENT_ID'),
      client_secret: required('CWS_OAUTH_CLIENT_SECRET'),
      refresh_token: required('CWS_OAUTH_REFRESH_TOKEN'),
      grant_type: 'refresh_token'
    });
    const response = await fetchImpl('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });
    const responseText = await response.text();
    if (!response.ok) throw new Error(`OAuth token refresh returned HTTP ${response.status}: ${redact(responseText).slice(0, 2000)}`);

    let tokenResponse;
    try {
      tokenResponse = JSON.parse(responseText);
    } catch {
      throw new Error('OAuth token refresh returned invalid JSON');
    }
    if (typeof tokenResponse.access_token !== 'string' || !tokenResponse.access_token) {
      throw new Error('OAuth token refresh response did not include an access token');
    }
    sensitiveValues.push(tokenResponse.access_token);
    return tokenResponse.access_token;
  }

  async function storeRequest(url, token, init = {}) {
    const response = await fetchImpl(url, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, ...init.headers }
    });
    const body = redact(await response.text());
    if (!response.ok) throw new Error(`Store API returned HTTP ${response.status}: ${body.slice(0, 2000)}`);

    if (!body.trim()) return {};
    try {
      return JSON.parse(body);
    } catch {
      throw new Error('Store API returned an unrecognized response');
    }
  }

  async function upload(crxFile) {
    if (!crxFile) throw new Error('the signed CRX file path was not provided');
    const publisherId = required('CWS_PUBLISHER_ID');
    const extensionId = required('CWS_EXTENSION_ID');
    const token = await getAccessToken();
    const crx = await readFileImpl(crxFile);
    const uploadUrl = endpoint('upload', publisherId, extensionId, 'upload');
    let status = await storeRequest(uploadUrl, token, {
      method: 'POST',
      headers: {
        'X-Goog-Upload-Protocol': 'raw',
        'X-Goog-Upload-File-Name': path.basename(crxFile),
        'Content-Type': 'application/octet-stream'
      },
      body: crx
    });

    const stateOf = value => value.uploadState ?? value.lastAsyncUploadState ?? value.state;
    let state = stateOf(status);
    if (CWS_UPLOAD_STATE.failed.includes(state)) throw new Error(`Store rejected the CRX upload (state ${state})`);

    if (CWS_UPLOAD_STATE.inProgress.includes(state)) {
      const statusUrl = endpoint('', publisherId, extensionId, 'fetchStatus');
      const deadline = now() + 120_000;
      do {
        await sleep(5000);
        status = await storeRequest(statusUrl, token, { method: 'GET' });
        state = stateOf(status);
        if (CWS_UPLOAD_STATE.failed.includes(state)) throw new Error(`Store rejected the CRX upload (state ${state})`);
      } while (CWS_UPLOAD_STATE.inProgress.includes(state) && now() < deadline);
      if (CWS_UPLOAD_STATE.inProgress.includes(state)) {
        throw new Error('Store upload remained in progress after two minutes');
      }
    }

    if (state !== CWS_UPLOAD_STATE.succeeded && state !== CWS_UPLOAD_STATE.legacySucceeded) {
      throw new Error(`Store did not confirm successful CRX upload (state ${state ?? 'missing'})`);
    }

    log(`Chrome Web Store accepted the signed CRX upload (upload state ${state}).`);
  }

  async function submit() {
    const publisherId = required('CWS_PUBLISHER_ID');
    const extensionId = required('CWS_EXTENSION_ID');
    const token = await getAccessToken();
    const submitUrl = endpoint('', publisherId, extensionId, 'publish');
    const result = await storeRequest(submitUrl, token, { method: 'POST' });
    if (!CWS_SUBMISSION_STATES.has(result.state)) {
      throw new Error(`Store did not confirm submission acceptance (state ${result.state ?? 'missing'})`);
    }
    log('Chrome Web Store accepted the submission request. Check the Store review and published status separately; this workflow reports request acceptance only.');
  }

  return { upload, submit };
}

export async function runChromeWebStoreCommand(args = process.argv.slice(2), dependencies = {}) {
  const [operation, archivePath] = args;
  const errorLog = dependencies.errorLog ?? console.error;
  if (!['upload', 'submit'].includes(operation)) {
    errorLog('Usage: node scripts/chrome-web-store.mjs <upload CRX_FILE|submit>');
    return 64;
  }

  const failureLabel = operation === 'upload' ? 'Chrome Web Store upload failed' : 'Chrome Web Store submission failed';
  const client = createChromeWebStoreClient(dependencies);
  try {
    if (operation === 'upload') await client.upload(archivePath);
    else await client.submit();
    return 0;
  } catch (error) {
    errorLog(`${failureLabel}: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : undefined;
if (invokedPath === import.meta.url) {
  process.exitCode = await runChromeWebStoreCommand();
}
