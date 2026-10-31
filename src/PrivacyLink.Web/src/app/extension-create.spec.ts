import { afterEach, describe, expect, it, vi } from 'vitest';
import { decryptFile, decryptMessage, derivePasswordToken, encryptFile } from '../../../PrivacyLink.Client/src';
import { mountCreateForm, privacyLinkCreateApi, type CreateApi, type CreateDependencies, type FileUploadPolicy } from '../../extension/src/create-secret';

const popupMarkup = `
  <form id="create-form">
    <textarea id="secret-message"></textarea>
    <input id="secret-files" type="file" multiple />
    <p id="file-limit-note"></p><ul id="selected-files"></ul><p id="file-error" hidden></p>
    <input id="secret-password-enabled" type="checkbox" /><div id="password-container" hidden><input id="secret-password" /></div>
    <input id="email-verification-enabled" type="checkbox" /><div id="recipient-email-container" hidden><input id="recipient-email" type="email" /></div>
    <select id="secret-expiry"><option value="1d">1 day</option><option value="7d" selected>7 days</option><option value="14d">14 days</option></select>
    <button id="create-button" type="submit">Create secret</button>
  </form>
  <p id="error-message" hidden></p>
  <section id="success-panel" hidden>
    <p id="expiry-message"></p><input id="share-link" />
    <button id="copy-link-button" type="button">Copy share link</button><p id="copy-status"></p>
    <div id="success-password" hidden><input id="result-password" /><button id="copy-password-button" type="button">Copy access code</button><p id="password-copy-status"></p></div>
  </section>`;
const challenge = {
  version: 1,
  challengeId: 'extension-test-challenge',
  nonce: 'extension-test-nonce',
  difficultyBits: 0,
  expiresAt: 1_900_000_000,
  signature: 'server-signature'
};
const uploadPolicy: FileUploadPolicy = {
  maxFiles: 15,
  maxTotalFileBytes: 75 * 1024 * 1024,
  allowedFileExtensions: ['.txt', '.pdf']
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  document.body.replaceChildren();
});

function makeApi(overrides: Partial<CreateApi> = {}) {
  const created = { id: 'AAAAAAAAAAAAAAAAAAAAAA', expiresAt: '2030-01-08T12:00:00Z', passwordProtected: false, revokeToken: 'revoke-token-must-not-be-kept' };
  const requests: Array<{ request?: unknown; body?: ArrayBuffer; proof: string }> = [];
  const api: CreateApi = {
    getFileUploadPolicy: vi.fn(async () => uploadPolicy),
    getCreateChallenge: vi.fn(async () => challenge),
    create: vi.fn(async (request, proof) => { requests.push({ request, proof }); return created; }),
    createSerialized: vi.fn(async (body, proof) => { requests.push({ body, proof }); return created; }),
    ...overrides
  };
  return { api, requests, created };
}

const fileCrypto: CreateDependencies['fileCrypto'] = {
  async encryptFilesAndSerialize(request, files, clientKey) {
    const encryptedFiles = await Promise.all(files.map(file => encryptFile(file, clientKey)));
    const body = JSON.stringify({ ...request, files: encryptedFiles });
    const encoded = new TextEncoder().encode(body);
    return encoded.buffer.slice(encoded.byteOffset, encoded.byteOffset + encoded.byteLength);
  }
};

function mountPopup(api: CreateApi, copyText: (value: string) => Promise<void>, useFileCrypto = false) {
  document.body.innerHTML = popupMarkup;
  mountCreateForm(document, { api, copyText, ...(useFileCrypto ? { fileCrypto } : {}) });
  return document;
}

async function waitForPolicy(popup: ParentNode = document): Promise<void> {
  await vi.waitFor(() => expect(popup.querySelector<HTMLElement>('#file-limit-note')!.textContent).toContain('Allowed types'));
}

function selectFiles(popup: ParentNode, files: File[]): void {
  const input = popup.querySelector<HTMLInputElement>('#secret-files')!;
  Object.defineProperty(input, 'files', { configurable: true, value: files });
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

async function submit(popup: ParentNode = document): Promise<void> {
  popup.querySelector<HTMLFormElement>('#create-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(popup.querySelector<HTMLButtonElement>('#create-button')!.disabled).toBe(false));
}

describe('PrivacyLink extension create popup', () => {
  it('creates encrypted text with the selected expiry, a fresh create proof, and a canonical share link', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, init });
      if (url.endsWith('/capabilities')) return new Response(JSON.stringify(uploadPolicy), { status: 200 });
      if (url.endsWith('/create-challenge')) return new Response(JSON.stringify(challenge), { status: 200 });
      return new Response(JSON.stringify({
        id: 'AAAAAAAAAAAAAAAAAAAAAA', expiresAt: '2030-01-08T12:00:00Z', passwordProtected: false,
        revokeToken: 'revoke-token-must-not-be-kept'
      }), { status: 201 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const copied: string[] = [];
    const popup = mountPopup(privacyLinkCreateApi, async value => { copied.push(value); });
    await waitForPolicy(popup);

    const plaintext = '  secret text 🔐  ';
    popup.querySelector<HTMLTextAreaElement>('#secret-message')!.value = plaintext;
    popup.querySelector<HTMLSelectElement>('#secret-expiry')!.value = '14d';
    await submit(popup);

    expect(calls.map(call => new URL(call.url).pathname)).toEqual([
      '/api/v1/capabilities', '/api/v1/secrets/create-challenge', '/api/v1/secrets'
    ]);
    const createCall = calls[2]!;
    expect(new URL(createCall.url).origin).toBe('https://privacylink.nl');
    expect(createCall.init?.method).toBe('POST');
    expect(createCall.init?.cache).toBe('no-store');
    expect(createCall.init?.referrerPolicy).toBe('no-referrer');
    const requestBody = JSON.parse(String(createCall.init?.body)) as {
      protocolVersion: number; expiry: string; message: { nonce: string; ciphertext: string }; files: unknown[];
    };
    expect(requestBody).toMatchObject({ protocolVersion: 1, expiry: '14d', files: [] });
    expect(JSON.stringify(requestBody)).not.toContain(plaintext.trim());
    const proof = new Headers(createCall.init?.headers).get('X-PrivacyLink-Proof');
    expect(proof).toBe(`${challenge.challengeId}.${challenge.nonce}.0.${challenge.expiresAt}.${challenge.signature}.0`);

    const linkField = popup.querySelector<HTMLInputElement>('#share-link')!;
    const link = new URL(linkField.value);
    expect(popup.querySelector<HTMLElement>('#success-panel')!.hidden).toBe(false);
    expect(link.origin).toBe('https://privacylink.nl');
    expect(link.pathname).toBe('/s/AAAAAAAAAAAAAAAAAAAAAA');
    expect(link.search).toBe('');
    expect(link.hash).toMatch(/^#[A-Za-z0-9_-]{43}$/);
    expect(JSON.stringify(requestBody)).not.toContain(link.hash.slice(1));
    expect(JSON.stringify(createCall.init?.headers)).not.toContain(link.hash.slice(1));
    expect(await decryptMessage({ protocolVersion: 1, message: requestBody.message, files: [] }, link.hash.slice(1))).toBe(plaintext);

    popup.querySelector<HTMLButtonElement>('#copy-link-button')!.click();
    await vi.waitFor(() => expect(popup.querySelector<HTMLElement>('#copy-status')!.textContent).toBe('Share link copied.'));
    expect(copied).toEqual([linkField.value]);
    expect(popup.querySelector<HTMLTextAreaElement>('#secret-message')!.value).toBe('');
    expect(localStorage.getItem('privacylink.sender-history')).toBeNull();
    expect(document.body.textContent).not.toContain('revoke-token-must-not-be-kept');
  });

  it('creates encrypted files within API-advertised type, count, and total-size limits', async () => {
    const policy = { maxFiles: 2, maxTotalFileBytes: 10, allowedFileExtensions: ['.txt', '.pdf'] };
    const { api, requests } = makeApi({ getFileUploadPolicy: vi.fn(async () => policy) });
    const popup = mountPopup(api, async () => {}, true);
    await waitForPolicy(popup);

    const accepted = [new File(['123456'], 'notes.txt', { type: 'text/plain', lastModified: 1 }), new File(['1234'], 'scan.pdf', { type: 'application/pdf', lastModified: 2 })];
    selectFiles(popup, [
      accepted[0]!,
      new File(['12345'], 'too-large.pdf', { type: 'application/pdf', lastModified: 3 }),
      new File(['bad'], 'payload.exe', { type: 'application/octet-stream', lastModified: 4 }),
      new File([], 'empty.txt', { type: 'text/plain', lastModified: 5 }),
      accepted[1]!,
      new File(['x'], 'third.txt', { type: 'text/plain', lastModified: 6 })
    ]);
    expect(popup.querySelector<HTMLInputElement>('#secret-files')!.accept).toBe('.txt,.pdf');
    expect([...popup.querySelectorAll('#selected-files li')].map(item => item.textContent)).toEqual(expect.arrayContaining([expect.stringContaining('notes.txt'), expect.stringContaining('scan.pdf')]));
    expect(popup.querySelector<HTMLElement>('#file-error')!.textContent).toContain('unsupported file type');
    expect(popup.querySelector<HTMLElement>('#file-error')!.textContent).toContain('empty files');
    expect(popup.querySelector<HTMLElement>('#file-error')!.textContent).toContain('total limit');
    expect(popup.querySelector<HTMLElement>('#file-error')!.textContent).toContain('at most 2 files');

    await submit(popup);
    expect(api.createSerialized).toHaveBeenCalledOnce();
    expect(api.create).not.toHaveBeenCalled();
    const { body, proof } = requests[0]!;
    expect(proof).toBe(`${challenge.challengeId}.${challenge.nonce}.0.${challenge.expiresAt}.${challenge.signature}.0`);
    const serialized = JSON.parse(new TextDecoder().decode(body)) as {
      protocolVersion: number; expiry: string; message: null; files: Array<{ id: string; extension: string; size: number; nonce: string; ciphertext: string }>;
    };
    expect(serialized).toMatchObject({ protocolVersion: 1, expiry: '7d', message: null });
    expect(serialized.files).toHaveLength(2);
    expect(serialized.files.map(file => [file.extension, file.size])).toEqual([['.txt', 6], ['.pdf', 4]]);
    const shareLink = new URL(popup.querySelector<HTMLInputElement>('#share-link')!.value);
    expect(shareLink.pathname).toBe('/s/AAAAAAAAAAAAAAAAAAAAAA');
    expect(JSON.stringify(serialized)).not.toContain(shareLink.hash.slice(1));
    expect(await decryptFile(serialized.files[0]!, shareLink.hash.slice(1)).then(bytes => new TextDecoder().decode(bytes))).toBe('123456');
    expect(popup.querySelector<HTMLElement>('#file-limit-note')!.textContent).toContain('2 files and 1 KB total');
  });

  it('sends the password token and email address using the existing create contract, and only shows the code in the result', async () => {
    const { api, requests } = makeApi();
    const copied: string[] = [];
    const popup = mountPopup(api, async value => { copied.push(value); });
    await waitForPolicy(popup);
    popup.querySelector<HTMLTextAreaElement>('#secret-message')!.value = 'Protected message';
    const passwordToggle = popup.querySelector<HTMLInputElement>('#secret-password-enabled')!;
    passwordToggle.checked = true;
    passwordToggle.dispatchEvent(new Event('change', { bubbles: true }));
    const password = 'a private access code';
    popup.querySelector<HTMLInputElement>('#secret-password')!.value = password;
    const emailToggle = popup.querySelector<HTMLInputElement>('#email-verification-enabled')!;
    emailToggle.checked = true;
    emailToggle.dispatchEvent(new Event('change', { bubbles: true }));
    popup.querySelector<HTMLInputElement>('#recipient-email')!.value = 'reader@example.com';
    await submit(popup);

    expect(api.create).toHaveBeenCalledOnce();
    const createRequest = requests[0]!.request as { protocolVersion: number; expiry: string; password: string; emailAddress: string; message: unknown; files: unknown[] };
    expect(createRequest).toMatchObject({ protocolVersion: 1, expiry: '7d', emailAddress: 'reader@example.com', files: [] });
    expect(createRequest.password).toBe(await derivePasswordToken(password, popup.querySelector<HTMLInputElement>('#share-link')!.value.split('#')[1]!));
    expect(createRequest.password).not.toBe(password);
    expect(JSON.stringify(createRequest)).not.toContain(password);
    expect(JSON.stringify(createRequest)).not.toContain(popup.querySelector<HTMLInputElement>('#share-link')!.value.split('#')[1]!);
    expect(popup.querySelector<HTMLElement>('#success-password')!.hidden).toBe(false);
    expect(popup.querySelector<HTMLInputElement>('#result-password')!.value).toBe(password);
    popup.querySelector<HTMLButtonElement>('#copy-password-button')!.click();
    await vi.waitFor(() => expect(popup.querySelector<HTMLElement>('#password-copy-status')!.textContent).toBe('Access code copied.'));
    expect(copied).toEqual([password]);
    expect(document.body.textContent).not.toContain('revoke-token-must-not-be-kept');
    expect(localStorage.length).toBe(0);
  });

  it('rejects unsupported or over-limit files and invalid email before the create API is called', async () => {
    const { api, requests } = makeApi({ getFileUploadPolicy: vi.fn(async () => ({ maxFiles: 1, maxTotalFileBytes: 4, allowedFileExtensions: ['.txt'] })) });
    const popup = mountPopup(api, async () => {}, true);
    await waitForPolicy(popup);
    selectFiles(popup, [new File(['012345'], 'large.txt', { type: 'text/plain' }), new File(['x'], 'bad.exe', { type: 'text/plain' })]);
    expect(popup.querySelectorAll('#selected-files li')).toHaveLength(0);
    expect(api.create).not.toHaveBeenCalled();

    popup.querySelector<HTMLTextAreaElement>('#secret-message')!.value = 'valid content';
    const passwordToggle = popup.querySelector<HTMLInputElement>('#secret-password-enabled')!;
    passwordToggle.checked = true;
    passwordToggle.dispatchEvent(new Event('change', { bubbles: true }));
    const passwordField = popup.querySelector<HTMLInputElement>('#secret-password')!;
    passwordField.value = '   ';
    await submit(popup);
    expect(popup.querySelector<HTMLElement>('#error-message')!.textContent).toContain('Enter an access code');
    expect(api.create).not.toHaveBeenCalled();

    const password = 'x';
    passwordField.value = password;
    const emailToggle = popup.querySelector<HTMLInputElement>('#email-verification-enabled')!;
    emailToggle.checked = true;
    emailToggle.dispatchEvent(new Event('change', { bubbles: true }));
    popup.querySelector<HTMLInputElement>('#recipient-email')!.value = 'not an address';
    await submit(popup);
    expect(popup.querySelector<HTMLElement>('#error-message')!.textContent).toContain('valid recipient email');
    expect(api.create).not.toHaveBeenCalled();

    popup.querySelector<HTMLInputElement>('#recipient-email')!.value = 'reader@example.com';
    await submit(popup);
    const request = requests[0]!.request as { password: string };
    expect(request.password).toBe(await derivePasswordToken(password, popup.querySelector<HTMLInputElement>('#share-link')!.value.split('#')[1]!));
  });

  it('leaves password length policy to the configured API validator', async () => {
    for (const password of ['x', 'p'.repeat(300)]) {
      document.body.replaceChildren();
      const { api, requests } = makeApi();
      const popup = mountPopup(api, async () => {});
      await waitForPolicy(popup);
      popup.querySelector<HTMLTextAreaElement>('#secret-message')!.value = 'Password compatibility';
      const passwordToggle = popup.querySelector<HTMLInputElement>('#secret-password-enabled')!;
      passwordToggle.checked = true;
      passwordToggle.dispatchEvent(new Event('change', { bubbles: true }));
      popup.querySelector<HTMLInputElement>('#secret-password')!.value = password;
      await submit(popup);

      const request = requests[0]!.request as { password: string };
      const clientKey = popup.querySelector<HTMLInputElement>('#share-link')!.value.split('#')[1]!;
      expect(request.password).toBe(await derivePasswordToken(password, clientKey));
      expect(request.password).not.toBe(password);
      expect(popup.querySelector<HTMLElement>('#error-message')!.hidden).toBe(true);
    }
  });

  it('keeps the content visible when extension-origin creation is rejected', async () => {
    const api = makeApi({ create: vi.fn(async () => { throw Object.assign(new Error('rejected'), { status: 403, code: 'forbidden' }); }) });
    const popup = mountPopup(api.api, async () => {});
    await waitForPolicy(popup);

    const message = popup.querySelector<HTMLTextAreaElement>('#secret-message')!;
    message.value = 'Keep this in the form';
    await submit(popup);

    expect(popup.querySelector<HTMLElement>('#error-message')!.textContent).toContain('extension creation is not enabled on the API');
    expect(message.value).toBe('Keep this in the form');
    expect(popup.querySelector<HTMLElement>('#success-panel')!.hidden).toBe(true);
  });

  it('preserves text entered while the create request is pending', async () => {
    let resolveCreate: ((response: Awaited<ReturnType<CreateApi['create']>>) => void) | undefined;
    let notifyCreateStarted!: () => void;
    const createStarted = new Promise<void>(resolve => { notifyCreateStarted = resolve; });
    const api = makeApi({ create: vi.fn(async (_request: Parameters<CreateApi['create']>[0], _proof: string): Promise<Awaited<ReturnType<CreateApi['create']>>> => {
      notifyCreateStarted();
      return new Promise<Awaited<ReturnType<CreateApi['create']>>>(resolve => { resolveCreate = resolve; });
    }) });
    const popup = mountPopup(api.api, async () => {});
    await waitForPolicy(popup);
    const message = popup.querySelector<HTMLTextAreaElement>('#secret-message')!;
    message.value = 'submitted text';
    popup.querySelector<HTMLFormElement>('#create-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await createStarted;
    message.value = 'new text typed while waiting';
    resolveCreate!({ id: 'AAAAAAAAAAAAAAAAAAAAAA', expiresAt: '2030-01-08T12:00:00Z', passwordProtected: false });

    await vi.waitFor(() => expect(popup.querySelector<HTMLElement>('#success-panel')!.hidden).toBe(false));
    expect(message.value).toBe('new text typed while waiting');
  });

  it('gets one fresh create challenge after proof_required', async () => {
    let challengeCount = 0;
    let createCount = 0;
    const api = makeApi({
      getCreateChallenge: vi.fn(async () => ({ ...challenge, challengeId: `challenge-${++challengeCount}` })),
      create: vi.fn(async () => {
        if (++createCount === 1) throw Object.assign(new Error('proof required'), { status: 403, code: 'proof_required' });
        return { id: 'AAAAAAAAAAAAAAAAAAAAAA', expiresAt: '2030-01-08T12:00:00Z', passwordProtected: false };
      })
    });
    const popup = mountPopup(api.api, async () => {});
    await waitForPolicy(popup);
    popup.querySelector<HTMLTextAreaElement>('#secret-message')!.value = 'retry securely';
    await submit(popup);

    expect(challengeCount).toBe(2);
    expect(createCount).toBe(2);
    expect(popup.querySelector<HTMLElement>('#error-message')!.hidden).toBe(true);
  });

  it('uses no persisted sender state and keeps revoke tokens out of extension API requests', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      if (String(input).endsWith('/capabilities')) return new Response(JSON.stringify(uploadPolicy), { status: 200 });
      if (String(input).endsWith('/create-challenge')) return new Response(JSON.stringify(challenge), { status: 200 });
      return new Response(JSON.stringify({ id: 'AAAAAAAAAAAAAAAAAAAAAA', expiresAt: '2030-01-08T12:00:00Z', passwordProtected: false, revokeToken: 'no-persist-this' }), { status: 201 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const popup = mountPopup(privacyLinkCreateApi, async () => {});
    await waitForPolicy(popup);
    popup.querySelector<HTMLTextAreaElement>('#secret-message')!.value = 'secret';
    await submit(popup);

    expect(setItem).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(calls.some(call => String(call.init?.body).includes('no-persist-this'))).toBe(false);
    expect(document.body.textContent).not.toContain('no-persist-this');
    const createBody = JSON.parse(String(calls.find(call => call.url.endsWith('/api/v1/secrets'))?.init?.body)) as Record<string, unknown>;
    expect(createBody).not.toHaveProperty('revokeToken');
    expect(createBody).not.toHaveProperty('clientKey');
    const clientKey = popup.querySelector<HTMLInputElement>('#share-link')!.value.split('#')[1]!;
    expect(JSON.stringify(calls)).not.toContain(clientKey);
  });
});
