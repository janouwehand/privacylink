import { afterEach, describe, expect, it, vi } from 'vitest';
import { decryptMessage } from '../../../PrivacyLink.Client/src';
import { mountCreateForm, privacyLinkCreateApi } from '../../extension/src/create-secret';

const popupMarkup = `
  <form id="create-form">
    <textarea id="secret-message"></textarea>
    <select id="secret-expiry"><option value="1d">1 day</option><option value="7d" selected>7 days</option><option value="14d">14 days</option></select>
    <button id="create-button" type="submit">Create secret</button>
  </form>
  <p id="error-message" hidden></p>
  <section id="success-panel" hidden>
    <p id="expiry-message"></p>
    <input id="share-link" />
    <button id="copy-link-button" type="button">Copy share link</button>
    <p id="copy-status"></p>
  </section>`;
const challenge = {
  version: 1,
  challengeId: 'extension-test-challenge',
  nonce: 'extension-test-nonce',
  difficultyBits: 0,
  expiresAt: 1_900_000_000,
  signature: 'server-signature'
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  document.body.replaceChildren();
});

function mountPopup(copyText: (value: string) => Promise<void>) {
  document.body.innerHTML = popupMarkup;
  mountCreateForm(document, { api: privacyLinkCreateApi, copyText });
  return document;
}

describe('PrivacyLink extension create popup', () => {
  it('creates a compatible encrypted text payload and shows a copyable canonical share link', async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, init });
      if (url.endsWith('/create-challenge')) return new Response(JSON.stringify(challenge), { status: 200 });
      return new Response(JSON.stringify({
        id: 'AAAAAAAAAAAAAAAAAAAAAA',
        expiresAt: '2030-01-08T12:00:00Z',
        passwordProtected: false,
        revokeToken: 'server-response-is-not-stored'
      }), { status: 201 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const copied: string[] = [];
    const popup = mountPopup(async value => { copied.push(value); });

    popup.querySelector<HTMLTextAreaElement>('#secret-message')!.value = '  secret text 🔐  ';
    popup.querySelector<HTMLSelectElement>('#secret-expiry')!.value = '14d';
    popup.querySelector<HTMLFormElement>('#create-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(popup.querySelector<HTMLButtonElement>('#create-button')!.disabled).toBe(false));

    expect(requests.map(request => new URL(request.url).pathname)).toEqual([
      '/api/v1/secrets/create-challenge',
      '/api/v1/secrets'
    ]);
    const createRequest = requests[1]!;
    expect(new URL(createRequest.url).origin).toBe('https://privacylink.nl');
    expect(createRequest.init?.method).toBe('POST');
    expect(createRequest.init?.cache).toBe('no-store');
    expect(createRequest.init?.referrerPolicy).toBe('no-referrer');
    const requestBody = JSON.parse(String(createRequest.init?.body)) as {
      protocolVersion: number;
      expiry: string;
      message: { nonce: string; ciphertext: string };
      files: unknown[];
    };
    expect(requestBody).toMatchObject({ protocolVersion: 1, expiry: '14d', files: [] });
    expect(JSON.stringify(requestBody)).not.toContain('secret text');
    const proof = new Headers(createRequest.init?.headers).get('X-PrivacyLink-Proof');
    expect(proof).toBe(`${challenge.challengeId}.${challenge.nonce}.0.${challenge.expiresAt}.${challenge.signature}.0`);

    const linkField = popup.querySelector<HTMLInputElement>('#share-link')!;
    const link = new URL(linkField.value);
    expect(popup.querySelector<HTMLElement>('#success-panel')!.hidden).toBe(false);
    expect(link.origin).toBe('https://privacylink.nl');
    expect(link.pathname).toBe('/s/AAAAAAAAAAAAAAAAAAAAAA');
    expect(link.search).toBe('');
    expect(link.hash).toMatch(/^#[A-Za-z0-9_-]{43}$/);
    expect(JSON.stringify(requestBody)).not.toContain(link.hash.slice(1));
    expect(JSON.stringify(createRequest.init?.headers)).not.toContain(link.hash.slice(1));
    expect(await decryptMessage({ protocolVersion: 1, message: requestBody.message, files: [] }, link.hash.slice(1))).toBe('  secret text 🔐  ');

    popup.querySelector<HTMLButtonElement>('#copy-link-button')!.click();
    await vi.waitFor(() => expect(popup.querySelector<HTMLElement>('#copy-status')!.textContent).toBe('Share link copied.'));
    expect(copied).toEqual([linkField.value]);
    expect(popup.querySelector<HTMLTextAreaElement>('#secret-message')!.value).toBe('');
  });

  it('keeps the text visible and reports when the API rejects an extension-origin create', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith('/create-challenge')) return new Response(JSON.stringify(challenge), { status: 200 });
      return new Response(JSON.stringify({ code: 'forbidden' }), { status: 403 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const popup = mountPopup(async () => {});

    const message = popup.querySelector<HTMLTextAreaElement>('#secret-message')!;
    message.value = 'Keep this in the form';
    popup.querySelector<HTMLFormElement>('#create-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(popup.querySelector<HTMLElement>('#error-message')!.hidden).toBe(false));

    expect(popup.querySelector<HTMLElement>('#error-message')!.textContent).toContain('API currently accepts creation only from the website');
    expect(message.value).toBe('Keep this in the form');
    expect(popup.querySelector<HTMLElement>('#success-panel')!.hidden).toBe(true);
  });

  it('gets a fresh create challenge once when the API reports proof_required', async () => {
    let challengeCount = 0;
    let createCount = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).endsWith('/create-challenge')) {
        challengeCount++;
        return new Response(JSON.stringify({ ...challenge, challengeId: `challenge-${challengeCount}` }), { status: 200 });
      }
      createCount++;
      if (createCount === 1) return new Response(JSON.stringify({ code: 'proof_required' }), { status: 403 });
      return new Response(JSON.stringify({
        id: 'AAAAAAAAAAAAAAAAAAAAAA',
        expiresAt: '2030-01-08T12:00:00Z',
        passwordProtected: false,
        revokeToken: 'not-retained'
      }), { status: 201 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const popup = mountPopup(async () => {});
    popup.querySelector<HTMLTextAreaElement>('#secret-message')!.value = 'retry securely';
    popup.querySelector<HTMLFormElement>('#create-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(popup.querySelector<HTMLElement>('#success-panel')!.hidden).toBe(false));

    expect(challengeCount).toBe(2);
    expect(createCount).toBe(2);
    expect(popup.querySelector<HTMLElement>('#error-message')!.hidden).toBe(true);
  });
});
