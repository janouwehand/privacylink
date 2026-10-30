import { afterEach, describe, expect, it, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import { decryptMessage, derivePasswordToken, encryptFile, encryptMessage } from '../../../PrivacyLink.Client/src';
import { parseRecipientShareUrl, startRecipientContentScript, type RecipientFlowController, type RecipientFlowDependencies } from '../../extension/src/recipient-flow';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
  document.body.replaceChildren();
});

function metadata(overrides: Record<string, unknown> = {}) {
  return {
    exists: true,
    protocolVersion: 1,
    expiresAt: '2030-01-01T00:00:00.000Z',
    passwordProtected: false,
    hasMessage: true,
    fileCount: 0,
    files: [],
    emailVerificationRequired: false,
    maskedEmailAddress: null,
    ...overrides
  };
}

function makeFetch(responses: (path: string, init?: RequestInit) => Response | Promise<Response>) {
  const requests: Array<{ url: string; path: string; init?: RequestInit }> = [];
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const path = new URL(url, 'https://privacylink.nl').pathname;
    requests.push({ url, path, init });
    return responses(path, init);
  });
  return { fetcher, requests };
}

function start(url: string, fetcher: typeof fetch, options: Pick<RecipientFlowDependencies, 'clearFragment' | 'mount' | 'downloadFile'> = {}) {
  return startRecipientContentScript(document, url, {
    ...options,
    fetch: fetcher,
    storage: localStorage,
    clearFragment: options.clearFragment ?? (() => {}),
    mount: options.mount ?? (() => {})
  });
}

describe('PrivacyLink extension recipient flow', () => {
  it('matches only canonical PrivacyLink share links with a fragment client key', () => {
    const valid = 'https://privacylink.nl/s/AAAAAAAAAAAAAAAAAAAAAA#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    expect(parseRecipientShareUrl(valid)).toEqual({
      id: 'AAAAAAAAAAAAAAAAAAAAAA',
      clientKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    });
    expect(parseRecipientShareUrl('https://privacylink.nl/s/AAAAAAAAAAAAAAAAAAAAAA')).toBeNull();
    expect(parseRecipientShareUrl('https://privacylink.nl/s/AAAAAAAAAAAAAAAAAAAAAA?key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')).toBeNull();
    expect(parseRecipientShareUrl('https://example.com/s/AAAAAAAAAAAAAAAAAAAAAA#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')).toBeNull();
    expect(parseRecipientShareUrl('https://privacylink.nl/s/AAAAAAAAAAAAAAAAAAAAAA/extra#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')).toBeNull();
    expect(parseRecipientShareUrl('https://privacylink.nl/history#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')).toBeNull();
    expect(parseRecipientShareUrl('https://privacylink.nl/s/AAAAAAAAAAAAAAAAAAAAAA#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!')).toBeNull();
  });

  it('opens a share link with the packaged client and never sends the client key to the API', async () => {
    const encrypted = await encryptMessage('Extension recipient text');
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    const url = `https://privacylink.nl/s/${id}#${encrypted.clientKey}`;
    const { fetcher, requests } = makeFetch(path => {
      if (path === `/api/v1/secrets/${id}`) return new Response(JSON.stringify(metadata()), { status: 200 });
      if (path === `/api/v1/secrets/${id}/open`) {
        return new Response(JSON.stringify({ protocolVersion: 1, message: encrypted.message, files: [] }), { status: 200 });
      }
      return new Response('{}', { status: 404 });
    });
    const cleared: string[] = [];
    const controller = start(url, fetcher, { clearFragment: link => cleared.push(link.pathname + link.search) });

    expect(controller).not.toBeNull();
    await controller!.ready;
    expect(controller!.snapshot().phase).toBe('ready');
    await controller!.open();

    expect(controller!.snapshot()).toMatchObject({ phase: 'opened', openedMessage: 'Extension recipient text' });
    expect(cleared).toEqual([`/s/${id}`]);
    expect(requests.map(request => request.path)).toEqual([`/api/v1/secrets/${id}`, `/api/v1/secrets/${id}/open`]);
    expect(requests.every(request => new URL(request.url).origin === 'https://privacylink.nl')).toBe(true);
    expect(requests.every(request => request.init?.credentials === 'same-origin')).toBe(true);
    expect(JSON.stringify(requests)).not.toContain(encrypted.clientKey);
    expect(await decryptMessage({ protocolVersion: 1, message: encrypted.message, files: [] }, encrypted.clientKey)).toBe('Extension recipient text');
    controller!.dispose();
  });

  it('preserves the website flow when the route is not eligible for extension handling', () => {
    const fetcher = vi.fn();
    const mount = vi.fn();
    const clearFragment = vi.fn();
    const controller = start(
      'https://privacylink.nl/history#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      fetcher as typeof fetch,
      { mount, clearFragment }
    );

    expect(controller).toBeNull();
    expect(fetcher).not.toHaveBeenCalled();
    expect(mount).not.toHaveBeenCalled();
    expect(clearFragment).not.toHaveBeenCalled();
  });

  it('removes recipient UI, key listeners, and state after SPA navigation away, and handles later route events', async () => {
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    const clientKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const shareUrl = `https://privacylink.nl/s/${id}#${clientKey}`;
    const dom = new JSDOM('', { url: shareUrl, pretendToBeVisual: true });
    const view = dom.window;
    let shadowRoot: ShadowRoot | undefined;
    const attachShadow = view.Element.prototype.attachShadow;
    view.Element.prototype.attachShadow = function(this: Element, init: ShadowRootInit): ShadowRoot {
      const root = attachShadow.call(this, init);
      if (this.getAttribute('aria-label') === 'PrivacyLink extension recipient') shadowRoot = root;
      return root;
    };
    const navigation = new EventTarget();
    const removedEvents = vi.spyOn(view, 'removeEventListener');
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      return path === `/api/v1/secrets/${id}`
        ? new Response(JSON.stringify(metadata({ passwordProtected: true })), { status: 200 })
        : new Response('{}', { status: 404 });
    });
    const controller = startRecipientContentScript(view.document, shareUrl, {
      fetch: fetcher,
      storage: view.localStorage,
      navigation
    });

    expect(controller).not.toBeNull();
    await controller!.ready;
    expect(view.document.querySelector('[aria-label="PrivacyLink extension recipient"]')).not.toBeNull();
    const password = shadowRoot!.querySelector<HTMLInputElement>('input[type="password"]')!;
    password.focus();
    const pageKeyHandler = vi.fn();
    view.addEventListener('keydown', pageKeyHandler);
    password.dispatchEvent(new view.KeyboardEvent('keydown', { key: 'x', bubbles: true, composed: true }));
    expect(pageKeyHandler).not.toHaveBeenCalled();

    view.history.pushState({}, '', '/history');
    navigation.dispatchEvent(new Event('currententrychange'));
    expect(view.document.querySelector('[aria-label="PrivacyLink extension recipient"]')).toBeNull();
    expect(controller!.snapshot()).toMatchObject({ phase: 'unavailable', fileCount: 0, files: [], openedMessage: '' });
    expect(removedEvents.mock.calls.some(call => call[0] === 'keydown')).toBe(true);
    expect(removedEvents.mock.calls.some(call => call[0] === 'input')).toBe(true);
    const pageInput = view.document.createElement('input');
    view.document.body.append(pageInput);
    pageInput.focus();
    pageInput.dispatchEvent(new view.KeyboardEvent('keydown', { key: 'x', bubbles: true, composed: true }));
    expect(pageKeyHandler).toHaveBeenCalledOnce();

    view.history.pushState({}, '', shareUrl.replace('https://privacylink.nl', ''));
    view.dispatchEvent(new view.PopStateEvent('popstate'));
    expect(view.document.querySelector('[aria-label="PrivacyLink extension recipient"]')).not.toBeNull();
    view.history.replaceState({}, '', '/history');
    navigation.dispatchEvent(new Event('currententrychange'));
    expect(view.document.querySelector('[aria-label="PrivacyLink extension recipient"]')).toBeNull();

    view.history.pushState({}, '', shareUrl.replace('https://privacylink.nl', ''));
    view.dispatchEvent(new view.HashChangeEvent('hashchange'));
    expect(view.document.querySelector('[aria-label="PrivacyLink extension recipient"]')).not.toBeNull();
    view.history.replaceState({}, '', `/s/${id}#invalid`);
    view.dispatchEvent(new view.HashChangeEvent('hashchange'));
    expect(view.document.querySelector('[aria-label="PrivacyLink extension recipient"]')).toBeNull();

    controller!.dispose();
    expect(removedEvents.mock.calls.filter(call => call[0] === 'popstate' || call[0] === 'hashchange').length).toBeGreaterThanOrEqual(2);
    view.close();
  });

  it('updates the email cooldown every second and preserves focused code entry', async () => {
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    const clientKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const shareUrl = `https://privacylink.nl/s/${id}#${clientKey}`;
    const dom = new JSDOM('', { url: shareUrl, pretendToBeVisual: true });
    const view = dom.window;
    let shadowRoot: ShadowRoot | undefined;
    const attachShadow = view.Element.prototype.attachShadow;
    view.Element.prototype.attachShadow = function(this: Element, init: ShadowRootInit): ShadowRoot {
      const root = attachShadow.call(this, init);
      if (this.getAttribute('aria-label') === 'PrivacyLink extension recipient') shadowRoot = root;
      return root;
    };
    let tick: (() => void) | undefined;
    const interval = ((callback: TimerHandler) => {
      tick = callback as () => void;
      return 1;
    }) as typeof setInterval;
    const fetcher = vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      if (path === `/api/v1/secrets/${id}`) {
        return new Response(JSON.stringify(metadata({ emailVerificationRequired: true })), { status: 200 });
      }
      return new Response(JSON.stringify({ code: 'verification_requested' }), { status: 202 });
    });
    const controller = startRecipientContentScript(view.document, shareUrl, {
      fetch: fetcher,
      storage: view.localStorage,
      clearFragment: () => {},
      setInterval: interval,
      clearInterval: () => {}
    });
    const countdowns: number[] = [];
    controller!.subscribe(snapshot => countdowns.push(snapshot.emailCodeCooldownSeconds));
    await controller!.ready;
    await controller!.requestEmailCode();
    const codeInput = shadowRoot!.querySelector<HTMLInputElement>('[aria-label="Six-digit email verification code"]')!;
    codeInput.focus();
    codeInput.value = '123';
    codeInput.dispatchEvent(new view.Event('input', { bubbles: true, composed: true }));

    for (let remaining = 59; remaining >= 0; remaining--) {
      tick!();
      expect(controller!.snapshot().emailCodeCooldownSeconds).toBe(remaining);
      const cooldownButton = shadowRoot!.querySelector('button.secondary')?.textContent ?? '';
      if (remaining) expect(cooldownButton).toContain(`00:${String(remaining).padStart(2, '0')}`);
      else expect(cooldownButton).toBe('Request another code');
    }
    expect(countdowns).toEqual(expect.arrayContaining([60, 59, 1, 0]));
    expect(countdowns).toContain(2);
    expect(countdowns).toContain(30);
    expect(shadowRoot!.activeElement?.getAttribute('aria-label')).toBe('Six-digit email verification code');
    expect(shadowRoot!.querySelector<HTMLInputElement>('[aria-label="Six-digit email verification code"]')?.value).toBe('123');
    controller!.dispose();
    view.close();
  });

  it('keeps email verification first and uses the existing derived-password unlock contract', async () => {
    const encrypted = await encryptMessage('Protected extension text');
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    const url = `https://privacylink.nl/s/${id}#${encrypted.clientKey}`;
    let unlocks = 0;
    const { fetcher, requests } = makeFetch((path, init) => {
      if (path === `/api/v1/secrets/${id}`) {
        return new Response(JSON.stringify(metadata({
          passwordProtected: true,
          emailVerificationRequired: true,
          maskedEmailAddress: 'r***@example.com'
        })), { status: 200 });
      }
      if (path === `/api/v1/secrets/${id}/email-verification/request`) {
        return new Response(JSON.stringify({ code: 'verification_requested' }), { status: 202 });
      }
      if (path === `/api/v1/secrets/${id}/email-verification/verify`) {
        return JSON.parse(String(init?.body)).code === '123456' ? new Response(null, { status: 204 }) : new Response(JSON.stringify({ code: 'invalid_code' }), { status: 400 });
      }
      if (path === `/api/v1/secrets/${id}/unlock`) {
        unlocks++;
        if (unlocks === 1) return new Response(JSON.stringify({ code: 'forbidden' }), { status: 403 });
        return new Response(JSON.stringify({ protocolVersion: 1, message: encrypted.message, files: [] }), { status: 200 });
      }
      return new Response('{}', { status: 404 });
    });
    const controller = start(url, fetcher);

    expect(controller).not.toBeNull();
    await controller!.ready;
    expect(controller!.snapshot()).toMatchObject({ emailVerificationRequired: true, emailVerified: false, passwordProtected: true });
    await controller!.open('reader password');
    expect(unlocks).toBe(0);

    await controller!.requestEmailCode();
    expect(controller!.snapshot().emailCodeRequested).toBe(true);
    await controller!.verifyEmailCode('654321');
    expect(controller!.snapshot()).toMatchObject({ emailVerified: false, emailCodeRequested: true });
    expect(controller!.snapshot().error).toContain('incorrect or expired');
    await controller!.verifyEmailCode('123456');
    expect(controller!.snapshot().emailVerified).toBe(true);
    expect(localStorage.getItem(`privacylink.email-verification.${id}`)).toBeTruthy();

    await controller!.open('reader password');
    expect(controller!.snapshot().error).toContain('password is incorrect');
    await controller!.open('reader password');
    const unlockRequest = requests.filter(request => request.path.endsWith('/unlock')).at(-1)!;
    expect(unlocks).toBe(2);
    expect(JSON.parse(String(unlockRequest.init?.body))).toEqual({ password: await derivePasswordToken('reader password', encrypted.clientKey) });
    expect(JSON.stringify(requests)).not.toContain(encrypted.clientKey);
    expect(controller!.snapshot()).toMatchObject({ phase: 'opened', openedMessage: 'Protected extension text' });
    controller!.dispose();
  });

  it('decrypts downloadable file payloads locally without sending the fragment key', async () => {
    const encrypted = await encryptMessage('');
    const clientKey = (await import('../../../PrivacyLink.Client/src')).decodeCanonical(encrypted.clientKey, 32);
    const file = await encryptFile(new File(['private file bytes'], 'notes.txt', { type: 'text/plain' }), clientKey);
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    const url = `https://privacylink.nl/s/${id}#${encrypted.clientKey}`;
    const downloads: Array<{ name: string; bytes: string }> = [];
    const { fetcher, requests } = makeFetch(path => {
      if (path === `/api/v1/secrets/${id}`) return new Response(JSON.stringify(metadata({ hasMessage: false, fileCount: 1, files: [file] })), { status: 200 });
      if (path === `/api/v1/secrets/${id}/open`) return new Response(JSON.stringify({ protocolVersion: 1, message: null, files: [] }), { status: 200 });
      if (path === `/api/v1/secrets/${id}/files/${file.id}/open`) return new Response(JSON.stringify({ protocolVersion: 1, file }), { status: 200 });
      return new Response('{}', { status: 404 });
    });
    const controller = start(url, fetcher, {
      downloadFile: (_document, recipientFile, filename, bytes) => downloads.push({ name: filename || recipientFile.name, bytes: new TextDecoder().decode(bytes) })
    });

    expect(controller).not.toBeNull();
    await controller!.ready;
    expect(controller!.snapshot().files.map(item => item.name)).toEqual(['notes.txt']);
    await controller!.open();
    await controller!.download(file.id);

    expect(downloads).toEqual([{ name: 'notes.txt', bytes: 'private file bytes' }]);
    expect(JSON.stringify(requests)).not.toContain(encrypted.clientKey);
    controller!.dispose();
  });
});
