import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideRouter, Router } from '@angular/router';
import { vi } from 'vitest';
import { App } from './app';
import { routes } from './app.routes';
import { AppState } from './app-state';
import { CreateState } from './create/create-state';
import { HistoryState } from './history/history-state';
import { LanguageState } from './language-state';
import { RecipientState } from './recipient/recipient-state';
import { RecipientPage } from './recipient/recipient-page';
import { SecretApi, SecretApiError } from './secret-api';
import { SecretHistoryStore } from './secret-history-store';
import { installTestWebLocks } from '../../test-utils/web-locks';
import { decodeCanonical, decryptFile, decryptFileName, decryptMessage, encryptFile, encryptMessage } from './secret-crypto';

class InlineCryptoWorker extends EventTarget {
  postMessage(message: { id: number; operation: string; payload: unknown; clientKey: string | Uint8Array }): void {
    void (async () => {
      let result: unknown;
      if (message.operation === 'solveCreateProof') {
        result = '0';
      } else if (message.operation === 'decryptOpenSecretResponse') {
        const payload = JSON.parse(new TextDecoder().decode(message.payload as ArrayBuffer));
        const text = payload.message ? await decryptMessage(payload, message.clientKey as string) : null;
        const files = await Promise.all(payload.files.map(async (file: Parameters<typeof decryptFileName>[0]) => ({
          id: file.id,
          extension: file.extension,
          name: await decryptFileName(file, message.clientKey as string),
          mimeType: file.mimeType,
          size: file.size
        })));
        result = { token: 'test-cache-token', message: text, files };
      } else if (message.operation === 'decryptOpenFileResponse') {
        const payload = JSON.parse(new TextDecoder().decode(message.payload as ArrayBuffer));
        const filename = await decryptFileName(payload.file, message.clientKey as string);
        const data = await decryptFile(payload.file, message.clientKey as string);
        result = { filename, mimeType: payload.file.mimeType, data: data.buffer };
      } else if (message.operation === 'decryptFileName') {
        result = await decryptFileName(message.payload as Parameters<typeof decryptFileName>[0], message.clientKey as string);
      } else if (message.operation === 'encryptFilesAndSerialize') {
        const input = message.payload as { request: Record<string, unknown>; files: File[] };
        const files = [];
        for (const file of input.files) files.push(await encryptFile(file, message.clientKey as Uint8Array));
        result = new TextEncoder().encode(JSON.stringify({ ...input.request, files })).buffer;
      } else if (message.operation === 'clearCachedFiles') {
        result = undefined;
      } else {
        throw new Error(`Unexpected worker operation: ${message.operation}`);
      }
      this.dispatchEvent(new MessageEvent('message', { data: { id: message.id, type: 'result', result } }));
    })().catch(error => this.dispatchEvent(new MessageEvent('message', {
      data: { id: message.id, type: 'error', error: error instanceof Error ? error.message : 'worker error' }
    })));
  }

  terminate(): void {}
}

function createSecretApiStub() {
  return {
    getFileUploadPolicy: vi.fn().mockResolvedValue({ maxFiles: 15, maxTotalFileBytes: 75 * 1024 * 1024, allowedFileExtensions: ['.txt'] }),
    getCreateChallenge: vi.fn().mockResolvedValue({ version: 1, challengeId: 'AAAAAAAAAAAAAAAAAAAAAA', nonce: 'AAAAAAAAAAAAAAAAAAAAAA', difficultyBits: 1, expiresAt: Math.floor(Date.now() / 1000) + 300, signature: 'test-signature' }),
    create: vi.fn().mockResolvedValue({ id: 'AAAAAAAAAAAAAAAAAAAAAA', expiresAt: '2030-01-01T00:00:00.000Z', passwordProtected: false, revokeToken: 'test-revoke-token' }),
    createSerialized: vi.fn((_body: ArrayBuffer) => Promise.resolve({ id: 'AAAAAAAAAAAAAAAAAAAAAA', expiresAt: '2030-01-01T00:00:00.000Z', passwordProtected: false, revokeToken: 'test-revoke-token' })),
    revoke: vi.fn().mockResolvedValue(undefined),
    getMetadata: vi.fn().mockResolvedValue({ exists: true, protocolVersion: 1, expiresAt: '2030-01-01T00:00:00.000Z', passwordProtected: false, hasMessage: true, fileCount: 0, files: [] }),
    requestEmailCode: vi.fn().mockResolvedValue({ code: 'verification_requested' }),
    verifyEmailCode: vi.fn().mockResolvedValue(undefined),
    open: vi.fn(),
    openRaw: vi.fn(),
    unlock: vi.fn(),
    unlockRaw: vi.fn(),
    openFile: vi.fn(),
    openFileRaw: vi.fn()
  };
}

describe('App', () => {
  let api: ReturnType<typeof createSecretApiStub>;
  let addedDialogMethods = false;
  let restoreWebLocks: (() => void) | undefined;

  beforeEach(async () => {
    restoreWebLocks = installTestWebLocks();
    addedDialogMethods = typeof HTMLDialogElement.prototype.showModal !== 'function';
    if (addedDialogMethods) {
      Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', ''); } });
      Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value() { this.removeAttribute('open'); this.dispatchEvent(new Event('close')); } });
    }
    localStorage.clear();
    vi.stubGlobal('Worker', InlineCryptoWorker);
    api = createSecretApiStub();
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [
        provideRouter(routes),
        { provide: SecretApi, useValue: api }
      ]
    })
      .compileComponents();
  });

  afterEach(() => {
    restoreWebLocks?.();
    if (addedDialogMethods) {
      Reflect.deleteProperty(HTMLDialogElement.prototype, 'showModal');
      Reflect.deleteProperty(HTMLDialogElement.prototype, 'close');
    }
  });

  async function renderApp(url = '/') {
    TestBed.inject(LanguageState).setLanguage('en');
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    await TestBed.inject(Router).navigateByUrl(url);
    await fixture.whenStable();
    fixture.detectChanges();
    return fixture;
  }

  it('should render the text and file landing page', async () => {
    const fixture = await renderApp();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h1')?.textContent).toContain('Share text and files with a single secure link.');
    expect(compiled.querySelector('.message-field .field-note')?.textContent).toContain('0 / 20,000 characters');
    expect(document.documentElement.lang).toBe('en');
    compiled.querySelector<HTMLButtonElement>('.language button[aria-label="Dutch"]')!.click();
    fixture.detectChanges();
    expect(compiled.querySelector('.message-field .field-note')?.textContent).toContain('0 / 20.000 karakters');
    expect(compiled.querySelector('h1')?.textContent).toContain('Deel tekst en bestanden via één veilige link.');
    expect(compiled.querySelector('.language button[aria-pressed="true"]')?.textContent).toBe('NL');
    expect(document.documentElement.lang).toBe('nl');
    expect(document.title).toBe('PrivacyLink — veilig delen');
    expect(localStorage.getItem('privacylink.language')).toBe('nl');
  });

  it('does not add a statistics link to the home page', async () => {
    const fixture = await renderApp();
    const links = [...(fixture.nativeElement as HTMLElement).querySelectorAll('a')];
    expect(links.some(link => link.getAttribute('href') === '/stats')).toBe(false);
  });

  it('restores the saved language when the app starts', async () => {
    localStorage.setItem('privacylink.language', 'nl');
    const language = TestBed.inject(LanguageState);
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    await TestBed.inject(Router).navigateByUrl('/');
    await fixture.whenStable();
    fixture.detectChanges();

    expect(language.lang()).toBe('nl');
    expect((fixture.nativeElement as HTMLElement).querySelector('h1')?.textContent).toContain('Deel tekst en bestanden via één veilige link.');
    expect(document.documentElement.lang).toBe('nl');
  });

  it('re-renders existing error messages in the selected language', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    const language = TestBed.inject(LanguageState);
    create.setError({ key: 'tooManyFiles', params: { max: 15 } });
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error')?.textContent).toContain('You can add at most 15 files.');

    language.setLanguage('nl');
    fixture.detectChanges();
    expect(compiled.querySelector('.error')?.textContent).toContain('Je kunt maximaal 15 bestanden toevoegen.');
  });

  it('encrypts selected files and serializes the upload through the worker', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    (create as unknown as { setFiles(files: File[], append?: boolean): void }).setFiles([new File(['hello'], 'hello.txt', { type: 'text/plain' })]);
    create.setRecipientEmail('recipient@example.com');
    create.enableEmailVerification();

    await create.create();
    fixture.detectChanges();

    expect(api.create).not.toHaveBeenCalled();
    expect(api.createSerialized).toHaveBeenCalledOnce();
    const body = api.createSerialized.mock.calls[0]?.[0];
    expect(Object.prototype.toString.call(body)).toBe('[object ArrayBuffer]');
    const request = JSON.parse(new TextDecoder().decode(body));
    expect(request.files).toHaveLength(1);
    expect(request.files[0].extension).toBe('.txt');
    expect(request.emailAddress).toBe('recipient@example.com');
    expect(api.requestEmailCode).not.toHaveBeenCalled();
    expect((fixture.nativeElement as HTMLElement).querySelector('h1')?.textContent).toContain('Your secure link is ready.');
  });

  it('creates an email-protected link after an address is selected', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    create.message.set('Protected message');
    create.setRecipientEmail('recipient@example.com');
    create.enableEmailVerification();
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    const button = compiled.querySelector<HTMLButtonElement>('.compose-actions .primary')!;
    expect(button.disabled).toBe(false);
    expect(api.create).not.toHaveBeenCalled();
    expect(api.requestEmailCode).not.toHaveBeenCalled();
    button.click();
    await vi.waitFor(() => expect(api.create).toHaveBeenCalledOnce());
    await fixture.whenStable();
    fixture.detectChanges();
    expect(api.create).toHaveBeenCalledWith(expect.objectContaining({ emailAddress: 'recipient@example.com' }), expect.any(String));
    expect(api.requestEmailCode).not.toHaveBeenCalled();
    expect(compiled.querySelector('h1')?.textContent).toContain('Your secure link is ready.');
  });

  it('waits for an explicit unlock action and renders decrypted content as text', async () => {
    const messageText = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const encrypted = await encryptMessage(messageText);
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    api.getMetadata.mockResolvedValue({ exists: true, protocolVersion: 1, expiresAt: '2030-01-01T00:00:00.000Z', passwordProtected: true, hasMessage: true, fileCount: 0, files: [] });
    api.unlockRaw.mockResolvedValue(new TextEncoder().encode(JSON.stringify({ protocolVersion: 1, message: encrypted.message, files: [] })).buffer);
    const fixture = await renderApp(`/s/${id}#${encrypted.clientKey}`);
    const recipient = fixture.debugElement.query(By.directive(RecipientPage)).injector.get(RecipientState);
    await vi.waitFor(() => expect(recipient.metadataReady()).toBe(true));
    fixture.detectChanges();
    expect(api.getMetadata).toHaveBeenCalledWith(id);
    expect(api.open).not.toHaveBeenCalled();
    expect(api.unlock).not.toHaveBeenCalled();

    const password = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>('#unlock-password');
    expect(password).not.toBeNull();
    password!.value = 'test-pin';
    password!.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('.card .primary')!.click();
    await vi.waitFor(() => expect(api.unlockRaw).toHaveBeenCalledTimes(1));
    await fixture.whenStable();
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    const message = compiled.querySelector('.message-display');
    expect(message?.textContent).toBe(messageText);
    expect(message?.querySelector('img, script')).toBeNull();
    expect(api.unlockRaw.mock.calls[0]?.[0]).toBe(id);
    expect(api.open).not.toHaveBeenCalled();
  });

  it('opens unprotected content through the worker using the raw response', async () => {
    const encrypted = await encryptMessage('Worker opened this message');
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    api.openRaw.mockResolvedValue(new TextEncoder().encode(JSON.stringify({ protocolVersion: 1, message: encrypted.message, files: [] })).buffer);
    const fixture = await renderApp(`/s/${id}#${encrypted.clientKey}`);
    const recipient = fixture.debugElement.query(By.directive(RecipientPage)).injector.get(RecipientState);
    await vi.waitFor(() => expect(recipient.metadataReady()).toBe(true));

    await recipient.open();
    fixture.detectChanges();

    expect(api.openRaw).toHaveBeenCalledWith(id);
    expect(api.open).not.toHaveBeenCalled();
    expect(recipient.openedMessage()).toBe('Worker opened this message');
    expect(recipient.opened()).toBe(true);
  });

  it('shows only the localized unavailable message for a malformed recipient link', async () => {
    const fixture = await renderApp('/s/not-valid#broken');
    const main = (fixture.nativeElement as HTMLElement).querySelector('main')!;

    expect(main.textContent?.trim()).toBe('This link is unavailable.');
    expect(main.querySelector('button, input, a')).toBeNull();
    expect(api.getMetadata).not.toHaveBeenCalled();

    TestBed.inject(LanguageState).setLanguage('nl');
    fixture.detectChanges();
    expect(main.textContent?.trim()).toBe('Deze link is niet beschikbaar.');
  });

  it('shows only the same unavailable message when metadata returns not found', async () => {
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    api.getMetadata.mockRejectedValueOnce(new SecretApiError(404, null, 'not_found'));
    const fixture = await renderApp(`/s/${id}#${'A'.repeat(43)}`);
    await vi.waitFor(() => expect(fixture.nativeElement.querySelector('main')?.textContent?.trim()).toBe('This link is unavailable.'));

    const main = (fixture.nativeElement as HTMLElement).querySelector('main')!;
    expect(main.textContent?.trim()).toBe('This link is unavailable.');
    expect(main.querySelector('button, input, a')).toBeNull();
    expect(main.textContent).not.toContain('Someone shared something');
    expect(main.textContent).not.toContain('does not exist');
  });

  it('switches to the unavailable state when opening returns not found after metadata loaded', async () => {
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    api.openRaw.mockRejectedValueOnce(new SecretApiError(404, null, 'not_found'));
    const fixture = await renderApp(`/s/${id}#${'A'.repeat(43)}`);
    const recipient = fixture.debugElement.query(By.directive(RecipientPage)).injector.get(RecipientState);
    await vi.waitFor(() => expect(recipient.metadataReady()).toBe(true));
    expect((fixture.nativeElement as HTMLElement).querySelector('.card .primary')).not.toBeNull();

    await recipient.open();
    fixture.detectChanges();

    const main = (fixture.nativeElement as HTMLElement).querySelector('main')!;
    expect(main.textContent?.trim()).toBe('This link is unavailable.');
    expect(main.querySelector('button, input, a')).toBeNull();
    expect(main.textContent).not.toContain('Someone shared something');
  });

  it.each([
    ['network failure', new TypeError('Failed to fetch')],
    ['HTTP 408 timeout', new SecretApiError(408, null, 'request_timeout')],
    ['HTTP 503', new SecretApiError(503, null, 'temporarily_unavailable')]
  ])('shows the retry-later message for metadata %s', async (_label, failure) => {
    api.getMetadata.mockRejectedValueOnce(failure);
    const fixture = await renderApp(`/s/AAAAAAAAAAAAAAAAAAAAAA#${'A'.repeat(43)}`);
    await vi.waitFor(() => expect(fixture.nativeElement.querySelector('.recipient-card .error')?.textContent).toContain('Please try again in a few moments.'));

    const main = (fixture.nativeElement as HTMLElement).querySelector('main')!;
    expect(main.textContent).toContain('The service is busy. Please try again in a few moments.');
    expect(main.textContent).not.toContain('This link is unavailable.');
    expect(main.textContent).toContain('Someone shared something with you through PrivacyLink.');
  });

  it.each([
    ['network failure', new TypeError('Failed to fetch')],
    ['HTTP 408 timeout', new SecretApiError(408, null, 'request_timeout')],
    ['HTTP 500', new SecretApiError(500, null, 'server_error')]
  ])('keeps retryable content-opening failure separate from unavailable links (%s)', async (_label, failure) => {
    api.openRaw.mockRejectedValueOnce(failure);
    const fixture = await renderApp(`/s/AAAAAAAAAAAAAAAAAAAAAA#${'A'.repeat(43)}`);
    const recipient = fixture.debugElement.query(By.directive(RecipientPage)).injector.get(RecipientState);
    await vi.waitFor(() => expect(recipient.metadataReady()).toBe(true));

    await recipient.open();
    fixture.detectChanges();

    const main = (fixture.nativeElement as HTMLElement).querySelector('main')!;
    expect(main.textContent).toContain('The service is busy. Please try again in a few moments.');
    expect(main.textContent).not.toContain('This link is unavailable.');
  });

  it('keeps incorrect-password, email-verification, and rate-limit responses distinct', async () => {
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    const key = 'A'.repeat(43);
    api.getMetadata.mockResolvedValue({
      exists: true,
      protocolVersion: 1,
      expiresAt: '2030-01-01T00:00:00.000Z',
      passwordProtected: true,
      hasMessage: true,
      fileCount: 0,
      files: []
    });
    api.unlockRaw.mockRejectedValueOnce(new SecretApiError(403, null, 'forbidden'));
    const passwordFixture = await renderApp(`/s/${id}#${key}`);
    const passwordRecipient = passwordFixture.debugElement.query(By.directive(RecipientPage)).injector.get(RecipientState);
    await vi.waitFor(() => expect(passwordRecipient.metadataReady()).toBe(true));
    passwordRecipient.unlockPassword.set('wrong password');
    await passwordRecipient.open();
    passwordFixture.detectChanges();
    expect((passwordFixture.nativeElement as HTMLElement).textContent).toContain('That did not work. Check the PIN or password');
    expect((passwordFixture.nativeElement as HTMLElement).textContent).not.toContain('This link is unavailable.');

    passwordFixture.destroy();
    localStorage.setItem(`privacylink.email-verification.${id}`, String(Date.now() + 60_000));
    api.getMetadata.mockResolvedValueOnce({
      exists: true,
      protocolVersion: 1,
      expiresAt: '2030-01-01T00:00:00.000Z',
      passwordProtected: false,
      hasMessage: true,
      fileCount: 0,
      files: [],
      emailVerificationRequired: true,
      maskedEmailAddress: 'r***@example.com'
    });
    api.openRaw.mockRejectedValueOnce(new SecretApiError(403, null, 'email_verification_required'));
    const emailFixture = await renderApp(`/s/${id}#${key}`);
    const emailRecipient = emailFixture.debugElement.query(By.directive(RecipientPage)).injector.get(RecipientState);
    await vi.waitFor(() => expect(emailRecipient.metadataReady()).toBe(true));
    await emailRecipient.open();
    emailFixture.detectChanges();
    expect((emailFixture.nativeElement as HTMLElement).textContent).toContain('Verify the email address before opening this link.');
    expect((emailFixture.nativeElement as HTMLElement).textContent).not.toContain('This link is unavailable.');

    emailFixture.destroy();
    api.getMetadata.mockResolvedValueOnce({
      exists: true,
      protocolVersion: 1,
      expiresAt: '2030-01-01T00:00:00.000Z',
      passwordProtected: false,
      hasMessage: true,
      fileCount: 0,
      files: []
    });
    api.openRaw.mockRejectedValueOnce(new SecretApiError(429, 60, 'rate_limited'));
    const rateLimitFixture = await renderApp(`/s/${id}#${key}`);
    const rateLimitRecipient = rateLimitFixture.debugElement.query(By.directive(RecipientPage)).injector.get(RecipientState);
    await vi.waitFor(() => expect(rateLimitRecipient.metadataReady()).toBe(true));
    await rateLimitRecipient.open();
    rateLimitFixture.detectChanges();
    expect((rateLimitFixture.nativeElement as HTMLElement).textContent).toContain('too many failed attempts');
    expect((rateLimitFixture.nativeElement as HTMLElement).textContent).not.toContain('This link is unavailable.');
  });

  it('sends a code only after the recipient requests it and then verifies the code before opening', async () => {
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    api.getMetadata.mockResolvedValue({
      exists: true,
      protocolVersion: 1,
      expiresAt: '2030-01-01T00:00:00.000Z',
      passwordProtected: false,
      hasMessage: true,
      fileCount: 0,
      files: [],
      emailVerificationRequired: true,
      maskedEmailAddress: 'r***@example.com'
    });
    const fixture = await renderApp(`/s/${id}#${'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'}`);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('r***@example.com');
    expect(compiled.textContent).toContain('This also applies when you open the link in another browser.');
    const requestButton = compiled.querySelector<HTMLButtonElement>('[data-testid="request-email-code"]');
    expect(requestButton).not.toBeNull();
    expect(api.requestEmailCode).not.toHaveBeenCalled();
    expect(api.openRaw).not.toHaveBeenCalled();
    expect(compiled.querySelector('.card .primary')?.textContent).toContain('Request code');

    requestButton!.click();
    await vi.waitFor(() => expect(api.requestEmailCode).toHaveBeenCalledOnce());
    expect(api.requestEmailCode).toHaveBeenCalledWith(id);
    await fixture.whenStable();
    fixture.detectChanges();
    expect(compiled.textContent).toContain('this page does not tell you whether an email was sent');
    const resendButton = compiled.querySelector<HTMLButtonElement>('[data-testid="request-new-email-code"]');
    expect(resendButton).not.toBeNull();
    expect(resendButton!.disabled).toBe(true);
    expect(resendButton!.textContent).toContain('01:00');
    resendButton!.click();
    expect(api.requestEmailCode).toHaveBeenCalledOnce();

    const code = compiled.querySelector<HTMLInputElement>('[data-testid="email-verification-code"]')!;
    code.value = '123456';
    code.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    compiled.querySelector<HTMLFormElement>('.email-verification-code-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(api.verifyEmailCode).toHaveBeenCalledWith(id, '123456'));
    await fixture.whenStable();
    fixture.detectChanges();
    expect(compiled.querySelector('.card > .primary')?.textContent).toContain('Open content');
    expect(api.openRaw).not.toHaveBeenCalled();
    expect(localStorage.getItem(`privacylink.email-verification.${id}`)).toBeTruthy();
  });

  it('does not apply a code request response to a different link', async () => {
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    const nextId = 'AQAAAAAAAAAAAAAAAAAAAA';
    let completeRequest!: (result: { code: string }) => void;
    api.getMetadata.mockResolvedValue({
      exists: true,
      protocolVersion: 1,
      expiresAt: '2030-01-01T00:00:00.000Z',
      passwordProtected: false,
      hasMessage: true,
      fileCount: 0,
      files: [],
      emailVerificationRequired: true,
      maskedEmailAddress: 'r***@example.com'
    });
    api.requestEmailCode.mockImplementation(() => new Promise(resolve => { completeRequest = resolve; }));
    const fixture = await renderApp(`/s/${id}#${'A'.repeat(43)}`);
    const recipient = fixture.debugElement.query(By.directive(RecipientPage)).injector.get(RecipientState);
    await vi.waitFor(() => expect(recipient.metadataReady()).toBe(true));
    (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('[data-testid="request-email-code"]')!.click();
    await vi.waitFor(() => expect(api.requestEmailCode).toHaveBeenCalledOnce());

    await TestBed.inject(Router).navigateByUrl(`/s/${nextId}#${'A'.repeat(43)}`);
    await vi.waitFor(() => expect(api.getMetadata).toHaveBeenCalledTimes(2));
    await fixture.whenStable();
    completeRequest({ code: 'verification_requested' });
    await fixture.whenStable();
    fixture.detectChanges();

    expect(recipient.emailCodeRequested()).toBe(false);
    expect(recipient.emailVerified()).toBe(false);
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="request-email-code"]')).not.toBeNull();
  });

  it('does not save a verification session for a link opened while verification is pending', async () => {
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    const nextId = 'AQAAAAAAAAAAAAAAAAAAAA';
    let completeVerification!: () => void;
    api.getMetadata.mockResolvedValue({
      exists: true,
      protocolVersion: 1,
      expiresAt: '2030-01-01T00:00:00.000Z',
      passwordProtected: false,
      hasMessage: true,
      fileCount: 0,
      files: [],
      emailVerificationRequired: true,
      maskedEmailAddress: 'r***@example.com'
    });
    api.verifyEmailCode.mockImplementation(() => new Promise<void>(resolve => { completeVerification = () => resolve(); }));
    const fixture = await renderApp(`/s/${id}#${'A'.repeat(43)}`);
    const recipient = fixture.debugElement.query(By.directive(RecipientPage)).injector.get(RecipientState);
    await vi.waitFor(() => expect(recipient.metadataReady()).toBe(true));
    (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('[data-testid="request-email-code"]')!.click();
    await vi.waitFor(() => expect(api.requestEmailCode).toHaveBeenCalledOnce());
    await fixture.whenStable();
    fixture.detectChanges();
    const code = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>('[data-testid="email-verification-code"]')!;
    code.value = '123456';
    code.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    (fixture.nativeElement as HTMLElement).querySelector<HTMLFormElement>('.email-verification-code-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(api.verifyEmailCode).toHaveBeenCalledOnce());

    await TestBed.inject(Router).navigateByUrl(`/s/${nextId}#${'A'.repeat(43)}`);
    await vi.waitFor(() => expect(api.getMetadata).toHaveBeenCalledTimes(2));
    await fixture.whenStable();
    completeVerification();
    await fixture.whenStable();
    fixture.detectChanges();

    expect(recipient.emailVerified()).toBe(false);
    expect(localStorage.getItem(`privacylink.email-verification.${id}`)).toBeNull();
    expect(localStorage.getItem(`privacylink.email-verification.${nextId}`)).toBeNull();
  });

  it('keeps metadata files visible when the unprotected open response only contains the message', async () => {
    const encrypted = await encryptMessage('Message with files');
    const key = decodeCanonical(encrypted.clientKey, 32);
    const encryptedFiles = await Promise.all([
      encryptFile(new File(['first'], 'first.pdf', { type: 'application/pdf' }), key),
      encryptFile(new File(['second'], 'second.pdf', { type: 'application/pdf' }), key)
    ]);
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    api.getMetadata.mockResolvedValue({
      exists: true,
      protocolVersion: 1,
      expiresAt: '2030-01-01T00:00:00.000Z',
      passwordProtected: false,
      hasMessage: true,
      fileCount: encryptedFiles.length,
      files: encryptedFiles
    });
    api.openRaw.mockResolvedValue(new TextEncoder().encode(JSON.stringify({
      protocolVersion: 1,
      message: encrypted.message,
      files: []
    })).buffer);
    api.openFileRaw.mockResolvedValue(new TextEncoder().encode(JSON.stringify({
      protocolVersion: 1,
      file: encryptedFiles[0]
    })).buffer);
    const fixture = await renderApp(`/s/${id}#${encrypted.clientKey}`);
    const recipient = fixture.debugElement.query(By.directive(RecipientPage)).injector.get(RecipientState);
    await vi.waitFor(() => expect(recipient.metadataReady()).toBe(true));
    expect(recipient.metadataFiles().map(file => file.name)).toEqual(['first.pdf', 'second.pdf']);

    await recipient.open();

    expect(recipient.openedMessage()).toBe('Message with files');
    expect(recipient.metadataFiles().map(file => file.name)).toEqual(['first.pdf', 'second.pdf']);
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    await recipient.download(recipient.metadataFiles()[0]!);
    anchorClick.mockRestore();
    expect(api.openFileRaw).toHaveBeenCalledWith(id, encryptedFiles[0]!.id);
  });

  it('renders the security and not-found routes with matching titles and focus', async () => {
    const fixture = await renderApp('/security');
    const router = TestBed.inject(Router);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('h1')?.textContent).toContain('How the security works');
    expect(document.title).toBe('Security — PrivacyLink');
    expect(document.activeElement).toBe((fixture.nativeElement as HTMLElement).querySelector('#page-title'));

    await router.navigateByUrl('/missing-page');
    await fixture.whenStable();
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('h1')?.textContent).toContain('This page could not be found');
    expect(document.title).toBe('Page not found — PrivacyLink');
  });

  it('creates a link with its client key in the URL fragment only', async () => {
    const fixture = await renderApp();
    const message = (fixture.nativeElement as HTMLElement).querySelector<HTMLTextAreaElement>('#message');
    expect(message).not.toBeNull();
    message!.value = 'A private message';
    message!.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('.compose-actions .primary')!.click();
    await vi.waitFor(() => expect(api.create).toHaveBeenCalledTimes(1));
    await fixture.whenStable();
    fixture.detectChanges();

    expect(TestBed.inject(AppState).mode()).toBe('result');
    const shareLink = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>('#share-link')?.value;
    expect(shareLink).toBeTruthy();
    const link = new URL(shareLink!);
    expect(link.pathname).toBe('/s/AAAAAAAAAAAAAAAAAAAAAA');
    expect(link.search).toBe('');
    expect(link.hash).toMatch(/^#[A-Za-z0-9_-]{43}$/);
    expect(TestBed.inject(Router).url).toBe('/');
    expect(api.create).toHaveBeenCalledWith(expect.not.objectContaining({ clientKey: expect.any(String) }), expect.stringMatching(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[0-9]+\.[0-9]+\.[A-Za-z0-9_-]+\.[0-9]+$/));
    expect(localStorage.getItem('privacylink.secret-history.v1')).toBeNull();
    expect(localStorage.getItem('privacylink.secret-history.v2')).toBeNull();
    expect(localStorage.getItem('privacylink.secret-history.v3')).toBeNull();
  });

  it('stores no sender history unless the user opts in', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    create.message.set('Do not retain this message');
    await create.create();
    fixture.detectChanges();

    expect(TestBed.inject(AppState).mode()).toBe('result');
    expect(localStorage.getItem('privacylink.secret-history.v1')).toBeNull();
    expect(localStorage.getItem('privacylink.secret-history.v2')).toBeNull();
    expect(localStorage.getItem('privacylink.secret-history.v3')).toBeNull();
    expect(localStorage.getItem('privacylink.secret-history.credential.v2')).toBeNull();
  });

  it('stores opted-in history only as ciphertext after passphrase setup', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    create.message.set('History secret text');
    create.password.set('History secret password');
    const compiled = fixture.nativeElement as HTMLElement;
    compiled.querySelector<HTMLButtonElement>('.header-tools .history-nav-link')!.click();
    expect(compiled.querySelector('#history-opt-in-description')?.textContent).toContain('History contains the full link');
    const passphraseInput = compiled.querySelector<HTMLInputElement>('#history-passphrase')!;
    const confirmationInput = compiled.querySelector<HTMLInputElement>('#history-passphrase-confirmation')!;
    passphraseInput.value = 'violet lantern river meadow';
    passphraseInput.dispatchEvent(new Event('input'));
    confirmationInput.value = 'violet lantern river meadow';
    confirmationInput.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    compiled.querySelector<HTMLButtonElement>('.history-opt-in-confirm')!.click();
    fixture.detectChanges();
    const optInDialog = compiled.querySelector<HTMLDialogElement>('#history-opt-in-title')!.closest('dialog')!;
    expect(create.historySetupBusy()).toBe(true);
    expect(optInDialog.querySelector<HTMLButtonElement>('.generator-close')?.disabled).toBe(true);
    const cancelSetup = new Event('cancel', { cancelable: true });
    optInDialog.dispatchEvent(cancelSetup);
    expect(cancelSetup.defaultPrevented).toBe(true);
    expect(optInDialog.open).toBe(true);
    await vi.waitFor(() => expect(TestBed.inject(SecretHistoryStore).unlocked()).toBe(true));
    await fixture.whenStable();
    await create.create(true);
    fixture.detectChanges();

    const stored = [...Array(localStorage.length)].map((_, index) => localStorage.getItem(localStorage.key(index)!) ?? '').join('\n');
    expect(localStorage.getItem('privacylink.secret-history.v3')).toContain('"version":3');
    expect(stored).not.toContain(create.shareLink());
    expect(stored).not.toContain('History secret password');
    expect(stored).not.toContain('test-revoke-token');
  });

  it('does not enable history when the passphrase confirmation does not match', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    create.message.set('Link remains available');
    const compiled = fixture.nativeElement as HTMLElement;
    compiled.querySelector<HTMLButtonElement>('.header-tools .history-nav-link')!.click();
    const passphraseInput = compiled.querySelector<HTMLInputElement>('#history-passphrase')!;
    const confirmationInput = compiled.querySelector<HTMLInputElement>('#history-passphrase-confirmation')!;
    passphraseInput.value = 'violet lantern river meadow';
    passphraseInput.dispatchEvent(new Event('input'));
    confirmationInput.value = 'different violet river meadow';
    confirmationInput.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    compiled.querySelector<HTMLButtonElement>('.history-opt-in-confirm')!.click();
    expect(TestBed.inject(SecretHistoryStore).enabled()).toBe(false);
    await create.create();
    fixture.detectChanges();

    expect(TestBed.inject(AppState).mode()).toBe('result');
    expect(localStorage.getItem('privacylink.secret-history.v1')).toBeNull();
    expect(localStorage.getItem('privacylink.secret-history.v2')).toBeNull();
    expect(localStorage.getItem('privacylink.secret-history.credential.v2')).toBeNull();
    expect(localStorage.getItem('privacylink.secret-history.v3')).toBeNull();
  });

  it('lets the user cancel a create while history is locked or continue without saving', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    const history = TestBed.inject(SecretHistoryStore);
    create.message.set('Keep this draft');
    expect(await history.enable('violet lantern river meadow')).toBe(true);
    history.unlocked.set(false);

    await create.create();
    expect(create.historyLockedDialogOpen()).toBe(true);
    expect(api.create).not.toHaveBeenCalled();
    create.cancelLockedHistoryCreation();
    expect(create.message()).toBe('Keep this draft');
    expect(api.create).not.toHaveBeenCalled();

    await create.create();
    create.continueWithoutHistory();
    await vi.waitFor(() => expect(api.create).toHaveBeenCalledOnce());
    await fixture.whenStable();
    fixture.detectChanges();

    expect(TestBed.inject(AppState).mode()).toBe('result');
    expect(create.historyWarning()).toBe('notSaved');
    expect(history.entries()).toEqual([]);
  });

  it('shows one header history control for disabled, locked and unlocked states', async () => {
    const fixture = await renderApp();
    const compiled = fixture.nativeElement as HTMLElement;
    const store = TestBed.inject(SecretHistoryStore);
    const headerControl = () => compiled.querySelector<HTMLElement>('.header-tools .history-nav-link')!;

    expect(headerControl().textContent).toContain('Save links to history');
    expect(compiled.querySelector('.compose-actions .history-opt-in-link')).toBeNull();
    headerControl().click();
    fixture.detectChanges();
    const optInDialog = compiled.querySelector<HTMLDialogElement>('#history-opt-in-title')!.closest('dialog')!;
    expect(optInDialog.open).toBe(true);
    optInDialog.querySelector<HTMLButtonElement>('.generator-close')!.click();
    fixture.detectChanges();
    expect(optInDialog.open).toBe(false);

    expect(await store.enable('violet lantern river meadow')).toBe(true);
    store.unlocked.set(false);
    fixture.detectChanges();
    expect(headerControl().textContent).toContain('Unlock history');
    expect(compiled.querySelector('.compose-actions .history-opt-in-link')).toBeNull();

    store.unlocked.set(true);
    fixture.detectChanges();
    expect(compiled.querySelector<HTMLAnchorElement>('.header-tools .history-nav-link')?.textContent).toContain('History');
    expect(compiled.querySelector('.compose-actions .history-opt-in-link')).toBeNull();
    headerControl().click();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(TestBed.inject(Router).url).toBe('/history');
  });

  it('explains result-page history setup does not save the current link', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    const store = TestBed.inject(SecretHistoryStore);
    const compiled = fixture.nativeElement as HTMLElement;
    create.message.set('Current link is not retroactively saved');
    await create.create();
    fixture.detectChanges();

    compiled.querySelector<HTMLButtonElement>('.header-tools .history-nav-link')!.click();
    fixture.detectChanges();
    expect(compiled.querySelector('#history-enable-future-only')?.textContent).toContain('This current link will not be added');
    const passphraseInput = compiled.querySelector<HTMLInputElement>('#history-passphrase')!;
    const confirmationInput = compiled.querySelector<HTMLInputElement>('#history-passphrase-confirmation')!;
    passphraseInput.value = 'violet lantern river meadow';
    passphraseInput.dispatchEvent(new Event('input'));
    confirmationInput.value = 'violet lantern river meadow';
    confirmationInput.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    compiled.querySelector<HTMLButtonElement>('.history-opt-in-confirm')!.click();

    await vi.waitFor(() => expect(store.unlocked()).toBe(true));
    await fixture.whenStable();
    fixture.detectChanges();
    expect(store.entries()).toEqual([]);
    expect(compiled.querySelector('.card [role="status"]')?.textContent).toContain('This link was not added');
    expect(compiled.querySelector<HTMLAnchorElement>('.header-tools .history-nav-link')?.textContent).toContain('History');
    expect(create.historyEnabledFromResult()).toBe(true);

    compiled.querySelector<HTMLAnchorElement>('.header-tools .history-nav-link')!.click();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(TestBed.inject(AppState).mode()).toBe('history');
    expect(create.historyEnabledFromResult()).toBe(false);

    compiled.querySelector<HTMLAnchorElement>('.header-tools a')!.click();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(TestBed.inject(AppState).mode()).toBe('create');
    expect(create.historyEnabledFromResult()).toBe(false);
    create.message.set('A new link after history was enabled');
    await create.create();
    fixture.detectChanges();
    expect(TestBed.inject(AppState).mode()).toBe('result');
    expect(store.entries()).toHaveLength(1);
    expect(compiled.querySelector('.card [role="status"]')).toBeNull();
  });

  it('opens the shared unlock dialog from the create header and stays on the create form after success', async () => {
    const store = TestBed.inject(SecretHistoryStore);
    expect(await store.enable('violet lantern river meadow')).toBe(true);
    store.unlocked.set(false);
    const fixture = await renderApp();
    const compiled = fixture.nativeElement as HTMLElement;
    const trigger = compiled.querySelector<HTMLButtonElement>('.header-tools .history-nav-link')!;

    expect(trigger.textContent).toContain('Unlock history');
    trigger.click();
    fixture.detectChanges();
    const dialog = compiled.querySelector<HTMLDialogElement>('#unlock-history-dialog')!;
    expect(dialog.open).toBe(true);
    const passphrase = compiled.querySelector<HTMLInputElement>('#history-unlock-passphrase')!;
    passphrase.value = 'violet lantern river meadow';
    passphrase.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    compiled.querySelector<HTMLButtonElement>('.history-unlock-confirm')!.click();

    await vi.waitFor(() => expect(store.unlocked()).toBe(true));
    await fixture.whenStable();
    fixture.detectChanges();
    expect(TestBed.inject(Router).url).toBe('/');
    expect(TestBed.inject(AppState).mode()).toBe('create');
    expect(compiled.querySelector('#message')).not.toBeNull();
    expect(compiled.querySelector('.history-empty')).toBeNull();
  });

  it('keeps the locked History page passphrase-free and opens reset from the shared dialog', async () => {
    const store = TestBed.inject(SecretHistoryStore);
    expect(await store.enable('violet lantern river meadow')).toBe(true);
    store.unlocked.set(false);
    const fixture = await renderApp('/history');
    const compiled = fixture.nativeElement as HTMLElement;

    expect(compiled.querySelector('.history-vault-notice input')).toBeNull();
    const trigger = compiled.querySelector<HTMLButtonElement>('.history-vault-notice button.primary')!;
    trigger.click();
    fixture.detectChanges();
    const unlockDialog = compiled.querySelector<HTMLDialogElement>('#unlock-history-dialog')!;
    expect(unlockDialog.open).toBe(true);
    compiled.querySelector<HTMLButtonElement>('.history-reset-link button')!.click();
    fixture.detectChanges();

    const resetDialog = compiled.querySelector<HTMLDialogElement>('#reset-vault-title')!.closest('dialog')!;
    expect(unlockDialog.open).toBe(false);
    expect(resetDialog.open).toBe(true);
  });

  it('keeps the reset dialog open while deriving the replacement vault key', async () => {
    const store = TestBed.inject(SecretHistoryStore);
    expect(await store.enable('violet lantern river meadow')).toBe(true);
    await store.add({
      id: 'AAAAAAAAAAAAAAAAAAAAAA',
      createdAt: '2026-10-24T07:00:00.000Z',
      link: 'https://example.test/s/secret#client-key',
      expiresAt: '2030-01-01T00:00:00.000Z',
      password: '',
      revokeToken: 'test-token'
    });
    const fixture = await renderApp('/history');
    const history = TestBed.inject(HistoryState);
    history.requestResetVault();
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    const passphrase = compiled.querySelector<HTMLInputElement>('#reset-history-passphrase')!;
    const confirmation = compiled.querySelector<HTMLInputElement>('#reset-history-passphrase-confirmation')!;
    passphrase.value = 'different violet river meadow';
    passphrase.dispatchEvent(new Event('input'));
    confirmation.value = 'different violet river meadow';
    confirmation.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    const dialog = compiled.querySelector<HTMLDialogElement>('#reset-vault-title')!.closest('dialog')!;
    compiled.querySelector<HTMLButtonElement>('#reset-vault-title ~ .history-passphrase-fields ~ .dialog-actions .primary')!.click();
    fixture.detectChanges();
    expect(history.vaultBusy()).toBe(true);
    const cancel = new Event('cancel', { cancelable: true });
    dialog.dispatchEvent(cancel);
    expect(cancel.defaultPrevented).toBe(true);
    expect(dialog.open).toBe(true);
    expect(compiled.querySelector<HTMLButtonElement>('#reset-vault-title ~ .history-passphrase-fields ~ .dialog-actions .secondary')?.disabled).toBe(true);

    await vi.waitFor(() => expect(history.resetVaultDialogOpen()).toBe(false));
    expect(store.entries()).toEqual([]);
  });

  it('creates successfully when the local wall clock is five minutes ahead of the challenge issuer', async () => {
    const actualNow = Date.now();
    const serverExpiresAt = Math.floor(actualNow / 1000) + 300;
    api.getCreateChallenge.mockResolvedValue({
      version: 1,
      challengeId: 'AAAAAAAAAAAAAAAAAAAAAA',
      nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
      difficultyBits: 1,
      expiresAt: serverExpiresAt,
      signature: 'test-signature'
    });
    const wallClock = vi.spyOn(Date, 'now').mockReturnValue(actualNow + 5 * 60 * 1000);

    try {
      const fixture = await renderApp();
      const message = (fixture.nativeElement as HTMLElement).querySelector<HTMLTextAreaElement>('#message');
      message!.value = 'A private message';
      message!.dispatchEvent(new Event('input'));
      fixture.detectChanges();

      (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('.compose-actions .primary')!.click();
      await vi.waitFor(() => expect(api.create).toHaveBeenCalledTimes(1));
      await fixture.whenStable();

      expect(TestBed.inject(AppState).mode()).toBe('result');
      expect(api.create.mock.calls[0]?.[1]?.split('.')[3]).toBe(String(serverExpiresAt));
    } finally {
      wallClock.mockRestore();
    }
  });

  it('keeps history cell labels available to the compact layout after unlocking the vault', async () => {
    const history = TestBed.inject(SecretHistoryStore);
    await history.enable('violet lantern river meadow');
    await history.add({
      id: 'AAAAAAAAAAAAAAAAAAAAAA',
      createdAt: '2026-09-25T12:00:00.000Z',
      link: 'http://localhost:4200/s/AAAAAAAAAAAAAAAAAAAAAA#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      expiresAt: '2030-01-01T00:00:00.000Z',
      password: 'test-only-pin',
      revokeToken: 'test-only-revoke-token'
    });
    const fixture = await renderApp('/history');
    const cells = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll<HTMLTableCellElement>('.history-table tbody tr td'));

    expect(cells.slice(0, 4).map(cell => cell.dataset['label'])).toEqual(['Created', 'Secure link', 'Expires on', 'PIN / password']);
  });
});
