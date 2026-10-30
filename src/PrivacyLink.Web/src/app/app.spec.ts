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
import { LinkSharingState } from './link-sharing-state';
import { RecipientState } from './recipient/recipient-state';
import { RecipientPage } from './recipient/recipient-page';
import { SecretApi, SecretApiError } from './secret-api';
import { SECRET_HISTORY_STORAGE, SecretHistoryStore } from './secret-history-store';
import { installTestWebLocks } from '../../test-utils/web-locks';
import { MemoryHistoryStorage } from '../../test-utils/memory-history-storage';
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
  let historyStorage: MemoryHistoryStorage;
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
    historyStorage = new MemoryHistoryStorage();
    vi.stubGlobal('Worker', InlineCryptoWorker);
    api = createSecretApiStub();
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [
        provideRouter(routes),
        { provide: SecretApi, useValue: api },
        { provide: SECRET_HISTORY_STORAGE, useValue: historyStorage }
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

  it('keeps the website recipient flow available when extension site access is unavailable', async () => {
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
    expect((passwordFixture.nativeElement as HTMLElement).textContent).toContain('That did not work. Check the access code');
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
      passwordProtected: true,
      hasMessage: true,
      fileCount: 0,
      files: [],
      emailVerificationRequired: true,
      maskedEmailAddress: 'r***@example.com'
    });
    const fixture = await renderApp(`/s/${id}#${'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'}`);

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('To open this content, the recipient first verifies the email address and then enters the access code.');
    expect(compiled.querySelector('#unlock-password')).toBeNull();
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
    expect(compiled.querySelector('#unlock-password')).not.toBeNull();
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

  it('configures optional security separately and shows the access code on the result page', async () => {
    const fixture = await renderApp();
    const compiled = fixture.nativeElement as HTMLElement;
    const create = TestBed.inject(CreateState);
    const sharing = TestBed.inject(LinkSharingState);
    const copySpy = vi.spyOn(sharing, 'copy').mockResolvedValue(true);
    const shareSpy = vi.spyOn(sharing, 'share').mockResolvedValue();
    const accessCode = 'separate-channel-code';
    const securityDisclosure = compiled.querySelector<HTMLDetailsElement>('[data-testid="security-disclosure"]')!;

    expect(securityDisclosure.open).toBe(false);
    expect(compiled.querySelector('.security-disclosure-status')?.textContent).toContain('Not configured');
    expect(compiled.querySelector('.security-status-summary')).toBeNull();
    expect(compiled.querySelector('#expiry')).not.toBeNull();
    expect(compiled.querySelector('#access-code-input')?.closest('dialog')?.open).toBe(false);
    expect(compiled.querySelector('#password-copy-title')).toBeNull();

    securityDisclosure.open = true;
    fixture.detectChanges();
    compiled.querySelector<HTMLButtonElement>('[data-testid="access-code-action"]')!.click();
    fixture.detectChanges();
    let accessCodeDialog = compiled.querySelector<HTMLDialogElement>('#access-code-title')!.closest('dialog')!;
    let accessCodeInput = compiled.querySelector<HTMLInputElement>('[data-testid="access-code-input"]')!;
    expect(document.activeElement).toBe(accessCodeInput);
    accessCodeInput.value = 'discarded-draft';
    accessCodeInput.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    accessCodeDialog.querySelector<HTMLButtonElement>('.dialog-actions .secondary')!.click();
    fixture.detectChanges();
    expect(create.password()).toBe('');

    compiled.querySelector<HTMLButtonElement>('[data-testid="access-code-action"]')!.click();
    fixture.detectChanges();
    accessCodeDialog = compiled.querySelector<HTMLDialogElement>('#access-code-title')!.closest('dialog')!;
    accessCodeInput = compiled.querySelector<HTMLInputElement>('[data-testid="access-code-input"]')!;
    const generateAccessCodeButton = accessCodeDialog.querySelector<HTMLButtonElement>('[data-testid="generate-access-code"]')!;
    expect(generateAccessCodeButton.textContent).toContain('Generate access code');
    generateAccessCodeButton.click();
    fixture.detectChanges();
    const generatorDialog = compiled.querySelector<HTMLDialogElement>('.password-generator-dialog')!;
    expect(generatorDialog.open).toBe(true);
    const generatedCode = generatorDialog.querySelector<HTMLOutputElement>('.generator-value')!.textContent!.trim();
    generatorDialog.querySelector<HTMLButtonElement>('[aria-label="Copy access code"]')!.click();
    await fixture.whenStable();
    expect(copySpy).toHaveBeenCalledWith(generatedCode);
    generatorDialog.querySelector<HTMLButtonElement>('.generator-actions .primary')!.click();
    fixture.detectChanges();
    expect(compiled.querySelector<HTMLInputElement>('[data-testid="access-code-input"]')!.value).toBe(generatedCode);
    expect(accessCodeInput.type).toBe('text');
    expect(accessCodeInput.autocomplete).toBe('off');
    expect(accessCodeDialog.querySelector('[aria-label="Show access code"]')).toBeNull();
    expect(create.password()).toBe('');
    accessCodeInput.value = accessCode;
    accessCodeInput.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    expect(accessCodeInput.value).toBe(accessCode);
    accessCodeDialog.querySelector<HTMLButtonElement>('.dialog-actions .primary')!.click();
    fixture.detectChanges();
    expect(create.password()).toBe(accessCode);
    expect(compiled.querySelector('.security-option-summary')?.textContent).toContain('Access code set');
    expect(compiled.querySelector('.security-disclosure-status')?.textContent).toContain('Access code set');
    const accessCodeAction = compiled.querySelector<HTMLButtonElement>('[data-testid="access-code-action"]')!;
    expect(accessCodeAction.textContent).toContain('Remove');
    expect(accessCodeAction.getAttribute('aria-label')).toBe('Remove access code');

    accessCodeAction.click();
    fixture.detectChanges();
    expect(create.password()).toBe('');
    expect(compiled.querySelector('[data-testid="access-code-action"]')?.textContent).toContain('Set access code');
    compiled.querySelector<HTMLButtonElement>('[data-testid="access-code-action"]')!.click();
    fixture.detectChanges();
    accessCodeInput = compiled.querySelector<HTMLInputElement>('[data-testid="access-code-input"]')!;
    accessCodeInput.value = 'unsaved-change';
    accessCodeInput.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    accessCodeDialog.querySelector<HTMLButtonElement>('.dialog-actions .secondary')!.click();
    fixture.detectChanges();
    expect(create.password()).toBe('');
    compiled.querySelector<HTMLButtonElement>('[data-testid="access-code-action"]')!.click();
    fixture.detectChanges();
    accessCodeInput = compiled.querySelector<HTMLInputElement>('[data-testid="access-code-input"]')!;
    accessCodeInput.value = accessCode;
    accessCodeInput.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    accessCodeDialog.querySelector<HTMLButtonElement>('.dialog-actions .primary')!.click();
    fixture.detectChanges();
    expect(create.password()).toBe(accessCode);

    compiled.querySelector<HTMLButtonElement>('[data-testid="email-verification-action"]')!.click();
    fixture.detectChanges();
    const emailDialog = compiled.querySelector<HTMLDialogElement>('#email-verification-title')!.closest('dialog')!;
    let email = compiled.querySelector<HTMLInputElement>('#recipient-email')!;
    email.value = 'recipient@example.com';
    email.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    emailDialog.querySelector<HTMLButtonElement>('.dialog-actions .secondary')!.click();
    fixture.detectChanges();
    expect(create.emailVerificationEnabled()).toBe(false);

    compiled.querySelector<HTMLButtonElement>('[data-testid="email-verification-action"]')!.click();
    fixture.detectChanges();
    email = compiled.querySelector<HTMLInputElement>('#recipient-email')!;
    email.value = 'recipient@example.com';
    email.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    compiled.querySelector<HTMLFormElement>('.email-verification-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    fixture.detectChanges();
    expect(create.emailVerificationEnabled()).toBe(true);
    expect(compiled.querySelector('.security-disclosure-status')?.textContent).toContain('Both options set');
    const emailVerificationAction = compiled.querySelector<HTMLButtonElement>('[data-testid="email-verification-action"]')!;
    expect(emailVerificationAction.textContent).toContain('Remove');
    expect(emailVerificationAction.getAttribute('aria-label')).toBe('Remove email verification');
    emailVerificationAction.click();
    fixture.detectChanges();
    expect(create.emailVerificationEnabled()).toBe(false);
    expect(compiled.querySelector('[data-testid="email-verification-action"]')?.textContent).toContain('Set up email verification');
    compiled.querySelector<HTMLButtonElement>('[data-testid="email-verification-action"]')!.click();
    fixture.detectChanges();
    email = compiled.querySelector<HTMLInputElement>('#recipient-email')!;
    email.value = 'recipient@example.com';
    email.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    compiled.querySelector<HTMLFormElement>('.email-verification-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    fixture.detectChanges();
    expect(create.emailVerificationEnabled()).toBe(true);

    const message = compiled.querySelector<HTMLTextAreaElement>('#message')!;
    message.value = 'Protected content';
    message.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    compiled.querySelector<HTMLButtonElement>('.compose-actions .primary')!.click();
    await vi.waitFor(() => expect(api.create).toHaveBeenCalledOnce());
    await fixture.whenStable();
    fixture.detectChanges();

    const request = api.create.mock.calls[0]?.[0];
    expect(request).toEqual(expect.objectContaining({ emailAddress: 'recipient@example.com', password: expect.any(String) }));
    expect(create.password()).toBe('');
    expect(create.resultAccessCode()).toBe(accessCode);
    expect(compiled.querySelector<HTMLInputElement>('#result-access-code')?.value).toBe(accessCode);
    expect(compiled.querySelector('#expiry')).toBeNull();
    expect(compiled.textContent).toContain('Expires on');
    expect(create.shareLink()).not.toContain(accessCode);

    create.share();
    expect(shareSpy).toHaveBeenCalledWith(create.shareLink());
    compiled.querySelector<HTMLButtonElement>('[data-testid="copy-result-access-code"]')!.click();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(copySpy).toHaveBeenCalledWith(accessCode);
    const copyAccessCodeButton = compiled.querySelector<HTMLButtonElement>('[data-testid="copy-result-access-code"]');
    expect(copyAccessCodeButton?.getAttribute('aria-label')).toBe('Copy access code');
    expect(copyAccessCodeButton?.textContent?.trim()).toBe('');
    expect(copyAccessCodeButton?.classList.contains('is-copied')).toBe(true);
    expect(compiled.querySelector('[data-testid="copy-access-code-status"]')?.textContent?.trim()).toBe('Access code copied');

    compiled.querySelector<HTMLButtonElement>('[data-testid="copy-result-link"]')!.click();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(copySpy).toHaveBeenCalledWith(create.shareLink());
    const copyLinkButton = compiled.querySelector<HTMLButtonElement>('[data-testid="copy-result-link"]');
    expect(copyLinkButton?.getAttribute('aria-label')).toBe('Copy link');
    expect(copyLinkButton?.classList.contains('is-copied')).toBe(true);
    expect(compiled.querySelector('[data-testid="copy-link-status"]')?.textContent?.trim()).toBe('Link copied');

    await TestBed.inject(Router).navigateByUrl('/security');
    await fixture.whenStable();
    fixture.detectChanges();
    expect(create.resultAccessCode()).toBe('');
    expect(compiled.querySelector('#result-access-code')).toBeNull();

    await TestBed.inject(Router).navigateByUrl('/');
    await fixture.whenStable();
    create.password.set('next-secret-code');
    create.message.set('Another secret');
    await create.create();
    fixture.detectChanges();
    expect(create.resultAccessCode()).toBe('next-secret-code');
    compiled.querySelector<HTMLButtonElement>('.result-create-another')!.click();
    fixture.detectChanges();
    expect(create.resultAccessCode()).toBe('');
  });

  it('automatically saves newly created links as encrypted history entries', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    const store = TestBed.inject(SecretHistoryStore);
    await store.whenReady();
    create.message.set('History secret text');
    create.password.set('History secret password');

    await create.create();
    fixture.detectChanges();

    expect(TestBed.inject(AppState).mode()).toBe('result');
    expect(store.entries()).toHaveLength(1);
    expect(store.entries()[0]).toMatchObject({
      link: create.shareLink(),
      password: 'History secret password',
      revokeToken: 'test-revoke-token'
    });
    expect(historyStorage.records.size).toBe(1);
    const persisted = JSON.stringify([...historyStorage.records.values()].map(record => ({
      id: record.id,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      iv: Array.from(new Uint8Array(record.iv)),
      ciphertext: Array.from(new Uint8Array(record.ciphertext))
    })));
    expect(persisted).not.toContain(create.shareLink());
    expect(persisted).not.toContain('History secret password');
    expect(persisted).not.toContain('test-revoke-token');

    const key = historyStorage.metadata.get('encryptionKey') as CryptoKey;
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
  });

  it('opens history automatically without an unlock prompt and lets the sender edit a label', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    const store = TestBed.inject(SecretHistoryStore);
    create.message.set('A link with a label');
    await create.create();

    await TestBed.inject(Router).navigateByUrl('/history');
    await fixture.whenStable();
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;

    expect(compiled.querySelector('.history-vault-actions')).toBeNull();
    expect(compiled.textContent).not.toContain('Turn off and erase history');
    expect(compiled.querySelector('#unlock-history-dialog')).toBeNull();
    expect(compiled.querySelector('.history-table')).not.toBeNull();
    compiled.querySelector<HTMLButtonElement>('.history-label-action')!.click();
    fixture.detectChanges();
    const label = compiled.querySelector<HTMLInputElement>('.history-label-editor input')!;
    label.value = 'Finance handoff';
    label.dispatchEvent(new Event('input', { bubbles: true }));
    fixture.detectChanges();
    expect(TestBed.inject(HistoryState).labelDraft()).toBe('Finance handoff');
    compiled.querySelector<HTMLButtonElement>('.history-label-editor .secondary')!.click();
    await vi.waitFor(() => expect(TestBed.inject(HistoryState).editingLabelId()).toBe(''));
    fixture.detectChanges();

    expect(store.entries()[0]?.givenLabel).toBe('Finance handoff');
    const record = historyStorage.records.values().next().value!;
    const encryptedText = JSON.stringify(Array.from(new Uint8Array(record.ciphertext)));
    expect(encryptedText).not.toContain('Finance handoff');
    expect(compiled.querySelector('.history-entry-label')?.textContent).toContain('Finance handoff');
  });

  it('preserves copy, open, share, local remove, and explicit revoke actions', async () => {
    const fixture = await renderApp('/history');
    const store = TestBed.inject(SecretHistoryStore);
    const history = TestBed.inject(HistoryState);
    const sharing = TestBed.inject(LinkSharingState);
    const entry = {
      id: 'BBBBBBBBBBBBBBBBBBBBBB',
      createdAt: '2026-10-24T07:00:00.000Z',
      link: 'https://example.test/s/secret#client-key',
      expiresAt: '2030-01-01T00:00:00.000Z',
      password: 'access-code',
      revokeToken: 'revoke-token'
    };
    const copy = vi.spyOn(sharing, 'copy').mockResolvedValue(true);
    const open = vi.spyOn(sharing, 'openInNewTab');
    const share = vi.spyOn(sharing, 'share').mockResolvedValue();
    await store.add(entry);

    await history.copyHistoryValue(entry, 'link');
    history.openHistoryLink(entry);
    history.share(entry.link);
    expect(copy).toHaveBeenCalledWith(entry.link);
    expect(open).toHaveBeenCalledWith(entry.link);
    expect(share).toHaveBeenCalledWith(entry.link);

    history.requestHistoryAction(entry, 'forget');
    history.confirmHistoryAction();
    await vi.waitFor(() => expect(store.entries()).toHaveLength(0));
    expect(api.revoke).not.toHaveBeenCalled();

    await store.add(entry);
    history.requestHistoryAction(entry, 'revoke');
    history.confirmHistoryAction();
    await vi.waitFor(() => expect(api.revoke).toHaveBeenCalledWith(entry.id, entry.revokeToken));
    await vi.waitFor(() => expect(store.entries()).toHaveLength(0));
  });

  it('clears history and continues saving newly created links automatically', async () => {
    const store = TestBed.inject(SecretHistoryStore);
    await store.whenReady();
    const initialKey = historyStorage.metadata.get('encryptionKey');
    await store.add({
      id: 'CCCCCCCCCCCCCCCCCCCCCC',
      createdAt: '2026-10-24T07:00:00.000Z',
      link: 'https://example.test/s/secret#client-key',
      expiresAt: '2030-01-01T00:00:00.000Z',
      password: '',
      revokeToken: 'revoke-token'
    });

    expect(await store.clear()).toBe(true);
    expect(historyStorage.metadata.get('encryptionKey')).toBe(initialKey);
    expect(historyStorage.records.size).toBe(0);

    expect(await store.add({
      id: 'DDDDDDDDDDDDDDDDDDDDDD',
      createdAt: '2026-10-24T07:00:00.000Z',
      link: 'https://example.test/s/secret#client-key',
      expiresAt: '2030-01-01T00:00:00.000Z',
      password: '',
      revokeToken: 'revoke-token'
    })).toBe(true);
    expect(store.entries().map(item => item.id)).toEqual(['DDDDDDDDDDDDDDDDDDDDDD']);
  });

  it('keeps a created link available and warns when browser history storage fails', async () => {
    const fixture = await renderApp();
    const create = TestBed.inject(CreateState);
    await TestBed.inject(SecretHistoryStore).whenReady();
    historyStorage.failWrites = true;
    create.message.set('The link must remain available');
    create.password.set('separate-access-code');

    await create.create();
    fixture.detectChanges();

    expect(TestBed.inject(AppState).mode()).toBe('result');
    expect(create.shareLink()).toContain('/s/AAAAAAAAAAAAAAAAAAAAAA#');
    expect(create.resultAccessCode()).toBe('separate-access-code');
    expect(fixture.nativeElement.textContent).toContain('Copy the link and access code now');
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

  it('keeps history cell labels available to the compact layout', async () => {
    const history = TestBed.inject(SecretHistoryStore);
    await history.whenReady();
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

    expect(cells.slice(0, 4).map(cell => cell.dataset['label'])).toEqual(['Created', 'Secure link', 'Expires on', 'Access code']);
  });
});
