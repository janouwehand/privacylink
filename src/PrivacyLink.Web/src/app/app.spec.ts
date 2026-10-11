import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { provideRouter, Router } from '@angular/router';
import { vi } from 'vitest';
import { App } from './app';
import { routes } from './app.routes';
import { AppState } from './app-state';
import { CreateState } from './create/create-state';
import { LanguageState } from './language-state';
import { RecipientState } from './recipient/recipient-state';
import { RecipientPage } from './recipient/recipient-page';
import { SecretApi } from './secret-api';
import { SecretHistoryStore } from './secret-history-store';
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

  beforeEach(async () => {
    localStorage.clear();
    vi.stubGlobal('Worker', InlineCryptoWorker);
    api = createSecretApiStub();
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideRouter(routes), { provide: SecretApi, useValue: api }]
    })
      .compileComponents();
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

    await create.create();
    fixture.detectChanges();

    expect(api.create).not.toHaveBeenCalled();
    expect(api.createSerialized).toHaveBeenCalledOnce();
    const body = api.createSerialized.mock.calls[0]?.[0];
    expect(Object.prototype.toString.call(body)).toBe('[object ArrayBuffer]');
    const request = JSON.parse(new TextDecoder().decode(body));
    expect(request.files).toHaveLength(1);
    expect(request.files[0].extension).toBe('.txt');
    expect((fixture.nativeElement as HTMLElement).querySelector('h1')?.textContent).toContain('Your secure link is ready.');
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
  });

  it('keeps history cell labels available to the compact layout', async () => {
    const history = TestBed.inject(SecretHistoryStore);
    history.add({
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
