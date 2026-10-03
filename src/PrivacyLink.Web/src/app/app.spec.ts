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
import { encryptMessage } from './secret-crypto';

function createSecretApiStub() {
  return {
    getFileUploadPolicy: vi.fn().mockResolvedValue({ maxFiles: 10, maxTotalFileBytes: 25 * 1024 * 1024, allowedFileExtensions: ['.txt'] }),
    create: vi.fn().mockResolvedValue({ id: 'AAAAAAAAAAAAAAAAAAAAAA', expiresAt: '2030-01-01T00:00:00.000Z', passwordProtected: false, revokeToken: 'test-revoke-token' }),
    revoke: vi.fn().mockResolvedValue(undefined),
    getMetadata: vi.fn().mockResolvedValue({ exists: true, protocolVersion: 1, expiresAt: '2030-01-01T00:00:00.000Z', passwordProtected: false, hasMessage: true, fileCount: 0, files: [] }),
    open: vi.fn(),
    unlock: vi.fn(),
    openFile: vi.fn()
  };
}

describe('App', () => {
  let api: ReturnType<typeof createSecretApiStub>;

  beforeEach(async () => {
    localStorage.clear();
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
    create.setError({ key: 'tooManyFiles', params: { max: 10 } });
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.error')?.textContent).toContain('You can add at most 10 files.');

    language.setLanguage('nl');
    fixture.detectChanges();
    expect(compiled.querySelector('.error')?.textContent).toContain('Je kunt maximaal 10 bestanden toevoegen.');
  });

  it('waits for an explicit unlock action and renders decrypted content as text', async () => {
    const messageText = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const encrypted = await encryptMessage(messageText);
    const id = 'AAAAAAAAAAAAAAAAAAAAAA';
    api.getMetadata.mockResolvedValue({ exists: true, protocolVersion: 1, expiresAt: '2030-01-01T00:00:00.000Z', passwordProtected: true, hasMessage: true, fileCount: 0, files: [] });
    api.unlock.mockResolvedValue({ protocolVersion: 1, message: encrypted.message, files: [] });
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
    await vi.waitFor(() => expect(api.unlock).toHaveBeenCalledTimes(1));
    await fixture.whenStable();
    fixture.detectChanges();

    const compiled = fixture.nativeElement as HTMLElement;
    const message = compiled.querySelector('.message-display');
    expect(message?.textContent).toBe(messageText);
    expect(message?.querySelector('img, script')).toBeNull();
    expect(api.unlock.mock.calls[0]?.[0]).toBe(id);
    expect(api.open).not.toHaveBeenCalled();
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
    expect(api.create).toHaveBeenCalledWith(expect.not.objectContaining({ clientKey: expect.any(String) }));
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
