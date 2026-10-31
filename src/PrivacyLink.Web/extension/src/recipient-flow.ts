import {
  decodeCanonical,
  decryptFile,
  decryptFileName,
  decryptMessage,
  derivePasswordToken,
  type EncryptedFileMetadata,
  type EncryptedPayload,
  type OpenedFile
} from '../../../PrivacyLink.Client/src';

const SHARE_ORIGIN = 'https://privacylink.nl';
const EMAIL_VERIFICATION_SESSION_MS = 30 * 60 * 1000;
const EMAIL_CODE_REQUEST_COOLDOWN_SECONDS = 60;
const RETRYABLE_STATUS_MIN = 500;

export interface RecipientFile {
  id: string;
  name: string;
  mimeType: string;
  size: number;
}

export interface RecipientSnapshot {
  phase: 'loading' | 'ready' | 'opened' | 'unavailable' | 'error';
  error: string;
  expiresAt: string;
  passwordProtected: boolean;
  emailVerificationRequired: boolean;
  maskedEmailAddress: string;
  emailVerified: boolean;
  emailCodeRequested: boolean;
  emailCodeCooldownSeconds: number;
  fileCount: number;
  files: RecipientFile[];
  openedMessage: string;
  busy: boolean;
  lockoutSeconds: number;
}

export interface RecipientFlowController {
  readonly ready: Promise<void>;
  snapshot(): RecipientSnapshot;
  subscribe(listener: (snapshot: RecipientSnapshot) => void): () => void;
  open(password?: string): Promise<void>;
  requestEmailCode(): Promise<void>;
  verifyEmailCode(code: string): Promise<void>;
  download(fileId: string): Promise<void>;
  dispose(): void;
}

export interface RecipientFlowDependencies {
  fetch?: typeof fetch;
  storage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
  now?: () => number;
  setInterval?: typeof setInterval;
  clearInterval?: typeof clearInterval;
  clearFragment?: (url: URL) => void;
  mount?: (document: Document, controller: RecipientFlowController) => void | (() => void);
  navigation?: EventTarget;
  downloadFile?: (document: Document, file: RecipientFile, filename: string, data: Uint8Array) => void;
}

export function parseRecipientShareUrl(value: string): { id: string; clientKey: string } | null {
  let url: URL;
  try { url = new URL(value); }
  catch { return null; }

  if (url.origin !== SHARE_ORIGIN || url.search !== '') return null;
  const match = /^\/s\/([A-Za-z0-9_-]{22})$/.exec(url.pathname);
  const clientKey = url.hash.slice(1);
  if (!match || !clientKey) return null;

  try {
    decodeCanonical(match[1]!, 16);
    decodeCanonical(clientKey, 32);
  } catch {
    return null;
  }
  return { id: match[1]!, clientKey };
}

export function startRecipientContentScript(
  document: Document,
  href: string,
  dependencies: RecipientFlowDependencies = {}
): RecipientFlowController | null {
  let route = parseRecipientShareUrl(href);
  if (!route) return null;

  const url = new URL(href);
  let initialClientKey = route.clientKey;
  const initialId = route.id;
  route = null;
  href = '';
  (dependencies.clearFragment ?? (value => clearWebsiteFragment(document, value)))(url);
  url.hash = '';
  const createEntry = (id: string, clientKey: string): RecipientEntry => {
    const controller = createRecipientFlow(id, clientKey, document, dependencies);
    const disposeMount = (dependencies.mount ?? mountRecipientOverlay)(document, controller);
    void controller.ready;
    return { id, controller, disposeController: controller.dispose.bind(controller), disposeMount };
  };
  const initial = createEntry(initialId, initialClientKey);
  initialClientKey = '';
  let active: RecipientEntry | undefined = initial;
  const view = document.defaultView;
  const navigation = dependencies.navigation ?? (view as (Window & { navigation?: EventTarget }) | null)?.navigation;
  const disposeEntry = (entry: RecipientEntry): void => {
    entry.disposeMount?.();
    entry.disposeController();
  };
  const updateRoute = (): void => {
    if (!view) return;
    const current = new URL(view.location.href);
    if (active && current.pathname === `/s/${active.id}` && current.search === '' && current.hash === '') return;

    const nextRoute = parseRecipientShareUrl(current.href);
    if (active) disposeEntry(active);
    active = undefined;
    if (!nextRoute) return;

    (dependencies.clearFragment ?? (value => clearWebsiteFragment(document, value)))(current);
    active = createEntry(nextRoute.id, nextRoute.clientKey);
  };
  const onRouteChange = (): void => updateRoute();
  const stopWatching = (): void => {
    navigation?.removeEventListener('currententrychange', onRouteChange);
    view?.removeEventListener('popstate', onRouteChange);
    view?.removeEventListener('hashchange', onRouteChange);
  };
  navigation?.addEventListener('currententrychange', onRouteChange);
  view?.addEventListener('popstate', onRouteChange);
  view?.addEventListener('hashchange', onRouteChange);
  initial.controller.dispose = (): void => {
    stopWatching();
    if (active) disposeEntry(active);
    active = undefined;
  };
  const controller = initial.controller;
  return controller;
}

interface RecipientEntry {
  id: string;
  controller: RecipientFlowController;
  disposeController: () => void;
  disposeMount: void | (() => void);
}

function clearWebsiteFragment(document: Document, url: URL): void {
  const view = document.defaultView;
  if (!view) return;
  try {
    view.history.replaceState(view.history.state, '', `${url.pathname}${url.search}`);
  } catch {
    // Continue with the extension's isolated key even when the page cannot replace its URL.
  }
}

interface ApiError extends Error {
  status: number;
  retryAfterSeconds: number | null;
  code: string | null;
}

function apiError(response: Response, code: string | null = null): ApiError {
  const retryAfter = Number.parseInt(response.headers.get('Retry-After') ?? '', 10);
  const error = new Error(`HTTP ${response.status}`) as ApiError;
  error.status = response.status;
  error.retryAfterSeconds = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null;
  error.code = code;
  return error;
}

async function readApiError(response: Response): Promise<ApiError> {
  let code: string | null = null;
  try { code = (await response.json() as { code?: string }).code ?? null; }
  catch { /* Keep the HTTP status when the API returns an empty or non-JSON response. */ }
  return apiError(response, code);
}

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) throw await readApiError(response);
  return response.json() as Promise<T>;
}

function isRetryableRequestFailure(error: unknown): boolean {
  if (error instanceof Error && 'status' in error) {
    const status = (error as ApiError).status;
    return status === 408 || status >= RETRYABLE_STATUS_MIN;
  }
  return error instanceof TypeError || (error instanceof DOMException && (error.name === 'AbortError' || error.name === 'TimeoutError'));
}

function errorText(error: unknown, operation: 'metadata' | 'open' | 'email' | 'download'): string {
  if (error instanceof Error && 'status' in error) {
    const api = error as ApiError;
    if (api.status === 404) return 'This secret is unavailable.';
    if (api.status === 429) return 'Too many attempts. Please wait and try again.';
    if (api.status === 403 && api.code === 'email_verification_required') return 'Verify your email address before opening this secret.';
    if (api.status === 400 && api.code === 'invalid_code') return 'That verification code is incorrect or expired.';
    if (api.status === 403 && operation === 'open') return 'The password is incorrect.';
  }
  return isRetryableRequestFailure(error)
    ? 'PrivacyLink is temporarily unavailable. Please try again.'
    : operation === 'email' ? 'The verification request could not be completed.' : 'This secret could not be opened.';
}

function asMetadataFile(value: EncryptedFileMetadata): EncryptedFileMetadata {
  if (!value || typeof value.id !== 'string' || typeof value.extension !== 'string' ||
      typeof value.nameNonce !== 'string' || typeof value.nameCiphertext !== 'string' ||
      typeof value.mimeType !== 'string' || !Number.isSafeInteger(value.size) || value.size < 0) {
    throw new Error('Invalid secret metadata');
  }
  return value;
}

function createRecipientFlow(
  id: string,
  clientKey: string,
  document: Document,
  dependencies: RecipientFlowDependencies
): RecipientFlowController {
  let recipientId = id;
  let clientKeyValue = clientKey;
  const fetcher = dependencies.fetch ?? ((input, init) => fetch(input, init));
  const now = dependencies.now ?? Date.now;
  const schedule = dependencies.setInterval ?? setInterval;
  const cancel = dependencies.clearInterval ?? clearInterval;
  const storage = dependencies.storage ?? (() => {
    try { return document.defaultView?.localStorage; }
    catch { return undefined; }
  })();
  const filesById = new Map<string, OpenedFile>();
  const listeners = new Set<(snapshot: RecipientSnapshot) => void>();
  const abortController = new AbortController();
  let lockoutTimer: ReturnType<typeof setInterval> | undefined;
  let emailCooldownTimer: ReturnType<typeof setInterval> | undefined;
  let disposed = false;
  const state: RecipientSnapshot = {
    phase: 'loading', error: '', expiresAt: '', passwordProtected: false,
    emailVerificationRequired: false, maskedEmailAddress: '', emailVerified: false,
    emailCodeRequested: false, emailCodeCooldownSeconds: 0, fileCount: 0,
    files: [], openedMessage: '', busy: false, lockoutSeconds: 0
  };
  const emit = (): void => {
    if (disposed) return;
    const copy = { ...state, files: state.files.map(file => ({ ...file })) };
    for (const listener of listeners) listener(copy);
  };
  const emailSessionKey = `privacylink.email-verification.${recipientId}`;
  const hasEmailSession = (): boolean => {
    try {
      const expiresAt = Number(storage?.getItem(emailSessionKey));
      if (Number.isFinite(expiresAt) && expiresAt > now()) return true;
      storage?.removeItem(emailSessionKey);
    } catch { /* Local storage is only a UI hint; the API cookie remains authoritative. */ }
    return false;
  };
  const removeEmailSession = (): void => {
    try { storage?.removeItem(emailSessionKey); }
    catch { /* Keep the API cookie authoritative when browser storage is unavailable. */ }
  };
  const clearLockout = (): void => {
    if (lockoutTimer !== undefined) cancel(lockoutTimer);
    lockoutTimer = undefined;
    state.lockoutSeconds = 0;
  };
  const clearEmailCooldown = (): void => {
    if (emailCooldownTimer !== undefined) cancel(emailCooldownTimer);
    emailCooldownTimer = undefined;
    state.emailCodeCooldownSeconds = 0;
  };
  const setLockout = (seconds: number | null): void => {
    clearLockout();
    if (!seconds) return;
    state.lockoutSeconds = seconds;
    lockoutTimer = schedule(() => {
      state.lockoutSeconds = Math.max(0, state.lockoutSeconds - 1);
      if (!state.lockoutSeconds) clearLockout();
      if (!state.lockoutSeconds) emit();
    }, 1000);
  };
  const setEmailCooldown = (): void => {
    clearEmailCooldown();
    state.emailCodeCooldownSeconds = EMAIL_CODE_REQUEST_COOLDOWN_SECONDS;
    emailCooldownTimer = schedule(() => {
      state.emailCodeCooldownSeconds = Math.max(0, state.emailCodeCooldownSeconds - 1);
      if (!state.emailCodeCooldownSeconds) clearEmailCooldown();
      emit();
    }, 1000);
  };
  const request = (path: string, init: RequestInit = {}): Promise<Response> => fetcher(`${SHARE_ORIGIN}${path}`, {
    ...init,
    signal: abortController.signal,
    cache: 'no-store',
    credentials: 'same-origin',
    referrerPolicy: 'no-referrer'
  });

  const ready = (async (): Promise<void> => {
    try {
      const metadata = await readJson<{
        exists: boolean;
        protocolVersion: number;
        expiresAt: string;
        passwordProtected: boolean;
        hasMessage: boolean;
        fileCount: number;
        files: EncryptedFileMetadata[];
        emailVerificationRequired?: boolean;
        maskedEmailAddress?: string | null;
      }>(await request(`/api/v1/secrets/${encodeURIComponent(recipientId)}`));
      if (disposed) return;
      if (!metadata.exists || metadata.protocolVersion !== 1 || (!metadata.hasMessage && metadata.fileCount === 0)) {
        state.phase = 'unavailable';
        state.error = 'This secret is unavailable.';
        emit();
        return;
      }
      const files = !metadata.passwordProtected && Array.isArray(metadata.files)
        ? await Promise.all(metadata.files.map(async item => {
            const file = asMetadataFile(item);
            return {
              id: file.id,
              name: await decryptFileName(file, clientKeyValue),
              mimeType: file.mimeType,
              size: file.size
            };
          }))
        : [];
      if (disposed) return;
      state.phase = 'ready';
      state.expiresAt = metadata.expiresAt;
      state.passwordProtected = metadata.passwordProtected;
      state.emailVerificationRequired = metadata.emailVerificationRequired === true;
      state.maskedEmailAddress = metadata.maskedEmailAddress ?? '';
      state.emailVerified = state.emailVerificationRequired && hasEmailSession();
      state.fileCount = metadata.fileCount;
      state.files = files;
      emit();
    } catch (error) {
      if (disposed) return;
      state.phase = error instanceof Error && 'status' in error && (error as ApiError).status === 404 ? 'unavailable' : 'error';
      state.error = errorText(error, 'metadata');
      emit();
    }
  })();

  const clearError = (): void => { state.error = ''; };
  const controller: RecipientFlowController = {
    ready,
    snapshot: () => ({ ...state, files: state.files.map(file => ({ ...file })) }),
    subscribe(listener) {
      if (disposed) return () => {};
      listeners.add(listener);
      listener(controller.snapshot());
      return () => listeners.delete(listener);
    },
    async requestEmailCode(): Promise<void> {
      if (state.busy || state.emailCodeCooldownSeconds > 0 || !state.emailVerificationRequired || disposed) return;
      state.busy = true;
      clearError();
      emit();
      try {
        await readJson<{ code: string }>(await request(`/api/v1/secrets/${encodeURIComponent(recipientId)}/email-verification/request`, { method: 'POST' }));
        if (disposed) return;
        state.emailCodeRequested = true;
        setEmailCooldown();
      } catch (error) {
        if (disposed) return;
        state.error = errorText(error, 'email');
      } finally {
        if (!disposed) {
          state.busy = false;
          emit();
        }
      }
    },
    async verifyEmailCode(code: string): Promise<void> {
      if (state.busy || !state.emailCodeRequested || !/^\d{6}$/.test(code) || disposed) return;
      state.busy = true;
      clearError();
      emit();
      try {
        const response = await request(`/api/v1/secrets/${encodeURIComponent(recipientId)}/email-verification/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code })
        });
        if (disposed) return;
        if (!response.ok) throw await readApiError(response);
        state.emailVerified = true;
        state.emailCodeRequested = false;
        clearEmailCooldown();
        try { storage?.setItem(emailSessionKey, String(now() + EMAIL_VERIFICATION_SESSION_MS)); }
        catch { /* The API's HttpOnly cookie remains authoritative. */ }
      } catch (error) {
        if (disposed) return;
        state.error = errorText(error, 'email');
      } finally {
        if (!disposed) {
          state.busy = false;
          emit();
        }
      }
    },
    async open(password = ''): Promise<void> {
      if (state.busy || state.phase !== 'ready' || state.lockoutSeconds > 0 || disposed) return;
      if (state.emailVerificationRequired && !state.emailVerified) return;
      state.busy = true;
      clearError();
      emit();
      try {
        let response: Response;
        if (state.passwordProtected) {
          const token = await derivePasswordToken(password, clientKeyValue);
          if (disposed) return;
          for (let attempt = 0; ; attempt++) {
            if (disposed) return;
            response = await request(`/api/v1/secrets/${encodeURIComponent(recipientId)}/unlock`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ password: token })
            });
            if (response.status !== 503 || attempt >= 2) break;
            const retryAfter = Number.parseInt(response.headers.get('Retry-After') ?? '', 10);
            const backoff = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : Math.min(1000 * 2 ** attempt, 4000);
            await new Promise(resolve => setTimeout(resolve, Math.min(backoff, 5000) + Math.floor(Math.random() * 250)));
          }
        } else {
          response = await request(`/api/v1/secrets/${encodeURIComponent(recipientId)}/open`, { method: 'POST' });
        }
        if (disposed) return;
        if (!response.ok) {
          const error = await readApiError(response);
          if (error.status === 429) setLockout(error.retryAfterSeconds);
          if (error.status === 403 && error.code === 'email_verification_required') {
            state.emailVerified = false;
            state.emailCodeRequested = false;
            removeEmailSession();
          }
          throw error;
        }
        const opened = await response.json() as EncryptedPayload;
        if (disposed) return;
        if (opened.protocolVersion !== 1 || (!opened.message && opened.files.length === 0 && state.fileCount === 0)) {
          throw new Error('Unsupported secret payload');
        }
        const message = opened.message ? await decryptMessage(opened, clientKeyValue) : '';
        if (disposed) return;
        if (state.passwordProtected) {
          if (!opened.files.length && state.fileCount > 0) throw new Error('Missing protected file payload');
          filesById.clear();
          const files = await Promise.all(opened.files.map(async file => {
            filesById.set(file.id, file);
            return {
              id: file.id,
              name: await decryptFileName(file, clientKeyValue),
              mimeType: file.mimeType,
              size: file.size
            };
          }));
          if (disposed) return;
          state.files = files;
        }
        if (disposed) return;
        state.openedMessage = message;
        state.phase = 'opened';
      } catch (error) {
        if (disposed) return;
        state.error = errorText(error, 'open');
      } finally {
        if (!disposed) {
          state.busy = false;
          emit();
        }
      }
    },
    async download(fileId: string): Promise<void> {
      if (state.busy || state.phase !== 'opened' || disposed) return;
      const fileInfo = state.files.find(file => file.id === fileId);
      if (!fileInfo) return;
      state.busy = true;
      clearError();
      emit();
      try {
        let openedFile = filesById.get(fileId);
        if (!openedFile) {
          const response = await request(`/api/v1/secrets/${encodeURIComponent(recipientId)}/files/${encodeURIComponent(fileId)}/open`, { method: 'POST' });
          if (disposed) return;
          const payload = await readJson<{ protocolVersion: number; file: OpenedFile }>(response);
          if (payload.protocolVersion !== 1) throw new Error('Unsupported file payload');
          openedFile = payload.file;
        }
        if (disposed || !openedFile) return;
        const file = asMetadataFile(openedFile);
        const filename = await decryptFileName(file, clientKeyValue);
        if (disposed) return;
        const data = await decryptFile(openedFile, clientKeyValue);
        if (disposed) return;
        (dependencies.downloadFile ?? downloadBrowserFile)(document, fileInfo, filename, data);
      } catch (error) {
        if (disposed) return;
        state.error = errorText(error, 'download');
      } finally {
        if (!disposed) {
          state.busy = false;
          emit();
        }
      }
    },
    dispose(): void {
      if (disposed) return;
      disposed = true;
      abortController.abort();
      clearLockout();
      clearEmailCooldown();
      filesById.clear();
      state.phase = 'unavailable';
      state.error = '';
      state.expiresAt = '';
      state.passwordProtected = false;
      state.emailVerificationRequired = false;
      state.maskedEmailAddress = '';
      state.emailVerified = false;
      state.emailCodeRequested = false;
      state.fileCount = 0;
      state.files = [];
      state.openedMessage = '';
      state.busy = false;
      state.lockoutSeconds = 0;
      recipientId = '';
      clientKeyValue = '';
      listeners.clear();
    }
  };
  return controller;
}

function downloadBrowserFile(document: Document, file: RecipientFile, filename: string, data: Uint8Array): void {
  const view = document.defaultView;
  if (!view) return;
  const url = view.URL.createObjectURL(new Blob([data as BlobPart], { type: file.mimeType || 'application/octet-stream' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename.replace(/[\\/:\0]/g, '_');
  anchor.click();
  view.setTimeout(() => view.URL.revokeObjectURL(url), 1000);
}

function mountRecipientOverlay(document: Document, controller: RecipientFlowController): () => void {
  let emailCodeValue = '';
  let passwordValue = '';
  let activeSensitiveInput: HTMLInputElement | undefined;
  let pendingFocus: 'email' | 'password' | undefined;
  let isRendering = false;
  let emailCodeInput: HTMLInputElement | undefined;
  let verifyEmailButton: HTMLButtonElement | undefined;
  let passwordInput: HTMLInputElement | undefined;
  let openButton: HTMLButtonElement | undefined;
  const host = document.createElement('div');
  host.setAttribute('aria-label', 'PrivacyLink extension recipient');
  const shadow = host.attachShadow({ mode: 'closed' });
  shadow.innerHTML = `
    <style>
      :host { all: initial; position: fixed; inset: 0; z-index: 2147483647; color: #17262a; font: 16px/1.5 system-ui, sans-serif; }
      * { box-sizing: border-box; }
      .backdrop { position: fixed; inset: 0; overflow: auto; display: grid; place-items: center; padding: 24px; background: #f5f8f7; }
      main { width: min(100%, 680px); padding: clamp(24px, 5vw, 48px); border: 1px solid #d8e2de; border-radius: 18px; background: white; box-shadow: 0 18px 70px #17352d26; }
      .brand { margin: 0 0 10px; color: #527168; font-size: 11px; font-weight: 750; letter-spacing: .16em; }
      h1 { margin: 0 0 18px; font-size: 28px; letter-spacing: -.025em; }
      h2 { margin: 0 0 10px; font-size: 18px; }
      p { margin: 0 0 16px; }
      .note { color: #52655f; font-size: 13px; }
      .error { margin: 14px 0; border-radius: 8px; padding: 10px 12px; background: #fff0ee; color: #8b2820; font-size: 14px; }
      label { display: block; margin: 18px 0 7px; font-size: 14px; font-weight: 650; }
      input { display: block; width: 100%; border: 1px solid #cbd8d4; border-radius: 9px; padding: 11px 12px; background: white; color: inherit; font: inherit; }
      input:focus { outline: 3px solid #a6dac8; outline-offset: 1px; border-color: #298367; }
      button { border: 0; border-radius: 9px; padding: 11px 16px; background: #176d55; color: white; font: inherit; font-size: 14px; font-weight: 700; cursor: pointer; }
      button:disabled { cursor: wait; opacity: .7; }
      button.secondary { margin-left: 8px; background: #e4f2ec; color: #145a46; }
      pre { overflow-wrap: anywhere; white-space: pre-wrap; font: inherit; }
      ul { margin: 0; padding: 0; list-style: none; }
      li { display: flex; align-items: center; justify-content: space-between; gap: 20px; border-top: 1px solid #e1e9e5; padding: 12px 0; }
      li button { flex: 0 0 auto; }
      @media (max-width: 560px) { .backdrop { padding: 12px; } main { padding: 22px; } li { align-items: flex-start; flex-direction: column; gap: 8px; } li button { width: 100%; } }
    </style>
    <div class="backdrop"><main aria-labelledby="recipient-title"><p class="brand">PRIVACYLINK · INSTALLED CLIENT</p><h1 id="recipient-title">Received secret</h1><div id="recipient-content" aria-live="polite"></div></main></div>`;
  const content = shadow.querySelector<HTMLElement>('#recipient-content')!;
  const suppressSensitiveInputEvents = (event: Event): void => {
    if (!activeSensitiveInput || document.activeElement !== host) return;
    const eventTarget = event.target;
    if (eventTarget !== host && !(eventTarget instanceof Node && shadow.contains(eventTarget))) return;

    if (event.type === 'input') {
      if (activeSensitiveInput === emailCodeInput) {
        activeSensitiveInput.value = activeSensitiveInput.value.replace(/\D/g, '').slice(0, 6);
        emailCodeValue = activeSensitiveInput.value;
        if (verifyEmailButton) verifyEmailButton.disabled = emailCodeValue.length !== 6;
      } else if (activeSensitiveInput === passwordInput) {
        passwordValue = activeSensitiveInput.value;
        if (openButton) openButton.disabled = !passwordValue;
      }
    }

    if (event.type === 'keydown' && activeSensitiveInput === passwordInput && (event as KeyboardEvent).key === 'Enter') {
      const password = activeSensitiveInput.value;
      passwordValue = '';
      void controller.open(password);
    }

    // These composed events otherwise expose typed characters or pasted values to page scripts.
    event.stopImmediatePropagation();
  };
  for (const type of ['keydown', 'keyup', 'keypress', 'beforeinput', 'input', 'change', 'compositionstart', 'compositionupdate', 'compositionend', 'paste', 'cut', 'copy']) {
    document.defaultView?.addEventListener(type, suppressSensitiveInputEvents, true);
  }

  const renderContent = (snapshot: RecipientSnapshot): void => {
    if (snapshot.emailVerified || snapshot.phase === 'opened') emailCodeValue = '';
    emailCodeInput = undefined;
    verifyEmailButton = undefined;
    passwordInput = undefined;
    openButton = undefined;
    content.replaceChildren();
    if (snapshot.phase === 'loading') {
      content.append(makeTextElement(document, 'p', 'Loading secret…'));
      return;
    }
    if (snapshot.error) {
      const error = makeTextElement(document, 'p', snapshot.error, 'error');
      error.setAttribute('role', 'alert');
      content.append(error);
    }
    if (snapshot.phase === 'unavailable' || snapshot.phase === 'error') return;
    if (snapshot.phase === 'opened') {
      content.append(makeTextElement(document, 'p', 'The secret was decrypted in the installed PrivacyLink client.', 'note'));
      if (snapshot.openedMessage) {
        const section = document.createElement('section');
        section.append(makeTextElement(document, 'h2', 'Message'));
        section.append(makeTextElement(document, 'pre', snapshot.openedMessage));
        content.append(section);
      }
      if (snapshot.files.length) {
        const section = document.createElement('section');
        section.append(makeTextElement(document, 'h2', `Files (${snapshot.files.length})`));
        const list = document.createElement('ul');
        for (const file of snapshot.files) {
          const item = document.createElement('li');
          const details = makeTextElement(document, 'span', `${file.name} · ${formatFileSize(file.size)}`);
          const button = document.createElement('button');
          button.type = 'button';
          button.textContent = snapshot.busy ? 'Preparing…' : 'Download';
          button.disabled = snapshot.busy;
          button.addEventListener('click', () => void controller.download(file.id));
          item.append(details, button);
          list.append(item);
        }
        section.append(list);
        content.append(section);
      }
      return;
    }

    const expiry = new Date(snapshot.expiresAt);
    content.append(makeTextElement(document, 'p', `This link expires ${Number.isNaN(expiry.valueOf()) ? 'soon' : expiry.toLocaleString()}.`, 'note'));
    if (snapshot.fileCount) content.append(makeTextElement(document, 'p', `${snapshot.fileCount} file${snapshot.fileCount === 1 ? '' : 's'} included.`, 'note'));

    if (snapshot.emailVerificationRequired && !snapshot.emailVerified) {
      content.append(makeTextElement(document, 'h2', 'Verify your email'));
      content.append(makeTextElement(document, 'p', `A verification code is required${snapshot.maskedEmailAddress ? ` for ${snapshot.maskedEmailAddress}` : ''}.`, 'note'));
      if (snapshot.emailCodeRequested) {
        const label = makeTextElement(document, 'label', 'Six-digit code');
        const input = document.createElement('input');
        emailCodeInput = input;
        input.type = 'text';
        input.inputMode = 'numeric';
        input.autocomplete = 'one-time-code';
        input.maxLength = 6;
        input.value = emailCodeValue;
        input.setAttribute('aria-label', 'Six-digit email verification code');
        input.addEventListener('focus', () => { activeSensitiveInput = input; pendingFocus = 'email'; });
        input.addEventListener('blur', () => { if (!isRendering && activeSensitiveInput === input) activeSensitiveInput = undefined; });
        const verify = document.createElement('button');
        verifyEmailButton = verify;
        verify.type = 'button';
        verify.textContent = snapshot.busy ? 'Checking…' : 'Verify code';
        verify.disabled = snapshot.busy || !/^\d{6}$/.test(input.value);
        verify.addEventListener('click', () => void controller.verifyEmailCode(emailCodeValue));
        const requestAgain = document.createElement('button');
        requestAgain.type = 'button';
        requestAgain.className = 'secondary';
        requestAgain.textContent = snapshot.emailCodeCooldownSeconds > 0
          ? `Request another code in ${formatCountdown(snapshot.emailCodeCooldownSeconds)}`
          : 'Request another code';
        requestAgain.disabled = snapshot.busy || snapshot.emailCodeCooldownSeconds > 0;
        requestAgain.addEventListener('click', () => void controller.requestEmailCode());
        content.append(label, input, verify, requestAgain);
      } else {
        const requestCode = document.createElement('button');
        requestCode.type = 'button';
        requestCode.textContent = snapshot.busy ? 'Requesting…' : 'Request email code';
        requestCode.disabled = snapshot.busy;
        requestCode.addEventListener('click', () => void controller.requestEmailCode());
        content.append(requestCode);
      }
      return;
    }

    if (snapshot.passwordProtected) {
      content.append(makeTextElement(document, 'label', 'Password'));
      const input = document.createElement('input');
      passwordInput = input;
      input.type = 'password';
      input.value = passwordValue;
      input.autocomplete = 'off';
      input.autocapitalize = 'off';
      input.spellcheck = false;
      input.disabled = snapshot.busy || snapshot.lockoutSeconds > 0;
      input.addEventListener('focus', () => { activeSensitiveInput = input; pendingFocus = 'password'; });
      input.addEventListener('blur', () => { if (!isRendering && activeSensitiveInput === input) activeSensitiveInput = undefined; });
      content.append(input);
    }
    const open = document.createElement('button');
    openButton = open;
    open.type = 'button';
    open.textContent = snapshot.busy ? 'Opening…' : snapshot.lockoutSeconds > 0
      ? `Wait ${formatCountdown(snapshot.lockoutSeconds)}`
      : snapshot.passwordProtected ? 'Unlock secret' : 'Open secret';
    open.disabled = snapshot.busy || snapshot.lockoutSeconds > 0 || (snapshot.passwordProtected && !content.querySelector<HTMLInputElement>('input[type="password"]')?.value);
    open.addEventListener('click', () => {
      const password = passwordInput?.value ?? '';
      passwordValue = '';
      void controller.open(password);
    });
    content.append(open);
  };
  const render = (snapshot: RecipientSnapshot): void => {
    if (snapshot.emailVerified || snapshot.phase === 'opened' || snapshot.phase === 'unavailable' || snapshot.phase === 'error') {
      pendingFocus = undefined;
      activeSensitiveInput = undefined;
    } else if (activeSensitiveInput === emailCodeInput) {
      pendingFocus = 'email';
    } else if (activeSensitiveInput === passwordInput) {
      pendingFocus = 'password';
    }
    const focusedField = activeSensitiveInput;
    const selectionStart = focusedField?.selectionStart;
    const selectionEnd = focusedField?.selectionEnd;
    const selectionDirection = focusedField?.selectionDirection ?? undefined;

    isRendering = true;
    try {
      renderContent(snapshot);
    } finally {
      isRendering = false;
      const field = pendingFocus === 'email' ? emailCodeInput : pendingFocus === 'password' ? passwordInput : undefined;
      if (field && !field.disabled) {
        field.focus();
        if (selectionStart !== null && selectionStart !== undefined && selectionEnd !== null && selectionEnd !== undefined) {
          field.setSelectionRange(selectionStart, selectionEnd, selectionDirection);
        }
        activeSensitiveInput = field;
        pendingFocus = undefined;
      } else if (!field) {
        activeSensitiveInput = undefined;
        pendingFocus = undefined;
      }
    }
  };
  const unsubscribe = controller.subscribe(render);

  const view = document.defaultView;
  let observer: MutationObserver | undefined;
  const attach = (): boolean => {
    const root = document.documentElement;
    if (!root) return false;
    if (!host.isConnected) root.append(host);
    return true;
  };
  if (!attach()) {
    const Observer = view?.MutationObserver ?? MutationObserver;
    observer = new Observer(() => { if (attach()) observer?.disconnect(); });
    observer.observe(document, { childList: true, subtree: true });
  }
  return (): void => {
    unsubscribe();
    observer?.disconnect();
    for (const type of ['keydown', 'keyup', 'keypress', 'beforeinput', 'input', 'change', 'compositionstart', 'compositionupdate', 'compositionend', 'paste', 'cut', 'copy']) {
      view?.removeEventListener(type, suppressSensitiveInputEvents, true);
    }
    host.remove();
    content.replaceChildren();
    activeSensitiveInput = undefined;
    emailCodeInput = undefined;
    passwordInput = undefined;
    verifyEmailButton = undefined;
    openButton = undefined;
    pendingFocus = undefined;
    emailCodeValue = '';
    passwordValue = '';
  };
}

function makeTextElement(document: Document, tag: string, text: string, className?: string): HTMLElement {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unit = units[0]!;
  for (let index = 1; index < units.length && value >= 1024; index++) {
    value /= 1024;
    unit = units[index]!;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${unit}`;
}

function formatCountdown(totalSeconds: number): string {
  const minutes = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
  const seconds = (totalSeconds % 60).toString().padStart(2, '0');
  return `${minutes}:${seconds}`;
}
