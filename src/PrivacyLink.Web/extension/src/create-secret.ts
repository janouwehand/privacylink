import { decodeCanonical, encryptMessage, solveCreateProof, type CreateChallenge, type EncryptedMessage } from '../../../PrivacyLink.Client/src';

type Expiry = '1d' | '7d' | '14d';
type CreateRequest = {
  protocolVersion: 1;
  expiry: Expiry;
  message: EncryptedMessage;
  files: [];
};
type CreateResponse = { id: string; expiresAt: string; passwordProtected: boolean; revokeToken: string };
type ApiError = Error & { status?: number; code?: string };

export interface CreateApi {
  getCreateChallenge(): Promise<CreateChallenge>;
  create(request: CreateRequest, proof: string): Promise<CreateResponse>;
}

export interface CreateDependencies {
  api: CreateApi;
  copyText(value: string): Promise<void>;
}

const API_ORIGIN = 'https://privacylink.nl';
const SHARE_ORIGIN = 'https://privacylink.nl';
const CREATE_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const CREATE_CHALLENGE_SAFETY_MARGIN_MS = 5 * 1000;
const MAX_MESSAGE_CHARACTERS = 20_000;
const MAX_MESSAGE_BYTES = 80_000;

function asApiError(status: number, code: string | null): ApiError {
  const error = new Error(`PrivacyLink API returned HTTP ${status}`) as ApiError;
  error.status = status;
  error.code = code ?? undefined;
  return error;
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let code: string | null = null;
    try {
      code = (await response.json() as { code?: string }).code ?? null;
    } catch {
      // Keep the status when the API returns a non-JSON error.
    }
    throw asApiError(response.status, code);
  }
  return response.json() as Promise<T>;
}

export const privacyLinkCreateApi: CreateApi = {
  getCreateChallenge(): Promise<CreateChallenge> {
    return fetch(`${API_ORIGIN}/api/v1/secrets/create-challenge`, {
      cache: 'no-store',
      referrerPolicy: 'no-referrer'
    }).then(response => parseResponse<CreateChallenge>(response));
  },

  create(request: CreateRequest, proof: string): Promise<CreateResponse> {
    return fetch(`${API_ORIGIN}/api/v1/secrets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-PrivacyLink-Proof': proof },
      body: JSON.stringify(request),
      cache: 'no-store',
      referrerPolicy: 'no-referrer'
    }).then(response => parseResponse<CreateResponse>(response));
  }
};

export function browserClipboard(document: Document): (value: string) => Promise<void> {
  return async value => {
    const clipboard = document.defaultView?.navigator.clipboard;
    if (!clipboard) throw new Error('Clipboard access is unavailable');
    await clipboard.writeText(value);
  };
}

function expiryValue(value: string): Expiry | null {
  return value === '1d' || value === '7d' || value === '14d' ? value : null;
}

function challengeHeader(challenge: CreateChallenge, counter: string): string {
  return `${challenge.challengeId}.${challenge.nonce}.${challenge.difficultyBits}.${challenge.expiresAt}.${challenge.signature}.${counter}`;
}

async function solveFreshProof(api: CreateApi): Promise<string> {
  const startedAt = performance.now();
  const challenge = await api.getCreateChallenge();
  if (challenge.version !== 1 || !Number.isInteger(challenge.difficultyBits) || challenge.difficultyBits < 0) {
    throw new Error('Unsupported create challenge');
  }
  const counter = await solveCreateProof(challenge);
  const deadline = startedAt + CREATE_CHALLENGE_TTL_MS - CREATE_CHALLENGE_SAFETY_MARGIN_MS;
  if (deadline <= performance.now()) throw new Error('Create challenge expired before it could be used');
  return challengeHeader(challenge, counter);
}

async function createWithProof(api: CreateApi, request: CreateRequest): Promise<CreateResponse> {
  for (let attempt = 0; ; attempt++) {
    const proof = await solveFreshProof(api);
    try {
      return await api.create(request, proof);
    } catch (error) {
      const apiError = error as ApiError;
      if (apiError.status !== 403 || apiError.code !== 'proof_required' || attempt > 0) throw error;
    }
  }
}

function errorMessage(error: unknown): string {
  const apiError = error as ApiError;
  if (apiError.status === 403 && apiError.code === 'forbidden') {
    return 'PrivacyLink rejected this extension request because the API currently accepts creation only from the website. Your text is still in this form. Open privacylink.nl to create it for now.';
  }
  if (apiError.status === 429) return 'Too many secrets have been created recently. Please wait and try again.';
  if (apiError.status === 403 && apiError.code === 'proof_required') return 'PrivacyLink could not validate the create challenge. Please try again.';
  return 'The secret could not be created. Your text is still in this form. Check your connection and try again.';
}

export function mountCreateForm(document: Document, dependencies: CreateDependencies = {
  api: privacyLinkCreateApi,
  copyText: browserClipboard(document)
}): void {
  const form = document.querySelector<HTMLFormElement>('#create-form');
  const messageField = document.querySelector<HTMLTextAreaElement>('#secret-message');
  const expiryField = document.querySelector<HTMLSelectElement>('#secret-expiry');
  const createButton = document.querySelector<HTMLButtonElement>('#create-button');
  const errorPanel = document.querySelector<HTMLElement>('#error-message');
  const successPanel = document.querySelector<HTMLElement>('#success-panel');
  const linkField = document.querySelector<HTMLInputElement>('#share-link');
  const copyButton = document.querySelector<HTMLButtonElement>('#copy-link-button');
  const copyStatus = document.querySelector<HTMLElement>('#copy-status');
  const expiryMessage = document.querySelector<HTMLElement>('#expiry-message');

  if (!form || !messageField || !expiryField || !createButton || !errorPanel || !successPanel || !linkField || !copyButton || !copyStatus || !expiryMessage) {
    throw new Error('PrivacyLink extension create form is incomplete');
  }

  form.addEventListener('submit', event => {
    event.preventDefault();
    if (createButton.disabled) return;

    const plaintext = messageField.value;
    const expiry = expiryValue(expiryField.value);
    if (!plaintext.trim()) {
      errorPanel.textContent = 'Enter some text before creating a secret.';
      errorPanel.hidden = false;
      successPanel.hidden = true;
      messageField.focus();
      return;
    }
    const characterCount = Array.from(plaintext).length;
    const byteCount = new TextEncoder().encode(plaintext).length;
    if (characterCount > MAX_MESSAGE_CHARACTERS || byteCount > MAX_MESSAGE_BYTES) {
      errorPanel.textContent = 'This text is too long for a PrivacyLink secret.';
      errorPanel.hidden = false;
      successPanel.hidden = true;
      messageField.focus();
      return;
    }
    if (!expiry) {
      errorPanel.textContent = 'Choose a valid expiry time.';
      errorPanel.hidden = false;
      successPanel.hidden = true;
      expiryField.focus();
      return;
    }

    void (async () => {
      errorPanel.hidden = true;
      successPanel.hidden = true;
      copyStatus.textContent = '';
      createButton.disabled = true;
      createButton.textContent = 'Creating…';
      try {
        const encrypted = await encryptMessage(plaintext);
        decodeCanonical(encrypted.clientKey, 32);
        const request: CreateRequest = {
          protocolVersion: 1,
          expiry,
          message: encrypted.message,
          files: []
        };
        const created = await createWithProof(dependencies.api, request);
        decodeCanonical(created.id, 16);
        const shareLink = `${SHARE_ORIGIN}/s/${created.id}#${encrypted.clientKey}`;
        linkField.value = shareLink;
        const expiryDate = new Date(created.expiresAt);
        expiryMessage.textContent = Number.isNaN(expiryDate.valueOf())
          ? `This link expires after ${expiry}.`
          : `This link expires ${expiryDate.toLocaleString()}.`;
        successPanel.hidden = false;
        if (messageField.value === plaintext) messageField.value = '';
      } catch (error) {
        errorPanel.textContent = errorMessage(error);
        errorPanel.hidden = false;
      } finally {
        createButton.disabled = false;
        createButton.textContent = 'Create secret';
      }
    })();
  });

  copyButton.addEventListener('click', () => {
    if (!linkField.value) return;
    void dependencies.copyText(linkField.value).then(() => {
      copyStatus.textContent = 'Share link copied.';
    }).catch(() => {
      linkField.focus();
      linkField.select();
      copyStatus.textContent = 'Could not copy automatically. The link is selected so you can copy it manually.';
    });
  });
}
