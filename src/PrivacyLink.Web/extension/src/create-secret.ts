import { decodeCanonical, derivePasswordToken, encryptMessage, solveCreateProof, type CreateChallenge, type EncryptedFile, type EncryptedMessage } from '../../../PrivacyLink.Client/src';
import { SecretCryptoWorkerClient } from '../../src/app/secret-crypto-worker-client';

type Expiry = '1d' | '7d' | '14d';
export interface FileUploadPolicy { maxFiles: number; maxTotalFileBytes: number; allowedFileExtensions: string[] }
type CreateRequest = {
  protocolVersion: 1;
  expiry: Expiry;
  message: EncryptedMessage | null;
  files: EncryptedFile[];
  password?: string;
  emailAddress?: string;
};
type CreateResponse = { id: string; expiresAt: string; passwordProtected: boolean };
type ApiError = Error & { status?: number; code?: string };

export interface CreateApi {
  getFileUploadPolicy(): Promise<FileUploadPolicy>;
  getCreateChallenge(): Promise<CreateChallenge>;
  create(request: CreateRequest, proof: string): Promise<CreateResponse>;
  createSerialized(body: ArrayBuffer, proof: string): Promise<CreateResponse>;
}

export interface CreateFileCrypto {
  encryptFilesAndSerialize(request: Omit<CreateRequest, 'files'>, files: File[], clientKey: Uint8Array): Promise<ArrayBuffer>;
}

export interface CreateDependencies {
  api: CreateApi;
  copyText(value: string): Promise<void>;
  fileCrypto?: CreateFileCrypto;
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
  getFileUploadPolicy(): Promise<FileUploadPolicy> {
    return fetch(`${API_ORIGIN}/api/v1/capabilities`, {
      cache: 'no-store',
      referrerPolicy: 'no-referrer'
    }).then(response => parseResponse<FileUploadPolicy>(response));
  },

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
  },

  createSerialized(body: ArrayBuffer, proof: string): Promise<CreateResponse> {
    return fetch(`${API_ORIGIN}/api/v1/secrets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-PrivacyLink-Proof': proof },
      body,
      cache: 'no-store',
      referrerPolicy: 'no-referrer'
    }).then(response => parseResponse<CreateResponse>(response));
  }
};

const defaultFileCrypto: CreateFileCrypto = new SecretCryptoWorkerClient();

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

async function createWithProof(api: CreateApi, request: CreateRequest, serializedBody?: ArrayBuffer): Promise<CreateResponse> {
  for (let attempt = 0; ; attempt++) {
    const proof = await solveFreshProof(api);
    try {
      return serializedBody ? await api.createSerialized(serializedBody, proof) : await api.create(request, proof);
    } catch (error) {
      const apiError = error as ApiError;
      if (apiError.status !== 403 || apiError.code !== 'proof_required' || attempt > 0) throw error;
    }
  }
}

function errorMessage(error: unknown): string {
  const apiError = error as ApiError;
  if (apiError.status === 403 && apiError.code === 'forbidden') {
    return 'PrivacyLink rejected this extension request because extension creation is not enabled on the API. Your content is still in this form. Open privacylink.nl to create it for now.';
  }
  if (apiError.status === 429) return 'Too many secrets have been created recently. Please wait and try again.';
  if (apiError.status === 403 && apiError.code === 'proof_required') return 'PrivacyLink could not validate the create challenge. Please try again.';
  return 'The secret could not be created. Your content is still in this form. Check your connection and try again.';
}

export function mountCreateForm(document: Document, dependencies: CreateDependencies = {
  api: privacyLinkCreateApi,
  copyText: browserClipboard(document)
}): void {
  const form = document.querySelector<HTMLFormElement>('#create-form');
  const messageField = document.querySelector<HTMLTextAreaElement>('#secret-message');
  const expiryField = document.querySelector<HTMLSelectElement>('#secret-expiry');
  const fileInput = document.querySelector<HTMLInputElement>('#secret-files');
  const fileList = document.querySelector<HTMLElement>('#selected-files');
  const fileLimitNote = document.querySelector<HTMLElement>('#file-limit-note');
  const fileError = document.querySelector<HTMLElement>('#file-error');
  const passwordEnabledField = document.querySelector<HTMLInputElement>('#secret-password-enabled');
  const passwordContainer = document.querySelector<HTMLElement>('#password-container');
  const passwordField = document.querySelector<HTMLInputElement>('#secret-password');
  const emailEnabledField = document.querySelector<HTMLInputElement>('#email-verification-enabled');
  const emailField = document.querySelector<HTMLInputElement>('#recipient-email');
  const emailContainer = document.querySelector<HTMLElement>('#recipient-email-container');
  const createButton = document.querySelector<HTMLButtonElement>('#create-button');
  const errorPanel = document.querySelector<HTMLElement>('#error-message');
  const successPanel = document.querySelector<HTMLElement>('#success-panel');
  const linkField = document.querySelector<HTMLInputElement>('#share-link');
  const copyButton = document.querySelector<HTMLButtonElement>('#copy-link-button');
  const copyStatus = document.querySelector<HTMLElement>('#copy-status');
  const expiryMessage = document.querySelector<HTMLElement>('#expiry-message');

  const successPassword = document.querySelector<HTMLElement>('#success-password');
  const passwordValue = document.querySelector<HTMLInputElement>('#result-password');
  const copyPasswordButton = document.querySelector<HTMLButtonElement>('#copy-password-button');
  const passwordCopyStatus = document.querySelector<HTMLElement>('#password-copy-status');

  if (!form || !messageField || !expiryField || !fileInput || !fileList || !fileLimitNote || !fileError || !passwordEnabledField || !passwordContainer || !passwordField || !emailEnabledField || !emailField || !emailContainer || !createButton || !errorPanel || !successPanel || !linkField || !copyButton || !copyStatus || !expiryMessage || !successPassword || !passwordValue || !copyPasswordButton || !passwordCopyStatus) {
    throw new Error('PrivacyLink extension create form is incomplete');
  }

  const files: File[] = [];
  fileError.hidden = true;
  let filePolicy: FileUploadPolicy | undefined;
  let filePolicyReady = false;
  void dependencies.api.getFileUploadPolicy().then(policy => {
    if (!Number.isInteger(policy.maxFiles) || policy.maxFiles < 1 || !Number.isSafeInteger(policy.maxTotalFileBytes) || policy.maxTotalFileBytes < 1 || !Array.isArray(policy.allowedFileExtensions) || policy.allowedFileExtensions.some(extension => typeof extension !== 'string' || !/^\.[a-z0-9]{1,15}$/.test(extension))) {
      throw new Error('Invalid file upload policy');
    }
    filePolicy = { ...policy, allowedFileExtensions: [...new Set(policy.allowedFileExtensions)] };
    fileInput.accept = filePolicy.allowedFileExtensions.join(',');
    fileLimitNote.textContent = `Up to ${filePolicy.maxFiles} files and ${formatFileSize(filePolicy.maxTotalFileBytes)} total. Allowed types: ${filePolicy.allowedFileExtensions.join(', ')}.`;
    filePolicyReady = true;
  }).catch(() => {
    filePolicyReady = false;
    fileLimitNote.textContent = 'File limits could not be loaded. Check your connection and try again.';
  });

  const renderFiles = (): void => {
    fileList.replaceChildren();
    for (const [index, file] of files.entries()) {
      const item = document.createElement('li');
      const label = document.createElement('span');
      label.textContent = `${file.name} (${formatFileSize(file.size)})`;
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'remove-file';
      remove.textContent = 'Remove';
      remove.setAttribute('aria-label', `Remove ${file.name}`);
      remove.addEventListener('click', () => { files.splice(index, 1); fileError.textContent = ''; fileError.hidden = true; renderFiles(); });
      item.append(label, remove);
      fileList.append(item);
    }
  };

  const addFiles = (selected: FileList | null): void => {
    fileError.textContent = '';
    fileError.hidden = true;
    if (!filePolicyReady || !filePolicy) {
      fileError.textContent = 'File limits are not available yet. Try again when they have loaded.';
      fileError.hidden = false;
      fileInput.value = '';
      return;
    }
    const errors: string[] = [];
    for (const file of Array.from(selected ?? [])) {
      const dot = file.name.lastIndexOf('.');
      const extension = dot >= 0 ? file.name.slice(dot).toLowerCase() : '';
      if (!filePolicy.allowedFileExtensions.includes(extension)) { errors.push(`${file.name}: unsupported file type.`); continue; }
      if (file.size < 1) { errors.push(`${file.name}: empty files are not supported.`); continue; }
      if (files.some(existing => existing.name === file.name && existing.size === file.size && existing.lastModified === file.lastModified && existing.type === file.type)) continue;
      if (files.length >= filePolicy.maxFiles) { errors.push(`You can add at most ${filePolicy.maxFiles} files.`); continue; }
      const currentTotal = files.reduce((total, existing) => total + existing.size, 0);
      if (file.size > filePolicy.maxTotalFileBytes - currentTotal) { errors.push(`The selected files exceed the ${formatFileSize(filePolicy.maxTotalFileBytes)} total limit.`); continue; }
      files.push(file);
    }
    fileInput.value = '';
    fileError.textContent = errors.join(' ');
    fileError.hidden = errors.length === 0;
    renderFiles();
  };
  fileInput.addEventListener('change', () => addFiles(fileInput.files));
  passwordEnabledField.addEventListener('change', () => {
    passwordContainer.hidden = !passwordEnabledField.checked;
    passwordField.required = passwordEnabledField.checked;
    if (!passwordEnabledField.checked) passwordField.value = '';
  });
  emailEnabledField.addEventListener('change', () => {
    emailContainer.hidden = !emailEnabledField.checked;
    emailField.required = emailEnabledField.checked;
  });

  function formatFileSize(bytes: number): string {
    if (bytes < 1024 * 1024) return `${Math.ceil(bytes / 1024)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  form.addEventListener('submit', event => {
    event.preventDefault();
    if (createButton.disabled) return;

    const plaintext = messageField.value;
    const expiry = expiryValue(expiryField.value);
    if (!plaintext.trim() && files.length === 0) {
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
    if (files.length && (!filePolicyReady || !filePolicy)) {
      errorPanel.textContent = 'File limits could not be loaded. Check your connection and try again.';
      errorPanel.hidden = false;
      successPanel.hidden = true;
      return;
    }
    const password = passwordEnabledField.checked ? passwordField.value : '';
    if (passwordEnabledField.checked && !password.trim()) {
      errorPanel.textContent = 'Enter an access code or turn off access-code protection.';
      errorPanel.hidden = false;
      successPanel.hidden = true;
      passwordField.focus();
      return;
    }
    const emailAddress = emailEnabledField.checked ? emailField.value.trim() : '';
    if (emailEnabledField.checked && (!emailAddress || !emailField.checkValidity())) {
      errorPanel.textContent = 'Enter a valid recipient email address.';
      errorPanel.hidden = false;
      successPanel.hidden = true;
      emailField.focus();
      return;
    }

    const selectedFiles = [...files];
    void (async () => {
      errorPanel.hidden = true;
      successPanel.hidden = true;
      copyStatus.textContent = '';
      createButton.disabled = true;
      createButton.textContent = 'Creating…';
      try {
        const encrypted = await encryptMessage(plaintext);
        decodeCanonical(encrypted.clientKey, 32);
        const requestWithoutFiles: Omit<CreateRequest, 'files'> = {
          protocolVersion: 1,
          expiry,
          message: plaintext.trim() ? encrypted.message : null,
          ...(password ? { password: await derivePasswordToken(password, encrypted.clientKey) } : {}),
          ...(emailAddress ? { emailAddress } : {})
        };
        const created = selectedFiles.length
          ? await (async () => {
              const body = await (dependencies.fileCrypto ?? defaultFileCrypto).encryptFilesAndSerialize(requestWithoutFiles, selectedFiles, decodeCanonical(encrypted.clientKey, 32));
              return createWithProof(dependencies.api, { ...requestWithoutFiles, files: [] }, body);
            })()
          : await createWithProof(dependencies.api, { ...requestWithoutFiles, files: [] });
        decodeCanonical(created.id, 16);
        const shareLink = `${SHARE_ORIGIN}/s/${created.id}#${encrypted.clientKey}`;
        linkField.value = shareLink;
        const expiryDate = new Date(created.expiresAt);
        expiryMessage.textContent = Number.isNaN(expiryDate.valueOf())
          ? `This link expires after ${expiry}.`
          : `This link expires ${expiryDate.toLocaleString()}.`;
        successPanel.hidden = false;
        passwordValue.value = password;
        successPassword.hidden = !password;
        if (messageField.value === plaintext) messageField.value = '';
        if (passwordField.value === password) passwordField.value = '';
        const submittedFiles = new Set(selectedFiles);
        for (let index = files.length - 1; index >= 0; index--) if (submittedFiles.has(files[index]!)) files.splice(index, 1);
        renderFiles();
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

  copyPasswordButton.addEventListener('click', () => {
    const password = passwordValue.value;
    if (!password) return;
    void dependencies.copyText(password).then(() => {
      passwordCopyStatus.textContent = 'Access code copied.';
    }).catch(() => {
      passwordValue.focus();
      passwordValue.select();
      passwordCopyStatus.textContent = 'Could not copy automatically. Select and copy the access code.';
    });
  });
}
