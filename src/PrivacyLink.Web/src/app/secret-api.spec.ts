import { afterEach, describe, expect, it, vi } from 'vitest';
import { SecretApi, SecretApiError } from './secret-api';

describe('SecretApi unlock retries', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('retries temporary overloads using Retry-After and succeeds', async () => {
    vi.useFakeTimers();
    vi.spyOn(Math, 'random').mockReturnValue(0);
    const payload = { protocolVersion: 1, message: null, files: [] };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 503, headers: { 'Retry-After': '2' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify(payload), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const unlocking = new SecretApi().unlock('secret-id', 'password-token');
    await vi.runAllTimersAsync();

    await expect(unlocking).resolves.toEqual(payload);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/secrets/secret-id/unlock');
  });

  it('stops after two retries and surfaces the final 503', async () => {
    vi.useFakeTimers();
    vi.spyOn(Math, 'random').mockReturnValue(0);
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 503, headers: { 'Retry-After': '1' } }));
    vi.stubGlobal('fetch', fetchMock);

    const unlocking = new SecretApi().unlock('secret-id', 'password-token');
    const rejected = expect(unlocking).rejects.toMatchObject({ status: 503 });
    await vi.runAllTimersAsync();

    await rejected;
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('does not retry non-overload errors', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 403 }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(new SecretApi().unlock('secret-id', 'password-token')).rejects.toBeInstanceOf(SecretApiError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('returns the raw unlock response so large file payloads can be parsed in the worker', async () => {
    const response = new TextEncoder().encode(JSON.stringify({ protocolVersion: 1, message: null, files: [] }));
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(response, { status: 200 })));

    const raw = await new SecretApi().unlockRaw('secret-id', 'password-token');

    expect(new TextDecoder().decode(raw)).toBe(JSON.stringify({ protocolVersion: 1, message: null, files: [] }));
  });

  it('returns the raw open response so large file payloads can be parsed in the worker', async () => {
    const response = new TextEncoder().encode(JSON.stringify({ protocolVersion: 1, message: null, files: [] }));
    const fetchMock = vi.fn().mockResolvedValue(new Response(response, { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const raw = await new SecretApi().openRaw('secret-id');

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/secrets/secret-id/open', expect.objectContaining({ method: 'POST' }));
    expect(new TextDecoder().decode(raw)).toBe(JSON.stringify({ protocolVersion: 1, message: null, files: [] }));
  });

  it('sends the worker-serialized request body without stringifying it again', async () => {
    const result = { id: 'AAAAAAAAAAAAAAAAAAAAAA', expiresAt: '2030-01-01T00:00:00.000Z', passwordProtected: false, revokeToken: 'token' };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(result), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);
    const body = new TextEncoder().encode('{"protocolVersion":1,"files":[]}').buffer;

    await expect(new SecretApi().createSerialized(body)).resolves.toEqual(result);
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(body);
  });
});
