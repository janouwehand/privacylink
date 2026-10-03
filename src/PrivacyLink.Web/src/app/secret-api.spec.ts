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
});
