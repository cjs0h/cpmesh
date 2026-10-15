import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { api, ApiError, apiWithToken, requestReauth, setReauthHandler } from './api';
import { getAccessToken, getRefreshToken, setTokens } from './auth';
import { jsonResponse } from '../test/setup';

const fetchMock = () => fetch as unknown as Mock;

describe('api()', () => {
  beforeEach(() => {
    fetchMock().mockReset();
    setReauthHandler(null);
  });

  it('sends unauthenticated requests without an Authorization header', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { ok: true }));

    const result = await api<{ ok: boolean }>('/api/plans');

    expect(result).toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock().mock.calls[0];
    expect(url).toBe('/api/plans');
    expect(init.headers).not.toHaveProperty('Authorization');
    expect(init.headers).not.toHaveProperty('Content-Type');
  });

  it('adds a bearer token and JSON content type for string bodies', async () => {
    setTokens('tok', 'ref');
    fetchMock().mockResolvedValueOnce(jsonResponse(200, {}));

    await api('/api/devices', { method: 'POST', body: JSON.stringify({ name: 'x' }) });

    const [, init] = fetchMock().mock.calls[0];
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer tok');
    expect(init.headers['Content-Type']).toBe('application/json');
  });

  it('preserves caller-supplied headers', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(200, {}));

    await api('/api/x', { headers: { 'X-Custom': '1' } });

    const [, init] = fetchMock().mock.calls[0];
    expect(init.headers['x-custom']).toBe('1');
  });

  it('returns undefined for 204 responses', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(204, null));
    await expect(api('/api/clipboard', { method: 'DELETE' })).resolves.toBeUndefined();
  });

  it('throws the server error message on failure', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(400, { error: 'bad input' }));
    await expect(api('/api/x')).rejects.toThrow('bad input');
  });

  it('falls back to the status text when the error body is not JSON', async () => {
    fetchMock().mockResolvedValueOnce({
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
      json: async () => {
        throw new Error('not json');
      },
    } as unknown as Response);
    await expect(api('/api/x')).rejects.toThrow('Bad Gateway');
  });

  it('uses a generic message when neither error nor status text is present', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(500, {}));
    await expect(api('/api/x')).rejects.toThrow('Request failed');
  });

  it('does not attempt a refresh for 401s without a token', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(401, { error: 'missing authorization token' }));
    await expect(api('/api/me')).rejects.toThrow('missing authorization token');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('refreshes the access token on 401 and retries the request once', async () => {
    setTokens('expired', 'refresh-1');
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(401, { error: 'invalid or expired token' }))
      .mockResolvedValueOnce(jsonResponse(200, { access_token: 'fresh', refresh_token: 'refresh-2' }))
      .mockResolvedValueOnce(jsonResponse(200, { id: 'me' }));

    const result = await api('/api/me');

    expect(result).toEqual({ id: 'me' });
    expect(fetch).toHaveBeenCalledTimes(3);
    const [refreshUrl, refreshInit] = fetchMock().mock.calls[1];
    expect(refreshUrl).toBe('/api/auth/refresh');
    expect(refreshInit.method).toBe('POST');
    expect(JSON.parse(refreshInit.body)).toEqual({ refresh_token: 'refresh-1' });
    const [, retryInit] = fetchMock().mock.calls[2];
    expect(retryInit.headers.Authorization).toBe('Bearer fresh');
    // Refresh tokens are single-use: the rotated one replaces the spent one, which the
    // server would treat as stolen if it were presented again
    expect(getAccessToken()).toBe('fresh');
    expect(getRefreshToken()).toBe('refresh-2');
  });

  it('clears the session and redirects to login when the refresh fails', async () => {
    setTokens('expired', 'refresh-1');
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(401, { error: 'invalid or expired token' }))
      .mockResolvedValueOnce(jsonResponse(401, { error: 'invalid refresh token' }));

    await expect(api('/api/me')).rejects.toThrow('Session expired');
    expect(getAccessToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(window.location.hash).toBe('#/login');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('treats a network failure during refresh as a failed refresh', async () => {
    setTokens('expired', 'refresh-1');
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(401, { error: 'expired' }))
      .mockRejectedValueOnce(new TypeError('network down'));

    await expect(api('/api/me')).rejects.toThrow('Session expired');
    expect(getAccessToken()).toBeNull();
  });

  it('does not refresh when there is no refresh token', async () => {
    localStorage.setItem('cpmesh_access_token', 'expired');
    fetchMock().mockResolvedValueOnce(jsonResponse(401, { error: 'expired' }));

    await expect(api('/api/me')).rejects.toThrow('Session expired');
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('recovers after a refresh was skipped for lack of a refresh token', async () => {
    // Regression: the skipped refresh used to leave the "in flight" flag set forever,
    // so every later 401 failed immediately without attempting a refresh.
    localStorage.setItem('cpmesh_access_token', 'expired');
    fetchMock().mockResolvedValueOnce(jsonResponse(401, { error: 'expired' }));
    await expect(api('/api/me')).rejects.toThrow('Session expired');

    setTokens('expired-again', 'refresh-2');
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(401, { error: 'expired' }))
      .mockResolvedValueOnce(jsonResponse(200, { access_token: 'fresh-2' }))
      .mockResolvedValueOnce(jsonResponse(200, { id: 'me' }));

    await expect(api('/api/me')).resolves.toEqual({ id: 'me' });
    expect(getAccessToken()).toBe('fresh-2');
  });

  it('deduplicates concurrent refreshes', async () => {
    setTokens('expired', 'refresh-1');
    let resolveRefresh!: (r: Response) => void;
    const pendingRefresh = new Promise<Response>((resolve) => {
      resolveRefresh = resolve;
    });
    fetchMock().mockImplementation((url: string, init?: RequestInit) => {
      if (url === '/api/auth/refresh') return pendingRefresh;
      const auth = (init?.headers as Record<string, string>)?.Authorization;
      if (auth === 'Bearer fresh') return Promise.resolve(jsonResponse(200, { url }));
      return Promise.resolve(jsonResponse(401, { error: 'expired' }));
    });

    const first = api('/api/a');
    const second = api('/api/b');
    // Let both initial requests fail and both callers reach tryRefresh()
    await Promise.resolve();
    await Promise.resolve();
    resolveRefresh(jsonResponse(200, { access_token: 'fresh' }));

    await expect(first).resolves.toEqual({ url: '/api/a' });
    await expect(second).resolves.toEqual({ url: '/api/b' });
    const refreshCalls = fetchMock().mock.calls.filter(([url]) => url === '/api/auth/refresh');
    expect(refreshCalls).toHaveLength(1);
  });

  it('takes turns with other tabs through a Web Lock while refreshing', async () => {
    const request = vi.fn((_name: string, callback: () => Promise<boolean>) => callback());
    vi.stubGlobal('navigator', { locks: { request } });
    setTokens('expired', 'refresh-1');
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(401, { error: 'invalid or expired token' }))
      .mockResolvedValueOnce(jsonResponse(200, { access_token: 'fresh', refresh_token: 'refresh-2' }))
      .mockResolvedValueOnce(jsonResponse(200, { id: 'me' }));

    await expect(api('/api/me')).resolves.toEqual({ id: 'me' });
    expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0][0]).toBe('cpmesh-token-refresh');
  });

  it('uses tokens another tab already refreshed instead of refreshing again', async () => {
    setTokens('expired', 'refresh-1');
    fetchMock()
      .mockImplementationOnce(async () => {
        // Another tab rotates the shared tokens while this request is in flight
        setTokens('from-other-tab', 'refresh-2');
        return jsonResponse(401, { error: 'invalid or expired token' });
      })
      .mockResolvedValueOnce(jsonResponse(200, { id: 'me' }));

    await expect(api('/api/me')).resolves.toEqual({ id: 'me' });

    expect(fetch).toHaveBeenCalledTimes(2);
    const [, retryInit] = fetchMock().mock.calls[1];
    expect(retryInit.headers.Authorization).toBe('Bearer from-other-tab');
    expect(getRefreshToken()).toBe('refresh-2');
  });

  it('adopts the tokens another tab saves when the server reports a concurrent refresh', async () => {
    setTokens('expired', 'refresh-1');
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(401, { error: 'invalid or expired token' }))
      .mockImplementationOnce(async () => {
        // The other tab's refresh won the race and saves its pair shortly after
        setTimeout(() => setTokens('from-other-tab', 'refresh-2'), 150);
        return jsonResponse(409, { error: 'refresh token already used' });
      })
      .mockResolvedValueOnce(jsonResponse(200, { id: 'me' }));

    await expect(api('/api/me')).resolves.toEqual({ id: 'me' });

    const [, retryInit] = fetchMock().mock.calls[2];
    expect(retryInit.headers.Authorization).toBe('Bearer from-other-tab');
  });

  it('expires the session when no tab saves the rotated tokens', async () => {
    vi.useFakeTimers();
    try {
      setTokens('expired', 'refresh-1');
      fetchMock()
        .mockResolvedValueOnce(jsonResponse(401, { error: 'invalid or expired token' }))
        .mockResolvedValueOnce(jsonResponse(409, { error: 'refresh token already used' }));

      const failed = expect(api('/api/me')).rejects.toThrow('Session expired');
      await vi.advanceTimersByTimeAsync(3_100);
      await failed;
      // The spent token is never presented again
      expect(fetch).toHaveBeenCalledTimes(2);
      expect(getRefreshToken()).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('api() errors and step-up', () => {
  beforeEach(() => {
    fetchMock().mockReset();
    setReauthHandler(null);
  });

  it('throws ApiError with the status, code and body', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(403, { error: 'Finish two-factor authentication first.', code: 'mfa_required', enrolled: true }));

    const error = await api('/api/admin/users').catch((e) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('Finish two-factor authentication first.');
    expect(error.status).toBe(403);
    expect(error.code).toBe('mfa_required');
    expect(error.data).toEqual({ error: 'Finish two-factor authentication first.', code: 'mfa_required', enrolled: true });
  });

  it('leaves the code unset for plain errors', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(409, { error: 'conflict' }));
    const error = await api('/api/x').catch((e) => e);
    expect(error.status).toBe(409);
    expect(error.code).toBeUndefined();
  });

  it('asks for a confirmation on reauth_required and retries with the new session', async () => {
    setTokens('stale', 'refresh-1');
    const handler = vi.fn(async () => {
      setTokens('confirmed', 'refresh-2');
      return true;
    });
    setReauthHandler(handler);
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(403, { error: "Confirm it's you to continue.", code: 'reauth_required' }))
      .mockResolvedValueOnce(jsonResponse(200, { done: true }));

    await expect(api('/api/mfa/recovery-codes', { method: 'POST' })).resolves.toEqual({ done: true });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledTimes(2);
    const [url, init] = fetchMock().mock.calls[1];
    expect(url).toBe('/api/mfa/recovery-codes');
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer confirmed');
  });

  it('returns undefined when the retried request answers 204', async () => {
    setTokens('stale', 'refresh-1');
    setReauthHandler(async () => true);
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(403, { error: 'Confirm', code: 'reauth_required' }))
      .mockResolvedValueOnce(jsonResponse(204, null));

    await expect(api('/api/admin/users/u1', { method: 'DELETE' })).resolves.toBeUndefined();
  });

  it('throws reauth_required when the user cancels', async () => {
    setTokens('stale', 'refresh-1');
    const handler = vi.fn(async () => false);
    setReauthHandler(handler);
    fetchMock().mockResolvedValueOnce(jsonResponse(403, { error: "Confirm it's you to continue.", code: 'reauth_required' }));

    const error = await api('/api/mfa/totp', { method: 'DELETE' }).catch((e) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe('reauth_required');
    expect(handler).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('throws reauth_required without a registered handler', async () => {
    setTokens('stale', 'refresh-1');
    fetchMock().mockResolvedValueOnce(jsonResponse(403, { error: 'Confirm', code: 'reauth_required' }));

    await expect(api('/api/mfa/totp', { method: 'DELETE' })).rejects.toMatchObject({ code: 'reauth_required', status: 403 });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('retries only once and reports the second answer', async () => {
    setTokens('stale', 'refresh-1');
    const handler = vi.fn(async () => true);
    setReauthHandler(handler);
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(403, { error: 'Confirm', code: 'reauth_required' }))
      .mockResolvedValueOnce(jsonResponse(409, { error: 'add another method before removing this one' }));

    await expect(api('/api/mfa/totp', { method: 'DELETE' })).rejects.toMatchObject({
      status: 409,
      message: 'add another method before removing this one',
    });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('sends FormData without a JSON content type', async () => {
    setTokens('tok', 'ref');
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { uploaded: [] }));
    const body = new FormData();
    body.append('replace', 'true');

    await api('/api/admin/downloads/upload', { method: 'POST', body });

    const [, init] = fetchMock().mock.calls[0];
    expect(init.body).toBe(body);
    expect(init.headers).not.toHaveProperty('Content-Type');
    expect(init.headers.Authorization).toBe('Bearer tok');
  });

  it('runs the registered handler through requestReauth', async () => {
    await expect(requestReauth()).resolves.toBe(false);
    setReauthHandler(async () => true);
    await expect(requestReauth()).resolves.toBe(true);
  });
});

describe('apiWithToken()', () => {
  beforeEach(() => {
    fetchMock().mockReset();
  });

  it('uses the given token instead of the stored session', async () => {
    setTokens('stored', 'stored-refresh');
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { ok: true }));

    await expect(apiWithToken('/api/mfa', 'ticket', { headers: { 'X-Custom': '1' } })).resolves.toEqual({ ok: true });

    const [, init] = fetchMock().mock.calls[0];
    expect(init.headers.Authorization).toBe('Bearer ticket');
    expect(init.headers['x-custom']).toBe('1');
  });

  it('sends no Authorization header without a token', async () => {
    setTokens('stored', 'stored-refresh');
    fetchMock().mockResolvedValueOnce(jsonResponse(200, {}));

    await apiWithToken('/api/auth/login', null, { method: 'POST', body: JSON.stringify({ username: 'a' }) });

    const [, init] = fetchMock().mock.calls[0];
    expect(init.headers).not.toHaveProperty('Authorization');
    expect(init.headers['Content-Type']).toBe('application/json');
  });

  it('throws ApiError on 401 without refreshing or signing out', async () => {
    setTokens('stored', 'stored-refresh');
    fetchMock().mockResolvedValueOnce(jsonResponse(401, { error: 'invalid or expired token; sign in again' }));

    const error = await apiWithToken('/api/mfa/verify', 'ticket', { method: 'POST', body: '{}' }).catch((e) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(401);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(getAccessToken()).toBe('stored');
    expect(window.location.hash).toBe('');
  });

  it('keeps structured error fields', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(403, { error: 'suspended', code: 'account_suspended' }));
    await expect(apiWithToken('/api/auth/login', null, { method: 'POST', body: '{}' })).rejects.toMatchObject({
      status: 403,
      code: 'account_suspended',
      data: { error: 'suspended', code: 'account_suspended' },
    });
  });

  it('returns undefined for 204 responses', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(204, null));
    await expect(apiWithToken('/api/x', 't', { method: 'DELETE' })).resolves.toBeUndefined();
  });
});
