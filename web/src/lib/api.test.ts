import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { api } from './api';
import { getAccessToken, getRefreshToken, setTokens } from './auth';
import { jsonResponse } from '../test/setup';

const fetchMock = () => fetch as unknown as Mock;

describe('api()', () => {
  beforeEach(() => {
    fetchMock().mockReset();
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
