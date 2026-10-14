import { getAccessToken, getRefreshToken, setTokens, clearTokens } from './auth';

let refreshPromise: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  // Concurrent 401s share a single in-flight refresh
  if (refreshPromise) return refreshPromise;
  const attempt = refreshOnce();
  refreshPromise = attempt;
  try {
    return await attempt;
  } finally {
    if (refreshPromise === attempt) refreshPromise = null;
  }
}

async function refreshOnce(): Promise<boolean> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;
  try {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    // Keep existing refresh token, update access token
    setTokens(data.access_token, refreshToken);
    return true;
  } catch {
    return false;
  }
}

export async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getAccessToken();
  const headers: Record<string, string> = {
    ...Object.fromEntries(new Headers(options.headers).entries()),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (options.body && typeof options.body === 'string') {
    headers['Content-Type'] = 'application/json';
  }

  let res = await fetch(path, { ...options, headers });

  if (res.status === 401 && token) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      headers['Authorization'] = `Bearer ${getAccessToken()}`;
      res = await fetch(path, { ...options, headers });
    } else {
      clearTokens();
      window.location.hash = '#/login';
      throw new Error('Session expired');
    }
  }

  if (res.status === 204) return undefined as T;

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || 'Request failed');
  }

  return res.json();
}
