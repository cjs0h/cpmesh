import { getAccessToken, getRefreshToken, setTokens, clearTokens } from './auth';

let refreshPromise: Promise<boolean> | null = null;

/** How long to wait for another tab to save the tokens it just rotated. */
const ROTATION_WAIT_MS = 3000;

/** Gets a working access token after `rejected` was refused. */
async function tryRefresh(rejected: string): Promise<boolean> {
  // Concurrent 401s share a single in-flight refresh
  if (refreshPromise) return refreshPromise;
  const attempt = refreshAcrossTabs(rejected);
  refreshPromise = attempt;
  try {
    return await attempt;
  } finally {
    if (refreshPromise === attempt) refreshPromise = null;
  }
}

/**
 * Refresh tokens are single-use, and every tab shares the pair in localStorage. The
 * server treats a reused refresh token as stolen and signs the user out on every
 * device, so tabs take turns (Web Locks) and never present a token another tab has
 * already rotated.
 */
function refreshAcrossTabs(rejected: string): Promise<boolean> {
  const locks = (globalThis.navigator as Navigator | undefined)?.locks;
  const run = () => refreshOnce(rejected);
  return locks ? locks.request('cpmesh-token-refresh', run) : run();
}

async function refreshOnce(rejected: string): Promise<boolean> {
  // Another tab refreshed already: use its tokens
  const access = getAccessToken();
  if (access && access !== rejected) return true;

  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;
  try {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    // Another tab used this token moments ago (browsers without Web Locks)
    if (res.status === 409) return waitForRotation(refreshToken);
    if (!res.ok) return false;
    const data = await res.json();
    // The presented refresh token is now spent: keep the rotated one
    setTokens(data.access_token, data.refresh_token ?? refreshToken);
    return true;
  } catch {
    return false;
  }
}

/** Waits for the tab that rotated `spent` to save the new pair. */
async function waitForRotation(spent: string): Promise<boolean> {
  const deadline = Date.now() + ROTATION_WAIT_MS;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 100));
    const current = getRefreshToken();
    if (current !== spent) return current !== null;
  }
  return false;
}

/** An error response from the API. `code` is set for errors clients act on
 * (e.g. `reauth_required`, `mfa_required`); `data` is the full JSON body. */
export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly data: Record<string, any>;

  constructor(message: string, status: number, data: Record<string, any> = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = typeof data.code === 'string' ? data.code : undefined;
    this.data = data;
  }
}

/** Asks the user to confirm it's them (second factor or password) and stores the
 * refreshed session; resolves `false` when they cancel. */
export type ReauthHandler = () => Promise<boolean>;

let reauthHandler: ReauthHandler | null = null;

/** Registers the dialog used when the server answers `reauth_required`. */
export function setReauthHandler(handler: ReauthHandler | null) {
  reauthHandler = handler;
}

/** Asks the user to confirm it's them through the registered handler; false without one or when they cancel. */
export async function requestReauth(): Promise<boolean> {
  return reauthHandler ? reauthHandler() : false;
}

async function readError(res: Response): Promise<ApiError> {
  const data = await res.json().catch(() => ({ error: res.statusText }));
  const body = data && typeof data === 'object' ? data : {};
  return new ApiError(body.error || res.statusText || 'Request failed', res.status, body);
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
    const refreshed = await tryRefresh(token);
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
    let err = await readError(res);
    // Sensitive actions need a recent confirmation: ask for it, then retry once
    if (err.code === 'reauth_required' && reauthHandler && (await reauthHandler())) {
      headers['Authorization'] = `Bearer ${getAccessToken()}`;
      res = await fetch(path, { ...options, headers });
      if (res.status === 204) return undefined as T;
      if (res.ok) return res.json();
      err = await readError(res);
    }
    throw err;
  }

  return res.json();
}

/**
 * A request authenticated with `token` (or nothing) instead of the stored session:
 * the sign-in ticket while a second factor is pending, or a session that is handed
 * to the desktop app and never stored. No refresh or step-up; failures throw `ApiError`.
 */
export async function apiWithToken<T = any>(path: string, token: string | null, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    ...Object.fromEntries(new Headers(options.headers).entries()),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (options.body && typeof options.body === 'string') {
    headers['Content-Type'] = 'application/json';
  }

  const res = await fetch(path, { ...options, headers });
  if (res.status === 204) return undefined as T;
  if (!res.ok) throw await readError(res);
  return res.json();
}
