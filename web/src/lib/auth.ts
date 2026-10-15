const TOKEN_KEY = 'cpmesh_access_token';
const REFRESH_KEY = 'cpmesh_refresh_token';

export function getAccessToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY);
}

export function setTokens(access: string, refresh: string) {
  localStorage.setItem(TOKEN_KEY, access);
  localStorage.setItem(REFRESH_KEY, refresh);
}

export function clearTokens() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

export function isLoggedIn(): boolean {
  return !!getAccessToken();
}

/**
 * The desktop app's "Sign in with browser": it opens
 * `#/login?client_redirect=cpmesh://auth/callback&code_challenge=…` and receives a
 * one-time code for the finished sign-in instead of this browser keeping the session.
 */
export interface AppSignIn {
  clientRedirect: string;
  /** PKCE S256 challenge; only the app holds the verifier. */
  codeChallenge: string;
}

/** Reads an app sign-in request from a hash query string. Only `cpmesh://` redirects are honoured. */
export function parseAppSignIn(querystring: string | null | undefined): AppSignIn | null {
  const params = new URLSearchParams(querystring ?? '');
  const clientRedirect = params.get('client_redirect') ?? '';
  const codeChallenge = params.get('code_challenge') ?? '';
  if (!clientRedirect.startsWith('cpmesh://') || !codeChallenge) return null;
  return { clientRedirect, codeChallenge };
}

/** The `cpmesh://` URL that hands the one-time `code` to the app. */
export function appCallbackUrl(request: AppSignIn, code: string): string {
  const separator = request.clientRedirect.includes('?') ? '&' : '?';
  return `${request.clientRedirect}${separator}code=${encodeURIComponent(code)}`;
}

/** Single sign-on, ending in the app (PKCE) when it asked for the sign-in. */
export function ssoLoginUrl(request: AppSignIn | null): string {
  if (!request) return '/api/auth/social/login';
  const params = new URLSearchParams({
    client_redirect: request.clientRedirect,
    code_challenge: request.codeChallenge,
    code_challenge_method: 'S256',
  });
  return `/api/auth/social/login?${params}`;
}

/** The sign-in page, still signing in to the app when it asked for the sign-in. */
export function loginPageUrl(request: AppSignIn | null): string {
  if (!request) return '#/login';
  const params = new URLSearchParams({ client_redirect: request.clientRedirect, code_challenge: request.codeChallenge });
  return `#/login?${params}`;
}
