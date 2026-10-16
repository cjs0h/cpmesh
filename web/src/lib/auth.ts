import { writable } from 'svelte/store';

const TOKEN_KEY = 'cpmesh_access_token';
const REFRESH_KEY = 'cpmesh_refresh_token';
let generation = 0;
const sessionEndHandlers = new Set<() => void>();
export const authSession = writable(typeof localStorage !== 'undefined' && !!getAccessToken());

export function authGeneration(): number { return generation; }
export function onSessionEnd(handler: () => void): () => void {
  sessionEndHandlers.add(handler);
  return () => { sessionEndHandlers.delete(handler); };
}

export function getAccessToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY);
}

export function setTokens(access: string, refresh: string) {
  if (!getAccessToken()) generation++;
  localStorage.setItem(TOKEN_KEY, access);
  localStorage.setItem(REFRESH_KEY, refresh);
  authSession.set(!!access);
}

export function clearTokens() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
  endSession();
}

function endSession() {
  generation++;
  authSession.set(false);
  sessionEndHandlers.forEach((handler) => handler());
}

if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
  window.addEventListener('storage', (event) => {
    if (event.key !== TOKEN_KEY && event.key !== null) return;
    if (!getAccessToken()) endSession();
    else authSession.set(true);
  });
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

/**
 * Where an AI agent asks for access. They need a session; signed out, they show the
 * sign-in form and continue once the user has signed in.
 */
const CONSENT_ROUTES = ['/authorize', '/activate'];
const RETURN_KEY = 'cpmesh_return_to';
/** A single sign-on that takes longer than this doesn't go back to the agent's page. */
const RETURN_TTL_MS = 30 * 60_000;

/** The agent's consent page in `hash` (`#/authorize?…`, `#/activate?…`), with its query; null for other pages. */
export function returnPathFrom(hash: string | null | undefined): string | null {
  const route = (hash ?? '').replace(/^#/, '');
  return CONSENT_ROUTES.includes(route.split('?')[0]) ? `#${route}` : null;
}

/** Where to sign in again when the session ends: the agent's consent page the user is on, else the sign-in page. */
export function signInLocation(hash: string = window.location.hash): string {
  return returnPathFrom(hash) ?? '#/login';
}

/** Keeps the agent's consent page across the single sign-on round trip (this tab only). */
export function rememberReturnPath(path: string) {
  try {
    sessionStorage.setItem(RETURN_KEY, JSON.stringify({ path, at: Date.now() }));
  } catch {
    // Storage unavailable: the user starts again from the agent
  }
}

/** The consent page a single sign-on started from, if recent. It is forgotten once read. */
export function takeReturnPath(now: number = Date.now()): string | null {
  let stored: string | null;
  try {
    stored = sessionStorage.getItem(RETURN_KEY);
    sessionStorage.removeItem(RETURN_KEY);
  } catch {
    return null;
  }
  if (!stored) return null;
  try {
    const { path, at } = JSON.parse(stored);
    if (typeof path !== 'string' || typeof at !== 'number' || at > now || now - at > RETURN_TTL_MS) return null;
    return returnPathFrom(path);
  } catch {
    return null;
  }
}
