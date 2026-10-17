import { describe, expect, it } from 'vitest';
import {
  appCallbackUrl,
  clearTokens,
  getAccessToken,
  getRefreshToken,
  isLoggedIn,
  loginPageUrl,
  parseAppSignIn,
  rememberReturnPath,
  returnPathFrom,
  setTokens,
  signInLocation,
  ssoLoginUrl,
  takeReturnPath,
} from './auth';

describe('auth token storage', () => {
  it('starts logged out with no tokens', () => {
    expect(getAccessToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(isLoggedIn()).toBe(false);
  });

  it('stores and reads both tokens under stable keys', () => {
    setTokens('access-1', 'refresh-1');
    expect(getAccessToken()).toBe('access-1');
    expect(getRefreshToken()).toBe('refresh-1');
    expect(isLoggedIn()).toBe(true);
    // Keys are part of the persisted contract with existing sessions
    expect(localStorage.getItem('cpmesh_access_token')).toBe('access-1');
    expect(localStorage.getItem('cpmesh_refresh_token')).toBe('refresh-1');
  });

  it('overwrites previous tokens', () => {
    setTokens('a1', 'r1');
    setTokens('a2', 'r2');
    expect(getAccessToken()).toBe('a2');
    expect(getRefreshToken()).toBe('r2');
  });

  it('clears both tokens', () => {
    setTokens('a', 'r');
    clearTokens();
    expect(getAccessToken()).toBeNull();
    expect(getRefreshToken()).toBeNull();
    expect(isLoggedIn()).toBe(false);
  });

  it('treats an empty access token as logged out', () => {
    setTokens('', 'r');
    expect(isLoggedIn()).toBe(false);
  });
});

describe('desktop app sign-in', () => {
  const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

  it('reads the request from the sign-in page query', () => {
    expect(parseAppSignIn(`client_redirect=cpmesh%3A%2F%2Fauth%2Fcallback&code_challenge=${challenge}`)).toEqual({
      clientRedirect: 'cpmesh://auth/callback',
      codeChallenge: challenge,
    });
  });

  it('ignores redirects to anything but the cpmesh:// scheme', () => {
    expect(parseAppSignIn(`client_redirect=https%3A%2F%2Fevil.example%2Fcb&code_challenge=${challenge}`)).toBeNull();
    expect(parseAppSignIn(`client_redirect=javascript%3Aalert(1)&code_challenge=${challenge}`)).toBeNull();
  });

  it('needs both the redirect and the challenge', () => {
    expect(parseAppSignIn('client_redirect=cpmesh%3A%2F%2Fauth%2Fcallback')).toBeNull();
    expect(parseAppSignIn(`code_challenge=${challenge}`)).toBeNull();
    expect(parseAppSignIn('')).toBeNull();
    expect(parseAppSignIn(undefined)).toBeNull();
  });

  it('adds the one-time code to the redirect', () => {
    const request = { clientRedirect: 'cpmesh://auth/callback', codeChallenge: challenge };
    expect(appCallbackUrl(request, 'a+b/c')).toBe('cpmesh://auth/callback?code=a%2Bb%2Fc');
    expect(appCallbackUrl({ ...request, clientRedirect: 'cpmesh://auth/callback?state=1' }, 'x')).toBe('cpmesh://auth/callback?state=1&code=x');
  });

  it('keeps the request across single sign-on and back to the sign-in page', () => {
    const request = { clientRedirect: 'cpmesh://auth/callback', codeChallenge: challenge };
    expect(ssoLoginUrl(null)).toBe('/api/auth/social/login');
    expect(ssoLoginUrl(request)).toBe(
      `/api/auth/social/login?client_redirect=cpmesh%3A%2F%2Fauth%2Fcallback&code_challenge=${challenge}&code_challenge_method=S256`,
    );
    expect(loginPageUrl(null)).toBe('#/login');
    expect(parseAppSignIn(loginPageUrl(request).split('?')[1])).toEqual(request);
  });
});

describe("returning to an AI agent's consent page after signing in", () => {
  const authorize =
    '#/authorize?client_id=cpmesh-mcp&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2Fcallback&response_type=code&state=s%2B1&scope=clipboard%3Aread';

  it('recognizes the consent pages, keeping their query intact', () => {
    expect(returnPathFrom(authorize)).toBe(authorize);
    expect(returnPathFrom('#/activate?user_code=BCDF-GHJK')).toBe('#/activate?user_code=BCDF-GHJK');
    expect(returnPathFrom('#/activate')).toBe('#/activate');
    expect(returnPathFrom('/authorize?state=x')).toBe('#/authorize?state=x');
  });

  it('ignores every other page', () => {
    for (const hash of ['', '#/', '#/login', '#/clipboard', '#/authorize/x', '#/activated', '#/mcp?x=/authorize', null, undefined]) {
      expect(returnPathFrom(hash), String(hash)).toBeNull();
    }
  });

  it('signs in again on the consent page, or on the sign-in page elsewhere', () => {
    expect(signInLocation(authorize)).toBe(authorize);
    expect(signInLocation('#/devices')).toBe('#/login');
    window.location.hash = '#/activate?user_code=BCDF-GHJK';
    expect(signInLocation()).toBe('#/activate?user_code=BCDF-GHJK');
  });

  it('keeps the page across a single sign-on, once', () => {
    rememberReturnPath(authorize);
    expect(takeReturnPath()).toBe(authorize);
    expect(takeReturnPath()).toBeNull();
  });

  it('forgets a single sign-on that took longer than 30 minutes', () => {
    const now = Date.now();
    rememberReturnPath(authorize);
    expect(takeReturnPath(now + 31 * 60_000)).toBeNull();
    // Read once, even when too old
    expect(takeReturnPath(now)).toBeNull();
  });

  it('only returns to consent pages', () => {
    rememberReturnPath('#/admin/users');
    expect(takeReturnPath()).toBeNull();
    sessionStorage.setItem('cpmesh_return_to', 'not json');
    expect(takeReturnPath()).toBeNull();
    sessionStorage.setItem('cpmesh_return_to', JSON.stringify({ path: 'javascript:alert(1)', at: Date.now() }));
    expect(takeReturnPath()).toBeNull();
  });
});
