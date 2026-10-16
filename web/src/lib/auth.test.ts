import { describe, expect, it } from 'vitest';
import {
  appCallbackUrl,
  clearTokens,
  getAccessToken,
  getRefreshToken,
  isLoggedIn,
  loginPageUrl,
  parseAppSignIn,
  setTokens,
  ssoLoginUrl,
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
