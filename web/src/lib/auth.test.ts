import { describe, expect, it } from 'vitest';
import { clearTokens, getAccessToken, getRefreshToken, isLoggedIn, setTokens } from './auth';

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
