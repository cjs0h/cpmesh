// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://cpmesh.test/"}
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import AuthCallback from './AuthCallback.svelte';
import { clearTokens, getAccessToken, rememberReturnPath } from '../lib/auth';
import { jsonResponse } from '../test/setup';
import { button, cleanup, findText, goTo, render, type } from '../test/dom';

const fetchMock = () => fetch as unknown as Mock;
const ACTIVATE = '#/activate?user_code=BCDF-GHJK';

let reload: Mock;

beforeEach(() => {
  reload = vi.spyOn(window.location, 'reload').mockImplementation(() => {}) as unknown as Mock;
  fetchMock().mockImplementation(async (url: string) => {
    if (url === '/api/mfa') {
      return jsonResponse(200, {
        required: false,
        enabled: true,
        totp: true,
        passkeys: [],
        recovery_codes_remaining: 8,
        passkeys_available: false,
        session_verified: null,
        recent_auth: null,
        has_password: false,
        stage: 'verify',
        email_code_required: false,
      });
    }
    if (url === '/api/mfa/verify') return jsonResponse(200, { access_token: 'access-2', refresh_token: 'refresh-2' });
    return jsonResponse(404, { error: `unexpected ${url}` });
  });
});

afterEach(() => {
  cleanup();
  clearTokens();
});

describe("single sign-on started on an AI agent's consent page", () => {
  it('goes back to the consent page with the session', async () => {
    rememberReturnPath(ACTIVATE);
    goTo('#/auth/callback?access_token=access-1&refresh_token=refresh-1');
    render(AuthCallback);

    await vi.waitFor(() => expect(reload).toHaveBeenCalledOnce());
    expect(getAccessToken()).toBe('access-1');
    expect(window.location.hash).toBe(ACTIVATE);
  });

  it('goes back to the consent page after the second factor', async () => {
    rememberReturnPath(ACTIVATE);
    goTo('#/auth/callback?mfa_token=ticket-1');
    render(AuthCallback);

    await findText('Sign in to approve an AI agent');
    type(document.querySelector<HTMLInputElement>('input[autocomplete="one-time-code"]')!, '123456');

    await vi.waitFor(() => expect(reload).toHaveBeenCalledOnce());
    expect(getAccessToken()).toBe('access-2');
    expect(window.location.hash).toBe(ACTIVATE);
  });

  it('shows the sign-in form on the consent page when the second step is abandoned', async () => {
    rememberReturnPath(ACTIVATE);
    goTo('#/auth/callback?mfa_token=ticket-1');
    render(AuthCallback);
    await findText('Back to sign in');

    button('Back to sign in').click();

    await vi.waitFor(() => expect(window.location.hash).toBe(ACTIVATE));
  });

  it('opens the dashboard otherwise', async () => {
    goTo('#/auth/callback?access_token=access-1&refresh_token=refresh-1');
    render(AuthCallback);

    await vi.waitFor(() => expect(reload).toHaveBeenCalledOnce());
    expect(window.location.hash).toBe('#/');
  });
});
