// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://cpmesh.test/"}
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import Login from './Login.svelte';
import { clearTokens, getAccessToken, rememberReturnPath, takeReturnPath } from '../lib/auth';
import { jsonResponse } from '../test/setup';
import { button, cleanup, findText, goTo, pageText, render, type } from '../test/dom';

const fetchMock = () => fetch as unknown as Mock;
const AUTHORIZE =
  '#/authorize?client_id=cpmesh-mcp&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2Fcallback&response_type=code&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=clipboard%3Aread%20clipboard%3Awrite';

/** The server, with single sign-on on and two-factor sign-in for the password. */
function serve() {
  fetchMock().mockImplementation(async (url: string) => {
    if (url === '/api/auth/social/status') return jsonResponse(200, { enabled: true, provider: 'google' });
    if (url === '/api/settings') return jsonResponse(200, {});
    if (url === '/api/auth/login') {
      return jsonResponse(401, {
        error: 'mfa_required',
        code: 'mfa_required',
        mfa_token: 'ticket-1',
        stage: 'verify',
        methods: ['totp'],
      });
    }
    if (url === '/api/mfa/verify') return jsonResponse(200, { access_token: 'access-1', refresh_token: 'refresh-1' });
    return jsonResponse(404, { error: `unexpected ${url}` });
  });
}

function input(selector: string): HTMLInputElement {
  const found = document.querySelector<HTMLInputElement>(selector);
  if (!found) throw new Error(`no ${selector}`);
  return found;
}

let reload: Mock;

beforeEach(() => {
  serve();
  reload = vi.spyOn(window.location, 'reload').mockImplementation(() => {}) as unknown as Mock;
});

afterEach(() => {
  cleanup();
  clearTokens();
});

describe("signing in from an AI agent's consent page", () => {
  it('comes back to the consent page after a password and a second factor', async () => {
    goTo(AUTHORIZE);
    render(Login);
    expect(pageText()).toContain('Sign in to approve an AI agent');

    type(input('input[autocomplete="username"]'), 'hayder');
    type(input('input[type="password"]'), 'correct horse');
    document.querySelector<HTMLButtonElement>('form button[type="submit"]')!.click();
    await findText('Two-factor authentication');
    type(input('input[autocomplete="one-time-code"]'), '123456');

    await vi.waitFor(() => expect(reload).toHaveBeenCalledOnce());
    expect(getAccessToken()).toBe('access-1');
    expect(window.location.hash).toBe(AUTHORIZE);
  });

  it('keeps the consent page for the way back from single sign-on', async () => {
    goTo('#/activate?user_code=BCDF-GHJK');
    render(Login);
    await findText('Continue with Google');
    const stopNavigation = (e: Event) => e.preventDefault();
    window.addEventListener('click', stopNavigation, true);

    button('Continue with Google').click();

    window.removeEventListener('click', stopNavigation, true);
    expect(takeReturnPath()).toBe('#/activate?user_code=BCDF-GHJK');
  });

  it('shows a failed single sign-on on the consent page it started from', async () => {
    rememberReturnPath(AUTHORIZE);
    goTo('#/login?social_error=User+cancelled');
    render(Login);

    await findText('User cancelled');
    expect(window.location.hash).toBe(AUTHORIZE);
    expect(pageText()).toContain('Sign in to approve an AI agent');
    expect(takeReturnPath()).toBeNull();
  });

  it('does not send other sign-ins to a consent page', async () => {
    goTo('#/login?social_error=User+cancelled');
    render(Login);

    await findText('User cancelled');
    await vi.waitFor(() => expect(window.location.hash).toBe('#/login'));
    expect(pageText()).not.toContain('Sign in to approve an AI agent');
  });
});
