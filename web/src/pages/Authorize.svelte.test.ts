// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://cpmesh.test/"}
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import Authorize from './Authorize.svelte';
import { setReauthHandler } from '../lib/api';
import { clearTokens, setTokens } from '../lib/auth';
import { userState } from '../lib/stores/user.svelte';
import { jsonResponse } from '../test/setup';
import { button, checkboxes, cleanup, click, findText, goTo, pageText, render, toggle } from '../test/dom';

const fetchMock = () => fetch as unknown as Mock;
const REDIRECT = 'http://127.0.0.1:53682/callback';
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const ISSUER = 'https%3A%2F%2Fcpmesh.test';

/** `#/authorize` as the server's `/oauth/authorize` redirects to it. */
function authorizeHash(overrides: Record<string, string> = {}): string {
  const params = new URLSearchParams({
    client_id: 'cpmesh-mcp',
    redirect_uri: REDIRECT,
    response_type: 'code',
    state: 'st4te+/=',
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
    scope: 'clipboard:read clipboard:write devices:manage',
    agent_name: 'Claude Code via cpmesh-mcp on laptop',
    ...overrides,
  });
  return `#/authorize?${params}`;
}

function sent(): Record<string, unknown>[] {
  return fetchMock()
    .mock.calls.filter(([url]) => url === '/api/oauth/authorize')
    .map(([, init]) => JSON.parse(init.body));
}

let leave: Mock;

beforeEach(() => {
  setTokens('access', 'refresh');
  userState.username = 'hayder';
  leave = vi.spyOn(window.location, 'replace').mockImplementation(() => {}) as unknown as Mock;
});

afterEach(() => {
  cleanup();
  setReauthHandler(null);
  clearTokens();
});

describe('#/authorize', () => {
  it('shows the agent as it reported itself and offers only the requested scopes, read and write on', () => {
    goTo(authorizeHash());
    render(Authorize);

    expect(pageText()).toContain('Approve cpmesh MCP');
    expect(pageText()).toContain('cpmesh MCP');
    expect(pageText()).toContain('Claude Code via cpmesh-mcp on laptop');
    expect(pageText()).toContain('Name reported by the agent');
    expect(pageText()).toContain('127.0.0.1:53682 on this computer');
    expect(pageText()).toContain('Signed in as @hayder');
    expect(checkboxes()).toEqual([
      ['Read the clipboard (clipboard:read)', true],
      ['Send to the clipboard (clipboard:write)', true],
      ['Manage devices (devices:manage)', false],
    ]);
    expect(pageText()).not.toContain('Delete clipboard entries');
  });

  it('starts with the opt-in scopes off when the agent asks for everything', () => {
    goTo(authorizeHash({ scope: '' }));
    render(Authorize);

    expect(checkboxes()).toEqual([
      ['Read the clipboard (clipboard:read)', true],
      ['Send to the clipboard (clipboard:write)', true],
      ['Delete clipboard entries (clipboard:delete)', false],
      ['Manage devices (devices:manage)', false],
    ]);
  });

  it('never answers on its own', async () => {
    goTo(authorizeHash());
    render(Authorize);

    await vi.waitFor(() => expect(button('Approve').disabled).toBe(false), { timeout: 2000 });
    expect(fetch).not.toHaveBeenCalled();
    expect(leave).not.toHaveBeenCalled();
  });

  it('approves the chosen scopes and sends the browser back to the agent', async () => {
    const redirect = `${REDIRECT}?code=c0de&state=st4te%2B%2F%3D&iss=${ISSUER}`;
    fetchMock().mockResolvedValue(jsonResponse(200, { redirect_to: redirect }));
    goTo(authorizeHash());
    render(Authorize);

    toggle('Send to the clipboard');
    toggle('Manage devices');
    await click('Approve');

    await vi.waitFor(() => expect(leave).toHaveBeenCalledWith(redirect));
    expect(sent()).toEqual([
      {
        client_id: 'cpmesh-mcp',
        redirect_uri: REDIRECT,
        state: 'st4te+/=',
        code_challenge: CHALLENGE,
        code_challenge_method: 'S256',
        scope: 'clipboard:read devices:manage',
        agent_name: 'Claude Code via cpmesh-mcp on laptop',
        decision: 'approve',
      },
    ]);
    await findText('Returning to your agent');
  });

  it('denies and sends the denial back to the agent', async () => {
    const redirect = `${REDIRECT}?error=access_denied&error_description=the%20user%20denied%20the%20request&state=st4te&iss=${ISSUER}`;
    fetchMock().mockResolvedValue(jsonResponse(200, { redirect_to: redirect }));
    goTo(authorizeHash());
    render(Authorize);

    await click('Deny');

    await vi.waitFor(() => expect(leave).toHaveBeenCalledWith(redirect));
    expect(sent()).toEqual([{ client_id: 'cpmesh-mcp', redirect_uri: REDIRECT, state: 'st4te+/=', decision: 'deny' }]);
    await findText('Request denied');
  });

  it('needs at least one scope to approve', async () => {
    goTo(authorizeHash());
    render(Authorize);

    toggle('Read the clipboard');
    toggle('Send to the clipboard');

    expect(pageText()).toContain('Turn on at least one permission to approve.');
    await new Promise((resolve) => setTimeout(resolve, 700));
    expect(button('Approve').disabled).toBe(true);
    expect(button('Deny').disabled).toBe(false);
  });

  it.each(['reauth_required', 'mfa_required'])('confirms it is the user on %s, then retries', async (code) => {
    const handler = vi.fn(async () => true);
    setReauthHandler(handler);
    const redirect = `${REDIRECT}?code=c0de&state=st4te&iss=${ISSUER}`;
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(403, { error: "Confirm it's you to continue.", code }))
      .mockResolvedValueOnce(jsonResponse(200, { redirect_to: redirect }));
    goTo(authorizeHash());
    render(Authorize);

    await click('Approve');

    await vi.waitFor(() => expect(leave).toHaveBeenCalledWith(redirect));
    expect(handler).toHaveBeenCalledOnce();
    expect(sent()).toHaveLength(2);
    expect(sent()[1]).toEqual(sent()[0]);
  });

  it('stays on the page when the user closes the confirmation', async () => {
    setReauthHandler(async () => false);
    fetchMock().mockResolvedValue(jsonResponse(403, { error: "Confirm it's you to continue.", code: 'reauth_required' }));
    goTo(authorizeHash());
    render(Authorize);

    await click('Approve');

    await findText("Confirm it's you to answer the agent.");
    expect(leave).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(button('Approve').disabled).toBe(false));
  });

  it('explains requests the server refuses', async () => {
    fetchMock().mockResolvedValue(jsonResponse(400, { error: 'state must be at most 512 printable ASCII characters', code: 'invalid_request' }));
    goTo(authorizeHash());
    render(Authorize);

    await click('Approve');

    await findText("This request can't be used (state must be at most 512 printable ASCII characters).");
    expect(leave).not.toHaveBeenCalled();
  });

  it('refuses a link that does not return to an agent on this computer', () => {
    goTo(authorizeHash({ redirect_uri: 'https://evil.example/callback' }));
    render(Authorize);

    expect(pageText()).toContain("This link can't be used");
    expect(pageText()).toContain("It doesn't return to an agent on this computer.");
    expect(document.querySelectorAll('input[type="checkbox"]')).toHaveLength(0);
    expect(() => button('Approve')).toThrow();
  });

  it('titles the tab while it is open, and gives the title back to the dashboard', () => {
    document.title = 'cpmesh';
    goTo(authorizeHash());
    render(Authorize);
    expect(document.title).toBe('Approve cpmesh MCP — cpmesh');

    cleanup();
    expect(document.title).toBe('cpmesh');
  });
});
