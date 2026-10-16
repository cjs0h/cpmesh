// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://cpmesh.test/"}
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { flushSync } from 'svelte';
import Activate from './Activate.svelte';
import { setReauthHandler } from '../lib/api';
import { clearTokens, setTokens } from '../lib/auth';
import { userState } from '../lib/stores/user.svelte';
import { jsonResponse } from '../test/setup';
import { button, checkboxes, cleanup, click, findText, goTo, pageText, render, toggle, type } from '../test/dom';

const fetchMock = () => fetch as unknown as Mock;

/** `GET /api/oauth/device` for a pending request. */
function deviceRequest(overrides: Record<string, unknown> = {}) {
  const now = Date.now();
  return {
    user_code: 'BCDF-GHJK',
    client_id: 'cpmesh-mcp',
    client_name: 'cpmesh MCP',
    agent_name: 'Codex via cpmesh-mcp on build-box',
    scopes: ['clipboard:read', 'clipboard:write'],
    requester_ip: '203.0.113.10',
    user_agent: 'cpmesh-mcp/0.3.0 (linux; node 22)',
    created_at: new Date(now - 60_000).toISOString(),
    expires_at: new Date(now + 9 * 60_000 + 30_000).toISOString(),
    ...overrides,
  };
}

function codeField(): HTMLInputElement {
  const input = document.querySelector<HTMLInputElement>('input[type="text"]');
  if (!input) throw new Error('no code field');
  return input;
}

function calls(path: string): Record<string, unknown>[] {
  return fetchMock()
    .mock.calls.filter(([url]) => url === path)
    .map(([, init]) => JSON.parse(init.body));
}

function lookups(): string[] {
  return fetchMock()
    .mock.calls.map(([url]) => String(url))
    .filter((url) => url.startsWith('/api/oauth/device?'));
}

/** Answers the lookup with `lookup`, and the decisions with `decision`. */
function serve(lookup: Response, decision: Response = jsonResponse(500, { error: 'unexpected' })) {
  fetchMock().mockImplementation(async (url: string) => (url.startsWith('/api/oauth/device?') ? lookup : decision));
}

/** Opens the page from the agent's link and looks the code up. */
async function review(request = deviceRequest()) {
  serve(jsonResponse(200, request));
  goTo('#/activate?user_code=BCDF-GHJK');
  render(Activate);
  await click('Continue');
  await findText('Check the request before you answer it.');
}

beforeEach(() => {
  setTokens('access', 'refresh');
  userState.username = 'hayder';
});

afterEach(() => {
  cleanup();
  setReauthHandler(null);
  clearTokens();
});

describe('#/activate: the user code', () => {
  it("fills in the code from the agent's link, normalized", () => {
    goTo('#/activate?user_code=bcdf%20ghjk');
    render(Activate);

    expect(codeField().value).toBe('BCDF-GHJK');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('starts empty without a code', () => {
    goTo('#/activate');
    render(Activate);

    expect(codeField().value).toBe('');
    expect(pageText()).toContain('Enter the code your agent shows.');
  });

  it('normalizes a typed code before looking it up', async () => {
    serve(jsonResponse(200, deviceRequest()));
    goTo('#/activate');
    render(Activate);

    type(codeField(), ' bcdf ghjk ');
    await click('Continue');

    await findText('Codex via cpmesh-mcp on build-box');
    expect(lookups()).toEqual(['/api/oauth/device?user_code=BCDF-GHJK']);
  });

  it('refuses what cannot be a code without asking the server', async () => {
    goTo('#/activate');
    render(Activate);

    for (const typed of ['ABCD-EFGH', 'BCDF-GHJ', 'BCDF-GHJ1']) {
      type(codeField(), typed);
      await click('Continue');
      expect(pageText()).toContain('Enter the 8 letters your agent shows, like BCDF-GHJK.');
    }
    expect(fetch).not.toHaveBeenCalled();
  });

  it('explains unknown, expired or used codes', async () => {
    serve(jsonResponse(404, { error: 'This code is wrong or expired.', code: 'not_found' }));
    goTo('#/activate?user_code=BCDF-GHJK');
    render(Activate);

    await click('Continue');

    await findText('This code is wrong or has expired, or it was already used.');
    expect(codeField()).toBeTruthy();
  });

  it('asks to wait when rate limited', async () => {
    serve(jsonResponse(429, { error: 'too many requests, please try again later', code: 'rate_limited' }));
    goTo('#/activate?user_code=BCDF-GHJK');
    render(Activate);

    await click('Continue');

    await findText('Too many attempts. Wait a minute, then try again.');
  });
});

describe('#/activate: the request', () => {
  it('shows where the request came from, with the warning, and offers only the requested scopes', async () => {
    await review(deviceRequest({ scopes: ['clipboard:write', 'clipboard:delete'] }));

    const text = pageText();
    expect(text).toContain('Approve cpmesh MCP');
    expect(text).toContain('cpmesh MCP');
    expect(text).toContain('Codex via cpmesh-mcp on build-box');
    expect(text).toContain('Name reported by the agent');
    expect(text).toContain('BCDF-GHJK');
    expect(text).toContain('203.0.113.10');
    expect(text).toContain('cpmesh-mcp/0.3.0 (linux; node 22)');
    expect(text).toContain('1m ago');
    expect(text).toContain('expires in 9 min');
    expect(text).toContain(
      'Only approve if you just started this from your AI agent. It still has to be paired on one of your devices before it can read your clipboard.',
    );
    expect(checkboxes()).toEqual([
      ['Send to the clipboard (clipboard:write)', true],
      ['Delete clipboard entries (clipboard:delete)', false],
    ]);
  });

  it('copes with an agent that reported neither a name nor a user agent', async () => {
    await review(deviceRequest({ agent_name: '', user_agent: null }));

    expect(pageText()).toContain("The agent didn't report a name.");
    expect(pageText()).toContain('Not reported');
  });

  it('approves the chosen scopes', async () => {
    await review();
    serve(jsonResponse(200, deviceRequest()), jsonResponse(200, { status: 'approved', scope: 'clipboard:read' }));

    toggle('Send to the clipboard');
    await click('Approve');

    await findText('Go back to your agent; it continues on its own');
    expect(calls('/api/oauth/device/approve')).toEqual([{ user_code: 'BCDF-GHJK', scope: 'clipboard:read' }]);
    expect(pageText()).toContain('Compare the 8-digit code');
  });

  it('denies', async () => {
    await review();
    serve(jsonResponse(200, deviceRequest()), jsonResponse(200, { status: 'denied' }));

    await click('Deny');

    await findText("The agent doesn't get access");
    expect(calls('/api/oauth/device/deny')).toEqual([{ user_code: 'BCDF-GHJK' }]);
  });

  it('ends clearly when the request expired or was already answered', async () => {
    await review();
    serve(jsonResponse(200, deviceRequest()), jsonResponse(404, { error: 'This code is wrong or expired.', code: 'not_found' }));

    await click('Approve');

    await findText('This request has ended');
    expect(pageText()).toContain('It expired or was already answered.');
    await click('Enter another code');
    expect(codeField().value).toBe('');
  });

  it('asks to wait when a decision is rate limited, and lets the user try again', async () => {
    await review();
    serve(jsonResponse(200, deviceRequest()), jsonResponse(429, { error: 'too many requests, please try again later', code: 'rate_limited' }));

    await click('Deny');

    await findText('Too many attempts. Wait a minute, then try again.');
    await vi.waitFor(() => expect(button('Deny').disabled).toBe(false));
  });

  it('confirms it is the user before deciding, then retries', async () => {
    const handler = vi.fn(async () => true);
    setReauthHandler(handler);
    await review();
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(403, { error: 'Finish two-factor authentication first.', code: 'mfa_required' }))
      .mockResolvedValueOnce(jsonResponse(200, { status: 'approved', scope: 'clipboard:read clipboard:write' }));

    await click('Approve');

    await findText('Go back to your agent; it continues on its own');
    expect(handler).toHaveBeenCalledOnce();
    expect(calls('/api/oauth/device/approve')).toHaveLength(2);
  });

  it('goes back to the code field for another code', async () => {
    await review();

    button('Enter a different code').click();
    flushSync();

    expect(codeField().value).toBe('');
    expect(pageText()).toContain('Enter the code your agent shows.');
  });
});
