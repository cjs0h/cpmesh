import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { setReauthHandler } from './api';
import { setTokens } from './auth';
import {
  agentNameFrom,
  approveDeviceRequest,
  decideAuthorization,
  defaultScopes,
  denyDeviceRequest,
  formatUserCode,
  isStepUpRequired,
  knownScopes,
  listAgentGrants,
  lookupDeviceRequest,
  loopbackListener,
  normalizeUserCode,
  parseAuthorizeRequest,
  parseScopes,
  revokeAgentGrant,
  scopeLabel,
  scopeString,
  SCOPES,
  type AuthorizeRequest,
} from './oauth';
import { jsonResponse } from '../test/setup';

const fetchMock = () => fetch as unknown as Mock;
const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
const REDIRECT = 'http://127.0.0.1:53682/callback';

/** The query `/oauth/authorize` sends to `#/authorize` (see the server's `handle_authorize`). */
function authorizeQuery(overrides: Record<string, string | null> = {}): string {
  const params: Record<string, string | null> = {
    client_id: 'cpmesh-mcp',
    redirect_uri: REDIRECT,
    response_type: 'code',
    state: 'af0ifjsldkj',
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
    scope: 'clipboard:read clipboard:write clipboard:delete devices:manage',
    agent_name: 'Claude Code via cpmesh-mcp on laptop',
    ...overrides,
  };
  return Object.entries(params)
    .filter((entry): entry is [string, string] => entry[1] !== null)
    .map(([name, value]) => `${name}=${encodeURIComponent(value)}`)
    .join('&');
}

function requestFrom(query = authorizeQuery()): AuthorizeRequest {
  const parsed = parseAuthorizeRequest(query);
  if (!parsed.request) throw new Error(parsed.error);
  return parsed.request;
}

function body(call: number): Record<string, unknown> {
  return JSON.parse(fetchMock().mock.calls[call][1].body);
}

describe('scopes', () => {
  it('reads scope strings in the server order, whatever the order and repeats', () => {
    expect(parseScopes('clipboard:write  clipboard:read clipboard:write')).toEqual(['clipboard:read', 'clipboard:write']);
    expect(parseScopes('devices:manage\tclipboard:delete')).toEqual(['clipboard:delete', 'devices:manage']);
    expect(parseScopes('')).toEqual([]);
    expect(parseScopes(null)).toEqual([]);
  });

  it('refuses scopes it does not know', () => {
    expect(parseScopes('clipboard:read admin')).toBeNull();
    expect(parseScopes('CLIPBOARD:READ')).toBeNull();
  });

  it('turns on read and write by default, only when requested', () => {
    expect(defaultScopes([...SCOPES])).toEqual(['clipboard:read', 'clipboard:write']);
    expect(defaultScopes(['clipboard:write', 'devices:manage'])).toEqual(['clipboard:write']);
    expect(defaultScopes(['clipboard:delete', 'devices:manage'])).toEqual([]);
  });

  it('writes scope strings in the server order', () => {
    expect(scopeString(['devices:manage', 'clipboard:read'])).toBe('clipboard:read devices:manage');
    expect(knownScopes(['devices:manage', 'clipboard:everything', 'clipboard:write'])).toEqual(['clipboard:write', 'devices:manage']);
  });

  it('names each scope the way the agent does, with its ID', () => {
    expect(SCOPES.map(scopeLabel)).toEqual([
      'Read the clipboard (clipboard:read)',
      'Send to the clipboard (clipboard:write)',
      'Delete clipboard entries (clipboard:delete)',
      'Manage devices (devices:manage)',
    ]);
  });
});

describe('loopbackListener', () => {
  it('accepts the loopback redirect URIs the server registers', () => {
    expect(loopbackListener('http://127.0.0.1:53682/callback')).toBe('127.0.0.1:53682');
    expect(loopbackListener('http://[::1]:1/callback')).toBe('[::1]:1');
    expect(loopbackListener('http://127.0.0.1:65535/callback')).toBe('127.0.0.1:65535');
  });

  it('refuses anything else', () => {
    for (const uri of [
      'http://localhost:53682/callback',
      'https://127.0.0.1:53682/callback',
      'http://127.0.0.1:53682/callback/',
      'http://127.0.0.1:53682/other',
      'http://127.0.0.1/callback',
      'http://127.0.0.1:0/callback',
      'http://127.0.0.1:065/callback',
      'http://127.0.0.1:65536/callback',
      'http://user@127.0.0.1:53682/callback',
      'http://127.0.0.1:53682/callback?x=1',
      'http://127.0.0.1:53682/callback#x',
      'http://127.0.0.1:53682/%63allback',
      'http://evil.example/callback',
    ]) {
      expect(loopbackListener(uri), uri).toBeNull();
    }
  });
});

describe('agentNameFrom', () => {
  it('trims and allows up to 100 characters', () => {
    expect(agentNameFrom('  Codex via cpmesh-mcp on build-box ')).toBe('Codex via cpmesh-mcp on build-box');
    expect(agentNameFrom(null)).toBe('');
    expect(agentNameFrom('é'.repeat(100))).toHaveLength(100);
  });

  it('refuses long names and hidden characters', () => {
    for (const name of ['é'.repeat(101), 'line\nbreak', 'nul\0', 'evil\u202Etxt.exe', 'isolate\u2066x', 'mark\u200F']) {
      expect(agentNameFrom(name), JSON.stringify(name)).toBeNull();
    }
  });
});

describe('parseAuthorizeRequest', () => {
  it('reads the request the server forwards', () => {
    expect(parseAuthorizeRequest(authorizeQuery({ scope: 'clipboard:write clipboard:read' }))).toEqual({
      request: {
        clientId: 'cpmesh-mcp',
        clientName: 'cpmesh MCP',
        redirectUri: REDIRECT,
        listener: '127.0.0.1:53682',
        state: 'af0ifjsldkj',
        codeChallenge: CHALLENGE,
        scopes: ['clipboard:read', 'clipboard:write'],
        agentName: 'Claude Code via cpmesh-mcp on laptop',
      },
    });
  });

  it('treats a missing or empty scope as every scope, for the user to choose from', () => {
    expect(requestFrom(authorizeQuery({ scope: null })).scopes).toEqual([...SCOPES]);
    expect(requestFrom(authorizeQuery({ scope: '' })).scopes).toEqual([...SCOPES]);
  });

  it('keeps state exactly, and allows a missing agent name', () => {
    const request = requestFrom(authorizeQuery({ state: 'a+b c/=?&%', agent_name: null }));
    expect(request.state).toBe('a+b c/=?&%');
    expect(request.agentName).toBe('');
  });

  it('refuses links the server would refuse', () => {
    const cases: Record<string, string | null>[] = [
      { client_id: null },
      { client_id: 'other-app' },
      { client_id: 'constructor' },
      { redirect_uri: null },
      { redirect_uri: 'https://evil.example/callback' },
      { redirect_uri: 'http://localhost:53682/callback' },
      { response_type: 'token' },
      { response_type: null },
      { state: null },
      { state: 'x'.repeat(513) },
      { state: 'tab\there' },
      { code_challenge: null },
      { code_challenge: 'short' },
      { code_challenge_method: 'plain' },
      { code_challenge_method: null },
      { scope: 'clipboard:read openid' },
      { agent_name: 'a'.repeat(101) },
      { agent_name: 'bidi\u202Eexe' },
    ];
    for (const overrides of cases) {
      const parsed = parseAuthorizeRequest(authorizeQuery(overrides));
      expect(parsed.request, JSON.stringify(overrides)).toBeUndefined();
      expect(parsed.error, JSON.stringify(overrides)).toBeTruthy();
    }
  });

  it('refuses repeated parameters and empty links', () => {
    expect(parseAuthorizeRequest(`${authorizeQuery()}&state=again`).error).toBe('state is repeated.');
    expect(parseAuthorizeRequest('').error).toBeTruthy();
    expect(parseAuthorizeRequest(undefined).error).toBeTruthy();
  });
});

describe('user codes', () => {
  it('normalizes codes as typed, like the server', () => {
    for (const typed of ['BCDF-GHJK', 'bcdf-ghjk', 'bcdfghjk', ' BcDf GhJk ', 'B-C-D-F-G-H-J-K', 'bcdf\tghjk']) {
      expect(normalizeUserCode(typed), typed).toBe('BCDFGHJK');
    }
    expect(formatUserCode('BCDFGHJK')).toBe('BCDF-GHJK');
  });

  it('refuses anything that is not eight letters of the alphabet', () => {
    for (const typed of ['ABCD-EFGH', 'BCDF-GHJ', 'BCDF-GHJKL', 'BCDF-GHJ1', 'BCDF_GHJK', 'BCDF-GHJÉ', '', `${'-'.repeat(60)}BCDFGHJK`]) {
      expect(normalizeUserCode(typed), typed).toBeNull();
    }
  });
});

describe('consent requests', () => {
  beforeEach(() => {
    fetchMock().mockReset();
    setReauthHandler(null);
    setTokens('access', 'refresh');
  });

  it('approves an authorization request with the chosen scopes and returns the redirect', async () => {
    const redirect = `${REDIRECT}?code=c0de&state=af0ifjsldkj&iss=https%3A%2F%2Fcpmesh.test`;
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { redirect_to: redirect }));

    await expect(decideAuthorization(requestFrom(), 'approve', ['clipboard:write', 'clipboard:read'])).resolves.toBe(redirect);
    const [url, init] = fetchMock().mock.calls[0];
    expect(url).toBe('/api/oauth/authorize');
    expect(init.method).toBe('POST');
    expect(body(0)).toEqual({
      client_id: 'cpmesh-mcp',
      redirect_uri: REDIRECT,
      state: 'af0ifjsldkj',
      code_challenge: CHALLENGE,
      code_challenge_method: 'S256',
      scope: 'clipboard:read clipboard:write',
      agent_name: 'Claude Code via cpmesh-mcp on laptop',
      decision: 'approve',
    });
  });

  it('denies with only what the server checks for a denial', async () => {
    const redirect = `${REDIRECT}?error=access_denied&error_description=x&state=af0ifjsldkj&iss=https%3A%2F%2Fcpmesh.test`;
    fetchMock().mockResolvedValueOnce(jsonResponse(200, { redirect_to: redirect }));

    await expect(decideAuthorization(requestFrom(), 'deny')).resolves.toBe(redirect);
    expect(body(0)).toEqual({ client_id: 'cpmesh-mcp', redirect_uri: REDIRECT, state: 'af0ifjsldkj', decision: 'deny' });
  });

  it('never leaves for anything but the listener the user was shown', async () => {
    for (const redirect of ['https://evil.example/?code=x', `${REDIRECT}.evil.example?code=x`, REDIRECT, null]) {
      fetchMock().mockResolvedValueOnce(jsonResponse(200, { redirect_to: redirect }));
      await expect(decideAuthorization(requestFrom(), 'approve', ['clipboard:read'])).rejects.toThrow("doesn't lead back to your agent");
    }
  });

  it('confirms it is the user on reauth_required, then retries', async () => {
    const handler = vi.fn(async () => true);
    setReauthHandler(handler);
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(403, { error: "Confirm it's you to continue.", code: 'reauth_required' }))
      .mockResolvedValueOnce(jsonResponse(200, { redirect_to: `${REDIRECT}?code=c&state=s&iss=i` }));

    await expect(decideAuthorization(requestFrom(), 'approve', ['clipboard:read'])).resolves.toBe(`${REDIRECT}?code=c&state=s&iss=i`);
    expect(handler).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(body(1)).toEqual(body(0));
  });

  it('confirms the second factor on mfa_required, then retries once', async () => {
    const handler = vi.fn(async () => true);
    setReauthHandler(handler);
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(403, { error: 'Finish two-factor authentication first.', code: 'mfa_required' }))
      .mockResolvedValueOnce(jsonResponse(200, { status: 'denied' }));

    await expect(denyDeviceRequest('BCDF-GHJK')).resolves.toEqual({ status: 'denied' });
    expect(handler).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('gives up when the user closes the confirmation', async () => {
    setReauthHandler(async () => false);
    fetchMock().mockResolvedValue(jsonResponse(403, { error: 'Finish two-factor authentication first.', code: 'mfa_required' }));

    const failure = await approveDeviceRequest('BCDF-GHJK', ['clipboard:read']).catch((err) => err);
    expect(isStepUpRequired(failure)).toBe(true);
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('looks up, approves and denies device requests by user code', async () => {
    fetchMock()
      .mockResolvedValueOnce(jsonResponse(200, { user_code: 'BCDF-GHJK' }))
      .mockResolvedValueOnce(jsonResponse(200, { status: 'approved', scope: 'clipboard:write' }))
      .mockResolvedValueOnce(jsonResponse(200, { status: 'denied' }));

    await lookupDeviceRequest('BCDF-GHJK');
    await approveDeviceRequest('BCDF-GHJK', ['clipboard:write']);
    await denyDeviceRequest('BCDF-GHJK');

    const calls = fetchMock().mock.calls;
    expect(calls[0][0]).toBe('/api/oauth/device?user_code=BCDF-GHJK');
    expect(calls[1][0]).toBe('/api/oauth/device/approve');
    expect(body(1)).toEqual({ user_code: 'BCDF-GHJK', scope: 'clipboard:write' });
    expect(calls[2][0]).toBe('/api/oauth/device/deny');
    expect(body(2)).toEqual({ user_code: 'BCDF-GHJK' });
  });

  it('lists and revokes connected agents', async () => {
    fetchMock().mockResolvedValueOnce(jsonResponse(200, [])).mockResolvedValueOnce(jsonResponse(204, null));

    await expect(listAgentGrants()).resolves.toEqual([]);
    await expect(revokeAgentGrant('0b8f6a2e-0000-4000-8000-000000000001')).resolves.toBeUndefined();
    expect(fetchMock().mock.calls[0][0]).toBe('/api/oauth/grants');
    expect(fetchMock().mock.calls[1][0]).toBe('/api/oauth/grants/0b8f6a2e-0000-4000-8000-000000000001');
    expect(fetchMock().mock.calls[1][1].method).toBe('DELETE');
  });
});
