// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://cpmesh.test/"}
import { afterEach, expect, it, vi } from 'vitest';
import { mount, unmount, tick } from 'svelte';
import App from './App.svelte';
import { setTokens, clearTokens, getAccessToken } from './lib/auth';
import { userState } from './lib/stores/user.svelte';
import { clipboardState } from './lib/stores/clipboard.svelte';
import { devicesState } from './lib/stores/devices.svelte';
import { adminState } from './lib/stores/admin.svelte';
import { connectWS, disconnectWS } from './lib/ws';
import { FakeWebSocket, jsonResponse } from './test/setup';

let app: ReturnType<typeof mount> | undefined;
afterEach(async () => {
  if (app) await unmount(app);
  app = undefined;
  disconnectWS();
  clearTokens();
  document.body.innerHTML = '';
});

it('mounts the public login route and clears every account snapshot when refresh expires', async () => {
  history.replaceState(null, '', '#/clipboard');
  setTokens('expired-access', 'unusable-refresh');
  userState.id = 'old-user';
  userState.loaded = true;
  clipboardState.entries = [{
    id: 'old-entry', device_id: 'old-device', device_name: 'Old laptop',
    content_type: 'text', encrypted_size: 52, created_at: '2026-01-01T00:00:00Z',
  }];
  devicesState.list = [{ id: 'old-device', name: 'Old laptop', online: true, last_seen: '', status: 'approved' }];
  adminState.usersQuery = 'private account search';
  vi.mocked(fetch).mockImplementation(async (input) => {
    const path = String(input);
    if (path === '/api/ws/ticket') return jsonResponse(200, { ticket: 'existing-socket' });
    if (path === '/api/auth/refresh' || path === '/api/me' || path.startsWith('/api/clipboard')) {
      return jsonResponse(401, { error: 'expired' });
    }
    if (path === '/api/auth/social/status') return jsonResponse(200, { enabled: false });
    return jsonResponse(200, {});
  });
  await connectWS();
  const socket = FakeWebSocket.latest();
  socket.open();
  const target = document.createElement('main');
  document.body.append(target);
  app = mount(App, { target });
  await vi.waitFor(async () => {
    await tick();
    expect(window.location.hash).toBe('#/login');
    expect(document.querySelector('input[type="password"]')).not.toBeNull();
  });
  expect(getAccessToken()).toBeNull();
  expect(userState.id).toBe('');
  expect(clipboardState.entries).toEqual([]);
  expect(devicesState.list).toEqual([]);
  expect(adminState.usersQuery).toBe('');
  expect(socket.close).toHaveBeenCalledOnce();
  expect(document.body.textContent).not.toContain('Page not found');
});

const AUTHORIZE =
  '#/authorize?client_id=cpmesh-mcp&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2Fcallback&response_type=code&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=clipboard%3Aread%20clipboard%3Awrite&agent_name=Claude%20Code';

function mountAt(hash: string) {
  history.replaceState(null, '', hash);
  window.dispatchEvent(new HashChangeEvent('hashchange'));
  const target = document.createElement('main');
  document.body.append(target);
  app = mount(App, { target });
}

it("asks signed-out users to sign in on an AI agent's consent page, keeping the request", async () => {
  vi.mocked(fetch).mockImplementation(async (input) =>
    String(input) === '/api/auth/social/status' ? jsonResponse(200, { enabled: false }) : jsonResponse(200, {}),
  );
  mountAt(AUTHORIZE);

  await vi.waitFor(async () => {
    await tick();
    expect(document.querySelector('input[type="password"]')).not.toBeNull();
  });
  expect(document.body.textContent).toContain('Sign in to approve an AI agent');
  expect(window.location.hash).toBe(AUTHORIZE);
});

it('shows the consent page on its own to signed-in users', async () => {
  setTokens('access', 'refresh');
  vi.mocked(fetch).mockImplementation(async (input) => {
    const path = String(input);
    if (path === '/api/me') {
      return jsonResponse(200, {
        id: 'user-1', username: 'hayder', email: 'h@example.org', full_name: 'Hayder', email_verified: true,
        auth_provider: 'local', is_admin: false, mfa: { enabled: true, required: true, session_verified: true },
      });
    }
    if (path === '/api/ws/ticket') return jsonResponse(200, { ticket: 'ticket' });
    return jsonResponse(200, {});
  });
  mountAt(AUTHORIZE);

  await vi.waitFor(async () => {
    await tick();
    expect(document.body.textContent).toContain('Approve cpmesh MCP');
  });
  const text = document.body.textContent ?? '';
  expect(text).toContain('Claude Code');
  expect(text).toContain('@hayder');
  // Without the dashboard's navigation around it
  expect(text).not.toContain('Overview');
  expect(window.location.hash).toBe(AUTHORIZE);
});
