// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://cpmesh.test/"}
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import ConnectedAgents from './ConnectedAgents.svelte';
import { clearTokens, setTokens } from '../../lib/auth';
import type { AgentGrant } from '../../lib/oauth';
import { toastState } from '../../lib/stores/toast.svelte';
import { jsonResponse } from '../../test/setup';
import { button, cleanup, click, findText, pageText, render } from '../../test/dom';

const fetchMock = () => fetch as unknown as Mock;
const HOUR = 3_600_000;

function grant(overrides: Partial<AgentGrant>): AgentGrant {
  return {
    id: 'grant-1',
    client_id: 'cpmesh-mcp',
    client_name: 'cpmesh MCP',
    agent_name: 'Claude Code via cpmesh-mcp on laptop',
    scopes: ['clipboard:read', 'clipboard:write'],
    device: { id: 'device-1', name: 'Claude Code (laptop)', status: 'approved' },
    created_at: new Date(Date.now() - 50 * HOUR).toISOString(),
    last_used_at: new Date(Date.now() - 2 * HOUR).toISOString(),
    status: 'active',
    ...overrides,
  };
}

const grants: AgentGrant[] = [
  grant({}),
  grant({
    id: 'grant-2',
    agent_name: 'Codex via cpmesh-mcp on build-box',
    scopes: ['clipboard:write'],
    device: { id: 'device-2', name: 'Codex (build-box)', status: 'pending' },
    status: 'signed_out',
  }),
  grant({ id: 'grant-3', agent_name: '', scopes: ['clipboard:delete', 'devices:manage'], device: null, last_used_at: null }),
  grant({ id: 'grant-4', agent_name: 'Gemini via cpmesh-mcp on old-box', device: null, status: 'signed_out' }),
];

/** The list item of the agent named `name`. */
function item(name: string): HTMLLIElement {
  const found = [...document.querySelectorAll<HTMLLIElement>('ul.divide-y > li')].find((li) => li.textContent?.includes(name));
  if (!found) throw new Error(`no agent "${name}"`);
  return found;
}

function text(el: Element): string {
  return (el.textContent ?? '').replace(/\s+/g, ' ');
}

beforeEach(() => {
  setTokens('access', 'refresh');
  toastState.items = [];
});

afterEach(() => {
  cleanup();
  clearTokens();
});

describe('Connected agents', () => {
  it('lists each agent with its scopes, device and status', async () => {
    fetchMock().mockResolvedValue(jsonResponse(200, grants));
    render(ConnectedAgents);

    await findText('Claude Code via cpmesh-mcp on laptop');
    expect(fetchMock().mock.calls[0][0]).toBe('/api/oauth/grants');

    const claude = text(item('Claude Code via cpmesh-mcp on laptop'));
    expect(claude).toContain('Active');
    expect(claude).toContain('cpmesh MCP · name reported by the agent');
    expect(claude).toContain('Read');
    expect(claude).toContain('Send');
    expect(claude).toContain('Claude Code (laptop) Paired');
    expect(claude).toContain('Connected 2d ago');
    expect(claude).toContain('Last used 2h ago');

    const codex = text(item('Codex via cpmesh-mcp on build-box'));
    expect(codex).toContain('Signed out');
    expect(codex).toContain('Codex (build-box) Waiting for pairing');
    expect(codex).toContain('Its sign-in ended');
    expect(codex).toContain('Revoke it to remove the device.');
    expect(codex).not.toContain('Read');

    const unnamed = text(item('Unnamed agent'));
    expect(unnamed).toContain('Not registered yet');
    expect(unnamed).toContain('Delete entries');
    expect(unnamed).toContain('Manage devices');
    expect(unnamed).toContain('Last used Never');

    // Signed out before it registered a device: nothing stays paired
    const gemini = text(item('Gemini via cpmesh-mcp on old-box'));
    expect(gemini).toContain('Signed out');
    expect(gemini).toContain('It can sign in again from the agent. Revoke it to remove it from this list.');
    expect(gemini).not.toContain('stays paired');
  });

  it('shows how to connect one when there is none', async () => {
    fetchMock().mockResolvedValue(jsonResponse(200, []));
    render(ConnectedAgents);

    await findText('No agents connected yet');
  });

  it('revokes an agent after explaining that its device goes and the key rotates', async () => {
    fetchMock().mockImplementation(async (url: string, init?: RequestInit) =>
      init?.method === 'DELETE' ? jsonResponse(204, null) : jsonResponse(200, grants),
    );
    render(ConnectedAgents);
    await findText('Claude Code via cpmesh-mcp on laptop');

    item('Claude Code via cpmesh-mcp on laptop').querySelector('button')!.click();
    await findText('Revoke this agent?');
    const dialog = text(document.querySelector('dialog')!);
    expect(dialog).toContain('Claude Code via cpmesh-mcp on laptop is signed out');
    expect(dialog).toContain('Its device, Claude Code (laptop), is removed from your account');
    expect(dialog).toContain('your other devices rotate the encryption key');
    expect(fetchMock().mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false);

    await click('Revoke access');

    await vi.waitFor(() => expect(document.body.textContent).not.toContain('Claude Code via cpmesh-mcp on laptop'));
    const deletes = fetchMock().mock.calls.filter(([, init]) => init?.method === 'DELETE');
    expect(deletes.map(([url]) => url)).toEqual(['/api/oauth/grants/grant-1']);
    expect(pageText()).toContain('Codex via cpmesh-mcp on build-box');
    expect(toastState.items.map((t) => t.title)).toContain('Agent revoked');
  });

  it('says so when an agent without a device is revoked', async () => {
    fetchMock().mockResolvedValue(jsonResponse(200, grants));
    render(ConnectedAgents);
    await findText('Unnamed agent');

    item('Unnamed agent').querySelector('button')!.click();

    await findText("It hasn't registered a device yet");
  });

  it('keeps an agent the server could not revoke', async () => {
    fetchMock().mockImplementation(async (url: string, init?: RequestInit) =>
      init?.method === 'DELETE' ? jsonResponse(503, { error: 'temporarily unavailable, please retry' }) : jsonResponse(200, grants),
    );
    render(ConnectedAgents);
    await findText('Claude Code via cpmesh-mcp on laptop');

    item('Claude Code via cpmesh-mcp on laptop').querySelector('button')!.click();
    await click('Revoke access');

    await vi.waitFor(() => expect(toastState.items.map((t) => t.title)).toContain("Couldn't revoke the agent"));
    expect(button('Revoke access').disabled).toBe(false);
    expect(pageText()).toContain('Claude Code via cpmesh-mcp on laptop');
  });
});
