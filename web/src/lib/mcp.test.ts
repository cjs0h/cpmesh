import { describe, expect, it } from 'vitest';
import {
  agentSetups,
  cursorInstallLink,
  envVars,
  firstRunSteps,
  normalizeServerUrl,
  DEFAULT_SERVER_URL,
  prerequisites,
  securityNotes,
  shellQuote,
  toolGroups,
  troubleshooting,
} from './mcp';

const URL_ = 'https://relay.example.org';

function block(id: string, lang: string) {
  const setup = agentSetups(URL_).find((s) => s.id === id);
  const b = setup?.blocks.find((x) => x.lang === lang);
  if (!b) throw new Error(`missing ${lang} block for ${id}`);
  return b.code;
}

describe('normalizeServerUrl', () => {
  it('trims whitespace and trailing slashes', () => {
    expect(normalizeServerUrl('  https://a.b/// ')).toBe('https://a.b');
  });
  it('falls back to the hosted cpmesh servers when empty', () => {
    expect(DEFAULT_SERVER_URL).toBe('https://cpmesh.com');
    expect(normalizeServerUrl('')).toBe(DEFAULT_SERVER_URL);
    expect(normalizeServerUrl(undefined)).toBe(DEFAULT_SERVER_URL);
  });
});

describe('shellQuote', () => {
  it('leaves safe values alone', () => {
    expect(shellQuote('CPMESH_SERVER_URL=https://a.b:8443/x')).toBe('CPMESH_SERVER_URL=https://a.b:8443/x');
  });
  it('single-quotes and escapes unsafe values', () => {
    expect(shellQuote("a b'c")).toBe(`'a b'\\''c'`);
  });
});

describe('agentSetups', () => {
  const setups = agentSetups(URL_);

  it('covers the popular agents with unique ids', () => {
    const ids = setups.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ['claude-code', 'claude-desktop', 'cursor', 'vscode', 'copilot-cli', 'codex', 'gemini-cli', 'windsurf', 'cline', 'zed', 'opencode', 'other']) {
      expect(ids).toContain(id);
    }
  });

  it('produces valid JSON that launches cpmesh-mcp with the server URL', () => {
    for (const s of setups) {
      for (const b of s.blocks.filter((x) => x.lang === 'json')) {
        const parsed = JSON.parse(b.code);
        const text = JSON.stringify(parsed);
        expect(text, s.id).toContain('cpmesh-mcp');
        expect(text, s.id).toContain(URL_);
      }
    }
  });

  it('uses each client’s config shape', () => {
    expect(JSON.parse(block('claude-desktop', 'json')).mcpServers.cpmesh).toEqual({
      command: 'npx',
      args: ['-y', 'cpmesh-mcp'],
      env: { CPMESH_SERVER_URL: URL_ },
    });
    expect(JSON.parse(block('cursor', 'json')).mcpServers.cpmesh.type).toBe('stdio');
    expect(JSON.parse(block('copilot-cli', 'json')).mcpServers.cpmesh).toMatchObject({ type: 'local', tools: ['*'] });
    expect(JSON.parse(block('zed', 'json')).context_servers.cpmesh.command).toBe('npx');
    expect(JSON.parse(block('opencode', 'json')).mcp.cpmesh).toMatchObject({
      type: 'local',
      command: ['npx', '-y', 'cpmesh-mcp'],
      environment: { CPMESH_SERVER_URL: URL_ },
    });
  });

  it('builds CLI commands with the server command after "--"', () => {
    expect(block('claude-code', 'bash')).toBe(`claude mcp add cpmesh --scope user --env CPMESH_SERVER_URL=${URL_} -- npx -y cpmesh-mcp`);
    expect(block('copilot-cli', 'bash')).toBe(`copilot mcp add cpmesh --env CPMESH_SERVER_URL=${URL_} -- npx -y cpmesh-mcp`);
    expect(block('codex', 'bash')).toBe(`codex mcp add cpmesh --env CPMESH_SERVER_URL=${URL_} -- npx -y cpmesh-mcp`);
    expect(block('gemini-cli', 'bash')).toBe(`gemini mcp add --scope user -e CPMESH_SERVER_URL=${URL_} cpmesh npx -- -y cpmesh-mcp`);
  });

  it('emits a VS Code --add-mcp payload that round-trips', () => {
    const cmd = block('vscode', 'bash');
    const payload = cmd.slice(cmd.indexOf("'") + 1, cmd.lastIndexOf("'"));
    expect(JSON.parse(payload)).toEqual({ name: 'cpmesh', command: 'npx', args: ['-y', 'cpmesh-mcp'], env: { CPMESH_SERVER_URL: URL_ } });
  });

  it('writes a Codex TOML table', () => {
    const toml = block('codex', 'toml');
    expect(toml).toContain('[mcp_servers.cpmesh]');
    expect(toml).toContain('args = ["-y", "cpmesh-mcp"]');
    expect(toml).toContain(`CPMESH_SERVER_URL = "${URL_}"`);
  });
});

describe('cursorInstallLink', () => {
  it('encodes the server entry as base64 JSON', () => {
    const link = new URL(cursorInstallLink(URL_));
    expect(link.protocol).toBe('cursor:');
    expect(link.searchParams.get('name')).toBe('cpmesh');
    const config = JSON.parse(atob(link.searchParams.get('config')!));
    expect(config).toEqual({ command: 'npx', args: ['-y', 'cpmesh-mcp'], env: { CPMESH_SERVER_URL: URL_ } });
  });
});

describe('toolGroups', () => {
  it('documents all thirteen MCP tools', () => {
    const names = toolGroups.flatMap((g) => g.tools.map((t) => t.name));
    expect(names).toHaveLength(13);
    expect(new Set(names).size).toBe(13);
  });
});

describe('sign-in copy', () => {
  /** Every piece of guide copy and every snippet, for one server URL. */
  function allCopy(url: string): string {
    return JSON.stringify([agentSetups(url), toolGroups, envVars, prerequisites, firstRunSteps(url), securityNotes, troubleshooting(url)]);
  }

  it('never asks for a password or a one-time code in the agent', () => {
    for (const url of [URL_, DEFAULT_SERVER_URL]) {
      const copy = allCopy(url);
      for (const banned of [/password/i, /\btotp\b/i, /authenticator/i, /6-digit/i, /CPMESH_USERNAME/, /CPMESH_PASSWORD/]) {
        expect(copy, String(banned)).not.toMatch(banned);
      }
    }
  });

  it('documents only the server URL and home directory variables', () => {
    expect(envVars.map((v) => v.name)).toEqual(['CPMESH_SERVER_URL', 'CPMESH_HOME']);
  });

  it('walks through browser approval, or a code at /activate, then pairing with the 8-digit code', () => {
    const steps = firstRunSteps(`${URL_}/`);
    expect(steps.map((s) => s.title)).toEqual([
      'Ask your agent to connect',
      'Approve it in your browser',
      'Pair it on a trusted device',
      'Start using it',
    ]);
    expect(steps[0].desc).toContain('opens the cpmesh approval page in a browser on the same computer');
    expect(steps[0].desc).toContain(`a code to enter at ${URL_}/activate`);
    expect(steps[1].desc).toContain('then approve');
    expect(steps[2].desc).toContain('8-digit pairing code');
    expect(steps[2].desc).toContain('cpmesh_confirm_pairing');
    expect(steps[3].desc).toContain('cpmesh_wait_for_approval');
  });

  it('helps when no browser opens, and with agents that were signed out or can only send', () => {
    const help = troubleshooting(URL_);
    const answer = (q: string) => help.find((t) => t.q === q)?.a ?? '';
    expect(answer('No browser opened')).toContain(`${URL_}/activate`);
    expect(answer('The agent was signed out')).toContain('no code to compare');
    expect(answer("The agent can't read my clipboard")).toContain('turn on reading the clipboard (clipboard:read) on the cpmesh approval page');
    expect(help.some((t) => /two-factor/i.test(t.q))).toBe(false);
  });

  it('describes browser sign-in and revocation in the tool reference', () => {
    const tools = Object.fromEntries(toolGroups.flatMap((g) => g.tools.map((t) => [t.name, t.desc])));
    expect(tools.cpmesh_login).toContain('cpmesh approval page in a browser on this computer');
    expect(tools.cpmesh_login).toContain('/activate');
    expect(tools.cpmesh_logout).toContain('Revokes the agent, which removes its device');
  });
});
