/**
 * Content and config generators for the cpmesh MCP server guide.
 *
 * Every snippet is generated from the user's server URL so the guide can show
 * copy-paste-ready commands. Client config formats were checked against each
 * agent's official MCP documentation (linked from `docsUrl`).
 */

export const MCP_PACKAGE = 'cpmesh-mcp';
export const MCP_SERVER_NAME = 'cpmesh';
/** The hosted cpmesh relay. Self-hosters swap in their own URL. */
export const DEFAULT_SERVER_URL = 'https://cpmesh.com';
export const MCP_SOURCE_URL = 'https://github.com/cjs0h/cpmesh/tree/master/mcp/cpmesh-mcp';

export type SnippetLang = 'bash' | 'json' | 'toml';

export interface SetupBlock {
  /** Short heading, e.g. "Run in your terminal". */
  title: string;
  lang: SnippetLang;
  code: string;
  /** Config file the snippet belongs in, if any. */
  file?: string;
}

export interface AgentSetup {
  id: string;
  name: string;
  kind: 'CLI' | 'Editor' | 'Desktop app' | 'Any client';
  /** One-line orientation shown above the snippets. */
  intro: string;
  blocks: SetupBlock[];
  /** Extra hints rendered as a list under the snippets. */
  notes: string[];
  docsUrl?: string;
  /** One-click install deeplink (e.g. Cursor). */
  installLink?: { label: string; href: string };
}

/** Trim, drop trailing slashes and fall back to the hosted relay when empty. */
export function normalizeServerUrl(input: string | null | undefined): string {
  const trimmed = (input ?? '').trim().replace(/\/+$/, '');
  return trimmed || DEFAULT_SERVER_URL;
}

/** Quote a value for POSIX shells only when it needs it. */
export function shellQuote(value: string): string {
  if (/^[A-Za-z0-9_\-.:/=@%+,~]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function json(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

/** Base64 that also works for non-ASCII input. */
function base64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** The stdio launch definition shared by most clients. */
export function serverEntry(serverUrl: string) {
  return {
    command: 'npx',
    args: ['-y', MCP_PACKAGE],
    env: { CPMESH_SERVER_URL: normalizeServerUrl(serverUrl) },
  };
}

/** `cursor://` deeplink that opens Cursor's "install MCP server" prompt. */
export function cursorInstallLink(serverUrl: string): string {
  const config = base64(JSON.stringify(serverEntry(serverUrl)));
  return `cursor://anysphere.cursor-deeplink/mcp/install?name=${MCP_SERVER_NAME}&config=${encodeURIComponent(config)}`;
}

/** Shell command that registers the server with an `<agent> mcp add` style CLI. */
function cliAdd(prefix: string, serverUrl: string): string {
  const env = shellQuote(`CPMESH_SERVER_URL=${normalizeServerUrl(serverUrl)}`);
  return `${prefix} --env ${env} -- npx -y ${MCP_PACKAGE}`;
}

export function agentSetups(serverUrlInput: string): AgentSetup[] {
  const url = normalizeServerUrl(serverUrlInput);
  const entry = serverEntry(url);
  const mcpServers = { mcpServers: { [MCP_SERVER_NAME]: entry } };
  const envArg = shellQuote(`CPMESH_SERVER_URL=${url}`);

  return [
    {
      id: 'claude-code',
      name: 'Claude Code',
      kind: 'CLI',
      intro: 'Register the server once with the Claude Code CLI. Everything after "--" is the command Claude Code runs.',
      blocks: [
        { title: 'Run in your terminal', lang: 'bash', code: cliAdd(`claude mcp add ${MCP_SERVER_NAME} --scope user`, url) },
      ],
      notes: [
        'Drop "--scope user" to enable it for the current project only, or use "--scope project" to share it through .mcp.json.',
        'Check it with "claude mcp list", or run /mcp inside a session.',
      ],
      docsUrl: 'https://code.claude.com/docs/en/mcp',
    },
    {
      id: 'claude-desktop',
      name: 'Claude Desktop',
      kind: 'Desktop app',
      intro: 'Open Settings → Developer → Edit Config and add cpmesh to claude_desktop_config.json.',
      blocks: [{ title: 'claude_desktop_config.json', lang: 'json', code: json(mcpServers), file: 'claude_desktop_config.json' }],
      notes: [
        'macOS: ~/Library/Application Support/Claude/claude_desktop_config.json',
        'Windows: %APPDATA%\\Claude\\claude_desktop_config.json',
        'Quit and reopen Claude Desktop after saving so it starts the server.',
      ],
      docsUrl: 'https://modelcontextprotocol.io/docs/develop/connect-local-servers',
    },
    {
      id: 'cursor',
      name: 'Cursor',
      kind: 'Editor',
      intro: 'Use the one-click install link, or add the server to your global or project mcp.json.',
      blocks: [
        {
          title: '~/.cursor/mcp.json',
          lang: 'json',
          code: json({ mcpServers: { [MCP_SERVER_NAME]: { type: 'stdio', ...entry } } }),
          file: '~/.cursor/mcp.json',
        },
      ],
      notes: ['Use .cursor/mcp.json in a project to enable it only there.', 'Enable the server under Settings → MCP if Cursor does not start it automatically.'],
      docsUrl: 'https://cursor.com/docs/mcp',
      installLink: { label: 'Add to Cursor', href: cursorInstallLink(url) },
    },
    {
      id: 'vscode',
      name: 'VS Code (GitHub Copilot)',
      kind: 'Editor',
      intro: 'Add the server from the command line, or commit a .mcp.json to share it with your team. You can also run "MCP: Add Server" → Command (stdio).',
      blocks: [
        {
          title: 'Run in your terminal',
          lang: 'bash',
          code: `code --add-mcp ${shellQuote(JSON.stringify({ name: MCP_SERVER_NAME, ...entry }))}`,
        },
        {
          title: '.mcp.json (workspace root)',
          lang: 'json',
          code: json({ mcpServers: { [MCP_SERVER_NAME]: { type: 'stdio', ...entry } } }),
          file: '.mcp.json',
        },
      ],
      notes: [
        'In Windows PowerShell, prefer the .mcp.json file: the JSON quoting of "code --add-mcp" differs between shells.',
        'Use Agent mode in Copilot Chat, then confirm that you trust the server when VS Code asks.',
      ],
      docsUrl: 'https://code.visualstudio.com/docs/copilot/customization/mcp-servers',
    },
    {
      id: 'copilot-cli',
      name: 'GitHub Copilot CLI',
      kind: 'CLI',
      intro: 'Add the server with the copilot CLI. It is saved to ~/.copilot/mcp-config.json and available in every session.',
      blocks: [
        { title: 'Run in your terminal', lang: 'bash', code: cliAdd(`copilot mcp add ${MCP_SERVER_NAME}`, url) },
        {
          title: '~/.copilot/mcp-config.json',
          lang: 'json',
          code: json({ mcpServers: { [MCP_SERVER_NAME]: { type: 'local', ...entry, tools: ['*'] } } }),
          file: '~/.copilot/mcp-config.json',
        },
      ],
      notes: ['Inside an interactive session, /mcp add opens the same form and /mcp show lists your servers.'],
      docsUrl: 'https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers',
    },
    {
      id: 'codex',
      name: 'OpenAI Codex',
      kind: 'CLI',
      intro: 'Codex CLI, the IDE extension and the desktop app share ~/.codex/config.toml, so one entry covers all three.',
      blocks: [
        { title: 'Run in your terminal', lang: 'bash', code: cliAdd(`codex mcp add ${MCP_SERVER_NAME}`, url) },
        {
          title: '~/.codex/config.toml',
          lang: 'toml',
          code: [
            `[mcp_servers.${MCP_SERVER_NAME}]`,
            'command = "npx"',
            `args = ["-y", "${MCP_PACKAGE}"]`,
            '',
            `[mcp_servers.${MCP_SERVER_NAME}.env]`,
            `CPMESH_SERVER_URL = ${JSON.stringify(url)}`,
          ].join('\n'),
          file: '~/.codex/config.toml',
        },
      ],
      notes: ['Check it with "codex mcp list", or type /mcp in the Codex TUI.'],
      docsUrl: 'https://developers.openai.com/codex/mcp',
    },
    {
      id: 'gemini-cli',
      name: 'Gemini CLI',
      kind: 'CLI',
      intro: 'Add the server to your user settings. The "--" keeps npx\'s -y flag from being read by Gemini CLI.',
      blocks: [
        { title: 'Run in your terminal', lang: 'bash', code: `gemini mcp add --scope user -e ${envArg} ${MCP_SERVER_NAME} npx -- -y ${MCP_PACKAGE}` },
        { title: '~/.gemini/settings.json', lang: 'json', code: json(mcpServers), file: '~/.gemini/settings.json' },
      ],
      notes: ['Check it with "gemini mcp list", or run /mcp inside a session.'],
      docsUrl: 'https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md',
    },
    {
      id: 'windsurf',
      name: 'Windsurf (Devin Desktop)',
      kind: 'Editor',
      intro: 'In the Cascade panel, open the … menu → Open MCP config file, then add cpmesh under mcpServers.',
      blocks: [{ title: 'mcp_config.json', lang: 'json', code: json(mcpServers), file: 'mcp_config.json' }],
      notes: [
        'macOS / Linux: ~/.config/devin/mcp_config.json · Windows: %APPDATA%\\devin\\mcp_config.json',
        'Older Windsurf builds read ~/.codeium/windsurf/mcp_config.json instead.',
      ],
      docsUrl: 'https://docs.devin.ai/desktop/cascade/mcp',
    },
    {
      id: 'cline',
      name: 'Cline',
      kind: 'Editor',
      intro: 'In the Cline panel, open MCP Servers → Configure → Configure MCP Servers and add cpmesh to the JSON.',
      blocks: [
        {
          title: 'cline_mcp_settings.json',
          lang: 'json',
          code: json({ mcpServers: { [MCP_SERVER_NAME]: { ...entry, disabled: false, autoApprove: [] } } }),
          file: 'cline_mcp_settings.json',
        },
      ],
      notes: [
        'Cline CLI reads ~/.cline/data/settings/cline_mcp_settings.json, or run "cline mcp" for an interactive wizard.',
        'Keep autoApprove empty or limited to read-only tools so you confirm every push.',
      ],
      docsUrl: 'https://docs.cline.bot/mcp/mcp-overview',
    },
    {
      id: 'zed',
      name: 'Zed',
      kind: 'Editor',
      intro: 'Open Settings → AI → MCP Servers → Add Server → Add Local Server, or add the entry to settings.json yourself.',
      blocks: [
        { title: 'settings.json', lang: 'json', code: json({ context_servers: { [MCP_SERVER_NAME]: entry } }), file: 'settings.json' },
      ],
      notes: ['Run "zed: open settings file" to edit settings.json. A green dot next to cpmesh means the server is active.'],
      docsUrl: 'https://zed.dev/docs/ai/mcp',
    },
    {
      id: 'opencode',
      name: 'opencode',
      kind: 'CLI',
      intro: 'Add a local MCP server to your opencode config. opencode takes the command and its arguments as one array.',
      blocks: [
        {
          title: 'opencode.json',
          lang: 'json',
          code: json({
            $schema: 'https://opencode.ai/config.json',
            mcp: {
              [MCP_SERVER_NAME]: {
                type: 'local',
                command: ['npx', '-y', MCP_PACKAGE],
                environment: { CPMESH_SERVER_URL: url },
                enabled: true,
              },
            },
          }),
          file: 'opencode.json',
        },
      ],
      notes: ['Use opencode.json in a project, or ~/.config/opencode/opencode.json for every project.'],
      docsUrl: 'https://opencode.ai/docs/mcp-servers/',
    },
    {
      id: 'other',
      name: 'Any MCP client',
      kind: 'Any client',
      intro: 'cpmesh-mcp is a standard stdio MCP server. Most clients accept this mcpServers block. Otherwise use: command "npx", arguments "-y cpmesh-mcp", and the CPMESH_SERVER_URL environment variable.',
      blocks: [
        { title: 'mcpServers config', lang: 'json', code: json(mcpServers) },
        { title: 'Or run it directly', lang: 'bash', code: `CPMESH_SERVER_URL=${shellQuote(url)} npx -y ${MCP_PACKAGE}` },
      ],
      notes: ['The server speaks MCP over stdin/stdout, so it is meant to be started by your MCP client, not run on its own.'],
    },
  ];
}

export interface McpTool {
  name: string;
  desc: string;
}

export interface McpToolGroup {
  title: string;
  icon: string;
  tools: McpTool[];
}

export const toolGroups: McpToolGroup[] = [
  {
    title: 'Setup and pairing',
    icon: 'key',
    tools: [
      { name: 'cpmesh_status', desc: 'Login and approval state, the pairing code if pending, the group-key version and the exact next step.' },
      { name: 'cpmesh_login', desc: 'Sign in and register the agent with proof of key possession.' },
      { name: 'cpmesh_confirm_pairing', desc: 'Confirm the 8-digit pairing code (or the full 64-character code) compared on your trusted device.' },
      { name: 'cpmesh_verify_device', desc: 'Verify an existing peer using its full public-key fingerprint after an upgrade or recovery.' },
      { name: 'cpmesh_wait_for_approval', desc: 'Waits until you approve the device, then syncs the encryption key.' },
      { name: 'cpmesh_logout', desc: 'Signs out and wipes the local device key, keyring and session.' },
    ],
  },
  {
    title: 'Clipboard',
    icon: 'clipboard',
    tools: [
      { name: 'cpmesh_push_clipboard', desc: 'Encrypts text and confirms relay persistence. Delivery to other devices is not guaranteed.' },
      { name: 'cpmesh_get_clipboard', desc: 'Decrypted clipboard history, newest first, with pagination.' },
      { name: 'cpmesh_get_latest_clipboard', desc: 'The single latest entry. skip_own ignores what the agent pushed itself.' },
      { name: 'cpmesh_search_clipboard', desc: 'Case-insensitive search across your decrypted history.' },
      { name: 'cpmesh_delete_clipboard_entry', desc: 'Deletes one history entry by ID.' },
    ],
  },
  {
    title: 'Devices',
    icon: 'monitor',
    tools: [
      { name: 'cpmesh_list_devices', desc: 'Every device on your account, with approval status and online state.' },
      { name: 'cpmesh_remove_device', desc: 'Removes another device and revokes its access.' },
    ],
  },
];

export const envVars = [
  { name: 'CPMESH_SERVER_URL', def: '—', desc: 'Your cpmesh server URL. Can also be passed to cpmesh_login.' },
  { name: 'CPMESH_USERNAME', def: '—', desc: 'Optional. With CPMESH_PASSWORD, signs in automatically at startup.' },
  { name: 'CPMESH_PASSWORD', def: '—', desc: 'Optional. Only use it in a private, user-level config file.' },
  { name: 'CPMESH_HOME', def: '~/.cpmesh/mcp', desc: 'Where the device key, keyring, session and key pins are stored.' },
];

export const examplePrompts = [
  { prompt: 'Send the deploy command to my phone.', tool: 'cpmesh_push_clipboard' },
  { prompt: 'What did I just copy on my laptop?', tool: 'cpmesh_get_latest_clipboard' },
  { prompt: 'Find the staging URL I copied this morning.', tool: 'cpmesh_search_clipboard' },
  { prompt: 'Which of my devices are online right now?', tool: 'cpmesh_list_devices' },
];
