/**
 * cpmesh MCP server — exposes cpmesh E2E-encrypted clipboard sync to AI agents.
 *
 * The server acts as a full cpmesh device: it holds its own ECDH key pair,
 * goes through the device-approval pairing flow, and keeps the group key
 * locally so clipboard content stays end-to-end encrypted between the agent
 * and the user's other devices.
 *
 * Environment variables:
 *   CPMESH_SERVER_URL  — server base URL (can also be passed to cpmesh_login)
 *   CPMESH_USERNAME    — optional; enables auto-login at startup
 *   CPMESH_PASSWORD    — optional; enables auto-login at startup (with two-factor
 *                        authentication, the agent still asks the user for the code)
 *   CPMESH_HOME        — state directory (default ~/.cpmesh/mcp)
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { CpmeshDevice, DeviceNotReadyError } from "./device.js";
import { sameAccount } from "./signin.js";
import { loadSession } from "./state.js";

const VERSION = "0.1.0";

// stdout is the MCP protocol channel — all diagnostics go to stderr.
const log = (...args: unknown[]) =>
  console.error("[cpmesh-mcp]", ...args);

const device = new CpmeshDevice();

function result(data: unknown, summary?: string) {
  return {
    content: [
      {
        type: "text" as const,
        text: (summary ? summary + "\n\n" : "") + JSON.stringify(data, null, 2),
      },
    ],
  };
}

function failure(error: unknown) {
  const message =
    error instanceof DeviceNotReadyError
      ? `${error.message} — next step: ${error.nextStep}`
      : error instanceof Error
        ? error.message
        : String(error);
  log("tool error:", message);
  return {
    content: [{ type: "text" as const, text: `ERROR: ${message}` }],
    isError: true,
  };
}

// === Tool argument schemas ===

const loginSchema = {
  server_url: z
    .string()
    .optional()
    .describe(
      "cpmesh server base URL: https://cpmesh.com for the hosted service, or the user's self-hosted server. " +
        "Optional if CPMESH_SERVER_URL is set in the server environment.",
    ),
  username: z
    .string()
    .optional()
    .describe(
      "cpmesh account username. Optional when CPMESH_USERNAME is set, or when finishing a sign-in " +
        "that is waiting for a two-factor code.",
    ),
  password: z
    .string()
    .optional()
    .describe(
      "cpmesh account password. Not needed when finishing a sign-in that is waiting for a two-factor " +
        "code (for 10 minutes after cpmesh_login asked for it), or when CPMESH_PASSWORD is set for this account.",
    ),
  code: z
    .string()
    .max(64)
    .optional()
    .describe(
      "Two-factor authentication code: the current 6-digit code from the user's authenticator app, or one " +
        'of their recovery codes. Pass it after cpmesh_login answered status "mfa_required". Never store or log it.',
    ),
};

const waitForApprovalSchema = {
  timeout_seconds: z
    .number()
    .int()
    .min(5)
    .max(600)
    .default(180)
    .describe("How long to keep polling for the user's approval."),
};

const pushSchema = {
  text: z.string().min(1).max(1_000_000).describe("Text to share to the user's devices"),
};

const getSchema = {
  limit: z.number().int().min(1).max(100).default(20).describe("Max entries to return"),
  offset: z.number().int().min(0).default(0).describe("Pagination offset"),
};

const latestSchema = {
  skip_own: z
    .boolean()
    .default(false)
    .describe("Skip entries pushed by this MCP device itself"),
};

const searchSchema = {
  query: z.string().min(1).describe("Case-insensitive substring to search for"),
  limit: z.number().int().min(1).max(50).default(10).describe("Max matches to return"),
};

const deleteSchema = {
  entry_id: z.string().describe("Clipboard entry ID to delete"),
};

const removeDeviceSchema = {
  device_id: z.string().describe("Device ID to remove"),
  force: z
    .boolean()
    .default(false)
    .describe("Allow removing this MCP device's own registration"),
};

// === Server setup ===

const server = new McpServer({ name: "cpmesh", version: VERSION });

server.registerTool(
  "cpmesh_status",
  {
    title: "cpmesh status",
    description:
      "Check cpmesh readiness: login state, device approval status, pairing code (if pending), " +
      "group key version, and the exact next step to take. Call this first if unsure.",
    inputSchema: {},
  },
  async () => {
    try {
      return result(await device.status());
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_login",
  {
    title: "Log in and register this agent as a cpmesh device",
    description:
      "Logs into the cpmesh server and registers this MCP server as a new device under the " +
      "user's account. Ask the user for their server URL, username and password before calling. " +
      'With two-factor authentication the response has status "mfa_required": ask the user for the ' +
      "current 6-digit code from their authenticator app (or a recovery code), then call cpmesh_login " +
      "again with code (the password can be left out for 10 minutes). " +
      "Unless this is the account's first device, the device starts PENDING: the response " +
      "includes an 8-digit pairing code that the user must confirm on one of their approved " +
      "cpmesh devices. After they confirm, call cpmesh_wait_for_approval.",
    inputSchema: loginSchema,
  },
  async ({ server_url, username, password, code }) => {
    try {
      // Left-out values continue the sign-in waiting for a two-factor code, else come from the environment
      const env = process.env;
      const waiting = device.waitingSignIn(server_url, username);
      const url = server_url ?? waiting?.serverUrl ?? env.CPMESH_SERVER_URL;
      if (!url) {
        return failure(
          new Error(
            "No server URL: pass server_url or set CPMESH_SERVER_URL in the MCP server environment.",
          ),
        );
      }
      const user = username ?? waiting?.username ?? env.CPMESH_USERNAME;
      if (!user) {
        return failure(
          new Error("No username: pass username or set CPMESH_USERNAME in the MCP server environment."),
        );
      }
      const envAccount =
        env.CPMESH_SERVER_URL !== undefined &&
        env.CPMESH_USERNAME !== undefined &&
        sameAccount(
          { serverUrl: url, username: user },
          { serverUrl: env.CPMESH_SERVER_URL, username: env.CPMESH_USERNAME },
        );
      const res = await device.login(
        url,
        user,
        password ?? (envAccount ? env.CPMESH_PASSWORD : undefined),
        code,
      );
      return result(res, res.message);
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_wait_for_approval",
  {
    title: "Wait for device approval",
    description:
      "Polls until the user approves this MCP device on one of their approved cpmesh devices " +
      "(they compare the 8-digit pairing code shown there with the one from cpmesh_login / " +
      "cpmesh_status). On approval, the group key is synced automatically and clipboard tools " +
      "become usable. Tell the user to go approve the device BEFORE calling this.",
    inputSchema: waitForApprovalSchema,
  },
  async ({ timeout_seconds }) => {
    try {
      const res = await device.waitForApproval(timeout_seconds * 1000);
      return result(res, res.message);
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_push_clipboard",
  {
    title: "Share text to the user's clipboard mesh",
    description:
      "End-to-end encrypts text and pushes it to the user's cpmesh clipboard — it appears " +
      "instantly on all their approved devices (desktop app, phone). Use it to hand the user " +
      "snippets, commands, URLs or generated content they should paste elsewhere.",
    inputSchema: pushSchema,
  },
  async ({ text }) => {
    try {
      const res = await device.pushText(text);
      return result(
        res,
        `Shared ${res.size} bytes to the user's devices (group key v${res.key_version}).`,
      );
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_get_clipboard",
  {
    title: "Read clipboard history",
    description:
      "Returns the user's clipboard history, decrypted (newest first). Each entry includes the " +
      "text, source device, timestamp and size. Use this to see what the user copied recently " +
      "on their devices.",
    inputSchema: getSchema,
  },
  async ({ limit, offset }) => {
    try {
      const res = await device.getClipboard(limit, offset);
      return result(
        res,
        res.items.length
          ? `${res.items.length} entr${res.items.length === 1 ? "y" : "ies"} (newest first)${res.has_more ? ", more available" : ""}.`
          : "Clipboard history is empty.",
      );
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_get_latest_clipboard",
  {
    title: "Read the latest clipboard entry",
    description:
      "Returns the single most recent clipboard entry across the user's devices (decrypted). " +
      "With skip_own=true it ignores entries pushed by this agent and returns what the user " +
      "actually copied last on their devices.",
    inputSchema: latestSchema,
  },
  async ({ skip_own }) => {
    try {
      const item = await device.getLatestClipboard(skip_own);
      return result(
        item ?? { found: false },
        item
          ? `Latest entry (${item.created_at}) from "${item.device_name}":\n${item.text ?? `[${item.content_type}, ${item.size} bytes]`}`
          : "No clipboard entries found.",
      );
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_search_clipboard",
  {
    title: "Search clipboard history",
    description:
      "Case-insensitive substring search over the user's decrypted clipboard history. " +
      "Useful to find something the user copied earlier.",
    inputSchema: searchSchema,
  },
  async ({ query, limit }) => {
    try {
      const items = await device.searchClipboard(query, limit);
      return result(
        { query, matches: items },
        items.length
          ? `${items.length} match${items.length === 1 ? "" : "es"} for "${query}".`
          : `No matches for "${query}".`,
      );
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_delete_clipboard_entry",
  {
    title: "Delete a clipboard entry",
    description:
      "Deletes one entry from the (shared) clipboard history by ID. Get IDs from " +
      "cpmesh_get_clipboard / cpmesh_search_clipboard.",
    inputSchema: deleteSchema,
  },
  async ({ entry_id }) => {
    try {
      const { api } = await device.ensureReady();
      await api.deleteClipboardEntry(entry_id);
      return result({ deleted: entry_id });
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_list_devices",
  {
    title: "List the user's devices",
    description:
      "Lists all devices on the user's cpmesh account with name, status, and online state.",
    inputSchema: {},
  },
  async () => {
    try {
      const devices = await device.listDevices();
      return result(
        { devices },
        `${devices.length} device${devices.length === 1 ? "" : "s"} on the account.`,
      );
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_remove_device",
  {
    title: "Remove a device from the account",
    description:
      "Removes another device from the user's cpmesh account by ID (revokes its access). " +
      "Refuses to remove this MCP device's own registration unless force=true — for that, " +
      "prefer cpmesh_logout.",
    inputSchema: removeDeviceSchema,
  },
  async ({ device_id, force }) => {
    try {
      const msg = await device.removeDevice(device_id, force);
      return result({ removed: device_id }, msg);
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_logout",
  {
    title: "Log out",
    description:
      "Logs out and wipes all local cpmesh state (device key, group keyring, session tokens). " +
      "The device registration stays on the account until removed server-side.",
    inputSchema: {},
  },
  async () => {
    try {
      const msg = await device.logout();
      return result({ logged_out: true }, msg);
    } catch (error) {
      return failure(error);
    }
  },
);

// === Skill prompt: usage instructions straight from the server ===

function loadSkillText(): string {
  const candidates = [
    new URL("../SKILL.md", import.meta.url),
  ];
  for (const url of candidates) {
    try {
      return readFileSync(fileURLToPath(url), "utf8");
    } catch {
      // try next
    }
  }
  return [
    "# cpmesh skill",
    "",
    "1. Install: add {\"mcpServers\":{\"cpmesh\":{\"command\":\"npx\",\"args\":[\"-y\",\"cpmesh-mcp\"],\"env\":{\"CPMESH_SERVER_URL\":\"https://cpmesh.com\"}}}} to your MCP client config (self-hosted users put their own server URL).",
    "2. First run: call cpmesh_login (needs username+password). If it answers status mfa_required, ask the user for the current 6-digit code from their authenticator app (or a recovery code) and call cpmesh_login again with code — never store the code. Then relay the 8-digit pairing code to the user, wait for them to confirm it on an approved device, and call cpmesh_wait_for_approval.",
    "3. Use cpmesh_push_clipboard to share text to the user's devices and cpmesh_get_clipboard / cpmesh_get_latest_clipboard / cpmesh_search_clipboard to read what they copied.",
  ].join("\n");
}

server.registerPrompt(
  "cpmesh_skill",
  {
    title: "How to install and use cpmesh",
    description:
      "Instructions for setting up and using the cpmesh MCP server: installation snippet, " +
      "first-run device pairing, and tool usage patterns.",
  },
  async () => ({
    messages: [
      {
        role: "user",
        content: { type: "text", text: loadSkillText() },
      },
    ],
  }),
);

// === Startup ===

async function autoLoginFromEnv(): Promise<void> {
  const { CPMESH_SERVER_URL, CPMESH_USERNAME, CPMESH_PASSWORD } = process.env;
  if (!CPMESH_SERVER_URL || !CPMESH_USERNAME || !CPMESH_PASSWORD) return;
  try {
    if (loadSession()) return; // already logged in
    const res = await device.login(CPMESH_SERVER_URL, CPMESH_USERNAME, CPMESH_PASSWORD);
    log("auto-login:", res.message);
  } catch (e) {
    log(
      "auto-login failed:",
      e instanceof Error ? e.message : String(e),
      "— tools will report not-logged-in; the agent can call cpmesh_login.",
    );
  }
}

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log(`cpmesh MCP server v${VERSION} running (stdio)`);
  await autoLoginFromEnv();
}

main().catch((e) => {
  log("fatal:", e instanceof Error ? e.message : String(e));
  process.exit(1);
});
