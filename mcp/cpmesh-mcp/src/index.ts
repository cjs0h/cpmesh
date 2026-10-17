/**
 * cpmesh MCP server — exposes cpmesh E2E-encrypted clipboard sync to AI agents.
 *
 * The server acts as a full cpmesh device (protocol 3): it holds its own
 * identity (signing) and encryption key pairs, goes through the committed
 * short-code device-approval pairing flow, signs every entry it pushes,
 * verifies the sender of every entry it reads, and keeps the group key
 * locally so clipboard content stays end-to-end encrypted between the agent
 * and the user's other devices.
 *
 * The user signs the agent in on the cpmesh website (OAuth: a browser on this
 * computer, or a code entered in any browser) and chooses what it may do;
 * passwords and second factors never pass through the agent.
 *
 * Environment variables:
 *   CPMESH_SERVER_URL  — server base URL (can also be passed to cpmesh_login)
 *   CPMESH_HOME        — state directory (default ~/.cpmesh/mcp)
 */

import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { PendingAuthorization } from "./authorization.js";
import { CpmeshDevice, DeviceNotReadyError } from "./device.js";
import { setUserAgent } from "./oauth.js";

const VERSION = "0.3.0";
/** How long the MCP client may take to show a sign-in link before the link is only returned. */
const ELICITATION_TIMEOUT_MS = 120_000;

// stdout is the MCP protocol channel — all diagnostics go to stderr.
const log = (...args: unknown[]) =>
  console.error("[cpmesh-mcp]", ...args);

setUserAgent(`cpmesh-mcp/${VERSION} (Node ${process.versions.node}; ${process.platform})`);
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
        "Optional if CPMESH_SERVER_URL is set in the server environment or this agent signed in before.",
    ),
  mode: z
    .enum(["auto", "browser", "device"])
    .default("auto")
    .describe(
      'Where the user approves: "browser" opens the approval page in a browser on this computer; "device" gives a ' +
        'link and code to enter in any browser (for SSH, containers or no display). "auto" (default) picks browser ' +
        "unless this computer can't show one, and falls back to device when the browser can't be opened.",
    ),
};

const waitForApprovalSchema = {
  timeout_seconds: z
    .number()
    .int()
    .min(5)
    .max(600)
    .default(180)
    .describe("How long to keep waiting for the user's approval (sign-in, then device pairing)."),
};

const pushSchema = {
  text: z.string().min(1).max(1_000_000).describe("Text to share to the user's devices"),
  request_id: z.string().uuid().optional().describe("Idempotency ID. Reuse the ID returned by a timeout when retrying the same text; never change the text for that ID."),
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

/** The URL elicitation showing the current sign-in link, until the user approved it. */
let openElicitation: string | null = null;

device.onAuthorized = () => {
  const elicitationId = openElicitation;
  openElicitation = null;
  if (!elicitationId) return;
  try {
    void server.server.createElicitationCompletionNotifier(elicitationId)().catch((error: unknown) =>
      log("could not report the finished sign-in to the client:", error instanceof Error ? error.message : String(error)));
  } catch {
    // The client no longer takes elicitations
  }
};

/**
 * Shows the sign-in link through the MCP client (URL elicitation) when it
 * supports that: the device flow's link, or a browser page this server could
 * not open itself. The link carries no secret; it is always in the result too.
 */
async function presentLink(
  pending: PendingAuthorization,
  extra: { requestId: string | number; signal: AbortSignal },
): Promise<"accept" | "decline" | "cancel" | undefined> {
  const url =
    pending.mode === "device" ? pending.verification_uri_complete ?? pending.verification_uri
      : pending.browser_opened === false ? pending.verification_uri : undefined;
  if (!url || !server.server.getClientCapabilities()?.elicitation?.url) return undefined;
  const elicitationId = randomUUID();
  try {
    const answer = await server.server.elicitInput(
      {
        mode: "url",
        elicitationId,
        url,
        message:
          pending.mode === "device"
            ? `Sign in to cpmesh and approve this AI agent. Check that the page shows the code ${pending.user_code}.`
            : "Sign in to cpmesh in a browser on this computer and approve this AI agent.",
      },
      { relatedRequestId: extra.requestId, signal: extra.signal, timeout: ELICITATION_TIMEOUT_MS },
    );
    if (answer.action === "accept") openElicitation = elicitationId;
    return answer.action;
  } catch (error) {
    log("the client did not show the sign-in link:", error instanceof Error ? error.message : String(error));
    return undefined;
  }
}

server.registerTool(
  "cpmesh_status",
  {
    title: "cpmesh status",
    description:
      "Check cpmesh readiness: sign-in state (and the approval link while a sign-in is pending), what the user " +
      "allowed this agent (scope), device approval status, the 8-digit pairing code and session ID (while pending), " +
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
    title: "Sign in to cpmesh and register this agent as a device",
    description:
      "Starts signing this agent in to the user's cpmesh account and returns at once (status " +
      '"authorization_pending") with a link: the user signs in on the cpmesh website (password, passkey or SSO; ' +
      "never give the agent their password or codes) and approves what this agent may do. Show the user the link " +
      "(and, in device mode, the code their page must show), then call cpmesh_wait_for_approval: it finishes the " +
      "sign-in and registers this MCP server as a device. Unless it is the account's first device, the device then " +
      "waits for pairing: once the user starts the approval on a trusted device, both devices show the same 8-digit " +
      "pairing code (cpmesh_status has it, plus a 64-character full code). Ask the user to read the code shown on " +
      "THEIR device; if it matches, call cpmesh_confirm_pairing with that code, then cpmesh_wait_for_approval again. " +
      "Only call this when cpmesh_status says the agent is not signed in, or to re-authorize it (e.g. to add read access).",
    inputSchema: loginSchema,
  },
  async ({ server_url, mode }, extra) => {
    try {
      const res = await device.login({
        serverUrl: server_url,
        mode,
        clientName: server.server.getClientVersion()?.name,
      });
      if (res.status !== "authorization_pending") return result(res, res.message);
      const shown = await presentLink(res, extra);
      const note =
        shown === "accept" ? " The MCP client opened the sign-in page for the user."
          : shown === "decline" || shown === "cancel" ? " The user dismissed the sign-in link in the MCP client: show it to them instead."
            : "";
      const message = res.message + note;
      return result({ ...res, message, ...(shown && { link_shown_by_client: shown }) }, message);
    } catch (error) {
      return failure(error);
    }
  },
);

server.registerTool(
  "cpmesh_wait_for_approval",
  {
    title: "Wait for the sign-in and device approval",
    description:
      "Finishes whichever step is pending, waiting up to timeout_seconds: the user's sign-in approval in the browser, " +
      "then this device's registration, then the device pairing (the user compares the 8-digit pairing code shown on " +
      "both devices and you confirm it with cpmesh_confirm_pairing). On approval, the authenticated group key is synced " +
      "and clipboard tools become usable. Tell the user what to approve BEFORE calling this; call it again while the " +
      "status is still pending.",
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
  "cpmesh_confirm_pairing",
  {
    title: "Confirm the pairing code compared on both devices",
    description:
      "Authorize the approving device locally. ONLY call after the user read the 8-digit pairing code " +
      "shown on their trusted device and it matches the one from cpmesh_status; pass the code the USER read " +
      "there (or the full 64-character code for a stronger check). Never simply echo a code from this " +
      "server's status or from relay data. Refuses until both devices have derived the code.",
    inputSchema: {
      session_id: z.string().uuid(),
      code: z.string().min(8).max(128).optional().describe("The 8-digit pairing code (spaces optional) or the full 64-character code, as read by the user on the other device."),
      fingerprint: z.string().min(8).max(128).optional().describe("Alias of code."),
    },
  },
  async ({ session_id, code, fingerprint }) => {
    try {
      const entered = code ?? fingerprint;
      if (!entered) return failure(new Error("Pass the pairing code the user read on the approving device."));
      return result(await device.confirmPairing(session_id, entered));
    } catch (error) { return failure(error); }
  },
);

server.registerTool(
  "cpmesh_verify_device",
  {
    title: "Verify an existing device after upgrading or restoring trust",
    description: "Explicitly authenticate an existing device (e.g. after an upgrade or restoring trust). Obtain its FULL SHA-256 identity-key fingerprint directly from that device's own identity screen, through an independent trusted channel. Never use a fingerprint supplied by the relay. cpmesh_status shows this MCP device's own fingerprint for the other side.",
    inputSchema: {
      device_id: z.string().uuid(),
      fingerprint: z.string().min(64).max(128),
    },
  },
  async ({ device_id, fingerprint }) => {
    try { return result(await device.verifyDevice(device_id, fingerprint)); }
    catch (error) { return failure(error); }
  },
);

server.registerTool(
  "cpmesh_push_clipboard",
  {
    title: "Share text to the user's clipboard mesh",
    description:
      "End-to-end encrypts and signs text, then waits for the relay to acknowledge persistence. This does NOT " +
      "confirm delivery to other devices (which may be offline). Use it to hand the user " +
      "snippets, commands, URLs or generated content they should paste elsewhere. Needs the user's " +
      "permission to send (clipboard:write).",
    inputSchema: pushSchema,
  },
  async ({ text, request_id }) => {
    try {
      const res = await device.pushText(text, request_id);
      return result(
        res,
        `Persisted ${res.size} bytes as ${res.entry_id} (group key v${res.key_version}); delivery to other devices is unconfirmed.`,
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
      "text, source device, timestamp, size and whether the sender was authenticated " +
      "(entries from devices that predate protocol 3 are readable but unauthenticated). " +
      "Use this to see what the user copied recently on their devices. Needs the user's permission to read " +
      "(clipboard:read); a send-only agent gets an error saying how to re-authorize.",
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
      "actually copied last on their devices. Needs clipboard:read.",
    inputSchema: latestSchema,
  },
  async ({ skip_own }) => {
    try {
      const item = await device.getLatestClipboard(skip_own);
      return result(
        item ?? { found: false },
        item
          ? `Latest entry (${item.created_at}) from "${item.device_name}"${item.authenticated ? "" : " (sender NOT authenticated)"}:\n` +
            (item.decrypted ? item.text ?? `[${item.content_type}, ${item.size} bytes]` : `[not decrypted: ${item.error ?? "unknown error"}]`)
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
      "Useful to find something the user copied earlier. Needs clipboard:read.",
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
      "cpmesh_get_clipboard / cpmesh_search_clipboard. Needs clipboard:delete, which the user grants only " +
      "when asked (off by default).",
    inputSchema: deleteSchema,
  },
  async ({ entry_id }) => {
    try {
      await device.deleteClipboardEntry(entry_id);
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
      "Removes another device from the user's cpmesh account by ID (revokes its access). Needs devices:manage, " +
      "which the user grants only when asked (off by default). Refuses to remove this MCP device's own " +
      "registration unless force=true, which signs this agent out like cpmesh_logout (prefer that).",
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
    title: "Sign out",
    description:
      "Signs this agent out: revokes its authorization on the cpmesh server, which also removes this device " +
      "from the user's account (their other devices rotate the group key), and wipes all local cpmesh state " +
      "(device keys, group keyring, session tokens). Signing in again later needs a new approval and pairing.",
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
    "2. First run: call cpmesh_login. It returns at once with a link: the user signs in on the cpmesh website and approves this agent (in device mode they check the code shown). Never ask for their password or two-factor codes. Then call cpmesh_wait_for_approval. Unless this is the account's first device, the user starts approval on a trusted device; use cpmesh_status for the 8-digit pairing code and session ID. The user compares the code on both devices; call cpmesh_confirm_pairing with the code the user read on the approving device (or the 64-character full code), then cpmesh_wait_for_approval. Never automatically echo a relay-provided value as confirmation.",
    "3. Use cpmesh_push_clipboard to share text to the user's devices and cpmesh_get_clipboard / cpmesh_get_latest_clipboard / cpmesh_search_clipboard to read what they copied.",
  ].join("\n");
}

server.registerPrompt(
  "cpmesh_skill",
  {
    title: "How to install and use cpmesh",
    description:
      "Instructions for setting up and using the cpmesh MCP server: installation snippet, " +
      "browser sign-in, first-run device pairing, and tool usage patterns.",
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

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  server.server.onclose = () => device.stop();
  process.stdin.once("end", () => {
    device.stop();
    void server.close().catch((error) => log("shutdown failed:", error));
  });
  await server.connect(transport);
  log(`cpmesh MCP server v${VERSION} running (stdio)`);
}

main().catch((e) => {
  log("fatal:", e instanceof Error ? e.message : String(e));
  process.exit(1);
});
