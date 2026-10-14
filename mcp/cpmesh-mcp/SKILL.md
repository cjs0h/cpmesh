---
name: cpmesh
description: >-
  Use when the user wants to share clipboard content across their devices with
  cpmesh (E2E-encrypted clipboard sync), when they mention cpmesh, or when a
  task would benefit from sending text/commands/URLs to the user's other
  devices or reading what the user copied. Covers installing the cpmesh MCP
  server, first-run device pairing, and using the clipboard tools.
---

# cpmesh — E2E-encrypted clipboard sync for AI agents

cpmesh syncs the user's clipboard across their devices, end-to-end encrypted.
With this MCP server you can **push text to all the user's devices** and
**read/search their clipboard history**. The server acts as its own cpmesh
device with its own keys — the cpmesh server only ever sees ciphertext.

## Prerequisites

- A cpmesh account — on the hosted service at `https://cpmesh.com`, or on a
  self-hosted cpmesh server.
- The user's cpmesh username and password.
- At least one already-approved cpmesh device (desktop app) — needed once, to
  approve this agent. If the account has NO devices yet, the MCP device
  auto-approves as the first device instead.

## 1. Install the MCP server

Add to your MCP client config (Claude Desktop `claude_desktop_config.json`,
Cursor `.cursor/mcp.json`, or equivalent):

```json
{
  "mcpServers": {
    "cpmesh": {
      "command": "npx",
      "args": ["-y", "cpmesh-mcp"],
      "env": {
        "CPMESH_SERVER_URL": "https://cpmesh.com"
      }
    }
  }
}
```

Self-hosted users put their own server's URL in `CPMESH_SERVER_URL`.
Requires Node.js ≥ 18.19. No other setup — `npx` fetches and runs the package.
Restart the client after editing the config. You can also ask the server for
these instructions at any time via the `cpmesh_skill` prompt.

Optional environment variables:
- `CPMESH_USERNAME` / `CPMESH_PASSWORD` — auto-login at startup (otherwise login happens through the `cpmesh_login` tool).
- `CPMESH_HOME` — where keys/tokens are stored (default `~/.cpmesh/mcp`).

## 2. First-run pairing (once per account)

1. Call `cpmesh_status` — if it says not logged in, continue.
2. Ask the user for their username and password, then call `cpmesh_login`
   (if `CPMESH_SERVER_URL` is not set, pass `server_url` — `https://cpmesh.com`
   unless the user self-hosts).
3. The response contains an **8-digit pairing code**. Tell the user:
   "Open the cpmesh app on one of your approved devices, start approving the
   new device **MCP Agent - \<hostname\>**, and confirm it shows code
   **XXXXXXXX**."
4. After the user confirms, call `cpmesh_wait_for_approval`. On approval the
   group key is synced automatically and all clipboard tools become usable.

Login persists across restarts (tokens + keys live in `~/.cpmesh/mcp`).

## 3. Using it

- **Share something with the user's devices** — `cpmesh_push_clipboard` with
  the text. It appears instantly on their desktop/phone clipboard. Use this to
  hand over commands, URLs, snippets, or any generated content the user should
  paste elsewhere.
- **See what the user copied** — `cpmesh_get_clipboard` (newest first),
  `cpmesh_get_latest_clipboard` (single latest; `skip_own: true` to ignore
  your own pushes), or `cpmesh_search_clipboard` to find something specific.
- **Manage devices** — `cpmesh_list_devices`, `cpmesh_remove_device`.
- **Cleanup** — `cpmesh_delete_clipboard_entry` removes a history entry.
- When unsure of the current state, call `cpmesh_status` first — it always
  includes the exact next step.

## Security notes

- Content is end-to-end encrypted (AES-256-GCM, group key wrapped via ECDH
  P-256). The relay server only stores ciphertext.
- Never print or log the user's password, tokens, or the contents of
  `~/.cpmesh/mcp`.
- Device approval requires a human comparing the 8-digit code — this is the
  anti-MITM guarantee. Never try to bypass it.
