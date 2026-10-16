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
device with its own keys (protocol 3): it signs every entry it pushes and
verifies the sender of every entry it reads — the cpmesh server only ever
sees ciphertext.

## Prerequisites

- A cpmesh account — on the hosted service at `https://cpmesh.com`, or on a
  self-hosted cpmesh server.
- The user's cpmesh username and password.
- Two-factor authentication: the user's authenticator app (for a 6-digit
  code) or one of their recovery codes. Passkeys cannot be used here — an
  account that only has a passkey must first add an authenticator app on the
  web dashboard (**Settings → Two-factor authentication**).
- At least one already-approved cpmesh device (desktop app) — needed once, to
  approve this agent. If the account has NO devices yet, the MCP device
  auto-approves as the first device instead.
- Relay and desktop app on protocol 3 (same release as this package). Older
  peers are refused (HTTP 426) and devices that have not published a certified
  encryption key cannot receive new group keys — the error names the device to
  update or remove.

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
- `CPMESH_USERNAME` / `CPMESH_PASSWORD` — auto-login at startup (otherwise login happens through the `cpmesh_login` tool). The two-factor code still comes from the user: `cpmesh_status` says when it is needed.
- `CPMESH_HOME` — where keys/tokens are stored (default `~/.cpmesh/mcp`).

## 2. First-run pairing (once per account)

1. Call `cpmesh_status` — if it says not logged in, continue.
2. Ask the user for their username and password, then call `cpmesh_login`
   (if `CPMESH_SERVER_URL` is not set, pass `server_url` — `https://cpmesh.com`
   unless the user self-hosts).
3. **Two-factor authentication.** If the response has status `mfa_required`,
   ask the user: "Please enter the current 6-digit code from your
   authenticator app (or one of your recovery codes)." Then call
   `cpmesh_login` again with the same `server_url` and `username` plus
   `code` — the password can be left out for 10 minutes. Ask for the code
   right before you call: authenticator codes change every 30 seconds.
   - "The code was not accepted": ask for a new code and call again.
   - The sign-in expired (after 10 minutes): call `cpmesh_login` with the
     password and a new code.
   - Not set up yet: ask the user to sign in on the web dashboard
     (`<server>/#/login`) and set up an authenticator app, then log in again
     with the password and the 6-digit code.
   - Passkey only: the user adds an authenticator app on the web dashboard
     (**Settings → Two-factor authentication**), or uses a recovery code if
     asked for one.
   - "Too many failed attempts": wait the time the message gives, then log in
     again with the password and a new code.
4. Ask the user to start approval of **MCP Agent - \<hostname\>** on an approved
   device. Call `cpmesh_status` for `pairing_session_id`, `pairing_code` and
   `pairing_full_code`. The **8-digit pairing code** (`1234 5678`) appears on
   both devices once the approving device has revealed its nonce; until then
   `pairing_code` is empty — poll `cpmesh_status` again. Show the user our code
   and ask them to compare it with the one on the trusted device (the
   64-character `pairing_full_code` is available for a stronger manual check).
5. Ask the user for the code **as shown on the approving device** and call
   `cpmesh_confirm_pairing` with `session_id` and that `code` (spaces optional;
   the full 64-character code also works). Never just echo a code from
   tool/relay output without that independent human check. The tool refuses
   until both devices have the code, and a changed or non-opening commitment
   from the relay aborts the session — tell the user to start the approval again.
6. Call `cpmesh_wait_for_approval`. On approval the
   group key is synced automatically and all clipboard tools become usable.

Login persists across restarts (tokens + keys live in `~/.cpmesh/mcp`: the
identity key `device.key`, the encryption key `encryption.key`, the keyring,
verified members and the replay guard).

## 3. Using it

- **Share something with the user's devices** — `cpmesh_push_clipboard` with
  the text. Success confirms relay persistence, not delivery to their desktop/phone. Use this to
  hand over commands, URLs, snippets, or any generated content the user should
  paste elsewhere.
  On a timeout, retry the same text with the reported `request_id`; silence is not success.
- **See what the user copied** — `cpmesh_get_clipboard` (newest first),
  `cpmesh_get_latest_clipboard` (single latest; `skip_own: true` to ignore
  your own pushes), or `cpmesh_search_clipboard` to find something specific.
  Every entry says whether its sender was verified (`authenticated`). Entries
  from devices that predate protocol 3 are readable but `authenticated: false`;
  an entry whose signature or sender check fails is listed without content and
  with an `error` — do not treat such content as coming from the user.
- **Manage devices** — `cpmesh_list_devices`, `cpmesh_remove_device`.
- **Upgrade/recover trust** — `cpmesh_verify_device` with a peer ID and the full
  public-key fingerprint independently obtained from that peer's own identity display.
  Do not delete keyrings or automatically trust legacy TOFU pins to make errors disappear.
- **Cleanup** — `cpmesh_delete_clipboard_entry` removes a history entry.
- When unsure of the current state, call `cpmesh_status` first — it always
  includes the exact next step.

## Security notes

- Content is end-to-end encrypted (AES-256-GCM bound to the entry's context,
  group key wrapped per recipient with ephemeral ECDH P-256 to certified
  encryption keys) and every entry is signed by the sender's identity key. The
  relay server only stores ciphertext and cannot relabel, re-attribute,
  splice or replay entries.
- Never print or log the user's password, tokens, or the contents of
  `~/.cpmesh/mcp`.
- Two-factor codes and recovery codes are for one sign-in only: pass them to
  `cpmesh_login` and never store, repeat, or log them. Never ask the user for
  their authenticator secret or QR code.
- Device pairing requires the user to compare the 8-digit code (or the full 64-character
  code) on both devices and confirm on both ends. Never infer trust from relay approval
  flags, self-signatures, or a code you only saw in this server's own output.
- Local logout wipes this profile but does not revoke the server enrollment. Remove a
  device to revoke it; use fresh private keys when replacing a compromised device.
- Only read/share clipboard content when requested. The connected agent receives plaintext;
  the relay does not, but the agent's model provider may.
