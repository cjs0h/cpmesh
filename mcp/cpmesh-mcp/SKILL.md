---
name: cpmesh
description: >-
  Use when the user wants to share clipboard content across their devices with
  cpmesh (E2E-encrypted clipboard sync), when they mention cpmesh, or when a
  task would benefit from sending text/commands/URLs to the user's other
  devices or reading what the user copied. Covers installing the cpmesh MCP
  server, signing it in through the browser, first-run device pairing, and
  using the clipboard tools.
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
  self-hosted cpmesh server recent enough to sign in AI agents, with its
  `BASE_URL` set (`cpmesh_login` says when a server must be upgraded).
- The user signs in on the cpmesh website themselves, with whatever their
  account uses (password, passkey or SSO, plus two-factor authentication).
  **Never ask the user for their password, authenticator codes or recovery
  codes**: this server does not take them.
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
- `CPMESH_HOME` — where keys/tokens are stored (default `~/.cpmesh/mcp`).

## 2. Sign in and pair (once per agent)

1. Call `cpmesh_status` — if it says not signed in, continue.
2. Call `cpmesh_login` (if `CPMESH_SERVER_URL` is not set, pass `server_url` —
   `https://cpmesh.com` unless the user self-hosts). It returns at once with
   status `authorization_pending` and a link; it does not wait.
   - **Browser on this computer** (the default on a desktop): a browser tab
     opens on the cpmesh website. Tell the user to sign in there if asked and
     approve this agent. If no tab opened, give them the `verification_uri`
     link to open on this computer.
   - **Device code** (chosen automatically over SSH, in containers or without
     a display; or pass `mode: "device"`): give the user the
     `verification_uri_complete` link (any browser, e.g. their phone) and the
     `user_code`, and ask them to approve only if the page shows that same code.
   - Some MCP clients show the link themselves (the result then says so).
   On the approval page the user chooses what this agent may do: read the
   clipboard, send to it, delete entries, manage devices (the last two are off
   by default). Do not ask for more than the task needs.
3. Call `cpmesh_wait_for_approval`. It finishes the sign-in once the user
   approved, registers this MCP server as a device, and continues with the
   pairing. If it answers `authorization_pending`, call it again (the request
   lasts 10 minutes); `access_denied` or `expired_token` means call
   `cpmesh_login` again if the user still wants to connect.
4. If the account has no devices yet, this device is approved at once and you
   are done. Otherwise ask the user to start approval of
   **MCP Agent - \<hostname\>** on an approved device. Call `cpmesh_status`
   for `pairing_session_id`, `pairing_code` and `pairing_full_code`. The
   **8-digit pairing code** (`1234 5678`) appears on both devices once the
   approving device has revealed its nonce; until then `pairing_code` is empty —
   poll `cpmesh_status` again. Show the user our code and ask them to compare it
   with the one on the trusted device (the 64-character `pairing_full_code` is
   available for a stronger manual check).
5. Ask the user for the code **as shown on the approving device** and call
   `cpmesh_confirm_pairing` with `session_id` and that `code` (spaces optional;
   the full 64-character code also works). Never just echo a code from
   tool/relay output without that independent human check. The tool refuses
   until both devices have the code, and a changed or non-opening commitment
   from the relay aborts the session — tell the user to start the approval again.
6. Call `cpmesh_wait_for_approval`. On approval the
   group key is synced automatically and all clipboard tools become usable.

The sign-in lasts while the agent is used (it renews itself; 30 days without
use end it). Sign-in and keys persist across restarts in `~/.cpmesh/mcp`: the
identity key `device.key`, the encryption key `encryption.key`, the keyring,
verified members, the replay guard and, while a device-code sign-in waits,
`authorization.json`. When `cpmesh_status` says the sign-in ended, call
`cpmesh_login` again: the device keeps its keys and needs no new pairing
(unless the user removed it).

**Upgrading from cpmesh-mcp 0.2:** a profile that was signed in with a
password counts as signed out. Call `cpmesh_login` once; the device keeps its
keys and pairing.

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
- **Manage devices** — `cpmesh_list_devices`, `cpmesh_remove_device` (needs
  the user to have allowed managing devices).
- **Upgrade/recover trust** — `cpmesh_verify_device` with a peer ID and the full
  public-key fingerprint independently obtained from that peer's own identity display.
  Do not delete keyrings or automatically trust legacy TOFU pins to make errors disappear.
- **Cleanup** — `cpmesh_delete_clipboard_entry` removes a history entry (needs
  the user to have allowed deleting entries).
- **Permissions** — `cpmesh_status` shows what the user allowed (`scope`). A
  tool the user did not allow fails with a message saying so: for example a
  send-only agent cannot read the clipboard. Ask the user whether they want to
  allow it; if they do, call `cpmesh_login` again and let them turn it on (the
  device stays paired).
- **Sign out** — `cpmesh_logout` revokes this agent on the server, which also
  removes its device from the account, and wipes the local profile.
- When unsure of the current state, call `cpmesh_status` first — it always
  includes the exact next step.

## Security notes

- Content is end-to-end encrypted (AES-256-GCM bound to the entry's context,
  group key wrapped per recipient with ephemeral ECDH P-256 to certified
  encryption keys) and every entry is signed by the sender's identity key. The
  relay server only stores ciphertext and cannot relabel, re-attribute,
  splice or replay entries.
- The user signs in on the cpmesh website only. Never ask for or handle their
  password, two-factor or recovery codes, and never print or log tokens or the
  contents of `~/.cpmesh/mcp`.
- In device mode, tell the user to approve only if the page shows the same
  code as you gave them, and only right after you asked: anyone can send them
  a link.
- Device pairing requires the user to compare the 8-digit code (or the full 64-character
  code) on both devices and confirm on both ends. Never infer trust from relay approval
  flags, self-signatures, or a code you only saw in this server's own output.
- `cpmesh_logout` revokes this agent's access on the server (its device is removed and the
  user's other devices rotate the group key) and wipes this profile. The user can also revoke
  the agent on the dashboard (**Connected agents**). Use fresh private keys when replacing a
  compromised device.
- Only read/share clipboard content when requested. The connected agent receives plaintext;
  the relay does not, but the agent's model provider may.
