# cpmesh-mcp

MCP server that lets AI agents use [cpmesh](https://github.com/cjs0h/cpmesh)
end-to-end-encrypted clipboard sync: share text to the user's devices, read
and search clipboard history, and manage devices — all through the standard
Model Context Protocol.

The server behaves as a first-class cpmesh **device**: it generates its own
ECDH P-256 key pair, goes through the same 8-digit device-approval pairing as
the desktop app, and keeps the group key locally. Content stays end-to-end
encrypted between the agent and the user's other devices — the cpmesh server
only ever sees ciphertext. The crypto is a byte-compatible port of the desktop
client's Rust implementation, pinned by golden-vector tests.

## Install (for AI agents and humans)

Add to your MCP client config (Claude Desktop, Cursor, ZCode, or any stdio
MCP client):

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

`https://cpmesh.com` is the hosted cpmesh service; if you self-host, use your
own server's URL instead.

See [SKILL.md](./SKILL.md) for the full agent skill: first-run pairing, tool
usage patterns, and security notes. Agents can also fetch those instructions
at runtime via the `cpmesh_skill` MCP prompt.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `CPMESH_SERVER_URL` | — | Server base URL, e.g. `https://cpmesh.com` (can also be passed to the `cpmesh_login` tool) |
| `CPMESH_USERNAME` | — | With `CPMESH_PASSWORD`, auto-login at startup (the agent still asks the user for the two-factor code) |
| `CPMESH_PASSWORD` | — | See above |
| `CPMESH_HOME` | `~/.cpmesh/mcp` | Directory for device key, keyring, session, key pins |

## Tools

| Tool | What it does |
|---|---|
| `cpmesh_status` | Login/approval state, pairing code if pending, group-key version, and the exact next step |
| `cpmesh_login` | Log in (with the two-factor code when asked) + register this agent as a device; returns the 8-digit pairing code |
| `cpmesh_wait_for_approval` | Poll until the user approves the device; syncs the group key on approval |
| `cpmesh_push_clipboard` | E2E-encrypt text and push it to all the user's devices |
| `cpmesh_get_clipboard` | Decrypted clipboard history (newest first, paginated) |
| `cpmesh_get_latest_clipboard` | Single latest entry (`skip_own` to ignore the agent's own pushes) |
| `cpmesh_search_clipboard` | Case-insensitive substring search over history |
| `cpmesh_delete_clipboard_entry` | Delete one history entry by ID |
| `cpmesh_list_devices` | Devices on the account with status/online state |
| `cpmesh_remove_device` | Remove another device from the account |
| `cpmesh_logout` | Wipe local session, keyring and device key |

Plus the `cpmesh_skill` prompt with install/usage instructions.

## First-run flow

1. Agent calls `cpmesh_login` (server URL — `https://cpmesh.com` unless the
   user self-hosts — and the user's credentials).
2. The account uses two-factor authentication, so the response has status
   `mfa_required`: the agent asks the user for the current 6-digit code from
   their authenticator app (or a recovery code) and calls `cpmesh_login` again
   with `code` (see [Two-factor authentication](#two-factor-authentication)).
3. Device registers as **pending**; an 8-digit code is derived via ECDH with
   the approver's public key.
4. The user confirms the code on an already-approved device (anti-MITM).
5. Agent calls `cpmesh_wait_for_approval` → group key is unwrapped and cached;
   clipboard tools go live.

If the account has no devices yet, the MCP device becomes the first device:
it is auto-approved and creates group key v1.

## Two-factor authentication

cpmesh accounts sign in with a second factor (a self-hosted server can require
it for staff accounts only). After a correct password the server returns a
sign-in ticket instead of tokens, valid for 10 minutes and usable once;
`cpmesh_login` keeps it in memory and answers `status: "mfa_required"`.
Calling `cpmesh_login` again with `code` finishes the sign-in — without the
password while the ticket is valid; once it has expired, the password is
needed again together with a new code. The code can also be passed with the
password in a single call.

- **Codes:** a 6-digit code from an authenticator app (spaces are ignored), or
  one of the account's recovery codes (e.g. `abcd-efgh-ijkl-mnop`; each works
  once).
- **Passkeys** only work in the browser, so the MCP server cannot use them.
  Accounts whose only second factor is a passkey add an authenticator app on
  the web dashboard (**Settings → Two-factor authentication**); until then
  they can sign in with a recovery code.
- **Accounts without two-factor authentication yet** set it up first by
  signing in on the web dashboard (`<server>/#/login`).
- After 10 wrong codes in a row, two-factor sign-in is locked for 15 minutes.
  Suspended accounts cannot sign in.

With `CPMESH_USERNAME` / `CPMESH_PASSWORD`, the startup auto-login stops at the
second factor: `cpmesh_status` then tells the agent to ask the user for the
code, and `cpmesh_login` with just `code` finishes the sign-in (it signs in
with the configured password again if the ticket has expired).

## Local state & security

State lives in `CPMESH_HOME` (default `~/.cpmesh/mcp`, files `0600` on Unix):

- `device.key` — device ECDH private key (same PEM format as the desktop app)
- `keyring.enc` — encrypted group-key keyring (same file format as the desktop app)
- `session.json` — server URL, device identity, JWT tokens. Refresh tokens are
  single-use: each refresh rotates them and writes the new pair back here, so
  several MCP processes can share one state directory.
- `pinned_keys.json` — TOFU pins of peer device keys; a changed peer key is
  treated as a possible MITM and refused

Two-factor codes and sign-in tickets are never written to disk or logged; a
ticket waiting for its code lives in memory only.

Peer public keys are verified via their ECDSA self-signatures, matching the
desktop client. Group-key rotation (every 24h by default) is handled
transparently: the keyring is re-fetched and unwrapped when a new version is
detected.

## Development

```bash
cd mcp/cpmesh-mcp
npm install
npm run typecheck
npm test          # unit + golden-vector compatibility tests
npm run build
node scripts/smoke.mjs   # protocol smoke test against dist/
```

### Regenerating golden vectors

`test/vectors.json` pins byte-compatibility with the desktop client's Rust
crypto. Regenerate it whenever `desktop-tauri/src-tauri/src/crypto/` changes:

```bash
cd vector-gen
cargo run --release > ../test/vectors.json
```

The generator includes the desktop crypto modules via `#[path]`, so the
vectors always reflect the real implementation.

### End-to-end test against a real server

With a local cpmesh server running (e.g. `docker compose up` from the repo
root), and an account whose two-factor authentication is set up on the web
dashboard:

```bash
node scripts/e2e-smoke.mjs https://localhost:39271 user password 123456
```

The last argument is the current code from the authenticator app (or a
recovery code). It logs in as a first device (auto-approved), pushes a clip,
and reads it back decrypted.

## License

MIT OR Apache-2.0 (same as cpmesh).
