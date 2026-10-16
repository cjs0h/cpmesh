# cpmesh-mcp

MCP server that lets AI agents use [cpmesh](https://github.com/cjs0h/cpmesh)
end-to-end-encrypted clipboard sync: share text to the user's devices, read
and search clipboard history, and manage devices — all through the standard
Model Context Protocol.

The server behaves as a first-class cpmesh **device** speaking protocol 3: it
generates its own P-256 identity (signing) and encryption (ECDH) key pairs,
goes through the same committed short-code device pairing as the desktop app,
signs every clipboard entry it pushes, verifies the sender of every entry it
reads, and keeps the group key locally. Content stays end-to-end encrypted
between the agent and the user's other devices — the cpmesh server only ever
sees ciphertext. The crypto is a byte-compatible port of the desktop client's
Rust implementation, pinned by golden-vector tests.

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
| `CPMESH_HOME` | `~/.cpmesh/mcp` | Directory for device keys, keyring, session, key pins, replay guard |

There are no credential variables: the user signs the agent in on the cpmesh website.

## Tools

| Tool | What it does |
|---|---|
| `cpmesh_status` | Sign-in state (with the approval link while pending), granted scopes, approval state, the 8-digit pairing code and session while pending, group-key version, and the exact next step |
| `cpmesh_login` | Start the sign-in on the cpmesh website (`mode`: `auto`, `browser` or `device`); returns at once with the link (and code) |
| `cpmesh_confirm_pairing` | Confirm the 8-digit pairing code (or the 64-character full code) the user compared on the trusted device |
| `cpmesh_verify_device` | Explicitly verify an existing peer's full identity-key fingerprint after upgrade/recovery |
| `cpmesh_wait_for_approval` | Finish what is pending: the sign-in approval, the device registration (proof of key possession, certified encryption key), then the pairing; syncs the group key on approval |
| `cpmesh_push_clipboard` | E2E-encrypt and sign text, await persistence; returns the canonical entry ID, not a delivery guarantee; needs `clipboard:write` |
| `cpmesh_get_clipboard` | Decrypted, sender-verified clipboard history (newest first, paginated); needs `clipboard:read` |
| `cpmesh_get_latest_clipboard` | Single latest entry (`skip_own` to ignore the agent's own pushes) |
| `cpmesh_search_clipboard` | Case-insensitive substring search over history |
| `cpmesh_delete_clipboard_entry` | Delete one history entry by ID; needs `clipboard:delete` |
| `cpmesh_list_devices` | Devices on the account with status/online state |
| `cpmesh_remove_device` | Remove another device from the account; needs `devices:manage` |
| `cpmesh_logout` | Revoke this agent on the server (which removes its device), then wipe the local session, keyring and device keys |

Plus the `cpmesh_skill` prompt with install/usage instructions.

## First-run flow

1. Agent calls `cpmesh_login` (server URL — `https://cpmesh.com` unless the
   user self-hosts). It returns at once with status `authorization_pending`
   and a link (see [Signing in](#signing-in)).
2. The user signs in on the cpmesh website (password, passkey or SSO, with
   their second factor) and approves the agent, choosing what it may do.
   The agent calls `cpmesh_wait_for_approval`, which finishes the sign-in and
   registers the device.
3. The device registers as **pending**. The user starts approval on a trusted
   device; both devices then run the committed short-authentication-string
   exchange and show the same **8-digit pairing code**. The agent calls
   `cpmesh_status` to obtain `pairing_session_id`, `pairing_code` and
   `pairing_full_code` (a 64-character code over both identity keys, for a
   stronger manual check).
4. The user compares the 8-digit code on both devices (or every character of
   the full code) and confirms on the trusted device. The agent asks the user
   for the code **as shown on the trusted device**, then calls
   `cpmesh_confirm_pairing` with the session ID and that code; it never echoes
   a relay/MCP value as confirmation. Neither side pins the other before its
   own code exists, and a changed or non-opening commitment aborts the session.
5. Agent calls `cpmesh_wait_for_approval` → the authenticated group key is unwrapped and cached;
   clipboard tools go live.

If the account has no devices yet, the MCP device becomes the first device:
it is auto-approved and creates group key v1.

## Signing in

The agent never handles the user's password or second factor: `cpmesh_login`
signs it in with OAuth (cpmesh is the authorization server, `cpmesh-mcp` a
public client), and the user approves it on the cpmesh website with whatever
their account uses — password, passkey or SSO, plus two-factor authentication.
Accounts that sign in with a passkey or SSO only work too.

- **Browser on this computer** (`mode: "browser"`): authorization code with
  PKCE (S256). The server listens on `127.0.0.1` on a random port, opens the
  approval page in the default browser, and accepts exactly one answer: it
  must carry the request's `state` and the server's issuer (`iss`, RFC 9207),
  then it shows "You can close this tab" and stops listening. Unanswered
  requests end after 10 minutes.
- **Device code** (`mode: "device"`, RFC 8628): the user opens a link in any
  browser (a phone works) and confirms the code `cpmesh_login` returned
  (`BCDF-GHJK`). Nothing listens locally; `cpmesh_wait_for_approval` polls
  at the server's pace (5 s, slower when it says `slow_down`). The pending
  request is kept in `authorization.json`, so restarting the MCP client does
  not lose it. Requests last 10 minutes.
- **`auto`** (the default) uses the browser unless the server runs over SSH
  (`SSH_CONNECTION`, `SSH_TTY`), in a container (`/.dockerenv`,
  `/run/.containerenv`, `container`, `CODESPACES`, `REMOTE_CONTAINERS`) or on
  Linux without `DISPLAY`/`WAYLAND_DISPLAY`, and falls back to the device code
  when the browser cannot be opened.

`cpmesh_login` returns at once with the link (and code). MCP clients that
support URL elicitation show the link to the user themselves; it is always in
the tool result too (it carries no secret). Discovery reads the server's
metadata (`/.well-known/oauth-authorization-server`); its issuer must be the
server URL, and a server that answers with its web page instead is too old for
this version.

The consent page lists the agent as it reports itself, e.g. "Claude Code via
cpmesh-mcp on laptop", and offers four scopes: `clipboard:read` and
`clipboard:write` (on by default), `clipboard:delete` and `devices:manage`
(off by default). Read and write are independent, so a send-only agent is
possible: its read tools fail with a message telling the user how to allow
reading. Calling `cpmesh_login` again re-authorizes the agent, for example
with other scopes: the device moves to the new authorization without pairing
again, and the old one ends.

Access tokens last an hour; refresh tokens are single use and last 30 days,
renewed with each refresh. The agent refreshes only at the server's
`/oauth/token`. When the server ends the session (the user revoked the agent,
signed out everywhere, or 30 days passed without use), `cpmesh_status` says
so; `cpmesh_login` signs in again and keeps the device's keys and pairing,
unless the device was removed.

**Upgrading from 0.2.** Profiles that 0.2 signed in with a password count as
signed out, and their tokens are never used again. Call `cpmesh_login` once:
the device registers again with its existing keys, the server moves it to the
new authorization, and it needs no new pairing. `CPMESH_USERNAME` and
`CPMESH_PASSWORD` are no longer read.

## Local state & security

State lives in `CPMESH_HOME` (default `~/.cpmesh/mcp`, files `0600` on Unix):

- `device.key` — identity private key (P-256, PEM; signs only: registration proofs,
  encryption-key certification, membership transitions and clipboard entries)
- `encryption.key` — static encryption private key (P-256, PEM; only receives ECDH
  group-key wraps). Created on first use for installs that predate protocol 3 and
  published to the relay with a certification by the identity key.
- `keyring.enc` — encrypted group-key keyring (same file format as the desktop app;
  KEK derived from the identity key)
- `session.json` — server URL, device identity, OAuth grant (`grant_id`,
  `client_id`, granted `scope`) and tokens. Refresh tokens are single-use: each
  refresh rotates them and writes the new pair back here, so several MCP
  processes can share one state directory. When the server ends the session,
  the tokens are cleared and the rest is kept for signing in again.
- `authorization.json` — a sign-in in progress: the pending device code (with
  its polling schedule, shared by every process using the profile), or approved
  tokens until the device has registered with them
- `verified_keys.json` — independently verified identities, authenticated membership
  epochs and revocation records. Legacy `pinned_keys.json` is not imported automatically.
- `clipboard_requests.json` — at most 32 signed, encrypted pushes and persistence receipts,
  so a retry can use the same ciphertext, signature and request ID after a restart
- `sender_clocks.json` — replay guard: the newest accepted `sent_at` per sender device,
  for entries received live over the WebSocket
- `.state.lock` — a cross-process lock with a heartbeat, held during profile mutations;
  do not remove it while an MCP process is running

The user's password and second factor never reach the agent. The loopback
sign-in's PKCE verifier and `state` live in memory only.

A self-signature is not membership authorization. New identities require independent
fingerprint verification or a transition signed by an already verified member. Signed
transitions bind the version, sender, recipient, wrapped key and complete membership.
Revoked IDs cannot be silently re-admitted; historical identities remain usable only
for earlier epochs. Keyring restoration is strict and never replaces existing-version
key material or treats corrupt files as an empty mesh.

**Protocol 3.** Device WebSockets require `X-Cpmesh-Protocol: 3` in both directions and
pairing requires `pairing_version` 3; the relay, the desktop app and this package must be
upgraded together (old peers get HTTP 426, and there is no fallback). What changed:

- Every clipboard entry is bound to its context — key version, content type, sender,
  request ID and sender clock — through AES-GCM associated data (separately for data and
  metadata), and the sender's identity key signs that context plus both ciphertexts. The
  MCP server signs everything it pushes and, before decrypting anything it reads, checks
  that the sender is a locally verified member and that its signature is valid. Entries
  pushed by devices before the upgrade carry no signature: they are still readable from
  history but reported with `authenticated: false`, and are rejected on the live path.
  Live entries must also carry a strictly increasing `sent_at` per sender (replay guard).
- Group keys are wrapped per recipient with a fresh ephemeral key against the recipient's
  **certified encryption key** (125-byte wraps), so compromising a device's long-term keys
  later does not open past wraps. The identity key only signs. A member without a
  certified encryption key cannot receive new keys: update or remove that device. Wraps
  created before the upgrade (60 bytes) remain importable for catch-up.
- Pairing compares an 8-digit code derived from nonces both sides commit to before
  revealing, so a relay that substitutes a key succeeds with probability 1e-8 per attempt
  and every failed attempt is visible. The 64-character full code is still available.

Existing meshes must explicitly verify peers with `cpmesh_verify_device`
(get the fingerprint from the peer's own identity display, not from the relay).
Automatic/required rotation then uses authenticated membership and retains historical keys.

An accepted push means **persisted**, not delivered to an online device. On a timeout,
reuse the reported `request_id` with exactly the same text; never infer success from
silence. Duplicate requests do not re-create history deleted within the relay's receipt
retention window (at least 24 hours).

`cpmesh_logout` revokes this agent's authorization on the server (`/oauth/revoke` with
its refresh token), which removes its device from the account and makes the user's other
devices rotate the group key, then erases this local profile. **Changed in 0.3:** 0.2's
logout only erased the profile and left the enrollment on the account. The user can also
revoke an agent under **Connected agents** on the dashboard. Re-enrolling after forgetting
the private key requires removing the old enrollment first. For a compromised device,
use fresh keys rather than reusing its profile. The connected agent receives decrypted
clipboard text and may forward it to its model provider under that client's policy.

## Development

```bash
cd mcp/cpmesh-mcp
npm install
npm run typecheck
npm test          # unit + golden-vector compatibility tests
npm run build
node scripts/smoke.mjs   # protocol smoke test against dist/
```

Build tooling is esbuild 0.28.2+; Node 18.19+ remains supported for the published executable.
The test runner needs Node 22.12+.

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
root, with `BASE_URL` set), and an account whose two-factor authentication is
set up on the web dashboard:

```bash
CPMESH_HOME=$(mktemp -d) node scripts/e2e-smoke.mjs http://localhost:39271 user password 123456
```

The script plays the user: it signs in to the web API with the password and the
current code from the authenticator app (or a recovery code), then approves the
agent's device-code sign-in the way the dashboard's approval page does. The agent
registers as a first device (auto-approved), pushes a clip, checks the canonical
persistence acknowledgement and retries, restarts the MCP process, and reads the
original clip back decrypted. It then re-authorizes the agent as send-only through
the browser flow, with the script as the browser (no real browser opens), checks
that reading is refused while sending works, and signs out, which must remove the
agent and its device from the account.

CI runs this against a freshly started relay and synthetic TOTP-enabled account using
`scripts/live-smoke.mjs`. See the root [contributing guide](../../CONTRIBUTING.md#dependency-constraints)
for dependency constraints and the preceding live-test setup instructions.

## License

MIT OR Apache-2.0 (same as cpmesh).
