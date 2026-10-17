# cpmesh

[![Server CI](https://github.com/cjs0h/cpmesh/actions/workflows/server.yml/badge.svg)](https://github.com/cjs0h/cpmesh/actions/workflows/server.yml)
[![Web CI](https://github.com/cjs0h/cpmesh/actions/workflows/web.yml/badge.svg)](https://github.com/cjs0h/cpmesh/actions/workflows/web.yml)
[![Desktop CI](https://github.com/cjs0h/cpmesh/actions/workflows/desktop.yml/badge.svg)](https://github.com/cjs0h/cpmesh/actions/workflows/desktop.yml)
[![Built with AI, supervised by an experienced engineer](https://img.shields.io/badge/built_with_AI-engineer_supervised-ff5c38)](#how-cpmesh-is-built)

> **Warning:** This project is under heavy development and has not reached a stable release. APIs, configuration, and behavior may change without notice. Use at your own risk.

**Website:** [cpmesh.com](https://cpmesh.com) | **Source:** [GitHub](https://github.com/cjs0h/cpmesh)

Cross-platform encrypted clipboard sharing. Copy on one device, paste on any other instantly and securely.

## What is cpmesh?

cpmesh is a self-hosted clipboard sync tool with end-to-end encryption. It lets you share clipboard content (text, images, files) across your devices in real time over WebSocket, with the server never seeing your plaintext data.

- **End-to-end encrypted** — AES-256-GCM with per-entry keys, every entry bound to its context and signed by the sending device. Group keys travel in ephemeral ECDH P-256 wraps to identity-certified encryption keys. The relay server stores only ciphertext.
- **Real-time sync** — WebSocket push delivery. Copy on one device, paste on another in under a second.
- **Cross-platform** — Desktop app (Tauri) for Windows, macOS, and Linux, plus a web dashboard.
- **Self-hosted** — Run the relay server on your own infrastructure. Single binary + PostgreSQL. Docker Compose ready.
- **Two-factor authentication** — Every sign-in is confirmed with an authenticator app code (TOTP) or a passkey, with recovery codes as a fallback.

## Architecture

```
┌──────────────────────┐
│   cpmesh Server      │  Rust binary (Axum) + PostgreSQL
│   (relay + API)      │  Stores encrypted data only
│   + Web Dashboard    │  Svelte SPA served at /
└──────┬───────────────┘
       │ WebSocket + REST API
       │
  ┌────┴──────────────────────────┐
  │                               │
Desktop App                  Browser
(Tauri+SvelteKit)            (Web dashboard)
```

**Encryption flow (protocol 3):**
1. Each device has two P-256 keys: an **identity key** that only signs, and an **encryption key** that only does ECDH and is certified by the identity key. The identity key proves possession with a single-use, session-bound challenge before the device receives device-bound access and refresh tokens; the identity and encryption private keys live in the OS credential store on desktop.
2. The first device creates a random 256-bit group key. Other devices join through committed short-code pairing: both devices show the same 8-digit code (derived from nonces each side commits to before seeing the other's, plus both identity keys) and the user confirms on both; a 64-character full code is available for a stronger manual check. An authenticated membership transition then rotates the key and wraps it for every approved member using a fresh ephemeral key per recipient, so a later theft of long-term keys does not open past wraps.
3. Clipboard data and metadata are encrypted with a per-entry key derived from the group key (AES-256-GCM via HKDF). The ciphertexts are bound to the key version, content type, sender, request ID and sender clock, and the sending device signs that context together with both ciphertexts.
4. Receivers accept an entry only from a member they pinned themselves, only with a valid sender signature, and only with a strictly increasing sender clock; the relay can neither relabel, splice, re-attribute nor replay entries. The relay still sees content type, encrypted size, device identity and timing.

## Quick Start

### 1. Clone the repo and create local config

```bash
git clone https://github.com/cjs0h/cpmesh
cd cpmesh
cp .env.example .env
./scripts/generate-dev-jwt.sh
# Or on Windows PowerShell:
# pwsh ./scripts/generate-dev-jwt.ps1
```

The helper script writes development JWT material to `./.dev/jwt/`. That directory is ignored by git and should not be committed.

### 2. Fill the required secrets in `.env`

At minimum, set:

- `PII_MASTER_KEY` and `PII_HMAC_KEY` to base64-encoded 32-byte values
- `INITIAL_ADMIN_PASSWORD` to the password you want for the bootstrap admin account
- `INITIAL_ADMIN_EMAIL`, `BASE_URL`, and `ALLOWED_ORIGINS` for your environment

You can generate the PII keys with:

```bash
openssl rand -base64 32
openssl rand -base64 32
```

### 3. Start the stack

```bash
docker compose up -d
```

The server listens on port `8080` inside the container. The default Docker Compose mapping exposes the dashboard at `http://localhost:39271`.

### 4. Build from source (optional)

The server can also be built and run directly:

```bash
# Requires Rust 1.94+, Node.js 22.12+ and a running PostgreSQL instance
cp .env.example .env
./scripts/generate-dev-jwt.sh
# Fill the required values in .env, then:
npm --prefix web ci
npm --prefix web run build    # web/dist is embedded by RustEmbed at compile time
cargo build --release -p cpmesh-server
./target/release/cpmesh-server
```

### 5. Install the desktop app

Download the latest release from the [Releases page](https://github.com/cjs0h/cpmesh/releases) or the Downloads section on [cpmesh.com](https://cpmesh.com) (installers for Windows, macOS, Linux and Android are published by the Release workflow, see [Releasing](CONTRIBUTING.md#releasing)), or build from source:

```bash
# Requires Rust 1.94+, Node.js 22.17+ (24 LTS recommended), and Tauri CLI
cd desktop-tauri
npm install
npx tauri build
```

### 6. Log in and connect

Sign in to the web dashboard (`http://localhost:39271`) with the admin credentials from your `.env`. Every account needs
two-factor authentication, so the first sign-in walks you through setting up an authenticator app or a passkey and shows
your recovery codes (see [Two-factor authentication](#two-factor-authentication)).

Then open the desktop app, enter your server URL and click Connect: sign in with your password and the code from your
authenticator app, or choose **Sign in with browser** to use a passkey or SSO. The app runs in your system tray, so
closing the window hides it instead of quitting. Press `Ctrl+Shift+Space` (`⇧⌘Space` on macOS) to bring it back from
any app, or change or turn off that shortcut under **Settings → Keyboard shortcuts**. Wayland desktops may not pass app
shortcuts on; there, Settings shows a command to bind in your desktop's own keyboard settings instead.

## Components

| Component | Location | Tech | Description |
|-----------|----------|------|-------------|
| Server | `crates/cpmesh-server/` | Rust, Axum, SQLx, PostgreSQL | REST API, WebSocket relay, and web dashboard host |
| Shared Proto | `crates/cpmesh-proto/` | Rust | Shared WebSocket message types and API request/response types |
| Desktop App | `desktop-tauri/` | Rust, Tauri v2, SvelteKit 3, Tailwind CSS 4 | Desktop client with tray integration, light/dark themes and local device state |
| Web Dashboard | `web/` | Svelte 5, TypeScript, Vite 8, Tailwind CSS 4 | Landing page, sign-in with two-factor authentication, device management, live clipboard history, and admin console |
| MCP Server | `mcp/cpmesh-mcp/` | TypeScript, MCP SDK | Lets AI agents use cpmesh: share clipboard text, read history, manage devices |

## AI agents (MCP)

cpmesh ships an MCP server (`cpmesh-mcp`, published to npm) that lets AI agents
share clipboard text with your devices, read and search clipboard history, and
manage devices — with the same end-to-end encryption and device-approval
pairing as the desktop app. The server acts as its own cpmesh device and keeps
its keys locally; the relay only ever sees ciphertext.

Add it to any stdio MCP client (Claude Desktop, Cursor, ZCode, ...):

```json
{
  "mcpServers": {
    "cpmesh": {
      "command": "npx",
      "args": ["-y", "cpmesh-mcp"],
      "env": { "CPMESH_SERVER_URL": "https://cpmesh.com" }
    }
  }
}
```

`https://cpmesh.com` is the hosted service; point `CPMESH_SERVER_URL` at your own
server if you self-host.

On first use the agent asks for your credentials and the 6-digit code from your
authenticator app (or a recovery code; the MCP server cannot use passkeys, so add
an authenticator app under **Settings → Two-factor authentication** if a passkey
is your only second factor), then walks you through device pairing. Both devices show the
same 8-digit pairing code (the full 64-character code is available for a stronger check);
confirm on both devices only if the codes are identical. The agent uses `cpmesh_confirm_pairing`
before waiting for approval.
Full agent instructions live in
[`mcp/cpmesh-mcp/SKILL.md`](mcp/cpmesh-mcp/SKILL.md) — install that file into
your agent's skills directory (e.g. `~/.agents/skills/cpmesh/`), or let the
agent pull them from the `cpmesh_skill` MCP prompt. See
[`mcp/cpmesh-mcp/README.md`](mcp/cpmesh-mcp/README.md) for the complete tool
reference.

## Two-factor authentication

Signing in takes a password (or SSO) plus a second factor:

- **Authenticator app (TOTP)** — any RFC 6238 app (1Password, Google Authenticator, Aegis, ...). Works everywhere:
  the web dashboard, the desktop app and the MCP server.
- **Passkey** — a WebAuthn credential (Touch ID, Windows Hello, a security key, a synced passkey). Passkeys belong to
  the site's domain, so they are used in the browser; the desktop app's **Sign in with browser** button hands a browser
  sign-in back to the app.
- **Recovery codes** — ten single-use codes shown when the first factor is set up. Store them somewhere safe.

`MFA_REQUIRED=all` (the default) requires a second factor for every account: an account without one sets it up during
its next sign-in. When SMTP is configured, a password sign-in must first confirm a code emailed to the account, so a
leaked password alone cannot enroll someone else's authenticator. `MFA_REQUIRED=staff` limits the requirement to staff
accounts and lets everyone else opt in. Sessions that existed before two-factor authentication keep working; members
manage their factors under **Settings → Two-factor authentication**.

After 10 wrong codes in a row the account's second factor locks for 15 minutes. Adding or removing a factor, and
sensitive admin actions, need a recent sign-in: the dashboard asks you to confirm your second factor again.
Administrators can reset a member's two-factor authentication (for a lost phone); the member sets it up again at their
next sign-in and gets an email about it.

Changing a password ends all sessions, including the initiating session and live sockets. Refresh
and step-up preserve the original session issuance time, so an in-flight refresh cannot evade revocation.

## Secure-sync upgrade and compatibility

Upgrade the relay, desktop apps and MCP package together, and reload the web dashboard. This is an
intentional protocol boundary, not a transparent mixed-version rollout. Existing ciphertext and
encrypted-keyring byte formats stay readable, but unsafe authorization paths are not retained.

Before upgrading, back up each device's private keys, encrypted keyring and local history. Legacy
`pinned_keys.json` files were trust-on-first-use and are **not** silently promoted to authenticated
membership. On an existing mesh, use the desktop **Devices** page or MCP `cpmesh_verify_device` to
compare a peer's complete public-key fingerprint directly with that peer's own identity display.
After verification, clients rotate to an authenticated membership and learn later approved members
through signed transitions. Don't delete keyring files to get past an error: a missing wrapped copy is
not evidence of a new mesh, and lost historical key material cannot be regenerated. The desktop app
handles each of these situations itself (see [Recovering keys in the desktop app](#recovering-keys-in-the-desktop-app)).

Device WebSockets negotiate `X-Cpmesh-Protocol: 3` in both directions. Older devices receive HTTP 426;
updated clients refuse relays that do not confirm this version. Browser metadata sockets and the public
download/update endpoints remain available, including to apps downloading an upgrade. Registration and
reconnection require a session-bound proof; an unbound refresh token cannot select an approved device ID.
The legacy group-key GET remains readable, but legacy writes and non-committed pairing return HTTP 426.
Every 426 says what the client is missing, and that a previous version still running after an update
has to be quit from its tray (menu bar) icon and opened again.

**Protocol 3 changes.** On first start, each updated device moves its `device.key` into the OS
credential store (Keychain, Credential Manager or Secret Service; a 0600 file when none is available),
generates a separate encryption key certified by its identity key, and publishes that certification.
Key rotation now wraps only to certified encryption keys, so a mesh cannot rotate until every approved
member has been updated — remove devices you no longer use. New wraps are 125 bytes (ephemeral key,
nonce, ciphertext, tag); wraps created before the upgrade remain importable for catch-up. Clipboard
pushes carry `sent_at` and `sender_signature`; the relay verifies the signature against the sending
device's identity key and refuses unsigned pushes, and receivers verify it again themselves. Entries
stored before the upgrade are unsigned: they still decrypt for history display, are marked
unauthenticated, and are never written to the clipboard.

Removing a device closes its socket and blocks old-key writes until rotation. Clients persist verified
epochs and revocation records, reject known rollbacks/re-admissions, and retain historical keys. Removal
cannot erase plaintext or keys a device already copied. For a lost or compromised device, use fresh
private keys when enrolling its replacement; do not reuse the compromised profile. A relay can still
withhold traffic, and this protocol is not a ratcheting protocol with retroactive erasure: ephemeral
wraps protect past key distribution against a later theft of long-term keys, but the encrypted keyring
on each device still holds every historical group key so that history stays readable.

Clipboard pushes carry a UUID `request_id`. A `clipboard_ack` confirms database persistence and returns
the canonical entry ID, or reports rejection/uncertain persistence. It is **not** proof that another device
received the clipboard. Retries reuse the identical request and ID; relay receipts survive history deletion
for at least 24 hours, and MCP retains up to 32 encrypted requests/receipts for restart-safe retries.

### Updating the desktop app

cpmesh keeps running in the tray after its window is closed, so an update (a package upgrade, the in-app updater's
installer or a new AppImage) leaves the previous version running until it restarts. Opening cpmesh again starts the new
version: on Linux, launching an upgraded package ends your previous version still running the replaced binary (never
another user's); otherwise the running version restarts into the new one with the launch's arguments (a `cpmesh://`
sign-in link stays with the version that started the sign-in). While the window is open, a **Restart now** banner appears
once a newer version is installed. Versions up to 0.4.0 do neither: if a server answers "update your client" (HTTP 426)
right after you installed an update, quit cpmesh from its tray (menu bar) icon and open it again.

### Recovering keys in the desktop app

These situations used to need hand-edited files or database resets. The app walks through each one, asks before every
change, never uses one account's keys for another and never deletes key material: what it moves out of the way goes into
a folder in its data folder (`backups/` or `archive/`), and **Settings → Encryption keys** restores from there.

| Situation | What the app offers |
| --- | --- |
| Keys saved by a version before 0.3, whose account nothing records (signing out on those versions cleared it) | At sign-in: use them for the account signing in (it shows whether one of that account's devices has this computer's device key), or set them aside in `backups/` |
| Keys of another account, when signing in to another server or account | At sign-in: archive them in `archive/<server>_<user>_<time>/`; they come back when that account signs in on this computer again |
| Keys this device can't open, because its device key changed | At sign-in: set them aside; restore them later with the old `device.key` |
| "This computer is already registered with different keys" (HTTP 409) | At sign-in: replace that registration. If it was the account's only approved device, the app warns that it held the only copy of the encryption key, and removes devices waiting for approval along with it (they can ask again): only a registration on an account without devices is approved by itself |
| "This device doesn't have your account's current encryption key" | **Settings → Encryption keys** (also offered by a banner): verify this device on another device that still has the key, which then shares it; restore it from a backup (one cpmesh made, or a folder with `keyring.enc` and the `device.key` that was next to it), re-encrypted for this device and checked against your clipboard history; or, as a last resort, start new encryption keys |

Starting new encryption keys needs every other approved device verified on this device or removed, since each one gets
the new key. Clips synced before stay unreadable on devices without the old key, though restoring a backup later still
opens them. It is never automatic, and it replaces resetting `group_key_versions` in the database by hand.

## Admin console

Staff accounts see the admin console in the web dashboard. It requires a session confirmed with a second factor, and
what each person can do depends on their role:

| Role | Can |
|------|-----|
| Viewer | See users, statistics, the audit log, plans, releases and settings |
| Support | Viewer, plus verify emails, change plans, suspend and reinstate members, and sign them out everywhere |
| Admin | Support, plus delete users, reset two-factor authentication, manage plans, downloads, releases, settings and API tokens |
| Owner | Admin, plus change roles and act on other staff accounts |

The `INITIAL_ADMIN` account (and anyone who was an admin before roles existed) is an owner. The server always keeps at
least one owner. Mutation handlers await their audit writes; failures are reported in server logs rather than
discarded silently. The audit log also shows sign-ins and security changes per user.

**Settings** can override `REGISTRATION_OPEN` and show an announcement banner at runtime. **API tokens** let automation
publish releases without an interactive sign-in: a token (scope `releases:write`) only works on the downloads and
releases endpoints, acts as the staff member who created it, and can expire or be revoked. The Release workflow uses
one (see [Releasing](CONTRIBUTING.md#releasing)).

The downloads page and the apps' update check are what users install from, so protect them:

- set `UPDATER_PUBLIC_KEY` to the contents of `desktop-tauri/src-tauri/updater-key.pub`, and installers uploaded to the
  server must carry a valid signature from the release key;
- set `DOWNLOAD_URL_PREFIXES` (for example `https://github.com/cjs0h/cpmesh/releases/download/`), and download links and
  releases can only point there or at files uploaded to the server.

On a public deployment, consider also putting `/api/admin/` behind an access proxy or VPN.

## Testing

Every component ships with an automated test suite; see [CONTRIBUTING.md](CONTRIBUTING.md#testing) for details.

```bash
npm --prefix web ci && npm --prefix web run build  # required before Cargo on a clean checkout
cargo test --workspace                       # server + shared proto (unit, router and wire-format tests)
cd desktop-tauri/src-tauri && cargo test     # desktop crypto, history, config and protocol tests
cd web && npm test                           # web dashboard (Vitest)
cd desktop-tauri && npm test                 # desktop frontend (Vitest)
cd mcp/cpmesh-mcp && npm test                # MCP server crypto, API client and two-factor sign-in (Vitest)
```

The PostgreSQL-backed integration tests in `crates/cpmesh-server/tests/db.rs` run only when
`TEST_DATABASE_URL` points at a database you can create schemas in; otherwise they are skipped.
MCP CI also runs the published executable against the real relay, including mandatory MFA, proof of
possession, acknowledgements, idempotent retry, restart and bounded streaming downloads.

## Configuration

### Server environment variables

JWT signing uses explicit RS256 key material in every environment. `JWT_PUBLIC_KEYS_PATH` must point to a JSON array shaped like `[{"kid":"...","pem":"..."}]`.

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://cpmesh:cpmesh@localhost:5432/cpmesh?sslmode=disable` | PostgreSQL connection string |
| `JWT_ACTIVE_KID` | *(required)* | Key ID to place in JWT headers |
| `JWT_PRIVATE_KEY_PATH` | *(required)* | Path to the RS256 private signing key PEM |
| `JWT_PUBLIC_KEYS_PATH` | *(required)* | Path to the JSON file containing public verification keys |
| `ADDR` | `0.0.0.0:8080` | Server listen address |
| `DOWNLOADS_DIR` | `./downloads` | Directory with pre-built binaries for the download page |
| `ALLOWED_ORIGINS` | `""` | Comma-separated CORS origins (empty = same-origin only) |
| `PII_MASTER_KEY` | *(required)* | Base64-encoded 32-byte AES key for PII encryption at rest |
| `PII_HMAC_KEY` | *(required)* | Base64-encoded 32-byte HMAC key for blind indexes |
| `INITIAL_ADMIN` | `""` | Create an admin user on first run |
| `INITIAL_ADMIN_PASSWORD` | `""` | Password for the initial admin |
| `INITIAL_ADMIN_EMAIL` | `""` | Email for the initial admin |
| `CPNET_INSECURE_DEV` | `0` | Set to `1` to bypass PII and weak-password checks in development; JWT key configuration is still required |
| `SMTP_HOST` | `""` | SMTP server for email verification (empty = disabled) |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | `""` | SMTP username |
| `SMTP_PASSWORD` | `""` | SMTP password |
| `SMTP_FROM` | `""` | Sender address for emails |
| `SMTP_TLS` | `true` | Use TLS for SMTP |
| `BASE_URL` | `""` | Public base URL for email links and redirects (for example `https://cpmesh.example.com`) |
| `REGISTRATION_OPEN` | `true` | Allow self-service registration |
| `OIDC_ISSUER_URL` | `""` | OIDC issuer URL (empty = disabled) |
| `OIDC_CLIENT_ID` | `""` | OIDC client ID |
| `OIDC_CLIENT_SECRET` | `""` | OIDC client secret |
| `OIDC_CALLBACK_URL` | `""` | OIDC callback URL |
| `TRUST_PROXY_HEADERS` | `0` | Trust forwarded proxy headers for scheme and host detection |
| `GROUP_KEY_ROTATION_INTERVAL_HOURS` | `24` | Automatic group key rotation interval |
| `MFA_REQUIRED` | `all` | Who must use two-factor authentication: `all` accounts, or only `staff` (the admin console always requires it) |
| `WEBAUTHN_RP_ID` | host of `BASE_URL` | Passkey relying party ID (a domain); passkeys are unavailable when neither is set |
| `WEBAUTHN_ORIGINS` | `""` | Extra origins (comma-separated) passkey ceremonies may run on, besides the `BASE_URL` origin |
| `UPDATER_PUBLIC_KEY` | `""` | Contents of the apps' `updater-key.pub`; when set, uploaded installers need a valid signature |
| `DOWNLOAD_URL_PREFIXES` | `""` | Comma-separated URL prefixes download links and releases may use (empty = any http(s) URL) |

## Content types

| Type | Max Size | Description |
|------|----------|-------------|
| Text | 1 MiB | Plain text, URLs, code snippets |
| Image | 10 MiB | Encoded PNG screenshots and images |
| File | 25 MiB | Arbitrary file data with metadata |

The relay allows the 44-byte encryption overhead in addition to these limits and caps encoded metadata
at 16 KiB. Device queues hold at most eight messages, share a 64 MiB per-user byte budget, and have a
five-second write deadline. Slow consumers disconnect and recover from persisted history. Ciphertext
history pages are byte-bounded; the browser requests size/metadata projections instead of ciphertext.
Installer downloads stream with single byte-range support and cache validators.

## How cpmesh is built

cpmesh is built using AI, under the supervision of an experienced software engineer. AI coding agents write and change the code; the engineer sets the architecture and the security model, directs the work, and reviews it before it is merged.

The same safeguards apply as for any other project: each component has automated tests that run in CI (see [Testing](#testing)), and security issues can be reported as described in [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution Licensing

For development and submission guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
