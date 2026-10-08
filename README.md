# cpmesh

[![Server CI](https://github.com/cjs0h/cpmesh/actions/workflows/server.yml/badge.svg)](https://github.com/cjs0h/cpmesh/actions/workflows/server.yml)
[![Web CI](https://github.com/cjs0h/cpmesh/actions/workflows/web.yml/badge.svg)](https://github.com/cjs0h/cpmesh/actions/workflows/web.yml)
[![Desktop CI](https://github.com/cjs0h/cpmesh/actions/workflows/desktop.yml/badge.svg)](https://github.com/cjs0h/cpmesh/actions/workflows/desktop.yml)

> **Warning:** This project is under heavy development and has not reached a stable release. APIs, configuration, and behavior may change without notice. Use at your own risk.

**Website:** [cpmesh.com](https://cpmesh.com) | **Source:** [GitHub](https://github.com/cjs0h/cpmesh)

Cross-platform encrypted clipboard sharing. Copy on one device, paste on any other instantly and securely.

## What is cpmesh?

cpmesh is a self-hosted clipboard sync tool with end-to-end encryption. It lets you share clipboard content (text, images, files) across your devices in real time over WebSocket, with the server never seeing your plaintext data.

- **End-to-end encrypted** — AES-256-GCM encryption with ECDH P-256 key exchange. The relay server stores only ciphertext.
- **Real-time sync** — WebSocket push delivery. Copy on one device, paste on another in under a second.
- **Cross-platform** — Desktop app (Tauri) for Windows, macOS, and Linux, plus a web dashboard.
- **Self-hosted** — Run the relay server on your own infrastructure. Single binary + PostgreSQL. Docker Compose ready.

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

**Encryption flow:**
1. Each device generates an ECDH P-256 key pair. The public key is registered with the server.
2. The first device creates a random 256-bit group key and encrypts it for every other device using ECDH.
3. All clipboard data is encrypted with the group key (AES-256-GCM via HKDF derivation) before leaving the device.
4. The server relays encrypted blobs. It cannot decrypt anything.

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
# Requires Rust 1.94+ and a running PostgreSQL instance
cp .env.example .env
./scripts/generate-dev-jwt.sh
# Fill the required values in .env, then:
cargo build --release -p cpmesh-server
./target/release/cpmesh-server
```

### 5. Install the desktop app

Download the latest release from the [Releases page](https://github.com/cjs0h/cpmesh/releases) or build from source:

```bash
# Requires Rust 1.94+, Node.js 22.17+ (24 LTS recommended), and Tauri CLI
cd desktop-tauri
npm install
npx tauri build
```

### 6. Log in and connect

Open the desktop app, enter your server URL and the admin credentials from your `.env`, and click Connect. The app runs in your system tray, so closing the window hides it instead of quitting.

## Components

| Component | Location | Tech | Description |
|-----------|----------|------|-------------|
| Server | `crates/cpmesh-server/` | Rust, Axum, SQLx, PostgreSQL | REST API, WebSocket relay, and web dashboard host |
| Shared Proto | `crates/cpmesh-proto/` | Rust | Shared WebSocket message types and API request/response types |
| Desktop App | `desktop-tauri/` | Rust, Tauri v2, SvelteKit 3 | Desktop client with tray integration and local device state |
| Web Dashboard | `web/` | Svelte 5, TypeScript, Vite 8, Tailwind CSS 4 | Landing page, sign-in, device management, live clipboard history, and admin console |

## Testing

Every component ships with an automated test suite; see [CONTRIBUTING.md](CONTRIBUTING.md#testing) for details.

```bash
cargo test --workspace                       # server + shared proto (unit, router and wire-format tests)
cd desktop-tauri/src-tauri && cargo test     # desktop crypto, history, config and protocol tests
cd web && npm test                           # web dashboard (Vitest)
cd desktop-tauri && npm test                 # desktop frontend (Vitest)
```

The PostgreSQL-backed integration tests in `crates/cpmesh-server/tests/db.rs` run only when
`TEST_DATABASE_URL` points at a database you can create schemas in; otherwise they are skipped.

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

## Content types

| Type | Max Size | Description |
|------|----------|-------------|
| Text | 1 MB | Plain text, URLs, code snippets |
| Image | 10 MB | PNG screenshots and images |
| File | 25 MB | Arbitrary file data with metadata |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution Licensing

For development and submission guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
