# Contributing to cpmesh

Thank you for your interest in contributing to cpmesh! This document provides guidelines and instructions for contributing.

## Before You Start

**Every contribution must start with a GitHub issue.** Whether it's a bug fix, new feature, or documentation improvement — open an issue first (or find an existing one) so the change can be discussed before any code is written. This helps avoid duplicated effort and ensures your contribution aligns with the project's direction.

1. Open or find a related [GitHub issue](https://github.com/cjs0h/cpmesh/issues)
2. Wait for maintainer approval before starting work on larger changes
3. Fork the repository and clone your fork locally
4. Create a new branch for your feature or bug fix

## Development Setup

### Server

```bash
# Requires Rust 1.94+ and a running PostgreSQL instance
cp .env.example .env
# Generate repo-local dev JWT keys
./scripts/generate-dev-jwt.sh
# Or on Windows PowerShell:
# pwsh ./scripts/generate-dev-jwt.ps1
#
# Then edit .env with the required secrets and database credentials
cargo build -p cpmesh-server
cargo run -p cpmesh-server
```

### Web Dashboard

```bash
# Requires Node.js 22.12+ (24 LTS recommended)
cd web
npm install
npm run dev
```

### Desktop App

```bash
# Requires Node.js 22.17+ (24 LTS recommended)
cd desktop-tauri
npm install
npx tauri dev
```

## Testing

All suites run in CI; please run the ones relevant to your change locally first.

### Rust

```bash
# Server + shared proto crate: unit tests, router tests (no database needed) and wire-format tests
cargo test --workspace

# Desktop crate: crypto, key exchange, local history (SQLite), config and WebSocket client tests
cd desktop-tauri/src-tauri && cargo test
```

The server's PostgreSQL integration tests (`crates/cpmesh-server/tests/db.rs`) are skipped unless
`TEST_DATABASE_URL` is set. Each test migrates into its own throwaway schema, so any scratch
database works — for example with Docker:

```bash
docker run --rm -d --name cpmesh-test-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:55432:5432 postgres:16-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55432/postgres cargo test -p cpmesh-server --test db
docker rm -f cpmesh-test-pg
```

Lints are enforced with warnings denied, so also run:

```bash
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
cd desktop-tauri/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings
```

### Frontends

Both frontends use [Vitest](https://vitest.dev/) for unit tests and `svelte-check` for type checking:

```bash
cd web && npm run check && npm test
cd desktop-tauri && npm run check && npm test
```

Tests live next to the code they cover (`*.test.ts`). Modules that use Svelte runes must be
tested from a `*.svelte.test.ts` file so the runes are compiled.

#### Web dashboard UI conventions

- The visual language is **minimal monochrome**: white surfaces, 1px `#e5e5e5` hairlines
  (`border border-border`), near-black text, Geist for UI text and Geist Mono for identifiers/code.
  Primary actions are solid black (`Button` default); the single coral accent (`text-accent`,
  `bg-accent`) is reserved for live indicators and small points of emphasis — never for large fills.
  Semantic states use the muted `success` / `warning` / `danger` tokens.
- Design tokens live in `web/src/app.css` (`@theme`): surfaces (`bg-bg`, `bg-bg-deep`, `bg-surface`,
  `bg-surface-2`, `bg-surface-3`), borders (`border-border`, `border-border-strong`), text (`text-fg`,
  `text-ink`, `text-muted`, `text-dim`) and the accent/semantic colours. Prefer these over raw hex values.
  Shadows are faint (`shadow-xs/sm/md/lg`) and used sparingly; there are no gradients or glows.
- Reusable primitives are in `web/src/components/ui/` (`Button`, `Card`, `Badge`, `Field`, `Select`, `Switch`,
  `Dialog`, `ConfirmAction`, `EmptyState`, `Alert`, `StatCard`, `Toaster`, …). Reach for these before
  hand-writing utility strings; page files should mostly be layout and data wiring. Use `.cell-grid`
  for feature/stat grids that should only show hairlines *between* cells, and `.tbl` for data tables.
- Motion is intentional and minimal: the only sustained animation is the `SyncDemo` product demo on the
  landing page (transform/opacity only, static frame under `prefers-reduced-motion`). Everything else is
  limited to ~150ms colour/border hover transitions. Do not add scroll-reveal, parallax, blur or
  background-plane animations; content must be visible immediately on load.
- Layout: the landing page uses the `.wrap` container (1200px, growing to 1360px/1520px on large
  monitors) with full-bleed hairline section dividers, and the app shell grows to 1600px, so wide screens
  do not feel boxed. Give every responsive grid an explicit `grid-cols-1` so single-column tracks cannot
  exceed the viewport.
- Mount-time data loading belongs in `onMount`, not `$effect`, so store reads inside the fetch
  (for example the clipboard `offset`) do not become reactive dependencies that re-trigger the load.
- User feedback goes through the `toast` store (`lib/stores/toast.svelte.ts`).

## Submitting Changes

1. Make sure your code compiles without warnings (`cargo check`, `cargo clippy`)
2. Add or update tests for your change and make sure the relevant suites pass
3. Commit your changes with a clear, descriptive commit message
4. Push to your fork and submit a pull request

## Pull Request Guidelines

- **Reference the GitHub issue** in your PR description (e.g., `Closes #42`)
- Keep PRs focused on a single change
- Describe what the PR does and why
- Make sure CI passes
- PRs without a linked issue may be closed

## Reporting Bugs

Open an issue on GitHub with:

- A clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Rust version, etc.)

## License

By contributing to cpmesh, you agree that your contributions will be dual licensed under the MIT and Apache 2.0 licenses. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.
