# Contributing to cpmesh

Thank you for your interest in contributing to cpmesh! This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a new branch for your feature or bug fix

## Development Setup

### Server

```bash
# Requires Rust 1.75+ and a running PostgreSQL instance
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
cd web
npm install
npm run dev
```

### Desktop App

```bash
cd desktop-tauri
npm install
npx tauri dev
```

## Submitting Changes

1. Make sure your code compiles without warnings (`cargo check`, `cargo clippy`)
2. Test your changes locally
3. Commit your changes with a clear, descriptive commit message
4. Push to your fork and submit a pull request

## Pull Request Guidelines

- Keep PRs focused on a single change
- Describe what the PR does and why
- Link any related issues
- Make sure CI passes

## Reporting Bugs

Open an issue on GitHub with:

- A clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Rust version, etc.)

## License

By contributing to cpmesh, you agree that your contributions will be dual licensed under the MIT and Apache 2.0 licenses. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.
