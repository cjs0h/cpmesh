#!/usr/bin/env bash
# build-mac.sh — Build cpmesh Tauri desktop app for macOS (.dmg + .app)
# Run from the project root: ./scripts/build-mac.sh
set -euo pipefail

VERSION="0.1.0"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Building cpmesh $VERSION for macOS ==="

# ── Pre-flight checks ──
MISSING=""

if ! command -v cargo >/dev/null 2>&1; then
    MISSING="$MISSING\n  - Rust (install from https://rustup.rs)"
fi

if ! command -v node >/dev/null 2>&1; then
    MISSING="$MISSING\n  - Node.js LTS (install from https://nodejs.org)"
fi

if command -v cargo >/dev/null 2>&1 && ! cargo tauri --version >/dev/null 2>&1; then
    MISSING="$MISSING\n  - Tauri CLI (run: cargo install tauri-cli --locked)"
fi

if [ -n "$MISSING" ]; then
    echo ""
    echo "The following prerequisites are missing:"
    echo -e "$MISSING"
    echo ""
    exit 1
fi

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    arm64|aarch64) ARCH_LABEL="arm64" ;;
    x86_64)        ARCH_LABEL="amd64" ;;
    *)             ARCH_LABEL="$ARCH" ;;
esac

# Install frontend dependencies if needed
cd "$ROOT/desktop-tauri"
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

# Build Tauri app (runs npm build automatically via beforeBuildCommand)
# Use --bundles app to skip Tauri's DMG bundler (has a known bug in CLI 2.x
# where bundle_dmg.sh is invoked without arguments), then create DMG manually.
echo "Building Tauri app (release)..."
cargo tauri build --bundles app

# Locate the .app bundle
APP_DIR="$ROOT/desktop-tauri/src-tauri/target/release/bundle/macos"
APP_PATH=$(find "$APP_DIR" -maxdepth 1 -name "*.app" -type d 2>/dev/null | head -1)
if [ -z "$APP_PATH" ]; then
    echo "ERROR: Build failed — no .app bundle found" >&2
    exit 1
fi
APP_NAME=$(basename "$APP_PATH")

# Create DMG installer with hdiutil
echo "Creating DMG installer..."
mkdir -p "$ROOT/downloads"
DEST="$ROOT/downloads/cpmesh-${VERSION}-darwin-${ARCH_LABEL}.dmg"
rm -f "$DEST"

STAGE=$(mktemp -d)
cp -R "$APP_PATH" "$STAGE/$APP_NAME"
ln -s /Applications "$STAGE/Applications"

hdiutil create -volname "cpmesh" \
    -srcfolder "$STAGE" \
    -ov -format UDZO \
    "$DEST"

rm -rf "$STAGE"

SIZE=$(du -h "$DEST" | cut -f1)
echo "  Installer: $DEST ($SIZE)"

echo ""
echo "=== macOS build complete ==="
