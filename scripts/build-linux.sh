#!/usr/bin/env bash
# build-linux.sh — Build cpmesh Tauri desktop app for Linux (.deb + .AppImage)
# Run from the project root: ./scripts/build-linux.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# The app version, kept in step with releases by scripts/release/set-version.mjs
VERSION="$(grep -m1 '"version"' "$ROOT/desktop-tauri/src-tauri/tauri.conf.json" | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"

echo "=== Building cpmesh $VERSION for Linux ==="

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

# Check Linux system dependencies (Debian/Ubuntu)
if command -v dpkg >/dev/null 2>&1; then
    DEPS="libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev pkg-config patchelf"
    for pkg in $DEPS; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            MISSING="$MISSING\n  - $pkg"
        fi
    done
fi

if [ -n "$MISSING" ]; then
    echo ""
    echo "The following prerequisites are missing:"
    echo -e "$MISSING"
    if command -v apt-get >/dev/null 2>&1; then
        echo ""
        echo "For system libraries, run:"
        echo "  sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev pkg-config patchelf"
    fi
    echo ""
    exit 1
fi

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    aarch64) ARCH_LABEL="arm64" ;;
    x86_64)  ARCH_LABEL="amd64" ;;
    *)       ARCH_LABEL="$ARCH" ;;
esac

# Install frontend dependencies when they are missing or out of date with package-lock.json
cd "$ROOT/desktop-tauri"
if ! node "$ROOT/scripts/check-deps.mjs"; then
    echo "Installing frontend dependencies with npm ci..."
    npm ci
fi

# Build Tauri app — deb + AppImage
echo "Building Tauri app (release)..."
cargo tauri build -b deb appimage

# Copy outputs to downloads/
mkdir -p "$ROOT/downloads"

DEB=$(find "$ROOT/desktop-tauri/src-tauri/target/release/bundle/deb" -name "*.deb" 2>/dev/null | head -1)
if [ -n "$DEB" ]; then
    DEST="$ROOT/downloads/cpmesh-desktop-${VERSION}-linux-${ARCH_LABEL}.deb"
    cp "$DEB" "$DEST"
    SIZE=$(du -h "$DEST" | cut -f1)
    echo "  Installer: $DEST ($SIZE)"
else
    echo "ERROR: Build failed — no .deb found" >&2
    exit 1
fi

echo ""
echo "=== Linux build complete ==="
