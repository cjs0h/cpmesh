#!/usr/bin/env bash
# build-android.sh — Build cpmesh Tauri app for Android (APK)
# Run from the project root: ./scripts/build-android.sh
#
# Prerequisites:
#   - Rust + Android targets: rustup target add aarch64-linux-android armv7-linux-androideabi
#   - Node.js LTS
#   - Tauri CLI: cargo install tauri-cli --locked
#   - Android SDK (via Android Studio or sdkmanager)
#   - Android NDK (version 25+)
#   - Java 17+
#   - ANDROID_HOME and ANDROID_NDK_HOME environment variables set
#
# Optional: pass --aab to build Android App Bundle instead of APK
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# The app version, kept in step with releases by scripts/release/set-version.mjs
VERSION="$(grep -m1 '"version"' "$ROOT/desktop-tauri/src-tauri/tauri.conf.json" | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"
BUILD_AAB=false

for arg in "$@"; do
    case "$arg" in
        --aab) BUILD_AAB=true ;;
    esac
done

echo "=== Building cpmesh $VERSION for Android ==="

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

if [ -z "${ANDROID_HOME:-}" ]; then
    # Try common locations
    if [ -d "$HOME/Android/Sdk" ]; then
        export ANDROID_HOME="$HOME/Android/Sdk"
    elif [ -d "$HOME/Library/Android/sdk" ]; then
        export ANDROID_HOME="$HOME/Library/Android/sdk"
    else
        MISSING="$MISSING\n  - ANDROID_HOME not set (install Android SDK via Android Studio)"
    fi
fi

if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -n "${ANDROID_HOME:-}" ]; then
    # Auto-detect NDK
    NDK_DIR="$ANDROID_HOME/ndk"
    if [ -d "$NDK_DIR" ]; then
        LATEST_NDK=$(ls -1 "$NDK_DIR" 2>/dev/null | sort -V | tail -1)
        if [ -n "$LATEST_NDK" ]; then
            export ANDROID_NDK_HOME="$NDK_DIR/$LATEST_NDK"
        fi
    fi
    if [ -z "${ANDROID_NDK_HOME:-}" ]; then
        MISSING="$MISSING\n  - Android NDK (install via: sdkmanager 'ndk;25.2.9519653')"
    fi
fi

if ! command -v java >/dev/null 2>&1; then
    MISSING="$MISSING\n  - Java 17+ (install from https://adoptium.net)"
fi

# Check Rust Android targets
if command -v rustup >/dev/null 2>&1; then
    TARGETS=$(rustup target list --installed 2>/dev/null || true)
    if ! echo "$TARGETS" | grep -q "aarch64-linux-android"; then
        MISSING="$MISSING\n  - Rust target: aarch64-linux-android (run: rustup target add aarch64-linux-android)"
    fi
fi

if [ -n "$MISSING" ]; then
    echo ""
    echo "The following prerequisites are missing:"
    echo -e "$MISSING"
    echo ""
    exit 1
fi

cd "$ROOT/desktop-tauri"

# Install frontend dependencies when they are missing or out of date with package-lock.json
if ! node "$ROOT/scripts/check-deps.mjs"; then
    echo "Installing frontend dependencies with npm ci..."
    npm ci
fi

# Initialize Android project if needed
if [ ! -d "src-tauri/gen/android" ]; then
    echo "Initializing Tauri Android project..."
    npx tauri android init
fi

# Build
if [ "$BUILD_AAB" = true ]; then
    echo "Building Android App Bundle (AAB)..."
    npx tauri android build --aab
else
    echo "Building Android APK..."
    npx tauri android build --apk
fi

# Copy outputs to downloads/
mkdir -p "$ROOT/downloads"

if [ "$BUILD_AAB" = true ]; then
    AAB=$(find "$ROOT/desktop-tauri/src-tauri/gen/android/app/build/outputs/bundle" -name "*.aab" 2>/dev/null | head -1)
    if [ -n "$AAB" ]; then
        DEST="$ROOT/downloads/cpmesh-${VERSION}-android.aab"
        cp "$AAB" "$DEST"
        SIZE=$(du -h "$DEST" | cut -f1)
        echo ""
        echo "=== Build complete ==="
        echo "  Bundle: $DEST ($SIZE)"
    else
        echo "ERROR: Build failed — no .aab found" >&2
        exit 1
    fi
else
    APK=$(find "$ROOT/desktop-tauri/src-tauri/gen/android/app/build/outputs/apk" -name "*.apk" 2>/dev/null | head -1)
    if [ -n "$APK" ]; then
        DEST="$ROOT/downloads/cpmesh-${VERSION}-android.apk"
        cp "$APK" "$DEST"
        SIZE=$(du -h "$DEST" | cut -f1)
        echo ""
        echo "=== Build complete ==="
        echo "  APK: $DEST ($SIZE)"
    else
        echo "ERROR: Build failed — no .apk found" >&2
        exit 1
    fi
fi
