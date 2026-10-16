#!/usr/bin/env bash
# build-ios.sh — Build cpmesh Tauri app for iOS (IPA)
# Run from the project root: ./scripts/build-ios.sh
#
# Prerequisites (macOS only):
#   - Rust + iOS targets: rustup target add aarch64-apple-ios
#   - Node.js LTS
#   - Tauri CLI: cargo install tauri-cli --locked
#   - Xcode 15+ with iOS SDK
#   - CocoaPods: sudo gem install cocoapods (or via Homebrew)
#
# For device builds, you also need:
#   - Apple Developer account
#   - Valid signing certificate and provisioning profile
set -euo pipefail

# Ensure cargo from rustup is prioritized over Homebrew's rust
export PATH="$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# The app version, kept in step with releases by scripts/release/set-version.mjs
VERSION="$(grep -m1 '"version"' "$ROOT/desktop-tauri/src-tauri/tauri.conf.json" | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"

echo "=== Building cpmesh $VERSION for iOS ==="

# ── Platform check ──
if [ "$(uname -s)" != "Darwin" ]; then
    echo "ERROR: iOS builds require macOS with Xcode." >&2
    exit 1
fi

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

if ! command -v xcodebuild >/dev/null 2>&1; then
    MISSING="$MISSING\n  - Xcode (install from the App Store)"
fi

if ! command -v pod >/dev/null 2>&1; then
    MISSING="$MISSING\n  - CocoaPods (run: sudo gem install cocoapods)"
fi

# Check Rust iOS target
if command -v rustup >/dev/null 2>&1; then
    TARGETS=$(rustup target list --installed 2>/dev/null || true)
    if ! echo "$TARGETS" | grep -q "aarch64-apple-ios"; then
        MISSING="$MISSING\n  - Rust target: aarch64-apple-ios (run: rustup target add aarch64-apple-ios)"
    fi
fi

if [ -n "$MISSING" ]; then
    echo ""
    echo "The following prerequisites are missing:"
    echo -e "$MISSING"
    echo ""
    exit 1
fi

# Initialize iOS project if needed
cd "$ROOT/desktop-tauri"
if [ ! -d "src-tauri/gen/apple" ]; then
    echo "Initializing Tauri iOS project..."
    npx tauri ios init
fi

# Install frontend dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

# ── Configure code signing in Xcode project ──
PBXPROJ="$ROOT/desktop-tauri/src-tauri/gen/apple/cpmesh-desktop.xcodeproj/project.pbxproj"

if [ -n "${APPLE_DEVELOPMENT_TEAM:-}" ]; then
    echo "Configuring signing (team: $APPLE_DEVELOPMENT_TEAM)..."
    # Inject DEVELOPMENT_TEAM into both debug and release build configurations
    sed -i '' 's/CODE_SIGN_IDENTITY = "iPhone Developer";/CODE_SIGN_IDENTITY = "iPhone Developer";\n\t\t\t\tDEVELOPMENT_TEAM = "'"$APPLE_DEVELOPMENT_TEAM"'";/' "$PBXPROJ"
    
    # Build for device
    echo "Building iOS app for device..."
    npx tauri ios build
else
    echo "WARNING: APPLE_DEVELOPMENT_TEAM not set — building for simulator without code signing"
    echo "  To build for device, set APPLE_DEVELOPMENT_TEAM in .env"
    
    # The naive pbxproj sed hacks often fail or break the project.
    # Native simulator builds don't require code signing when explicitly targeting the simulator.
    
    echo "Building iOS app for simulator..."
    npx tauri ios build --target aarch64-sim
fi

# Copy outputs to downloads/
mkdir -p "$ROOT/downloads"

IPA=$(find "$ROOT/desktop-tauri/src-tauri/gen/apple/build" -name "*.ipa" 2>/dev/null | head -1)
if [ -n "$IPA" ]; then
    DEST="$ROOT/downloads/cpmesh-${VERSION}-ios.ipa"
    cp "$IPA" "$DEST"
    SIZE=$(du -h "$DEST" | cut -f1)
    echo ""
    echo "=== Build complete ==="
    echo "  IPA: $DEST ($SIZE)"
else
    # iOS builds may produce an .app bundle in the build directory instead of IPA
    APP=$(find "$ROOT/desktop-tauri/src-tauri/gen/apple/build" -name "*.app" -type d 2>/dev/null | head -1)
    if [ -n "$APP" ]; then
        echo ""
        echo "=== Build complete ==="
        echo "  App bundle: $APP"
        echo ""
        echo "Note: To generate an IPA for distribution, archive via Xcode:"
        echo "  xcodebuild -workspace ... -scheme ... -archivePath ... archive"
        echo "  xcodebuild -exportArchive -archivePath ... -exportPath ... -exportOptionsPlist ..."
    else
        echo "ERROR: Build failed — no .ipa or .app found" >&2
        exit 1
    fi
fi
