#!/usr/bin/env bash
# Copies one desktop build's Tauri bundles into <out-dir> under the release asset names
# that scripts/release/publish-website.mjs understands: cpmesh-<version>-<os>-<arch>[-setup].<ext>
#
# Usage: scripts/release/collect-desktop.sh <windows|macos|linux> <rust-target> <version> <out-dir>
#
# macOS: unless MACOS_SIGNED=true (Tauri signed the app with a Developer ID certificate), the app is
# ad-hoc signed so Gatekeeper reports an unverified developer, which users can allow, rather than a
# damaged app. The .app is then packed into a drag-to-Applications DMG.
set -euo pipefail

if [ "$#" -ne 4 ]; then
    echo "usage: $0 <windows|macos|linux> <rust-target> <version> <out-dir>" >&2
    exit 2
fi
platform="$1"
target="$2"
version="$3"
out="$4"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bundle="$root/desktop-tauri/src-tauri/target/$target/release/bundle"

# Prints the only file in <dir> matching <glob>; fails unless there is exactly one.
single() {
    local dir="$1" pattern="$2" matches
    shopt -s nullglob
    # shellcheck disable=SC2206 # the pattern is expanded on purpose
    matches=("$dir"/$pattern)
    shopt -u nullglob
    if [ "${#matches[@]}" -ne 1 ]; then
        echo "error: expected exactly one $pattern in $dir, found ${#matches[@]}" >&2
        return 1
    fi
    printf '%s\n' "${matches[0]}"
}

case "$target" in
    x86_64-*) arch=amd64 ;;
    aarch64-*) arch=arm64 ;;
    universal-*) arch=universal ;;
    *)
        echo "error: unsupported target $target" >&2
        exit 2
        ;;
esac

mkdir -p "$out"

case "$platform" in
    windows)
        exe="$(single "$bundle/nsis" '*-setup.exe')"
        cp "$exe" "$out/cpmesh-$version-windows-$arch-setup.exe"
        ;;
    linux)
        deb="$(single "$bundle/deb" '*.deb')"
        appimage="$(single "$bundle/appimage" '*.AppImage')"
        cp "$deb" "$out/cpmesh-$version-linux-$arch.deb"
        cp "$appimage" "$out/cpmesh-$version-linux-$arch.AppImage"
        ;;
    macos)
        app="$(single "$bundle/macos" '*.app')"
        if [ "${MACOS_SIGNED:-false}" != "true" ]; then
            codesign --force --deep --sign - "$app"
        fi
        codesign --verify --deep --strict "$app"

        executable="$(plutil -extract CFBundleExecutable raw -o - "$app/Contents/Info.plist")"
        archs="$(lipo -archs "$app/Contents/MacOS/$executable")"
        echo "$executable architectures: $archs"
        if [ "$arch" = universal ] && ! { [[ " $archs " == *" x86_64 "* ]] && [[ " $archs " == *" arm64 "* ]]; }; then
            echo "error: expected a universal (x86_64 + arm64) binary" >&2
            exit 1
        fi

        stage="$(mktemp -d)"
        ditto "$app" "$stage/$(basename "$app")"
        ln -s /Applications "$stage/Applications"
        dmg="$out/cpmesh-$version-macos-$arch.dmg"
        # hdiutil occasionally fails with "Resource busy" on CI runners, so retry
        for attempt in 1 2 3; do
            if hdiutil create -volname cpmesh -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg"; then
                break
            fi
            if [ "$attempt" -eq 3 ]; then
                echo "error: hdiutil failed to create $dmg" >&2
                exit 1
            fi
            sleep 10
        done
        rm -rf "$stage"
        ;;
    *)
        echo "error: unsupported platform $platform" >&2
        exit 2
        ;;
esac

ls -l "$out"
