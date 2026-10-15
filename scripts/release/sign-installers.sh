#!/usr/bin/env bash
# Signs the installers in <dir> for the apps' updater, which only installs an update whose
# signature verifies against desktop-tauri/src-tauri/updater-key.pub. Each signature is written
# next to its installer as <installer>.sig and then checked against that public key.
#
# Usage: scripts/release/sign-installers.sh <version> <dir>
#
# Environment: TAURI_SIGNING_PRIVATE_KEY (the private key file's contents, as written by
# `tauri signer generate`) and TAURI_SIGNING_PRIVATE_KEY_PASSWORD. If the repository has no
# public key yet, signing is skipped with a warning and the apps will not install the update
# automatically. See "Signing updates" in CONTRIBUTING.md.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <version> <dir>" >&2
    exit 2
fi
version="$1"
dir="$(cd "$2" && pwd)"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
public_key="$root/desktop-tauri/src-tauri/updater-key.pub"

if ! grep -q '[^[:space:]]' "$public_key" 2>/dev/null; then
    echo "::warning::desktop-tauri/src-tauri/updater-key.pub is empty, so installers are not signed and the apps will not install this update automatically"
    exit 0
fi
if [ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]; then
    echo "::error::TAURI_SIGNING_PRIVATE_KEY is not set, but the apps only install updates signed with the key in updater-key.pub"
    exit 1
fi
# An empty password is valid for a key generated without one
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"

shopt -s nullglob
installers=()
for file in "$dir"/cpmesh-"$version"-*; do
    [[ "$file" == *.sig ]] || installers+=("$file")
done
if [ "${#installers[@]}" -eq 0 ]; then
    echo "error: no cpmesh-$version-* installers in $dir" >&2
    exit 1
fi

for file in "${installers[@]}"; do
    (cd "$root/desktop-tauri" && npx tauri signer sign --app-version "$version" "$file" < /dev/null)
done
node "$root/scripts/release/verify-signature.mjs" --public-key "$public_key" --version "$version" "${installers[@]}"
