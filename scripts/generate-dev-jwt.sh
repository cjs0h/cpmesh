#!/usr/bin/env bash
# generate-dev-jwt.sh — Generate repo-local development RS256 JWT keys.
# Run from the project root: ./scripts/generate-dev-jwt.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${ROOT}/.dev/jwt"
KID="${JWT_ACTIVE_KID:-dev-key-1}"
PRIVATE_KEY="${OUT_DIR}/jwt_private.pem"
PUBLIC_KEY="${OUT_DIR}/jwt_public.pem"
PUBLIC_KEYS_JSON="${OUT_DIR}/jwt_public_keys.json"

if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl is required to generate JWT keys." >&2
    exit 1
fi

mkdir -p "${OUT_DIR}"

openssl genrsa -out "${PRIVATE_KEY}" 2048 >/dev/null 2>&1
openssl rsa -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}" >/dev/null 2>&1

escaped_pem=$(
    awk '
        BEGIN { printf "\"" }
        {
            gsub(/\\/, "\\\\");
            gsub(/"/, "\\\"");
            printf "%s\\n", $0
        }
        END { printf "\"" }
    ' "${PUBLIC_KEY}"
)

printf '[{"kid":"%s","pem":%s}]\n' "${KID}" "${escaped_pem}" > "${PUBLIC_KEYS_JSON}"

echo "Generated development JWT keys:"
echo "  ${PRIVATE_KEY}"
echo "  ${PUBLIC_KEY}"
echo "  ${PUBLIC_KEYS_JSON}"
