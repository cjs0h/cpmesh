# generate-dev-jwt.ps1 — Generate repo-local development RS256 JWT keys.
# Run from the project root: pwsh ./scripts/generate-dev-jwt.ps1

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..").Path
$OutDir = Join-Path $Root ".dev\jwt"
$Kid = if ($env:JWT_ACTIVE_KID) { $env:JWT_ACTIVE_KID } else { "dev-key-1" }
$PrivateKey = Join-Path $OutDir "jwt_private.pem"
$PublicKey = Join-Path $OutDir "jwt_public.pem"
$PublicKeysJson = Join-Path $OutDir "jwt_public_keys.json"

if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "openssl is required to generate JWT keys."
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

& openssl genrsa -out $PrivateKey 2048 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to generate RSA private key."
}

& openssl rsa -in $PrivateKey -pubout -out $PublicKey | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to generate RSA public key."
}

$PublicPem = Get-Content $PublicKey -Raw
@(@{ kid = $Kid; pem = $PublicPem }) |
    ConvertTo-Json -Compress |
    Set-Content -Path $PublicKeysJson

Write-Host "Generated development JWT keys:"
Write-Host "  $PrivateKey"
Write-Host "  $PublicKey"
Write-Host "  $PublicKeysJson"
