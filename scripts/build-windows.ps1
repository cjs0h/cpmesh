# build-windows.ps1 — Build cpmesh Tauri desktop app for Windows installer (NSIS)
# Run from the project root: .\scripts\build-windows.ps1

$ErrorActionPreference = "Stop"
$ROOT = (Resolve-Path "$PSScriptRoot\..").Path
# The app version, kept in step with releases by scripts/release/set-version.mjs
$VERSION = (Get-Content "$ROOT\desktop-tauri\src-tauri\tauri.conf.json" -Raw | ConvertFrom-Json).version

Write-Host "=== Building cpmesh $VERSION for Windows ===" -ForegroundColor Cyan

# ── Pre-flight checks ──
$missing = @()

# Rust / cargo
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    if (Test-Path "$env:USERPROFILE\.cargo\bin\cargo.exe") {
        $env:Path += ";$env:USERPROFILE\.cargo\bin"
    } else {
        $missing += "Rust (install from https://rustup.rs)"
    }
}

# Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    $missing += "Node.js LTS (install from https://nodejs.org)"
}

# Tauri CLI
if (Get-Command cargo -ErrorAction SilentlyContinue) {
    $ErrorActionPreference = "Continue"
    $null = cargo tauri --version 2>&1
    $ErrorActionPreference = "Stop"
    if ($LASTEXITCODE -ne 0) {
        $missing += "Tauri CLI  (run: cargo install tauri-cli --locked)"
    }
}

if ($missing.Count -gt 0) {
    Write-Host "`nThe following prerequisites are missing:" -ForegroundColor Red
    foreach ($m in $missing) {
        Write-Host "  - $m" -ForegroundColor Yellow
    }
    Write-Host ""
    exit 1
}

# Install frontend dependencies if needed
Push-Location "$ROOT\desktop-tauri"
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing frontend dependencies..."
    npm install
}
Pop-Location

# Build the Tauri NSIS installer explicitly.
Write-Host "Building Tauri installer (NSIS)..."
Push-Location "$ROOT\desktop-tauri"
$ErrorActionPreference = "Continue"
cargo tauri build -b nsis 2>&1 | ForEach-Object { "$_" }
$ErrorActionPreference = "Stop"
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Write-Error "Tauri build failed"
    exit 1
}
Pop-Location

# Copy outputs to downloads/
$downloadsDir = "$ROOT\downloads"
if (-not (Test-Path $downloadsDir)) {
    New-Item -ItemType Directory -Path $downloadsDir | Out-Null
}

$bundleRoot = "$ROOT\desktop-tauri\src-tauri\target\release\bundle"
$nsisInstaller = Get-ChildItem "$bundleRoot\nsis\*-setup.exe" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (-not $nsisInstaller) {
    Write-Error "Build failed: no NSIS installer found in $bundleRoot\nsis"
    exit 1
}

$nsisDest = "$downloadsDir\cpmesh-setup-$VERSION-windows-amd64-nsis.exe"
Copy-Item $nsisInstaller.FullName $nsisDest -Force
Write-Host "  NSIS setup: $nsisDest ($([math]::Round($nsisInstaller.Length / 1MB, 1)) MB)" -ForegroundColor Green

Write-Host "`n=== Windows build complete ===" -ForegroundColor Cyan
