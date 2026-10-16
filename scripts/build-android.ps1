# build-android.ps1 — Build cpmesh Tauri app for Android (APK or AAB)
# Run from the project root: .\scripts\build-android.ps1
# Optional: .\scripts\build-android.ps1 -Aab to build Android App Bundle instead of APK

param(
    [switch]$Aab
)

$ErrorActionPreference = "Stop"
$ROOT = (Resolve-Path "$PSScriptRoot\..").Path
# The app version, kept in step with releases by scripts/release/set-version.mjs
$VERSION = (Get-Content "$ROOT\desktop-tauri\src-tauri\tauri.conf.json" -Raw | ConvertFrom-Json).version

Write-Host "=== Building cpmesh $VERSION for Android ===" -ForegroundColor Cyan

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
        $missing += "Tauri CLI (run: cargo install tauri-cli --locked)"
    }
}

# Java — try JAVA_HOME, then Android Studio bundled JBR, then PATH
if (-not $env:JAVA_HOME) {
    $asJbr = "C:\Program Files\Android\Android Studio\jbr"
    if (Test-Path "$asJbr\bin\java.exe") {
        $env:JAVA_HOME = $asJbr
        $env:Path += ";$asJbr\bin"
        Write-Host "  Using Android Studio JBR: $asJbr" -ForegroundColor DarkGray
    } elseif (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        $missing += "Java 17+ (install from https://adoptium.net or use Android Studio's bundled JBR)"
    }
} else {
    if (-not ($env:Path -like "*$($env:JAVA_HOME)*")) {
        $env:Path += ";$env:JAVA_HOME\bin"
    }
}

# Android SDK — try ANDROID_HOME, then common locations
if (-not $env:ANDROID_HOME) {
    $candidates = @(
        "$env:LOCALAPPDATA\Android\Sdk",
        "$env:USERPROFILE\AppData\Local\Android\Sdk"
    )
    foreach ($dir in $candidates) {
        if (Test-Path $dir) {
            $env:ANDROID_HOME = $dir
            Write-Host "  Auto-detected ANDROID_HOME: $dir" -ForegroundColor DarkGray
            break
        }
    }
    if (-not $env:ANDROID_HOME) {
        $missing += "ANDROID_HOME not set (install Android SDK via Android Studio)"
    }
}

# Android NDK — try NDK_HOME, then auto-detect latest in SDK
if (-not $env:NDK_HOME -and $env:ANDROID_HOME) {
    $ndkDir = "$env:ANDROID_HOME\ndk"
    if (Test-Path $ndkDir) {
        $latestNdk = Get-ChildItem $ndkDir -Directory | Sort-Object Name | Select-Object -Last 1
        if ($latestNdk) {
            $env:NDK_HOME = $latestNdk.FullName
            Write-Host "  Auto-detected NDK: $($latestNdk.FullName)" -ForegroundColor DarkGray
        }
    }
    if (-not $env:NDK_HOME) {
        $missing += "Android NDK (install via Android Studio SDK Manager or: sdkmanager 'ndk;29.0.13846066')"
    }
}

# Rust Android targets
if (Get-Command rustup -ErrorAction SilentlyContinue) {
    $targets = (rustup target list --installed 2>&1) -join "`n"
    if ($targets -notmatch "aarch64-linux-android") {
        $missing += "Rust target: aarch64-linux-android (run: rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android)"
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

Push-Location "$ROOT\desktop-tauri"

# Install frontend dependencies when they are missing or out of date with package-lock.json
node "$ROOT\scripts\check-deps.mjs"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing frontend dependencies with npm ci..."
    npm ci
    if ($LASTEXITCODE -ne 0) {
        Pop-Location
        Write-Error "npm ci failed"
        exit 1
    }
}

# Initialize Android project if needed
if (-not (Test-Path "src-tauri\gen\android")) {
    Write-Host "Initializing Tauri Android project..."
    npx tauri android init
    if ($LASTEXITCODE -ne 0) {
        Pop-Location
        Write-Error "tauri android init failed"
        exit 1
    }
}

# Build
if ($Aab) {
    Write-Host "Building Android App Bundle (AAB)..."
    $ErrorActionPreference = "Continue"
    npx tauri android build --aab 2>&1 | ForEach-Object { "$_" }
    $ErrorActionPreference = "Stop"
} else {
    Write-Host "Building Android APK..."
    $ErrorActionPreference = "Continue"
    npx tauri android build --apk 2>&1 | ForEach-Object { "$_" }
    $ErrorActionPreference = "Stop"
}

if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Write-Error "Android build failed"
    exit 1
}

Pop-Location

# Copy outputs to downloads/
$downloadsDir = "$ROOT\downloads"
if (-not (Test-Path $downloadsDir)) {
    New-Item -ItemType Directory -Path $downloadsDir | Out-Null
}

if ($Aab) {
    $aabFile = Get-ChildItem "$ROOT\desktop-tauri\src-tauri\gen\android\app\build\outputs\bundle" -Recurse -Filter "*.aab" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($aabFile) {
        $dest = "$downloadsDir\cpmesh-${VERSION}-android.aab"
        Copy-Item $aabFile.FullName $dest -Force
        $size = "{0:N1} MB" -f ($aabFile.Length / 1MB)
        Write-Host ""
        Write-Host "=== Build complete ===" -ForegroundColor Green
        Write-Host "  Bundle: $dest ($size)"
    } else {
        Write-Error "Build failed - no .aab found"
        exit 1
    }
} else {
    $apkFile = Get-ChildItem "$ROOT\desktop-tauri\src-tauri\gen\android\app\build\outputs\apk" -Recurse -Filter "*.apk" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($apkFile) {
        $dest = "$downloadsDir\cpmesh-${VERSION}-android.apk"
        Copy-Item $apkFile.FullName $dest -Force
        $size = "{0:N1} MB" -f ($apkFile.Length / 1MB)
        Write-Host ""
        Write-Host "=== Build complete ===" -ForegroundColor Green
        Write-Host "  APK: $dest ($size)"
    } else {
        Write-Error "Build failed - no .apk found"
        exit 1
    }
}
