# build/m0/build.ps1 — M0 build script (Windows PowerShell 5.1+)
#
# Builds the four M0 binaries into build/m0/bin. All endpoints/keys are injected
# at runtime via environment variables or CLI flags — no secrets in source.
#
# Env vars (all optional, defaults are loopback/documentation values):
#   C2_CLIENT_LISTEN   server client listener    (default 127.0.0.1:9909)
#   C2_OPERATOR_LISTEN server operator listener  (default 127.0.0.1:9910)
#   C2_OPERATOR_USER   operator username         (default ops)
#   C2_OPERATOR_PSK    operator PSK at runtime   (never written to disk)
#   C2_CLIENT_ADDR     default client address    (default 127.0.0.1:9909)
#
# Usage: powershell -ExecutionPolicy Bypass -File build/m0/build.ps1 [-SkipTests] [-Release]

[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$Release,
    [string]$OutDir = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $OutDir) { $OutDir = Join-Path $root 'build\m0\bin' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$logDir = Join-Path $root 'build\m0\logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$fails = 0
function Run($name, $dir, $block) {
    Write-Host "== $name ==" -ForegroundColor Cyan
    Push-Location $dir
    try { & $block } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED: $name (exit $LASTEXITCODE)" -ForegroundColor Red; $script:fails++ }
}

# Rust client ---------------------------------------------------------------
Run 'cargo build (offline)' (Join-Path $root 'src\m0\client-rust') {
    if ($Release) { cmd /c "cargo build --release --offline 2>&1" } else { cmd /c "cargo build --offline 2>&1" }
}
if (-not $SkipTests) {
    Run 'cargo test (offline)' (Join-Path $root 'src\m0\client-rust') { cmd /c "cargo test --offline 2>&1" }
}
$rsProfile = if ($Release) { 'release' } else { 'debug' }
$rsBin = Join-Path $root "src\m0\client-rust\target\$rsProfile\c2client.exe"
if (Test-Path $rsBin) { Copy-Item $rsBin (Join-Path $OutDir 'c2client.exe') -Force }

# Go binaries ---------------------------------------------------------------
foreach ($m in @('server-go', 'operator-go', 'builder')) {
    $outName = switch ($m) {
        'server-go'   { 'c2server.exe' }
        'operator-go' { 'c2operator.exe' }
        'builder'     { 'c2builder.exe' }
    }
    Run "go build ($m)" (Join-Path $root "src\m0\$m") {
        go build -trimpath -ldflags "-s -w" -o (Join-Path $OutDir $outName) .
    }
    if (-not $SkipTests) {
        Run "go vet ($m)" (Join-Path $root "src\m0\$m") { go vet ./... }
        Run "go test ($m)" (Join-Path $root "src\m0\$m") { go test ./... }
    }
}

Write-Host ''
Write-Host "artifacts in $OutDir" -ForegroundColor Green
Get-ChildItem $OutDir | Select-Object Name, Length | Format-Table -AutoSize
if ($fails -gt 0) { Write-Host "$fails build step(s) FAILED" -ForegroundColor Red; exit 1 }
Write-Host 'M0 build OK' -ForegroundColor Green
Write-Host "logs: $logDir"
exit 0
