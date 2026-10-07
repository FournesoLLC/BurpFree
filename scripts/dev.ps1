# Development launcher for the BurpFree desktop app on Windows.
#
# Opens two consoles:
#   1. vite dev server on 127.0.0.1:5173 serving the React UI
#   2. the Tauri Rust binary pointed at that dev server
#
# Prerequisites (installed in-session during the initial build):
#   - rustup w/ stable-x86_64-pc-windows-gnu toolchain
#   - MinGW-w64 under %USERPROFILE%\mingw64\
#   - Node 18+
#
# Usage: pwsh -ExecutionPolicy Bypass -File .\scripts\dev.ps1

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..')
$mingw = "$env:USERPROFILE\mingw64\bin"
$sc    = "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained"
$cargo = "$env:USERPROFILE\.cargo\bin"
$rust  = "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\bin"
$env:Path = "$mingw;$sc;$cargo;$rust;$env:Path"

Push-Location (Join-Path $repo 'web')
if (-not (Test-Path 'node_modules')) {
    Write-Host 'Installing frontend dependencies...'
    npm install --no-audit --no-fund
}
Pop-Location

Write-Host 'Starting vite dev server (http://127.0.0.1:5173)...'
Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "cd /d `"$($repo.Path)\web`" && npm run dev" -WindowStyle Minimized

Write-Host 'Waiting for vite to accept connections...'
for ($i = 0; $i -lt 30; $i++) {
    try {
        Invoke-WebRequest -Uri 'http://127.0.0.1:5173/' -UseBasicParsing -TimeoutSec 1 | Out-Null
        break
    } catch { Start-Sleep -Seconds 1 }
}

Write-Host 'Launching BurpFree desktop (dev build)...'
Push-Location $repo
try {
    cargo run -p burpfree-tauri
} finally {
    Pop-Location
}
