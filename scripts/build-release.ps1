# Build the BurpFree desktop binary in release mode, with the frontend
# bundled in via the Tauri `embed` mechanism.
#
# Produces:
#   target\release\burpfree.exe        — headless CLI
#   target\release\burpfree-tauri.exe  — desktop app
#
# Usage: pwsh -ExecutionPolicy Bypass -File .\scripts\build-release.ps1

$ErrorActionPreference = 'Stop'
$repo  = Resolve-Path (Join-Path $PSScriptRoot '..')
$mingw = "$env:USERPROFILE\mingw64\bin"
$sc    = "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained"
$cargo = "$env:USERPROFILE\.cargo\bin"
$rust  = "$env:USERPROFILE\.rustup\toolchains\stable-x86_64-pc-windows-gnu\bin"
$env:Path = "$mingw;$sc;$cargo;$rust;$env:Path"

Push-Location (Join-Path $repo 'web')
if (-not (Test-Path 'node_modules')) {
    npm install --no-audit --no-fund
}
Write-Host 'Building frontend...'
npm run build
Pop-Location

Push-Location $repo
try {
    Write-Host 'Building release binaries...'
    cargo build --workspace --release
    Write-Host ''
    Write-Host 'Done. Binaries:'
    Get-ChildItem (Join-Path $repo 'target\release') -Filter '*.exe' | ForEach-Object {
        $sizeMB = [math]::Round($_.Length / 1MB, 2)
        Write-Host "  $($_.Name)  ($sizeMB MB)"
    }
} finally {
    Pop-Location
}
