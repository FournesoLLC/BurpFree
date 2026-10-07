# Round-trip smoke for `burpfree export` -> `burpfree import-bundle`.
$ErrorActionPreference = "Stop"
$exe = Join-Path (Split-Path -Parent $PSScriptRoot) "target\debug\burpfree.exe"
$proj = Join-Path $env:LOCALAPPDATA "BurpFree\default-project"
$bundle = Join-Path $env:TEMP "test-bundle.burpfree"
$dest = Join-Path $env:TEMP ("imported-" + [Guid]::NewGuid().ToString("N").Substring(0,8))

Write-Host "=== export ==="
& $exe export --project $proj --out $bundle
if ($LASTEXITCODE -ne 0) { throw "export failed: $LASTEXITCODE" }

if (-not (Test-Path $bundle)) { throw "bundle not created" }
Write-Host ("bundle size: {0} bytes" -f (Get-Item $bundle).Length)

Write-Host ""
Write-Host "=== import ==="
& $exe import-bundle $bundle --dest $dest
if ($LASTEXITCODE -ne 0) { throw "import failed: $LASTEXITCODE" }

Write-Host ""
Write-Host "=== imported project info ==="
& $exe project info $dest
if ($LASTEXITCODE -ne 0) { throw "project info failed: $LASTEXITCODE" }

Write-Host ""
Write-Host "=== layout check ==="
foreach ($f in @("config.json", "history.db", "ca/ca-cert.pem", "blobs")) {
    $full = Join-Path $dest $f
    if (Test-Path $full) {
        Write-Host "  OK   $f"
    } else {
        Write-Host "  MISS $f"
    }
}
$keyPath = Join-Path $dest "ca/ca-key.pem"
if (Test-Path $keyPath) {
    Write-Host "  WARN ca/ca-key.pem leaked"
} else {
    Write-Host "  OK   ca/ca-key.pem not included (expected)"
}

Write-Host ""
Write-Host "cleaning up"
Remove-Item -Recurse -Force $dest -ErrorAction SilentlyContinue
Remove-Item -Force $bundle -ErrorAction SilentlyContinue
Write-Host "DONE"
