# End-to-end smoke for Round-2 verification.
$ErrorActionPreference = "Continue"
$exe = Join-Path (Split-Path -Parent $PSScriptRoot) "target\debug\burpfree.exe"
$proj = Join-Path $env:LOCALAPPDATA "BurpFree\default-project"
$bundle = Join-Path $env:TEMP "verify.burpfree"

Write-Host "=== drive proxy traffic ==="
$sites = @("http://example.com/", "http://neverssl.com/", "http://httpbin.org/get")
foreach ($u in $sites) {
    & curl.exe --max-time 8 --silent --output NUL -x http://127.0.0.1:8085 $u `
        -w ("{0,-30} HTTP %{{http_code}}  %{{size_download}}B`n" -f $u)
}

Write-Host ""
Write-Host "=== bundle export ==="
& $exe export --project $proj --out $bundle
if ($LASTEXITCODE -eq 0 -and (Test-Path $bundle)) {
    Write-Host ("bundle size: {0} KB" -f [math]::Round((Get-Item $bundle).Length / 1KB, 1))
} else {
    Write-Host "export failed"
}

Write-Host ""
Write-Host "=== ci scan (SARIF) ==="
$sarif = Join-Path $env:TEMP "verify.sarif"
& $exe ci scan --project $proj --fail-on high --report-format sarif --out $sarif 2>&1 |
    Select-Object -Last 10
Write-Host "ci exit: $LASTEXITCODE"

if (Test-Path $sarif) {
    $s = Get-Content $sarif -Raw | ConvertFrom-Json
    Write-Host ("SARIF: {0} rules, {1} results" -f `
        ($s.runs[0].tool.driver.rules | Measure-Object).Count, `
        ($s.runs[0].results | Measure-Object).Count)
}

Write-Host ""
Write-Host "=== history count ==="
& $exe history --project $proj count

Write-Host ""
Write-Host "=== cleaning verification artifacts ==="
Remove-Item -Force $bundle, $sarif -ErrorAction SilentlyContinue
Write-Host "DONE"
