# End-to-end smoke test for `burpfree ci scan` and `burpfree report`.
# Starts a local HTTP origin, proxies traffic through BurpFree, scans and
# emits a report, then verifies the SARIF contains findings.

$ErrorActionPreference = 'Stop'
$cli = "c:\Users\pc\Desktop\BurpFree\target\debug\burpfree.exe"
$proj = Join-Path $env:TEMP "burpfree-smoke-ci"
if (Test-Path $proj) { Remove-Item -Recurse -Force $proj }

& $cli project new $proj | Out-Null

# A mock origin that returns an insecure cookie + info-disclosure header.
$originJob = Start-Job -ScriptBlock {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:7828/")
    $listener.Start()
    while ($listener.IsListening) {
        try {
            $ctx = $listener.GetContext()
            $body = [Text.Encoding]::UTF8.GetBytes("<html></html>")
            $ctx.Response.Headers.Add("Content-Type", "text/html")
            $ctx.Response.Headers.Add("X-Powered-By", "burpfree-test/1.0")
            $ctx.Response.AddHeader("Set-Cookie", "sid=abc; Path=/")
            $ctx.Response.ContentLength64 = $body.Length
            $ctx.Response.OutputStream.Write($body, 0, $body.Length)
            $ctx.Response.Close()
        } catch { break }
    }
    $listener.Stop()
}
Start-Sleep -Milliseconds 400

$proxyJob = Start-Job -ArgumentList $cli, $proj -ScriptBlock {
    param($cliExe, $projPath)
    & $cliExe proxy --project $projPath --listen 127.0.0.1:19105
}
Start-Sleep -Seconds 2

& curl.exe --silent --output "$env:TEMP\burpfree-smoke-nul" -x http://127.0.0.1:19105 http://127.0.0.1:7828/login
& curl.exe --silent --output "$env:TEMP\burpfree-smoke-nul" -x http://127.0.0.1:19105 http://127.0.0.1:7828/account
& curl.exe --silent --output "$env:TEMP\burpfree-smoke-nul" -x http://127.0.0.1:19105 http://127.0.0.1:7828/admin
Start-Sleep -Seconds 1
Remove-Item -Force "$env:TEMP\burpfree-smoke-nul" -ErrorAction SilentlyContinue

$count = (& $cli history --project $proj count).Trim()
Write-Output "transactions recorded: $count"

$sarifPath = Join-Path $proj "out.sarif"
& $cli ci scan --project $proj --fail-on medium --report-format sarif --out $sarifPath
$ciExit = $LASTEXITCODE
Write-Output "ci scan exit code (expect 1 since cookies miss HttpOnly): $ciExit"

$sarif = Get-Content $sarifPath -Raw | ConvertFrom-Json
Write-Output "sarif rules: $($sarif.runs[0].tool.driver.rules.Count)"
Write-Output "sarif results: $($sarif.runs[0].results.Count)"

# Re-run to verify dedup: result count should not grow.
& $cli ci scan --project $proj --fail-on medium --report-format sarif --out $sarifPath
$sarif2 = Get-Content $sarifPath -Raw | ConvertFrom-Json
Write-Output "after rerun -> results: $($sarif2.runs[0].results.Count)"

& $cli ci scan --project $proj --fail-on critical --report-format sarif --out $sarifPath
$critExit = $LASTEXITCODE
Write-Output "ci scan with fail-on critical exit code (expect 0): $critExit"

$htmlPath = Join-Path $proj "report.html"
& $cli report --project $proj --format html --out $htmlPath
Write-Output "html report bytes: $((Get-Item $htmlPath).Length)"

Stop-Job $proxyJob -ErrorAction SilentlyContinue
Remove-Job $proxyJob -Force -ErrorAction SilentlyContinue
Stop-Job $originJob -ErrorAction SilentlyContinue
Remove-Job $originJob -Force -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue

Write-Output "DONE"
