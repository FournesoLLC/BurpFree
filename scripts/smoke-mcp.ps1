# MCP server smoke: send JSON-RPC frames and verify the server answers
# `initialize`, `tools/list`, and `tools/call` for a few of the exposed tools.
#
# Uses Start-Process + file-redirected stdio because `|` into a native
# command with stderr output trips PowerShell's NativeCommandError handling.

$exe = Join-Path (Split-Path -Parent $PSScriptRoot) "target\debug\burpfree.exe"
$proj = Join-Path $env:LOCALAPPDATA "BurpFree\default-project"

$frames = @(
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}'
  '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"project_info","arguments":{}}}'
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"history_list","arguments":{"limit":3}}}'
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"scope_check","arguments":{"url":"https://example.com/"}}}'
  '{"jsonrpc":"2.0","id":6,"method":"ping"}'
)

$stdinFile  = Join-Path $env:TEMP "mcp-stdin.txt"
$stdoutFile = Join-Path $env:TEMP "mcp-stdout.txt"
$stderrFile = Join-Path $env:TEMP "mcp-stderr.txt"

# NB: NDJSON — one frame per line, trailing newline so the server sees EOF after the last frame.
# Use .NET UTF8Encoding(false) to avoid the UTF-8 BOM that Set-Content -Encoding utf8 injects.
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($stdinFile, (($frames -join "`n") + "`n"), $utf8NoBom)

Write-Host "=== driving MCP server over stdio ==="
$p = Start-Process -FilePath $exe `
                   -ArgumentList @("mcp","--project",$proj) `
                   -NoNewWindow `
                   -Wait `
                   -RedirectStandardInput  $stdinFile `
                   -RedirectStandardOutput $stdoutFile `
                   -RedirectStandardError  $stderrFile `
                   -PassThru

Write-Host ("exit code: {0}" -f $p.ExitCode)
Write-Host ""
Write-Host "=== stderr (tracing) ==="
Get-Content $stderrFile

Write-Host ""
Write-Host "=== stdout (JSON-RPC frames) ==="
Get-Content $stdoutFile

$ok = 0
$fail = 0
Write-Host ""
Write-Host "=== parsed summaries ==="
foreach ($line in Get-Content $stdoutFile) {
  if (-not $line.Trim()) { continue }
  try {
    $obj = $line | ConvertFrom-Json
    if ($obj.result) {
      $preview =
        if ($obj.result.protocolVersion) { "initialize ok (protocol " + $obj.result.protocolVersion + ")" }
        elseif ($obj.result.tools)       { "{0} tool(s): {1}" -f $obj.result.tools.Count, (($obj.result.tools | ForEach-Object { $_.name }) -join ", ") }
        elseif ($obj.result.content)     { "tool text: " + ($obj.result.content[0].text -replace "`n", " ") }
        else                              { ($obj.result | ConvertTo-Json -Compress -Depth 6) }
      Write-Host ("id={0}  {1}" -f $obj.id, $preview)
      $ok++
    } elseif ($obj.error) {
      Write-Host ("id={0}  ERROR code={1} msg={2}" -f $obj.id, $obj.error.code, $obj.error.message)
      $fail++
    }
  } catch {
    Write-Host "skip non-JSON: $line"
  }
}

Write-Host ""
Write-Host ("DONE  ok={0}  fail={1}" -f $ok, $fail)
if ($fail -gt 0 -or $ok -lt 5) { exit 1 } else { exit 0 }
