# Summarise a captured workspace test run.
param([string]$Path = "$env:TEMP\final-ws.txt")

$lines = Select-String -Path $Path -Pattern "^test result:" | ForEach-Object { $_.Line }
$lines

Write-Host ""
Write-Host "--- total ---"

$sum = 0
$fail = 0
foreach ($l in $lines) {
    if ($l -match "(\d+) passed; (\d+) failed") {
        $sum += [int]$Matches[1]
        $fail += [int]$Matches[2]
    }
}
Write-Host "passed: $sum"
Write-Host "failed: $fail"
