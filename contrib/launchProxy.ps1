Set-Location $PSScriptRoot

$lines = Get-Content .\ignored-hosts.txt
$ignoredHosts = $lines -join "|"

Write-Host "Launching with ignored hosts" $ignoredHosts

cd ../venv/Scripts
.\Activate.ps1

.\mitmdump.exe --mode transparent --set block_global=false --ssl-insecure -s ..\..\contrib\jarvis-filter.py --ignore-hosts $ignoredHosts