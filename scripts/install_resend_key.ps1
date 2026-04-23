param(
    [Parameter(Mandatory = $true)]
    [string]$ApiKey
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$distExe = Join-Path $projectRoot "dist\RagnarProtect.exe"

if (Test-Path $distExe) {
    $targetDir = Split-Path -Parent $distExe
    $targetPath = Join-Path $targetDir "RagnarProtect.resend_key.txt"
} else {
    $targetDir = Join-Path $env:LOCALAPPDATA "RagnarProtect"
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    $targetPath = Join-Path $targetDir "resend_api_key.txt"
}

Set-Content -Path $targetPath -Value ($ApiKey.Trim()) -Encoding UTF8 -NoNewline
Write-Host "Resend key installed at: $targetPath"
