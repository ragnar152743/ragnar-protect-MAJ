param(
    [Parameter(Mandatory = $true)]
    [string]$SamplePath
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$distExe = Join-Path $projectRoot "dist\RagnarProtect.exe"
$mainPy = Join-Path $projectRoot "main.py"

if (Test-Path $distExe) {
    & $distExe --launch-exe-sandbox $SamplePath --nogui
    exit $LASTEXITCODE
}

& python $mainPy --launch-exe-sandbox $SamplePath --nogui
exit $LASTEXITCODE
