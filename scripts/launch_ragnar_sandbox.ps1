param(
    [string]$SamplePath,
    [switch]$AutoRunSample,
    [switch]$Headless,
    [switch]$NoConnect,
    [int]$WaitForLogsSeconds = 20,
    [int]$AutoStopAfterSeconds = 0
)

$ErrorActionPreference = "Stop"

function Get-CompactXml {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $raw = Get-Content -Path $Path -Raw -Encoding UTF8
    return [regex]::Replace($raw.Trim(), ">\s+<", "><")
}

function Write-Info {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host "[RagnarSandbox] $Message"
}

function Resolve-SandboxIdFromPayload {
    param(
        [string]$Payload
    )

    if (-not $Payload) {
        return ""
    }

    try {
        $decoded = $Payload | ConvertFrom-Json -ErrorAction Stop
        if ($decoded.WindowsSandboxEnvironments) {
            foreach ($entry in $decoded.WindowsSandboxEnvironments) {
                if ($entry.Id) {
                    return [string]$entry.Id
                }
            }
        }
        if ($decoded.Id) {
            return [string]$decoded.Id
        }
    } catch {
    }

    $match = [regex]::Match($Payload, "\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
    if ($match.Success) {
        return $match.Value
    }

    return ""
}

function Get-RunningSandboxIds {
    if (-not $wsbCli) {
        return @()
    }

    $payload = & $wsbCli list --raw 2>$null | Out-String
    if ($LASTEXITCODE -ne 0 -or -not $payload.Trim()) {
        return @()
    }

    try {
        $decoded = $payload | ConvertFrom-Json -ErrorAction Stop
        if ($decoded.WindowsSandboxEnvironments) {
            return @($decoded.WindowsSandboxEnvironments | ForEach-Object { [string]$_.Id } | Where-Object { $_ })
        }
    } catch {
    }

    return @([regex]::Matches($payload, "\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b") | ForEach-Object { $_.Value })
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$distExe = Join-Path $projectRoot "dist\RagnarProtect.exe"
$sandboxExe = Join-Path $env:SystemRoot "System32\WindowsSandbox.exe"
$wsbCli = (Get-Command wsb.exe -ErrorAction SilentlyContinue).Source

if (-not (Test-Path $distExe)) {
    throw "Built executable not found: $distExe"
}

if (-not (Test-Path $sandboxExe) -and -not $wsbCli) {
    throw "Windows Sandbox is unavailable on this machine. Enable the feature first."
}

$resolvedSample = $null
if ($SamplePath) {
    $resolvedSample = (Resolve-Path -LiteralPath $SamplePath).Path
    if (-not (Test-Path $resolvedSample -PathType Leaf)) {
        throw "Sample not found: $SamplePath"
    }
}

$bundleRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ragnar-sandbox-test_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
$toolsDir = Join-Path $bundleRoot "tools"
$resultsDir = Join-Path $bundleRoot "results"
$appDataDir = Join-Path $resultsDir "appdata"
$samplesDir = Join-Path $bundleRoot "samples"

New-Item -ItemType Directory -Path $toolsDir, $resultsDir, $appDataDir -Force | Out-Null
if ($resolvedSample) {
    New-Item -ItemType Directory -Path $samplesDir -Force | Out-Null
}

$sandboxExeCopy = Join-Path $toolsDir "RagnarProtect.exe"
Copy-Item -LiteralPath $distExe -Destination $sandboxExeCopy -Force

$sampleName = ""
$sampleCopyPath = ""
if ($resolvedSample) {
    $sampleName = [System.IO.Path]::GetFileName($resolvedSample)
    $sampleCopyPath = Join-Path $samplesDir $sampleName
    Copy-Item -LiteralPath $resolvedSample -Destination $sampleCopyPath -Force
}

$sampleMappedPath = if ($sampleName) { "C:\Users\WDAGUtilityAccount\Desktop\RagnarSample\$sampleName" } else { "" }
$sampleAutoRunLiteral = if ($AutoRunSample.IsPresent) { '$true' } else { '$false' }

$launcherPath = Join-Path $toolsDir "launch-ragnar.ps1"
$launcherContent = @"
`$ErrorActionPreference = 'Continue'
`$resultsRoot = 'C:\Users\WDAGUtilityAccount\Desktop\RagnarHostResults'
`$appDataRoot = Join-Path `$resultsRoot 'appdata'
`$sessionLog = Join-Path `$resultsRoot 'sandbox-session-log.txt'
`$mappedExePath = 'C:\Users\WDAGUtilityAccount\Desktop\RagnarTools\RagnarProtect.exe'
`$runtimeDir = 'C:\Users\WDAGUtilityAccount\Desktop\RagnarRuntime'
`$exePath = Join-Path `$runtimeDir 'RagnarProtect.exe'
`$sampleMapped = '$sampleMappedPath'
`$autoRunSample = $sampleAutoRunLiteral
`$sampleWorkDir = 'C:\Users\WDAGUtilityAccount\Desktop\RagnarSampleWork'
New-Item -ItemType Directory -Path `$resultsRoot, `$appDataRoot, `$sampleWorkDir, `$runtimeDir -Force | Out-Null
`$env:RAGNAR_APP_DIR = `$appDataRoot
[System.IO.File]::WriteAllBytes(`$exePath, [System.IO.File]::ReadAllBytes(`$mappedExePath))
Unblock-File -Path `$exePath -ErrorAction SilentlyContinue
Set-Content -Path `$sessionLog -Encoding UTF8 -Value ('Started=' + (Get-Date).ToString('s'))
Add-Content -Path `$sessionLog -Value ('RAGNAR_APP_DIR=' + `$env:RAGNAR_APP_DIR)
Add-Content -Path `$sessionLog -Value ('ExePath=' + `$exePath)
try {
    `$ragnar = Start-Process -FilePath `$exePath -WorkingDirectory `$runtimeDir -PassThru
    Add-Content -Path `$sessionLog -Value ('RagnarPid=' + `$ragnar.Id)
} catch {
    Add-Content -Path `$sessionLog -Value ('RagnarLaunchError=' + `$_.Exception.Message)
}
Start-Sleep -Seconds 10
`$running = @(Get-Process RagnarProtect -ErrorAction SilentlyContinue)
Add-Content -Path `$sessionLog -Value ('RagnarProcessCount=' + `$running.Count)
if (`$sampleMapped -and (Test-Path -LiteralPath `$sampleMapped)) {
    `$sampleLocal = Join-Path `$sampleWorkDir ([System.IO.Path]::GetFileName(`$sampleMapped))
    Copy-Item -LiteralPath `$sampleMapped -Destination `$sampleLocal -Force
    Add-Content -Path `$sessionLog -Value ('SamplePrepared=' + `$sampleLocal)
    if (`$autoRunSample) {
        try {
            `$sampleProc = Start-Process -FilePath `$sampleLocal -PassThru
            Add-Content -Path `$sessionLog -Value ('SamplePid=' + `$sampleProc.Id)
        } catch {
            Add-Content -Path `$sessionLog -Value ('SampleLaunchError=' + `$_.Exception.Message)
        }
    }
}
`$deadline = (Get-Date).AddSeconds($WaitForLogsSeconds)
`$ragnarLog = Join-Path `$appDataRoot 'logs\ragnar_protect.log'
while ((Get-Date) -lt `$deadline -and -not (Test-Path -LiteralPath `$ragnarLog)) {
    Start-Sleep -Seconds 2
}
Add-Content -Path `$sessionLog -Value ('RagnarLogExists=' + [string](Test-Path -LiteralPath `$ragnarLog))
try {
    Get-ChildItem -Path `$appDataRoot -Recurse -Force -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime |
        ConvertTo-Json -Depth 3 |
        Set-Content -Path (Join-Path `$resultsRoot 'appdata-files.json') -Encoding UTF8
} catch {
    Add-Content -Path `$sessionLog -Value ('InventoryError=' + `$_.Exception.Message)
}
"@
Set-Content -Path $launcherPath -Value $launcherContent -Encoding UTF8

$configPath = Join-Path $bundleRoot "ragnar-test.wsb"
$configLines = @(
    "<Configuration>",
    "  <Networking>Disable</Networking>",
    "  <ClipboardRedirection>Disable</ClipboardRedirection>",
    "  <ProtectedClient>Disable</ProtectedClient>",
    "  <MappedFolders>",
    "    <MappedFolder>",
    "      <HostFolder>$toolsDir</HostFolder>",
    "      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\RagnarTools</SandboxFolder>",
    "      <ReadOnly>true</ReadOnly>",
    "    </MappedFolder>",
    "    <MappedFolder>",
    "      <HostFolder>$resultsDir</HostFolder>",
    "      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\RagnarHostResults</SandboxFolder>",
    "      <ReadOnly>false</ReadOnly>",
    "    </MappedFolder>"
)

if ($sampleCopyPath) {
    $configLines += @(
        "    <MappedFolder>",
        "      <HostFolder>$samplesDir</HostFolder>",
        "      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\RagnarSample</SandboxFolder>",
        "      <ReadOnly>true</ReadOnly>",
        "    </MappedFolder>"
    )
}

$configLines += @(
    "  </MappedFolders>",
    "  <LogonCommand>",
    "    <Command>powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\WDAGUtilityAccount\Desktop\RagnarTools\launch-ragnar.ps1</Command>",
    "  </LogonCommand>",
    "</Configuration>"
)

Set-Content -Path $configPath -Value ($configLines -join [Environment]::NewLine) -Encoding UTF8

$sessionId = ""
$launched = $false
$mode = "WindowsSandboxExe"
$startOutput = ""
$runningBefore = @()
$runningAfter = @()

if ($Headless.IsPresent) {
    if (-not $wsbCli) {
        throw "Headless mode requires wsb.exe from Windows Sandbox CLI."
    }
    $requestedSessionId = [guid]::NewGuid().Guid
    $mode = "wsb-headless"
    $compactConfig = Get-CompactXml -Path $configPath
    $runningBefore = @(Get-RunningSandboxIds)
    Get-Process -Name wsb -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Info "Starting Windows Sandbox session with wsb.exe"
    $startOutput = (& $wsbCli start --raw --id $requestedSessionId --config $compactConfig 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "wsb start failed: $startOutput"
    }
    $runningAfter = @(Get-RunningSandboxIds)
    $sessionId = Resolve-SandboxIdFromPayload -Payload $startOutput
    if (-not $sessionId) {
        $sessionId = @($runningAfter | Where-Object { $_ -notin $runningBefore } | Select-Object -First 1)
    }
    if (-not $sessionId -and $runningAfter.Count -eq 1) {
        $sessionId = $runningAfter[0]
    }
    if (-not $sessionId) {
        $sessionId = $requestedSessionId
    }
    $launched = $true
} else {
    Write-Info "Launching WindowsSandbox.exe with .wsb configuration"
    $runningBefore = @(Get-RunningSandboxIds)
    Start-Process -FilePath $sandboxExe -ArgumentList $configPath | Out-Null
    $launched = $true
    if ($wsbCli) {
        Start-Sleep -Seconds 8
        $runningAfter = @(Get-RunningSandboxIds)
        $sessionId = ($runningAfter | Where-Object { $_ -notin $runningBefore } | Select-Object -First 1)
        if (-not $sessionId -and $runningAfter.Count -eq 1) {
            $sessionId = $runningAfter[0]
        }
    }
}

$metadata = [ordered]@{
    bundle_root = $bundleRoot
    config_path = $configPath
    tools_dir = $toolsDir
    results_dir = $resultsDir
    app_data_dir = $appDataDir
    launcher_path = $launcherPath
    session_id = $sessionId
    mode = $mode
    launched = $launched
    start_output = $startOutput
    running_ids_before = @($runningBefore)
    running_ids_after = @($runningAfter)
    sample_copy_path = $sampleCopyPath
    ragnar_log_path = (Join-Path $appDataDir "logs\ragnar_protect.log")
    sandbox_session_log = (Join-Path $resultsDir "sandbox-session-log.txt")
}

$metadataPath = Join-Path $bundleRoot "bundle-metadata.json"
$metadata | ConvertTo-Json -Depth 4 | Set-Content -Path $metadataPath -Encoding UTF8
$sessionLogPath = Join-Path $resultsDir "sandbox-session-log.txt"

Write-Info "Bundle: $bundleRoot"
Write-Info "Config: $configPath"
Write-Info "Results: $resultsDir"
if ($sessionId) {
    Write-Info "SessionId: $sessionId"
}
Write-Info "Metadata: $metadataPath"

if ($AutoStopAfterSeconds -gt 0 -and $sessionId) {
    Write-Info "Waiting $AutoStopAfterSeconds second(s) before stopping the sandbox"
    Start-Sleep -Seconds $AutoStopAfterSeconds
    & $wsbCli stop --id $sessionId | Out-Null
    Write-Info "Sandbox stopped"
}

if (Test-Path -LiteralPath $sessionLogPath) {
    $sessionSummary = Get-Content -Path $sessionLogPath -Raw -Encoding UTF8
    Write-Info "Session log: $sessionLogPath"
    if ($sessionSummary -match "RagnarLaunchError=(.+)") {
        Write-Info ("Sandbox result: Ragnar launch failed inside sandbox -> " + $Matches[1].Trim())
    } elseif ($sessionSummary -match "RagnarLogExists=True") {
        Write-Info "Sandbox result: Ragnar started and exported its log."
    } else {
        Write-Info "Sandbox result: session log captured, inspect it for details."
    }
}
