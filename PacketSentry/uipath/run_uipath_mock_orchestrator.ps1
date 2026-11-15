<#
.SYNOPSIS
    PacketSentry UiPath Orchestration Simulation & Execution Test Script
    Replicates the exact sequence of UiPath Studio activities (Steps 1 through 9).
    Fully robust to execution from any working directory (UiPath project root or Repo root).
#>

[CmdletBinding()]
param (
    [string]$WatchFolder = "",
    [string]$TargetFile = "",
    [string]$OutputRoot = "",
    [string]$PythonExe = "",
    [string]$AnalystName = "UiPath Automated SOC Bot"
)

$ErrorActionPreference = "Stop"

# Determine Repository Root robustly
if ($PSScriptRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
} else {
    $RepoRoot = "C:\Users\mehna\.gemini\antigravity\scratch\PacketSentry"
}

# Resolve Watch Folder
if (-not $WatchFolder) {
    $WatchFolder = Join-Path $RepoRoot "data\uploads"
} elseif (-not [System.IO.Path]::IsPathRooted($WatchFolder)) {
    $cand = Join-Path $RepoRoot $WatchFolder
    if (Test-Path $cand) { $WatchFolder = $cand }
}

# Resolve Output Root
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $RepoRoot "output\investigations"
} elseif (-not [System.IO.Path]::IsPathRooted($OutputRoot)) {
    $cand = Join-Path $RepoRoot $OutputRoot
    if (Test-Path $cand) { $OutputRoot = $cand }
}
if (-not (Test-Path $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
}

# Resolve Python Executable
if (-not $PythonExe) {
    if (Test-Path "C:\Python314\python.exe") {
        $PythonExe = "C:\Python314\python.exe"
    } else {
        $cmd = Get-Command python -ErrorAction SilentlyContinue
        if ($cmd) { $PythonExe = $cmd.Source } else { $PythonExe = "python.exe" }
    }
}

$cliPath = Join-Path $RepoRoot "cli.py"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  PACKETSENTRY // UIPATH WORKFLOW ORCHESTRATOR EXECUTION  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Repo Root    : $RepoRoot" -ForegroundColor Gray
Write-Host "Watch Folder : $WatchFolder" -ForegroundColor Gray
Write-Host "Output Root  : $OutputRoot" -ForegroundColor Gray
Write-Host "Python Path  : $PythonExe" -ForegroundColor Gray
Write-Host "CLI Script   : $cliPath" -ForegroundColor Gray

# Step 1: Discover Capture Files
Write-Host "`n[STEP 1] Scanning intake directory: $WatchFolder..." -ForegroundColor Yellow

$captureList = @()
if ($TargetFile) {
    if (-not [System.IO.Path]::IsPathRooted($TargetFile)) {
        if (Test-Path (Join-Path $WatchFolder $TargetFile)) {
            $TargetFile = Join-Path $WatchFolder $TargetFile
        } elseif (Test-Path (Join-Path $RepoRoot $TargetFile)) {
            $TargetFile = Join-Path $RepoRoot $TargetFile
        }
    }
    if (Test-Path $TargetFile) {
        $captureList += (Get-Item $TargetFile)
    } else {
        Write-Error "Specified TargetFile does not exist: $TargetFile"
        exit 1
    }
} else {
    if (Test-Path $WatchFolder) {
        $captureList = @(Get-ChildItem -Path $WatchFolder | Where-Object { $_.Extension -in @(".pcap", ".pcapng", ".cap") } | Sort-Object LastWriteTime -Descending)
    }
}

if ($captureList.Count -eq 0) {
    Write-Warning "No capture files (.pcap, .pcapng, .cap) found to process."
    exit 0
}

Write-Host "  -> Discovered $($captureList.Count) capture file(s) for automated processing." -ForegroundColor Green

$processedCount = 0
$alertsEncountered = 0

foreach ($targetPcap in $captureList) {
    $processedCount++
    Write-Host "`n----------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host " [FILE $processedCount/$($captureList.Count)] Processing: $($targetPcap.Name)" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  -> Path: $($targetPcap.FullName)" -ForegroundColor Gray
    Write-Host "  -> Size: $($targetPcap.Length) bytes" -ForegroundColor Gray

    # Step 2: Validate File
    Write-Host "`n[STEP 2] Validating file properties..." -ForegroundColor Yellow
    if ($targetPcap.Length -lt 24) {
        Write-Warning "Validation Failed: File is smaller than minimum PCAP header size (24 bytes). Skipping."
        continue
    }
    Write-Host "  -> Validation Passed: Valid file size and non-empty." -ForegroundColor Green

    # Step 3: Invoke Python Analysis Engine
    Write-Host "`n[STEP 3] Invoking PacketSentry CLI Analysis Engine..." -ForegroundColor Yellow
    $cliArgs = "`"$cliPath`" --pcap `"$($targetPcap.FullName)`" --output-dir `"$OutputRoot`" --analyst `"$AnalystName`""
    Write-Host "  -> Executing: $PythonExe $cliArgs" -ForegroundColor Gray

    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = $PythonExe
    $processInfo.Arguments = $cliArgs
    $processInfo.WorkingDirectory = $RepoRoot
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($processInfo)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()

    # Step 4: Wait for Process Completion
    Write-Host "`n[STEP 4] Synchronizing on process completion..." -ForegroundColor Yellow
    $proc.WaitForExit(120000) # 120s timeout
    $exitCode = $proc.ExitCode
    Write-Host "  -> Process exited with return code: $exitCode" -ForegroundColor $(if ($exitCode -in @(0, 10)) { "Green" } else { "Red" })

    if ($exitCode -notin @(0, 10)) {
        Write-Warning "Analysis Engine Failed with code $($exitCode): $stderr"
        continue
    }

    # Step 5: Read & Deserialize Intermediate JSON Results
    Write-Host "`n[STEP 5] Reading and deserializing 'investigation_summary.json'..." -ForegroundColor Yellow
    $jsonPattern = "(?s)=== PACKETSENTRY_EXECUTION_RESULT_JSON ===\s*(.*?)\s*=== END_RESULT ==="
    $summary = $null
    if ($stdout -match $jsonPattern) {
        $rawJson = $matches[1]
        try {
            $summary = $rawJson | ConvertFrom-Json
        } catch {
            $summary = $null
        }
    }
    if ($null -eq $summary) {
        # Fallback to reading most recent folder matching target name in OutputRoot
        $matchingFolders = Get-ChildItem -Path $OutputRoot -Directory | Where-Object { $_.Name -like "INV_$($targetPcap.BaseName)_*" } | Sort-Object LastWriteTime -Descending
        if ($matchingFolders) {
            $summaryFile = Join-Path $matchingFolders[0].FullName "investigation_summary.json"
            if (Test-Path $summaryFile) {
                $summary = Get-Content $summaryFile -Raw | ConvertFrom-Json
            }
        }
    }

    if ($null -eq $summary) {
        Write-Error "Could not parse investigation summary for $($targetPcap.Name)."
        continue
    }

    Write-Host "  -> Investigation ID : $($summary.investigation_id)" -ForegroundColor Cyan
    Write-Host "  -> Packets Analyzed : $($summary.packets_processed)" -ForegroundColor Cyan
    Write-Host "  -> Total Alerts     : $($summary.total_alerts_count)" -ForegroundColor Cyan
    Write-Host "  -> Processing Time  : $($summary.processing_time_sec)s" -ForegroundColor Cyan

    # Step 6: Check If Security Alerts Were Generated
    Write-Host "`n[STEP 6] Evaluating Alert Thresholds..." -ForegroundColor Yellow
    $hasHighRisk = $summary.high_or_critical_alerts_detected
    if ($hasHighRisk -or $exitCode -eq 10) {
        Write-Host "  [!] HIGH/CRITICAL THREAT DETECTED: Escalation Required!" -ForegroundColor Red
        $branchDecision = "ESCALATED_HIGH_PRIORITY"
        $alertsEncountered += $summary.total_alerts_count
    } else {
        Write-Host "  [OK] Clean or Low Severity Capture." -ForegroundColor Green
        $branchDecision = "STANDARD_ARCHIVE"
    }

    # Step 7: Verify Organized Investigation Folder
    Write-Host "`n[STEP 7] Verifying organized investigation directory..." -ForegroundColor Yellow
    $invFolder = $summary.investigation_folder
    Write-Host "  -> Folder: $invFolder" -ForegroundColor Gray
    $requiredArtifacts = @("telemetry.json", "alerts.json", "investigation_summary.json")
    foreach ($art in $requiredArtifacts) {
        $artPath = Join-Path $invFolder $art
        if (Test-Path $artPath) {
            Write-Host "     [+] Artifact verified: $art" -ForegroundColor Green
        } else {
            Write-Warning "     [-] Missing artifact: $art"
        }
    }

    # Step 8: Verify PDF Investigation Report Compilation
    Write-Host "`n[STEP 8] Validating PDF Investigation Report..." -ForegroundColor Yellow
    $pdfPath = $summary.artifacts.pdf_report
    if ($pdfPath -and (Test-Path $pdfPath)) {
        $pdfSize = (Get-Item $pdfPath).Length
        Write-Host "  -> Report PDF Verified: $pdfPath ($pdfSize bytes)" -ForegroundColor Green
    } else {
        Write-Warning "  -> PDF Report not found or not compiled."
    }

    # Step 9: Record Audit Log Trail
    Write-Host "`n[STEP 9] Recording execution status to audit log..." -ForegroundColor Yellow
    $auditLogFile = Join-Path $OutputRoot "execution_audit.log"
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
    $logLine = "[$timestamp] [STATUS: $branchDecision] Investigation: $($summary.investigation_id) | File: $($targetPcap.Name) | Packets: $($summary.packets_processed) | Alerts: $($summary.total_alerts_count) | PDF: $(Split-Path $pdfPath -Leaf) | ExitCode: $exitCode"
    Add-Content -Path $auditLogFile -Value $logLine
    Write-Host "  -> Audit record written to: $auditLogFile" -ForegroundColor Green
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  UIPATH ORCHESTRATION COMPLETED ($processedCount file(s) processed)  " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
