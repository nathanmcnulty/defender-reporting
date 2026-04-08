<#
.SYNOPSIS
    Manual path-coverage test for dashboard normalization and cache flows.

.DESCRIPTION
    Exercises the synthetic manifest, raw-store, cache-build, cache-hit, and legacy
    fallback branches against a local synthetic dataset. This harness is intended for
    interactive troubleshooting and is not part of the default regression bundle.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$BasePath,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
if ([string]::IsNullOrWhiteSpace($BasePath)) {
    $preferredBasePath = Join-Path (Join-Path $repoRoot '.local') 'exports-synthetic'
    $BasePath = if (Test-Path -LiteralPath $preferredBasePath -PathType Container) {
        $preferredBasePath
    }
    else {
        Join-Path $repoRoot 'exports-synthetic'
    }
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path (Join-Path $repoRoot '.local') 'stress-output'
}

. (Join-Path $repoRoot 'Import-SharedHelpers.ps1')

if (-not (Test-Path -LiteralPath $BasePath -PathType Container)) {
    throw "BasePath '$BasePath' not found."
}

if (-not (Test-Path -LiteralPath $OutputDir -PathType Container)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$backupDir = Join-Path $BasePath '.test-backup'
if (-not (Test-Path -LiteralPath $backupDir)) {
    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
}

function Save-TestBackupFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $sourcePath = Join-Path $BasePath $Name
    if (Test-Path -LiteralPath $sourcePath) {
        $backupPath = Join-Path $backupDir $Name
        Move-Item -LiteralPath $sourcePath -Destination $backupPath -Force
        return $backupPath
    }

    return $null
}

function Restore-TestBackupFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $backupPath = Join-Path $backupDir $Name
    $destinationPath = Join-Path $BasePath $Name
    if (Test-Path -LiteralPath $backupPath) {
        Move-Item -LiteralPath $backupPath -Destination $destinationPath -Force
    }
}

function Clear-DashboardCache {
    [CmdletBinding()]
    param()

    $cacheDir = Join-Path $BasePath '.dashboard-cache'
    if (Test-Path -LiteralPath $cacheDir) {
        Remove-Item -LiteralPath $cacheDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-DashboardTest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestName,

        [Parameter(Mandatory = $false)]
        [string]$DataPath = $BasePath,

        [Parameter(Mandatory = $false)]
        [string]$DashboardPath
    )

    if (-not $DashboardPath) {
        $DashboardPath = Join-Path $OutputDir ("$TestName.html")
    }

    $dashboardScriptPath = Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1'
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host ''
    Write-Host ('=' * 70)
    Write-Host ("  TEST: {0}" -f $TestName)
    Write-Host ('=' * 70)

    try {
        & $dashboardScriptPath -DirectoryPath $DataPath -OutputPath $DashboardPath -ExportMachineData:$false

        $stopwatch.Stop()
        $process = Get-Process -Id $PID
        $dashboardSize = if (Test-Path -LiteralPath $DashboardPath) { (Get-Item -LiteralPath $DashboardPath).Length } else { 0 }

        Write-Host ("  PASS: {0}" -f $TestName)
        Write-Host ("    Time:       {0:F1}s" -f $stopwatch.Elapsed.TotalSeconds)
        Write-Host ("    Peak WS:    {0:F0}MB" -f ($process.WorkingSet64 / 1MB))
        Write-Host ("    Dashboard:  {0:F1}MB" -f ($dashboardSize / 1MB))

        return [PSCustomObject]@{
            Test = $TestName
            Result = 'PASS'
            Time = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
            PeakMB = [math]::Round($process.WorkingSet64 / 1MB)
            DashSizeMB = [math]::Round($dashboardSize / 1MB, 1)
            Error = $null
        }
    }
    catch {
        $stopwatch.Stop()
        Write-Host ("  FAIL: {0}" -f $TestName)
        Write-Host ("    Error: {0}" -f $_)
        Write-Host ("    Stack: {0}" -f $_.ScriptStackTrace)
        return [PSCustomObject]@{
            Test = $TestName
            Result = 'FAIL'
            Time = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
            PeakMB = [math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB)
            DashSizeMB = 0
            Error = $_.Exception.Message
        }
    }
}

$results = [System.Collections.Generic.List[pscustomobject]]::new()

Write-Host "`n>>> PATH 1: Content-store fast path"
Write-Host '    (synthetic-manifest.json + VulnContentDictionary + VulnCurrentRefs + VulnHistoryRefs)'
Clear-DashboardCache
$results.Add((Invoke-DashboardTest -TestName 'P1-ContentStoreFastPath'))
Invoke-FullGarbageCollection

Write-Host "`n>>> PATH 2: Raw store fast path"
Write-Host '    (synthetic-manifest.json + raw NDJSON rows, NO content store)'
Clear-DashboardCache
try {
    Save-TestBackupFile -Name 'VulnContentDictionary.json.gz' | Out-Null
    Save-TestBackupFile -Name 'VulnCurrentRefs.json.gz' | Out-Null
    foreach ($file in @(Get-ChildItem -LiteralPath $BasePath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue)) {
        Save-TestBackupFile -Name $file.Name | Out-Null
    }
    $results.Add((Invoke-DashboardTest -TestName 'P2-RawStoreFastPath'))
}
finally {
    Restore-TestBackupFile -Name 'VulnContentDictionary.json.gz'
    Restore-TestBackupFile -Name 'VulnCurrentRefs.json.gz'
    foreach ($file in @(Get-ChildItem -LiteralPath $backupDir -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue)) {
        Restore-TestBackupFile -Name $file.Name
    }
}
Invoke-FullGarbageCollection

Write-Host "`n>>> PATH 3: Content-store cache build path"
Write-Host '    (NO manifest, content store present, cache cleared)'
Clear-DashboardCache
try {
    Save-TestBackupFile -Name 'synthetic-manifest.json' | Out-Null
    $results.Add((Invoke-DashboardTest -TestName 'P3-ContentStoreCacheBuild'))
}
finally {
    Restore-TestBackupFile -Name 'synthetic-manifest.json'
}
Invoke-FullGarbageCollection

Write-Host "`n>>> PATH 4: Cache hit path"
Write-Host '    (NO manifest, using cache from P3 run)'
try {
    Save-TestBackupFile -Name 'synthetic-manifest.json' | Out-Null
    $results.Add((Invoke-DashboardTest -TestName 'P4-CacheHit'))
}
finally {
    Restore-TestBackupFile -Name 'synthetic-manifest.json'
}
Invoke-FullGarbageCollection

Write-Host "`n>>> PATH 5: Legacy fallback cache build path"
Write-Host '    (NO manifest, NO content store, raw NDJSON rows only, cache cleared)'
Clear-DashboardCache
try {
    Save-TestBackupFile -Name 'synthetic-manifest.json' | Out-Null
    Save-TestBackupFile -Name 'VulnContentDictionary.json.gz' | Out-Null
    Save-TestBackupFile -Name 'VulnCurrentRefs.json.gz' | Out-Null
    foreach ($file in @(Get-ChildItem -LiteralPath $BasePath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue)) {
        Save-TestBackupFile -Name $file.Name | Out-Null
    }
    $results.Add((Invoke-DashboardTest -TestName 'P5-LegacyFallbackCacheBuild'))
}
finally {
    Restore-TestBackupFile -Name 'synthetic-manifest.json'
    Restore-TestBackupFile -Name 'VulnContentDictionary.json.gz'
    Restore-TestBackupFile -Name 'VulnCurrentRefs.json.gz'
    foreach ($file in @(Get-ChildItem -LiteralPath $backupDir -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue)) {
        Restore-TestBackupFile -Name $file.Name
    }
}
Invoke-FullGarbageCollection

Write-Host "`n"
Write-Host ('=' * 70)
Write-Host '  TEST SUMMARY'
Write-Host ('=' * 70)
$results | Format-Table -Property Test, Result, @{ n = 'Time(s)'; e = { $_.Time } }, @{ n = 'PeakMB'; e = { $_.PeakMB } }, @{ n = 'DashMB'; e = { $_.DashSizeMB } }, Error -AutoSize

$failed = @($results | Where-Object Result -eq 'FAIL')
if ($failed.Count -gt 0) {
    Write-Host "`nFAILED TESTS:" -ForegroundColor Red
    foreach ($result in $failed) {
        Write-Host ("  - {0}: {1}" -f $result.Test, $result.Error) -ForegroundColor Red
    }
    exit 1
}

Write-Host ("`nAll {0} tests passed." -f $results.Count) -ForegroundColor Green

if (Test-Path -LiteralPath $backupDir) {
    $remaining = @(Get-ChildItem -LiteralPath $backupDir -File -ErrorAction SilentlyContinue)
    if ($remaining.Count -eq 0) {
        Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Warning ("Backup directory still has files: {0}" -f ($remaining.Name -join ', '))
    }
}