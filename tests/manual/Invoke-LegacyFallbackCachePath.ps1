<#
.SYNOPSIS
    Manual smoke test for the legacy fallback cache-build path.

.DESCRIPTION
    Removes content-store sidecars and manifest metadata from a synthetic dataset,
    clears derived cache output, and runs dashboard generation against raw rows only.
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
    }
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

Save-TestBackupFile -Name 'synthetic-manifest.json'
Save-TestBackupFile -Name 'VulnContentDictionary.json.gz'
Save-TestBackupFile -Name 'VulnCurrentRefs.json.gz'
foreach ($file in @(Get-ChildItem -LiteralPath $BasePath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue)) {
    Save-TestBackupFile -Name $file.Name
}
Clear-DashboardCache

Write-Host 'Content-store files moved aside. Remaining files:'
Get-ChildItem -LiteralPath $BasePath -File |
    Select-Object Name, @{ n = 'SizeMB'; e = { [math]::Round($_.Length / 1MB, 2) } } |
    Format-Table -Auto

$dashboardScriptPath = Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1'
$outputPath = Join-Path $OutputDir 'P5-LegacyFallbackCacheBuild.html'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
    Write-Host "`n=== Starting P5: Legacy Fallback Cache Build ==="
    & $dashboardScriptPath -DirectoryPath $BasePath -OutputPath $outputPath -ExportMachineData:$false
    $stopwatch.Stop()
    Write-Host ("`nPASS: P5 completed in {0}s" -f ([math]::Round($stopwatch.Elapsed.TotalSeconds, 1)))
    Write-Host ("Peak WS: {0}MB" -f ([math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB)))
}
catch {
    $stopwatch.Stop()
    Write-Host ("`nFAIL: P5 crashed after {0}s" -f ([math]::Round($stopwatch.Elapsed.TotalSeconds, 1))) -ForegroundColor Red
    Write-Host ("Error: {0}" -f $_) -ForegroundColor Red
    Write-Host ("Stack: {0}" -f $_.ScriptStackTrace) -ForegroundColor Red
    Write-Host ("Peak WS: {0}MB" -f ([math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB)))
}
finally {
    Write-Host "`nRestoring content-store files..."
    Restore-TestBackupFile -Name 'synthetic-manifest.json'
    Restore-TestBackupFile -Name 'VulnContentDictionary.json.gz'
    Restore-TestBackupFile -Name 'VulnCurrentRefs.json.gz'
    foreach ($file in @(Get-ChildItem -LiteralPath $backupDir -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue)) {
        Restore-TestBackupFile -Name $file.Name
    }

    foreach ($directory in @(Get-ChildItem -LiteralPath $BasePath -Directory -Filter '.vuln-content-store-staging-*' -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $directory.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }

    $remaining = @(Get-ChildItem -LiteralPath $backupDir -File -ErrorAction SilentlyContinue)
    if ($remaining.Count -eq 0) {
        Remove-Item -LiteralPath $backupDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host 'Files restored.'
}