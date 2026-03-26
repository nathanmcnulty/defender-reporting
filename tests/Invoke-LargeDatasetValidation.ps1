#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('DeviceCardinalityFirst', 'BalancedMediumHeavy', 'CurrentDensity')]
    [string]$Preset = 'BalancedMediumHeavy',

    [Parameter(Mandatory = $false)]
    [string]$SourcePath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports'),

    [Parameter(Mandatory = $false)]
    [string]$SyntheticOutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports-synthetic'),

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 200000)]
    [int]$TargetDeviceCount = 0,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50000000)]
    [int]$TargetTotalVulnRows = 0,

    [Parameter(Mandatory = $false)]
    [int]$Seed = 20260322,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSyntheticGeneration,

    [Parameter(Mandatory = $false)]
    [switch]$Validate,

    [Parameter(Mandatory = $false)]
    [string]$DashboardOutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'shared-helpers.ps1')

function Get-StreamingCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Source
    )

    $count = 0
    foreach ($item in (& $Source)) {
        if ($null -ne $item) {
            $count++
        }
    }

    return $count
}

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$generatorScript = Join-Path $PSScriptRoot 'Generate-SyntheticLargeExports.ps1'
$dashboardScript = Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1'

if (-not $SkipSyntheticGeneration) {
    $generatorArgs = @{
        Preset = $Preset
        SourcePath = $SourcePath
        OutputPath = $SyntheticOutputPath
        Seed = $Seed
        CleanOutput = $true
    }
    if ($TargetDeviceCount -gt 0) {
        $generatorArgs.TargetDeviceCount = $TargetDeviceCount
    }
    if ($TargetTotalVulnRows -gt 0) {
        $generatorArgs.TargetTotalVulnRows = $TargetTotalVulnRows
    }

    & $generatorScript @generatorArgs
}

$resolvedSyntheticPath = [System.IO.Path]::GetFullPath($SyntheticOutputPath)
if (-not (Test-Path -LiteralPath $resolvedSyntheticPath -PathType Container)) {
    throw "Synthetic export path '$resolvedSyntheticPath' was not found."
}

$manifestPath = Join-Path $resolvedSyntheticPath 'synthetic-manifest.json'
$manifest = if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    Get-Content -Path $manifestPath -Raw | ConvertFrom-Json -Depth 20
}
else {
    $null
}
$skipObservedWindowMerge = ($null -ne $manifest)

$dashboardOutput = if (-not [string]::IsNullOrWhiteSpace($DashboardOutputPath)) {
    $DashboardOutputPath
}
else {
    Join-Path ([System.IO.Path]::GetTempPath()) ('stress-dashboard-' + [guid]::NewGuid().ToString('N') + '.html')
}

if ($null -ne $manifest) {
    $machineCount = [int]$manifest.actualDeviceCount
    $currentRowCount = [int]$manifest.actualCurrentRows
    $historyRowCount = [int]$manifest.actualHistoryRows
}
else {
    $machineCurrentPath = Get-MachineCurrentPath -BasePath $resolvedSyntheticPath
    $vulnCurrentPath = Get-VulnCurrentPath -BasePath $resolvedSyntheticPath

    $machineCount = Get-StreamingCount -Source { Read-MachineRecordsFromFile -Path $machineCurrentPath }
    $currentRowCount = Get-StreamingCount -Source { Read-VulnNdjsonLinesFromPath -Path $vulnCurrentPath }
    $historyRowCount = 0
    foreach ($historyRowsFile in @(Get-ChildItem -Path $resolvedSyntheticPath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue)) {
        $historyPath = $historyRowsFile.FullName
        $historyRowCount += Get-StreamingCount -Source { Read-VulnNdjsonLinesFromPath -Path $historyPath }
    }
}

$generateArgs = @{
    DirectoryPath = $resolvedSyntheticPath
    OutputPath = $dashboardOutput
    ExportMachineData = $false
}
if ($skipObservedWindowMerge) {
    $generateArgs.SkipObservedWindowMerge = $true
}
if ($Validate) {
    $generateArgs.Validate = $true
}

Write-Output ''
Write-Output 'Running dashboard generation against the synthetic exports...'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
& $dashboardScript @generateArgs
$stopwatch.Stop()

$dashboardItem = Get-Item -LiteralPath $dashboardOutput
$report = [PSCustomObject]@{
    preset = $Preset
    syntheticPath = $resolvedSyntheticPath
    dashboardOutputPath = [System.IO.Path]::GetFullPath($dashboardOutput)
    elapsedSeconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
    machineCount = $machineCount
    currentRowCount = $currentRowCount
    historyRowCount = $historyRowCount
    totalVulnRows = ($currentRowCount + $historyRowCount)
    dashboardBytes = $dashboardItem.Length
    manifest = $manifest
}

$reportPath = Join-Path $resolvedSyntheticPath 'stress-validation-report.json'
$report | ConvertTo-Json -Depth 20 | Set-Content -Path $reportPath -Encoding utf8

Write-Output ''
Write-Output 'Stress validation completed.'
Write-Output ("  Synthetic path: {0}" -f $resolvedSyntheticPath)
Write-Output ("  Dashboard output: {0}" -f ([System.IO.Path]::GetFullPath($dashboardOutput)))
Write-Output ("  Elapsed: {0} seconds" -f ([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)))
Write-Output ("  Devices: {0}" -f $machineCount)
Write-Output ("  Vulnerability rows: {0} current + {1} history = {2} total" -f $currentRowCount, $historyRowCount, ($currentRowCount + $historyRowCount))
Write-Output ("  Dashboard size: {0:N2} MB" -f ($dashboardItem.Length / 1MB))
Write-Output ("  Report: {0}" -f $reportPath)
