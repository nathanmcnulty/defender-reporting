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
    [ValidateRange(1, 200000)]
    [int]$PlanningSourceMachineLimit = 50000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 500000)]
    [int]$PlanningSourceRowLimit = 100000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 200000)]
    [int]$SafetyDeviceLimit = 25000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50000000)]
    [int]$SafetyRowLimit = 2500000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 256)]
    [int]$MinimumAvailableMemoryGB = 8,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 2048)]
    [int]$MinimumFreeDiskGB = 10,

    [Parameter(Mandatory = $false)]
    [int]$Seed = 20260322,

    [Parameter(Mandatory = $false)]
    [switch]$AllowLargeDataset,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSyntheticGeneration,

    [Parameter(Mandatory = $false)]
    [switch]$Validate,

    [Parameter(Mandatory = $false)]
    [string]$DashboardOutputPath,

    [Parameter(Mandatory = $false)]
    [string]$ValidationOutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateRange(15, 3600)]
    [int]$ValidationHeartbeatSeconds = 60,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 64)]
    [int]$ValidationPartitionCompareParallelism = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'build\Import-SharedHelpers.ps1')

if (-not $Validate -and -not [string]::IsNullOrWhiteSpace($ValidationOutputPath)) {
    throw 'ValidationOutputPath requires -Validate.'
}

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

function Get-ValidationAuditSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Audit
    )

    if ($null -eq $Audit) {
        return $null
    }

    $semanticParity = if ($Audit.PSObject.Properties['SemanticParity']) {
        $Audit.SemanticParity
    }
    else {
        $null
    }

    return [PSCustomObject]@{
        auditMode = if ($Audit.PSObject.Properties['AuditMode']) { [string]$Audit.AuditMode } else { $null }
        rowMatch = if ($Audit.PSObject.Properties['RowComparison']) { [bool]$Audit.RowComparison.Match } else { $null }
        payloadByteParityMatch = if ($null -ne $semanticParity -and $semanticParity.PSObject.Properties['PayloadByteParityMatch']) { [bool]$semanticParity.PayloadByteParityMatch } else { $null }
        attestationUsed = if ($null -ne $semanticParity -and $semanticParity.PSObject.Properties['AttestationUsed']) { [bool]$semanticParity.AttestationUsed } else { $false }
        comparisonStorage = if ($null -ne $semanticParity -and $semanticParity.PSObject.Properties['ComparisonStorage']) { [string]$semanticParity.ComparisonStorage } else { $null }
        comparisonPayloadSource = if ($null -ne $semanticParity -and $semanticParity.PSObject.Properties['ComparisonPayloadSource']) { [string]$semanticParity.ComparisonPayloadSource } else { $null }
        phaseTimings = if ($Audit.PSObject.Properties['PhaseTimings']) { $Audit.PhaseTimings } elseif ($null -ne $semanticParity -and $semanticParity.PSObject.Properties['PhaseTimings']) { $semanticParity.PhaseTimings } else { $null }
    }
}

function Write-StressValidationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,

        [Parameter(Mandatory = $true)]
        [datetime]$StartedOn,

        [Parameter(Mandatory = $true)]
        [string]$Preset,

        [Parameter(Mandatory = $true)]
        [string]$SyntheticPath,

        [Parameter(Mandatory = $true)]
        [string]$DashboardOutputPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ResolvedValidationAuditPath,

        [Parameter(Mandatory = $true)]
        [double]$ElapsedSeconds,

        [Parameter(Mandatory = $true)]
        [int]$MachineCount,

        [Parameter(Mandatory = $true)]
        [int]$CurrentRowCount,

        [Parameter(Mandatory = $true)]
        [int]$HistoryRowCount,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Manifest,

        [Parameter(Mandatory = $true)]
        [bool]$SkipObservedWindowMerge,

        [Parameter(Mandatory = $true)]
        [ValidateSet('success', 'failure')]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [int]$DashboardExitCode,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $FailureRecord,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Audit
    )

    $resolvedDashboardOutputPath = [System.IO.Path]::GetFullPath($DashboardOutputPath)
    $dashboardExists = Test-Path -LiteralPath $DashboardOutputPath -PathType Leaf
    $dashboardBytes = if ($dashboardExists) { (Get-Item -LiteralPath $DashboardOutputPath).Length } else { $null }

    $report = [PSCustomObject]@{
        preset = $Preset
        status = $Status
        startedOn = $StartedOn.ToString('o')
        completedOn = (Get-Date).ToString('o')
        syntheticPath = $SyntheticPath
        dashboardOutputPath = $resolvedDashboardOutputPath
        elapsedSeconds = [math]::Round($ElapsedSeconds, 2)
        machineCount = $MachineCount
        currentRowCount = $CurrentRowCount
        historyRowCount = $HistoryRowCount
        totalVulnRows = ($CurrentRowCount + $HistoryRowCount)
        dashboardExists = $dashboardExists
        dashboardBytes = $dashboardBytes
        dashboardExitCode = $DashboardExitCode
        manifest = $Manifest
        validation = [PSCustomObject]@{
            validate = $Validate.IsPresent
            heartbeatSeconds = $ValidationHeartbeatSeconds
            partitionCompareParallelism = $ValidationPartitionCompareParallelism
            skipObservedWindowMerge = $SkipObservedWindowMerge
            auditPath = if ([string]::IsNullOrWhiteSpace($ResolvedValidationAuditPath)) { $null } else { [System.IO.Path]::GetFullPath($ResolvedValidationAuditPath) }
            auditSummary = Get-ValidationAuditSummary -Audit $Audit
        }
        error = if ($null -ne $FailureRecord) {
            [PSCustomObject]@{
                message = $FailureRecord.Exception.Message
                type = $FailureRecord.Exception.GetType().FullName
                fullyQualifiedErrorId = $FailureRecord.FullyQualifiedErrorId
                scriptStackTrace = $FailureRecord.ScriptStackTrace
            }
        }
        else {
            $null
        }
    }

    $report | ConvertTo-Json -Depth 20 | Set-Content -Path $ReportPath -Encoding utf8
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
    $generatorArgs.PlanningSourceMachineLimit = $PlanningSourceMachineLimit
    $generatorArgs.PlanningSourceRowLimit = $PlanningSourceRowLimit
    $generatorArgs.SafetyDeviceLimit = $SafetyDeviceLimit
    $generatorArgs.SafetyRowLimit = $SafetyRowLimit
    $generatorArgs.MinimumAvailableMemoryGB = $MinimumAvailableMemoryGB
    $generatorArgs.MinimumFreeDiskGB = $MinimumFreeDiskGB
    if ($AllowLargeDataset) {
        $generatorArgs.AllowLargeDataset = $true
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

$resolvedValidationOutputPath = if (-not [string]::IsNullOrWhiteSpace($ValidationOutputPath)) {
    [System.IO.Path]::GetFullPath($ValidationOutputPath)
}
elseif ($Validate) {
    Join-Path $resolvedSyntheticPath 'dashboard-audit.json'
}
else {
    $null
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
    ValidationHeartbeatSeconds = $ValidationHeartbeatSeconds
    ValidationPartitionCompareParallelism = $ValidationPartitionCompareParallelism
}
if ($skipObservedWindowMerge) {
    $generateArgs.SkipObservedWindowMerge = $true
}
if ($Validate) {
    $generateArgs.Validate = $true
    if (-not [string]::IsNullOrWhiteSpace($resolvedValidationOutputPath)) {
        $generateArgs.ValidationOutputPath = $resolvedValidationOutputPath
    }
}

$reportPath = Join-Path $resolvedSyntheticPath 'stress-validation-report.json'
if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
    Remove-Item -LiteralPath $reportPath -Force
}

if (Test-Path -LiteralPath $dashboardOutput -PathType Leaf) {
    Remove-Item -LiteralPath $dashboardOutput -Force
}
if (-not [string]::IsNullOrWhiteSpace($resolvedValidationOutputPath) -and (Test-Path -LiteralPath $resolvedValidationOutputPath -PathType Leaf)) {
    Remove-Item -LiteralPath $resolvedValidationOutputPath -Force
}

Write-Output ''
Write-Output 'Running dashboard generation against the synthetic exports...'
$startedOn = Get-Date
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$status = 'success'
$dashboardExitCode = $null
$failureRecord = $null
$audit = $null
try {
    $global:LASTEXITCODE = 0
    & $dashboardScript @generateArgs

    $dashboardExitCode = [int]$global:LASTEXITCODE
    if ($dashboardExitCode -ne 0) {
        throw "Dashboard generation failed with exit code $dashboardExitCode."
    }

    if (-not (Test-Path -LiteralPath $dashboardOutput -PathType Leaf)) {
        throw "Dashboard output '$dashboardOutput' was not created."
    }

    if (-not [string]::IsNullOrWhiteSpace($resolvedValidationOutputPath)) {
        if (-not (Test-Path -LiteralPath $resolvedValidationOutputPath -PathType Leaf)) {
            throw "Validation audit '$resolvedValidationOutputPath' was not created."
        }

        $audit = Get-Content -Path $resolvedValidationOutputPath -Raw | ConvertFrom-Json -Depth 100
    }
}
catch {
    $status = 'failure'
    $failureRecord = $_
    throw
}
finally {
    $stopwatch.Stop()
    Write-StressValidationReport `
        -ReportPath $reportPath `
        -StartedOn $startedOn `
        -Preset $Preset `
        -SyntheticPath $resolvedSyntheticPath `
        -DashboardOutputPath $dashboardOutput `
        -ResolvedValidationAuditPath $resolvedValidationOutputPath `
        -ElapsedSeconds $stopwatch.Elapsed.TotalSeconds `
        -MachineCount $machineCount `
        -CurrentRowCount $currentRowCount `
        -HistoryRowCount $historyRowCount `
        -Manifest $manifest `
        -SkipObservedWindowMerge $skipObservedWindowMerge `
        -Status $status `
        -DashboardExitCode $dashboardExitCode `
        -FailureRecord $failureRecord `
        -Audit $audit
}

$dashboardItem = Get-Item -LiteralPath $dashboardOutput

Write-Output ''
Write-Output 'Stress validation completed.'
Write-Output ("  Synthetic path: {0}" -f $resolvedSyntheticPath)
Write-Output ("  Dashboard output: {0}" -f ([System.IO.Path]::GetFullPath($dashboardOutput)))
if (-not [string]::IsNullOrWhiteSpace($resolvedValidationOutputPath)) {
    Write-Output ("  Validation audit: {0}" -f $resolvedValidationOutputPath)
}
Write-Output ("  Elapsed: {0} seconds" -f ([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)))
Write-Output ("  Devices: {0}" -f $machineCount)
Write-Output ("  Vulnerability rows: {0} current + {1} history = {2} total" -f $currentRowCount, $historyRowCount, ($currentRowCount + $historyRowCount))
Write-Output ("  Dashboard size: {0:N2} MB" -f ($dashboardItem.Length / 1MB))
Write-Output ("  Report: {0}" -f $reportPath)
