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
    [switch]$ForceFullValidation,

    [Parameter(Mandatory = $false)]
    [ValidateSet('semantic', 'artifacts')]
    [string]$ValidationMode = 'semantic',

    [Parameter(Mandatory = $false)]
    [switch]$AllowLargeSemanticValidation,

    [Parameter(Mandatory = $false)]
    [ValidateRange(100000, 50000000)]
    [int]$SemanticValidationRowLimit = 1000000,

    [Parameter(Mandatory = $false)]
    [string]$DashboardOutputPath,

    [Parameter(Mandatory = $false)]
    [string]$DiagnosticPhaseLogPath,

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
. (Join-Path $PSScriptRoot 'helpers\TestScriptSupport.ps1')
. (Join-Path $PSScriptRoot 'helpers\ValidationReviewSupport.ps1')

if (-not $Validate -and -not [string]::IsNullOrWhiteSpace($ValidationOutputPath)) {
    throw 'ValidationOutputPath requires -Validate.'
}

$resolvedValidationMode = if ($Validate) { $ValidationMode } else { 'none' }
if ($resolvedValidationMode -eq 'artifacts' -and -not [string]::IsNullOrWhiteSpace($ValidationOutputPath)) {
    throw 'ValidationOutputPath is only supported with -ValidationMode semantic.'
}
if ($resolvedValidationMode -eq 'artifacts' -and $ForceFullValidation) {
    throw '-ForceFullValidation is only supported with -ValidationMode semantic.'
}
$resolvedForceFullValidation = ($resolvedValidationMode -eq 'semantic')

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
        [string]$HostedDashboardOutputPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ResolvedDiagnosticPhaseLogPath,

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
        $Audit,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $DiagnosticTimingSummary,

        [Parameter(Mandatory = $true)]
        [string]$ResolvedValidationMode,

        [Parameter(Mandatory = $true)]
        [bool]$ResolvedForceFullValidation,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $ArtifactValidationSummary
    )

    $resolvedDashboardOutputPath = [System.IO.Path]::GetFullPath($DashboardOutputPath)
    $dashboardExists = Test-Path -LiteralPath $DashboardOutputPath -PathType Leaf
    $dashboardBytes = if ($dashboardExists) { (Get-Item -LiteralPath $DashboardOutputPath).Length } else { $null }
    $resolvedHostedDashboardOutputPath = if ([string]::IsNullOrWhiteSpace($HostedDashboardOutputPath)) { $null } else { [System.IO.Path]::GetFullPath($HostedDashboardOutputPath) }

    $report = [PSCustomObject]@{
        preset = $Preset
        status = $Status
        startedOn = $StartedOn.ToString('o')
        completedOn = (Get-Date).ToString('o')
        syntheticPath = $SyntheticPath
        dashboardOutputPath = $resolvedDashboardOutputPath
        hostedDashboardOutputPath = $resolvedHostedDashboardOutputPath
        diagnosticPhaseLogPath = if ([string]::IsNullOrWhiteSpace($ResolvedDiagnosticPhaseLogPath)) { $null } else { [System.IO.Path]::GetFullPath($ResolvedDiagnosticPhaseLogPath) }
        elapsedSeconds = [math]::Round($ElapsedSeconds, 2)
        generationTiming = if ($null -ne $DiagnosticTimingSummary) {
            $pipelineElapsedSeconds = Get-ObjectPropertyValue -InputObject $DiagnosticTimingSummary -Name 'pipeline_elapsed_seconds'
            if ($null -eq $pipelineElapsedSeconds) {
                $pipelineElapsedSeconds = Get-ObjectPropertyValue -InputObject $DiagnosticTimingSummary -Name 'pipelineElapsedSeconds'
            }

            $phaseElapsedSeconds = Get-ObjectPropertyValue -InputObject $DiagnosticTimingSummary -Name 'phase_elapsed_seconds'
            if ($null -eq $phaseElapsedSeconds) {
                $phaseElapsedSeconds = Get-ObjectPropertyValue -InputObject $DiagnosticTimingSummary -Name 'phaseElapsedSeconds'
            }

            $phaseTimings = Get-ObjectPropertyValue -InputObject $DiagnosticTimingSummary -Name 'phase_timings'
            if ($null -eq $phaseTimings) {
                $phaseSummaries = @(Get-ObjectPropertyValue -InputObject $DiagnosticTimingSummary -Name 'phase_summaries')
                $phaseTimingMap = [ordered]@{}
                $phaseElapsedAccumulator = 0.0
                foreach ($phaseSummary in $phaseSummaries) {
                    $phaseName = [string](Get-ObjectPropertyValue -InputObject $phaseSummary -Name 'name')
                    $phaseSeconds = Get-ObjectPropertyValue -InputObject $phaseSummary -Name 'elapsedSeconds'
                    if ([string]::IsNullOrWhiteSpace($phaseName) -or $null -eq $phaseSeconds) {
                        continue
                    }

                    $phaseTimingMap[$phaseName] = [double]$phaseSeconds
                    $phaseElapsedAccumulator += [double]$phaseSeconds
                }

                if ($null -eq $phaseElapsedSeconds -and $phaseTimingMap.Count -gt 0) {
                    $phaseElapsedSeconds = [math]::Round($phaseElapsedAccumulator, 2)
                }
                $phaseTimings = if ($phaseTimingMap.Count -gt 0) { [PSCustomObject]$phaseTimingMap } else { $null }
            }

            [PSCustomObject]@{
                source = if ($null -ne (Get-ObjectPropertyValue -InputObject $DiagnosticTimingSummary -Name 'source')) { [string](Get-ObjectPropertyValue -InputObject $DiagnosticTimingSummary -Name 'source') } else { 'diagnostic-phase-log' }
                generatedOnUtc = if ($null -ne (Get-ObjectPropertyValue -InputObject $DiagnosticTimingSummary -Name 'generated_on_utc')) { [string](Get-ObjectPropertyValue -InputObject $DiagnosticTimingSummary -Name 'generated_on_utc') } else { [datetime]::UtcNow.ToString('o') }
                pipelineElapsedSeconds = $pipelineElapsedSeconds
                phaseElapsedSeconds = $phaseElapsedSeconds
                wrapperElapsedSeconds = [math]::Round($ElapsedSeconds, 2)
                wrapperOverheadSeconds = if ($null -ne $phaseElapsedSeconds) { [math]::Round(([math]::Round($ElapsedSeconds, 2) - [double]$phaseElapsedSeconds), 2) } else { $null }
                phaseTimings = $phaseTimings
            }
        }
        else {
            $null
        }
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
            validationMode = $ResolvedValidationMode
            forceFullValidation = $ResolvedForceFullValidation
            heartbeatSeconds = $ValidationHeartbeatSeconds
            partitionCompareParallelism = $ValidationPartitionCompareParallelism
            skipObservedWindowMerge = $SkipObservedWindowMerge
            auditPath = if ([string]::IsNullOrWhiteSpace($ResolvedValidationAuditPath)) { $null } else { [System.IO.Path]::GetFullPath($ResolvedValidationAuditPath) }
            auditSummary = Get-ValidationAuditSummary -Audit $Audit
            artifactSummary = $ArtifactValidationSummary
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

$hostedDashboardOutput = if ($resolvedValidationMode -eq 'artifacts') {
    Add-PathSuffixBeforeExtensionLocal -Path $dashboardOutput -Suffix '.Hosted'
}
else {
    $null
}

$resolvedValidationOutputPath = if (-not [string]::IsNullOrWhiteSpace($ValidationOutputPath)) {
    [System.IO.Path]::GetFullPath($ValidationOutputPath)
}
elseif ($resolvedValidationMode -eq 'semantic') {
    Join-Path $resolvedSyntheticPath 'dashboard-audit.json'
}
else {
    $null
}

$resolvedDiagnosticPhaseLogPath = if (-not [string]::IsNullOrWhiteSpace($DiagnosticPhaseLogPath)) {
    [System.IO.Path]::GetFullPath($DiagnosticPhaseLogPath)
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

$totalVulnRowCount = ($currentRowCount + $historyRowCount)
if ($resolvedValidationMode -eq 'semantic' -and $totalVulnRowCount -gt $SemanticValidationRowLimit -and -not $AllowLargeSemanticValidation) {
    throw ("Semantic large-dataset validation is blocked for datasets above {0:N0} row(s). '{1}' contains {2:N0} row(s). Re-run with -AllowLargeSemanticValidation only when you explicitly want the long semantic replay, or switch to -ValidationMode artifacts." -f $SemanticValidationRowLimit, $resolvedSyntheticPath, $totalVulnRowCount)
}

if ($resolvedValidationMode -eq 'semantic' -and $totalVulnRowCount -gt $SemanticValidationRowLimit -and $AllowLargeSemanticValidation) {
    Write-Warning ("Large semantic validation override enabled for {0:N0} row(s)." -f $totalVulnRowCount)
}
if ($resolvedValidationMode -eq 'semantic' -and -not $ForceFullValidation) {
    Write-Output 'Semantic large-dataset validation forces a fresh full replay for this entrypoint.'
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
if ($resolvedValidationMode -eq 'semantic') {
    $generateArgs.Validate = $true
    $generateArgs.ForceFullValidation = $true
    if (-not [string]::IsNullOrWhiteSpace($resolvedValidationOutputPath)) {
        $generateArgs.ValidationOutputPath = $resolvedValidationOutputPath
    }
}
elseif ($resolvedValidationMode -eq 'artifacts') {
    $generateArgs.DualPackage = $true
    $generateArgs.HostedOutputPath = $hostedDashboardOutput
}
if (-not [string]::IsNullOrWhiteSpace($resolvedDiagnosticPhaseLogPath)) {
    $generateArgs.DiagnosticPhaseLogPath = $resolvedDiagnosticPhaseLogPath
}

$reportPath = Join-Path $resolvedSyntheticPath 'stress-validation-report.json'
if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
    Remove-Item -LiteralPath $reportPath -Force
}

if (Test-Path -LiteralPath $dashboardOutput -PathType Leaf) {
    Remove-Item -LiteralPath $dashboardOutput -Force
}
if (-not [string]::IsNullOrWhiteSpace($hostedDashboardOutput) -and (Test-Path -LiteralPath $hostedDashboardOutput -PathType Leaf)) {
    Remove-Item -LiteralPath $hostedDashboardOutput -Force
}
if (-not [string]::IsNullOrWhiteSpace($hostedDashboardOutput)) {
    $hostedAssetsPath = Join-Path (Split-Path -Path $hostedDashboardOutput -Parent) (([System.IO.Path]::GetFileNameWithoutExtension($hostedDashboardOutput)) + '.assets')
    if (Test-Path -LiteralPath $hostedAssetsPath -PathType Container) {
        Remove-Item -LiteralPath $hostedAssetsPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
if (-not [string]::IsNullOrWhiteSpace($resolvedDiagnosticPhaseLogPath) -and (Test-Path -LiteralPath $resolvedDiagnosticPhaseLogPath -PathType Leaf)) {
    Remove-Item -LiteralPath $resolvedDiagnosticPhaseLogPath -Force
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
$artifactValidationSummary = $null
$diagnosticTimingSummary = $null
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

    if ($resolvedValidationMode -eq 'semantic' -and -not [string]::IsNullOrWhiteSpace($resolvedValidationOutputPath)) {
        if (-not (Test-Path -LiteralPath $resolvedValidationOutputPath -PathType Leaf)) {
            throw "Validation audit '$resolvedValidationOutputPath' was not created."
        }

        $audit = Get-Content -Path $resolvedValidationOutputPath -Raw | ConvertFrom-Json -Depth 100
        $auditSummary = Get-ValidationAuditSummary -Audit $audit
        if ($resolvedForceFullValidation -and $null -ne $auditSummary -and $auditSummary.attestationUsed) {
            throw 'Semantic large-dataset sign-off unexpectedly reused an attestation instead of running a fresh full replay.'
        }
    }
    elseif ($resolvedValidationMode -eq 'artifacts') {
        if (-not (Test-Path -LiteralPath $hostedDashboardOutput -PathType Leaf)) {
            throw "Hosted dashboard output '$hostedDashboardOutput' was not created."
        }

        $artifactValidationSummary = Invoke-GeneratedArtifactValidation -SelfContainedPath $dashboardOutput -HostedPath $hostedDashboardOutput
    }
}
catch {
    $status = 'failure'
    $failureRecord = $_
    throw
}
finally {
    $diagnosticTimingSummary = Get-DiagnosticPhaseTimingSummary -Path $resolvedDiagnosticPhaseLogPath
    $stopwatch.Stop()
    Write-StressValidationReport `
        -ReportPath $reportPath `
        -StartedOn $startedOn `
        -Preset $Preset `
        -SyntheticPath $resolvedSyntheticPath `
        -DashboardOutputPath $dashboardOutput `
        -HostedDashboardOutputPath $hostedDashboardOutput `
        -ResolvedDiagnosticPhaseLogPath $resolvedDiagnosticPhaseLogPath `
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
        -Audit $audit `
        -DiagnosticTimingSummary $diagnosticTimingSummary `
        -ResolvedValidationMode $resolvedValidationMode `
        -ResolvedForceFullValidation $resolvedForceFullValidation `
        -ArtifactValidationSummary $artifactValidationSummary
}

$dashboardItem = Get-Item -LiteralPath $dashboardOutput

Write-Output ''
Write-Output 'Stress validation completed.'
Write-Output ("  Synthetic path: {0}" -f $resolvedSyntheticPath)
Write-Output ("  Dashboard output: {0}" -f ([System.IO.Path]::GetFullPath($dashboardOutput)))
if (-not [string]::IsNullOrWhiteSpace($hostedDashboardOutput)) {
    Write-Output ("  Hosted dashboard output: {0}" -f ([System.IO.Path]::GetFullPath($hostedDashboardOutput)))
}
if (-not [string]::IsNullOrWhiteSpace($resolvedDiagnosticPhaseLogPath)) {
    Write-Output ("  Diagnostic phase log: {0}" -f $resolvedDiagnosticPhaseLogPath)
}
Write-Output ("  Validation mode: {0}" -f $resolvedValidationMode)
if ($resolvedValidationMode -eq 'semantic' -and -not [string]::IsNullOrWhiteSpace($resolvedValidationOutputPath)) {
    Write-Output ("  Full semantic replay: {0}" -f $(if ($resolvedForceFullValidation) { 'forced' } else { 'disabled' }))
    Write-Output ("  Validation audit: {0}" -f $resolvedValidationOutputPath)
}
elseif ($resolvedValidationMode -eq 'artifacts') {
    Write-Output '  Artifact validation: passed.'
}
Write-Output ("  Elapsed: {0} seconds" -f ([math]::Round($stopwatch.Elapsed.TotalSeconds, 2)))
Write-Output ("  Devices: {0}" -f $machineCount)
Write-Output ("  Vulnerability rows: {0} current + {1} history = {2} total" -f $currentRowCount, $historyRowCount, ($currentRowCount + $historyRowCount))
Write-Output ("  Dashboard size: {0:N2} MB" -f ($dashboardItem.Length / 1MB))
Write-Output ("  Report: {0}" -f $reportPath)
