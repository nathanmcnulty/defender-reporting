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
    [ValidateSet('semantic', 'artifacts')]
    [string]$ValidationMode = 'semantic',

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

if (-not $Validate -and -not [string]::IsNullOrWhiteSpace($ValidationOutputPath)) {
    throw 'ValidationOutputPath requires -Validate.'
}

$resolvedValidationMode = if ($Validate) { $ValidationMode } else { 'none' }
if ($resolvedValidationMode -eq 'artifacts' -and -not [string]::IsNullOrWhiteSpace($ValidationOutputPath)) {
    throw 'ValidationOutputPath is only supported with -ValidationMode semantic.'
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

function Add-PathSuffixBeforeExtensionLocal {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Suffix
    )

    $extension = [System.IO.Path]::GetExtension($Path)
    if ([string]::IsNullOrEmpty($extension)) {
        return ($Path + $Suffix)
    }

    return ($Path.Substring(0, $Path.Length - $extension.Length) + $Suffix + $extension)
}

function Invoke-GeneratedArtifactValidation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SelfContainedPath,

        [Parameter(Mandatory = $true)]
        [string]$HostedPath
    )

    $validatorScriptPath = Join-Path $PSScriptRoot 'Validate-DashboardGeneratedArtifacts.js'
    if (-not (Test-Path -LiteralPath $validatorScriptPath -PathType Leaf)) {
        throw "Artifact validator '$validatorScriptPath' was not found."
    }

    $nodeCommand = Get-Command -Name 'node' -ErrorAction Stop
    & $nodeCommand.Source $validatorScriptPath $SelfContainedPath $HostedPath

    $validatorExitCode = [int]$global:LASTEXITCODE
    if ($validatorExitCode -ne 0) {
        throw "Generated artifact validation failed with exit code $validatorExitCode."
    }

    return [PSCustomObject]@{
        mode = 'generated-artifact-parity'
        validatorScriptPath = [System.IO.Path]::GetFullPath($validatorScriptPath)
        selfContainedPath = [System.IO.Path]::GetFullPath($SelfContainedPath)
        hostedPath = [System.IO.Path]::GetFullPath($HostedPath)
        hostedAssetsPath = Join-Path (Split-Path -Path (Resolve-Path -LiteralPath $HostedPath).Path -Parent) (([System.IO.Path]::GetFileNameWithoutExtension($HostedPath)) + '.assets')
        passed = $true
    }
}

function ConvertTo-DiagnosticUtcDateTime {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [datetime]) {
        return ([datetime]$Value).ToUniversalTime()
    }

    if ($Value -is [datetimeoffset]) {
        return ([datetimeoffset]$Value).UtcDateTime
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($text, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }

    return $null
}

function Get-DiagnosticPhaseTimingSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $phaseByName = [ordered]@{}
    $pipelineStartUtc = $null
    $pipelineEndUtc = $null

    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $parts = @([string]$line -split "`t")
        if ($parts.Count -lt 3) {
            continue
        }

        $timestampUtc = ConvertTo-DiagnosticUtcDateTime -Value $parts[0]
        if ($null -eq $timestampUtc) {
            continue
        }

        $eventType = [string]$parts[1]
        $name = [string]$parts[2]
        switch ($eventType) {
            'pipeline-start' {
                if ($null -eq $pipelineStartUtc) {
                    $pipelineStartUtc = $timestampUtc
                }
            }
            'pipeline-end' {
                $pipelineEndUtc = $timestampUtc
            }
            'phase-start' {
                if (-not $phaseByName.Contains($name)) {
                    $phaseByName[$name] = [ordered]@{ start_utc = $null; end_utc = $null }
                }

                if ($null -eq $phaseByName[$name].start_utc) {
                    $phaseByName[$name].start_utc = $timestampUtc
                }
            }
            'phase-end' {
                if (-not $phaseByName.Contains($name)) {
                    $phaseByName[$name] = [ordered]@{ start_utc = $null; end_utc = $null }
                }

                $phaseByName[$name].end_utc = $timestampUtc
            }
        }
    }

    $phaseTimings = [ordered]@{}
    $phaseElapsedSeconds = 0.0
    foreach ($phaseName in $phaseByName.Keys) {
        $phaseEntry = $phaseByName[$phaseName]
        if ($null -eq $phaseEntry.start_utc -or $null -eq $phaseEntry.end_utc) {
            continue
        }

        $elapsedSeconds = [math]::Round((New-TimeSpan -Start $phaseEntry.start_utc -End $phaseEntry.end_utc).TotalSeconds, 2)
        $phaseTimings[$phaseName] = $elapsedSeconds
        $phaseElapsedSeconds += $elapsedSeconds
    }

    return [PSCustomObject]@{
        source = 'diagnostic-phase-log'
        generated_on_utc = [datetime]::UtcNow.ToString('o')
        pipeline_elapsed_seconds = if ($null -ne $pipelineStartUtc -and $null -ne $pipelineEndUtc) {
            [math]::Round((New-TimeSpan -Start $pipelineStartUtc -End $pipelineEndUtc).TotalSeconds, 2)
        }
        else {
            $null
        }
        phase_elapsed_seconds = [math]::Round($phaseElapsedSeconds, 2)
        phase_timings = [PSCustomObject]$phaseTimings
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
            [PSCustomObject]@{
                source = [string]$DiagnosticTimingSummary.source
                generatedOnUtc = [string]$DiagnosticTimingSummary.generated_on_utc
                pipelineElapsedSeconds = $DiagnosticTimingSummary.pipeline_elapsed_seconds
                phaseElapsedSeconds = $DiagnosticTimingSummary.phase_elapsed_seconds
                wrapperElapsedSeconds = [math]::Round($ElapsedSeconds, 2)
                wrapperOverheadSeconds = [math]::Round(([math]::Round($ElapsedSeconds, 2) - [double]$DiagnosticTimingSummary.phase_elapsed_seconds), 2)
                phaseTimings = $DiagnosticTimingSummary.phase_timings
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
