#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DirectoryPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports'),

    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) ('.local\hot-phase-review\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [Parameter(Mandatory = $false)]
    [switch]$SplitAssets,

    [Parameter(Mandatory = $false)]
    [switch]$ForceFullValidation,

    [Parameter(Mandatory = $false)]
    [ValidateSet('artifacts', 'semantic')]
    [string]$ValidationMode = 'artifacts',

    [Parameter(Mandatory = $false)]
    [switch]$AllowLargeSemanticValidation,

    [Parameter(Mandatory = $false)]
    [ValidateRange(100000, 50000000)]
    [int]$SemanticValidationRowLimit = 1000000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(15, 3600)]
    [int]$ValidationHeartbeatSeconds = 60,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 64)]
    [int]$ValidationPartitionCompareParallelism = 1,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$PollIntervalSeconds = 5,

    [Parameter(Mandatory = $false)]
    [switch]$BucketedMachineLookup,

    [Parameter(Mandatory = $false)]
    [switch]$DirectMergeDeviceLookup,

    [Parameter(Mandatory = $false)]
    [switch]$RebuildLookupsBeforePayload
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helpers\TestScriptSupport.ps1')
. (Join-Path $PSScriptRoot 'helpers\ValidationReviewSupport.ps1')

if (-not $IsWindows) {
    throw 'tests/Invoke-HotPhaseReview.ps1 currently supports Windows only because it relies on Win32 CIM classes for process and memory sampling.'
}

function Get-DatasetRowCountForReview {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $manifestPath = Join-Path $Path 'synthetic-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return 0
    }

    $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json -Depth 20
    if ($manifest.PSObject.Properties['actualTotalVulnRows']) {
        return [int]$manifest.actualTotalVulnRows
    }

    if ($manifest.PSObject.Properties['actualCurrentRows'] -and $manifest.PSObject.Properties['actualHistoryRows']) {
        return ([int]$manifest.actualCurrentRows + [int]$manifest.actualHistoryRows)
    }

    return 0
}

function Write-ReviewHeartbeat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Stopwatch]$Stopwatch,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Samples,

        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $true)]
        [int64]$PeakRssBytes,

        [Parameter(Mandatory = $true)]
        [int64]$PeakPrivateBytes
    )

    $lastSample = if ($Samples.Count -gt 0) { $Samples[$Samples.Count - 1] } else { $null }
    $stdoutStatus = Get-HeartbeatFileStatus -Path $StdoutPath
    $availableMemory = if ($null -ne $lastSample) { [double]$lastSample.available_memory_gb } else { Get-AvailableMemoryGB }
    $stdoutAgeText = if ($null -ne $stdoutStatus.ageSeconds) { ('{0:N1}s' -f $stdoutStatus.ageSeconds) } else { 'n/a' }

    $message = "[{0}] Review heartbeat: elapsed={1} peak-rss={2}GB peak-private={3}GB samples={4} available={5}GB stdout-bytes={6} stdout-age={7}" -f @(
        (Get-HeartbeatTimestampText)
        $Stopwatch.Elapsed.ToString('hh\:mm\:ss')
        [math]::Round(($PeakRssBytes / 1GB), 3)
        [math]::Round(($PeakPrivateBytes / 1GB), 3)
        $Samples.Count
        $availableMemory
        $stdoutStatus.bytes
        $stdoutAgeText
    )
    Write-Output $message
}

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$dashboardScript = Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1'
$resolvedDirectoryPath = [System.IO.Path]::GetFullPath($DirectoryPath)
$resolvedOutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)

if ($ValidationMode -eq 'artifacts' -and $ForceFullValidation) {
    throw '-ForceFullValidation is only supported with -ValidationMode semantic.'
}

if ($ValidationMode -eq 'artifacts' -and $SplitAssets) {
    throw '-SplitAssets cannot be combined with -ValidationMode artifacts. Use the default dual-package artifact review or switch to -ValidationMode semantic.'
}

if (-not (Test-Path -LiteralPath $resolvedDirectoryPath -PathType Container)) {
    throw "Directory '$resolvedDirectoryPath' was not found."
}

$datasetRowCount = Get-DatasetRowCountForReview -Path $resolvedDirectoryPath
if ($ValidationMode -eq 'semantic' -and $datasetRowCount -gt $SemanticValidationRowLimit -and -not $AllowLargeSemanticValidation) {
    throw ("Semantic hot phase review is blocked for datasets above {0:N0} row(s). '{1}' reports {2:N0} row(s). Re-run with -AllowLargeSemanticValidation only when you explicitly want the long semantic replay, or use -ValidationMode artifacts." -f $SemanticValidationRowLimit, $resolvedDirectoryPath, $datasetRowCount)
}

if ($ValidationMode -eq 'semantic' -and $datasetRowCount -gt $SemanticValidationRowLimit -and $AllowLargeSemanticValidation) {
    Write-Warning ("Large semantic hot phase review override enabled for {0:N0} row(s)." -f $datasetRowCount)
}

if (-not (Test-Path -LiteralPath $resolvedOutputRoot -PathType Container)) {
    $null = New-Item -Path $resolvedOutputRoot -ItemType Directory -Force
}

$dashboardPath = Join-Path $resolvedOutputRoot 'VulnerabilityDashboard.html'
$hostedDashboardPath = Add-PathSuffixBeforeExtensionLocal -Path $dashboardPath -Suffix '.Hosted'
$auditPath = if ($ValidationMode -eq 'semantic') { Join-Path $resolvedOutputRoot 'dashboard-audit.json' } else { $null }
$stdoutPath = Join-Path $resolvedOutputRoot 'hot-phase-review.stdout.log'
$stderrPath = Join-Path $resolvedOutputRoot 'hot-phase-review.stderr.log'
$reportPath = Join-Path $resolvedOutputRoot 'hot-phase-review.json'

foreach ($path in @($dashboardPath, $hostedDashboardPath, $auditPath, $stdoutPath, $stderrPath, $reportPath) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$hostedAssetsPath = Join-Path (Split-Path -Path $hostedDashboardPath -Parent) (([System.IO.Path]::GetFileNameWithoutExtension($hostedDashboardPath)) + '.assets')
if (Test-Path -LiteralPath $hostedAssetsPath -PathType Container) {
    Remove-Item -LiteralPath $hostedAssetsPath -Recurse -Force -ErrorAction SilentlyContinue
}

$argumentList = @(
    '-NoProfile'
    '-File', $dashboardScript
    '-DirectoryPath', $resolvedDirectoryPath
    '-OutputPath', $dashboardPath
    '-ExportMachineData:$false'
    '-ValidationHeartbeatSeconds', $ValidationHeartbeatSeconds
    '-ValidationPartitionCompareParallelism', $ValidationPartitionCompareParallelism
)
if ($ValidationMode -eq 'semantic') {
    $argumentList += '-Validate'
    $argumentList += '-ValidationOutputPath', $auditPath
}
else {
    $argumentList += '-DualPackage'
    $argumentList += '-HostedOutputPath', $hostedDashboardPath
}
if ($ValidationMode -eq 'semantic' -and $SplitAssets) {
    $argumentList += '-SplitAssets'
}
if ($ForceFullValidation) {
    $argumentList += '-ForceFullValidation'
}
if ($BucketedMachineLookup) {
    $argumentList += '-BucketedMachineLookup'
}
if ($DirectMergeDeviceLookup) {
    $argumentList += '-DirectMergeDeviceLookup'
}
if ($RebuildLookupsBeforePayload) {
    $argumentList += '-RebuildLookupsBeforePayload'
}

Write-Output 'Running hot phase review...'
Write-Output ("  Dataset: {0}" -f $resolvedDirectoryPath)
Write-Output ("  Output root: {0}" -f $resolvedOutputRoot)

$process = Start-Process -FilePath 'pwsh' -ArgumentList $argumentList -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$samples = [System.Collections.Generic.List[object]]::new()
$peakRssBytes = [int64]0
$peakRssAt = [double]0
$peakPrivateBytes = [int64]0
$peakPrivateAt = [double]0

Add-MeasurementSample -Samples $samples -Process $process -Stopwatch $stopwatch -PeakRssBytes ([ref]$peakRssBytes) -PeakRssAt ([ref]$peakRssAt) -PeakPrivateBytes ([ref]$peakPrivateBytes) -PeakPrivateAt ([ref]$peakPrivateAt)
Write-ReviewHeartbeat -Stopwatch $stopwatch -Samples $samples -StdoutPath $stdoutPath -PeakRssBytes $peakRssBytes -PeakPrivateBytes $peakPrivateBytes

while (-not $process.HasExited) {
    Start-Sleep -Seconds $PollIntervalSeconds
    $process.Refresh()
    Add-MeasurementSample -Samples $samples -Process $process -Stopwatch $stopwatch -PeakRssBytes ([ref]$peakRssBytes) -PeakRssAt ([ref]$peakRssAt) -PeakPrivateBytes ([ref]$peakPrivateBytes) -PeakPrivateAt ([ref]$peakPrivateAt)
    if (-not $process.HasExited) {
        Write-ReviewHeartbeat -Stopwatch $stopwatch -Samples $samples -StdoutPath $stdoutPath -PeakRssBytes $peakRssBytes -PeakPrivateBytes $peakPrivateBytes
    }
}

$process.WaitForExit()
$process.Refresh()
Add-MeasurementSample -Samples $samples -Process $process -Stopwatch $stopwatch -PeakRssBytes ([ref]$peakRssBytes) -PeakRssAt ([ref]$peakRssAt) -PeakPrivateBytes ([ref]$peakPrivateBytes) -PeakPrivateAt ([ref]$peakPrivateAt)
$stopwatch.Stop()

$generatorPhases = Get-LocalPhaseSummaryFromLog -Path $stdoutPath
$artifactValidationSummary = if ($ValidationMode -eq 'artifacts') {
    Invoke-GeneratedArtifactValidation -SelfContainedPath $dashboardPath -HostedPath $hostedDashboardPath
}
else {
    $null
}
$audit = if ($ValidationMode -eq 'semantic' -and (Test-Path -LiteralPath $auditPath -PathType Leaf)) {
    Get-Content -Path $auditPath -Raw | ConvertFrom-Json -Depth 100
}
else {
    $null
}
$auditSummary = Get-ValidationAuditSummary -Audit $audit
$validationPhases = Get-ValidationPhaseSummaryFromAudit -Audit $audit
$hotPhases = Get-HotPhaseSummary -GeneratorPhases @($generatorPhases) -ValidationPhases @($validationPhases)

$observations = [System.Collections.Generic.List[string]]::new()
$topGeneratorPhase = @($generatorPhases | Where-Object { $null -ne $_.elapsedSeconds } | Sort-Object -Property elapsedSeconds -Descending | Select-Object -First 1)
if ($topGeneratorPhase.Count -gt 0) {
    $observations.Add(("Generator hot phase: {0} ({1:N2}s)." -f $topGeneratorPhase[0].name, $topGeneratorPhase[0].elapsedSeconds)) | Out-Null
}

$topValidationPhase = @($validationPhases | Sort-Object -Property elapsedSeconds -Descending | Select-Object -First 1)
if ($topValidationPhase.Count -gt 0) {
    $observations.Add(("Validation hot phase: {0} ({1:N2}s)." -f $topValidationPhase[0].name, $topValidationPhase[0].elapsedSeconds)) | Out-Null
}
elseif ($null -ne $audit) {
    $observations.Add('Validation audit completed without semantic phase timings for this dataset shape.') | Out-Null
}

if ($null -ne $artifactValidationSummary) {
    $observations.Add('Artifact validation compared hosted and self-contained outputs instead of running semantic replay.') | Out-Null
}

if ($null -ne $auditSummary -and $auditSummary.attestationUsed) {
    $observations.Add('Validation reused a semantic attestation, so the captured validation timings represent the attested fast path.') | Out-Null
}
elseif ($null -ne $auditSummary -and [string]$auditSummary.comparisonStorage -eq 'partitioned-hash-files') {
    $observations.Add('Validation used the partitioned signature comparison path, so signature and comparison phases are the primary optimization targets in the audit.') | Out-Null
}

$report = [PSCustomObject]@{
    generatedOnUtc = [datetime]::UtcNow.ToString('o')
    datasetPath = $resolvedDirectoryPath
    outputRoot = $resolvedOutputRoot
    command = @('pwsh') + $argumentList
    status = if ($process.ExitCode -eq 0) { 'success' } else { 'failure' }
    processMetrics = [PSCustomObject]@{
        elapsedSeconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
        peakTreeRssBytes = $peakRssBytes
        peakTreeRssGb = [math]::Round(($peakRssBytes / 1GB), 3)
        peakTreeRssAtSeconds = $peakRssAt
        peakTreePrivateBytes = $peakPrivateBytes
        peakTreePrivateGb = [math]::Round(($peakPrivateBytes / 1GB), 3)
        peakTreePrivateAtSeconds = $peakPrivateAt
        sampleCount = $samples.Count
        dashboardExists = (Test-Path -LiteralPath $dashboardPath -PathType Leaf)
        dashboardBytes = if (Test-Path -LiteralPath $dashboardPath -PathType Leaf) { (Get-Item -LiteralPath $dashboardPath).Length } else { 0 }
    }
    artifacts = [PSCustomObject]@{
        dashboardPath = $dashboardPath
        hostedDashboardPath = if (Test-Path -LiteralPath $hostedDashboardPath -PathType Leaf) { $hostedDashboardPath } else { $null }
        auditPath = if (-not [string]::IsNullOrWhiteSpace($auditPath) -and (Test-Path -LiteralPath $auditPath -PathType Leaf)) { $auditPath } else { $null }
        stdoutPath = $stdoutPath
        stderrPath = $stderrPath
        reportPath = $reportPath
    }
    review = [PSCustomObject]@{
        validationMode = $ValidationMode
        validationHeartbeatSeconds = $ValidationHeartbeatSeconds
        validationPartitionCompareParallelism = $ValidationPartitionCompareParallelism
        splitAssets = ($SplitAssets -eq $true)
        forceFullValidation = ($ForceFullValidation -eq $true)
        allowLargeSemanticValidation = ($AllowLargeSemanticValidation -eq $true)
        semanticValidationRowLimit = $SemanticValidationRowLimit
        datasetRowCount = $datasetRowCount
    }
    generatorPhases = @($generatorPhases)
    validationAuditSummary = $auditSummary
    artifactValidationSummary = $artifactValidationSummary
    validationPhases = @($validationPhases)
    hotPhases = @($hotPhases)
    observations = @($observations)
    samples = @($samples)
}

$report | ConvertTo-Json -Depth 20 | Set-Content -Path $reportPath -Encoding utf8

Write-Output ''
Write-Output 'Hot phase review completed.'
Write-Output ("  Elapsed seconds: {0}" -f $report.processMetrics.elapsedSeconds)
Write-Output ("  Peak RSS GB: {0}" -f $report.processMetrics.peakTreeRssGb)
Write-Output ("  Peak Private GB: {0}" -f $report.processMetrics.peakTreePrivateGb)
foreach ($hotPhase in @($hotPhases | Select-Object -First 5)) {
    Write-Output ("  Hot phase [{0}] {1}: {2:N2}s" -f $hotPhase.scope, $hotPhase.name, $hotPhase.elapsedSeconds)
}
Write-Output ("  Report: {0}" -f $reportPath)

if ($process.ExitCode -ne 0) {
    Write-LogTail -Path $stdoutPath -Label 'Child stdout'
    Write-LogTail -Path $stderrPath -Label 'Child stderr'
    throw "Hot phase review child process exited with code $($process.ExitCode)."
}
