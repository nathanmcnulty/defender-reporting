#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$BenchmarkDatasetId = 'benchmark-medium-v1',

    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) ('.local\routine-semantic-review\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),

    [Parameter(Mandatory = $false)]
    [switch]$ForceDatasetRefresh,

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
    [int]$PollIntervalSeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Import-BenchmarkDatasetCatalog.ps1')

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$definition = Get-BenchmarkDatasetDefinition -DatasetId $BenchmarkDatasetId -RepoRoot $repoRoot
if ($null -eq $definition) {
    throw "Benchmark dataset definition '$BenchmarkDatasetId' was not found."
}

$datasetScriptPath = Join-Path $PSScriptRoot 'New-BenchmarkDataset.ps1'
$reviewScriptPath = Join-Path $PSScriptRoot 'Invoke-HotPhaseReview.ps1'
if (-not (Test-Path -LiteralPath $datasetScriptPath -PathType Leaf)) {
    throw "Benchmark dataset materializer was not found: '$datasetScriptPath'"
}

if (-not (Test-Path -LiteralPath $reviewScriptPath -PathType Leaf)) {
    throw "Hot phase review script was not found: '$reviewScriptPath'"
}

$resolvedDatasetPath = Resolve-BenchmarkDatasetOutputPath -Definition $definition -RepoRoot $repoRoot
$resolvedOutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)

$plan = [PSCustomObject]@{
    benchmarkDatasetId = $BenchmarkDatasetId
    datasetPath = $resolvedDatasetPath
    outputRoot = $resolvedOutputRoot
    validationMode = 'semantic'
    forceFullValidation = $true
    semanticValidationRowLimit = $SemanticValidationRowLimit
    validationHeartbeatSeconds = $ValidationHeartbeatSeconds
    validationPartitionCompareParallelism = $ValidationPartitionCompareParallelism
    pollIntervalSeconds = $PollIntervalSeconds
}

Write-Output 'Running routine semantic review...'
Write-Output ("  Benchmark dataset id: {0}" -f $plan.benchmarkDatasetId)
Write-Output ("  Dataset path: {0}" -f $plan.datasetPath)
Write-Output ("  Output root: {0}" -f $plan.outputRoot)
Write-Output '  Validation mode: semantic (full review)'

if ($PSCmdlet.ShouldProcess($resolvedDatasetPath, ("Ensure benchmark dataset '{0}' is ready" -f $BenchmarkDatasetId))) {
    $datasetArguments = @{
        DatasetId = $BenchmarkDatasetId
    }
    if ($ForceDatasetRefresh) {
        $datasetArguments['Force'] = $true
    }

    & $datasetScriptPath @datasetArguments
}

if ($PSCmdlet.ShouldProcess($resolvedDatasetPath, 'Run full semantic hot phase review')) {
    $reviewArguments = @{
        DirectoryPath = $resolvedDatasetPath
        OutputRoot = $resolvedOutputRoot
        ValidationMode = 'semantic'
        ForceFullValidation = $true
        SemanticValidationRowLimit = $SemanticValidationRowLimit
        ValidationHeartbeatSeconds = $ValidationHeartbeatSeconds
        ValidationPartitionCompareParallelism = $ValidationPartitionCompareParallelism
        PollIntervalSeconds = $PollIntervalSeconds
    }

    & $reviewScriptPath @reviewArguments
}

return $plan