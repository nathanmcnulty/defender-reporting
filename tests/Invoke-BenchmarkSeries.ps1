#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$BenchmarkDatasetId = 'benchmark-medium-v1',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 20)]
    [int]$Iterations = 3,

    [Parameter(Mandatory = $false)]
    [string]$CurrentBaselineName = 'current-working-tree',

    [Parameter(Mandatory = $false)]
    [string]$ResultsRoot = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\benchmark-series'),

    [Parameter(Mandatory = $false)]
    [ValidateRange(0.5, 256.0)]
    [double]$MinimumAvailableMemoryGB = 3,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeLocalBenchmark,

    [Parameter(Mandatory = $false)]
    [switch]$LocalOnly,

    [Parameter(Mandatory = $false)]
    [switch]$IncludePersistentLocalWorkflow,

    [Parameter(Mandatory = $false)]
    [switch]$ForceDatasetRefresh
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Import-BenchmarkDatasetCatalog.ps1')
. (Join-Path $PSScriptRoot 'helpers\BenchmarkSeriesTools.ps1')

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$definition = Get-BenchmarkDatasetDefinition -DatasetId $BenchmarkDatasetId -RepoRoot $repoRoot
if ($null -eq $definition) {
    throw "Benchmark dataset definition '$BenchmarkDatasetId' was not found."
}

$datasetPath = Resolve-BenchmarkDatasetOutputPath -Definition $definition -RepoRoot $repoRoot
$resolvedResultsRoot = [System.IO.Path]::GetFullPath((Join-Path $ResultsRoot ($BenchmarkDatasetId + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))))
if (-not (Test-Path -LiteralPath $resolvedResultsRoot -PathType Container)) {
    $null = New-Item -Path $resolvedResultsRoot -ItemType Directory -Force
}

& (Join-Path $PSScriptRoot 'New-BenchmarkDataset.ps1') -DatasetId $BenchmarkDatasetId -MinimumAvailableMemoryGB $MinimumAvailableMemoryGB -Force:$ForceDatasetRefresh

$historyTags = @($definition.historyTags | ForEach-Object { [string]$_ }) + @('series-capture')
$measureScriptPath = Join-Path $PSScriptRoot 'Measure-BranchVsMainBenchmark.ps1'
$historyScriptPath = Join-Path $PSScriptRoot 'Record-BenchmarkHistory.ps1'

$runResults = [System.Collections.Generic.List[object]]::new()
$resultPaths = [System.Collections.Generic.List[string]]::new()
$effectiveIncludeLocalBenchmark = ($LocalOnly -or $IncludeLocalBenchmark -or $IncludePersistentLocalWorkflow)

for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
    $resultPath = Join-Path $resolvedResultsRoot ('run-{0:00}.json' -f $iteration)
    Write-Host ('Starting benchmark iteration {0}/{1}: {2}' -f $iteration, $Iterations, $resultPath) -ForegroundColor Cyan

    $measureArguments = @{
        CurrentOnly = $true
        BenchmarkDatasetId = $BenchmarkDatasetId
        ResultsOutputPath = $resultPath
        CurrentBaselineName = $CurrentBaselineName
        MinimumAvailableMemoryGB = $MinimumAvailableMemoryGB
    }
    if ($LocalOnly) {
        $measureArguments.LocalOnly = $true
    }
    elseif ($effectiveIncludeLocalBenchmark) {
        $measureArguments.IncludeLocalBenchmark = $true
    }
    if ($IncludePersistentLocalWorkflow) {
        $measureArguments.IncludePersistentLocalWorkflow = $true
    }

    & $measureScriptPath @measureArguments
    & $historyScriptPath -BenchmarkResultPath $resultPath -Tags ($historyTags + @('series', ('iteration-{0:00}' -f $iteration)))

    $runResults.Add((Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json -Depth 50)) | Out-Null
    $resultPaths.Add($resultPath) | Out-Null
}

$summaryProperties = [ordered]@{
    generated_utc = [datetime]::UtcNow.ToString('o')
    benchmark_dataset_id = [string]$definition.id
    benchmark_dataset_path = $datasetPath
    iteration_count = $Iterations
    local_only = ($LocalOnly -eq $true)
    include_local_benchmark = $effectiveIncludeLocalBenchmark
    persistent_local_workflow = ($IncludePersistentLocalWorkflow -eq $true)
    result_paths = @($resultPaths)
}

if ($runResults.Count -gt 0) {
    $summaryProperties.benchmark_mode = [string]$runResults[0].benchmark_mode
}

$metricSummary = Get-BenchmarkSeriesMetricSummary -RunResults @($runResults) -LocalOnly ($LocalOnly -eq $true) -IncludeLocalBenchmark $effectiveIncludeLocalBenchmark -IncludePersistentLocalWorkflow ($IncludePersistentLocalWorkflow -eq $true)
foreach ($property in $metricSummary.PSObject.Properties) {
    $summaryProperties[$property.Name] = $property.Value
}

$summary = [PSCustomObject]$summaryProperties

$summaryArtifacts = Write-BenchmarkSeriesSummaryOutput -ResultsRoot $resolvedResultsRoot -Summary $summary
Write-Host ('Benchmark series summary: {0}' -f $summaryArtifacts.SummaryPath) -ForegroundColor Green
Write-Host ('Benchmark series markdown: {0}' -f $summaryArtifacts.SummaryMarkdownPath) -ForegroundColor Green