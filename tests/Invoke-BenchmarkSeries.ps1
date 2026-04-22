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
    [switch]$LocalOnly,

    [Parameter(Mandatory = $false)]
    [switch]$IncludePersistentLocalWorkflow,

    [Parameter(Mandatory = $false)]
    [switch]$ForceDatasetRefresh
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Import-BenchmarkDatasetCatalog.ps1')

function Get-PercentileValue {
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [double[]]$SortedValues,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0.0, 100.0)]
        [double]$Percentile
    )

    if ($SortedValues.Count -eq 0) {
        return $null
    }

    if ($SortedValues.Count -eq 1) {
        return [math]::Round($SortedValues[0], 2)
    }

    $rank = ($Percentile / 100.0) * ($SortedValues.Count - 1)
    $lowerIndex = [int][math]::Floor($rank)
    $upperIndex = [int][math]::Ceiling($rank)
    if ($lowerIndex -eq $upperIndex) {
        return [math]::Round($SortedValues[$lowerIndex], 2)
    }

    $weight = $rank - $lowerIndex
    $interpolatedValue = $SortedValues[$lowerIndex] + (($SortedValues[$upperIndex] - $SortedValues[$lowerIndex]) * $weight)
    return [math]::Round($interpolatedValue, 2)
}

function Get-NumericSeriesSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [double[]]$Values
    )

    $filteredValues = @($Values | Where-Object { $null -ne $_ })
    if ($filteredValues.Count -eq 0) {
        return $null
    }

    $orderedValues = @($filteredValues | Sort-Object)
    $middleIndex = [math]::Floor($orderedValues.Count / 2)
    $median = if (($orderedValues.Count % 2) -eq 1) {
        $orderedValues[$middleIndex]
    }
    else {
        [math]::Round((($orderedValues[$middleIndex - 1] + $orderedValues[$middleIndex]) / 2.0), 2)
    }

    $average = [double](($orderedValues | Measure-Object -Average).Average)
    $variance = if ($orderedValues.Count -gt 1) {
        (($orderedValues | ForEach-Object { [math]::Pow(([double]$_ - $average), 2) } | Measure-Object -Sum).Sum) / ($orderedValues.Count - 1)
    }
    else {
        0.0
    }

    $percentile05 = Get-PercentileValue -SortedValues $orderedValues -Percentile 5
    $percentile95 = Get-PercentileValue -SortedValues $orderedValues -Percentile 95

    return [PSCustomObject]@{
        count = $orderedValues.Count
        min = [math]::Round(($orderedValues | Measure-Object -Minimum).Minimum, 2)
        max = [math]::Round(($orderedValues | Measure-Object -Maximum).Maximum, 2)
        average = [math]::Round($average, 2)
        median = $median
        standard_deviation = [math]::Round([math]::Sqrt($variance), 2)
        percentile_05 = $percentile05
        percentile_95 = $percentile95
        spread_90 = if ($null -ne $percentile05 -and $null -ne $percentile95) { [math]::Round(($percentile95 - $percentile05), 2) } else { $null }
    }
}

function Get-MarkdownStatisticLine {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Summary
    )

    if ($null -eq $Summary) {
        return ('- {0}: n/a' -f $Label)
    }

    return ('- {0}: min `{1:N2}s`, p05-p95 `{2:N2}s`-`{3:N2}s`, median `{4:N2}s`, avg `{5:N2}s`, max `{6:N2}s`, stdev `{7:N2}s`' -f $Label, [double]$Summary.min, [double]$Summary.percentile_05, [double]$Summary.percentile_95, [double]$Summary.median, [double]$Summary.average, [double]$Summary.max, [double]$Summary.standard_deviation)
}

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
    if ($IncludePersistentLocalWorkflow) {
        $measureArguments.IncludePersistentLocalWorkflow = $true
    }

    & $measureScriptPath @measureArguments
    & $historyScriptPath -BenchmarkResultPath $resultPath -Tags ($historyTags + @('series', ('iteration-{0:00}' -f $iteration)))

    $runResults.Add((Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json -Depth 50)) | Out-Null
    $resultPaths.Add($resultPath) | Out-Null
}

$summary = [PSCustomObject]@{
    generated_utc = [datetime]::UtcNow.ToString('o')
    benchmark_dataset_id = [string]$definition.id
    benchmark_dataset_path = $datasetPath
    iteration_count = $Iterations
    local_only = ($LocalOnly -eq $true)
    persistent_local_workflow = ($IncludePersistentLocalWorkflow -eq $true)
    result_paths = @($resultPaths)
    local_elapsed_seconds = Get-NumericSeriesSummary -Values @($runResults | ForEach-Object { [double]$_.current.local.elapsed_seconds })
    runbook_elapsed_seconds = if ($LocalOnly) { $null } else { Get-NumericSeriesSummary -Values @($runResults | ForEach-Object { [double]$_.current.runbook.elapsed_seconds }) }
    function_active_elapsed_seconds = if ($LocalOnly) { $null } else { Get-NumericSeriesSummary -Values @($runResults | ForEach-Object { if ($null -ne $_.current.function_app.active_elapsed_seconds) { [double]$_.current.function_app.active_elapsed_seconds } }) }
    function_end_to_end_elapsed_seconds = if ($LocalOnly) { $null } else { Get-NumericSeriesSummary -Values @($runResults | ForEach-Object { [double]$_.current.function_app.end_to_end_elapsed_seconds }) }
    function_pickup_delay_seconds = if ($LocalOnly) { $null } else { Get-NumericSeriesSummary -Values @($runResults | ForEach-Object { if ($null -ne $_.current.function_app.pickup_delay_seconds) { [double]$_.current.function_app.pickup_delay_seconds } }) }
    persistent_reuse_elapsed_seconds = if ($IncludePersistentLocalWorkflow) { Get-NumericSeriesSummary -Values @($runResults | ForEach-Object { [double]$_.current.local_persistent_cache.reuse_after_payload_eviction.elapsed_seconds }) } else { $null }
}

$summaryPath = Join-Path $resolvedResultsRoot 'series-summary.json'
$summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $summaryPath -Encoding utf8

$summaryLines = [System.Collections.Generic.List[string]]::new()
$summaryLines.Add('# Benchmark Series Summary') | Out-Null
$summaryLines.Add('') | Out-Null
$summaryLines.Add(('- Dataset: `{0}`' -f [string]$definition.id)) | Out-Null
$summaryLines.Add(('- Dataset path: `{0}`' -f $datasetPath)) | Out-Null
$summaryLines.Add(('- Iterations: `{0}`' -f $Iterations)) | Out-Null
$summaryLines.Add(('- Results root: `{0}`' -f $resolvedResultsRoot)) | Out-Null
$summaryLines.Add('') | Out-Null
$summaryLines.Add((Get-MarkdownStatisticLine -Label 'Local elapsed' -Summary $summary.local_elapsed_seconds)) | Out-Null
if (-not $LocalOnly) {
    $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Runbook elapsed' -Summary $summary.runbook_elapsed_seconds)) | Out-Null
    $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Function active elapsed' -Summary $summary.function_active_elapsed_seconds)) | Out-Null
    $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Function end-to-end elapsed' -Summary $summary.function_end_to_end_elapsed_seconds)) | Out-Null
    $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Function pickup delay' -Summary $summary.function_pickup_delay_seconds)) | Out-Null
}
if ($IncludePersistentLocalWorkflow) {
    $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Persistent local reuse elapsed' -Summary $summary.persistent_reuse_elapsed_seconds)) | Out-Null
}

$summaryMarkdownPath = Join-Path $resolvedResultsRoot 'series-summary.md'
[System.IO.File]::WriteAllLines($summaryMarkdownPath, $summaryLines, [System.Text.UTF8Encoding]::new($false))

Write-Host ('Benchmark series summary: {0}' -f $summaryPath) -ForegroundColor Green
Write-Host ('Benchmark series markdown: {0}' -f $summaryMarkdownPath) -ForegroundColor Green