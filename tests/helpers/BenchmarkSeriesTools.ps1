function Get-SeriesPercentileValue {
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

    $percentile05 = Get-SeriesPercentileValue -SortedValues $orderedValues -Percentile 5
    $percentile95 = Get-SeriesPercentileValue -SortedValues $orderedValues -Percentile 95

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

function Get-BenchmarkMetricSeriesValueList {
    [CmdletBinding()]
    [OutputType([double[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$RunResults,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Selector
    )

    $values = [System.Collections.Generic.List[double]]::new()
    foreach ($runResult in $RunResults) {
        $value = & $Selector $runResult
        if ($null -eq $value) {
            continue
        }

        $parsedValue = 0.0
        if ([double]::TryParse([string]$value, [ref]$parsedValue)) {
            $values.Add($parsedValue) | Out-Null
        }
    }

    return @($values)
}

function Get-BenchmarkSeriesMetricSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$RunResults,

        [Parameter(Mandatory = $true)]
        [bool]$LocalOnly,

        [Parameter(Mandatory = $true)]
        [bool]$IncludePersistentLocalWorkflow
    )

    return [PSCustomObject]@{
        local_elapsed_seconds = Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValueList -RunResults $RunResults -Selector {
            param($result)
            [double]$result.current.local.elapsed_seconds
        })
        runbook_elapsed_seconds = if ($LocalOnly) { $null } else { Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValueList -RunResults $RunResults -Selector {
            param($result)
            if ($null -ne $result.current.runbook) {
                [double]$result.current.runbook.elapsed_seconds
            }
        }) }
        function_active_elapsed_seconds = if ($LocalOnly) { $null } else { Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValueList -RunResults $RunResults -Selector {
            param($result)
            if ($null -ne $result.current.function_app -and $null -ne $result.current.function_app.active_elapsed_seconds) {
                [double]$result.current.function_app.active_elapsed_seconds
            }
        }) }
        function_end_to_end_elapsed_seconds = if ($LocalOnly) { $null } else { Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValueList -RunResults $RunResults -Selector {
            param($result)
            if ($null -ne $result.current.function_app) {
                [double]$result.current.function_app.end_to_end_elapsed_seconds
            }
        }) }
        function_pickup_delay_seconds = if ($LocalOnly) { $null } else { Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValueList -RunResults $RunResults -Selector {
            param($result)
            if ($null -ne $result.current.function_app -and $null -ne $result.current.function_app.pickup_delay_seconds) {
                [double]$result.current.function_app.pickup_delay_seconds
            }
        }) }
        persistent_reuse_elapsed_seconds = if ($IncludePersistentLocalWorkflow) { Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValueList -RunResults $RunResults -Selector {
            param($result)
            if ($null -ne $result.current.local_persistent_cache -and $null -ne $result.current.local_persistent_cache.reuse_after_payload_eviction) {
                [double]$result.current.local_persistent_cache.reuse_after_payload_eviction.elapsed_seconds
            }
        }) } else { $null }
    }
}

function Write-BenchmarkSeriesSummaryOutput {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResultsRoot,

        [Parameter(Mandatory = $true)]
        $Summary
    )

    $resolvedResultsRoot = [System.IO.Path]::GetFullPath($ResultsRoot)
    $summaryPath = Join-Path $resolvedResultsRoot 'series-summary.json'
    $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $summaryPath -Encoding utf8

    $summaryLines = [System.Collections.Generic.List[string]]::new()
    $summaryLines.Add('# Benchmark Series Summary') | Out-Null
    $summaryLines.Add('') | Out-Null

    $benchmarkModeProperty = $Summary.PSObject.Properties['benchmark_mode']
    if ($null -ne $benchmarkModeProperty -and -not [string]::IsNullOrWhiteSpace([string]$benchmarkModeProperty.Value)) {
        $summaryLines.Add(('- Benchmark mode: `{0}`' -f [string]$benchmarkModeProperty.Value)) | Out-Null
    }

    $baselineProperty = $Summary.PSObject.Properties['current_baseline_name']
    if ($null -ne $baselineProperty -and -not [string]::IsNullOrWhiteSpace([string]$baselineProperty.Value)) {
        $summaryLines.Add(('- Baseline: `{0}`' -f [string]$baselineProperty.Value)) | Out-Null
    }

    $datasetIdProperty = $Summary.PSObject.Properties['benchmark_dataset_id']
    if ($null -ne $datasetIdProperty -and -not [string]::IsNullOrWhiteSpace([string]$datasetIdProperty.Value)) {
        $summaryLines.Add(('- Dataset: `{0}`' -f [string]$datasetIdProperty.Value)) | Out-Null
    }

    $datasetPathProperty = $Summary.PSObject.Properties['benchmark_dataset_path']
    if ($null -ne $datasetPathProperty -and -not [string]::IsNullOrWhiteSpace([string]$datasetPathProperty.Value)) {
        $summaryLines.Add(('- Dataset path: `{0}`' -f [string]$datasetPathProperty.Value)) | Out-Null
    }

    $summaryLines.Add(('- Iterations: `{0}`' -f [int]$Summary.iteration_count)) | Out-Null
    $summaryLines.Add(('- Results root: `{0}`' -f $resolvedResultsRoot)) | Out-Null
    $summaryLines.Add('') | Out-Null
    $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Local elapsed' -Summary $Summary.local_elapsed_seconds)) | Out-Null

    $localOnly = [bool]$Summary.local_only
    if (-not $localOnly) {
        $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Runbook elapsed' -Summary $Summary.runbook_elapsed_seconds)) | Out-Null
        $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Function active elapsed' -Summary $Summary.function_active_elapsed_seconds)) | Out-Null
        $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Function end-to-end elapsed' -Summary $Summary.function_end_to_end_elapsed_seconds)) | Out-Null
        $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Function pickup delay' -Summary $Summary.function_pickup_delay_seconds)) | Out-Null
    }

    if ([bool]$Summary.persistent_local_workflow) {
        $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Persistent local reuse elapsed' -Summary $Summary.persistent_reuse_elapsed_seconds)) | Out-Null
    }

    $summaryMarkdownPath = Join-Path $resolvedResultsRoot 'series-summary.md'
    [System.IO.File]::WriteAllLines($summaryMarkdownPath, $summaryLines, [System.Text.UTF8Encoding]::new($false))

    return [PSCustomObject]@{
        SummaryPath = $summaryPath
        SummaryMarkdownPath = $summaryMarkdownPath
    }
}