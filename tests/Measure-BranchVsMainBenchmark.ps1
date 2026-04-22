#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CurrentRepoPath = (Split-Path -Path $PSScriptRoot -Parent),

    [Parameter(Mandatory = $false)]
    [string]$MainRepoPath = (Join-Path $env:TEMP 'defender-reporting-main-bench'),

    [Parameter(Mandatory = $false)]
    [string]$DatasetPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports-synthetic'),

    [Parameter(Mandatory = $false)]
    [string]$BenchmarkDatasetId,

    [Parameter(Mandatory = $false)]
    [string]$AutomationAccountName = 'aa-defender-reporting',

    [Parameter(Mandatory = $false)]
    [string]$AutomationResourceGroup = 'rg-defender-reporting',

    [Parameter(Mandatory = $false)]
    [string]$RunbookName = 'Invoke-DashboardPipeline',

    [Parameter(Mandatory = $false)]
    [string]$RunbookStorageAccountName = 'stdefenderrepaad73',

    [Parameter(Mandatory = $false)]
    [string]$FunctionAppName = 'func-defender-reporting-parallel-0404a',

    [Parameter(Mandatory = $false)]
    [string]$FunctionAppResourceGroup = 'rg-defender-reporting-parallel',

    [Parameter(Mandatory = $false)]
    [string]$FunctionStorageAccountName = 'stdefrepaad730404a',

    [Parameter(Mandatory = $false)]
    [string]$ResultsOutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'reports' ('branch-vs-main-benchmark-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')),

    [Parameter(Mandatory = $false)]
    [string]$CurrentBaselineName = 'current-working-tree',

    [Parameter(Mandatory = $false)]
    [string]$MainBaselineName = 'main-clean',

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 60)]
    [int]$PollIntervalSeconds = 15,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0.5, 256.0)]
    [double]$MinimumAvailableMemoryGB = 8,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 2048)]
    [int]$MinimumFreeDiskGB = 10,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50000000)]
    [int]$MaximumDatasetRows = 2500000,

    [Parameter(Mandatory = $false)]
    [switch]$AllowLargeDataset,

    [Parameter(Mandatory = $false)]
    [switch]$CurrentOnly,

    [Parameter(Mandatory = $false)]
    [switch]$LocalOnly,

    [Parameter(Mandatory = $false)]
    [switch]$IncludePersistentLocalWorkflow,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRestoreCurrentDeployment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:AutomationAccountName = $AutomationAccountName
$script:AutomationResourceGroup = $AutomationResourceGroup
$script:RunbookName = $RunbookName
$script:RunbookStorageAccountName = $RunbookStorageAccountName
$script:FunctionAppName = $FunctionAppName
$script:FunctionAppResourceGroup = $FunctionAppResourceGroup
$script:FunctionStorageAccountName = $FunctionStorageAccountName
$script:PollIntervalSeconds = $PollIntervalSeconds

. (Join-Path $PSScriptRoot 'Import-BenchmarkDatasetCatalog.ps1')

function Get-HeartbeatTimestampText {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}

function ConvertTo-UtcDateTime {
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

function Get-ObjectPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-TextWithoutAnsiEscape {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    return ([regex]::Replace($Text, "`e\[[0-9;]*m", ''))
}

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

function Get-BenchmarkMetricSeriesValues {
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

function Write-AdHocBenchmarkSeriesSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResultPath
    )

    $resultLeaf = Split-Path -Path $ResultPath -Leaf
    if ($resultLeaf -notlike 'run-*.json') {
        return
    }

    $resultsDirectory = Split-Path -Path $ResultPath -Parent
    $resultFiles = @(Get-ChildItem -LiteralPath $resultsDirectory -Filter 'run-*.json' -File | Sort-Object Name)
    if ($resultFiles.Count -eq 0) {
        return
    }

    $runResults = [System.Collections.Generic.List[object]]::new()
    $resultPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($resultFile in $resultFiles) {
        $runResults.Add((Get-Content -LiteralPath $resultFile.FullName -Raw | ConvertFrom-Json -Depth 50)) | Out-Null
        $resultPaths.Add($resultFile.FullName) | Out-Null
    }

    $firstResult = $runResults[0]
    $dataset = Get-ObjectPropertyValue -InputObject $firstResult -Name 'dataset'
    $datasetDefinition = Get-ObjectPropertyValue -InputObject $dataset -Name 'definition'
    $currentBaseline = Get-ObjectPropertyValue -InputObject (Get-ObjectPropertyValue -InputObject $firstResult -Name 'current') -Name 'baseline'
    $localOnly = [bool](Get-ObjectPropertyValue -InputObject $firstResult -Name 'local_only')
    $persistentLocalWorkflow = [bool](Get-ObjectPropertyValue -InputObject $firstResult -Name 'persistent_local_workflow')

    $summary = [PSCustomObject]@{
        generated_utc = [datetime]::UtcNow.ToString('o')
        benchmark_mode = [string](Get-ObjectPropertyValue -InputObject $firstResult -Name 'benchmark_mode')
        benchmark_dataset_id = [string](Get-ObjectPropertyValue -InputObject $datasetDefinition -Name 'id')
        benchmark_dataset_path = [string](Get-ObjectPropertyValue -InputObject $dataset -Name 'path')
        iteration_count = $runResults.Count
        local_only = $localOnly
        persistent_local_workflow = $persistentLocalWorkflow
        current_baseline_name = [string]$currentBaseline
        result_paths = @($resultPaths)
        local_elapsed_seconds = Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValues -RunResults $runResults -Selector {
            param($result)
            $current = Get-ObjectPropertyValue -InputObject $result -Name 'current'
            $local = Get-ObjectPropertyValue -InputObject $current -Name 'local'
            Get-ObjectPropertyValue -InputObject $local -Name 'elapsed_seconds'
        })
        runbook_elapsed_seconds = if ($localOnly) { $null } else { Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValues -RunResults $runResults -Selector {
            param($result)
            $current = Get-ObjectPropertyValue -InputObject $result -Name 'current'
            $runbook = Get-ObjectPropertyValue -InputObject $current -Name 'runbook'
            Get-ObjectPropertyValue -InputObject $runbook -Name 'elapsed_seconds'
        }) }
        function_active_elapsed_seconds = if ($localOnly) { $null } else { Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValues -RunResults $runResults -Selector {
            param($result)
            $current = Get-ObjectPropertyValue -InputObject $result -Name 'current'
            $functionApp = Get-ObjectPropertyValue -InputObject $current -Name 'function_app'
            Get-ObjectPropertyValue -InputObject $functionApp -Name 'active_elapsed_seconds'
        }) }
        function_end_to_end_elapsed_seconds = if ($localOnly) { $null } else { Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValues -RunResults $runResults -Selector {
            param($result)
            $current = Get-ObjectPropertyValue -InputObject $result -Name 'current'
            $functionApp = Get-ObjectPropertyValue -InputObject $current -Name 'function_app'
            Get-ObjectPropertyValue -InputObject $functionApp -Name 'end_to_end_elapsed_seconds'
        }) }
        function_pickup_delay_seconds = if ($localOnly) { $null } else { Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValues -RunResults $runResults -Selector {
            param($result)
            $current = Get-ObjectPropertyValue -InputObject $result -Name 'current'
            $functionApp = Get-ObjectPropertyValue -InputObject $current -Name 'function_app'
            Get-ObjectPropertyValue -InputObject $functionApp -Name 'pickup_delay_seconds'
        }) }
        persistent_reuse_elapsed_seconds = if ($persistentLocalWorkflow) { Get-NumericSeriesSummary -Values (Get-BenchmarkMetricSeriesValues -RunResults $runResults -Selector {
            param($result)
            $current = Get-ObjectPropertyValue -InputObject $result -Name 'current'
            $localPersistentCache = Get-ObjectPropertyValue -InputObject $current -Name 'local_persistent_cache'
            $reuse = Get-ObjectPropertyValue -InputObject $localPersistentCache -Name 'reuse_after_payload_eviction'
            Get-ObjectPropertyValue -InputObject $reuse -Name 'elapsed_seconds'
        }) } else { $null }
    }

    $summaryPath = Join-Path $resultsDirectory 'series-summary.json'
    $summary | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $summaryPath -Encoding utf8

    $summaryLines = [System.Collections.Generic.List[string]]::new()
    $summaryLines.Add('# Benchmark Series Summary') | Out-Null
    $summaryLines.Add('') | Out-Null
    $summaryLines.Add(('- Benchmark mode: `{0}`' -f [string]$summary.benchmark_mode)) | Out-Null
    if (-not [string]::IsNullOrWhiteSpace([string]$summary.current_baseline_name)) {
        $summaryLines.Add(('- Baseline: `{0}`' -f [string]$summary.current_baseline_name)) | Out-Null
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$summary.benchmark_dataset_id)) {
        $summaryLines.Add(('- Dataset: `{0}`' -f [string]$summary.benchmark_dataset_id)) | Out-Null
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$summary.benchmark_dataset_path)) {
        $summaryLines.Add(('- Dataset path: `{0}`' -f [string]$summary.benchmark_dataset_path)) | Out-Null
    }
    $summaryLines.Add(('- Iterations: `{0}`' -f $summary.iteration_count)) | Out-Null
    $summaryLines.Add(('- Results root: `{0}`' -f $resultsDirectory)) | Out-Null
    $summaryLines.Add('') | Out-Null
    $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Local elapsed' -Summary $summary.local_elapsed_seconds)) | Out-Null
    if (-not $localOnly) {
        $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Runbook elapsed' -Summary $summary.runbook_elapsed_seconds)) | Out-Null
        $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Function active elapsed' -Summary $summary.function_active_elapsed_seconds)) | Out-Null
        $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Function end-to-end elapsed' -Summary $summary.function_end_to_end_elapsed_seconds)) | Out-Null
        $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Function pickup delay' -Summary $summary.function_pickup_delay_seconds)) | Out-Null
    }
    if ($persistentLocalWorkflow) {
        $summaryLines.Add((Get-MarkdownStatisticLine -Label 'Persistent local reuse elapsed' -Summary $summary.persistent_reuse_elapsed_seconds)) | Out-Null
    }

    $summaryMarkdownPath = Join-Path $resultsDirectory 'series-summary.md'
    [System.IO.File]::WriteAllLines($summaryMarkdownPath, $summaryLines, [System.Text.UTF8Encoding]::new($false))
}

function Get-LocalDiagnosticTimingSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
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

        $timestampUtc = ConvertTo-UtcDateTime -Value $parts[0]
        if ($null -eq $timestampUtc) {
            continue
        }

        $eventType = [string]$parts[1]
        $name = [string]$parts[2]
        $status = if ($parts.Count -ge 4) { [string]$parts[3] } else { $null }

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
                    $phaseByName[$name] = [ordered]@{
                        name = $name
                        start_utc = $null
                        end_utc = $null
                        status = $null
                    }
                }

                if ($null -eq $phaseByName[$name].start_utc) {
                    $phaseByName[$name].start_utc = $timestampUtc
                }
            }
            'phase-end' {
                if (-not $phaseByName.Contains($name)) {
                    $phaseByName[$name] = [ordered]@{
                        name = $name
                        start_utc = $null
                        end_utc = $null
                        status = $null
                    }
                }

                $phaseByName[$name].end_utc = $timestampUtc
                $phaseByName[$name].status = $status
            }
        }
    }

    $phaseSummaries = @(
        foreach ($phaseEntry in $phaseByName.Values) {
            $elapsedSeconds = if ($null -ne $phaseEntry.start_utc -and $null -ne $phaseEntry.end_utc) {
                [math]::Round((New-TimeSpan -Start $phaseEntry.start_utc -End $phaseEntry.end_utc).TotalSeconds, 2)
            }
            else {
                $null
            }

            [PSCustomObject]@{
                name = [string]$phaseEntry.name
                status = if ([string]::IsNullOrWhiteSpace([string]$phaseEntry.status)) { 'unknown' } else { [string]$phaseEntry.status }
                elapsedSeconds = $elapsedSeconds
            }
        }
    )

    return [PSCustomObject]@{
        path = $Path
        phase_summaries = $phaseSummaries
        pipeline_elapsed_seconds = if ($null -ne $pipelineStartUtc -and $null -ne $pipelineEndUtc) {
            [math]::Round((New-TimeSpan -Start $pipelineStartUtc -End $pipelineEndUtc).TotalSeconds, 2)
        }
        else {
            $null
        }
    }
}

function Get-LocalPhaseSummaryFromLog {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }

    $phaseByName = [ordered]@{}
    foreach ($rawLine in Get-Content -Path $Path) {
        $line = Get-TextWithoutAnsiEscape -Text ([string]$rawLine)
        if ($line -match '^\s*--- Local Phase: (?<name>.+?) ---\s*$') {
            $phaseName = [string]$matches.name
            if (-not $phaseByName.Contains($phaseName)) {
                $phaseByName[$phaseName] = [ordered]@{
                    name = $phaseName
                    status = 'started'
                    elapsedSeconds = $null
                }
            }

            continue
        }

        if ($line -match '^\s*\[(?<name>.+?)\] Elapsed: (?<seconds>[0-9.,]+)s(?:\s*\((?<status>[^)]+)\))?\s*$') {
            $phaseName = [string]$matches.name
            if (-not $phaseByName.Contains($phaseName)) {
                $phaseByName[$phaseName] = [ordered]@{ name = $phaseName }
            }

            $phaseEntry = $phaseByName[$phaseName]
            $phaseEntry.elapsedSeconds = [double](($matches.seconds -replace ',', ''))
            $phaseEntry.status = if ($matches.status) { [string]$matches.status } else { 'completed' }
        }
    }

    return @(
        foreach ($phaseEntry in $phaseByName.Values) {
            [PSCustomObject]@{
                name = [string]$phaseEntry.name
                status = if ($phaseEntry.Contains('status')) { [string]$phaseEntry.status } else { 'unknown' }
                elapsedSeconds = if ($phaseEntry.Contains('elapsedSeconds')) { $phaseEntry.elapsedSeconds } else { $null }
            }
        }
    )
}

function Get-LocalBenchmarkLogSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DiagnosticLogPath
    )

    $phaseSummary = [ordered]@{}
    $diagnosticTimingSummary = if ([string]::IsNullOrWhiteSpace($DiagnosticLogPath)) {
        $null
    }
    else {
        Get-LocalDiagnosticTimingSummary -Path $DiagnosticLogPath
    }

    $phaseEntries = if ($null -ne $diagnosticTimingSummary -and @($diagnosticTimingSummary.phase_summaries).Count -gt 0) {
        @($diagnosticTimingSummary.phase_summaries)
    }
    else {
        @(Get-LocalPhaseSummaryFromLog -Path $StdoutPath)
    }

    foreach ($phase in $phaseEntries) {
        if ($null -ne $phase.elapsedSeconds) {
            $phaseSummary[[string]$phase.name] = [double]$phase.elapsedSeconds
        }
    }

    $stdoutText = if (Test-Path -LiteralPath $StdoutPath -PathType Leaf) {
        Get-TextWithoutAnsiEscape -Text (Get-Content -LiteralPath $StdoutPath -Raw)
    }
    else {
        ''
    }

    return [PSCustomObject]@{
        phase_elapsed_seconds = [PSCustomObject]$phaseSummary
        phase_timing_source = if ($null -ne $diagnosticTimingSummary -and @($diagnosticTimingSummary.phase_summaries).Count -gt 0) { 'diagnostic-log' } else { 'stdout' }
        pipeline_elapsed_seconds = if ($null -ne $diagnosticTimingSummary) { $diagnosticTimingSummary.pipeline_elapsed_seconds } else { $null }
        used_cached_payload = ($stdoutText -match 'Reusing cached normalized payload')
        used_cached_vuln_columns = ($stdoutText -match 'Reusing cached normalized vuln columns')
        published_cached_vuln_columns = ($stdoutText -match 'Cached normalized vuln columns as')
    }
}

function Get-LocalBenchmarkProcessReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatasetPath
    )

    $reportPath = Join-Path -Path $DatasetPath -ChildPath 'stress-validation-report.json'
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        return $null
    }

    return [PSCustomObject]@{
        path = $reportPath
        report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 50
    }
}

function Get-LocalBenchmarkProcessTimingSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $ProcessReport
    )

    if ($null -eq $ProcessReport -or $null -eq $ProcessReport.report) {
        return $null
    }

    $generationTiming = Get-ObjectPropertyValue -InputObject $ProcessReport.report -Name 'generationTiming'
    if ($null -eq $generationTiming) {
        return $null
    }

    $phaseTimings = Get-ObjectPropertyValue -InputObject $generationTiming -Name 'phaseTimings'
    if ($null -eq $phaseTimings) {
        return $null
    }

    return [PSCustomObject]@{
        phase_elapsed_seconds = $phaseTimings
        phase_timing_source = 'process-report'
        pipeline_elapsed_seconds = Get-ObjectPropertyValue -InputObject $generationTiming -Name 'pipelineElapsedSeconds'
        wrapper_overhead_seconds = Get-ObjectPropertyValue -InputObject $generationTiming -Name 'wrapperOverheadSeconds'
    }
}

function Invoke-AzCli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $false)]
        [switch]$ExpectJson,

        [Parameter(Mandatory = $false)]
        [switch]$AllowEmpty
    )

    $output = (& az @Arguments 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw ("az {0}`n{1}" -f ($Arguments -join ' '), $output.Trim())
    }

    $trimmed = $output.Trim()
    if (-not $ExpectJson) {
        return $trimmed
    }

    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        if ($AllowEmpty) {
            return $null
        }

        throw ("Expected JSON output from az {0}, but command returned nothing." -f ($Arguments -join ' '))
    }

    $jsonLines = @($trimmed -split "`r?`n")
    $jsonStartIndex = -1
    for ($index = 0; $index -lt $jsonLines.Count; $index++) {
        if ($jsonLines[$index] -match '^\s*[\[{]') {
            $jsonStartIndex = $index
            break
        }
    }

    if ($jsonStartIndex -ge 0) {
        $trimmed = (($jsonLines[$jsonStartIndex..($jsonLines.Count - 1)]) -join "`n").Trim()
    }

    return ($trimmed | ConvertFrom-Json -Depth 100)
}

function Invoke-RepoScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string]$RelativeScriptPath,

        [Parameter(Mandatory = $false)]
        [hashtable]$Arguments = @{}
    )

    $scriptPath = Join-Path -Path $RepoPath -ChildPath $RelativeScriptPath
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Script not found: $scriptPath"
    }

    Push-Location $RepoPath
    try {
        & $scriptPath @Arguments | Out-Host
    }
    finally {
        Pop-Location
    }
}

function Write-BaselineBenchmarkHeartbeat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselineName,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$LocalState,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $RunbookJob,

        [Parameter(Mandatory = $true)]
        [string]$FunctionStatus,

        [Parameter(Mandatory = $true)]
        [datetime]$FunctionInvokeStartedUtc,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $FunctionExecutionActivity
    )

    $localElapsedSeconds = [math]::Round($LocalState.stopwatch.Elapsed.TotalSeconds, 2)
    $localStatus = if ($LocalState.completed) { 'Completed' } else { 'Running' }
    $localPeakRssGb = [math]::Round(($LocalState.peakRssBytes / 1GB), 3)
    $runbookStatus = if ($null -ne $RunbookJob -and $RunbookJob.PSObject.Properties['status']) { [string]$RunbookJob.status } else { 'Pending' }
    $functionElapsedSeconds = [math]::Round((New-TimeSpan -Start $FunctionInvokeStartedUtc -End ([datetime]::UtcNow)).TotalSeconds, 2)
    $functionExecutionCount = if ($null -ne $FunctionExecutionActivity -and $FunctionExecutionActivity.PSObject.Properties['total_count']) { [int]$FunctionExecutionActivity.total_count } else { 0 }

    $message = "[{0}] {1} heartbeat: local={2} elapsed={3:N0}s peak-rss={4}GB; runbook={5}; function={6} elapsed={7:N0}s exec-count={8}" -f @(
        (Get-HeartbeatTimestampText)
        $BaselineName
        $localStatus
        $localElapsedSeconds
        $localPeakRssGb
        $runbookStatus
        $FunctionStatus
        $functionElapsedSeconds
        $functionExecutionCount
    )
    Write-Host $message
}

function Get-DatasetFiles {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper intentionally returns a collection of dataset files.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return @(
        Get-ChildItem -LiteralPath $Path -File |
            Where-Object {
                $_.Name -match '\.json(\.gz)?$' -and
                $_.Name -notin @(
                    '.synthetic-progress.json',
                    '.synthetic-progress.json.gz',
                    'stress-validation-report.json',
                    'stress-validation-report.json.gz'
                )
            } |
            Sort-Object -Property Name
    )
}

function Copy-BenchmarkDataset {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper stages a working dataset directory for repeatable local runs.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDatasetPath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationDatasetPath
    )

    if (Test-Path -LiteralPath $DestinationDatasetPath) {
        Remove-Item -LiteralPath $DestinationDatasetPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    $null = New-Item -Path $DestinationDatasetPath -ItemType Directory -Force
    foreach ($datasetFile in Get-DatasetFiles -Path $SourceDatasetPath) {
        Copy-Item -LiteralPath $datasetFile.FullName -Destination (Join-Path -Path $DestinationDatasetPath -ChildPath $datasetFile.Name) -Force
    }
}

function Reset-LocalBenchmarkCache {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper only clears derived dashboard cache content in the staged benchmark dataset.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatasetPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('all', 'payload-only', 'none')]
        [string]$Mode = 'all'
    )

    if ($Mode -eq 'none') {
        return
    }

    $cachePath = Join-Path -Path $DatasetPath -ChildPath '.dashboard-cache'
    if (-not (Test-Path -LiteralPath $cachePath -PathType Container)) {
        return
    }

    switch ($Mode) {
        'all' {
            Remove-Item -LiteralPath $cachePath -Recurse -Force -ErrorAction SilentlyContinue
        }
        'payload-only' {
            $payloadPath = Join-Path -Path $cachePath -ChildPath 'payloads'
            if (Test-Path -LiteralPath $payloadPath -PathType Container) {
                Remove-Item -LiteralPath $payloadPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-FreeDiskByteCount {
    [CmdletBinding()]
    [OutputType([int64])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($resolvedPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "Unable to determine drive root for '$resolvedPath'."
    }

    return [int64]([System.IO.DriveInfo]::new($root).AvailableFreeSpace)
}

function Assert-BenchmarkDatasetReady {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatasetPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $true)]
        [int]$MaximumDatasetRows,

        [Parameter(Mandatory = $true)]
        [bool]$AllowLargeDataset,

        [Parameter(Mandatory = $true)]
        [double]$MinimumAvailableMemoryGB,

        [Parameter(Mandatory = $true)]
        [int]$MinimumFreeDiskGB
    )

    $manifestPath = Join-Path -Path $DatasetPath -ChildPath 'synthetic-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Synthetic benchmark dataset is incomplete. Missing manifest: $manifestPath"
    }

    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
    $progressPath = Join-Path -Path $DatasetPath -ChildPath '.synthetic-progress.json'
    $progress = if (Test-Path -LiteralPath $progressPath -PathType Leaf) {
        Get-Content -LiteralPath $progressPath -Raw | ConvertFrom-Json -Depth 20
    }
    else {
        $null
    }

    if ($null -ne $progress -and [string]$progress.stage -ne 'completed') {
        throw ("Synthetic benchmark dataset is incomplete. Progress file reports stage '{0}'." -f [string]$progress.stage)
    }

    $missingFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($requiredName in @('Machines_Current.json.gz', 'VulnContentDictionary.json.gz', 'VulnCurrentRefs.json.gz')) {
        if (-not (Test-Path -LiteralPath (Join-Path -Path $DatasetPath -ChildPath $requiredName) -PathType Leaf)) {
            $missingFiles.Add($requiredName)
        }
    }

    if (@(Get-ChildItem -LiteralPath $DatasetPath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue).Count -eq 0) {
        $missingFiles.Add('VulnHistoryRefs_*.json.gz')
    }

    if ($missingFiles.Count -gt 0) {
        throw ("Synthetic benchmark dataset is incomplete. Missing required file(s): {0}" -f ($missingFiles -join ', '))
    }

    if (-not ($manifest.PSObject.Properties['actualCurrentRows'] -and $manifest.PSObject.Properties['actualHistoryRows'])) {
        throw 'Synthetic benchmark dataset manifest is missing actual row counts.'
    }

    $totalRows = [int]$manifest.actualCurrentRows + [int]$manifest.actualHistoryRows
    if ($totalRows -le 0) {
        throw 'Synthetic benchmark dataset manifest reports zero rows.'
    }

    if ($manifest.PSObject.Properties['targetTotalVulnRows']) {
        $targetTotalRows = [int]$manifest.targetTotalVulnRows
        if ($targetTotalRows -gt 0 -and $targetTotalRows -ne $totalRows) {
            throw ("Synthetic benchmark dataset manifest does not match its requested size. actual rows={0}; target rows={1}." -f $totalRows, $targetTotalRows)
        }
    }

    if ($totalRows -gt $MaximumDatasetRows -and -not $AllowLargeDataset) {
        throw ("Synthetic benchmark dataset has {0} rows, which exceeds the unattended benchmark limit of {1}. Re-run with -AllowLargeDataset only after reviewing memory headroom." -f $totalRows, $MaximumDatasetRows)
    }

    $datasetFiles = @(Get-DatasetFiles -Path $DatasetPath)
    $datasetBytes = [int64](($datasetFiles | Measure-Object -Property Length -Sum).Sum)
    $availableMemoryGB = Get-AvailableMemoryGB
    if ($availableMemoryGB -lt $MinimumAvailableMemoryGB) {
        throw ("Available system memory is {0} GB, below the benchmark preflight floor of {1} GB." -f $availableMemoryGB, $MinimumAvailableMemoryGB)
    }

    $freeDiskBytes = Get-FreeDiskByteCount -Path $OutputDirectory
    $requiredFreeDiskBytes = [Math]::Max(([int64]$MinimumFreeDiskGB * 1GB), (($datasetBytes * 2) + 2GB))
    if ($freeDiskBytes -lt $requiredFreeDiskBytes) {
        throw ("Available disk space on the benchmark output drive is {0:N2} GB, but at least {1:N2} GB is required for the dataset copy and outputs." -f ($freeDiskBytes / 1GB), ($requiredFreeDiskBytes / 1GB))
    }

    if ($totalRows -gt $MaximumDatasetRows) {
        Write-Warning ("Large benchmark dataset override enabled for {0} rows." -f $totalRows)
    }

    return [PSCustomObject]@{
        manifest = $manifest
        progress = $progress
        totalRows = $totalRows
        datasetBytes = $datasetBytes
        availableMemoryGB = $availableMemoryGB
        freeDiskGB = [math]::Round(($freeDiskBytes / 1GB), 2)
        requiredFreeDiskGB = [math]::Round(($requiredFreeDiskBytes / 1GB), 2)
    }
}

function Get-BenchmarkDatasetResultMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Metadata is a fixed benchmark sidecar concept in this repository and matches benchmark-dataset.json.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatasetPath,

        [Parameter(Mandatory = $true)]
        $Manifest,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$BenchmarkDatasetId,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $metadata = Get-BenchmarkDatasetMetadata -DatasetPath $DatasetPath
    $definition = $null

    if ($null -ne $metadata -and $metadata.PSObject.Properties['id'] -and -not [string]::IsNullOrWhiteSpace([string]$metadata.id)) {
        $definition = Get-BenchmarkDatasetDefinition -DatasetId ([string]$metadata.id) -RepoRoot $RepoRoot
    }

    if ($null -eq $definition -and -not [string]::IsNullOrWhiteSpace($BenchmarkDatasetId)) {
        $definition = Get-BenchmarkDatasetDefinition -DatasetId $BenchmarkDatasetId -RepoRoot $RepoRoot
    }

    if ($null -eq $definition) {
        $definition = Find-BenchmarkDatasetDefinitionForManifest -Manifest $Manifest -RepoRoot $RepoRoot
    }

    if ($null -eq $definition) {
        return $null
    }

    return [PSCustomObject]@{
        id = [string]$definition.id
        description = [string]$definition.description
        preset = [string]$definition.preset
        seed = [int]$definition.seed
        target_device_count = [int]$definition.targetDeviceCount
        target_total_vuln_rows = [int]$definition.targetTotalVulnRows
        output_path = Resolve-BenchmarkDatasetOutputPath -Definition $definition -RepoRoot $RepoRoot
        history_tags = @($definition.historyTags)
    }
}

function Clear-BlobContainer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName
    )

    $blobs = @(Invoke-AzCli -Arguments @('storage', 'blob', 'list', '--account-name', $AccountName, '--container-name', $ContainerName, '--auth-mode', 'login', '-o', 'json') -ExpectJson -AllowEmpty)
    foreach ($blob in $blobs) {
        Invoke-AzCli -Arguments @('storage', 'blob', 'delete', '--account-name', $AccountName, '--container-name', $ContainerName, '--name', $blob.name, '--auth-mode', 'login', '--output', 'none') | Out-Null
    }
}

function Seed-ExportsContainer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper prepares the benchmark exports container for a run.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$DatasetRoot
    )

    Clear-BlobContainer -AccountName $AccountName -ContainerName 'exports'
    foreach ($file in (Get-DatasetFiles -Path $DatasetRoot)) {
        $contentType = if ($file.Name.EndsWith('.gz')) { 'application/gzip' } else { 'application/json' }
        Invoke-AzCli -Arguments @(
            'storage', 'blob', 'upload',
            '--account-name', $AccountName,
            '--container-name', 'exports',
            '--name', $file.Name,
            '--file', $file.FullName,
            '--content-type', $contentType,
            '--auth-mode', 'login',
            '--overwrite',
            '--output', 'none'
        ) | Out-Null
    }
}

function Get-BlobDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName
    )

    try {
        return (Invoke-AzCli -Arguments @(
            'storage', 'blob', 'show',
            '--account-name', $AccountName,
            '--container-name', $ContainerName,
            '--name', $BlobName,
            '--auth-mode', 'login',
            '-o', 'json'
        ) -ExpectJson)
    }
    catch {
        if ($_.Exception.Message -match 'BlobNotFound|ResourceNotFound|The specified blob does not exist') {
            return $null
        }

        throw
    }
}

function Get-BlobTextContent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName
    )

    $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) ('blob-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        Invoke-AzCli -Arguments @(
            'storage', 'blob', 'download',
            '--account-name', $AccountName,
            '--container-name', $ContainerName,
            '--name', $BlobName,
            '--file', $tempPath,
            '--auth-mode', 'login',
            '--overwrite',
            '--output', 'none'
        ) | Out-Null

        if (-not (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            return $null
        }

        return (Get-Content -LiteralPath $tempPath -Raw)
    }
    catch {
        if ($_.Exception.Message -match 'BlobNotFound|ResourceNotFound|The specified blob does not exist') {
            return $null
        }

        throw
    }
    finally {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-FunctionExecutionStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName
    )

    $statusContent = Get-BlobTextContent -AccountName $AccountName -ContainerName 'dashboards' -BlobName '_diagnostics/ExportAndGenerate.status.json'
    if ([string]::IsNullOrWhiteSpace($statusContent)) {
        return $null
    }

    return ($statusContent | ConvertFrom-Json -Depth 30)
}

function Get-BlobLengthBytes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper returns one blob length value in bytes.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName
    )

    $blob = Get-BlobDetail -AccountName $AccountName -ContainerName $ContainerName -BlobName $BlobName
    if ($null -eq $blob) {
        return [int64]0
    }

    return [int64]$blob.properties.contentLength
}

function Build-AndDeploy-Runbook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath
    )

    Invoke-RepoScript -RepoPath $RepoPath -RelativeScriptPath 'build/azure/Build-Runbook.ps1'

    $artifactPath = Join-Path -Path $RepoPath -ChildPath 'azure/Invoke-DashboardPipeline.ps1'
    Invoke-AzCli -Arguments @(
        'automation', 'runbook', 'replace-content',
        '--automation-account-name', $AutomationAccountName,
        '--resource-group', $AutomationResourceGroup,
        '--name', $RunbookName,
        '--content', ("@{0}" -f $artifactPath)
    ) | Out-Null
    Invoke-AzCli -Arguments @(
        'automation', 'runbook', 'publish',
        '--automation-account-name', $AutomationAccountName,
        '--resource-group', $AutomationResourceGroup,
        '--name', $RunbookName
    ) | Out-Null
}

function Build-AndDeploy-FunctionApp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath
    )

    Invoke-RepoScript -RepoPath $RepoPath -RelativeScriptPath 'build/azure/Build-FunctionApp.ps1'

    $functionAppDir = Join-Path -Path $RepoPath -ChildPath 'azure/function-app'
    $zipPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('funcapp-deploy-' + [guid]::NewGuid().ToString('N') + '.zip')

    Push-Location $functionAppDir
    try {
        Compress-Archive -Path '.\*' -DestinationPath $zipPath -Force
    }
    finally {
        Pop-Location
    }

    try {
        $maxAttempts = 3
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            try {
                Invoke-AzCli -Arguments @(
                    'functionapp', 'deployment', 'source', 'config-zip',
                    '--src', $zipPath,
                    '--name', $FunctionAppName,
                    '--resource-group', $FunctionAppResourceGroup,
                    '--output', 'none'
                ) | Out-Null
                break
            }
            catch {
                if ($_.Exception.Message -match 'Deployment was partially successful') {
                    Write-Warning 'Function App zip deployment reported partial success without retained logs. Continuing and relying on host readiness validation.'
                    break
                }

                if ($attempt -ge $maxAttempts -or $_.Exception.Message -notmatch 'BadGatewayConnection|Bad Gateway') {
                    throw
                }

                Write-Warning ("Function App zip deployment hit a transient gateway error (attempt {0}/{1}). Retrying..." -f $attempt, $maxAttempts)
                Start-Sleep -Seconds (5 * $attempt)
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-FunctionHostName {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Invoke-AzCli -Arguments @('functionapp', 'show', '--name', $FunctionAppName, '--resource-group', $FunctionAppResourceGroup, '--query', 'properties.defaultHostName', '-o', 'tsv'))
}

function Get-FunctionResourceId {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Invoke-AzCli -Arguments @('functionapp', 'show', '--name', $FunctionAppName, '--resource-group', $FunctionAppResourceGroup, '--query', 'id', '-o', 'tsv'))
}

function Get-FunctionMasterKey {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $keys = Invoke-AzCli -Arguments @('functionapp', 'keys', 'list', '--name', $FunctionAppName, '--resource-group', $FunctionAppResourceGroup, '-o', 'json') -ExpectJson
    return [string]$keys.masterKey
}

function Get-FunctionMetricSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTimeUtc,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTimeUtc
    )

    $metrics = Invoke-AzCli -Arguments @(
        'monitor', 'metrics', 'list',
        '--resource', $ResourceId,
        '--start-time', $StartTimeUtc.ToString('o'),
        '--end-time', $EndTimeUtc.ToString('o'),
        '--interval', 'PT1M',
        '--aggregation', 'Average', 'Maximum', 'Total',
        '--metrics', 'MemoryWorkingSet', 'AverageMemoryWorkingSet', 'CpuPercentage', 'OnDemandFunctionExecutionUnits',
        '-o', 'json'
    ) -ExpectJson

    $peakWorkingSetMb = 0.0
    $averageWorkingSetMb = 0.0
    $peakCpuPercentage = 0.0
    $executionUnits = 0.0

    foreach ($metric in @($metrics.value)) {
        $metricName = [string]$metric.name.value
        $dataPoints = @($metric.timeseries | ForEach-Object { $_.data })
        foreach ($dataPoint in $dataPoints) {
            switch ($metricName) {
                'MemoryWorkingSet' {
                    if ($null -ne $dataPoint.maximum) {
                        $peakWorkingSetMb = [math]::Max($peakWorkingSetMb, ([double]$dataPoint.maximum / 1MB))
                    }
                    elseif ($null -ne $dataPoint.average) {
                        $peakWorkingSetMb = [math]::Max($peakWorkingSetMb, ([double]$dataPoint.average / 1MB))
                    }
                }
                'AverageMemoryWorkingSet' {
                    if ($null -ne $dataPoint.average) {
                        $averageWorkingSetMb = [math]::Max($averageWorkingSetMb, ([double]$dataPoint.average / 1MB))
                    }
                }
                'CpuPercentage' {
                    if ($null -ne $dataPoint.maximum) {
                        $peakCpuPercentage = [math]::Max($peakCpuPercentage, [double]$dataPoint.maximum)
                    }
                    elseif ($null -ne $dataPoint.average) {
                        $peakCpuPercentage = [math]::Max($peakCpuPercentage, [double]$dataPoint.average)
                    }
                }
                'OnDemandFunctionExecutionUnits' {
                    if ($null -ne $dataPoint.total) {
                        $executionUnits += [double]$dataPoint.total
                    }
                }
            }
        }
    }

    return [PSCustomObject]@{
        peak_working_set_mb = [math]::Round($peakWorkingSetMb, 1)
        average_working_set_mb = [math]::Round($averageWorkingSetMb, 1)
        peak_cpu_percentage = [math]::Round($peakCpuPercentage, 1)
        execution_units = [math]::Round($executionUnits, 2)
    }
}

function Get-FunctionExecutionActivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTimeUtc,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTimeUtc
    )

    $metrics = Invoke-AzCli -Arguments @(
        'monitor', 'metrics', 'list',
        '--resource', $ResourceId,
        '--start-time', $StartTimeUtc.ToString('o'),
        '--end-time', $EndTimeUtc.ToString('o'),
        '--interval', 'PT1M',
        '--aggregation', 'Total',
        '--metrics', 'OnDemandFunctionExecutionCount',
        '-o', 'json'
    ) -ExpectJson

    $totalCount = 0.0
    $latestTimestampUtc = $null

    foreach ($metric in @($metrics.value)) {
        foreach ($series in @($metric.timeseries)) {
            foreach ($dataPoint in @($series.data)) {
                if ($null -eq $dataPoint.total) {
                    continue
                }

                $pointTotal = [double]$dataPoint.total
                if ($pointTotal -le 0) {
                    continue
                }

                $totalCount += $pointTotal
                $pointTimestampUtc = ([datetimeoffset]$dataPoint.timeStamp).UtcDateTime
                if ($null -eq $latestTimestampUtc -or $pointTimestampUtc -gt $latestTimestampUtc) {
                    $latestTimestampUtc = $pointTimestampUtc
                }
            }
        }
    }

    return [PSCustomObject]@{
        total_count = [int][math]::Round($totalCount, 0)
        latest_timestamp_utc = $latestTimestampUtc
    }
}

function Get-FunctionTraceSetting {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $settings = @(Invoke-AzCli -Arguments @('functionapp', 'config', 'appsettings', 'list', '--name', $FunctionAppName, '--resource-group', $FunctionAppResourceGroup, '-o', 'json') -ExpectJson)
    $setting = $settings | Where-Object { $_.name -eq 'PIPELINE_FILE_TRACE_ENABLED' } | Select-Object -First 1
    if ($null -eq $setting) {
        return $null
    }

    return [string]$setting.value
}

function Set-FunctionAppBenchmarkSettings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper updates Function App settings in a controlled script flow.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper applies a coordinated group of benchmark settings.')]
    [CmdletBinding()]
    param()

    Invoke-AzCli -Arguments @(
        'functionapp', 'config', 'appsettings', 'set',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionAppResourceGroup,
        '--settings',
        ("STORAGE_ACCOUNT_NAME={0}" -f $FunctionStorageAccountName),
        'DASHBOARD_DELIVERY_MODE=SelfContained',
        'INCLUDE_ADVANCED_HUNTING=true',
        'USE_EXISTING_EXPORTS_ONLY=true',
        'PIPELINE_FILE_TRACE_ENABLED=true',
        '--output', 'none'
    ) | Out-Null
}

function Restart-FunctionAppForBenchmark {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper restarts the Function App after changing benchmark-specific settings.')]
    [CmdletBinding()]
    param()

    Invoke-AzCli -Arguments @(
        'functionapp', 'restart',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionAppResourceGroup,
        '--output', 'none'
    ) | Out-Null
}

function Restore-FunctionTraceSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$OriginalValue
    )

    if ($null -eq $OriginalValue) {
        Invoke-AzCli -Arguments @(
            'functionapp', 'config', 'appsettings', 'delete',
            '--name', $FunctionAppName,
            '--resource-group', $FunctionAppResourceGroup,
            '--setting-names', 'PIPELINE_FILE_TRACE_ENABLED',
            '--output', 'none'
        ) | Out-Null
        return
    }

    Invoke-AzCli -Arguments @(
        'functionapp', 'config', 'appsettings', 'set',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionAppResourceGroup,
        '--settings', ("PIPELINE_FILE_TRACE_ENABLED={0}" -f $OriginalValue),
        '--output', 'none'
    ) | Out-Null
}

function Invoke-FunctionAdminRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'Post', 'Delete')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Body
    )

    $headers = @{ 'x-functions-key' = $MasterKey }
    if ($Method -eq 'Delete') {
        $headers['If-Match'] = '*'
    }

    $uri = "https://$HostName/$Path"
    $invokeParams = @{
        Method = $Method
        Uri = $uri
        Headers = $headers
        ErrorAction = 'Stop'
    }

    if ($Method -eq 'Post') {
        $invokeParams.ContentType = 'application/json'
        $invokeParams.Body = if ([string]::IsNullOrWhiteSpace($Body)) { '{}' } else { $Body }
    }

    try {
        return Invoke-WebRequest @invokeParams
    }
    catch {
        $response = $_.Exception.Response
        if ($null -ne $response -and [int]$response.StatusCode -eq 404) {
            return $null
        }

        throw
    }
}

function Wait-FunctionHostReady {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 10
    )

    $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
    while ([datetime]::UtcNow -lt $deadline) {
        try {
            $response = Invoke-FunctionAdminRequest -Method Get -HostName $HostName -MasterKey $MasterKey -Path 'admin/host/status'
            if ($null -ne $response -and $response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                return
            }
        }
        catch {
            Write-Verbose ("Function host not ready yet: {0}" -f $_.Exception.Message)
        }

        Start-Sleep -Seconds 10
    }

    throw "Timed out waiting for Function App host '$HostName' to become ready."
}

function Remove-FunctionTraceFiles {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper removes known trace files in a controlled script flow.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper targets a fixed set of trace files.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey
    )

    $paths = @(
        'admin/vfs/tmp/FunctionsData/ExportAndGenerate.trace.log',
        'admin/vfs/tmp/FunctionsData/FunctionProfile.trace.log',
        'admin/vfs/home/site/diagnostics/ExportAndGenerate.trace.log',
        'admin/vfs/home/site/diagnostics/FunctionProfile.trace.log'
    )

    foreach ($path in $paths) {
        try {
            $null = Invoke-FunctionAdminRequest -Method Delete -HostName $HostName -MasterKey $MasterKey -Path $path
        }
        catch {
            Write-Verbose ("Ignoring trace cleanup failure for {0}: {1}" -f $path, $_.Exception.Message)
        }
    }
}

function Get-FunctionTraceFileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $true)]
        [string[]]$CandidatePaths
    )

    foreach ($path in @($CandidatePaths)) {
        try {
            $response = Invoke-FunctionAdminRequest -Method Get -HostName $HostName -MasterKey $MasterKey -Path $path
        }
        catch {
            $response = $_.Exception.Response
            if ($null -ne $response -and [int]$response.StatusCode -in @(403, 404)) {
                continue
            }

            throw
        }

        if ($null -eq $response) {
            continue
        }

        $content = [string]$response.Content
        if ([string]::IsNullOrWhiteSpace($content)) {
            continue
        }

        return $content
    }

    return $null
}

function Get-TraceEventsFromContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [datetime]$NotBeforeUtc
    )

    $events = [System.Collections.Generic.List[object]]::new()
    foreach ($line in ($Content -split "`r?`n")) {
        if ($line -notmatch '^\[(?<timestamp>[^\]]+)\]\s?(?<message>.*)$') {
            continue
        }

        try {
            $timestamp = ([datetimeoffset]$matches.timestamp).UtcDateTime
        }
        catch {
            continue
        }

        if ($timestamp -lt $NotBeforeUtc.AddSeconds(-5)) {
            continue
        }

        $events.Add([PSCustomObject]@{
            timestamp_utc = $timestamp
            message = $matches.message
        }) | Out-Null
    }

    return @($events | Sort-Object -Property timestamp_utc, message -Unique)
}

function Get-FunctionTraceEvents {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper returns a collection of Function trace events.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $true)]
        [datetime]$NotBeforeUtc
    )

    $content = Get-FunctionTraceFileContent -HostName $HostName -MasterKey $MasterKey -CandidatePaths @(
        'admin/vfs/tmp/FunctionsData/ExportAndGenerate.trace.log',
        'admin/vfs/home/site/diagnostics/ExportAndGenerate.trace.log'
    )
    if ([string]::IsNullOrWhiteSpace($content)) {
        return @()
    }

    return @(Get-TraceEventsFromContent -Content $content -NotBeforeUtc $NotBeforeUtc)
}

function Get-FunctionTraceTerminalStatus {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Events
    )

    if (@($Events | Where-Object { [string]$_.message -match 'Pipeline Failed!|^Error:' }).Count -gt 0) {
        return 'Failed'
    }

    if (@($Events | Where-Object { [string]$_.message -match 'Pipeline Complete!' }).Count -gt 0) {
        return 'Completed'
    }

    return $null
}

function Start-RunbookBenchmark {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper starts a runbook job as part of the scripted workflow.')]
    [CmdletBinding()]
    param()

    $job = Invoke-AzCli -Arguments @(
        'automation', 'runbook', 'start',
        '--automation-account-name', $AutomationAccountName,
        '--resource-group', $AutomationResourceGroup,
        '--name', $RunbookName,
        '--parameters', 'UseExistingExportsOnly=true', 'DashboardDeliveryMode=SelfContained',
        '-o', 'json'
    ) -ExpectJson

    return [PSCustomObject]@{
        name = [string]$job.name
        jobId = [string]$job.jobId
        status = [string]$job.status
        creationTimeUtc = ([datetimeoffset]$job.creationTime).UtcDateTime
    }
}

function Get-RunbookJobStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JobName
    )

    return (Invoke-AzCli -Arguments @(
        'automation', 'job', 'show',
        '--automation-account-name', $AutomationAccountName,
        '--resource-group', $AutomationResourceGroup,
        '--name', $JobName,
        '-o', 'json'
    ) -ExpectJson)
}

function Get-RunbookEvents {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper returns a collection of runbook events.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JobName,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [datetime]$NotBeforeUtc
    )

    $uri = "/subscriptions/$SubscriptionId/resourceGroups/$AutomationResourceGroup/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/$JobName/streams?api-version=2019-06-01"
    $payload = Invoke-AzCli -Arguments @('rest', '--method', 'get', '--url', $uri, '-o', 'json') -ExpectJson
    $events = [System.Collections.Generic.List[object]]::new()

    foreach ($item in @($payload.value)) {
        $summary = [string]$item.properties.summary
        if ([string]::IsNullOrWhiteSpace($summary)) {
            continue
        }

        $timestamp = ([datetimeoffset]$item.properties.time).UtcDateTime
        if ($timestamp -lt $NotBeforeUtc.AddSeconds(-5)) {
            continue
        }

        $events.Add([PSCustomObject]@{
            timestamp_utc = $timestamp
            message = $summary
        }) | Out-Null
    }

    return @($events | Sort-Object -Property timestamp_utc, message -Unique)
}

function Get-AvailableMemoryGB {
    [CmdletBinding()]
    [OutputType([double])]
    param()

    $os = Get-CimInstance Win32_OperatingSystem
    return [math]::Round(($os.FreePhysicalMemory / 1MB), 2)
}

function Get-PreBenchmarkEnvironmentSnapshot {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [PSCustomObject]@{
        captured_utc = [datetime]::UtcNow.ToString('o')
        logical_cpu_count = [int][System.Environment]::ProcessorCount
        available_memory_gb = Get-AvailableMemoryGB
        free_disk_gb = [math]::Round(((Get-FreeDiskByteCount -Path $Path) / 1GB), 2)
    }
}

function Get-ProcessTree {
    [CmdletBinding()]
    [OutputType([System.Diagnostics.Process[]])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$RootProcessId
    )

    $processById = @{}
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        $processById[$process.Id] = $process
    }

    $childrenByParent = @{}
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $parentId = [int]$process.ParentProcessId
        if (-not $childrenByParent.ContainsKey($parentId)) {
            $childrenByParent[$parentId] = [System.Collections.Generic.List[int]]::new()
        }

        $childrenByParent[$parentId].Add([int]$process.ProcessId)
    }

    $queue = [System.Collections.Generic.Queue[int]]::new()
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $queue.Enqueue($RootProcessId)

    while ($queue.Count -gt 0) {
        $currentId = $queue.Dequeue()
        if (-not $seen.Add($currentId)) {
            continue
        }

        if ($childrenByParent.ContainsKey($currentId)) {
            foreach ($childId in $childrenByParent[$currentId]) {
                $queue.Enqueue($childId)
            }
        }
    }

    $processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
    foreach ($processId in $seen) {
        if ($processById.ContainsKey($processId)) {
            $processes.Add($processById[$processId]) | Out-Null
        }
    }

    return @($processes | Sort-Object -Property Id)
}

function Start-LocalBenchmark {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper stages local files and launches the benchmark process.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$BenchmarkDatasetPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$WorkingDatasetPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet('all', 'payload-only', 'none')]
        [string]$CacheResetMode = 'all'
    )

    $localDatasetPath = if ([string]::IsNullOrWhiteSpace($WorkingDatasetPath)) {
        Join-Path -Path $OutputDirectory -ChildPath ($Name + '.local.dataset')
    }
    else {
        [System.IO.Path]::GetFullPath($WorkingDatasetPath)
    }

    if ([string]::IsNullOrWhiteSpace($WorkingDatasetPath)) {
        Copy-BenchmarkDataset -SourceDatasetPath $BenchmarkDatasetPath -DestinationDatasetPath $localDatasetPath
    }
    elseif (-not (Test-Path -LiteralPath $localDatasetPath -PathType Container)) {
        throw "Working local benchmark dataset not found: $localDatasetPath"
    }

    Reset-LocalBenchmarkCache -DatasetPath $localDatasetPath -Mode $CacheResetMode

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
    }

    $stdoutPath = Join-Path -Path $OutputDirectory -ChildPath ($Name + '.local.stdout.log')
    $stderrPath = Join-Path -Path $OutputDirectory -ChildPath ($Name + '.local.stderr.log')
    $dashboardPath = Join-Path -Path $OutputDirectory -ChildPath ($Name + '.local.html')
    $phaseLogPath = Join-Path -Path $OutputDirectory -ChildPath ($Name + '.local.phase.log')
    $processReportPath = Join-Path -Path $OutputDirectory -ChildPath ($Name + '.local.report.json')

    foreach ($path in @($stdoutPath, $stderrPath, $dashboardPath, $phaseLogPath, $processReportPath)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $scriptPath = Join-Path -Path $RepoPath -ChildPath 'tests/Invoke-LargeDatasetValidation.ps1'
    $argumentList = @(
        '-NoProfile',
        '-File', $scriptPath,
        '-SkipSyntheticGeneration',
        '-SyntheticOutputPath', $localDatasetPath,
        '-DashboardOutputPath', $dashboardPath,
        '-DiagnosticPhaseLogPath', $phaseLogPath
    )

    $process = Start-Process -FilePath 'pwsh' -ArgumentList $argumentList -WorkingDirectory $RepoPath -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
    return [ordered]@{
        name = $Name
        repoPath = $RepoPath
        sourceDatasetPath = $BenchmarkDatasetPath
        datasetPath = $localDatasetPath
        environmentSnapshot = Get-PreBenchmarkEnvironmentSnapshot -Path $OutputDirectory
        process = $process
        stdoutPath = $stdoutPath
        stderrPath = $stderrPath
        dashboardPath = $dashboardPath
        phaseLogPath = $phaseLogPath
        processReportPath = $processReportPath
        stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        samples = [System.Collections.Generic.List[object]]::new()
        peakRssBytes = [int64]0
        peakRssAtSeconds = [double]0
        peakPrivateBytes = [int64]0
        peakPrivateAtSeconds = [double]0
        completed = $false
        exitCode = $null
    }
}

function Update-LocalBenchmark {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper updates in-memory process sampling state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$State
    )

    if ($State.completed) {
        return
    }

    try {
        $State.process.Refresh()
    }
    catch {
        Write-Verbose ("Ignoring process refresh failure: {0}" -f $_.Exception.Message)
    }

    $tree = @(Get-ProcessTree -RootProcessId $State.process.Id)
    if ($tree.Count -eq 0) {
        try {
            $null = $State.process.WorkingSet64
            $tree = @($State.process)
        }
        catch {
            $tree = @()
        }
    }

    if ($tree.Count -gt 0) {
        $rssBytes = [int64](($tree | Measure-Object -Property WorkingSet64 -Sum).Sum)
        $privateBytes = [int64](($tree | Measure-Object -Property PrivateMemorySize64 -Sum).Sum)
        $elapsedSeconds = [math]::Round($State.stopwatch.Elapsed.TotalSeconds, 2)

        if ($rssBytes -gt $State.peakRssBytes) {
            $State.peakRssBytes = $rssBytes
            $State.peakRssAtSeconds = $elapsedSeconds
        }

        if ($privateBytes -gt $State.peakPrivateBytes) {
            $State.peakPrivateBytes = $privateBytes
            $State.peakPrivateAtSeconds = $elapsedSeconds
        }

        $State.samples.Add([PSCustomObject]@{
            elapsed_seconds = $elapsedSeconds
            process_count = $tree.Count
            tree_rss_bytes = $rssBytes
            tree_private_bytes = $privateBytes
            available_memory_gb = Get-AvailableMemoryGB
        }) | Out-Null
    }

    if ($State.process.HasExited) {
        $State.stopwatch.Stop()
        $State.completed = $true
        $State.exitCode = [int]$State.process.ExitCode
    }
}

function Get-LocalBenchmarkResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$State,

        [Parameter(Mandatory = $true)]
        [int]$TotalRows,

        [Parameter(Mandatory = $false)]
        [switch]$KeepDatasetPath
    )

    $processReport = Get-LocalBenchmarkProcessReport -DatasetPath $State.datasetPath
    if ($null -ne $processReport -and $State.Contains('processReportPath') -and -not [string]::IsNullOrWhiteSpace([string]$State.processReportPath)) {
        Copy-Item -LiteralPath $processReport.path -Destination $State.processReportPath -Force
    }
    $processTimingSummary = Get-LocalBenchmarkProcessTimingSummary -ProcessReport $processReport
    $logSummary = Get-LocalBenchmarkLogSummary -StdoutPath $State.stdoutPath -DiagnosticLogPath $State.phaseLogPath
    $elapsedSeconds = if ($null -ne $processReport -and $processReport.report.PSObject.Properties['elapsedSeconds']) {
        [math]::Round([double]$processReport.report.elapsedSeconds, 2)
    }
    elseif ($null -ne $logSummary.pipeline_elapsed_seconds) {
        [math]::Round([double]$logSummary.pipeline_elapsed_seconds, 2)
    }
    else {
        [math]::Round($State.stopwatch.Elapsed.TotalSeconds, 2)
    }
    $elapsedTimingSource = if ($null -ne $processReport -and $processReport.report.PSObject.Properties['elapsedSeconds']) {
        'process-report'
    }
    elseif ($null -ne $logSummary.pipeline_elapsed_seconds) {
        'diagnostic-log'
    }
    else {
        'poll-stopwatch'
    }

    $result = [PSCustomObject]@{
        status = if ($State.exitCode -eq 0) { 'Completed' } else { 'Failed' }
        elapsed_seconds = $elapsedSeconds
        elapsed_timing_source = $elapsedTimingSource
        peak_tree_rss_bytes = $State.peakRssBytes
        peak_tree_rss_gb = [math]::Round(($State.peakRssBytes / 1GB), 3)
        peak_tree_rss_at_seconds = $State.peakRssAtSeconds
        peak_tree_private_bytes = $State.peakPrivateBytes
        peak_tree_private_gb = [math]::Round(($State.peakPrivateBytes / 1GB), 3)
        peak_tree_private_at_seconds = $State.peakPrivateAtSeconds
        rows_per_second = if ($elapsedSeconds -gt 0) { [math]::Round(($TotalRows / $elapsedSeconds), 0) } else { 0 }
        sample_count = $State.samples.Count
        dashboard_bytes = if (Test-Path -LiteralPath $State.dashboardPath -PathType Leaf) { (Get-Item -LiteralPath $State.dashboardPath).Length } else { 0 }
        dashboard_mb = if (Test-Path -LiteralPath $State.dashboardPath -PathType Leaf) { [math]::Round(((Get-Item -LiteralPath $State.dashboardPath).Length / 1MB), 2) } else { 0 }
        phase_elapsed_seconds = if ($null -ne $processTimingSummary) { $processTimingSummary.phase_elapsed_seconds } else { $logSummary.phase_elapsed_seconds }
        phase_timing_source = if ($null -ne $processTimingSummary) { $processTimingSummary.phase_timing_source } else { $logSummary.phase_timing_source }
        wrapper_overhead_seconds = if ($null -ne $processTimingSummary) { $processTimingSummary.wrapper_overhead_seconds } else { $null }
        used_cached_payload = [bool]$logSummary.used_cached_payload
        used_cached_vuln_columns = [bool]$logSummary.used_cached_vuln_columns
        published_cached_vuln_columns = [bool]$logSummary.published_cached_vuln_columns
        environment_snapshot = $State.environmentSnapshot
        process_report_path = if ($null -ne $processReport -and $State.Contains('processReportPath')) { $State.processReportPath } else { $null }
        phase_log_path = if (Test-Path -LiteralPath $State.phaseLogPath -PathType Leaf) { $State.phaseLogPath } else { $null }
        stdout_path = $State.stdoutPath
        stderr_path = $State.stderrPath
        dashboard_path = $State.dashboardPath
    }

    if ((-not $KeepDatasetPath) -and $State.Contains('datasetPath') -and -not [string]::IsNullOrWhiteSpace([string]$State.datasetPath) -and (Test-Path -LiteralPath $State.datasetPath)) {
        Remove-Item -LiteralPath $State.datasetPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    return $result
}

function Wait-LocalBenchmarkCompletion {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$State,

        [Parameter(Mandatory = $true)]
        [int]$TotalRows,

        [Parameter(Mandatory = $false)]
        [switch]$KeepDatasetPath
    )

    while (-not $State.completed) {
        Update-LocalBenchmark -State $State
        if (-not $State.completed) {
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    }

    Update-LocalBenchmark -State $State
    return (Get-LocalBenchmarkResult -State $State -TotalRows $TotalRows -KeepDatasetPath:$KeepDatasetPath)
}

function Get-PhaseElapsedSecondsValue {
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Result,

        [Parameter(Mandatory = $true)]
        [string]$PhaseName
    )

    if ($null -eq $Result -or -not $Result.PSObject.Properties['phase_elapsed_seconds']) {
        return $null
    }

    $phaseContainer = $Result.phase_elapsed_seconds
    if ($null -eq $phaseContainer) {
        return $null
    }

    $phaseProperty = $phaseContainer.PSObject.Properties[$PhaseName]
    if ($null -eq $phaseProperty -or $null -eq $phaseProperty.Value) {
        return $null
    }

    return [double]$phaseProperty.Value
}

function Get-PhaseElapsedSecondsDeltaSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $CurrentResult,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $MainResult
    )

    $phaseNames = [System.Collections.Generic.List[string]]::new()
    foreach ($phaseContainer in @(
        (Get-ObjectPropertyValue -InputObject $CurrentResult -Name 'phase_elapsed_seconds'),
        (Get-ObjectPropertyValue -InputObject $MainResult -Name 'phase_elapsed_seconds')
    )) {
        if ($null -eq $phaseContainer) {
            continue
        }

        foreach ($phaseProperty in $phaseContainer.PSObject.Properties) {
            $phaseName = [string]$phaseProperty.Name
            if (-not $phaseNames.Contains($phaseName)) {
                $phaseNames.Add($phaseName) | Out-Null
            }
        }
    }

    $deltaByName = [ordered]@{}
    foreach ($phaseName in $phaseNames) {
        $currentPhaseSeconds = Get-PhaseElapsedSecondsValue -Result $CurrentResult -PhaseName $phaseName
        $mainPhaseSeconds = Get-PhaseElapsedSecondsValue -Result $MainResult -PhaseName $phaseName
        if ($null -eq $currentPhaseSeconds -or $null -eq $mainPhaseSeconds) {
            continue
        }

        $deltaByName[$phaseName] = [math]::Round(($currentPhaseSeconds - $mainPhaseSeconds), 2)
    }

    if ($deltaByName.Count -eq 0) {
        return $null
    }

    return [PSCustomObject]$deltaByName
}

function Get-EnvironmentSnapshotDeltaSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $CurrentResult,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $MainResult
    )

    $currentEnvironmentSnapshot = Get-ObjectPropertyValue -InputObject $CurrentResult -Name 'environment_snapshot'
    $mainEnvironmentSnapshot = Get-ObjectPropertyValue -InputObject $MainResult -Name 'environment_snapshot'
    if ($null -eq $currentEnvironmentSnapshot -or $null -eq $mainEnvironmentSnapshot) {
        return $null
    }

    return [PSCustomObject]@{
        available_memory_gb_delta = if ($null -ne $currentEnvironmentSnapshot.available_memory_gb -and $null -ne $mainEnvironmentSnapshot.available_memory_gb) {
            [math]::Round(([double]$currentEnvironmentSnapshot.available_memory_gb - [double]$mainEnvironmentSnapshot.available_memory_gb), 2)
        }
        else {
            $null
        }
        free_disk_gb_delta = if ($null -ne $currentEnvironmentSnapshot.free_disk_gb -and $null -ne $mainEnvironmentSnapshot.free_disk_gb) {
            [math]::Round(([double]$currentEnvironmentSnapshot.free_disk_gb - [double]$mainEnvironmentSnapshot.free_disk_gb), 2)
        }
        else {
            $null
        }
        logical_cpu_count_delta = if ($null -ne $currentEnvironmentSnapshot.logical_cpu_count -and $null -ne $mainEnvironmentSnapshot.logical_cpu_count) {
            [int]$currentEnvironmentSnapshot.logical_cpu_count - [int]$mainEnvironmentSnapshot.logical_cpu_count
        }
        else {
            $null
        }
    }
}

function Invoke-LocalPersistentCacheWorkflow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselineName,

        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string]$BenchmarkDatasetPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $true)]
        [int]$TotalRows
    )

    $workflowDatasetPath = Join-Path -Path $OutputDirectory -ChildPath ($BaselineName + '.persistent.local.dataset')
    Copy-BenchmarkDataset -SourceDatasetPath $BenchmarkDatasetPath -DestinationDatasetPath $workflowDatasetPath

    try {
        Write-Host 'Running persistent local cache prime pass...'
        $primeState = Start-LocalBenchmark -RepoPath $RepoPath -Name ($BaselineName + '.persistent-prime') -BenchmarkDatasetPath $BenchmarkDatasetPath -OutputDirectory $OutputDirectory -WorkingDatasetPath $workflowDatasetPath -CacheResetMode 'all'
        $primeResult = Wait-LocalBenchmarkCompletion -State $primeState -TotalRows $TotalRows -KeepDatasetPath

        Write-Host 'Running persistent local cache reuse pass after payload-cache eviction...'
        $reuseState = Start-LocalBenchmark -RepoPath $RepoPath -Name ($BaselineName + '.persistent-reuse') -BenchmarkDatasetPath $BenchmarkDatasetPath -OutputDirectory $OutputDirectory -WorkingDatasetPath $workflowDatasetPath -CacheResetMode 'payload-only'
        $reuseResult = Wait-LocalBenchmarkCompletion -State $reuseState -TotalRows $TotalRows -KeepDatasetPath

        $primeNormalizeSeconds = Get-PhaseElapsedSecondsValue -Result $primeResult -PhaseName 'Normalize source data'
        $reuseNormalizeSeconds = Get-PhaseElapsedSecondsValue -Result $reuseResult -PhaseName 'Normalize source data'
        $primePreparePayloadSeconds = Get-PhaseElapsedSecondsValue -Result $primeResult -PhaseName 'Prepare normalized payload'
        $reusePreparePayloadSeconds = Get-PhaseElapsedSecondsValue -Result $reuseResult -PhaseName 'Prepare normalized payload'

        return [PSCustomObject]@{
            dataset_path = $workflowDatasetPath
            prime = $primeResult
            reuse_after_payload_eviction = $reuseResult
            comparison = [PSCustomObject]@{
                elapsed_seconds_delta = [math]::Round(($reuseResult.elapsed_seconds - $primeResult.elapsed_seconds), 2)
                normalize_source_data_delta = if ($null -ne $primeNormalizeSeconds -and $null -ne $reuseNormalizeSeconds) { [math]::Round(($reuseNormalizeSeconds - $primeNormalizeSeconds), 2) } else { $null }
                prepare_normalized_payload_delta = if ($null -ne $primePreparePayloadSeconds -and $null -ne $reusePreparePayloadSeconds) { [math]::Round(($reusePreparePayloadSeconds - $primePreparePayloadSeconds), 2) } else { $null }
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $workflowDatasetPath -PathType Container) {
            Remove-Item -LiteralPath $workflowDatasetPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-PipelineEventSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events,

        [Parameter(Mandatory = $true)]
        [double]$TotalElapsedSeconds,

        [Parameter(Mandatory = $false)]
        [int64]$DashboardBytes = 0,

        [Parameter(Mandatory = $false)]
        [int]$TotalRows = 0,

        [Parameter(Mandatory = $false)]
        [string]$TerminalStatus = 'Completed'
    )

    $orderedEvents = @($Events | Sort-Object -Property timestamp_utc, message)
    $stageInfo = [ordered]@{}
    $peakWorkingSetMb = 0.0
    $peakGcHeapMb = 0.0
    $devices = 0
    $cves = 0
    $dashboardSizeMb = 0.0
    $usedCachedPayload = $false
    $skippedFreshExport = $false
    $sawFailure = $false

    foreach ($entry in $orderedEvents) {
        $message = [string]$entry.message
        if ($message -match '^\s*--- Stage (?<letter>[A-Z]): (?<name>.+) ---$') {
            $stageInfo[$matches.letter] = [PSCustomObject]@{
                letter = $matches.letter
                name = $matches.name
                started_utc = $entry.timestamp_utc
            }
            continue
        }

        if ($message -match 'Memory .*?Working set: (?<working>[0-9.]+)MB\s+\|\s+GC heap: (?<heap>[0-9.]+)MB') {
            $working = [double]$matches.working
            $heap = [double]$matches.heap
            if ($working -gt $peakWorkingSetMb) {
                $peakWorkingSetMb = $working
            }
            if ($heap -gt $peakGcHeapMb) {
                $peakGcHeapMb = $heap
            }
            continue
        }

        if ($message -match '^\s*Devices:\s*(?<count>\d+)') {
            $devices = [int]$matches.count
            continue
        }

        if ($message -match '^\s*CVEs:\s*(?<count>\d+)') {
            $cves = [int]$matches.count
            continue
        }

        if ($message -match '^\s*Dashboard size:\s*(?<size>[0-9.]+)MB') {
            $dashboardSizeMb = [double]$matches.size
            continue
        }

        if ($message -match 'Reusing cached normalized payload') {
            $usedCachedPayload = $true
            continue
        }

        if ($message -match 'Skipping fresh MDE export') {
            $skippedFreshExport = $true
            continue
        }

        if ($message -match 'Pipeline Failed!') {
            $sawFailure = $true
        }
    }

    $stageDurations = [ordered]@{}
    $stageKeys = @($stageInfo.Keys | Sort-Object)
    for ($index = 0; $index -lt $stageKeys.Count; $index++) {
        $currentKey = $stageKeys[$index]
        $currentStage = $stageInfo[$currentKey]
        $nextStage = if ($index + 1 -lt $stageKeys.Count) { $stageInfo[$stageKeys[$index + 1]] } else { $null }
        $endTime = if ($null -ne $nextStage) {
            $nextStage.started_utc
        }
        elseif ($orderedEvents.Count -gt 0) {
            $orderedEvents[-1].timestamp_utc
        }
        else {
            $currentStage.started_utc
        }

        $stageDurations[$currentStage.name] = [math]::Round((New-TimeSpan -Start $currentStage.started_utc -End $endTime).TotalSeconds, 2)
    }

    if ($dashboardSizeMb -eq 0 -and $DashboardBytes -gt 0) {
        $dashboardSizeMb = [math]::Round(($DashboardBytes / 1MB), 2)
    }

    return [PSCustomObject]@{
        status = if ($sawFailure -or $TerminalStatus -eq 'Failed') { 'Failed' } else { $TerminalStatus }
        elapsed_seconds = [math]::Round($TotalElapsedSeconds, 2)
        stage_elapsed_seconds = $stageDurations
        peak_working_set_mb = [math]::Round($peakWorkingSetMb, 1)
        peak_gc_heap_mb = [math]::Round($peakGcHeapMb, 1)
        rows_per_second = if ($TotalElapsedSeconds -gt 0 -and $TotalRows -gt 0) { [math]::Round(($TotalRows / $TotalElapsedSeconds), 0) } else { 0 }
        devices = $devices
        cves = $cves
        dashboard_bytes = $DashboardBytes
        dashboard_mb = $dashboardSizeMb
        used_cached_payload = $usedCachedPayload
        skipped_fresh_export = $skippedFreshExport
    }
}

function Invoke-BaselineBenchmark {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselineName,

        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string]$DatasetRoot,

        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$FunctionHostName,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$FunctionResourceId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [int]$TotalRows,

        [Parameter(Mandatory = $false)]
        [switch]$LocalOnly,

        [Parameter(Mandatory = $false)]
        [switch]$IncludePersistentLocalWorkflow
    )

    Write-Host ''
    Write-Host ('=== {0} ===' -f $BaselineName) -ForegroundColor Cyan
    Write-Host ('Repo: {0}' -f $RepoPath)

    $baselineOutputDirectory = Join-Path -Path $OutputRoot -ChildPath $BaselineName
    if (-not (Test-Path -LiteralPath $baselineOutputDirectory)) {
        $null = New-Item -Path $baselineOutputDirectory -ItemType Directory -Force
    }

    $localPersistentCacheResult = $null
    if ($IncludePersistentLocalWorkflow) {
        Write-Host 'Exercising persistent local cache workflow before the cold benchmark run...'
        $localPersistentCacheResult = Invoke-LocalPersistentCacheWorkflow -BaselineName $BaselineName -RepoPath $RepoPath -BenchmarkDatasetPath $DatasetRoot -OutputDirectory $baselineOutputDirectory -TotalRows $TotalRows
    }

    if ($LocalOnly) {
        $localState = Start-LocalBenchmark -RepoPath $RepoPath -Name $BaselineName -BenchmarkDatasetPath $DatasetRoot -OutputDirectory $baselineOutputDirectory
        $localResult = Wait-LocalBenchmarkCompletion -State $localState -TotalRows $TotalRows

        return [PSCustomObject]@{
            baseline = $BaselineName
            repo_path = $RepoPath
            local = $localResult
            local_persistent_cache = $localPersistentCacheResult
            runbook = $null
            function_app = $null
            runbook_job_name = $null
            function_invoked_at_utc = $null
            runbook_events = @()
            function_events = @()
        }
    }

    Write-Host 'Deploying runbook artifact...'
    Build-AndDeploy-Runbook -RepoPath $RepoPath
    Write-Host 'Deploying Function App package...'
    Build-AndDeploy-FunctionApp -RepoPath $RepoPath
    Write-Host 'Applying Function App benchmark settings...'
    Set-FunctionAppBenchmarkSettings
    Write-Host 'Restarting Function App to apply benchmark settings...'
    Restart-FunctionAppForBenchmark

    Write-Host 'Uploading templates to both storage accounts...'
    Upload-TemplatesForBaseline -RepoPath $RepoPath -StorageAccountName $RunbookStorageAccountName
    Upload-TemplatesForBaseline -RepoPath $RepoPath -StorageAccountName $FunctionStorageAccountName

    Write-Host 'Seeding cold benchmark data into both storage accounts...'
    Seed-EnvironmentData -RunbookStorageAccountName $RunbookStorageAccountName -FunctionStorageAccountName $FunctionStorageAccountName -DatasetRoot $DatasetRoot

    $effectiveFunctionMasterKey = Get-FunctionMasterKey
    Write-Host 'Waiting for Function App host readiness...'
    Wait-FunctionHostReady -HostName $FunctionHostName -MasterKey $effectiveFunctionMasterKey
    Remove-FunctionTraceFiles -HostName $FunctionHostName -MasterKey $effectiveFunctionMasterKey

    $localState = Start-LocalBenchmark -RepoPath $RepoPath -Name $BaselineName -BenchmarkDatasetPath $DatasetRoot -OutputDirectory $baselineOutputDirectory
    $runbookState = Start-RunbookBenchmark
    $functionInvokeStartedUtc = [datetime]::UtcNow
    $null = Invoke-FunctionAdminRequest -Method Post -HostName $FunctionHostName -MasterKey $effectiveFunctionMasterKey -Path 'admin/functions/ExportAndGenerate' -Body '{}'
    Write-Host 'Local, runbook, and Function App runs started.'

    $runbookCompleted = $false
    $runbookJob = $null
    $runbookEvents = @()
    $functionCompleted = $false
    $functionCompletedUtc = $null
    $functionStatus = 'Running'
    $functionTimeoutMinutes = [math]::Max(15, ([math]::Ceiling(([double]$TotalRows / 500000.0)) * 10))
    $functionDeadlineUtc = $functionInvokeStartedUtc.AddMinutes($functionTimeoutMinutes)
    $functionExecutionActivity = $null
    $functionLastMetricPollUtc = [datetime]::MinValue
    $functionEvents = @()
    $functionLastTracePollUtc = [datetime]::MinValue
    $functionTraceCompletedUtc = $null
    $functionLastStatusPollUtc = [datetime]::MinValue
    $functionPipelineStatus = $null
    $functionActiveStartedUtc = $null
    $functionDashboardCompletedUtc = $null
    $functionCompletionSource = $null

    while (-not ($localState.completed -and $runbookCompleted -and $functionCompleted)) {
        Update-LocalBenchmark -State $localState

        if (-not $runbookCompleted) {
            $runbookJob = Get-RunbookJobStatus -JobName $runbookState.name
            $runbookCompleted = ($runbookJob.status -in @('Completed', 'Failed', 'Stopped', 'Suspended'))
            if ($runbookCompleted) {
                $runbookEvents = @(Get-RunbookEvents -JobName $runbookState.name -SubscriptionId $SubscriptionId -NotBeforeUtc $runbookState.creationTimeUtc)
            }
        }

        if (-not $functionCompleted) {
            $nowUtc = [datetime]::UtcNow

            if ($nowUtc -ge $functionLastStatusPollUtc.AddSeconds([math]::Max($PollIntervalSeconds, 15))) {
                $functionPipelineStatus = Get-FunctionExecutionStatus -AccountName $FunctionStorageAccountName
                $functionLastStatusPollUtc = $nowUtc

                if ($null -ne $functionPipelineStatus) {
                    $statusStartedUtc = ConvertTo-UtcDateTime -Value (Get-ObjectPropertyValue -InputObject $functionPipelineStatus -Name 'startedOnUtc')
                    if ($null -ne $statusStartedUtc) {
                        $functionActiveStartedUtc = $statusStartedUtc
                    }

                    $statusCompletedUtc = ConvertTo-UtcDateTime -Value (Get-ObjectPropertyValue -InputObject $functionPipelineStatus -Name 'completedOnUtc')
                    $statusUpdatedUtc = ConvertTo-UtcDateTime -Value (Get-ObjectPropertyValue -InputObject $functionPipelineStatus -Name 'updatedOnUtc')
                    switch ([string](Get-ObjectPropertyValue -InputObject $functionPipelineStatus -Name 'status')) {
                        'succeeded' {
                            $functionCompletedUtc = if ($null -ne $statusCompletedUtc) { $statusCompletedUtc } else { $statusUpdatedUtc }
                            if ($null -eq $functionCompletedUtc) {
                                $functionCompletedUtc = $nowUtc
                            }
                            $functionCompleted = $true
                            $functionStatus = 'Completed'
                            $functionCompletionSource = 'status-blob'
                        }
                        'failed' {
                            $functionCompletedUtc = if ($null -ne $statusCompletedUtc) { $statusCompletedUtc } else { $statusUpdatedUtc }
                            if ($null -eq $functionCompletedUtc) {
                                $functionCompletedUtc = $nowUtc
                            }
                            $functionCompleted = $true
                            $functionStatus = 'Failed'
                            $functionCompletionSource = 'status-blob'
                        }
                    }
                }
            }

            if (-not $functionCompleted) {
                $functionDashboardBlob = Get-BlobDetail -AccountName $FunctionStorageAccountName -ContainerName 'dashboards' -BlobName 'VulnerabilityDashboard.html'
                if ($null -ne $functionDashboardBlob) {
                    $lastModifiedUtc = ([datetimeoffset]$functionDashboardBlob.properties.lastModified).UtcDateTime
                    if ($lastModifiedUtc -ge $functionInvokeStartedUtc.AddSeconds(-5)) {
                        $functionDashboardCompletedUtc = $lastModifiedUtc
                    }
                }
            }

            if ((-not $functionCompleted) -and $nowUtc -ge $functionLastTracePollUtc.AddSeconds([math]::Max($PollIntervalSeconds, 15))) {
                $functionEvents = @(Get-FunctionTraceEvents -HostName $FunctionHostName -MasterKey $effectiveFunctionMasterKey -NotBeforeUtc $functionInvokeStartedUtc)
                $functionLastTracePollUtc = $nowUtc

                $functionTraceTerminalStatus = Get-FunctionTraceTerminalStatus -Events $functionEvents
                if ($functionTraceTerminalStatus -eq 'Failed') {
                    $functionCompletedUtc = @($functionEvents | Where-Object { [string]$_.message -match 'Pipeline Failed!|^Error:' } | Sort-Object timestamp_utc | Select-Object -Last 1 | ForEach-Object { $_.timestamp_utc }) | Select-Object -First 1
                    if ($null -eq $functionCompletedUtc) {
                        $functionCompletedUtc = $nowUtc
                    }
                    $functionCompleted = $true
                    $functionStatus = 'Failed'
                    $functionCompletionSource = 'trace-log'
                }
                elseif ($functionTraceTerminalStatus -eq 'Completed') {
                    $functionTraceCompletedUtc = @($functionEvents | Where-Object { [string]$_.message -match 'Pipeline Complete!' } | Sort-Object timestamp_utc | Select-Object -Last 1 | ForEach-Object { $_.timestamp_utc }) | Select-Object -First 1
                }
            }

            if ((-not $functionCompleted) -and $nowUtc -ge $functionLastMetricPollUtc.AddSeconds([math]::Max($PollIntervalSeconds, 30))) {
                $functionExecutionActivity = Get-FunctionExecutionActivity -ResourceId $FunctionResourceId -StartTimeUtc $functionInvokeStartedUtc.AddMinutes(-1) -EndTimeUtc $nowUtc
                $functionLastMetricPollUtc = $nowUtc
            }

            if ((-not $functionCompleted) -and $null -ne $functionTraceCompletedUtc -and $nowUtc -ge $functionTraceCompletedUtc.AddMinutes(2)) {
                $functionCompletedUtc = $functionTraceCompletedUtc
                $functionCompleted = $true
                $functionStatus = 'FailedNoDashboard'
                $functionCompletionSource = 'trace-log'
            }

            if ((-not $functionCompleted) -and $null -ne $functionDashboardCompletedUtc -and (($null -eq $functionPipelineStatus) -or $nowUtc -ge $functionDashboardCompletedUtc.AddMinutes(2))) {
                $functionCompletedUtc = $functionDashboardCompletedUtc
                $functionCompleted = $true
                $functionStatus = 'Completed'
                $functionCompletionSource = 'dashboard-blob'
            }

            if ((-not $functionCompleted) -and [datetime]::UtcNow -ge $functionDeadlineUtc) {
                $functionCompletedUtc = [datetime]::UtcNow
                $functionCompleted = $true
                $functionStatus = 'TimedOut'
                $functionCompletionSource = 'timeout'
            }
        }

        if (-not ($localState.completed -and $runbookCompleted -and $functionCompleted)) {
            Write-BaselineBenchmarkHeartbeat -BaselineName $BaselineName -LocalState $localState -RunbookJob $runbookJob -FunctionStatus $functionStatus -FunctionInvokeStartedUtc $functionInvokeStartedUtc -FunctionExecutionActivity $functionExecutionActivity
        }

        if (-not ($localState.completed -and $runbookCompleted -and $functionCompleted)) {
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    }

    Update-LocalBenchmark -State $localState

    $runbookElapsedSeconds = if ($null -ne $runbookJob -and $null -ne $runbookJob.startTime -and $null -ne $runbookJob.endTime) {
        [math]::Round((New-TimeSpan -Start ([datetimeoffset]$runbookJob.startTime).UtcDateTime -End ([datetimeoffset]$runbookJob.endTime).UtcDateTime).TotalSeconds, 2)
    }
    elseif ($runbookEvents.Count -gt 1) {
        [math]::Round((New-TimeSpan -Start $runbookEvents[0].timestamp_utc -End $runbookEvents[-1].timestamp_utc).TotalSeconds, 2)
    }
    else {
        0
    }

    $functionEndToEndElapsedSeconds = if ($null -ne $functionCompletedUtc) {
        [math]::Round((New-TimeSpan -Start $functionInvokeStartedUtc -End $functionCompletedUtc).TotalSeconds, 2)
    }
    else {
        0
    }

    $functionActiveElapsedSeconds = if ($null -ne $functionActiveStartedUtc -and $null -ne $functionCompletedUtc) {
        [math]::Round([math]::Max((New-TimeSpan -Start $functionActiveStartedUtc -End $functionCompletedUtc).TotalSeconds, 0), 2)
    }
    else {
        $null
    }

    $functionPickupDelaySeconds = if ($null -ne $functionActiveStartedUtc) {
        [math]::Round([math]::Max((New-TimeSpan -Start $functionInvokeStartedUtc -End $functionActiveStartedUtc).TotalSeconds, 0), 2)
    }
    else {
        $null
    }

    $functionTimingBasis = if ($null -ne $functionActiveElapsedSeconds -and $functionActiveElapsedSeconds -gt 0) {
        'active-execution'
    }
    else {
        'invoke-to-finish-fallback'
    }

    $functionHeadlineElapsedSeconds = if ($functionTimingBasis -eq 'active-execution') {
        $functionActiveElapsedSeconds
    }
    else {
        $functionEndToEndElapsedSeconds
    }

    $functionMetricStartUtc = if ($null -ne $functionActiveStartedUtc) {
        $functionActiveStartedUtc.AddMinutes(-1)
    }
    else {
        $functionInvokeStartedUtc.AddMinutes(-1)
    }

    $functionMetricEndUtc = if ($null -ne $functionCompletedUtc) {
        $functionCompletedUtc.AddMinutes(1)
    }
    else {
        [datetime]::UtcNow
    }
    $functionEvents = @(Get-FunctionTraceEvents -HostName $FunctionHostName -MasterKey $effectiveFunctionMasterKey -NotBeforeUtc $functionInvokeStartedUtc)
    $functionMetricSummary = Get-FunctionMetricSummary -ResourceId $FunctionResourceId -StartTimeUtc $functionMetricStartUtc -EndTimeUtc $functionMetricEndUtc

    $localResult = Get-LocalBenchmarkResult -State $localState -TotalRows $TotalRows
    $runbookResult = Get-PipelineEventSummary -Events $runbookEvents -TotalElapsedSeconds $runbookElapsedSeconds -DashboardBytes (Get-BlobLengthBytes -AccountName $RunbookStorageAccountName -ContainerName 'dashboards' -BlobName 'VulnerabilityDashboard.html') -TotalRows $TotalRows -TerminalStatus ([string]$runbookJob.status)
    $functionDashboardBytes = Get-BlobLengthBytes -AccountName $FunctionStorageAccountName -ContainerName 'dashboards' -BlobName 'VulnerabilityDashboard.html'
    $functionResult = [PSCustomObject]@{
        status = $functionStatus
        timing_basis = $functionTimingBasis
        elapsed_seconds = $functionHeadlineElapsedSeconds
        active_elapsed_seconds = $functionActiveElapsedSeconds
        end_to_end_elapsed_seconds = $functionEndToEndElapsedSeconds
        pickup_delay_seconds = $functionPickupDelaySeconds
        peak_working_set_mb = $functionMetricSummary.peak_working_set_mb
        average_working_set_mb = $functionMetricSummary.average_working_set_mb
        peak_cpu_percentage = $functionMetricSummary.peak_cpu_percentage
        execution_units = $functionMetricSummary.execution_units
        execution_count = if ($null -ne $functionExecutionActivity) { $functionExecutionActivity.total_count } else { 0 }
        rows_per_second = if ($functionHeadlineElapsedSeconds -gt 0 -and $TotalRows -gt 0) { [math]::Round(($TotalRows / $functionHeadlineElapsedSeconds), 0) } else { 0 }
        end_to_end_rows_per_second = if ($functionEndToEndElapsedSeconds -gt 0 -and $TotalRows -gt 0) { [math]::Round(($TotalRows / $functionEndToEndElapsedSeconds), 0) } else { 0 }
        dashboard_bytes = $functionDashboardBytes
        dashboard_mb = [math]::Round(($functionDashboardBytes / 1MB), 2)
        invoke_started_utc = $functionInvokeStartedUtc
        active_started_utc = $functionActiveStartedUtc
        completion_utc = $functionCompletedUtc
        completion_source = $functionCompletionSource
        status_stage = [string](Get-ObjectPropertyValue -InputObject $functionPipelineStatus -Name 'stage')
        status_message = [string](Get-ObjectPropertyValue -InputObject $functionPipelineStatus -Name 'message')
    }

    return [PSCustomObject]@{
        baseline = $BaselineName
        repo_path = $RepoPath
        local = $localResult
        local_persistent_cache = $localPersistentCacheResult
        runbook = $runbookResult
        function_app = $functionResult
        runbook_job_name = $runbookState.name
        function_invoked_at_utc = $functionInvokeStartedUtc
        runbook_events = $runbookEvents
        function_events = $functionEvents
    }
}

function Upload-TemplatesForBaseline {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper uploads benchmark template assets for a baseline run.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    Invoke-RepoScript -RepoPath $RepoPath -RelativeScriptPath 'azure/Upload-Templates.ps1' -Arguments @{ StorageAccountName = $StorageAccountName }
}

function Seed-EnvironmentData {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper prepares storage data for a benchmark run.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunbookStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$FunctionStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$DatasetRoot
    )

    foreach ($accountName in @($RunbookStorageAccountName, $FunctionStorageAccountName)) {
        Clear-BlobContainer -AccountName $accountName -ContainerName 'dashboards'
        Seed-ExportsContainer -AccountName $accountName -DatasetRoot $DatasetRoot
    }
}

function Restore-CurrentAzureDeployment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath
    )

    Write-Host ''
    Write-Host 'Restoring current branch code to Azure...' -ForegroundColor Yellow
    Build-AndDeploy-Runbook -RepoPath $RepoPath
    Build-AndDeploy-FunctionApp -RepoPath $RepoPath
    Upload-TemplatesForBaseline -RepoPath $RepoPath -StorageAccountName $RunbookStorageAccountName
    Upload-TemplatesForBaseline -RepoPath $RepoPath -StorageAccountName $FunctionStorageAccountName
}

function Get-ComparisonBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Current,

        [Parameter(Mandatory = $true)]
        [psobject]$Main
    )

    return [PSCustomObject]@{
        local = [PSCustomObject]@{
            elapsed_seconds_delta = [math]::Round(($Current.local.elapsed_seconds - $Main.local.elapsed_seconds), 2)
            peak_rss_gb_delta = [math]::Round(($Current.local.peak_tree_rss_gb - $Main.local.peak_tree_rss_gb), 3)
            peak_private_gb_delta = [math]::Round(($Current.local.peak_tree_private_gb - $Main.local.peak_tree_private_gb), 3)
            phase_elapsed_seconds_delta = Get-PhaseElapsedSecondsDeltaSummary -CurrentResult $Current.local -MainResult $Main.local
            environment_snapshot_delta = Get-EnvironmentSnapshotDeltaSummary -CurrentResult $Current.local -MainResult $Main.local
        }
        local_persistent_cache = if ($Current.PSObject.Properties['local_persistent_cache'] -and $Main.PSObject.Properties['local_persistent_cache'] -and $null -ne $Current.local_persistent_cache -and $null -ne $Main.local_persistent_cache) {
            [PSCustomObject]@{
                prime_elapsed_seconds_delta = [math]::Round(($Current.local_persistent_cache.prime.elapsed_seconds - $Main.local_persistent_cache.prime.elapsed_seconds), 2)
                reuse_elapsed_seconds_delta = [math]::Round(($Current.local_persistent_cache.reuse_after_payload_eviction.elapsed_seconds - $Main.local_persistent_cache.reuse_after_payload_eviction.elapsed_seconds), 2)
                reuse_normalize_phase_delta = if (
                    $null -ne (Get-PhaseElapsedSecondsValue -Result $Current.local_persistent_cache.reuse_after_payload_eviction -PhaseName 'Normalize source data') -and
                    $null -ne (Get-PhaseElapsedSecondsValue -Result $Main.local_persistent_cache.reuse_after_payload_eviction -PhaseName 'Normalize source data')
                ) {
                    [math]::Round(((Get-PhaseElapsedSecondsValue -Result $Current.local_persistent_cache.reuse_after_payload_eviction -PhaseName 'Normalize source data') - (Get-PhaseElapsedSecondsValue -Result $Main.local_persistent_cache.reuse_after_payload_eviction -PhaseName 'Normalize source data')), 2)
                }
                else {
                    $null
                }
            }
        }
        else {
            $null
        }
        runbook = if ($null -ne $Current.runbook -and $null -ne $Main.runbook) {
            [PSCustomObject]@{
                elapsed_seconds_delta = [math]::Round(($Current.runbook.elapsed_seconds - $Main.runbook.elapsed_seconds), 2)
                peak_working_set_mb_delta = [math]::Round(($Current.runbook.peak_working_set_mb - $Main.runbook.peak_working_set_mb), 1)
                peak_gc_heap_mb_delta = [math]::Round(($Current.runbook.peak_gc_heap_mb - $Main.runbook.peak_gc_heap_mb), 1)
            }
        }
        else {
            $null
        }
        function_app = if ($null -ne $Current.function_app -and $null -ne $Main.function_app) {
            [PSCustomObject]@{
                elapsed_seconds_delta = [math]::Round(($Current.function_app.elapsed_seconds - $Main.function_app.elapsed_seconds), 2)
                active_elapsed_seconds_delta = if ($null -ne $Current.function_app.active_elapsed_seconds -and $null -ne $Main.function_app.active_elapsed_seconds) {
                    [math]::Round(($Current.function_app.active_elapsed_seconds - $Main.function_app.active_elapsed_seconds), 2)
                }
                else {
                    $null
                }
                end_to_end_elapsed_seconds_delta = if ($null -ne $Current.function_app.end_to_end_elapsed_seconds -and $null -ne $Main.function_app.end_to_end_elapsed_seconds) {
                    [math]::Round(($Current.function_app.end_to_end_elapsed_seconds - $Main.function_app.end_to_end_elapsed_seconds), 2)
                }
                else {
                    $null
                }
                pickup_delay_seconds_delta = if ($null -ne $Current.function_app.pickup_delay_seconds -and $null -ne $Main.function_app.pickup_delay_seconds) {
                    [math]::Round(($Current.function_app.pickup_delay_seconds - $Main.function_app.pickup_delay_seconds), 2)
                }
                else {
                    $null
                }
                peak_working_set_mb_delta = [math]::Round(($Current.function_app.peak_working_set_mb - $Main.function_app.peak_working_set_mb), 1)
                execution_units_delta = [math]::Round(($Current.function_app.execution_units - $Main.function_app.execution_units), 2)
            }
        }
        else {
            $null
        }
    }
}

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$resolvedCurrentRepoPath = [System.IO.Path]::GetFullPath($CurrentRepoPath)
$datasetDefinition = if (-not [string]::IsNullOrWhiteSpace($BenchmarkDatasetId)) { Get-BenchmarkDatasetDefinition -DatasetId $BenchmarkDatasetId -RepoRoot $repoRoot } else { $null }
if (-not [string]::IsNullOrWhiteSpace($BenchmarkDatasetId) -and $null -eq $datasetDefinition) {
    throw "Benchmark dataset definition '$BenchmarkDatasetId' was not found."
}

$resolvedDatasetPath = if ($null -ne $datasetDefinition -and -not $PSBoundParameters.ContainsKey('DatasetPath')) {
    Resolve-BenchmarkDatasetOutputPath -Definition $datasetDefinition -RepoRoot $repoRoot
}
else {
    [System.IO.Path]::GetFullPath($DatasetPath)
}
$resolvedResultsOutputPath = [System.IO.Path]::GetFullPath($ResultsOutputPath)
$outputDirectory = Split-Path -Path $resolvedResultsOutputPath -Parent

$resolvedMainRepoPath = if ($CurrentOnly) {
    $null
}
else {
    [System.IO.Path]::GetFullPath($MainRepoPath)
}

foreach ($requiredPath in @($resolvedCurrentRepoPath, $resolvedDatasetPath, $resolvedMainRepoPath)) {
    if ([string]::IsNullOrWhiteSpace($requiredPath)) {
        continue
    }

    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required path not found: $requiredPath"
    }
}

if (-not (Test-Path -LiteralPath $outputDirectory)) {
    $null = New-Item -Path $outputDirectory -ItemType Directory -Force
}

$datasetPreflight = Assert-BenchmarkDatasetReady `
    -DatasetPath $resolvedDatasetPath `
    -OutputDirectory $outputDirectory `
    -MaximumDatasetRows $MaximumDatasetRows `
    -AllowLargeDataset ($AllowLargeDataset -eq $true) `
    -MinimumAvailableMemoryGB $MinimumAvailableMemoryGB `
    -MinimumFreeDiskGB $MinimumFreeDiskGB

$datasetManifest = $datasetPreflight.manifest
$datasetDefinitionMatch = if ($null -ne $datasetDefinition) { Test-BenchmarkDatasetDefinitionMatch -Definition $datasetDefinition -Manifest $datasetManifest } else { $false }
if ($null -ne $datasetDefinition -and -not $datasetDefinitionMatch) {
    throw ("Dataset '{0}' does not match benchmark dataset definition '{1}'." -f $resolvedDatasetPath, $BenchmarkDatasetId)
}

$datasetDefinitionMetadata = Get-BenchmarkDatasetResultMetadata -DatasetPath $resolvedDatasetPath -Manifest $datasetManifest -BenchmarkDatasetId $BenchmarkDatasetId -RepoRoot $repoRoot
$totalRows = [int]$datasetPreflight.totalRows

Write-Host ("Dataset preflight passed: {0} rows, {1:N2} GB on disk, {2} GB free memory, {3} GB free disk." -f $totalRows, ($datasetPreflight.datasetBytes / 1GB), $datasetPreflight.availableMemoryGB, $datasetPreflight.freeDiskGB)

$subscription = if ($LocalOnly) { $null } else { Invoke-AzCli -Arguments @('account', 'show', '-o', 'json') -ExpectJson }
$functionHostName = if ($LocalOnly) { $null } else { Get-FunctionHostName }
$functionResourceId = if ($LocalOnly) { $null } else { Get-FunctionResourceId }
$originalFunctionTraceSetting = if ($LocalOnly) { $null } else { Get-FunctionTraceSetting }

$currentResult = $null
$mainResult = $null

try {
    if (-not $LocalOnly) {
        $functionMasterKey = Get-FunctionMasterKey
        Wait-FunctionHostReady -HostName $functionHostName -MasterKey $functionMasterKey
    }

    $currentResult = @(Invoke-BaselineBenchmark -BaselineName $CurrentBaselineName -RepoPath $resolvedCurrentRepoPath -DatasetRoot $resolvedDatasetPath -OutputRoot $outputDirectory -FunctionHostName $functionHostName -FunctionResourceId $functionResourceId -SubscriptionId $(if ($LocalOnly) { '' } else { [string]$subscription.id }) -TotalRows $totalRows -LocalOnly:$LocalOnly -IncludePersistentLocalWorkflow:$IncludePersistentLocalWorkflow) | Select-Object -Last 1
    $currentResult | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path -Path $outputDirectory -ChildPath ($CurrentBaselineName + '.result.json')) -Encoding utf8

    if (-not $CurrentOnly) {
        if (-not $LocalOnly) {
            $functionMasterKey = Get-FunctionMasterKey
            Wait-FunctionHostReady -HostName $functionHostName -MasterKey $functionMasterKey
        }

        $mainResult = @(Invoke-BaselineBenchmark -BaselineName $MainBaselineName -RepoPath $resolvedMainRepoPath -DatasetRoot $resolvedDatasetPath -OutputRoot $outputDirectory -FunctionHostName $functionHostName -FunctionResourceId $functionResourceId -SubscriptionId $(if ($LocalOnly) { '' } else { [string]$subscription.id }) -TotalRows $totalRows -LocalOnly:$LocalOnly -IncludePersistentLocalWorkflow:$IncludePersistentLocalWorkflow) | Select-Object -Last 1
        $mainResult | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path -Path $outputDirectory -ChildPath ($MainBaselineName + '.result.json')) -Encoding utf8
    }
}
finally {
    if (-not $LocalOnly) {
        try {
            if (-not $SkipRestoreCurrentDeployment) {
                Restore-CurrentAzureDeployment -RepoPath $resolvedCurrentRepoPath
            }
        }
        finally {
            Restore-FunctionTraceSetting -OriginalValue $originalFunctionTraceSetting
        }
    }
}

$result = [PSCustomObject]@{
    benchmark_schema_version = 2
    generated_utc = [datetime]::UtcNow.ToString('o')
    benchmark_mode = if ($LocalOnly) {
        if ($CurrentOnly) { 'local-current-only' } else { 'local-branch-vs-main' }
    }
    else {
        if ($CurrentOnly) { 'current-only' } else { 'branch-vs-main' }
    }
    local_only = ($LocalOnly -eq $true)
    persistent_local_workflow = ($IncludePersistentLocalWorkflow -eq $true)
    subscription = if ($null -ne $subscription) {
        [PSCustomObject]@{
            id = [string]$subscription.id
            name = [string]$subscription.name
            tenantId = [string]$subscription.tenantId
        }
    }
    else {
        $null
    }
    dataset = [PSCustomObject]@{
        path = $resolvedDatasetPath
        definition = $datasetDefinitionMetadata
        files = @(Get-DatasetFiles -Path $resolvedDatasetPath | ForEach-Object { $_.Name })
        manifest = $datasetManifest
        total_rows = $totalRows
        dataset_bytes = [int64]$datasetPreflight.datasetBytes
        progress_stage = if ($null -ne $datasetPreflight.progress) { [string]$datasetPreflight.progress.stage } else { $null }
        preflight = [PSCustomObject]@{
            available_memory_gb = $datasetPreflight.availableMemoryGB
            free_disk_gb = $datasetPreflight.freeDiskGB
            required_free_disk_gb = $datasetPreflight.requiredFreeDiskGB
        }
    }
    current = $currentResult
    main = $mainResult
    comparison = if ($null -ne $currentResult -and $null -ne $mainResult) { Get-ComparisonBlock -Current $currentResult -Main $mainResult } else { $null }
}

$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resolvedResultsOutputPath -Encoding utf8
Write-AdHocBenchmarkSeriesSummary -ResultPath $resolvedResultsOutputPath

Write-Host ''
Write-Host ('Benchmark report: {0}' -f $resolvedResultsOutputPath) -ForegroundColor Green
if ($null -ne $currentResult) {
    if ($LocalOnly) {
        Write-Host ('{0} local elapsed: {1}s' -f $CurrentBaselineName, $currentResult.local.elapsed_seconds)
    }
    else {
        Write-Host ('{0} local/runbook/function elapsed: {1}s / {2}s / {3}s ({4})' -f $CurrentBaselineName, $currentResult.local.elapsed_seconds, $currentResult.runbook.elapsed_seconds, $currentResult.function_app.elapsed_seconds, $currentResult.function_app.timing_basis)
        if ($null -ne $currentResult.function_app.end_to_end_elapsed_seconds) {
            Write-Host ('{0} function end-to-end/pickup delay: {1}s / {2}s' -f $CurrentBaselineName, $currentResult.function_app.end_to_end_elapsed_seconds, $currentResult.function_app.pickup_delay_seconds)
        }
    }
    if ($null -ne $currentResult.local_persistent_cache) {
        Write-Host ('{0} persistent local prime/reuse elapsed: {1}s / {2}s' -f $CurrentBaselineName, $currentResult.local_persistent_cache.prime.elapsed_seconds, $currentResult.local_persistent_cache.reuse_after_payload_eviction.elapsed_seconds)
    }
}
if ($null -ne $mainResult) {
    if ($LocalOnly) {
        Write-Host ('{0} local elapsed: {1}s' -f $MainBaselineName, $mainResult.local.elapsed_seconds)
    }
    else {
        Write-Host ('{0} local/runbook/function elapsed: {1}s / {2}s / {3}s ({4})' -f $MainBaselineName, $mainResult.local.elapsed_seconds, $mainResult.runbook.elapsed_seconds, $mainResult.function_app.elapsed_seconds, $mainResult.function_app.timing_basis)
        if ($null -ne $mainResult.function_app.end_to_end_elapsed_seconds) {
            Write-Host ('{0} function end-to-end/pickup delay: {1}s / {2}s' -f $MainBaselineName, $mainResult.function_app.end_to_end_elapsed_seconds, $mainResult.function_app.pickup_delay_seconds)
        }
    }
    if ($null -ne $mainResult.local_persistent_cache) {
        Write-Host ('{0} persistent local prime/reuse elapsed: {1}s / {2}s' -f $MainBaselineName, $mainResult.local_persistent_cache.prime.elapsed_seconds, $mainResult.local_persistent_cache.reuse_after_payload_eviction.elapsed_seconds)
    }
}
