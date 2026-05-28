#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BenchmarkResultPath,

    [Parameter(Mandatory = $false)]
    [string]$HistoryPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\benchmark-history\benchmark-history.jsonl'),

    [Parameter(Mandatory = $false)]
    [string]$SummaryOutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\benchmark-history\latest-summary.md'),

    [Parameter(Mandatory = $false, ValueFromRemainingArguments = $true)]
    [string[]]$Tags = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Import-BenchmarkDatasetCatalog.ps1')
. (Join-Path $PSScriptRoot 'helpers\BenchmarkSeriesTools.ps1')
. (Join-Path $PSScriptRoot 'helpers\TestScriptSupport.ps1')

function Format-DateTimeValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [datetime]) {
        return ([datetime]$Value).ToString('o')
    }

    if ($Value -is [datetimeoffset]) {
        return ([datetimeoffset]$Value).ToString('o')
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($text, [ref]$parsed)) {
        return $parsed.ToString('o')
    }

    return $text
}

function Get-RepoSnapshot {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$RepoPath
    )

    if ([string]::IsNullOrWhiteSpace($RepoPath)) {
        return $null
    }

    $resolvedRepoPath = [System.IO.Path]::GetFullPath($RepoPath)
    $branch = Invoke-GitText -RepoPath $resolvedRepoPath -Arguments @('rev-parse', '--abbrev-ref', 'HEAD')
    $commit = Invoke-GitText -RepoPath $resolvedRepoPath -Arguments @('rev-parse', 'HEAD')
    $commitShort = Invoke-GitText -RepoPath $resolvedRepoPath -Arguments @('rev-parse', '--short', 'HEAD')
    $status = Invoke-GitText -RepoPath $resolvedRepoPath -Arguments @('status', '--short', '--untracked-files=no')

    return [PSCustomObject]@{
        repo_path = $resolvedRepoPath
        branch = $branch
        commit = $commit
        commit_short = $commitShort
        dirty = (-not [string]::IsNullOrWhiteSpace($status))
    }
}

function Get-DatasetSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Result
    )

    $dataset = Get-ObjectPropertyValue -InputObject $Result -Name 'dataset'
    $manifest = Get-ObjectPropertyValue -InputObject $dataset -Name 'manifest'
    $definition = Get-ObjectPropertyValue -InputObject $dataset -Name 'definition'
    $datasetPath = [string](Get-ObjectPropertyValue -InputObject $dataset -Name 'path')
    $datasetLeaf = if ([string]::IsNullOrWhiteSpace($datasetPath)) { $null } else { Split-Path -Path $datasetPath -Leaf }
    $preset = [string](Get-ObjectPropertyValue -InputObject $manifest -Name 'preset')
    $totalRows = Get-ObjectPropertyValue -InputObject $dataset -Name 'total_rows'
    $actualDeviceCount = Get-ObjectPropertyValue -InputObject $manifest -Name 'actualDeviceCount'
    $definitionId = [string](Get-ObjectPropertyValue -InputObject $definition -Name 'id')

    if ([string]::IsNullOrWhiteSpace($definitionId) -and $null -ne $manifest) {
        $resolvedDefinition = Find-BenchmarkDatasetDefinitionForManifest -Manifest $manifest
        if ($null -ne $resolvedDefinition) {
            $definitionId = [string]$resolvedDefinition.id
            $definition = $resolvedDefinition
        }
    }

    $datasetIdentityParts = [System.Collections.Generic.List[string]]::new()
    foreach ($part in @($definitionId, $datasetLeaf, $preset, $totalRows, $actualDeviceCount)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$part)) {
            $datasetIdentityParts.Add([string]$part) | Out-Null
        }
    }

    return [PSCustomObject]@{
        identity = if ($datasetIdentityParts.Count -gt 0) { $datasetIdentityParts -join '|' } else { $datasetPath }
        definition_id = $definitionId
        definition_description = [string](Get-ObjectPropertyValue -InputObject $definition -Name 'description')
        path = $datasetPath
        leaf = $datasetLeaf
        preset = $preset
        seed = Get-ObjectPropertyValue -InputObject $manifest -Name 'seed'
        generated_on_utc = Get-ObjectPropertyValue -InputObject $manifest -Name 'generatedOnUtc'
        total_rows = $totalRows
        dataset_bytes = Get-ObjectPropertyValue -InputObject $dataset -Name 'dataset_bytes'
        actual_device_count = $actualDeviceCount
        actual_current_rows = Get-ObjectPropertyValue -InputObject $manifest -Name 'actualCurrentRows'
        actual_history_rows = Get-ObjectPropertyValue -InputObject $manifest -Name 'actualHistoryRows'
        advanced_hunting_rows = Get-ObjectPropertyValue -InputObject $manifest -Name 'advancedHuntingRows'
        content_template_count = Get-ObjectPropertyValue -InputObject $manifest -Name 'contentTemplateCount'
        unique_cve_id_count = Get-ObjectPropertyValue -InputObject $manifest -Name 'uniqueCveIdCount'
        normalized_cve_lookup_count = Get-ObjectPropertyValue -InputObject $manifest -Name 'normalizedCveLookupCount'
        history_periods = @((Get-ObjectPropertyValue -InputObject $manifest -Name 'historyPeriods') | ForEach-Object { [string]$_ })
    }
}

function Get-BaselineSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $BaselineResult
    )

    if ($null -eq $BaselineResult) {
        return $null
    }

    $local = Get-ObjectPropertyValue -InputObject $BaselineResult -Name 'local'
    $runbook = Get-ObjectPropertyValue -InputObject $BaselineResult -Name 'runbook'
    $functionApp = Get-ObjectPropertyValue -InputObject $BaselineResult -Name 'function_app'
    $localPersistentCache = Get-ObjectPropertyValue -InputObject $BaselineResult -Name 'local_persistent_cache'
    $localPersistentPrime = Get-ObjectPropertyValue -InputObject $localPersistentCache -Name 'prime'
    $localPersistentReuse = Get-ObjectPropertyValue -InputObject $localPersistentCache -Name 'reuse_after_payload_eviction'
    $localPersistentComparison = Get-ObjectPropertyValue -InputObject $localPersistentCache -Name 'comparison'
    $repoPath = [string](Get-ObjectPropertyValue -InputObject $BaselineResult -Name 'repo_path')

    return [PSCustomObject]@{
        baseline = [string](Get-ObjectPropertyValue -InputObject $BaselineResult -Name 'baseline')
        repo_path = $repoPath
        repo = Get-RepoSnapshot -RepoPath $repoPath
        local_elapsed_seconds = Get-ObjectPropertyValue -InputObject $local -Name 'elapsed_seconds'
        local_rows_per_second = Get-ObjectPropertyValue -InputObject $local -Name 'rows_per_second'
        local_peak_rss_gb = Get-ObjectPropertyValue -InputObject $local -Name 'peak_tree_rss_gb'
        local_peak_private_gb = Get-ObjectPropertyValue -InputObject $local -Name 'peak_tree_private_gb'
        local_phase_elapsed_seconds = Get-ObjectPropertyValue -InputObject $local -Name 'phase_elapsed_seconds'
        local_environment_snapshot = Get-ObjectPropertyValue -InputObject $local -Name 'environment_snapshot'
        runbook_elapsed_seconds = Get-ObjectPropertyValue -InputObject $runbook -Name 'elapsed_seconds'
        runbook_rows_per_second = Get-ObjectPropertyValue -InputObject $runbook -Name 'rows_per_second'
        runbook_peak_working_set_mb = Get-ObjectPropertyValue -InputObject $runbook -Name 'peak_working_set_mb'
        runbook_peak_gc_heap_mb = Get-ObjectPropertyValue -InputObject $runbook -Name 'peak_gc_heap_mb'
        function_timing_basis = [string](Get-ObjectPropertyValue -InputObject $functionApp -Name 'timing_basis')
        function_elapsed_seconds = Get-ObjectPropertyValue -InputObject $functionApp -Name 'elapsed_seconds'
        function_active_elapsed_seconds = Get-ObjectPropertyValue -InputObject $functionApp -Name 'active_elapsed_seconds'
        function_end_to_end_elapsed_seconds = Get-ObjectPropertyValue -InputObject $functionApp -Name 'end_to_end_elapsed_seconds'
        function_pickup_delay_seconds = Get-ObjectPropertyValue -InputObject $functionApp -Name 'pickup_delay_seconds'
        function_rows_per_second = Get-ObjectPropertyValue -InputObject $functionApp -Name 'rows_per_second'
        function_peak_working_set_mb = Get-ObjectPropertyValue -InputObject $functionApp -Name 'peak_working_set_mb'
        function_average_working_set_mb = Get-ObjectPropertyValue -InputObject $functionApp -Name 'average_working_set_mb'
        function_execution_units = Get-ObjectPropertyValue -InputObject $functionApp -Name 'execution_units'
        persistent_prime_elapsed_seconds = Get-ObjectPropertyValue -InputObject $localPersistentPrime -Name 'elapsed_seconds'
        persistent_reuse_elapsed_seconds = Get-ObjectPropertyValue -InputObject $localPersistentReuse -Name 'elapsed_seconds'
        persistent_elapsed_delta_seconds = Get-ObjectPropertyValue -InputObject $localPersistentComparison -Name 'elapsed_seconds_delta'
        persistent_normalize_delta_seconds = Get-ObjectPropertyValue -InputObject $localPersistentComparison -Name 'normalize_source_data_delta'
        persistent_prepare_payload_delta_seconds = Get-ObjectPropertyValue -InputObject $localPersistentComparison -Name 'prepare_normalized_payload_delta'
        persistent_used_cached_vuln_columns = if ($null -ne $localPersistentReuse) { [bool](Get-ObjectPropertyValue -InputObject $localPersistentReuse -Name 'used_cached_vuln_columns') } else { $false }
    }
}

function Get-BenchmarkHistoryEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResultPath,

        [Parameter(Mandatory = $true)]
        $Result,

        [Parameter(Mandatory = $false)]
        [string[]]$Tags = @()
    )

    $subscription = Get-ObjectPropertyValue -InputObject $Result -Name 'subscription'
    $normalizedTags = @($Tags | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ } | Select-Object -Unique)
    $subscriptionSummary = $null
    if ($null -ne $subscription) {
        $subscriptionSummary = [PSCustomObject]@{
            id = [string](Get-ObjectPropertyValue -InputObject $subscription -Name 'id')
            name = [string](Get-ObjectPropertyValue -InputObject $subscription -Name 'name')
            tenantId = [string](Get-ObjectPropertyValue -InputObject $subscription -Name 'tenantId')
        }
    }

    return [PSCustomObject][ordered]@{
        benchmark_schema_version = Get-ObjectPropertyValue -InputObject $Result -Name 'benchmark_schema_version'
        recorded_utc = [datetime]::UtcNow.ToString('o')
        benchmark_result_path = $ResultPath
        benchmark_generated_utc = Format-DateTimeValue -Value (Get-ObjectPropertyValue -InputObject $Result -Name 'generated_utc')
        benchmark_mode = [string](Get-ObjectPropertyValue -InputObject $Result -Name 'benchmark_mode')
        baseline_execution_order_requested = [string](Get-ObjectPropertyValue -InputObject $Result -Name 'baseline_execution_order_requested')
        baseline_execution_order_effective = [string](Get-ObjectPropertyValue -InputObject $Result -Name 'baseline_execution_order_effective')
        baseline_execution_sequence = @(
            @(Get-ObjectPropertyValue -InputObject $Result -Name 'baseline_execution_sequence') |
                ForEach-Object { [string](Get-ObjectPropertyValue -InputObject $_ -Name 'baseline_name') }
        )
        local_only = [bool](Get-ObjectPropertyValue -InputObject $Result -Name 'local_only')
        include_local_benchmark = Test-BenchmarkIncludesLocalRun -BenchmarkObject $Result
        persistent_local_workflow = [bool](Get-ObjectPropertyValue -InputObject $Result -Name 'persistent_local_workflow')
        subscription = $subscriptionSummary
        dataset = Get-DatasetSummary -Result $Result
        current = Get-BaselineSummary -BaselineResult (Get-ObjectPropertyValue -InputObject $Result -Name 'current')
        main = Get-BaselineSummary -BaselineResult (Get-ObjectPropertyValue -InputObject $Result -Name 'main')
        comparison = Get-ObjectPropertyValue -InputObject $Result -Name 'comparison'
        tags = $normalizedTags
    }
}

function Import-BenchmarkHistoryEntries {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper reads the full set of locally recorded benchmark history entries.')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $entries.Add(($line | ConvertFrom-Json -Depth 30)) | Out-Null
    }

    return @($entries)
}

function Find-PreviousMatchingEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Entries,

        [Parameter(Mandatory = $true)]
        $CurrentEntry
    )

    $candidateEntries = @(
        $Entries | Where-Object {
            ([string]$_.benchmark_result_path -ne [string]$CurrentEntry.benchmark_result_path) -and
            ((Get-BenchmarkModeScenarioKey -BenchmarkMode ([string]$_.benchmark_mode)) -eq (Get-BenchmarkModeScenarioKey -BenchmarkMode ([string]$CurrentEntry.benchmark_mode))) -and
            ([bool]$_.local_only -eq [bool]$CurrentEntry.local_only) -and
            ((Test-BenchmarkIncludesLocalRun -BenchmarkObject $_) -eq (Test-BenchmarkIncludesLocalRun -BenchmarkObject $CurrentEntry)) -and
            ([bool]$_.persistent_local_workflow -eq [bool]$CurrentEntry.persistent_local_workflow) -and
            ([string]$_.dataset.identity -eq [string]$CurrentEntry.dataset.identity) -and
            ([string]$_.current.baseline -eq [string]$CurrentEntry.current.baseline) -and
            ([string]$_.current.function_timing_basis -eq [string]$CurrentEntry.current.function_timing_basis)
        }
    )

    if ($candidateEntries.Count -eq 0) {
        return $null
    }

    return @($candidateEntries | Sort-Object { [datetime]$_.recorded_utc })[-1]
}

function Format-SecondsValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return 'n/a'
    }

    return ('{0:N2}s' -f [double]$Value)
}

function Format-DeltaValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $CurrentValue,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $PreviousValue
    )

    if ($null -eq $CurrentValue -or $null -eq $PreviousValue) {
        return 'n/a'
    }

    $delta = [math]::Round(([double]$CurrentValue - [double]$PreviousValue), 2)
    $deltaText = if ($delta -gt 0) {
        '+' + ('{0:N2}' -f $delta)
    }
    else {
        ('{0:N2}' -f $delta)
    }

    $trend = if ($delta -lt 0) {
        'faster'
    }
    elseif ($delta -gt 0) {
        'slower'
    }
    else {
        'unchanged'
    }

    return ('{0}s ({1})' -f $deltaText, $trend)
}

function Format-SignedSecondsDeltaValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return 'n/a'
    }

    $delta = [math]::Round([double]$Value, 2)
    $deltaText = if ($delta -gt 0) {
        '+' + ('{0:N2}' -f $delta)
    }
    else {
        ('{0:N2}' -f $delta)
    }

    $trend = if ($delta -lt 0) {
        'faster'
    }
    elseif ($delta -gt 0) {
        'slower'
    }
    else {
        'unchanged'
    }

    return ('{0}s ({1})' -f $deltaText, $trend)
}

function Format-SignedNumberDeltaValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value,

        [Parameter(Mandatory = $false)]
        [string]$Suffix = '',

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 6)]
        [int]$Decimals = 3
    )

    if ($null -eq $Value) {
        return 'n/a'
    }

    $delta = [math]::Round([double]$Value, $Decimals)
    $format = '{0:N' + $Decimals + '}'
    $deltaText = if ($delta -gt 0) {
        '+' + ($format -f $delta)
    }
    else {
        ($format -f $delta)
    }

    return ($deltaText + $Suffix)
}

function Format-EnvironmentSnapshotValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Snapshot
    )

    if ($null -eq $Snapshot) {
        return 'n/a'
    }

    return ('{0} CPU | {1:N2} GB free memory | {2:N2} GB free disk' -f [int]$Snapshot.logical_cpu_count, [double]$Snapshot.available_memory_gb, [double]$Snapshot.free_disk_gb)
}

function Format-PhaseDeltaSummaryValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $PhaseSummary
    )

    if ($null -eq $PhaseSummary) {
        return 'n/a'
    }

    $phaseParts = [System.Collections.Generic.List[string]]::new()
    foreach ($phaseProperty in $PhaseSummary.PSObject.Properties) {
        $phaseParts.Add(('{0}: {1}' -f [string]$phaseProperty.Name, (Format-SignedSecondsDeltaValue -Value $phaseProperty.Value))) | Out-Null
    }

    if ($phaseParts.Count -eq 0) {
        return 'n/a'
    }

    return ($phaseParts -join '; ')
}

function Format-BenchmarkBreadthValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return 'n/a'
    }

    return [string]$Value
}

function Write-BenchmarkHistorySummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Entry,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $PreviousEntry,

        [Parameter(Mandatory = $true)]
        [string]$HistoryPath,

        [Parameter(Mandatory = $true)]
        [bool]$WasAppended
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $entryRecordedUtc = Format-DateTimeValue -Value $Entry.recorded_utc
    $previousEntryRecordedUtc = Format-DateTimeValue -Value $(if ($null -ne $PreviousEntry) { $PreviousEntry.recorded_utc } else { $null })
    $entryIncludesLocalBenchmark = Test-BenchmarkIncludesLocalRun -BenchmarkObject $Entry
    $previousEntryIncludesLocalBenchmark = if ($null -ne $PreviousEntry) { Test-BenchmarkIncludesLocalRun -BenchmarkObject $PreviousEntry } else { $false }
    $lines.Add('# Benchmark History Summary') | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('Latest capture') | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add(('- Recorded: `{0}`' -f $entryRecordedUtc)) | Out-Null
    $lines.Add(('- Result file: `{0}`' -f $Entry.benchmark_result_path)) | Out-Null
    $lines.Add(('- History action: {0}' -f $(if ($WasAppended) { 'appended' } else { 'already present' }))) | Out-Null
    $lines.Add(('- Benchmark mode: `{0}`' -f $Entry.benchmark_mode)) | Out-Null
    $datasetLabel = if (-not [string]::IsNullOrWhiteSpace([string]$Entry.dataset.definition_id)) { [string]$Entry.dataset.definition_id } else { [string]$Entry.dataset.leaf }
    $lines.Add(('- Dataset: `{0}` | preset `{1}` | `{2}` rows | `{3}` devices' -f $datasetLabel, $Entry.dataset.preset, $Entry.dataset.total_rows, $Entry.dataset.actual_device_count)) | Out-Null
    if ($null -ne $Entry.dataset.unique_cve_id_count -or $null -ne $Entry.dataset.normalized_cve_lookup_count -or $null -ne $Entry.dataset.content_template_count) {
        $lines.Add(('- Dataset breadth: `{0}` unique CVE IDs | `{1}` normalized CVE lookups | `{2}` content templates' -f (Format-BenchmarkBreadthValue -Value $Entry.dataset.unique_cve_id_count), (Format-BenchmarkBreadthValue -Value $Entry.dataset.normalized_cve_lookup_count), (Format-BenchmarkBreadthValue -Value $Entry.dataset.content_template_count))) | Out-Null
    }
    $lines.Add(('- Current baseline: `{0}`' -f $Entry.current.baseline)) | Out-Null
    if ($null -ne $Entry.current.repo) {
        $lines.Add(('- Current git: `{0}` @ `{1}` ({2})' -f $Entry.current.repo.branch, $Entry.current.repo.commit_short, $(if ($Entry.current.repo.dirty) { 'dirty' } else { 'clean' }))) | Out-Null
    }
    if ($entryIncludesLocalBenchmark) {
        $lines.Add(('- Local elapsed: {0}' -f (Format-SecondsValue -Value $Entry.current.local_elapsed_seconds))) | Out-Null
        $lines.Add(('- Local pre-run environment: {0}' -f (Format-EnvironmentSnapshotValue -Snapshot $Entry.current.local_environment_snapshot))) | Out-Null
    }
    $lines.Add(('- Runbook elapsed: {0}' -f (Format-SecondsValue -Value $Entry.current.runbook_elapsed_seconds))) | Out-Null
    $lines.Add(('- Function elapsed: {0} ({1})' -f (Format-SecondsValue -Value $Entry.current.function_elapsed_seconds), $(if ([string]::IsNullOrWhiteSpace([string]$Entry.current.function_timing_basis)) { 'legacy' } else { [string]$Entry.current.function_timing_basis }))) | Out-Null
    if ($null -ne $Entry.current.function_end_to_end_elapsed_seconds) {
        $lines.Add(('- Function end-to-end / pickup delay: {0} / {1}' -f (Format-SecondsValue -Value $Entry.current.function_end_to_end_elapsed_seconds), (Format-SecondsValue -Value $Entry.current.function_pickup_delay_seconds))) | Out-Null
    }
    if (@($Entry.baseline_execution_sequence).Count -gt 0) {
        $lines.Add(('- Baseline execution order: `{0}` ({1})' -f (@($Entry.baseline_execution_sequence) -join ' -> '), $(if ([string]::IsNullOrWhiteSpace([string]$Entry.baseline_execution_order_effective)) { 'unspecified' } else { [string]$Entry.baseline_execution_order_effective }))) | Out-Null
    }
    if ($Entry.persistent_local_workflow) {
        $lines.Add(('- Persistent local prime/reuse: {0} / {1}' -f (Format-SecondsValue -Value $Entry.current.persistent_prime_elapsed_seconds), (Format-SecondsValue -Value $Entry.current.persistent_reuse_elapsed_seconds))) | Out-Null
        $lines.Add(('- Persistent local elapsed delta: {0}' -f (Format-SecondsValue -Value $Entry.current.persistent_elapsed_delta_seconds))) | Out-Null
    }
    if (@($Entry.tags).Count -gt 0) {
        $lines.Add(('- Tags: `{0}`' -f (@($Entry.tags) -join '`, `'))) | Out-Null
    }
    $lines.Add(('- History file: `{0}`' -f $HistoryPath)) | Out-Null

    if ($null -ne $Entry.comparison -and $null -ne $Entry.comparison.local) {
        $lines.Add('') | Out-Null
        $lines.Add('Current vs main baseline') | Out-Null
        $lines.Add('') | Out-Null
        $lines.Add('- Delta semantics: current minus main; negative elapsed values mean the current branch is faster.') | Out-Null
        $lines.Add(('- Local elapsed delta: {0}' -f (Format-SignedSecondsDeltaValue -Value $Entry.comparison.local.elapsed_seconds_delta))) | Out-Null
        $lines.Add(('- Local peak RSS / private delta: {0} / {1}' -f (Format-SignedNumberDeltaValue -Value $Entry.comparison.local.peak_rss_gb_delta -Suffix 'GB' -Decimals 3), (Format-SignedNumberDeltaValue -Value $Entry.comparison.local.peak_private_gb_delta -Suffix 'GB' -Decimals 3))) | Out-Null
        $lines.Add(('- Local phase deltas: {0}' -f (Format-PhaseDeltaSummaryValue -PhaseSummary $Entry.comparison.local.phase_elapsed_seconds_delta))) | Out-Null
        if ($null -ne $Entry.comparison.local.environment_snapshot_delta) {
            $lines.Add(('- Local pre-run environment delta: memory {0}, disk {1}, cpu {2}' -f (Format-SignedNumberDeltaValue -Value $Entry.comparison.local.environment_snapshot_delta.available_memory_gb_delta -Suffix 'GB' -Decimals 2), (Format-SignedNumberDeltaValue -Value $Entry.comparison.local.environment_snapshot_delta.free_disk_gb_delta -Suffix 'GB' -Decimals 2), (Format-SignedNumberDeltaValue -Value $Entry.comparison.local.environment_snapshot_delta.logical_cpu_count_delta -Decimals 0))) | Out-Null
        }
        if ($null -ne $Entry.comparison.function_app -and $Entry.comparison.function_app.PSObject.Properties['timing_basis_consistent'] -and -not [bool]$Entry.comparison.function_app.timing_basis_consistent) {
            $lines.Add(('- Function elapsed delta is not directly comparable because timing bases differ: branch `{0}`, main `{1}`' -f [string]$Entry.comparison.function_app.timing_basis_current, [string]$Entry.comparison.function_app.timing_basis_main)) | Out-Null
        }
    }

    if ($null -ne $PreviousEntry) {
        $lines.Add('') | Out-Null
        $lines.Add('Previous matching capture') | Out-Null
        $lines.Add('') | Out-Null
        $lines.Add(('- Recorded: `{0}`' -f $previousEntryRecordedUtc)) | Out-Null
        $lines.Add(('- Result file: `{0}`' -f $PreviousEntry.benchmark_result_path)) | Out-Null
        if ($entryIncludesLocalBenchmark -and $previousEntryIncludesLocalBenchmark) {
            $lines.Add(('- Local delta: {0}' -f (Format-DeltaValue -CurrentValue $Entry.current.local_elapsed_seconds -PreviousValue $PreviousEntry.current.local_elapsed_seconds))) | Out-Null
        }
        $lines.Add(('- Runbook delta: {0}' -f (Format-DeltaValue -CurrentValue $Entry.current.runbook_elapsed_seconds -PreviousValue $PreviousEntry.current.runbook_elapsed_seconds))) | Out-Null
        $lines.Add(('- Function delta: {0}' -f (Format-DeltaValue -CurrentValue $Entry.current.function_elapsed_seconds -PreviousValue $PreviousEntry.current.function_elapsed_seconds))) | Out-Null
        if ($null -ne $Entry.dataset.unique_cve_id_count -and $null -ne $PreviousEntry.dataset.unique_cve_id_count) {
            $lines.Add(('- Dataset breadth delta: unique CVE IDs {0} | normalized CVE lookups {1} | content templates {2}' -f (Format-DeltaValue -CurrentValue $Entry.dataset.unique_cve_id_count -PreviousValue $PreviousEntry.dataset.unique_cve_id_count), (Format-DeltaValue -CurrentValue $Entry.dataset.normalized_cve_lookup_count -PreviousValue $PreviousEntry.dataset.normalized_cve_lookup_count), (Format-DeltaValue -CurrentValue $Entry.dataset.content_template_count -PreviousValue $PreviousEntry.dataset.content_template_count))) | Out-Null
        }
        if ($null -ne $Entry.current.function_end_to_end_elapsed_seconds -and $null -ne $PreviousEntry.current.function_end_to_end_elapsed_seconds) {
            $lines.Add(('- Function end-to-end delta: {0}' -f (Format-DeltaValue -CurrentValue $Entry.current.function_end_to_end_elapsed_seconds -PreviousValue $PreviousEntry.current.function_end_to_end_elapsed_seconds))) | Out-Null
        }
        if ($Entry.persistent_local_workflow) {
            $lines.Add(('- Persistent reuse delta: {0}' -f (Format-DeltaValue -CurrentValue $Entry.current.persistent_reuse_elapsed_seconds -PreviousValue $PreviousEntry.current.persistent_reuse_elapsed_seconds))) | Out-Null
        }
    }
    else {
        $lines.Add('') | Out-Null
        $lines.Add('Previous matching capture') | Out-Null
        $lines.Add('') | Out-Null
        $lines.Add('- None yet for this dataset and benchmark mode.') | Out-Null
    }

    $outputDirectory = Split-Path -Path $Path -Parent
    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
        $null = New-Item -Path $outputDirectory -ItemType Directory -Force
    }

    [System.IO.File]::WriteAllLines($Path, $lines, [System.Text.UTF8Encoding]::new($false))
}

$resolvedBenchmarkResultPath = [System.IO.Path]::GetFullPath($BenchmarkResultPath)
$resolvedHistoryPath = [System.IO.Path]::GetFullPath($HistoryPath)
$resolvedSummaryOutputPath = [System.IO.Path]::GetFullPath($SummaryOutputPath)

if (-not (Test-Path -LiteralPath $resolvedBenchmarkResultPath -PathType Leaf)) {
    throw "Benchmark result file not found: $resolvedBenchmarkResultPath"
}

$historyDirectory = Split-Path -Path $resolvedHistoryPath -Parent
if (-not (Test-Path -LiteralPath $historyDirectory -PathType Container)) {
    $null = New-Item -Path $historyDirectory -ItemType Directory -Force
}

$result = Get-Content -LiteralPath $resolvedBenchmarkResultPath -Raw | ConvertFrom-Json -Depth 50
$historyEntries = @(Import-BenchmarkHistoryEntries -Path $resolvedHistoryPath)
$entry = Get-BenchmarkHistoryEntry -ResultPath $resolvedBenchmarkResultPath -Result $result -Tags $Tags

$existingEntry = @(
    $historyEntries | Where-Object {
        ([string]$_.benchmark_result_path -eq [string]$entry.benchmark_result_path) -or
        (([string]$_.benchmark_generated_utc -eq [string]$entry.benchmark_generated_utc) -and ([string]$_.current.baseline -eq [string]$entry.current.baseline) -and ([string]$_.dataset.identity -eq [string]$entry.dataset.identity))
    }
) | Select-Object -First 1

$wasAppended = $false
if ($null -eq $existingEntry) {
    ($entry | ConvertTo-Json -Compress -Depth 30) | Add-Content -LiteralPath $resolvedHistoryPath -Encoding utf8
    $historyEntries += $entry
    $wasAppended = $true
}
else {
    $entry = $existingEntry
}

$previousEntry = Find-PreviousMatchingEntry -Entries $historyEntries -CurrentEntry $entry
Write-BenchmarkHistorySummary -Path $resolvedSummaryOutputPath -Entry $entry -PreviousEntry $previousEntry -HistoryPath $resolvedHistoryPath -WasAppended $wasAppended

Write-Host ('Benchmark history: {0}' -f $resolvedHistoryPath) -ForegroundColor Green
Write-Host ('History summary: {0}' -f $resolvedSummaryOutputPath) -ForegroundColor Green
if ($wasAppended) {
    Write-Host ('Recorded benchmark result: {0}' -f $resolvedBenchmarkResultPath)
}
else {
    Write-Host ('Benchmark result already recorded: {0}' -f $resolvedBenchmarkResultPath)
}
if ($null -ne $previousEntry) {
    Write-Host ('Previous matching capture: {0}' -f [string]$previousEntry.benchmark_result_path)
}
