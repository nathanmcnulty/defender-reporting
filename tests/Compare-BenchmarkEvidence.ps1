#Requires -Version 7.6

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CurrentPath,
    [Parameter(Mandatory = $false)][string]$BaselinePath,
    [Parameter(Mandatory = $false)][double]$MaximumWorkingSetMB = 0,
    [Parameter(Mandatory = $false)][double]$MaximumPrivateMemoryMB = 0,
    [Parameter(Mandatory = $false)][double]$MaximumGcHeapMB = 0,
    [Parameter(Mandatory = $false)][switch]$RequireProcessWorkingSetPeak,
    [Parameter(Mandatory = $false)][switch]$StrictWorkingSetLimit,
    [Parameter(Mandatory = $false)][ValidateRange(0, 1000)][double]$MaximumElapsedRegressionPercent = 20,
    [Parameter(Mandatory = $false)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helpers\BenchmarkEvidenceTools.ps1')

if ($StrictWorkingSetLimit -and $MaximumWorkingSetMB -le 0) {
    throw 'StrictWorkingSetLimit requires a positive MaximumWorkingSetMB.'
}

function Add-ValidatedNumericPropertyValue {
    param($Value, [string]$Name, [System.Collections.Generic.List[double]]$Accumulator)
    if ($null -eq $Value) { return }
    $number = [double]$Value
    if (-not [double]::IsFinite($number) -or $number -lt 0) { throw "Benchmark metric '$Name' must be a finite nonnegative number." }
    $Accumulator.Add($number)
}

function Add-NumericPropertyValue {
    param($Item, [string[]]$PropertyNames, [System.Collections.Generic.List[double]]$Accumulator)
    if ($null -eq $Item -or $Item -is [string] -or $Item -is [ValueType]) { return }
    if ($Item -is [System.Collections.IDictionary]) {
        foreach ($key in $Item.Keys) {
            if ($PropertyNames -contains [string]$key) { Add-ValidatedNumericPropertyValue -Value $Item[$key] -Name ([string]$key) -Accumulator $Accumulator }
            Add-NumericPropertyValue -Item $Item[$key] -PropertyNames $PropertyNames -Accumulator $Accumulator
        }
        return
    }
    if ($Item -is [System.Collections.IEnumerable]) { foreach ($entry in $Item) { Add-NumericPropertyValue -Item $entry -PropertyNames $PropertyNames -Accumulator $Accumulator }; return }
    foreach ($property in $Item.PSObject.Properties) {
        if ($PropertyNames -contains $property.Name) { Add-ValidatedNumericPropertyValue -Value $property.Value -Name $property.Name -Accumulator $Accumulator }
        Add-NumericPropertyValue -Item $property.Value -PropertyNames $PropertyNames -Accumulator $Accumulator
    }
}

function Get-NumericPropertyMaximum {
    param([AllowNull()]$Value, [Parameter(Mandatory = $true)][string[]]$Names)

    $values = [System.Collections.Generic.List[double]]::new()
    Add-NumericPropertyValue -Item $Value -PropertyNames $Names -Accumulator $values
    if ($values.Count -eq 0) { return $null }
    return ($values | Measure-Object -Maximum).Maximum
}

function Read-EvidenceResult([string]$Path) {
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "Benchmark result '$resolved' was not found." }
    $document = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json -Depth 100
    $evidence = $document.PSObject.Properties['benchmark_evidence']?.Value
    if ($null -eq $evidence) { $evidence = $document }
    if ([int]$evidence.evidence_schema_version -ne 1) { throw "Benchmark result '$resolved' does not contain evidence schema version 1." }
    return [PSCustomObject]@{ Path = $resolved; Document = $document; Evidence = $evidence }
}

function Get-BenchmarkMetric($record) {
    return [PSCustomObject]@{
        peak_working_set_mb = Get-NumericPropertyMaximum $record.Evidence.execution @('peak_working_set_mb', 'peakWorkingSetMb', 'working_set_mb', 'processPeakWorkingSetMb', 'process_peak_working_set_mb')
        process_peak_working_set_mb = Get-NumericPropertyMaximum $record.Evidence.execution @('processPeakWorkingSetMb', 'process_peak_working_set_mb')
        peak_private_memory_mb = Get-NumericPropertyMaximum $record.Evidence.execution @('peak_private_memory_mb', 'peakPrivateMemoryMb', 'private_memory_mb')
        peak_gc_heap_mb = Get-NumericPropertyMaximum $record.Evidence.execution @('peak_gc_heap_mb', 'peakGcHeapMb', 'gc_heap_mb')
        elapsed_seconds = Get-NumericPropertyMaximum $record.Evidence.execution @('elapsed_seconds')
    }
}

$current = Read-EvidenceResult $CurrentPath
$currentMetrics = Get-BenchmarkMetric $current
$baseline = if ([string]::IsNullOrWhiteSpace($BaselinePath)) { $null } else { Read-EvidenceResult $BaselinePath }
$baselineMetrics = if ($null -eq $baseline) { $null } else { Get-BenchmarkMetric $baseline }
$failures = [System.Collections.Generic.List[string]]::new()

if ($RequireProcessWorkingSetPeak -and ($null -eq $currentMetrics.process_peak_working_set_mb -or $currentMetrics.process_peak_working_set_mb -le 0)) {
    $failures.Add('Process working-set high-water evidence is unavailable.')
}

foreach ($limit in @(
        @{ Name = 'working set'; Property = 'peak_working_set_mb'; Maximum = $MaximumWorkingSetMB },
        @{ Name = 'private memory'; Property = 'peak_private_memory_mb'; Maximum = $MaximumPrivateMemoryMB },
        @{ Name = 'GC heap'; Property = 'peak_gc_heap_mb'; Maximum = $MaximumGcHeapMB }
    )) {
    $value = $currentMetrics.($limit.Property)
    if ($limit.Maximum -gt 0 -and $null -eq $value) {
        $failures.Add(("Peak {0} evidence is unavailable." -f $limit.Name))
    }
    elseif ($limit.Maximum -gt 0 -and ($value -gt $limit.Maximum -or ($StrictWorkingSetLimit -and $limit.Property -eq 'peak_working_set_mb' -and $value -eq $limit.Maximum))) {
        $comparison = if ($StrictWorkingSetLimit -and $limit.Property -eq 'peak_working_set_mb') { 'must be below' } else { 'exceeded' }
        $failures.Add(("Peak {0} {1} MiB {2} {3} MiB." -f $limit.Name, $value, $comparison, $limit.Maximum))
    }
}

$elapsedRegressionPercent = $null
if ($null -ne $baselineMetrics) {
    if ($null -eq $baselineMetrics.elapsed_seconds -or $baselineMetrics.elapsed_seconds -le 0 -or $null -eq $currentMetrics.elapsed_seconds -or $currentMetrics.elapsed_seconds -le 0) {
        $failures.Add('Elapsed-time comparison requires positive baseline and current elapsed-time evidence.')
    }
    else {
        $baselineElapsed = [decimal]$baselineMetrics.elapsed_seconds
        $currentElapsed = [decimal]$currentMetrics.elapsed_seconds
        $elapsedRegressionPercent = (($currentElapsed - $baselineElapsed) / $baselineElapsed) * 100
        if ($elapsedRegressionPercent -gt [decimal]$MaximumElapsedRegressionPercent) {
            $failures.Add(("Elapsed time regressed by {0}% (maximum {1}%)." -f $elapsedRegressionPercent, $MaximumElapsedRegressionPercent))
        }
    }
}

$comparison = [PSCustomObject]@{
    evidence_schema_version = 1
    kind = 'benchmark-comparison'
    generated_utc = [datetime]::UtcNow.ToString('o')
    current_path = $current.Path
    baseline_path = if ($null -eq $baseline) { $null } else { $baseline.Path }
    current = $currentMetrics
    baseline = $baselineMetrics
    elapsed_regression_percent = $elapsedRegressionPercent
    passed = ($failures.Count -eq 0)
    failures = @($failures)
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { Write-BenchmarkEvidenceEnvelope -Path $OutputPath -Evidence $comparison }
$comparison
if ($failures.Count -gt 0) { throw ($failures -join ' ') }
