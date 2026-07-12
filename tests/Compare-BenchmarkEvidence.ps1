#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CurrentPath,
    [Parameter(Mandatory = $false)][string]$BaselinePath,
    [Parameter(Mandatory = $false)][double]$MaximumWorkingSetMB = 0,
    [Parameter(Mandatory = $false)][double]$MaximumPrivateMemoryMB = 0,
    [Parameter(Mandatory = $false)][double]$MaximumGcHeapMB = 0,
    [Parameter(Mandatory = $false)][ValidateRange(0, 1000)][double]$MaximumElapsedRegressionPercent = 20,
    [Parameter(Mandatory = $false)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helpers\BenchmarkEvidenceTools.ps1')

function Add-NumericPropertyValue {
    param($Item, [string[]]$PropertyNames, [System.Collections.Generic.List[double]]$Accumulator)
    if ($null -eq $Item -or $Item -is [string] -or $Item -is [ValueType]) { return }
    if ($Item -is [System.Collections.IDictionary]) {
        foreach ($key in $Item.Keys) {
            if ($PropertyNames -contains [string]$key -and $null -ne $Item[$key]) { $Accumulator.Add([double]$Item[$key]) }
            Add-NumericPropertyValue -Item $Item[$key] -PropertyNames $PropertyNames -Accumulator $Accumulator
        }
        return
    }
    if ($Item -is [System.Collections.IEnumerable]) { foreach ($entry in $Item) { Add-NumericPropertyValue -Item $entry -PropertyNames $PropertyNames -Accumulator $Accumulator }; return }
    foreach ($property in $Item.PSObject.Properties) {
        if ($PropertyNames -contains $property.Name -and $null -ne $property.Value) { $Accumulator.Add([double]$property.Value) }
        Add-NumericPropertyValue -Item $property.Value -PropertyNames $PropertyNames -Accumulator $Accumulator
    }
}

function Get-NumericPropertyMaximum {
    param([AllowNull()]$Value, [Parameter(Mandatory = $true)][string[]]$Names)

    $values = [System.Collections.Generic.List[double]]::new()
    Add-NumericPropertyValue -Item $Value -PropertyNames $Names -Accumulator $values
    if ($values.Count -eq 0) { return $null }
    return [math]::Round(($values | Measure-Object -Maximum).Maximum, 2)
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
        peak_working_set_mb = Get-NumericPropertyMaximum $record.Evidence.execution @('peak_working_set_mb', 'peakWorkingSetMb', 'working_set_mb')
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

foreach ($limit in @(
        @{ Name = 'working set'; Property = 'peak_working_set_mb'; Maximum = $MaximumWorkingSetMB },
        @{ Name = 'private memory'; Property = 'peak_private_memory_mb'; Maximum = $MaximumPrivateMemoryMB },
        @{ Name = 'GC heap'; Property = 'peak_gc_heap_mb'; Maximum = $MaximumGcHeapMB }
    )) {
    $value = $currentMetrics.($limit.Property)
    if ($limit.Maximum -gt 0 -and $null -ne $value -and $value -gt $limit.Maximum) {
        $failures.Add(("Peak {0} {1}MB exceeded {2}MB." -f $limit.Name, $value, $limit.Maximum))
    }
}

$elapsedRegressionPercent = $null
if ($null -ne $baselineMetrics -and $null -ne $baselineMetrics.elapsed_seconds -and $baselineMetrics.elapsed_seconds -gt 0 -and $null -ne $currentMetrics.elapsed_seconds) {
    $elapsedRegressionPercent = [math]::Round((($currentMetrics.elapsed_seconds - $baselineMetrics.elapsed_seconds) / $baselineMetrics.elapsed_seconds) * 100, 2)
    if ($elapsedRegressionPercent -gt $MaximumElapsedRegressionPercent) {
        $failures.Add(("Elapsed time regressed by {0}% (maximum {1}%)." -f $elapsedRegressionPercent, $MaximumElapsedRegressionPercent))
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
