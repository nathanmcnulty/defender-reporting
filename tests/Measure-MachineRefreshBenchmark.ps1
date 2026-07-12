#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DatasetPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-datasets\synthetic-50k-1_5m'),

    [Parameter(Mandatory = $false)]
    [ValidateSet('all', 'no-change', 'small-change', 'moderate-change', 'removal-heavy')]
    [string]$Scenario = 'all',

    [Parameter(Mandatory = $false)]
    [ValidateRange(100, 5000)]
    [int]$PageSize = 1000,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'build\Import-SharedHelpers.ps1')
. (Join-Path $PSScriptRoot 'helpers\BenchmarkEvidenceTools.ps1')

if (-not (Test-Path -LiteralPath $DatasetPath -PathType Container)) {
    throw "Dataset path '$DatasetPath' does not exist."
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputDirectory = Join-Path $repoRoot ('.local\machine-refresh-benchmarks\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [void](New-Item -Path $outputDirectory -ItemType Directory -Force)
    $OutputPath = Join-Path $outputDirectory 'machine-refresh-benchmark.json'
}
else {
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
        [void](New-Item -Path $outputDirectory -ItemType Directory -Force)
    }
}

function Get-BenchmarkSnapshotRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Stopwatch]$Stopwatch
    )

    $process = [System.Diagnostics.Process]::GetCurrentProcess()
    return [PSCustomObject]@{
        label = $Label
        elapsed_seconds = [math]::Round($Stopwatch.Elapsed.TotalSeconds, 2)
        working_set_mb = [math]::Round(($process.WorkingSet64 / 1MB), 1)
        private_memory_mb = [math]::Round(($process.PrivateMemorySize64 / 1MB), 1)
        gc_heap_mb = [math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 1)
    }
}

function Add-BenchmarkSnapshot {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$Snapshots,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Stopwatch]$Stopwatch
    )

    $snapshot = Get-BenchmarkSnapshotRecord -Label $Label -Stopwatch $Stopwatch
    $Snapshots.Add($snapshot) | Out-Null
    Write-Host ("[{0}] ws={1}MB private={2}MB gc={3}MB elapsed={4}s" -f $snapshot.label, $snapshot.working_set_mb, $snapshot.private_memory_mb, $snapshot.gc_heap_mb, $snapshot.elapsed_seconds)
}

function Get-BenchmarkPeakSnapshot {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Snapshots,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    $peak = $null
    foreach ($snapshot in @($Snapshots)) {
        if ($null -eq $peak -or ([double]$snapshot.$PropertyName -gt [double]$peak.$PropertyName)) {
            $peak = $snapshot
        }
    }

    return $peak
}

function Copy-BenchmarkMachineRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Machine
    )

    $clone = [ordered]@{}
    foreach ($property in $Machine.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [System.Array]) {
            $clone[$property.Name] = @($value)
        }
        else {
            $clone[$property.Name] = $value
        }
    }

    return [PSCustomObject]$clone
}

function Get-ChangedBenchmarkMachineRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Machine,

        [Parameter(Mandatory = $true)]
        [int]$Ordinal
    )

    $clone = Copy-BenchmarkMachineRecord -Machine $Machine
    $riskCycle = @('Low', 'Medium', 'High')
    $nextRisk = $riskCycle[$Ordinal % $riskCycle.Count]
    $clone.riskScore = $nextRisk
    $clone.deviceValue = if (($Ordinal % 2) -eq 0) { 'High' } else { 'Normal' }
    $clone.healthStatus = if (($Ordinal % 3) -eq 0) { 'Inactive' } else { 'Active' }
    $existingTags = @($clone.machineTags)
    $existingTags += ('Bench' + ($Ordinal % 5))
    $clone.machineTags = @($existingTags | Select-Object -Unique)
    return $clone
}

function Get-ScenarioChangedIndexSet {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[int]])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$TotalCount,

        [Parameter(Mandatory = $true)]
        [int]$Count,

        [Parameter(Mandatory = $false)]
        [int]$Offset = 0
    )

    $effectiveCount = [Math]::Min([Math]::Max($Count, 0), $TotalCount)
    $result = [System.Collections.Generic.HashSet[int]]::new()
    if ($effectiveCount -le 0 -or $TotalCount -le 0) {
        return ,$result
    }

    $step = [Math]::Max([Math]::Floor($TotalCount / $effectiveCount), 1)
    $index = $Offset % $TotalCount
    while ($result.Count -lt $effectiveCount) {
        [void]$result.Add($index)
        $index = ($index + $step) % $TotalCount
    }

    return ,$result
}

function Get-MachineRefreshScenarioRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [psobject[]]$SourceMachines,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [int]$ChangeCount,

        [Parameter(Mandatory = $true)]
        [int]$RemovalCount,

        [Parameter(Mandatory = $true)]
        [int]$PageSize
    )

    $totalCount = @($SourceMachines).Count
    $removedIndexSet = Get-ScenarioChangedIndexSet -TotalCount $totalCount -Count $RemovalCount -Offset 0
    $changedIndexSet = Get-ScenarioChangedIndexSet -TotalCount $totalCount -Count $ChangeCount -Offset 137
    foreach ($removedIndex in @($removedIndexSet)) {
        [void]$changedIndexSet.Remove($removedIndex)
    }

    $pageResponses = [System.Collections.Generic.List[object]]::new()
    $currentPage = [System.Collections.Generic.List[object]]::new()
    $effectiveChangeCount = 0
    $effectiveRemovalCount = 0
    $pageOrdinal = 0
    $ordinal = 0

    foreach ($machine in @($SourceMachines)) {
        if ($removedIndexSet.Contains($ordinal)) {
            $effectiveRemovalCount++
            $ordinal++
            continue
        }

        $pageMachine = if ($changedIndexSet.Contains($ordinal)) {
            $effectiveChangeCount++
            Get-ChangedBenchmarkMachineRecord -Machine $machine -Ordinal $ordinal
        }
        else {
            $machine
        }

        $currentPage.Add($pageMachine) | Out-Null
        if ($currentPage.Count -ge $PageSize) {
            $pageOrdinal++
            $pageResponses.Add([PSCustomObject]@{
                    value = @($currentPage.ToArray())
                    nextLink = ("mock://machines/page/{0}" -f ($pageOrdinal + 1))
                }) | Out-Null
            $currentPage = [System.Collections.Generic.List[object]]::new()
        }

        $ordinal++
    }

    if ($currentPage.Count -gt 0) {
        $pageOrdinal++
        $pageResponses.Add([PSCustomObject]@{
                value = @($currentPage.ToArray())
                nextLink = $null
            }) | Out-Null
    }
    elseif ($pageResponses.Count -gt 0) {
        $pageResponses[$pageResponses.Count - 1].nextLink = $null
    }

    return [PSCustomObject]@{
        name = $Name
        total_machines = $totalCount
        changed_count = $effectiveChangeCount
        removal_count = $effectiveRemovalCount
        page_count = $pageResponses.Count
        pages = @($pageResponses.ToArray())
    }
}

function Invoke-MachineRefreshBenchmarkMode {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatasetPath,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Scenario,

        [Parameter(Mandatory = $true)]
        [ValidateSet('legacy-full', 'statehash-only')]
        [string]$Mode
    )

    $modeUsesStateHashOnly = ($Mode -eq 'statehash-only')
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-refresh-benchmark-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $stagedCurrentPath = Join-Path $tempRoot 'Machines_Current.json.gz'
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $snapshots = [System.Collections.Generic.List[object]]::new()
    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $script:MachineRefreshBenchmarkPages = @($Scenario.pages)
    $script:MachineRefreshBenchmarkPageIndex = 0

    try {
        Add-BenchmarkSnapshot -Snapshots $snapshots -Label 'Start' -Stopwatch $stopwatch
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [hashtable]$Headers,
                [string]$Method
            )

            [void]$Uri
            [void]$Headers
            [void]$Method

            if ($script:MachineRefreshBenchmarkPageIndex -ge $script:MachineRefreshBenchmarkPages.Count) {
                throw "Benchmark machine refresh mock exceeded the available response page count."
            }

            $response = $script:MachineRefreshBenchmarkPages[$script:MachineRefreshBenchmarkPageIndex]
            $script:MachineRefreshBenchmarkPageIndex++
            $result = [ordered]@{
                value = @($response.value)
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$response.nextLink)) {
                $result['@odata.nextLink'] = [string]$response.nextLink
            }

            return [PSCustomObject]$result
        }

        $store = Initialize-MachineHistoryStore -Path $DatasetPath -LoadCurrentRecordsStateHashOnly:$modeUsesStateHashOnly
        Add-BenchmarkSnapshot -Snapshots $snapshots -Label 'PostInitializeCurrentRecords' -Stopwatch $stopwatch
        $refreshPlan = Get-MdeMachineRefreshPublishPlan -Headers @{ Authorization = 'Bearer benchmark' } -BaseApiUrl 'https://example.invalid' -ObservedOn '2026-05-10' -CurrentRecords $store.CurrentRecords -StagedCurrentPath $stagedCurrentPath
        Add-BenchmarkSnapshot -Snapshots $snapshots -Label 'PostRefreshPlan' -Stopwatch $stopwatch
        $residualCurrentCount = $store.CurrentRecords.Count
        $store.CurrentRecords = $null
        $refreshPlanCurrentPath = $refreshPlan.StagedCurrentPath
        $refreshPlanHistoryPath = $refreshPlan.StagedHistoryPath
        $refreshPlanHistoryTargetPath = $refreshPlan.HistoryTargetPath
        $refreshPlanChangeCount = $refreshPlan.ChangeCount
        $refreshPlanMachineCount = $refreshPlan.MachineCount
        $refreshPlanPageCount = $refreshPlan.PageCount
        $refreshPlan = $null
        Invoke-FullGarbageCollection
        Add-BenchmarkSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch

        $peakWorkingSet = Get-BenchmarkPeakSnapshot -Snapshots @($snapshots.ToArray()) -PropertyName 'working_set_mb'
        $peakPrivateMemory = Get-BenchmarkPeakSnapshot -Snapshots @($snapshots.ToArray()) -PropertyName 'private_memory_mb'
        $peakGcHeap = Get-BenchmarkPeakSnapshot -Snapshots @($snapshots.ToArray()) -PropertyName 'gc_heap_mb'

        return [PSCustomObject]@{
            mode = $Mode
            load_current_records_statehash_only = $modeUsesStateHashOnly
            elapsed_seconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
            machine_count = $refreshPlanMachineCount
            change_count = $refreshPlanChangeCount
            removal_count = $Scenario.removal_count
            page_count = $refreshPlanPageCount
            residual_current_records = $residualCurrentCount
            peak_working_set_mb = [double]$peakWorkingSet.working_set_mb
            peak_working_set_label = [string]$peakWorkingSet.label
            peak_private_memory_mb = [double]$peakPrivateMemory.private_memory_mb
            peak_private_memory_label = [string]$peakPrivateMemory.label
            peak_gc_heap_mb = [double]$peakGcHeap.gc_heap_mb
            peak_gc_heap_label = [string]$peakGcHeap.label
            staged_current_path = $refreshPlanCurrentPath
            staged_history_path = $refreshPlanHistoryPath
            history_target_path = $refreshPlanHistoryTargetPath
            snapshots = @($snapshots.ToArray())
        }
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Remove-Variable -Name MachineRefreshBenchmarkPages -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name MachineRefreshBenchmarkPageIndex -Scope Script -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $tempRoot -PathType Container) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

$machineCurrentPath = Get-MachineCurrentPath -BasePath $DatasetPath
if (-not (Test-Path -LiteralPath $machineCurrentPath -PathType Leaf)) {
    throw "Machine current store '$machineCurrentPath' was not found."
}

Write-Output ("Loading machine records from {0}..." -f $machineCurrentPath)
$sourceMachines = @(Read-MachineRecordsFromFile -Path $machineCurrentPath)
if ($sourceMachines.Count -eq 0) {
    throw "No machine records were loaded from '$machineCurrentPath'."
}

$scenarioDefinitions = @(
    [PSCustomObject]@{ name = 'no-change'; changed = 0; removed = 0 }
    [PSCustomObject]@{ name = 'small-change'; changed = 100; removed = 0 }
    [PSCustomObject]@{ name = 'moderate-change'; changed = 5000; removed = 0 }
    [PSCustomObject]@{ name = 'removal-heavy'; changed = 5000; removed = 10000 }
)

$selectedDefinitions = if ($Scenario -eq 'all') {
    $scenarioDefinitions
}
else {
    @($scenarioDefinitions | Where-Object { $_.name -eq $Scenario })
}

$results = [System.Collections.Generic.List[object]]::new()
foreach ($definition in $selectedDefinitions) {
    Write-Output ''
    Write-Output ("=== Scenario: {0} ===" -f $definition.name)
    $scenarioState = Get-MachineRefreshScenarioRecord -SourceMachines $sourceMachines -Name $definition.name -ChangeCount $definition.changed -RemovalCount $definition.removed -PageSize $PageSize
    Write-Output ("Prepared {0} page(s) from {1} machine(s): changed={2}, removed={3}" -f $scenarioState.page_count, $scenarioState.total_machines, $scenarioState.changed_count, $scenarioState.removal_count)

    $legacyResult = Invoke-MachineRefreshBenchmarkMode -DatasetPath $DatasetPath -Scenario $scenarioState -Mode 'legacy-full'
    $stateHashResult = Invoke-MachineRefreshBenchmarkMode -DatasetPath $DatasetPath -Scenario $scenarioState -Mode 'statehash-only'

    if (($legacyResult.machine_count -ne $stateHashResult.machine_count) -or ($legacyResult.change_count -ne $stateHashResult.change_count) -or ($legacyResult.page_count -ne $stateHashResult.page_count)) {
        throw ("Scenario '{0}' produced different refresh results between modes." -f $definition.name)
    }

    $comparison = [PSCustomObject]@{
        scenario = $definition.name
        working_set_delta_mb = [math]::Round(([double]$stateHashResult.peak_working_set_mb - [double]$legacyResult.peak_working_set_mb), 1)
        private_memory_delta_mb = [math]::Round(([double]$stateHashResult.peak_private_memory_mb - [double]$legacyResult.peak_private_memory_mb), 1)
        gc_heap_delta_mb = [math]::Round(([double]$stateHashResult.peak_gc_heap_mb - [double]$legacyResult.peak_gc_heap_mb), 1)
        elapsed_delta_seconds = [math]::Round(([double]$stateHashResult.elapsed_seconds - [double]$legacyResult.elapsed_seconds), 2)
    }

    Write-Output ("Legacy full map: ws={0}MB private={1}MB gc={2}MB elapsed={3}s" -f $legacyResult.peak_working_set_mb, $legacyResult.peak_private_memory_mb, $legacyResult.peak_gc_heap_mb, $legacyResult.elapsed_seconds)
    Write-Output ("StateHash map: ws={0}MB private={1}MB gc={2}MB elapsed={3}s" -f $stateHashResult.peak_working_set_mb, $stateHashResult.peak_private_memory_mb, $stateHashResult.peak_gc_heap_mb, $stateHashResult.elapsed_seconds)
    Write-Output ("Delta (stateHash - legacy): ws={0}MB private={1}MB gc={2}MB elapsed={3}s" -f $comparison.working_set_delta_mb, $comparison.private_memory_delta_mb, $comparison.gc_heap_delta_mb, $comparison.elapsed_delta_seconds)

    $results.Add([PSCustomObject]@{
            scenario = $definition.name
            metadata = [PSCustomObject]@{
                total_machines = $scenarioState.total_machines
                changed_count = $scenarioState.changed_count
                removal_count = $scenarioState.removal_count
                page_count = $scenarioState.page_count
                page_size = $PageSize
            }
            legacy_full = $legacyResult
            statehash_only = $stateHashResult
            comparison = $comparison
        }) | Out-Null
}

$result = [PSCustomObject]@{
    generated_utc = (Get-Date).ToUniversalTime().ToString('o')
    dataset_path = [System.IO.Path]::GetFullPath($DatasetPath)
    output_path = [System.IO.Path]::GetFullPath($OutputPath)
    page_size = $PageSize
    results = @($results.ToArray())
}

$result | Add-Member -NotePropertyName benchmark_evidence -NotePropertyValue (Get-BenchmarkEvidenceEnvelope `
        -Kind 'machine-refresh' `
        -RepoPath $repoRoot `
        -Dataset (Get-BenchmarkDatasetEvidence -DatasetPath $DatasetPath) `
        -Environment ([PSCustomObject]@{ host = 'local'; platform = [System.Environment]::OSVersion.ToString() }) `
        -Execution ([PSCustomObject]@{ scenario = $Scenario; page_size = $PageSize; results = @($results.ToArray()) }) `
        -Validation ([PSCustomObject]@{ compared_modes = @('legacy_full', 'statehash_only') }))
Write-BenchmarkEvidenceEnvelope -Path $OutputPath -Evidence $result

Write-Output ''
Write-Output ("Results written to {0}" -f [System.IO.Path]::GetFullPath($OutputPath))
