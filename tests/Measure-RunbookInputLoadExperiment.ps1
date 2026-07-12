#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DatasetPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-datasets\synthetic-50k-1_5m'),

    [Parameter(Mandatory = $true)]
    [ValidateSet('baseline', 'precompact-machines', 'gc-after-load', 'precompact-plus-gc', 'bundle-only', 'bundle-precompact', 'bundle-precompact-plus-gc', 'machine-full', 'machine-id-index', 'machine-file-backed', 'machine-file-backed-bucketed', 'machine-file-backed-profile-access', 'machine-sequential-profile-access', 'machine-merge-profile-access', 'machine-merge-spill-profile-access', 'machine-merge-spill-profile-access-gc', 'device-lookup-file-backed', 'device-lookup-direct-merge', 'device-lookup-direct-merge-spill')]
    [string]$Experiment,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$CompareToPath
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
    $outputDirectory = Join-Path $repoRoot ('.local\runbook-input-experiments\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [void](New-Item -Path $outputDirectory -ItemType Directory -Force)
    $OutputPath = Join-Path $outputDirectory ($Experiment + '.json')
}
else {
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
        [void](New-Item -Path $outputDirectory -ItemType Directory -Force)
    }
}

if (-not [string]::IsNullOrWhiteSpace($CompareToPath)) {
    $CompareToPath = [System.IO.Path]::GetFullPath($CompareToPath)
    if (-not (Test-Path -LiteralPath $CompareToPath -PathType Leaf)) {
        throw "Compare-to path '$CompareToPath' does not exist."
    }
}

function Get-ExperimentPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject[$Name]
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Get-ExperimentMemorySnapshot {
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
        gc_heap_mb = [math]::Round(([System.GC]::GetTotalMemory($false) / 1MB), 1)
    }
}

function Add-ExperimentSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Snapshots,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Stopwatch]$Stopwatch
    )

    $snapshot = Get-ExperimentMemorySnapshot -Label $Label -Stopwatch $Stopwatch
    $Snapshots.Add($snapshot) | Out-Null
    Write-Output ("[{0}] working-set={1}MB gc-heap={2}MB elapsed={3}s" -f $snapshot.label, $snapshot.working_set_mb, $snapshot.gc_heap_mb, $snapshot.elapsed_seconds)
}

function Get-ExperimentSnapshotAreaSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Snapshots,

        [Parameter(Mandatory = $true)]
        [double]$ElapsedSeconds
    )

    $snapshotArray = @($Snapshots)
    if ($snapshotArray.Count -eq 0) {
        return [PSCustomObject]@{
            WorkingSetAreaMbSeconds = 0.0
            GcHeapAreaMbSeconds = 0.0
        }
    }

    $workingSetAreaMbSeconds = 0.0
    $gcHeapAreaMbSeconds = 0.0
    for ($index = 0; $index -lt ($snapshotArray.Count - 1); $index++) {
        $currentSnapshot = $snapshotArray[$index]
        $nextSnapshot = $snapshotArray[$index + 1]
        $deltaSeconds = [math]::Max(([double]$nextSnapshot.elapsed_seconds - [double]$currentSnapshot.elapsed_seconds), 0.0)
        if ($deltaSeconds -le 0.0) {
            continue
        }

        $workingSetAreaMbSeconds += ((([double]$currentSnapshot.working_set_mb + [double]$nextSnapshot.working_set_mb) / 2.0) * $deltaSeconds)
        $gcHeapAreaMbSeconds += ((([double]$currentSnapshot.gc_heap_mb + [double]$nextSnapshot.gc_heap_mb) / 2.0) * $deltaSeconds)
    }

    $lastSnapshot = $snapshotArray[$snapshotArray.Count - 1]
    $tailSeconds = [math]::Max(($ElapsedSeconds - [double]$lastSnapshot.elapsed_seconds), 0.0)
    if ($tailSeconds -gt 0.0) {
        $workingSetAreaMbSeconds += ([double]$lastSnapshot.working_set_mb * $tailSeconds)
        $gcHeapAreaMbSeconds += ([double]$lastSnapshot.gc_heap_mb * $tailSeconds)
    }

    return [PSCustomObject]@{
        WorkingSetAreaMbSeconds = [math]::Round($workingSetAreaMbSeconds, 2)
        GcHeapAreaMbSeconds = [math]::Round($gcHeapAreaMbSeconds, 2)
    }
}

function Get-ExperimentDiskFootprintByteCount {
    [CmdletBinding()]
    [OutputType([int64])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Details
    )

    if ($null -eq $Details) {
        return [int64]0
    }

    $totalBytes = [int64]0
    foreach ($property in $Details.PSObject.Properties) {
        if ($property.Name -notlike '*_bytes') {
            continue
        }

        if ($null -eq $property.Value) {
            continue
        }

        $totalBytes += [int64]$property.Value
    }

    return $totalBytes
}

function Get-ExperimentTradeoffSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Result
    )

    if ($null -eq $Result) {
        return $null
    }

    $elapsedSeconds = [double](Get-ExperimentPropertyValue -InputObject $Result -Name 'elapsed_seconds')
    $peakWorkingSetMb = [double](Get-ExperimentPropertyValue -InputObject $Result -Name 'peak_working_set_mb')
    $peakGcHeapMb = [double](Get-ExperimentPropertyValue -InputObject $Result -Name 'peak_gc_heap_mb')
    $details = Get-ExperimentPropertyValue -InputObject $Result -Name 'details'
    $counts = Get-ExperimentPropertyValue -InputObject $Result -Name 'counts'
    $snapshots = @(Get-ExperimentPropertyValue -InputObject $Result -Name 'snapshots')
    $snapshotArea = Get-ExperimentSnapshotAreaSummary -Snapshots $snapshots -ElapsedSeconds $elapsedSeconds
    $diskFootprintBytes = Get-ExperimentDiskFootprintByteCount -Details $details

    $workUnitLabel = $null
    $workUnitCount = 0
    $deviceProfileCount = Get-ExperimentPropertyValue -InputObject $details -Name 'device_profile_count'
    if ($null -ne $deviceProfileCount -and [int]$deviceProfileCount -gt 0) {
        $workUnitLabel = 'device_profiles'
        $workUnitCount = [int]$deviceProfileCount
    }
    else {
        $machineCount = Get-ExperimentPropertyValue -InputObject $counts -Name 'machines'
        if ($null -ne $machineCount -and [int]$machineCount -gt 0) {
            $workUnitLabel = 'machines'
            $workUnitCount = [int]$machineCount
        }
    }

    return [PSCustomObject]@{
        work_unit_label = $workUnitLabel
        work_unit_count = $workUnitCount
        work_units_per_second = if ($workUnitCount -gt 0 -and $elapsedSeconds -gt 0.0) {
            [math]::Round(($workUnitCount / $elapsedSeconds), 2)
        }
        else {
            $null
        }
        disk_footprint_mb = if ($diskFootprintBytes -gt 0) {
            [math]::Round(($diskFootprintBytes / 1MB), 2)
        }
        else {
            $null
        }
        peak_working_set_mb_seconds = [math]::Round(($peakWorkingSetMb * $elapsedSeconds), 2)
        peak_gc_heap_mb_seconds = [math]::Round(($peakGcHeapMb * $elapsedSeconds), 2)
        snapshot_working_set_area_mb_seconds = [double]$snapshotArea.WorkingSetAreaMbSeconds
        snapshot_gc_heap_area_mb_seconds = [double]$snapshotArea.GcHeapAreaMbSeconds
    }
}

function Get-ExperimentComparisonSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$CurrentResult,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$BaselineResult,

        [Parameter(Mandatory = $true)]
        [string]$BaselinePath
    )

    if ($null -eq $CurrentResult -or $null -eq $BaselineResult) {
        return $null
    }

    $currentTradeoff = Get-ExperimentTradeoffSummary -Result $CurrentResult
    $baselineTradeoff = Get-ExperimentTradeoffSummary -Result $BaselineResult

    $peakWorkingSetDeltaMb = [math]::Round(
        ([double](Get-ExperimentPropertyValue -InputObject $CurrentResult -Name 'peak_working_set_mb') -
            [double](Get-ExperimentPropertyValue -InputObject $BaselineResult -Name 'peak_working_set_mb')),
        2
    )
    $peakGcHeapDeltaMb = [math]::Round(
        ([double](Get-ExperimentPropertyValue -InputObject $CurrentResult -Name 'peak_gc_heap_mb') -
            [double](Get-ExperimentPropertyValue -InputObject $BaselineResult -Name 'peak_gc_heap_mb')),
        2
    )
    $elapsedDeltaSeconds = [math]::Round(
        ([double](Get-ExperimentPropertyValue -InputObject $CurrentResult -Name 'elapsed_seconds') -
            [double](Get-ExperimentPropertyValue -InputObject $BaselineResult -Name 'elapsed_seconds')),
        2
    )

    $assessment = 'mixed'
    if ($peakWorkingSetDeltaMb -lt 0 -and $peakGcHeapDeltaMb -lt 0 -and $elapsedDeltaSeconds -lt 0) {
        $assessment = 'faster_and_lower_memory'
    }
    elseif ($peakWorkingSetDeltaMb -lt 0 -and $peakGcHeapDeltaMb -lt 0 -and $elapsedDeltaSeconds -gt 0) {
        $assessment = 'lower_memory_but_slower'
    }
    elseif ($peakWorkingSetDeltaMb -gt 0 -and $peakGcHeapDeltaMb -gt 0 -and $elapsedDeltaSeconds -lt 0) {
        $assessment = 'faster_but_higher_memory'
    }
    elseif ($peakWorkingSetDeltaMb -gt 0 -and $peakGcHeapDeltaMb -gt 0 -and $elapsedDeltaSeconds -gt 0) {
        $assessment = 'slower_and_higher_memory'
    }

    return [PSCustomObject]@{
        baseline_path = $BaselinePath
        baseline_experiment = Get-ExperimentPropertyValue -InputObject $BaselineResult -Name 'experiment'
        baseline_generated_utc = Get-ExperimentPropertyValue -InputObject $BaselineResult -Name 'generated_utc'
        assessment = $assessment
        peak_working_set_delta_mb = $peakWorkingSetDeltaMb
        peak_gc_heap_delta_mb = $peakGcHeapDeltaMb
        elapsed_delta_seconds = $elapsedDeltaSeconds
        snapshot_working_set_area_delta_mb_seconds = [math]::Round(
            ([double](Get-ExperimentPropertyValue -InputObject $currentTradeoff -Name 'snapshot_working_set_area_mb_seconds') -
                [double](Get-ExperimentPropertyValue -InputObject $baselineTradeoff -Name 'snapshot_working_set_area_mb_seconds')),
            2
        )
        snapshot_gc_heap_area_delta_mb_seconds = [math]::Round(
            ([double](Get-ExperimentPropertyValue -InputObject $currentTradeoff -Name 'snapshot_gc_heap_area_mb_seconds') -
                [double](Get-ExperimentPropertyValue -InputObject $baselineTradeoff -Name 'snapshot_gc_heap_area_mb_seconds')),
            2
        )
        disk_footprint_delta_mb = if ($null -ne (Get-ExperimentPropertyValue -InputObject $currentTradeoff -Name 'disk_footprint_mb') -and
            $null -ne (Get-ExperimentPropertyValue -InputObject $baselineTradeoff -Name 'disk_footprint_mb')) {
            [math]::Round(
                ([double](Get-ExperimentPropertyValue -InputObject $currentTradeoff -Name 'disk_footprint_mb') -
                    [double](Get-ExperimentPropertyValue -InputObject $baselineTradeoff -Name 'disk_footprint_mb')),
                2
            )
        }
        else {
            $null
        }
        work_units_per_second_delta = if ($null -ne (Get-ExperimentPropertyValue -InputObject $currentTradeoff -Name 'work_units_per_second') -and
            $null -ne (Get-ExperimentPropertyValue -InputObject $baselineTradeoff -Name 'work_units_per_second')) {
            [math]::Round(
                ([double](Get-ExperimentPropertyValue -InputObject $currentTradeoff -Name 'work_units_per_second') -
                    [double](Get-ExperimentPropertyValue -InputObject $baselineTradeoff -Name 'work_units_per_second')),
                2
            )
        }
        else {
            $null
        }
        working_set_mb_saved_per_added_second = if ($peakWorkingSetDeltaMb -lt 0 -and $elapsedDeltaSeconds -gt 0) {
            [math]::Round(((-1.0 * $peakWorkingSetDeltaMb) / $elapsedDeltaSeconds), 2)
        }
        else {
            $null
        }
        gc_heap_mb_saved_per_added_second = if ($peakGcHeapDeltaMb -lt 0 -and $elapsedDeltaSeconds -gt 0) {
            [math]::Round(((-1.0 * $peakGcHeapDeltaMb) / $elapsedDeltaSeconds), 2)
        }
        else {
            $null
        }
    }
}

function Read-ContentStoreDeviceProfileIdList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $dictionaryPath = Join-Path $Path 'VulnContentDictionary.json.gz'
    if (-not (Test-Path -LiteralPath $dictionaryPath -PathType Leaf)) {
        return @()
    }

    $deviceProfileIds = [System.Collections.Generic.List[string]]::new()
    Read-VulnContentDictionaryArrayEntries -Path $dictionaryPath -PropertyName 'deviceProfiles' | ForEach-Object {
        $deviceId = [string]$_.id
        if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
            $deviceProfileIds.Add($deviceId) | Out-Null
        }
    }

    return [string[]]$deviceProfileIds.ToArray()
}

function Read-JsonTextReaderScalarValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader
    )

    switch ($Reader.TokenType) {
        ([Newtonsoft.Json.JsonToken]::Null) { return $null }
        ([Newtonsoft.Json.JsonToken]::String) { return [string]$Reader.Value }
        ([Newtonsoft.Json.JsonToken]::Boolean) { return [bool]$Reader.Value }
        ([Newtonsoft.Json.JsonToken]::Integer) { return $Reader.Value }
        ([Newtonsoft.Json.JsonToken]::Float) { return $Reader.Value }
        default { return $Reader.Value }
    }
}

function Read-JsonTextReaderStringArrayValue {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader
    )

    if ($Reader.TokenType -eq [Newtonsoft.Json.JsonToken]::Null) {
        return [string[]]@()
    }

    if ($Reader.TokenType -eq [Newtonsoft.Json.JsonToken]::String) {
        return [string[]]@(Get-NormalizedMachineTag -Tags ([string]$Reader.Value))
    }

    if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray) {
        return [string[]]@(Get-NormalizedMachineTag -Tags (Read-JsonTextReaderScalarValue -Reader $Reader))
    }

    $values = [System.Collections.Generic.List[string]]::new()
    while ($Reader.Read()) {
        if ($Reader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndArray) {
            break
        }

        $value = Read-JsonTextReaderScalarValue -Reader $Reader
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            $values.Add([string]$value) | Out-Null
        }
    }

    return [string[]]@(Get-NormalizedMachineTag -Tags @($values))
}

function ConvertFrom-MachineJsonTextReaderToNormalizationEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader
    )

    $machineId = $null
    $removed = $false
    $ip = $null
    $externalIp = $null
    $healthStatus = $null
    $riskScore = $null
    $exposureLevel = $null
    $deviceValue = $null
    $managedBy = $null
    $isAadJoined = $null
    $lastSeen = $null
    $firstSeen = $null
    $osVersion = $null
    $computerDnsName = $null
    $rbacGroupName = $null
    $osPlatform = $null
    $machineTags = [string[]]@()

    while ($Reader.Read()) {
        if ($Reader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndObject) {
            break
        }

        if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::PropertyName) {
            continue
        }

        $propertyName = [string]$Reader.Value
        if (-not $Reader.Read()) {
            throw 'Unexpected end of machine record while reading property value.'
        }

        switch ($propertyName) {
            'id' { $machineId = [string](Read-JsonTextReaderScalarValue -Reader $Reader) }
            'removed' { $removed = ((Read-JsonTextReaderScalarValue -Reader $Reader) -eq $true) }
            'lastIpAddress' { $ip = Read-JsonTextReaderScalarValue -Reader $Reader }
            'lastExternalIpAddress' { $externalIp = Read-JsonTextReaderScalarValue -Reader $Reader }
            'healthStatus' { $healthStatus = Read-JsonTextReaderScalarValue -Reader $Reader }
            'riskScore' { $riskScore = Read-JsonTextReaderScalarValue -Reader $Reader }
            'exposureLevel' { $exposureLevel = Read-JsonTextReaderScalarValue -Reader $Reader }
            'deviceValue' { $deviceValue = Read-JsonTextReaderScalarValue -Reader $Reader }
            'managedBy' { $managedBy = Read-JsonTextReaderScalarValue -Reader $Reader }
            'isAadJoined' { $isAadJoined = Read-JsonTextReaderScalarValue -Reader $Reader }
            'lastSeen' { $lastSeen = Read-JsonTextReaderScalarValue -Reader $Reader }
            'firstSeen' { $firstSeen = Read-JsonTextReaderScalarValue -Reader $Reader }
            'osVersion' { $osVersion = Read-JsonTextReaderScalarValue -Reader $Reader }
            'computerDnsName' { $computerDnsName = Read-JsonTextReaderScalarValue -Reader $Reader }
            'rbacGroupName' { $rbacGroupName = Read-JsonTextReaderScalarValue -Reader $Reader }
            'osPlatform' { $osPlatform = Read-JsonTextReaderScalarValue -Reader $Reader }
            'machineTags' { $machineTags = Read-JsonTextReaderStringArrayValue -Reader $Reader }
            default { Skip-VulnJsonReaderValue -Reader $Reader }
        }
    }

    if ([string]::IsNullOrWhiteSpace($machineId)) {
        return $null
    }

    if ($removed) {
        return [PSCustomObject]@{
            id = $machineId
            removed = $true
            tuple = $null
        }
    }

    $tuple = [object[]]@(
        $ip,
        $externalIp,
        $healthStatus,
        $riskScore,
        $exposureLevel,
        $deviceValue,
        $managedBy,
        $isAadJoined,
        $lastSeen,
        $firstSeen,
        $osVersion,
        $computerDnsName,
        $rbacGroupName,
        $osPlatform,
        @($machineTags)
    )

    $hasTupleValue = $false
    foreach ($value in $tuple) {
        if ($null -ne $value -and ($value -isnot [System.Array] -or $value.Length -gt 0)) {
            $hasTupleValue = $true
            break
        }
    }

    return [PSCustomObject]@{
        id = $machineId
        removed = $false
        tuple = if ($hasTupleValue) { $tuple } else { $null }
    }
}

function Open-MachineNormalizationEntryJsonReader {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $readerState = Open-VulnJsonTextReader -Path $Path
    $jsonReader = $readerState.JsonReader
    $jsonReader.SupportMultipleContent = $true

    $mode = 'Empty'
    $hasPendingObject = $false
    if ($jsonReader.Read()) {
        if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::StartArray) {
            $mode = 'Array'
        }
        elseif ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::StartObject) {
            $mode = 'Multiple'
            $hasPendingObject = $true
        }
        else {
            throw "Unsupported machine source token '$($jsonReader.TokenType)' in '$Path'."
        }
    }

    return [PSCustomObject]@{
        ReaderState = $readerState
        Mode = $mode
        HasPendingObject = $hasPendingObject
    }
}

function Read-NextMachineNormalizationEntryFromJsonReader {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Reader
    )

    $jsonReader = $Reader.ReaderState.JsonReader
    if ($Reader.Mode -eq 'Empty') {
        return $null
    }

    while ($true) {
        if ($Reader.Mode -eq 'Array') {
            if (-not $jsonReader.Read()) {
                return $null
            }

            if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndArray) {
                return $null
            }

            if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::Null) {
                continue
            }

            if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartObject) {
                throw "Unexpected token '$($jsonReader.TokenType)' while reading machine array."
            }
        }
        elseif ($Reader.HasPendingObject) {
            $Reader.HasPendingObject = $false
        }
        else {
            if (-not $jsonReader.Read()) {
                return $null
            }

            if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::Comment) {
                continue
            }

            if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartObject) {
                throw "Unexpected token '$($jsonReader.TokenType)' while reading machine sequence."
            }
        }

        return (ConvertFrom-MachineJsonTextReaderToNormalizationEntry -Reader $jsonReader)
    }
}

function Close-MachineNormalizationEntryJsonReader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [pscustomobject]$Reader
    )

    if ($null -eq $Reader) {
        return
    }

    Close-VulnJsonTextReader -State $Reader.ReaderState
}

function Get-ResolvedMachineCurrentReadPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $currentPath = Get-MachineCurrentPath -BasePath $Path
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath
    if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
        return $currentPath
    }

    if (Test-Path -LiteralPath $legacyCurrentPath -PathType Leaf) {
        return $legacyCurrentPath
    }

    return $null
}

function Invoke-DeviceLookupFileBackedPass {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $context = Get-NormalizationContext
    $deviceLookupStorePath = Join-Path ([System.IO.Path]::GetTempPath()) ('device-lookups-file-backed-' + [System.Guid]::NewGuid().ToString('N') + '.json')
    $context.Lookups.devices = Open-NormalizedLookupFileStore -Path $deviceLookupStorePath
    $context.AdvancedHuntingDeviceUsers = @{}
    $context.Machines = Read-NormalizationMachineLookup -Path $Path -FileBacked

    $deviceProfileCount = 0
    $onboardedCount = 0
    try {
        $dictionaryPath = Get-VulnContentDictionaryPath -BasePath $Path
        Read-VulnContentDictionaryArrayEntries -Path $dictionaryPath -PropertyName 'deviceProfiles' | ForEach-Object {
            $deviceProfile = $_
            $deviceProfileCount++
            if ((Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ob') -eq $true) {
                $onboardedCount++
            }

            [void](Add-NormalizedDevice `
                    -DeviceId ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'id')) `
                    -DeviceName ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'n')) `
                    -GroupName ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'g')) `
                    -OsPlatform ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'o')) `
                    -OsVersion ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ov')) `
                    -MachineTags @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $deviceProfile -Name 't')) `
                    -Context $context)
        }

        Complete-NormalizedLookupFileStore -Store $context.Lookups.devices
        return [PSCustomObject]@{
            DeviceProfileCount = $deviceProfileCount
            OnboardedCount = $onboardedCount
            DeviceLookupCount = [int]$context.Lookups.devices.Count
            DeviceLookupStorePath = $deviceLookupStorePath
            DeviceLookupBytes = if (Test-Path -LiteralPath $deviceLookupStorePath -PathType Leaf) { [int64](Get-Item -LiteralPath $deviceLookupStorePath).Length } else { 0L }
        }
    }
    finally {
        if (Test-FileBackedNormalizationMachineLookup -Machines $context.Machines) {
            Remove-FileBackedNormalizationMachineLookup -Machines $context.Machines
        }
        Complete-NormalizedLookupFileStore -Store $context.Lookups.devices
        try {
            Remove-NormalizedLookupFileStore -Store $context.Lookups.devices
        }
        catch {
            Write-Verbose "Failed to dispose the direct machine-profile access lookup store during cleanup."
        }
    }
}

function Invoke-DeviceLookupDirectMergePass {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $machineCurrentReadPath = Get-ResolvedMachineCurrentReadPath -Path $Path
    if ([string]::IsNullOrWhiteSpace($machineCurrentReadPath)) {
        throw "No current machine source found under '$Path'."
    }

    $context = Get-NormalizationContext
    $deviceLookupStorePath = Join-Path ([System.IO.Path]::GetTempPath()) ('device-lookups-direct-merge-' + [System.Guid]::NewGuid().ToString('N') + '.json')
    $context.Lookups.devices = Open-NormalizedLookupFileStore -Path $deviceLookupStorePath
    $context.AdvancedHuntingDeviceUsers = @{}
    $context.Machines = @{}

    $machineReader = $null
    $currentMachineEntry = $null
    $deviceProfileCount = 0
    $onboardedCount = 0
    $matchedMachineCount = 0
    $mismatchCount = 0
    $lookupMissCount = 0
    try {
        $machineReader = Open-MachineNormalizationEntryJsonReader -Path $machineCurrentReadPath
        $dictionaryPath = Get-VulnContentDictionaryPath -BasePath $Path
        Read-VulnContentDictionaryArrayEntries -Path $dictionaryPath -PropertyName 'deviceProfiles' | ForEach-Object {
            $deviceProfile = $_
            $deviceProfileCount++
            $deviceId = [string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'id')
            if ((Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ob') -eq $true) {
                $onboardedCount++
            }

            if ($null -eq $currentMachineEntry) {
                $currentMachineEntry = Read-NextMachineNormalizationEntryFromJsonReader -Reader $machineReader
            }

            $context.Machines = @{}
            if ($null -ne $currentMachineEntry) {
                while ($null -ne $currentMachineEntry -and $currentMachineEntry.removed -eq $true) {
                    $currentMachineEntry = Read-NextMachineNormalizationEntryFromJsonReader -Reader $machineReader
                }
                $currentMachineId = if ($null -ne $currentMachineEntry) { [string]$currentMachineEntry.id } else { $null }

                if (-not [string]::IsNullOrWhiteSpace($currentMachineId) -and $currentMachineId -eq $deviceId) {
                    if ($null -ne $currentMachineEntry.tuple) {
                        $context.Machines[$deviceId] = [object[]]$currentMachineEntry.tuple
                    }
                    $matchedMachineCount++
                    $currentMachineEntry = Read-NextMachineNormalizationEntryFromJsonReader -Reader $machineReader
                }
                elseif (-not [string]::IsNullOrWhiteSpace($deviceId)) {
                    $mismatchCount++
                    $lookupMissCount++
                }
            }
            elseif (-not [string]::IsNullOrWhiteSpace($deviceId)) {
                $lookupMissCount++
            }

            [void](Add-NormalizedDevice `
                    -DeviceId $deviceId `
                    -DeviceName ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'n')) `
                    -GroupName ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'g')) `
                    -OsPlatform ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'o')) `
                    -OsVersion ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ov')) `
                    -MachineTags @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $deviceProfile -Name 't')) `
                    -Context $context)
        }

        Complete-NormalizedLookupFileStore -Store $context.Lookups.devices
        return [PSCustomObject]@{
            DeviceProfileCount = $deviceProfileCount
            OnboardedCount = $onboardedCount
            MatchedMachineCount = $matchedMachineCount
            MismatchCount = $mismatchCount
            LookupMissCount = $lookupMissCount
            DeviceLookupCount = [int]$context.Lookups.devices.Count
            DeviceLookupStorePath = $deviceLookupStorePath
            DeviceLookupBytes = if (Test-Path -LiteralPath $deviceLookupStorePath -PathType Leaf) { [int64](Get-Item -LiteralPath $deviceLookupStorePath).Length } else { 0L }
        }
    }
    finally {
        Close-MachineNormalizationEntryJsonReader -Reader $machineReader
        Complete-NormalizedLookupFileStore -Store $context.Lookups.devices
        try {
            Remove-NormalizedLookupFileStore -Store $context.Lookups.devices
        }
        catch {
            Write-Verbose "Failed to dispose the direct-merge device lookup store during cleanup."
        }
    }
}

function Invoke-DeviceLookupDirectMergeSpillPass {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateRange(4, 512)]
        [int]$BucketCount = 64,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 64)]
        [int]$BucketCacheLimit = 8
    )

    $machineCurrentReadPath = Get-ResolvedMachineCurrentReadPath -Path $Path
    if ([string]::IsNullOrWhiteSpace($machineCurrentReadPath)) {
        throw "No current machine source found under '$Path'."
    }

    $context = Get-NormalizationContext
    $deviceLookupStorePath = Join-Path ([System.IO.Path]::GetTempPath()) ('device-lookups-direct-merge-spill-' + [System.Guid]::NewGuid().ToString('N') + '.json')
    $context.Lookups.devices = Open-NormalizedLookupFileStore -Path $deviceLookupStorePath
    $context.AdvancedHuntingDeviceUsers = @{}
    $context.Machines = @{}

    $machineReader = $null
    $currentMachineEntry = $null
    $bucketDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('device-lookup-merge-spill-' + [System.Guid]::NewGuid().ToString('N'))
    $bucketWriters = [System.Collections.Generic.List[System.IO.StreamWriter]]::new()
    $bucketCache = [System.Collections.Specialized.OrderedDictionary]::new()
    $deviceProfileCount = 0
    $onboardedCount = 0
    $matchedMachineCount = 0
    $mismatchCount = 0
    $lookupMissCount = 0
    $spillCount = 0
    $spillResolveCount = 0
    $bucketLoadCount = 0
    $spillBytes = [int64]0
    $firstMismatch = $null
    try {
        [void](New-Item -Path $bucketDirectory -ItemType Directory -Force)
        for ($bucketIndex = 0; $bucketIndex -lt $BucketCount; $bucketIndex++) {
            $bucketPath = Join-Path $bucketDirectory ('bucket-{0:D3}.ndjson' -f $bucketIndex)
            $bucketWriter = [System.IO.StreamWriter]::new(
                [System.IO.File]::Open($bucketPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite),
                [System.Text.UTF8Encoding]::new($false)
            )
            $bucketWriters.Add($bucketWriter) | Out-Null
        }

        $machineReader = Open-MachineNormalizationEntryJsonReader -Path $machineCurrentReadPath
        $dictionaryPath = Get-VulnContentDictionaryPath -BasePath $Path
        Read-VulnContentDictionaryArrayEntries -Path $dictionaryPath -PropertyName 'deviceProfiles' | ForEach-Object {
            $deviceProfile = $_
            $deviceProfileCount++
            $deviceId = [string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'id')
            if ((Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ob') -eq $true) {
                $onboardedCount++
            }

            $machineTupleForDevice = $null
            $context.Machines = @{}

            if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
                if ($spillCount -gt 0) {
                    $bucketLookup = Get-LoadedSpillMachineBucket -BucketDirectory $bucketDirectory -DeviceId $deviceId -BucketCache $bucketCache -BucketCacheLimit $BucketCacheLimit -BucketCount $BucketCount -BucketLoadCount ([ref]$bucketLoadCount)
                    if ($null -ne $bucketLookup -and $bucketLookup.ContainsKey($deviceId)) {
                        $machineTupleForDevice = [object[]]@($bucketLookup[$deviceId])
                        $spillResolveCount++
                    }
                }

                while ($null -eq $machineTupleForDevice) {
                    if ($null -eq $currentMachineEntry) {
                        $currentMachineEntry = Read-NextMachineNormalizationEntryFromJsonReader -Reader $machineReader
                        if ($null -eq $currentMachineEntry) {
                            break
                        }
                    }

                    if ($currentMachineEntry.removed -eq $true) {
                        $currentMachineEntry = $null
                        continue
                    }

                    $currentMachineId = [string]$currentMachineEntry.id
                    if ($currentMachineId -eq $deviceId) {
                        if ($null -ne $currentMachineEntry.tuple) {
                            $machineTupleForDevice = [object[]]$currentMachineEntry.tuple
                        }
                        $matchedMachineCount++
                        $currentMachineEntry = $null
                        break
                    }

                    if ($null -eq $firstMismatch) {
                        $firstMismatch = [PSCustomObject]@{
                            Expected = $deviceId
                            Actual = $currentMachineId
                        }
                    }

                    if ($null -ne $currentMachineEntry.tuple) {
                        $tupleJson = ConvertTo-Json -InputObject @($currentMachineEntry.tuple) -Compress -Depth 6
                        $bucketId = Get-NormalizationMachineBucketId -DeviceId $currentMachineId -BucketCount $BucketCount
                        $bucketWriters[$bucketId].WriteLine(($currentMachineId + "`t" + $tupleJson))
                        $bucketWriters[$bucketId].Flush()
                        $bucketKey = [string]$bucketId
                        if ($bucketCache.Contains($bucketKey)) {
                            $bucketCache.Remove($bucketKey)
                        }
                        $spillBytes += [System.Text.Encoding]::UTF8.GetByteCount($currentMachineId + "`t" + $tupleJson + "`n")
                        $spillCount++
                    }
                    $mismatchCount++
                    $currentMachineEntry = $null
                }

                if ($null -eq $machineTupleForDevice -and $spillCount -gt 0) {
                    $bucketLookup = Get-LoadedSpillMachineBucket -BucketDirectory $bucketDirectory -DeviceId $deviceId -BucketCache $bucketCache -BucketCacheLimit $BucketCacheLimit -BucketCount $BucketCount -BucketLoadCount ([ref]$bucketLoadCount)
                    if ($null -ne $bucketLookup -and $bucketLookup.ContainsKey($deviceId)) {
                        $machineTupleForDevice = [object[]]@($bucketLookup[$deviceId])
                        $spillResolveCount++
                    }
                }

                if ($null -eq $machineTupleForDevice) {
                    $lookupMissCount++
                }
            }

            if ($null -ne $machineTupleForDevice) {
                $context.Machines[$deviceId] = $machineTupleForDevice
            }

            [void](Add-NormalizedDevice `
                    -DeviceId $deviceId `
                    -DeviceName ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'n')) `
                    -GroupName ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'g')) `
                    -OsPlatform ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'o')) `
                    -OsVersion ([string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ov')) `
                    -MachineTags @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $deviceProfile -Name 't')) `
                    -Context $context)
        }

        foreach ($bucketWriter in @($bucketWriters)) {
            $bucketWriter.Flush()
            $bucketWriter.Dispose()
        }
        $bucketWriters.Clear()

        Complete-NormalizedLookupFileStore -Store $context.Lookups.devices
        $bucketFileCount = [int]@(Get-ChildItem -LiteralPath $bucketDirectory -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 }).Count
        return [PSCustomObject]@{
            DeviceProfileCount = $deviceProfileCount
            OnboardedCount = $onboardedCount
            MatchedMachineCount = $matchedMachineCount
            MismatchCount = $mismatchCount
            LookupMissCount = $lookupMissCount
            SpillCount = $spillCount
            SpillResolveCount = $spillResolveCount
            SpillBytes = $spillBytes
            SpillBucketFileCount = $bucketFileCount
            SpillBucketLoadCount = $bucketLoadCount
            FirstMismatchExpected = if ($null -ne $firstMismatch) { $firstMismatch.Expected } else { $null }
            FirstMismatchActual = if ($null -ne $firstMismatch) { $firstMismatch.Actual } else { $null }
            DeviceLookupCount = [int]$context.Lookups.devices.Count
            DeviceLookupStorePath = $deviceLookupStorePath
            DeviceLookupBytes = if (Test-Path -LiteralPath $deviceLookupStorePath -PathType Leaf) { [int64](Get-Item -LiteralPath $deviceLookupStorePath).Length } else { 0L }
        }
    }
    finally {
        foreach ($bucketWriter in @($bucketWriters)) {
            try {
                $bucketWriter.Dispose()
            }
            catch {
                Write-Verbose "Failed to dispose a spill bucket writer during direct-merge spill cleanup."
            }
        }
        Close-MachineNormalizationEntryJsonReader -Reader $machineReader
        Remove-SpillMachineBucketDirectory -BucketDirectory $bucketDirectory
        Complete-NormalizedLookupFileStore -Store $context.Lookups.devices
        try {
            Remove-NormalizedLookupFileStore -Store $context.Lookups.devices
        }
        catch {
            Write-Verbose "Failed to dispose the direct-merge spill lookup store during cleanup."
        }
    }
}

function Open-SequentialMachineAccessCursor {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Write-Host ("Reading machine data from {0}..." -f $Path)
    $lookupPath = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-tuples-sequential-' + [System.Guid]::NewGuid().ToString('N') + '.ndjson')
    $writer = $null
    try {
        $writer = [System.IO.StreamWriter]::new(
            [System.IO.File]::Open($lookupPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None),
            [System.Text.UTF8Encoding]::new($false)
        )

        $recordCount = 0
        foreach ($record in (Get-MachineRecordSequence -Path $Path -AsNormalizationTuple)) {
            $recordId = [string]$record.PSObject.Properties['id']?.Value
            if ([string]::IsNullOrWhiteSpace($recordId)) {
                continue
            }

            if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                continue
            }

            $machineTuple = $record.PSObject.Properties['tuple']?.Value
            if ($null -eq $machineTuple) {
                continue
            }

            $writer.WriteLine(($recordId + "`t" + (ConvertTo-Json -InputObject @($machineTuple) -Compress -Depth 6)))
            $recordCount++
        }

        $writer.Flush()
        $writer.Dispose()
        $writer = $null

        Write-Host ("  Loaded {0} unique machines (sequential machine cursor)" -f $recordCount)
        return [PSCustomObject]@{
            LookupPath = $lookupPath
            Reader = [System.IO.StreamReader]::new(
                [System.IO.File]::Open($lookupPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read),
                [System.Text.UTF8Encoding]::new($false),
                $false
            )
            RecordCount = $recordCount
            Pending = [System.Collections.Specialized.OrderedDictionary]::new()
            PendingPeakCount = 0
            LookupMissCount = 0
        }
    }
    catch {
        if ($null -ne $writer) {
            $writer.Dispose()
        }

        if (Test-Path -LiteralPath $lookupPath -PathType Leaf) {
            Remove-Item -LiteralPath $lookupPath -Force -ErrorAction SilentlyContinue
        }

        throw
    }
}

function Read-SequentialMachineAccessCursorTuple {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Cursor,

        [Parameter(Mandatory = $true)]
        [string]$DeviceId
    )

    if ([string]::IsNullOrWhiteSpace($DeviceId)) {
        return $null
    }

    if ($Cursor.Pending.Contains($DeviceId)) {
        $tuple = [object[]]@($Cursor.Pending[$DeviceId])
        $Cursor.Pending.Remove($DeviceId)
        return $tuple
    }

    while (-not $Cursor.Reader.EndOfStream) {
        $line = $Cursor.Reader.ReadLine()
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $separatorIndex = $line.IndexOf("`t")
        if ($separatorIndex -lt 1) {
            continue
        }

        $recordId = $line.Substring(0, $separatorIndex)
        $tupleJson = $line.Substring($separatorIndex + 1)
        if ([string]::IsNullOrWhiteSpace($recordId) -or [string]::IsNullOrWhiteSpace($tupleJson)) {
            continue
        }

        $tuple = [object[]]@($tupleJson | ConvertFrom-Json -Depth 20)
        if ($recordId -eq $DeviceId) {
            return $tuple
        }

        $Cursor.Pending[$recordId] = $tuple
        if ($Cursor.Pending.Count -gt $Cursor.PendingPeakCount) {
            $Cursor.PendingPeakCount = $Cursor.Pending.Count
        }
    }

    $Cursor.LookupMissCount++
    return $null
}

function Remove-SequentialMachineAccessCursor {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Benchmark cleanup helper only disposes temp cursor artifacts created for the current run.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [pscustomobject]$Cursor
    )

    if ($null -eq $Cursor) {
        return
    }

    if ($null -ne $Cursor.Reader) {
        try {
            $Cursor.Reader.Dispose()
        }
        catch {
            Write-Verbose "Failed to dispose the sequential machine access cursor reader during cleanup."
        }
    }

    if (-not [string]::IsNullOrWhiteSpace([string]$Cursor.LookupPath) -and (Test-Path -LiteralPath ([string]$Cursor.LookupPath) -PathType Leaf)) {
        Remove-Item -LiteralPath ([string]$Cursor.LookupPath) -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-MergeSequentialMachineProfileAccess {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$DeviceProfileIds
    )

    $matchedCount = 0
    $mismatchCount = 0
    $firstMismatchExpected = $null
    $firstMismatchActual = $null
    $machineCount = 0

    foreach ($record in (Get-MachineRecordSequence -Path $Path -AsNormalizationTuple)) {
        $recordId = [string]$record.PSObject.Properties['id']?.Value
        if ([string]::IsNullOrWhiteSpace($recordId)) {
            continue
        }

        if ($record.PSObject.Properties['removed']?.Value -eq $true) {
            continue
        }

        $machineTuple = $record.PSObject.Properties['tuple']?.Value
        if ($null -eq $machineTuple) {
            continue
        }

        $machineCount++
        if ($matchedCount -ge $DeviceProfileIds.Count) {
            continue
        }

        $expectedDeviceId = [string]$DeviceProfileIds[$matchedCount]
        if ($recordId -ne $expectedDeviceId) {
            $mismatchCount++
            if ($null -eq $firstMismatchExpected) {
                $firstMismatchExpected = $expectedDeviceId
                $firstMismatchActual = $recordId
            }
            continue
        }

        $matchedCount++
    }

    return [PSCustomObject]@{
        DeviceProfileCount = $DeviceProfileIds.Count
        MachineCount = $machineCount
        MatchedCount = $matchedCount
        MismatchCount = $mismatchCount
        FirstMismatchExpected = $firstMismatchExpected
        FirstMismatchActual = $firstMismatchActual
    }
}

function Get-LoadedSpillMachineBucket {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BucketDirectory,

        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$BucketCache,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 64)]
        [int]$BucketCacheLimit = 8,

        [Parameter(Mandatory = $false)]
        [ValidateRange(4, 512)]
        [int]$BucketCount = 64,

        [Parameter(Mandatory = $true)]
        [ref]$BucketLoadCount
    )

    if ([string]::IsNullOrWhiteSpace($BucketDirectory) -or -not (Test-Path -LiteralPath $BucketDirectory -PathType Container)) {
        return $null
    }

    $bucketId = Get-NormalizationMachineBucketId -DeviceId $DeviceId -BucketCount $BucketCount
    $bucketKey = [string]$bucketId
    if ($BucketCache.Contains($bucketKey)) {
        Touch-FileBackedNormalizationMachineBucketCacheEntry -Cache $BucketCache -BucketKey $bucketKey
        return [hashtable]$BucketCache[$bucketKey]
    }

    $bucketLookup = @{}
    $bucketPath = Join-Path $BucketDirectory ('bucket-{0:D3}.ndjson' -f $bucketId)
    if (Test-Path -LiteralPath $bucketPath -PathType Leaf) {
        foreach ($line in [System.IO.File]::ReadLines($bucketPath)) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $separatorIndex = $line.IndexOf("`t")
            if ($separatorIndex -lt 1) {
                continue
            }

            $recordId = $line.Substring(0, $separatorIndex)
            $tupleJson = $line.Substring($separatorIndex + 1)
            if ([string]::IsNullOrWhiteSpace($recordId) -or [string]::IsNullOrWhiteSpace($tupleJson)) {
                continue
            }

            $bucketLookup[$recordId] = [object[]]@($tupleJson | ConvertFrom-Json -Depth 20)
        }
    }

    $BucketLoadCount.Value = [int]$BucketLoadCount.Value + 1
    $BucketCache.Add($bucketKey, $bucketLookup)
    while ($BucketCache.Count -gt $BucketCacheLimit) {
        $evictKey = [string]$BucketCache.Keys[0]
        $BucketCache.Remove($evictKey)
    }

    return $bucketLookup
}

function Remove-SpillMachineBucketDirectory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Benchmark cleanup helper only removes temp spill directories created for the current run.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$BucketDirectory
    )

    if (-not [string]::IsNullOrWhiteSpace($BucketDirectory) -and (Test-Path -LiteralPath $BucketDirectory -PathType Container)) {
        Remove-Item -LiteralPath $BucketDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-MergeSpillMachineProfileAccess {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$DeviceProfileIds,

        [Parameter(Mandatory = $false)]
        [ValidateRange(4, 512)]
        [int]$BucketCount = 64,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 64)]
        [int]$BucketCacheLimit = 8,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Snapshots,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Diagnostics.Stopwatch]$Stopwatch,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 1000000)]
        [int]$ForceGcInterval = 0,

        [Parameter(Mandatory = $false)]
        [string]$SnapshotLabelPrefix = 'MachineMergeSpillGc'
    )

    $bucketDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-merge-spill-' + [System.Guid]::NewGuid().ToString('N'))
    $bucketWriters = [System.Collections.Generic.List[System.IO.StreamWriter]]::new()
    $bucketCache = [System.Collections.Specialized.OrderedDictionary]::new()
    $matchedCount = 0
    $spillCount = 0
    $spillResolveCount = 0
    $lookupMissCount = 0
    $machineCount = 0
    $bucketLoadCount = 0
    $firstMismatchExpected = $null
    $firstMismatchActual = $null
    $spillBytes = [int64]0

    try {
        [void](New-Item -Path $bucketDirectory -ItemType Directory -Force)
        for ($bucketIndex = 0; $bucketIndex -lt $BucketCount; $bucketIndex++) {
            $bucketPath = Join-Path $bucketDirectory ('bucket-{0:D3}.ndjson' -f $bucketIndex)
            $bucketWriter = [System.IO.StreamWriter]::new(
                [System.IO.File]::Open($bucketPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read),
                [System.Text.UTF8Encoding]::new($false)
            )
            $bucketWriters.Add($bucketWriter) | Out-Null
        }

        foreach ($record in (Get-MachineRecordSequence -Path $Path -AsNormalizationTuple)) {
            $recordId = [string]$record.PSObject.Properties['id']?.Value
            if ([string]::IsNullOrWhiteSpace($recordId)) {
                continue
            }

            if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                continue
            }

            $machineTuple = $record.PSObject.Properties['tuple']?.Value
            if ($null -eq $machineTuple) {
                continue
            }

            $machineCount++
            if ($matchedCount -lt $DeviceProfileIds.Count) {
                $expectedDeviceId = [string]$DeviceProfileIds[$matchedCount]
                if ($recordId -eq $expectedDeviceId) {
                    $matchedCount++
                    if ($ForceGcInterval -gt 0 -and ($machineCount % $ForceGcInterval) -eq 0) {
                        Invoke-FullGarbageCollection
                        if ($null -ne $Snapshots -and $null -ne $Stopwatch) {
                            [void](Add-ExperimentSnapshot -Snapshots $Snapshots -Label ($SnapshotLabelPrefix + '-' + $machineCount) -Stopwatch $Stopwatch)
                        }
                    }
                    if ($matchedCount -ge $DeviceProfileIds.Count) {
                        break
                    }
                    continue
                }

                if ($null -eq $firstMismatchExpected) {
                    $firstMismatchExpected = $expectedDeviceId
                    $firstMismatchActual = $recordId
                }
            }

            $tupleJson = ConvertTo-Json -InputObject @($machineTuple) -Compress -Depth 6
            $bucketId = Get-NormalizationMachineBucketId -DeviceId $recordId -BucketCount $BucketCount
            $bucketWriters[$bucketId].WriteLine(($recordId + "`t" + $tupleJson))
            $spillCount++
            $spillBytes += [System.Text.Encoding]::UTF8.GetByteCount($recordId + "`t" + $tupleJson + "`n")
            if ($ForceGcInterval -gt 0 -and ($machineCount % $ForceGcInterval) -eq 0) {
                Invoke-FullGarbageCollection
                if ($null -ne $Snapshots -and $null -ne $Stopwatch) {
                    [void](Add-ExperimentSnapshot -Snapshots $Snapshots -Label ($SnapshotLabelPrefix + '-' + $machineCount) -Stopwatch $Stopwatch)
                }
            }
        }

        foreach ($bucketWriter in @($bucketWriters)) {
            $bucketWriter.Flush()
            $bucketWriter.Dispose()
        }
        $bucketWriters.Clear()

        for ($deviceProfileIndex = $matchedCount; $deviceProfileIndex -lt $DeviceProfileIds.Count; $deviceProfileIndex++) {
            $deviceId = [string]$DeviceProfileIds[$deviceProfileIndex]
            if ([string]::IsNullOrWhiteSpace($deviceId)) {
                $lookupMissCount++
                continue
            }

            $bucketLookup = Get-LoadedSpillMachineBucket -BucketDirectory $bucketDirectory -DeviceId $deviceId -BucketCache $bucketCache -BucketCacheLimit $BucketCacheLimit -BucketCount $BucketCount -BucketLoadCount ([ref]$bucketLoadCount)
            if ($null -eq $bucketLookup -or -not $bucketLookup.ContainsKey($deviceId)) {
                $lookupMissCount++
                continue
            }

            $spillResolveCount++
        }

        $bucketFileCount = [int]@(Get-ChildItem -LiteralPath $bucketDirectory -File -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 }).Count
        return [PSCustomObject]@{
            DeviceProfileCount = $DeviceProfileIds.Count
            MachineCount = $machineCount
            MatchedCount = $matchedCount
            SpillCount = $spillCount
            SpillResolveCount = $spillResolveCount
            LookupMissCount = $lookupMissCount
            BucketDirectory = $bucketDirectory
            BucketFileCount = $bucketFileCount
            SpillBytes = $spillBytes
            BucketLoadCount = $bucketLoadCount
            FirstMismatchExpected = $firstMismatchExpected
            FirstMismatchActual = $firstMismatchActual
        }
    }
    catch {
        foreach ($bucketWriter in @($bucketWriters)) {
            try {
                $bucketWriter.Dispose()
            }
            catch {
                Write-Verbose "Failed to dispose a merge-spill bucket writer during cleanup."
            }
        }

        Remove-SpillMachineBucketDirectory -BucketDirectory $bucketDirectory
        throw
    }
}

function Resolve-AdvancedHuntingSourceFileList {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $currentPath = Get-AdvancedHuntingCurrentPath -BasePath $Path
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath

    if ((-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) -and (Test-Path -LiteralPath $legacyCurrentPath -PathType Leaf)) {
        $currentPath = $legacyCurrentPath
    }

    if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
        return @((Get-Item -LiteralPath $currentPath))
    }

    return @(Get-ChildItem -Path $Path -Filter 'AdvancedHunting_*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { Test-IsLegacyAdvancedHuntingSnapshotFileName -Name $_.Name } |
        Sort-Object Name -Descending)
}

function Read-AdvancedHuntingBundle {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDeviceUsers
    )

    $includeDeviceUsersRequested = [bool]$IncludeDeviceUsers

    function ConvertTo-AdvancedHuntingStringArray {
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Value
        )

        if ($null -eq $Value) {
            return @()
        }

        $values = [System.Collections.Generic.List[string]]::new()
        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            foreach ($item in $Value) {
                if ($null -eq $item) { continue }
                $text = [string]$item
                if (-not [string]::IsNullOrWhiteSpace($text)) {
                    $values.Add($text)
                }
            }
        }
        else {
            $text = [string]$Value
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $values.Add($text)
            }
        }

        return [string[]]$values.ToArray()
    }

    function ConvertTo-AdvancedHuntingDescriptionValue {
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

        if ($Value -is [string]) {
            return $Value
        }

        $parts = @(ConvertTo-AdvancedHuntingStringArray -Value $Value)
        if ($parts.Count -eq 0) {
            return $null
        }

        return ($parts -join "`n")
    }

    function ConvertTo-AdvancedHuntingNullableBoolean {
        [CmdletBinding()]
        [OutputType([Nullable[bool]])]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Value
        )

        if ($null -eq $Value) {
            return $null
        }

        if ($Value -is [bool]) {
            return $Value
        }

        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) {
            return $null
        }

        switch -Regex ($text.Trim().ToLowerInvariant()) {
            '^(true|1|yes)$' { return $true }
            '^(false|0|no)$' { return $false }
        }

        return $null
    }

    function Add-AdvancedHuntingLoggedOnUserValue {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Value,

            [Parameter(Mandatory = $true)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.List[string]]$Values,

            [Parameter(Mandatory = $true)]
            [AllowEmptyCollection()]
            [System.Collections.Generic.HashSet[string]]$Seen
        )

        if ($null -eq $Value) {
            return
        }

        if ($Value -is [string]) {
            $text = $Value.Trim()
            if ([string]::IsNullOrWhiteSpace($text)) {
                return
            }

            if ((($text.StartsWith('[') -and $text.EndsWith(']')) -or ($text.StartsWith('{') -and $text.EndsWith('}')))) {
                try {
                    $parsedValue = $text | ConvertFrom-Json -Depth 20
                    Add-AdvancedHuntingLoggedOnUserValue -Value $parsedValue -Values $Values -Seen $Seen
                    return
                }
                catch {
                    Write-Verbose ("Falling back to raw LoggedOnUsers text after JSON parse failed: {0}" -f $_.Exception.Message)
                }
            }

            if ($Seen.Add($text)) {
                $Values.Add($text)
            }
            return
        }

        if ($Value -is [pscustomobject] -or $Value -is [System.Collections.IDictionary]) {
            $propertyBag = $Value.PSObject.Properties
            $upn = [string]$propertyBag['UserPrincipalName']?.Value
            $domainName = [string]$propertyBag['DomainName']?.Value
            $accountName = [string]$propertyBag['AccountName']?.Value
            $userName = [string]$propertyBag['UserName']?.Value
            $displayName = [string]$propertyBag['Name']?.Value

            $resolvedName = $null
            if (-not [string]::IsNullOrWhiteSpace($upn)) {
                $resolvedName = $upn.Trim()
            }
            elseif (-not [string]::IsNullOrWhiteSpace($accountName)) {
                $resolvedName = if (-not [string]::IsNullOrWhiteSpace($domainName)) {
                    $domainName.Trim() + '\' + $accountName.Trim()
                }
                else {
                    $accountName.Trim()
                }
            }
            elseif (-not [string]::IsNullOrWhiteSpace($userName)) {
                $resolvedName = if (-not [string]::IsNullOrWhiteSpace($domainName)) {
                    $domainName.Trim() + '\' + $userName.Trim()
                }
                else {
                    $userName.Trim()
                }
            }
            elseif (-not [string]::IsNullOrWhiteSpace($displayName)) {
                $resolvedName = $displayName.Trim()
            }

            if (-not [string]::IsNullOrWhiteSpace($resolvedName)) {
                if ($Seen.Add($resolvedName)) {
                    $Values.Add($resolvedName)
                }
                return
            }

            foreach ($property in $propertyBag) {
                Add-AdvancedHuntingLoggedOnUserValue -Value $property.Value -Values $Values -Seen $Seen
            }
            return
        }

        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            foreach ($item in $Value) {
                Add-AdvancedHuntingLoggedOnUserValue -Value $item -Values $Values -Seen $Seen
            }
            return
        }

        $fallbackText = [string]$Value
        if (-not [string]::IsNullOrWhiteSpace($fallbackText) -and $Seen.Add($fallbackText)) {
            $Values.Add($fallbackText)
        }
    }

    function ConvertTo-AdvancedHuntingLoggedOnUserList {
        [CmdletBinding()]
        [OutputType([string[]])]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Value
        )

        $values = [System.Collections.Generic.List[string]]::new()
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Add-AdvancedHuntingLoggedOnUserValue -Value $Value -Values $values -Seen $seen
        return [string[]]$values.ToArray()
    }

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'advancedhunting' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'advancedhunting'

        $ahData = @{}
        $deviceUsers = @{}
        $parseErrors = 0
        $sourceFiles = @(Resolve-AdvancedHuntingSourceFileList -Path $Path)

        if ($sourceFiles.Count -eq 0) {
            return [PSCustomObject]@{
                AdvancedHuntingData = @{}
                DeviceUsers = @{}
            }
        }

        foreach ($file in $sourceFiles) {
            foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
                try {
                    $recordType = Get-AdvancedHuntingRecordType -Record $record
                    if ($recordType -eq 'DeviceUsers' -and $includeDeviceUsersRequested) {
                        $deviceId = [string]$record.PSObject.Properties['DeviceId']?.Value
                        if (-not [string]::IsNullOrWhiteSpace($deviceId) -and -not $deviceUsers.ContainsKey($deviceId)) {
                            $loggedOnUsers = @(ConvertTo-AdvancedHuntingLoggedOnUserList -Value $record.PSObject.Properties['LoggedOnUsers']?.Value)
                            if ($loggedOnUsers.Count -gt 0) {
                                $deviceUsers[$deviceId] = @($loggedOnUsers)
                            }
                        }

                        continue
                    }

                    $cveId = [string]$record.PSObject.Properties['CveId']?.Value
                    if (-not [string]::IsNullOrWhiteSpace($cveId) -and -not $ahData.ContainsKey($cveId)) {
                        $pdRaw = $record.PSObject.Properties['PublishedDate']?.Value
                        $rawDescription = $record.PSObject.Properties['VulnerabilityDescription']?.Value
                        $rawAffectedSoftware = $record.PSObject.Properties['AffectedSoftware']?.Value
                        $affectedSoftware = @(ConvertTo-AdvancedHuntingStringArray -Value $rawAffectedSoftware)
                        $ahData[$cveId] = @{
                            PublishedDate = Convert-ToYmdDate -DateValue $pdRaw
                            VulnerabilityDescription = ConvertTo-AdvancedHuntingDescriptionValue -Value $rawDescription
                            EpssScore = $record.PSObject.Properties['EpssScore']?.Value
                            AffectedSoftware = if ($affectedSoftware.Count -gt 0) { @($affectedSoftware) } else { $null }
                            IsExploitAvailable = ConvertTo-AdvancedHuntingNullableBoolean -Value $record.PSObject.Properties['IsExploitAvailable']?.Value
                        }
                    }
                }
                catch {
                    $parseErrors++
                    if ($parseErrors -le 5) {
                        Write-Warning "Failed to process Advanced Hunting bundle record in $($file.Name): $_"
                    }
                }
            }
        }

        if ($parseErrors -gt 0) {
            Write-Warning "Total bundle parse errors: $parseErrors"
        }

        return [PSCustomObject]@{
            AdvancedHuntingData = $ahData
            DeviceUsers = $deviceUsers
        }
    }
}

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$snapshots = [System.Collections.Generic.List[object]]::new()
$machines = $null
$machineCursor = $null
$mergeMachineCount = 0
$machineCount = 0
$advancedHuntingData = @{}
$advancedHuntingDeviceUsers = @{}
$experimentDetails = [ordered]@{}

Write-Output ("Running input-load experiment '{0}' against {1}" -f $Experiment, $DatasetPath)
Add-ExperimentSnapshot -Snapshots $snapshots -Label 'Start' -Stopwatch $stopwatch

switch ($Experiment) {
    'baseline' {
        $machines = Read-MachineData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineLoad' -Stopwatch $stopwatch

        $advancedHuntingData = Read-AdvancedHuntingData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostAdvancedHuntingData' -Stopwatch $stopwatch

        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceUsers' -Stopwatch $stopwatch
    }

    'precompact-machines' {
        $machines = Read-MachineData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineLoad' -Stopwatch $stopwatch

        Compress-NormalizationMachineLookup -Machines $machines | Out-Null
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineCompaction' -Stopwatch $stopwatch

        $advancedHuntingData = Read-AdvancedHuntingData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostAdvancedHuntingData' -Stopwatch $stopwatch

        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceUsers' -Stopwatch $stopwatch
    }

    'gc-after-load' {
        $machines = Read-MachineData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineLoad' -Stopwatch $stopwatch

        $advancedHuntingData = Read-AdvancedHuntingData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostAdvancedHuntingData' -Stopwatch $stopwatch

        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceUsers' -Stopwatch $stopwatch

        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'precompact-plus-gc' {
        $machines = Read-MachineData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineLoad' -Stopwatch $stopwatch

        Compress-NormalizationMachineLookup -Machines $machines | Out-Null
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineCompaction' -Stopwatch $stopwatch

        $advancedHuntingData = Read-AdvancedHuntingData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostAdvancedHuntingData' -Stopwatch $stopwatch

        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceUsers' -Stopwatch $stopwatch

        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'bundle-only' {
        $machines = Read-MachineData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineLoad' -Stopwatch $stopwatch

        $bundle = Read-AdvancedHuntingBundle -Path $DatasetPath -IncludeDeviceUsers
        $advancedHuntingData = [hashtable]$bundle.AdvancedHuntingData
        $advancedHuntingDeviceUsers = [hashtable]$bundle.DeviceUsers
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostAdvancedHuntingBundle' -Stopwatch $stopwatch
    }

    'bundle-precompact' {
        $machines = Read-MachineData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineLoad' -Stopwatch $stopwatch

        Compress-NormalizationMachineLookup -Machines $machines | Out-Null
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineCompaction' -Stopwatch $stopwatch

        $bundle = Read-AdvancedHuntingBundle -Path $DatasetPath -IncludeDeviceUsers
        $advancedHuntingData = [hashtable]$bundle.AdvancedHuntingData
        $advancedHuntingDeviceUsers = [hashtable]$bundle.DeviceUsers
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostAdvancedHuntingBundle' -Stopwatch $stopwatch
    }

    'bundle-precompact-plus-gc' {
        $machines = Read-MachineData -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineLoad' -Stopwatch $stopwatch

        Compress-NormalizationMachineLookup -Machines $machines | Out-Null
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineCompaction' -Stopwatch $stopwatch

        $bundle = Read-AdvancedHuntingBundle -Path $DatasetPath -IncludeDeviceUsers
        $advancedHuntingData = [hashtable]$bundle.AdvancedHuntingData
        $advancedHuntingDeviceUsers = [hashtable]$bundle.DeviceUsers
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostAdvancedHuntingBundle' -Stopwatch $stopwatch

        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'machine-full' {
        $machines = Read-NormalizationMachineLookup -Path $DatasetPath
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineLookupLoad' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'machine-id-index' {
        $machines = @{}
        foreach ($record in (Get-MachineRecordSequence -Path $DatasetPath -AsNormalizationTuple)) {
            $recordId = [string]$record.PSObject.Properties['id']?.Value
            if ([string]::IsNullOrWhiteSpace($recordId)) {
                continue
            }

            if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                $machines.Remove($recordId)
                continue
            }

            $machines[$recordId] = $true
        }

        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineIdIndexLoad' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'machine-file-backed' {
        $machines = Read-NormalizationMachineLookup -Path $DatasetPath -FileBacked
        $lookupPath = [string]$machines.PSObject.Properties['FileBackedPath']?.Value
        if (-not [string]::IsNullOrWhiteSpace($lookupPath) -and (Test-Path -LiteralPath $lookupPath -PathType Leaf)) {
            $experimentDetails.file_backed_lookup_path = $lookupPath
            $experimentDetails.file_backed_lookup_bytes = [int64](Get-Item -LiteralPath $lookupPath).Length
        }

        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineFileBackedLoad' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'machine-file-backed-bucketed' {
        $machines = Read-NormalizationMachineLookup -Path $DatasetPath -FileBacked -Bucketed
        $bucketDirectory = [string]$machines.PSObject.Properties['FileBackedBucketDirectory']?.Value
        if (-not [string]::IsNullOrWhiteSpace($bucketDirectory) -and (Test-Path -LiteralPath $bucketDirectory -PathType Container)) {
            $experimentDetails.file_backed_bucket_directory = $bucketDirectory
            $experimentDetails.file_backed_bucket_file_count = [int]@(Get-ChildItem -LiteralPath $bucketDirectory -File -ErrorAction SilentlyContinue).Count
            $experimentDetails.file_backed_bucket_bytes = [int64]((Get-ChildItem -LiteralPath $bucketDirectory -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum)
        }

        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineFileBackedBucketedLoad' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'machine-file-backed-profile-access' {
        $machines = Read-NormalizationMachineLookup -Path $DatasetPath -FileBacked
        $lookupPath = [string]$machines.PSObject.Properties['FileBackedPath']?.Value
        if (-not [string]::IsNullOrWhiteSpace($lookupPath) -and (Test-Path -LiteralPath $lookupPath -PathType Leaf)) {
            $experimentDetails.file_backed_lookup_path = $lookupPath
            $experimentDetails.file_backed_lookup_bytes = [int64](Get-Item -LiteralPath $lookupPath).Length
        }

        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineFileBackedLoad' -Stopwatch $stopwatch
        $deviceProfileIds = @(Read-ContentStoreDeviceProfileIdList -Path $DatasetPath)
        $lookupMissCount = 0
        foreach ($deviceId in $deviceProfileIds) {
            if ($null -eq (Read-FileBackedNormalizationMachineTuple -Machines $machines -DeviceId $deviceId)) {
                $lookupMissCount++
            }
        }

        $experimentDetails.device_profile_count = $deviceProfileIds.Count
        $experimentDetails.lookup_miss_count = $lookupMissCount
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceProfileLookupPass' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'machine-sequential-profile-access' {
        $machineCursor = Open-SequentialMachineAccessCursor -Path $DatasetPath
        $experimentDetails.sequential_lookup_path = [string]$machineCursor.LookupPath
        if (-not [string]::IsNullOrWhiteSpace([string]$machineCursor.LookupPath) -and (Test-Path -LiteralPath ([string]$machineCursor.LookupPath) -PathType Leaf)) {
            $experimentDetails.sequential_lookup_bytes = [int64](Get-Item -LiteralPath ([string]$machineCursor.LookupPath)).Length
        }

        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineSequentialLoad' -Stopwatch $stopwatch
        $deviceProfileIds = @(Read-ContentStoreDeviceProfileIdList -Path $DatasetPath)
        foreach ($deviceId in $deviceProfileIds) {
            [void](Read-SequentialMachineAccessCursorTuple -Cursor $machineCursor -DeviceId $deviceId)
        }

        $experimentDetails.device_profile_count = $deviceProfileIds.Count
        $experimentDetails.lookup_miss_count = [int]$machineCursor.LookupMissCount
        $experimentDetails.pending_peak_count = [int]$machineCursor.PendingPeakCount
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostSequentialProfileAccessPass' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'machine-merge-profile-access' {
        $deviceProfileIds = @(Read-ContentStoreDeviceProfileIdList -Path $DatasetPath)
        $experimentDetails.device_profile_count = $deviceProfileIds.Count
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceProfileRead' -Stopwatch $stopwatch

        $mergeResult = Invoke-MergeSequentialMachineProfileAccess -Path $DatasetPath -DeviceProfileIds $deviceProfileIds
        $mergeMachineCount = [int]$mergeResult.MachineCount
        $experimentDetails.machine_count = [int]$mergeResult.MachineCount
        $experimentDetails.matched_count = [int]$mergeResult.MatchedCount
        $experimentDetails.mismatch_count = [int]$mergeResult.MismatchCount
        $experimentDetails.first_mismatch_expected = $mergeResult.FirstMismatchExpected
        $experimentDetails.first_mismatch_actual = $mergeResult.FirstMismatchActual
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineMergeAccessPass' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'machine-merge-spill-profile-access' {
        $deviceProfileIds = @(Read-ContentStoreDeviceProfileIdList -Path $DatasetPath)
        $experimentDetails.device_profile_count = $deviceProfileIds.Count
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceProfileRead' -Stopwatch $stopwatch

        $mergeSpillResult = Invoke-MergeSpillMachineProfileAccess -Path $DatasetPath -DeviceProfileIds $deviceProfileIds
        $mergeMachineCount = [int]$mergeSpillResult.MachineCount
        $experimentDetails.machine_count = [int]$mergeSpillResult.MachineCount
        $experimentDetails.matched_count = [int]$mergeSpillResult.MatchedCount
        $experimentDetails.spill_count = [int]$mergeSpillResult.SpillCount
        $experimentDetails.spill_resolve_count = [int]$mergeSpillResult.SpillResolveCount
        $experimentDetails.lookup_miss_count = [int]$mergeSpillResult.LookupMissCount
        $experimentDetails.spill_bucket_file_count = [int]$mergeSpillResult.BucketFileCount
        $experimentDetails.spill_bucket_load_count = [int]$mergeSpillResult.BucketLoadCount
        $experimentDetails.spill_bytes = [int64]$mergeSpillResult.SpillBytes
        $experimentDetails.first_mismatch_expected = $mergeSpillResult.FirstMismatchExpected
        $experimentDetails.first_mismatch_actual = $mergeSpillResult.FirstMismatchActual
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineMergeSpillAccessPass' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch

        Remove-SpillMachineBucketDirectory -BucketDirectory ([string]$mergeSpillResult.BucketDirectory)
    }

    'machine-merge-spill-profile-access-gc' {
        $deviceProfileIds = @(Read-ContentStoreDeviceProfileIdList -Path $DatasetPath)
        $experimentDetails.device_profile_count = $deviceProfileIds.Count
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceProfileRead' -Stopwatch $stopwatch

        $mergeSpillResult = Invoke-MergeSpillMachineProfileAccess -Path $DatasetPath -DeviceProfileIds $deviceProfileIds -Snapshots $snapshots -Stopwatch $stopwatch -ForceGcInterval 10000 -SnapshotLabelPrefix 'MachineMergeSpillPeriodicGc'
        $mergeMachineCount = [int]$mergeSpillResult.MachineCount
        $experimentDetails.machine_count = [int]$mergeSpillResult.MachineCount
        $experimentDetails.matched_count = [int]$mergeSpillResult.MatchedCount
        $experimentDetails.spill_count = [int]$mergeSpillResult.SpillCount
        $experimentDetails.spill_resolve_count = [int]$mergeSpillResult.SpillResolveCount
        $experimentDetails.lookup_miss_count = [int]$mergeSpillResult.LookupMissCount
        $experimentDetails.spill_bucket_file_count = [int]$mergeSpillResult.BucketFileCount
        $experimentDetails.spill_bucket_load_count = [int]$mergeSpillResult.BucketLoadCount
        $experimentDetails.spill_bytes = [int64]$mergeSpillResult.SpillBytes
        $experimentDetails.first_mismatch_expected = $mergeSpillResult.FirstMismatchExpected
        $experimentDetails.first_mismatch_actual = $mergeSpillResult.FirstMismatchActual
        $experimentDetails.force_gc_interval = 10000
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostMachineMergeSpillAccessPass' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch

        Remove-SpillMachineBucketDirectory -BucketDirectory ([string]$mergeSpillResult.BucketDirectory)
    }

    'device-lookup-file-backed' {
        $deviceLookupResult = Invoke-DeviceLookupFileBackedPass -Path $DatasetPath
        $experimentDetails.device_profile_count = [int]$deviceLookupResult.DeviceProfileCount
        $experimentDetails.onboarded_device_profile_count = [int]$deviceLookupResult.OnboardedCount
        $experimentDetails.device_lookup_count = [int]$deviceLookupResult.DeviceLookupCount
        $experimentDetails.device_lookup_bytes = [int64]$deviceLookupResult.DeviceLookupBytes
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceLookupFileBackedPass' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'device-lookup-direct-merge' {
        $deviceLookupResult = Invoke-DeviceLookupDirectMergePass -Path $DatasetPath
        $experimentDetails.device_profile_count = [int]$deviceLookupResult.DeviceProfileCount
        $experimentDetails.onboarded_device_profile_count = [int]$deviceLookupResult.OnboardedCount
        $experimentDetails.device_lookup_count = [int]$deviceLookupResult.DeviceLookupCount
        $experimentDetails.device_lookup_bytes = [int64]$deviceLookupResult.DeviceLookupBytes
        $experimentDetails.matched_machine_count = [int]$deviceLookupResult.MatchedMachineCount
        $experimentDetails.mismatch_count = [int]$deviceLookupResult.MismatchCount
        $experimentDetails.lookup_miss_count = [int]$deviceLookupResult.LookupMissCount
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceLookupDirectMergePass' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }

    'device-lookup-direct-merge-spill' {
        $deviceLookupResult = Invoke-DeviceLookupDirectMergeSpillPass -Path $DatasetPath
        $experimentDetails.device_profile_count = [int]$deviceLookupResult.DeviceProfileCount
        $experimentDetails.onboarded_device_profile_count = [int]$deviceLookupResult.OnboardedCount
        $experimentDetails.device_lookup_count = [int]$deviceLookupResult.DeviceLookupCount
        $experimentDetails.device_lookup_bytes = [int64]$deviceLookupResult.DeviceLookupBytes
        $experimentDetails.matched_machine_count = [int]$deviceLookupResult.MatchedMachineCount
        $experimentDetails.mismatch_count = [int]$deviceLookupResult.MismatchCount
        $experimentDetails.lookup_miss_count = [int]$deviceLookupResult.LookupMissCount
        $experimentDetails.spill_count = [int]$deviceLookupResult.SpillCount
        $experimentDetails.spill_resolve_count = [int]$deviceLookupResult.SpillResolveCount
        $experimentDetails.spill_bytes = [int64]$deviceLookupResult.SpillBytes
        $experimentDetails.spill_bucket_file_count = [int]$deviceLookupResult.SpillBucketFileCount
        $experimentDetails.spill_bucket_load_count = [int]$deviceLookupResult.SpillBucketLoadCount
        $experimentDetails.first_mismatch_expected = $deviceLookupResult.FirstMismatchExpected
        $experimentDetails.first_mismatch_actual = $deviceLookupResult.FirstMismatchActual
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostDeviceLookupDirectMergeSpillPass' -Stopwatch $stopwatch
        Invoke-FullGarbageCollection
        Add-ExperimentSnapshot -Snapshots $snapshots -Label 'PostForcedGc' -Stopwatch $stopwatch
    }
}

$stopwatch.Stop()
$machineCount = if ($null -ne $machineCursor) {
    [int]$machineCursor.RecordCount
}
elseif ($mergeMachineCount -gt 0) {
    $mergeMachineCount
}
else {
    Get-NormalizationMachineLookupCount -Machines $machines
}

$peakWorkingSetMb = 0.0
$peakGcHeapMb = 0.0
foreach ($snapshot in $snapshots) {
    if ([double]$snapshot.working_set_mb -gt $peakWorkingSetMb) {
        $peakWorkingSetMb = [double]$snapshot.working_set_mb
    }

    if ([double]$snapshot.gc_heap_mb -gt $peakGcHeapMb) {
        $peakGcHeapMb = [double]$snapshot.gc_heap_mb
    }
}

$result = [ordered]@{
    experiment = $Experiment
    dataset_path = [System.IO.Path]::GetFullPath($DatasetPath)
    generated_utc = (Get-Date).ToUniversalTime().ToString('o')
    elapsed_seconds = [math]::Round($stopwatch.Elapsed.TotalSeconds, 2)
    peak_working_set_mb = $peakWorkingSetMb
    peak_gc_heap_mb = $peakGcHeapMb
    counts = [ordered]@{
        machines = $machineCount
        advanced_hunting_cves = if ($null -ne $advancedHuntingData) { $advancedHuntingData.Count } else { 0 }
        device_users = if ($null -ne $advancedHuntingDeviceUsers) { $advancedHuntingDeviceUsers.Count } else { 0 }
    }
    details = $experimentDetails
    snapshots = @($snapshots)
}

$result.tradeoff = Get-ExperimentTradeoffSummary -Result $result
$result.comparison = $null
if (-not [string]::IsNullOrWhiteSpace($CompareToPath)) {
    $baselineResult = Get-Content -LiteralPath $CompareToPath -Raw | ConvertFrom-Json -Depth 20
    $result.comparison = Get-ExperimentComparisonSummary -CurrentResult $result -BaselineResult $baselineResult -BaselinePath $CompareToPath
}

if (Test-FileBackedNormalizationMachineLookup -Machines $machines) {
    Remove-FileBackedNormalizationMachineLookup -Machines $machines
}
if ($null -ne $machineCursor) {
    Remove-SequentialMachineAccessCursor -Cursor $machineCursor
}

$result | Add-Member -NotePropertyName benchmark_evidence -NotePropertyValue (Get-BenchmarkEvidenceEnvelope `
        -Kind 'runbook-input-load-experiment' `
        -RepoPath $repoRoot `
        -Dataset (Get-BenchmarkDatasetEvidence -DatasetPath $DatasetPath) `
        -Environment ([PSCustomObject]@{ host = 'local'; platform = [System.Environment]::OSVersion.ToString() }) `
        -Execution ([PSCustomObject]@{ experiment = $Experiment; tradeoff = $result.tradeoff; counts = $result.counts; snapshots = @($snapshots) }) `
        -Validation ([PSCustomObject]@{ comparison = $result.comparison }))
Write-BenchmarkEvidenceEnvelope -Path $OutputPath -Evidence $result

Write-Output ''
Write-Output ("Peak working set: {0}MB" -f $peakWorkingSetMb)
Write-Output ("Peak GC heap: {0}MB" -f $peakGcHeapMb)
if ($null -ne $result.tradeoff.work_units_per_second) {
    Write-Output ("Throughput: {0} {1}/s" -f $result.tradeoff.work_units_per_second, $result.tradeoff.work_unit_label)
}
if ($null -ne $result.tradeoff.disk_footprint_mb) {
    Write-Output ("Disk footprint: {0}MB" -f $result.tradeoff.disk_footprint_mb)
}
Write-Output ("Memory-time exposure: peak-ws={0} MB*s peak-gc={1} MB*s snapshot-ws={2} MB*s snapshot-gc={3} MB*s" -f @(
        $result.tradeoff.peak_working_set_mb_seconds,
        $result.tradeoff.peak_gc_heap_mb_seconds,
        $result.tradeoff.snapshot_working_set_area_mb_seconds,
        $result.tradeoff.snapshot_gc_heap_area_mb_seconds
    ))
if ($null -ne $result.comparison) {
    Write-Output ("Comparison vs baseline: assessment={0} ws-delta={1}MB gc-delta={2}MB elapsed-delta={3}s" -f @(
            $result.comparison.assessment,
            $result.comparison.peak_working_set_delta_mb,
            $result.comparison.peak_gc_heap_delta_mb,
            $result.comparison.elapsed_delta_seconds
        ))
    if ($null -ne $result.comparison.working_set_mb_saved_per_added_second) {
        Write-Output ("Working-set savings per added second: {0} MB/s" -f $result.comparison.working_set_mb_saved_per_added_second)
    }
    if ($null -ne $result.comparison.gc_heap_mb_saved_per_added_second) {
        Write-Output ("GC-heap savings per added second: {0} MB/s" -f $result.comparison.gc_heap_mb_saved_per_added_second)
    }
}
Write-Output ("Machines: {0}; AH CVEs: {1}; device users: {2}" -f $result.counts.machines, $result.counts.advanced_hunting_cves, $result.counts.device_users)
Write-Output ("Results written to {0}" -f [System.IO.Path]::GetFullPath($OutputPath))
