#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DatasetPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-datasets\synthetic-50k-1_5m'),

    [Parameter(Mandatory = $true)]
    [ValidateSet('baseline', 'precompact-machines', 'gc-after-load', 'precompact-plus-gc', 'bundle-only', 'bundle-precompact', 'bundle-precompact-plus-gc', 'machine-full', 'machine-id-index', 'machine-file-backed')]
    [string]$Experiment,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'build\Import-SharedHelpers.ps1')

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
}

$stopwatch.Stop()
$machineCount = if ($null -ne $machines) { $machines.Count } else { 0 }

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

if (Test-FileBackedNormalizationMachineLookup -Machines $machines) {
    Remove-FileBackedNormalizationMachineLookup -Machines $machines
}

[System.IO.File]::WriteAllText(
    [System.IO.Path]::GetFullPath($OutputPath),
    ($result | ConvertTo-Json -Depth 20),
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output ''
Write-Output ("Peak working set: {0}MB" -f $peakWorkingSetMb)
Write-Output ("Peak GC heap: {0}MB" -f $peakGcHeapMb)
Write-Output ("Machines: {0}; AH CVEs: {1}; device users: {2}" -f $result.counts.machines, $result.counts.advanced_hunting_cves, $result.counts.device_users)
Write-Output ("Results written to {0}" -f [System.IO.Path]::GetFullPath($OutputPath))
