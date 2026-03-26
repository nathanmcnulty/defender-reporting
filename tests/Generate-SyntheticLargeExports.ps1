#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('DeviceCardinalityFirst', 'BalancedMediumHeavy', 'CurrentDensity')]
    [string]$Preset = 'BalancedMediumHeavy',

    [Parameter(Mandatory = $false)]
    [string]$SourcePath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports'),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports-synthetic'),

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 200000)]
    [int]$TargetDeviceCount = 0,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50000000)]
    [int]$TargetTotalVulnRows = 0,

    [Parameter(Mandatory = $false)]
    [int]$Seed = 20260322,

    [Parameter(Mandatory = $false)]
    [switch]$CleanOutput,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeRawRows
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'shared-helpers.ps1')

function Get-PresetSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    switch ($Name) {
        'DeviceCardinalityFirst' {
            return @{
                TargetDeviceCount = 20000
                TargetTotalVulnRows = 500000
            }
        }
        'BalancedMediumHeavy' {
            return @{
                TargetDeviceCount = 20000
                TargetTotalVulnRows = 1500000
            }
        }
        'CurrentDensity' {
            return @{
                TargetDeviceCount = 20000
                TargetTotalVulnRows = 8400000
            }
        }
        default {
            throw "Unsupported preset '$Name'."
        }
    }
}

function ConvertTo-ObjectCopy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    $copy = [ordered]@{}
    foreach ($prop in $InputObject.PSObject.Properties) {
        $copy[$prop.Name] = $prop.Value
    }

    return [PSCustomObject]$copy
}

function Add-ObjectProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    Add-Member -InputObject $InputObject -NotePropertyName $Name -NotePropertyValue $Value -Force
}

function Get-MachineRecordValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Machine,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Fallback = $null
    )

    $property = $Machine.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Fallback
    }

    return $property.Value
}

function Get-RowPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Row,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Fallback = $null
    )

    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Fallback
    }

    return $property.Value
}

function Get-ProfileKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DeviceId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DeviceName
    )

    if (-not [string]::IsNullOrWhiteSpace($DeviceId)) {
        return $DeviceId
    }

    if (-not [string]::IsNullOrWhiteSpace($DeviceName)) {
        return ('name:' + $DeviceName)
    }

    return 'unknown'
}

function Get-SyntheticDeviceId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseId,

        [Parameter(Mandatory = $true)]
        [int]$Index
    )

    $normalizedBase = if ([string]::IsNullOrWhiteSpace($BaseId)) { 'device' } else { $BaseId }
    return ('sim-{0:D5}-{1}' -f $Index, $normalizedBase)
}

function Get-SyntheticDeviceName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseName,

        [Parameter(Mandatory = $true)]
        [int]$Index
    )

    $normalizedBase = if ([string]::IsNullOrWhiteSpace($BaseName)) { 'device' } else { $BaseName.Trim() }
    $dotIndex = $normalizedBase.IndexOf('.')
    if ($dotIndex -gt 0) {
        $hostName = $normalizedBase.Substring(0, $dotIndex)
        $domain = $normalizedBase.Substring($dotIndex)
        return ('{0}-sim-{1:D5}{2}' -f $hostName, $Index, $domain)
    }

    return ('{0}-sim-{1:D5}' -f $normalizedBase, $Index)
}

function Get-SyntheticRowId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $SourceRow,

        [Parameter(Mandatory = $true)]
        [string]$DeviceId
    )

    $sourceId = [string](Get-RowPropertyValue -Row $SourceRow -Name 'Id' -Fallback '')
    $sourceDeviceId = [string](Get-RowPropertyValue -Row $SourceRow -Name 'DeviceId' -Fallback '')
    if (-not [string]::IsNullOrWhiteSpace($sourceId) -and -not [string]::IsNullOrWhiteSpace($sourceDeviceId)) {
        $expectedPrefix = $sourceDeviceId + '_'
        if ($sourceId.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return ($DeviceId + '_' + $sourceId.Substring($expectedPrefix.Length))
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($sourceId)) {
        return ($DeviceId + '_' + $sourceId)
    }

    $cveId = [string](Get-RowPropertyValue -Row $SourceRow -Name 'CveId' -Fallback 'cve')
    $softwareName = [string](Get-RowPropertyValue -Row $SourceRow -Name 'SoftwareName' -Fallback 'software')
    return ($DeviceId + '_' + $softwareName + '_' + $cveId)
}

function ConvertTo-SyntheticMachineRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $TemplateMachine,

        [Parameter(Mandatory = $true)]
        [string]$DeviceId,

        [Parameter(Mandatory = $true)]
        [string]$DeviceName,

        [Parameter(Mandatory = $true)]
        [string]$ObservedOn
    )

    $machine = ConvertTo-ObjectCopy -InputObject $TemplateMachine
    Add-ObjectProperty -InputObject $machine -Name 'id' -Value $DeviceId
    Add-ObjectProperty -InputObject $machine -Name 'computerDnsName' -Value $DeviceName
    Add-ObjectProperty -InputObject $machine -Name 'observedOn' -Value $ObservedOn
    Add-ObjectProperty -InputObject $machine -Name 'stateHash' -Value (Get-MachineStateHash -Machine $machine)
    return $machine
}

function ConvertTo-SyntheticRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $SourceRow,

        [Parameter(Mandatory = $true)]
        $SyntheticMachine,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$RbacGroupId
    )

    $row = Copy-VulnRecord -Record $SourceRow
    $deviceId = [string](Get-MachineRecordValue -Machine $SyntheticMachine -Name 'id')
    Add-ObjectProperty -InputObject $row -Name 'DeviceId' -Value $deviceId
    Add-ObjectProperty -InputObject $row -Name 'DeviceName' -Value ([string](Get-MachineRecordValue -Machine $SyntheticMachine -Name 'computerDnsName'))
    Add-ObjectProperty -InputObject $row -Name 'RbacGroupName' -Value ([string](Get-MachineRecordValue -Machine $SyntheticMachine -Name 'rbacGroupName'))
    Add-ObjectProperty -InputObject $row -Name 'OSPlatform' -Value ([string](Get-MachineRecordValue -Machine $SyntheticMachine -Name 'osPlatform'))
    Add-ObjectProperty -InputObject $row -Name 'OSVersion' -Value (Get-MachineRecordValue -Machine $SyntheticMachine -Name 'osVersion')
    Add-ObjectProperty -InputObject $row -Name 'MachineTags' -Value (@(Get-NormalizedMachineTag -Tags (Get-MachineRecordValue -Machine $SyntheticMachine -Name 'machineTags')))
    Add-ObjectProperty -InputObject $row -Name 'IsOnboarded' -Value $true
    Add-ObjectProperty -InputObject $row -Name 'Id' -Value (Get-SyntheticRowId -SourceRow $SourceRow -DeviceId $deviceId)
    if ($null -ne $RbacGroupId) {
        Add-ObjectProperty -InputObject $row -Name 'RbacGroupId' -Value $RbacGroupId
    }
    return $row
}

function Get-PeriodKeyFromFileName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $match = [regex]::Match($Name, '^VulnHistoryRows_(?<period>\d{4}Q[1-4]|\d{4})\.json\.gz$')
    if (-not $match.Success) {
        throw "Unable to determine period key from '$Name'."
    }

    return $match.Groups['period'].Value
}

function Get-HistorySnapshotDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Row,

        [Parameter(Mandatory = $true)]
        [string]$FallbackPeriod
    )

    $snapshotDate = Convert-ToYmdDate -DateValue (Get-RowPropertyValue -Row $Row -Name 'LastSeenTimestamp')
    if (-not [string]::IsNullOrWhiteSpace($snapshotDate)) {
        return $snapshotDate
    }

    $snapshotDate = Convert-ToYmdDate -DateValue (Get-RowPropertyValue -Row $Row -Name 'FirstSeenTimestamp')
    if (-not [string]::IsNullOrWhiteSpace($snapshotDate)) {
        return $snapshotDate
    }

    if ($FallbackPeriod -match '^(?<year>\d{4})Q(?<quarter>[1-4])$') {
        $month = (([int]$Matches['quarter'] - 1) * 3) + 1
        return ('{0:D4}-{1:D2}-01' -f [int]$Matches['year'], $month)
    }

    if ($FallbackPeriod -match '^\d{4}$') {
        return ('{0}-01-01' -f $FallbackPeriod)
    }

    return (Get-Date).ToString('yyyy-MM-dd')
}

function Open-GzipWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [System.IO.Compression.CompressionLevel]$CompressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
    )

    $fileStream = [System.IO.File]::Create($Path)
    $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, $CompressionLevel, $false)
    $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))

    return [PSCustomObject]@{
        Path = $Path
        FileStream = $fileStream
        GzipStream = $gzipStream
        Writer = $writer
    }
}

function Sync-GzipWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $WriterState
    )

    if ($WriterState.Writer) {
        $WriterState.Writer.Flush()
    }
    if ($WriterState.GzipStream) {
        $WriterState.GzipStream.Flush()
    }
    if ($WriterState.FileStream) {
        $WriterState.FileStream.Flush()
    }
}

function Close-GzipWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $WriterState
    )

    if ($WriterState.Writer) {
        $WriterState.Writer.Dispose()
        return
    }
    if ($WriterState.GzipStream) {
        $WriterState.GzipStream.Dispose()
        return
    }
    if ($WriterState.FileStream) {
        $WriterState.FileStream.Dispose()
    }
}

function Get-AllocationCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$Value,

        [Parameter(Mandatory = $true)]
        [System.Random]$Random
    )

    if ($Value -le 0) {
        return 0
    }

    $whole = [int][math]::Floor($Value)
    $fraction = $Value - $whole
    if ($fraction -gt 0 -and $Random.NextDouble() -lt $fraction) {
        $whole++
    }

    return $whole
}

function Add-DeltaAcrossPlanSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$Plans,

        [Parameter(Mandatory = $true)]
        [string]$Kind,

        [Parameter(Mandatory = $true)]
        [int]$Delta,

        [Parameter(Mandatory = $true)]
        [System.Random]$Random
    )

    if ($Delta -eq 0) {
        return
    }

    $countProperty = if ($Kind -eq 'Current') { 'CurrentTarget' } else { 'HistoryTarget' }
    $capacityProperty = if ($Kind -eq 'Current') { 'CurrentCapacity' } else { 'HistoryCapacity' }
    $direction = if ($Delta -gt 0) { 1 } else { -1 }
    $remaining = [math]::Abs($Delta)

    $eligible = [System.Collections.Generic.List[object]]::new()
    foreach ($plan in $Plans) {
        $countValue = [int]$plan.$countProperty
        $capacityValue = [int]$plan.$capacityProperty
        if ($direction -gt 0) {
            if ($capacityValue -gt $countValue) {
                $eligible.Add($plan)
            }
        }
        elseif ($countValue -gt 0) {
            $eligible.Add($plan)
        }
    }

    if ($eligible.Count -eq 0) {
        return
    }

    for ($i = $eligible.Count - 1; $i -gt 0; $i--) {
        $swapIndex = $Random.Next(0, $i + 1)
        $temp = $eligible[$i]
        $eligible[$i] = $eligible[$swapIndex]
        $eligible[$swapIndex] = $temp
    }

    $index = 0
    while ($remaining -gt 0 -and $eligible.Count -gt 0) {
        if ($index -ge $eligible.Count) {
            $index = 0
        }

        $plan = $eligible[$index]
        $countValue = [int]$plan.$countProperty
        $capacityValue = [int]$plan.$capacityProperty

        if ($direction -gt 0) {
            if ($countValue -lt $capacityValue) {
                $plan.$countProperty = $countValue + 1
                $remaining--
            }
            else {
                $eligible.RemoveAt($index)
                continue
            }
        }
        else {
            if ($countValue -gt 0) {
                $plan.$countProperty = $countValue - 1
                $remaining--
            }
            else {
                $eligible.RemoveAt($index)
                continue
            }
        }

        $index++
    }
}

function Get-SampledItemSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Items,

        [Parameter(Mandatory = $true)]
        [int]$Count,

        [Parameter(Mandatory = $true)]
        [System.Random]$Random
    )

    if ($Count -le 0 -or $Items.Count -eq 0) {
        return @()
    }

    if ($Count -ge $Items.Count) {
        $copy = [object[]]@($Items)
        for ($i = $copy.Length - 1; $i -gt 0; $i--) {
            $swapIndex = $Random.Next(0, $i + 1)
            $temp = $copy[$i]
            $copy[$i] = $copy[$swapIndex]
            $copy[$swapIndex] = $temp
        }
        return @($copy)
    }

    $indices = [int[]](0..($Items.Count - 1))
    for ($i = 0; $i -lt $Count; $i++) {
        $swapIndex = $Random.Next($i, $indices.Length)
        $temp = $indices[$i]
        $indices[$i] = $indices[$swapIndex]
        $indices[$swapIndex] = $temp
    }

    $selection = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $Count; $i++) {
        $selection.Add($Items[$indices[$i]])
    }

    return @($selection)
}

function Write-GenerationCheckpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$Stage,

        [Parameter(Mandatory = $true)]
        [int]$CompletedDevices,

        [Parameter(Mandatory = $true)]
        [int]$TotalDevices,

        [Parameter(Mandatory = $true)]
        [int]$WrittenCurrentRows,

        [Parameter(Mandatory = $true)]
        [int]$WrittenHistoryRows,

        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Stopwatch]$Stopwatch,

        [Parameter(Mandatory = $false)]
        [hashtable]$Extra = @{}
    )

    $checkpointPath = Join-Path $OutputPath '.synthetic-progress.json'
    $payload = [ordered]@{
        generatedOnUtc = (Get-Date).ToUniversalTime().ToString('o')
        stage = $Stage
        completedDevices = $CompletedDevices
        totalDevices = $TotalDevices
        writtenCurrentRows = $WrittenCurrentRows
        writtenHistoryRows = $WrittenHistoryRows
        writtenTotalRows = ($WrittenCurrentRows + $WrittenHistoryRows)
        elapsedSeconds = [math]::Round($Stopwatch.Elapsed.TotalSeconds, 2)
    }

    foreach ($key in $Extra.Keys) {
        $payload[$key] = $Extra[$key]
    }

    $payload | ConvertTo-Json -Depth 10 | Set-Content -Path $checkpointPath -Encoding utf8
}

function Add-SourceRowContentTemplateIndex {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        $Row,

        [Parameter(Mandatory = $false)]
        [System.Collections.Generic.List[object]]$ContentTemplates,

        [Parameter(Mandatory = $true)]
        [hashtable]$ContentTemplateIndex
    )

    $existing = $Row.PSObject.Properties['SyntheticContentTemplateIndex']
    if ($null -ne $existing) {
        return [int]$existing.Value
    }

    $contentSignature = Get-VulnContentTemplateSignature -Row $Row
    if (-not $ContentTemplateIndex.ContainsKey($contentSignature)) {
        $ContentTemplateIndex[$contentSignature] = $ContentTemplates.Count
        [void]$ContentTemplates.Add((ConvertTo-VulnContentTemplate -Row $Row))
    }

    $contentIndexValue = [int]$ContentTemplateIndex[$contentSignature]
    Add-Member -InputObject $Row -NotePropertyName 'SyntheticContentTemplateIndex' -NotePropertyValue $contentIndexValue -Force
    return $contentIndexValue
}

$presetSettings = Get-PresetSetting -Name $Preset
if ($TargetDeviceCount -le 0) {
    $TargetDeviceCount = [int]$presetSettings.TargetDeviceCount
}
if ($TargetTotalVulnRows -le 0) {
    $TargetTotalVulnRows = [int]$presetSettings.TargetTotalVulnRows
}

if (-not (Test-Path -LiteralPath $SourcePath -PathType Container)) {
    throw "Source path '$SourcePath' was not found."
}

if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
    [void](New-Item -Path $OutputPath -ItemType Directory -Force)
}
elseif ($CleanOutput) {
    $pathsToRemove = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(Get-ChildItem -Path $OutputPath -Force -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
        $relativeName = [System.IO.Path]::GetRelativePath($OutputPath, $item.FullName).Replace('\', '/')
        if ($item.PSIsContainer) {
            if (Test-IsTransientExportArtifactName -Name ($relativeName + '/')) {
                $pathsToRemove.Add($item.FullName)
            }
            continue
        }

        if ((Test-IsExportTransferArtifactName -Name $relativeName) -or (Test-IsTransientExportArtifactName -Name $relativeName)) {
            $pathsToRemove.Add($item.FullName)
        }
    }

    foreach ($path in @($pathsToRemove | Sort-Object -Unique)) {
        $removed = $false
        for ($attempt = 1; $attempt -le 5 -and -not $removed; $attempt++) {
            try {
                if (Test-Path -LiteralPath $path -PathType Container) {
                    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                }
                else {
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                }
                $removed = $true
            }
            catch {
                if ($attempt -ge 5) {
                    throw
                }
                Start-Sleep -Milliseconds (200 * $attempt)
            }
        }
    }
}

$random = [System.Random]::new($Seed)
$generationDate = (Get-Date).ToString('yyyy-MM-dd')

Write-Output "Reading source machine data from '$SourcePath'..."
$sourceMachines = Read-MachineData -Path $SourcePath
$machineTemplates = [System.Collections.Generic.List[object]]::new()
foreach ($machine in $sourceMachines.Values) {
    if ($null -eq $machine) { continue }
    $machineTemplates.Add($machine)
}
if ($machineTemplates.Count -eq 0) {
    throw 'No source machine data was found.'
}

Write-Output "Reading source current vulnerability rows..."
$sourceCurrentRows = @(Read-VulnNdjsonRecordsFromPath -Path (Get-VulnCurrentPath -BasePath $SourcePath))

Write-Output "Reading source history vulnerability rows..."
$sourceHistoryEntries = [System.Collections.Generic.List[object]]::new()
foreach ($historyRowsFile in @(Get-ChildItem -Path $SourcePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
    $periodKey = Get-PeriodKeyFromFileName -Name $historyRowsFile.Name
    foreach ($row in Read-VulnNdjsonRecordsFromPath -Path $historyRowsFile.FullName) {
        $sourceHistoryEntries.Add([PSCustomObject]@{
            PeriodKey = $periodKey
            SnapshotDate = Get-HistorySnapshotDate -Row $row -FallbackPeriod $periodKey
            Row = $row
        })
    }
}

if (($sourceCurrentRows.Count + $sourceHistoryEntries.Count) -eq 0) {
    throw 'No source vulnerability rows were found.'
}

Write-Output "Reading source Advanced Hunting rows..."
$sourceAdvancedHuntingRecords = @(Read-AdvancedHuntingRecordsFromFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $SourcePath))
$contentTemplates = [System.Collections.Generic.List[object]]::new()
$contentTemplateIndex = @{}

foreach ($row in $sourceCurrentRows) {
    [void](Add-SourceRowContentTemplateIndex -Row $row -ContentTemplates $contentTemplates -ContentTemplateIndex $contentTemplateIndex)
}

foreach ($historyEntry in $sourceHistoryEntries) {
    [void](Add-SourceRowContentTemplateIndex -Row $historyEntry.Row -ContentTemplates $contentTemplates -ContentTemplateIndex $contentTemplateIndex)
}

$rowProfileMap = @{}
foreach ($machine in $machineTemplates) {
    $machineId = [string](Get-MachineRecordValue -Machine $machine -Name 'id')
    $machineName = [string](Get-MachineRecordValue -Machine $machine -Name 'computerDnsName')
    $profileKey = Get-ProfileKey -DeviceId $machineId -DeviceName $machineName
    if (-not $rowProfileMap.ContainsKey($profileKey)) {
        $rowProfileMap[$profileKey] = [PSCustomObject]@{
            ProfileKey = $profileKey
            TemplateMachine = $machine
            CurrentRows = [System.Collections.Generic.List[object]]::new()
            HistoryEntries = [System.Collections.Generic.List[object]]::new()
            RbacGroupId = $null
        }
    }
    elseif ($null -eq $rowProfileMap[$profileKey].TemplateMachine) {
        $rowProfileMap[$profileKey].TemplateMachine = $machine
    }
}

foreach ($row in $sourceCurrentRows) {
    $profileKey = Get-ProfileKey -DeviceId ([string](Get-RowPropertyValue -Row $row -Name 'DeviceId')) -DeviceName ([string](Get-RowPropertyValue -Row $row -Name 'DeviceName'))
    if (-not $rowProfileMap.ContainsKey($profileKey)) {
        $rowProfileMap[$profileKey] = [PSCustomObject]@{
            ProfileKey = $profileKey
            TemplateMachine = $null
            CurrentRows = [System.Collections.Generic.List[object]]::new()
            HistoryEntries = [System.Collections.Generic.List[object]]::new()
            RbacGroupId = $null
        }
    }
    $rowProfileMap[$profileKey].CurrentRows.Add($row)
    if ($null -eq $rowProfileMap[$profileKey].RbacGroupId -and $row.PSObject.Properties['RbacGroupId']) {
        $rowProfileMap[$profileKey].RbacGroupId = $row.RbacGroupId
    }
}

foreach ($historyEntry in $sourceHistoryEntries) {
    $row = $historyEntry.Row
    $profileKey = Get-ProfileKey -DeviceId ([string](Get-RowPropertyValue -Row $row -Name 'DeviceId')) -DeviceName ([string](Get-RowPropertyValue -Row $row -Name 'DeviceName'))
    if (-not $rowProfileMap.ContainsKey($profileKey)) {
        $rowProfileMap[$profileKey] = [PSCustomObject]@{
            ProfileKey = $profileKey
            TemplateMachine = $null
            CurrentRows = [System.Collections.Generic.List[object]]::new()
            HistoryEntries = [System.Collections.Generic.List[object]]::new()
            RbacGroupId = $null
        }
    }
    $rowProfileMap[$profileKey].HistoryEntries.Add($historyEntry)
    if ($null -eq $rowProfileMap[$profileKey].RbacGroupId -and $row.PSObject.Properties['RbacGroupId']) {
        $rowProfileMap[$profileKey].RbacGroupId = $row.RbacGroupId
    }
}

$rowProfiles = [System.Collections.Generic.List[object]]::new()
foreach ($rowProfileEntry in $rowProfileMap.Values) {
    if ($null -eq $rowProfileEntry.TemplateMachine) {
        $fallbackRow = if ($rowProfileEntry.CurrentRows.Count -gt 0) { $rowProfileEntry.CurrentRows[0] } elseif ($rowProfileEntry.HistoryEntries.Count -gt 0) { $rowProfileEntry.HistoryEntries[0].Row } else { $null }
        if ($null -ne $fallbackRow) {
            $rowProfileEntry.TemplateMachine = [PSCustomObject]@{
                id = [string](Get-RowPropertyValue -Row $fallbackRow -Name 'DeviceId')
                computerDnsName = [string](Get-RowPropertyValue -Row $fallbackRow -Name 'DeviceName')
                rbacGroupName = [string](Get-RowPropertyValue -Row $fallbackRow -Name 'RbacGroupName')
                osPlatform = [string](Get-RowPropertyValue -Row $fallbackRow -Name 'OSPlatform')
                osVersion = Get-RowPropertyValue -Row $fallbackRow -Name 'OSVersion'
                machineTags = @(Get-NormalizedMachineTag -Tags (Get-RowPropertyValue -Row $fallbackRow -Name 'MachineTags'))
                lastIpAddress = $null
                lastExternalIpAddress = $null
                healthStatus = 'Active'
                riskScore = 'Low'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Synthetic'
                isAadJoined = $true
                lastSeen = $generationDate
                firstSeen = $generationDate
            }
        }
    }

    if (($rowProfileEntry.CurrentRows.Count + $rowProfileEntry.HistoryEntries.Count) -gt 0 -and $null -ne $rowProfileEntry.TemplateMachine) {
        $rowProfiles.Add($rowProfileEntry)
    }
}

if ($rowProfiles.Count -eq 0) {
    throw 'No usable source row profiles were built from the source exports.'
}

$sourceCurrentCount = $sourceCurrentRows.Count
$sourceHistoryCount = $sourceHistoryEntries.Count
$sourceTotalCount = $sourceCurrentCount + $sourceHistoryCount
$sourceCurrentShare = [double]$sourceCurrentCount / [double]$sourceTotalCount
$targetCurrentRows = [int][math]::Round($TargetTotalVulnRows * $sourceCurrentShare)
$targetHistoryRows = $TargetTotalVulnRows - $targetCurrentRows
$sourceAveragePerProfile = [double]$sourceTotalCount / [double]$rowProfiles.Count
$scaleFactor = [double]$TargetTotalVulnRows / ([double]$TargetDeviceCount * $sourceAveragePerProfile)
$generationStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$checkpointIntervalDevices = 250
$nextCheckpointDevice = $checkpointIntervalDevices

Write-Output "Source rows: $sourceTotalCount total ($sourceCurrentCount current, $sourceHistoryCount history)"
Write-Output "Target rows: $TargetTotalVulnRows total ($targetCurrentRows current, $targetHistoryRows history)"
Write-Output ("Scale factor per source device profile: {0:N4}" -f $scaleFactor)
Write-GenerationCheckpoint -OutputPath $OutputPath -Stage 'planning' -CompletedDevices 0 -TotalDevices $TargetDeviceCount -WrittenCurrentRows 0 -WrittenHistoryRows 0 -Stopwatch $generationStopwatch -Extra @{
    targetCurrentRows = $targetCurrentRows
    targetHistoryRows = $targetHistoryRows
    scaleFactor = [math]::Round($scaleFactor, 6)
}

$plans = [System.Collections.Generic.List[object]]::new()
for ($i = 0; $i -lt $TargetDeviceCount; $i++) {
    $machineTemplate = $machineTemplates[$i % $machineTemplates.Count]
    $rowProfile = $rowProfiles[$random.Next(0, $rowProfiles.Count)]

    $deviceOrdinal = $i + 1
    $sourceMachineId = [string](Get-MachineRecordValue -Machine $machineTemplate -Name 'id' -Fallback ("device-{0:D5}" -f $deviceOrdinal))
    $sourceMachineName = [string](Get-MachineRecordValue -Machine $machineTemplate -Name 'computerDnsName' -Fallback ("device-{0:D5}" -f $deviceOrdinal))
    $deviceId = Get-SyntheticDeviceId -BaseId $sourceMachineId -Index $deviceOrdinal
    $deviceName = Get-SyntheticDeviceName -BaseName $sourceMachineName -Index $deviceOrdinal
    $syntheticMachine = ConvertTo-SyntheticMachineRecord -TemplateMachine $machineTemplate -DeviceId $deviceId -DeviceName $deviceName -ObservedOn $generationDate

    $currentCapacity = $rowProfile.CurrentRows.Count
    $historyCapacity = $rowProfile.HistoryEntries.Count
    $currentTarget = Get-AllocationCount -Value ($currentCapacity * $scaleFactor) -Random $random
    $historyTarget = Get-AllocationCount -Value ($historyCapacity * $scaleFactor) -Random $random

    if (($currentTarget + $historyTarget) -eq 0) {
        if ($historyCapacity -gt 0) {
            $historyTarget = 1
        }
        elseif ($currentCapacity -gt 0) {
            $currentTarget = 1
        }
    }

    if ($currentTarget -gt $currentCapacity) { $currentTarget = $currentCapacity }
    if ($historyTarget -gt $historyCapacity) { $historyTarget = $historyCapacity }

    $plans.Add([PSCustomObject]@{
        DeviceOrdinal = $deviceOrdinal
        Machine = $syntheticMachine
        RowProfile = $rowProfile
        CurrentTarget = $currentTarget
        HistoryTarget = $historyTarget
        CurrentCapacity = $currentCapacity
        HistoryCapacity = $historyCapacity
        RbacGroupId = if ($null -ne $rowProfile.RbacGroupId) { $rowProfile.RbacGroupId } else { 343 }
    })
}

$currentDelta = $targetCurrentRows - (@($plans | Measure-Object -Property CurrentTarget -Sum).Sum)
$historyDelta = $targetHistoryRows - (@($plans | Measure-Object -Property HistoryTarget -Sum).Sum)
Add-DeltaAcrossPlanSet -Plans $plans -Kind 'Current' -Delta $currentDelta -Random $random
Add-DeltaAcrossPlanSet -Plans $plans -Kind 'History' -Delta $historyDelta -Random $random

$currentWriter = if ($IncludeRawRows) { Open-GzipWriter -Path (Get-VulnCurrentPath -BasePath $OutputPath) } else { $null }
$currentRefsPath = Get-VulnCurrentRefsPath -BasePath $OutputPath
$currentRefsWriter = Open-GzipWriter -Path $currentRefsPath
$historyWriters = @{}
$historyRefsWriters = @{}
$historyLatestByPeriod = @{}
$advancedHuntingCveIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$deviceProfiles = [System.Collections.Generic.List[object]]::new()
$deviceProfileIndex = @{}

$syntheticMachines = [System.Collections.Generic.List[object]]::new()
$writtenCurrentRows = 0
$writtenHistoryRows = 0

try {
    foreach ($plan in $plans) {
        $syntheticMachines.Add($plan.Machine)
        $planDeviceProfileRow = [PSCustomObject]@{
            DeviceId = [string](Get-MachineRecordValue -Machine $plan.Machine -Name 'id')
            DeviceName = [string](Get-MachineRecordValue -Machine $plan.Machine -Name 'computerDnsName')
            RbacGroupName = [string](Get-MachineRecordValue -Machine $plan.Machine -Name 'rbacGroupName')
            OSPlatform = [string](Get-MachineRecordValue -Machine $plan.Machine -Name 'osPlatform')
            OSVersion = Get-MachineRecordValue -Machine $plan.Machine -Name 'osVersion'
            MachineTags = @(Get-NormalizedMachineTag -Tags (Get-MachineRecordValue -Machine $plan.Machine -Name 'machineTags'))
            IsOnboarded = $true
        }
        $deviceSignature = Get-VulnDeviceProfileSignature -Row $planDeviceProfileRow
        if (-not $deviceProfileIndex.ContainsKey($deviceSignature)) {
            $deviceProfileIndex[$deviceSignature] = $deviceProfiles.Count
            [void]$deviceProfiles.Add((ConvertTo-VulnDeviceProfileTemplate -Row $planDeviceProfileRow))
        }
        $deviceIndexValue = [int]$deviceProfileIndex[$deviceSignature]
        $syntheticDeviceId = [string]$planDeviceProfileRow.DeviceId

        $selectedCurrentRows = Get-SampledItemSet -Items @($plan.RowProfile.CurrentRows) -Count ([int]$plan.CurrentTarget) -Random $random
        foreach ($sourceRow in $selectedCurrentRows) {
            $row = $null
            if ($IncludeRawRows) {
                $row = ConvertTo-SyntheticRow -SourceRow $sourceRow -SyntheticMachine $plan.Machine -RbacGroupId $plan.RbacGroupId
                $currentWriter.Writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 20))
            }
            $rowId = if ($row) { [string](Get-RowPropertyValue -Row $row -Name 'Id') } else { Get-SyntheticRowId -SourceRow $sourceRow -DeviceId $syntheticDeviceId }
            $firstSeenTimestamp = [string](Get-RowPropertyValue -Row $sourceRow -Name 'FirstSeenTimestamp')
            $lastSeenTimestamp = [string](Get-RowPropertyValue -Row $sourceRow -Name 'LastSeenTimestamp')
            $contentIndexValue = [int](Get-RowPropertyValue -Row $sourceRow -Name 'SyntheticContentTemplateIndex')

            Write-VulnObservationRefLine `
                -Writer $currentRefsWriter.Writer `
                -Id $rowId `
                -DeviceProfileIndex $deviceIndexValue `
                -ContentTemplateIndex $contentIndexValue `
                -FirstSeenTimestamp $firstSeenTimestamp `
                -LastSeenTimestamp $lastSeenTimestamp

            [void]$advancedHuntingCveIds.Add([string](Get-RowPropertyValue -Row $sourceRow -Name 'CveId'))
            $writtenCurrentRows++
        }

        $selectedHistoryEntries = Get-SampledItemSet -Items @($plan.RowProfile.HistoryEntries) -Count ([int]$plan.HistoryTarget) -Random $random
        foreach ($historyEntry in $selectedHistoryEntries) {
            $row = $null
            $periodKey = [string]$historyEntry.PeriodKey
            $sourceHistoryRow = $historyEntry.Row
            $historyLastSeenTimestamp = [string](Get-RowPropertyValue -Row $sourceHistoryRow -Name 'LastSeenTimestamp')
            $historyFirstSeenTimestamp = [string](Get-RowPropertyValue -Row $sourceHistoryRow -Name 'FirstSeenTimestamp')
            if ($IncludeRawRows) {
                $row = ConvertTo-SyntheticRow -SourceRow $sourceHistoryRow -SyntheticMachine $plan.Machine -RbacGroupId $plan.RbacGroupId
            }
            if ([string]::IsNullOrWhiteSpace($periodKey)) {
                $periodKey = Get-QuarterPeriodKeyFromDate -Date (Convert-ToYmdDate -DateValue $historyLastSeenTimestamp)
            }
            if (-not $historyRefsWriters.ContainsKey($periodKey)) {
                if ($IncludeRawRows) {
                    $historyRowsPath = Get-VulnHistoryRowsPath -BasePath $OutputPath -PeriodKey $periodKey
                    $historyWriters[$periodKey] = Open-GzipWriter -Path $historyRowsPath
                }
                $historyRefsPath = Get-VulnHistoryRefsPath -BasePath $OutputPath -PeriodKey $periodKey
                $historyRefsWriters[$periodKey] = Open-GzipWriter -Path $historyRefsPath
                $historyLatestByPeriod[$periodKey] = ''
            }

            if ($historyWriters.ContainsKey($periodKey)) {
                $historyWriters[$periodKey].Writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 20))
            }
            $rowId = if ($row) { [string](Get-RowPropertyValue -Row $row -Name 'Id') } else { Get-SyntheticRowId -SourceRow $sourceHistoryRow -DeviceId $syntheticDeviceId }
            $contentIndexValue = [int](Get-RowPropertyValue -Row $sourceHistoryRow -Name 'SyntheticContentTemplateIndex')

            Write-VulnObservationRefLine `
                -Writer $historyRefsWriters[$periodKey].Writer `
                -Id $rowId `
                -DeviceProfileIndex $deviceIndexValue `
                -ContentTemplateIndex $contentIndexValue `
                -FirstSeenTimestamp $historyFirstSeenTimestamp `
                -LastSeenTimestamp $historyLastSeenTimestamp

            $snapshotDate = Convert-ToYmdDate -DateValue $historyEntry.SnapshotDate
            if ([string]::IsNullOrWhiteSpace($snapshotDate)) {
                $snapshotDate = Convert-ToYmdDate -DateValue $historyLastSeenTimestamp
            }
            if ([string]::IsNullOrWhiteSpace($snapshotDate)) {
                $snapshotDate = $generationDate
            }
            $historyLatestByPeriod[$periodKey] = Get-MaxVulnDate -Primary ([string]$historyLatestByPeriod[$periodKey]) -Secondary $snapshotDate
            [void]$advancedHuntingCveIds.Add([string](Get-RowPropertyValue -Row $sourceHistoryRow -Name 'CveId'))
            $writtenHistoryRows++
        }

        if ($plan.DeviceOrdinal -ge $nextCheckpointDevice -or $plan.DeviceOrdinal -eq $TargetDeviceCount) {
            if ($currentWriter) {
                Sync-GzipWriter -WriterState $currentWriter
            }
            Sync-GzipWriter -WriterState $currentRefsWriter
            foreach ($writerState in $historyWriters.Values) {
                Sync-GzipWriter -WriterState $writerState
            }
            foreach ($writerState in $historyRefsWriters.Values) {
                Sync-GzipWriter -WriterState $writerState
            }

            Write-Output ("Progress: {0}/{1} devices, {2} current rows, {3} history rows, elapsed {4}" -f $plan.DeviceOrdinal, $TargetDeviceCount, $writtenCurrentRows, $writtenHistoryRows, $generationStopwatch.Elapsed.ToString('hh\:mm\:ss'))
            Write-GenerationCheckpoint -OutputPath $OutputPath -Stage 'writing-vulnerability-rows' -CompletedDevices $plan.DeviceOrdinal -TotalDevices $TargetDeviceCount -WrittenCurrentRows $writtenCurrentRows -WrittenHistoryRows $writtenHistoryRows -Stopwatch $generationStopwatch -Extra @{
                targetCurrentRows = $targetCurrentRows
                targetHistoryRows = $targetHistoryRows
                activeHistoryPeriods = @($historyWriters.Keys | Sort-Object)
            }
            $nextCheckpointDevice += $checkpointIntervalDevices
        }
    }
}
finally {
    if ($currentWriter) {
        Close-GzipWriter -WriterState $currentWriter
    }
    Close-GzipWriter -WriterState $currentRefsWriter
    foreach ($writerState in $historyWriters.Values) {
        Close-GzipWriter -WriterState $writerState
    }
    foreach ($writerState in $historyRefsWriters.Values) {
        Close-GzipWriter -WriterState $writerState
    }
}

$machineCurrentPath = Get-MachineCurrentPath -BasePath $OutputPath
Write-GenerationCheckpoint -OutputPath $OutputPath -Stage 'writing-machine-data' -CompletedDevices $TargetDeviceCount -TotalDevices $TargetDeviceCount -WrittenCurrentRows $writtenCurrentRows -WrittenHistoryRows $writtenHistoryRows -Stopwatch $generationStopwatch
Write-NdjsonRecordsFile -Path $machineCurrentPath -Records $syntheticMachines

foreach ($periodKey in @($historyWriters.Keys | Sort-Object)) {
    $periodInfo = Get-VulnHistoryPeriodInfo -PeriodKey $periodKey
    $historyDocument = [PSCustomObject]@{
        year = $periodInfo.Year
        quarter = $periodInfo.Quarter
        period = $periodKey
        latestDate = [string]$historyLatestByPeriod[$periodKey]
        snapshots = @()
    }
    $historyPath = Get-VulnHistoryPath -BasePath $OutputPath -PeriodKey $periodKey
    Write-VulnHistoryDocument -Path $historyPath -HistoryDocument $historyDocument
}

$filteredAdvancedHunting = if ($advancedHuntingCveIds.Count -gt 0) {
    @($sourceAdvancedHuntingRecords | Where-Object { $advancedHuntingCveIds.Contains([string]$_.CveId) })
}
else {
    @($sourceAdvancedHuntingRecords)
}
Write-GenerationCheckpoint -OutputPath $OutputPath -Stage 'writing-advanced-hunting' -CompletedDevices $TargetDeviceCount -TotalDevices $TargetDeviceCount -WrittenCurrentRows $writtenCurrentRows -WrittenHistoryRows $writtenHistoryRows -Stopwatch $generationStopwatch
Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $OutputPath) -Records $filteredAdvancedHunting

$contentDictionary = [PSCustomObject]@{
    version = 'content-dictionary-v1'
    deviceProfiles = @($deviceProfiles)
    contentTemplates = @($contentTemplates)
} | ConvertTo-Json -Compress -Depth 20
Write-GenerationCheckpoint -OutputPath $OutputPath -Stage 'writing-content-dictionary' -CompletedDevices $TargetDeviceCount -TotalDevices $TargetDeviceCount -WrittenCurrentRows $writtenCurrentRows -WrittenHistoryRows $writtenHistoryRows -Stopwatch $generationStopwatch
Write-GzipTextFile -Path (Get-VulnContentDictionaryPath -BasePath $OutputPath) -Content $contentDictionary

$manifest = [PSCustomObject]@{
    preset = $Preset
    seed = $Seed
    generatedOnUtc = (Get-Date).ToUniversalTime().ToString('o')
    sourcePath = [System.IO.Path]::GetFullPath($SourcePath)
    outputPath = [System.IO.Path]::GetFullPath($OutputPath)
    targetDeviceCount = $TargetDeviceCount
    targetTotalVulnRows = $TargetTotalVulnRows
    targetCurrentRows = $targetCurrentRows
    targetHistoryRows = $targetHistoryRows
    actualDeviceCount = $syntheticMachines.Count
    includeRawRows = ($IncludeRawRows -eq $true)
    actualCurrentRows = $writtenCurrentRows
    actualHistoryRows = $writtenHistoryRows
    actualTotalVulnRows = ($writtenCurrentRows + $writtenHistoryRows)
    scaleFactor = $scaleFactor
    sourceCurrentRows = $sourceCurrentCount
    sourceHistoryRows = $sourceHistoryCount
    sourceRowProfiles = $rowProfiles.Count
    historyPeriods = @($historyWriters.Keys | Sort-Object)
    advancedHuntingRows = $filteredAdvancedHunting.Count
}
$manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $OutputPath 'synthetic-manifest.json') -Encoding utf8
$generationStopwatch.Stop()
Write-GenerationCheckpoint -OutputPath $OutputPath -Stage 'completed' -CompletedDevices $TargetDeviceCount -TotalDevices $TargetDeviceCount -WrittenCurrentRows $writtenCurrentRows -WrittenHistoryRows $writtenHistoryRows -Stopwatch $generationStopwatch -Extra @{
    advancedHuntingRows = $filteredAdvancedHunting.Count
    historyPeriods = @($historyWriters.Keys | Sort-Object)
}

Write-Output ''
Write-Output 'Synthetic export generation completed.'
Write-Output ("  Output path: {0}" -f ([System.IO.Path]::GetFullPath($OutputPath)))
Write-Output ("  Devices: {0}" -f $syntheticMachines.Count)
Write-Output ("  Vulnerability rows: {0} current + {1} history = {2} total" -f $writtenCurrentRows, $writtenHistoryRows, ($writtenCurrentRows + $writtenHistoryRows))
Write-Output ("  Advanced Hunting rows: {0}" -f $filteredAdvancedHunting.Count)
Write-Output ("  History periods: {0}" -f ((@($historyWriters.Keys | Sort-Object) -join ', ')))
