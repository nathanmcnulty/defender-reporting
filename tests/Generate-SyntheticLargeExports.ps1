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
    [ValidateRange(1, 200000)]
    [int]$PlanningSourceMachineLimit = 50000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 500000)]
    [int]$PlanningSourceRowLimit = 100000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 200000)]
    [int]$SafetyDeviceLimit = 25000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50000000)]
    [int]$SafetyRowLimit = 2500000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 256)]
    [int]$MinimumAvailableMemoryGB = 8,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 2048)]
    [int]$MinimumFreeDiskGB = 10,

    [Parameter(Mandatory = $false)]
    [int]$Seed = 20260322,

    [Parameter(Mandatory = $false)]
    [switch]$CleanOutput,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeRawRows,

    [Parameter(Mandatory = $false)]
    [switch]$AllowLargeDataset
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

function Get-AvailableMemoryGB {
    [CmdletBinding()]
    [OutputType([double])]
    param()

    if (-not $IsWindows) {
        return [double]::NaN
    }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    return [math]::Round(($os.FreePhysicalMemory / 1MB), 2)
}

function Get-FreeDiskSpaceGB {
    [CmdletBinding()]
    [OutputType([double])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($resolvedPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "Unable to determine drive root for '$resolvedPath'."
    }

    $driveInfo = [System.IO.DriveInfo]::new($root)
    return [math]::Round(($driveInfo.AvailableFreeSpace / 1GB), 2)
}

function Test-EquivalentPath {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Left,

        [Parameter(Mandatory = $true)]
        [string]$Right
    )

    $leftPath = [System.IO.Path]::GetFullPath($Left).TrimEnd('\', '/')
    $rightPath = [System.IO.Path]::GetFullPath($Right).TrimEnd('\', '/')
    return [System.StringComparer]::OrdinalIgnoreCase.Equals($leftPath, $rightPath)
}

function Assert-SyntheticGenerationPreflight {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$TargetDeviceCount,

        [Parameter(Mandatory = $true)]
        [int]$TargetTotalVulnRows,

        [Parameter(Mandatory = $true)]
        [int]$SafetyDeviceLimit,

        [Parameter(Mandatory = $true)]
        [int]$SafetyRowLimit,

        [Parameter(Mandatory = $true)]
        [int]$MinimumAvailableMemoryGB,

        [Parameter(Mandatory = $true)]
        [int]$MinimumFreeDiskGB,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [bool]$AllowLargeDataset
    )

    $requiresOverride = ($TargetDeviceCount -gt $SafetyDeviceLimit) -or ($TargetTotalVulnRows -gt $SafetyRowLimit)
    if ($requiresOverride -and -not $AllowLargeDataset) {
        throw ("Requested synthetic dataset size ({0} devices, {1} rows) exceeds the unattended safety limit ({2} devices, {3} rows). Re-run with -AllowLargeDataset only after reviewing memory and disk headroom." -f $TargetDeviceCount, $TargetTotalVulnRows, $SafetyDeviceLimit, $SafetyRowLimit)
    }

    $availableMemoryGB = Get-AvailableMemoryGB
    if (-not [double]::IsNaN($availableMemoryGB) -and $availableMemoryGB -lt $MinimumAvailableMemoryGB) {
        throw ("Available system memory is {0} GB, below the required preflight floor of {1} GB." -f $availableMemoryGB, $MinimumAvailableMemoryGB)
    }

    $freeDiskGB = Get-FreeDiskSpaceGB -Path $OutputPath
    if ($freeDiskGB -lt $MinimumFreeDiskGB) {
        throw ("Available disk space at '{0}' is {1} GB, below the required preflight floor of {2} GB." -f $OutputPath, $freeDiskGB, $MinimumFreeDiskGB)
    }

    if ($requiresOverride) {
        Write-Warning ("Large synthetic dataset override enabled for {0} devices / {1} rows." -f $TargetDeviceCount, $TargetTotalVulnRows)
    }

    return [PSCustomObject]@{
        availableMemoryGB = $availableMemoryGB
        freeDiskGB = $freeDiskGB
        largeDatasetOverrideRequired = $requiresOverride
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

function Write-GzipJsonRecordLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $WriterState,

        [Parameter(Mandatory = $true)]
        $Record
    )

    $lineWriter = $null
    $jsonWriter = $null

    try {
        $lineWriter = [System.IO.StringWriter]::new([System.Globalization.CultureInfo]::InvariantCulture)
        $jsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($lineWriter)
        $jsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None
        Write-JsonValueToWriter -Writer $jsonWriter -Value $Record
        $jsonWriter.Flush()
        $WriterState.Writer.WriteLine($lineWriter.ToString())
    }
    finally {
        if ($jsonWriter) {
            $jsonWriter.Close()
        }
        elseif ($lineWriter) {
            $lineWriter.Dispose()
        }
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

function Invoke-SampledItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IList]$Items,

        [Parameter(Mandatory = $true)]
        [int]$Count,

        [Parameter(Mandatory = $true)]
        [System.Random]$Random
    )

    if ($Count -le 0 -or $Items.Count -eq 0) {
        return
    }

    $indices = [int[]](0..($Items.Count - 1))
    $limit = [Math]::Min($Count, $Items.Count)

    for ($i = 0; $i -lt $limit; $i++) {
        $swapIndex = $Random.Next($i, $indices.Length)
        $temp = $indices[$i]
        $indices[$i] = $indices[$swapIndex]
        $indices[$swapIndex] = $temp
        $Items[$indices[$i]]
    }
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

$SourcePath = [System.IO.Path]::GetFullPath($SourcePath)
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

if (Test-EquivalentPath -Left $SourcePath -Right $OutputPath) {
    throw 'OutputPath must differ from SourcePath.'
}

$preflight = Assert-SyntheticGenerationPreflight `
    -TargetDeviceCount $TargetDeviceCount `
    -TargetTotalVulnRows $TargetTotalVulnRows `
    -SafetyDeviceLimit $SafetyDeviceLimit `
    -SafetyRowLimit $SafetyRowLimit `
    -MinimumAvailableMemoryGB $MinimumAvailableMemoryGB `
    -MinimumFreeDiskGB $MinimumFreeDiskGB `
    -OutputPath $OutputPath `
    -AllowLargeDataset ($AllowLargeDataset -eq $true)

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
        if (-not (Test-Path -LiteralPath $path)) { continue }
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

$sourceMachinePath = Get-MachineCurrentPath -BasePath $SourcePath
if (-not (Test-Path -LiteralPath $sourceMachinePath -PathType Leaf)) {
    throw "Source machine export was not found at '$sourceMachinePath'."
}

$sourceCurrentPath = Get-VulnCurrentPath -BasePath $SourcePath
if (-not (Test-Path -LiteralPath $sourceCurrentPath -PathType Leaf)) {
    throw "Source current vulnerability export was not found at '$sourceCurrentPath'."
}

$sourceHistoryFiles = @(Get-ChildItem -Path $SourcePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)

Write-Output 'Running source-shape preflight...'
$sourceMachineCountForPlanning = 0
foreach ($machineRecord in Read-MachineRecordsFromFile -Path $sourceMachinePath) {
    if ($null -ne $machineRecord) {
        $sourceMachineCountForPlanning++
    }
}

$sourceCurrentCountForPlanning = 0
foreach ($line in Read-VulnNdjsonLinesFromPath -Path $sourceCurrentPath) {
    if (-not [string]::IsNullOrWhiteSpace($line)) {
        $sourceCurrentCountForPlanning++
    }
}

$sourceHistoryCountForPlanning = 0
foreach ($historyRowsFile in $sourceHistoryFiles) {
    foreach ($line in Read-VulnNdjsonLinesFromPath -Path $historyRowsFile.FullName) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $sourceHistoryCountForPlanning++
        }
    }
}

$sourcePlanningRowCount = $sourceCurrentCountForPlanning + $sourceHistoryCountForPlanning
if ($sourceMachineCountForPlanning -gt $PlanningSourceMachineLimit -and -not $AllowLargeDataset) {
    throw ("Source template machine count {0} exceeds the in-memory planning limit of {1}. Point the generator at the compact source exports or re-run with -AllowLargeDataset after reviewing memory headroom." -f $sourceMachineCountForPlanning, $PlanningSourceMachineLimit)
}
if ($sourcePlanningRowCount -gt $PlanningSourceRowLimit -and -not $AllowLargeDataset) {
    throw ("Source template row count {0} exceeds the in-memory planning limit of {1}. This generator is intended to plan from a compact export sample, not an already-expanded synthetic dataset." -f $sourcePlanningRowCount, $PlanningSourceRowLimit)
}
if ($sourceMachineCountForPlanning -gt $PlanningSourceMachineLimit) {
    Write-Warning ("Large source machine template set override enabled for {0} machine records." -f $sourceMachineCountForPlanning)
}
if ($sourcePlanningRowCount -gt $PlanningSourceRowLimit) {
    Write-Warning ("Large source vulnerability template set override enabled for {0} rows." -f $sourcePlanningRowCount)
}

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
$sourceCurrentRows = @(Read-VulnNdjsonRecordsFromPath -Path $sourceCurrentPath)

Write-Output "Reading source history vulnerability rows..."
$sourceHistoryEntries = [System.Collections.Generic.List[object]]::new()
foreach ($historyRowsFile in $sourceHistoryFiles) {
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

Write-Output ("Preflight resources: {0} GB free memory, {1} GB free disk" -f $preflight.availableMemoryGB, $preflight.freeDiskGB)
Write-Output "Source rows: $sourceTotalCount total ($sourceCurrentCount current, $sourceHistoryCount history)"
Write-Output "Target rows: $TargetTotalVulnRows total ($targetCurrentRows current, $targetHistoryRows history)"
Write-Output ("Scale factor per source device profile: {0:N4}" -f $scaleFactor)
Write-GenerationCheckpoint -OutputPath $OutputPath -Stage 'planning' -CompletedDevices 0 -TotalDevices $TargetDeviceCount -WrittenCurrentRows 0 -WrittenHistoryRows 0 -Stopwatch $generationStopwatch -Extra @{
    targetCurrentRows = $targetCurrentRows
    targetHistoryRows = $targetHistoryRows
    scaleFactor = [math]::Round($scaleFactor, 6)
    availableMemoryGB = $preflight.availableMemoryGB
    freeDiskGB = $preflight.freeDiskGB
    sourceTemplateMachines = $sourceMachineCountForPlanning
    sourceTemplateRows = $sourcePlanningRowCount
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
        MachineTemplate = $machineTemplate
        DeviceId = $deviceId
        DeviceName = $deviceName
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

$plannedCurrentCapacity = [int](($plans | Measure-Object -Property CurrentCapacity -Sum).Sum)
$plannedHistoryCapacity = [int](($plans | Measure-Object -Property HistoryCapacity -Sum).Sum)
$plannedCurrentRows = [int](($plans | Measure-Object -Property CurrentTarget -Sum).Sum)
$plannedHistoryRows = [int](($plans | Measure-Object -Property HistoryTarget -Sum).Sum)

if ($targetCurrentRows -gt $plannedCurrentCapacity -or $targetHistoryRows -gt $plannedHistoryCapacity) {
    throw ("The synthetic plan cannot satisfy the requested row targets. Requested current/history rows = {0}/{1}; available capacity after profile assignment = {2}/{3}." -f $targetCurrentRows, $targetHistoryRows, $plannedCurrentCapacity, $plannedHistoryCapacity)
}

if ($plannedCurrentRows -ne $targetCurrentRows -or $plannedHistoryRows -ne $targetHistoryRows) {
    throw ("Synthetic planning drift detected before writing any rows. Planned current/history rows = {0}/{1}; requested current/history rows = {2}/{3}." -f $plannedCurrentRows, $plannedHistoryRows, $targetCurrentRows, $targetHistoryRows)
}

$currentWriter = if ($IncludeRawRows) { Open-GzipWriter -Path (Get-VulnCurrentPath -BasePath $OutputPath) } else { $null }
$machineCurrentPath = Get-MachineCurrentPath -BasePath $OutputPath
$machineWriter = Open-GzipWriter -Path $machineCurrentPath
$currentRefsPath = Get-VulnCurrentRefsPath -BasePath $OutputPath
$currentRefsWriter = Open-GzipWriter -Path $currentRefsPath
$historyWriters = @{}
$historyRefsWriters = @{}
$historyLatestByPeriod = @{}
$advancedHuntingCveIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$deviceProfiles = [System.Collections.Generic.List[object]]::new()
$deviceProfileIndex = @{}

$writtenCurrentRows = 0
$writtenHistoryRows = 0

try {
    foreach ($plan in $plans) {
        $syntheticMachine = ConvertTo-SyntheticMachineRecord -TemplateMachine $plan.MachineTemplate -DeviceId ([string]$plan.DeviceId) -DeviceName ([string]$plan.DeviceName) -ObservedOn $generationDate
        Write-GzipJsonRecordLine -WriterState $machineWriter -Record (New-MachineSnapshotRecord -Machine $syntheticMachine -ObservedOn $generationDate)

        $planDeviceProfileRow = [PSCustomObject]@{
            DeviceId = [string](Get-MachineRecordValue -Machine $syntheticMachine -Name 'id')
            DeviceName = [string](Get-MachineRecordValue -Machine $syntheticMachine -Name 'computerDnsName')
            RbacGroupName = [string](Get-MachineRecordValue -Machine $syntheticMachine -Name 'rbacGroupName')
            OSPlatform = [string](Get-MachineRecordValue -Machine $syntheticMachine -Name 'osPlatform')
            OSVersion = Get-MachineRecordValue -Machine $syntheticMachine -Name 'osVersion'
            MachineTags = @(Get-NormalizedMachineTag -Tags (Get-MachineRecordValue -Machine $syntheticMachine -Name 'machineTags'))
            IsOnboarded = $true
        }
        $deviceSignature = Get-VulnDeviceProfileSignature -Row $planDeviceProfileRow
        if (-not $deviceProfileIndex.ContainsKey($deviceSignature)) {
            $deviceProfileIndex[$deviceSignature] = $deviceProfiles.Count
            [void]$deviceProfiles.Add((ConvertTo-VulnDeviceProfileTemplate -Row $planDeviceProfileRow))
        }
        $deviceIndexValue = [int]$deviceProfileIndex[$deviceSignature]
        $syntheticDeviceId = [string]$planDeviceProfileRow.DeviceId

        foreach ($sourceRow in Invoke-SampledItems -Items $plan.RowProfile.CurrentRows -Count ([int]$plan.CurrentTarget) -Random $random) {
            $row = $null
            if ($IncludeRawRows) {
                $row = ConvertTo-SyntheticRow -SourceRow $sourceRow -SyntheticMachine $syntheticMachine -RbacGroupId $plan.RbacGroupId
                Write-GzipJsonRecordLine -WriterState $currentWriter -Record $row
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

        foreach ($historyEntry in Invoke-SampledItems -Items $plan.RowProfile.HistoryEntries -Count ([int]$plan.HistoryTarget) -Random $random) {
            $row = $null
            $periodKey = [string]$historyEntry.PeriodKey
            $sourceHistoryRow = $historyEntry.Row
            $historyLastSeenTimestamp = [string](Get-RowPropertyValue -Row $sourceHistoryRow -Name 'LastSeenTimestamp')
            $historyFirstSeenTimestamp = [string](Get-RowPropertyValue -Row $sourceHistoryRow -Name 'FirstSeenTimestamp')
            if ($IncludeRawRows) {
                $row = ConvertTo-SyntheticRow -SourceRow $sourceHistoryRow -SyntheticMachine $syntheticMachine -RbacGroupId $plan.RbacGroupId
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
                Write-GzipJsonRecordLine -WriterState $historyWriters[$periodKey] -Record $row
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
            Sync-GzipWriter -WriterState $machineWriter
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
                activeHistoryPeriods = @($historyRefsWriters.Keys | Sort-Object)
            }
            $nextCheckpointDevice += $checkpointIntervalDevices
        }
    }
}
finally {
    Close-GzipWriter -WriterState $machineWriter
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

Write-GenerationCheckpoint -OutputPath $OutputPath -Stage 'writing-history-metadata' -CompletedDevices $TargetDeviceCount -TotalDevices $TargetDeviceCount -WrittenCurrentRows $writtenCurrentRows -WrittenHistoryRows $writtenHistoryRows -Stopwatch $generationStopwatch

foreach ($periodKey in @($historyRefsWriters.Keys | Sort-Object)) {
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
    actualDeviceCount = $plans.Count
    includeRawRows = ($IncludeRawRows -eq $true)
    actualCurrentRows = $writtenCurrentRows
    actualHistoryRows = $writtenHistoryRows
    actualTotalVulnRows = ($writtenCurrentRows + $writtenHistoryRows)
    scaleFactor = $scaleFactor
    sourceCurrentRows = $sourceCurrentCount
    sourceHistoryRows = $sourceHistoryCount
    sourceRowProfiles = $rowProfiles.Count
    historyPeriods = @($historyRefsWriters.Keys | Sort-Object)
    advancedHuntingRows = $filteredAdvancedHunting.Count
}
$manifest | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $OutputPath 'synthetic-manifest.json') -Encoding utf8
$generationStopwatch.Stop()
Write-GenerationCheckpoint -OutputPath $OutputPath -Stage 'completed' -CompletedDevices $TargetDeviceCount -TotalDevices $TargetDeviceCount -WrittenCurrentRows $writtenCurrentRows -WrittenHistoryRows $writtenHistoryRows -Stopwatch $generationStopwatch -Extra @{
    advancedHuntingRows = $filteredAdvancedHunting.Count
    historyPeriods = @($historyRefsWriters.Keys | Sort-Object)
}

Write-Output ''
Write-Output 'Synthetic export generation completed.'
Write-Output ("  Output path: {0}" -f ([System.IO.Path]::GetFullPath($OutputPath)))
Write-Output ("  Devices: {0}" -f $plans.Count)
Write-Output ("  Vulnerability rows: {0} current + {1} history = {2} total" -f $writtenCurrentRows, $writtenHistoryRows, ($writtenCurrentRows + $writtenHistoryRows))
Write-Output ("  Advanced Hunting rows: {0}" -f $filteredAdvancedHunting.Count)
Write-Output ("  History periods: {0}" -f ((@($historyRefsWriters.Keys | Sort-Object) -join ', ')))
