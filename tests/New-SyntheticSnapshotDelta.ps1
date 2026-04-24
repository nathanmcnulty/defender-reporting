#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SourcePath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-datasets\synthetic-50k-1_5m'),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-datasets\synthetic-50k-1_5m-delta'),

    [Parameter(Mandatory = $false)]
    [string]$TargetLatestDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd'),

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$CopyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'build\Import-SharedHelpers.ps1')

$script:InvariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
$script:DateShiftDays = 0
$script:ShiftedDateCache = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
$script:ReferenceDeviceMetadataByBaseId = $null
$script:ReferenceGroupIdByGroupName = $null

function Test-EquivalentPath {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Left,

        [Parameter(Mandatory = $true)]
        [string]$Right
    )

    $trimChars = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $leftPath = [System.IO.Path]::GetFullPath($Left).TrimEnd($trimChars)
    $rightPath = [System.IO.Path]::GetFullPath($Right).TrimEnd($trimChars)
    return [System.StringComparer]::OrdinalIgnoreCase.Equals($leftPath, $rightPath)
}

function Get-JsonStringPropertyValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonLine,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    $pattern = '"' + [regex]::Escape($PropertyName) + '"\s*:\s*"(?<value>[^"]*)"'
    $match = [regex]::Match($JsonLine, $pattern)
    if (-not $match.Success) {
        return ''
    }

    return $match.Groups['value'].Value
}

function Get-SyntheticBaseDeviceId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DeviceId
    )

    if ([string]::IsNullOrWhiteSpace($DeviceId)) {
        return ''
    }

    $match = [regex]::Match($DeviceId, '^sim-\d{5}-(?<base>.+)$')
    if ($match.Success) {
        return [string]$match.Groups['base'].Value
    }

    return $DeviceId
}

function Get-ShiftedDateValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value) -or $script:DateShiftDays -eq 0) {
        return $Value
    }

    if ($script:ShiftedDateCache.ContainsKey($Value)) {
        return $script:ShiftedDateCache[$Value]
    }

    $shiftedValue = $Value
    $dateOnly = [datetime]::MinValue
    $dateTimeOffset = [datetimeoffset]::MinValue
    $dateTime = [datetime]::MinValue

    if ([datetime]::TryParseExact($Value, 'yyyy-MM-dd', $script:InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dateOnly)) {
        $shiftedValue = $dateOnly.AddDays($script:DateShiftDays).ToString('yyyy-MM-dd', $script:InvariantCulture)
    }
    elseif ([datetimeoffset]::TryParse($Value, $script:InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$dateTimeOffset)) {
        $shiftedOffset = $dateTimeOffset.AddDays($script:DateShiftDays)
        if ($Value.EndsWith('Z', [System.StringComparison]::OrdinalIgnoreCase)) {
            $shiftedValue = $shiftedOffset.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', $script:InvariantCulture)
        }
        else {
            $shiftedValue = $shiftedOffset.ToString('o', $script:InvariantCulture)
        }
    }
    elseif ([datetime]::TryParse($Value, $script:InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dateTime)) {
        $shiftedValue = $dateTime.ToUniversalTime().AddDays($script:DateShiftDays).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', $script:InvariantCulture)
    }

    $script:ShiftedDateCache[$Value] = $shiftedValue
    return $shiftedValue
}

function Shift-JsonLineDateFields {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper for rewriting JSON date fields during synthetic delta generation.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper accepts multiple field names by design.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonLine,

        [Parameter(Mandatory = $true)]
        [string[]]$FieldNames
    )

    $updatedLine = $JsonLine
    foreach ($fieldName in $FieldNames) {
        $originalValue = Get-JsonStringPropertyValue -JsonLine $updatedLine -PropertyName $fieldName
        if ([string]::IsNullOrWhiteSpace($originalValue)) {
            continue
        }

        $shiftedValue = Get-ShiftedDateValue -Value $originalValue
        $originalAssignment = '"' + $fieldName + '":"' + $originalValue + '"'
        $updatedAssignment = '"' + $fieldName + '":"' + $shiftedValue + '"'

        if ($updatedLine.Contains($originalAssignment)) {
            $updatedLine = $updatedLine.Replace($originalAssignment, $updatedAssignment)
        }
        else {
            $pattern = '"' + [regex]::Escape($fieldName) + '"\s*:\s*"' + [regex]::Escape($originalValue) + '"'
            $updatedLine = [regex]::Replace($updatedLine, $pattern, $updatedAssignment)
        }
    }

    return $updatedLine
}

function Initialize-ReferenceMetadataLookup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReferencePath
    )

    if ($null -ne $script:ReferenceDeviceMetadataByBaseId -and $null -ne $script:ReferenceGroupIdByGroupName) {
        return
    }

    $script:ReferenceDeviceMetadataByBaseId = @{}
    $script:ReferenceGroupIdByGroupName = @{}

    if (-not (Test-Path -LiteralPath $ReferencePath -PathType Container)) {
        return
    }

    $referenceFiles = @()
    $referenceCurrentPath = Get-VulnCurrentPath -BasePath $ReferencePath
    if (Test-Path -LiteralPath $referenceCurrentPath -PathType Leaf) {
        $referenceFiles += $referenceCurrentPath
    }

    $referenceFiles += @(
        Get-ChildItem -LiteralPath $ReferencePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue |
            Sort-Object -Property Name |
            ForEach-Object { $_.FullName }
    )

    foreach ($referenceFile in $referenceFiles) {
        foreach ($line in Read-VulnNdjsonLinesFromPath -Path $referenceFile) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $row = $line | ConvertFrom-Json -Depth 20
            $baseDeviceId = Get-SyntheticBaseDeviceId -DeviceId ([string]$row.DeviceId)
            $groupName = [string]$row.RbacGroupName
            $groupId = [string]$row.RbacGroupId
            $osVersion = [string]$row.OSVersion

            if (-not [string]::IsNullOrWhiteSpace($baseDeviceId)) {
                if (-not $script:ReferenceDeviceMetadataByBaseId.ContainsKey($baseDeviceId)) {
                    $script:ReferenceDeviceMetadataByBaseId[$baseDeviceId] = [ordered]@{
                        GroupName = $groupName
                        GroupId = $groupId
                        OSVersion = $osVersion
                    }
                }
                else {
                    $metadata = $script:ReferenceDeviceMetadataByBaseId[$baseDeviceId]
                    if ([string]::IsNullOrWhiteSpace([string]$metadata.GroupName) -and -not [string]::IsNullOrWhiteSpace($groupName)) {
                        $metadata.GroupName = $groupName
                    }
                    if ([string]::IsNullOrWhiteSpace([string]$metadata.GroupId) -and -not [string]::IsNullOrWhiteSpace($groupId)) {
                        $metadata.GroupId = $groupId
                    }
                    if ([string]::IsNullOrWhiteSpace([string]$metadata.OSVersion) -and -not [string]::IsNullOrWhiteSpace($osVersion)) {
                        $metadata.OSVersion = $osVersion
                    }
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($groupName) -and -not [string]::IsNullOrWhiteSpace($groupId) -and -not $script:ReferenceGroupIdByGroupName.ContainsKey($groupName)) {
                $script:ReferenceGroupIdByGroupName[$groupName] = $groupId
            }
        }
    }
}

function Resolve-ReferenceDeviceMetadata {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DeviceId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$GroupName
    )

    $resolved = [ordered]@{
        GroupId = ''
        OSVersion = ''
    }

    $baseDeviceId = Get-SyntheticBaseDeviceId -DeviceId $DeviceId
    if (-not [string]::IsNullOrWhiteSpace($baseDeviceId) -and $script:ReferenceDeviceMetadataByBaseId.ContainsKey($baseDeviceId)) {
        $metadata = $script:ReferenceDeviceMetadataByBaseId[$baseDeviceId]
        $resolved.GroupId = [string]$metadata.GroupId
        $resolved.OSVersion = [string]$metadata.OSVersion
    }

    if ([string]::IsNullOrWhiteSpace([string]$resolved.GroupId) -and -not [string]::IsNullOrWhiteSpace($GroupName) -and $script:ReferenceGroupIdByGroupName.ContainsKey($GroupName)) {
        $resolved.GroupId = [string]$script:ReferenceGroupIdByGroupName[$GroupName]
    }

    return $resolved
}

function Get-LegacySnapshotGroupIdFromJsonLine {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonLine
    )

    $match = [regex]::Match($JsonLine, '"RbacGroupId"\s*:\s*(?:(?:"(?<text>[^"]*)")|(?<number>-?\d+)|null)')
    if (-not $match.Success) {
        return '0'
    }

    $rawValue = if ($match.Groups['text'].Success) {
        [string]$match.Groups['text'].Value
    }
    elseif ($match.Groups['number'].Success) {
        [string]$match.Groups['number'].Value
    }
    else {
        ''
    }

    if ([string]::IsNullOrWhiteSpace($rawValue)) {
        return '0'
    }

    $trimmed = $rawValue.Trim()
    if ($trimmed -match '^\d+$') {
        return $trimmed
    }

    $digitMatch = [regex]::Match($trimmed, '\d+')
    if ($digitMatch.Success) {
        return [string]$digitMatch.Value
    }

    return '0'
}

function Invoke-CurrentSnapshotJsonLines {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper streams multiple current vulnerability JSON lines by design.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $currentPath = Get-VulnCurrentPath -BasePath $BasePath
    if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
        foreach ($line in Read-VulnNdjsonLinesFromPath -Path $currentPath) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            Write-Output $line
        }

        return
    }

    if (-not (Test-VulnContentStoreExistence -BasePath $BasePath)) {
        throw "Current vulnerability export not found: $currentPath"
    }

    $currentRefsPath = Get-VulnCurrentRefsPath -BasePath $BasePath
    if (-not (Test-Path -LiteralPath $currentRefsPath -PathType Leaf)) {
        throw "Current vulnerability refs were not found: $currentRefsPath"
    }

    $dictionary = Read-VulnContentDictionary -Path (Get-VulnContentDictionaryPath -BasePath $BasePath)
    foreach ($refLine in Read-VulnNdjsonLinesFromPath -Path $currentRefsPath) {
        if ([string]::IsNullOrWhiteSpace($refLine)) {
            continue
        }

        $ref = $refLine | ConvertFrom-Json -Depth 10
        $device = $dictionary.deviceProfiles[[int]$ref[1]]
        $content = $dictionary.contentTemplates[[int]$ref[2]]
        $referenceMetadata = Resolve-ReferenceDeviceMetadata -DeviceId ([string]$device.id) -GroupName ([string]$device.g)
        $row = [PSCustomObject]@{
            Id = [string]$ref[0]
            DeviceId = [string]$device.id
            DeviceName = [string]$device.n
            RbacGroupName = [string]$device.g
            RbacGroupId = [string]$referenceMetadata.GroupId
            OSPlatform = [string]$device.o
            OSVersion = if (-not [string]::IsNullOrWhiteSpace([string]$device.ov)) { [string]$device.ov } else { [string]$referenceMetadata.OSVersion }
            MachineTags = @($device.t)
            CveId = [string]$content.c
            SoftwareVendor = [string]$content.sv
            SoftwareName = [string]$content.sn
            SoftwareVersion = [string]$content.ver
            VulnerabilitySeverityLevel = [string]$content.sev
            CvssScore = $content.sc
            ExploitabilityLevel = [string]$content.ex
            RecommendationReference = [string]$content.rr
            RecommendedSecurityUpdate = [string]$content.ru
            RecommendedSecurityUpdateId = [string]$content.rid
            RecommendedSecurityUpdateUrl = [string]$content.url
            SecurityUpdateAvailable = ($content.ua -eq $true)
            FirstSeenTimestamp = [string]$ref[3]
            LastSeenTimestamp = [string]$ref[4]
            DiskPaths = @($content.dp)
            RegistryPaths = @($content.rp)
            CveBatchTitle = [string]$content.bt
            CveBatchUrl = [string]$content.bu
            IsOnboarded = ($device.ob -eq $true)
        }

        Write-Output (ConvertTo-Json -InputObject $row -Compress -Depth 20)
    }
}

function New-GzipWriterState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper stages gzip output files for this synthetic delta generator.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $directoryPath = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($directoryPath) -and -not (Test-Path -LiteralPath $directoryPath)) {
        $null = New-Item -Path $directoryPath -ItemType Directory -Force
    }

    $fileStream = [System.IO.File]::Create($Path)
    $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
    $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
    return [PSCustomObject]@{
        Path = $Path
        FileStream = $fileStream
        GzipStream = $gzipStream
        Writer = $writer
        RowCount = 0
    }
}

function Close-GzipWriterState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $State
    )

    if ($null -eq $State) {
        return
    }

    if ($State.Writer) {
        $State.Writer.Dispose()
        $State.Writer = $null
    }
    elseif ($State.GzipStream) {
        $State.GzipStream.Dispose()
        $State.GzipStream = $null
    }
    elseif ($State.FileStream) {
        $State.FileStream.Dispose()
        $State.FileStream = $null
    }
}

function Get-SnapshotWriterState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$WritersByGroup,

        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate,

        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    if (-not $WritersByGroup.ContainsKey($GroupId)) {
        $path = Join-Path -Path $OutputRoot -ChildPath ('VulnExport_{0}_{1}.json.gz' -f $GroupId, $SnapshotDate)
        $WritersByGroup[$GroupId] = New-GzipWriterState -Path $path
    }

    return $WritersByGroup[$GroupId]
}

function Close-SnapshotWriterStates {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper closes all tracked gzip writer states.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$WritersByGroup
    )

    foreach ($groupId in @($WritersByGroup.Keys)) {
        Close-GzipWriterState -State $WritersByGroup[$groupId]
    }
}

function Copy-OrLinkFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper stages a read-only overlay dataset by linking or copying unchanged files.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceFilePath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationFilePath,

        [Parameter(Mandatory = $true)]
        [bool]$CopyOnly,

        [Parameter(Mandatory = $true)]
        [ref]$LinkedFileCount,

        [Parameter(Mandatory = $true)]
        [ref]$CopiedFileCount
    )

    $destinationDirectory = Split-Path -Path $DestinationFilePath -Parent
    if (-not [string]::IsNullOrWhiteSpace($destinationDirectory) -and -not (Test-Path -LiteralPath $destinationDirectory)) {
        $null = New-Item -Path $destinationDirectory -ItemType Directory -Force
    }

    if (Test-Path -LiteralPath $DestinationFilePath -PathType Leaf) {
        Remove-Item -LiteralPath $DestinationFilePath -Force -ErrorAction SilentlyContinue
    }

    $linked = $false
    if ((-not $CopyOnly) -and $IsWindows) {
        $sourceRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($SourceFilePath))
        $destinationRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($DestinationFilePath))
        if ([System.StringComparer]::OrdinalIgnoreCase.Equals($sourceRoot, $destinationRoot)) {
            try {
                $null = New-Item -ItemType HardLink -Path $DestinationFilePath -Target $SourceFilePath -ErrorAction Stop
                $linked = $true
            }
            catch {
                $linked = $false
            }
        }
    }

    if ($linked) {
        $LinkedFileCount.Value++
        return
    }

    Copy-Item -LiteralPath $SourceFilePath -Destination $DestinationFilePath -Force
    $CopiedFileCount.Value++
}

$resolvedSourcePath = [System.IO.Path]::GetFullPath($SourcePath)
$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$resolvedTargetLatestDate = Convert-ToYmdDate -DateValue $TargetLatestDate

if (-not (Test-Path -LiteralPath $resolvedSourcePath -PathType Container)) {
    throw "Source path not found: $resolvedSourcePath"
}

if ([string]::IsNullOrWhiteSpace($resolvedTargetLatestDate)) {
    throw "Unable to parse TargetLatestDate '$TargetLatestDate' as yyyy-MM-dd."
}

if (Test-EquivalentPath -Left $resolvedSourcePath -Right $resolvedOutputPath) {
    throw 'OutputPath must differ from SourcePath.'
}

if (Test-Path -LiteralPath $resolvedOutputPath) {
    if (-not $Force) {
        throw "Output path already exists: $resolvedOutputPath"
    }

    Remove-Item -LiteralPath $resolvedOutputPath -Recurse -Force -ErrorAction SilentlyContinue
}

$null = New-Item -Path $resolvedOutputPath -ItemType Directory -Force

$sourceManifestPath = Join-Path $resolvedSourcePath 'synthetic-manifest.json'
$sourceManifest = if (Test-Path -LiteralPath $sourceManifestPath -PathType Leaf) {
    Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json -Depth 20
}
else {
    $null
}

$sourceMachinePath = Get-MachineCurrentPath -BasePath $resolvedSourcePath
$sourceAdvancedHuntingPath = Get-AdvancedHuntingCurrentPath -BasePath $resolvedSourcePath
$referencePath = Join-Path $repoRoot 'exports'

Initialize-ReferenceMetadataLookup -ReferencePath $referencePath

if (-not (Test-Path -LiteralPath $sourceMachinePath -PathType Leaf)) {
    throw "Machine export not found: $sourceMachinePath"
}

$sourceLatestDate = Get-VulnStoreLatestSnapshotDate -BasePath $resolvedSourcePath
if ([string]::IsNullOrWhiteSpace($sourceLatestDate)) {
    throw "Unable to determine the latest vulnerability snapshot date in '$resolvedSourcePath'."
}

$script:DateShiftDays = [int](New-TimeSpan -Start ([datetime]$sourceLatestDate) -End ([datetime]$resolvedTargetLatestDate)).TotalDays
if ($script:DateShiftDays -le 0) {
    throw "TargetLatestDate '$resolvedTargetLatestDate' must be later than the source latest date '$sourceLatestDate' to create a synthetic delta snapshot."
}

$linkedFileCount = 0
$copiedFileCount = 0
$seedFileNames = @(
    Get-ChildItem -LiteralPath $resolvedSourcePath -File |
        Where-Object {
            $_.Name -match '\.json(\.gz)?$' -and
            $_.Name -notin @(
                '.synthetic-progress.json',
                '.synthetic-progress.json.gz',
                'stress-validation-report.json',
                'stress-validation-report.json.gz',
                'synthetic-manifest.json',
                'benchmark-dataset.json',
                (Split-Path -Path $sourceMachinePath -Leaf)
            ) -and
            (-not (Test-IsLegacyVulnSnapshotFileName -Name $_.Name))
        } |
        Sort-Object -Property Name
)

foreach ($file in $seedFileNames) {
    Copy-OrLinkFile `
        -SourceFilePath $file.FullName `
        -DestinationFilePath (Join-Path $resolvedOutputPath $file.Name) `
        -CopyOnly ($CopyOnly -eq $true) `
        -LinkedFileCount ([ref]$linkedFileCount) `
        -CopiedFileCount ([ref]$copiedFileCount)
}

Write-Host ('Source latest date: {0}' -f $sourceLatestDate)
Write-Host ('Target latest date: {0}' -f $resolvedTargetLatestDate)
Write-Host ('Creating synthetic delta snapshot: +{0} day(s)' -f $script:DateShiftDays)

$machineWriter = $null
$machineCount = 0
try {
    Write-Host 'Shifting machine current snapshot...'
    $machineWriter = New-GzipWriterState -Path (Get-MachineCurrentPath -BasePath $resolvedOutputPath)
    foreach ($line in Read-VulnNdjsonLinesFromPath -Path $sourceMachinePath) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $shiftedMachineLine = Shift-JsonLineDateFields -JsonLine $line -FieldNames @('firstSeen', 'lastSeen', 'observedOn')
        $machineDeviceId = Get-JsonStringPropertyValue -JsonLine $shiftedMachineLine -PropertyName 'id'
        $machineGroupName = Get-JsonStringPropertyValue -JsonLine $shiftedMachineLine -PropertyName 'rbacGroupName'
        $machineOsVersion = Get-JsonStringPropertyValue -JsonLine $shiftedMachineLine -PropertyName 'osVersion'
        if ([string]::IsNullOrWhiteSpace($machineOsVersion)) {
            $referenceMetadata = Resolve-ReferenceDeviceMetadata -DeviceId $machineDeviceId -GroupName $machineGroupName
            if (-not [string]::IsNullOrWhiteSpace([string]$referenceMetadata.OSVersion)) {
                $pattern = '"osVersion"\s*:\s*(?:null|"")'
                $replacement = '"osVersion":"' + [string]$referenceMetadata.OSVersion + '"'
                $shiftedMachineLine = [regex]::Replace($shiftedMachineLine, $pattern, $replacement, 1)
            }
        }

        $machineWriter.Writer.WriteLine($shiftedMachineLine)
        $machineCount++
    }
}
finally {
    Close-GzipWriterState -State $machineWriter
}

$snapshotWriterStates = @{}
$deltaRowCount = 0
try {
    Write-Host 'Writing legacy vulnerability snapshot delta files...'
    foreach ($line in Invoke-CurrentSnapshotJsonLines -BasePath $resolvedSourcePath) {
        $shiftedLine = Shift-JsonLineDateFields -JsonLine $line -FieldNames @('FirstSeenTimestamp', 'LastSeenTimestamp')
        $groupId = Get-LegacySnapshotGroupIdFromJsonLine -JsonLine $shiftedLine
        $writerState = Get-SnapshotWriterState -WritersByGroup $snapshotWriterStates -OutputRoot $resolvedOutputPath -SnapshotDate $resolvedTargetLatestDate -GroupId $groupId
        $writerState.Writer.WriteLine($shiftedLine)
        $writerState.RowCount++
        $deltaRowCount++
    }
}
finally {
    Close-SnapshotWriterStates -WritersByGroup $snapshotWriterStates
}

if ($deltaRowCount -le 0) {
    throw 'The source current vulnerability store contained no rows to project into a synthetic delta snapshot.'
}

$deltaSnapshotFiles = @(
    Get-ChildItem -LiteralPath $resolvedOutputPath -Filter ('VulnExport_*_{0}.json.gz' -f $resolvedTargetLatestDate) -File -ErrorAction SilentlyContinue |
        Sort-Object -Property Name |
        ForEach-Object { $_.Name }
)

$manifest = [ordered]@{
    preset = 'SyntheticSnapshotDelta'
    generatedOnUtc = [datetime]::UtcNow.ToString('o')
    sourcePath = $resolvedSourcePath
    outputPath = $resolvedOutputPath
    sourcePreset = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['preset']) { [string]$sourceManifest.preset } else { $null }
    sourceSeed = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['seed']) { $sourceManifest.seed } else { $null }
    sourceGeneratedOnUtc = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['generatedOnUtc']) { [string]$sourceManifest.generatedOnUtc } else { $null }
    sourceLatestDate = $sourceLatestDate
    targetLatestDate = $resolvedTargetLatestDate
    dateShiftDays = $script:DateShiftDays
    deltaSnapshotDate = $resolvedTargetLatestDate
    deltaSnapshotFiles = $deltaSnapshotFiles
    deltaSnapshotRows = $deltaRowCount
    snapshotGroupCount = $deltaSnapshotFiles.Count
    actualDeviceCount = $machineCount
    actualCurrentRows = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['actualCurrentRows']) { [int]$sourceManifest.actualCurrentRows } else { $deltaRowCount }
    actualHistoryRows = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['actualHistoryRows']) { [int]$sourceManifest.actualHistoryRows } else { 0 }
    actualTotalVulnRows = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['actualTotalVulnRows']) { [int]$sourceManifest.actualTotalVulnRows } else { $deltaRowCount }
    targetDeviceCount = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['targetDeviceCount']) { [int]$sourceManifest.targetDeviceCount } else { $machineCount }
    targetTotalVulnRows = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['targetTotalVulnRows']) { [int]$sourceManifest.targetTotalVulnRows } else { $deltaRowCount }
    hardLinkedSeedFiles = $linkedFileCount
    copiedSeedFiles = $copiedFileCount
    contentStoreReady = (Test-VulnContentStoreExistence -BasePath $resolvedOutputPath)
    advancedHuntingCopied = (Test-Path -LiteralPath (Join-Path $resolvedOutputPath (Split-Path -Path $sourceAdvancedHuntingPath -Leaf)) -PathType Leaf)
}

$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $resolvedOutputPath 'synthetic-manifest.json') -Encoding utf8

Write-Host ''
Write-Host ('Synthetic delta overlay created at: {0}' -f $resolvedOutputPath) -ForegroundColor Green
Write-Host ('  Seed files: {0} hard-linked, {1} copied' -f $linkedFileCount, $copiedFileCount)
Write-Host ('  Shifted machine rows: {0}' -f $machineCount)
Write-Host ('  Delta snapshot rows: {0}' -f $deltaRowCount)
Write-Host ('  Delta snapshot files: {0}' -f ($deltaSnapshotFiles -join ', '))