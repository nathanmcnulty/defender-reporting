#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SourcePath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports-synthetic'),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports-synthetic-live'),

    [Parameter(Mandatory = $false)]
    [string]$TargetLatestDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd'),

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$SkipContentStoreSidecars
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'build\Import-SharedHelpers.ps1')

$script:InvariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
$script:DateShiftDays = 0
$script:ShiftedDateCache = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)

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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper for rewriting JSON date fields during synthetic export generation.')]
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

function New-GzipWriterState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper used only by this script to stage output files.')]
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

function Get-HistoryAppendState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AppendStates,

        [Parameter(Mandatory = $true)]
        [string]$ScratchRoot,

        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    if (-not $AppendStates.ContainsKey($PeriodKey)) {
        $appendPath = Join-Path -Path $ScratchRoot -ChildPath ("VulnHistory_{0}.append.ndjson" -f $PeriodKey)
        $AppendStates[$PeriodKey] = [PSCustomObject]@{
            PeriodKey = $PeriodKey
            AppendPath = $appendPath
            Writer = [System.IO.StreamWriter]::new($appendPath, $false, [System.Text.UTF8Encoding]::new($false))
            LatestDate = ''
            Count = 0
        }
    }

    return $AppendStates[$PeriodKey]
}

function Close-HistoryAppendStates {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper closes all tracked append writer states.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AppendStates
    )

    foreach ($periodKey in @($AppendStates.Keys)) {
        $state = $AppendStates[$periodKey]
        if ($null -ne $state -and $null -ne $state.Writer) {
            $state.Writer.Dispose()
            $state.Writer = $null
        }
    }
}

function Sort-AppendFileBySnapshotDate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper returns the sorted append file path.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $sortedPath = $Path + '.sorted'
    if (Test-Path -LiteralPath $sortedPath) {
        Remove-Item -LiteralPath $sortedPath -Force
    }

    if ($IsWindows) {
        $sortCommand = Get-Command -Name 'sort.exe' -ErrorAction SilentlyContinue
        if ($null -ne $sortCommand) {
            & $sortCommand.Source /o $sortedPath $Path | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to sort append file '$Path'."
            }
        }
        else {
            Get-Content -LiteralPath $Path | Sort-Object | Set-Content -LiteralPath $sortedPath -Encoding utf8
        }
    }
    else {
        $sortCommand = Get-Command -Name 'sort' -ErrorAction SilentlyContinue
        if ($null -ne $sortCommand) {
            & $sortCommand.Source -o $sortedPath $Path | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to sort append file '$Path'."
            }
        }
        else {
            Get-Content -LiteralPath $Path | Sort-Object | Set-Content -LiteralPath $sortedPath -Encoding utf8
        }
    }

    return $sortedPath
}

function Get-DatasetLatestObservationDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $latestDate = ''
    foreach ($historyFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $latestDate = Get-MaxVulnDate -Primary $latestDate -Secondary (Get-VulnHistoryFileLatestDate -Path $historyFile.FullName)
    }

    $currentPath = Get-VulnCurrentPath -BasePath $BasePath
    if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
        foreach ($line in Read-VulnNdjsonLinesFromPath -Path $currentPath) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $lastSeen = Convert-ToYmdDate -DateValue (Get-JsonStringPropertyValue -JsonLine $line -PropertyName 'LastSeenTimestamp')
            $latestDate = Get-MaxVulnDate -Primary $latestDate -Secondary $lastSeen
        }
    }

    if ([string]::IsNullOrWhiteSpace($latestDate)) {
        throw "Unable to determine the latest observation date in '$BasePath'."
    }

    return $latestDate
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

if ([System.StringComparer]::OrdinalIgnoreCase.Equals($resolvedSourcePath.TrimEnd('\', '/'), $resolvedOutputPath.TrimEnd('\', '/'))) {
    throw 'OutputPath must differ from SourcePath.'
}

if (Test-Path -LiteralPath $resolvedOutputPath) {
    if (-not $Force) {
        throw "Output path already exists: $resolvedOutputPath"
    }

    Remove-Item -LiteralPath $resolvedOutputPath -Recurse -Force
}

$null = New-Item -Path $resolvedOutputPath -ItemType Directory -Force
$scratchRoot = Join-Path -Path $resolvedOutputPath -ChildPath '.history-append'
$null = New-Item -Path $scratchRoot -ItemType Directory -Force

$sourceManifestPath = Join-Path -Path $resolvedSourcePath -ChildPath 'synthetic-manifest.json'
$sourceManifest = if (Test-Path -LiteralPath $sourceManifestPath -PathType Leaf) {
    Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json -Depth 20
}
else {
    $null
}

$sourceLatestDate = Get-DatasetLatestObservationDate -BasePath $resolvedSourcePath
$script:DateShiftDays = [int](New-TimeSpan -Start ([datetime]$sourceLatestDate) -End ([datetime]$resolvedTargetLatestDate)).TotalDays
if ($script:DateShiftDays -lt 0) {
    throw "TargetLatestDate '$resolvedTargetLatestDate' is earlier than the source latest date '$sourceLatestDate'."
}

Write-Host ("Source latest date: {0}" -f $sourceLatestDate)
Write-Host ("Target latest date: {0}" -f $resolvedTargetLatestDate)
Write-Host ("Applying synthetic live-export shift: +{0} day(s)" -f $script:DateShiftDays)

$machineCount = 0
$currentRowCount = 0
$historyRowCount = 0
$historyAppendStates = @{}

$sourceCurrentPath = Get-VulnCurrentPath -BasePath $resolvedSourcePath
$sourceMachinePath = Get-MachineCurrentPath -BasePath $resolvedSourcePath
$sourceAdvancedHuntingPath = Get-AdvancedHuntingCurrentPath -BasePath $resolvedSourcePath

if (-not (Test-Path -LiteralPath $sourceCurrentPath -PathType Leaf)) {
    throw "Current vulnerability export not found: $sourceCurrentPath"
}

if (-not (Test-Path -LiteralPath $sourceMachinePath -PathType Leaf)) {
    throw "Machine export not found: $sourceMachinePath"
}

$currentWriter = $null
$machineWriter = $null

try {
    Write-Host 'Shifting current vulnerability rows...'
    $currentWriter = New-GzipWriterState -Path (Get-VulnCurrentPath -BasePath $resolvedOutputPath)
    foreach ($line in Read-VulnNdjsonLinesFromPath -Path $sourceCurrentPath) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $currentWriter.Writer.WriteLine((Shift-JsonLineDateFields -JsonLine $line -FieldNames @('FirstSeenTimestamp', 'LastSeenTimestamp')))
        $currentRowCount++
    }

    Write-Host 'Shifting machine current snapshot...'
    $machineWriter = New-GzipWriterState -Path (Get-MachineCurrentPath -BasePath $resolvedOutputPath)
    foreach ($line in Read-VulnNdjsonLinesFromPath -Path $sourceMachinePath) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $machineWriter.Writer.WriteLine((Shift-JsonLineDateFields -JsonLine $line -FieldNames @('firstSeen', 'lastSeen', 'observedOn')))
        $machineCount++
    }

    Write-Host 'Shifting history rows and repartitioning by quarter...'
    foreach ($historyRowsFile in @(Get-ChildItem -Path $resolvedSourcePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        foreach ($line in Read-VulnNdjsonLinesFromPath -Path $historyRowsFile.FullName) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            $shiftedLastSeen = Get-ShiftedDateValue -Value (Get-JsonStringPropertyValue -JsonLine $line -PropertyName 'LastSeenTimestamp')
            $shiftedLine = Shift-JsonLineDateFields -JsonLine $line -FieldNames @('FirstSeenTimestamp', 'LastSeenTimestamp')
            $snapshotDate = Convert-ToYmdDate -DateValue $shiftedLastSeen
            if ([string]::IsNullOrWhiteSpace($snapshotDate)) {
                throw "History row in '$($historyRowsFile.FullName)' is missing LastSeenTimestamp after shifting."
            }

            $periodKey = Get-VulnHistoryPeriodKeyFromDate -Date $snapshotDate
            $appendState = Get-HistoryAppendState -AppendStates $historyAppendStates -ScratchRoot $scratchRoot -PeriodKey $periodKey
            $appendState.Writer.WriteLine($snapshotDate + "`t" + '{"reason":"removed","row":' + $shiftedLine + '}')
            $appendState.LatestDate = Get-MaxVulnDate -Primary ([string]$appendState.LatestDate) -Secondary $snapshotDate
            $appendState.Count++
            $historyRowCount++
        }
    }
}
finally {
    Close-GzipWriterState -State $currentWriter
    Close-GzipWriterState -State $machineWriter
    Close-HistoryAppendStates -AppendStates $historyAppendStates
}

$historyPeriods = @($historyAppendStates.Keys | Sort-Object)
foreach ($periodKey in $historyPeriods) {
    $appendState = $historyAppendStates[$periodKey]
    $sortedAppendPath = Sort-AppendFileBySnapshotDate -Path $appendState.AppendPath

    Write-VulnHistoryDocumentFromAppendFile `
        -Path (Get-VulnHistoryPath -BasePath $resolvedOutputPath -PeriodKey $periodKey) `
        -PeriodKey $periodKey `
        -AppendPath $sortedAppendPath `
        -LatestDate $appendState.LatestDate

    Write-VulnHistoryRowsFileFromAppendFile `
        -Path (Get-VulnHistoryRowsPath -BasePath $resolvedOutputPath -PeriodKey $periodKey) `
        -AppendPath $sortedAppendPath
}

if (Test-Path -LiteralPath $sourceAdvancedHuntingPath -PathType Leaf) {
    Write-Host 'Copying Advanced Hunting export...'
    Copy-Item -LiteralPath $sourceAdvancedHuntingPath -Destination (Get-AdvancedHuntingCurrentPath -BasePath $resolvedOutputPath) -Force
}

if ($SkipContentStoreSidecars) {
    Write-Host 'Skipping content-store sidecar generation.'
}
else {
    Write-Host 'Rebuilding vulnerability content store sidecars...'
    Publish-VulnContentStoreUnlocked -BasePath $resolvedOutputPath

    if (-not (Test-VulnContentStoreExistence -BasePath $resolvedOutputPath)) {
        throw "Content store sidecars were not generated successfully for '$resolvedOutputPath'."
    }
}

foreach ($historyFile in @(Get-ChildItem -Path $resolvedOutputPath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
    [void](Test-VulnHistoryFileLightweight -Path $historyFile.FullName)
}

$advancedHuntingRows = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['advancedHuntingRows']) {
    [int]$sourceManifest.advancedHuntingRows
}
elseif (Test-Path -LiteralPath $sourceAdvancedHuntingPath -PathType Leaf) {
    @(Read-VulnNdjsonLinesFromPath -Path $sourceAdvancedHuntingPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
}
else {
    0
}

$manifest = [ordered]@{
    preset = 'ShiftedSyntheticLiveExport'
    generatedOnUtc = [datetime]::UtcNow.ToString('o')
    sourcePath = $resolvedSourcePath
    outputPath = $resolvedOutputPath
    sourcePreset = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['preset']) { [string]$sourceManifest.preset } else { $null }
    sourceSeed = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['seed']) { $sourceManifest.seed } else { $null }
    sourceGeneratedOnUtc = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['generatedOnUtc']) { [string]$sourceManifest.generatedOnUtc } else { $null }
    sourceLatestDate = $sourceLatestDate
    targetLatestDate = $resolvedTargetLatestDate
    dateShiftDays = $script:DateShiftDays
    targetDeviceCount = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['targetDeviceCount']) { [int]$sourceManifest.targetDeviceCount } else { $machineCount }
    targetTotalVulnRows = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['targetTotalVulnRows']) { [int]$sourceManifest.targetTotalVulnRows } else { ($currentRowCount + $historyRowCount) }
    targetCurrentRows = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['targetCurrentRows']) { [int]$sourceManifest.targetCurrentRows } else { $currentRowCount }
    targetHistoryRows = if ($null -ne $sourceManifest -and $sourceManifest.PSObject.Properties['targetHistoryRows']) { [int]$sourceManifest.targetHistoryRows } else { $historyRowCount }
    actualDeviceCount = $machineCount
    includeRawRows = $true
    actualCurrentRows = $currentRowCount
    actualHistoryRows = $historyRowCount
    actualTotalVulnRows = ($currentRowCount + $historyRowCount)
    historyPeriods = $historyPeriods
    advancedHuntingRows = $advancedHuntingRows
    contentStoreReady = ((-not $SkipContentStoreSidecars) -and (Test-VulnContentStoreExistence -BasePath $resolvedOutputPath))
}

$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $resolvedOutputPath 'synthetic-manifest.json') -Encoding utf8

if (Test-Path -LiteralPath $scratchRoot) {
    Remove-Item -LiteralPath $scratchRoot -Recurse -Force
}

Write-Host ''
Write-Host ('Synthetic live export created at: {0}' -f $resolvedOutputPath) -ForegroundColor Green
Write-Host ('  Devices: {0}' -f $machineCount)
Write-Host ('  Vulnerability rows: {0} current + {1} history = {2} total' -f $currentRowCount, $historyRowCount, ($currentRowCount + $historyRowCount))
Write-Host ('  History periods: {0}' -f ($(if ($historyPeriods.Count -gt 0) { $historyPeriods -join ', ' } else { '(none)' })))
