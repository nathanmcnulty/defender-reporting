#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SourcePath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports-synthetic-live'),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports-synthetic-legacy'),

    [Parameter(Mandatory = $false)]
    [string[]]$SnapshotDates,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 31)]
    [int]$SnapshotCount = 2,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1000, 5000000)]
    [int]$ProgressIntervalRows = 100000,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'build\Import-SharedHelpers.ps1')

function Get-HistoryRowsReadPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$HistoryFile
    )

    $periodKey = Get-VulnHistoryPeriodKeyFromFileName -Name $HistoryFile.Name
    if ([string]::IsNullOrWhiteSpace($periodKey)) {
        return $HistoryFile.FullName
    }

    $rowsPath = Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodKey
    if (Test-Path -LiteralPath $rowsPath -PathType Leaf) {
        return $rowsPath
    }

    $legacyRowsPath = $rowsPath -replace '\.gz$', ''
    if (Test-Path -LiteralPath $legacyRowsPath -PathType Leaf) {
        return $legacyRowsPath
    }

    return $HistoryFile.FullName
}

function Invoke-SourceVulnRows {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper streams multiple vulnerability rows by design.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Process
    )

    $currentPath = Get-VulnCurrentPath -BasePath $BasePath
    if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
        Read-VulnNdjsonRecordsFromPath -Path $currentPath | ForEach-Object {
            & $Process $_ 'current'
        }
    }

    foreach ($historyFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $readPath = Get-HistoryRowsReadPath -BasePath $BasePath -HistoryFile $historyFile
        if ([System.StringComparer]::OrdinalIgnoreCase.Equals($readPath, $historyFile.FullName)) {
            Read-VulnHistoryRowsFromPath -Path $readPath | ForEach-Object {
                & $Process $_ 'history'
            }
            continue
        }

        Read-VulnNdjsonRecordsFromPath -Path $readPath | ForEach-Object {
            & $Process $_ 'history'
        }
    }
}

function Resolve-SnapshotDateList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$RequestedDates,

        [Parameter(Mandatory = $true)]
        [int]$SnapshotCount,

        [Parameter(Mandatory = $true)]
        [ref]$CurrentRowCount,

        [Parameter(Mandatory = $true)]
        [ref]$HistoryRowCount,

        [Parameter(Mandatory = $true)]
        [ref]$DistinctLastSeenDateCount
    )

    if ($null -ne $RequestedDates -and $RequestedDates.Count -gt 0) {
        $normalizedDates = [System.Collections.Generic.List[string]]::new()
        foreach ($requestedDate in @($RequestedDates)) {
            $normalizedDate = Convert-ToYmdDate -DateValue $requestedDate
            if ([string]::IsNullOrWhiteSpace($normalizedDate)) {
                throw "Unable to parse snapshot date '$requestedDate' as yyyy-MM-dd."
            }

            if (-not $normalizedDates.Contains($normalizedDate)) {
                $normalizedDates.Add($normalizedDate)
            }
        }

        $CurrentRowCount.Value = 0
        $HistoryRowCount.Value = 0
        Invoke-SourceVulnRows -BasePath $BasePath -Process {
            param($Row, [string]$Kind)

            [void]$Row

            if ($Kind -eq 'current') {
                $CurrentRowCount.Value++
            }
            else {
                $HistoryRowCount.Value++
            }
        }
        $DistinctLastSeenDateCount.Value = $normalizedDates.Count
        return [string[]]@($normalizedDates | Sort-Object)
    }

    $dateCounts = @{}
    $CurrentRowCount.Value = 0
    $HistoryRowCount.Value = 0
    Invoke-SourceVulnRows -BasePath $BasePath -Process {
        param($Row, [string]$Kind)

        if ($Kind -eq 'current') {
            $CurrentRowCount.Value++
        }
        else {
            $HistoryRowCount.Value++
        }

        $lastSeenDate = Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $Row -Name 'LastSeenTimestamp')
        if ([string]::IsNullOrWhiteSpace($lastSeenDate)) {
            return
        }

        if (-not $dateCounts.ContainsKey($lastSeenDate)) {
            $dateCounts[$lastSeenDate] = 0
        }
        $dateCounts[$lastSeenDate]++
    }

    $DistinctLastSeenDateCount.Value = $dateCounts.Keys.Count
    if ($dateCounts.Keys.Count -eq 0) {
        throw "Unable to find any vulnerability rows with a LastSeenTimestamp in '$BasePath'."
    }

    return [string[]]@(
        $dateCounts.Keys |
            Sort-Object -Descending |
            Select-Object -First $SnapshotCount |
            Sort-Object
    )
}

function Get-LegacySnapshotGroupId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $groupId = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RbacGroupId')
    if ([string]::IsNullOrWhiteSpace($groupId)) {
        return '0'
    }

    $trimmed = $groupId.Trim()
    if ($trimmed -match '^\d+$') {
        return $trimmed
    }

    $digitMatch = [regex]::Match($trimmed, '\d+')
    if ($digitMatch.Success) {
        return $digitMatch.Value
    }

    return '0'
}

function Test-RowActiveOnSnapshotDate {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Row,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate
    )

    $firstSeenDate = Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $Row -Name 'FirstSeenTimestamp')
    $lastSeenDate = Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $Row -Name 'LastSeenTimestamp')

    if ([string]::IsNullOrWhiteSpace($lastSeenDate)) {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($firstSeenDate)) {
        $firstSeenDate = $lastSeenDate
    }

    return (($firstSeenDate -le $SnapshotDate) -and ($lastSeenDate -ge $SnapshotDate))
}

function New-GzipWriterState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper stages gzip output writers for this synthetic data generator.')]
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
        [hashtable]$WriterStates,

        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate,

        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )

    $key = $SnapshotDate + '|' + $GroupId
    if (-not $WriterStates.ContainsKey($key)) {
        $filePath = Join-Path -Path $OutputRoot -ChildPath ("VulnExport_{0}_{1}.json.gz" -f $GroupId, $SnapshotDate)
        $WriterStates[$key] = New-GzipWriterState -Path $filePath
    }

    return $WriterStates[$key]
}

$resolvedSourcePath = [System.IO.Path]::GetFullPath($SourcePath)
$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)

if (-not (Test-Path -LiteralPath $resolvedSourcePath -PathType Container)) {
    throw "Source path not found: $resolvedSourcePath"
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

$currentRowCount = 0
$historyRowCount = 0
$distinctLastSeenDateCount = 0
$resolvedSnapshotDates = Resolve-SnapshotDateList `
    -BasePath $resolvedSourcePath `
    -RequestedDates $SnapshotDates `
    -SnapshotCount $SnapshotCount `
    -CurrentRowCount ([ref]$currentRowCount) `
    -HistoryRowCount ([ref]$historyRowCount) `
    -DistinctLastSeenDateCount ([ref]$distinctLastSeenDateCount)

$progressUpdateIntervalRows = $ProgressIntervalRows

if ($resolvedSnapshotDates.Count -eq 0) {
    throw "No snapshot dates were selected from '$resolvedSourcePath'."
}

Write-Host ('Selected snapshot dates: {0}' -f ($resolvedSnapshotDates -join ', ')) -ForegroundColor Cyan

$writerStates = @{}
$rowsPerSnapshotDate = @{}
$groupsPerSnapshotDate = @{}
$sourceRowsProcessed = 0
$generationStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
    foreach ($snapshotDate in $resolvedSnapshotDates) {
        $rowsPerSnapshotDate[$snapshotDate] = 0
        $groupsPerSnapshotDate[$snapshotDate] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    }

    Invoke-SourceVulnRows -BasePath $resolvedSourcePath -Process {
        param($Row, [string]$Kind)

        [void]$Kind

        $sourceRowsProcessed++
        $groupId = Get-LegacySnapshotGroupId -Row $Row
        foreach ($snapshotDate in $resolvedSnapshotDates) {
            if (-not (Test-RowActiveOnSnapshotDate -Row $Row -SnapshotDate $snapshotDate)) {
                continue
            }

            $writerState = Get-SnapshotWriterState -WriterStates $writerStates -OutputRoot $resolvedOutputPath -SnapshotDate $snapshotDate -GroupId $groupId
            $writerState.Writer.WriteLine((Convert-VulnObjectToCompactJson -InputObject $Row -Depth 20))
            $writerState.RowCount++
            $rowsPerSnapshotDate[$snapshotDate] = [int]$rowsPerSnapshotDate[$snapshotDate] + 1
            [void]$groupsPerSnapshotDate[$snapshotDate].Add($groupId)
        }

        if (($sourceRowsProcessed % $progressUpdateIntervalRows) -eq 0) {
            Write-Host ('[{0}] Processed {1} source rows in {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $sourceRowsProcessed, $generationStopwatch.Elapsed.ToString('hh\:mm\:ss'))
        }
    }
}
finally {
    foreach ($writerState in @($writerStates.Values)) {
        Close-GzipWriterState -State $writerState
    }
}

$emptySnapshotDates = @($resolvedSnapshotDates | Where-Object { [int]$rowsPerSnapshotDate[$_] -eq 0 })
if ($emptySnapshotDates.Count -gt 0) {
    throw ("No rows were materialized for snapshot date(s): {0}" -f ($emptySnapshotDates -join ', '))
}

$snapshotFiles = @(
    Get-ChildItem -Path $resolvedOutputPath -Filter 'VulnExport_*.json.gz' -File -ErrorAction SilentlyContinue |
        Sort-Object Name |
        Select-Object -ExpandProperty Name
)

$manifest = [PSCustomObject]@{
    preset = 'SyntheticLegacyVulnSnapshotSet'
    generatedOnUtc = [datetime]::UtcNow.ToString('o')
    sourcePath = $resolvedSourcePath
    outputPath = $resolvedOutputPath
    snapshotDates = @($resolvedSnapshotDates)
    snapshotCount = $resolvedSnapshotDates.Count
    sourceCurrentRows = $currentRowCount
    sourceHistoryRows = $historyRowCount
    sourceTotalRows = ($currentRowCount + $historyRowCount)
    distinctLastSeenDates = $distinctLastSeenDateCount
    snapshotRows = @(
        foreach ($snapshotDate in $resolvedSnapshotDates) {
            [PSCustomObject]@{
                date = $snapshotDate
                rowCount = [int]$rowsPerSnapshotDate[$snapshotDate]
                groupCount = $groupsPerSnapshotDate[$snapshotDate].Count
                groupIds = @($groupsPerSnapshotDate[$snapshotDate] | Sort-Object)
            }
        }
    )
    snapshotFiles = $snapshotFiles
}
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $resolvedOutputPath 'synthetic-legacy-manifest.json') -Encoding utf8

$generationStopwatch.Stop()

Write-Host ''
Write-Host ('Synthetic legacy vulnerability snapshot set created at: {0}' -f $resolvedOutputPath) -ForegroundColor Green
Write-Host ('  Snapshot dates: {0}' -f ($resolvedSnapshotDates -join ', '))
Write-Host ('  Snapshot files: {0}' -f $snapshotFiles.Count)
Write-Host ('  Source rows: {0} current + {1} history = {2} total' -f $currentRowCount, $historyRowCount, ($currentRowCount + $historyRowCount))
foreach ($snapshotDate in $resolvedSnapshotDates) {
    Write-Host ('  {0}: {1} rows across {2} group file(s)' -f $snapshotDate, [int]$rowsPerSnapshotDate[$snapshotDate], $groupsPerSnapshotDate[$snapshotDate].Count)
}