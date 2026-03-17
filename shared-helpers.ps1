Set-StrictMode -Version Latest

# Canonical shared helper surface for the Defender reporting scripts.
#
# This file is the authoritative source for reusable logic shared by:
# - Invoke-VulnerabilityExport.ps1
# - Generate-VulnerabilityDashboard.ps1
# - the generated Azure Automation runbook
#
# TEMPORARY THROUGH 2026-07-01:
# The vulnerability current/history migration and legacy compatibility paths
# remain here in a dedicated section so they can be removed cleanly once all
# callers have upgraded off the legacy VulnExport_<group>_<date>.json(.gz)
# snapshot layout.

$Script:VulnCurrentFileName = 'VulnExport_current.json.gz'
$Script:VulnHistoryFileNamePattern = 'VulnHistory_{0}.json.gz'

function Get-VulnPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-VulnCurrentPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:VulnCurrentFileName
}

function Test-VulnStoreExistence {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if (Test-Path -Path (Get-VulnCurrentPath -BasePath $BasePath)) {
        return $true
    }

    $historyFiles = @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue)
    return $historyFiles.Count -gt 0
}

function Get-VulnHistoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [int]$Year
    )

    return Join-Path -Path $BasePath -ChildPath ([string]::Format($Script:VulnHistoryFileNamePattern, $Year))
}

function Test-IsLegacyVulnSnapshotFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^VulnExport_\d+_\d{4}-\d{2}-\d{2}\.json(?:\.gz)?$')
}

function Get-VulnSnapshotDateFromName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $match = [regex]::Match($Name, '\d{4}-\d{2}-\d{2}')
    if (-not $match.Success) {
        throw "Unable to parse snapshot date from '$Name'."
    }

    return $match.Value
}

function Get-VulnLegacySnapshotFile {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths
    )

    if ($null -ne $LegacyFilePaths -and $LegacyFilePaths.Count -gt 0) {
        return [System.IO.FileInfo[]]@(
            $LegacyFilePaths |
                ForEach-Object {
                    if (Test-Path -LiteralPath $_ -PathType Leaf) {
                        Get-Item -LiteralPath $_
                    }
                } |
                Where-Object { $null -ne $_ -and (Test-IsLegacyVulnSnapshotFileName -Name $_.Name) } |
                Sort-Object Name
        )
    }

    return [System.IO.FileInfo[]]@(
        Get-ChildItem -Path $BasePath -Filter 'VulnExport_*' -File -ErrorAction SilentlyContinue |
            Where-Object { Test-IsLegacyVulnSnapshotFileName -Name $_.Name } |
            Sort-Object Name
    )
}

function Convert-VulnToYmdDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DateValue
    )

    if ($null -eq $DateValue) { return $null }

    $raw = $DateValue.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    if ($raw -match '^\d{4}-\d{2}-\d{2}$') {
        return $raw
    }

    if ($raw -match '^(\d{1,2})/(\d{1,2})/(\d{4})') {
        $month = [int]$Matches[1]
        $day = [int]$Matches[2]
        $year = [int]$Matches[3]
        if ($month -ge 1 -and $month -le 12 -and $day -ge 1 -and $day -le 31) {
            return ('{0:D4}-{1:D2}-{2:D2}' -f $year, $month, $day)
        }
    }

    try {
        return ([datetime]$raw).ToString('yyyy-MM-dd')
    }
    catch {
        return $null
    }
}

function Get-VulnNextDay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    return ([datetime]$Date).AddDays(1).ToString('yyyy-MM-dd')
}

function Get-VulnPreviousDay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    return ([datetime]$Date).AddDays(-1).ToString('yyyy-MM-dd')
}

function Get-MaxVulnDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Primary,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Secondary
    )

    if ([string]::IsNullOrWhiteSpace($Primary)) { return $Secondary }
    if ([string]::IsNullOrWhiteSpace($Secondary)) { return $Primary }
    if ([datetime]$Primary -ge [datetime]$Secondary) { return $Primary }
    return $Secondary
}

function Get-MinVulnDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Primary,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Secondary
    )

    if ([string]::IsNullOrWhiteSpace($Primary)) { return $Secondary }
    if ([string]::IsNullOrWhiteSpace($Secondary)) { return $Primary }
    if ([datetime]$Primary -le [datetime]$Secondary) { return $Primary }
    return $Secondary
}

function Get-VulnCanonicalRowSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $payload = [ordered]@{
        DeviceId = [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceId')
        DeviceName = [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceName')
        RbacGroupName = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RbacGroupName')
        OSPlatform = [string](Get-VulnPropertyValue -InputObject $Row -Name 'OSPlatform')
        OSVersion = [string](Get-VulnPropertyValue -InputObject $Row -Name 'OSVersion')
        CveId = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveId')
        CvssScore = Get-VulnPropertyValue -InputObject $Row -Name 'CvssScore'
        VulnerabilitySeverityLevel = [string](Get-VulnPropertyValue -InputObject $Row -Name 'VulnerabilitySeverityLevel')
        ExploitabilityLevel = [string](Get-VulnPropertyValue -InputObject $Row -Name 'ExploitabilityLevel')
        CveBatchUrl = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveBatchUrl')
        CveBatchTitle = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveBatchTitle')
        SoftwareVendor = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVendor')
        SoftwareName = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareName')
        SoftwareVersion = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVersion')
        RecommendationReference = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendationReference')
        SecurityUpdateAvailable = ((Get-VulnPropertyValue -InputObject $Row -Name 'SecurityUpdateAvailable') -eq $true)
        RecommendedSecurityUpdate = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdate')
        RecommendedSecurityUpdateId = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdateId')
        RecommendedSecurityUpdateUrl = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdateUrl')
        DiskPaths = @((@(Get-VulnPropertyValue -InputObject $Row -Name 'DiskPaths') | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique))
        RegistryPaths = @((@(Get-VulnPropertyValue -InputObject $Row -Name 'RegistryPaths') | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique))
    }

    return ($payload | ConvertTo-Json -Compress -Depth 20)
}

function Copy-VulnRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Record
    )

    $copy = [ordered]@{}
    foreach ($prop in $Record.PSObject.Properties) {
        $copy[$prop.Name] = $prop.Value
    }
    return [PSCustomObject]$copy
}

function New-ClosedVulnEntry {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter(Mandatory = $true)]
        [ValidateSet('removed', 'changed')]
        [string]$Reason,

        [Parameter(Mandatory = $true)]
        [string]$ClosedOn,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$ReplacementId
    )

    $row = Copy-VulnRecord -Record $Record
    $firstSeen = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $row -Name 'FirstSeenTimestamp')
    $lastSeen = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $row -Name 'LastSeenTimestamp')
    $boundedLastSeen = if ($lastSeen) { Get-MinVulnDate -Primary $lastSeen -Secondary $ClosedOn } else { $ClosedOn }
    $boundedFirstSeen = if ($firstSeen) { Get-MinVulnDate -Primary $firstSeen -Secondary $boundedLastSeen } else { $boundedLastSeen }
    $row.FirstSeenTimestamp = $boundedFirstSeen
    $row.LastSeenTimestamp = $boundedLastSeen

    $entry = [ordered]@{
        reason = $Reason
        row = $row
    }

    if (-not [string]::IsNullOrWhiteSpace($ReplacementId)) {
        $entry.replacementId = $ReplacementId
    }

    return [PSCustomObject]$entry
}

function New-OpenVulnRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter(Mandatory = $true)]
        [string]$VersionStartDate
    )

    $open = Copy-VulnRecord -Record $Record
    $normalizedFirstSeen = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $open -Name 'FirstSeenTimestamp')
    $normalizedLastSeen = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $open -Name 'LastSeenTimestamp')
    $open.FirstSeenTimestamp = if ($normalizedFirstSeen) { Get-MaxVulnDate -Primary $normalizedFirstSeen -Secondary $VersionStartDate } else { $VersionStartDate }
    $open.LastSeenTimestamp = if ($normalizedLastSeen) { $normalizedLastSeen } else { $open.FirstSeenTimestamp }
    return $open
}

function Get-VulnHistorySeed {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Year
    )

    return [ordered]@{
        year = $Year
        latestDate = ''
        snapshots = @()
    }
}

function Get-VulnHistorySnapshotMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $map = @{}
    foreach ($snapshot in @($HistoryDocument.snapshots)) {
        if ($null -eq $snapshot) { continue }
        $map[[string]$snapshot.date] = $snapshot
    }
    return $map
}

function Read-GzipTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 2
        $bytesRead = $fileStream.Read($header, 0, $header.Length)
        $fileStream.Position = 0

        if (($bytesRead -ne 2) -or $header[0] -ne 0x1f -or $header[1] -ne 0x8b) {
            $plainReader = [System.IO.StreamReader]::new($fileStream, [System.Text.UTF8Encoding]::new($false), $true)
            try {
                return $plainReader.ReadToEnd()
            }
            finally {
                $plainReader.Dispose()
            }
        }

        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $reader = [System.IO.StreamReader]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                return $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-GzipTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $writer.Write($Content)
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Read-VulnNdjsonRecordsFromPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }

                    $record = $line | ConvertFrom-Json -Depth 20
                    if ($null -ne $record) {
                        Write-Output $record
                    }
                }
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            if ($contentStream -ne $fileStream) {
                $contentStream.Dispose()
            }
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-VulnCurrentFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Records
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                foreach ($record in $Records) {
                    if ($null -eq $record) { continue }
                    $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Read-VulnHistoryDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = Read-GzipTextFile -Path $Path
    if ([string]::IsNullOrWhiteSpace($content)) {
        throw "History file '$Path' is empty."
    }

    return ($content | ConvertFrom-Json -Depth 100)
}

function Write-VulnHistoryDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $json = $HistoryDocument | ConvertTo-Json -Compress -Depth 100
    Write-GzipTextFile -Path $Path -Content $json
}

function Publish-VulnStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        $Store
    )

    $stageRoot = Join-Path $BasePath '.vuln-store-staging'
    if (Test-Path -Path $stageRoot) {
        Remove-Item -Path $stageRoot -Recurse -Force
    }

    New-Item -Path $stageRoot -ItemType Directory | Out-Null

    try {
        $stagedCurrentPath = Get-VulnCurrentPath -BasePath $stageRoot
        Write-VulnCurrentFile -Path $stagedCurrentPath -Records $Store.CurrentRecords

        foreach ($historyDocument in @($Store.HistoryDocuments)) {
            $historyPath = Get-VulnHistoryPath -BasePath $stageRoot -Year ([int]$historyDocument.year)
            Write-VulnHistoryDocument -Path $historyPath -HistoryDocument $historyDocument
        }

        $currentCount = Test-VulnCurrentFile -Path $stagedCurrentPath
        foreach ($historyFile in Get-ChildItem -Path $stageRoot -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue) {
            [void](Test-VulnHistoryFile -Path $historyFile.FullName)
        }

        $finalCurrentPath = Get-VulnCurrentPath -BasePath $BasePath
        if (Test-Path -Path $finalCurrentPath) {
            Remove-Item -Path $finalCurrentPath -Force
        }

        foreach ($existingHistory in Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue) {
            Remove-Item -Path $existingHistory.FullName -Force
        }

        Move-Item -Path $stagedCurrentPath -Destination $finalCurrentPath -Force
        foreach ($historyFile in Get-ChildItem -Path $stageRoot -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue) {
            Move-Item -Path $historyFile.FullName -Destination (Join-Path $BasePath $historyFile.Name) -Force
        }

        return [PSCustomObject]@{
            CurrentRows = $currentCount
            HistoryYears = @($Store.HistoryDocuments).Count
            LatestSnapshotDate = $Store.LatestSnapshotDate
        }
    }
    finally {
        if (Test-Path -Path $stageRoot) {
            Remove-Item -Path $stageRoot -Recurse -Force
        }
    }
}

function Publish-VulnStoreFromLegacySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveLegacyFiles
    )

    $legacyFiles = @(Get-VulnLegacySnapshotFile -BasePath $BasePath -LegacyFilePaths $LegacyFilePaths)

    if ($legacyFiles.Count -eq 0) {
        throw "No legacy VulnExport snapshot files found in '$BasePath'."
    }

    $store = Update-VulnStoreFromLegacySnapshot -BasePath $BasePath -LegacyFilePaths $legacyFiles.FullName
    $publishResult = Publish-VulnStore -BasePath $BasePath -Store $store

    if ($RemoveLegacyFiles) {
        foreach ($legacyFile in @(Get-VulnLegacySnapshotFile -BasePath $BasePath)) {
            Remove-Item -Path $legacyFile.FullName -Force
        }
    }

    return [PSCustomObject]@{
        DownloadedFiles = $legacyFiles.Count
        CurrentRows = $publishResult.CurrentRows
        HistoryYears = $publishResult.HistoryYears
        LatestSnapshotDate = $publishResult.LatestSnapshotDate
        MigratedLegacy = $true
        RemovedLegacyFiles = ($RemoveLegacyFiles -eq $true)
    }
}

function Read-VulnStoreRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $currentPath = Get-VulnCurrentPath -BasePath $BasePath
    if (Test-Path -Path $currentPath) {
        foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $currentPath) {
            Write-Output $record
        }
    }

    $historyFiles = @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File | Sort-Object Name)
    foreach ($file in $historyFiles) {
        $document = Read-VulnHistoryDocument -Path $file.FullName
        foreach ($snapshot in @($document.snapshots)) {
            foreach ($entry in @($snapshot.closed)) {
                if ($null -ne $entry -and $entry.PSObject.Properties['row']) {
                    Write-Output $entry.row
                }
            }
        }
    }
}

function Write-VulnCompatibilitySnapshotFromStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Store,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $fileStream = [System.IO.File]::Create($OutputPath)
    $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
    $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
    try {
        foreach ($record in $Store.CurrentRecords) {
            if ($null -eq $record) { continue }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
        }

        foreach ($historyDocument in $Store.HistoryDocuments) {
            foreach ($snapshot in $historyDocument.snapshots) {
                foreach ($entry in $snapshot.closed) {
                    $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                    if ($null -eq $row) { continue }
                    $writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 20))
                }
            }
        }
    }
    finally {
        $writer.Dispose()
    }
}

function Write-VulnCompatibilitySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $fileStream = [System.IO.File]::Create($OutputPath)
    $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
    $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
    try {
        foreach ($record in Read-VulnStoreRow -BasePath $BasePath) {
            if ($null -eq $record) { continue }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
        }
    }
    finally {
        $writer.Dispose()
    }
}

function Test-VulnCurrentFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $idSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $rowCount = 0
    foreach ($row in Read-VulnNdjsonRecordsFromPath -Path $Path) {
        $id = [string](Get-VulnPropertyValue -InputObject $row -Name 'Id')
        if ([string]::IsNullOrWhiteSpace($id)) {
            throw "Current vulnerability store contains a row without Id."
        }
        if (-not $idSet.Add($id)) {
            throw "Current vulnerability store contains duplicate Id '$id'."
        }
        $rowCount++
    }

    return $rowCount
}

function Test-VulnHistoryFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $document = Read-VulnHistoryDocument -Path $Path
    if ($null -eq $document.PSObject.Properties['year']) {
        throw "History file '$Path' is missing 'year'."
    }
    if ($null -eq $document.PSObject.Properties['snapshots']) {
        throw "History file '$Path' is missing 'snapshots'."
    }

    $snapshotDates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($snapshot in @($document.snapshots)) {
        if ($null -eq $snapshot) { continue }
        $date = [string](Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
        if ([string]::IsNullOrWhiteSpace($date)) {
            throw "History file '$Path' contains a snapshot without date."
        }
        if (-not $snapshotDates.Add($date)) {
            throw "History file '$Path' contains duplicate snapshot date '$date'."
        }
        foreach ($entry in @($snapshot.closed)) {
            if ($null -eq $entry) { continue }
            $reason = [string](Get-VulnPropertyValue -InputObject $entry -Name 'reason')
            if ($reason -notin @('removed', 'changed')) {
                throw "History file '$Path' contains invalid close reason '$reason'."
            }
            $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
            if ($null -eq $row) {
                throw "History file '$Path' contains a closed entry without row payload."
            }
            $id = [string](Get-VulnPropertyValue -InputObject $row -Name 'Id')
            if ([string]::IsNullOrWhiteSpace($id)) {
                throw "History file '$Path' contains a closed row without Id."
            }
        }
    }

    $storedLatestDate = [string](Get-VulnPropertyValue -InputObject $document -Name 'latestDate')
    if (-not [string]::IsNullOrWhiteSpace($storedLatestDate) -and $snapshotDates.Count -gt 0) {
        $maxSnapshotDate = @($snapshotDates | Sort-Object)[-1]
        if ($storedLatestDate -ne $maxSnapshotDate) {
            throw "History file '$Path' latestDate '$storedLatestDate' does not match max snapshot date '$maxSnapshotDate'."
        }
    }

    return @($document.snapshots).Count
}

function Get-VulnHistoryDocumentList {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $documents = [System.Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name) {
        $documents.Add((Read-VulnHistoryDocument -Path $file.FullName))
    }

    return @($documents)
}

function Get-VulnStoreLatestSnapshotDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $maxDate = $null

    $currentPath = Get-VulnCurrentPath -BasePath $BasePath
    if (Test-Path -Path $currentPath) {
        foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $currentPath) {
            $lastSeen = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $record -Name 'LastSeenTimestamp')
            if (-not [string]::IsNullOrWhiteSpace($lastSeen)) {
                $maxDate = Get-MaxVulnDate -Primary $maxDate -Secondary $lastSeen
            }
        }
    }

    foreach ($document in Get-VulnHistoryDocumentList -BasePath $BasePath) {
        $docLatest = [string](Get-VulnPropertyValue -InputObject $document -Name 'latestDate')
        if (-not [string]::IsNullOrWhiteSpace($docLatest)) {
            $maxDate = Get-MaxVulnDate -Primary $maxDate -Secondary $docLatest
        } else {
            foreach ($snapshot in @($document.snapshots)) {
                $snapshotDate = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
                if (-not [string]::IsNullOrWhiteSpace($snapshotDate)) {
                    $maxDate = Get-MaxVulnDate -Primary $maxDate -Secondary $snapshotDate
                }
            }
        }
    }

    return $maxDate
}

function Add-VulnHistoryEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$HistoryByYear,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate,

        [Parameter(Mandatory = $true)]
        [string]$ClosedOn,

        [Parameter(Mandatory = $true)]
        $Entry,

        [hashtable]$SnapshotMaps = $null
    )

    $year = ([datetime]$ClosedOn).Year
    if (-not $HistoryByYear.ContainsKey($year)) {
        $HistoryByYear[$year] = Get-VulnHistorySeed -Year $year
    }

    if ($null -ne $SnapshotMaps) {
        if (-not $SnapshotMaps.ContainsKey($year)) {
            $SnapshotMaps[$year] = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByYear[$year]
        }
        $snapshotMap = $SnapshotMaps[$year]
        if (-not $snapshotMap.ContainsKey($SnapshotDate)) {
            $newSnapshot = [PSCustomObject]@{ date = $SnapshotDate; closed = @() }
            $HistoryByYear[$year].snapshots += $newSnapshot
            $snapshotMap[$SnapshotDate] = $newSnapshot
        }
    } else {
        $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByYear[$year]
        if (-not $snapshotMap.ContainsKey($SnapshotDate)) {
            $HistoryByYear[$year].snapshots += [PSCustomObject]@{ date = $SnapshotDate; closed = @() }
            $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByYear[$year]
        }
    }

    $snapshotMap[$SnapshotDate].closed += $Entry

    $currentLatest = [string](Get-VulnPropertyValue -InputObject $HistoryByYear[$year] -Name 'latestDate')
    $newLatest = Get-MaxVulnDate -Primary $currentLatest -Secondary $SnapshotDate
    if ($HistoryByYear[$year] -is [System.Collections.IDictionary]) {
        $HistoryByYear[$year]['latestDate'] = $newLatest
    } else {
        $HistoryByYear[$year] | Add-Member -NotePropertyName 'latestDate' -NotePropertyValue $newLatest -Force
    }
}

function Update-VulnStoreFromLegacySnapshot {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths
    )

    $legacyFiles = @(Get-VulnLegacySnapshotFile -BasePath $BasePath -LegacyFilePaths $LegacyFilePaths)

    if ($legacyFiles.Count -eq 0) {
        throw "No legacy VulnExport snapshot files found in '$BasePath'."
    }

    if (-not (Test-VulnStoreExistence -BasePath $BasePath)) {
        return (Convert-LegacyVulnSnapshotsToStore -BasePath $BasePath)
    }

    $currentMap = @{}
    $currentPath = Get-VulnCurrentPath -BasePath $BasePath
    if (Test-Path -Path $currentPath) {
        foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $currentPath) {
            $id = [string](Get-VulnPropertyValue -InputObject $record -Name 'Id')
            if ([string]::IsNullOrWhiteSpace($id)) { continue }

            $versionStartDate = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $record -Name 'FirstSeenTimestamp')
            $currentMap[$id] = [PSCustomObject]@{
                Record = $record
                Signature = Get-VulnCanonicalRowSignature -Row $record
                VersionStartDate = $versionStartDate
            }
        }
    }

    $historyByYear = @{}
    foreach ($document in Get-VulnHistoryDocumentList -BasePath $BasePath) {
        $historyByYear[[int]$document.year] = $document
    }
    $snapshotMaps = @{}

    $latestKnownSnapshot = Get-VulnStoreLatestSnapshotDate -BasePath $BasePath
    $snapshotDates = @($legacyFiles | ForEach-Object { Get-VulnSnapshotDateFromName -Name $_.Name } | Sort-Object -Unique)

    if (-not [string]::IsNullOrWhiteSpace($latestKnownSnapshot)) {
        $staleDates = @($snapshotDates | Where-Object { ([datetime]$_) -le ([datetime]$latestKnownSnapshot) })
        if ($staleDates.Count -gt 0) {
            Write-Verbose "Skipping legacy snapshot dates already represented in the current store. StoreLatest=$latestKnownSnapshot Incoming=$($staleDates -join ', ')"
            $snapshotDates = @($snapshotDates | Where-Object { ([datetime]$_) -gt ([datetime]$latestKnownSnapshot) })
        }
    }

    if ($snapshotDates.Count -eq 0) {
        return [PSCustomObject]@{
            CurrentRecords = @($currentMap.Values | Sort-Object { $_.Record.Id } | ForEach-Object { $_.Record })
            HistoryDocuments = @($historyByYear.Values | Sort-Object year)
            SnapshotCount = 0
            LatestSnapshotDate = $latestKnownSnapshot
        }
    }

    $filesByDate = @{}
    foreach ($file in $legacyFiles) {
        $date = Get-VulnSnapshotDateFromName -Name $file.Name
        if (-not $filesByDate.ContainsKey($date)) { $filesByDate[$date] = [System.Collections.Generic.List[object]]::new() }
        $filesByDate[$date].Add($file)
    }

    foreach ($snapshotDate in $snapshotDates) {
        $snapshotRows = @{}
        foreach ($file in ($filesByDate[$snapshotDate] ?? @())) {
            foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $file.FullName) {
                $id = [string](Get-VulnPropertyValue -InputObject $record -Name 'Id')
                if ([string]::IsNullOrWhiteSpace($id)) { continue }
                if ((Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -ne $true) { continue }
                $snapshotRows[$id] = $record
            }
        }

        foreach ($id in @($currentMap.Keys)) {
            if ($snapshotRows.ContainsKey($id)) { continue }

            $closedOn = Get-VulnPreviousDay -Date $snapshotDate
            $closedEntry = New-ClosedVulnEntry -Record $currentMap[$id].Record -Reason 'removed' -ClosedOn $closedOn
            Add-VulnHistoryEntry -HistoryByYear $historyByYear -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps
            $currentMap.Remove($id)
        }

        foreach ($id in $snapshotRows.Keys) {
            $record = $snapshotRows[$id]
            $signature = Get-VulnCanonicalRowSignature -Row $record

            if (-not $currentMap.ContainsKey($id)) {
                $currentMap[$id] = [PSCustomObject]@{
                    Record = New-OpenVulnRecord -Record $record -VersionStartDate $snapshotDate
                    Signature = $signature
                    VersionStartDate = $snapshotDate
                }
                continue
            }

            $currentVersion = $currentMap[$id]
            if ($currentVersion.Signature -eq $signature) {
                $versionStartDate = if ([string]::IsNullOrWhiteSpace($currentVersion.VersionStartDate)) { $snapshotDate } else { $currentVersion.VersionStartDate }
                $currentMap[$id] = [PSCustomObject]@{
                    Record = New-OpenVulnRecord -Record $record -VersionStartDate $versionStartDate
                    Signature = $signature
                    VersionStartDate = $versionStartDate
                }
                continue
            }

            $closedOn = Get-VulnPreviousDay -Date $snapshotDate
            $closedEntry = New-ClosedVulnEntry -Record $currentVersion.Record -Reason 'changed' -ClosedOn $closedOn -ReplacementId $id
            Add-VulnHistoryEntry -HistoryByYear $historyByYear -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps

            $currentMap[$id] = [PSCustomObject]@{
                Record = New-OpenVulnRecord -Record $record -VersionStartDate $snapshotDate
                Signature = $signature
                VersionStartDate = $snapshotDate
            }
        }
    }

    return [PSCustomObject]@{
        CurrentRecords = @($currentMap.Values | Sort-Object { $_.Record.Id } | ForEach-Object { $_.Record })
        HistoryDocuments = @($historyByYear.Values | Sort-Object year)
        SnapshotCount = $snapshotDates.Count
        LatestSnapshotDate = $snapshotDates[-1]
    }
}

function Convert-LegacyVulnSnapshotsToStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $legacyFiles = @(Get-VulnLegacySnapshotFile -BasePath $BasePath)
    if ($legacyFiles.Count -eq 0) {
        throw "No legacy VulnExport snapshot files found in '$BasePath'."
    }

    $openVersions = @{}
    $historyByYear = @{}
    $snapshotMaps = @{}
    $allSnapshotDates = @($legacyFiles | ForEach-Object { Get-VulnSnapshotDateFromName -Name $_.Name } | Sort-Object -Unique)
    $lastSnapshotDate = $allSnapshotDates[-1]

    $filesByDate = @{}
    foreach ($file in $legacyFiles) {
        $date = Get-VulnSnapshotDateFromName -Name $file.Name
        if (-not $filesByDate.ContainsKey($date)) { $filesByDate[$date] = [System.Collections.Generic.List[object]]::new() }
        $filesByDate[$date].Add($file)
    }

    foreach ($snapshotDate in $allSnapshotDates) {
        $snapshotRows = @{}
        foreach ($file in ($filesByDate[$snapshotDate] ?? @())) {
            foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $file.FullName) {
                $id = [string](Get-VulnPropertyValue -InputObject $record -Name 'Id')
                if ([string]::IsNullOrWhiteSpace($id)) { continue }
                if ((Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -ne $true) { continue }
                $snapshotRows[$id] = $record
            }
        }

        foreach ($id in @($openVersions.Keys)) {
            if (-not $snapshotRows.ContainsKey($id)) {
                $closedOn = Get-VulnPreviousDay -Date $snapshotDate
                $closedEntry = New-ClosedVulnEntry -Record $openVersions[$id].Record -Reason 'removed' -ClosedOn $closedOn
                Add-VulnHistoryEntry -HistoryByYear $historyByYear -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps
                $openVersions.Remove($id)
            }
        }

        foreach ($id in $snapshotRows.Keys) {
            $record = $snapshotRows[$id]
            $signature = Get-VulnCanonicalRowSignature -Row $record

            if (-not $openVersions.ContainsKey($id)) {
                $openVersions[$id] = [PSCustomObject]@{
                    Record = New-OpenVulnRecord -Record $record -VersionStartDate $snapshotDate
                    Signature = $signature
                    VersionStartDate = $snapshotDate
                }
                continue
            }

            $openVersion = $openVersions[$id]
            if ($openVersion.Signature -eq $signature) {
                $updatedRecord = New-OpenVulnRecord -Record $record -VersionStartDate $openVersion.VersionStartDate
                $openVersions[$id] = [PSCustomObject]@{
                    Record = $updatedRecord
                    Signature = $signature
                    VersionStartDate = $openVersion.VersionStartDate
                }
                continue
            }

            $closedOn = Get-VulnPreviousDay -Date $snapshotDate
            $closedEntry = New-ClosedVulnEntry -Record $openVersion.Record -Reason 'changed' -ClosedOn $closedOn -ReplacementId $id
            Add-VulnHistoryEntry -HistoryByYear $historyByYear -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps

            $openVersions[$id] = [PSCustomObject]@{
                Record = New-OpenVulnRecord -Record $record -VersionStartDate $snapshotDate
                Signature = $signature
                VersionStartDate = $snapshotDate
            }
        }
    }

    $currentRecords = @($openVersions.Values | Sort-Object { $_.Record.Id } | ForEach-Object { $_.Record })
    return [PSCustomObject]@{
        CurrentRecords = $currentRecords
        HistoryDocuments = @($historyByYear.Values | Sort-Object year)
        SnapshotCount = $allSnapshotDates.Count
        LatestSnapshotDate = $lastSnapshotDate
    }
}

# Shared machine storage helpers used by export, generator, and the Azure runbook.

function ConvertTo-CompactMachineRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Machine
    )

    return [PSCustomObject]@{
        id                    = $Machine.PSObject.Properties['id']?.Value
        computerDnsName       = $Machine.PSObject.Properties['computerDnsName']?.Value
        rbacGroupName         = $Machine.PSObject.Properties['rbacGroupName']?.Value
        osPlatform            = $Machine.PSObject.Properties['osPlatform']?.Value
        osVersion             = $Machine.PSObject.Properties['osVersion']?.Value
        machineTags           = Get-NormalizedMachineTag -Tags $Machine.PSObject.Properties['machineTags']?.Value
        lastIpAddress         = $Machine.PSObject.Properties['lastIpAddress']?.Value
        lastExternalIpAddress = $Machine.PSObject.Properties['lastExternalIpAddress']?.Value
        healthStatus          = $Machine.PSObject.Properties['healthStatus']?.Value
        riskScore             = $Machine.PSObject.Properties['riskScore']?.Value
        exposureLevel         = $Machine.PSObject.Properties['exposureLevel']?.Value
        deviceValue           = $Machine.PSObject.Properties['deviceValue']?.Value
        managedBy             = $Machine.PSObject.Properties['managedBy']?.Value
        isAadJoined           = $Machine.PSObject.Properties['isAadJoined']?.Value
        lastSeen              = $Machine.PSObject.Properties['lastSeen']?.Value
        firstSeen             = $Machine.PSObject.Properties['firstSeen']?.Value
    }
}

function Get-NormalizedMachineTag {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Tags
    )

    $tagList = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $Tags) {
        return [string[]]@()
    }

    if ($Tags -is [string]) {
        if (-not [string]::IsNullOrWhiteSpace($Tags)) {
            $tagList.Add($Tags)
        }
    }
    elseif ($Tags -is [System.Collections.IEnumerable]) {
        foreach ($tag in $Tags) {
            if (-not [string]::IsNullOrWhiteSpace([string]$tag)) {
                $tagList.Add([string]$tag)
            }
        }
    }
    else {
        $tagValue = [string]$Tags
        if (-not [string]::IsNullOrWhiteSpace($tagValue)) {
            $tagList.Add($tagValue)
        }
    }

    if ($tagList.Count -eq 0) {
        return [string[]]@()
    }

    return [string[]]@($tagList | Sort-Object -Unique)
}

function Get-MachineCurrentPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:MachineCurrentFileName
}

function Get-MachineHistoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:MachineHistoryFileName
}

function Get-AdvancedHuntingCurrentPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:AdvancedHuntingCurrentFileName
}

function Get-LegacyCanonicalPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring(0, $Path.Length - 3)
    }

    return "$Path.gz"
}

function Test-IsLegacyMachineSnapshotFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^Machines_\d{4}-\d{2}-\d{2}\.json$')
}

function Test-IsLegacyAdvancedHuntingSnapshotFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^AdvancedHunting_\d+_\d{4}-\d{2}-\d{2}\.json$')
}

function Read-TextFileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
        return (Read-GzipTextFile -Path $Path)
    }

    return (Get-Content -Path $Path -Raw)
}

function Get-JsonFileMode {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        } else { $fileStream }
        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.Encoding]::UTF8, $true)
            try {
                while (-not $reader.EndOfStream) {
                    $charValue = $reader.Read()
                    if ($charValue -lt 0) { break }
                    $char = [char]$charValue
                    if (-not [char]::IsWhiteSpace($char)) {
                        if ($char -eq '[') { return 'Array' }
                        return 'Ndjson'
                    }
                }
                return 'Empty'
            }
            finally { $reader.Dispose() }
        }
        finally { if ($contentStream -ne $fileStream) { $contentStream.Dispose() } }
    }
    finally { $fileStream.Dispose() }
}

function Read-MachineRecordsFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileMode = Get-JsonFileMode -Path $Path
    if ($fileMode -eq 'Empty') {
        return
    }

    if ($fileMode -eq 'Array') {
        $rawContent = Read-TextFileContent -Path $Path
        $machineList = $rawContent | ConvertFrom-Json
        $rawContent = $null
        if ($null -eq $machineList) { return }
        if ($machineList -isnot [System.Array]) { $machineList = @($machineList) }

        foreach ($machine in $machineList) {
            if ($null -eq $machine) { continue }
            $record = ConvertTo-CompactMachineRecord -Machine $machine
            $stateHash = $machine.PSObject.Properties['stateHash']?.Value
            $observedOn = $machine.PSObject.Properties['observedOn']?.Value
            if ($stateHash) { Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue $stateHash }
            if ($observedOn) { Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue $observedOn }
            Write-Output $record
        }

        return
    }

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        } else { $fileStream }
        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    try {
                        $machine = $line | ConvertFrom-Json
                    }
                    catch {
                        Write-Warning "Failed to parse machine line in $(Split-Path -Leaf $Path): $_"
                        continue
                    }

                    if ($null -eq $machine) { continue }
                    $record = ConvertTo-CompactMachineRecord -Machine $machine
                    $stateHash = $machine.PSObject.Properties['stateHash']?.Value
                    $observedOn = $machine.PSObject.Properties['observedOn']?.Value
                    if ($stateHash) { Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue $stateHash }
                    if ($observedOn) { Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue $observedOn }
                    Write-Output $record
                }
            }
            finally { $reader.Dispose() }
        }
        finally { if ($contentStream -ne $fileStream) { $contentStream.Dispose() } }
    }
    finally { $fileStream.Dispose() }
}

function Get-MachineStateHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Machine
    )

    $state = [ordered]@{
        computerDnsName       = $Machine.PSObject.Properties['computerDnsName']?.Value
        rbacGroupName         = $Machine.PSObject.Properties['rbacGroupName']?.Value
        osPlatform            = $Machine.PSObject.Properties['osPlatform']?.Value
        osVersion             = $Machine.PSObject.Properties['osVersion']?.Value
        machineTags           = @(Get-NormalizedMachineTag -Tags $Machine.PSObject.Properties['machineTags']?.Value)
        lastIpAddress         = $Machine.PSObject.Properties['lastIpAddress']?.Value
        lastExternalIpAddress = $Machine.PSObject.Properties['lastExternalIpAddress']?.Value
        healthStatus          = $Machine.PSObject.Properties['healthStatus']?.Value
        riskScore             = $Machine.PSObject.Properties['riskScore']?.Value
        exposureLevel         = $Machine.PSObject.Properties['exposureLevel']?.Value
        deviceValue           = $Machine.PSObject.Properties['deviceValue']?.Value
        managedBy             = $Machine.PSObject.Properties['managedBy']?.Value
        isAadJoined           = $Machine.PSObject.Properties['isAadJoined']?.Value
    }

    $stateJson = $state | ConvertTo-Json -Compress -Depth 5
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($stateJson)
    if (-not (Get-Variable -Name _sha256 -Scope Script -ErrorAction Ignore)) {
        $Script:_sha256 = [System.Security.Cryptography.SHA256]::Create()
    }
    $hashBytes = $Script:_sha256.ComputeHash($bytes)
    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
}

function New-MachineSnapshotRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Machine,

        [Parameter(Mandatory = $true)]
        [string]$ObservedOn
    )

    $compactRecord = ConvertTo-CompactMachineRecord -Machine $Machine
    $snapshot = [ordered]@{}
    foreach ($property in $compactRecord.PSObject.Properties) {
        $snapshot[$property.Name] = $property.Value
    }
    $snapshot['observedOn'] = $ObservedOn
    $snapshot['stateHash'] = Get-MachineStateHash -Machine $compactRecord

    return [PSCustomObject]$snapshot
}

function Write-NdjsonRecordsFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Records
    )

    $fileStream = $null
    $gzipStream = $null
    $writer = $null
    try {
        if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            $fileStream = [System.IO.File]::Create($Path)
            $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
        }
        else {
            $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))
        }

        foreach ($record in $Records) {
            if ($null -eq $record) { continue }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 6))
        }
    }
    finally {
        if ($writer) { $writer.Dispose() }
        elseif ($gzipStream) { $gzipStream.Dispose() }
        elseif ($fileStream) { $fileStream.Dispose() }
    }
}

function Initialize-MachineHistoryStore {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveLegacyFiles
    )

    $currentPath = Get-MachineCurrentPath -BasePath $Path
    $historyPath = Get-MachineHistoryPath -BasePath $Path
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath
    $legacyHistoryPath = Get-LegacyCanonicalPath -Path $historyPath
    $currentReadPath = if (Test-Path -Path $currentPath) { $currentPath } elseif (Test-Path -Path $legacyCurrentPath) { $legacyCurrentPath } else { $null }
    $historyReadPath = if (Test-Path -Path $historyPath) { $historyPath } elseif (Test-Path -Path $legacyHistoryPath) { $legacyHistoryPath } else { $null }
    $currentExists = $null -ne $currentReadPath
    $historyExists = $null -ne $historyReadPath
    $legacyFiles = @(Get-ChildItem -Path $Path -Filter 'Machines_*.json' -File | Where-Object { Test-IsLegacyMachineSnapshotFileName -Name $_.Name } | Sort-Object Name)
    $currentRecords = @{}
    $migratedLegacy = $false

    if ($currentExists) {
        foreach ($record in Read-MachineRecordsFromFile -Path $currentReadPath) {
            if (-not $record.id) { continue }
            if (-not $record.PSObject.Properties['stateHash']) {
                Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue (Get-MachineStateHash -Machine $record)
            }
            if (-not $record.PSObject.Properties['observedOn']) {
                Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd')
            }
            $currentRecords[$record.id] = $record
        }
    }
    elseif ($historyExists) {
        foreach ($record in Read-MachineRecordsFromFile -Path $historyReadPath) {
            if (-not $record.id) { continue }
            if (-not $record.PSObject.Properties['stateHash']) {
                Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue (Get-MachineStateHash -Machine $record)
            }
            $currentRecords[$record.id] = $record
        }
    }

    if (($currentRecords.Count -eq 0) -and $legacyFiles.Count -gt 0) {
        $historyRecords = [System.Collections.Generic.List[object]]::new()

        foreach ($file in $legacyFiles) {
            $observedOn = [regex]::Match($file.Name, '\d{4}-\d{2}-\d{2}').Value
            foreach ($record in Read-MachineRecordsFromFile -Path $file.FullName) {
                if (-not $record.id) { continue }
                $snapshot = New-MachineSnapshotRecord -Machine $record -ObservedOn $observedOn
                $existing = $currentRecords[$snapshot.id]
                if (($null -eq $existing) -or ($existing.stateHash -ne $snapshot.stateHash)) {
                    $historyRecords.Add($snapshot)
                }
                $currentRecords[$snapshot.id] = $snapshot
            }
        }

        if ($historyRecords.Count -gt 0) {
            Write-NdjsonRecordsFile -Path $historyPath -Records $historyRecords
        }
        if ($currentRecords.Count -gt 0) {
            Write-NdjsonRecordsFile -Path $currentPath -Records $currentRecords.Values
        }
        if ($RemoveLegacyFiles) {
            Remove-Item -Path $legacyFiles.FullName -Force -ErrorAction SilentlyContinue
        }
        $migratedLegacy = $true
        $historyExists = Test-Path -Path $historyPath
        $currentExists = Test-Path -Path $currentPath
    }

    if ((-not $historyExists) -and $currentRecords.Count -gt 0) {
        $seedRecords = foreach ($record in $currentRecords.Values) {
            if (-not $record.PSObject.Properties['stateHash']) {
                Add-Member -InputObject $record -NotePropertyName stateHash -NotePropertyValue (Get-MachineStateHash -Machine $record)
            }
            if (-not $record.PSObject.Properties['observedOn']) {
                Add-Member -InputObject $record -NotePropertyName observedOn -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd')
            }
            $record
        }
        Write-NdjsonRecordsFile -Path $historyPath -Records $seedRecords
    }

    if ((-not $currentExists) -and $currentRecords.Count -gt 0) {
        Write-NdjsonRecordsFile -Path $currentPath -Records $currentRecords.Values
    }

    if ($RemoveLegacyFiles -and $legacyFiles.Count -gt 0 -and $currentRecords.Count -gt 0) {
        Remove-Item -Path $legacyFiles.FullName -Force -ErrorAction SilentlyContinue
    }

    if ($migratedLegacy) {
        if (Test-Path -Path $legacyCurrentPath) { Remove-Item -Path $legacyCurrentPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path -Path $legacyHistoryPath) { Remove-Item -Path $legacyHistoryPath -Force -ErrorAction SilentlyContinue }
    }

    return @{
        CurrentPath    = $currentPath
        HistoryPath    = $historyPath
        CurrentRecords = $currentRecords
        MigratedLegacy = $migratedLegacy
    }
}

function Convert-ToYmdDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DateValue
    )

    if ($null -eq $DateValue) {
        return $null
    }

    $raw = $DateValue.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    if ($raw -match '^\d{4}-\d{2}-\d{2}$') {
        return $raw
    }

    if ($raw -match '^(\d{1,2})/(\d{1,2})/(\d{4})') {
        $month = [int]$Matches[1]
        $day = [int]$Matches[2]
        $year = [int]$Matches[3]
        if ($month -ge 1 -and $month -le 12 -and $day -ge 1 -and $day -le 31) {
            return ('{0:D4}-{1:D2}-{2:D2}' -f $year, $month, $day)
        }
    }

    try {
        return ([datetime]$raw).ToString('yyyy-MM-dd')
    }
    catch {
        return $null
    }
}

function Get-AdvancedHuntingLastModifiedKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$LastModifiedTime,

        [Parameter(Mandatory = $false)]
        [string]$FallbackDate = ''
    )

    if ($null -ne $LastModifiedTime) {
        $rawValue = $LastModifiedTime.ToString().Trim()
        if (-not [string]::IsNullOrWhiteSpace($rawValue)) {
            try {
                return ([datetimeoffset]$rawValue).UtcDateTime.ToString('o')
            }
            catch {
                $normalized = Convert-ToYmdDate -DateValue $rawValue
                if ($normalized) {
                    return $normalized
                }

                return $rawValue
            }
        }
    }

    return $FallbackDate
}

function Read-AdvancedHuntingRecordsFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileMode = Get-JsonFileMode -Path $Path
    if ($fileMode -eq 'Empty') {
        return
    }

    if ($fileMode -eq 'Array') {
        $rawContent = Read-TextFileContent -Path $Path
        $records = $rawContent | ConvertFrom-Json
        $rawContent = $null
        if ($null -eq $records) { return }
        if ($records -isnot [System.Array]) { $records = @($records) }

        foreach ($record in $records) {
            if ($null -ne $record) {
                Write-Output $record
            }
        }

        return
    }

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        } else { $fileStream }
        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                while (-not $reader.EndOfStream) {
                    $line = $reader.ReadLine()
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    try {
                        $record = $line | ConvertFrom-Json
                        if ($null -ne $record) { Write-Output $record }
                    }
                    catch {
                        Write-Warning "Failed to parse Advanced Hunting line in $(Split-Path -Leaf $Path): $_"
                    }
                }
            }
            finally { $reader.Dispose() }
        }
        finally { if ($contentStream -ne $fileStream) { $contentStream.Dispose() } }
    }
    finally { $fileStream.Dispose() }
}

function Initialize-AdvancedHuntingStore {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveLegacyFiles
    )

    $currentPath = Get-AdvancedHuntingCurrentPath -BasePath $Path
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath
    $currentRecords = @{}
    $migratedLegacy = $false
    $legacyFiles = @(Get-ChildItem -Path $Path -Filter 'AdvancedHunting_*.json' -File | Where-Object { Test-IsLegacyAdvancedHuntingSnapshotFileName -Name $_.Name } | Sort-Object Name)

    if (Test-Path -Path $currentPath) {
        foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $currentPath) {
            $cveId = $record.PSObject.Properties['CveId']?.Value
            if ($cveId) {
                $currentRecords[$cveId] = $record
            }
        }
    }
    elseif (Test-Path -Path $legacyCurrentPath) {
        foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $legacyCurrentPath) {
            $cveId = $record.PSObject.Properties['CveId']?.Value
            if ($cveId) {
                $currentRecords[$cveId] = $record
            }
        }
        $migratedLegacy = $true
    }

    if ($legacyFiles.Count -gt 0) {
        foreach ($file in $legacyFiles) {
            $fallbackDate = [regex]::Match($file.Name, '\d{4}-\d{2}-\d{2}').Value
            foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
                $cveId = $record.PSObject.Properties['CveId']?.Value
                if (-not $cveId) { continue }

                $incomingKey = Get-AdvancedHuntingLastModifiedKey -LastModifiedTime $record.PSObject.Properties['LastModifiedTime']?.Value -FallbackDate $fallbackDate
                $existing = $currentRecords[$cveId]

                if ($null -eq $existing) {
                    $currentRecords[$cveId] = $record
                    $migratedLegacy = $true
                    continue
                }

                $existingKey = Get-AdvancedHuntingLastModifiedKey -LastModifiedTime $existing.PSObject.Properties['LastModifiedTime']?.Value -FallbackDate ''
                if ([string]::CompareOrdinal($incomingKey, $existingKey) -gt 0) {
                    $currentRecords[$cveId] = $record
                    $migratedLegacy = $true
                }
            }
        }

        if ($migratedLegacy) {
            Write-NdjsonRecordsFile -Path $currentPath -Records $currentRecords.Values
        }

        if ($RemoveLegacyFiles -and $currentRecords.Count -gt 0) {
            Remove-Item -Path $legacyFiles.FullName -Force -ErrorAction SilentlyContinue
            if (Test-Path -Path $legacyCurrentPath) {
                Remove-Item -Path $legacyCurrentPath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    return @{
        CurrentPath    = $currentPath
        CurrentRecords = $currentRecords
        MigratedLegacy = $migratedLegacy
    }
}

# Shared MDE export helpers used by local export, generator refresh, and the Azure runbook.

function Get-MdeHeaderCollection {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

    return @{
        'Content-Type'  = 'application/json'
        'Accept'        = 'application/json'
        'Authorization' = "Bearer $AccessToken"
    }
}

function Invoke-MdeBulkVulnerabilitySnapshotDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$ExportUrl
    )

    $response = Invoke-RestMethod -Uri $ExportUrl -Headers $Headers -Method Get -ErrorAction Stop
    $exportFiles = @($response.exportFiles)
    if ($exportFiles.Count -eq 0) {
        throw 'Bulk vulnerability export returned no files.'
    }

    $downloadedFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($fileUrl in $exportFiles) {
        if ($fileUrl -match '/collection/([^/?]+)/.*%3DgroupId%3D([^&%? ]+)') {
            $date = $Matches[1]
            $groupId = [System.Uri]::UnescapeDataString($Matches[2])
        }
        elseif ($fileUrl -match '/flat-va/([^/?]+)/[^/?]+/json/_RbacGroupId(?:%3D|=)([^/?&]+)') {
            $date = $Matches[1]
            $groupId = [System.Uri]::UnescapeDataString($Matches[2])
        }
        else {
            throw "Unexpected export URL format. Cannot extract date and groupId from: $fileUrl"
        }

        $outputFile = Join-Path $OutputPath "VulnExport_${groupId}_${date}.json.gz"
        Invoke-WebRequest -Uri $fileUrl -OutFile $outputFile
        $downloadedFiles.Add($outputFile)
    }

    return [PSCustomObject]@{
        ExportFileCount = $exportFiles.Count
        DownloadedFiles = @($downloadedFiles)
    }
}

function Invoke-MdeAdvancedHuntingStoreRefresh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$QueryUrl
    )

    $query = @"
DeviceTvmSoftwareVulnerabilities
| join kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId
| summarize arg_max(LastModifiedTime, PublishedDate, VulnerabilityDescription, IsExploitAvailable, EpssScore, AffectedSoftware) by CveId
| project CveId, PublishedDate = format_datetime(PublishedDate, 'yyyy-MM-dd'), VulnerabilityDescription, IsExploitAvailable, EpssScore, AffectedSoftware, LastModifiedTime
"@

    $body = @{ Query = $query } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri $QueryUrl -Headers $Headers -Method Post -Body $body -ErrorAction Stop

    if (-not $response.Results) {
        return [PSCustomObject]@{
            Success = $false
            RecordCount = 0
            OutputFile = $null
            MigratedLegacy = $false
        }
    }

    $store = Initialize-AdvancedHuntingStore -Path $OutputPath -RemoveLegacyFiles
    foreach ($result in $response.Results) {
        $cveId = $result.PSObject.Properties['CveId']?.Value
        if ($cveId) {
            $store.CurrentRecords[$cveId] = $result
        }
    }

    Write-NdjsonRecordsFile -Path $store.CurrentPath -Records $store.CurrentRecords.Values

    return [PSCustomObject]@{
        Success = $true
        RecordCount = @($response.Results).Count
        OutputFile = $store.CurrentPath
        MigratedLegacy = $store.MigratedLegacy
    }
}

function Invoke-MdeMachineStoreRefresh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$BaseApiUrl
    )

    $url = "$BaseApiUrl/api/machines?`$filter=onboardingStatus eq 'Onboarded'"
    $pageCount = 0
    $observedOn = Get-Date -Format 'yyyy-MM-dd'
    $store = Initialize-MachineHistoryStore -Path $OutputPath -RemoveLegacyFiles
    $historyRecords = [System.Collections.Generic.List[object]]::new()

    if (Test-Path -Path $store.HistoryPath) {
        foreach ($record in Read-MachineRecordsFromFile -Path $store.HistoryPath) {
            if ($null -ne $record) {
                $historyRecords.Add($record)
            }
        }
    }

    $machineCount = 0
    $changeCount = 0

    do {
        $pageCount++
        $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get -ErrorAction Stop

        if ($response.value) {
            foreach ($machine in $response.value) {
                $snapshot = New-MachineSnapshotRecord -Machine $machine -ObservedOn $observedOn
                $existing = $store.CurrentRecords[$snapshot.id]
                if (($null -eq $existing) -or ($existing.stateHash -ne $snapshot.stateHash)) {
                    $historyRecords.Add($snapshot)
                    $changeCount++
                }
                $store.CurrentRecords[$snapshot.id] = $snapshot
                $machineCount++
            }
        }

        $url = if ($response.PSObject.Properties['@odata.nextLink']) {
            $response.'@odata.nextLink'
        }
        else {
            $null
        }
    } while ($url)

    Write-NdjsonRecordsFile -Path $store.HistoryPath -Records $historyRecords
    Write-NdjsonRecordsFile -Path $store.CurrentPath -Records $store.CurrentRecords.Values

    return [PSCustomObject]@{
        Success = $true
        MachineCount = $machineCount
        ChangeCount = $changeCount
        PageCount = $pageCount
        OutputFiles = @($store.CurrentPath, $store.HistoryPath)
        MigratedLegacy = $store.MigratedLegacy
    }
}

# Shared generator/runbook helpers used for dashboard normalization and HTML assembly.

function Get-JSLibrary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [bool]$Critical = $false
    )

    Write-Information "Downloading $Name library..." -InformationAction Continue

    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec 30
        Write-Information "  $Name downloaded successfully" -InformationAction Continue
        return $response.Content
    }
    catch {
        $errorMessage = "Failed to download $Name from $Url`: $_"
        if ($Critical) {
            Write-Error $errorMessage
            throw
        }

        Write-Warning $errorMessage
        Write-Warning "Using fallback for $Name (PDF export may not work)"
        return "// $Name failed to load - functionality may be limited"
    }
}

function Write-Base64FileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.TextWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $Writer.Write([System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($FilePath)))
}

function Write-CombinedPayloadGzip {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Lookups,

        [Parameter(Mandatory = $true)]
        [string]$VulnsPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $fileStream = $null
    $gzipStream = $null
    $writer = $null
    $vulnReader = $null

    try {
        $fileStream = [System.IO.File]::Create($OutputPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))

        $writer.Write('{"lookups":')
        $lookupsJson = $Lookups | ConvertTo-Json -Depth 10 -Compress
        $writer.Write($lookupsJson)
        $lookupsJson = $null

        $writer.Write(',"vulns":')
        $vulnReader = [System.IO.StreamReader]::new($VulnsPath, [System.Text.Encoding]::UTF8)
        $charBuffer = New-Object char[] 16384
        while (($charsRead = $vulnReader.Read($charBuffer, 0, $charBuffer.Length)) -gt 0) {
            $writer.Write($charBuffer, 0, $charsRead)
        }

        $writer.Write('}')
    }
    finally {
        if ($vulnReader) { $vulnReader.Dispose() }
        if ($writer) { $writer.Dispose() }
        elseif ($gzipStream) { $gzipStream.Dispose() }
        elseif ($fileStream) { $fileStream.Dispose() }
    }
}

function Write-TemplatedHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Template,

        [Parameter(Mandatory = $true)]
        [array]$Segments,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $writer = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        $position = 0
        foreach ($segment in $Segments) {
            $placeholder = $segment.Placeholder
            $index = $Template.IndexOf($placeholder, $position, [System.StringComparison]::Ordinal)
            if ($index -lt 0) {
                throw "Template placeholder not found: $placeholder"
            }

            $writer.Write($Template.Substring($position, $index - $position))
            if ($segment.ContainsKey('Base64FilePath')) {
                Write-Base64FileContent -Writer $writer -FilePath $segment.Base64FilePath
            }
            else {
                $writer.Write([string]$segment.Value)
            }

            $position = $index + $placeholder.Length
        }

        $writer.Write($Template.Substring($position))
    }
    finally {
        $writer.Dispose()
    }
}

function Read-MachineData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Write-Information "Reading machine data from $Path..." -InformationAction Continue
    $machines = @{}

    $currentPath = Get-MachineCurrentPath -BasePath $Path
    $historyPath = Get-MachineHistoryPath -BasePath $Path
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath
    $legacyHistoryPath = Get-LegacyCanonicalPath -Path $historyPath
    $currentReadPath = if (Test-Path -Path $currentPath) { $currentPath } elseif (Test-Path -Path $legacyCurrentPath) { $legacyCurrentPath } else { $null }
    $historyReadPath = if (Test-Path -Path $historyPath) { $historyPath } elseif (Test-Path -Path $legacyHistoryPath) { $legacyHistoryPath } else { $null }

    if ($null -ne $currentReadPath) {
        Write-Information "  Using $(Split-Path -Leaf $currentReadPath)" -InformationAction Continue
        foreach ($record in Read-MachineRecordsFromFile -Path $currentReadPath) {
            if ($record.id) {
                $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
            }
        }
    }
    elseif ($null -ne $historyReadPath) {
        Write-Information "  Using $(Split-Path -Leaf $historyReadPath) to reconstruct current state" -InformationAction Continue
        foreach ($record in Read-MachineRecordsFromFile -Path $historyReadPath) {
            if ($record.id) {
                $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
            }
        }
    }
    else {
        $machineFiles = @(Get-ChildItem -Path $Path -Filter 'Machines_*.json' -File | Where-Object { Test-IsLegacyMachineSnapshotFileName -Name $_.Name } | Sort-Object Name -Descending)

        if ($machineFiles.Count -eq 0) {
            Write-Warning 'No machine data files found. Device details may be incomplete.'
            return @{}
        }

        Write-Information "  Found $($machineFiles.Count) legacy machine snapshot file(s)" -InformationAction Continue
        foreach ($file in $machineFiles) {
            Write-Information "  Processing $($file.Name)..." -InformationAction Continue
            foreach ($record in Read-MachineRecordsFromFile -Path $file.FullName) {
                if ($record.id -and -not $machines.ContainsKey($record.id)) {
                    $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
                }
            }
        }
    }

    Write-Information "  Loaded $($machines.Count) unique machines" -InformationAction Continue
    return $machines
}

function Read-AdvancedHuntingData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Write-Information "Reading Advanced Hunting data from $Path..." -InformationAction Continue

    $ahData = @{}
    $parseErrors = 0
    $currentPath = Get-AdvancedHuntingCurrentPath -BasePath $Path
    $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath

    if ((-not (Test-Path -Path $currentPath)) -and (Test-Path -Path $legacyCurrentPath)) {
        $currentPath = $legacyCurrentPath
    }

    if (Test-Path -Path $currentPath) {
        Write-Information "  Using $(Split-Path -Leaf $currentPath)" -InformationAction Continue
        $sourceFiles = @(Get-Item -Path $currentPath)
    }
    else {
        $sourceFiles = @(Get-ChildItem -Path $Path -Filter 'AdvancedHunting_*.json' -File |
            Where-Object { Test-IsLegacyAdvancedHuntingSnapshotFileName -Name $_.Name } |
            Sort-Object Name -Descending)

        if ($sourceFiles.Count -eq 0) {
            Write-Warning 'No Advanced Hunting data files found. CVE enrichment will be skipped.'
            return @{}
        }

        Write-Information "  Found $($sourceFiles.Count) legacy Advanced Hunting file(s)" -InformationAction Continue
    }

    foreach ($file in $sourceFiles) {
        Write-Information "  Processing $($file.Name)..." -InformationAction Continue
        foreach ($record in Read-AdvancedHuntingRecordsFromFile -Path $file.FullName) {
            try {
                $cveId = $record.CveId
                if ($cveId -and -not $ahData.ContainsKey($cveId)) {
                    $pdRaw = $record.PSObject.Properties['PublishedDate']?.Value
                    $ahData[$cveId] = @{
                        PublishedDate = Convert-ToYmdDate -DateValue $pdRaw
                        VulnerabilityDescription = $record.PSObject.Properties['VulnerabilityDescription']?.Value
                        EpssScore = $record.PSObject.Properties['EpssScore']?.Value
                        AffectedSoftware = $record.PSObject.Properties['AffectedSoftware']?.Value
                    }
                }
            }
            catch {
                $parseErrors++
                if ($parseErrors -le 5) {
                    Write-Warning "Failed to process Advanced Hunting record in $($file.Name): $_"
                }
            }
        }
    }

    if ($parseErrors -gt 0) {
        Write-Warning "Total parse errors: $parseErrors"
    }

    Write-Information "  Loaded enrichment data for $($ahData.Count) unique CVEs" -InformationAction Continue
    return $ahData
}

function Convert-CveUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Url
    )

    if ([string]::IsNullOrWhiteSpace($Url)) {
        return $Url
    }

    if ($Url -match '^https://(?:portal\.)?msrc\.microsoft\.com/en-US/security-guidance/advisory/(CVE-\d{4}-\d+)') {
        $cveId = $Matches[1]
        return "https://msrc.microsoft.com/update-guide/vulnerability/$cveId"
    }

    return $Url
}

function Get-GzipLine {
    param([string]$Path)
    $fs = [System.IO.File]::OpenRead($Path)
    $gs = [System.IO.Compression.GZipStream]::new($fs, [System.IO.Compression.CompressionMode]::Decompress)
    $lr = [System.IO.StreamReader]::new($gs, [System.Text.Encoding]::UTF8)
    try {
        while (-not $lr.EndOfStream) { $lr.ReadLine() }
    }
    finally { $lr.Dispose() }
}

function Get-OrCreateIndex {
    param($value, $list, $indexMap)
    if ($null -eq $value -or $value -eq '') { return -1 }
    $key = $value.ToString()
    if (-not $indexMap.ContainsKey($key)) {
        $indexMap[$key] = $list.Count
        $list.Add($key)
    }
    return $indexMap[$key]
}

function ConvertTo-NormalizedData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataPath,

        [Parameter(Mandatory = $true)]
        [string]$VulnOutputPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Machines,

        [Parameter(Mandatory = $false)]
        [hashtable]$AdvancedHuntingData = @{}
    )

    Write-Information '  Normalizing data structure...' -InformationAction Continue

    $lookups = @{
        vendors = [System.Collections.Generic.List[string]]::new()
        severities = @('Critical', 'High', 'Medium', 'Low')
        exploitLevels = [System.Collections.Generic.List[string]]::new()
        groups = [System.Collections.Generic.List[string]]::new()
        platforms = [System.Collections.Generic.List[string]]::new()
        tags = [System.Collections.Generic.List[string]]::new()
        updates = [System.Collections.Generic.List[PSObject]]::new()
        versions = [System.Collections.Generic.List[string]]::new()
        dates = [System.Collections.Generic.List[string]]::new()
        diskPaths = [System.Collections.Generic.List[string]]::new()
        regPaths = [System.Collections.Generic.List[string]]::new()
        affSoftware = [System.Collections.Generic.List[string]]::new()
        batchTitles = [System.Collections.Generic.List[string]]::new()
        devices = [System.Collections.Generic.List[PSObject]]::new()
        software = [System.Collections.Generic.List[PSObject]]::new()
        cves = [System.Collections.Generic.List[PSObject]]::new()
    }

    $vendorIndex = @{}
    $exploitIndex = @{}
    $groupIndex = @{}
    $platformIndex = @{}
    $tagIndex = @{}
    $updateIndex = @{}
    $deviceIndex = @{}
    $softwareIndex = @{}
    $cveIndex = @{}
    $versionIndex = @{}
    $dateIndex = @{}
    $diskPathIndex = @{}
    $regPathIndex = @{}
    $affSoftwareIndex = @{}
    $batchTitleIndex = @{}

    $dateValueCache = @{}
    function Get-CachedYmdDate {
        param($dateValue)

        if ($null -eq $dateValue) {
            return $null
        }

        $cacheKey = $dateValue.ToString()
        if ($dateValueCache.ContainsKey($cacheKey)) {
            return $dateValueCache[$cacheKey]
        }

        $normalized = Convert-ToYmdDate -DateValue $dateValue
        $dateValueCache[$cacheKey] = $normalized
        return $normalized
    }

    $firstLastSwappedCount = 0
    $processedCount = 0
    $parseErrors = 0
    $hasNoTags = $false
    $vulnWriter = $null
    $isFirstVuln = $true

    $jsonFiles = @()
    $tempMergedVulnPath = $null

    if (Test-VulnStoreExistence -BasePath $DataPath) {
        $tempMergedVulnPath = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-store-' + [guid]::NewGuid().ToString('N') + '.json.gz')
        Write-VulnCompatibilitySnapshot -BasePath $DataPath -OutputPath $tempMergedVulnPath

        $jsonFiles = @((Get-Item -LiteralPath $tempMergedVulnPath))
        Write-Information '  Found vulnerability current/history store to normalize...' -InformationAction Continue
    }
    else {
        $legacyFiles = @(Get-VulnLegacySnapshotFile -BasePath $DataPath)
        if ($legacyFiles.Count -eq 0) { throw "No VulnExport snapshot files found in '$DataPath'." }

        $tempMergedVulnPath = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-legacy-store-' + [guid]::NewGuid().ToString('N') + '.json.gz')
        $legacyStore = Convert-LegacyVulnSnapshotsToStore -BasePath $DataPath
        Write-VulnCompatibilitySnapshotFromStore -Store $legacyStore -OutputPath $tempMergedVulnPath

        $jsonFiles = @((Get-Item -LiteralPath $tempMergedVulnPath))
        Write-Information "  Found $($legacyFiles.Count) legacy export file(s); canonicalizing for normalization..." -InformationAction Continue
    }

    try {
        $vulnWriter = [System.IO.StreamWriter]::new($VulnOutputPath, $false, [System.Text.UTF8Encoding]::new($false))
        $vulnWriter.Write('[')

        foreach ($file in $jsonFiles) {
            Write-Information "  Processing $($file.Name)..." -InformationAction Continue
            foreach ($line in Get-GzipLine -Path $file.FullName) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                try { $v = $line | ConvertFrom-Json }
                catch {
                    $parseErrors++
                    if ($parseErrors -le 5) { Write-Warning "Parse error in $($file.Name): $_" }
                    continue
                }
                if ($v.PSObject.Properties['IsOnboarded']?.Value -ne $true) { continue }
                $processedCount++

                $deviceId = $v.DeviceId
                if (-not $deviceIndex.ContainsKey($deviceId)) {
                    $machine = $Machines[$deviceId]

                    $groupName = if ($machine) { $machine.PSObject.Properties['rbacGroupName']?.Value } else { $v.PSObject.Properties['RbacGroupName']?.Value }
                    if ([string]::IsNullOrWhiteSpace([string]$groupName)) {
                        $fallbackGroupName = $v.PSObject.Properties['RbacGroupName']?.Value
                        $groupName = if ([string]::IsNullOrWhiteSpace([string]$fallbackGroupName)) { '(none)' } else { $fallbackGroupName }
                    }
                    $groupIdx = Get-OrCreateIndex -value $groupName -list $lookups.groups -indexMap $groupIndex

                    $osPlat = if ($machine) { $machine.PSObject.Properties['osPlatform']?.Value } else { $v.PSObject.Properties['OSPlatform']?.Value }
                    $platIdx = Get-OrCreateIndex -value $osPlat -list $lookups.platforms -indexMap $platformIndex

                    $machineTags = if ($machine -and $machine.PSObject.Properties['machineTags']?.Value) { $machine.machineTags }
                                  elseif ($v.PSObject.Properties['MachineTags']?.Value) { $v.PSObject.Properties['MachineTags']?.Value }
                                  else { @() }
                    $tagIndices = [System.Collections.Generic.List[int]]::new()
                    foreach ($tag in $machineTags) {
                        $tagIdx = Get-OrCreateIndex -value $tag -list $lookups.tags -indexMap $tagIndex
                        if ($tagIdx -ge 0) { $tagIndices.Add($tagIdx) }
                    }
                    if ($tagIndices.Count -eq 0) { $hasNoTags = $true }

                    $deviceIndex[$deviceId] = $lookups.devices.Count

                    $machineInfo = $null
                    if ($machine) {
                        $machineLastSeen = $machine.PSObject.Properties['lastSeen']?.Value
                        $machineFirstSeen = $machine.PSObject.Properties['firstSeen']?.Value
                        $machineInfo = [PSCustomObject]@{
                            ip = $machine.PSObject.Properties['lastIpAddress']?.Value
                            eip = $machine.PSObject.Properties['lastExternalIpAddress']?.Value
                            hs = $machine.PSObject.Properties['healthStatus']?.Value
                            rs = $machine.PSObject.Properties['riskScore']?.Value
                            el = $machine.PSObject.Properties['exposureLevel']?.Value
                            dv = $machine.PSObject.Properties['deviceValue']?.Value
                            mb = $machine.PSObject.Properties['managedBy']?.Value
                            aad = $machine.PSObject.Properties['isAadJoined']?.Value
                            ls = Get-CachedYmdDate -dateValue $machineLastSeen
                            fs = Get-CachedYmdDate -dateValue $machineFirstSeen
                        }
                    }

                    $lookups.devices.Add([PSCustomObject]@{
                        id = $deviceId
                        n = if ($machine) { $machine.PSObject.Properties['computerDnsName']?.Value } elseif ($v.PSObject.Properties['DeviceName']?.Value) { $v.PSObject.Properties['DeviceName']?.Value } else { '(no machine data)' }
                        g = $groupIdx
                        o = $platIdx
                        ov = if ($machine) { $machine.PSObject.Properties['osVersion']?.Value } else { $v.PSObject.Properties['OSVersion']?.Value }
                        t = $tagIndices
                        m = $machineInfo
                    })
                }
                $devIdx = $deviceIndex[$deviceId]

                $vendorIdx = Get-OrCreateIndex -value $v.PSObject.Properties['SoftwareVendor']?.Value -list $lookups.vendors -indexMap $vendorIndex

                $softwareVendor = $v.PSObject.Properties['SoftwareVendor']?.Value ?? ''
                $softwareName = $v.PSObject.Properties['SoftwareName']?.Value ?? ''
                $softwareKey = "$softwareVendor|$softwareName"
                if (-not $softwareIndex.ContainsKey($softwareKey)) {
                    $softwareIndex[$softwareKey] = $lookups.software.Count
                    $lookups.software.Add([PSCustomObject]@{
                        v = $vendorIdx
                        n = $softwareName
                        r = $v.PSObject.Properties['RecommendationReference']?.Value
                    })
                }
                $swIdx = $softwareIndex[$softwareKey]

                $cveId = $v.CveId
                $cvssScore = $v.PSObject.Properties['CvssScore']?.Value
                $sevLevel = $v.PSObject.Properties['VulnerabilitySeverityLevel']?.Value
                $sevIdx = switch ($sevLevel) {
                    'Critical' { 0 }
                    'High' { 1 }
                    'Medium' { 2 }
                    'Low' { 3 }
                    default { -1 }
                }

                $exploitabilityLevel = $v.PSObject.Properties['ExploitabilityLevel']?.Value
                $expIdx = Get-OrCreateIndex -value $exploitabilityLevel -list $lookups.exploitLevels -indexMap $exploitIndex

                $cveBatchUrl = Convert-CveUrl -Url $v.PSObject.Properties['CveBatchUrl']?.Value
                $btValue = $v.PSObject.Properties['CveBatchTitle']?.Value
                $cveKey = @(
                    [string]$cveId,
                    [string]$cvssScore,
                    [string]$sevLevel,
                    [string]$exploitabilityLevel,
                    [string]$cveBatchUrl,
                    [string]$btValue
                ) -join '|'

                if (-not $cveIndex.ContainsKey($cveKey)) {
                    $ahData = $AdvancedHuntingData[$cveId]
                    $publishedDate = $null
                    $vulnDescription = $null
                    $epssScore = $null
                    $affSoftwareIndices = $null
                    if ($ahData) {
                        $publishedDate = $ahData.PublishedDate
                        $vulnDescription = $ahData.VulnerabilityDescription
                        $epssScore = $ahData.EpssScore
                        if ($ahData.AffectedSoftware -and $ahData.AffectedSoftware.Count -gt 0) {
                            $affSoftwareIndices = [System.Collections.Generic.List[int]]::new()
                            foreach ($sw in $ahData.AffectedSoftware) {
                                $asIdx = Get-OrCreateIndex -value $sw -list $lookups.affSoftware -indexMap $affSoftwareIndex
                                if ($asIdx -ge 0) { $affSoftwareIndices.Add($asIdx) }
                            }
                        }
                    }

                    $btIdx = Get-OrCreateIndex -value $btValue -list $lookups.batchTitles -indexMap $batchTitleIndex

                    $cveIndex[$cveKey] = $lookups.cves.Count
                    $lookups.cves.Add([PSCustomObject]@{
                        id = $cveId
                        sc = $cvssScore
                        sv = $sevIdx
                        ex = $expIdx
                        u = $cveBatchUrl
                        bt = $btIdx
                        pd = $publishedDate
                        desc = $vulnDescription
                        ep = $epssScore
                        as = $affSoftwareIndices
                    })
                }
                $cveIdx = $cveIndex[$cveKey]

                $recUpdate = $v.PSObject.Properties['RecommendedSecurityUpdate']?.Value
                $recUpdateId = $v.PSObject.Properties['RecommendedSecurityUpdateId']?.Value
                $recUpdateUrl = $v.PSObject.Properties['RecommendedSecurityUpdateUrl']?.Value
                $updateName = if ($recUpdate -and $recUpdate -ne '--') { $recUpdate } else { $null }
                if ($null -eq $updateName -or $updateName -eq '') {
                    $updIdx = -1
                }
                else {
                    $updateKey = @(
                        [string]$updateName,
                        [string]$recUpdateId,
                        [string]$recUpdateUrl
                    ) -join '|'
                    if ($updateIndex.ContainsKey($updateKey)) {
                        $updIdx = $updateIndex[$updateKey]
                    }
                    else {
                        $updIdx = $lookups.updates.Count
                        $updateIndex[$updateKey] = $updIdx
                        $lookups.updates.Add([PSCustomObject]@{
                            n = $updateName
                            id = $recUpdateId
                            url = $recUpdateUrl
                        })
                    }
                }

                $firstSeenTs = $v.PSObject.Properties['FirstSeenTimestamp']?.Value
                $lastSeenTs = $v.PSObject.Properties['LastSeenTimestamp']?.Value
                $firstSeen = Get-CachedYmdDate -dateValue $firstSeenTs
                $lastSeen = Get-CachedYmdDate -dateValue $lastSeenTs

                if ($firstSeen -and $lastSeen -and $firstSeen -gt $lastSeen) {
                    $temp = $firstSeen
                    $firstSeen = $lastSeen
                    $lastSeen = $temp
                    $firstLastSwappedCount++
                }

                if (-not $firstSeen) { $firstSeen = '' }
                if (-not $lastSeen) { $lastSeen = '' }
                $firstSeenIdx = Get-OrCreateIndex -value $firstSeen -list $lookups.dates -indexMap $dateIndex
                $lastSeenIdx = Get-OrCreateIndex -value $lastSeen -list $lookups.dates -indexMap $dateIndex

                $versionStr = $v.PSObject.Properties['SoftwareVersion']?.Value
                $versionIdx = Get-OrCreateIndex -value $versionStr -list $lookups.versions -indexMap $versionIndex

                $rawDiskPaths = $v.PSObject.Properties['DiskPaths']?.Value
                $rawRegPaths = $v.PSObject.Properties['RegistryPaths']?.Value
                $diskPathIndices = $null
                $regPathIndices = $null
                if ($rawDiskPaths -and $rawDiskPaths.Count -gt 0) {
                    $diskPathIndices = [System.Collections.Generic.List[int]]::new()
                    foreach ($dp in $rawDiskPaths) {
                        $dpIdx = Get-OrCreateIndex -value $dp -list $lookups.diskPaths -indexMap $diskPathIndex
                        if ($dpIdx -ge 0) { $diskPathIndices.Add($dpIdx) }
                    }
                }
                if ($rawRegPaths -and $rawRegPaths.Count -gt 0) {
                    $regPathIndices = [System.Collections.Generic.List[int]]::new()
                    foreach ($rp in $rawRegPaths) {
                        $rpIdx = Get-OrCreateIndex -value $rp -list $lookups.regPaths -indexMap $regPathIndex
                        if ($rpIdx -ge 0) { $regPathIndices.Add($rpIdx) }
                    }
                }

                $secUpdateAvail = $v.PSObject.Properties['SecurityUpdateAvailable']?.Value
                $compactRecord = @(
                    $devIdx,
                    $cveIdx,
                    $swIdx,
                    $versionIdx,
                    $firstSeenIdx,
                    $lastSeenIdx,
                    [int]($secUpdateAvail -eq $true),
                    $updIdx,
                    $diskPathIndices,
                    $regPathIndices
                )

                if (-not $isFirstVuln) {
                    $vulnWriter.Write(',')
                }
                $vulnWriter.Write(($compactRecord | ConvertTo-Json -Compress -Depth 5))
                $isFirstVuln = $false
            }
        }

        $vulnWriter.Write(']')
    }
    finally {
        if ($vulnWriter) {
            $vulnWriter.Dispose()
        }
        if ($tempMergedVulnPath -and (Test-Path -LiteralPath $tempMergedVulnPath)) {
            Remove-Item -LiteralPath $tempMergedVulnPath -Force
        }
    }

    if ($parseErrors -gt 0) { Write-Warning "Parse errors: $parseErrors" }
    if ($processedCount -eq 0) { throw 'No onboarded vulnerabilities found after streaming all export files.' }
    Write-Information "  Loaded $processedCount onboarded vulnerability records" -InformationAction Continue

    $noTagsLabel = '(No Tags)'
    if ($hasNoTags -and -not $tagIndex.ContainsKey($noTagsLabel)) {
        $tagIndex[$noTagsLabel] = $lookups.tags.Count
        $lookups.tags.Add($noTagsLabel)
    }
    $noTagsIdx = if ($tagIndex.ContainsKey($noTagsLabel)) { $tagIndex[$noTagsLabel] } else { -1 }

    Write-Information "  Normalized: $($lookups.devices.Count) devices, $($lookups.cves.Count) CVEs, $($lookups.software.Count) software, $($lookups.vendors.Count) vendors" -InformationAction Continue
    if ($firstLastSwappedCount -gt 0) {
        Write-Warning "  Corrected $firstLastSwappedCount record(s) with FirstSeenTimestamp > LastSeenTimestamp"
    }

    $datasetVendors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($vendor in $lookups.vendors) {
        [void]$datasetVendors.Add($vendor)
    }

    foreach ($cve in $lookups.cves) {
        if ($null -ne $cve.as -and $cve.as.Count -gt 0) {
            $filteredIndices = [System.Collections.Generic.List[int]]::new()
            foreach ($asIdx in $cve.as) {
                $swStr = $lookups.affSoftware[$asIdx]
                $separatorIndex = $swStr.IndexOf(':')
                $swVendor = if ($separatorIndex -ge 0) { $swStr.Substring(0, $separatorIndex) } else { $swStr }
                if ($datasetVendors.Contains($swVendor)) {
                    $filteredIndices.Add($asIdx)
                }
            }
            $cve.as = if ($filteredIndices.Count -gt 0) { $filteredIndices } else { $null }
        }
    }

    return @{
        Lookups = [PSCustomObject]@{
            vendors = $lookups.vendors
            severities = $lookups.severities
            exploitLevels = $lookups.exploitLevels
            groups = $lookups.groups
            platforms = $lookups.platforms
            tags = $lookups.tags
            updates = $lookups.updates
            versions = $lookups.versions
            dates = $lookups.dates
            diskPaths = $lookups.diskPaths
            regPaths = $lookups.regPaths
            affSoftware = $lookups.affSoftware
            batchTitles = $lookups.batchTitles
            devices = $lookups.devices
            software = $lookups.software
            cves = $lookups.cves
            noTagsIdx = $noTagsIdx
        }
        Quality = [PSCustomObject]@{
            FirstLastSwappedCount = $firstLastSwappedCount
        }
        VulnCount = $processedCount
        VulnsPath = $VulnOutputPath
    }
}
