Set-StrictMode -Version Latest

# TEMPORARY THROUGH 2026-07-01:
# Shared helper surface for the vulnerability current/history migration and
# compatibility paths. Main scripts now invoke this automatically and the
# remaining legacy upgrade paths should be removed after callers have upgraded.

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

function Test-VulnStoreExists {
    [CmdletBinding()]
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

function Get-VulnLegacySnapshotFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths
    )

    if ($null -ne $LegacyFilePaths -and $LegacyFilePaths.Count -gt 0) {
        return @(
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

    return @(
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

    return ($Record | ConvertTo-Json -Compress -Depth 20 | ConvertFrom-Json -Depth 20)
}

function New-ClosedVulnEntry {
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
    param(
        [Parameter(Mandatory = $true)]
        [int]$Year
    )

    return [ordered]@{
        year = $Year
        snapshots = @()
    }
}

function Get-VulnHistorySnapshotMap {
    [CmdletBinding()]
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

function Publish-VulnStoreFromLegacySnapshots {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveLegacyFiles
    )

    $legacyFiles = @(Get-VulnLegacySnapshotFiles -BasePath $BasePath -LegacyFilePaths $LegacyFilePaths)

    if ($legacyFiles.Count -eq 0) {
        throw "No legacy VulnExport snapshot files found in '$BasePath'."
    }

    $store = Update-VulnStoreFromLegacySnapshots -BasePath $BasePath -LegacyFilePaths $legacyFiles.FullName
    $publishResult = Publish-VulnStore -BasePath $BasePath -Store $store

    if ($RemoveLegacyFiles) {
        foreach ($legacyFile in @(Get-VulnLegacySnapshotFiles -BasePath $BasePath)) {
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

function Read-VulnStoreRows {
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

    $writer = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        foreach ($record in @($Store.CurrentRecords)) {
            if ($null -eq $record) { continue }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
        }

        foreach ($historyDocument in @($Store.HistoryDocuments)) {
            foreach ($snapshot in @($historyDocument.snapshots)) {
                foreach ($entry in @($snapshot.closed)) {
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

    $writer = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        foreach ($record in Read-VulnStoreRows -BasePath $BasePath) {
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

    return @($document.snapshots).Count
}

function Read-VulnHistoryDocuments {
    [CmdletBinding()]
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

    foreach ($document in Read-VulnHistoryDocuments -BasePath $BasePath) {
        foreach ($snapshot in @($document.snapshots)) {
            $snapshotDate = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
            if (-not [string]::IsNullOrWhiteSpace($snapshotDate)) {
                $maxDate = Get-MaxVulnDate -Primary $maxDate -Secondary $snapshotDate
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
        $Entry
    )

    $year = ([datetime]$ClosedOn).Year
    if (-not $HistoryByYear.ContainsKey($year)) {
        $HistoryByYear[$year] = Get-VulnHistorySeed -Year $year
    }

    $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByYear[$year]
    if (-not $snapshotMap.ContainsKey($SnapshotDate)) {
        $HistoryByYear[$year].snapshots += [PSCustomObject]@{ date = $SnapshotDate; closed = @() }
        $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByYear[$year]
    }

    $snapshotMap[$SnapshotDate].closed += $Entry
}

function Update-VulnStoreFromLegacySnapshots {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths
    )

    $legacyFiles = @(Get-VulnLegacySnapshotFiles -BasePath $BasePath -LegacyFilePaths $LegacyFilePaths)

    if ($legacyFiles.Count -eq 0) {
        throw "No legacy VulnExport snapshot files found in '$BasePath'."
    }

    if (-not (Test-VulnStoreExists -BasePath $BasePath)) {
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
    foreach ($document in Read-VulnHistoryDocuments -BasePath $BasePath) {
        $historyByYear[[int]$document.year] = $document
    }

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

    foreach ($snapshotDate in $snapshotDates) {
        $snapshotRows = @{}
        foreach ($file in $legacyFiles | Where-Object { (Get-VulnSnapshotDateFromName -Name $_.Name) -eq $snapshotDate }) {
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
            Add-VulnHistoryEntry -HistoryByYear $historyByYear -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry
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
            Add-VulnHistoryEntry -HistoryByYear $historyByYear -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry

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

    $legacyFiles = @(Get-VulnLegacySnapshotFiles -BasePath $BasePath)
    if ($legacyFiles.Count -eq 0) {
        throw "No legacy VulnExport snapshot files found in '$BasePath'."
    }

    $openVersions = @{}
    $historyByYear = @{}
    $allSnapshotDates = @($legacyFiles | ForEach-Object { Get-VulnSnapshotDateFromName -Name $_.Name } | Sort-Object -Unique)
    $lastSnapshotDate = $allSnapshotDates[-1]

    foreach ($snapshotDate in $allSnapshotDates) {
        $snapshotRows = @{}
        foreach ($file in $legacyFiles | Where-Object { (Get-VulnSnapshotDateFromName -Name $_.Name) -eq $snapshotDate }) {
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
                $year = [datetime]$closedOn | ForEach-Object { $_.Year }
                if (-not $historyByYear.ContainsKey($year)) {
                    $historyByYear[$year] = Get-VulnHistorySeed -Year $year
                }
                $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $historyByYear[$year]
                if (-not $snapshotMap.ContainsKey($snapshotDate)) {
                    $historyByYear[$year].snapshots += [PSCustomObject]@{ date = $snapshotDate; closed = @() }
                    $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $historyByYear[$year]
                }
                $snapshotMap[$snapshotDate].closed += $closedEntry
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
            $year = [datetime]$closedOn | ForEach-Object { $_.Year }
            if (-not $historyByYear.ContainsKey($year)) {
                $historyByYear[$year] = Get-VulnHistorySeed -Year $year
            }
            $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $historyByYear[$year]
            if (-not $snapshotMap.ContainsKey($snapshotDate)) {
                $historyByYear[$year].snapshots += [PSCustomObject]@{ date = $snapshotDate; closed = @() }
                $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $historyByYear[$year]
            }
            $snapshotMap[$snapshotDate].closed += $closedEntry

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