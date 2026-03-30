
# =============================================================================
# TEMPORARY LEGACY VULNERABILITY MIGRATION HELPERS
# Remove after $Script:LegacyVulnMigrationRemovalDate once legacy VulnExport_* snapshots
# are no longer supported.
# =============================================================================

function Test-VulnStoreRequiresCanonicalRepair {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [object[]]$HistoryDocuments
    )

    $historyFiles = @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue)
    if (@($historyFiles | Where-Object { $_.BaseName -match '^VulnHistory_\d{4}$' }).Count -gt 0) {
        return $true
    }

    foreach ($historyDocument in @($HistoryDocuments)) {
        $periodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $historyDocument
        $rowsPath = Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodKey
        if (-not (Test-Path -LiteralPath $rowsPath -PathType Leaf)) {
            return $true
        }
    }

    return $false
}

function Publish-VulnStoreExistingCanonicalState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$LatestSnapshotDate
    )

    $currentPath = Get-VulnCurrentPath -BasePath $BasePath
    $historyDocuments = @(Get-VulnHistoryDocumentList -BasePath $BasePath)
    $requiresCanonicalRepair = Test-VulnStoreRequiresCanonicalRepair -BasePath $BasePath -HistoryDocuments $historyDocuments
    if ($requiresCanonicalRepair) {
        $currentRecords = if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
            @(Read-VulnNdjsonRecordsFromPath -Path $currentPath)
        }
        else {
            @()
        }

        [void](Publish-VulnStoreUnlocked -BasePath $BasePath -Store ([PSCustomObject]@{
            CurrentRecords = $currentRecords
            HistoryDocuments = $historyDocuments
            LatestSnapshotDate = $LatestSnapshotDate
        }))
    }

    $historyPeriodCount = Repair-VulnHistoryLayout -BasePath $BasePath
    $currentRows = if (Test-Path -LiteralPath $currentPath -PathType Leaf) { Test-VulnCurrentFile -Path $currentPath } else { 0 }
    Publish-VulnContentStoreUnlocked -BasePath $BasePath

    return [PSCustomObject]@{
        CurrentRows = $currentRows
        HistoryYears = if ($historyPeriodCount -gt 0) { $historyPeriodCount } else { $historyDocuments.Count }
        LatestSnapshotDate = $LatestSnapshotDate
        MigratedLegacy = $requiresCanonicalRepair
    }
}

function Get-VulnLegacyFilesBySnapshotDate {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$LegacyFiles,

        [Parameter(Mandatory = $true)]
        [string[]]$SnapshotDates
    )

    $filesByDate = @{}
    foreach ($file in @($LegacyFiles)) {
        $date = Get-VulnSnapshotDateFromName -Name $file.Name
        if ($date -notin $SnapshotDates) { continue }
        if (-not $filesByDate.ContainsKey($date)) {
            $filesByDate[$date] = [System.Collections.Generic.List[object]]::new()
        }
        $filesByDate[$date].Add($file)
    }

    return $filesByDate
}

function Publish-VulnStoreFromLegacySnapshot {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveLegacyFiles
    )

    if ([datetime]::UtcNow -ge [datetime]$Script:LegacyVulnMigrationRemovalDate) {
        Write-Warning "Legacy vulnerability migration is past its scheduled removal date ($Script:LegacyVulnMigrationRemovalDate). This code path should be removed."
    }

    $legacyFiles = @(Get-VulnLegacySnapshotFile -BasePath $BasePath -LegacyFilePaths $LegacyFilePaths)

    if ($legacyFiles.Count -eq 0) {
        throw "No legacy VulnExport snapshot files found in '$BasePath'."
    }

    $publishOutput = @(Invoke-WithStoreLock -BasePath $BasePath -StoreName 'vuln' -ScriptBlock {
        Restore-StoreTransaction -BasePath $BasePath -StoreName 'vuln'

        $storeExists = Test-VulnStoreExistence -BasePath $BasePath
        $partitionCount = $Script:VulnDiskPartitionCount
        $latestKnownSnapshot = if ($storeExists) { Get-VulnStoreLatestSnapshotDate -BasePath $BasePath } else { $null }
        $snapshotDates = @($legacyFiles | ForEach-Object { Get-VulnSnapshotDateFromName -Name $_.Name } | Sort-Object -Unique)

        if (-not [string]::IsNullOrWhiteSpace($latestKnownSnapshot)) {
            $duplicateLatestDates = @($snapshotDates | Where-Object { ([datetime]$_) -eq ([datetime]$latestKnownSnapshot) })
            if ($duplicateLatestDates.Count -gt 0) {
                Write-Verbose "Skipping legacy snapshot dates already represented by the current store latest snapshot date. StoreLatest=$latestKnownSnapshot Incoming=$($duplicateLatestDates -join ', ')"
                $snapshotDates = @($snapshotDates | Where-Object { ([datetime]$_) -ne ([datetime]$latestKnownSnapshot) })
            }

            $backfillDates = @($snapshotDates | Where-Object { ([datetime]$_) -lt ([datetime]$latestKnownSnapshot) })
            if ($backfillDates.Count -gt 0) {
                throw ("Legacy snapshot date(s) {0} are older than the current store latest snapshot date {1}. Incremental import would skip or mis-order those older snapshots. Rebuild the vulnerability store from the full legacy snapshot set before importing backfilled history." -f ($backfillDates -join ', '), $latestKnownSnapshot)
            }
        }

        if ($snapshotDates.Count -eq 0 -and $storeExists) {
            $canonicalState = Publish-VulnStoreExistingCanonicalState -BasePath $BasePath -LatestSnapshotDate $latestKnownSnapshot
            return [PSCustomObject]@{
                DownloadedFiles = $legacyFiles.Count
                CurrentRows = $canonicalState.CurrentRows
                HistoryYears = $canonicalState.HistoryYears
                LatestSnapshotDate = $canonicalState.LatestSnapshotDate
                MigratedLegacy = $canonicalState.MigratedLegacy
                RemovedLegacyFiles = $false
            }
        }

        $filesByDate = Get-VulnLegacyFilesBySnapshotDate -LegacyFiles $legacyFiles -SnapshotDates $snapshotDates

        $stageRoot = Join-Path $BasePath ('.vuln-store-staging-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -Path $stageRoot -ItemType Directory -Force)

        $historyAppendState = @{}
        try {
            $currentPath = Get-VulnCurrentPath -BasePath $BasePath
            $currentPartitionRoot = Join-Path $stageRoot 'current-partitions'
            [void](New-Item -Path $currentPartitionRoot -ItemType Directory -Force)
            if ($storeExists -and (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
                [void](Split-VulnJsonPartition -InputPaths @($currentPath) -OutputRoot $currentPartitionRoot -Prefix 'current' -PartitionCount $partitionCount)
            }

            Write-Output ("  Canonicalizing {0} new snapshot date(s) across {1} file(s) using {2} disk partition(s)..." -f $snapshotDates.Count, $legacyFiles.Count, $partitionCount)
            foreach ($snapshotDate in $snapshotDates) {
                $closedOn = Get-VulnPreviousDay -Date $snapshotDate
                $snapshotPartitionRoot = Join-Path $stageRoot ('snapshot-' + $snapshotDate)
                [void](New-Item -Path $snapshotPartitionRoot -ItemType Directory -Force)
                $snapshotFilesForDate = @($filesByDate[$snapshotDate] ?? @())
                $snapshotIndex = [array]::IndexOf($snapshotDates, $snapshotDate) + 1
                Write-Output ("  [{0}/{1}] Processing snapshot date {2} from {3} file(s)..." -f $snapshotIndex, $snapshotDates.Count, $snapshotDate, $snapshotFilesForDate.Count)
                if (Get-Command -Name Write-MemoryUsage -ErrorAction SilentlyContinue) {
                    Write-MemoryUsage -Label ("VulnStore " + $snapshotDate + " Start")
                }

                try {
                    [void](Split-VulnJsonPartition `
                        -InputPaths @($snapshotFilesForDate | ForEach-Object { $_.FullName }) `
                        -OutputRoot $snapshotPartitionRoot `
                        -Prefix 'snapshot' `
                        -OnboardedOnly `
                        -PartitionCount $partitionCount)

                    for ($partitionIndex = 0; $partitionIndex -lt $partitionCount; $partitionIndex++) {
                        $currentPartitionPath = Get-VulnPartitionFilePath -Root $currentPartitionRoot -Prefix 'current' -Index $partitionIndex
                        $snapshotPartitionPath = Get-VulnPartitionFilePath -Root $snapshotPartitionRoot -Prefix 'snapshot' -Index $partitionIndex

                        if (-not (Test-Path -LiteralPath $currentPartitionPath -PathType Leaf) -and -not (Test-Path -LiteralPath $snapshotPartitionPath -PathType Leaf)) {
                            continue
                        }

                        $currentMap = Read-VulnPartitionMapFile -Path $currentPartitionPath
                        $snapshotRows = Read-VulnPartitionMapFile -Path $snapshotPartitionPath

                        foreach ($id in @($currentMap.Keys)) {
                            if ($snapshotRows.ContainsKey($id)) { continue }

                            $closedEntry = New-ClosedVulnEntry -Record ($currentMap[$id].Json | ConvertFrom-Json -Depth 20) -Reason 'removed' -ClosedOn $closedOn
                            Add-VulnHistoryEntryToAppendStore -AppendStateByPeriod $historyAppendState -ScratchRoot $stageRoot -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry
                        }

                        foreach ($id in @($snapshotRows.Keys)) {
                            $incomingVersion = $snapshotRows[$id]
                            $incomingRecord = $incomingVersion.Json | ConvertFrom-Json -Depth 20
                            $existing = $currentMap[$id]
                            $versionStartDate = if ($null -eq $existing -or [string]::IsNullOrWhiteSpace([string]$existing.VersionStartDate)) {
                                $snapshotDate
                            }
                            else {
                                [string]$existing.VersionStartDate
                            }

                            if ($null -ne $existing -and [string]$existing.Signature -ne [string]$incomingVersion.Signature) {
                                $closedEntry = New-ClosedVulnEntry -Record ($existing.Json | ConvertFrom-Json -Depth 20) -Reason 'changed' -ClosedOn $closedOn -ReplacementId $id
                                Add-VulnHistoryEntryToAppendStore -AppendStateByPeriod $historyAppendState -ScratchRoot $stageRoot -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry
                                $versionStartDate = $snapshotDate
                            }

                            $openRecord = New-OpenVulnRecord -Record $incomingRecord -VersionStartDate $versionStartDate
                            $snapshotRows[$id] = [PSCustomObject]@{
                                Json = $openRecord | ConvertTo-Json -Compress -Depth 20
                                Signature = [string]$incomingVersion.Signature
                                VersionStartDate = $versionStartDate
                            }
                        }

                        [void](Write-VulnPartitionMapFile -Path $currentPartitionPath -RowsById $snapshotRows)
                    }
                }
                finally {
                    if (Get-Command -Name Write-MemoryUsage -ErrorAction SilentlyContinue) {
                        Write-MemoryUsage -Label ("VulnStore " + $snapshotDate + " End")
                    }
                    if (Test-Path -LiteralPath $snapshotPartitionRoot) {
                        Remove-Item -LiteralPath $snapshotPartitionRoot -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }

            Close-VulnHistoryAppendStore -AppendStateByPeriod $historyAppendState

            $stagedCurrentPath = Get-VulnCurrentPath -BasePath $stageRoot
            [void](Write-VulnCurrentFileFromPartition -PartitionRoot $currentPartitionRoot -PartitionPrefix 'current' -OutputPath $stagedCurrentPath -PartitionCount $partitionCount)
            $currentCount = Test-VulnCurrentFile -Path $stagedCurrentPath

            $filesToPublish = [System.Collections.Generic.List[object]]::new()
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = $stagedCurrentPath
                TargetPath = Get-VulnCurrentPath -BasePath $BasePath
            })

            $existingHistoryByPeriod = @{}
            foreach ($historyDocument in Get-VulnHistoryDocumentList -BasePath $BasePath) {
                $existingHistoryByPeriod[(Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $historyDocument)] = $historyDocument
            }

            $touchedPeriods = @($historyAppendState.Keys | Sort-Object)
            foreach ($periodKey in $touchedPeriods) {
                $appendState = $historyAppendState[$periodKey]
                $existingDocument = if ($existingHistoryByPeriod.ContainsKey($periodKey)) {
                    $existingHistoryByPeriod[$periodKey]
                }
                else {
                    $null
                }
                $existingLatestDate = if ($null -ne $existingDocument) {
                    Get-VulnHistoryDocumentLatestDate -HistoryDocument $existingDocument
                }
                else {
                    $null
                }

                $finalLatestDate = Get-MaxVulnDate `
                    -Primary $existingLatestDate `
                    -Secondary ([string]$appendState.LatestDate)
                $historyStagePath = Get-VulnHistoryPath -BasePath $stageRoot -PeriodKey $periodKey
                Write-VulnHistoryDocumentFromAppendFile `
                    -Path $historyStagePath `
                    -PeriodKey $periodKey `
                    -ExistingDocument $existingDocument `
                    -AppendPath ([string]$appendState.AppendPath) `
                    -LatestDate $finalLatestDate
                [void](Test-VulnHistoryFileLightweight -Path $historyStagePath)
                $historyRowsStagePath = Get-VulnHistoryRowsPath -BasePath $stageRoot -PeriodKey $periodKey
                Write-VulnHistoryRowsFileFromAppendFile `
                    -Path $historyRowsStagePath `
                    -ExistingDocument $existingDocument `
                    -AppendPath ([string]$appendState.AppendPath)

                $filesToPublish.Add([PSCustomObject]@{
                    StagePath = $historyStagePath
                    TargetPath = Get-VulnHistoryPath -BasePath $BasePath -PeriodKey $periodKey
                })
                $filesToPublish.Add([PSCustomObject]@{
                    StagePath = $historyRowsStagePath
                    TargetPath = Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodKey
                })
            }

            foreach ($periodKey in @($existingHistoryByPeriod.Keys | Sort-Object)) {
                if ($periodKey -in $touchedPeriods) { continue }

                $historyRowsTargetPath = Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodKey
                if (Test-Path -LiteralPath $historyRowsTargetPath -PathType Leaf) { continue }

                $historyRowsStagePath = Get-VulnHistoryRowsPath -BasePath $stageRoot -PeriodKey $periodKey
                Write-VulnHistoryRowsFile -Path $historyRowsStagePath -HistoryDocument $existingHistoryByPeriod[$periodKey]
                $filesToPublish.Add([PSCustomObject]@{
                    StagePath = $historyRowsStagePath
                    TargetPath = $historyRowsTargetPath
                })
            }

            $finalHistoryPeriods = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($periodKey in $existingHistoryByPeriod.Keys) { [void]$finalHistoryPeriods.Add([string]$periodKey) }
            foreach ($periodKey in $touchedPeriods) { [void]$finalHistoryPeriods.Add([string]$periodKey) }

            $publishedHistoryNames = if ($finalHistoryPeriods.Count -gt 0) {
                Get-VulnHistoryPublishedNameSet -PeriodKeys @($finalHistoryPeriods)
            }
            else {
                [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
            $historyFilesToRemove = Get-VulnHistoryRemovePaths -BasePath $BasePath -PublishedHistoryNames $publishedHistoryNames
            Publish-StoreFilesTransactional -BasePath $BasePath -StoreName 'vuln' -Files @($filesToPublish) -RemovePaths $historyFilesToRemove
            $historyPeriodCount = Repair-VulnHistoryLayout -BasePath $BasePath
            Publish-VulnContentStoreUnlocked -BasePath $BasePath

            return [PSCustomObject]@{
                DownloadedFiles = $legacyFiles.Count
                CurrentRows = $currentCount
                HistoryYears = if ($historyPeriodCount -gt 0) { $historyPeriodCount } else { $finalHistoryPeriods.Count }
                LatestSnapshotDate = if ($snapshotDates.Count -gt 0) { $snapshotDates[-1] } else { $latestKnownSnapshot }
                MigratedLegacy = $true
                RemovedLegacyFiles = $false
            }
        }
        finally {
            Close-VulnHistoryAppendStore -AppendStateByPeriod $historyAppendState
            if (Test-Path -LiteralPath $stageRoot) {
                Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    })

    $publishResult = $null
    foreach ($item in $publishOutput) {
        if ($null -ne $item -and $item.PSObject.Properties.Match('MigratedLegacy').Count -gt 0) {
            $publishResult = $item
            continue
        }

        if ($null -ne $item) {
            Write-Host ([string]$item)
        }
    }

    if ($null -eq $publishResult) {
        throw 'Publish-VulnStoreFromLegacySnapshot did not return a publish result.'
    }

    if ($RemoveLegacyFiles) {
        foreach ($legacyFile in @(Get-VulnLegacySnapshotFile -BasePath $BasePath)) {
            Remove-Item -Path $legacyFile.FullName -Force
        }
    }

    return [PSCustomObject]@{
        DownloadedFiles = $publishResult.DownloadedFiles
        CurrentRows = $publishResult.CurrentRows
        HistoryYears = $publishResult.HistoryYears
        LatestSnapshotDate = $publishResult.LatestSnapshotDate
        MigratedLegacy = $publishResult.MigratedLegacy
        RemovedLegacyFiles = ($RemoveLegacyFiles -eq $true)
    }
}

function Read-VulnStoreRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    Invoke-WithStoreLock -BasePath $BasePath -StoreName 'vuln' -ScriptBlock {
        Restore-StoreTransaction -BasePath $BasePath -StoreName 'vuln'

        if (-not (Test-VulnContentStoreExistence -BasePath $BasePath)) {
            try {
                Publish-VulnContentStoreUnlocked -BasePath $BasePath
            }
            catch {
                Write-Verbose "Vulnerability content sidecar rebuild failed; falling back to raw row files. $_"
            }
        }

        if (Test-VulnContentStoreExistence -BasePath $BasePath) {
            foreach ($record in Read-VulnContentStoreRow -BasePath $BasePath) {
                Write-Output $record
            }
            return
        }

        $currentPath = Get-VulnCurrentPath -BasePath $BasePath
        if (Test-Path -Path $currentPath) {
            foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $currentPath) {
                Write-Output $record
            }
        }

        $historyFiles = @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File | Sort-Object Name)
        foreach ($file in $historyFiles) {
            $periodMatch = [regex]::Match($file.Name, '^VulnHistory_(?<period>\d{4}Q[1-4]|\d{4})\.json\.gz$')
            $rowsPath = if ($periodMatch.Success) {
                Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodMatch.Groups['period'].Value
            }
            else {
                $null
            }
            $rowsReadPath = if (-not [string]::IsNullOrWhiteSpace($rowsPath) -and (Test-Path -LiteralPath $rowsPath -PathType Leaf)) {
                $rowsPath
            }
            elseif (-not [string]::IsNullOrWhiteSpace($rowsPath)) {
                $legacyRowsPath = $rowsPath -replace '\.gz$', ''
                if (Test-Path -LiteralPath $legacyRowsPath -PathType Leaf) { $legacyRowsPath } else { $null }
            }
            else {
                $null
            }

            if (-not [string]::IsNullOrWhiteSpace($rowsReadPath)) {
                foreach ($record in Read-VulnNdjsonRecordsFromPath -Path $rowsReadPath) {
                    Write-Output $record
                }
                continue
            }

            foreach ($record in Read-VulnHistoryRowsFromPath -Path $file.FullName) {
                Write-Output $record
            }
        }
    } | Write-Output
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
    $hasYear = $null -ne $document.PSObject.Properties['year']
    $hasPeriod = $null -ne $document.PSObject.Properties['period']
    $hasQuarter = $null -ne $document.PSObject.Properties['quarter']
    if ((-not $hasYear) -or (($hasPeriod -or $hasQuarter) -and -not ($hasPeriod -and $hasQuarter))) {
        throw "History file '$Path' is missing required partition metadata."
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

function Test-VulnHistoryFileLightweight {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 2
        $bytesRead = $fileStream.Read($header, 0, $header.Length)
        $fileStream.Position = 0

        $contentStream = if (($bytesRead -eq 2) -and $header[0] -eq 0x1f -and $header[1] -eq 0x8b) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $prefixBuilder = [System.Text.StringBuilder]::new()
                $buffer = New-Object char[] 8192
                $totalChars = 0

                while (($charsRead = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($prefixBuilder.Length -lt 4096) {
                        $charsToKeep = [Math]::Min(4096 - $prefixBuilder.Length, $charsRead)
                        [void]$prefixBuilder.Append($buffer, 0, $charsToKeep)
                    }
                    $totalChars += $charsRead
                }

                if ($totalChars -eq 0) {
                    throw "History file '$Path' is empty."
                }

                $prefix = $prefixBuilder.ToString()
                if ($prefix -notmatch '^\s*\{') {
                    throw "History file '$Path' does not begin with a JSON object."
                }
                if ($prefix -notmatch '"year"\s*:') {
                    throw "History file '$Path' is missing 'year'."
                }
                if ($prefix -notmatch '"latestDate"\s*:') {
                    throw "History file '$Path' is missing 'latestDate'."
                }
                if ($prefix -notmatch '"snapshots"\s*:') {
                    throw "History file '$Path' is missing 'snapshots'."
                }
                $hasPeriod = $prefix -match '"period"\s*:'
                $hasQuarter = $prefix -match '"quarter"\s*:'
                if ($hasPeriod -xor $hasQuarter) {
                    throw "History file '$Path' has incomplete quarter partition metadata."
                }

                return $totalChars
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

function Get-VulnHistoryDocumentList {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $documents = [System.Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name) {
        foreach ($document in Convert-VulnHistoryDocumentToQuarterlyDocuments -HistoryDocument (Read-VulnHistoryDocument -Path $file.FullName)) {
            $documents.Add($document)
        }
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

    foreach ($file in Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name) {
        $docLatest = Get-VulnHistoryFileLatestDate -Path $file.FullName
        if (-not [string]::IsNullOrWhiteSpace($docLatest)) {
            $maxDate = Get-MaxVulnDate -Primary $maxDate -Secondary $docLatest
        }
    }

    return $maxDate
}

function Add-VulnHistoryEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$HistoryByPeriod,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate,

        [Parameter(Mandatory = $true)]
        [string]$ClosedOn,

        [Parameter(Mandatory = $true)]
        $Entry,

        [hashtable]$SnapshotMaps = $null
    )

    $periodKey = Get-VulnHistoryPeriodKeyFromDate -Date $ClosedOn
    if (-not $HistoryByPeriod.ContainsKey($periodKey)) {
        $HistoryByPeriod[$periodKey] = Get-VulnHistorySeed -PeriodKey $periodKey
    }

    if ($null -ne $SnapshotMaps) {
        if (-not $SnapshotMaps.ContainsKey($periodKey)) {
            $SnapshotMaps[$periodKey] = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByPeriod[$periodKey]
        }
        $snapshotMap = $SnapshotMaps[$periodKey]
        if (-not $snapshotMap.ContainsKey($SnapshotDate)) {
            $newSnapshot = [PSCustomObject]@{ date = $SnapshotDate; closed = @() }
            $HistoryByPeriod[$periodKey].snapshots += $newSnapshot
            $snapshotMap[$SnapshotDate] = $newSnapshot
        }
    } else {
        $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByPeriod[$periodKey]
        if (-not $snapshotMap.ContainsKey($SnapshotDate)) {
            $HistoryByPeriod[$periodKey].snapshots += [PSCustomObject]@{ date = $SnapshotDate; closed = @() }
            $snapshotMap = Get-VulnHistorySnapshotMap -HistoryDocument $HistoryByPeriod[$periodKey]
        }
    }

    $snapshotMap[$SnapshotDate].closed += $Entry

    $currentLatest = [string](Get-VulnPropertyValue -InputObject $HistoryByPeriod[$periodKey] -Name 'latestDate')
    $newLatest = Get-MaxVulnDate -Primary $currentLatest -Secondary $SnapshotDate
    if ($HistoryByPeriod[$periodKey] -is [System.Collections.IDictionary]) {
        $HistoryByPeriod[$periodKey]['latestDate'] = $newLatest
    } else {
        $HistoryByPeriod[$periodKey] | Add-Member -NotePropertyName 'latestDate' -NotePropertyValue $newLatest -Force
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

    $historyByPeriod = @{}
    foreach ($document in Get-VulnHistoryDocumentList -BasePath $BasePath) {
        $historyByPeriod[(Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $document)] = $document
    }
    $snapshotMaps = @{}

    $latestKnownSnapshot = Get-VulnStoreLatestSnapshotDate -BasePath $BasePath
    $snapshotDates = @($legacyFiles | ForEach-Object { Get-VulnSnapshotDateFromName -Name $_.Name } | Sort-Object -Unique)

    if (-not [string]::IsNullOrWhiteSpace($latestKnownSnapshot)) {
        $duplicateLatestDates = @($snapshotDates | Where-Object { ([datetime]$_) -eq ([datetime]$latestKnownSnapshot) })
        if ($duplicateLatestDates.Count -gt 0) {
            Write-Verbose "Skipping legacy snapshot dates already represented by the current store latest snapshot date. StoreLatest=$latestKnownSnapshot Incoming=$($duplicateLatestDates -join ', ')"
            $snapshotDates = @($snapshotDates | Where-Object { ([datetime]$_) -ne ([datetime]$latestKnownSnapshot) })
        }

        $backfillDates = @($snapshotDates | Where-Object { ([datetime]$_) -lt ([datetime]$latestKnownSnapshot) })
        if ($backfillDates.Count -gt 0) {
            throw ("Legacy snapshot date(s) {0} are older than the current store latest snapshot date {1}. Incremental import would skip or mis-order those older snapshots. Rebuild the vulnerability store from the full legacy snapshot set before importing backfilled history." -f ($backfillDates -join ', '), $latestKnownSnapshot)
        }
    }

    if ($snapshotDates.Count -eq 0) {
        return [PSCustomObject]@{
            CurrentRecords = @($currentMap.Values | Sort-Object { $_.Record.Id } | ForEach-Object { $_.Record })
            HistoryDocuments = @($historyByPeriod.Values | Sort-Object period)
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
            Add-VulnHistoryEntry -HistoryByPeriod $historyByPeriod -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps
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
            Add-VulnHistoryEntry -HistoryByPeriod $historyByPeriod -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps

            $currentMap[$id] = [PSCustomObject]@{
                Record = New-OpenVulnRecord -Record $record -VersionStartDate $snapshotDate
                Signature = $signature
                VersionStartDate = $snapshotDate
            }
        }
    }

    return [PSCustomObject]@{
        CurrentRecords = @($currentMap.Values | Sort-Object { $_.Record.Id } | ForEach-Object { $_.Record })
        HistoryDocuments = @($historyByPeriod.Values | Sort-Object period)
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
    $historyByPeriod = @{}
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
                Add-VulnHistoryEntry -HistoryByPeriod $historyByPeriod -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps
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
            Add-VulnHistoryEntry -HistoryByPeriod $historyByPeriod -SnapshotDate $snapshotDate -ClosedOn $closedOn -Entry $closedEntry -SnapshotMaps $snapshotMaps

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
        HistoryDocuments = @($historyByPeriod.Values | Sort-Object period)
        SnapshotCount = $allSnapshotDates.Count
        LatestSnapshotDate = $lastSnapshotDate
    }
}
