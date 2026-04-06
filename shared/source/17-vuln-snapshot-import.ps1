
# Bulk snapshot import helpers. The downloaded file names retain the historic
# VulnExport_* shape, but local normalization no longer supports that format as
# a first-class input.

function Test-VulnStoreRequiresCanonicalRepair {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
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
        CanonicalRepairPerformed = $requiresCanonicalRepair
    }
}

function Get-VulnSnapshotFilesBySnapshotDate {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$SnapshotFiles,

        [Parameter(Mandatory = $true)]
        [string[]]$SnapshotDates
    )

    $filesByDate = @{}
    foreach ($file in @($SnapshotFiles)) {
        $date = Get-VulnSnapshotDateFromName -Name $file.Name
        if ($date -notin $SnapshotDates) { continue }
        if (-not $filesByDate.ContainsKey($date)) {
            $filesByDate[$date] = [System.Collections.Generic.List[object]]::new()
        }
        $filesByDate[$date].Add($file)
    }

    return $filesByDate
}

function Publish-VulnStoreFromBulkSnapshot {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$SnapshotFilePaths,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveSnapshotFiles
    )

    $snapshotFiles = @(Get-VulnLegacySnapshotFile -BasePath $BasePath -LegacyFilePaths $SnapshotFilePaths)

    if ($snapshotFiles.Count -eq 0) {
        if (-not (Test-VulnStoreExistence -BasePath $BasePath)) {
            throw "No downloaded vulnerability snapshot files were found in '$BasePath'."
        }

        $canonicalState = Publish-VulnStoreExistingCanonicalState -BasePath $BasePath -LatestSnapshotDate (Get-VulnStoreLatestSnapshotDate -BasePath $BasePath)
        return [PSCustomObject]@{
            DownloadedFiles = 0
            CurrentRows = $canonicalState.CurrentRows
            HistoryYears = $canonicalState.HistoryYears
            LatestSnapshotDate = $canonicalState.LatestSnapshotDate
            CanonicalRepairPerformed = $canonicalState.CanonicalRepairPerformed
            RemovedSnapshotFiles = $false
        }
    }

    $publishOutput = @(Invoke-WithStoreLock -BasePath $BasePath -StoreName 'vuln' -ScriptBlock {
        Restore-StoreTransaction -BasePath $BasePath -StoreName 'vuln'

        $storeExists = Test-VulnStoreExistence -BasePath $BasePath
        $partitionCount = $Script:VulnDiskPartitionCount
        $latestKnownSnapshot = if ($storeExists) { Get-VulnStoreLatestSnapshotDate -BasePath $BasePath } else { $null }
        $snapshotDates = @($snapshotFiles | ForEach-Object { Get-VulnSnapshotDateFromName -Name $_.Name } | Sort-Object -Unique)

        if (-not [string]::IsNullOrWhiteSpace($latestKnownSnapshot)) {
            $duplicateLatestDates = @($snapshotDates | Where-Object { ([datetime]$_) -eq ([datetime]$latestKnownSnapshot) })
            if ($duplicateLatestDates.Count -gt 0) {
                Write-Verbose "Skipping snapshot dates already represented by the current store latest snapshot date. StoreLatest=$latestKnownSnapshot Incoming=$($duplicateLatestDates -join ', ')"
                $snapshotDates = @($snapshotDates | Where-Object { ([datetime]$_) -ne ([datetime]$latestKnownSnapshot) })
            }

            $backfillDates = @($snapshotDates | Where-Object { ([datetime]$_) -lt ([datetime]$latestKnownSnapshot) })
            if ($backfillDates.Count -gt 0) {
                throw ("Snapshot date(s) {0} are older than the current store latest snapshot date {1}. Rebuild the vulnerability store from the full snapshot set before importing backfilled history." -f ($backfillDates -join ', '), $latestKnownSnapshot)
            }
        }

        if ($snapshotDates.Count -eq 0 -and $storeExists) {
            $canonicalState = Publish-VulnStoreExistingCanonicalState -BasePath $BasePath -LatestSnapshotDate $latestKnownSnapshot
            return [PSCustomObject]@{
                DownloadedFiles = $snapshotFiles.Count
                CurrentRows = $canonicalState.CurrentRows
                HistoryYears = $canonicalState.HistoryYears
                LatestSnapshotDate = $canonicalState.LatestSnapshotDate
                CanonicalRepairPerformed = $canonicalState.CanonicalRepairPerformed
                RemovedSnapshotFiles = $false
            }
        }

        $filesByDate = Get-VulnSnapshotFilesBySnapshotDate -SnapshotFiles $snapshotFiles -SnapshotDates $snapshotDates

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

            Write-Output ("  Canonicalizing {0} new snapshot date(s) across {1} file(s) using {2} disk partition(s)..." -f $snapshotDates.Count, $snapshotFiles.Count, $partitionCount)
            foreach ($snapshotDate in $snapshotDates) {
                $closedOn = Get-VulnPreviousDay -Date $snapshotDate
                $snapshotPartitionRoot = Join-Path $stageRoot ('snapshot-' + $snapshotDate)
                [void](New-Item -Path $snapshotPartitionRoot -ItemType Directory -Force)
                $snapshotFilesForDate = @($filesByDate[$snapshotDate] ?? @())
                $snapshotIndex = [array]::IndexOf($snapshotDates, $snapshotDate) + 1
                Write-Output ("  [{0}/{1}] Processing snapshot date {2} from {3} file(s)..." -f $snapshotIndex, $snapshotDates.Count, $snapshotDate, $snapshotFilesForDate.Count)
                if (Get-Command -Name Write-MemoryUsage -ErrorAction SilentlyContinue) {
                    Write-MemoryUsage -Label ("VulnStore " + $snapshotDate + ' Start')
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
                        Write-MemoryUsage -Label ("VulnStore " + $snapshotDate + ' End')
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
                DownloadedFiles = $snapshotFiles.Count
                CurrentRows = $currentCount
                HistoryYears = if ($historyPeriodCount -gt 0) { $historyPeriodCount } else { $finalHistoryPeriods.Count }
                LatestSnapshotDate = if ($snapshotDates.Count -gt 0) { $snapshotDates[-1] } else { $latestKnownSnapshot }
                CanonicalRepairPerformed = $false
                RemovedSnapshotFiles = $false
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
        if ($null -ne $item -and $item.PSObject.Properties.Match('CurrentRows').Count -gt 0 -and $item.PSObject.Properties.Match('HistoryYears').Count -gt 0) {
            $publishResult = $item
            continue
        }

        if ($null -ne $item) {
            Write-Host ([string]$item)
        }
    }

    if ($null -eq $publishResult) {
        throw 'Publish-VulnStoreFromBulkSnapshot did not return a publish result.'
    }

    if ($RemoveSnapshotFiles) {
        foreach ($snapshotFile in @(Get-VulnLegacySnapshotFile -BasePath $BasePath)) {
            Remove-Item -Path $snapshotFile.FullName -Force
        }
    }

    return [PSCustomObject]@{
        DownloadedFiles = $publishResult.DownloadedFiles
        CurrentRows = $publishResult.CurrentRows
        HistoryYears = $publishResult.HistoryYears
        LatestSnapshotDate = $publishResult.LatestSnapshotDate
        CanonicalRepairPerformed = ($publishResult.PSObject.Properties['CanonicalRepairPerformed']?.Value -eq $true)
        RemovedSnapshotFiles = ($RemoveSnapshotFiles -eq $true)
    }
}