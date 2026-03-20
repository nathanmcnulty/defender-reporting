
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

    return Invoke-WithStoreLock -BasePath $OutputPath -StoreName 'advancedhunting' -ScriptBlock {
        Restore-StoreTransaction -BasePath $OutputPath -StoreName 'advancedhunting'

        $store = Initialize-AdvancedHuntingStore -Path $OutputPath -RemoveLegacyFiles
        foreach ($result in $response.Results) {
            $cveId = $result.PSObject.Properties['CveId']?.Value
            if ($cveId) {
                $store.CurrentRecords[$cveId] = $result
            }
        }

        $stageRoot = Join-Path $OutputPath ('.advancedhunting-store-staging-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -Path $stageRoot -ItemType Directory -Force)

        try {
            $stagedCurrentPath = Join-Path $stageRoot (Split-Path -Leaf $store.CurrentPath)
            Write-NdjsonRecordsFile -Path $stagedCurrentPath -Records $store.CurrentRecords.Values
            Write-Information ("  Advanced Hunting store publish: {0} record(s)" -f $store.CurrentRecords.Count) -InformationAction Continue

            Publish-StoreFilesTransactional -BasePath $OutputPath -StoreName 'advancedhunting' -Files @([PSCustomObject]@{
                StagePath = $stagedCurrentPath
                TargetPath = $store.CurrentPath
            })

            return [PSCustomObject]@{
                Success = $true
                RecordCount = @($response.Results).Count
                OutputFile = $store.CurrentPath
                MigratedLegacy = $store.MigratedLegacy
            }
        }
        finally {
            if (Test-Path -Path $stageRoot) {
                Remove-Item -Path $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-MdeMachineSnapshotMap {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$BaseApiUrl,

        [Parameter(Mandatory = $true)]
        [string]$ObservedOn
    )

    $url = "$BaseApiUrl/api/machines?`$filter=onboardingStatus eq 'Onboarded'"
    $pageCount = 0
    $snapshotsById = @{}

    do {
        $pageCount++
        $response = Invoke-RestMethod -Uri $url -Headers $Headers -Method Get -ErrorAction Stop

        if ($response.value) {
            foreach ($machine in $response.value) {
                $snapshot = New-MachineSnapshotRecord -Machine $machine -ObservedOn $ObservedOn
                $snapshotsById[$snapshot.id] = $snapshot
            }
        }

        $url = if ($response.PSObject.Properties['@odata.nextLink']) {
            $response.'@odata.nextLink'
        }
        else {
            $null
        }
        $response = $null
    } while ($url)

    return [PSCustomObject]@{
        SnapshotsById = $snapshotsById
        PageCount = $pageCount
    }
}

function Get-MachineStoreRefreshPlan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$CurrentRecords,

        [Parameter(Mandatory = $true)]
        [hashtable]$FetchedSnapshotsById,

        [Parameter(Mandatory = $true)]
        [string]$ObservedOn
    )

    $changeRecords = [System.Collections.Generic.List[object]]::new()
    $nextCurrentRecords = @{}

    foreach ($snapshot in $FetchedSnapshotsById.Values) {
        $existing = $CurrentRecords[$snapshot.id]
        if (($null -eq $existing) -or ($existing.stateHash -ne $snapshot.stateHash)) {
            $changeRecords.Add($snapshot)
        }

        $nextCurrentRecords[$snapshot.id] = $snapshot
    }

    foreach ($existingId in @($CurrentRecords.Keys)) {
        if (-not $nextCurrentRecords.ContainsKey($existingId)) {
            $changeRecords.Add((New-MachineRemovalRecord -MachineId $existingId -ObservedOn $ObservedOn))
        }
    }

    return [PSCustomObject]@{
        ChangeRecords = $changeRecords
        NextCurrentRecords = $nextCurrentRecords
        MachineCount = $nextCurrentRecords.Count
    }
}

function Publish-MachineStoreState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [hashtable]$Store,

        [Parameter(Mandatory = $true)]
        $ChangeRecords
    )

    $stageRoot = Join-Path $OutputPath ('.machine-store-staging-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $stageRoot -ItemType Directory -Force)

    try {
        $stagedCurrentPath = Join-Path $stageRoot (Split-Path -Leaf $Store.CurrentPath)
        Write-NdjsonRecordsFile -Path $stagedCurrentPath -Records $Store.CurrentRecords.Values
        Write-Information ("  Machine store publish: {0} current record(s), {1} history period(s), {2} change record(s)" -f $Store.CurrentRecords.Count, $Store.HistoryRecordsByPeriod.Count, @($ChangeRecords).Count) -InformationAction Continue

        $filesToPublish = [System.Collections.Generic.List[object]]::new()
        $filesToPublish.Add([PSCustomObject]@{
            StagePath = $stagedCurrentPath
            TargetPath = $Store.CurrentPath
        })

        $outputFiles = [System.Collections.Generic.List[string]]::new()
        $outputFiles.Add($Store.CurrentPath)

        $historyRecordKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($periodKey in @($Store.HistoryRecordsByPeriod.Keys)) {
            foreach ($record in @($Store.HistoryRecordsByPeriod[$periodKey])) {
                [void]$historyRecordKeys.Add((Get-MachineHistoryRecordKey -Record $record))
            }
        }

        foreach ($changeRecord in $ChangeRecords) {
            Add-MachineHistoryRecordToPeriodMap -HistoryRecordsByPeriod $Store.HistoryRecordsByPeriod -RecordKeys $historyRecordKeys -Record $changeRecord
        }

        $publishedHistoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($periodKey in @($Store.HistoryRecordsByPeriod.Keys | Sort-Object)) {
            $historyStagePath = Get-MachineHistoryQuarterlyPath -BasePath $stageRoot -PeriodKey $periodKey
            Write-NdjsonRecordsFile -Path $historyStagePath -Records $Store.HistoryRecordsByPeriod[$periodKey]

            $historyTargetPath = Get-MachineHistoryQuarterlyPath -BasePath $OutputPath -PeriodKey $periodKey
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = $historyStagePath
                TargetPath = $historyTargetPath
            })

            $historyName = Split-Path -Leaf $historyTargetPath
            [void]$publishedHistoryNames.Add($historyName)
            $outputFiles.Add($historyTargetPath)
        }

        $removePaths = @(Get-MachineHistoryRemovePaths -BasePath $OutputPath -PublishedHistoryNames $publishedHistoryNames)
        Publish-StoreFilesTransactional -BasePath $OutputPath -StoreName 'machines' -Files @($filesToPublish) -RemovePaths $removePaths

        return [PSCustomObject]@{
            Success = $true
            ChangeCount = $ChangeRecords.Count
            OutputFiles = @($outputFiles)
            MigratedLegacy = $Store.MigratedLegacy
        }
    }
    finally {
        if (Test-Path -Path $stageRoot) {
            Remove-Item -Path $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
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

    $observedOn = Get-Date -Format 'yyyy-MM-dd'
    $snapshotResult = Get-MdeMachineSnapshotMap -Headers $Headers -BaseApiUrl $BaseApiUrl -ObservedOn $observedOn

    return Invoke-WithStoreLock -BasePath $OutputPath -StoreName 'machines' -ScriptBlock {
        Restore-StoreTransaction -BasePath $OutputPath -StoreName 'machines'

        $store = Initialize-MachineHistoryStore -Path $OutputPath -RemoveLegacyFiles
        $refreshPlan = Get-MachineStoreRefreshPlan -CurrentRecords $store.CurrentRecords -FetchedSnapshotsById $snapshotResult.SnapshotsById -ObservedOn $observedOn
        $store.CurrentRecords = $refreshPlan.NextCurrentRecords

        $publishResult = Publish-MachineStoreState -OutputPath $OutputPath -Store $store -ChangeRecords $refreshPlan.ChangeRecords
        return [PSCustomObject]@{
            Success = $true
            MachineCount = $refreshPlan.MachineCount
            ChangeCount = $publishResult.ChangeCount
            PageCount = $snapshotResult.PageCount
            OutputFiles = @($publishResult.OutputFiles)
            MigratedLegacy = $publishResult.MigratedLegacy
        }
    }
}