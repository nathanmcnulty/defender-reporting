
# Shared MDE export helpers used by local export, generator refresh, and the Azure runbook.

function Get-MdeAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AppId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $AppSecret,

        [Parameter(Mandatory = $false)]
        [string]$ResourceAppIdUri = 'https://api.securitycenter.microsoft.com',

        [Parameter(Mandatory = $false)]
        [switch]$UseEnvironmentFallback,

        [Parameter(Mandatory = $false)]
        [switch]$UseAzureCliFallback,

        [Parameter(Mandatory = $false)]
        [switch]$WriteStatus
    )

    if (-not [string]::IsNullOrWhiteSpace($AccessToken)) {
        if ($WriteStatus) {
            Write-Host 'Using provided Microsoft Defender for Endpoint access token' -ForegroundColor Cyan
        }

        return $AccessToken.Trim()
    }

    $resolvedTenantId = $TenantId
    $resolvedAppId = $AppId
    $resolvedSecret = $AppSecret

    if ($UseEnvironmentFallback) {
        $environmentAccessToken = $env:DEFENDER_ACCESS_TOKEN
        if (-not [string]::IsNullOrWhiteSpace($environmentAccessToken)) {
            return $environmentAccessToken.Trim()
        }

        if ([string]::IsNullOrWhiteSpace($resolvedTenantId)) {
            $resolvedTenantId = $env:DEFENDER_TENANT_ID
        }
        if ([string]::IsNullOrWhiteSpace($resolvedAppId)) {
            $resolvedAppId = $env:DEFENDER_APP_ID
        }
        if ($null -eq $resolvedSecret -or [string]::IsNullOrWhiteSpace([string]$resolvedSecret)) {
            $resolvedSecret = $env:DEFENDER_APP_SECRET
        }
    }

    $resolvedSecretText = ''
    if ($resolvedSecret -is [System.Security.SecureString]) {
        $resolvedSecretText = [System.Net.NetworkCredential]::new('', [System.Security.SecureString]$resolvedSecret).Password
    }
    elseif ($null -ne $resolvedSecret) {
        $resolvedSecretText = [string]$resolvedSecret
    }

    if (
        -not [string]::IsNullOrWhiteSpace($resolvedTenantId) -and
        -not [string]::IsNullOrWhiteSpace($resolvedAppId) -and
        -not [string]::IsNullOrWhiteSpace($resolvedSecretText)
    ) {
        if ($WriteStatus) {
            Write-Host 'Authenticating to Microsoft Defender for Endpoint...' -ForegroundColor Cyan
        }

        $oAuthUri = "https://login.microsoftonline.com/$resolvedTenantId/oauth2/token"
        $authBody = [ordered]@{
            resource = $ResourceAppIdUri
            client_id = $resolvedAppId
            client_secret = $resolvedSecretText
            grant_type = 'client_credentials'
        }

        try {
            $response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
            if ($WriteStatus) {
                Write-Host '  Authentication successful' -ForegroundColor Green
            }

            return [string]$response.access_token
        }
        catch {
            throw "Failed to authenticate to Microsoft Defender for Endpoint: $_"
        }
    }

    if ($UseAzureCliFallback) {
        $azCommand = Get-Command -Name 'az' -CommandType Application -ErrorAction SilentlyContinue
        if ($null -ne $azCommand) {
            try {
                $azAccessToken = [string](& $azCommand.Source 'account' 'get-access-token' '--resource' $ResourceAppIdUri '--query' 'accessToken' '-o' 'tsv')
                if (-not [string]::IsNullOrWhiteSpace($azAccessToken)) {
                    return $azAccessToken.Trim()
                }
            }
            catch {
                Write-Verbose "Azure CLI token acquisition failed: $_"
            }
        }
    }

    if ($UseEnvironmentFallback -or $UseAzureCliFallback) {
        throw "No Defender API token source available. Provide -AccessToken, set DEFENDER_ACCESS_TOKEN, set DEFENDER_TENANT_ID/DEFENDER_APP_ID/DEFENDER_APP_SECRET, or sign in with 'az login'."
    }

    throw 'No Defender API token source available. Provide -AccessToken or -TenantId/-AppId/-AppSecret.'
}

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

    $response = Invoke-RestMethodWithRetry -Uri $ExportUrl -Headers $Headers -Method Get
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
        Invoke-WebRequestWithRetry -Uri $fileUrl -OutFile $outputFile
        $downloadedFiles.Add($outputFile)
    }

    return [PSCustomObject]@{
        ExportFileCount = $exportFiles.Count
        DownloadedFiles = @($downloadedFiles)
    }
}

function Export-MdeBulkVulnerabilityData {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$ExportUrl
    )

    Write-Host 'Exporting vulnerability data from MDE API...' -ForegroundColor Cyan
    $result = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers $Headers -OutputPath $OutputPath -ExportUrl $ExportUrl
    foreach ($downloadedFile in $result.DownloadedFiles) {
        Write-Host "  Downloading $(Split-Path -Leaf $downloadedFile)" -ForegroundColor Gray
    }

    return @($result.DownloadedFiles)
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

    function Invoke-MdeAdvancedHuntingQuery {
        [CmdletBinding()]
        [OutputType([object[]])]
        param(
            [Parameter(Mandatory = $true)]
            [hashtable]$RequestHeaders,

            [Parameter(Mandatory = $true)]
            [string]$RequestUrl,

            [Parameter(Mandatory = $true)]
            [string]$Query,

            [Parameter(Mandatory = $true)]
            [string]$Label
        )

        Write-Information ("  Running Advanced Hunting query: {0}" -f $Label) -InformationAction Continue
        $body = @{ Query = $Query } | ConvertTo-Json
        $response = Invoke-RestMethodWithRetry -Uri $RequestUrl -Headers $RequestHeaders -Method Post -Body $body
        if ($null -eq $response -or $null -eq $response.Results) {
            return @()
        }

        return @($response.Results)
    }

    function Set-AdvancedHuntingResultRecordType {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only annotates in-memory Advanced Hunting query results with a record-type marker.')]
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [object[]]$Records,

            [Parameter(Mandatory = $true)]
            [string]$RecordType
        )

        foreach ($record in @($Records)) {
            if ($null -eq $record) {
                continue
            }

            if ($record.PSObject.Properties['RecordType']) {
                $record.RecordType = $RecordType
            }
            else {
                Add-Member -InputObject $record -NotePropertyName RecordType -NotePropertyValue $RecordType -Force
            }
        }
    }

    $cveQuery = @"
let RelevantCves =
    DeviceTvmSoftwareVulnerabilities
    | where isnotempty(CveId)
    | distinct CveId;
RelevantCves
| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where isnotempty(CveId)
    | project CveId, PublishedDate, VulnerabilityDescription, EpssScore, AffectedSoftware, IsExploitAvailable, LastModifiedTime
) on CveId
| summarize arg_max(LastModifiedTime, PublishedDate, VulnerabilityDescription, EpssScore, AffectedSoftware, IsExploitAvailable) by CveId
| project CveId,
    PublishedDate = format_datetime(PublishedDate, 'yyyy-MM-dd'),
    VulnerabilityDescription,
    EpssScore,
    AffectedSoftware,
    IsExploitAvailable,
    LastModifiedTime
"@

    $deviceUsersQuery = @"
DeviceInfo
| where OnboardingStatus == 'Onboarded'
| where isnotempty(DeviceId) and isnotempty(LoggedOnUsers)
| project DeviceId, Timestamp, LoggedOnUsers
| summarize arg_max(Timestamp, LoggedOnUsers) by DeviceId
| project DeviceId, LoggedOnUsers, LastModifiedTime = Timestamp
"@

    $inventoryQuery = @"
let RelevantSoftware =
    DeviceTvmSoftwareVulnerabilities
    | where isnotempty(DeviceId) and isnotempty(SoftwareName)
    | summarize by DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion;
RelevantSoftware
| join kind=leftouter (
    DeviceTvmSoftwareInventory
    | where isnotempty(DeviceId) and isnotempty(SoftwareName)
    | project DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, ProductCodeCpe, EndOfSupportStatus, EndOfSupportDate
    | extend InventorySignalCount =
        iff(isnotempty(ProductCodeCpe), 1, 0) +
        iff(isnotempty(EndOfSupportStatus), 1, 0) +
        iff(isnotempty(EndOfSupportDate), 1, 0)
) on DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| summarize arg_max(InventorySignalCount, ProductCodeCpe, EndOfSupportStatus, EndOfSupportDate) by DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion
| project DeviceId,
    SoftwareVendor,
    SoftwareName,
    SoftwareVersion,
    ProductCodeCpe,
    EndOfSupportStatus,
    EndOfSupportDate = format_datetime(EndOfSupportDate, 'yyyy-MM-dd')
"@

    $cveResults = @(Invoke-MdeAdvancedHuntingQuery -RequestHeaders $Headers -RequestUrl $QueryUrl -Query $cveQuery -Label 'cve-enrichment')
    $deviceUserResults = @(Invoke-MdeAdvancedHuntingQuery -RequestHeaders $Headers -RequestUrl $QueryUrl -Query $deviceUsersQuery -Label 'device-users')
    $inventoryResults = @(Invoke-MdeAdvancedHuntingQuery -RequestHeaders $Headers -RequestUrl $QueryUrl -Query $inventoryQuery -Label 'software-inventory')

    Set-AdvancedHuntingResultRecordType -Records $cveResults -RecordType 'Cve'
    Set-AdvancedHuntingResultRecordType -Records $deviceUserResults -RecordType 'DeviceUsers'
    Set-AdvancedHuntingResultRecordType -Records $inventoryResults -RecordType 'Inventory'

    if ($cveResults.Count -eq 0 -and $deviceUserResults.Count -eq 0 -and $inventoryResults.Count -eq 0) {
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

        foreach ($existingKey in @($store.CurrentRecords.Keys)) {
            $existingRecord = $store.CurrentRecords[$existingKey]
            $recordType = Get-AdvancedHuntingRecordType -Record $existingRecord
            if ($recordType -eq 'DeviceUsers' -or $recordType -eq 'Inventory') {
                [void]$store.CurrentRecords.Remove($existingKey)
            }
        }

        foreach ($result in $cveResults) {
            $storeKey = Get-AdvancedHuntingStoreKey -Record $result
            if ($storeKey) {
                $store.CurrentRecords[$storeKey] = $result
            }
        }

        foreach ($result in $deviceUserResults) {
            $storeKey = Get-AdvancedHuntingStoreKey -Record $result
            if ($storeKey) {
                $store.CurrentRecords[$storeKey] = $result
            }
        }

        foreach ($result in $inventoryResults) {
            $storeKey = Get-AdvancedHuntingStoreKey -Record $result
            if ($storeKey) {
                $store.CurrentRecords[$storeKey] = $result
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
                RecordCount = ($cveResults.Count + $deviceUserResults.Count + $inventoryResults.Count)
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

function Export-MdeAdvancedHuntingData {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$QueryUrl
    )

    Write-Host 'Exporting Advanced Hunting data...' -ForegroundColor Cyan
    Write-Host '  Running Advanced Hunting query...' -ForegroundColor Gray
    $result = Invoke-MdeAdvancedHuntingStoreRefresh -Headers $Headers -OutputPath $OutputPath -QueryUrl $QueryUrl

    if ($result.Success) {
        Write-Host "  Retrieved $($result.RecordCount) records from Advanced Hunting" -ForegroundColor Green
        if ($result.MigratedLegacy) {
            Write-Host '  Migrated legacy Advanced Hunting snapshots to current cache' -ForegroundColor Green
        }
        Write-Host "  Saved to: $($result.OutputFile)" -ForegroundColor Green
        return $result
    }

    Write-Warning 'Advanced Hunting query returned no results'
    return $result
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
        $response = Invoke-RestMethodWithRetry -Uri $url -Headers $Headers -Method Get

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

function Export-MdeMachineData {
    [CmdletBinding(DefaultParameterSetName = 'Headers')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Headers')]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true, ParameterSetName = 'AccessToken')]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [string]$BaseApiUrl = 'https://api.securitycenter.microsoft.com'
    )

    $resolvedHeaders = if ($PSCmdlet.ParameterSetName -eq 'AccessToken') {
        Get-MdeHeaderCollection -AccessToken $AccessToken
    }
    else {
        $Headers
    }

    Write-Host 'Exporting machine data from Defender API...' -ForegroundColor Cyan
    $result = Invoke-MdeMachineStoreRefresh -Headers $resolvedHeaders -OutputPath $OutputPath -BaseApiUrl $BaseApiUrl

    Write-Host "  Retrieved $($result.MachineCount) machines" -ForegroundColor Green
    Write-Host "  Machine state changes captured: $($result.ChangeCount)" -ForegroundColor Green
    if ($result.MigratedLegacy) {
        Write-Host '  Migrated legacy machine snapshots to current/history store' -ForegroundColor Green
    }
    $outputFiles = @($result.OutputFiles | ForEach-Object { Split-Path -Leaf $_ })
    Write-Host "  Saved to $($outputFiles -join ', ')" -ForegroundColor Green

    return $result
}