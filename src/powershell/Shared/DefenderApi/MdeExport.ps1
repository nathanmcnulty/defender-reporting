
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
            throw ("Failed to authenticate to Microsoft Defender for Endpoint for tenant '{0}', app '{1}', resource '{2}': {3}" -f $resolvedTenantId, $resolvedAppId, $ResourceAppIdUri, $_.Exception.Message)
        }
    }

    $diagnostics = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($resolvedTenantId)) {
        $diagnostics.Add('TenantId is missing')
    }
    if ([string]::IsNullOrWhiteSpace($resolvedAppId)) {
        $diagnostics.Add('AppId is missing')
    }
    if ([string]::IsNullOrWhiteSpace($resolvedSecretText)) {
        $diagnostics.Add('AppSecret is missing')
    }

    if ($UseAzureCliFallback) {
        $azCommand = Get-Command -Name 'az' -CommandType Application -ErrorAction SilentlyContinue
        if ($null -ne $azCommand) {
            try {
                $azAccessToken = [string](& $azCommand.Source 'account' 'get-access-token' '--resource' $ResourceAppIdUri '--query' 'accessToken' '-o' 'tsv')
                if (-not [string]::IsNullOrWhiteSpace($azAccessToken)) {
                    return $azAccessToken.Trim()
                }

                $diagnostics.Add("Azure CLI fallback returned no access token for resource '$ResourceAppIdUri'")
            }
            catch {
                Write-Verbose "Azure CLI token acquisition failed: $_"
                $diagnostics.Add(("Azure CLI fallback failed: {0}" -f $_.Exception.Message))
            }
        }
        else {
            $diagnostics.Add("Azure CLI fallback is unavailable because 'az' is not installed")
        }
    }

    if ($UseEnvironmentFallback) {
        if ([string]::IsNullOrWhiteSpace([string]$env:DEFENDER_ACCESS_TOKEN)) {
            $diagnostics.Add('DEFENDER_ACCESS_TOKEN is not set')
        }
        if ([string]::IsNullOrWhiteSpace([string]$env:DEFENDER_TENANT_ID)) {
            $diagnostics.Add('DEFENDER_TENANT_ID is not set')
        }
        if ([string]::IsNullOrWhiteSpace([string]$env:DEFENDER_APP_ID)) {
            $diagnostics.Add('DEFENDER_APP_ID is not set')
        }
        if ([string]::IsNullOrWhiteSpace([string]$env:DEFENDER_APP_SECRET)) {
            $diagnostics.Add('DEFENDER_APP_SECRET is not set')
        }
    }

    $diagnosticSuffix = if ($diagnostics.Count -gt 0) {
        ' Diagnostics: ' + (($diagnostics | Select-Object -Unique) -join '; ') + '.'
    }
    else {
        ''
    }

    if ($UseEnvironmentFallback -or $UseAzureCliFallback) {
        throw ("No Defender API token source available. Provide -AccessToken, set DEFENDER_ACCESS_TOKEN, set DEFENDER_TENANT_ID/DEFENDER_APP_ID/DEFENDER_APP_SECRET, or sign in with 'az login'.{0}" -f $diagnosticSuffix)
    }

    throw ("No Defender API token source available. Provide -AccessToken or -TenantId/-AppId/-AppSecret.{0}" -f $diagnosticSuffix)
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

function Resolve-UriQueryParameterValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $absoluteUri = $null
    if (-not [System.Uri]::TryCreate($Uri, [System.UriKind]::Absolute, [ref]$absoluteUri)) {
        return $Uri
    }

    $uriBuilder = [System.UriBuilder]::new($absoluteUri)
    $queryEntries = [System.Collections.Generic.List[string]]::new()
    foreach ($queryEntry in @($uriBuilder.Query.TrimStart('?').Split('&', [System.StringSplitOptions]::RemoveEmptyEntries))) {
        $key = [System.Uri]::UnescapeDataString(($queryEntry.Split('=', 2))[0])
        if ($key -ieq $Name) {
            continue
        }

        $queryEntries.Add($queryEntry)
    }

    $queryEntries.Add(("{0}={1}" -f [System.Uri]::EscapeDataString($Name), [System.Uri]::EscapeDataString($Value)))
    $uriBuilder.Query = [string]::Join('&', $queryEntries)
    return $uriBuilder.Uri.AbsoluteUri
}

function Get-MdeBulkVulnerabilityExportRequestUri {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExportUrl,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 6)]
        [int]$SasValidHours = 6
    )

    return (Resolve-UriQueryParameterValue -Uri $ExportUrl -Name 'sasValidHours' -Value ([string]$SasValidHours))
}

function Get-VulnSnapshotStagingPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    return (Join-Path -Path (Split-Path -Path $OutputFile -Parent) -ChildPath ('.' + (Split-Path -Path $OutputFile -Leaf) + '.partial'))
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

    $emptyDownloadMaxAttempts = 4
    $emptyDownloadInitialDelayMs = 2000
    $emptyDownloadBackoffMultiplier = 2.0

    $resolvedExportUrl = Get-MdeBulkVulnerabilityExportRequestUri -ExportUrl $ExportUrl
    $response = Invoke-RestMethodWithRetry -Uri $resolvedExportUrl -Headers $Headers -Method Get -MaxRetries 4 -InitialDelayMs 5000 -TimeoutSec 600 -RetryTransientTransportFailures
    $exportFiles = @($response.exportFiles)
    if ($exportFiles.Count -eq 0) {
        throw 'Bulk vulnerability export returned no files.'
    }

    $downloadedFiles = [System.Collections.Generic.List[string]]::new()
    $partIndexBySnapshotKey = @{}
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
            throw "Unexpected export URL format. Cannot extract date and groupId from: $(Get-SanitizedUriForLog -Uri $fileUrl)"
        }

        $snapshotKey = "${groupId}|${date}"
        $partIndex = if ($partIndexBySnapshotKey.ContainsKey($snapshotKey)) {
            [int]$partIndexBySnapshotKey[$snapshotKey]
        }
        else {
            0
        }
        $partIndexBySnapshotKey[$snapshotKey] = ($partIndex + 1)

        $outputFile = Join-Path $OutputPath ("VulnExport_{0}_{1}_part_{2}.json.gz" -f $groupId, $date, $partIndex)
        $stagingOutputFile = Get-VulnSnapshotStagingPath -OutputFile $outputFile
        $downloadAttempt = 0
        $emptyDownloadDelayMs = $emptyDownloadInitialDelayMs

        while ($true) {
            if (Test-Path -LiteralPath $stagingOutputFile -PathType Leaf) {
                Remove-Item -LiteralPath $stagingOutputFile -Force -ErrorAction SilentlyContinue
            }

            try {
                $downloadAttempt++
                Invoke-WebRequestWithRetry -Uri $fileUrl -OutFile $stagingOutputFile -MaxRetries 6 -InitialDelayMs 2000 -TimeoutSec 1800 -RetryTransientTransportFailures
                $stagingFile = Get-Item -LiteralPath $stagingOutputFile -Force -ErrorAction Stop
            }
            catch {
                if (Test-Path -LiteralPath $stagingOutputFile -PathType Leaf) {
                    Remove-Item -LiteralPath $stagingOutputFile -Force -ErrorAction SilentlyContinue
                }

                throw
            }

            if ($stagingFile.Length -gt 0) {
                try {
                    if (Test-Path -LiteralPath $outputFile -PathType Leaf) {
                        Remove-Item -LiteralPath $outputFile -Force -ErrorAction SilentlyContinue
                    }

                    [System.IO.File]::Move($stagingOutputFile, $outputFile)
                }
                catch {
                    if (Test-Path -LiteralPath $stagingOutputFile -PathType Leaf) {
                        Remove-Item -LiteralPath $stagingOutputFile -Force -ErrorAction SilentlyContinue
                    }

                    throw
                }

                break
            }

            if (Test-Path -LiteralPath $stagingOutputFile -PathType Leaf) {
                Remove-Item -LiteralPath $stagingOutputFile -Force -ErrorAction SilentlyContinue
            }

            if ($downloadAttempt -ge $emptyDownloadMaxAttempts) {
                throw "Downloaded file is empty: $(Get-SanitizedUriForLog -Uri $fileUrl)"
            }

            Write-Warning ("Downloaded file was empty for {0} (attempt {1}/{2}). Retrying in {3}s..." -f (Get-SanitizedUriForLog -Uri $fileUrl), $downloadAttempt, $emptyDownloadMaxAttempts, [math]::Round($emptyDownloadDelayMs / 1000, 1))
            Start-Sleep -Milliseconds $emptyDownloadDelayMs
            $emptyDownloadDelayMs = [int]($emptyDownloadDelayMs * $emptyDownloadBackoffMultiplier)
        }

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

function Get-MdeMachineRefreshPublishPlan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$BaseApiUrl,

        [Parameter(Mandatory = $true)]
        [string]$ObservedOn,

        [Parameter(Mandatory = $true)]
        [hashtable]$CurrentRecords,

        [Parameter(Mandatory = $true)]
        [string]$StagedCurrentPath
    )

    $url = "$BaseApiUrl/api/machines?`$filter=onboardingStatus eq 'Onboarded'"
    $pageCount = 0
    $machineCount = 0
    $changeCount = 0
    $seenMachineIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $currentFileStream = $null
    $currentGzipStream = $null
    $currentWriter = $null
    $currentJsonWriter = $null
    $stagedHistoryPath = $null
    $historyTargetPath = $null
    $historyFileStream = $null
    $historyGzipStream = $null
    $historyWriter = $null
    $historyJsonWriter = $null

    try {
        $currentFileStream = [System.IO.File]::Create($StagedCurrentPath)
        $currentGzipStream = [System.IO.Compression.GZipStream]::new($currentFileStream, [System.IO.Compression.CompressionMode]::Compress)
        $currentWriter = [System.IO.StreamWriter]::new($currentGzipStream, [System.Text.UTF8Encoding]::new($false))
        $currentJsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($currentWriter)
        $currentJsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None

        do {
            $pageCount++
            $response = Invoke-RestMethodWithRetry -Uri $url -Headers $Headers -Method Get

            if ($response.value) {
                foreach ($machine in $response.value) {
                    $snapshot = New-MachineSnapshotRecord -Machine $machine -ObservedOn $ObservedOn
                    $snapshotId = [string]$snapshot.id
                    if ([string]::IsNullOrWhiteSpace($snapshotId)) {
                        continue
                    }

                    if (-not $seenMachineIds.Add($snapshotId)) {
                        continue
                    }

                    Write-JsonValueToWriter -Writer $currentJsonWriter -Value $snapshot
                    $currentJsonWriter.Flush()
                    $currentWriter.WriteLine()
                    $machineCount++

                    $existing = $CurrentRecords[$snapshotId]
                    $existingStateHash = if ($existing -is [string]) {
                        $existing
                    }
                    elseif ($null -ne $existing) {
                        [string]$existing.stateHash
                    }
                    else {
                        $null
                    }
                    if (($null -eq $existing) -or ($existingStateHash -ne [string]$snapshot.stateHash)) {
                        if ($null -eq $historyJsonWriter) {
                            $historyFileName = New-MachineHistorySegmentFileName
                            $stageDirectory = Split-Path -Path $StagedCurrentPath -Parent
                            $stagedHistoryPath = Join-Path $stageDirectory ('.' + $historyFileName)
                            $historyTargetPath = Join-Path $stageDirectory $historyFileName
                            $historyFileStream = [System.IO.File]::Create($stagedHistoryPath)
                            $historyGzipStream = [System.IO.Compression.GZipStream]::new($historyFileStream, [System.IO.Compression.CompressionMode]::Compress)
                            $historyWriter = [System.IO.StreamWriter]::new($historyGzipStream, [System.Text.UTF8Encoding]::new($false))
                            $historyJsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($historyWriter)
                            $historyJsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None
                        }

                        Write-JsonValueToWriter -Writer $historyJsonWriter -Value $snapshot
                        $historyJsonWriter.Flush()
                        $historyWriter.WriteLine()
                        $changeCount++
                    }

                    [void]$CurrentRecords.Remove($snapshotId)
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

        foreach ($existingId in @($CurrentRecords.Keys)) {
            $removalRecord = New-MachineRemovalRecord -MachineId $existingId -ObservedOn $ObservedOn

            if ($null -eq $historyJsonWriter) {
                $historyFileName = New-MachineHistorySegmentFileName
                $stageDirectory = Split-Path -Path $StagedCurrentPath -Parent
                $stagedHistoryPath = Join-Path $stageDirectory ('.' + $historyFileName)
                $historyTargetPath = Join-Path $stageDirectory $historyFileName
                $historyFileStream = [System.IO.File]::Create($stagedHistoryPath)
                $historyGzipStream = [System.IO.Compression.GZipStream]::new($historyFileStream, [System.IO.Compression.CompressionMode]::Compress)
                $historyWriter = [System.IO.StreamWriter]::new($historyGzipStream, [System.Text.UTF8Encoding]::new($false))
                $historyJsonWriter = [Newtonsoft.Json.JsonTextWriter]::new($historyWriter)
                $historyJsonWriter.Formatting = [Newtonsoft.Json.Formatting]::None
            }

            Write-JsonValueToWriter -Writer $historyJsonWriter -Value $removalRecord
            $historyJsonWriter.Flush()
            $historyWriter.WriteLine()
            $changeCount++
        }
    }
    finally {
        if ($currentJsonWriter) { $currentJsonWriter.Close() }
        elseif ($currentWriter) { $currentWriter.Dispose() }
        elseif ($currentGzipStream) { $currentGzipStream.Dispose() }
        elseif ($currentFileStream) { $currentFileStream.Dispose() }

        if ($historyJsonWriter) { $historyJsonWriter.Close() }
        elseif ($historyWriter) { $historyWriter.Dispose() }
        elseif ($historyGzipStream) { $historyGzipStream.Dispose() }
        elseif ($historyFileStream) { $historyFileStream.Dispose() }
    }

    return [PSCustomObject]@{
        ChangeCount = $changeCount
        MachineCount = $machineCount
        PageCount = $pageCount
        StagedCurrentPath = $StagedCurrentPath
        StagedHistoryPath = $stagedHistoryPath
        HistoryTargetPath = $historyTargetPath
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
    $nextCurrentRecords = $FetchedSnapshotsById

    foreach ($snapshot in $FetchedSnapshotsById.Values) {
        $existing = $CurrentRecords[$snapshot.id]
        if (($null -eq $existing) -or ($existing.stateHash -ne $snapshot.stateHash)) {
            $changeRecords.Add($snapshot)
        }
    }

    foreach ($existingId in @($CurrentRecords.Keys)) {
        if (-not $nextCurrentRecords.ContainsKey($existingId)) {
            $changeRecords.Add((New-MachineRemovalRecord -MachineId $existingId -ObservedOn $ObservedOn))
        }
    }

    return [PSCustomObject]@{
        ChangeRecords = $changeRecords
        NextCurrentRecords = $nextCurrentRecords
        MachineCount = $FetchedSnapshotsById.Count
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
        [int]$ChangeCount,

        [Parameter(Mandatory = $true)]
        [string]$StagedCurrentPath,

        [Parameter(Mandatory = $true)]
        [int]$CurrentRecordCount,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$StagedHistoryPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$HistoryTargetPath
    )

    $stageRoot = Join-Path $OutputPath ('.machine-store-staging-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $stageRoot -ItemType Directory -Force)

    try {
        $historyFileCount = if ([string]::IsNullOrWhiteSpace($HistoryTargetPath)) { 0 } else { 1 }
        Write-Information ("  Machine store publish: {0} current record(s), {1} staged history file(s), {2} change record(s)" -f $CurrentRecordCount, $historyFileCount, $ChangeCount) -InformationAction Continue

        $filesToPublish = [System.Collections.Generic.List[object]]::new()
        $filesToPublish.Add([PSCustomObject]@{
            StagePath = $StagedCurrentPath
            TargetPath = $Store.CurrentPath
        })

        $outputFiles = [System.Collections.Generic.List[string]]::new()
        $outputFiles.Add($Store.CurrentPath)

        $publishedHistoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($historyFile in Get-MachineHistoryQuarterlyFiles -BasePath $OutputPath) {
            [void]$publishedHistoryNames.Add($historyFile.Name)
        }

        if (-not [string]::IsNullOrWhiteSpace($StagedHistoryPath) -and -not [string]::IsNullOrWhiteSpace($HistoryTargetPath)) {
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = $StagedHistoryPath
                TargetPath = $HistoryTargetPath
            })

            $historyName = Split-Path -Leaf $HistoryTargetPath
            [void]$publishedHistoryNames.Add($historyName)
            $outputFiles.Add($HistoryTargetPath)
        }

        $removePaths = @(Get-MachineHistoryRemovePaths -BasePath $OutputPath -PublishedHistoryNames $publishedHistoryNames)
        Publish-StoreFilesTransactional -BasePath $OutputPath -StoreName 'machines' -Files @($filesToPublish) -RemovePaths $removePaths

        return [PSCustomObject]@{
            Success = $true
            ChangeCount = $ChangeCount
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
    $resolvedHeaders = $Headers
    $resolvedOutputPath = $OutputPath
    $resolvedBaseApiUrl = $BaseApiUrl
    $resolvedObservedOn = $observedOn

    return Invoke-WithStoreLock -BasePath $resolvedOutputPath -StoreName 'machines' -ScriptBlock {
        Restore-StoreTransaction -BasePath $resolvedOutputPath -StoreName 'machines'

        $store = Initialize-MachineHistoryStore -Path $resolvedOutputPath -RemoveLegacyFiles -LoadCurrentRecordsStateHashOnly
        $stagedCurrentPath = Join-Path $resolvedOutputPath ('.machine-current-staged-' + [guid]::NewGuid().ToString('N') + '.json.gz')
        $refreshPlan = Get-MdeMachineRefreshPublishPlan -Headers $resolvedHeaders -BaseApiUrl $resolvedBaseApiUrl -ObservedOn $resolvedObservedOn -CurrentRecords $store.CurrentRecords -StagedCurrentPath $stagedCurrentPath
        $store.CurrentRecords = $null

        if (Get-Command -Name Invoke-FullGarbageCollection -ErrorAction SilentlyContinue) {
            Invoke-FullGarbageCollection
        }

        try {
            $publishResult = Publish-MachineStoreState -OutputPath $resolvedOutputPath -Store $store -ChangeCount $refreshPlan.ChangeCount -StagedCurrentPath $refreshPlan.StagedCurrentPath -CurrentRecordCount $refreshPlan.MachineCount -StagedHistoryPath $refreshPlan.StagedHistoryPath -HistoryTargetPath $refreshPlan.HistoryTargetPath
            return [PSCustomObject]@{
                Success = $true
                MachineCount = $refreshPlan.MachineCount
                ChangeCount = $publishResult.ChangeCount
                PageCount = $refreshPlan.PageCount
                OutputFiles = @($publishResult.OutputFiles)
                MigratedLegacy = $publishResult.MigratedLegacy
            }
        }
        finally {
            if (Test-Path -LiteralPath $stagedCurrentPath -PathType Leaf) {
                Remove-Item -LiteralPath $stagedCurrentPath -Force -ErrorAction SilentlyContinue
            }
            if (-not [string]::IsNullOrWhiteSpace($refreshPlan.StagedHistoryPath) -and (Test-Path -LiteralPath $refreshPlan.StagedHistoryPath -PathType Leaf)) {
                Remove-Item -LiteralPath $refreshPlan.StagedHistoryPath -Force -ErrorAction SilentlyContinue
            }
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
