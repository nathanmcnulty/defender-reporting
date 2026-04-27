if (-not (Get-Variable -Name LegacyVulnMigrationRemovalDate -Scope Script -ErrorAction SilentlyContinue)) {
    $Script:LegacyVulnMigrationRemovalDate = '2026-07-01'
}

function Get-BuildRemediationString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $kbId = $null
    if ($Row.RecommendedSecurityUpdateId) {
        $kbText = [string]$Row.RecommendedSecurityUpdateId
        $kbId = if ($kbText.StartsWith('KB')) { $kbText } else { "KB$kbText" }
    }

    if ($Row.CveBatchTitle) {
        return $(if ($kbId) { "$($Row.CveBatchTitle) ($kbId)" } else { [string]$Row.CveBatchTitle })
    }

    if ($Row.RecommendedSecurityUpdate -and $kbId) {
        return "$($Row.RecommendedSecurityUpdate) ($kbId)"
    }

    if ($Row.RecommendedSecurityUpdate) {
        return [string]$Row.RecommendedSecurityUpdate
    }

    if ($kbId) {
        return $kbId
    }

    return 'Not Specified'
}

function Format-ProductPart {
    [CmdletBinding()]
    param([AllowNull()][string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return 'Unknown' }
    return (($Text -split '_') | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) { return $_ }
        $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1).ToLowerInvariant()
    }) -join ' '
}

function Get-NormalizedRemediationText {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return '' }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return '' }

    $trimmed = $text.Trim()
    if ($trimmed.ToLowerInvariant() -eq 'unknown') { return '' }

    return $trimmed
}

function Get-NormalizedKbId {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)

    $text = Get-NormalizedRemediationText -Value $Value
    if ([string]::IsNullOrWhiteSpace($text)) { return '' }
    return $(if ($text.StartsWith('KB', [System.StringComparison]::OrdinalIgnoreCase)) { $text.ToUpperInvariant() } else { "KB$text" })
}

function Test-IsNumericRemediationReference {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value -match '^\d+$' -or $Value -match '^KB\d+$')
}

function Test-IsCveRemediationReference {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value -match '^CVE-\d{4}-\d+$')
}

function Get-RemediationPatchReferenceSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.Generic.HashSet[string]]$Values
    )

    if ($null -eq $Values -or $Values.Count -eq 0) {
        return ''
    }

    $sortedValues = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($sortedValues.Count -eq 0) {
        return ''
    }

    if ($sortedValues.Count -eq 1) {
        return [string]$sortedValues[0]
    }

    if ($sortedValues.Count -eq 2) {
        return ([string]::Join(', ', $sortedValues))
    }

    return ("{0} +{1} more" -f $sortedValues[0], ($sortedValues.Count - 1))
}

function Get-RemediationDescriptor {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $advisoryTitle = Get-NormalizedRemediationText -Value $Row.CveBatchTitle
    $updateName = Get-NormalizedRemediationText -Value $Row.RecommendedSecurityUpdate
    $updateId = Get-NormalizedRemediationText -Value $Row.RecommendedSecurityUpdateId
    $kbId = Get-NormalizedKbId -Value $updateId
    $updateUrl = Get-NormalizedRemediationText -Value $Row.RecommendedSecurityUpdateUrl
    $osPlatform = Get-NormalizedRemediationText -Value $Row.OSPlatform
    if ([string]::IsNullOrWhiteSpace($osPlatform)) { $osPlatform = 'Unknown' }

    $recommendationReference = Get-NormalizedRemediationText -Value $Row.RecommendationReference
    $vendorPart = if ([string]::IsNullOrWhiteSpace([string]$Row.SoftwareVendor)) { '' } else { Format-ProductPart -Text ([string]$Row.SoftwareVendor) }
    $productPart = if ([string]::IsNullOrWhiteSpace([string]$Row.SoftwareName)) { '' } else { Format-ProductPart -Text ([string]$Row.SoftwareName) }

    $productLabel = if ($vendorPart -and $productPart) {
        "$vendorPart - $productPart"
    }
    elseif ($vendorPart) {
        $vendorPart
    }
    elseif ($productPart) {
        $productPart
    }
    else {
        'Unknown'
    }

    $scopeLabel = if ($productPart) {
        $productPart
    }
    elseif (-not [string]::IsNullOrWhiteSpace($productLabel) -and $productLabel -ne 'Unknown') {
        $productLabel
    }
    elseif ($vendorPart) {
        $vendorPart
    }
    else {
        'Unknown'
    }

    $scopeKey = if ($recommendationReference) {
        $recommendationReference
    }
    else {
        $vendorKey = Get-NormalizedRemediationText -Value $Row.SoftwareVendor
        $productKey = Get-NormalizedRemediationText -Value $Row.SoftwareName
        if ($vendorKey -or $productKey) {
            @($vendorKey, $productKey) -join '|'
        }
        else {
            $scopeLabel
        }
    }

    $familyTitle = if ($advisoryTitle) {
        $advisoryTitle
    }
    elseif ($updateName) {
        $updateName
    }
    elseif ($kbId) {
        $kbId
    }
    elseif ($recommendationReference) {
        $recommendationReference
    }
    else {
        'Not Specified'
    }

    $title = $familyTitle
    if ($scopeLabel -ne 'Unknown') {
        if ($advisoryTitle) {
            $title = if ($advisoryTitle.IndexOf($scopeLabel, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $advisoryTitle
            }
            else {
                "${scopeLabel}: $advisoryTitle"
            }
        }
        elseif ($updateName) {
            if (Test-IsNumericRemediationReference -Value $updateName) {
                $title = "$scopeLabel patch $updateName"
            }
            elseif (Test-IsCveRemediationReference -Value $updateName) {
                $title = "$scopeLabel advisory $updateName"
            }
            else {
                $title = "${scopeLabel}: $updateName"
            }
        }
        elseif ($kbId) {
            $title = "$scopeLabel patch $kbId"
        }
        elseif ($recommendationReference -and $recommendationReference -ne $scopeLabel) {
            $title = "${scopeLabel}: $recommendationReference"
        }
        else {
            $title = $scopeLabel
        }
    }

    $patchReference = if ($updateName -and $updateName -ne $familyTitle) {
        $updateName
    }
    elseif ($kbId -and $kbId -ne $familyTitle) {
        $kbId
    }
    else {
        ''
    }

    return [PSCustomObject]@{
        Key = "$scopeKey|$familyTitle|$osPlatform"
        Title = $title
        FamilyTitle = $familyTitle
        ProductLabel = $productLabel
        ScopeLabel = $scopeLabel
        PatchReference = $patchReference
        UpdateName = $(if ($updateName) { $updateName } else { 'Unknown' })
        UpdateId = $updateId
        UpdateUrl = $updateUrl
        OSPlatform = $osPlatform
    }
}

function Get-CanonicalRowSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $payload = [ordered]@{
        DeviceId = [string]$Row.DeviceId
        DeviceName = [string]$Row.DeviceName
        RbacGroupName = [string]$Row.RbacGroupName
        OSPlatform = [string]$Row.OSPlatform
        OSVersion = [string]$Row.OSVersion
        MachineTags = @((Get-StringArray $Row.MachineTags | Sort-Object -Unique))
        MachineIp = if ($Row.MachineInfo) { [string]$Row.MachineInfo.ip } else { '' }
        CveId = [string]$Row.CveId
        CvssScore = (Get-NormalizedAuditDecimalString -Value $Row.CvssScore)
        VulnerabilitySeverityLevel = [string]$Row.VulnerabilitySeverityLevel
        ExploitabilityLevel = [string]$Row.ExploitabilityLevel
        CveBatchUrl = [string]$Row.CveBatchUrl
        CveBatchTitle = [string]$Row.CveBatchTitle
        SoftwareVendor = [string]$Row.SoftwareVendor
        SoftwareName = [string]$Row.SoftwareName
        SoftwareVersion = [string]$Row.SoftwareVersion
        RecommendationReference = [string]$Row.RecommendationReference
        ProductCodeCpe = [string]$Row.ProductCodeCpe
        EndOfSupportStatus = [string]$Row.EndOfSupportStatus
        EndOfSupportDate = [string](Convert-ToYmdDate -DateValue $Row.EndOfSupportDate)
        FirstSeenTimestamp = [string]$Row.FirstSeenTimestamp
        LastSeenTimestamp = [string]$Row.LastSeenTimestamp
        SecurityUpdateAvailable = [bool]$Row.SecurityUpdateAvailable
        RecommendedSecurityUpdate = [string]$Row.RecommendedSecurityUpdate
        RecommendedSecurityUpdateId = [string]$Row.RecommendedSecurityUpdateId
        RecommendedSecurityUpdateUrl = [string]$Row.RecommendedSecurityUpdateUrl
        DiskPaths = @((Get-StringArray $Row.DiskPaths | Sort-Object -Unique))
        RegistryPaths = @((Get-StringArray $Row.RegistryPaths | Sort-Object -Unique))
    }

    return ($payload | ConvertTo-Json -Compress -Depth 20)
}

function Get-ObjectSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    $json = ConvertTo-Json -InputObject $InputObject -Compress -Depth 100
    if ($null -eq $json) {
        $json = 'null'
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
}

function Read-SourceRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ExportsPath,
        [Parameter(Mandatory = $true)]$Machines,
        [Parameter(Mandatory = $true)]$AdvancedHunting,
        [Parameter(Mandatory = $false)][switch]$SkipObservedWindowMerge,
        [Parameter(Mandatory = $false)]$AdvancedHuntingInventory = @{},
        [Parameter(Mandatory = $false)]$NvdCveData = @{}
    )

    $rawRows = [System.Collections.Generic.List[object]]::new()
    $vendorSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $sourceRowsAlreadyNormalized = $false
    $sourceInputMode = ''
    $shouldSkipObservedWindowMerge = ($SkipObservedWindowMerge -or (Test-IsSyntheticDataset -BasePath $ExportsPath))

    $contentStoreAvailable = Sync-VulnContentStoreSidecar -BasePath $ExportsPath

    if ($contentStoreAvailable) {
        $sourceInputMode = 'content-store'
        $sourceRowsAlreadyNormalized = $shouldSkipObservedWindowMerge
        foreach ($record in Read-VulnContentStoreRow -BasePath $ExportsPath) {
            if ((Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -ne $true) { continue }
            $rawRows.Add([PSCustomObject]@{
                FileName = 'VulnExportContentStore'
                Record = $record
            })
            $vendor = [string](Get-VulnPropertyValue -InputObject $record -Name 'SoftwareVendor')
            $vendorMatchKey = Get-VendorMatchKey -Vendor $vendor
            if (-not [string]::IsNullOrWhiteSpace($vendorMatchKey)) {
                [void]$vendorSet.Add($vendorMatchKey)
            }
        }
    }
    elseif (Test-VulnStoreExistence -BasePath $ExportsPath) {
        $sourceInputMode = 'normalized-vuln-store'
        $sourceRowsAlreadyNormalized = $true
        foreach ($record in Read-NormalizedVulnStoreRow -BasePath $ExportsPath) {
            if ((Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -ne $true) { continue }
            $rawRows.Add([PSCustomObject]@{
                FileName = 'VulnExportStore'
                Record = $record
            })
            $vendor = [string](Get-VulnPropertyValue -InputObject $record -Name 'SoftwareVendor')
            $vendorMatchKey = Get-VendorMatchKey -Vendor $vendor
            if (-not [string]::IsNullOrWhiteSpace($vendorMatchKey)) {
                [void]$vendorSet.Add($vendorMatchKey)
            }
        }
    }
    else {
        throw "No canonical vulnerability store or content-store sidecars were found in '$ExportsPath'."
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $firstLastSwappedCount = 0
    $missingMachineCount = 0
    $deviceProfiles = @{}

    foreach ($entry in $rawRows) {
        $record = $entry.Record
        $deviceId = [string]$record.DeviceId
        $machine = if ($Machines.ContainsKey($deviceId)) { $Machines[$deviceId] } else { $null }
        if ($null -eq $machine) { $missingMachineCount++ }
        $fallbackDeviceName = [string]$record.PSObject.Properties['DeviceName']?.Value
        $fallbackGroupName = [string]$record.PSObject.Properties['RbacGroupName']?.Value
        $fallbackPlatform = [string]$record.PSObject.Properties['OSPlatform']?.Value
        $fallbackOsVersion = [string]$record.PSObject.Properties['OSVersion']?.Value
        $fallbackMachineTags = if ($record.PSObject.Properties['MachineTags']?.Value) {
            @(Get-StringArray -Value $record.PSObject.Properties['MachineTags']?.Value)
        }
        else {
            @()
        }
        $deviceKey = if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
            $deviceId
        }
        else {
            @(
                $fallbackDeviceName
                $fallbackGroupName
                $fallbackPlatform
                $fallbackOsVersion
            ) -join '|'
        }

        if (-not $deviceProfiles.ContainsKey($deviceKey)) {
            $machineProjection = Get-MachineProjection -Machine $machine
            $groupName = if ($machineProjection) { [string]$machineProjection.RbacGroupName } else { $fallbackGroupName }
            if ([string]::IsNullOrWhiteSpace($groupName)) {
                $groupName = if ([string]::IsNullOrWhiteSpace($fallbackGroupName)) { '(none)' } else { $fallbackGroupName }
            }

            $projectedDeviceName = if ($machineProjection) { [string]$machineProjection.ComputerDnsName } else { $null }
            $projectedOsPlatform = if ($machineProjection) { [string]$machineProjection.OSPlatform } else { $null }
            $projectedOsVersion = if ($machineProjection) { [string]$machineProjection.OSVersion } else { $null }

            $machineTags = if ($machineProjection -and @($machineProjection.MachineTags).Count -gt 0) {
                @($machineProjection.MachineTags)
            }
            elseif (@($fallbackMachineTags).Count -gt 0) {
                @($fallbackMachineTags)
            }
            else {
                @()
            }

            $deviceProfiles[$deviceKey] = [PSCustomObject]@{
                DeviceName = if (-not [string]::IsNullOrWhiteSpace($projectedDeviceName)) { $projectedDeviceName } elseif (-not [string]::IsNullOrWhiteSpace([string]$fallbackDeviceName)) { $fallbackDeviceName } else { '(no machine data)' }
                RbacGroupName = $groupName
                OSPlatform = if (-not [string]::IsNullOrWhiteSpace($projectedOsPlatform)) { $projectedOsPlatform } else { $fallbackPlatform }
                OSVersion = if (-not [string]::IsNullOrWhiteSpace($projectedOsVersion)) { $projectedOsVersion } else { $fallbackOsVersion }
                MachineTags = $machineTags
                MachineInfo = if ($machineProjection) { $machineProjection.MachineInfo } else { $null }
            }
        }
        $deviceProfile = $deviceProfiles[$deviceKey]

        $seenWindow = Get-NormalizedVulnSeenWindow `
            -FirstSeenValue $record.PSObject.Properties['FirstSeenTimestamp']?.Value `
            -LastSeenValue $record.PSObject.Properties['LastSeenTimestamp']?.Value
        $firstSeen = $seenWindow.FirstSeenTimestamp
        $lastSeen = $seenWindow.LastSeenTimestamp
        if ($seenWindow.WasReordered) {
            $firstLastSwappedCount++
        }
        if (-not $firstSeen) { $firstSeen = '' }
        if (-not $lastSeen) { $lastSeen = '' }

        $cveEnrichment = Get-SourceCveEnrichment -CveId ([string]$record.CveId) -AdvancedHunting $AdvancedHunting -NvdCveData $NvdCveData -VendorSet $vendorSet
        $inventoryEnrichment = Get-SourceInventoryEnrichment -Record $record -AdvancedHuntingInventory $AdvancedHuntingInventory

        $recommendedUpdate = [string]$record.PSObject.Properties['RecommendedSecurityUpdate']?.Value
        if ([string]::IsNullOrWhiteSpace($recommendedUpdate) -or $recommendedUpdate -eq '--') {
            $recommendedUpdate = $null
        }

        $updateId = if ($recommendedUpdate) { [string]$record.PSObject.Properties['RecommendedSecurityUpdateId']?.Value } else { $null }
        $updateUrl = if ($recommendedUpdate) { [string]$record.PSObject.Properties['RecommendedSecurityUpdateUrl']?.Value } else { $null }

        $rows.Add([PSCustomObject]@{
            SourceFile = $entry.FileName
            SourceId = [string]$record.Id
            DeviceId = $deviceId
            DeviceName = [string]$deviceProfile.DeviceName
            RbacGroupName = [string]$deviceProfile.RbacGroupName
            OSPlatform = [string]$deviceProfile.OSPlatform
            OSVersion = [string]$deviceProfile.OSVersion
            MachineTags = @($deviceProfile.MachineTags)
            MachineInfo = $deviceProfile.MachineInfo
            CveId = [string]$record.CveId
            CvssScore = $record.PSObject.Properties['CvssScore']?.Value
            VulnerabilitySeverityLevel = [string]$record.PSObject.Properties['VulnerabilitySeverityLevel']?.Value
            ExploitabilityLevel = [string]$record.PSObject.Properties['ExploitabilityLevel']?.Value
            CveBatchUrl = Convert-CveUrl -Url ([string]$record.PSObject.Properties['CveBatchUrl']?.Value)
            CveBatchTitle = [string]$record.PSObject.Properties['CveBatchTitle']?.Value
            PublishedDate = $cveEnrichment.PublishedDate
            VulnerabilityDescription = $cveEnrichment.VulnerabilityDescription
            EpssScore = $cveEnrichment.EpssScore
            AffectedSoftware = $cveEnrichment.AffectedSoftware
            IsExploitAvailable = $cveEnrichment.IsExploitAvailable
            NvdLastModifiedDate = $cveEnrichment.NvdLastModifiedDate
            NvdBaseScore = $cveEnrichment.NvdBaseScore
            NvdBaseSeverity = $cveEnrichment.NvdBaseSeverity
            NvdVector = $cveEnrichment.NvdVector
            NvdKevDate = $cveEnrichment.NvdKevDate
            NvdActionDue = $cveEnrichment.NvdActionDue
            NvdRequiredAction = $cveEnrichment.NvdRequiredAction
            NvdWeaknesses = $cveEnrichment.NvdWeaknesses
            SoftwareVendor = [string]$record.PSObject.Properties['SoftwareVendor']?.Value
            SoftwareName = [string]$record.PSObject.Properties['SoftwareName']?.Value
            SoftwareVersion = [string]$record.PSObject.Properties['SoftwareVersion']?.Value
            RecommendationReference = [string]$record.PSObject.Properties['RecommendationReference']?.Value
            ProductCodeCpe = $inventoryEnrichment.ProductCodeCpe
            EndOfSupportStatus = $inventoryEnrichment.EndOfSupportStatus
            EndOfSupportDate = $inventoryEnrichment.EndOfSupportDate
            FirstSeenTimestamp = $firstSeen
            LastSeenTimestamp = $lastSeen
            SecurityUpdateAvailable = ($record.PSObject.Properties['SecurityUpdateAvailable']?.Value -eq $true)
            RecommendedSecurityUpdate = $recommendedUpdate
            RecommendedSecurityUpdateId = $updateId
            RecommendedSecurityUpdateUrl = $updateUrl
            DiskPaths = Get-StringArray -Value $record.PSObject.Properties['DiskPaths']?.Value
            RegistryPaths = Get-StringArray -Value $record.PSObject.Properties['RegistryPaths']?.Value
        })
    }

    $comparisonRows = [System.Collections.Generic.List[object]]::new()
    if ($sourceRowsAlreadyNormalized) {
        foreach ($row in $rows) {
            $comparisonRows.Add($row)
        }
    }
    else {
        foreach ($row in @(Merge-VulnObservedWindowRows -Rows @($rows))) {
            $comparisonRows.Add($row)
        }
    }

    return [PSCustomObject]@{
        Rows = $comparisonRows
        FirstLastSwappedCount = $firstLastSwappedCount
        MissingMachineCount = $missingMachineCount
        VendorSet = @($vendorSet)
        RawRowCount = @($rawRows).Count
        InputMode = $sourceInputMode
    }
}

function Read-DashboardPayload {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $content = [System.IO.File]::ReadAllText($resolvedPath, [System.Text.Encoding]::UTF8)
    $dataFormat = Get-DashboardHtmlScriptContent -Html $content -ScriptId 'dataFormat'

    if ($dataFormat -eq 'external-compressed') {
        $dashboardConfigJson = Get-DashboardHtmlScriptContent -Html $content -ScriptId 'dashboardConfig'
        if ([string]::IsNullOrWhiteSpace($dashboardConfigJson)) {
            throw "Unable to locate dashboardConfig metadata in '$Path'."
        }

        $dashboardConfig = $dashboardConfigJson | ConvertFrom-Json -Depth 20
        $payloadUrl = [string]$dashboardConfig.payloadUrl
        if ([string]::IsNullOrWhiteSpace($payloadUrl)) {
            throw "dashboardConfig in '$Path' does not define payloadUrl."
        }

        $htmlDirectory = Split-Path -Path $resolvedPath -Parent
        $payloadRelativePath = $payloadUrl.Replace('/', '\')
        $payloadPath = [System.IO.Path]::GetFullPath((Join-Path $htmlDirectory $payloadRelativePath))
        return (Read-CompressedPayloadObject -Path $payloadPath)
    }

    $startMarker = '<script id="vulnsData" type="application/json">'
    $endMarker = '</script>'
    $startIndex = $content.IndexOf($startMarker)

    if ($startIndex -lt 0) {
        throw "Unable to locate embedded vulnerability payload in '$Path'."
    }
    $payloadStart = $startIndex + $startMarker.Length
    $payloadEnd = $content.IndexOf($endMarker, $payloadStart)
    if ($payloadEnd -lt 0) {
        throw "Unable to locate payload terminator in '$Path'."
    }

    $base64 = ($content.Substring($payloadStart, $payloadEnd - $payloadStart) -replace '\s+', '')
    $bytes = [Convert]::FromBase64String($base64)

    $stream = [System.IO.MemoryStream]::new($bytes)
    try {
        $gzip = [System.IO.Compression.GZipStream]::new($stream, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $reader = [System.IO.StreamReader]::new($gzip, [System.Text.Encoding]::UTF8)
            try {
                $json = $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $gzip.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }

    return ($json | ConvertFrom-Json -Depth 100)
}

function Read-CompressedPayloadObject {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $gzip = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $reader = [System.IO.StreamReader]::new($gzip, [System.Text.Encoding]::UTF8)
            try {
                $json = $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $gzip.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }

    return ($json | ConvertFrom-Json -Depth 100)
}

function Read-DashboardRow {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Payload)

    $rows = [System.Collections.Generic.List[object]]::new()
    $lookups = $Payload.lookups
    function Get-LookupValue {
        param(
            [Parameter(Mandatory = $true)]
            $List,

            [Parameter(Mandatory = $false)]
            $Index
        )

        if ($null -eq $List -or $null -eq $Index) { return $null }

        try {
            $resolvedIndex = [int]$Index
        }
        catch {
            return $null
        }

        if ($resolvedIndex -lt 0) { return $null }
        if ($resolvedIndex -ge @($List).Count) { return $null }
        return $List[$resolvedIndex]
    }

    function Get-PayloadVulnCount {
        param([Parameter(Mandatory = $true)]$Vulns)

        if ($Vulns -is [System.Collections.IList]) {
            return $Vulns.Count
        }

        if ($Vulns.PSObject.Properties['d']) {
            return @($Vulns.d).Count
        }

        return 0
    }

    function Get-PayloadVulnRecord {
        param(
            [Parameter(Mandatory = $true)]$Vulns,
            [Parameter(Mandatory = $true)][int]$Index
        )

        if ($Vulns -is [System.Collections.IList]) {
            return $Vulns[$Index]
        }

        $diskPathValue = $Vulns.dp[$Index]
        if ($null -ne $diskPathValue -and ($diskPathValue -isnot [System.Collections.IEnumerable] -or $diskPathValue -is [string])) {
            $diskPathValue = @($diskPathValue)
        }

        $registryPathValue = $Vulns.rp[$Index]
        if ($null -ne $registryPathValue -and ($registryPathValue -isnot [System.Collections.IEnumerable] -or $registryPathValue -is [string])) {
            $registryPathValue = @($registryPathValue)
        }

        return @(
            $Vulns.d[$Index]
            $Vulns.c[$Index]
            $Vulns.s[$Index]
            $Vulns.v[$Index]
            $Vulns.f[$Index]
            $Vulns.l[$Index]
            $Vulns.ua[$Index]
            $Vulns.u[$Index]
            ,$diskPathValue
            ,$registryPathValue
            $(if ($Vulns.PSObject.Properties['iv']) { $Vulns.iv[$Index] } else { -1 })
        )
    }

    $vulnCount = Get-PayloadVulnCount -Vulns $Payload.vulns
    for ($i = 0; $i -lt $vulnCount; $i++) {
        $v = Get-PayloadVulnRecord -Vulns $Payload.vulns -Index $i
        $device = $lookups.devices[$v[0]]
        $cve = $lookups.cves[$v[1]]
        $software = $lookups.software[$v[2]]

        $machineTags = @()
        $tagIndices = @($device.t | Where-Object { $null -ne $_ })
        if ($tagIndices.Count -gt 0) {
            foreach ($tagIndex in $tagIndices) {
                $machineTags += [string]$lookups.tags[$tagIndex]
            }
        }

        $diskPaths = @()
        $diskPathIndices = @($v[8] | Where-Object { $null -ne $_ })
        if ($diskPathIndices.Count -gt 0) {
            foreach ($pathIndex in $diskPathIndices) {
                $resolvedPath = Get-LookupValue -List $lookups.diskPaths -Index $pathIndex
                if ($null -ne $resolvedPath) {
                    $diskPaths += [string]$resolvedPath
                }
            }
        }

        $registryPaths = @()
        $registryPathIndices = @($v[9] | Where-Object { $null -ne $_ })
        if ($registryPathIndices.Count -gt 0) {
            foreach ($pathIndex in $registryPathIndices) {
                $resolvedPath = Get-LookupValue -List $lookups.regPaths -Index $pathIndex
                if ($null -ne $resolvedPath) {
                    $registryPaths += [string]$resolvedPath
                }
            }
        }

        $affectedSoftware = $null
        $affectedSoftwareIndices = @($cve.as | Where-Object { $null -ne $_ })
        if ($affectedSoftwareIndices.Count -gt 0) {
            $resolved = [System.Collections.Generic.List[string]]::new()
            foreach ($index in $affectedSoftwareIndices) {
                $resolvedSoftware = Get-LookupValue -List $lookups.affSoftware -Index $index
                if ($null -ne $resolvedSoftware) {
                    $resolved.Add([string]$resolvedSoftware)
                }
            }
            if ($resolved.Count -gt 0) {
                $affectedSoftware = @($resolved)
            }
        }

        $updateObject = if ($v[7] -ge 0) { $lookups.updates[$v[7]] } else { $null }
        $inventoryObject = if ($v.Count -gt 10 -and $v[10] -ge 0) { Get-LookupValue -List $lookups.inventory -Index $v[10] } else { $null }
        $groupName = Get-LookupValue -List $lookups.groups -Index $device.g
        $platformName = Get-LookupValue -List $lookups.platforms -Index $device.o
        $severityName = Get-LookupValue -List $lookups.severities -Index $cve.sv
        $exploitabilityName = Get-LookupValue -List $lookups.exploitLevels -Index $cve.ex
        $batchTitle = Get-LookupValue -List $lookups.batchTitles -Index $cve.bt
        $softwareVendor = Get-LookupValue -List $lookups.vendors -Index $software.v
        $softwareVersion = Get-LookupValue -List $lookups.versions -Index $v[3]
        $firstSeenDate = Get-LookupValue -List $lookups.dates -Index $v[4]
        $lastSeenDate = Get-LookupValue -List $lookups.dates -Index $v[5]

        $rows.Add([PSCustomObject]@{
            DeviceId = [string]$device.id
            DeviceName = [string]$device.n
            RbacGroupName = if ($groupName -and -not [string]::IsNullOrWhiteSpace([string]$groupName)) { [string]$groupName } else { '(none)' }
            OSPlatform = if ($null -ne $platformName) { [string]$platformName } else { $null }
            OSVersion = [string]$device.ov
            MachineTags = $machineTags
            MachineInfo = if ($device.m) { [PSCustomObject]$device.m } else { $null }
            CveId = [string]$cve.id
            CvssScore = $cve.sc
            VulnerabilitySeverityLevel = if ($null -ne $severityName) { [string]$severityName } else { $null }
            ExploitabilityLevel = if ($null -ne $exploitabilityName) { [string]$exploitabilityName } else { $null }
            CveBatchUrl = [string]$cve.u
            CveBatchTitle = if ($null -ne $batchTitle) { [string]$batchTitle } else { $null }
            PublishedDate = Convert-ToYmdDate -DateValue $cve.pd
            VulnerabilityDescription = if ($null -ne $cve.desc) { [string]$cve.desc } else { $null }
            EpssScore = if ($null -ne $cve.ep) { $cve.ep } else { $null }
            AffectedSoftware = $affectedSoftware
            IsExploitAvailable = if ($null -eq $cve.PSObject.Properties['ea']?.Value) { $null } else { ($cve.ea -eq $true) }
            NvdLastModifiedDate = Convert-ToYmdDate -DateValue $cve.PSObject.Properties['nlm']?.Value
            NvdBaseScore = $cve.PSObject.Properties['nbs']?.Value
            NvdBaseSeverity = [string]$cve.PSObject.Properties['nsv']?.Value
            NvdVector = [string]$cve.PSObject.Properties['nvec']?.Value
            NvdKevDate = Convert-ToYmdDate -DateValue $cve.PSObject.Properties['nkev']?.Value
            NvdActionDue = Convert-ToYmdDate -DateValue $cve.PSObject.Properties['ndu']?.Value
            NvdRequiredAction = [string]$cve.PSObject.Properties['nact']?.Value
            NvdWeaknesses = if ($cve.PSObject.Properties['nw']?.Value) { @(Get-StringArray -Value $cve.nw) } else { $null }
            SoftwareVendor = if ($null -ne $softwareVendor) { [string]$softwareVendor } else { $null }
            SoftwareName = [string]$software.n
            SoftwareVersion = if ($null -ne $softwareVersion) { [string]$softwareVersion } else { $null }
            RecommendationReference = [string]$software.r
            ProductCodeCpe = if ($inventoryObject) { [string]$inventoryObject.cpe } else { $null }
            EndOfSupportStatus = if ($inventoryObject) { [string]$inventoryObject.eos } else { $null }
            EndOfSupportDate = if ($inventoryObject) { (Convert-ToYmdDate -DateValue $inventoryObject.eod) } else { $null }
            FirstSeenTimestamp = if ($null -ne $firstSeenDate) { (Convert-ToYmdDate -DateValue $firstSeenDate) ?? '' } else { '' }
            LastSeenTimestamp = if ($null -ne $lastSeenDate) { (Convert-ToYmdDate -DateValue $lastSeenDate) ?? '' } else { '' }
            SecurityUpdateAvailable = ($v[6] -eq 1)
            RecommendedSecurityUpdate = if ($updateObject) { [string]($updateObject.n ?? $updateObject) } else { $null }
            RecommendedSecurityUpdateId = if ($updateObject -and $updateObject.id) { [string]$updateObject.id } else { $null }
            RecommendedSecurityUpdateUrl = if ($updateObject -and $updateObject.url) { [string]$updateObject.url } else { $null }
            DiskPaths = $diskPaths
            RegistryPaths = $registryPaths
            _index = $i
        })
    }

    return $rows
}

function Compare-RowSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$ExpectedRows,
        [Parameter(Mandatory = $true)]$ActualRows
    )

    $expectedMap = @{}
    foreach ($row in $ExpectedRows) {
        $signature = Get-CanonicalRowSignature -Row $row
        $expectedMap[$signature] = 1 + ($expectedMap[$signature] ?? 0)
    }

    $actualMap = @{}
    foreach ($row in $ActualRows) {
        $signature = Get-CanonicalRowSignature -Row $row
        $actualMap[$signature] = 1 + ($actualMap[$signature] ?? 0)
    }

    $missingSamples = [System.Collections.Generic.List[object]]::new()
    $extraSamples = [System.Collections.Generic.List[object]]::new()
    $missingCount = 0
    $extraCount = 0

    foreach ($key in $expectedMap.Keys) {
        $actualCount = $actualMap[$key] ?? 0
        if ($actualCount -lt $expectedMap[$key]) {
            $diff = $expectedMap[$key] - $actualCount
            $missingCount += $diff
            if ($missingSamples.Count -lt 5) {
                $missingSamples.Add([PSCustomObject]@{
                    MissingOccurrences = $diff
                    Signature = ($key | ConvertFrom-Json -Depth 20)
                })
            }
        }
    }

    foreach ($key in $actualMap.Keys) {
        $expectedCount = $expectedMap[$key] ?? 0
        if ($expectedCount -lt $actualMap[$key]) {
            $diff = $actualMap[$key] - $expectedCount
            $extraCount += $diff
            if ($extraSamples.Count -lt 5) {
                $extraSamples.Add([PSCustomObject]@{
                    ExtraOccurrences = $diff
                    Signature = ($key | ConvertFrom-Json -Depth 20)
                })
            }
        }
    }

    return [PSCustomObject]@{
        Match = ($missingCount -eq 0 -and $extraCount -eq 0)
        ExpectedRows = $ExpectedRows.Count
        ActualRows = $ActualRows.Count
        MissingCount = $missingCount
        ExtraCount = $extraCount
        MissingSamples = $missingSamples
        ExtraSamples = $extraSamples
    }
}

function Get-DateRange {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rows)

    $firstDates = @($Rows | ForEach-Object { $_.FirstSeenTimestamp } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
    $lastDates = @($Rows | ForEach-Object { $_.LastSeenTimestamp } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
    return [PSCustomObject]@{
        Start = $firstDates[0]
        End = $lastDates[-1]
    }
}

function Get-DateSeries {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$StartDate,
        [Parameter(Mandatory = $true)][string]$EndDate
    )

    $dates = [System.Collections.Generic.List[string]]::new()
    $current = [datetime]$StartDate
    $end = [datetime]$EndDate
    while ($current -le $end) {
        $dates.Add($current.ToString('yyyy-MM-dd'))
        $current = $current.AddDays(1)
    }
    return $dates
}

function Get-RowMachineLastSeenDate {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Row)

    if ($null -eq $Row.MachineInfo) {
        return ''
    }

    return (Convert-ToYmdDate -DateValue ($Row.MachineInfo.PSObject.Properties['ls']?.Value))
}

function Get-RowLatestActivityDate {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Row)

    $vulnLastSeen = [string]$Row.LastSeenTimestamp
    $machineLastSeen = Get-RowMachineLastSeenDate -Row $Row
    if ([string]::IsNullOrWhiteSpace($machineLastSeen)) {
        return $vulnLastSeen
    }

    if ([string]::IsNullOrWhiteSpace($vulnLastSeen)) {
        return $machineLastSeen
    }

    if ([datetime]$machineLastSeen -gt [datetime]$vulnLastSeen) {
        return $machineLastSeen
    }

    return $vulnLastSeen
}

function Test-RowHasPatchedEvidence {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)]$Row)

    $vulnLastSeen = [string]$Row.LastSeenTimestamp
    $latestActivity = Get-RowLatestActivityDate -Row $Row
    if ([string]::IsNullOrWhiteSpace($vulnLastSeen) -or [string]::IsNullOrWhiteSpace($latestActivity)) {
        return $false
    }

    return ([datetime]$latestActivity -gt [datetime]$vulnLastSeen)
}

function Get-RowEffectiveOpenEndDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]$Row,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 365)]
        [int]$InactivityWindowDays = 30
    )

    $vulnLastSeen = [string]$Row.LastSeenTimestamp
    if ([string]::IsNullOrWhiteSpace($vulnLastSeen)) {
        return ''
    }

    $latestActivity = Get-RowLatestActivityDate -Row $Row
    if ([string]::IsNullOrWhiteSpace($latestActivity)) {
        $latestActivity = $vulnLastSeen
    }

    if (Test-RowHasPatchedEvidence -Row $Row) {
        return $vulnLastSeen
    }

    return ([datetime]$latestActivity).AddDays($InactivityWindowDays).ToString('yyyy-MM-dd')
}

function Get-LatestObservedDate {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)]$Rows)

    $maxDate = ''
    foreach ($row in @($Rows)) {
        $candidate = Get-RowLatestActivityDate -Row $row
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and ($candidate -gt $maxDate)) {
            $maxDate = $candidate
        }
    }

    return $maxDate
}

function Get-OpenDateRange {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rows)

    $firstDates = @($Rows | ForEach-Object { $_.FirstSeenTimestamp } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
    $effectiveEndDates = @($Rows | ForEach-Object { Get-RowEffectiveOpenEndDate -Row $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object)
    return [PSCustomObject]@{
        Start = if ($firstDates.Count -gt 0) { $firstDates[0] } else { '' }
        End = if ($effectiveEndDates.Count -gt 0) { $effectiveEndDates[-1] } else { '' }
    }
}

function Get-OpenRowsAtDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Rows,

        [Parameter(Mandatory = $true)]
        [string]$AsOfDate
    )

    return @(
        $Rows | Where-Object {
            $effectiveEnd = Get-RowEffectiveOpenEndDate -Row $_
            -not [string]::IsNullOrWhiteSpace($_.FirstSeenTimestamp) -and
            -not [string]::IsNullOrWhiteSpace($effectiveEnd) -and
            $_.FirstSeenTimestamp -le $AsOfDate -and
            $effectiveEnd -ge $AsOfDate
        }
    )
}

function Get-StatsReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $latestObservedDate = Get-LatestObservedDate -Rows $Rows
    $activeRows = if ([string]::IsNullOrWhiteSpace($latestObservedDate)) { @($Rows) } else { @(Get-OpenRowsAtDate -Rows $Rows -AsOfDate $latestObservedDate) }
    $counts = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    foreach ($row in $activeRows) {
        if ($row.VulnerabilitySeverityLevel -and $counts.Contains($row.VulnerabilitySeverityLevel)) {
            $counts[$row.VulnerabilitySeverityLevel]++
        }
    }
    return [PSCustomObject]$counts
}

function Get-ActiveChartReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $range = Get-OpenDateRange -Rows $Rows
    $dates = Get-DateSeries -StartDate $range.Start -EndDate $range.End
    $events = @{}

    foreach ($row in $Rows) {
        $startDate = $row.FirstSeenTimestamp
        $effectiveEndDate = Get-RowEffectiveOpenEndDate -Row $row
        $endDateExclusive = ([datetime]$effectiveEndDate).AddDays(1).ToString('yyyy-MM-dd')
        if ($endDateExclusive -le $startDate) {
            $endDateExclusive = ([datetime]$startDate).AddDays(1).ToString('yyyy-MM-dd')
        }

        if (-not $events.ContainsKey($startDate)) { $events[$startDate] = [PSCustomObject]@{ Starts = [System.Collections.Generic.List[object]]::new(); Ends = [System.Collections.Generic.List[object]]::new() } }
        if (-not $events.ContainsKey($endDateExclusive)) { $events[$endDateExclusive] = [PSCustomObject]@{ Starts = [System.Collections.Generic.List[object]]::new(); Ends = [System.Collections.Generic.List[object]]::new() } }
        $events[$startDate].Starts.Add($row)
        $events[$endDateExclusive].Ends.Add($row)
    }

    $severity = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    $deviceActive = @{}
    $total = 0
    $series = [System.Collections.Generic.List[object]]::new()

    foreach ($date in $dates) {
        if ($events.ContainsKey($date)) {
            foreach ($row in $events[$date].Starts) {
                $total++
                if ($row.VulnerabilitySeverityLevel -and $severity.ContainsKey($row.VulnerabilitySeverityLevel)) { $severity[$row.VulnerabilitySeverityLevel]++ }
                $deviceActive[$row.DeviceId] = 1 + ($deviceActive[$row.DeviceId] ?? 0)
            }
            foreach ($row in $events[$date].Ends) {
                if ($total -gt 0) { $total-- }
                if ($row.VulnerabilitySeverityLevel -and $severity.ContainsKey($row.VulnerabilitySeverityLevel) -and $severity[$row.VulnerabilitySeverityLevel] -gt 0) { $severity[$row.VulnerabilitySeverityLevel]-- }
                $count = $deviceActive[$row.DeviceId] ?? 0
                if ($count -le 1) { $deviceActive.Remove($row.DeviceId) } else { $deviceActive[$row.DeviceId] = $count - 1 }
            }
        }

        $series.Add([PSCustomObject]@{
            Date = $date
            Critical = $severity.Critical
            High = $severity.High
            Medium = $severity.Medium
            Low = $severity.Low
            Total = $total
            Devices = $deviceActive.Count
        })
    }

    return $series
}

function Get-RemediationChartReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $range = Get-DateRange -Rows $Rows
    $range.End = Get-LatestObservedDate -Rows $Rows
    $dates = Get-DateSeries -StartDate $range.Start -EndDate $range.End
    $index = @{}
    foreach ($row in @($Rows | Where-Object { Test-RowHasPatchedEvidence -Row $_ })) {
        $lastSeen = [string]$row.LastSeenTimestamp
        if (-not $index.ContainsKey($lastSeen)) {
            $index[$lastSeen] = [System.Collections.Generic.List[object]]::new()
        }
        $index[$lastSeen].Add($row)
    }

    $series = [System.Collections.Generic.List[object]]::new()
    foreach ($date in $dates) {
        $items = if ($index.ContainsKey($date)) { $index[$date] } else { @() }
        $devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $severity = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
        foreach ($row in $items) {
            [void]$devices.Add([string]$row.DeviceId)
            if ($row.VulnerabilitySeverityLevel -and $severity.ContainsKey($row.VulnerabilitySeverityLevel)) { $severity[$row.VulnerabilitySeverityLevel]++ }
        }

        $series.Add([PSCustomObject]@{
            Date = $date
            Critical = $severity.Critical
            High = $severity.High
            Medium = $severity.Medium
            Low = $severity.Low
            Total = @($items).Count
            Devices = $devices.Count
        })
    }

    return $series
}

function Get-RemediationTableReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $latestObservedDate = Get-LatestObservedDate -Rows $Rows
    $rows = if ([string]::IsNullOrWhiteSpace($latestObservedDate)) { @($Rows) } else { @(Get-OpenRowsAtDate -Rows $Rows -AsOfDate $latestObservedDate) }
    $map = @{}
    foreach ($row in $Rows) {
        $vendor = Format-ProductPart -Text $row.SoftwareVendor
        $software = Format-ProductPart -Text $row.SoftwareName
        $remediation = Get-BuildRemediationString -Row $row
        $key = "$vendor|$software|$remediation"
        if (-not $map.ContainsKey($key)) {
            $map[$key] = [PSCustomObject]@{
                Key = $key
                Vendor = $vendor
                Software = $software
                Remediation = $remediation
                Devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Vulnerabilities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Exploits = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Kits = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                RowCount = 0
            }
        }

        $item = $map[$key]
        [void]$item.Devices.Add([string]$row.DeviceId)
        [void]$item.Vulnerabilities.Add([string]$row.CveId)
        if ($row.ExploitabilityLevel -in @('ExploitIsVerified', 'ExploitIsPublic', 'ExploitIsInKit')) {
            [void]$item.Exploits.Add([string]$row.CveId)
        }
        if ($row.ExploitabilityLevel -eq 'ExploitIsInKit') {
            [void]$item.Kits.Add([string]$row.CveId)
        }
        $item.RowCount++
    }

    return @($map.Values | ForEach-Object {
        [PSCustomObject]@{
            Key = $_.Key
            Devices = $_.Devices.Count
            Vulnerabilities = $_.Vulnerabilities.Count
            Exploits = $_.Exploits.Count
            Kits = $_.Kits.Count
            RowCount = $_.RowCount
        }
    } | Sort-Object Key)
}

function Get-RemediationDetailsReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $map = @{}
    foreach ($row in @($Rows | Where-Object { Test-RowHasPatchedEvidence -Row $_ })) {
        $remediation = Get-BuildRemediationString -Row $row
        $key = "$($row.LastSeenTimestamp)|$remediation"
        if (-not $map.ContainsKey($key)) {
            $map[$key] = [PSCustomObject]@{
                Key = $key
                Date = [string]$row.LastSeenTimestamp
                Remediation = $remediation
                Devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Vulnerabilities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
        }
        [void]$map[$key].Devices.Add([string]$row.DeviceId)
        [void]$map[$key].Vulnerabilities.Add([string]$row.CveId)
    }

    return @($map.Values | ForEach-Object {
        [PSCustomObject]@{
            Key = $_.Key
            Date = $_.Date
            Remediation = $_.Remediation
            Devices = $_.Devices.Count
            Vulnerabilities = $_.Vulnerabilities.Count
            Total = ($_.Devices.Count * $_.Vulnerabilities.Count)
        }
    } | Sort-Object Date, Remediation)
}

function Get-ImpactReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $latestObservedDate = Get-LatestObservedDate -Rows $Rows
    $currentRows = if ([string]::IsNullOrWhiteSpace($latestObservedDate)) { @($Rows) } else { @(Get-OpenRowsAtDate -Rows $Rows -AsOfDate $latestObservedDate) }
    $remediationMap = @{}
    foreach ($row in $currentRows) {
        $remediation = Get-BuildRemediationString -Row $row
        if (-not $remediationMap.ContainsKey($remediation)) {
            $remediationMap[$remediation] = [PSCustomObject]@{
                Name = $remediation
                Devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Vulnerabilities = [System.Collections.Generic.List[object]]::new()
            }
        }
        [void]$remediationMap[$remediation].Devices.Add([string]$row.DeviceId)
        $remediationMap[$remediation].Vulnerabilities.Add($row)
    }

    $top25 = @($remediationMap.Values | ForEach-Object {
        $cves = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($row in $_.Vulnerabilities) { [void]$cves.Add([string]$row.CveId) }
        [PSCustomObject]@{
            Name = $_.Name
            Devices = $_.Devices.Count
            Cves = $cves.Count
            Impact = ($_.Devices.Count * $cves.Count)
            Rows = @($_.Vulnerabilities)
        }
    } | Sort-Object Impact, Name -Descending | Select-Object -First 25)

    $top25KeySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in $top25) {
        foreach ($row in $item.Rows) {
            [void]$top25KeySet.Add((Get-CanonicalRowSignature -Row $row))
        }
    }

    $range = Get-OpenDateRange -Rows $Rows
    $dates = Get-DateSeries -StartDate $range.Start -EndDate $range.End
    $timelineMap = @{}
    foreach ($row in $Rows) {
        $startDate = $row.FirstSeenTimestamp
        $effectiveEndDate = Get-RowEffectiveOpenEndDate -Row $row
        $endDateExclusive = ([datetime]$effectiveEndDate).AddDays(1).ToString('yyyy-MM-dd')
        if ($endDateExclusive -le $startDate) {
            $endDateExclusive = ([datetime]$startDate).AddDays(1).ToString('yyyy-MM-dd')
        }
        $signature = Get-CanonicalRowSignature -Row $row
        $isTop25 = $top25KeySet.Contains($signature)
        if (-not $timelineMap.ContainsKey($startDate)) { $timelineMap[$startDate] = [PSCustomObject]@{ Starts = [System.Collections.Generic.List[object]]::new(); Ends = [System.Collections.Generic.List[object]]::new() } }
        if (-not $timelineMap.ContainsKey($endDateExclusive)) { $timelineMap[$endDateExclusive] = [PSCustomObject]@{ Starts = [System.Collections.Generic.List[object]]::new(); Ends = [System.Collections.Generic.List[object]]::new() } }
        $timelineMap[$startDate].Starts.Add([PSCustomObject]@{ Row = $row; IsTop25 = $isTop25 })
        $timelineMap[$endDateExclusive].Ends.Add([PSCustomObject]@{ Row = $row; IsTop25 = $isTop25 })
    }

    $currentSeverity = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    $projectedSeverity = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    $currentTotal = 0
    $projectedTotal = 0
    $series = [System.Collections.Generic.List[object]]::new()

    foreach ($date in $dates) {
        if ($timelineMap.ContainsKey($date)) {
            foreach ($timelineEvent in $timelineMap[$date].Starts) {
                $currentTotal++
                if ($timelineEvent.Row.VulnerabilitySeverityLevel -and $currentSeverity.ContainsKey($timelineEvent.Row.VulnerabilitySeverityLevel)) { $currentSeverity[$timelineEvent.Row.VulnerabilitySeverityLevel]++ }
                if (-not $timelineEvent.IsTop25) {
                    $projectedTotal++
                    if ($timelineEvent.Row.VulnerabilitySeverityLevel -and $projectedSeverity.ContainsKey($timelineEvent.Row.VulnerabilitySeverityLevel)) { $projectedSeverity[$timelineEvent.Row.VulnerabilitySeverityLevel]++ }
                }
            }
            foreach ($timelineEvent in $timelineMap[$date].Ends) {
                if ($currentTotal -gt 0) { $currentTotal-- }
                if ($timelineEvent.Row.VulnerabilitySeverityLevel -and $currentSeverity.ContainsKey($timelineEvent.Row.VulnerabilitySeverityLevel) -and $currentSeverity[$timelineEvent.Row.VulnerabilitySeverityLevel] -gt 0) { $currentSeverity[$timelineEvent.Row.VulnerabilitySeverityLevel]-- }
                if (-not $timelineEvent.IsTop25) {
                    if ($projectedTotal -gt 0) { $projectedTotal-- }
                    if ($timelineEvent.Row.VulnerabilitySeverityLevel -and $projectedSeverity.ContainsKey($timelineEvent.Row.VulnerabilitySeverityLevel) -and $projectedSeverity[$timelineEvent.Row.VulnerabilitySeverityLevel] -gt 0) { $projectedSeverity[$timelineEvent.Row.VulnerabilitySeverityLevel]-- }
                }
            }
        }

        $series.Add([PSCustomObject]@{
            Date = $date
            CurrentCritical = $currentSeverity.Critical
            CurrentHigh = $currentSeverity.High
            CurrentMedium = $currentSeverity.Medium
            CurrentLow = $currentSeverity.Low
            CurrentTotal = $currentTotal
            ProjectedCritical = $projectedSeverity.Critical
            ProjectedHigh = $projectedSeverity.High
            ProjectedMedium = $projectedSeverity.Medium
            ProjectedLow = $projectedSeverity.Low
            ProjectedTotal = $projectedTotal
        })
    }

    return [PSCustomObject]@{
        Top25 = @($top25 | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Devices = $_.Devices
                Cves = $_.Cves
                Impact = $_.Impact
            }
        })
        Series = $series
    }
}

function Get-DevicesByRemediationReport {
    param([Parameter(Mandatory = $true)]$Rows)

    function Get-SeverityRank {
        param([Parameter(Mandatory = $false)][AllowNull()][string]$Severity)

        switch ($Severity) {
            'Critical' { return 4 }
            'High' { return 3 }
            'Medium' { return 2 }
            'Low' { return 1 }
            default { return 0 }
        }
    }

    $latestObservedDate = Get-LatestObservedDate -Rows $Rows
    $rows = if ([string]::IsNullOrWhiteSpace($latestObservedDate)) { @($Rows) } else { @(Get-OpenRowsAtDate -Rows $Rows -AsOfDate $latestObservedDate) }
    $map = @{}
    foreach ($row in $rows) {
        $remediation = Get-RemediationDescriptor -Row $row
        $key = [string]$remediation.Key
        if (-not $map.ContainsKey($key)) {
            $map[$key] = [PSCustomObject]@{
                Key = $key
                Title = [string]$remediation.Title
                FamilyTitle = [string]$remediation.FamilyTitle
                OSPlatform = [string]$remediation.OSPlatform
                PatchReferences = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Cves = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                CveDetails = @{}
            }
        }
        if ($remediation.PatchReference) {
            [void]$map[$key].PatchReferences.Add([string]$remediation.PatchReference)
        }
        [void]$map[$key].Devices.Add([string]$row.DeviceId)
        [void]$map[$key].Cves.Add([string]$row.CveId)
        $severity = [string]$row.VulnerabilitySeverityLevel
        if (-not $map[$key].CveDetails.ContainsKey($row.CveId)) {
            $map[$key].CveDetails[$row.CveId] = $severity
        }
        elseif ((Get-SeverityRank -Severity $severity) -gt (Get-SeverityRank -Severity ([string]$map[$key].CveDetails[$row.CveId]))) {
            $map[$key].CveDetails[$row.CveId] = $severity
        }
    }

    return @($map.Values | ForEach-Object {
        $sev = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
        foreach ($severity in $_.CveDetails.Values) {
            if ($sev.ContainsKey($severity)) { $sev[$severity]++ }
        }
        [PSCustomObject]@{
            Key = $_.Key
            Title = $_.Title
            FamilyTitle = $_.FamilyTitle
            PatchReference = (Get-RemediationPatchReferenceSummary -Values $_.PatchReferences)
            OSPlatform = $_.OSPlatform
            Devices = $_.Devices.Count
            Cves = $_.Cves.Count
            Critical = $sev.Critical
            High = $sev.High
            Medium = $sev.Medium
            Low = $sev.Low
        }
    } | Sort-Object Key)
}

function Get-RemediationsByDeviceReport {
    param([Parameter(Mandatory = $true)]$Rows)

    $latestObservedDate = Get-LatestObservedDate -Rows $Rows
    $rows = if ([string]::IsNullOrWhiteSpace($latestObservedDate)) { @($Rows) } else { @(Get-OpenRowsAtDate -Rows $Rows -AsOfDate $latestObservedDate) }
    $map = @{}
    foreach ($row in $rows) {
        $deviceId = [string]$row.DeviceId
        if (-not $map.ContainsKey($deviceId)) {
            $map[$deviceId] = [PSCustomObject]@{
                DeviceId = $deviceId
                Cves = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                DeviceCveSeverity = @{}
                Remediations = @{}
            }
        }

        [void]$map[$deviceId].Cves.Add([string]$row.CveId)
        if (-not $map[$deviceId].DeviceCveSeverity.ContainsKey($row.CveId)) {
            $map[$deviceId].DeviceCveSeverity[$row.CveId] = [string]$row.VulnerabilitySeverityLevel
        }

        $remediation = Get-RemediationDescriptor -Row $row
        $remKey = [string]$remediation.Key
        if (-not $map[$deviceId].Remediations.ContainsKey($remKey)) {
            $map[$deviceId].Remediations[$remKey] = [ordered]@{
                Key = $remKey
                Title = [string]$remediation.Title
                FamilyTitle = [string]$remediation.FamilyTitle
                OSPlatform = [string]$remediation.OSPlatform
                PatchReferences = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                CveSeverity = @{}
            }
        }
        if ($remediation.PatchReference) {
            [void]$map[$deviceId].Remediations[$remKey].PatchReferences.Add([string]$remediation.PatchReference)
        }
        if (-not $map[$deviceId].Remediations[$remKey].CveSeverity.ContainsKey($row.CveId)) {
            $map[$deviceId].Remediations[$remKey].CveSeverity[$row.CveId] = [string]$row.VulnerabilitySeverityLevel
        }
    }

    return @($map.Values | ForEach-Object {
        $deviceSev = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
        foreach ($severity in $_.DeviceCveSeverity.Values) {
            if ($deviceSev.ContainsKey($severity)) { $deviceSev[$severity]++ }
        }

        $remediations = @($_.Remediations.GetEnumerator() | ForEach-Object {
            $sev = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
            foreach ($severity in $_.Value.CveSeverity.Values) {
                if ($sev.ContainsKey($severity)) { $sev[$severity]++ }
            }
            [PSCustomObject]@{
                Key = $_.Value.Key
                Title = $_.Value.Title
                FamilyTitle = $_.Value.FamilyTitle
                PatchReference = (Get-RemediationPatchReferenceSummary -Values $_.Value.PatchReferences)
                OSPlatform = $_.Value.OSPlatform
                Cves = $_.Value.CveSeverity.Count
                Critical = $sev.Critical
                High = $sev.High
                Medium = $sev.Medium
                Low = $sev.Low
            }
        } | Sort-Object Key)

        [PSCustomObject]@{
            DeviceId = $_.DeviceId
            RemediationCount = $_.Remediations.Count
            CveCount = $_.Cves.Count
            Critical = $deviceSev.Critical
            High = $deviceSev.High
            Medium = $deviceSev.Medium
            Low = $deviceSev.Low
            Remediations = $remediations
        }
    } | Sort-Object DeviceId)
}

function Get-EnrichmentAudit {
    param(
        [Parameter(Mandatory = $true)]$SourceRows,
        [Parameter(Mandatory = $true)]$DashboardRows
    )

    $sourceMap = @{}
    foreach ($row in $SourceRows) {
        if (-not $sourceMap.ContainsKey($row.CveId)) {
            $sourceMap[$row.CveId] = $row
        }
    }

    $dashboardMap = @{}
    foreach ($row in $DashboardRows) {
        if (-not $dashboardMap.ContainsKey($row.CveId)) {
            $dashboardMap[$row.CveId] = $row
        }
    }

    $cvEs = @($dashboardMap.Keys | Sort-Object)
    $publishedMismatch = 0
    $descriptionMismatch = 0
    $epssMismatch = 0
    $affectedSoftwareMismatch = 0
    $exploitAvailableMismatch = 0
    $nvdLastModifiedMismatch = 0
    $nvdBaseScoreMismatch = 0
    $nvdBaseSeverityMismatch = 0
    $nvdVectorMismatch = 0
    $nvdKevMismatch = 0
    $nvdActionDueMismatch = 0
    $nvdRequiredActionMismatch = 0
    $nvdWeaknessMismatch = 0
    $samples = [System.Collections.Generic.List[object]]::new()

    foreach ($cveId in $cvEs) {
        $source = $sourceMap[$cveId]
        $dash = $dashboardMap[$cveId]
        if ($null -eq $source -or $null -eq $dash) { continue }

        $sourcePublished = [string]$source.PublishedDate
        $dashPublished = [string]$dash.PublishedDate
        $sourceDescription = Get-NormalizedAuditText -Text ([string]$source.VulnerabilityDescription)
        $dashDescription = Get-NormalizedAuditText -Text ([string]$dash.VulnerabilityDescription)
        $sourceEpss = Get-NormalizedAuditDecimalString -Value $source.EpssScore
        $dashEpss = Get-NormalizedAuditDecimalString -Value $dash.EpssScore
        $sourceAffected = @((Get-StringArray $source.AffectedSoftware | Sort-Object -Unique))
        $dashAffected = @((Get-StringArray $dash.AffectedSoftware | Sort-Object -Unique))
        $sourceExploitAvailable = if ($null -eq $source.IsExploitAvailable) { '' } else { [string]([bool]$source.IsExploitAvailable) }
        $dashExploitAvailable = if ($null -eq $dash.IsExploitAvailable) { '' } else { [string]([bool]$dash.IsExploitAvailable) }
        $sourceNvdLastModified = [string](Convert-ToYmdDate -DateValue $source.NvdLastModifiedDate)
        $dashNvdLastModified = [string](Convert-ToYmdDate -DateValue $dash.NvdLastModifiedDate)
        $sourceNvdBaseScore = Get-NormalizedAuditDecimalString -Value $source.NvdBaseScore
        $dashNvdBaseScore = Get-NormalizedAuditDecimalString -Value $dash.NvdBaseScore
        $sourceNvdBaseSeverity = [string]$source.NvdBaseSeverity
        $dashNvdBaseSeverity = [string]$dash.NvdBaseSeverity
        $sourceNvdVector = [string]$source.NvdVector
        $dashNvdVector = [string]$dash.NvdVector
        $sourceNvdKevDate = [string](Convert-ToYmdDate -DateValue $source.NvdKevDate)
        $dashNvdKevDate = [string](Convert-ToYmdDate -DateValue $dash.NvdKevDate)
        $sourceNvdActionDue = [string](Convert-ToYmdDate -DateValue $source.NvdActionDue)
        $dashNvdActionDue = [string](Convert-ToYmdDate -DateValue $dash.NvdActionDue)
        $sourceNvdRequiredAction = Get-NormalizedAuditText -Text ([string]$source.NvdRequiredAction)
        $dashNvdRequiredAction = Get-NormalizedAuditText -Text ([string]$dash.NvdRequiredAction)
        $sourceNvdWeaknesses = @((Get-StringArray $source.NvdWeaknesses | Sort-Object -Unique))
        $dashNvdWeaknesses = @((Get-StringArray $dash.NvdWeaknesses | Sort-Object -Unique))

        $mismatch = $false
        if ($sourcePublished -ne $dashPublished) { $publishedMismatch++; $mismatch = $true }
        if ($sourceDescription -ne $dashDescription) { $descriptionMismatch++; $mismatch = $true }
        if ($sourceEpss -ne $dashEpss) { $epssMismatch++; $mismatch = $true }
        if ((($sourceAffected -join "`n") -ne ($dashAffected -join "`n"))) { $affectedSoftwareMismatch++; $mismatch = $true }
        if ($sourceExploitAvailable -ne $dashExploitAvailable) { $exploitAvailableMismatch++; $mismatch = $true }
        if ($sourceNvdLastModified -ne $dashNvdLastModified) { $nvdLastModifiedMismatch++; $mismatch = $true }
        if ($sourceNvdBaseScore -ne $dashNvdBaseScore) { $nvdBaseScoreMismatch++; $mismatch = $true }
        if ($sourceNvdBaseSeverity -ne $dashNvdBaseSeverity) { $nvdBaseSeverityMismatch++; $mismatch = $true }
        if ($sourceNvdVector -ne $dashNvdVector) { $nvdVectorMismatch++; $mismatch = $true }
        if ($sourceNvdKevDate -ne $dashNvdKevDate) { $nvdKevMismatch++; $mismatch = $true }
        if ($sourceNvdActionDue -ne $dashNvdActionDue) { $nvdActionDueMismatch++; $mismatch = $true }
        if ($sourceNvdRequiredAction -ne $dashNvdRequiredAction) { $nvdRequiredActionMismatch++; $mismatch = $true }
        if ((($sourceNvdWeaknesses -join "`n") -ne ($dashNvdWeaknesses -join "`n"))) { $nvdWeaknessMismatch++; $mismatch = $true }

        if ($mismatch -and $samples.Count -lt 5) {
            $samples.Add([PSCustomObject]@{
                CveId = $cveId
                SourcePublishedDate = $sourcePublished
                DashboardPublishedDate = $dashPublished
                SourceEpss = $sourceEpss
                DashboardEpss = $dashEpss
                SourceExploitAvailable = $sourceExploitAvailable
                DashboardExploitAvailable = $dashExploitAvailable
                SourceNvdBaseScore = $sourceNvdBaseScore
                DashboardNvdBaseScore = $dashNvdBaseScore
                SourceNvdKevDate = $sourceNvdKevDate
                DashboardNvdKevDate = $dashNvdKevDate
                SourceAffectedSoftware = $sourceAffected
                DashboardAffectedSoftware = $dashAffected
                SourceNvdWeaknesses = $sourceNvdWeaknesses
                DashboardNvdWeaknesses = $dashNvdWeaknesses
                DescriptionMatches = ($sourceDescription -eq $dashDescription)
            })
        }
    }

    return [PSCustomObject]@{
        DashboardCveCount = $cvEs.Count
        PublishedDateMismatchCount = $publishedMismatch
        DescriptionMismatchCount = $descriptionMismatch
        EpssMismatchCount = $epssMismatch
        AffectedSoftwareMismatchCount = $affectedSoftwareMismatch
        ExploitAvailableMismatchCount = $exploitAvailableMismatch
        NvdLastModifiedMismatchCount = $nvdLastModifiedMismatch
        NvdBaseScoreMismatchCount = $nvdBaseScoreMismatch
        NvdBaseSeverityMismatchCount = $nvdBaseSeverityMismatch
        NvdVectorMismatchCount = $nvdVectorMismatch
        NvdKevMismatchCount = $nvdKevMismatch
        NvdActionDueMismatchCount = $nvdActionDueMismatch
        NvdRequiredActionMismatchCount = $nvdRequiredActionMismatch
        NvdWeaknessMismatchCount = $nvdWeaknessMismatch
        Samples = $samples
    }
}

function Compare-ReportOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$Actual
    )

    $expectedHash = Get-ObjectSha256 -InputObject $Expected
    $actualHash = Get-ObjectSha256 -InputObject $Actual
    return [PSCustomObject]@{
        Name = $Name
        Match = ($expectedHash -eq $actualHash)
        ExpectedHash = $expectedHash
        ActualHash = $actualHash
        ExpectedCount = if ($Expected -is [System.Collections.ICollection]) { $Expected.Count } else { $null }
        ActualCount = if ($Actual -is [System.Collections.ICollection]) { $Actual.Count } else { $null }
        SampleExpected = if ($Expected -is [System.Collections.ICollection]) { $Expected | Select-Object -First 3 } else { $Expected }
        SampleActual = if ($Actual -is [System.Collections.ICollection]) { $Actual | Select-Object -First 3 } else { $Actual }
    }
}

function Compare-BaselineAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $CurrentAudit,

        [Parameter(Mandatory = $true)]
        [string]$BaselinePath
    )

    if (-not (Test-Path -Path $BaselinePath -PathType Leaf)) {
        throw "Baseline audit '$BaselinePath' does not exist."
    }

    $baseline = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json -Depth 100
    $mismatches = [System.Collections.Generic.List[object]]::new()

    if ($baseline.Dashboard.RowCount -ne $CurrentAudit.Dashboard.RowCount) {
        $mismatches.Add([PSCustomObject]@{
            Name = 'Dashboard.RowCount'
            Baseline = $baseline.Dashboard.RowCount
            Current = $CurrentAudit.Dashboard.RowCount
        })
    }

    $baselineReports = @{}
    foreach ($report in @($baseline.ReportComparisons)) {
        $baselineReports[[string]$report.Name] = $report
    }

    foreach ($report in @($CurrentAudit.ReportComparisons)) {
        $name = [string]$report.Name
        if (-not $baselineReports.ContainsKey($name)) {
            $mismatches.Add([PSCustomObject]@{
                Name = $name
                Baseline = 'missing'
                Current = [string]$report.ActualHash
            })
            continue
        }

        $baselineReport = $baselineReports[$name]
        if ([string]$baselineReport.ActualHash -ne [string]$report.ActualHash) {
            $mismatches.Add([PSCustomObject]@{
                Name = $name
                Baseline = [string]$baselineReport.ActualHash
                Current = [string]$report.ActualHash
            })
        }
    }

    return [PSCustomObject]@{
        Enabled = $true
        BaselineAuditPath = $BaselinePath
        Match = ($mismatches.Count -eq 0)
        MismatchCount = $mismatches.Count
        Mismatches = @($mismatches)
    }
}

function Compare-BaselineDashboardCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $CurrentDashboardRows,

        [Parameter(Mandatory = $true)]
        [string]$BaselineHtmlPath
    )

    if (-not (Test-Path -Path $BaselineHtmlPath -PathType Leaf)) {
        throw "Baseline dashboard '$BaselineHtmlPath' does not exist."
    }

    $baselinePayload = Read-DashboardPayload -Path $BaselineHtmlPath
    $baselineRows = Read-DashboardRow -Payload $baselinePayload
    $comparison = Compare-RowSet -ExpectedRows $baselineRows -ActualRows $CurrentDashboardRows

    return [PSCustomObject]@{
        Enabled = $true
        RemovalDate = $Script:LegacyVulnMigrationRemovalDate
        BaselineHtmlPath = $BaselineHtmlPath
        ContainsAllBaselineRows = ($comparison.MissingCount -eq 0)
        ExactMatch = $comparison.Match
        BaselineRowCount = $baselineRows.Count
        CurrentRowCount = $CurrentDashboardRows.Count
        MissingCount = $comparison.MissingCount
        MissingSamples = @($comparison.MissingSamples)
        AdditionalCurrentRowCount = $comparison.ExtraCount
        AdditionalCurrentRowSamples = @($comparison.ExtraSamples)
    }
}

function Resolve-BaselineDashboardHtmlPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$RequestedPath
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        return $RequestedPath
    }

    return $null
}

function Get-DuplicateIdentityAudit {
    param([Parameter(Mandatory = $true)]$SourceRows)

    $byId = @{}
    foreach ($row in $SourceRows) {
        $id = [string]$row.SourceId
        if (-not $byId.ContainsKey($id)) {
            $byId[$id] = [System.Collections.Generic.List[object]]::new()
        }
        $byId[$id].Add($row)
    }

    $duplicateIds = @($byId.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 })
    $overlapCount = 0
    $sampleOverlap = $null

    foreach ($entry in $duplicateIds) {
        $items = @($entry.Value | Sort-Object FirstSeenTimestamp, LastSeenTimestamp)
        $hasOverlap = $false
        for ($i = 0; $i -lt $items.Count -and -not $hasOverlap; $i++) {
            for ($j = $i + 1; $j -lt $items.Count; $j++) {
                $aStart = [datetime]$items[$i].FirstSeenTimestamp
                $aEnd = [datetime]$items[$i].LastSeenTimestamp
                $bStart = [datetime]$items[$j].FirstSeenTimestamp
                $bEnd = [datetime]$items[$j].LastSeenTimestamp
                if ($aStart -le $bEnd -and $bStart -le $aEnd) {
                    $hasOverlap = $true
                    $overlapCount++
                    if (-not $sampleOverlap) {
                        $sampleOverlap = [PSCustomObject]@{
                            SourceId = $entry.Key
                            Occurrences = $items.Count
                            Rows = $items | Select-Object -First 5 SourceFile, DeviceId, CveId, SoftwareVendor, SoftwareName, SoftwareVersion, FirstSeenTimestamp, LastSeenTimestamp
                        }
                    }
                    break
                }
            }
        }
    }

    $latestDate = @($SourceRows | ForEach-Object LastSeenTimestamp | Sort-Object)[-1]
    $activeRowsOnLatest = @($SourceRows | Where-Object { $_.FirstSeenTimestamp -le $latestDate -and $_.LastSeenTimestamp -ge $latestDate })
    $activeIdsOnLatest = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $activeRowsOnLatest) {
        [void]$activeIdsOnLatest.Add([string]$row.SourceId)
    }

    return [PSCustomObject]@{
        TotalRows = $SourceRows.Count
        UniqueSourceIds = $byId.Count
        DuplicateSourceIdCount = $duplicateIds.Count
        DuplicateRowExcess = ($SourceRows.Count - $byId.Count)
        OverlappingDuplicateSourceIdCount = $overlapCount
        LatestObservedLastSeen = $latestDate
        ActiveRowsOnLatestObservedDate = $activeRowsOnLatest.Count
        ActiveUniqueSourceIdsOnLatestObservedDate = $activeIdsOnLatest.Count
        PotentialLatestDateInflation = ($activeRowsOnLatest.Count - $activeIdsOnLatest.Count)
        SampleOverlap = $sampleOverlap
    }
}

function Get-OpenStateAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Rows)

    $latestObservedDate = Get-LatestObservedDate -Rows $Rows
    $currentRows = if ([string]::IsNullOrWhiteSpace($latestObservedDate)) { @() } else { @(Get-OpenRowsAtDate -Rows $Rows -AsOfDate $latestObservedDate) }
    $currentDevices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $currentCves = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $currentRows) {
        [void]$currentDevices.Add([string]$row.DeviceId)
        [void]$currentCves.Add([string]$row.CveId)
    }

    $provenPatchedRows = @($Rows | Where-Object { Test-RowHasPatchedEvidence -Row $_ })
    $assumedOpenRows = @($Rows | Where-Object { -not (Test-RowHasPatchedEvidence -Row $_) })
    $inactiveSuppressedRows = if ([string]::IsNullOrWhiteSpace($latestObservedDate)) {
        @()
    }
    else {
        @($assumedOpenRows | Where-Object { (Get-RowEffectiveOpenEndDate -Row $_) -lt $latestObservedDate })
    }

    return [PSCustomObject]@{
        LatestObservedDate = $latestObservedDate
        InactivityWindowDays = 30
        CurrentOpenRowCount = @($currentRows).Count
        CurrentOpenDeviceCount = $currentDevices.Count
        CurrentOpenCveCount = $currentCves.Count
        ProvenPatchedRowCount = @($provenPatchedRows).Count
        AssumedOpenRowCount = @($assumedOpenRows).Count
        InactiveSuppressedRowCount = @($inactiveSuppressedRows).Count
    }
}

function Get-LegacyMigrationRegressionAudit {
    [CmdletBinding()]
    param()

    return [PSCustomObject]@{
        Enabled = $false
        Removed = $true
        RemovalDate = $Script:LegacyVulnMigrationRemovalDate
        Reason = 'Legacy snapshot normalization fallback has been removed. Validate canonical/current-store exports instead.'
    }
}

function New-DashboardAuditPhaseTimings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only creates an in-memory phase timing record for audit output.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper returns a structured collection of phase timing values by design.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Values = @{}
    )

    $phaseTimings = [ordered]@{
        MachineLoadElapsedSeconds = $null
        AdvancedHuntingLoadElapsedSeconds = $null
        SourceMaterializationElapsedSeconds = $null
        PayloadLoadElapsedSeconds = $null
        VendorIndexElapsedSeconds = $null
        SourceSignatureElapsedSeconds = $null
        PayloadSignatureElapsedSeconds = $null
        RowComparisonElapsedSeconds = $null
        EnrichmentAuditElapsedSeconds = $null
        ReportComparisonsElapsedSeconds = $null
        DuplicateIdentityElapsedSeconds = $null
        OpenStateElapsedSeconds = $null
        ComparisonElapsedSeconds = $null
        BaselineAuditElapsedSeconds = $null
        BaselineCoverageElapsedSeconds = $null
        LegacyFixtureRegressionElapsedSeconds = $null
        TotalElapsedSeconds = $null
    }

    foreach ($key in $Values.Keys) {
        if ($phaseTimings.Contains($key)) {
            $phaseTimings[$key] = $Values[$key]
        }
    }

    return [PSCustomObject]$phaseTimings
}

function Write-DashboardAuditPhaseTimingSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PhaseTimings
    )

    $phaseLabels = [ordered]@{
        MachineLoadElapsedSeconds = 'machine load'
        AdvancedHuntingLoadElapsedSeconds = 'Advanced Hunting load'
        SourceMaterializationElapsedSeconds = 'source materialization'
        PayloadLoadElapsedSeconds = 'payload load'
        VendorIndexElapsedSeconds = 'vendor index'
        SourceSignatureElapsedSeconds = 'source signatures'
        PayloadSignatureElapsedSeconds = 'payload signatures'
        RowComparisonElapsedSeconds = 'row comparison'
        EnrichmentAuditElapsedSeconds = 'enrichment audit'
        ReportComparisonsElapsedSeconds = 'report comparisons'
        DuplicateIdentityElapsedSeconds = 'duplicate identity audit'
        OpenStateElapsedSeconds = 'open-state audit'
        ComparisonElapsedSeconds = 'comparison'
        BaselineAuditElapsedSeconds = 'baseline audit'
        BaselineCoverageElapsedSeconds = 'baseline coverage'
        LegacyFixtureRegressionElapsedSeconds = 'legacy fixture regression'
        TotalElapsedSeconds = 'total'
    }

    $segments = [System.Collections.Generic.List[string]]::new()
    foreach ($propertyName in $phaseLabels.Keys) {
        $property = $PhaseTimings.PSObject.Properties[$propertyName]
        if ($null -eq $property -or $null -eq $property.Value) {
            continue
        }

        $segments.Add(("{0} {1:N2}s" -f $phaseLabels[$propertyName], [double]$property.Value)) | Out-Null
    }

    if ($segments.Count -gt 0) {
        Write-Information ("  Audit phase timing summary: {0}" -f ($segments -join '; ')) -InformationAction Continue
    }
}

function Get-DashboardAuditResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResolvedHtmlPath,

        [Parameter(Mandatory = $true)]
        [string]$ResolvedExportsPath,

        [Parameter(Mandatory = $false)]
        [string]$ResolvedBaselineAuditPath,

        [Parameter(Mandatory = $false)]
        [string]$ResolvedBaselineDashboardHtmlPath,

        [Parameter(Mandatory = $false)]
        [switch]$RunLegacyFixtureRegression,

        [Parameter(Mandatory = $false)]
        [string]$ResolvedLegacyFixturePath
    )

    $skipObservedWindowMerge = (Test-IsSyntheticDataset -BasePath $ResolvedExportsPath)
    $payloadCacheEntry = Get-NormalizedPayloadCacheEntry -BasePath $ResolvedExportsPath -SkipObservedWindowMerge:$skipObservedWindowMerge
    $largeAuditThreshold = 100000
    if (
        -not $payloadCacheEntry -and
        [string]::IsNullOrWhiteSpace($ResolvedBaselineAuditPath) -and
        [string]::IsNullOrWhiteSpace($ResolvedBaselineDashboardHtmlPath) -and
        -not $RunLegacyFixtureRegression
    ) {
        try {
            $manifestPath = Join-Path $ResolvedExportsPath 'synthetic-manifest.json'
            $manifest = if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
                Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
            }
            else {
                $null
            }

            $estimatedLargeRowCount = 0
            if ($null -ne $manifest -and $manifest.PSObject.Properties['actualCurrentRows'] -and $manifest.PSObject.Properties['actualHistoryRows']) {
                $estimatedLargeRowCount = [int]$manifest.actualCurrentRows + [int]$manifest.actualHistoryRows
            }

            if ($estimatedLargeRowCount -ge $largeAuditThreshold) {
                Write-Information '  Building local normalized payload cache for large-dataset validation...' -InformationAction Continue
                $machines = Read-NormalizationMachineLookup -Path $ResolvedExportsPath
                $advancedHunting = Read-AdvancedHuntingData -Path $ResolvedExportsPath
                $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $ResolvedExportsPath
                $sourceMetadata = Get-DashboardSourceSummary `
                    -BasePath $ResolvedExportsPath `
                    -MachineCount $machines.Count `
                    -AdvancedHuntingCveCount $advancedHunting.Count `
                    -AdvancedHuntingDeviceUserCount $advancedHuntingDeviceUsers.Count `
                    -AdvancedHuntingInventoryTupleCount 0 `
                    -NvdCveCount 0 `
                    -NormalizationMode 'validation-cache-bootstrap' `
                    -SkipObservedWindowMerge:$skipObservedWindowMerge
                $tempPayloadPath = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-validation-payload-' + [System.Guid]::NewGuid().ToString('N') + '.json.gz')
                $tempVulnsPath = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-validation-vulns-' + [System.Guid]::NewGuid().ToString('N') + '.json')
                try {
                    $normalizedResult = ConvertTo-NormalizedData -DataPath $ResolvedExportsPath -VulnOutputPath $tempVulnsPath -PayloadOutputPath $tempPayloadPath -Machines $machines -AdvancedHuntingData $advancedHunting -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers -SkipObservedWindowMerge:$skipObservedWindowMerge -ConsumeLookupsOnPayloadClose
                    $payloadCacheEntry = Publish-NormalizedPayloadCache -BasePath $ResolvedExportsPath -PayloadPath $normalizedResult.PayloadPath -VulnCount $normalizedResult.VulnCount -DeviceCount ([int]$normalizedResult.DeviceCount) -CveCount ([int]$normalizedResult.CveCount) -Quality $normalizedResult.Quality -SourceMetadata $sourceMetadata -SkipObservedWindowMerge:$skipObservedWindowMerge
                }
                finally {
                    if (Test-Path -LiteralPath $tempPayloadPath -PathType Leaf) {
                        Remove-Item -LiteralPath $tempPayloadPath -Force -ErrorAction SilentlyContinue
                    }
                    if (Test-Path -LiteralPath $tempVulnsPath -PathType Leaf) {
                        Remove-Item -LiteralPath $tempVulnsPath -Force -ErrorAction SilentlyContinue
                    }
                    $machines = $null
                    $advancedHunting = $null
                    $advancedHuntingDeviceUsers = $null
                    Invoke-FullGarbageCollection
                }
            }
        }
        catch {
            Write-Warning "  Large-dataset validation cache build failed; falling back to full validation path. $_"
        }
    }

    if (
        $payloadCacheEntry -and
        ([int]$payloadCacheEntry.Manifest.VulnCount -ge $largeAuditThreshold) -and
        [string]::IsNullOrWhiteSpace($ResolvedBaselineAuditPath) -and
        [string]::IsNullOrWhiteSpace($ResolvedBaselineDashboardHtmlPath) -and
        -not $RunLegacyFixtureRegression
    ) {
        return (Get-StreamingDashboardAuditResult -ResolvedHtmlPath $ResolvedHtmlPath -ResolvedExportsPath $ResolvedExportsPath -PayloadCacheEntry $payloadCacheEntry)
    }

    $auditStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $machineLoadStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $machines = Read-NormalizationMachineLookup -Path $ResolvedExportsPath
    $machineLoadStopwatch.Stop()
    $machineLoadElapsedSeconds = [math]::Round($machineLoadStopwatch.Elapsed.TotalSeconds, 2)

    $advancedHuntingLoadStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $advancedHunting = Read-AdvancedHuntingData -Path $ResolvedExportsPath
    $advancedHuntingInventory = Read-AdvancedHuntingInventoryData -Path $ResolvedExportsPath
    $nvdCveData = Read-NvdCveData -Path $ResolvedExportsPath
    $advancedHuntingLoadStopwatch.Stop()
    $advancedHuntingLoadElapsedSeconds = [math]::Round($advancedHuntingLoadStopwatch.Elapsed.TotalSeconds, 2)

    $sourceMaterializationStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $sourceResult = Read-SourceRow -ExportsPath $ResolvedExportsPath -Machines $machines -AdvancedHunting $advancedHunting -SkipObservedWindowMerge:$skipObservedWindowMerge -AdvancedHuntingInventory $advancedHuntingInventory -NvdCveData $nvdCveData
    $sourceMaterializationStopwatch.Stop()
    $sourceMaterializationElapsedSeconds = [math]::Round($sourceMaterializationStopwatch.Elapsed.TotalSeconds, 2)

    $payloadLoadStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $payload = Read-DashboardPayload -Path $ResolvedHtmlPath
    $dashboardRows = Read-DashboardRow -Payload $payload
    $payloadLoadStopwatch.Stop()
    $payloadLoadElapsedSeconds = [math]::Round($payloadLoadStopwatch.Elapsed.TotalSeconds, 2)
    $baselineDashboardHtmlPath = Resolve-BaselineDashboardHtmlPath -RequestedPath $ResolvedBaselineDashboardHtmlPath

    $rowComparisonStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $rowComparison = Compare-RowSet -ExpectedRows $sourceResult.Rows -ActualRows $dashboardRows
    $rowComparisonStopwatch.Stop()
    $rowComparisonElapsedSeconds = [math]::Round($rowComparisonStopwatch.Elapsed.TotalSeconds, 2)

    $enrichmentAuditStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $enrichmentAudit = Get-EnrichmentAudit -SourceRows $sourceResult.Rows -DashboardRows $dashboardRows
    $enrichmentAuditStopwatch.Stop()
    $enrichmentAuditElapsedSeconds = [math]::Round($enrichmentAuditStopwatch.Elapsed.TotalSeconds, 2)

    $reportComparisonsStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $reportComparisons = @(
        Compare-ReportOutput -Name 'Stats' -Expected (Get-StatsReport -Rows $sourceResult.Rows) -Actual (Get-StatsReport -Rows $dashboardRows)
        Compare-ReportOutput -Name 'ActiveChart' -Expected @(Get-ActiveChartReport -Rows $sourceResult.Rows) -Actual @(Get-ActiveChartReport -Rows $dashboardRows)
        Compare-ReportOutput -Name 'RemediationTable' -Expected @(Get-RemediationTableReport -Rows $sourceResult.Rows) -Actual @(Get-RemediationTableReport -Rows $dashboardRows)
        Compare-ReportOutput -Name 'RemediationChart' -Expected @(Get-RemediationChartReport -Rows $sourceResult.Rows) -Actual @(Get-RemediationChartReport -Rows $dashboardRows)
        Compare-ReportOutput -Name 'RemediationDetails' -Expected @(Get-RemediationDetailsReport -Rows $sourceResult.Rows) -Actual @(Get-RemediationDetailsReport -Rows $dashboardRows)
        Compare-ReportOutput -Name 'Impact' -Expected (Get-ImpactReport -Rows $sourceResult.Rows) -Actual (Get-ImpactReport -Rows $dashboardRows)
        Compare-ReportOutput -Name 'DevicesByRemediation' -Expected @(Get-DevicesByRemediationReport -Rows $sourceResult.Rows) -Actual @(Get-DevicesByRemediationReport -Rows $dashboardRows)
        Compare-ReportOutput -Name 'RemediationsByDevice' -Expected @(Get-RemediationsByDeviceReport -Rows $sourceResult.Rows) -Actual @(Get-RemediationsByDeviceReport -Rows $dashboardRows)
    )
    $reportComparisonsStopwatch.Stop()
    $reportComparisonsElapsedSeconds = [math]::Round($reportComparisonsStopwatch.Elapsed.TotalSeconds, 2)

    $duplicateAuditStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $duplicateAudit = Get-DuplicateIdentityAudit -SourceRows $sourceResult.Rows
    $duplicateAuditStopwatch.Stop()
    $duplicateIdentityElapsedSeconds = [math]::Round($duplicateAuditStopwatch.Elapsed.TotalSeconds, 2)

    $openStateAuditStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $openStateAudit = Get-OpenStateAudit -Rows $sourceResult.Rows
    $openStateAuditStopwatch.Stop()
    $openStateElapsedSeconds = [math]::Round($openStateAuditStopwatch.Elapsed.TotalSeconds, 2)

    $legacyMigrationAudit = Get-LegacyMigrationRegressionAudit
    $qualityMeta = if ($payload.PSObject.Properties['quality'] -and $payload.quality) { $payload.quality } else { $null }

    $baselineAuditElapsedSeconds = $null
    $baselineCoverageElapsedSeconds = $null
    $legacyFixtureRegressionElapsedSeconds = $null
    $auditSourceMetadata = Get-DashboardSourceSummary `
        -BasePath $ResolvedExportsPath `
        -MachineCount $machines.Count `
        -AdvancedHuntingCveCount $advancedHunting.Count `
        -AdvancedHuntingDeviceUserCount 0 `
        -AdvancedHuntingInventoryTupleCount $advancedHuntingInventory.Count `
        -NvdCveCount $nvdCveData.Count `
        -NormalizationMode 'full-dashboard-audit' `
        -SkipObservedWindowMerge:$skipObservedWindowMerge

    $result = [PSCustomObject]@{
        GeneratedOn = (Get-Date).ToString('o')
        HtmlPath = $ResolvedHtmlPath
        ExportsPath = $ResolvedExportsPath
        AuditMode = 'full-dashboard-audit'
        Source = [PSCustomObject]@{
            RowCount = $sourceResult.Rows.Count
            MissingMachineCount = $sourceResult.MissingMachineCount
            FirstLastSwappedCount = $sourceResult.FirstLastSwappedCount
            UniqueVendors = @($sourceResult.VendorSet | Sort-Object)
            InputMode = [string]$sourceResult.InputMode
        }
        SourceMetadata = $auditSourceMetadata
        Dashboard = [PSCustomObject]@{
            RowCount = $dashboardRows.Count
            Quality = $qualityMeta
        }
        RowComparison = $rowComparison
        EnrichmentAudit = $enrichmentAudit
        ReportComparisons = $reportComparisons
        DuplicateIdentityAudit = $duplicateAudit
        OpenStateAudit = $openStateAudit
        LegacyMigrationAudit = $legacyMigrationAudit
    }

    if (-not [string]::IsNullOrWhiteSpace($ResolvedBaselineAuditPath)) {
        $baselineAuditStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $result | Add-Member -NotePropertyName RegressionComparison -NotePropertyValue (Compare-BaselineAudit -CurrentAudit $result -BaselinePath $ResolvedBaselineAuditPath)
        $baselineAuditStopwatch.Stop()
        $baselineAuditElapsedSeconds = [math]::Round($baselineAuditStopwatch.Elapsed.TotalSeconds, 2)
    }

    if (-not [string]::IsNullOrWhiteSpace($baselineDashboardHtmlPath)) {
        $baselineCoverageStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $result | Add-Member -NotePropertyName BaselineDashboardCoverage -NotePropertyValue (Compare-BaselineDashboardCoverage -CurrentDashboardRows $dashboardRows -BaselineHtmlPath $baselineDashboardHtmlPath)
        $baselineCoverageStopwatch.Stop()
        $baselineCoverageElapsedSeconds = [math]::Round($baselineCoverageStopwatch.Elapsed.TotalSeconds, 2)
    }

    if ($RunLegacyFixtureRegression) {
        $legacyFixtureRegressionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $result | Add-Member -NotePropertyName LegacyFixtureRegression -NotePropertyValue (Get-LegacyFixtureRegressionAudit -FixturePath $ResolvedLegacyFixturePath)
        $legacyFixtureRegressionStopwatch.Stop()
        $legacyFixtureRegressionElapsedSeconds = [math]::Round($legacyFixtureRegressionStopwatch.Elapsed.TotalSeconds, 2)
    }

    $auditStopwatch.Stop()
    $phaseTimings = New-DashboardAuditPhaseTimings -Values @{
        MachineLoadElapsedSeconds = $machineLoadElapsedSeconds
        AdvancedHuntingLoadElapsedSeconds = $advancedHuntingLoadElapsedSeconds
        SourceMaterializationElapsedSeconds = $sourceMaterializationElapsedSeconds
        PayloadLoadElapsedSeconds = $payloadLoadElapsedSeconds
        RowComparisonElapsedSeconds = $rowComparisonElapsedSeconds
        EnrichmentAuditElapsedSeconds = $enrichmentAuditElapsedSeconds
        ReportComparisonsElapsedSeconds = $reportComparisonsElapsedSeconds
        DuplicateIdentityElapsedSeconds = $duplicateIdentityElapsedSeconds
        OpenStateElapsedSeconds = $openStateElapsedSeconds
        BaselineAuditElapsedSeconds = $baselineAuditElapsedSeconds
        BaselineCoverageElapsedSeconds = $baselineCoverageElapsedSeconds
        LegacyFixtureRegressionElapsedSeconds = $legacyFixtureRegressionElapsedSeconds
        TotalElapsedSeconds = [math]::Round($auditStopwatch.Elapsed.TotalSeconds, 2)
    }
    $result | Add-Member -NotePropertyName PhaseTimings -NotePropertyValue $phaseTimings
    Write-DashboardAuditPhaseTimingSummary -PhaseTimings $phaseTimings

    return $result
}

function Get-LegacyFixtureRegressionAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FixturePath
    )

    if (-not (Test-Path -Path $FixturePath -PathType Container)) {
        return [PSCustomObject]@{
            Enabled = $false
            Removed = $true
            Skipped = $true
            RemovalDate = $Script:LegacyVulnMigrationRemovalDate
            FixturePath = $FixturePath
            Match = $true
            Warning = "Legacy fixture regression is no longer applicable: $FixturePath"
        }
    }

    return [PSCustomObject]@{
        Enabled = $false
        Removed = $true
        Skipped = $true
        RemovalDate = $Script:LegacyVulnMigrationRemovalDate
        FixturePath = $FixturePath
        Match = $true
        Warning = 'Legacy fixture regression has been removed.'
    }
}
