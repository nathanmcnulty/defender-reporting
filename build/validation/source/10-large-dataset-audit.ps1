function Convert-ToCanonicalValidationListString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    $items = @(Get-StringArray -Value $Value)
    if ($items.Count -eq 0) {
        return ''
    }

    if ($items.Count -eq 1) {
        return [string]$items[0]
    }

    $sorted = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($item in $items) {
        if ([string]::IsNullOrWhiteSpace([string]$item)) {
            continue
        }

        [void]$sorted.Add([string]$item)
    }

    if ($sorted.Count -eq 0) {
        return ''
    }

    return [string]::Join([string][char]0x001e, @($sorted))
}

function Read-PayloadLookupsFromJsonReader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader
    )

    if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartObject) {
        throw "Expected lookups object while reading payload, found '$($Reader.TokenType)'."
    }

    $lookupsToken = [Newtonsoft.Json.Linq.JObject]::Load($Reader)
    return ($lookupsToken.ToString([Newtonsoft.Json.Formatting]::None) | ConvertFrom-Json -Depth 50)
}

function Read-PayloadIntArrayFromJsonReader {
    [CmdletBinding()]
    [OutputType([int[]])]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader,

        [Parameter(Mandatory = $false)]
        [int]$NullValue = -1
    )

    if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray) {
        throw "Expected array while reading payload, found '$($Reader.TokenType)'."
    }

    $values = [System.Collections.Generic.List[int]]::new()
    while ($Reader.Read()) {
        switch ($Reader.TokenType) {
            ([Newtonsoft.Json.JsonToken]::Integer) {
                $values.Add([int]$Reader.Value)
                continue
            }
            ([Newtonsoft.Json.JsonToken]::Null) {
                $values.Add($NullValue)
                continue
            }
            ([Newtonsoft.Json.JsonToken]::EndArray) {
                break
            }
            ([Newtonsoft.Json.JsonToken]::Comment) {
                continue
            }
            default {
                throw "Expected numeric array value while reading payload, found '$($Reader.TokenType)'."
            }
        }
    }

    return $values.ToArray()
}

function Get-PayloadLookupText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $LookupValues,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Index
    )

    if ($null -eq $Index) {
        return $null
    }

    try {
        $resolvedIndex = [int]$Index
    }
    catch {
        return $null
    }

    if ($resolvedIndex -lt 0) {
        return $null
    }

    if ($resolvedIndex -ge $LookupValues.Count) {
        return $null
    }

    $value = $LookupValues[$resolvedIndex]
    if ($null -eq $value) {
        return $null
    }

    return [string]$value
}

function Read-PayloadCanonicalStringArrayFromJsonReader {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader,

        [Parameter(Mandatory = $true)]
        $LookupValues
    )

    if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray) {
        throw "Expected nested array while reading payload, found '$($Reader.TokenType)'."
    }

    $values = [System.Collections.Generic.List[string]]::new()
    while ($Reader.Read()) {
        switch ($Reader.TokenType) {
            ([Newtonsoft.Json.JsonToken]::StartArray) {
                $resolvedValues = [System.Collections.Generic.List[string]]::new()
                while ($Reader.Read()) {
                    switch ($Reader.TokenType) {
                        ([Newtonsoft.Json.JsonToken]::Integer) {
                            $resolvedText = Get-PayloadLookupText -LookupValues $LookupValues -Index $Reader.Value
                            if ($null -ne $resolvedText) {
                                $resolvedValues.Add($resolvedText)
                            }
                            continue
                        }
                        ([Newtonsoft.Json.JsonToken]::Null) {
                            continue
                        }
                        ([Newtonsoft.Json.JsonToken]::EndArray) {
                            break
                        }
                        ([Newtonsoft.Json.JsonToken]::Comment) {
                            continue
                        }
                        default {
                            throw "Expected numeric nested array value while reading payload, found '$($Reader.TokenType)'."
                        }
                    }
                }

                $values.Add((Convert-ToCanonicalValidationListString -Value $resolvedValues))
                continue
            }
            ([Newtonsoft.Json.JsonToken]::Integer) {
                $resolvedText = Get-PayloadLookupText -LookupValues $LookupValues -Index $Reader.Value
                if ($null -eq $resolvedText) {
                    $values.Add('')
                }
                else {
                    $values.Add($resolvedText)
                }
                continue
            }
            ([Newtonsoft.Json.JsonToken]::Null) {
                $values.Add('')
                continue
            }
            ([Newtonsoft.Json.JsonToken]::EndArray) {
                break
            }
            ([Newtonsoft.Json.JsonToken]::Comment) {
                continue
            }
            default {
                throw "Expected nested array value while reading payload, found '$($Reader.TokenType)'."
            }
        }
    }

    return $values.ToArray()
}

function Read-PayloadVulnColumnsFromJsonReader {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader,

        [Parameter(Mandatory = $true)]
        $Lookups
    )

    if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartObject) {
        throw "Expected vuln columns object while reading payload, found '$($Reader.TokenType)'."
    }

    $columns = [ordered]@{
        d = $null
        c = $null
        s = $null
        v = $null
        f = $null
        l = $null
        ua = $null
        u = $null
        dp = $null
        rp = $null
    }

    while ($Reader.Read()) {
        if ($Reader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndObject) {
            break
        }

        if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::PropertyName) {
            continue
        }

        $propertyName = [string]$Reader.Value
        if (-not $Reader.Read()) {
            throw "Unexpected end of payload while reading column '$propertyName'."
        }

        switch ($propertyName) {
            'd' { $columns.d = Read-PayloadIntArrayFromJsonReader -Reader $Reader }
            'c' { $columns.c = Read-PayloadIntArrayFromJsonReader -Reader $Reader }
            's' { $columns.s = Read-PayloadIntArrayFromJsonReader -Reader $Reader }
            'v' { $columns.v = Read-PayloadIntArrayFromJsonReader -Reader $Reader }
            'f' { $columns.f = Read-PayloadIntArrayFromJsonReader -Reader $Reader }
            'l' { $columns.l = Read-PayloadIntArrayFromJsonReader -Reader $Reader }
            'ua' { $columns.ua = Read-PayloadIntArrayFromJsonReader -Reader $Reader -NullValue 0 }
            'u' { $columns.u = Read-PayloadIntArrayFromJsonReader -Reader $Reader }
            'dp' { $columns.dp = Read-PayloadCanonicalStringArrayFromJsonReader -Reader $Reader -LookupValues $Lookups.diskPaths }
            'rp' { $columns.rp = Read-PayloadCanonicalStringArrayFromJsonReader -Reader $Reader -LookupValues $Lookups.regPaths }
            default { $Reader.Skip() }
        }
    }

    return [PSCustomObject]$columns
}

function Get-PayloadCanonicalValidationRowSignature {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Device,

        [Parameter(Mandatory = $true)]
        $Cve,

        [Parameter(Mandatory = $true)]
        $Software,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$GroupName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$PlatformName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$SeverityName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$ExploitabilityName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$BatchTitle,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$SoftwareVendor,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$SoftwareVersion,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$FirstSeenDate,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$LastSeenDate,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $UpdateObject,

        [Parameter(Mandatory = $true)]
        [string]$MachineTagsCanonical,

        [Parameter(Mandatory = $true)]
        [string]$AffectedSoftwareCanonical,

        [Parameter(Mandatory = $true)]
        [string]$DiskPathsCanonical,

        [Parameter(Mandatory = $true)]
        [string]$RegistryPathsCanonical,

        [Parameter(Mandatory = $true)]
        [bool]$SecurityUpdateAvailable
    )

    $machineInfo = if ($Device.m) { $Device.m } else { $null }
    $valueDelimiter = [string][char]0x001f

    return @(
        [string]$Device.id
        [string]$Device.n
        if ($GroupName -and -not [string]::IsNullOrWhiteSpace([string]$GroupName)) { [string]$GroupName } else { '(none)' }
        if ($null -ne $PlatformName) { [string]$PlatformName } else { $null }
        [string]$Device.ov
        $MachineTagsCanonical
        [string]$(if ($machineInfo) { $machineInfo.ip } else { $null })
        [string]$(if ($machineInfo) { $machineInfo.eip } else { $null })
        [string]$(if ($machineInfo) { $machineInfo.hs } else { $null })
        [string]$(if ($machineInfo) { $machineInfo.rs } else { $null })
        [string]$(if ($machineInfo) { $machineInfo.el } else { $null })
        [string]$(if ($machineInfo) { $machineInfo.dv } else { $null })
        [string]$(if ($machineInfo) { $machineInfo.mb } else { $null })
        [string]([bool]$(if ($machineInfo) { $machineInfo.aad -eq $true } else { $false }))
        [string](Convert-ToYmdDate -DateValue $(if ($machineInfo) { $machineInfo.ls } else { $null }))
        [string](Convert-ToYmdDate -DateValue $(if ($machineInfo) { $machineInfo.fs } else { $null }))
        [string]$Cve.id
        (Get-NormalizedAuditDecimalString -Value $Cve.sc)
        if ($null -ne $SeverityName) { [string]$SeverityName } else { $null }
        if ($null -ne $ExploitabilityName) { [string]$ExploitabilityName } else { $null }
        [string]$Cve.u
        if ($null -ne $BatchTitle) { [string]$BatchTitle } else { $null }
        [string](Convert-ToYmdDate -DateValue $Cve.pd)
        (Get-NormalizedAuditText -Text ([string]$Cve.desc))
        (Get-NormalizedAuditDecimalString -Value $Cve.ep)
        $AffectedSoftwareCanonical
        if ($null -ne $SoftwareVendor) { [string]$SoftwareVendor } else { $null }
        [string]$Software.n
        if ($null -ne $SoftwareVersion) { [string]$SoftwareVersion } else { $null }
        [string]$Software.r
        [string](Convert-ToYmdDate -DateValue $FirstSeenDate)
        [string](Convert-ToYmdDate -DateValue $LastSeenDate)
        [string]([bool]$SecurityUpdateAvailable)
        if ($UpdateObject) { [string]($UpdateObject.n ?? $UpdateObject) } else { $null }
        if ($UpdateObject -and $UpdateObject.id) { [string]$UpdateObject.id } else { $null }
        if ($UpdateObject -and $UpdateObject.url) { [string]$UpdateObject.url } else { $null }
        $DiskPathsCanonical
        $RegistryPathsCanonical
    ) -join $valueDelimiter
}

function Read-PayloadCanonicalSignatureStream {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PayloadPath
    )

    $fileStream = $null
    $gzipStream = $null
    $streamReader = $null
    $jsonReader = $null
    $lookups = $null
    $columns = $null
    $vulnsFormat = $null

    try {
        $fileStream = [System.IO.File]::OpenRead($PayloadPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        $streamReader = [System.IO.StreamReader]::new($gzipStream, [System.Text.Encoding]::UTF8)
        $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($streamReader)
        $jsonReader.DateParseHandling = [Newtonsoft.Json.DateParseHandling]::None

        while ($jsonReader.Read()) {
            if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::PropertyName) {
                continue
            }

            $propertyName = [string]$jsonReader.Value
            if (-not $jsonReader.Read()) {
                throw "Unexpected end of payload while reading property '$propertyName'."
            }

            switch ($propertyName) {
                'lookups' {
                    $lookups = Read-PayloadLookupsFromJsonReader -Reader $jsonReader
                }
                'vulnsFormat' {
                    $vulnsFormat = [string]$jsonReader.Value
                }
                'vulns' {
                    if ($null -eq $lookups) {
                        throw "Payload '$PayloadPath' does not define lookups before vulns."
                    }

                    $columns = Read-PayloadVulnColumnsFromJsonReader -Reader $jsonReader -Lookups $lookups
                }
                default {
                    $jsonReader.Skip()
                }
            }
        }
    }
    finally {
        if ($jsonReader) { $jsonReader.Close() }
        elseif ($streamReader) { $streamReader.Dispose() }
        elseif ($gzipStream) { $gzipStream.Dispose() }
        elseif ($fileStream) { $fileStream.Dispose() }
    }

    if ($vulnsFormat -ne 'columns-v1') {
        throw "Streaming payload audit requires columns-v1 payload format. Found '$vulnsFormat' in '$PayloadPath'."
    }

    if (
        $null -eq $columns -or
        $null -eq $columns.d -or
        $null -eq $columns.c -or
        $null -eq $columns.s -or
        $null -eq $columns.v -or
        $null -eq $columns.f -or
        $null -eq $columns.l -or
        $null -eq $columns.ua -or
        $null -eq $columns.u -or
        $null -eq $columns.dp -or
        $null -eq $columns.rp
    ) {
        throw "Streaming payload audit could not read the required vuln columns from '$PayloadPath'."
    }

    Invoke-FullGarbageCollection

    $deviceTagCanonicalCache = [string[]]::new($lookups.devices.Count)
    $deviceTagCanonicalCacheInitialized = [bool[]]::new($lookups.devices.Count)
    $affectedSoftwareCanonicalCache = [string[]]::new($lookups.cves.Count)
    $affectedSoftwareCanonicalCacheInitialized = [bool[]]::new($lookups.cves.Count)

    function Get-DeviceTagCanonicalString {
        param([Parameter(Mandatory = $true)][int]$Index)

        if (-not $deviceTagCanonicalCacheInitialized[$Index]) {
            $device = $lookups.devices[$Index]
            $resolved = [System.Collections.Generic.List[string]]::new()
            foreach ($tagIndex in @($device.t)) {
                if ($null -eq $tagIndex) { continue }
                $tagText = Get-PayloadLookupText -LookupValues $lookups.tags -Index $tagIndex
                if ($null -ne $tagText) {
                    $resolved.Add($tagText)
                }
            }

            $deviceTagCanonicalCache[$Index] = Convert-ToCanonicalValidationListString -Value $resolved
            $deviceTagCanonicalCacheInitialized[$Index] = $true
        }

        return $deviceTagCanonicalCache[$Index]
    }

    function Get-AffectedSoftwareCanonicalString {
        param([Parameter(Mandatory = $true)][int]$Index)

        if (-not $affectedSoftwareCanonicalCacheInitialized[$Index]) {
            $cve = $lookups.cves[$Index]
            $resolved = [System.Collections.Generic.List[string]]::new()
            foreach ($softwareIndex in @($cve.as)) {
                if ($null -eq $softwareIndex) { continue }
                $softwareText = Get-PayloadLookupText -LookupValues $lookups.affSoftware -Index $softwareIndex
                if ($null -ne $softwareText) {
                    $resolved.Add($softwareText)
                }
            }

            $affectedSoftwareCanonicalCache[$Index] = Convert-ToCanonicalValidationListString -Value $resolved
            $affectedSoftwareCanonicalCacheInitialized[$Index] = $true
        }

        return $affectedSoftwareCanonicalCache[$Index]
    }

    $vulnCount = $columns.d.Length
    for ($i = 0; $i -lt $vulnCount; $i++) {
        $device = $lookups.devices[$columns.d[$i]]
        $cve = $lookups.cves[$columns.c[$i]]
        $software = $lookups.software[$columns.s[$i]]

        $groupName = Get-PayloadLookupText -LookupValues $lookups.groups -Index $device.g
        $platformName = Get-PayloadLookupText -LookupValues $lookups.platforms -Index $device.o
        $severityName = Get-PayloadLookupText -LookupValues $lookups.severities -Index $cve.sv
        $exploitabilityName = Get-PayloadLookupText -LookupValues $lookups.exploitLevels -Index $cve.ex
        $batchTitle = Get-PayloadLookupText -LookupValues $lookups.batchTitles -Index $cve.bt
        $softwareVendor = Get-PayloadLookupText -LookupValues $lookups.vendors -Index $software.v
        $softwareVersion = Get-PayloadLookupText -LookupValues $lookups.versions -Index $columns.v[$i]
        $firstSeenDate = Get-PayloadLookupText -LookupValues $lookups.dates -Index $columns.f[$i]
        $lastSeenDate = Get-PayloadLookupText -LookupValues $lookups.dates -Index $columns.l[$i]
        $updateObject = if ($columns.u[$i] -ge 0) { $lookups.updates[$columns.u[$i]] } else { $null }

        if ((($i + 1) % 250000) -eq 0) {
            Write-Information ("  Canonicalized {0} payload row(s)..." -f ($i + 1)) -InformationAction Continue
        }

        Get-PayloadCanonicalValidationRowSignature `
            -Device $device `
            -Cve $cve `
            -Software $software `
            -GroupName $groupName `
            -PlatformName $platformName `
            -SeverityName $severityName `
            -ExploitabilityName $exploitabilityName `
            -BatchTitle $batchTitle `
            -SoftwareVendor $softwareVendor `
            -SoftwareVersion $softwareVersion `
            -FirstSeenDate $firstSeenDate `
            -LastSeenDate $lastSeenDate `
            -UpdateObject $updateObject `
            -MachineTagsCanonical (Get-DeviceTagCanonicalString -Index $columns.d[$i]) `
            -AffectedSoftwareCanonical (Get-AffectedSoftwareCanonicalString -Index $columns.c[$i]) `
            -DiskPathsCanonical ([string]$columns.dp[$i]) `
            -RegistryPathsCanonical ([string]$columns.rp[$i]) `
            -SecurityUpdateAvailable ($columns.ua[$i] -eq 1)
    }
}

function Get-StreamingDashboardAuditResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResolvedHtmlPath,

        [Parameter(Mandatory = $true)]
        [string]$ResolvedExportsPath,

        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry
    )

    $skipObservedWindowMerge = (Test-IsSyntheticDataset -BasePath $ResolvedExportsPath)
    $dashboardPayloadSha256 = Get-DashboardPayloadGzipSha256 -Path $ResolvedHtmlPath
    $dashboardPayloadRowCount = Get-EmbeddedDashboardPayloadVulnCount -Path $ResolvedHtmlPath
    $cachedPayloadSha256 = Get-FileSha256Hex -Path $PayloadCacheEntry.PayloadPath
    $cachedPayloadRowCount = [int]$PayloadCacheEntry.Manifest.VulnCount

    $machines = Read-MachineData -Path $ResolvedExportsPath
    $advancedHunting = Read-AdvancedHuntingData -Path $ResolvedExportsPath
    $vendorSet = Get-SourceVendorSetForAudit -ExportsPath $ResolvedExportsPath -SkipObservedWindowMerge:$skipObservedWindowMerge

    $sourceFirstLastSwappedCount = 0
    $sourceMissingMachineCount = 0
    $sourceSignatureSet = $null
    $payloadSignatureSet = $null
    $sourceElapsedSeconds = 0
    $payloadElapsedSeconds = 0

    try {
        Write-Information '  Streaming semantic parity audit for large dataset...' -InformationAction Continue

        $sourceStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $sourceSignatureSet = Write-PartitionedSignatureSet -Label 'source' -SignatureSource {
            Read-SourceCanonicalSignatureStream `
                -ExportsPath $ResolvedExportsPath `
                -Machines $machines `
                -AdvancedHunting $advancedHunting `
                -VendorSet $vendorSet `
                -SkipObservedWindowMerge:$skipObservedWindowMerge `
                -FirstLastSwappedCount ([ref]$sourceFirstLastSwappedCount) `
                -MissingMachineCount ([ref]$sourceMissingMachineCount)
        }
        $sourceStopwatch.Stop()
        $sourceElapsedSeconds = [math]::Round($sourceStopwatch.Elapsed.TotalSeconds, 2)
        Write-Information ("  Source signature pass completed in {0:N2}s" -f $sourceElapsedSeconds) -InformationAction Continue

        $machines = $null
        $advancedHunting = $null
        Invoke-FullGarbageCollection

        $payloadStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $payloadSignatureSet = Write-PartitionedSignatureSet -Label 'payload' -SignatureSource {
            Read-PayloadCanonicalSignatureStream -PayloadPath $PayloadCacheEntry.PayloadPath
        }
        $payloadStopwatch.Stop()
        $payloadElapsedSeconds = [math]::Round($payloadStopwatch.Elapsed.TotalSeconds, 2)
        Write-Information ("  Payload signature pass completed in {0:N2}s" -f $payloadElapsedSeconds) -InformationAction Continue

        $rowComparison = Compare-PartitionedSignatureSet -Expected $sourceSignatureSet -Actual $payloadSignatureSet
    }
    finally {
        Remove-PartitionedSignatureSet -SignatureSet $sourceSignatureSet
        Remove-PartitionedSignatureSet -SignatureSet $payloadSignatureSet
        if ($null -ne $machines) { $machines = $null }
        if ($null -ne $advancedHunting) { $advancedHunting = $null }
        Invoke-FullGarbageCollection
    }

    return [PSCustomObject]@{
        GeneratedOn = (Get-Date).ToString('o')
        HtmlPath = $ResolvedHtmlPath
        ExportsPath = $ResolvedExportsPath
        AuditMode = 'streaming-large-dataset'
        Source = [PSCustomObject]@{
            RowCount = [int]$sourceSignatureSet.Count
            MissingMachineCount = $sourceMissingMachineCount
            FirstLastSwappedCount = $sourceFirstLastSwappedCount
            UniqueVendors = @($vendorSet | Sort-Object)
        }
        Dashboard = [PSCustomObject]@{
            RowCount = $dashboardPayloadRowCount
            Quality = $PayloadCacheEntry.Manifest.Quality
        }
        RowComparison = $rowComparison
        EnrichmentAudit = [PSCustomObject]@{
            DashboardCveCount = [int]$PayloadCacheEntry.Manifest.CveCount
            PublishedDateMismatchCount = 0
            DescriptionMismatchCount = 0
            EpssMismatchCount = 0
            AffectedSoftwareMismatchCount = 0
            Samples = @()
            Mode = 'Included in canonical streaming row signature'
        }
        ReportComparisons = @()
        DuplicateIdentityAudit = [PSCustomObject]@{
            Skipped = $true
            Reason = 'Streaming large-dataset audit mode'
        }
        OpenStateAudit = [PSCustomObject]@{
            Skipped = $true
            Reason = 'Streaming large-dataset audit mode'
        }
        LegacyMigrationAudit = [PSCustomObject]@{
            Enabled = $false
            Removed = $true
            RemovalDate = $Script:LegacyVulnMigrationRemovalDate
            Reason = 'Legacy snapshot normalization fallback has been removed.'
            Skipped = $true
        }
        PayloadParity = [PSCustomObject]@{
            Match = (($dashboardPayloadSha256 -eq $cachedPayloadSha256) -and ($dashboardPayloadRowCount -eq $cachedPayloadRowCount))
            DashboardPayloadSha256 = $dashboardPayloadSha256
            CachedPayloadSha256 = $cachedPayloadSha256
            DashboardRowCount = $dashboardPayloadRowCount
            CachedPayloadRowCount = $cachedPayloadRowCount
            CachedPayloadPath = $PayloadCacheEntry.PayloadPath
        }
        SemanticParity = [PSCustomObject]@{
            Match = $rowComparison.Match
            Mode = 'canonical-row-signature-stream'
            IncludesEnrichment = $true
            IncludesMachineInfo = $true
            PartitionCount = [int]$sourceSignatureSet.PartitionCount
            SourceSignatureElapsedSeconds = $sourceElapsedSeconds
            PayloadSignatureElapsedSeconds = $payloadElapsedSeconds
        }
    }
}