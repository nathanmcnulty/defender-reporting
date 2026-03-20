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

    $stream = [System.IO.File]::OpenRead($FilePath)
    try {
        $buffer = New-Object byte[] 12288
        $carry = New-Object byte[] 2
        $carryCount = 0

        while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $totalCount = $carryCount + $bytesRead
            $workBuffer = New-Object byte[] $totalCount

            if ($carryCount -gt 0) {
                [System.Array]::Copy($carry, 0, $workBuffer, 0, $carryCount)
            }
            [System.Array]::Copy($buffer, 0, $workBuffer, $carryCount, $bytesRead)

            $encodableCount = $totalCount - ($totalCount % 3)
            if ($encodableCount -gt 0) {
                $Writer.Write([System.Convert]::ToBase64String($workBuffer, 0, $encodableCount))
            }

            $carryCount = $totalCount - $encodableCount
            if ($carryCount -gt 0) {
                [System.Array]::Copy($workBuffer, $encodableCount, $carry, 0, $carryCount)
            }
        }

        if ($carryCount -gt 0) {
            $Writer.Write([System.Convert]::ToBase64String($carry, 0, $carryCount))
        }
    }
    finally {
        $stream.Dispose()
    }
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

        $writer.Write('{"lookups":{')
        $lookupPropertyNames = @(
            'vendors',
            'severities',
            'exploitLevels',
            'groups',
            'platforms',
            'tags',
            'updates',
            'versions',
            'dates',
            'diskPaths',
            'regPaths',
            'affSoftware',
            'batchTitles',
            'devices',
            'software',
            'cves',
            'noTagsIdx'
        )
        $isFirstLookupProperty = $true
        foreach ($lookupPropertyName in $lookupPropertyNames) {
            if (-not $isFirstLookupProperty) {
                $writer.Write(',')
            }

            $writer.Write(($lookupPropertyName | ConvertTo-Json -Compress))
            $writer.Write(':')
            $lookupValue = $Lookups.PSObject.Properties[$lookupPropertyName].Value
            $writer.Write(($lookupValue | ConvertTo-Json -Depth 10 -Compress))
            $isFirstLookupProperty = $false
        }
        $writer.Write('}')

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

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'machines' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'machines'

        Write-Information "Reading machine data from $Path..." -InformationAction Continue
        $machines = @{}

        $currentPath = Get-MachineCurrentPath -BasePath $Path
        $legacyCurrentPath = Get-LegacyCanonicalPath -Path $currentPath
        $currentReadPath = if (Test-Path -Path $currentPath) { $currentPath } elseif (Test-Path -Path $legacyCurrentPath) { $legacyCurrentPath } else { $null }
        $historySourcePaths = @(Get-MachineHistorySourcePaths -BasePath $Path)

        if ($null -ne $currentReadPath) {
            Write-Information "  Using $(Split-Path -Leaf $currentReadPath)" -InformationAction Continue
            foreach ($record in Read-MachineRecordsFromFile -Path $currentReadPath) {
                if ($record.id) {
                    if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                        $machines.Remove($record.id)
                        continue
                    }
                    $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
                }
            }
        }
        elseif ($historySourcePaths.Count -gt 0) {
            Write-Information "  Reconstructing current state from $($historySourcePaths.Count) machine history source file(s)" -InformationAction Continue
            foreach ($sourcePath in $historySourcePaths) {
                foreach ($record in Read-MachineRecordsFromFile -Path $sourcePath) {
                    if ($record.id) {
                        if ($record.PSObject.Properties['removed']?.Value -eq $true) {
                            $machines.Remove($record.id)
                            continue
                        }
                        $machines[$record.id] = ConvertTo-CompactMachineRecord -Machine $record
                    }
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
}

function Read-AdvancedHuntingData {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return Invoke-WithStoreLock -BasePath $Path -StoreName 'advancedhunting' -ScriptBlock {
        Restore-StoreTransaction -BasePath $Path -StoreName 'advancedhunting'

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

function Get-CaseSensitiveIndexMap {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[string, int]])]
    param()

    return [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
}

function Get-NormalizationContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    return [PSCustomObject]@{
        Lookups = @{
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
        Indexes = @{
            vendors = Get-CaseSensitiveIndexMap
            exploitLevels = Get-CaseSensitiveIndexMap
            groups = Get-CaseSensitiveIndexMap
            platforms = Get-CaseSensitiveIndexMap
            tags = Get-CaseSensitiveIndexMap
            updates = Get-CaseSensitiveIndexMap
            devices = Get-CaseSensitiveIndexMap
            software = Get-CaseSensitiveIndexMap
            cves = Get-CaseSensitiveIndexMap
            versions = Get-CaseSensitiveIndexMap
            dates = Get-CaseSensitiveIndexMap
            diskPaths = Get-CaseSensitiveIndexMap
            regPaths = Get-CaseSensitiveIndexMap
            affSoftware = Get-CaseSensitiveIndexMap
            batchTitles = Get-CaseSensitiveIndexMap
        }
        DateValueCache = @{}
    }
}

function Get-NormalizationCachedYmdDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Context,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DateValue
    )

    if ($null -eq $DateValue) {
        return $null
    }

    $cacheKey = $DateValue.ToString()
    if ($Context.DateValueCache.ContainsKey($cacheKey)) {
        return $Context.DateValueCache[$cacheKey]
    }

    $normalized = Convert-ToYmdDate -DateValue $DateValue
    $Context.DateValueCache[$cacheKey] = $normalized
    return $normalized
}

function Get-NormalizationSourceRows {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DataPath
    )

    if (Test-VulnStoreExistence -BasePath $DataPath) {
        Write-Information '  Found vulnerability current/history store to normalize...' -InformationAction Continue
        foreach ($record in Read-VulnStoreRow -BasePath $DataPath) {
            if ($null -ne $record) {
                Write-Output $record
            }
        }
        return
    }

    $legacyFiles = @(Get-VulnLegacySnapshotFile -BasePath $DataPath)
    if ($legacyFiles.Count -eq 0) { throw "No VulnExport snapshot files found in '$DataPath'." }

    $legacyStore = Convert-LegacyVulnSnapshotsToStore -BasePath $DataPath
    Write-Information "  Found $($legacyFiles.Count) legacy export file(s); canonicalizing in memory for normalization..." -InformationAction Continue

    foreach ($record in @($legacyStore.CurrentRecords)) {
        if ($null -ne $record) {
            Write-Output $record
        }
    }

    foreach ($historyDocument in @($legacyStore.HistoryDocuments)) {
        foreach ($snapshot in @($historyDocument.snapshots)) {
            foreach ($entry in @($snapshot.closed)) {
                $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                if ($null -ne $row) {
                    Write-Output $row
                }
            }
        }
    }
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
    Write-Information ("  Normalization inputs: {0} machine(s), {1} Advanced Hunting CVE(s)" -f $Machines.Count, $AdvancedHuntingData.Count) -InformationAction Continue
    $context = Get-NormalizationContext
    $lookups = $context.Lookups
    $vendorIndex = $context.Indexes.vendors
    $exploitIndex = $context.Indexes.exploitLevels
    $groupIndex = $context.Indexes.groups
    $platformIndex = $context.Indexes.platforms
    $tagIndex = $context.Indexes.tags
    $updateIndex = $context.Indexes.updates
    $deviceIndex = $context.Indexes.devices
    $softwareIndex = $context.Indexes.software
    $cveIndex = $context.Indexes.cves
    $versionIndex = $context.Indexes.versions
    $dateIndex = $context.Indexes.dates
    $diskPathIndex = $context.Indexes.diskPaths
    $regPathIndex = $context.Indexes.regPaths
    $affSoftwareIndex = $context.Indexes.affSoftware
    $batchTitleIndex = $context.Indexes.batchTitles

    $firstLastSwappedCount = 0
    $processedCount = 0
    $hasNoTags = $false
    $vulnWriter = $null
    $isFirstVuln = $true

    try {
        $vulnWriter = [System.IO.StreamWriter]::new($VulnOutputPath, $false, [System.Text.UTF8Encoding]::new($false))
        $vulnWriter.Write('[')

        foreach ($v in Get-NormalizationSourceRows -DataPath $DataPath) {
            if ($v.PSObject.Properties['IsOnboarded']?.Value -ne $true) { continue }
            $processedCount++

            $deviceId = [string]$v.DeviceId
            $machine = $Machines[$deviceId]
            $fallbackDeviceName = $v.PSObject.Properties['DeviceName']?.Value
            $fallbackGroupName = $v.PSObject.Properties['RbacGroupName']?.Value
            $fallbackPlatform = $v.PSObject.Properties['OSPlatform']?.Value
            $fallbackOsVersion = $v.PSObject.Properties['OSVersion']?.Value
            $deviceKey = if ($machine) {
                $deviceId
            }
            else {
                @(
                    $deviceId
                    [string]$fallbackDeviceName
                    [string]$fallbackGroupName
                    [string]$fallbackPlatform
                    [string]$fallbackOsVersion
                ) -join '|'
            }

            if (-not $deviceIndex.ContainsKey($deviceKey)) {
                    # When machine enrichment is missing, vulnerability exports can still carry
                    # row-specific device metadata. Keep distinct fallback variants instead of
                    # collapsing everything to the first row seen for a DeviceId.
                    $groupName = if ($machine) { $machine.PSObject.Properties['rbacGroupName']?.Value } else { $fallbackGroupName }
                    if ([string]::IsNullOrWhiteSpace([string]$groupName)) {
                        $groupName = if ([string]::IsNullOrWhiteSpace([string]$fallbackGroupName)) { '(none)' } else { $fallbackGroupName }
                    }
                    $groupIdx = Get-OrCreateIndex -value $groupName -list $lookups.groups -indexMap $groupIndex

                    $osPlat = if ($machine) { $machine.PSObject.Properties['osPlatform']?.Value } else { $fallbackPlatform }
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

                    $deviceIndex[$deviceKey] = $lookups.devices.Count

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
                            ls = Get-NormalizationCachedYmdDate -Context $context -DateValue $machineLastSeen
                            fs = Get-NormalizationCachedYmdDate -Context $context -DateValue $machineFirstSeen
                        }
                    }

                    $lookups.devices.Add([PSCustomObject]@{
                        id = $deviceId
                        n = if ($machine) { $machine.PSObject.Properties['computerDnsName']?.Value } elseif ($fallbackDeviceName) { $fallbackDeviceName } else { '(no machine data)' }
                        g = $groupIdx
                        o = $platIdx
                        ov = if ($machine) { $machine.PSObject.Properties['osVersion']?.Value } else { $fallbackOsVersion }
                        t = $tagIndices
                        m = $machineInfo
                    })
            }
            $devIdx = $deviceIndex[$deviceKey]

            $vendorIdx = Get-OrCreateIndex -value $v.PSObject.Properties['SoftwareVendor']?.Value -list $lookups.vendors -indexMap $vendorIndex

            $softwareVendor = $v.PSObject.Properties['SoftwareVendor']?.Value ?? ''
            $softwareName = $v.PSObject.Properties['SoftwareName']?.Value ?? ''
            $recommendationReference = $v.PSObject.Properties['RecommendationReference']?.Value ?? ''
            $softwareKey = "$softwareVendor|$softwareName|$recommendationReference"
            if (-not $softwareIndex.ContainsKey($softwareKey)) {
                $softwareIndex[$softwareKey] = $lookups.software.Count
                $lookups.software.Add([PSCustomObject]@{
                    v = $vendorIdx
                    n = $softwareName
                    r = $recommendationReference
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

            $seenWindow = Get-NormalizedVulnSeenWindow `
                -FirstSeenValue $v.PSObject.Properties['FirstSeenTimestamp']?.Value `
                -LastSeenValue $v.PSObject.Properties['LastSeenTimestamp']?.Value
            $firstSeen = if ($seenWindow.FirstSeenTimestamp) { Get-NormalizationCachedYmdDate -Context $context -DateValue $seenWindow.FirstSeenTimestamp } else { $null }
            $lastSeen = if ($seenWindow.LastSeenTimestamp) { Get-NormalizationCachedYmdDate -Context $context -DateValue $seenWindow.LastSeenTimestamp } else { $null }
            if ($seenWindow.WasReordered) {
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

        $vulnWriter.Write(']')
    }
    finally {
        if ($vulnWriter) {
            $vulnWriter.Dispose()
        }
    }

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
        [void]$datasetVendors.Add((Get-VendorMatchKey -Vendor $vendor))
    }

    foreach ($cve in $lookups.cves) {
        if ($null -ne $cve.as -and $cve.as.Count -gt 0) {
            $filteredIndices = [System.Collections.Generic.List[int]]::new()
            foreach ($asIdx in $cve.as) {
                $swStr = $lookups.affSoftware[$asIdx]
                $separatorIndex = $swStr.IndexOf(':')
                $swVendor = if ($separatorIndex -ge 0) { $swStr.Substring(0, $separatorIndex) } else { $swStr }
                if ($datasetVendors.Contains((Get-VendorMatchKey -Vendor $swVendor))) {
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
