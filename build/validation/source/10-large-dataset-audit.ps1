function Convert-ToCanonicalValidationListString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    $items = @()
    if ($null -ne $Value) {
        if ($Value -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($Value)) {
                $items = @([string]$Value)
            }
        }
        elseif ($Value -is [System.Collections.IEnumerable]) {
            $items = @($Value | ForEach-Object {
                if ($null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_)) {
                    [string]$_
                }
            })
        }
        else {
            $items = @([string]$Value)
        }
    }
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

function Get-NormalizedAuditText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return ([regex]::Replace($Text, '\s+', ' ')).Trim()
}

function Get-NormalizedAuditDecimalString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return ''
    }

    $raw = [string]$Value
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return ''
    }

    [decimal]$decimalValue = 0
    if ([decimal]::TryParse($raw, [ref]$decimalValue)) {
        return $decimalValue.ToString('0.#####', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    return $raw.Trim()
}

function Get-CanonicalValidationRowSignature {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $machineInfo = $Row.MachineInfo
    $valueDelimiter = [string][char]0x001f

    return @(
        [string]$Row.DeviceId
        [string]$Row.DeviceName
        [string]$Row.RbacGroupName
        [string]$Row.OSPlatform
        [string]$Row.OSVersion
        (Convert-ToCanonicalValidationListString -Value $Row.MachineTags)
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
        [string]$Row.CveId
        (Get-NormalizedAuditDecimalString -Value $Row.CvssScore)
        [string]$Row.VulnerabilitySeverityLevel
        [string]$Row.ExploitabilityLevel
        [string]$Row.CveBatchUrl
        [string]$Row.CveBatchTitle
        [string](Convert-ToYmdDate -DateValue $Row.PublishedDate)
        (Get-NormalizedAuditText -Text ([string]$Row.VulnerabilityDescription))
        (Get-NormalizedAuditDecimalString -Value $Row.EpssScore)
        (Convert-ToCanonicalValidationListString -Value $Row.AffectedSoftware)
        [string]$Row.SoftwareVendor
        [string]$Row.SoftwareName
        [string]$Row.SoftwareVersion
        [string]$Row.RecommendationReference
        [string](Convert-ToYmdDate -DateValue $Row.FirstSeenTimestamp)
        [string](Convert-ToYmdDate -DateValue $Row.LastSeenTimestamp)
        [string]([bool]$Row.SecurityUpdateAvailable)
        [string]$Row.RecommendedSecurityUpdate
        [string]$Row.RecommendedSecurityUpdateId
        [string]$Row.RecommendedSecurityUpdateUrl
        (Convert-ToCanonicalValidationListString -Value $Row.DiskPaths)
        (Convert-ToCanonicalValidationListString -Value $Row.RegistryPaths)
    ) -join $valueDelimiter
}

function Get-StringSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
}

function Get-PartitionedSignatureFilePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath,

        [Parameter(Mandatory = $true)]
        [int]$Index
    )

    return (Join-Path $DirectoryPath ("p{0:D3}.txt" -f $Index))
}

function Remove-PartitionedSignatureSet {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $SignatureSet
    )

    if ($null -eq $SignatureSet) {
        return
    }

    $directoryPath = [string]$SignatureSet.DirectoryPath
    if (-not [string]::IsNullOrWhiteSpace($directoryPath) -and (Test-Path -LiteralPath $directoryPath -PathType Container)) {
        Remove-Item -LiteralPath $directoryPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Write-PartitionedSignatureSet {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$SignatureSource,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $false)]
        [ValidateRange(4, 512)]
        [int]$PartitionCount = 128,

        [Parameter(Mandatory = $false)]
        [ValidateRange(10000, 1000000)]
        [int]$ProgressInterval = 250000
    )

    $directoryPath = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-audit-signatures-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $directoryPath -ItemType Directory -Force)

    $writers = [System.IO.StreamWriter[]]::new($PartitionCount)
    $count = 0
    try {
        & $SignatureSource | ForEach-Object {
            $resolvedSignature = [string]$_
            if (-not [string]::IsNullOrWhiteSpace($resolvedSignature)) {
                $signatureHash = Get-StringSha256Hex -Text $resolvedSignature
                $bucketSeed = [uint32]::Parse($signatureHash.Substring(0, 8), [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture)
                $bucket = [int]($bucketSeed % [uint32]$PartitionCount)

                if ($null -eq $writers[$bucket]) {
                    $partitionPath = Get-PartitionedSignatureFilePath -DirectoryPath $directoryPath -Index $bucket
                    $writers[$bucket] = [System.IO.StreamWriter]::new([System.IO.File]::Create($partitionPath), [System.Text.UTF8Encoding]::new($false))
                }

                $writers[$bucket].WriteLine($signatureHash)
                $count++

                if (($count % $ProgressInterval) -eq 0) {
                    Write-Information ("  Partitioned {0} {1} row signature(s)..." -f $count, $Label) -InformationAction Continue
                }
            }
        }
    }
    finally {
        foreach ($writer in $writers) {
            if ($null -ne $writer) {
                $writer.Dispose()
            }
        }
    }

    return [PSCustomObject]@{
        DirectoryPath = $directoryPath
        Count = $count
        PartitionCount = $PartitionCount
    }
}

function Compare-PartitionedSignatureSet {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Expected,

        [Parameter(Mandatory = $true)]
        $Actual
    )

    $partitionCount = [math]::Max([int]$Expected.PartitionCount, [int]$Actual.PartitionCount)
    $missingCount = 0
    $extraCount = 0
    $missingSamples = [System.Collections.Generic.List[string]]::new()
    $extraSamples = [System.Collections.Generic.List[string]]::new()

    for ($index = 0; $index -lt $partitionCount; $index++) {
        $expectedPath = Get-PartitionedSignatureFilePath -DirectoryPath $Expected.DirectoryPath -Index $index
        $actualPath = Get-PartitionedSignatureFilePath -DirectoryPath $Actual.DirectoryPath -Index $index
        $expectedMap = @{}
        $actualMap = @{}

        if (Test-Path -LiteralPath $expectedPath -PathType Leaf) {
            foreach ($line in [System.IO.File]::ReadLines($expectedPath, [System.Text.UTF8Encoding]::new($false))) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $expectedMap[$line] = 1 + ($expectedMap[$line] ?? 0)
            }
        }

        if (Test-Path -LiteralPath $actualPath -PathType Leaf) {
            foreach ($line in [System.IO.File]::ReadLines($actualPath, [System.Text.UTF8Encoding]::new($false))) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $actualMap[$line] = 1 + ($actualMap[$line] ?? 0)
            }
        }

        foreach ($key in $expectedMap.Keys) {
            $actualCountForKey = $actualMap[$key] ?? 0
            if ($actualCountForKey -lt $expectedMap[$key]) {
                $missingCount += ($expectedMap[$key] - $actualCountForKey)
                if ($missingSamples.Count -lt 5) {
                    $missingSamples.Add($key)
                }
            }
        }

        foreach ($key in $actualMap.Keys) {
            $expectedCountForKey = $expectedMap[$key] ?? 0
            if ($expectedCountForKey -lt $actualMap[$key]) {
                $extraCount += ($actualMap[$key] - $expectedCountForKey)
                if ($extraSamples.Count -lt 5) {
                    $extraSamples.Add($key)
                }
            }
        }
    }

    return [PSCustomObject]@{
        Match = ($missingCount -eq 0 -and $extraCount -eq 0)
        ExpectedRows = [int]$Expected.Count
        ActualRows = [int]$Actual.Count
        MissingCount = $missingCount
        ExtraCount = $extraCount
        MissingSamples = @($missingSamples)
        ExtraSamples = @($extraSamples)
    }
}

function Compare-CanonicalSignatureSourceMultiset {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ExpectedSignatureSource,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ActualSignatureSource,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedLabel = 'expected',

        [Parameter(Mandatory = $false)]
        [string]$ActualLabel = 'actual',

        [Parameter(Mandatory = $false)]
        [ValidateRange(10000, 1000000)]
        [int]$ProgressInterval = 250000
    )

    $expectedMap = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    $expectedCount = 0
    & $ExpectedSignatureSource | ForEach-Object {
        $resolvedSignature = [string]$_
        if ([string]::IsNullOrWhiteSpace($resolvedSignature)) {
            return
        }

        $signatureHash = Get-StringSha256Hex -Text $resolvedSignature
        $existingCount = 0
        if ($expectedMap.TryGetValue($signatureHash, [ref]$existingCount)) {
            $expectedMap[$signatureHash] = $existingCount + 1
        }
        else {
            $expectedMap[$signatureHash] = 1
        }

        $expectedCount++
        if (($expectedCount % $ProgressInterval) -eq 0) {
            Write-Information ("  Indexed {0} {1} row signature(s)..." -f $expectedCount, $ExpectedLabel) -InformationAction Continue
        }
    }

    $extraCount = 0
    $actualCount = 0
    $extraSamples = [System.Collections.Generic.List[string]]::new()
    & $ActualSignatureSource | ForEach-Object {
        $resolvedSignature = [string]$_
        if ([string]::IsNullOrWhiteSpace($resolvedSignature)) {
            return
        }

        $signatureHash = Get-StringSha256Hex -Text $resolvedSignature
        $existingCount = 0
        if ($expectedMap.TryGetValue($signatureHash, [ref]$existingCount) -and $existingCount -gt 0) {
            if ($existingCount -eq 1) {
                [void]$expectedMap.Remove($signatureHash)
            }
            else {
                $expectedMap[$signatureHash] = $existingCount - 1
            }
        }
        else {
            $extraCount++
            if ($extraSamples.Count -lt 5) {
                $extraSamples.Add($signatureHash)
            }
        }

        $actualCount++
        if (($actualCount % $ProgressInterval) -eq 0) {
            Write-Information ("  Compared {0} {1} row signature(s)..." -f $actualCount, $ActualLabel) -InformationAction Continue
        }
    }

    $missingCount = 0
    $missingSamples = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $expectedMap.GetEnumerator()) {
        $missingCount += $entry.Value
        if ($missingSamples.Count -lt 5) {
            $missingSamples.Add($entry.Key)
        }
    }

    return [PSCustomObject]@{
        Match = ($missingCount -eq 0 -and $extraCount -eq 0)
        ExpectedRows = $expectedCount
        ActualRows = $actualCount
        MissingCount = $missingCount
        ExtraCount = $extraCount
        MissingSamples = @($missingSamples)
        ExtraSamples = @($extraSamples)
        VerificationMode = 'canonical-row-signature-stream'
        ComparisonStorage = 'in-memory-hash-multiset'
    }
}

function Get-StringArray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
        return @($Value)
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $result = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            $text = [string]$item
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $result.Add($text)
            }
        }
        return @($result)
    }

    return @([string]$Value)
}

function New-MachineInfoObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Machine
    )

    if ($null -eq $Machine) {
        return $null
    }

    return [PSCustomObject]@{
        ip = $Machine.lastIpAddress
        eip = $Machine.lastExternalIpAddress
        hs = $Machine.healthStatus
        rs = $Machine.riskScore
        el = $Machine.exposureLevel
        dv = $Machine.deviceValue
        mb = $Machine.managedBy
        aad = $Machine.isAadJoined
        ls = Convert-ToYmdDate -DateValue $Machine.lastSeen
        fs = Convert-ToYmdDate -DateValue $Machine.firstSeen
    }
}

function Read-SourceAuditRecordStream {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExportsPath,

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge
    )

    $contentStoreAvailable = Sync-VulnContentStoreSidecar -BasePath $ExportsPath

    if ($SkipObservedWindowMerge) {
        if ($contentStoreAvailable) {
            Read-VulnContentStoreRow -BasePath $ExportsPath
            return
        }

        Read-VulnStoreRow -BasePath $ExportsPath
        return
    }

    if ($contentStoreAvailable) {
        Get-NormalizationSourceRows -DataPath $ExportsPath
        return
    }

    if (Test-VulnStoreExistence -BasePath $ExportsPath) {
        Read-NormalizedVulnStoreRow -BasePath $ExportsPath
        return
    }

    throw "No canonical vulnerability store or content-store sidecars were found in '$ExportsPath'."
}

function Get-SourceVendorSetForAudit {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExportsPath,

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge
    )

    $vendorSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $processedCount = 0
    Read-SourceAuditRecordStream -ExportsPath $ExportsPath -SkipObservedWindowMerge:$SkipObservedWindowMerge | ForEach-Object {
        $record = $_
        if ((Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -eq $true) {
            $vendor = [string](Get-VulnPropertyValue -InputObject $record -Name 'SoftwareVendor')
            if (-not [string]::IsNullOrWhiteSpace($vendor)) {
                [void]$vendorSet.Add($vendor)
            }

            $processedCount++
            if (($processedCount % 250000) -eq 0) {
                Write-Information ("  Indexed vendors from {0} source row(s)..." -f $processedCount) -InformationAction Continue
            }
        }
    }

    return $vendorSet
}

function Read-SourceCanonicalSignatureStream {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExportsPath,

        [Parameter(Mandatory = $true)]
        $Machines,

        [Parameter(Mandatory = $true)]
        $AdvancedHunting,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$VendorSet,

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge,

        [Parameter(Mandatory = $false)]
        [ref]$FirstLastSwappedCount = ([ref]0),

        [Parameter(Mandatory = $false)]
        [ref]$MissingMachineCount = ([ref]0)
    )

    $deviceProfiles = @{}
    $processedCount = 0

    Read-SourceAuditRecordStream -ExportsPath $ExportsPath -SkipObservedWindowMerge:$SkipObservedWindowMerge | ForEach-Object {
        $record = $_
        if ((Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -ne $true) {
            return
        }

        $deviceId = [string](Get-VulnPropertyValue -InputObject $record -Name 'DeviceId')
        $machine = if (-not [string]::IsNullOrWhiteSpace($deviceId) -and $Machines.ContainsKey($deviceId)) { $Machines[$deviceId] } else { $null }
        if ($null -eq $machine) {
            $MissingMachineCount.Value++
        }

        $fallbackDeviceName = [string](Get-VulnPropertyValue -InputObject $record -Name 'DeviceName')
        $fallbackGroupName = [string](Get-VulnPropertyValue -InputObject $record -Name 'RbacGroupName')
        $fallbackPlatform = [string](Get-VulnPropertyValue -InputObject $record -Name 'OSPlatform')
        $fallbackOsVersion = [string](Get-VulnPropertyValue -InputObject $record -Name 'OSVersion')
        $fallbackMachineTags = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $record -Name 'MachineTags'))

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
            $groupName = if ($machine) { [string]$machine.rbacGroupName } else { $fallbackGroupName }
            if ([string]::IsNullOrWhiteSpace($groupName)) {
                $groupName = if ([string]::IsNullOrWhiteSpace($fallbackGroupName)) { '(none)' } else { $fallbackGroupName }
            }

            $machineTags = if ($machine -and @($machine.machineTags).Count -gt 0) {
                @($machine.machineTags)
            }
            elseif (@($fallbackMachineTags).Count -gt 0) {
                @($fallbackMachineTags)
            }
            else {
                @()
            }

            $deviceProfiles[$deviceKey] = [PSCustomObject]@{
                DeviceName = if ($machine) { [string]$machine.computerDnsName } elseif ($fallbackDeviceName) { $fallbackDeviceName } else { '(no machine data)' }
                RbacGroupName = $groupName
                OSPlatform = if ($machine) { [string]$machine.osPlatform } else { $fallbackPlatform }
                OSVersion = if ($machine) { [string]$machine.osVersion } else { $fallbackOsVersion }
                MachineTags = $machineTags
                MachineInfo = New-MachineInfoObject -Machine $machine
            }
        }

        $deviceProfile = $deviceProfiles[$deviceKey]
        $seenWindow = Get-NormalizedVulnSeenWindow `
            -FirstSeenValue (Get-VulnPropertyValue -InputObject $record -Name 'FirstSeenTimestamp') `
            -LastSeenValue (Get-VulnPropertyValue -InputObject $record -Name 'LastSeenTimestamp')
        $firstSeen = $seenWindow.FirstSeenTimestamp
        $lastSeen = $seenWindow.LastSeenTimestamp
        if ($seenWindow.WasReordered) {
            $FirstLastSwappedCount.Value++
        }
        if (-not $firstSeen) { $firstSeen = '' }
        if (-not $lastSeen) { $lastSeen = '' }

        $cveId = [string](Get-VulnPropertyValue -InputObject $record -Name 'CveId')
        $ahRecord = if (-not [string]::IsNullOrWhiteSpace($cveId) -and $AdvancedHunting.ContainsKey($cveId)) { $AdvancedHunting[$cveId] } else { $null }
        $affectedSoftware = $null
        $affectedSoftwareSource = if ($ahRecord) { @(Get-StringArray -Value $ahRecord.AffectedSoftware) } else { @() }
        if (@($affectedSoftwareSource).Count -gt 0) {
            $filtered = [System.Collections.Generic.List[string]]::new()
            foreach ($software in $affectedSoftwareSource) {
                $vendor = if ($software -match ':') { $software.Split(':', 2)[0] } else { $software }
                if ($VendorSet.Contains($vendor)) {
                    $filtered.Add([string]$software)
                }
            }
            if (@($filtered).Count -gt 0) {
                $affectedSoftware = @($filtered)
            }
        }

        $recommendedUpdate = [string](Get-VulnPropertyValue -InputObject $record -Name 'RecommendedSecurityUpdate')
        if ([string]::IsNullOrWhiteSpace($recommendedUpdate) -or $recommendedUpdate -eq '--') {
            $recommendedUpdate = $null
        }

        $updateId = if ($recommendedUpdate) { [string](Get-VulnPropertyValue -InputObject $record -Name 'RecommendedSecurityUpdateId') } else { $null }
        $updateUrl = if ($recommendedUpdate) { [string](Get-VulnPropertyValue -InputObject $record -Name 'RecommendedSecurityUpdateUrl') } else { $null }

        $row = [PSCustomObject]@{
            DeviceId = $deviceId
            DeviceName = [string]$deviceProfile.DeviceName
            RbacGroupName = [string]$deviceProfile.RbacGroupName
            OSPlatform = [string]$deviceProfile.OSPlatform
            OSVersion = [string]$deviceProfile.OSVersion
            MachineTags = @($deviceProfile.MachineTags)
            MachineInfo = $deviceProfile.MachineInfo
            CveId = $cveId
            CvssScore = Get-VulnPropertyValue -InputObject $record -Name 'CvssScore'
            VulnerabilitySeverityLevel = [string](Get-VulnPropertyValue -InputObject $record -Name 'VulnerabilitySeverityLevel')
            ExploitabilityLevel = [string](Get-VulnPropertyValue -InputObject $record -Name 'ExploitabilityLevel')
            CveBatchUrl = Convert-CveUrl -Url ([string](Get-VulnPropertyValue -InputObject $record -Name 'CveBatchUrl'))
            CveBatchTitle = [string](Get-VulnPropertyValue -InputObject $record -Name 'CveBatchTitle')
            PublishedDate = if ($ahRecord) { [string]$ahRecord.PublishedDate } else { $null }
            VulnerabilityDescription = if ($ahRecord) { [string]$ahRecord.VulnerabilityDescription } else { $null }
            EpssScore = if ($ahRecord) { $ahRecord.EpssScore } else { $null }
            AffectedSoftware = $affectedSoftware
            SoftwareVendor = [string](Get-VulnPropertyValue -InputObject $record -Name 'SoftwareVendor')
            SoftwareName = [string](Get-VulnPropertyValue -InputObject $record -Name 'SoftwareName')
            SoftwareVersion = [string](Get-VulnPropertyValue -InputObject $record -Name 'SoftwareVersion')
            RecommendationReference = [string](Get-VulnPropertyValue -InputObject $record -Name 'RecommendationReference')
            FirstSeenTimestamp = $firstSeen
            LastSeenTimestamp = $lastSeen
            SecurityUpdateAvailable = ((Get-VulnPropertyValue -InputObject $record -Name 'SecurityUpdateAvailable') -eq $true)
            RecommendedSecurityUpdate = $recommendedUpdate
            RecommendedSecurityUpdateId = $updateId
            RecommendedSecurityUpdateUrl = $updateUrl
            DiskPaths = Get-StringArray -Value (Get-VulnPropertyValue -InputObject $record -Name 'DiskPaths')
            RegistryPaths = Get-StringArray -Value (Get-VulnPropertyValue -InputObject $record -Name 'RegistryPaths')
        }

        $processedCount++
        if (($processedCount % 250000) -eq 0) {
            Write-Information ("  Canonicalized {0} source row(s)..." -f $processedCount) -InformationAction Continue
        }

        Get-CanonicalValidationRowSignature -Row $row
    }
}

function Get-DashboardHtmlScriptContent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Html,

        [Parameter(Mandatory = $true)]
        [string]$ScriptId
    )

    $pattern = '<script\s+id="' + [regex]::Escape($ScriptId) + '"[^>]*>(?<content>.*?)</script>'
    $match = [regex]::Match(
        $Html,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline
    )

    if (-not $match.Success) {
        return ''
    }

    return $match.Groups['content'].Value.Trim()
}

function Get-DashboardEmbeddedPayloadTempPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($HtmlPath)
    $content = [System.IO.File]::ReadAllText($resolvedPath, [System.Text.Encoding]::UTF8)
    $dataFormat = Get-DashboardHtmlScriptContent -Html $content -ScriptId 'dataFormat'

    if ($dataFormat -eq 'external-compressed') {
        $dashboardConfigJson = Get-DashboardHtmlScriptContent -Html $content -ScriptId 'dashboardConfig'
        if ([string]::IsNullOrWhiteSpace($dashboardConfigJson)) {
            throw "Unable to locate dashboardConfig metadata in '$HtmlPath'."
        }

        $dashboardConfig = $dashboardConfigJson | ConvertFrom-Json -Depth 20
        $payloadUrl = [string]$dashboardConfig.payloadUrl
        if ([string]::IsNullOrWhiteSpace($payloadUrl)) {
            throw "dashboardConfig in '$HtmlPath' does not define payloadUrl."
        }

        $htmlDirectory = Split-Path -Path $resolvedPath -Parent
        $payloadRelativePath = $payloadUrl.Replace('/', '\')
        return [System.IO.Path]::GetFullPath((Join-Path $htmlDirectory $payloadRelativePath))
    }

    $startMarker = '<script id="vulnsData" type="application/json">'
    $endMarker = '</script>'
    $startIndex = $content.IndexOf($startMarker)
    if ($startIndex -lt 0) {
        throw "Unable to locate embedded vulnerability payload in '$HtmlPath'."
    }

    $payloadStart = $startIndex + $startMarker.Length
    $payloadEnd = $content.IndexOf($endMarker, $payloadStart)
    if ($payloadEnd -lt 0) {
        throw "Unable to locate payload terminator in '$HtmlPath'."
    }

    $base64 = ($content.Substring($payloadStart, $payloadEnd - $payloadStart) -replace '\s+', '')
    $bytes = [Convert]::FromBase64String($base64)
    $tempPayloadPath = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-embedded-payload-' + [guid]::NewGuid().ToString('N') + '.json.gz')
    [System.IO.File]::WriteAllBytes($tempPayloadPath, $bytes)
    return $tempPayloadPath
}

function Get-EmbeddedDashboardPayloadVulnCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedPath = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $content = Get-Content -LiteralPath $resolvedPath -Raw
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
        return (Get-CompressedPayloadVulnCount -Path $payloadPath)
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
    $stream = $null
    $gzip = $null
    $reader = $null
    $jsonReader = $null

    try {
        $stream = [System.IO.MemoryStream]::new($bytes)
        $gzip = [System.IO.Compression.GZipStream]::new($stream, [System.IO.Compression.CompressionMode]::Decompress)
        $reader = [System.IO.StreamReader]::new($gzip, [System.Text.Encoding]::UTF8)
        $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($reader)
        return (Get-PayloadVulnCountFromJsonReader -Reader $jsonReader -Path $Path)
    }
    finally {
        if ($jsonReader) { $jsonReader.Close() }
        elseif ($reader) { $reader.Dispose() }
        elseif ($gzip) { $gzip.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }
}

function Get-DashboardPayloadGzipSha256 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

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
        return (Get-FileSha256Hex -Path $payloadPath)
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
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
}

function Convert-JsonElementToIntArray {
    [CmdletBinding()]
    [OutputType([int[]])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Json.JsonElement]$Element,

        [Parameter(Mandatory = $false)]
        [int]$NullValue = -1
    )

    $values = [int[]]::new($Element.GetArrayLength())
    $index = 0
    foreach ($item in $Element.EnumerateArray()) {
        switch ($item.ValueKind) {
            ([System.Text.Json.JsonValueKind]::Number) { $values[$index] = $item.GetInt32() }
            ([System.Text.Json.JsonValueKind]::Null) { $values[$index] = $NullValue }
            ([System.Text.Json.JsonValueKind]::Undefined) { $values[$index] = $NullValue }
            default { throw "Expected numeric array value while reading payload, found '$($item.ValueKind)'." }
        }
        $index++
    }

    return $values
}

function Convert-JsonElementToNestedIntArray {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Json.JsonElement]$Element
    )

    $values = [object[]]::new($Element.GetArrayLength())
    $index = 0
    foreach ($item in $Element.EnumerateArray()) {
        switch ($item.ValueKind) {
            ([System.Text.Json.JsonValueKind]::Null) {
                $values[$index] = $null
            }
            ([System.Text.Json.JsonValueKind]::Undefined) {
                $values[$index] = $null
            }
            ([System.Text.Json.JsonValueKind]::Array) {
                $nested = [int[]]::new($item.GetArrayLength())
                $nestedIndex = 0
                foreach ($nestedItem in $item.EnumerateArray()) {
                    switch ($nestedItem.ValueKind) {
                        ([System.Text.Json.JsonValueKind]::Number) { $nested[$nestedIndex] = $nestedItem.GetInt32() }
                        ([System.Text.Json.JsonValueKind]::Null) { $nested[$nestedIndex] = -1 }
                        ([System.Text.Json.JsonValueKind]::Undefined) { $nested[$nestedIndex] = -1 }
                        default { throw "Expected numeric nested array value while reading payload, found '$($nestedItem.ValueKind)'." }
                    }
                    $nestedIndex++
                }
                $values[$index] = $nested
            }
            ([System.Text.Json.JsonValueKind]::Number) {
                $nested = [int[]]::new(1)
                $nested[0] = $item.GetInt32()
                $values[$index] = $nested
            }
            default {
                throw "Expected nested array value while reading payload, found '$($item.ValueKind)'."
            }
        }
        $index++
    }

    return $values
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

    Write-Output -InputObject ([Newtonsoft.Json.Linq.JObject]::Load($Reader)) -NoEnumerate
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

    if ($value -is [Newtonsoft.Json.Linq.JValue]) {
        return [string]$value.Value
    }

    return [string]$value
}

function Get-PayloadLookupItem {
    [CmdletBinding()]
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
    if ($value -is [Newtonsoft.Json.Linq.JValue]) {
        return $value.Value
    }

    Write-Output -InputObject $value -NoEnumerate
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
        [AllowEmptyString()]
        [string]$MachineTagsCanonical,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$AffectedSoftwareCanonical,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$DiskPathsCanonical,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$RegistryPathsCanonical,

        [Parameter(Mandatory = $true)]
        [bool]$SecurityUpdateAvailable
    )

    $machineInfo = Get-VulnPropertyValue -InputObject $Device -Name 'm'
    $updateName = if ($UpdateObject) { Get-VulnPropertyValue -InputObject $UpdateObject -Name 'n' } else { $null }
    $updateId = if ($UpdateObject) { Get-VulnPropertyValue -InputObject $UpdateObject -Name 'id' } else { $null }
    $updateUrl = if ($UpdateObject) { Get-VulnPropertyValue -InputObject $UpdateObject -Name 'url' } else { $null }
    $valueDelimiter = [string][char]0x001f

    return @(
        [string](Get-VulnPropertyValue -InputObject $Device -Name 'id')
        [string](Get-VulnPropertyValue -InputObject $Device -Name 'n')
        if ($GroupName -and -not [string]::IsNullOrWhiteSpace([string]$GroupName)) { [string]$GroupName } else { '(none)' }
        if ($null -ne $PlatformName) { [string]$PlatformName } else { $null }
        [string](Get-VulnPropertyValue -InputObject $Device -Name 'ov')
        $MachineTagsCanonical
        [string]$(if ($machineInfo) { Get-VulnPropertyValue -InputObject $machineInfo -Name 'ip' } else { $null })
        [string]$(if ($machineInfo) { Get-VulnPropertyValue -InputObject $machineInfo -Name 'eip' } else { $null })
        [string]$(if ($machineInfo) { Get-VulnPropertyValue -InputObject $machineInfo -Name 'hs' } else { $null })
        [string]$(if ($machineInfo) { Get-VulnPropertyValue -InputObject $machineInfo -Name 'rs' } else { $null })
        [string]$(if ($machineInfo) { Get-VulnPropertyValue -InputObject $machineInfo -Name 'el' } else { $null })
        [string]$(if ($machineInfo) { Get-VulnPropertyValue -InputObject $machineInfo -Name 'dv' } else { $null })
        [string]$(if ($machineInfo) { Get-VulnPropertyValue -InputObject $machineInfo -Name 'mb' } else { $null })
        [string]([bool]$(if ($machineInfo) { (Get-VulnPropertyValue -InputObject $machineInfo -Name 'aad') -eq $true } else { $false }))
        [string](Convert-ToYmdDate -DateValue $(if ($machineInfo) { Get-VulnPropertyValue -InputObject $machineInfo -Name 'ls' } else { $null }))
        [string](Convert-ToYmdDate -DateValue $(if ($machineInfo) { Get-VulnPropertyValue -InputObject $machineInfo -Name 'fs' } else { $null }))
        [string](Get-VulnPropertyValue -InputObject $Cve -Name 'id')
        (Get-NormalizedAuditDecimalString -Value (Get-VulnPropertyValue -InputObject $Cve -Name 'sc'))
        if ($null -ne $SeverityName) { [string]$SeverityName } else { $null }
        if ($null -ne $ExploitabilityName) { [string]$ExploitabilityName } else { $null }
        [string](Get-VulnPropertyValue -InputObject $Cve -Name 'u')
        if ($null -ne $BatchTitle) { [string]$BatchTitle } else { $null }
        [string](Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $Cve -Name 'pd'))
        (Get-NormalizedAuditText -Text ([string](Get-VulnPropertyValue -InputObject $Cve -Name 'desc')))
        (Get-NormalizedAuditDecimalString -Value (Get-VulnPropertyValue -InputObject $Cve -Name 'ep'))
        $AffectedSoftwareCanonical
        if ($null -ne $SoftwareVendor) { [string]$SoftwareVendor } else { $null }
        [string](Get-VulnPropertyValue -InputObject $Software -Name 'n')
        if ($null -ne $SoftwareVersion) { [string]$SoftwareVersion } else { $null }
        [string](Get-VulnPropertyValue -InputObject $Software -Name 'r')
        [string](Convert-ToYmdDate -DateValue $FirstSeenDate)
        [string](Convert-ToYmdDate -DateValue $LastSeenDate)
        [string]([bool]$SecurityUpdateAvailable)
        if ($UpdateObject) { [string]$(if ($null -ne $updateName) { $updateName } else { $UpdateObject }) } else { $null }
        if ($UpdateObject -and $null -ne $updateId) { [string]$updateId } else { $null }
        if ($UpdateObject -and $null -ne $updateUrl) { [string]$updateUrl } else { $null }
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
    $jsonDocument = $null
    $lookups = $null
    $vulnsFormat = $null
    $rowsPayload = $null
    $columnDeviceIndices = $null
    $columnCveIndices = $null
    $columnSoftwareIndices = $null
    $columnVersionIndices = $null
    $columnFirstSeenIndices = $null
    $columnLastSeenIndices = $null
    $columnUpdateAvailability = $null
    $columnUpdateIndices = $null
    $columnDiskPathIndices = $null
    $columnRegistryPathIndices = $null

    try {
        $fileStream = [System.IO.File]::OpenRead($PayloadPath)
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        $jsonDocument = [System.Text.Json.JsonDocument]::Parse($gzipStream)

        $root = $jsonDocument.RootElement
        $lookups = [Newtonsoft.Json.Linq.JObject]::Parse($root.GetProperty('lookups').GetRawText())
        $vulnsFormat = [string]$root.GetProperty('vulnsFormat').GetString()
        $vulns = $root.GetProperty('vulns')

        if ($vulnsFormat -eq 'rows-v1') {
            $rowsPayload = ($vulns.GetRawText() | ConvertFrom-Json -Depth 100)
        }
        elseif ($vulnsFormat -eq 'columns-v1') {
            $columnDeviceIndices = Convert-JsonElementToIntArray -Element ($vulns.GetProperty('d'))
            $columnCveIndices = Convert-JsonElementToIntArray -Element ($vulns.GetProperty('c'))
            $columnSoftwareIndices = Convert-JsonElementToIntArray -Element ($vulns.GetProperty('s'))
            $columnVersionIndices = Convert-JsonElementToIntArray -Element ($vulns.GetProperty('v'))
            $columnFirstSeenIndices = Convert-JsonElementToIntArray -Element ($vulns.GetProperty('f'))
            $columnLastSeenIndices = Convert-JsonElementToIntArray -Element ($vulns.GetProperty('l'))
            $columnUpdateAvailability = Convert-JsonElementToIntArray -Element ($vulns.GetProperty('ua')) -NullValue 0
            $columnUpdateIndices = Convert-JsonElementToIntArray -Element ($vulns.GetProperty('u'))
            $columnDiskPathIndices = Convert-JsonElementToNestedIntArray -Element ($vulns.GetProperty('dp'))
            $columnRegistryPathIndices = Convert-JsonElementToNestedIntArray -Element ($vulns.GetProperty('rp'))
        }
        else {
            throw "Streaming payload audit requires columns-v1 or rows-v1 payload format. Found '$vulnsFormat' in '$PayloadPath'."
        }
    }
    finally {
        if ($jsonDocument) { $jsonDocument.Dispose() }
        if ($gzipStream) { $gzipStream.Dispose() }
        if ($fileStream) { $fileStream.Dispose() }
    }

    Invoke-FullGarbageCollection

    if ($vulnsFormat -eq 'rows-v1') {
        $payloadRows = @($rowsPayload)
        if ($payloadRows.Count -gt 0) {
            $firstPayloadRow = $payloadRows[0]
            $firstPayloadRowIsNested = ($null -ne $firstPayloadRow -and $firstPayloadRow -is [System.Collections.IEnumerable] -and $firstPayloadRow -isnot [string])
            if (-not $firstPayloadRowIsNested) {
                $payloadRows = ,$payloadRows
            }
        }

        foreach ($v in $payloadRows) {
            if ($null -eq $v) { continue }

            $device = Get-PayloadLookupItem -LookupValues $lookups.devices -Index $v[0]
            $cve = Get-PayloadLookupItem -LookupValues $lookups.cves -Index $v[1]
            $software = Get-PayloadLookupItem -LookupValues $lookups.software -Index $v[2]

            $resolvedDiskPaths = [System.Collections.Generic.List[string]]::new()
            foreach ($pathIndex in @($v[8])) {
                if ($null -eq $pathIndex) { continue }
                $pathText = Get-PayloadLookupText -LookupValues $lookups.diskPaths -Index $pathIndex
                if ($null -ne $pathText) {
                    $resolvedDiskPaths.Add($pathText)
                }
            }

            $resolvedRegistryPaths = [System.Collections.Generic.List[string]]::new()
            foreach ($pathIndex in @($v[9])) {
                if ($null -eq $pathIndex) { continue }
                $pathText = Get-PayloadLookupText -LookupValues $lookups.regPaths -Index $pathIndex
                if ($null -ne $pathText) {
                    $resolvedRegistryPaths.Add($pathText)
                }
            }

            $resolvedMachineTags = [System.Collections.Generic.List[string]]::new()
            foreach ($tagIndex in @((Get-VulnPropertyValue -InputObject $device -Name 't'))) {
                if ($null -eq $tagIndex) { continue }
                $tagText = Get-PayloadLookupText -LookupValues $lookups.tags -Index $tagIndex
                if ($null -ne $tagText) {
                    $resolvedMachineTags.Add($tagText)
                }
            }

            $resolvedAffectedSoftware = [System.Collections.Generic.List[string]]::new()
            foreach ($softwareIndex in @((Get-VulnPropertyValue -InputObject $cve -Name 'as'))) {
                if ($null -eq $softwareIndex) { continue }
                $softwareText = Get-PayloadLookupText -LookupValues $lookups.affSoftware -Index $softwareIndex
                if ($null -ne $softwareText) {
                    $resolvedAffectedSoftware.Add($softwareText)
                }
            }

            $groupName = Get-PayloadLookupText -LookupValues $lookups.groups -Index (Get-VulnPropertyValue -InputObject $device -Name 'g')
            $platformName = Get-PayloadLookupText -LookupValues $lookups.platforms -Index (Get-VulnPropertyValue -InputObject $device -Name 'o')
            $severityName = Get-PayloadLookupText -LookupValues $lookups.severities -Index (Get-VulnPropertyValue -InputObject $cve -Name 'sv')
            $exploitabilityName = Get-PayloadLookupText -LookupValues $lookups.exploitLevels -Index (Get-VulnPropertyValue -InputObject $cve -Name 'ex')
            $batchTitle = Get-PayloadLookupText -LookupValues $lookups.batchTitles -Index (Get-VulnPropertyValue -InputObject $cve -Name 'bt')
            $softwareVendor = Get-PayloadLookupText -LookupValues $lookups.vendors -Index (Get-VulnPropertyValue -InputObject $software -Name 'v')
            $softwareVersion = Get-PayloadLookupText -LookupValues $lookups.versions -Index $v[3]
            $firstSeenDate = Get-PayloadLookupText -LookupValues $lookups.dates -Index $v[4]
            $lastSeenDate = Get-PayloadLookupText -LookupValues $lookups.dates -Index $v[5]
            $updateObject = if ($v[7] -ge 0) { Get-PayloadLookupItem -LookupValues $lookups.updates -Index $v[7] } else { $null }

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
                -MachineTagsCanonical (Convert-ToCanonicalValidationListString -Value $resolvedMachineTags) `
                -AffectedSoftwareCanonical (Convert-ToCanonicalValidationListString -Value $resolvedAffectedSoftware) `
                -DiskPathsCanonical (Convert-ToCanonicalValidationListString -Value $resolvedDiskPaths) `
                -RegistryPathsCanonical (Convert-ToCanonicalValidationListString -Value $resolvedRegistryPaths) `
                -SecurityUpdateAvailable ($v[6] -eq 1)
        }
        return
    }

    if (
        $null -eq $columnDeviceIndices -or
        $null -eq $columnCveIndices -or
        $null -eq $columnSoftwareIndices -or
        $null -eq $columnVersionIndices -or
        $null -eq $columnFirstSeenIndices -or
        $null -eq $columnLastSeenIndices -or
        $null -eq $columnUpdateAvailability -or
        $null -eq $columnUpdateIndices -or
        $null -eq $columnDiskPathIndices -or
        $null -eq $columnRegistryPathIndices
    ) {
        throw "Streaming payload audit could not read the required vuln columns from '$PayloadPath'."
    }

    $deviceTagCanonicalCache = [string[]]::new($lookups.devices.Count)
    $deviceTagCanonicalCacheInitialized = [bool[]]::new($lookups.devices.Count)
    $affectedSoftwareCanonicalCache = [string[]]::new($lookups.cves.Count)
    $affectedSoftwareCanonicalCacheInitialized = [bool[]]::new($lookups.cves.Count)

    function Get-DeviceTagCanonicalString {
        param([Parameter(Mandatory = $true)][int]$Index)

        if (-not $deviceTagCanonicalCacheInitialized[$Index]) {
            $device = Get-PayloadLookupItem -LookupValues $lookups.devices -Index $Index
            $resolved = [System.Collections.Generic.List[string]]::new()
            foreach ($tagIndex in @((Get-VulnPropertyValue -InputObject $device -Name 't'))) {
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
            $cve = Get-PayloadLookupItem -LookupValues $lookups.cves -Index $Index
            $resolved = [System.Collections.Generic.List[string]]::new()
            foreach ($softwareIndex in @((Get-VulnPropertyValue -InputObject $cve -Name 'as'))) {
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

    function Get-CanonicalLookupListStringFromIndexList {
        param(
            [Parameter(Mandatory = $true)]
            $LookupValues,

            [Parameter(Mandatory = $false)]
            [AllowNull()]
            $Indices
        )

        $resolved = [System.Collections.Generic.List[string]]::new()
        foreach ($lookupIndex in @($Indices)) {
            if ($null -eq $lookupIndex) { continue }
            $lookupText = Get-PayloadLookupText -LookupValues $LookupValues -Index $lookupIndex
            if ($null -ne $lookupText) {
                $resolved.Add($lookupText)
            }
        }

        return (Convert-ToCanonicalValidationListString -Value $resolved)
    }

    $vulnCount = $columnDeviceIndices.Length
    for ($i = 0; $i -lt $vulnCount; $i++) {
        $device = Get-PayloadLookupItem -LookupValues $lookups.devices -Index $columnDeviceIndices[$i]
        $cve = Get-PayloadLookupItem -LookupValues $lookups.cves -Index $columnCveIndices[$i]
        $software = Get-PayloadLookupItem -LookupValues $lookups.software -Index $columnSoftwareIndices[$i]

        $groupName = Get-PayloadLookupText -LookupValues $lookups.groups -Index (Get-VulnPropertyValue -InputObject $device -Name 'g')
        $platformName = Get-PayloadLookupText -LookupValues $lookups.platforms -Index (Get-VulnPropertyValue -InputObject $device -Name 'o')
        $severityName = Get-PayloadLookupText -LookupValues $lookups.severities -Index (Get-VulnPropertyValue -InputObject $cve -Name 'sv')
        $exploitabilityName = Get-PayloadLookupText -LookupValues $lookups.exploitLevels -Index (Get-VulnPropertyValue -InputObject $cve -Name 'ex')
        $batchTitle = Get-PayloadLookupText -LookupValues $lookups.batchTitles -Index (Get-VulnPropertyValue -InputObject $cve -Name 'bt')
        $softwareVendor = Get-PayloadLookupText -LookupValues $lookups.vendors -Index (Get-VulnPropertyValue -InputObject $software -Name 'v')
        $softwareVersion = Get-PayloadLookupText -LookupValues $lookups.versions -Index $columnVersionIndices[$i]
        $firstSeenDate = Get-PayloadLookupText -LookupValues $lookups.dates -Index $columnFirstSeenIndices[$i]
        $lastSeenDate = Get-PayloadLookupText -LookupValues $lookups.dates -Index $columnLastSeenIndices[$i]
        $updateObject = if ($columnUpdateIndices[$i] -ge 0) { Get-PayloadLookupItem -LookupValues $lookups.updates -Index $columnUpdateIndices[$i] } else { $null }

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
            -MachineTagsCanonical (Get-DeviceTagCanonicalString -Index $columnDeviceIndices[$i]) `
            -AffectedSoftwareCanonical (Get-AffectedSoftwareCanonicalString -Index $columnCveIndices[$i]) `
            -DiskPathsCanonical (Get-CanonicalLookupListStringFromIndexList -LookupValues $lookups.diskPaths -Indices $columnDiskPathIndices[$i]) `
            -RegistryPathsCanonical (Get-CanonicalLookupListStringFromIndexList -LookupValues $lookups.regPaths -Indices $columnRegistryPathIndices[$i]) `
            -SecurityUpdateAvailable ($columnUpdateAvailability[$i] -eq 1)
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
    $inMemoryComparisonThreshold = 1000000
    $payloadParityMatch = (($dashboardPayloadSha256 -eq $cachedPayloadSha256) -and ($dashboardPayloadRowCount -eq $cachedPayloadRowCount))

    $sourceSignatureSet = $null
    $payloadSignatureSet = $null
    $sourceElapsedSeconds = 0
    $payloadElapsedSeconds = 0
    $comparisonStorage = 'partitioned-hash-files'
    $comparisonPayloadSource = 'dashboard-payload'
    $dashboardPayloadPath = $null
    $comparisonPayloadPath = $null
    $comparisonPayloadLabel = 'dashboard'
    $machines = $null
    $advancedHunting = $null
    $vendorSet = $null
    $sourceFirstLastSwappedCount = 0
    $sourceMissingMachineCount = 0

    try {
        Write-Information '  Streaming semantic parity audit for large dataset directly against source exports...' -InformationAction Continue

        $machines = Read-MachineData -Path $ResolvedExportsPath
        $advancedHunting = Read-AdvancedHuntingData -Path $ResolvedExportsPath
        $vendorSet = Get-SourceVendorSetForAudit -ExportsPath $ResolvedExportsPath -SkipObservedWindowMerge:$skipObservedWindowMerge

        if ($payloadParityMatch) {
            $comparisonPayloadSource = 'cached-payload'
            $comparisonPayloadPath = $PayloadCacheEntry.PayloadPath
            $comparisonPayloadLabel = 'dashboard-cache'
            Write-Information '  Dashboard payload matches the normalized payload cache; reusing cached payload for semantic comparison.' -InformationAction Continue
        }
        else {
            $dashboardPayloadPath = Get-DashboardEmbeddedPayloadTempPath -HtmlPath $ResolvedHtmlPath
            $comparisonPayloadPath = $dashboardPayloadPath
            Write-Information '  Dashboard payload differs from the normalized payload cache; comparing dashboard payload directly against source exports.' -InformationAction Continue
        }

        try {
            if ($cachedPayloadRowCount -le $inMemoryComparisonThreshold) {
                $comparisonStorage = 'in-memory-hash-multiset'
                Write-Information ("  Using in-memory signature multiset comparison for {0} row(s)." -f $cachedPayloadRowCount) -InformationAction Continue

                $comparisonStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $rowComparison = Compare-CanonicalSignatureSourceMultiset `
                    -ExpectedLabel 'source' `
                    -ActualLabel $comparisonPayloadLabel `
                    -ExpectedSignatureSource {
                        Read-SourceCanonicalSignatureStream `
                            -ExportsPath $ResolvedExportsPath `
                            -Machines $machines `
                            -AdvancedHunting $advancedHunting `
                            -VendorSet $vendorSet `
                            -SkipObservedWindowMerge:$skipObservedWindowMerge `
                            -FirstLastSwappedCount ([ref]$sourceFirstLastSwappedCount) `
                            -MissingMachineCount ([ref]$sourceMissingMachineCount)
                    } `
                    -ActualSignatureSource {
                        Read-PayloadCanonicalSignatureStream -PayloadPath $comparisonPayloadPath
                    }
                $comparisonStopwatch.Stop()
                $sourceElapsedSeconds = [math]::Round($comparisonStopwatch.Elapsed.TotalSeconds, 2)
                $payloadElapsedSeconds = $sourceElapsedSeconds
                Write-Information ("  In-memory source-to-dashboard semantic comparison completed in {0:N2}s" -f $sourceElapsedSeconds) -InformationAction Continue
            }
            else {
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

                $payloadStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $payloadSignatureSet = Write-PartitionedSignatureSet -Label $comparisonPayloadLabel -SignatureSource {
                    Read-PayloadCanonicalSignatureStream -PayloadPath $comparisonPayloadPath
                }
                $payloadStopwatch.Stop()
                $payloadElapsedSeconds = [math]::Round($payloadStopwatch.Elapsed.TotalSeconds, 2)
                Write-Information ("  Comparison payload signature pass completed in {0:N2}s" -f $payloadElapsedSeconds) -InformationAction Continue

                $rowComparison = Compare-PartitionedSignatureSet -Expected $sourceSignatureSet -Actual $payloadSignatureSet
                $rowComparison | Add-Member -NotePropertyName VerificationMode -NotePropertyValue 'canonical-row-signature-stream'
                $rowComparison | Add-Member -NotePropertyName ComparisonStorage -NotePropertyValue 'partitioned-hash-files'
            }
        }
        finally {
            if (-not [string]::IsNullOrWhiteSpace($dashboardPayloadPath) -and (Test-Path -LiteralPath $dashboardPayloadPath -PathType Leaf)) {
                Remove-Item -LiteralPath $dashboardPayloadPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    finally {
        Remove-PartitionedSignatureSet -SignatureSet $sourceSignatureSet
        Remove-PartitionedSignatureSet -SignatureSet $payloadSignatureSet
        if ($null -ne $machines) { $machines = $null }
        if ($null -ne $advancedHunting) { $advancedHunting = $null }
        if ($null -ne $vendorSet) { $vendorSet = $null }
        Invoke-FullGarbageCollection
    }

    return [PSCustomObject]@{
        GeneratedOn = (Get-Date).ToString('o')
        HtmlPath = $ResolvedHtmlPath
        ExportsPath = $ResolvedExportsPath
        AuditMode = 'streaming-large-dataset'
        Source = [PSCustomObject]@{
            RowCount = [int]$rowComparison.ExpectedRows
            MissingMachineCount = $sourceMissingMachineCount
            FirstLastSwappedCount = $sourceFirstLastSwappedCount
            UniqueVendors = @($vendorSet | Sort-Object)
            Verification = 'Semantic parity was streamed directly from the current exports.'
            InputMode = if (Sync-VulnContentStoreSidecar -BasePath $ResolvedExportsPath) { 'content-store' } else { 'normalized-vuln-store' }
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
            Match = $payloadParityMatch
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
            ComparisonStorage = $comparisonStorage
            ComparisonPayloadSource = $comparisonPayloadSource
            PartitionCount = if ($sourceSignatureSet) { [int]$sourceSignatureSet.PartitionCount } elseif ($payloadSignatureSet) { [int]$payloadSignatureSet.PartitionCount } else { $null }
            SourceSignatureElapsedSeconds = $sourceElapsedSeconds
            PayloadSignatureElapsedSeconds = $payloadElapsedSeconds
            PayloadByteParityMatch = $payloadParityMatch
        }
    }
}
