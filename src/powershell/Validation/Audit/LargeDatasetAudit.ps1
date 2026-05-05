if (-not (Get-Variable -Name DashboardValidationProgressInterval -Scope Script -ErrorAction SilentlyContinue)) {
    $Script:DashboardValidationProgressInterval = 250000
}

if (-not (Get-Variable -Name DashboardValidationHeartbeatSeconds -Scope Script -ErrorAction SilentlyContinue)) {
    $Script:DashboardValidationHeartbeatSeconds = 60
}

if (-not (Get-Variable -Name DashboardValidationPartitionCompareParallelism -Scope Script -ErrorAction SilentlyContinue)) {
    $Script:DashboardValidationPartitionCompareParallelism = 1
}

if (-not (Get-Variable -Name DashboardValidationForceFull -Scope Script -ErrorAction SilentlyContinue)) {
    $Script:DashboardValidationForceFull = $false
}

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
        [string]$(if ($null -eq $Row.IsExploitAvailable) { '' } else { [bool]$Row.IsExploitAvailable })
        [string](Convert-ToYmdDate -DateValue $Row.NvdLastModifiedDate)
        (Get-NormalizedAuditDecimalString -Value $Row.NvdBaseScore)
        [string]$Row.NvdBaseSeverity
        [string]$Row.NvdVector
        [string](Convert-ToYmdDate -DateValue $Row.NvdKevDate)
        [string](Convert-ToYmdDate -DateValue $Row.NvdActionDue)
        (Get-NormalizedAuditText -Text ([string]$Row.NvdRequiredAction))
        (Convert-ToCanonicalValidationListString -Value $Row.NvdWeaknesses)
        [string]$Row.SoftwareVendor
        [string]$Row.SoftwareName
        [string]$Row.SoftwareVersion
        [string]$Row.RecommendationReference
        [string]$Row.ProductCodeCpe
        [string]$Row.EndOfSupportStatus
        [string](Convert-ToYmdDate -DateValue $Row.EndOfSupportDate)
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

function Get-PartitionedSignatureSetMetadataPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath
    )

    return (Join-Path $DirectoryPath 'signature-set.json')
}

function Get-PayloadSignatureCacheDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry,

        [Parameter(Mandatory = $false)]
        [switch]$Create
    )

    $payloadDirectory = Split-Path -Path ([System.IO.Path]::GetFullPath([string]$PayloadCacheEntry.PayloadPath)) -Parent
    $cacheDirectory = Join-Path $payloadDirectory ("payload-signatures-{0}" -f [string]$PayloadCacheEntry.Fingerprint)
    if ($Create) {
        [void](New-Item -Path $cacheDirectory -ItemType Directory -Force)
    }

    return $cacheDirectory
}

function Get-SourceSignatureCacheDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry,

        [Parameter(Mandatory = $true)]
        [string]$SourceFingerprint,

        [Parameter(Mandatory = $false)]
        [switch]$Create
    )

    $payloadDirectory = Split-Path -Path ([System.IO.Path]::GetFullPath([string]$PayloadCacheEntry.PayloadPath)) -Parent
    $cacheDirectory = Join-Path $payloadDirectory ("source-signatures-{0}" -f $SourceFingerprint)
    if ($Create) {
        [void](New-Item -Path $cacheDirectory -ItemType Directory -Force)
    }

    return $cacheDirectory
}

function Clear-StalePayloadSignatureCaches {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper clears multiple cached payload signature directories by design.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry
    )

    $payloadDirectory = Split-Path -Path ([System.IO.Path]::GetFullPath([string]$PayloadCacheEntry.PayloadPath)) -Parent
    if (-not (Test-Path -LiteralPath $payloadDirectory -PathType Container)) {
        return
    }

    $expectedDirectory = Get-PayloadSignatureCacheDirectory -PayloadCacheEntry $PayloadCacheEntry
    foreach ($cacheDirectory in @(Get-ChildItem -Path $payloadDirectory -Directory -Filter 'payload-signatures-*' -ErrorAction SilentlyContinue)) {
        if ([System.StringComparer]::OrdinalIgnoreCase.Equals($cacheDirectory.FullName, $expectedDirectory)) {
            continue
        }

        Remove-Item -LiteralPath $cacheDirectory.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Clear-StaleSourceSignatureCaches {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper clears multiple cached source signature directories by design.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSourceFingerprint
    )

    $payloadDirectory = Split-Path -Path ([System.IO.Path]::GetFullPath([string]$PayloadCacheEntry.PayloadPath)) -Parent
    if (-not (Test-Path -LiteralPath $payloadDirectory -PathType Container)) {
        return
    }

    $expectedDirectory = Get-SourceSignatureCacheDirectory -PayloadCacheEntry $PayloadCacheEntry -SourceFingerprint $ExpectedSourceFingerprint
    foreach ($cacheDirectory in @(Get-ChildItem -Path $payloadDirectory -Directory -Filter 'source-signatures-*' -ErrorAction SilentlyContinue)) {
        if ([System.StringComparer]::OrdinalIgnoreCase.Equals($cacheDirectory.FullName, $expectedDirectory)) {
            continue
        }

        Remove-Item -LiteralPath $cacheDirectory.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-CachedPayloadSignatureSet {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedPayloadSha256,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedPayloadRowCount
    )

    $cacheDirectory = Get-PayloadSignatureCacheDirectory -PayloadCacheEntry $PayloadCacheEntry
    $metadataPath = Get-PartitionedSignatureSetMetadataPath -DirectoryPath $cacheDirectory
    if ((-not (Test-Path -LiteralPath $cacheDirectory -PathType Container)) -or (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf))) {
        return $null
    }

    $metadata = Read-NormalizedPayloadManifest -Path $metadataPath
    if ($null -eq $metadata) {
        return $null
    }

    if ([string]$metadata.Version -ne 'payload-signature-cache-v1') {
        return $null
    }

    if ([string]$metadata.ValidationLogicVersion -ne (Get-DashboardSemanticValidationLogicVersion)) {
        return $null
    }

    if ([string]$metadata.Fingerprint -ne [string]$PayloadCacheEntry.Fingerprint) {
        return $null
    }

    if ([string]$metadata.PayloadSha256 -ne $ExpectedPayloadSha256) {
        return $null
    }

    if ([int]$metadata.PayloadRowCount -ne $ExpectedPayloadRowCount) {
        return $null
    }

    $partitionCount = [int]$metadata.PartitionCount
    $rowCount = [int]$metadata.RowCount
    if (($partitionCount -lt 1) -or ($rowCount -lt 0)) {
        return $null
    }

    return [PSCustomObject]@{
        DirectoryPath = $cacheDirectory
        Count = $rowCount
        PartitionCount = $partitionCount
        Persistent = $true
    }
}

function Get-CachedSourceSignatureSet {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSourceFingerprint
    )

    $cacheDirectory = Get-SourceSignatureCacheDirectory -PayloadCacheEntry $PayloadCacheEntry -SourceFingerprint $ExpectedSourceFingerprint
    $metadataPath = Get-PartitionedSignatureSetMetadataPath -DirectoryPath $cacheDirectory
    if ((-not (Test-Path -LiteralPath $cacheDirectory -PathType Container)) -or (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf))) {
        return $null
    }

    $metadata = Read-NormalizedPayloadManifest -Path $metadataPath
    if ($null -eq $metadata) {
        return $null
    }

    if ([string]$metadata.Version -ne 'source-signature-cache-v1') {
        return $null
    }

    if ([string]$metadata.ValidationLogicVersion -ne (Get-DashboardSemanticValidationLogicVersion)) {
        return $null
    }

    if ([string]$metadata.SourceFingerprint -ne $ExpectedSourceFingerprint) {
        return $null
    }

    $partitionCount = [int]$metadata.PartitionCount
    $rowCount = [int]$metadata.RowCount
    if (($partitionCount -lt 1) -or ($rowCount -lt 0)) {
        return $null
    }

    return [PSCustomObject]@{
        DirectoryPath = $cacheDirectory
        Count = $rowCount
        PartitionCount = $partitionCount
        Persistent = $true
        SourceMissingMachineCount = [int]$metadata.SourceMissingMachineCount
        SourceFirstLastSwappedCount = [int]$metadata.SourceFirstLastSwappedCount
        SourceUniqueVendors = @($metadata.SourceUniqueVendors | ForEach-Object { [string]$_ })
    }
}

function Write-CachedPayloadSignatureSetMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only writes cache metadata for a signature set generated from the current payload cache entry.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper writes metadata that describes a cached payload signature set.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry,

        [Parameter(Mandatory = $true)]
        [string]$PayloadSha256,

        [Parameter(Mandatory = $true)]
        [int]$PayloadRowCount,

        [Parameter(Mandatory = $true)]
        $SignatureSet
    )

    $cacheDirectory = Get-PayloadSignatureCacheDirectory -PayloadCacheEntry $PayloadCacheEntry -Create
    $metadataPath = Get-PartitionedSignatureSetMetadataPath -DirectoryPath $cacheDirectory
    $metadata = [ordered]@{
        Version = 'payload-signature-cache-v1'
        ValidationLogicVersion = Get-DashboardSemanticValidationLogicVersion
        Fingerprint = [string]$PayloadCacheEntry.Fingerprint
        PayloadPath = [string]$PayloadCacheEntry.PayloadPath
        PayloadSha256 = $PayloadSha256
        PayloadRowCount = $PayloadRowCount
        PartitionCount = [int]$SignatureSet.PartitionCount
        RowCount = [int]$SignatureSet.Count
        GeneratedOnUtc = (Get-Date).ToUniversalTime().ToString('o')
    }

    return (Write-NormalizedPayloadManifest -Path $metadataPath -Manifest $metadata)
}

function Write-CachedSourceSignatureSetMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only writes cache metadata for a signature set generated from the current source exports.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper writes metadata that describes a cached source signature set.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry,

        [Parameter(Mandatory = $true)]
        [string]$SourceFingerprint,

        [Parameter(Mandatory = $true)]
        $SignatureSet,

        [Parameter(Mandatory = $true)]
        [int]$SourceMissingMachineCount,

        [Parameter(Mandatory = $true)]
        [int]$SourceFirstLastSwappedCount,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$SourceUniqueVendors
    )

    $cacheDirectory = Get-SourceSignatureCacheDirectory -PayloadCacheEntry $PayloadCacheEntry -SourceFingerprint $SourceFingerprint -Create
    $metadataPath = Get-PartitionedSignatureSetMetadataPath -DirectoryPath $cacheDirectory
    $metadata = [ordered]@{
        Version = 'source-signature-cache-v1'
        ValidationLogicVersion = Get-DashboardSemanticValidationLogicVersion
        SourceFingerprint = $SourceFingerprint
        PartitionCount = [int]$SignatureSet.PartitionCount
        RowCount = [int]$SignatureSet.Count
        SourceMissingMachineCount = $SourceMissingMachineCount
        SourceFirstLastSwappedCount = $SourceFirstLastSwappedCount
        SourceUniqueVendors = @($SourceUniqueVendors)
        GeneratedOnUtc = (Get-Date).ToUniversalTime().ToString('o')
    }

    return (Write-NormalizedPayloadManifest -Path $metadataPath -Manifest $metadata)
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

    if ($SignatureSet.PSObject.Properties['Persistent'] -and ($SignatureSet.Persistent -eq $true)) {
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
        [int]$ProgressInterval = 250000,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$OutputDirectoryPath,

        [Parameter(Mandatory = $false)]
        [switch]$Persistent,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 2147483647)]
        [int]$ExpectedTotalCount = 0
    )

    $directoryPath = if (-not [string]::IsNullOrWhiteSpace($OutputDirectoryPath)) {
        [System.IO.Path]::GetFullPath($OutputDirectoryPath)
    }
    else {
        Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-audit-signatures-' + [guid]::NewGuid().ToString('N'))
    }

    [void](New-Item -Path $directoryPath -ItemType Directory -Force)
    foreach ($existingFile in @(Get-ChildItem -Path $directoryPath -File -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $existingFile.FullName -Force -ErrorAction SilentlyContinue
    }

    $writers = [System.IO.StreamWriter[]]::new($PartitionCount)
    $count = 0
    $progressState = New-ProgressMarkerState -ActivityName ("Partitioned {0}" -f $Label) -ProgressInterval $ProgressInterval -HeartbeatIntervalSeconds $Script:DashboardValidationHeartbeatSeconds -CheckInterval ([Math]::Min($ProgressInterval, 10000)) -TotalCount $ExpectedTotalCount
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
                Write-ProgressMarker -State $progressState -Count $count -UnitLabel 'row signature(s)'
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
        Persistent = ($Persistent -eq $true)
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
    $partitionIndices = if ($partitionCount -gt 0) { 0..($partitionCount - 1) } else { @() }
    $comparePartitionScript = {
        param(
            [Parameter(Mandatory = $true)]
            [int]$PartitionIndex,

            [Parameter(Mandatory = $true)]
            [string]$ExpectedDirectoryPath,

            [Parameter(Mandatory = $true)]
            [string]$ActualDirectoryPath
        )

        $expectedPath = Join-Path $ExpectedDirectoryPath ("p{0:D3}.txt" -f $PartitionIndex)
        $actualPath = Join-Path $ActualDirectoryPath ("p{0:D3}.txt" -f $PartitionIndex)
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

        $partitionMissingCount = 0
        $partitionExtraCount = 0
        $partitionMissingSamples = [System.Collections.Generic.List[string]]::new()
        $partitionExtraSamples = [System.Collections.Generic.List[string]]::new()

        foreach ($key in $expectedMap.Keys) {
            $actualCountForKey = $actualMap[$key] ?? 0
            if ($actualCountForKey -lt $expectedMap[$key]) {
                $partitionMissingCount += ($expectedMap[$key] - $actualCountForKey)
                if ($partitionMissingSamples.Count -lt 5) {
                    $partitionMissingSamples.Add($key)
                }
            }
        }

        foreach ($key in $actualMap.Keys) {
            $expectedCountForKey = $expectedMap[$key] ?? 0
            if ($expectedCountForKey -lt $actualMap[$key]) {
                $partitionExtraCount += ($actualMap[$key] - $expectedCountForKey)
                if ($partitionExtraSamples.Count -lt 5) {
                    $partitionExtraSamples.Add($key)
                }
            }
        }

        return [PSCustomObject]@{
            PartitionIndex = [int]$PartitionIndex
            MissingCount = $partitionMissingCount
            ExtraCount = $partitionExtraCount
            MissingSamples = @($partitionMissingSamples)
            ExtraSamples = @($partitionExtraSamples)
        }
    }

    if ($partitionIndices.Count -gt 0) {
        $requestedParallelism = [int]$Script:DashboardValidationPartitionCompareParallelism
        $effectiveParallelism = Resolve-RunspaceThrottleLimit -RequestedThrottleLimit $requestedParallelism -ActivityName 'Partitioned signature compare' -DisableInAzure
        if ($effectiveParallelism -gt 1 -and $partitionIndices.Count -gt 1) {
            Write-Information ("  Comparing {0} signature partition(s) with runspace pool x{1}..." -f $partitionCount, $effectiveParallelism) -InformationAction Continue
            $partitionResults = @(Invoke-BoundedRunspacePool -InputObject $partitionIndices -ScriptBlock $comparePartitionScript -ThrottleLimit $effectiveParallelism -ActivityName 'Partitioned signature compare' -DisableInAzure -ArgumentList @([string]$Expected.DirectoryPath, [string]$Actual.DirectoryPath))
        }
        else {
            Write-Information ("  Comparing {0} signature partition(s) single-threaded..." -f $partitionCount) -InformationAction Continue
            $partitionResults = [System.Collections.Generic.List[object]]::new()
            $progressState = New-ProgressMarkerState -ActivityName 'Compared signature partitions' -ProgressInterval ([Math]::Max(1, [Math]::Min(16, [math]::Ceiling($partitionCount / 8.0)))) -HeartbeatIntervalSeconds $Script:DashboardValidationHeartbeatSeconds -CheckInterval 1
            foreach ($index in $partitionIndices) {
                $partitionResults.Add((& $comparePartitionScript $index ([string]$Expected.DirectoryPath) ([string]$Actual.DirectoryPath)))
                Write-ProgressMarker -State $progressState -Count $partitionResults.Count -UnitLabel 'partition(s)'
            }

            $partitionResults = @($partitionResults)
        }

        foreach ($partitionResult in @($partitionResults | Sort-Object PartitionIndex)) {
            $missingCount += $partitionResult.MissingCount
            $extraCount += $partitionResult.ExtraCount

            foreach ($sample in @($partitionResult.MissingSamples)) {
                if ($missingSamples.Count -ge 5) {
                    break
                }

                $missingSamples.Add([string]$sample)
            }

            foreach ($sample in @($partitionResult.ExtraSamples)) {
                if ($extraSamples.Count -ge 5) {
                    break
                }

                $extraSamples.Add([string]$sample)
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
    $expectedProgressState = New-ProgressMarkerState -ActivityName ("Indexed {0}" -f $ExpectedLabel) -ProgressInterval $ProgressInterval -HeartbeatIntervalSeconds $Script:DashboardValidationHeartbeatSeconds -CheckInterval ([Math]::Min($ProgressInterval, 10000))
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
        Write-ProgressMarker -State $expectedProgressState -Count $expectedCount -UnitLabel 'row signature(s)'
    }

    $extraCount = 0
    $actualCount = 0
    $extraSamples = [System.Collections.Generic.List[string]]::new()
    $actualProgressState = New-ProgressMarkerState -ActivityName ("Compared {0}" -f $ActualLabel) -ProgressInterval $ProgressInterval -HeartbeatIntervalSeconds $Script:DashboardValidationHeartbeatSeconds -CheckInterval ([Math]::Min($ProgressInterval, 10000))
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
        Write-ProgressMarker -State $actualProgressState -Count $actualCount -UnitLabel 'row signature(s)'
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
        [switch]$SkipObservedWindowMerge,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 2147483647)]
        [int]$ExpectedTotalCount = 0
    )

    $vendorSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $processedCount = 0
    $progressState = New-ProgressMarkerState -ActivityName 'Indexed source vendors' -ProgressInterval $Script:DashboardValidationProgressInterval -HeartbeatIntervalSeconds $Script:DashboardValidationHeartbeatSeconds -CheckInterval 10000 -TotalCount $ExpectedTotalCount
    Read-SourceAuditRecordStream -ExportsPath $ExportsPath -SkipObservedWindowMerge:$SkipObservedWindowMerge | ForEach-Object {
        $record = $_
        if ((Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -eq $true) {
            $vendor = [string](Get-VulnPropertyValue -InputObject $record -Name 'SoftwareVendor')
            $vendorMatchKey = Get-VendorMatchKey -Vendor $vendor
            if (-not [string]::IsNullOrWhiteSpace($vendorMatchKey)) {
                [void]$vendorSet.Add($vendorMatchKey)
            }

            $processedCount++
            Write-ProgressMarker -State $progressState -Count $processedCount -UnitLabel 'row(s)'
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

        [Parameter(Mandatory = $false)]
        $AdvancedHuntingInventory = @{},

        [Parameter(Mandatory = $false)]
        $NvdCveData = @{},

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$VendorSet,

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge,

        [Parameter(Mandatory = $false)]
        [ref]$FirstLastSwappedCount = ([ref]0),

        [Parameter(Mandatory = $false)]
        [ref]$MissingMachineCount = ([ref]0),

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 2147483647)]
        [int]$ExpectedTotalCount = 0
    )

    $deviceProfiles = @{}
    $cveEnrichmentCache = @{}
    $processedCount = 0
    $progressState = New-ProgressMarkerState -ActivityName 'Canonicalized source' -ProgressInterval $Script:DashboardValidationProgressInterval -HeartbeatIntervalSeconds $Script:DashboardValidationHeartbeatSeconds -CheckInterval 10000 -TotalCount $ExpectedTotalCount

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
        $cveEnrichment = if (-not [string]::IsNullOrWhiteSpace($cveId) -and $cveEnrichmentCache.ContainsKey($cveId)) {
            $cveEnrichmentCache[$cveId]
        }
        else {
            $resolvedCveEnrichment = Get-SourceCveEnrichment -CveId $cveId -AdvancedHunting $AdvancedHunting -NvdCveData $NvdCveData -VendorSet $VendorSet
            if (-not [string]::IsNullOrWhiteSpace($cveId)) {
                $cveEnrichmentCache[$cveId] = $resolvedCveEnrichment
            }

            $resolvedCveEnrichment
        }
        $inventoryEnrichment = Get-SourceInventoryEnrichment -Record $record -AdvancedHuntingInventory $AdvancedHuntingInventory

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
            SoftwareVendor = [string](Get-VulnPropertyValue -InputObject $record -Name 'SoftwareVendor')
            SoftwareName = [string](Get-VulnPropertyValue -InputObject $record -Name 'SoftwareName')
            SoftwareVersion = [string](Get-VulnPropertyValue -InputObject $record -Name 'SoftwareVersion')
            RecommendationReference = [string](Get-VulnPropertyValue -InputObject $record -Name 'RecommendationReference')
            ProductCodeCpe = $inventoryEnrichment.ProductCodeCpe
            EndOfSupportStatus = $inventoryEnrichment.EndOfSupportStatus
            EndOfSupportDate = $inventoryEnrichment.EndOfSupportDate
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
        Write-ProgressMarker -State $progressState -Count $processedCount -UnitLabel 'row(s)'

        Get-CanonicalValidationRowSignature -Row $row
    }
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
    $columnInventoryIndices = $null

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

            $columnInventoryIndices = [int[]]::new($columnDeviceIndices.Length)
            for ($inventoryIndex = 0; $inventoryIndex -lt $columnInventoryIndices.Length; $inventoryIndex++) {
                $columnInventoryIndices[$inventoryIndex] = -1
            }

            $inventoryProperty = [System.Text.Json.JsonElement]::new()
            if ($vulns.TryGetProperty('iv', [ref]$inventoryProperty)) {
                $columnInventoryIndices = Convert-JsonElementToIntArray -Element $inventoryProperty
            }
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
    $progressState = New-ProgressMarkerState -ActivityName 'Canonicalized payload' -ProgressInterval $Script:DashboardValidationProgressInterval -HeartbeatIntervalSeconds $Script:DashboardValidationHeartbeatSeconds -CheckInterval 10000

    function Get-PayloadCanonicalValidationRow {
        param(
            [Parameter(Mandatory = $true)]
            $VulnRecord
        )

        $device = Get-PayloadLookupItem -LookupValues $lookups.devices -Index $VulnRecord[0]
        $cve = Get-PayloadLookupItem -LookupValues $lookups.cves -Index $VulnRecord[1]
        $software = Get-PayloadLookupItem -LookupValues $lookups.software -Index $VulnRecord[2]
        $machineInfo = Get-VulnPropertyValue -InputObject $device -Name 'm'

        $resolvedMachineTags = [System.Collections.Generic.List[string]]::new()
        foreach ($tagIndex in @((Get-VulnPropertyValue -InputObject $device -Name 't'))) {
            if ($null -eq $tagIndex) { continue }
            $tagText = Get-PayloadLookupText -LookupValues $lookups.tags -Index $tagIndex
            if ($null -ne $tagText) {
                $resolvedMachineTags.Add($tagText)
            }
        }

        $resolvedDiskPaths = [System.Collections.Generic.List[string]]::new()
        foreach ($pathIndex in @($VulnRecord[8])) {
            if ($null -eq $pathIndex -or [int]$pathIndex -lt 0) { continue }
            $pathText = Get-PayloadLookupText -LookupValues $lookups.diskPaths -Index $pathIndex
            if ($null -ne $pathText) {
                $resolvedDiskPaths.Add($pathText)
            }
        }

        $resolvedRegistryPaths = [System.Collections.Generic.List[string]]::new()
        foreach ($pathIndex in @($VulnRecord[9])) {
            if ($null -eq $pathIndex -or [int]$pathIndex -lt 0) { continue }
            $pathText = Get-PayloadLookupText -LookupValues $lookups.regPaths -Index $pathIndex
            if ($null -ne $pathText) {
                $resolvedRegistryPaths.Add($pathText)
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
        $softwareVersion = Get-PayloadLookupText -LookupValues $lookups.versions -Index $VulnRecord[3]
        $firstSeenDate = Get-PayloadLookupText -LookupValues $lookups.dates -Index $VulnRecord[4]
        $lastSeenDate = Get-PayloadLookupText -LookupValues $lookups.dates -Index $VulnRecord[5]
        $updateObject = if ($VulnRecord[7] -ge 0) { Get-PayloadLookupItem -LookupValues $lookups.updates -Index $VulnRecord[7] } else { $null }
        $updateName = if ($updateObject) { Get-VulnPropertyValue -InputObject $updateObject -Name 'n' } else { $null }
        $updateId = if ($updateObject) { Get-VulnPropertyValue -InputObject $updateObject -Name 'id' } else { $null }
        $updateUrl = if ($updateObject) { Get-VulnPropertyValue -InputObject $updateObject -Name 'url' } else { $null }
        $inventoryLookupValues = Get-VulnPropertyValue -InputObject $lookups -Name 'inventory'
        $inventoryObject = if ($null -ne $inventoryLookupValues -and $VulnRecord.Count -gt 10 -and [int]$VulnRecord[10] -ge 0) {
            Get-PayloadLookupItem -LookupValues $inventoryLookupValues -Index $VulnRecord[10]
        }
        else {
            $null
        }
        $nvdWeaknesses = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $cve -Name 'nw'))

        return [PSCustomObject]@{
            DeviceId = [string](Get-VulnPropertyValue -InputObject $device -Name 'id')
            DeviceName = [string](Get-VulnPropertyValue -InputObject $device -Name 'n')
            RbacGroupName = if ($groupName -and -not [string]::IsNullOrWhiteSpace([string]$groupName)) { [string]$groupName } else { '(none)' }
            OSPlatform = if ($null -ne $platformName) { [string]$platformName } else { $null }
            OSVersion = [string](Get-VulnPropertyValue -InputObject $device -Name 'ov')
            MachineTags = if ($resolvedMachineTags.Count -gt 0) { @($resolvedMachineTags) } else { $null }
            MachineInfo = if ($machineInfo) {
                [PSCustomObject]@{
                    ip = [string](Get-VulnPropertyValue -InputObject $machineInfo -Name 'ip')
                    eip = [string](Get-VulnPropertyValue -InputObject $machineInfo -Name 'eip')
                    hs = [string](Get-VulnPropertyValue -InputObject $machineInfo -Name 'hs')
                    rs = [string](Get-VulnPropertyValue -InputObject $machineInfo -Name 'rs')
                    el = [string](Get-VulnPropertyValue -InputObject $machineInfo -Name 'el')
                    dv = [string](Get-VulnPropertyValue -InputObject $machineInfo -Name 'dv')
                    mb = [string](Get-VulnPropertyValue -InputObject $machineInfo -Name 'mb')
                    aad = ((Get-VulnPropertyValue -InputObject $machineInfo -Name 'aad') -eq $true)
                    ls = Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $machineInfo -Name 'ls')
                    fs = Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $machineInfo -Name 'fs')
                }
            }
            else {
                $null
            }
            CveId = [string](Get-VulnPropertyValue -InputObject $cve -Name 'id')
            CvssScore = Get-VulnPropertyValue -InputObject $cve -Name 'sc'
            VulnerabilitySeverityLevel = if ($null -ne $severityName) { [string]$severityName } else { $null }
            ExploitabilityLevel = if ($null -ne $exploitabilityName) { [string]$exploitabilityName } else { $null }
            CveBatchUrl = [string](Get-VulnPropertyValue -InputObject $cve -Name 'u')
            CveBatchTitle = if ($null -ne $batchTitle) { [string]$batchTitle } else { $null }
            PublishedDate = Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $cve -Name 'pd')
            VulnerabilityDescription = [string](Get-VulnPropertyValue -InputObject $cve -Name 'desc')
            EpssScore = Get-VulnPropertyValue -InputObject $cve -Name 'ep'
            AffectedSoftware = if ($resolvedAffectedSoftware.Count -gt 0) { @($resolvedAffectedSoftware) } else { $null }
            IsExploitAvailable = if ($null -eq (Get-VulnPropertyValue -InputObject $cve -Name 'ea')) { $null } else { ((Get-VulnPropertyValue -InputObject $cve -Name 'ea') -eq $true) }
            NvdLastModifiedDate = Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $cve -Name 'nlm')
            NvdBaseScore = Get-VulnPropertyValue -InputObject $cve -Name 'nbs'
            NvdBaseSeverity = [string](Get-VulnPropertyValue -InputObject $cve -Name 'nsv')
            NvdVector = [string](Get-VulnPropertyValue -InputObject $cve -Name 'nvec')
            NvdKevDate = Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $cve -Name 'nkev')
            NvdActionDue = Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $cve -Name 'ndu')
            NvdRequiredAction = [string](Get-VulnPropertyValue -InputObject $cve -Name 'nact')
            NvdWeaknesses = if ($nvdWeaknesses.Count -gt 0) { $nvdWeaknesses } else { $null }
            SoftwareVendor = if ($null -ne $softwareVendor) { [string]$softwareVendor } else { $null }
            SoftwareName = [string](Get-VulnPropertyValue -InputObject $software -Name 'n')
            SoftwareVersion = if ($null -ne $softwareVersion) { [string]$softwareVersion } else { $null }
            RecommendationReference = [string](Get-VulnPropertyValue -InputObject $software -Name 'r')
            ProductCodeCpe = if ($inventoryObject) { [string](Get-VulnPropertyValue -InputObject $inventoryObject -Name 'cpe') } else { $null }
            EndOfSupportStatus = if ($inventoryObject) { [string](Get-VulnPropertyValue -InputObject $inventoryObject -Name 'eos') } else { $null }
            EndOfSupportDate = if ($inventoryObject) { (Convert-ToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $inventoryObject -Name 'eod')) } else { $null }
            FirstSeenTimestamp = if ($null -ne $firstSeenDate) { (Convert-ToYmdDate -DateValue $firstSeenDate) ?? '' } else { '' }
            LastSeenTimestamp = if ($null -ne $lastSeenDate) { (Convert-ToYmdDate -DateValue $lastSeenDate) ?? '' } else { '' }
            SecurityUpdateAvailable = ($VulnRecord[6] -eq 1)
            RecommendedSecurityUpdate = if ($updateObject) { [string]$(if ($null -ne $updateName) { $updateName } else { $updateObject }) } else { $null }
            RecommendedSecurityUpdateId = if ($updateObject -and $null -ne $updateId) { [string]$updateId } else { $null }
            RecommendedSecurityUpdateUrl = if ($updateObject -and $null -ne $updateUrl) { [string]$updateUrl } else { $null }
            DiskPaths = if ($resolvedDiskPaths.Count -gt 0) { @($resolvedDiskPaths) } else { $null }
            RegistryPaths = if ($resolvedRegistryPaths.Count -gt 0) { @($resolvedRegistryPaths) } else { $null }
        }
    }

    if ($vulnsFormat -eq 'rows-v1') {
        $payloadRows = @($rowsPayload)
        if ($payloadRows.Count -gt 0) {
            $firstPayloadRow = $payloadRows[0]
            $firstPayloadRowIsNested = ($null -ne $firstPayloadRow -and $firstPayloadRow -is [System.Collections.IEnumerable] -and $firstPayloadRow -isnot [string])
            if (-not $firstPayloadRowIsNested) {
                $payloadRows = ,$payloadRows
            }
        }

        $processedCount = 0
        foreach ($v in $payloadRows) {
            if ($null -eq $v) { continue }
            $processedCount++
            Write-ProgressMarker -State $progressState -Count $processedCount -UnitLabel 'row(s)'

            Get-CanonicalValidationRowSignature -Row (Get-PayloadCanonicalValidationRow -VulnRecord $v)
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

    $vulnCount = $columnDeviceIndices.Length
    for ($i = 0; $i -lt $vulnCount; $i++) {
        Write-ProgressMarker -State $progressState -Count ($i + 1) -UnitLabel 'row(s)'

        $payloadRecord = @(
            $columnDeviceIndices[$i]
            $columnCveIndices[$i]
            $columnSoftwareIndices[$i]
            $columnVersionIndices[$i]
            $columnFirstSeenIndices[$i]
            $columnLastSeenIndices[$i]
            $columnUpdateAvailability[$i]
            $columnUpdateIndices[$i]
            ,$columnDiskPathIndices[$i]
            ,$columnRegistryPathIndices[$i]
            $(if ($null -ne $columnInventoryIndices -and $i -lt $columnInventoryIndices.Length) { $columnInventoryIndices[$i] } else { -1 })
        )

        Get-CanonicalValidationRowSignature -Row (Get-PayloadCanonicalValidationRow -VulnRecord $payloadRecord)
    }
}

function Get-StreamingSemanticValidationAttestation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry,

        [Parameter(Mandatory = $true)]
        [string]$DashboardPayloadSha256,

        [Parameter(Mandatory = $true)]
        [int]$DashboardPayloadRowCount,

        [Parameter(Mandatory = $true)]
        [string]$CachedPayloadSha256,

        [Parameter(Mandatory = $true)]
        [int]$CachedPayloadRowCount
    )

    if ($Script:DashboardValidationForceFull) {
        return $null
    }

    if (($DashboardPayloadSha256 -ne $CachedPayloadSha256) -or ($DashboardPayloadRowCount -ne $CachedPayloadRowCount)) {
        return $null
    }

    $attestation = if ($PayloadCacheEntry.Manifest.PSObject.Properties['SemanticValidationAttestation']) {
        $PayloadCacheEntry.Manifest.SemanticValidationAttestation
    }
    else {
        $null
    }

    if ($null -eq $attestation) {
        return $null
    }

    if ([string]$attestation.ValidationLogicVersion -ne (Get-DashboardSemanticValidationLogicVersion)) {
        return $null
    }

    if ([string]$attestation.SourceFingerprint -ne [string]$PayloadCacheEntry.Fingerprint) {
        return $null
    }

    if ([string]$attestation.PayloadSha256 -ne $CachedPayloadSha256) {
        return $null
    }

    if ([int]$attestation.PayloadRowCount -ne $CachedPayloadRowCount) {
        return $null
    }

    return $attestation
}

function New-AttestedStreamingDashboardAuditResult {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only assembles an in-memory attested audit result record.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResolvedHtmlPath,

        [Parameter(Mandatory = $true)]
        [string]$ResolvedExportsPath,

        [Parameter(Mandatory = $true)]
        $PayloadCacheEntry,

        [Parameter(Mandatory = $true)]
        $Attestation,

        [Parameter(Mandatory = $true)]
        [string]$DashboardPayloadSha256,

        [Parameter(Mandatory = $true)]
        [int]$DashboardPayloadRowCount,

        [Parameter(Mandatory = $true)]
        [string]$CachedPayloadSha256,

        [Parameter(Mandatory = $true)]
        [int]$CachedPayloadRowCount
    )

    $phaseTimings = [PSCustomObject]@{
        MachineLoadElapsedSeconds = 0
        AdvancedHuntingLoadElapsedSeconds = 0
        SourceMaterializationElapsedSeconds = $null
        PayloadLoadElapsedSeconds = $null
        VendorIndexElapsedSeconds = 0
        SourceSignatureElapsedSeconds = 0
        PayloadSignatureElapsedSeconds = 0
        RowComparisonElapsedSeconds = $null
        EnrichmentAuditElapsedSeconds = $null
        ReportComparisonsElapsedSeconds = $null
        DuplicateIdentityElapsedSeconds = $null
        OpenStateElapsedSeconds = $null
        ComparisonElapsedSeconds = 0
        BaselineAuditElapsedSeconds = $null
        BaselineCoverageElapsedSeconds = $null
        LegacyFixtureRegressionElapsedSeconds = $null
        TotalElapsedSeconds = 0
    }

    return [PSCustomObject]@{
        GeneratedOn = (Get-Date).ToString('o')
        HtmlPath = $ResolvedHtmlPath
        ExportsPath = $ResolvedExportsPath
        AuditMode = 'streaming-large-dataset-attested'
        PhaseTimings = $phaseTimings
        Source = [PSCustomObject]@{
            RowCount = [int]$Attestation.SourceRowCount
            MissingMachineCount = [int]$Attestation.SourceMissingMachineCount
            FirstLastSwappedCount = [int]$Attestation.SourceFirstLastSwappedCount
            UniqueVendors = @($Attestation.SourceUniqueVendors)
            Verification = 'Semantic parity was satisfied by a versioned validation attestation.'
            InputMode = if (Sync-VulnContentStoreSidecar -BasePath $ResolvedExportsPath) { 'content-store' } else { 'normalized-vuln-store' }
        }
        SourceMetadata = if ($PayloadCacheEntry.Manifest.PSObject.Properties['SourceMetadata']) { $PayloadCacheEntry.Manifest.SourceMetadata } else { $null }
        Dashboard = [PSCustomObject]@{
            RowCount = $DashboardPayloadRowCount
            Quality = $PayloadCacheEntry.Manifest.Quality
        }
        RowComparison = [PSCustomObject]@{
            Match = $true
            ExpectedRows = [int]$Attestation.SourceRowCount
            ActualRows = $DashboardPayloadRowCount
            MissingCount = 0
            ExtraCount = 0
            MissingSamples = @()
            ExtraSamples = @()
            VerificationMode = 'attested-semantic-validation'
            ComparisonStorage = 'attested-manifest'
        }
        EnrichmentAudit = [PSCustomObject]@{
            DashboardCveCount = [int]$PayloadCacheEntry.Manifest.CveCount
            PublishedDateMismatchCount = 0
            DescriptionMismatchCount = 0
            EpssMismatchCount = 0
            AffectedSoftwareMismatchCount = 0
            ExploitAvailableMismatchCount = 0
            NvdLastModifiedMismatchCount = 0
            NvdBaseScoreMismatchCount = 0
            NvdBaseSeverityMismatchCount = 0
            NvdVectorMismatchCount = 0
            NvdKevMismatchCount = 0
            NvdActionDueMismatchCount = 0
            NvdRequiredActionMismatchCount = 0
            NvdWeaknessMismatchCount = 0
            Samples = @()
            Mode = 'Satisfied by validation attestation'
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
            Match = $true
            DashboardPayloadSha256 = $DashboardPayloadSha256
            CachedPayloadSha256 = $CachedPayloadSha256
            DashboardRowCount = $DashboardPayloadRowCount
            CachedPayloadRowCount = $CachedPayloadRowCount
            CachedPayloadPath = $PayloadCacheEntry.PayloadPath
        }
        SemanticParity = [PSCustomObject]@{
            Match = $true
            Mode = 'attested-semantic-validation'
            IncludesEnrichment = $true
            IncludesMachineInfo = $true
            ComparisonStorage = 'attested-manifest'
            ComparisonPayloadSource = 'cached-payload'
            SourceSignatureCacheUsed = $false
            PayloadSignatureCacheUsed = $false
            PartitionCount = if ($Attestation.PSObject.Properties['PartitionCount']) { [int]$Attestation.PartitionCount } else { $null }
            SourceSignatureElapsedSeconds = 0
            PayloadSignatureElapsedSeconds = 0
            ComparisonElapsedSeconds = 0
            PhaseTimings = $phaseTimings
            PayloadByteParityMatch = $true
            AttestationUsed = $true
            ValidationLogicVersion = [string]$Attestation.ValidationLogicVersion
            ValidatedOnUtc = [string]$Attestation.ValidatedOnUtc
        }
        Attestation = [PSCustomObject]@{
            Used = $true
            Source = 'normalized-payload-manifest'
            ValidationLogicVersion = [string]$Attestation.ValidationLogicVersion
            ValidatedOnUtc = [string]$Attestation.ValidatedOnUtc
            SourceFingerprint = [string]$Attestation.SourceFingerprint
            PayloadSha256 = [string]$Attestation.PayloadSha256
        }
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
    $payloadParityMatch = (($dashboardPayloadSha256 -eq $cachedPayloadSha256) -and ($dashboardPayloadRowCount -eq $cachedPayloadRowCount))
    $semanticAttestation = Get-StreamingSemanticValidationAttestation -PayloadCacheEntry $PayloadCacheEntry -DashboardPayloadSha256 $dashboardPayloadSha256 -DashboardPayloadRowCount $dashboardPayloadRowCount -CachedPayloadSha256 $cachedPayloadSha256 -CachedPayloadRowCount $cachedPayloadRowCount

    if ($null -ne $semanticAttestation) {
        Write-Information '  Dashboard payload matches a previously validated normalized payload attestation; skipping full semantic replay.' -InformationAction Continue
        return (New-AttestedStreamingDashboardAuditResult -ResolvedHtmlPath $ResolvedHtmlPath -ResolvedExportsPath $ResolvedExportsPath -PayloadCacheEntry $PayloadCacheEntry -Attestation $semanticAttestation -DashboardPayloadSha256 $dashboardPayloadSha256 -DashboardPayloadRowCount $dashboardPayloadRowCount -CachedPayloadSha256 $cachedPayloadSha256 -CachedPayloadRowCount $cachedPayloadRowCount)
    }

    $sourceSignatureSet = $null
    $payloadSignatureSet = $null
    $sourceElapsedSeconds = 0
    $payloadElapsedSeconds = 0
    $comparisonElapsedSeconds = 0
    $machineLoadElapsedSeconds = 0
    $advancedHuntingLoadElapsedSeconds = 0
    $vendorIndexElapsedSeconds = 0
    $comparisonStorage = 'partitioned-hash-files'
    $comparisonPayloadSource = 'dashboard-payload'
    $dashboardPayloadPath = $null
    $comparisonPayloadPath = $null
    $comparisonPayloadLabel = 'dashboard'
    $machines = $null
    $advancedHunting = $null
    $advancedHuntingInventory = $null
    $nvdCveData = $null
    $vendorSet = $null
    $sourceUniqueVendors = @()
    $sourceFirstLastSwappedCount = 0
    $sourceMissingMachineCount = 0
    $sourceSignatureCacheUsed = $false
    $payloadSignatureCacheUsed = $false
    $auditStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        Write-Information '  Streaming semantic parity audit for large dataset directly against source exports...' -InformationAction Continue
        Write-Information ("  Validation markers: progress every {0:N0} row(s), heartbeat every {1}s." -f $Script:DashboardValidationProgressInterval, $Script:DashboardValidationHeartbeatSeconds) -InformationAction Continue
        if ($Script:DashboardValidationPartitionCompareParallelism -gt 1) {
            Write-Information ("  Requested partition compare runspace throttle: {0}" -f $Script:DashboardValidationPartitionCompareParallelism) -InformationAction Continue
        }

        if ($payloadParityMatch) {
            $comparisonPayloadSource = 'cached-payload'
            $comparisonPayloadPath = $PayloadCacheEntry.PayloadPath
            $comparisonPayloadLabel = 'dashboard-cache'
            Clear-StalePayloadSignatureCaches -PayloadCacheEntry $PayloadCacheEntry
            Write-Information '  Dashboard payload matches the normalized payload cache; reusing cached payload for semantic comparison.' -InformationAction Continue
        }
        else {
            $dashboardPayloadPath = Get-DashboardEmbeddedPayloadTempPath -HtmlPath $ResolvedHtmlPath
            $comparisonPayloadPath = $dashboardPayloadPath
            Write-Information '  Dashboard payload differs from the normalized payload cache; comparing dashboard payload directly against source exports.' -InformationAction Continue
        }

        $currentSourceFingerprint = Get-DashboardPayloadCacheFingerprint -BasePath $ResolvedExportsPath -SkipObservedWindowMerge:$skipObservedWindowMerge
        if (-not [string]::IsNullOrWhiteSpace($currentSourceFingerprint)) {
            Clear-StaleSourceSignatureCaches -PayloadCacheEntry $PayloadCacheEntry -ExpectedSourceFingerprint $currentSourceFingerprint
        }

        try {
            $sourceStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            if (-not [string]::IsNullOrWhiteSpace($currentSourceFingerprint)) {
                $sourceSignatureSet = Get-CachedSourceSignatureSet -PayloadCacheEntry $PayloadCacheEntry -ExpectedSourceFingerprint $currentSourceFingerprint
            }

            if ($null -ne $sourceSignatureSet) {
                $sourceSignatureCacheUsed = $true
                $sourceMissingMachineCount = [int]$sourceSignatureSet.SourceMissingMachineCount
                $sourceFirstLastSwappedCount = [int]$sourceSignatureSet.SourceFirstLastSwappedCount
                $sourceUniqueVendors = @($sourceSignatureSet.SourceUniqueVendors)
                Write-Information '  Reusing cached source signature set for semantic comparison.' -InformationAction Continue
            }
            else {
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

                $vendorIndexStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $vendorSet = Get-SourceVendorSetForAudit -ExportsPath $ResolvedExportsPath -SkipObservedWindowMerge:$skipObservedWindowMerge -ExpectedTotalCount $cachedPayloadRowCount
                $vendorIndexStopwatch.Stop()
                $vendorIndexElapsedSeconds = [math]::Round($vendorIndexStopwatch.Elapsed.TotalSeconds, 2)
                $sourceUniqueVendors = @($vendorSet | Sort-Object)

                if (-not [string]::IsNullOrWhiteSpace($currentSourceFingerprint)) {
                        $sourceSignatureSet = Write-PartitionedSignatureSet -Label 'source' -ProgressInterval $Script:DashboardValidationProgressInterval -OutputDirectoryPath (Get-SourceSignatureCacheDirectory -PayloadCacheEntry $PayloadCacheEntry -SourceFingerprint $currentSourceFingerprint -Create) -Persistent -ExpectedTotalCount $cachedPayloadRowCount -SignatureSource {
                        Read-SourceCanonicalSignatureStream `
                            -ExportsPath $ResolvedExportsPath `
                            -Machines $machines `
                            -AdvancedHunting $advancedHunting `
                            -AdvancedHuntingInventory $advancedHuntingInventory `
                            -NvdCveData $nvdCveData `
                            -VendorSet $vendorSet `
                            -SkipObservedWindowMerge:$skipObservedWindowMerge `
                            -FirstLastSwappedCount ([ref]$sourceFirstLastSwappedCount) `
                            -MissingMachineCount ([ref]$sourceMissingMachineCount) `
                            -ExpectedTotalCount $cachedPayloadRowCount
                    }
                    Write-CachedSourceSignatureSetMetadata -PayloadCacheEntry $PayloadCacheEntry -SourceFingerprint $currentSourceFingerprint -SignatureSet $sourceSignatureSet -SourceMissingMachineCount $sourceMissingMachineCount -SourceFirstLastSwappedCount $sourceFirstLastSwappedCount -SourceUniqueVendors $sourceUniqueVendors | Out-Null
                    Write-Information '  Cached source signature set for future semantic comparisons.' -InformationAction Continue
                }
                else {
                        $sourceSignatureSet = Write-PartitionedSignatureSet -Label 'source' -ProgressInterval $Script:DashboardValidationProgressInterval -ExpectedTotalCount $cachedPayloadRowCount -SignatureSource {
                        Read-SourceCanonicalSignatureStream `
                            -ExportsPath $ResolvedExportsPath `
                            -Machines $machines `
                            -AdvancedHunting $advancedHunting `
                            -AdvancedHuntingInventory $advancedHuntingInventory `
                            -NvdCveData $nvdCveData `
                            -VendorSet $vendorSet `
                            -SkipObservedWindowMerge:$skipObservedWindowMerge `
                            -FirstLastSwappedCount ([ref]$sourceFirstLastSwappedCount) `
                            -MissingMachineCount ([ref]$sourceMissingMachineCount) `
                            -ExpectedTotalCount $cachedPayloadRowCount
                    }
                }
            }
            $sourceStopwatch.Stop()
            $sourceElapsedSeconds = [math]::Round($sourceStopwatch.Elapsed.TotalSeconds, 2)
            Write-Information ("  Source signature pass completed in {0:N2}s" -f $sourceElapsedSeconds) -InformationAction Continue

            $payloadStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            if ($payloadParityMatch) {
                $payloadSignatureSet = Get-CachedPayloadSignatureSet -PayloadCacheEntry $PayloadCacheEntry -ExpectedPayloadSha256 $cachedPayloadSha256 -ExpectedPayloadRowCount $cachedPayloadRowCount
                if ($null -ne $payloadSignatureSet) {
                    $payloadSignatureCacheUsed = $true
                    Write-Information '  Reusing cached payload signature set for semantic comparison.' -InformationAction Continue
                }
                else {
                    $payloadSignatureSet = Write-PartitionedSignatureSet -Label $comparisonPayloadLabel -ProgressInterval $Script:DashboardValidationProgressInterval -OutputDirectoryPath (Get-PayloadSignatureCacheDirectory -PayloadCacheEntry $PayloadCacheEntry -Create) -Persistent -ExpectedTotalCount $cachedPayloadRowCount -SignatureSource {
                        Read-PayloadCanonicalSignatureStream -PayloadPath $comparisonPayloadPath
                    }
                    Write-CachedPayloadSignatureSetMetadata -PayloadCacheEntry $PayloadCacheEntry -PayloadSha256 $cachedPayloadSha256 -PayloadRowCount $cachedPayloadRowCount -SignatureSet $payloadSignatureSet | Out-Null
                    Write-Information '  Cached payload signature set for future semantic comparisons.' -InformationAction Continue
                }
            }
            else {
                $payloadSignatureSet = Write-PartitionedSignatureSet -Label $comparisonPayloadLabel -ProgressInterval $Script:DashboardValidationProgressInterval -ExpectedTotalCount $dashboardPayloadRowCount -SignatureSource {
                    Read-PayloadCanonicalSignatureStream -PayloadPath $comparisonPayloadPath
                }
            }
            $payloadStopwatch.Stop()
            $payloadElapsedSeconds = [math]::Round($payloadStopwatch.Elapsed.TotalSeconds, 2)
            Write-Information ("  Comparison payload signature pass completed in {0:N2}s" -f $payloadElapsedSeconds) -InformationAction Continue

            $comparisonStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $rowComparison = Compare-PartitionedSignatureSet -Expected $sourceSignatureSet -Actual $payloadSignatureSet
            $comparisonStopwatch.Stop()
            $comparisonElapsedSeconds = [math]::Round($comparisonStopwatch.Elapsed.TotalSeconds, 2)
            Write-Information ("  Partitioned signature comparison completed in {0:N2}s" -f $comparisonElapsedSeconds) -InformationAction Continue
            $rowComparison | Add-Member -NotePropertyName VerificationMode -NotePropertyValue 'canonical-row-signature-stream'
            $rowComparison | Add-Member -NotePropertyName ComparisonStorage -NotePropertyValue 'partitioned-hash-files'
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
        if ($null -ne $advancedHuntingInventory) { $advancedHuntingInventory = $null }
        if ($null -ne $nvdCveData) { $nvdCveData = $null }
        if ($null -ne $vendorSet) { $vendorSet = $null }
        Invoke-FullGarbageCollection
    }

    $auditStopwatch.Stop()
    $totalElapsedSeconds = [math]::Round($auditStopwatch.Elapsed.TotalSeconds, 2)
    $comparisonPartitionCount = if ($sourceSignatureSet) { [int]$sourceSignatureSet.PartitionCount } elseif ($payloadSignatureSet) { [int]$payloadSignatureSet.PartitionCount } else { $null }
    $phaseTimings = [PSCustomObject]@{
        MachineLoadElapsedSeconds = $machineLoadElapsedSeconds
        AdvancedHuntingLoadElapsedSeconds = $advancedHuntingLoadElapsedSeconds
        SourceMaterializationElapsedSeconds = $null
        PayloadLoadElapsedSeconds = $null
        VendorIndexElapsedSeconds = $vendorIndexElapsedSeconds
        SourceSignatureElapsedSeconds = $sourceElapsedSeconds
        PayloadSignatureElapsedSeconds = $payloadElapsedSeconds
        RowComparisonElapsedSeconds = $null
        EnrichmentAuditElapsedSeconds = $null
        ReportComparisonsElapsedSeconds = $null
        DuplicateIdentityElapsedSeconds = $null
        OpenStateElapsedSeconds = $null
        ComparisonElapsedSeconds = $comparisonElapsedSeconds
        BaselineAuditElapsedSeconds = $null
        BaselineCoverageElapsedSeconds = $null
        LegacyFixtureRegressionElapsedSeconds = $null
        TotalElapsedSeconds = $totalElapsedSeconds
    }

    if ($payloadParityMatch -and $rowComparison.Match) {
        $semanticAttestation = [ordered]@{
            ValidationLogicVersion = Get-DashboardSemanticValidationLogicVersion
            ValidatedOnUtc = (Get-Date).ToUniversalTime().ToString('o')
            SourceFingerprint = [string]$PayloadCacheEntry.Fingerprint
            PayloadSha256 = $cachedPayloadSha256
            PayloadRowCount = $cachedPayloadRowCount
            SourceRowCount = [int]$rowComparison.ExpectedRows
            SourceMissingMachineCount = $sourceMissingMachineCount
            SourceFirstLastSwappedCount = $sourceFirstLastSwappedCount
            SourceUniqueVendors = @($sourceUniqueVendors)
            ComparisonStorage = $comparisonStorage
            ComparisonPayloadSource = $comparisonPayloadSource
            PartitionCount = $comparisonPartitionCount
            IncludesEnrichment = $true
            IncludesMachineInfo = $true
        }

        $updatedManifest = Set-NormalizedPayloadSemanticValidationAttestation -ManifestPath $PayloadCacheEntry.ManifestPath -ExpectedFingerprint $PayloadCacheEntry.Fingerprint -Attestation $semanticAttestation
        if ($null -ne $updatedManifest) {
            $PayloadCacheEntry.Manifest = $updatedManifest
        }

        $null = Set-DashboardValidationSidecarSemanticAttestation -HtmlPath $ResolvedHtmlPath -Attestation $semanticAttestation
    }

    Write-Information ("  Audit phase timing summary: machine load {0:N2}s; Advanced Hunting load {1:N2}s; vendor index {2:N2}s; source signatures {3:N2}s; payload signatures {4:N2}s; compare {5:N2}s; total {6:N2}s" -f $machineLoadElapsedSeconds, $advancedHuntingLoadElapsedSeconds, $vendorIndexElapsedSeconds, $sourceElapsedSeconds, $payloadElapsedSeconds, $comparisonElapsedSeconds, $totalElapsedSeconds) -InformationAction Continue

    return [PSCustomObject]@{
        GeneratedOn = (Get-Date).ToString('o')
        HtmlPath = $ResolvedHtmlPath
        ExportsPath = $ResolvedExportsPath
        AuditMode = 'streaming-large-dataset'
        PhaseTimings = $phaseTimings
        Source = [PSCustomObject]@{
            RowCount = [int]$rowComparison.ExpectedRows
            MissingMachineCount = $sourceMissingMachineCount
            FirstLastSwappedCount = $sourceFirstLastSwappedCount
            UniqueVendors = $sourceUniqueVendors
            Verification = 'Semantic parity was streamed directly from the current exports.'
            InputMode = if (Sync-VulnContentStoreSidecar -BasePath $ResolvedExportsPath) { 'content-store' } else { 'normalized-vuln-store' }
        }
        SourceMetadata = if ($PayloadCacheEntry.Manifest.PSObject.Properties['SourceMetadata']) { $PayloadCacheEntry.Manifest.SourceMetadata } else { $null }
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
            ExploitAvailableMismatchCount = 0
            NvdLastModifiedMismatchCount = 0
            NvdBaseScoreMismatchCount = 0
            NvdBaseSeverityMismatchCount = 0
            NvdVectorMismatchCount = 0
            NvdKevMismatchCount = 0
            NvdActionDueMismatchCount = 0
            NvdRequiredActionMismatchCount = 0
            NvdWeaknessMismatchCount = 0
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
            SourceSignatureCacheUsed = $sourceSignatureCacheUsed
            PayloadSignatureCacheUsed = $payloadSignatureCacheUsed
            PartitionCount = $comparisonPartitionCount
            SourceSignatureElapsedSeconds = $sourceElapsedSeconds
            PayloadSignatureElapsedSeconds = $payloadElapsedSeconds
            ComparisonElapsedSeconds = $comparisonElapsedSeconds
            PhaseTimings = $phaseTimings
            PayloadByteParityMatch = $payloadParityMatch
        }
    }
}
