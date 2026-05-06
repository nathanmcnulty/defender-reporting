#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'build\Import-SharedHelpers.ps1')

function Assert-True {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Get-OutputRecordText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Record
    )

    if ($null -eq $Record) {
        return $null
    }

    if ($Record -is [System.Management.Automation.InformationRecord]) {
        return [string]$Record.MessageData
    }

    return ($Record | Out-String).Trim()
}

function Get-TestVulnRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$CveId,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate,

        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    return [PSCustomObject]@{
        Id                           = $Id
        DeviceId                     = 'device-001'
        DeviceName                   = 'device01.contoso.com'
        RbacGroupName                = 'Servers'
        OSPlatform                   = 'Windows 11'
        OSVersion                    = '10.0.22631'
        MachineTags                  = @('Prod')
        CveId                        = $CveId
        SoftwareVendor               = 'Contoso'
        SoftwareName                 = 'Legacy Agent'
        SoftwareVersion              = $Version
        VulnerabilitySeverityLevel   = 'High'
        CvssScore                    = 8.1
        ExploitabilityLevel          = 'ExploitationLikely'
        RecommendationReference      = 'KB000001'
        RecommendedSecurityUpdate    = 'KB000001'
        RecommendedSecurityUpdateId  = 'KB000001'
        RecommendedSecurityUpdateUrl = 'https://example.invalid/kb000001'
        SecurityUpdateAvailable      = $true
        FirstSeenTimestamp           = $SnapshotDate
        LastSeenTimestamp            = $SnapshotDate
        DiskPaths                    = @('C:\Program Files\Legacy Agent\agent.exe')
        RegistryPaths                = @('HKLM\Software\Contoso\LegacyAgent')
        CveBatchTitle                = 'January 2026 Security Updates'
        CveBatchUrl                  = 'https://example.invalid/batch/jan-2026'
        IsOnboarded                  = $true
    }
}

function Get-TestMachineRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    return [PSCustomObject]@{
        id                    = $Id
        computerDnsName       = ($Id + '.contoso.com')
        rbacGroupName         = 'Servers'
        osPlatform            = 'Windows'
        osVersion             = '10.0.22631'
        machineTags           = @('Prod')
        lastIpAddress         = '10.0.0.10'
        lastExternalIpAddress = '52.0.0.10'
        healthStatus          = 'Active'
        riskScore             = 'Medium'
        exposureLevel         = 'High'
        deviceValue           = 'Normal'
        managedBy             = 'Intune'
        isAadJoined           = $true
        lastSeen              = '2026-04-22T00:00:00Z'
        firstSeen             = '2026-04-01T00:00:00Z'
    }
}

function Get-TestQuarterlyHistoryDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PeriodKey,

        [Parameter(Mandatory = $true)]
        [object[]]$Snapshots
    )

    $latestDate = $null
    foreach ($snapshot in @($Snapshots)) {
        if ($null -eq $snapshot) { continue }
        $snapshotDate = [string](Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
        if ([string]::IsNullOrWhiteSpace($snapshotDate)) { continue }

        if ([string]::IsNullOrWhiteSpace($latestDate) -or ([datetime]$snapshotDate -gt [datetime]$latestDate)) {
            $latestDate = $snapshotDate
        }
    }

    return [PSCustomObject]@{
        year = [int]$PeriodKey.Substring(0, 4)
        period = $PeriodKey
        quarter = [int]$PeriodKey.Substring($PeriodKey.Length - 1)
        latestDate = $latestDate
        snapshots = @($Snapshots)
    }
}

function Test-VulnPropertyHelpersSupportSupportedRowShapes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally refers to multiple supported row shapes.')]
    [CmdletBinding()]
    param()

    $psRow = [PSCustomObject]@{
        Id = 'ps-row-001'
        MachineTags = @('Prod', 'Pilot')
    }
    $dictionaryRow = [ordered]@{
        Id = 'dict-row-001'
        MachineTags = @('Blue')
    }
    $jsonRow = [Newtonsoft.Json.Linq.JObject]::Parse('{"Id":"json-row-001","MachineTags":["Ring0","Ring1"]}')

    Assert-True ([string](Get-VulnPropertyValue -InputObject $psRow -Name 'Id') -eq 'ps-row-001') 'Expected PSObject vulnerability rows to expose Id through Get-VulnPropertyValue.'
    Assert-True ([string](Get-VulnPropertyValue -InputObject $dictionaryRow -Name 'Id') -eq 'dict-row-001') 'Expected dictionary-backed vulnerability rows to expose Id through Get-VulnPropertyValue.'
    Assert-True ([string](Get-VulnPropertyValue -InputObject $jsonRow -Name 'Id') -eq 'json-row-001') 'Expected JObject vulnerability rows to expose Id through Get-VulnPropertyValue.'

    $psTags = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $psRow -Name 'MachineTags'))
    $dictionaryTags = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $dictionaryRow -Name 'MachineTags'))
    $jsonTags = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $jsonRow -Name 'MachineTags'))

    Assert-True ($psTags.Count -eq 2 -and $psTags[0] -eq 'Prod' -and $psTags[1] -eq 'Pilot') 'Expected PSObject array properties to round-trip through Get-VulnPropertyValue.'
    Assert-True ($dictionaryTags.Count -eq 1 -and $dictionaryTags[0] -eq 'Blue') 'Expected dictionary array properties to round-trip through Get-VulnPropertyValue.'
    Assert-True ($jsonTags.Count -eq 2 -and $jsonTags[0] -eq 'Ring0' -and $jsonTags[1] -eq 'Ring1') 'Expected JObject array properties to round-trip through Get-VulnPropertyValue.'

    Assert-True ((Test-VulnPropertyPresence -InputObject $psRow -Name 'Id') -eq $true) 'Expected Test-VulnPropertyPresence to report present PSObject properties.'
    Assert-True ((Test-VulnPropertyPresence -InputObject $psRow -Name 'Missing') -eq $false) 'Expected Test-VulnPropertyPresence to report missing PSObject properties as absent.'
}

function Test-CanonicalLayoutHelper {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('layout-helper-test-' + [guid]::NewGuid().ToString('N'))
    $advancedHuntingCurrentFileName = Split-Path -Leaf (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot)
    $machineCurrentFileName = Split-Path -Leaf (Get-MachineCurrentPath -BasePath $tempRoot)
    $vulnCurrentFileName = Split-Path -Leaf (Get-VulnCurrentPath -BasePath $tempRoot)
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        foreach ($name in @(
            $advancedHuntingCurrentFileName,
            $machineCurrentFileName,
            'Machines_History_2026Q1.json.gz',
            $vulnCurrentFileName,
            'VulnHistory_2026Q1.json.gz',
            'VulnHistoryRows_2026Q1.json.gz'
        )) {
            Set-Content -Path (Join-Path $tempRoot $name) -Value '' -Encoding utf8
        }

        $canonicalLocalNames = @(Get-CanonicalExportStoreFileNames -BasePath $tempRoot)
        Assert-True ($canonicalLocalNames.Count -eq 6) 'Expected six canonical local store files.'

        $existingNames = @(
            $canonicalLocalNames +
            @(
                'Machines_History_20260301T010101Z_deadbeef.json.gz',
                'VulnHistory_2026.json.gz',
                'VulnHistoryRows_2026.json.gz',
                '.dashboard-cache/payloads/payload-old.json.gz',
                'synthetic-manifest.json'
            )
        )
        $staleNames = @(Get-StaleExportStoreArtifactNames -ExistingNames $existingNames -CanonicalNames $canonicalLocalNames)

        Assert-True ('Machines_History_20260301T010101Z_deadbeef.json.gz' -in $staleNames) 'Expected stale machine segment to be removable.'
        Assert-True ('VulnHistory_2026.json.gz' -in $staleNames) 'Expected stale yearly vuln history file to be removable.'
        Assert-True ('VulnHistoryRows_2026.json.gz' -in $staleNames) 'Expected stale yearly vuln history rows file to be removable.'
        Assert-True ('.dashboard-cache/payloads/payload-old.json.gz' -in $staleNames) 'Expected transient dashboard cache artifacts to be removable.'
        Assert-True ('synthetic-manifest.json' -in $staleNames) 'Expected synthetic manifest to be removable when it is no longer part of the desired export set.'
        Assert-True ((Get-QuarterPeriodKeyFromDate -Date '2026-02-15') -eq '2026Q1') 'Quarter helper returned an unexpected value.'
        Assert-True ((Convert-ToYmdDate -DateValue '2/15/2026') -eq '2026-02-15') 'Date normalization returned an unexpected value.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-FileSetFingerprintIgnoresTimestampChange {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('file-fingerprint-stability-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $filePath = Join-Path $tempRoot 'source.json.gz'
        Set-Content -LiteralPath $filePath -Value 'alpha' -NoNewline -Encoding utf8

        $initialFingerprint = Get-FileSetFingerprint -Version 'test-cache-v1' -Files @((Get-Item -LiteralPath $filePath))
        [System.IO.File]::SetLastWriteTimeUtc($filePath, ([datetime]::UtcNow.AddDays(-7)))
        $timestampOnlyFingerprint = Get-FileSetFingerprint -Version 'test-cache-v1' -Files @((Get-Item -LiteralPath $filePath))

        Set-Content -LiteralPath $filePath -Value 'bravo' -NoNewline -Encoding utf8
        $contentChangedFingerprint = Get-FileSetFingerprint -Version 'test-cache-v1' -Files @((Get-Item -LiteralPath $filePath))

        Assert-True ($initialFingerprint -eq $timestampOnlyFingerprint) 'Expected file-set fingerprints to ignore timestamp-only changes when content is unchanged.'
        Assert-True ($timestampOnlyFingerprint -ne $contentChangedFingerprint) 'Expected file-set fingerprints to change when file content changes.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NormalizedPayloadCacheRejectsManifestHashMismatch {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('payload-cache-hash-mismatch-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $currentRow = Get-TestVulnRow -Id 'cache-hash-001' -CveId 'CVE-2026-0801' -SnapshotDate '2026-03-20' -Version '8.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)

        $payloadPath = Join-Path $tempRoot 'payload.json.gz'
        Write-GzipTextFile -Path $payloadPath -Content '{"lookups":{"devices":[],"cves":[]},"vulnsFormat":"rows-v1","vulns":[]}'

        $cacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $payloadPath -VulnCount 0 -DeviceCount 0 -CveCount 0 -Quality ([PSCustomObject]@{ FirstLastSwappedCount = 0 })
        Assert-True ($null -ne $cacheEntry) 'Expected normalized payload cache publish to create an entry.'
        Assert-True ($null -ne (Get-NormalizedPayloadCacheEntry -BasePath $tempRoot)) 'Expected normalized payload cache entry to be reusable before corruption.'

        Set-Content -LiteralPath $cacheEntry.PayloadPath -Value 'corrupt' -NoNewline -Encoding utf8
        $cacheMiss = Get-NormalizedPayloadCacheEntry -BasePath $tempRoot

        $throwFailure = $null
        try {
            $null = Confirm-NormalizedPayloadManifestPayloadSha -Manifest $cacheEntry.Manifest -PayloadPath $cacheEntry.PayloadPath -ThrowOnMismatch
        }
        catch {
            $throwFailure = $_
        }

        Assert-True ($null -eq $cacheMiss) 'Expected normalized payload cache lookup to reject a payload whose bytes do not match the manifest hash.'
        Assert-True ($null -ne $throwFailure) 'Expected strict normalized payload manifest confirmation to throw on hash mismatch.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NormalizedPayloadManifestSourceSummary {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('payload-source-metadata-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        Write-GzipTextFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Content '[{"id":"device-001"}]'
        Write-GzipTextFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Content '[{"CveId":"CVE-2026-0802"}]'
        Write-GzipTextFile -Path (Get-NvdCveCurrentPath -BasePath $tempRoot) -Content '{"records":[{"CveId":"CVE-2026-0802"}]}'

        $sourceMetadata = Get-DashboardSourceSummary `
            -BasePath $tempRoot `
            -MachineCount 1 `
            -AdvancedHuntingCveCount 2 `
            -AdvancedHuntingDeviceUserCount 3 `
            -AdvancedHuntingInventoryTupleCount 4 `
            -NvdCveCount 5 `
            -NormalizationMode 'regression-test'

        Assert-True ($sourceMetadata.Version -eq 'dashboard-source-metadata-v1') 'Expected source metadata to include a version marker.'
        Assert-True ($sourceMetadata.MachineData.RecordCount -eq 1) 'Expected source metadata to preserve machine record count.'
        Assert-True ($sourceMetadata.MachineData.Source.FileCount -eq 1) 'Expected source metadata to include machine source file summary.'
        Assert-True ($sourceMetadata.AdvancedHunting.CveCount -eq 2) 'Expected source metadata to preserve Advanced Hunting CVE count.'
        Assert-True ($sourceMetadata.AdvancedHunting.DeviceUserCount -eq 3) 'Expected source metadata to preserve Advanced Hunting device-user count.'
        Assert-True ($sourceMetadata.AdvancedHunting.InventoryTupleCount -eq 4) 'Expected source metadata to preserve Advanced Hunting inventory tuple count.'
        Assert-True ($sourceMetadata.NvdCve.RecordCount -eq 5) 'Expected source metadata to preserve NVD CVE count.'

        $payloadPath = Join-Path $tempRoot 'payload.json.gz'
        Write-GzipTextFile -Path $payloadPath -Content '{"lookups":{"devices":[],"cves":[]},"vulnsFormat":"rows-v1","vulns":[]}'

        $cacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $payloadPath -VulnCount 0 -DeviceCount 1 -CveCount 5 -Quality ([PSCustomObject]@{ FirstLastSwappedCount = 0 }) -SourceMetadata $sourceMetadata
        Assert-True ($null -ne $cacheEntry.Manifest.SourceMetadata) 'Expected normalized payload manifest to carry source metadata.'
        Assert-True ($cacheEntry.Manifest.SourceMetadata.AdvancedHunting.DeviceUserCount -eq 3) 'Expected manifest source metadata to retain enrichment counts.'

        $htmlPath = Join-Path $tempRoot 'dashboard.html'
        Set-Content -LiteralPath $htmlPath -Value '<html></html>' -NoNewline -Encoding utf8
        $sidecarPath = Write-DashboardValidationSidecar -HtmlPath $htmlPath -PayloadManifest $cacheEntry.Manifest -DashboardPayloadSha256 $cacheEntry.Manifest.PayloadSha256 -DashboardPayloadRowCount 0
        $sidecar = Get-Content -LiteralPath $sidecarPath -Raw | ConvertFrom-Json -Depth 20

        Assert-True ($null -ne $sidecar.SourceMetadata) 'Expected validation sidecar to copy source metadata from the payload manifest.'
        Assert-True ($sidecar.SourceMetadata.NvdCve.RecordCount -eq 5) 'Expected validation sidecar source metadata to retain NVD counts.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-SaveJSLibraryFileRefreshesEmptyCache {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('library-cache-empty-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'library.js'
    $secondOutputPath = Join-Path $tempRoot 'library-second.js'
    $existingInvokeWebRequestFunction = Get-Command -Name Invoke-WebRequest -CommandType Function -ErrorAction SilentlyContinue
    $existingInvokeWebRequestScriptBlock = if ($null -ne $existingInvokeWebRequestFunction) { (Get-Item -Path Function:Invoke-WebRequest).ScriptBlock } else { $null }

    try {
        $script:LibraryCacheRefreshDownloadAttempts = 0
        function Invoke-WebRequest {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Regression test shim for Save-JSLibraryFile without network access.')]
            param(
                [Parameter(Mandatory = $true)]
                [string]$Uri,

                [Parameter(Mandatory = $true)]
                [string]$OutFile,

                [Parameter(Mandatory = $false)]
                [int]$TimeoutSec
            )

            $null = $Uri
            $null = $TimeoutSec
            $script:LibraryCacheRefreshDownloadAttempts++
            [System.IO.File]::WriteAllText($OutFile, ("download-{0}" -f $script:LibraryCacheRefreshDownloadAttempts), [System.Text.UTF8Encoding]::new($false))
        }

        $null = Save-JSLibraryFile -Url 'https://example.invalid/library.js' -Name 'Test Library' -OutputPath $outputPath -Critical $true -CacheBasePath $tempRoot
        $cacheDirectory = Join-Path $tempRoot '.dashboard-cache\libraries'
        $cacheFile = Get-ChildItem -Path $cacheDirectory -File | Select-Object -First 1
        [System.IO.File]::WriteAllBytes($cacheFile.FullName, [byte[]]@())

        $null = Save-JSLibraryFile -Url 'https://example.invalid/library.js' -Name 'Test Library' -OutputPath $secondOutputPath -Critical $true -CacheBasePath $tempRoot
        $refreshedContent = Get-Content -LiteralPath $secondOutputPath -Raw
        $refreshedCacheLength = (Get-Item -LiteralPath $cacheFile.FullName).Length

        Assert-True ($script:LibraryCacheRefreshDownloadAttempts -eq 2) 'Expected an empty cached JavaScript library to be refreshed instead of reused.'
        Assert-True ($refreshedContent -eq 'download-2') 'Expected refreshed library output to come from the second download attempt.'
        Assert-True ($refreshedCacheLength -gt 0) 'Expected refreshed JavaScript library cache file to be non-empty.'
    }
    finally {
        if ($null -ne $existingInvokeWebRequestScriptBlock) {
            Set-Item -Path Function:Invoke-WebRequest -Value $existingInvokeWebRequestScriptBlock
        }
        else {
            Remove-Item -Path Function:Invoke-WebRequest -Force -ErrorAction SilentlyContinue
        }
        Remove-Variable -Name LibraryCacheRefreshDownloadAttempts -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnContentStoreExistenceNeedsRef {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('content-store-existence-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        Set-Content -Path (Get-VulnContentDictionaryPath -BasePath $tempRoot) -Value '{}' -Encoding utf8
        Assert-True ((Test-VulnContentStoreExistence -BasePath $tempRoot) -eq $false) 'Dictionary-only content store should not be treated as valid.'

        Set-Content -Path (Get-VulnCurrentRefsPath -BasePath $tempRoot) -Value '' -Encoding utf8
        Assert-True ((Test-VulnContentStoreExistence -BasePath $tempRoot) -eq $true) 'Current refs should make a minimal content store valid.'

        Set-Content -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -Value '' -Encoding utf8
        Assert-True ((Test-VulnContentStoreExistence -BasePath $tempRoot) -eq $false) 'History periods should require matching history refs sidecars.'

        Set-Content -Path (Get-VulnHistoryRefsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Value '' -Encoding utf8
        Assert-True ((Test-VulnContentStoreExistence -BasePath $tempRoot) -eq $true) 'Matching history refs should restore content-store validity.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-LocalExportArtifactCleanup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('export-artifact-cleanup-' + [guid]::NewGuid().ToString('N'))
    $machineCurrentFileName = Split-Path -Leaf (Get-MachineCurrentPath -BasePath $tempRoot)
    $vulnCurrentFileName = Split-Path -Leaf (Get-VulnCurrentPath -BasePath $tempRoot)
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        foreach ($relativePath in @(
            $machineCurrentFileName,
            $vulnCurrentFileName,
            'synthetic-manifest.json',
            '.dashboard-cache/payloads/payload-old.json.gz',
            '.vuln-content-store-staging-123/VulnCurrentRefs.json.gz',
            '.synthetic-progress.json'
        )) {
            $fullPath = Join-Path $tempRoot $relativePath
            $directory = Split-Path -Path $fullPath -Parent
            if (-not [string]::IsNullOrWhiteSpace($directory)) {
                [void](New-Item -Path $directory -ItemType Directory -Force)
            }
            Set-Content -Path $fullPath -Value '' -Encoding utf8
        }

        Clear-StaleLocalExportArtifact -BasePath $tempRoot -KeepNames @($machineCurrentFileName, $vulnCurrentFileName)

        Assert-True ((Test-Path -LiteralPath (Join-Path $tempRoot $machineCurrentFileName) -PathType Leaf)) 'Expected canonical machine store file to remain after cleanup.'
        Assert-True ((Test-Path -LiteralPath (Join-Path $tempRoot $vulnCurrentFileName) -PathType Leaf)) 'Expected canonical vulnerability store file to remain after cleanup.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot 'synthetic-manifest.json'))) 'Expected stale synthetic manifest to be removed.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot '.dashboard-cache'))) 'Expected transient dashboard cache directory to be removed.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot '.vuln-content-store-staging-123'))) 'Expected transient content-store staging directory to be removed.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot '.synthetic-progress.json'))) 'Expected transient synthetic progress file to be removed.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-InitializeMachineHistoryStoreBackfillsCurrentRecordMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally refers to current records and metadata fields as a set.')]
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-store-init-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $expectedObservedOn = Get-Date -Format 'yyyy-MM-dd'
        Write-NdjsonRecordsFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Records @(
            (Get-TestMachineRecord -Id 'machine-001'),
            [PSCustomObject]@{
                id = 'machine-002'
                removed = $true
            }
        )

        $store = Initialize-MachineHistoryStore -Path $tempRoot
        $currentRecord = $store.CurrentRecords['machine-001']
        $periodKey = Get-QuarterPeriodKeyFromDate -Date $expectedObservedOn
        $historyRecords = @($store.HistoryRecordsByPeriod[$periodKey])

        Assert-True ($store.CurrentRecords.Count -eq 1) 'Expected removal records to be excluded from the current machine map.'
        Assert-True ($null -ne $currentRecord) 'Expected the surviving machine record to remain in the current machine map.'
        Assert-True ([string]$currentRecord.observedOn -eq $expectedObservedOn) 'Expected current machine records without observedOn to be backfilled once during initialization.'
        Assert-True ([string]$currentRecord.stateHash -eq [string](Get-MachineStateHash -Machine $currentRecord)) 'Expected current machine records without stateHash to be backfilled during initialization.'
        Assert-True ($historyRecords.Count -eq 1) 'Expected current machine records to seed history when no history store exists yet.'
        Assert-True ([string]$historyRecords[0].id -eq 'machine-001') 'Expected seeded history to include the surviving machine record.'
        Assert-True ([string]$historyRecords[0].observedOn -eq $expectedObservedOn) 'Expected seeded history rows to preserve the backfilled observedOn value.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-MachineHistoryRemovePathsAllowsEmptyPublishedHistorySet {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-history-remove-empty-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $publishedHistoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $removePaths = @(Get-MachineHistoryRemovePaths -BasePath $tempRoot -PublishedHistoryNames $publishedHistoryNames)

        Assert-True ($removePaths.Count -eq 0) 'Expected empty machine history cleanup inputs to be accepted without removable paths.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkSnapshotImportSmoke {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-snapshot-import-smoke-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        @(
            @{ Name = 'VulnExport_1_2026-01-01.json'; Rows = @((Get-TestVulnRow -Id 'legacy-001' -CveId 'CVE-2026-0001' -SnapshotDate '2026-01-01' -Version '1.0.0')) }
            @{ Name = 'VulnExport_1_2026-01-02.json'; Rows = @((Get-TestVulnRow -Id 'legacy-002' -CveId 'CVE-2026-0002' -SnapshotDate '2026-01-02' -Version '1.0.1')) }
        ) | ForEach-Object {
            $path = Join-Path $tempRoot $_.Name
            $lines = @($_.Rows | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 })
            [System.IO.File]::WriteAllLines($path, $lines, [System.Text.UTF8Encoding]::new($false))
        }

        $publishResult = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles
        $storeRows = @(Read-VulnStoreRow -BasePath $tempRoot)

        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Canonical vuln current file was not materialized.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Canonical quarterly vuln history file was not materialized.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Canonical quarterly vuln history rows file was not materialized.'
        Assert-True (@(Get-VulnLegacySnapshotFile -BasePath $tempRoot).Count -eq 0) 'Downloaded vulnerability snapshots were not removed.'
        Assert-True ($publishResult.CurrentRows -eq 1) 'Expected one current row after migrating the smoke fixture.'
        Assert-True ($publishResult.HistoryYears -eq 1) 'Expected one history period after importing the smoke fixture.'
        Assert-True ($storeRows.Count -eq 2) 'Expected migrated store to expose one current row and one historical row.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkSnapshotImportSingleSnapshot {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-snapshot-import-single-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $path = Join-Path $tempRoot 'VulnExport_1_2026-03-20.json'
        $row = Get-TestVulnRow -Id 'single-001' -CveId 'CVE-2026-0099' -SnapshotDate '2026-03-20' -Version '1.0.0'
        [System.IO.File]::WriteAllLines($path, @($row | ConvertTo-Json -Compress -Depth 8), [System.Text.UTF8Encoding]::new($false))

        $publishResult = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles
        $storeRows = @(Read-VulnStoreRow -BasePath $tempRoot)

        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Canonical vuln current file was not materialized for a single snapshot.'
        Assert-True (@(Get-ChildItem -Path $tempRoot -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue).Count -eq 0) 'Single-snapshot migration should not create history period files.'
        Assert-True ($publishResult.CurrentRows -eq 1) 'Expected one current row after importing a single snapshot.'
        Assert-True ($publishResult.HistoryYears -eq 0) 'Expected zero history periods after importing a single snapshot.'
        Assert-True ($storeRows.Count -eq 1) 'Expected single-snapshot import to expose only one current row.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkSnapshotImportMultipartSnapshot {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-snapshot-import-multipart-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        @(
            @{
                Name = 'VulnExport_1_2026-01-01_part_0.json'
                Rows = @(
                    (Get-TestVulnRow -Id 'multipart-001' -CveId 'CVE-2026-1001' -SnapshotDate '2026-01-01' -Version '1.0.0')
                )
            }
            @{
                Name = 'VulnExport_1_2026-01-01_part_1.json'
                Rows = @(
                    (Get-TestVulnRow -Id 'multipart-002' -CveId 'CVE-2026-1002' -SnapshotDate '2026-01-01' -Version '1.0.0')
                )
            }
            @{
                Name = 'VulnExport_1_2026-01-02.json'
                Rows = @(
                    (Get-TestVulnRow -Id 'multipart-003' -CveId 'CVE-2026-1003' -SnapshotDate '2026-01-02' -Version '1.0.1')
                )
            }
        ) | ForEach-Object {
            $path = Join-Path $tempRoot $_.Name
            $lines = @($_.Rows | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 })
            [System.IO.File]::WriteAllLines($path, $lines, [System.Text.UTF8Encoding]::new($false))
        }

        Assert-True (Test-IsLegacyVulnSnapshotFileName -Name 'VulnExport_1_2026-01-01_part_0.json.gz') 'Expected multipart legacy snapshot names to be recognized.'
        Assert-True (Test-IsLegacyVulnSnapshotFileName -Name 'VulnExport_1_2026-01-02.json.gz') 'Expected legacy single-part snapshot names to remain recognized.'

        $publishResult = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles
        $storeRows = @(Read-VulnStoreRow -BasePath $tempRoot)
        $currentRows = @($storeRows | Where-Object { (Get-VulnPropertyValue -InputObject $_ -Name 'Id') -eq 'multipart-003' })
        $historyRows = @($storeRows | Where-Object { (Get-VulnPropertyValue -InputObject $_ -Name 'Id') -in @('multipart-001', 'multipart-002') })

        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Canonical vuln current file was not materialized for multipart snapshots.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Canonical quarterly vuln history file was not materialized for multipart snapshots.'
        Assert-True (@(Get-VulnLegacySnapshotFile -BasePath $tempRoot).Count -eq 0) 'Multipart vulnerability snapshots were not removed after publishing.'
        Assert-True ($publishResult.DownloadedFiles -eq 3) 'Expected all multipart snapshot files to be counted during publish.'
        Assert-True ($publishResult.CurrentRows -eq 1) 'Expected multipart import to leave one current row for the latest snapshot date.'
        Assert-True ($publishResult.HistoryYears -eq 1) 'Expected multipart import to create one history period.'
        Assert-True ($storeRows.Count -eq 3) 'Expected multipart import to preserve all rows across current and history.'
        Assert-True ($currentRows.Count -eq 1) 'Expected latest multipart snapshot import to retain one current row.'
        Assert-True ($historyRows.Count -eq 2) 'Expected prior multipart snapshot rows to be preserved in history.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkSnapshotImportMergesIntoExistingCanonicalStore {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-snapshot-import-existing-store-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $initialSnapshotPath = Join-Path $tempRoot 'VulnExport_1_2026-01-01.json'
        $initialRows = @(
            (Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-2001' -SnapshotDate '2026-01-01' -Version '1.0.0')
        )
        [System.IO.File]::WriteAllLines($initialSnapshotPath, @($initialRows | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 }), [System.Text.UTF8Encoding]::new($false))

        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        $deltaSnapshotPath = Join-Path $tempRoot 'VulnExport_1_2026-01-02.json'
        $deltaRows = @(
            (Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-2001' -SnapshotDate '2026-01-02' -Version '1.0.0')
            (Get-TestVulnRow -Id 'merge-002' -CveId 'CVE-2026-2002' -SnapshotDate '2026-01-02' -Version '2.0.0')
        )
        [System.IO.File]::WriteAllLines($deltaSnapshotPath, @($deltaRows | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 }), [System.Text.UTF8Encoding]::new($false))

        $publishResult = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles
        $storeRows = @(Read-VulnStoreRow -BasePath $tempRoot)
        $storeIds = @($storeRows | ForEach-Object { [string](Get-VulnPropertyValue -InputObject $_ -Name 'Id') })

        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Canonical vuln current file was not preserved when merging into an existing store.'
        Assert-True (@(Get-ChildItem -Path $tempRoot -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue).Count -eq 0) 'Merging an unchanged carry-forward snapshot into an existing store should not create history.'
        Assert-True (@(Get-VulnLegacySnapshotFile -BasePath $tempRoot).Count -eq 0) 'Delta vulnerability snapshots were not removed after merging into an existing store.'
        Assert-True ($publishResult.CurrentRows -eq 2) 'Expected the existing canonical store merge to retain both current rows from the latest snapshot.'
        Assert-True ($publishResult.HistoryYears -eq 0) 'Expected the existing canonical store merge to avoid creating history when rows are only carried forward or added.'
        Assert-True ([string]$publishResult.LatestSnapshotDate -eq '2026-01-02') 'Expected the existing canonical store merge to advance the latest snapshot date.'
        Assert-True ($storeRows.Count -eq 2) 'Expected the merged existing store to expose exactly the carried-forward and newly added current rows.'
        Assert-True (('merge-001' -in $storeIds) -and ('merge-002' -in $storeIds)) 'Expected the merged existing store to retain the original row and add the new row.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-HttpRetryDelayHelperBehavior {
    [CmdletBinding()]
    param()

    $fixedNow = [datetimeoffset]'2026-01-01T00:00:00Z'
    $retryAfterDate = $fixedNow.AddSeconds(9).ToString('r', [System.Globalization.CultureInfo]::InvariantCulture)

    Assert-True ((Get-HttpRetryDelayOverride -Headers @{ 'Retry-After' = '7' } -ReferenceTime $fixedNow) -eq 7000) 'Expected Retry-After integer seconds to convert to milliseconds.'
    Assert-True ((Get-HttpRetryDelayOverride -Headers @{ 'Retry-After' = $retryAfterDate } -ReferenceTime $fixedNow) -eq 9000) 'Expected Retry-After HTTP-date values to convert to milliseconds.'
    Assert-True ((Get-HttpRetryDelayOverride -Headers @{ 'x-ms-retry-after-ms' = '250' }) -eq 250) 'Expected retry-after-ms headers to convert directly to milliseconds.'
    Assert-True ((Get-HttpRetryDelayOverride -Headers @{ 'Retry-After' = '2147484' } -ReferenceTime $fixedNow) -eq [int]::MaxValue) 'Expected oversized Retry-After second values to clamp to the maximum supported sleep interval.'
    Assert-True ((Get-HttpRetryDelayOverride -Headers @{ 'x-ms-retry-after-ms' = '21474836470' }) -eq [int]::MaxValue) 'Expected oversized retry-after-ms header values to clamp to the maximum supported sleep interval.'
    Assert-True ($null -eq (Get-HttpRetryDelayOverride -Headers @{} -ReferenceTime $fixedNow)) 'Expected the retry delay helper to return no override when no retry headers are present.'
}

function Test-WebRequestWithRetryTransientTransportBehavior {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('webrequest-transient-retry-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $outputFile = Join-Path $tempRoot 'download.bin'
        $script:TransientWebRequestAttempts = 0
        $script:TransientWebRequestSleeps = [System.Collections.Generic.List[int]]::new()

        Set-Item -Path Function:Invoke-WebRequest -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$TimeoutSec,
                [string]$ErrorAction
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $TimeoutSec, $ErrorAction

            $script:TransientWebRequestAttempts++
            if ($script:TransientWebRequestAttempts -eq 1) {
                throw [System.Net.WebException]::new('The operation has timed out', [System.Net.WebExceptionStatus]::Timeout)
            }

            [System.IO.File]::WriteAllText($OutFile, 'ok', [System.Text.UTF8Encoding]::new($false))
            return [PSCustomObject]@{ StatusCode = 200 }
        }

        Set-Item -Path Function:Start-Sleep -Value {
            param([int]$Milliseconds)

            $script:TransientWebRequestSleeps.Add($Milliseconds)
        }

        $null = Invoke-WebRequestWithRetry -Uri 'https://example.invalid/blob/data.json.gz?sig=secret' -OutFile $outputFile -MaxRetries 3 -InitialDelayMs 1500 -RetryTransientTransportFailures

        Assert-True ($script:TransientWebRequestAttempts -eq 2) 'Expected transport retries to rerun Invoke-WebRequest after a timeout.'
        Assert-True ($script:TransientWebRequestSleeps.Count -eq 1 -and $script:TransientWebRequestSleeps[0] -eq 1500) 'Expected the first transport retry to use the configured fallback delay.'
        Assert-True ((Test-Path -LiteralPath $outputFile -PathType Leaf)) 'Expected transport retry to eventually materialize the requested download file.'
    }
    finally {
        Remove-Item -Path Function:Invoke-WebRequest -ErrorAction SilentlyContinue
        Remove-Item -Path Function:Start-Sleep -ErrorAction SilentlyContinue
        Remove-Variable -Name TransientWebRequestAttempts -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name TransientWebRequestSleeps -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadMultipartNameUniqueness {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-multipart-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        $script:MockMultipartExportFiles = @(
            'https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz'
            'https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c001.json.gz'
            'https://example.invalid/flat-va/2026-01-02/org/json/_RbacGroupId=1/part-001.c000.json.gz'
        )

        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $Body, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            return [PSCustomObject]@{
                exportFiles = @($script:MockMultipartExportFiles)
            }
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Method, $Headers, $InFile, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            [System.IO.File]::WriteAllText($OutFile, $Uri, [System.Text.UTF8Encoding]::new($false))
        }

        $result = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        $downloadedNames = @($result.DownloadedFiles | ForEach-Object { Split-Path -Leaf $_ })

        Assert-True ($result.ExportFileCount -eq 3) 'Expected mocked multipart download to surface three export files.'
        Assert-True ($downloadedNames.Count -eq 3) 'Expected mocked multipart download to emit three local files.'
        Assert-True (@($downloadedNames | Sort-Object -Unique).Count -eq 3) 'Expected multipart download filenames to remain unique.'
        Assert-True ('VulnExport_1_2026-01-01_part_0.json.gz' -in $downloadedNames) 'Expected first multipart file name to include part_0.'
        Assert-True ('VulnExport_1_2026-01-01_part_1.json.gz' -in $downloadedNames) 'Expected second multipart file name to include part_1.'
        Assert-True ('VulnExport_1_2026-01-02_part_0.json.gz' -in $downloadedNames) 'Expected next snapshot date to reset the multipart counter.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest
        Remove-Variable -Name MockMultipartExportFiles -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadStagingBehavior {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-staging-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        $script:CapturedBulkExportUri = ''
        $script:CapturedBulkExportMaxRetries = 0
        $script:CapturedBulkExportTimeoutSec = 0
        $script:CapturedDownloadOutFiles = [System.Collections.Generic.List[string]]::new()
        $script:CapturedDownloadMaxRetries = 0
        $script:CapturedDownloadTimeoutSec = 0

        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Method, $Headers, $Body, $ContentType, $InitialDelayMs, $BackoffMultiplier, $RetryTransientTransportFailures

            $script:CapturedBulkExportUri = $Uri
            $script:CapturedBulkExportMaxRetries = $MaxRetries
            $script:CapturedBulkExportTimeoutSec = $TimeoutSec

            return [PSCustomObject]@{
                exportFiles = @('https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz?sig=secret')
            }
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $InitialDelayMs, $BackoffMultiplier, $RetryTransientTransportFailures

            $script:CapturedDownloadOutFiles.Add($OutFile)
            $script:CapturedDownloadMaxRetries = $MaxRetries
            $script:CapturedDownloadTimeoutSec = $TimeoutSec
            [System.IO.File]::WriteAllText($OutFile, 'payload', [System.Text.UTF8Encoding]::new($false))
        }

        $result = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        $finalPath = Join-Path $tempRoot 'VulnExport_1_2026-01-01_part_0.json.gz'
        $stagingPath = Join-Path $tempRoot '.VulnExport_1_2026-01-01_part_0.json.gz.partial'

        Assert-True ($script:CapturedBulkExportUri -eq 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport?sasValidHours=6') 'Expected bulk export requests to request the maximum supported SAS lifetime.'
        Assert-True ($script:CapturedBulkExportMaxRetries -eq 4) 'Expected bulk export metadata fetches to use the tighter retry budget.'
        Assert-True ($script:CapturedBulkExportTimeoutSec -eq 600) 'Expected bulk export metadata fetches to use the configured timeout.'
        Assert-True ($script:CapturedDownloadOutFiles.Count -eq 1) 'Expected exactly one staged bulk snapshot download.'
        Assert-True ((Split-Path -Path $script:CapturedDownloadOutFiles[0] -Leaf) -eq '.VulnExport_1_2026-01-01_part_0.json.gz.partial') 'Expected bulk snapshot downloads to stage into transient partial files.'
        Assert-True ($script:CapturedDownloadMaxRetries -eq 6) 'Expected bulk snapshot downloads to use the higher download retry budget.'
        Assert-True ($script:CapturedDownloadTimeoutSec -eq 1800) 'Expected bulk snapshot downloads to use the longer download timeout.'
        Assert-True ((Test-IsTransientExportArtifactName -Name '.VulnExport_1_2026-01-01_part_0.json.gz.partial') -eq $true) 'Expected staged download files to be classified as transient export artifacts.'
        Assert-True ((Test-Path -LiteralPath $finalPath -PathType Leaf)) 'Expected the staged vulnerability snapshot to be renamed into the final export file.'
        Assert-True (-not (Test-Path -LiteralPath $stagingPath -PathType Leaf)) 'Expected staging files to be removed after a successful download.'
        Assert-True ($result.DownloadedFiles.Count -eq 1 -and $result.DownloadedFiles[0] -eq $finalPath) 'Expected the downloader to report only the finalized export file.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest
        Remove-Variable -Name CapturedBulkExportUri -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedBulkExportMaxRetries -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedBulkExportTimeoutSec -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedDownloadOutFiles -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedDownloadMaxRetries -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name CapturedDownloadTimeoutSec -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadRetriesEmptyBlob {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-empty-blob-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        $script:EmptyBlobDownloadAttempts = 0
        $script:EmptyBlobRetrySleeps = [System.Collections.Generic.List[int]]::new()

        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $Body, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            return [PSCustomObject]@{
                exportFiles = @('https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz?sig=secret')
            }
        }

        Set-Item -Path Function:Start-Sleep -Value {
            param(
                [int]$Milliseconds
            )

            $script:EmptyBlobRetrySleeps.Add($Milliseconds)
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            $script:EmptyBlobDownloadAttempts++
            if ($script:EmptyBlobDownloadAttempts -eq 1) {
                [System.IO.File]::WriteAllText($OutFile, '', [System.Text.UTF8Encoding]::new($false))
                return
            }

            [System.IO.File]::WriteAllText($OutFile, 'payload', [System.Text.UTF8Encoding]::new($false))
        }

        $result = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        $finalPath = Join-Path $tempRoot 'VulnExport_1_2026-01-01_part_0.json.gz'
        $stagingPath = Join-Path $tempRoot '.VulnExport_1_2026-01-01_part_0.json.gz.partial'

        Assert-True ($script:EmptyBlobDownloadAttempts -eq 2) 'Expected zero-byte bulk snapshot downloads to be retried.'
        Assert-True ($script:EmptyBlobRetrySleeps.Count -eq 1 -and $script:EmptyBlobRetrySleeps[0] -eq 2000) 'Expected the first empty bulk snapshot retry to wait for the configured initial delay.'
        Assert-True ((Test-Path -LiteralPath $finalPath -PathType Leaf)) 'Expected a retried empty bulk snapshot download to eventually finalize the export file.'
        Assert-True (-not (Test-Path -LiteralPath $stagingPath -PathType Leaf)) 'Expected empty bulk snapshot retries to clean up their partial files before retrying.'
        Assert-True ($result.DownloadedFiles.Count -eq 1 -and $result.DownloadedFiles[0] -eq $finalPath) 'Expected the downloader to report the finalized export path after retrying an empty blob.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest
        Remove-Item -Path Function:Start-Sleep -ErrorAction SilentlyContinue
        Remove-Variable -Name EmptyBlobDownloadAttempts -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name EmptyBlobRetrySleeps -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadEmptyBlobExhaustionBehavior {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-empty-blob-exhaustion-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        $script:EmptyBlobExhaustionDownloadAttempts = 0
        $script:EmptyBlobExhaustionSleeps = [System.Collections.Generic.List[int]]::new()

        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $Body, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            return [PSCustomObject]@{
                exportFiles = @('https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz?sig=secret')
            }
        }

        Set-Item -Path Function:Start-Sleep -Value {
            param(
                [int]$Milliseconds
            )

            $script:EmptyBlobExhaustionSleeps.Add($Milliseconds)
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            $script:EmptyBlobExhaustionDownloadAttempts++
            [System.IO.File]::WriteAllText($OutFile, '', [System.Text.UTF8Encoding]::new($false))
        }

        $downloadFailure = $null
        try {
            $null = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        }
        catch {
            $downloadFailure = $_
        }

        $finalPath = Join-Path $tempRoot 'VulnExport_1_2026-01-01_part_0.json.gz'
        $stagingPath = Join-Path $tempRoot '.VulnExport_1_2026-01-01_part_0.json.gz.partial'

        Assert-True ($null -ne $downloadFailure) 'Expected persistently empty bulk snapshot downloads to fail after exhausting retries.'
        Assert-True ($script:EmptyBlobExhaustionDownloadAttempts -eq 4) 'Expected empty bulk snapshot downloads to stop after four attempts.'
        Assert-True (($script:EmptyBlobExhaustionSleeps -join ',') -eq '2000,4000,8000') 'Expected empty bulk snapshot retries to use exponential backoff before the final failure.'
        Assert-True ([string]$downloadFailure.Exception.Message -eq 'Downloaded file is empty: https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz') 'Expected the empty bulk snapshot failure to surface the sanitized blob URL.'
        Assert-True (-not (Test-Path -LiteralPath $stagingPath -PathType Leaf)) 'Expected empty bulk snapshot retry exhaustion to clean up the staged partial file.'
        Assert-True (-not (Test-Path -LiteralPath $finalPath -PathType Leaf)) 'Expected empty bulk snapshot retry exhaustion to avoid finalizing an output file.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest
        Remove-Item -Path Function:Start-Sleep -ErrorAction SilentlyContinue
        Remove-Variable -Name EmptyBlobExhaustionDownloadAttempts -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name EmptyBlobExhaustionSleeps -Scope Script -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadMoveFailureCleanupBehavior {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-move-failure-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $Body, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            return [PSCustomObject]@{
                exportFiles = @('https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz?sig=secret')
            }
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures
            [System.IO.File]::WriteAllText($OutFile, 'payload', [System.Text.UTF8Encoding]::new($false))
        }

        $finalPath = Join-Path $tempRoot 'VulnExport_1_2026-01-01_part_0.json.gz'
        $stagingPath = Join-Path $tempRoot '.VulnExport_1_2026-01-01_part_0.json.gz.partial'
        [void](New-Item -Path $finalPath -ItemType Directory -Force)

        $moveFailure = $null
        try {
            $null = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        }
        catch {
            $moveFailure = $_
        }

        Assert-True ($null -ne $moveFailure) 'Expected a conflicting move target to surface a failure.'
        Assert-True ((Test-Path -LiteralPath $finalPath -PathType Container)) 'Expected the conflicting destination directory to remain in place.'
        Assert-True (-not (Test-Path -LiteralPath $stagingPath -PathType Leaf)) 'Expected move failures to clean up the staged partial file.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-BulkVulnerabilitySnapshotDownloadCleanupBehavior {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('bulk-download-staging-failure-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalWebRequest = (Get-Command -Name Invoke-WebRequestWithRetry -CommandType Function).ScriptBlock

    try {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [object]$Body,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $Body, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            return [PSCustomObject]@{
                exportFiles = @('https://example.invalid/flat-va/2026-01-01/org/json/_RbacGroupId=1/part-000.c000.json.gz?sig=secret')
            }
        }

        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value {
            param(
                [string]$Uri,
                [string]$Method,
                [hashtable]$Headers,
                [string]$OutFile,
                [string]$InFile,
                [string]$ContentType,
                [int]$MaxRetries,
                [int]$InitialDelayMs,
                [double]$BackoffMultiplier,
                [int]$TimeoutSec,
                [switch]$RetryTransientTransportFailures
            )

            $null = $Uri, $Method, $Headers, $InFile, $ContentType, $MaxRetries, $InitialDelayMs, $BackoffMultiplier, $TimeoutSec, $RetryTransientTransportFailures

            [System.IO.File]::WriteAllText($OutFile, 'partial', [System.Text.UTF8Encoding]::new($false))
            throw [System.TimeoutException]::new('The download timed out')
        }

        $downloadFailure = $null
        try {
            $null = Invoke-MdeBulkVulnerabilitySnapshotDownload -Headers @{} -OutputPath $tempRoot -ExportUrl 'https://example.invalid/api/machines/SoftwareVulnerabilitiesExport'
        }
        catch {
            $downloadFailure = $_
        }

        Assert-True ($null -ne $downloadFailure) 'Expected staged bulk snapshot downloads to surface failures when the download never completes.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot '.VulnExport_1_2026-01-01_part_0.json.gz.partial') -PathType Leaf)) 'Expected failed staged downloads to remove their partial files.'
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $tempRoot 'VulnExport_1_2026-01-01_part_0.json.gz') -PathType Leaf)) 'Expected failed staged downloads to avoid leaving behind a finalized snapshot file.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Invoke-WebRequestWithRetry -Value $originalWebRequest

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnCurrentFileRejectsDuplicateId {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-current-duplicate-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $currentPath = Get-VulnCurrentPath -BasePath $tempRoot
        Write-NdjsonRecordsFile -Path $currentPath -Records @(
            (Get-TestVulnRow -Id 'duplicate-001' -CveId 'CVE-2026-0101' -SnapshotDate '2026-03-20' -Version '1.0.0'),
            (Get-TestVulnRow -Id 'duplicate-001' -CveId 'CVE-2026-0101' -SnapshotDate '2026-03-21' -Version '1.0.1')
        )

        $duplicateFailure = $null
        try {
            $null = Test-VulnCurrentFile -Path $currentPath
        }
        catch {
            $duplicateFailure = $_
        }

        Assert-True ($null -ne $duplicateFailure) 'Expected current-file validation to reject duplicate Id values.'
        Assert-True (([string]$duplicateFailure).Contains("duplicate Id 'duplicate-001'")) 'Expected duplicate current-file validation failure to mention the repeated Id.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-RepairVulnHistoryLayoutSkipsCanonicalQuarterlyStore {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('repair-vuln-layout-skip-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $periodKey = '2026Q1'
        $historyPath = Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey $periodKey
        $historyRowsPath = Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey $periodKey
        $historyDocument = Get-TestQuarterlyHistoryDocument -PeriodKey $periodKey -Snapshots @(
            [PSCustomObject]@{
                date = '2026-03-20'
                closed = @(
                    [PSCustomObject]@{
                        reason = 'removed'
                        row = (Get-TestVulnRow -Id 'canonical-q1' -CveId 'CVE-2026-0100' -SnapshotDate '2026-03-20' -Version '1.0.0')
                    }
                )
            }
        )

        Write-VulnHistoryDocument -Path $historyPath -HistoryDocument $historyDocument
        Write-VulnHistoryRowsFile -Path $historyRowsPath -HistoryDocument $historyDocument

        $originalHistoryContent = Read-GzipTextFile -Path $historyPath
        $originalRowsContent = Read-GzipTextFile -Path $historyRowsPath
        $requiresRepair = Test-VulnStoreRequiresCanonicalRepair -BasePath $tempRoot

        $repairedPeriods = Repair-VulnHistoryLayout -BasePath $tempRoot

        Assert-True ($requiresRepair -eq $false) 'Expected valid canonical quarterly history layout to avoid repair.'
        Assert-True ($repairedPeriods -eq 1) 'Expected canonical quarterly history layout to be treated as already repaired.'
        Assert-True ((Read-GzipTextFile -Path $historyPath) -eq $originalHistoryContent) 'Expected canonical quarterly history file to be left untouched.'
        Assert-True ((Read-GzipTextFile -Path $historyRowsPath) -eq $originalRowsContent) 'Expected canonical quarterly history rows sidecar to be left untouched.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnStoreRequiresCanonicalRepairDetectsMalformedQuarterlyHistory {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('repair-vuln-layout-malformed-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $periodKey = '2026Q1'
        $historyPath = Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey $periodKey
        $historyRowsPath = Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey $periodKey

        Write-GzipTextFile -Path $historyPath -Content 'skip-deserialize-sentinel'
        Write-NdjsonRecordsFile -Path $historyRowsPath -Records @((Get-TestVulnRow -Id 'malformed-q1' -CveId 'CVE-2026-0109' -SnapshotDate '2026-03-20' -Version '1.0.9'))

        Assert-True ((Test-VulnStoreRequiresCanonicalRepair -BasePath $tempRoot) -eq $true) 'Expected malformed quarterly history content to require repair.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-RepairVulnHistoryLayoutRebuildsCanonicalQuarterlyRowSidecar {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('repair-vuln-layout-sidecar-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $periodKey = '2026Q1'
        $historyPath = Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey $periodKey
        $historyRowsPath = Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey $periodKey
        $expectedRow = Get-TestVulnRow -Id 'canonical-row-001' -CveId 'CVE-2026-0110' -SnapshotDate '2026-03-20' -Version '1.1.0'
        $historyDocument = Get-TestQuarterlyHistoryDocument -PeriodKey $periodKey -Snapshots @(
            [PSCustomObject]@{
                date = '2026-03-20'
                closed = @(
                    [PSCustomObject]@{
                        reason = 'changed'
                        row = $expectedRow
                        replacementId = 'canonical-row-001'
                    }
                )
            }
        )

        Write-VulnHistoryDocument -Path $historyPath -HistoryDocument $historyDocument
        Write-NdjsonRecordsFile -Path $historyRowsPath -Records @((Get-TestVulnRow -Id 'canonical-row-stale' -CveId 'CVE-2026-0999' -SnapshotDate '2026-03-20' -Version '9.9.9'))

        Assert-True ((Test-VulnStoreRequiresCanonicalRepair -BasePath $tempRoot) -eq $true) 'Expected mismatched quarterly rows sidecar to require repair.'

        $repairedPeriods = Repair-VulnHistoryLayout -BasePath $tempRoot
        $repairedRows = @(Read-VulnNdjsonRecordsFromPath -Path $historyRowsPath)

        Assert-True ($repairedPeriods -eq 1) 'Expected canonical quarterly rows sidecar repair to preserve one quarterly period.'
        Assert-True ($repairedRows.Count -eq 1) 'Expected repaired quarterly rows sidecar to contain one row.'
        Assert-True ([string](Get-VulnPropertyValue -InputObject $repairedRows[0] -Name 'Id') -eq 'canonical-row-001') 'Expected repaired quarterly rows sidecar to be rebuilt from the history document.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-RepairVulnHistoryLayoutRepairsLegacyYearlyStore {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('repair-vuln-layout-legacy-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $legacyHistoryPath = Join-Path $tempRoot 'VulnHistory_2026.json.gz'
        $legacyDocument = [PSCustomObject]@{
            year = 2026
            latestDate = '2026-04-02'
            snapshots = @(
                [PSCustomObject]@{
                    date = '2026-01-02'
                    closed = @(
                        [PSCustomObject]@{
                            reason = 'removed'
                            row = (Get-TestVulnRow -Id 'legacy-q1' -CveId 'CVE-2026-0101' -SnapshotDate '2026-01-02' -Version '1.0.0')
                        }
                    )
                },
                [PSCustomObject]@{
                    date = '2026-04-02'
                    closed = @(
                        [PSCustomObject]@{
                            reason = 'changed'
                            row = (Get-TestVulnRow -Id 'legacy-q2' -CveId 'CVE-2026-0102' -SnapshotDate '2026-04-02' -Version '2.0.0')
                            replacementId = 'legacy-q2'
                        }
                    )
                }
            )
        }

        Write-VulnHistoryDocument -Path $legacyHistoryPath -HistoryDocument $legacyDocument

        $repairedPeriods = Repair-VulnHistoryLayout -BasePath $tempRoot

        Assert-True ($repairedPeriods -eq 2) 'Expected yearly legacy history to split into two quarterly periods.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Expected repaired Q1 history file to exist.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q2') -PathType Leaf)) 'Expected repaired Q2 history file to exist.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Expected repaired Q1 history rows file to exist.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q2') -PathType Leaf)) 'Expected repaired Q2 history rows file to exist.'
        Assert-True (-not (Test-Path -LiteralPath $legacyHistoryPath -PathType Leaf)) 'Expected legacy yearly history file to be removed after repair.'

        $q1Rows = @(Read-VulnNdjsonRecordsFromPath -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1'))
        $q2Rows = @(Read-VulnNdjsonRecordsFromPath -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q2'))
        Assert-True ($q1Rows.Count -eq 1) 'Expected repaired Q1 history to retain one closed row.'
        Assert-True ($q2Rows.Count -eq 1) 'Expected repaired Q2 history to retain one closed row.'
        Assert-True ([string](Get-VulnPropertyValue -InputObject $q1Rows[0] -Name 'Id') -eq 'legacy-q1') 'Expected repaired Q1 history row Id to be preserved.'
        Assert-True ([string](Get-VulnPropertyValue -InputObject $q2Rows[0] -Name 'Id') -eq 'legacy-q2') 'Expected repaired Q2 history row Id to be preserved.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnHistoryFileValidatesQuarterlyHistoryDocument {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('history-file-validator-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $periodKey = '2026Q1'
        $historyPath = Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey $periodKey
        $historyDocument = Get-TestQuarterlyHistoryDocument -PeriodKey $periodKey -Snapshots @(
            [PSCustomObject]@{
                date = '2026-01-15'
                closed = @(
                    [PSCustomObject]@{
                        reason = 'removed'
                        row = (Get-TestVulnRow -Id 'validator-q1-a' -CveId 'CVE-2026-0120' -SnapshotDate '2026-01-15' -Version '1.2.0')
                    }
                )
            },
            [PSCustomObject]@{
                date = '2026-03-20'
                closed = @(
                    [PSCustomObject]@{
                        reason = 'changed'
                        row = (Get-TestVulnRow -Id 'validator-q1-b' -CveId 'CVE-2026-0121' -SnapshotDate '2026-03-20' -Version '1.2.1')
                        replacementId = 'validator-q1-b'
                    }
                )
            }
        )

        Write-VulnHistoryDocument -Path $historyPath -HistoryDocument $historyDocument

        Assert-True ((Test-VulnHistoryFile -Path $historyPath) -eq 2) 'Expected deep quarterly history validation to accept JObject-backed history documents.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnCanonicalSignatureStability {
    [CmdletBinding()]
    param()

    $baseline = Get-TestVulnRow -Id 'stable-001' -CveId 'CVE-2026-0003' -SnapshotDate '2026-03-17' -Version '1.0.0'
    $variant = Get-TestVulnRow -Id 'stable-001' -CveId 'CVE-2026-0003' -SnapshotDate '2026-03-19' -Version '1.0.0'
    $variant.OSVersion = '10.0.99999'
    $variant.RecommendedSecurityUpdate = 'KB999999'
    $variant.RecommendedSecurityUpdateId = 'KB999999'
    $variant.RecommendedSecurityUpdateUrl = 'https://example.invalid/kb999999'
    $variant.CveBatchTitle = 'March 2026 Security Updates'
    $variant.CveBatchUrl = 'https://example.invalid/batch/mar-2026'
    $variant.DiskPaths = @('C:\Program Files\Legacy Agent\alt.exe')
    $variant.RegistryPaths = @('HKLM\Software\Contoso\LegacyAgentV2')

    $baselineSignature = Get-VulnCanonicalRowSignature -Row $baseline
    $variantSignature = Get-VulnCanonicalRowSignature -Row $variant

    Assert-True ($baselineSignature -eq $variantSignature) 'Canonical vulnerability signature should ignore volatile metadata changes for the same Id.'
}

function Test-MergeVulnObservedWindowRows {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param()

    $first = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-17' -Version '1.0.0'
    $second = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-19' -Version '1.0.0'
    $second.RecommendedSecurityUpdate = 'KB000099'
    $second.RecommendedSecurityUpdateId = 'KB000099'
    $third = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-23' -Version '1.0.0'
    $third.RecommendedSecurityUpdate = 'KB000123'
    $third.RecommendedSecurityUpdateId = 'KB000123'
    $sameDayDuplicate = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-19' -Version '1.0.0'
    $sameDayDuplicate.RecommendedSecurityUpdate = 'KB000100'
    $sameDayDuplicate.RecommendedSecurityUpdateId = 'KB000100'
    $otherId = Get-TestVulnRow -Id 'merge-002' -CveId 'CVE-2026-0005' -SnapshotDate '2026-03-19' -Version '2.0.0'

    $merged = @(Merge-VulnObservedWindowRows -Rows @($first, $second, $third, $sameDayDuplicate, $otherId))
    $mergeIdRows = @($merged | Where-Object { $_.Id -eq 'merge-001' } | Sort-Object FirstSeenTimestamp, LastSeenTimestamp)

    Assert-True ($mergeIdRows.Count -eq 2) 'Expected same-Id windows with overlap or a one-day gap to collapse into two observation windows.'
    Assert-True ($mergeIdRows[0].FirstSeenTimestamp -eq '2026-03-17') 'Expected merged window to preserve the earliest first-seen date.'
    Assert-True ($mergeIdRows[0].LastSeenTimestamp -eq '2026-03-19') 'Expected merged window to span the one-day observation gap.'
    Assert-True ($mergeIdRows[0].RecommendedSecurityUpdate -eq 'KB000100') 'Expected merged window to retain the latest row metadata.'
    Assert-True ($mergeIdRows[1].FirstSeenTimestamp -eq '2026-03-23') 'Expected distant reappearance to remain a separate window.'
    Assert-True ($mergeIdRows[1].LastSeenTimestamp -eq '2026-03-23') 'Expected distant reappearance to remain a separate window.'
}

function Test-ReadNormalizedVulnStoreRow {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-vuln-reader-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $historyRow = Get-TestVulnRow -Id 'normalized-001' -CveId 'CVE-2026-0006' -SnapshotDate '2026-03-17' -Version '1.0.0'
        $currentRow = Get-TestVulnRow -Id 'normalized-001' -CveId 'CVE-2026-0006' -SnapshotDate '2026-03-19' -Version '1.0.0'
        $currentRow.RecommendedSecurityUpdate = 'KB000777'
        $currentRow.RecommendedSecurityUpdateId = 'KB000777'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        $normalizedRows = @(Read-NormalizedVulnStoreRow -BasePath $tempRoot)

        Assert-True ($normalizedRows.Count -eq 1) 'Expected normalized vuln reader to collapse overlapping same-Id windows from store history.'
        Assert-True ($normalizedRows[0].FirstSeenTimestamp -eq '2026-03-17') 'Expected normalized vuln reader to preserve the earliest first-seen date.'
        Assert-True ($normalizedRows[0].LastSeenTimestamp -eq '2026-03-19') 'Expected normalized vuln reader to preserve the latest last-seen date.'
        Assert-True ($normalizedRows[0].RecommendedSecurityUpdate -eq 'KB000777') 'Expected normalized vuln reader to retain the newest row metadata.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ResolveNormalizedLookupIndexListHandlesScalarAndCollectionValues {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally covers both scalar and collection values.')]
    [CmdletBinding()]
    param()

    $lookupList = [System.Collections.Generic.List[string]]::new()
    $indexMap = @{}

    $singleValueIndices = Resolve-NormalizedLookupIndexList -Values 'C:\Windows\System32\kernel32.dll' -List $lookupList -IndexMap $indexMap
    $mixedValueIndices = Resolve-NormalizedLookupIndexList -Values @('C:\Windows\System32\kernel32.dll', $null, 'HKLM\Software\Microsoft\Windows') -List $lookupList -IndexMap $indexMap
    $emptyValueIndices = Resolve-NormalizedLookupIndexList -Values @() -List $lookupList -IndexMap $indexMap

    Assert-True ($singleValueIndices.Count -eq 1) 'Expected scalar lookup input to resolve to a single lookup index.'
    Assert-True ($singleValueIndices[0] -eq 0) 'Expected the first scalar lookup input to create lookup index 0.'
    Assert-True ($mixedValueIndices.Count -eq 2) 'Expected mixed lookup input to skip nulls and keep two resolved values.'
    Assert-True ($mixedValueIndices[0] -eq 0) 'Expected repeated lookup values to reuse the existing lookup index.'
    Assert-True ($mixedValueIndices[1] -eq 1) 'Expected a new lookup value to receive the next lookup index.'
    Assert-True ($lookupList.Count -eq 2) 'Expected lookup storage to contain only the two unique non-null values.'
    Assert-True ($null -eq $emptyValueIndices) 'Expected empty lookup input to return no indices.'
}

function Test-ResolveNormalizedInventoryLookupSkipsEmptyInventoryData {
    [CmdletBinding()]
    param()

    $context = Get-NormalizationContext
    $emptyInventoryIndex = Resolve-NormalizedInventoryLookup `
        -DeviceId 'device-001' `
        -SoftwareVendor 'contoso' `
        -SoftwareName 'legacy_agent' `
        -SoftwareVersion '6.0.0' `
        -Context $context

    $inventoryKey = Get-AdvancedHuntingInventoryMatchKey -DeviceId 'device-001' -SoftwareVendor 'contoso' -SoftwareName 'legacy_agent' -SoftwareVersion '6.0.0'
    $context.AdvancedHuntingInventoryData = @{
        $inventoryKey = [PSCustomObject]@{
            ProductCodeCpe = 'cpe:/a:contoso:legacy_agent:6.0.0'
            EndOfSupportStatus = 'supported'
            EndOfSupportDate = '2027-10-01'
        }
    }

    $populatedInventoryIndex = Resolve-NormalizedInventoryLookup `
        -DeviceId 'device-001' `
        -SoftwareVendor 'contoso' `
        -SoftwareName 'legacy_agent' `
        -SoftwareVersion '6.0.0' `
        -Context $context

    $compactIdentityInventoryIndex = Resolve-NormalizedInventoryLookup `
        -DeviceId 'device-001' `
        -SoftwareIdentityKey 'contoso|legacy_agent|6.0.0' `
        -Context $context

    Assert-True ($emptyInventoryIndex -eq -1) 'Expected empty inventory data to skip normalized inventory lookup creation.'
    Assert-True ($context.Lookups.inventory.Count -eq 1) 'Expected only the populated inventory lookup to materialize in the lookup table.'
    Assert-True ($populatedInventoryIndex -eq 0) 'Expected populated inventory data to create the first normalized inventory lookup.'
    Assert-True ($compactIdentityInventoryIndex -eq $populatedInventoryIndex) 'Expected the compact software identity key to resolve the same normalized inventory lookup.'
    Assert-True ([string]$context.Lookups.inventory[0].cpe -eq 'cpe:/a:contoso:legacy_agent:6.0.0') 'Expected populated inventory lookup to preserve ProductCodeCpe.'
}

function Test-AddNormalizedCveUsesStableSeverityIndexLookup {
    [CmdletBinding()]
    param()

    $context = Get-NormalizationContext

    $highCveIndex = Add-NormalizedCve -CveId 'CVE-2026-1001' -CvssScore '9.0' -SeverityLevel 'High' -ExploitabilityLevel 'High' -CveUrl 'https://example.test/CVE-2026-1001' -CveBatchTitle 'baseline' -Context $context
    $noneCveIndex = Add-NormalizedCve -CveId 'CVE-2026-1002' -CvssScore '0.0' -SeverityLevel 'None' -ExploitabilityLevel 'Unproven' -CveUrl 'https://example.test/CVE-2026-1002' -CveBatchTitle 'baseline' -Context $context
    $unknownCveIndex = Add-NormalizedCve -CveId 'CVE-2026-1003' -CvssScore '5.0' -SeverityLevel 'Unexpected' -ExploitabilityLevel 'ProofOfConcept' -CveUrl 'https://example.test/CVE-2026-1003' -CveBatchTitle 'baseline' -Context $context

    Assert-True ($context.Lookups.cves[$highCveIndex].sv -eq 1) 'Expected High severity CVEs to serialize severity lookup index 1.'
    Assert-True ($context.Lookups.cves[$noneCveIndex].sv -eq 4) 'Expected None severity CVEs to serialize severity lookup index 4.'
    Assert-True ($context.Lookups.cves[$unknownCveIndex].sv -eq -1) 'Expected unknown severity CVEs to preserve the fallback lookup index.'
}

function Test-GetNormalizedRecordLookupHandlesScalarPathInputs {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally refers to multiple path inputs.')]
    [CmdletBinding()]
    param()

    $context = Get-NormalizationContext

    $recordLookup = Get-NormalizedRecordLookup `
        -DeviceId 'device-001' `
        -DeviceName 'device-001.contoso.com' `
        -GroupName 'Pilot' `
        -OsPlatform 'Windows10' `
        -OsVersion '10.0.26100' `
        -MachineTags @('Pilot') `
        -SoftwareVendor 'contoso' `
        -SoftwareName 'legacy_agent' `
        -RecommendationReference '' `
        -CveId 'CVE-2026-1004' `
        -CvssScore '6.5' `
        -SeverityLevel 'Medium' `
        -ExploitabilityLevel 'High' `
        -CveUrl 'https://example.test/CVE-2026-1004' `
        -CveBatchTitle 'baseline' `
        -RecommendedSecurityUpdate '' `
        -RecommendedSecurityUpdateId '' `
        -RecommendedSecurityUpdateUrl '' `
        -SoftwareVersion '6.0.0' `
        -DiskPaths 'C:\Windows\System32\kernel32.dll' `
        -RegistryPaths 'HKLM\Software\Microsoft\Windows' `
        -SecurityUpdateAvailable $false `
        -Context $context

    Assert-True ($recordLookup.ContentLookup.dp.Count -eq 1) 'Expected scalar disk path input to resolve to a single normalized lookup index.'
    Assert-True ($recordLookup.ContentLookup.dp[0] -eq 0) 'Expected scalar disk path input to create lookup index 0.'
    Assert-True ($recordLookup.ContentLookup.rp.Count -eq 1) 'Expected scalar registry path input to resolve to a single normalized lookup index.'
    Assert-True ($recordLookup.ContentLookup.rp[0] -eq 0) 'Expected scalar registry path input to create lookup index 0.'
    Assert-True ($context.Lookups.diskPaths.Count -eq 1) 'Expected scalar disk path input to materialize one disk path lookup.'
    Assert-True ($context.Lookups.regPaths.Count -eq 1) 'Expected scalar registry path input to materialize one registry path lookup.'
}

function Test-InvokeNormalizationProgressCallbackUsesCountAndHeartbeat {
    [CmdletBinding()]
    param()

    $progressEvents = [System.Collections.Generic.List[object]]::new()
    $progressState = New-NormalizationProgressState -ProgressInterval 3 -HeartbeatIntervalSeconds 60 -CheckInterval 1

    Invoke-NormalizationProgressCallback -State $progressState -Count 1 -Callback {
        param($ProgressEvent)

        $progressEvents.Add($ProgressEvent) | Out-Null
    }
    Assert-True ($progressEvents.Count -eq 0) 'Expected normalization progress callback to remain quiet before the progress interval is reached.'

    Invoke-NormalizationProgressCallback -State $progressState -Count 3 -Callback {
        param($ProgressEvent)

        $progressEvents.Add($ProgressEvent) | Out-Null
    }

    Assert-True ($progressEvents.Count -eq 1) 'Expected normalization progress callback to fire when the progress interval is reached.'
    Assert-True ([string]$progressEvents[0].Kind -eq 'progress') 'Expected normalization progress callback events to identify progress updates.'
    Assert-True ([string]$progressEvents[0].MarkerType -eq 'progress') 'Expected interval-driven normalization callback events to be labeled as progress updates.'
    Assert-True ([long]$progressEvents[0].Count -eq 3) 'Expected normalization progress callback events to carry the processed row count.'

    $heartbeatEvents = [System.Collections.Generic.List[object]]::new()
    $heartbeatState = [PSCustomObject]@{
        ProgressInterval = 100
        HeartbeatIntervalSeconds = 60
        CheckInterval = 1
        Stopwatch = [PSCustomObject]@{
            Elapsed = [TimeSpan]::FromSeconds(61)
        }
        LastHeartbeatSecond = -1
    }

    Invoke-NormalizationProgressCallback -State $heartbeatState -Count 1 -Callback {
        param($ProgressEvent)

        $heartbeatEvents.Add($ProgressEvent) | Out-Null
    }

    Assert-True ($heartbeatEvents.Count -eq 1) 'Expected normalization progress callback to emit a heartbeat event after the heartbeat interval elapses.'
    Assert-True ([string]$heartbeatEvents[0].MarkerType -eq 'heartbeat') 'Expected elapsed-time normalization callback events to be labeled as heartbeats.'
}

function Test-ConvertToNormalizedDataReportsContentStoreNormalizationPhase {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-progress-callback-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $currentRow = Get-TestVulnRow -Id 'progress-callback-001' -CveId 'CVE-2026-0999' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'progress-callback-002' -CveId 'CVE-2026-1000' -SnapshotDate '2026-03-18' -Version '1.0.1'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $events = [System.Collections.Generic.List[object]]::new()
        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{} -SkipObservedWindowMerge -NormalizationProgressCallback {
            param($ProgressEvent)

            $events.Add([PSCustomObject]@{
                Kind = [string]$ProgressEvent.Kind
                Phase = [string]$ProgressEvent.Phase
                Message = [string]$ProgressEvent.Message
                }) | Out-Null
        }

        Assert-True ($result.VulnCount -eq 2) 'Expected content-store normalization to preserve both onboarded test rows.'
        Assert-True ($events.Count -gt 0) 'Expected ConvertTo-NormalizedData to forward normalization callback events when a callback is provided.'

        $phaseNames = @($events | Where-Object { [string]$_.Kind -eq 'phase' } | ForEach-Object { [string]$_.Phase })
        Assert-True ('LoadContentStoreDeviceProfiles' -in $phaseNames) 'Expected content-store normalization to report device-profile loading through the normalization callback.'
        Assert-True ('LoadContentStoreTemplates' -in $phaseNames) 'Expected content-store normalization to report template loading through the normalization callback.'
        Assert-True ('StreamContentStoreRefs' -in $phaseNames) 'Expected content-store normalization to report ref streaming through the normalization callback.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataUsesStableDeviceIdFallback {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-device-key-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $first = Get-TestVulnRow -Id 'device-fallback-001' -CveId 'CVE-2026-0007' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $second = Get-TestVulnRow -Id 'device-fallback-002' -CveId 'CVE-2026-0008' -SnapshotDate '2026-03-20' -Version '1.1.0'
        $second.DeviceName = 'device01-renamed.contoso.com'
        $second.RbacGroupName = 'Pilot'
        $second.OSVersion = '10.0.99999'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($first, $second)

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{}

        Assert-True ($result.Lookups.devices.Count -eq 1) 'Expected normalization to reuse DeviceId when machine enrichment is missing.'
        Assert-True ([string]$result.Lookups.devices[0].id -eq 'device-001') 'Expected normalized device entry to keep the stable DeviceId.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataWritesExpectedRowCount {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-row-count-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $currentRow = Get-TestVulnRow -Id 'row-count-001' -CveId 'CVE-2026-0009' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'row-count-002' -CveId 'CVE-2026-0010' -SnapshotDate '2026-03-18' -Version '1.1.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{}

        if ($result.VulnsPath) {
            $writtenRowCount = Get-CompactVulnJsonRowCount -Path $result.VulnsPath
        }
        elseif ($result.VulnColumnPaths) {
            # Column-store format: count entries in the device-index column
            $colJson = Get-Content -Path $result.VulnColumnPaths['d'] -Raw
            $writtenRowCount = ([Newtonsoft.Json.Linq.JArray]::Parse($colJson)).Count
        }
        else {
            throw 'ConvertTo-NormalizedData returned neither VulnsPath nor VulnColumnPaths.'
        }

        Assert-True ($result.VulnCount -eq 2) 'Expected normalized data to include both current and history vulnerability rows.'
        Assert-True ($writtenRowCount -eq $result.VulnCount) 'Expected normalized vuln file row count to match the processed vulnerability count.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataWritesDirectPayload {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-direct-payload-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'direct-payload-001' -CveId 'CVE-2026-0111' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'direct-payload-002' -CveId 'CVE-2026-0112' -SnapshotDate '2026-03-18' -Version '1.1.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)
        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0111'
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = 'Direct payload filtering regression.'
                EpssScore = 0.42
                AffectedSoftware = @(
                    'contoso:legacy_agent'
                    'microsoft:windows_11'
                )
            }
        )

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData (Read-AdvancedHuntingData -Path $tempRoot)
        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100
        $payloadCve = @($payload.lookups.cves | Where-Object { $_.id -eq 'CVE-2026-0111' })[0]
        $payloadAffectedSoftware = @($payloadCve.as | ForEach-Object { [string]$payload.lookups.affSoftware[[int]$_] } | Sort-Object)

        Assert-True ([string]::IsNullOrWhiteSpace([string]$result.VulnsPath)) 'Expected direct payload mode not to materialize a vuln rows file.'
        Assert-True ($null -eq $result.VulnColumnPaths) 'Expected direct payload mode not to materialize vuln column files.'
        Assert-True ([string]$result.PayloadPath -eq $payloadPath) 'Expected direct payload mode to return the payload path.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected direct payload row count to match the processed vulnerability count.'
        Assert-True ($payloadAffectedSoftware.Count -eq 1) 'Expected direct payload mode to filter affected software down to dataset vendors.'
        Assert-True ($payloadAffectedSoftware[0] -eq 'contoso:legacy_agent') 'Expected direct payload mode to preserve only matching affected software vendor entries.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataPreservesOptionalNvdFallback {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-optional-nvd-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $ahPreferredRow = Get-TestVulnRow -Id 'optional-nvd-001' -CveId 'CVE-2026-0131' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $nvdFallbackRow = Get-TestVulnRow -Id 'optional-nvd-002' -CveId 'CVE-2026-0132' -SnapshotDate '2026-03-20' -Version '1.1.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($ahPreferredRow, $nvdFallbackRow)
        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0131'
                PublishedDate = '2026-03-19'
                VulnerabilityDescription = 'Advanced Hunting description wins.'
                EpssScore = 0.73
                AffectedSoftware = @(
                    'contoso:legacy_agent'
                    'microsoft:windows_11'
                )
            }
        )

        $nvdDocument = [PSCustomObject]@{
            records = @(
                [PSCustomObject]@{
                    CveId = 'CVE-2026-0131'
                    PublishedDate = '2026-03-10'
                    LastModifiedDate = '2026-03-22'
                    VulnerabilityDescription = 'NVD description should remain fallback only.'
                    BaseScore = 9.8
                    BaseSeverity = 'Critical'
                    Vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    CisaExploitAdd = '2026-03-23'
                    CisaActionDue = '2026-04-01'
                    CisaRequiredAction = 'Patch now.'
                    Weaknesses = @('CWE-79')
                }
                [PSCustomObject]@{
                    CveId = 'CVE-2026-0132'
                    PublishedDate = '2026-02-11'
                    LastModifiedDate = '2026-03-25'
                    VulnerabilityDescription = 'NVD description fills missing Advanced Hunting data.'
                    BaseScore = 7.5
                    BaseSeverity = 'High'
                    Vector = 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N'
                    CisaExploitAdd = '2026-03-26'
                    CisaActionDue = '2026-04-05'
                    CisaRequiredAction = 'Prioritize patching.'
                    Weaknesses = @('CWE-416', 'CWE-787')
                }
            )
        }
        Write-GzipTextFile -Path (Get-NvdCveCurrentPath -BasePath $tempRoot) -Content ($nvdDocument | ConvertTo-Json -Compress -Depth 20)

        $result = ConvertTo-NormalizedData `
            -DataPath $tempRoot `
            -VulnOutputPath $outputPath `
            -PayloadOutputPath $payloadPath `
            -Machines @{} `
            -AdvancedHuntingData (Read-AdvancedHuntingData -Path $tempRoot) `
            -NvdCveData (Read-NvdCveData -Path $tempRoot)

        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100
        $ahPreferred = @($payload.lookups.cves | Where-Object { $_.id -eq 'CVE-2026-0131' })[0]
        $nvdFallback = @($payload.lookups.cves | Where-Object { $_.id -eq 'CVE-2026-0132' })[0]
        $ahAffectedSoftware = @($ahPreferred.as | ForEach-Object { [string]$payload.lookups.affSoftware[[int]$_] } | Sort-Object)
        $nvdWeaknesses = @($nvdFallback.nw | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

        Assert-True ($result.VulnCount -eq 2) 'Expected optional NVD regression test to normalize both CVEs.'
        Assert-True ([string]$ahPreferred.pd -eq '2026-03-19') 'Expected Advanced Hunting PublishedDate to win when present.'
        Assert-True ([string]$ahPreferred.desc -eq 'Advanced Hunting description wins.') 'Expected Advanced Hunting description to win when present.'
        Assert-True ([math]::Abs(([double]$ahPreferred.ep) - 0.73) -lt 0.00001) 'Expected Advanced Hunting EPSS score to be preserved.'
        Assert-True ($ahAffectedSoftware.Count -eq 1) 'Expected Advanced Hunting affected software to stay filtered to dataset vendors.'
        Assert-True ($ahAffectedSoftware[0] -eq 'contoso:legacy_agent') 'Expected filtered affected software to preserve the matching vendor entry.'
        Assert-True ([string]$ahPreferred.nlm -eq '2026-03-22') 'Expected NVD last-modified metadata to be preserved alongside Advanced Hunting fields.'
        Assert-True ([double]$ahPreferred.nbs -eq 9.8) 'Expected NVD base score to be preserved.'
        Assert-True ([string]$ahPreferred.nsv -eq 'Critical') 'Expected NVD base severity to be preserved.'

        Assert-True ([string]$nvdFallback.pd -eq '2026-02-11') 'Expected NVD PublishedDate to backfill when Advanced Hunting data is missing.'
        Assert-True ([string]$nvdFallback.desc -eq 'NVD description fills missing Advanced Hunting data.') 'Expected NVD description to backfill when Advanced Hunting data is missing.'
        Assert-True ($null -eq $nvdFallback.ep) 'Expected EPSS score to stay empty when Advanced Hunting does not provide it.'
        Assert-True ($null -eq $nvdFallback.as) 'Expected affected software to stay empty when Advanced Hunting does not provide it.'
        Assert-True ([string]$nvdFallback.nact -eq 'Prioritize patching.') 'Expected NVD-required action to be preserved.'
        Assert-True ($nvdWeaknesses.Count -eq 2) 'Expected NVD weaknesses to be preserved as an array.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataCanConsumeLookupsOnPayloadClose {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-consume-lookups-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'consume-lookups-001' -CveId 'CVE-2026-0151' -SnapshotDate '2026-03-20' -Version '2.0.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{} -ConsumeLookupsOnPayloadClose
        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100

        Assert-True ([string]::IsNullOrWhiteSpace([string]$result.VulnsPath)) 'Expected consuming payload mode not to materialize a vuln rows file.'
        Assert-True ([string]$result.PayloadPath -eq $payloadPath) 'Expected consuming payload mode to return the payload path.'
        Assert-True ($result.LookupsConsumed -eq $true) 'Expected consuming payload mode to report that lookups were released during payload close.'
        Assert-True ($null -eq $result.Lookups) 'Expected consuming payload mode not to retain the lookup record.'
        Assert-True ($result.DeviceCount -eq 1) 'Expected consuming payload mode to preserve the device count summary.'
        Assert-True ($result.CveCount -eq 1) 'Expected consuming payload mode to preserve the CVE count summary.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected consuming payload mode to keep the payload row count aligned with processed vulnerabilities.'
        Assert-True ($payload.lookups.devices.Count -eq 1) 'Expected consuming payload mode to still serialize device lookups into the payload.'
        Assert-True ($payload.lookups.cves.Count -eq 1) 'Expected consuming payload mode to still serialize CVE lookups into the payload.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataContentStorePathDoesNotUseLegacyDictionaryReader {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-content-store-streaming-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $originalDictionaryReader = $null

    try {
        $currentRow = Get-TestVulnRow -Id 'content-store-streaming-001' -CveId 'CVE-2026-0152' -SnapshotDate '2026-03-20' -Version '2.0.0'
        $historyRow = Get-TestVulnRow -Id 'content-store-streaming-002' -CveId 'CVE-2026-0153' -SnapshotDate '2026-03-18' -Version '2.0.1'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $originalDictionaryReader = ${function:Read-VulnContentDictionary}
        Set-Item -Path Function:Read-VulnContentDictionary -Value {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path
            )

            throw "ConvertTo-NormalizedData should stream the content dictionary during content-store normalization instead of calling Read-VulnContentDictionary for '$Path'."
        }

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{} -SkipObservedWindowMerge -ConsumeLookupsOnPayloadClose

        Assert-True ($result.VulnCount -eq 2) 'Expected content-store normalization to preserve both current and history rows while bypassing the legacy dictionary reader.'
        Assert-True ([string]$result.PayloadPath -eq $payloadPath) 'Expected content-store normalization to still write the direct payload output.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected content-store streaming normalization to keep payload row count aligned with processed rows.'
    }
    finally {
        if ($null -ne $originalDictionaryReader) {
            Set-Item -Path Function:Read-VulnContentDictionary -Value $originalDictionaryReader
        }

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-InvokeContentStoreNormalizationReleasesTransientContextBeforePayloadClose {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-content-store-context-release-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'content-store-context-release-001' -CveId 'CVE-2026-0154' -SnapshotDate '2026-03-20' -Version '2.0.0'
        $currentRow.DeviceId = 'device-context-release-001'
        $currentRow.DeviceName = 'device-context-release-001.contoso.com'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $context = Get-NormalizationContext
        $machines = @{
            'device-context-release-001' = [PSCustomObject]@{
                id = 'device-context-release-001'
                computerDnsName = 'device-context-release-001.contoso.com'
                rbacGroupName = 'Prod'
                osPlatform = 'Windows 11'
                osVersion = '10.0.26100'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.21'
                lastExternalIpAddress = '52.0.0.21'
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Low'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-03-01'
            }
        }
        $advancedHuntingData = @{
            'CVE-2026-0154' = @{
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = 'Context release regression.'
                EpssScore = 0.18
                AffectedSoftware = @('contoso:legacy_agent')
            }
        }
        $advancedHuntingDeviceUsers = @{
            'device-context-release-001' = @('alice@contoso.com')
        }
        $advancedHuntingInventoryData = @{
            (Get-AdvancedHuntingInventoryMatchKey -DeviceId 'device-context-release-001' -SoftwareVendor 'Contoso' -SoftwareName 'Legacy Agent' -SoftwareVersion '2.0.0') = [PSCustomObject]@{
                ProductCodeCpe = 'cpe:/a:contoso:legacy_agent:2.0.0'
                EndOfSupportStatus = 'supported'
                EndOfSupportDate = '2027-12-31'
            }
        }
        $nvdCveData = @{
            'CVE-2026-0154' = [PSCustomObject]@{
                PublishedDate = '2026-03-19'
                LastModifiedDate = '2026-03-21'
                VulnerabilityDescription = 'NVD fallback metadata.'
                BaseScore = 7.1
                BaseSeverity = 'High'
                Vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'
                CisaExploitAdd = $null
                CisaActionDue = $null
                CisaRequiredAction = $null
                Weaknesses = @('CWE-416')
            }
        }

        $result = Invoke-ContentStoreNormalization `
            -DataPath $tempRoot `
            -VulnOutputPath $outputPath `
            -Context $context `
            -Machines $machines `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -NvdCveData $nvdCveData `
            -PayloadOutputPath $payloadPath `
            -ConsumeLookupsOnPayloadClose

        Assert-True ($result.ProcessedCount -eq 1) 'Expected content-store context-release regression fixture to normalize one row.'
        Assert-True ([string]$result.PayloadPath -eq $payloadPath) 'Expected content-store context-release regression fixture to write the direct payload output.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.ProcessedCount) 'Expected content-store context-release regression payload row count to match the processed count.'
        Assert-True ($context.Machines.Count -eq 0) 'Expected content-store normalization to release machine lookups before payload close.'
        Assert-True ($context.AdvancedHuntingData.Count -eq 0) 'Expected content-store normalization to release Advanced Hunting CVE data before payload close.'
        Assert-True ($context.AdvancedHuntingDeviceUsers.Count -eq 0) 'Expected content-store normalization to release Advanced Hunting device-user data before payload close.'
        Assert-True ($context.NvdCveData.Count -eq 0) 'Expected content-store normalization to release NVD CVE data before payload close.'
        Assert-True ($context.AdvancedHuntingInventoryData.Count -eq 1) 'Expected content-store normalization to preserve inventory enrichment needed during ref streaming.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-GetNormalizedContentLookupCacheEntryOmitsInventoryIdentityWhenUnused {
    [CmdletBinding()]
    param()

    $contentLookup = [PSCustomObject]@{
        sw = 1
        cve = 2
        ver = 3
        upd = 4
        ua = 1
        dp = ,([int[]]@(5))
        rp = ,([int[]]@(6))
    }

    $withoutInventoryIdentity = @(Get-NormalizedContentLookupCacheEntry -ContentLookup $contentLookup)
    $withInventoryIdentity = @(Get-NormalizedContentLookupCacheEntry -IncludeInventoryIdentity -SoftwareInventoryIdentityKey 'Contoso|Legacy Agent|2.0.0' -ContentLookup $contentLookup)

    Assert-True ($withoutInventoryIdentity.Count -eq 7) 'Expected content lookup cache entries without inventory data to omit the extra software identity fields.'
    Assert-True ($withInventoryIdentity.Count -eq 8) 'Expected content lookup cache entries with inventory data to retain only the compact software identity key.'
    Assert-True ([string]$withInventoryIdentity[7] -eq 'Contoso|Legacy Agent|2.0.0') 'Expected inventory-aware cache entries to preserve the compact software identity key.'
}

function Test-GetContentStoreDeviceProfileIdentityCacheOmitsIdsWhenUnused {
    [CmdletBinding()]
    param()

    $deviceProfileIds = [System.Collections.Generic.List[string]]::new()
    $deviceProfileIds.Add('device-001') | Out-Null
    $deviceProfileIds.Add('device-002') | Out-Null

    $withoutInventoryIdentity = @(Get-ContentStoreDeviceProfileIdentityCache -DeviceProfileIds $deviceProfileIds)
    $withInventoryIdentity = @(Get-ContentStoreDeviceProfileIdentityCache -IncludeInventoryIdentity -DeviceProfileIds $deviceProfileIds)

    Assert-True ($withoutInventoryIdentity.Count -eq 0) 'Expected content-store device profile identity cache to stay empty when inventory enrichment is not in use.'
    Assert-True ($withInventoryIdentity.Count -eq 2) 'Expected content-store device profile identity cache to preserve device IDs when inventory enrichment is enabled.'
    Assert-True ([string]$withInventoryIdentity[0] -eq 'device-001') 'Expected the first cached device ID to be preserved for inventory enrichment.'
    Assert-True ([string]$withInventoryIdentity[1] -eq 'device-002') 'Expected the second cached device ID to be preserved for inventory enrichment.'
}

function Test-ConvertToNormalizedDataDeduplicatesRepeatedCveLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-repeat-cve-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $firstRow = Get-TestVulnRow -Id 'repeat-cve-001' -CveId 'CVE-2026-0155' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $secondRow = Get-TestVulnRow -Id 'repeat-cve-002' -CveId 'CVE-2026-0155' -SnapshotDate '2026-03-21' -Version '1.0.1'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($firstRow, $secondRow)

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{}
        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100

        Assert-True ($result.VulnCount -eq 2) 'Expected repeated-CVE regression test to preserve both vulnerability rows.'
        Assert-True ($result.CveCount -eq 1) 'Expected repeated rows sharing the same CVE definition to reuse a single CVE lookup.'
        Assert-True ($payload.lookups.cves.Count -eq 1) 'Expected the payload to materialize only one CVE lookup for repeated CVE rows.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataReportsZeroOnboardedContentStoreDiagnostic {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-zero-onboarded-content-store-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $currentRow = Get-TestVulnRow -Id 'zero-onboarded-001' -CveId 'CVE-2026-0156' -SnapshotDate '2026-03-20' -Version '4.0.0'
        $currentRow.IsOnboarded = $false

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $errorMessage = $null
        try {
            $null = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{} -SkipObservedWindowMerge
            throw 'Expected zero-onboarded content-store normalization to fail with a diagnostic message.'
        }
        catch {
            $errorMessage = [string]$_.Exception.Message
        }

        Assert-True ($errorMessage -like "*No onboarded vulnerabilities were produced while normalizing content-store refs*") 'Expected zero-onboarded content-store failures to identify the content-store path.'
        Assert-True ($errorMessage -like '*device profiles 1 total/0 onboarded*') 'Expected zero-onboarded content-store failures to report device profile counts.'
        Assert-True ($errorMessage -like '*content templates 1*') 'Expected zero-onboarded content-store failures to report content template counts.'
        Assert-True ($errorMessage -like '*ob missing or false*') 'Expected zero-onboarded content-store failures to hint at compact onboarding flags.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataIncludesAdvancedHuntingDeviceUserMap {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-device-users-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $currentRow = Get-TestVulnRow -Id 'device-users-001' -CveId 'CVE-2026-0121' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $currentRow.DeviceId = 'device-users-001'
        $currentRow.DeviceName = 'device-users-001.contoso.com'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0121'
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = 'Device-user tooltip regression.'
                EpssScore = 0.15
                AffectedSoftware = @('contoso:legacy_agent')
            }
            [PSCustomObject]@{
                DeviceId = 'device-users-001'
                LoggedOnUsers = '[{"AccountName":"alice","DomainName":"CONTOSO"},{"UserPrincipalName":"bob@contoso.com"},{"AccountName":"alice","DomainName":"CONTOSO"}]'
                LastModifiedTime = '2026-03-20T08:30:00Z'
            }
        )

        $machines = @{
            'device-users-001' = [PSCustomObject]@{
                id = 'device-users-001'
                computerDnsName = 'device-users-001.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.21'
                lastExternalIpAddress = '52.0.0.21'
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-01'
            }
        }

        $advancedHuntingData = Read-AdvancedHuntingData -Path $tempRoot
        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $tempRoot
        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines $machines -AdvancedHuntingData $advancedHuntingData -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers

        $device = @($result.Lookups.devices | Where-Object { $_.id -eq 'device-users-001' })[0]
        $users = @($device.m.u)

        Assert-True ($advancedHuntingDeviceUsers.Count -eq 1) 'Expected one device-user entry to be loaded from Advanced Hunting.'
        Assert-True ($users.Count -eq 2) 'Expected normalized machine info to include two unique logged-on users.'
        Assert-True ('CONTOSO\alice' -in $users) 'Expected normalized device users to include the domain-qualified account name.'
        Assert-True ('bob@contoso.com' -in $users) 'Expected normalized device users to include the user principal name.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-WriteCombinedPayloadGzipPreservesColumnPayload {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('combined-payload-columns-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $columnPath = Join-Path $tempRoot 'columns'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'combined-columns-001' -CveId 'CVE-2026-0211' -SnapshotDate '2026-03-21' -Version '2.0.0'
        $historyRow = Get-TestVulnRow -Id 'combined-columns-002' -CveId 'CVE-2026-0212' -SnapshotDate '2026-03-19' -Version '2.1.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        $result = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -VulnColumnDirectoryPath $columnPath -Machines @{} -AdvancedHuntingData @{}
        Write-CombinedPayloadGzip -Lookups $result.Lookups -VulnColumnPaths $result.VulnColumnPaths -OutputPath $payloadPath

        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100

        Assert-True ([string]::IsNullOrWhiteSpace([string]$result.VulnsPath)) 'Expected explicit column normalization not to materialize a vuln rows file.'
        Assert-True ($null -ne $result.VulnColumnPaths) 'Expected explicit column normalization to return vuln column paths.'
        Assert-True ($payload.vulnsFormat -eq 'columns-v1') 'Expected combined payload writer to preserve the columns-v1 payload format.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected combined payload row count to match the processed vulnerability count.'
        Assert-True (@($payload.vulns.d).Count -eq $result.VulnCount) 'Expected device column count to match the processed vulnerability count.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NormalizedVulnColumnCacheRebuildsPayloadWithFreshLookups {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name is intentionally plural because it validates payload rebuild behavior across cached lookup inputs.')]
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-column-cache-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $columnPath = Join-Path $tempRoot 'columns'
    $originalPayloadPath = Join-Path $tempRoot 'original-payload.json.gz'
    $reusedPayloadPath = Join-Path $tempRoot 'reused-payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'column-cache-001' -CveId 'CVE-2026-0511' -SnapshotDate '2026-03-21' -Version '6.0.0'
        $historyRow = Get-TestVulnRow -Id 'column-cache-002' -CveId 'CVE-2026-0512' -SnapshotDate '2026-03-19' -Version '6.1.0'
        $historyRow.DeviceId = 'device-002'
        $historyRow.DeviceName = 'device02.contoso.com'
        $historyRow.MachineTags = @('Pilot', 'Prod')

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)
        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0511'
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = 'Column cache rebuild regression.'
                EpssScore = 0.31
                AffectedSoftware = @('contoso:legacy_agent')
            }
            [PSCustomObject]@{
                CveId = 'CVE-2026-0512'
                PublishedDate = '2026-03-18'
                VulnerabilityDescription = 'Column cache rebuild regression history row.'
                EpssScore = 0.22
                AffectedSoftware = @('contoso:legacy_agent')
            }
        )

        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $advancedHuntingData = Read-AdvancedHuntingData -Path $tempRoot
        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $tempRoot
        $advancedHuntingInventoryData = Read-AdvancedHuntingInventoryData -Path $tempRoot
        $normalizedResult = ConvertTo-NormalizedData `
            -DataPath $tempRoot `
            -VulnOutputPath $outputPath `
            -VulnColumnDirectoryPath $columnPath `
            -Machines @{} `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -SkipObservedWindowMerge
        Write-CombinedPayloadGzip -Lookups $normalizedResult.Lookups -VulnColumnPaths $normalizedResult.VulnColumnPaths -OutputPath $originalPayloadPath

        $cacheEntry = Publish-NormalizedVulnColumnCache `
            -BasePath $tempRoot `
            -VulnColumnPaths $normalizedResult.VulnColumnPaths `
            -VulnCount $normalizedResult.VulnCount `
            -Dates @($normalizedResult.Lookups.dates) `
            -Quality $normalizedResult.Quality `
            -SkipObservedWindowMerge `
            -InventoryTupleCount $advancedHuntingInventoryData.Count
        $restoredCacheEntry = Get-NormalizedVulnColumnCacheEntry -BasePath $tempRoot -SkipObservedWindowMerge
        $restoredLookups = Restore-ContentStoreNormalizedLookupsFromColumnCache `
            -DataPath $tempRoot `
            -Machines @{} `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -CachedDates @($restoredCacheEntry.Manifest.Dates)
        Write-CombinedPayloadGzip -Lookups $restoredLookups.Lookups -VulnColumnPaths $restoredCacheEntry.ColumnPaths -OutputPath $reusedPayloadPath

        $originalPayloadJson = Read-GzipTextFile -Path $originalPayloadPath
        $reusedPayloadJson = Read-GzipTextFile -Path $reusedPayloadPath

        Assert-True ($null -ne $cacheEntry) 'Expected normalized vuln column cache publish to succeed.'
        Assert-True ($null -ne $restoredCacheEntry) 'Expected normalized vuln column cache retrieval to succeed.'
        Assert-True ($advancedHuntingInventoryData.Count -eq 0) 'Expected test fixture to avoid Advanced Hunting inventory tuples so column cache reuse stays valid.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $originalPayloadPath) -eq (Get-CompressedPayloadVulnCount -Path $reusedPayloadPath)) 'Expected cached column payload rebuild to preserve vulnerability row count.'
        Assert-True ($originalPayloadJson -eq $reusedPayloadJson) 'Expected cached normalized vuln columns plus rebuilt lookups to reproduce the same payload JSON.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NormalizedVulnColumnCacheRefreshesInventoryColumn {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-column-cache-inventory-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $columnPath = Join-Path $tempRoot 'columns'
    $refreshedColumnPath = Join-Path $tempRoot 'refreshed-columns'
    $originalPayloadPath = Join-Path $tempRoot 'original-payload.json.gz'
    $reusedPayloadPath = Join-Path $tempRoot 'reused-payload.json.gz'

    try {
        $currentRow = Get-TestVulnRow -Id 'column-cache-inventory-001' -CveId 'CVE-2026-0611' -SnapshotDate '2026-03-21' -Version '6.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)

        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0611'
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = 'Column cache inventory regression.'
                EpssScore = 0.31
                AffectedSoftware = @('contoso:legacy_agent')
            }
            [PSCustomObject]@{
                DeviceId = 'device-001'
                SoftwareVendor = 'contoso'
                SoftwareName = 'legacy_agent'
                SoftwareVersion = '6.0.0'
                ProductCodeCpe = 'cpe:/a:contoso:legacy_agent:6.0.0'
                EndOfSupportStatus = 'supported'
                EndOfSupportDate = '2027-10-01'
            }
        )

        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $advancedHuntingData = Read-AdvancedHuntingData -Path $tempRoot
        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $tempRoot
        $advancedHuntingInventoryData = Read-AdvancedHuntingInventoryData -Path $tempRoot
        $normalizedResult = ConvertTo-NormalizedData `
            -DataPath $tempRoot `
            -VulnOutputPath $outputPath `
            -VulnColumnDirectoryPath $columnPath `
            -Machines @{} `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -SkipObservedWindowMerge
        Write-CombinedPayloadGzip -Lookups $normalizedResult.Lookups -VulnColumnPaths $normalizedResult.VulnColumnPaths -OutputPath $originalPayloadPath

        $cacheEntry = Publish-NormalizedVulnColumnCache `
            -BasePath $tempRoot `
            -VulnColumnPaths $normalizedResult.VulnColumnPaths `
            -VulnCount $normalizedResult.VulnCount `
            -Dates @($normalizedResult.Lookups.dates) `
            -Quality $normalizedResult.Quality `
            -SkipObservedWindowMerge `
            -InventoryTupleCount $advancedHuntingInventoryData.Count
        $restoredCacheEntry = Get-NormalizedVulnColumnCacheEntry -BasePath $tempRoot -SkipObservedWindowMerge
        $restoredLookups = Restore-ContentStoreNormalizedLookupsFromColumnCache `
            -DataPath $tempRoot `
            -Machines @{} `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -CachedDates @($restoredCacheEntry.Manifest.Dates)
        $restoredColumnPaths = Restore-NormalizedVulnColumnPathsFromCache `
            -CachedColumnPaths $restoredCacheEntry.ColumnPaths `
            -RestoredLookupsResult $restoredLookups `
            -OutputDirectoryPath $refreshedColumnPath `
            -CachedInventoryTupleCount ([int]$restoredCacheEntry.Manifest.InventoryTupleCount)
        Write-CombinedPayloadGzip -Lookups $restoredLookups.Lookups -VulnColumnPaths $restoredColumnPaths.ColumnPaths -OutputPath $reusedPayloadPath

        $originalPayloadJson = Read-GzipTextFile -Path $originalPayloadPath
        $reusedPayloadJson = Read-GzipTextFile -Path $reusedPayloadPath

        Assert-True ($null -ne $cacheEntry) 'Expected normalized vuln column cache publish to succeed for an inventory-backed fixture.'
        Assert-True ($null -ne $restoredCacheEntry) 'Expected normalized vuln column cache retrieval to succeed for an inventory-backed fixture.'
        Assert-True ($advancedHuntingInventoryData.Count -eq 1) 'Expected the inventory-backed fixture to produce one Advanced Hunting inventory tuple.'
        Assert-True ($restoredColumnPaths.RefreshedInventoryColumn -eq $true) 'Expected cached inventory column regeneration to run for an inventory-backed fixture.'
        Assert-True ($restoredLookups.Lookups.inventory.Count -eq $normalizedResult.Lookups.inventory.Count) 'Expected refreshed inventory lookups to preserve the same lookup cardinality as the original normalization.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $originalPayloadPath) -eq (Get-CompressedPayloadVulnCount -Path $reusedPayloadPath)) 'Expected refreshed inventory-column payload rebuild to preserve vulnerability row count.'
        Assert-True ($originalPayloadJson -eq $reusedPayloadJson) 'Expected cached normalized vuln columns plus refreshed inventory column to reproduce the same payload JSON.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-AdvancedHuntingBundleMatchesDedicatedReaderData {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('advanced-hunting-bundle-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        Write-NdjsonRecordsFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0711'
                PublishedDate = '2026-03-20'
                VulnerabilityDescription = @('Bundle regression line 1.', 'Bundle regression line 2.')
                EpssScore = 0.31
                AffectedSoftware = @('contoso:legacy_agent')
                IsExploitAvailable = 'true'
            }
            [PSCustomObject]@{
                DeviceId = 'device-001'
                LoggedOnUsers = @(
                    [PSCustomObject]@{ UserPrincipalName = 'user1@contoso.com' }
                    [PSCustomObject]@{ DomainName = 'CONTOSO'; AccountName = 'user2' }
                )
            }
            [PSCustomObject]@{
                DeviceId = 'device-001'
                SoftwareVendor = 'contoso'
                SoftwareName = 'legacy_agent'
                SoftwareVersion = '6.0.0'
                ProductCodeCpe = 'cpe:/a:contoso:legacy_agent:6.0.0'
                EndOfSupportStatus = 'supported'
                EndOfSupportDate = '2027-10-01'
            }
        )

        $advancedHuntingData = Read-AdvancedHuntingData -Path $tempRoot
        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUserMap -Path $tempRoot
        $advancedHuntingInventoryData = Read-AdvancedHuntingInventoryData -Path $tempRoot
        $bundle = Read-AdvancedHuntingBundle -Path $tempRoot -IncludeDeviceUsers -IncludeInventoryData

        Assert-True ($bundle.AdvancedHuntingData.Count -eq $advancedHuntingData.Count) 'Expected Advanced Hunting bundle CVE count to match the dedicated reader.'
        Assert-True ($bundle.DeviceUsers.Count -eq $advancedHuntingDeviceUsers.Count) 'Expected Advanced Hunting bundle device-user count to match the dedicated reader.'
        Assert-True ($bundle.InventoryData.Count -eq $advancedHuntingInventoryData.Count) 'Expected Advanced Hunting bundle inventory count to match the dedicated reader.'

        $bundleCve = $bundle.AdvancedHuntingData['CVE-2026-0711']
        $dedicatedCve = $advancedHuntingData['CVE-2026-0711']
        Assert-True ($bundleCve.PublishedDate -eq $dedicatedCve.PublishedDate) 'Expected bundle CVE published date to match the dedicated reader.'
        Assert-True ($bundleCve.VulnerabilityDescription -eq $dedicatedCve.VulnerabilityDescription) 'Expected bundle CVE description to match the dedicated reader.'
        Assert-True ($bundleCve.EpssScore -eq $dedicatedCve.EpssScore) 'Expected bundle CVE EPSS score to match the dedicated reader.'
        Assert-True ($bundleCve.IsExploitAvailable -eq $dedicatedCve.IsExploitAvailable) 'Expected bundle CVE exploit availability to match the dedicated reader.'
        Assert-True (@($bundleCve.AffectedSoftware).Count -eq @($dedicatedCve.AffectedSoftware).Count) 'Expected bundle CVE affected software count to match the dedicated reader.'
        Assert-True (@($bundleCve.AffectedSoftware)[0] -eq @($dedicatedCve.AffectedSoftware)[0]) 'Expected bundle CVE affected software values to match the dedicated reader.'

        $bundleUsers = @($bundle.DeviceUsers['device-001'])
        $dedicatedUsers = @($advancedHuntingDeviceUsers['device-001'])
        Assert-True ($bundleUsers.Count -eq $dedicatedUsers.Count) 'Expected bundle device-user list length to match the dedicated reader.'
        Assert-True ($bundleUsers[0] -eq $dedicatedUsers[0]) 'Expected bundle device-user list to preserve the first user.'
        Assert-True ($bundleUsers[1] -eq $dedicatedUsers[1]) 'Expected bundle device-user list to preserve the second user.'

        $inventoryKey = Get-AdvancedHuntingInventoryMatchKey -DeviceId 'device-001' -SoftwareVendor 'contoso' -SoftwareName 'legacy_agent' -SoftwareVersion '6.0.0'
        $bundleInventory = $bundle.InventoryData[$inventoryKey]
        $dedicatedInventory = $advancedHuntingInventoryData[$inventoryKey]
        Assert-True ($bundleInventory.ProductCodeCpe -eq $dedicatedInventory.ProductCodeCpe) 'Expected bundle inventory ProductCodeCpe to match the dedicated reader.'
        Assert-True ($bundleInventory.EndOfSupportStatus -eq $dedicatedInventory.EndOfSupportStatus) 'Expected bundle inventory EndOfSupportStatus to match the dedicated reader.'
        Assert-True ($bundleInventory.EndOfSupportDate -eq $dedicatedInventory.EndOfSupportDate) 'Expected bundle inventory EndOfSupportDate to match the dedicated reader.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-AdvancedHuntingBundleStringArrayFiltersSparseInputs {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally refers to multiple sparse inputs.')]
    [CmdletBinding()]
    param()

    $emptyResult = ConvertTo-AdvancedHuntingBundleStringArray -Value @()
    Assert-True ($emptyResult -is [string[]]) 'Expected empty Advanced Hunting bundle string arrays to preserve the string[] output type.'
    Assert-True ($emptyResult.Count -eq 0) 'Expected an empty Advanced Hunting bundle input to remain empty.'

    $singletonResult = ConvertTo-AdvancedHuntingBundleStringArray -Value 'contoso:legacy_agent'
    Assert-True ($singletonResult -is [string[]]) 'Expected singleton Advanced Hunting bundle values to preserve the string[] output type.'
    Assert-True ($singletonResult.Count -eq 1) 'Expected a singleton Advanced Hunting bundle value to stay a single entry.'
    Assert-True ($singletonResult[0] -eq 'contoso:legacy_agent') 'Expected a singleton Advanced Hunting bundle value to remain unchanged.'

    $filteredResult = ConvertTo-AdvancedHuntingBundleStringArray -Value @($null, 'contoso:legacy_agent', '   ', 'fabrikam:browser', "`t")
    Assert-True ($filteredResult -is [string[]]) 'Expected filtered Advanced Hunting bundle values to preserve the string[] output type.'
    Assert-True ($filteredResult.Count -eq 2) 'Expected Advanced Hunting bundle string normalization to drop null and whitespace-only entries.'
    Assert-True ($filteredResult[0] -eq 'contoso:legacy_agent') 'Expected Advanced Hunting bundle string normalization to preserve the first non-empty value.'
    Assert-True ($filteredResult[1] -eq 'fabrikam:browser') 'Expected Advanced Hunting bundle string normalization to preserve later non-empty values in order.'
}

function Test-ReadNormalizationMachineLookupMatchesCompressedMachineLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-tuple-reader-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        Write-NdjsonRecordsFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Records @(
            [PSCustomObject]@{
                id = 'device-live'
                computerDnsName = 'device-live.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.1'
                lastExternalIpAddress = '203.0.113.10'
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'High'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-03-10'
            }
            [PSCustomObject]@{
                id = 'device-sparse'
                computerDnsName = 'device-sparse.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = $null
                lastExternalIpAddress = $null
                healthStatus = $null
                riskScore = $null
                exposureLevel = $null
                deviceValue = $null
                managedBy = $null
                isAadJoined = $null
                lastSeen = $null
                firstSeen = $null
            }
            [PSCustomObject]@{
                id = 'device-removed'
                removed = $true
                observedOn = '2026-03-20'
                stateHash = 'removed'
            }
        )

        $standardMachines = Read-MachineData -Path $tempRoot
        $compressedMachines = @{}
        foreach ($deviceId in @($standardMachines.Keys)) {
            $compressedMachines[$deviceId] = $standardMachines[$deviceId]
        }
        Compress-NormalizationMachineLookup -Machines $compressedMachines | Out-Null

        $tupleMachines = Read-NormalizationMachineLookup -Path $tempRoot

        Assert-True ($tupleMachines.Count -eq $compressedMachines.Count) 'Expected tuple-mode machine loading to preserve the same machine count as the compressed machine lookup path.'
        Assert-True ($tupleMachines.ContainsKey('device-live')) 'Expected tuple-mode machine loading to preserve populated machines.'
        Assert-True ($tupleMachines.ContainsKey('device-sparse')) 'Expected tuple-mode machine loading to retain sparse machines when extended normalization metadata is present.'
        Assert-True (-not $tupleMachines.ContainsKey('device-removed')) 'Expected tuple-mode machine loading to drop removed machines from the current lookup.'

        $expectedTuple = [object[]]$compressedMachines['device-live']
        $actualTuple = [object[]]$tupleMachines['device-live']
        Assert-True ($actualTuple -is [System.Array]) 'Expected tuple-mode machine loading to materialize array-backed normalization tuples.'
        Assert-True ($actualTuple.Length -eq $expectedTuple.Length) 'Expected tuple-mode machine loading to preserve the normalization tuple shape.'

        $expectedSparseTuple = [object[]]$compressedMachines['device-sparse']
        $actualSparseTuple = [object[]]$tupleMachines['device-sparse']
        Assert-True ($actualSparseTuple -is [System.Array]) 'Expected tuple-mode machine loading to materialize sparse machines as array-backed normalization tuples.'
        Assert-True ($actualSparseTuple.Length -eq $expectedSparseTuple.Length) 'Expected tuple-mode machine loading to preserve the sparse normalization tuple shape.'

        for ($tupleIndex = 0; $tupleIndex -lt $expectedTuple.Length; $tupleIndex++) {
            $expectedTupleValue = ConvertTo-Json -InputObject $expectedTuple[$tupleIndex] -Compress -Depth 20
            $actualTupleValue = ConvertTo-Json -InputObject $actualTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualTupleValue -eq $expectedTupleValue) "Expected tuple-mode machine loading to preserve tuple slot $tupleIndex."
        }

        for ($tupleIndex = 0; $tupleIndex -lt $expectedSparseTuple.Length; $tupleIndex++) {
            $expectedSparseTupleValue = ConvertTo-Json -InputObject $expectedSparseTuple[$tupleIndex] -Compress -Depth 20
            $actualSparseTupleValue = ConvertTo-Json -InputObject $actualSparseTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualSparseTupleValue -eq $expectedSparseTupleValue) "Expected tuple-mode machine loading to preserve sparse tuple slot $tupleIndex."
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NormalizationMachineTupleExtendsLegacyTuple {
    [CmdletBinding()]
    param()

    $legacyTuple = [object[]]@(
        '10.0.0.30',
        '203.0.113.30',
        'Active',
        'Medium',
        'High',
        'Normal',
        'Intune',
        $true,
        '2026-04-22T00:00:00Z',
        '2026-04-01T00:00:00Z'
    )

    $normalizationTuple = ConvertTo-NormalizationMachineTuple -Machine $legacyTuple

    Assert-True ($normalizationTuple -is [object[]]) 'Expected legacy machine tuples to normalize as an object[] array.'
    Assert-True ($normalizationTuple.Count -eq 15) 'Expected legacy machine tuples with 10 elements to be extended to 15 normalization slots.'

    foreach ($index in 0..9) {
        Assert-True ($normalizationTuple[$index] -eq $legacyTuple[$index]) ("Expected normalization tuple slot {0} to preserve the legacy tuple value." -f $index)
    }

    foreach ($index in 10..14) {
        Assert-True ($null -eq $normalizationTuple[$index]) ("Expected normalization tuple slot {0} to be null-padded for legacy tuples without expanded metadata." -f $index)
    }
}

function Test-LegacyMachineTupleFallbackPreservesProjectedRowMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally describes legacy tuple fallback behavior.')]
    [CmdletBinding()]
    param()

    $legacyMachineTuple = [object[]]@(
        '10.0.0.30',
        '203.0.113.30',
        'Active',
        'Medium',
        'High',
        'Normal',
        'Intune',
        $true,
        '2026-04-22T00:00:00Z',
        '2026-04-01T00:00:00Z'
    )

    $projection = Get-MachineProjection -Machine $legacyMachineTuple
    Assert-True ($null -eq $projection.ComputerDnsName) 'Expected legacy tuples without expanded metadata to preserve a null ComputerDnsName projection.'
    Assert-True ($null -eq $projection.OSPlatform) 'Expected legacy tuples without expanded metadata to preserve a null OSPlatform projection.'
    Assert-True ($null -eq $projection.OSVersion) 'Expected legacy tuples without expanded metadata to preserve a null OSVersion projection.'

    $context = Get-NormalizationContext
    $context.Machines['device-legacy'] = $legacyMachineTuple

    $deviceIndex = Add-NormalizedDevice `
        -DeviceId 'device-legacy' `
        -DeviceName 'legacy-device.contoso.com' `
        -GroupName 'Pilot' `
        -OsPlatform 'Windows11' `
        -OsVersion '10.0.26100' `
        -MachineTags @('Pilot') `
        -Context $context

    $deviceLookup = $context.Lookups.devices[$deviceIndex]

    Assert-True ($deviceLookup.n -eq 'legacy-device.contoso.com') 'Expected Add-NormalizedDevice to fall back to the row DeviceName when a legacy tuple has no ComputerDnsName.'
    Assert-True ($context.Lookups.groups[$deviceLookup.g] -eq 'Pilot') 'Expected Add-NormalizedDevice to fall back to the row GroupName when a legacy tuple has no RBAC group.'
    Assert-True ($context.Lookups.platforms[$deviceLookup.o] -eq 'Windows11') 'Expected Add-NormalizedDevice to fall back to the row OSPlatform when a legacy tuple has no platform metadata.'
    Assert-True ($deviceLookup.ov -eq '10.0.26100') 'Expected Add-NormalizedDevice to fall back to the row OSVersion when a legacy tuple has no OSVersion metadata.'
    Assert-True ($context.Lookups.tags[$deviceLookup.t[0]] -eq 'Pilot') 'Expected Add-NormalizedDevice to fall back to row machine tags when a legacy tuple has no tag metadata.'
    Assert-True ($deviceLookup.m.ip -eq '10.0.0.30') 'Expected Add-NormalizedDevice to preserve machine info pulled from the legacy tuple.'
}

function Test-SourceCveEnrichmentReadsExploitAvailabilityFromObjectRecord {
    [CmdletBinding()]
    param()

    $vendorSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$vendorSet.Add((Get-VendorMatchKey -Vendor 'Contoso'))

    $advancedHunting = @{
        'CVE-2026-7777' = [PSCustomObject]@{
            PublishedDate = '2026-04-14'
            VulnerabilityDescription = 'Example vulnerability description.'
            EpssScore = 0.0042
            AffectedSoftware = @('Contoso:Legacy Agent')
            IsExploitAvailable = $true
        }
    }

    $enrichment = Get-SourceCveEnrichment -CveId 'CVE-2026-7777' -AdvancedHunting $advancedHunting -NvdCveData $null -VendorSet $vendorSet

    Assert-True ($enrichment.IsExploitAvailable -eq $true) 'Expected exploit availability to be preserved for PSCustomObject-based Advanced Hunting records.'
}

function Test-WriteBase64FileContentMatchesReferenceOutput {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('base64-writer-regression-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $filePath = Join-Path $tempRoot 'fixture.bin'

    try {
        $bytes = [byte[]]::new(65539)
        for ($index = 0; $index -lt $bytes.Length; $index++) {
            $bytes[$index] = [byte](($index * 17 + 29) % 256)
        }
        [System.IO.File]::WriteAllBytes($filePath, $bytes)

        $singleLineWriter = [System.IO.StringWriter]::new([System.Globalization.CultureInfo]::InvariantCulture)
        try {
            Write-Base64FileContent -Writer $singleLineWriter -FilePath $filePath
            $singleLineActual = $singleLineWriter.ToString()
        }
        finally {
            $singleLineWriter.Dispose()
        }

        $wrappedWriter = [System.IO.StringWriter]::new([System.Globalization.CultureInfo]::InvariantCulture)
        try {
            Write-Base64FileContent -Writer $wrappedWriter -FilePath $filePath -InsertLineBreaks
            $wrappedActual = $wrappedWriter.ToString()
        }
        finally {
            $wrappedWriter.Dispose()
        }

        $singleLineExpected = Get-Base64FileContent -FilePath $filePath
        $wrappedExpected = Get-Base64FileContent -FilePath $filePath -InsertLineBreaks

        Assert-True ($singleLineActual -eq $singleLineExpected) 'Expected streamed base64 writer to match the reference single-line output.'
        Assert-True ($wrappedActual -eq $wrappedExpected) 'Expected streamed base64 writer to match the reference wrapped output.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ValidationHelperPayloadCanonicalization {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('validation-helper-payload-formats-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $rowsOutputPath = Join-Path $tempRoot 'rows-normalized.json'
    $rowsPayloadPath = Join-Path $tempRoot 'rows-payload.json.gz'
    $columnsOutputPath = Join-Path $tempRoot 'columns-normalized.json'
    $columnPath = Join-Path $tempRoot 'columns'
    $columnsPayloadPath = Join-Path $tempRoot 'columns-payload.json.gz'

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $currentRow = Get-TestVulnRow -Id 'validation-format-001' -CveId 'CVE-2026-0311' -SnapshotDate '2026-03-20' -Version '3.0.0'
        $historyRow = Get-TestVulnRow -Id 'validation-format-002' -CveId 'CVE-2026-0312' -SnapshotDate '2026-03-18' -Version '3.1.0'
        $historyRow.DeviceId = 'device-002'
        $historyRow.DeviceName = 'device02.contoso.com'
        $historyRow.MachineTags = @('Pilot', 'Prod')
        $historyRow.DiskPaths = @('C:\Program Files\Legacy Agent\agent-alt.exe')
        $historyRow.RegistryPaths = @('HKLM\Software\Contoso\LegacyAgentAlt')

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        $rowsResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $rowsOutputPath -PayloadOutputPath $rowsPayloadPath -Machines @{} -AdvancedHuntingData @{}
        $columnsResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $columnsOutputPath -VulnColumnDirectoryPath $columnPath -Machines @{} -AdvancedHuntingData @{}
        Write-CombinedPayloadGzip -Lookups $columnsResult.Lookups -VulnColumnPaths $columnsResult.VulnColumnPaths -OutputPath $columnsPayloadPath

        $rowFormatSignatures = @(Read-PayloadCanonicalSignatureStream -PayloadPath $rowsPayloadPath | Sort-Object)
        $columnFormatSignatures = @(Read-PayloadCanonicalSignatureStream -PayloadPath $columnsPayloadPath | Sort-Object)

        Assert-True ($rowsResult.VulnCount -eq 2) 'Expected rows-v1 payload fixture to contain two vulnerability rows.'
        Assert-True ($columnsResult.VulnCount -eq 2) 'Expected columns-v1 payload fixture to contain two vulnerability rows.'
        Assert-True ($rowFormatSignatures.Count -eq $columnFormatSignatures.Count) 'Expected validation helper canonicalization to return the same number of rows for rows-v1 and columns-v1 payloads.'
        Assert-True (@(Compare-Object -ReferenceObject $rowFormatSignatures -DifferenceObject $columnFormatSignatures).Count -eq 0) 'Expected validation helper canonicalization to treat rows-v1 and columns-v1 payloads as semantically equivalent.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ValidationHelperStandaloneImport {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $pwshPath = Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Source
    if ([string]::IsNullOrWhiteSpace($pwshPath)) {
        throw 'pwsh is required to run validation helper import regression checks.'
    }

    $smokeScript = @'
$ErrorActionPreference = 'Stop'

. '__REPO_ROOT__\build\Import-ValidationHelpers.ps1'

$row = [PSCustomObject]@{
    DeviceId = 'device-standalone-001'
    DeviceName = 'device01.contoso.com'
    RbacGroupName = 'Prod'
    OSPlatform = 'Windows11'
    OSVersion = '23H2'
    MachineTags = @('Pilot')
    MachineInfo = [PSCustomObject]@{
        ip = '10.0.0.5'
        eip = '52.160.0.5'
        hs = 'Active'
        rs = 'Medium'
        el = 'Low'
        dv = 'Standard'
        mb = 'Intune'
        aad = $true
        ls = '2026-03-20'
        fs = '2026-03-01'
    }
    CveId = 'CVE-2026-0401'
    CvssScore = '7.5'
    VulnerabilitySeverityLevel = 'High'
    ExploitabilityLevel = 'ExploitIsPublic'
    CveBatchUrl = 'https://example.invalid/CVE-2026-0401'
    CveBatchTitle = 'Windows cumulative update'
    PublishedDate = '2026-03-02'
    VulnerabilityDescription = 'Standalone validation helper import smoke test'
    EpssScore = '0.81'
    AffectedSoftware = @('microsoft:windows')
    IsExploitAvailable = $true
    NvdLastModifiedDate = '2026-03-18'
    NvdBaseScore = '8.0'
    NvdBaseSeverity = 'HIGH'
    NvdVector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    NvdKevDate = '2026-03-19'
    NvdActionDue = '2026-04-01'
    NvdRequiredAction = 'Patch immediately'
    NvdWeaknesses = @('CWE-79')
    SoftwareVendor = 'microsoft'
    SoftwareName = 'windows'
    SoftwareVersion = '10.0.26100.1'
    RecommendationReference = 'Windows Security Update'
    ProductCodeCpe = 'cpe:/o:microsoft:windows_11'
    EndOfSupportStatus = 'supported'
    EndOfSupportDate = '2027-10-01'
    FirstSeenTimestamp = '2026-03-03'
    LastSeenTimestamp = '2026-03-20'
    SecurityUpdateAvailable = $true
    RecommendedSecurityUpdate = 'March 2026 cumulative update'
    RecommendedSecurityUpdateId = 'KB6000001'
    RecommendedSecurityUpdateUrl = 'https://example.invalid/kb6000001'
    DiskPaths = @('C:\Windows\System32\kernel32.dll')
    RegistryPaths = @('HKLM\Software\Microsoft\Windows')
}

$signature = Get-CanonicalValidationRowSignature -Row $row
if ([string]::IsNullOrWhiteSpace($signature)) {
    throw 'Standalone validation helper import smoke returned an empty signature.'
}
'@.Replace('__REPO_ROOT__', $repoRoot.Replace("'", "''"))

    & $pwshPath -NoProfile -Command $smokeScript
    if ($LASTEXITCODE -ne 0) {
        throw 'Standalone validation helper import smoke failed.'
    }
}

function Test-DashboardValidationFailureExtendedEnrichmentGate {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent

    . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

    $audit = [PSCustomObject]@{
        RowComparison = [PSCustomObject]@{
            Match = $true
            MissingCount = 0
            ExtraCount = 0
        }
        EnrichmentAudit = [PSCustomObject]@{
            PublishedDateMismatchCount = 0
            DescriptionMismatchCount = 0
            EpssMismatchCount = 0
            AffectedSoftwareMismatchCount = 0
            ExploitAvailableMismatchCount = 1
            NvdLastModifiedMismatchCount = 0
            NvdBaseScoreMismatchCount = 1
            NvdBaseSeverityMismatchCount = 0
            NvdVectorMismatchCount = 0
            NvdKevMismatchCount = 0
            NvdActionDueMismatchCount = 0
            NvdRequiredActionMismatchCount = 0
            NvdWeaknessMismatchCount = 0
        }
        ReportComparisons = @()
        LegacyMigrationAudit = [PSCustomObject]@{
            Enabled = $false
        }
    }

    $failures = @(Get-DashboardValidationFailure -Audit $audit)

    Assert-True ($failures.Count -eq 1) 'Expected extended enrichment mismatch counters to add exactly one validation failure.'
    Assert-True ($failures[0] -eq 'Dashboard enrichment fields do not match the source data.') 'Expected extended enrichment mismatch counters to use the standard enrichment failure message.'
}

function Test-StreamingDashboardAuditDetectsSourceMismatchDespitePayloadParity {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('streaming-dashboard-source-parity-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $vulnOutputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $htmlPath = Join-Path $tempRoot 'dashboard.html'

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $currentRow = Get-TestVulnRow -Id 'streaming-audit-001' -CveId 'CVE-2026-0321' -SnapshotDate '2026-03-20' -Version '4.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)

        $normalizedResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $vulnOutputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{}
        $payloadCacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $normalizedResult.PayloadPath -VulnCount $normalizedResult.VulnCount -DeviceCount $normalizedResult.Lookups.devices.Count -CveCount $normalizedResult.Lookups.cves.Count -Quality $normalizedResult.Quality

        $dashboardConfigJson = ([ordered]@{ payloadUrl = 'payload.json.gz' } | ConvertTo-Json -Compress)
        $dashboardHtml = @(
            '<!DOCTYPE html>'
            '<html lang="en">'
            '<head><meta charset="utf-8"><title>Streaming Audit Fixture</title></head>'
            '<body>'
            '<script id="dataFormat" type="application/json">external-compressed</script>'
            ('<script id="dashboardConfig" type="application/json">' + $dashboardConfigJson + '</script>')
            '</body>'
            '</html>'
        ) -join [Environment]::NewLine
        [System.IO.File]::WriteAllText($htmlPath, $dashboardHtml, [System.Text.UTF8Encoding]::new($false))

        $previousForceFull = $Script:DashboardValidationForceFull
        $Script:DashboardValidationForceFull = $true
        try {
            $primeAudit = Get-StreamingDashboardAuditResult -ResolvedHtmlPath $htmlPath -ResolvedExportsPath $tempRoot -PayloadCacheEntry $payloadCacheEntry

            $mutatedRow = Get-TestVulnRow -Id 'streaming-audit-002' -CveId 'CVE-2026-0322' -SnapshotDate '2026-03-21' -Version '4.1.0'
            Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow, $mutatedRow)

            $contentStoreFiles = @(
                Get-VulnContentDictionaryPath -BasePath $tempRoot
                Get-VulnCurrentRefsPath -BasePath $tempRoot
                Get-VulnHistoryRefsPath -BasePath $tempRoot -PeriodKey '2026Q1'
            )
            foreach ($contentStoreFile in $contentStoreFiles) {
                if (-not [string]::IsNullOrWhiteSpace($contentStoreFile) -and (Test-Path -LiteralPath $contentStoreFile -PathType Leaf)) {
                    Remove-Item -LiteralPath $contentStoreFile -Force -ErrorAction SilentlyContinue
                }
            }

            $audit = Get-StreamingDashboardAuditResult -ResolvedHtmlPath $htmlPath -ResolvedExportsPath $tempRoot -PayloadCacheEntry $payloadCacheEntry
        }
        finally {
            $Script:DashboardValidationForceFull = $previousForceFull
        }

        Assert-True ($primeAudit.RowComparison.Match -eq $true) 'Expected the priming forced streaming audit to succeed before the source exports diverge.'
        Assert-True ($primeAudit.SemanticParity.SourceSignatureCacheUsed -eq $false) 'Expected the priming forced streaming audit to build the source signature cache.'
        Assert-True ($audit.PayloadParity.Match -eq $true) 'Expected dashboard payload bytes to remain equal to the cached normalized payload.'
        Assert-True ($audit.SemanticParity.PayloadByteParityMatch -eq $true) 'Expected streaming audit diagnostics to record dashboard payload byte parity.'
        Assert-True ($audit.RowComparison.Match -eq $false) 'Expected streaming semantic parity to fail when the source exports diverge from the dashboard payload.'
        Assert-True ($audit.RowComparison.MissingCount -eq 1) 'Expected the extra source row to be reported as missing from the dashboard payload.'
        Assert-True ([string]$audit.SemanticParity.ComparisonPayloadSource -eq 'cached-payload') 'Expected source streaming audit to reuse the cached payload when byte parity proves dashboard equivalence.'
        Assert-True ($audit.SemanticParity.SourceSignatureCacheUsed -eq $false) 'Expected the streaming audit to bypass the cached source signature set after the source exports fingerprint changes.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-StreamingDashboardAuditReusesCachedPayloadSignatureSet {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('streaming-dashboard-payload-signatures-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $vulnOutputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $htmlPath = Join-Path $tempRoot 'dashboard.html'

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $currentRow = Get-TestVulnRow -Id 'streaming-cache-001' -CveId 'CVE-2026-0421' -SnapshotDate '2026-03-20' -Version '5.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)

        $normalizedResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $vulnOutputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{}
        $payloadCacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $normalizedResult.PayloadPath -VulnCount $normalizedResult.VulnCount -DeviceCount $normalizedResult.Lookups.devices.Count -CveCount $normalizedResult.Lookups.cves.Count -Quality $normalizedResult.Quality

        $dashboardConfigJson = ([ordered]@{ payloadUrl = 'payload.json.gz' } | ConvertTo-Json -Compress)
        $dashboardHtml = @(
            '<!DOCTYPE html>'
            '<html lang="en">'
            '<head><meta charset="utf-8"><title>Streaming Audit Cache Fixture</title></head>'
            '<body>'
            '<script id="dataFormat" type="application/json">external-compressed</script>'
            ('<script id="dashboardConfig" type="application/json">' + $dashboardConfigJson + '</script>')
            '</body>'
            '</html>'
        ) -join [Environment]::NewLine
        [System.IO.File]::WriteAllText($htmlPath, $dashboardHtml, [System.Text.UTF8Encoding]::new($false))

        $previousForceFull = $Script:DashboardValidationForceFull
        $Script:DashboardValidationForceFull = $true
        try {
            $firstAudit = Get-StreamingDashboardAuditResult -ResolvedHtmlPath $htmlPath -ResolvedExportsPath $tempRoot -PayloadCacheEntry $payloadCacheEntry
            $secondAudit = Get-StreamingDashboardAuditResult -ResolvedHtmlPath $htmlPath -ResolvedExportsPath $tempRoot -PayloadCacheEntry $payloadCacheEntry
        }
        finally {
            $Script:DashboardValidationForceFull = $previousForceFull
        }

        Assert-True ($firstAudit.RowComparison.Match -eq $true) 'Expected the initial forced streaming audit to succeed before caching payload signatures.'
        Assert-True ($firstAudit.SemanticParity.SourceSignatureCacheUsed -eq $false) 'Expected the initial forced streaming audit to build the source signature cache.'
        Assert-True ($firstAudit.SemanticParity.PayloadSignatureCacheUsed -eq $false) 'Expected the initial forced streaming audit to build the payload signature cache.'
        Assert-True ($secondAudit.RowComparison.Match -eq $true) 'Expected the repeated forced streaming audit to preserve semantic parity.'
        Assert-True ($secondAudit.SemanticParity.SourceSignatureCacheUsed -eq $true) 'Expected the repeated forced streaming audit to reuse the cached source signature set.'
        Assert-True ($secondAudit.SemanticParity.PayloadSignatureCacheUsed -eq $true) 'Expected the repeated forced streaming audit to reuse the cached payload signature set.'
        Assert-True ([double]$secondAudit.SemanticParity.SourceSignatureElapsedSeconds -lt [double]$firstAudit.SemanticParity.SourceSignatureElapsedSeconds) 'Expected cached source signature reuse to reduce the source signature phase time on the repeated forced streaming audit.'
        Assert-True ([double]$secondAudit.SemanticParity.PayloadSignatureElapsedSeconds -lt [double]$firstAudit.SemanticParity.PayloadSignatureElapsedSeconds) 'Expected cached payload signature reuse to reduce the payload signature phase time on the repeated forced streaming audit.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardAuditBootstrapsSyntheticLargePayloadCacheWithNormalizationLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-audit-synthetic-bootstrap-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $vulnOutputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $htmlPath = Join-Path $tempRoot 'dashboard.html'

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $row = Get-TestVulnRow -Id 'synthetic-bootstrap-001' -CveId 'CVE-2026-0521' -SnapshotDate '2026-03-20' -Version '6.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($row)

        $machines = @(
            [PSCustomObject]@{
                id = 'device-001'
                computerDnsName = 'device01.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.21'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-01'
            }
        )

        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), ($machines | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'AdvancedHunting_Current.json'), '[]', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'synthetic-manifest.json'), (([ordered]@{
            actualCurrentRows = 100000
            actualHistoryRows = 0
        }) | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))

        $normalizationMachines = Read-NormalizationMachineLookup -Path $tempRoot
        $normalizedResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $vulnOutputPath -PayloadOutputPath $payloadPath -Machines $normalizationMachines -AdvancedHuntingData @{} -AdvancedHuntingDeviceUsers @{} -AdvancedHuntingInventoryData @{} -NvdCveData @{} -SkipObservedWindowMerge

        $dashboardConfigJson = ([ordered]@{ payloadUrl = 'payload.json.gz' } | ConvertTo-Json -Compress)
        $dashboardHtml = @(
            '<!DOCTYPE html>'
            '<html lang="en">'
            '<head><meta charset="utf-8"><title>Synthetic Bootstrap Fixture</title></head>'
            '<body>'
            '<script id="dataFormat" type="application/json">external-compressed</script>'
            ('<script id="dashboardConfig" type="application/json">' + $dashboardConfigJson + '</script>')
            '</body>'
            '</html>'
        ) -join [Environment]::NewLine
        [System.IO.File]::WriteAllText($htmlPath, $dashboardHtml, [System.Text.UTF8Encoding]::new($false))

        $payloadCacheEntryBeforeAudit = Get-NormalizedPayloadCacheEntry -BasePath $tempRoot -SkipObservedWindowMerge
        $audit = Get-DashboardAuditResult -ResolvedHtmlPath $htmlPath -ResolvedExportsPath $tempRoot
        $payloadCacheEntryAfterAudit = Get-NormalizedPayloadCacheEntry -BasePath $tempRoot -SkipObservedWindowMerge

        Assert-True ($null -eq $payloadCacheEntryBeforeAudit) 'Expected synthetic large-dataset validation to start without a normalized payload cache entry.'
        Assert-True ($normalizedResult.VulnCount -eq 1) 'Expected the synthetic bootstrap fixture to generate exactly one normalized vulnerability row.'
        Assert-True ($audit.RowComparison.Match -eq $true) 'Expected dashboard audit to preserve semantic parity after bootstrapping a synthetic large-dataset payload cache from tuple-backed machines.'
        Assert-True ($null -ne $payloadCacheEntryAfterAudit) 'Expected synthetic large-dataset validation to publish a normalized payload cache entry.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardValidationUsesStableFallbackDeviceProfile {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-validation-device-profile-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $auditPath = Join-Path $tempRoot 'audit.json'

    try {
        $first = Get-TestVulnRow -Id 'device-profile-001' -CveId 'CVE-2026-0107' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $second = Get-TestVulnRow -Id 'device-profile-002' -CveId 'CVE-2026-0108' -SnapshotDate '2026-03-20' -Version '1.1.0'
        $second.DeviceName = 'device01-renamed.contoso.com'
        $second.RbacGroupName = 'Pilot'
        $second.OSVersion = '10.0.99999'
        $second.MachineTags = @('Pilot')
        $second.DiskPaths = @('C:\Program Files\Legacy Agent\agent-renamed.exe')
        $second.RegistryPaths = @('HKLM\Software\Contoso\LegacyAgentRenamed')

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($first, $second)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), '[]', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'AdvancedHunting_Current.json'), '[]', [System.Text.UTF8Encoding]::new($false))

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -Validate -ValidationOutputPath $auditPath | Out-Null

        $audit = Get-Content -Path $auditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($audit.RowComparison.Match -eq $true) 'Expected dashboard validation to reuse the stable fallback device profile for machine-less rows.'
        Assert-True ($audit.RowComparison.MissingCount -eq 0) 'Expected no missing rows when fallback device metadata varies across rows.'
        Assert-True ($audit.RowComparison.ExtraCount -eq 0) 'Expected no extra rows when fallback device metadata varies across rows.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardOpenStateAuditUsesPatchEvidenceAndInactivityCutoff {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-open-state-audit-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $auditPath = Join-Path $tempRoot 'audit.json'

    try {
        $patchedRow = Get-TestVulnRow -Id 'patched-001' -CveId 'CVE-2026-0201' -SnapshotDate '2026-03-01' -Version '1.0.0'
        $patchedRow.DeviceId = 'device-patched'
        $patchedRow.DeviceName = 'device-patched.contoso.com'

        $assumedOpenRow = Get-TestVulnRow -Id 'open-001' -CveId 'CVE-2026-0202' -SnapshotDate '2026-03-01' -Version '1.1.0'
        $assumedOpenRow.DeviceId = 'device-open'
        $assumedOpenRow.DeviceName = 'device-open.contoso.com'

        $staleRow = Get-TestVulnRow -Id 'stale-001' -CveId 'CVE-2026-0203' -SnapshotDate '2026-01-01' -Version '1.2.0'
        $staleRow.DeviceId = 'device-stale'
        $staleRow.DeviceName = 'device-stale.contoso.com'
        $staleRow.FirstSeenTimestamp = '2026-01-01'
        $staleRow.LastSeenTimestamp = '2026-01-01'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($assumedOpenRow, $staleRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($patchedRow)

        $machines = @(
            [PSCustomObject]@{
                id = 'device-patched'
                computerDnsName = 'device-patched.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.10'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-10'
                firstSeen = '2026-02-01'
            }
            [PSCustomObject]@{
                id = 'device-open'
                computerDnsName = 'device-open.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.11'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Medium'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-01'
                firstSeen = '2026-02-01'
            }
            [PSCustomObject]@{
                id = 'device-stale'
                computerDnsName = 'device-stale.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod')
                lastIpAddress = '10.0.0.12'
                lastExternalIpAddress = ''
                healthStatus = 'Inactive'
                riskScore = 'Low'
                exposureLevel = 'Low'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-01-01'
                firstSeen = '2025-12-01'
            }
        )

        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), ($machines | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'AdvancedHunting_Current.json'), '[]', [System.Text.UTF8Encoding]::new($false))

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -Validate -ValidationOutputPath $auditPath | Out-Null

        $audit = Get-Content -Path $auditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ([string]$audit.OpenStateAudit.LatestObservedDate -eq '2026-03-10') 'Expected latest observed date to follow the most recent machine heartbeat.'
        Assert-True ($audit.OpenStateAudit.ProvenPatchedRowCount -eq 1) 'Expected exactly one row with positive patch evidence.'
        Assert-True ($audit.OpenStateAudit.AssumedOpenRowCount -eq 2) 'Expected two rows to remain in the assumed-open bucket.'
        Assert-True ($audit.OpenStateAudit.InactiveSuppressedRowCount -eq 1) 'Expected one assumed-open row to age out after the inactivity cutoff.'
        Assert-True ($audit.OpenStateAudit.CurrentOpenRowCount -eq 1) 'Expected only one row to remain open at the latest observed date.'
        Assert-True ($audit.OpenStateAudit.CurrentOpenDeviceCount -eq 1) 'Expected only one device to contribute to the current open backlog.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardValidationPreservesNoneSeverityData {
    [CmdletBinding()]
    param()

    $fixturePath = Join-Path $PSScriptRoot 'fixtures\legacy-migration-none-severity'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-none-severity-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $auditPath = Join-Path $tempRoot 'audit.json'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        $cachePath = Join-Path $tempRoot '.dashboard-cache'
        if (Test-Path -LiteralPath $cachePath) {
            Remove-Item -LiteralPath $cachePath -Recurse -Force -ErrorAction SilentlyContinue
        }

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -Validate -ValidationOutputPath $auditPath | Out-Null

        $audit = Get-Content -Path $auditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($audit.RowComparison.Match -eq $true) 'Expected dashboard validation to preserve rows with VulnerabilitySeverityLevel=None.'
        Assert-True ($audit.RowComparison.MissingCount -eq 0) 'Expected no missing rows for none-severity data.'
        Assert-True ($audit.RowComparison.ExtraCount -eq 0) 'Expected no extra rows for none-severity data.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardSplitAssetsGenerationAndValidation {
    [CmdletBinding()]
    param()

    $fixturePath = Join-Path $PSScriptRoot 'fixtures\legacy-migration-none-severity'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-split-assets-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $auditPath = Join-Path $tempRoot 'audit.json'
    $validateOnlyAuditPath = Join-Path $tempRoot 'audit-validate-only.json'
    $assetsPath = Join-Path $tempRoot 'dashboard.assets'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        $cachePath = Join-Path $tempRoot '.dashboard-cache'
        if (Test-Path -LiteralPath $cachePath) {
            Remove-Item -LiteralPath $cachePath -Recurse -Force -ErrorAction SilentlyContinue
        }

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -SplitAssets -Validate -ValidationOutputPath $auditPath | Out-Null

        Assert-True ((Test-Path -LiteralPath $outputPath -PathType Leaf)) 'Expected split-assets generation to write the dashboard HTML.'
        Assert-True ((Test-Path -LiteralPath $assetsPath -PathType Container)) 'Expected split-assets generation to create the sibling asset directory.'

        foreach ($assetFileName in @('dashboard.css', 'dashboard.js', 'pako.js', 'chart.js', 'pdf-export.bundle.js', 'payload.json.gz')) {
            Assert-True ((Test-Path -LiteralPath (Join-Path $assetsPath $assetFileName) -PathType Leaf)) ("Expected split-assets generation to write '{0}'." -f $assetFileName)
        }

        $dashboardHtml = Get-Content -LiteralPath $outputPath -Raw
        Assert-True ($dashboardHtml.Contains('dashboard.assets/dashboard.css')) 'Expected split-assets dashboard HTML to reference the external stylesheet.'
        Assert-True ($dashboardHtml.Contains('dashboard.assets/dashboard.js')) 'Expected split-assets dashboard HTML to reference the external dashboard script.'
        Assert-True ($dashboardHtml.Contains('dashboard.assets/payload.json.gz')) 'Expected split-assets dashboard HTML to reference the external payload.'
        Assert-True ($dashboardHtml.Contains('external-compressed')) 'Expected split-assets dashboard HTML to advertise the external-compressed payload mode.'

        $audit = Get-Content -LiteralPath $auditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($audit.RowComparison.Match -eq $true) 'Expected split-assets dashboard validation to match the normalized source rows.'
        Assert-True ($audit.RowComparison.MissingCount -eq 0) 'Expected no missing rows in split-assets dashboard validation.'
        Assert-True ($audit.RowComparison.ExtraCount -eq 0) 'Expected no extra rows in split-assets dashboard validation.'

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ValidateOnly -ValidationOutputPath $validateOnlyAuditPath | Out-Null

        $validateOnlyAudit = Get-Content -LiteralPath $validateOnlyAuditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($validateOnlyAudit.RowComparison.Match -eq $true) 'Expected ValidateOnly to read and validate the external split-assets payload.'
        Assert-True ($validateOnlyAudit.RowComparison.MissingCount -eq 0) 'Expected ValidateOnly split-assets validation to report no missing rows.'
        Assert-True ($validateOnlyAudit.RowComparison.ExtraCount -eq 0) 'Expected ValidateOnly split-assets validation to report no extra rows.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardValidateOnlyFailsWhenHostedPayloadMissing {
    [CmdletBinding()]
    param()

    $fixturePath = Join-Path $PSScriptRoot 'fixtures\legacy-migration-none-severity'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-hosted-negative-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $outputPath = Join-Path $tempRoot 'dashboard.html'
    $auditPath = Join-Path $tempRoot 'audit.json'
    $assetsPath = Join-Path $tempRoot 'dashboard.assets'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -SplitAssets | Out-Null

        $payloadAssetPath = Join-Path $assetsPath 'payload.json.gz'
        Assert-True ((Test-Path -LiteralPath $payloadAssetPath -PathType Leaf)) 'Expected split-assets generation to write a hosted payload before the negative validation step.'
        Remove-Item -LiteralPath $payloadAssetPath -Force

        & pwsh -NoProfile -File $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ValidateOnly -ValidationOutputPath $auditPath | Out-Null
        $validationExitCode = $LASTEXITCODE

        Assert-True ($validationExitCode -ne 0) 'Expected ValidateOnly to fail when a hosted dashboard payload asset is missing.'
        Assert-True (-not (Test-Path -LiteralPath $auditPath -PathType Leaf)) 'Expected missing hosted payload validation to avoid writing a passing audit artifact.'
    }
    finally {
        $global:LASTEXITCODE = 0
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-PackageOnlyRejectsMismatchedNormalizedPayloadManifest {
    [CmdletBinding()]
    param()

    $fixturePath = Join-Path $PSScriptRoot 'fixtures\legacy-migration-none-severity'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-package-negative-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $normalizedPayloadPath = Join-Path $tempRoot '.local\payload\dashboard-payload.json.gz'
    $normalizedManifestPath = Join-Path $tempRoot '.local\payload\dashboard-payload.json'
    $tamperedPayloadPath = Join-Path $tempRoot '.local\payload\dashboard-payload-tampered.json.gz'
    $outputPath = Join-Path $tempRoot 'dashboard.html'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        & $dashboardScriptPath -DirectoryPath $tempRoot -ExportMachineData:$false -NormalizeOnly -NormalizedPayloadOutputPath $normalizedPayloadPath -NormalizedPayloadManifestOutputPath $normalizedManifestPath | Out-Null
        Assert-True ((Test-Path -LiteralPath $normalizedPayloadPath -PathType Leaf)) 'Expected NormalizeOnly to materialize a payload for the package-only negative test.'
        Assert-True ((Test-Path -LiteralPath $normalizedManifestPath -PathType Leaf)) 'Expected NormalizeOnly to materialize a manifest for the package-only negative test.'

        Write-GzipTextFile -Path $tamperedPayloadPath -Content '{"lookups":{"devices":[],"cves":[]},"vulnsFormat":"rows-v1","vulns":[]}'

        & pwsh -NoProfile -File $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -PackageOnly -NormalizedPayloadInputPath $tamperedPayloadPath -NormalizedPayloadManifestInputPath $normalizedManifestPath | Out-Null
        $packageExitCode = $LASTEXITCODE

        Assert-True ($packageExitCode -ne 0) 'Expected package-only generation to reject a payload whose bytes do not match the provided manifest.'
        Assert-True (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) 'Expected package-only manifest mismatch to avoid writing a dashboard.'
    }
    finally {
        $global:LASTEXITCODE = 0
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-DashboardDualPackagingGenerationAndValidation {
    [CmdletBinding()]
    param()

    $fixturePath = Join-Path $PSScriptRoot 'fixtures\legacy-migration-none-severity'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-dual-package-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $dashboardScriptPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
    $selfContainedOutputPath = Join-Path $tempRoot 'dashboard.html'
    $hostedOutputPath = Join-Path $tempRoot 'dashboard.Hosted.html'
    $hostedAssetsPath = Join-Path $tempRoot 'dashboard.Hosted.assets'
    $normalizedPayloadPath = Join-Path $tempRoot '.local\payload\dashboard-payload.json.gz'
    $selfAuditPath = Join-Path $tempRoot 'audit.json'
    $hostedAuditPath = Join-Path $tempRoot 'audit.hosted.json'
    $hostedValidateOnlyAuditPath = Join-Path $tempRoot 'audit.hosted.validate-only.json'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        $cachePath = Join-Path $tempRoot '.dashboard-cache'
        if (Test-Path -LiteralPath $cachePath) {
            Remove-Item -LiteralPath $cachePath -Recurse -Force -ErrorAction SilentlyContinue
        }

        & $dashboardScriptPath -DirectoryPath $tempRoot -ExportMachineData:$false -NormalizeOnly -NormalizedPayloadOutputPath $normalizedPayloadPath | Out-Null
        Assert-True ((Test-Path -LiteralPath $normalizedPayloadPath -PathType Leaf)) 'Expected NormalizeOnly to materialize the normalized payload for dual packaging.'

        $packageOutput = @(& $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $selfContainedOutputPath -ExportMachineData:$false -PackageOnly -NormalizedPayloadInputPath $normalizedPayloadPath -DualPackage -Validate -ValidationOutputPath $selfAuditPath 6>&1)
        $packageMessages = @($packageOutput | ForEach-Object { Get-OutputRecordText -Record $_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $hostedWriteMessageIndex = -1
        $selfContainedWriteMessageIndex = -1
        for ($i = 0; $i -lt $packageMessages.Count; $i++) {
            if ($hostedWriteMessageIndex -lt 0 -and $packageMessages[$i].Contains('Writing hosted dashboard to')) {
                $hostedWriteMessageIndex = $i
            }

            if ($selfContainedWriteMessageIndex -lt 0 -and $packageMessages[$i].Contains('Writing self-contained dashboard to')) {
                $selfContainedWriteMessageIndex = $i
            }
        }

        Assert-True ((Test-Path -LiteralPath $selfContainedOutputPath -PathType Leaf)) 'Expected dual packaging to write the self-contained dashboard HTML.'
        Assert-True ((Test-Path -LiteralPath $hostedOutputPath -PathType Leaf)) 'Expected dual packaging to write the hosted dashboard HTML.'
        Assert-True ((Test-Path -LiteralPath $hostedAssetsPath -PathType Container)) 'Expected dual packaging to create the hosted sibling asset directory.'
        Assert-True ($hostedWriteMessageIndex -ge 0) 'Expected dual packaging output to announce hosted dashboard generation.'
        Assert-True ($selfContainedWriteMessageIndex -ge 0) 'Expected dual packaging output to announce self-contained dashboard generation.'
        Assert-True ($hostedWriteMessageIndex -lt $selfContainedWriteMessageIndex) 'Expected dual packaging to write the hosted dashboard before the self-contained dashboard.'

        foreach ($assetFileName in @('dashboard.css', 'dashboard.js', 'pako.js', 'chart.js', 'pdf-export.bundle.js', 'payload.json.gz')) {
            Assert-True ((Test-Path -LiteralPath (Join-Path $hostedAssetsPath $assetFileName) -PathType Leaf)) ("Expected dual packaging to write '{0}' to the hosted asset directory." -f $assetFileName)
        }

        Assert-True ((Test-Path -LiteralPath ($selfContainedOutputPath + '.validation.json') -PathType Leaf)) 'Expected dual packaging to write a self-contained validation sidecar.'
        Assert-True ((Test-Path -LiteralPath ($hostedOutputPath + '.validation.json') -PathType Leaf)) 'Expected dual packaging to write a hosted validation sidecar.'

        $selfContainedHtml = Get-Content -LiteralPath $selfContainedOutputPath -Raw
        Assert-True ($selfContainedHtml.Contains('<script id="vulnsData" type="application/json">')) 'Expected the self-contained dashboard to embed the compressed payload script.'
        Assert-True ($selfContainedHtml.Contains('compressed')) 'Expected the self-contained dashboard to advertise the embedded compressed payload mode.'

        $hostedHtml = Get-Content -LiteralPath $hostedOutputPath -Raw
        Assert-True ($hostedHtml.Contains('dashboard.Hosted.assets/dashboard.css')) 'Expected the hosted dual-packaged dashboard to reference the hosted stylesheet.'
        Assert-True ($hostedHtml.Contains('dashboard.Hosted.assets/dashboard.js')) 'Expected the hosted dual-packaged dashboard to reference the hosted dashboard script.'
        Assert-True ($hostedHtml.Contains('dashboard.Hosted.assets/payload.json.gz')) 'Expected the hosted dual-packaged dashboard to reference the hosted payload.'
        Assert-True ($hostedHtml.Contains('external-compressed')) 'Expected the hosted dual-packaged dashboard to advertise the external-compressed payload mode.'

        $selfAudit = Get-Content -LiteralPath $selfAuditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($selfAudit.RowComparison.Match -eq $true) 'Expected dual packaging validation to preserve rows in the self-contained dashboard.'
        Assert-True ($selfAudit.RowComparison.MissingCount -eq 0) 'Expected no missing rows in self-contained dual packaging validation.'
        Assert-True ($selfAudit.RowComparison.ExtraCount -eq 0) 'Expected no extra rows in self-contained dual packaging validation.'

        $hostedAudit = Get-Content -LiteralPath $hostedAuditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($hostedAudit.RowComparison.Match -eq $true) 'Expected dual packaging validation to preserve rows in the hosted dashboard.'
        Assert-True ($hostedAudit.RowComparison.MissingCount -eq 0) 'Expected no missing rows in hosted dual packaging validation.'
        Assert-True ($hostedAudit.RowComparison.ExtraCount -eq 0) 'Expected no extra rows in hosted dual packaging validation.'

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $hostedOutputPath -ValidateOnly -ValidationOutputPath $hostedValidateOnlyAuditPath | Out-Null

        $hostedValidateOnlyAudit = Get-Content -LiteralPath $hostedValidateOnlyAuditPath -Raw | ConvertFrom-Json -Depth 100
        Assert-True ($hostedValidateOnlyAudit.RowComparison.Match -eq $true) 'Expected ValidateOnly to validate the hosted dual-packaged dashboard.'
        Assert-True ($hostedValidateOnlyAudit.RowComparison.MissingCount -eq 0) 'Expected ValidateOnly hosted dual packaging validation to report no missing rows.'
        Assert-True ($hostedValidateOnlyAudit.RowComparison.ExtraCount -eq 0) 'Expected ValidateOnly hosted dual packaging validation to report no extra rows.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnContentStoreRoundTrip {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-content-store-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalDictionaryReader = $null

    try {
        $currentRow = Get-TestVulnRow -Id 'content-001' -CveId 'CVE-2026-0101' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'content-002' -CveId 'CVE-2026-0102' -SnapshotDate '2026-03-18' -Version '1.1.0'
        $historyRow.DeviceId = 'device-002'
        $historyRow.DeviceName = 'device02.contoso.com'
        $historyRow.MachineTags = @('Pilot', 'Servers')

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $originalDictionaryReader = ${function:Read-VulnContentDictionary}
        Set-Item -Path Function:Read-VulnContentDictionary -Value {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path
            )

            throw "Read-VulnContentStoreRow should stream reduced content lookups instead of calling Read-VulnContentDictionary for '$Path'."
        }

        $roundTripped = @(Read-VulnContentStoreRow -BasePath $tempRoot | Sort-Object Id)

        Assert-True ((Test-Path -LiteralPath (Get-VulnContentDictionaryPath -BasePath $tempRoot) -PathType Leaf)) 'Expected vulnerability content dictionary sidecar to be created.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentRefsPath -BasePath $tempRoot) -PathType Leaf)) 'Expected vulnerability current refs sidecar to be created.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryRefsPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Expected vulnerability history refs sidecar to be created.'
        Assert-True ($roundTripped.Count -eq 2) 'Expected content sidecar round-trip to return both current and history rows.'

        $expectedRows = @($currentRow, $historyRow) | Sort-Object Id
        for ($i = 0; $i -lt $expectedRows.Count; $i++) {
            $expected = $expectedRows[$i]
            $actual = $roundTripped[$i]

            foreach ($propertyName in @(
                'Id',
                'DeviceId',
                'DeviceName',
                'RbacGroupName',
                'OSPlatform',
                'OSVersion',
                'CveId',
                'SoftwareVendor',
                'SoftwareName',
                'SoftwareVersion',
                'VulnerabilitySeverityLevel',
                'ExploitabilityLevel',
                'RecommendationReference',
                'RecommendedSecurityUpdate',
                'RecommendedSecurityUpdateId',
                'RecommendedSecurityUpdateUrl',
                'FirstSeenTimestamp',
                'LastSeenTimestamp',
                'CveBatchTitle',
                'CveBatchUrl'
            )) {
                Assert-True ([string]$expected.$propertyName -eq [string]$actual.$propertyName) "Expected content sidecar round-trip to preserve property '$propertyName'."
            }

            Assert-True ((@($expected.MachineTags) -join '|') -eq (@($actual.MachineTags) -join '|')) 'Expected content sidecar round-trip to preserve machine tags.'
            Assert-True ((@($expected.DiskPaths) -join '|') -eq (@($actual.DiskPaths) -join '|')) 'Expected content sidecar round-trip to preserve disk paths.'
            Assert-True ((@($expected.RegistryPaths) -join '|') -eq (@($actual.RegistryPaths) -join '|')) 'Expected content sidecar round-trip to preserve registry paths.'
            Assert-True (($expected.SecurityUpdateAvailable -eq $true) -eq ($actual.SecurityUpdateAvailable -eq $true)) 'Expected content sidecar round-trip to preserve update availability.'
            Assert-True (($expected.IsOnboarded -eq $true) -eq ($actual.IsOnboarded -eq $true)) 'Expected content sidecar round-trip to preserve onboarded state.'
        }
    }
    finally {
        if ($null -ne $originalDictionaryReader) {
            Set-Item -Path Function:Read-VulnContentDictionary -Value $originalDictionaryReader
        }

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-VulnObservedWindowCacheRoundTrip {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-observed-cache-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalDictionaryReader = $null

    try {
        $currentRow = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-17' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-19' -Version '1.0.0'
        $historyRow.RecommendedSecurityUpdate = 'KB000099'
        $historyRow.RecommendedSecurityUpdateId = 'KB000099'
        $otherHistoryRow = Get-TestVulnRow -Id 'merge-002' -CveId 'CVE-2026-0005' -SnapshotDate '2026-03-23' -Version '2.0.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow, $otherHistoryRow)

        Publish-VulnContentStoreUnlocked -BasePath $tempRoot
        $expectedRows = @(Write-MergedVulnObservedWindowRows -Source { @($currentRow, $historyRow, $otherHistoryRow) } | Sort-Object Id, FirstSeenTimestamp, LastSeenTimestamp)
        $cachePath = Publish-VulnObservedWindowCache -BasePath $tempRoot

        Assert-True ((Test-Path -LiteralPath $cachePath -PathType Leaf)) 'Expected observed-window cache to be created.'

        $originalDictionaryReader = ${function:Read-VulnContentDictionary}
        Set-Item -Path Function:Read-VulnContentDictionary -Value {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path
            )

            throw "Get-NormalizationSourceRows should stream reduced content lookups for compact observed-window caches instead of calling Read-VulnContentDictionary for '$Path'."
        }

        # Read the cache through Get-NormalizationSourceRows which auto-detects
        # the compact ref format (T5) or legacy full-record format.
        $cachedRows = @(Get-NormalizationSourceRows -DataPath $tempRoot | Sort-Object Id, FirstSeenTimestamp, LastSeenTimestamp)
        Assert-True ($expectedRows.Count -eq $cachedRows.Count) 'Expected observed-window cache to preserve merged row count.'

        for ($i = 0; $i -lt $expectedRows.Count; $i++) {
            $expected = $expectedRows[$i]
            $actual = $cachedRows[$i]
            foreach ($propertyName in @(
                'Id',
                'DeviceId',
                'CveId',
                'RecommendedSecurityUpdate',
                'RecommendedSecurityUpdateId',
                'FirstSeenTimestamp',
                'LastSeenTimestamp'
            )) {
                Assert-True ([string]$expected.$propertyName -eq [string]$actual.$propertyName) "Expected observed-window cache to preserve property '$propertyName'."
            }
        }
    }
    finally {
        if ($null -ne $originalDictionaryReader) {
            Set-Item -Path Function:Read-VulnContentDictionary -Value $originalDictionaryReader
        }

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-FunctionAppWriteOutputNoEnumeratePreservesJObject {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $functionAppPath = Join-Path $repoRoot 'azure\function-app\ExportAndGenerate\run.ps1'
    Assert-True ((Test-Path -LiteralPath $functionAppPath -PathType Leaf)) "Expected generated Function App artifact at '$functionAppPath'."

    $artifactText = Get-Content -LiteralPath $functionAppPath -Raw
    $functionMatch = [regex]::Match($artifactText, '(?s)function Write-Output \{.*?\r?\n\}\r?\n\r?\n\$isPastDue')
    Assert-True ($functionMatch.Success) 'Expected generated Function App artifact to contain the traced Write-Output override.'

    $functionDefinition = $functionMatch.Value -replace '\r?\n\r?\n\$isPastDue\z', ''
    $observed = @(& {
        function Write-PipelineFileTraceLine {
            param($Message)

            $null = $Message
        }

        . ([scriptblock]::Create($functionDefinition))

        $token = [Newtonsoft.Json.Linq.JObject]::Parse('{"ob":true,"id":"device-001"}')
        @(Write-Output -InputObject $token -NoEnumerate)
    })

    Assert-True ($observed.Count -eq 1) 'Expected Function App Write-Output -NoEnumerate to emit exactly one object.'
    Assert-True ($observed[0] -is [Newtonsoft.Json.Linq.JObject]) 'Expected Function App Write-Output -NoEnumerate to preserve JObject identity.'
    Assert-True ((Get-VulnPropertyValue -InputObject $observed[0] -Name 'ob') -eq $true) 'Expected Function App Write-Output -NoEnumerate to preserve compact boolean properties.'
}

function Test-FunctionExecutionStatusSummaryIncludesNormalizationProgressInfo {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $validationScriptPath = Join-Path $repoRoot 'build\Invoke-AzureDeploymentValidation.ps1'
    Assert-True ((Test-Path -LiteralPath $validationScriptPath -PathType Leaf)) "Expected validation script at '$validationScriptPath'."

    $scriptText = Get-Content -LiteralPath $validationScriptPath -Raw
    $functionMatch = [regex]::Match($scriptText, '(?s)function Get-FunctionExecutionStatusSummaryText \{.*?\r?\n\}\r?\n\r?\nfunction Set-FunctionExecutionControlBlob')
    Assert-True ($functionMatch.Success) 'Expected validation script to contain Get-FunctionExecutionStatusSummaryText.'

    $functionDefinition = $functionMatch.Value -replace '\r?\n\r?\nfunction Set-FunctionExecutionControlBlob\z', ''
    $summary = & {
        . ([scriptblock]::Create($functionDefinition))

        Get-FunctionExecutionStatusSummaryText -StatusDocument ([PSCustomObject]@{
                status = 'running'
                stage = 'NormalizeDashboardData'
                message = 'Streaming content-store vulnerability references into the normalized payload.'
                pipelineArchitectureVersion = 'monolithic-v1'
                normalizedPayloadCacheHit = $false
                normalizedSubPhase = 'StreamContentStoreRefs'
                normalizedRowCount = 125000
            })
    }

    Assert-True ($summary -like '*arch=monolithic-v1*') 'Expected validation status summary text to retain architecture metadata.'
    Assert-True ($summary -like '*payloadCache=miss*') 'Expected validation status summary text to retain payload-cache metadata.'
    Assert-True ($summary -like '*subphase=StreamContentStoreRefs*') 'Expected validation status summary text to surface normalization subphase metadata.'
    Assert-True ($summary -like '*rows=125,000*') 'Expected validation status summary text to surface formatted normalization row counts.'
}

Write-Output 'Running shared-helper regression checks...'
Test-CanonicalLayoutHelper
Write-Output '  Canonical layout helper checks passed.'
Test-FileSetFingerprintIgnoresTimestampChange
Write-Output '  File-set fingerprint stability checks passed.'
Test-NormalizedPayloadCacheRejectsManifestHashMismatch
Write-Output '  Normalized payload cache integrity checks passed.'
Test-NormalizedPayloadManifestSourceSummary
Write-Output '  Normalized payload source metadata checks passed.'
Test-SaveJSLibraryFileRefreshesEmptyCache
Write-Output '  JavaScript library cache refresh checks passed.'
Test-VulnContentStoreExistenceNeedsRef
Write-Output '  Content-store existence checks passed.'
Test-LocalExportArtifactCleanup
Write-Output '  Local export artifact cleanup checks passed.'
Test-InitializeMachineHistoryStoreBackfillsCurrentRecordMetadata
Write-Output '  Machine store initialization checks passed.'
Test-MachineHistoryRemovePathsAllowsEmptyPublishedHistorySet
Write-Output '  Machine history cleanup empty-set checks passed.'
Test-BulkSnapshotImportSmoke
Write-Output '  Bulk snapshot import smoke checks passed.'
Test-BulkSnapshotImportSingleSnapshot
Write-Output '  Single-snapshot vulnerability import checks passed.'
Test-BulkSnapshotImportMultipartSnapshot
Write-Output '  Multipart vulnerability import checks passed.'
Test-BulkSnapshotImportMergesIntoExistingCanonicalStore
Write-Output '  Existing-store vulnerability merge checks passed.'
Test-HttpRetryDelayHelperBehavior
Write-Output '  Retry delay helper checks passed.'
Test-WebRequestWithRetryTransientTransportBehavior
Write-Output '  Web request transient transport retry checks passed.'
Test-BulkVulnerabilitySnapshotDownloadMultipartNameUniqueness
Write-Output '  Multipart vulnerability download naming checks passed.'
Test-BulkVulnerabilitySnapshotDownloadStagingBehavior
Write-Output '  Multipart vulnerability download staging checks passed.'
Test-BulkVulnerabilitySnapshotDownloadRetriesEmptyBlob
Write-Output '  Multipart vulnerability empty-blob retry checks passed.'
Test-BulkVulnerabilitySnapshotDownloadEmptyBlobExhaustionBehavior
Write-Output '  Multipart vulnerability empty-blob retry exhaustion checks passed.'
Test-BulkVulnerabilitySnapshotDownloadMoveFailureCleanupBehavior
Write-Output '  Multipart vulnerability move-failure cleanup checks passed.'
Test-BulkVulnerabilitySnapshotDownloadCleanupBehavior
Write-Output '  Multipart vulnerability failed-download cleanup checks passed.'
Test-VulnCurrentFileRejectsDuplicateId
Write-Output '  Current-file duplicate Id checks passed.'
Test-RepairVulnHistoryLayoutSkipsCanonicalQuarterlyStore
Write-Output '  Canonical quarterly history repair skip checks passed.'
Test-VulnStoreRequiresCanonicalRepairDetectsMalformedQuarterlyHistory
Write-Output '  Canonical quarterly history gate checks passed.'
Test-RepairVulnHistoryLayoutRebuildsCanonicalQuarterlyRowSidecar
Write-Output '  Canonical quarterly rows-sidecar repair checks passed.'
Test-RepairVulnHistoryLayoutRepairsLegacyYearlyStore
Write-Output '  Legacy yearly history repair checks passed.'
Test-VulnHistoryFileValidatesQuarterlyHistoryDocument
Write-Output '  Quarterly history validation checks passed.'
Test-VulnCanonicalSignatureStability
Write-Output '  Canonical vulnerability signature checks passed.'
Test-MergeVulnObservedWindowRows
Write-Output '  Vulnerability observation merge checks passed.'
Test-ReadNormalizedVulnStoreRow
Write-Output '  Normalized vulnerability store reader checks passed.'
Test-ResolveNormalizedLookupIndexListHandlesScalarAndCollectionValues
Write-Output '  Lookup index list normalization checks passed.'
Test-ResolveNormalizedInventoryLookupSkipsEmptyInventoryData
Write-Output '  Inventory lookup normalization checks passed.'
Test-AddNormalizedCveUsesStableSeverityIndexLookup
Write-Output '  CVE severity lookup checks passed.'
Test-GetNormalizedRecordLookupHandlesScalarPathInputs
Write-Output '  Scalar path lookup checks passed.'
Test-InvokeNormalizationProgressCallbackUsesCountAndHeartbeat
Write-Output '  Normalization progress callback cadence checks passed.'
Test-ConvertToNormalizedDataReportsContentStoreNormalizationPhase
Write-Output '  Content-store normalization phase callback checks passed.'
Test-ConvertToNormalizedDataUsesStableDeviceIdFallback
Write-Output '  Stable device fallback identity checks passed.'
Test-ConvertToNormalizedDataWritesExpectedRowCount
Write-Output '  Normalized vuln row-count checks passed.'
Test-ConvertToNormalizedDataWritesDirectPayload
Write-Output '  Direct payload normalization checks passed.'
Test-ConvertToNormalizedDataPreservesOptionalNvdFallback
Write-Output '  Optional NVD fallback normalization checks passed.'
Test-ConvertToNormalizedDataCanConsumeLookupsOnPayloadClose
Write-Output '  Consuming payload-close lookup checks passed.'
Test-ConvertToNormalizedDataContentStorePathDoesNotUseLegacyDictionaryReader
Write-Output '  Content-store streaming normalization checks passed.'
Test-ConvertToNormalizedDataDeduplicatesRepeatedCveLookup
Write-Output '  Repeated CVE lookup deduplication checks passed.'
Test-ConvertToNormalizedDataReportsZeroOnboardedContentStoreDiagnostic
Write-Output '  Zero-onboarded content-store diagnostics checks passed.'
Test-ConvertToNormalizedDataIncludesAdvancedHuntingDeviceUserMap
Write-Output '  Advanced Hunting device-user normalization checks passed.'
Test-WriteCombinedPayloadGzipPreservesColumnPayload
Write-Output '  Combined payload writer column-path checks passed.'
Test-NormalizedVulnColumnCacheRebuildsPayloadWithFreshLookups
Write-Output '  Normalized vuln column cache reuse checks passed.'
Test-NormalizedVulnColumnCacheRefreshesInventoryColumn
Write-Output '  Inventory-backed normalized vuln column cache reuse checks passed.'
Test-WriteBase64FileContentMatchesReferenceOutput
Write-Output '  Streamed base64 writer checks passed.'
Test-ValidationHelperPayloadCanonicalization
Write-Output '  Validation helper payload-format checks passed.'
Test-ValidationHelperStandaloneImport
Write-Output '  Validation helper standalone import checks passed.'
Test-DashboardValidationFailureExtendedEnrichmentGate
Write-Output '  Validation helper failure-gate checks passed.'
Test-StreamingDashboardAuditDetectsSourceMismatchDespitePayloadParity
Write-Output '  Streaming dashboard source-parity checks passed.'
Test-StreamingDashboardAuditReusesCachedPayloadSignatureSet
Write-Output '  Streaming dashboard payload-signature reuse checks passed.'
Test-DashboardAuditBootstrapsSyntheticLargePayloadCacheWithNormalizationLookup
Write-Output '  Dashboard synthetic large-dataset bootstrap checks passed.'
Test-DashboardValidationUsesStableFallbackDeviceProfile
Write-Output '  Dashboard validation fallback device profile checks passed.'
Test-DashboardOpenStateAuditUsesPatchEvidenceAndInactivityCutoff
Write-Output '  Dashboard open-state audit checks passed.'
Test-DashboardValidationPreservesNoneSeverityData
Write-Output '  Dashboard none-severity validation checks passed.'
Test-DashboardSplitAssetsGenerationAndValidation
Write-Output '  Dashboard split-assets generation and validation checks passed.'
Test-DashboardValidateOnlyFailsWhenHostedPayloadMissing
Write-Output '  Hosted dashboard missing-payload negative checks passed.'
Test-PackageOnlyRejectsMismatchedNormalizedPayloadManifest
Write-Output '  Package-only manifest mismatch negative checks passed.'
Test-DashboardDualPackagingGenerationAndValidation
Write-Output '  Dashboard dual packaging generation and validation checks passed.'
Test-AdvancedHuntingBundleMatchesDedicatedReaderData
Write-Output '  Advanced Hunting bundle reader checks passed.'
Test-AdvancedHuntingBundleStringArrayFiltersSparseInputs
Write-Output '  Advanced Hunting bundle sparse string-array checks passed.'
Test-ReadNormalizationMachineLookupMatchesCompressedMachineLookup
Write-Output '  Machine tuple reader checks passed.'
Test-NormalizationMachineTupleExtendsLegacyTuple
Write-Output '  Machine tuple extension checks passed.'
Test-LegacyMachineTupleFallbackPreservesProjectedRowMetadata
Write-Output '  Legacy tuple fallback checks passed.'
Test-SourceCveEnrichmentReadsExploitAvailabilityFromObjectRecord
Write-Output '  Source enrichment exploit-availability checks passed.'
Test-VulnPropertyHelpersSupportSupportedRowShapes
Write-Output '  Vulnerability property helper shape checks passed.'
Test-VulnContentStoreRoundTrip
Write-Output '  Vulnerability content store round-trip checks passed.'
Test-VulnObservedWindowCacheRoundTrip
Write-Output '  Observed-window cache round-trip checks passed.'
Test-FunctionAppWriteOutputNoEnumeratePreservesJObject
Write-Output '  Function App Write-Output -NoEnumerate checks passed.'
Test-FunctionExecutionStatusSummaryIncludesNormalizationProgressInfo
Write-Output '  Function execution status summary metadata checks passed.'
Write-Output 'Shared-helper regression checks passed.'
