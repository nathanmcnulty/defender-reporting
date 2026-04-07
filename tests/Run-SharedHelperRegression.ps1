#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'shared-helpers.ps1')

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

function Test-ConvertToNormalizedDataIncludesAdvancedHuntingDeviceUsers {
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
        $advancedHuntingDeviceUsers = Read-AdvancedHuntingDeviceUsers -Path $tempRoot
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

        & pwsh -NoLogo -File $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -Validate -ValidationOutputPath $auditPath | Out-Null

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

        & pwsh -NoLogo -File $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -Validate -ValidationOutputPath $auditPath | Out-Null

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

        & pwsh -NoLogo -File $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -Validate -ValidationOutputPath $auditPath | Out-Null

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

        & pwsh -NoLogo -File $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -SplitAssets -Validate -ValidationOutputPath $auditPath | Out-Null

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

        & pwsh -NoLogo -File $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ValidateOnly -ValidationOutputPath $validateOnlyAuditPath | Out-Null

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

function Test-VulnContentStoreRoundTrip {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-content-store-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $currentRow = Get-TestVulnRow -Id 'content-001' -CveId 'CVE-2026-0101' -SnapshotDate '2026-03-20' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'content-002' -CveId 'CVE-2026-0102' -SnapshotDate '2026-03-18' -Version '1.1.0'
        $historyRow.DeviceId = 'device-002'
        $historyRow.DeviceName = 'device02.contoso.com'
        $historyRow.MachineTags = @('Pilot', 'Servers')

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        Publish-VulnContentStoreUnlocked -BasePath $tempRoot
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

    try {
        $currentRow = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-17' -Version '1.0.0'
        $historyRow = Get-TestVulnRow -Id 'merge-001' -CveId 'CVE-2026-0004' -SnapshotDate '2026-03-19' -Version '1.0.0'
        $historyRow.RecommendedSecurityUpdate = 'KB000099'
        $historyRow.RecommendedSecurityUpdateId = 'KB000099'
        $otherHistoryRow = Get-TestVulnRow -Id 'merge-002' -CveId 'CVE-2026-0005' -SnapshotDate '2026-03-23' -Version '2.0.0'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow, $otherHistoryRow)

        Publish-VulnContentStoreUnlocked -BasePath $tempRoot
        $expectedRows = @(Write-MergedVulnObservedWindowRows -Source { Read-VulnStoreRow -BasePath $tempRoot } | Sort-Object Id, FirstSeenTimestamp, LastSeenTimestamp)
        $cachePath = Publish-VulnObservedWindowCache -BasePath $tempRoot

        Assert-True ((Test-Path -LiteralPath $cachePath -PathType Leaf)) 'Expected observed-window cache to be created.'

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
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Output 'Running shared-helper regression checks...'
Test-CanonicalLayoutHelper
Write-Output '  Canonical layout helper checks passed.'
Test-VulnContentStoreExistenceNeedsRef
Write-Output '  Content-store existence checks passed.'
Test-LocalExportArtifactCleanup
Write-Output '  Local export artifact cleanup checks passed.'
Test-BulkSnapshotImportSmoke
Write-Output '  Bulk snapshot import smoke checks passed.'
Test-BulkSnapshotImportSingleSnapshot
Write-Output '  Single-snapshot vulnerability import checks passed.'
Test-VulnCanonicalSignatureStability
Write-Output '  Canonical vulnerability signature checks passed.'
Test-MergeVulnObservedWindowRows
Write-Output '  Vulnerability observation merge checks passed.'
Test-ReadNormalizedVulnStoreRow
Write-Output '  Normalized vulnerability store reader checks passed.'
Test-ConvertToNormalizedDataUsesStableDeviceIdFallback
Write-Output '  Stable device fallback identity checks passed.'
Test-ConvertToNormalizedDataWritesExpectedRowCount
Write-Output '  Normalized vuln row-count checks passed.'
Test-ConvertToNormalizedDataWritesDirectPayload
Write-Output '  Direct payload normalization checks passed.'
Test-ConvertToNormalizedDataIncludesAdvancedHuntingDeviceUsers
Write-Output '  Advanced Hunting device-user normalization checks passed.'
Test-WriteCombinedPayloadGzipPreservesColumnPayload
Write-Output '  Combined payload writer column-path checks passed.'
Test-DashboardValidationUsesStableFallbackDeviceProfile
Write-Output '  Dashboard validation fallback device profile checks passed.'
Test-DashboardOpenStateAuditUsesPatchEvidenceAndInactivityCutoff
Write-Output '  Dashboard open-state audit checks passed.'
Test-DashboardValidationPreservesNoneSeverityData
Write-Output '  Dashboard none-severity validation checks passed.'
Test-DashboardSplitAssetsGenerationAndValidation
Write-Output '  Dashboard split-assets generation and validation checks passed.'
Test-VulnContentStoreRoundTrip
Write-Output '  Vulnerability content store round-trip checks passed.'
Test-VulnObservedWindowCacheRoundTrip
Write-Output '  Observed-window cache round-trip checks passed.'
Write-Output 'Shared-helper regression checks passed.'
