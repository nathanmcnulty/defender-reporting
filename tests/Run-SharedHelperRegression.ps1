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
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        foreach ($name in @(
            $Script:AdvancedHuntingCurrentFileName,
            $Script:MachineCurrentFileName,
            'Machines_History_2026Q1.json.gz',
            $Script:VulnCurrentFileName,
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
                'VulnHistoryRows_2026.json.gz'
            )
        )
        $staleNames = @(Get-StaleExportStoreArtifactNames -ExistingNames $existingNames -CanonicalNames $canonicalLocalNames)

        Assert-True ('Machines_History_20260301T010101Z_deadbeef.json.gz' -in $staleNames) 'Expected stale machine segment to be removable.'
        Assert-True ('VulnHistory_2026.json.gz' -in $staleNames) 'Expected stale yearly vuln history file to be removable.'
        Assert-True ('VulnHistoryRows_2026.json.gz' -in $staleNames) 'Expected stale yearly vuln history rows file to be removable.'
        Assert-True ((Get-QuarterPeriodKeyFromDate -Date '2026-02-15') -eq '2026Q1') 'Quarter helper returned an unexpected value.'
        Assert-True ((Convert-ToYmdDate -DateValue '2/15/2026') -eq '2026-02-15') 'Date normalization returned an unexpected value.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-LegacyVulnMigrationSmoke {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('legacy-vuln-smoke-' + [guid]::NewGuid().ToString('N'))
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

        $publishResult = Publish-VulnStoreFromLegacySnapshot -BasePath $tempRoot -RemoveLegacyFiles
        $storeRows = @(Read-VulnStoreRow -BasePath $tempRoot)

        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Canonical vuln current file was not materialized.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Canonical quarterly vuln history file was not materialized.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -PathType Leaf)) 'Canonical quarterly vuln history rows file was not materialized.'
        Assert-True (@(Get-VulnLegacySnapshotFile -BasePath $tempRoot).Count -eq 0) 'Legacy vulnerability snapshots were not removed.'
        Assert-True ($publishResult.CurrentRows -eq 1) 'Expected one current row after migrating the smoke fixture.'
        Assert-True ($publishResult.HistoryYears -eq 1) 'Expected one history period after migrating the smoke fixture.'
        Assert-True ($storeRows.Count -eq 2) 'Expected migrated store to expose one current row and one historical row.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-LegacyVulnMigrationSingleSnapshot {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('legacy-vuln-single-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $path = Join-Path $tempRoot 'VulnExport_1_2026-03-20.json'
        $row = Get-TestVulnRow -Id 'single-001' -CveId 'CVE-2026-0099' -SnapshotDate '2026-03-20' -Version '1.0.0'
        [System.IO.File]::WriteAllLines($path, @($row | ConvertTo-Json -Compress -Depth 8), [System.Text.UTF8Encoding]::new($false))

        $publishResult = Publish-VulnStoreFromLegacySnapshot -BasePath $tempRoot -RemoveLegacyFiles
        $storeRows = @(Read-VulnStoreRow -BasePath $tempRoot)

        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Canonical vuln current file was not materialized for a single snapshot.'
        Assert-True (@(Get-ChildItem -Path $tempRoot -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue).Count -eq 0) 'Single-snapshot migration should not create history period files.'
        Assert-True ($publishResult.CurrentRows -eq 1) 'Expected one current row after migrating a single snapshot.'
        Assert-True ($publishResult.HistoryYears -eq 0) 'Expected zero history periods after migrating a single snapshot.'
        Assert-True ($storeRows.Count -eq 1) 'Expected single-snapshot migration to expose only one current row.'
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

Write-Output 'Running shared-helper regression checks...'
Test-CanonicalLayoutHelper
Write-Output '  Canonical layout helper checks passed.'
Test-LegacyVulnMigrationSmoke
Write-Output '  Legacy vulnerability migration smoke checks passed.'
Test-LegacyVulnMigrationSingleSnapshot
Write-Output '  Single-snapshot vulnerability migration checks passed.'
Test-VulnCanonicalSignatureStability
Write-Output '  Canonical vulnerability signature checks passed.'
Test-MergeVulnObservedWindowRows
Write-Output '  Vulnerability observation merge checks passed.'
Test-ReadNormalizedVulnStoreRow
Write-Output '  Normalized vulnerability store reader checks passed.'
Test-ConvertToNormalizedDataUsesStableDeviceIdFallback
Write-Output '  Stable device fallback identity checks passed.'
Write-Output 'Shared-helper regression checks passed.'
