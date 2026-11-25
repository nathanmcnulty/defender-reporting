# Shared-helper regression fragment (Validation). Dot-sourced by Run-SharedHelperRegression.ps1; not an entrypoint.

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

function Test-ValidationHelperSourceCanonicalization {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('validation-helper-source-canonicalization-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $row = Get-TestVulnRow -Id 'validation-source-001' -CveId 'CVE-2026-0313' -SnapshotDate '2026-03-20' -Version '3.2.0'
        $row.CvssScore = 8.15
        $row.VulnerabilitySeverityLevel = 'High'
        $row.ExploitabilityLevel = 'ExploitIsPublic'
        $row.FirstSeenTimestamp = '2026-03-21T00:00:00Z'
        $row.LastSeenTimestamp = '2026-03-18T00:00:00Z'
        $row.DiskPaths = @('C:\z-agent.dll', 'C:\a-agent.dll')
        $row.RegistryPaths = @('HKLM\Software\Contoso\ZAgent', 'HKLM\Software\Contoso\AAgent')
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($row)

        $machines = @{
            'device-001' = [PSCustomObject]@{
                id = 'device-001'
                computerDnsName = 'device01.contoso.com'
                rbacGroupName = 'Servers'
                osPlatform = 'Windows 11'
                osVersion = '10.0.22631'
                machineTags = @('Prod', 'Ring0')
                lastIpAddress = '10.0.0.21'
                lastExternalIpAddress = '52.0.0.21'
                healthStatus = 'Active'
                riskScore = 'Medium'
                exposureLevel = 'Low'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-22T00:00:00Z'
                firstSeen = '2026-02-15T00:00:00Z'
            }
        }
        $advancedHunting = @{
            'CVE-2026-0313' = [PSCustomObject]@{
                PublishedDate = '2026-03-05T10:11:12Z'
                VulnerabilityDescription = "  Source`n canonical   description  "
                EpssScore = 0.8123
                AffectedSoftware = @('contoso:legacy agent', 'fabrikam:other')
                IsExploitAvailable = $true
            }
        }
        $nvdCveData = @{
            'CVE-2026-0313' = [PSCustomObject]@{
                PublishedDate = '2026-03-04T00:00:00Z'
                VulnerabilityDescription = 'NVD fallback description'
                LastModifiedDate = '2026-03-17T01:02:03Z'
                BaseScore = 8.0
                BaseSeverity = 'HIGH'
                Vector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                CisaExploitAdd = '2026-03-18T00:00:00Z'
                CisaActionDue = '2026-04-01T00:00:00Z'
                CisaRequiredAction = " Patch`r`n immediately "
                Weaknesses = @('CWE-79', 'CWE-20')
            }
        }
        $inventoryKey = Get-AdvancedHuntingInventoryMatchKey -DeviceId $row.DeviceId -SoftwareVendor $row.SoftwareVendor -SoftwareName $row.SoftwareName -SoftwareVersion $row.SoftwareVersion
        $advancedHuntingInventory = @{
            $inventoryKey = [PSCustomObject]@{
                ProductCodeCpe = 'cpe:/a:contoso:legacy_agent'
                EndOfSupportStatus = 'supported'
                EndOfSupportDate = '2028-01-01T00:00:00Z'
            }
        }
        $vendorSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        [void]$vendorSet.Add((Get-VendorMatchKey -Vendor $row.SoftwareVendor))

        $firstLastSwappedCount = 0
        $missingMachineCount = 0
        $signatures = @(Read-SourceCanonicalSignatureStream -ExportsPath $tempRoot -Machines $machines -AdvancedHunting $advancedHunting -AdvancedHuntingInventory $advancedHuntingInventory -NvdCveData $nvdCveData -VendorSet $vendorSet -FirstLastSwappedCount ([ref]$firstLastSwappedCount) -MissingMachineCount ([ref]$missingMachineCount))

        $expectedRow = [PSCustomObject]@{
            DeviceId = 'device-001'
            DeviceName = 'device01.contoso.com'
            RbacGroupName = 'Servers'
            OSPlatform = 'Windows 11'
            OSVersion = '10.0.22631'
            MachineTags = @('Prod', 'Ring0')
            MachineInfo = [PSCustomObject]@{
                ip = '10.0.0.21'
                eip = '52.0.0.21'
                hs = 'Active'
                rs = 'Medium'
                el = 'Low'
                dv = 'Normal'
                mb = 'Intune'
                aad = $true
                ls = '2026-03-22'
                fs = '2026-02-15'
            }
            CveId = 'CVE-2026-0313'
            CvssScore = 8.15
            VulnerabilitySeverityLevel = 'High'
            ExploitabilityLevel = 'ExploitIsPublic'
            CveBatchUrl = $row.CveBatchUrl
            CveBatchTitle = $row.CveBatchTitle
            PublishedDate = '2026-03-05'
            VulnerabilityDescription = 'Source canonical description'
            EpssScore = 0.8123
            AffectedSoftware = @('contoso:legacy agent')
            IsExploitAvailable = $true
            NvdLastModifiedDate = '2026-03-17'
            NvdBaseScore = 8.0
            NvdBaseSeverity = 'HIGH'
            NvdVector = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
            NvdKevDate = '2026-03-18'
            NvdActionDue = '2026-04-01'
            NvdRequiredAction = 'Patch immediately'
            NvdWeaknesses = @('CWE-79', 'CWE-20')
            SoftwareVendor = 'Contoso'
            SoftwareName = 'Legacy Agent'
            SoftwareVersion = '3.2.0'
            RecommendationReference = 'KB000001'
            ProductCodeCpe = 'cpe:/a:contoso:legacy_agent'
            EndOfSupportStatus = 'supported'
            EndOfSupportDate = '2028-01-01'
            FirstSeenTimestamp = '2026-03-18'
            LastSeenTimestamp = '2026-03-21'
            SecurityUpdateAvailable = $true
            RecommendedSecurityUpdate = 'KB000001'
            RecommendedSecurityUpdateId = 'KB000001'
            RecommendedSecurityUpdateUrl = 'https://example.invalid/kb000001'
            DiskPaths = @('C:\z-agent.dll', 'C:\a-agent.dll')
            RegistryPaths = @('HKLM\Software\Contoso\ZAgent', 'HKLM\Software\Contoso\AAgent')
        }
        $expectedSignature = Get-CanonicalValidationRowSignature -Row $expectedRow

        Assert-True ($signatures.Count -eq 1) 'Expected source canonicalization fixture to emit one signature.'
        Assert-True ($signatures[0] -eq $expectedSignature) 'Expected source canonicalization to preserve the canonical row signature for enriched source records.'
        Assert-True ($firstLastSwappedCount -eq 1) 'Expected source canonicalization to continue tracking reordered first/last seen timestamps.'
        Assert-True ($missingMachineCount -eq 0) 'Expected source canonicalization fixture to resolve machine metadata without fallback misses.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-GetDashboardEmbeddedPayloadInspectionStreamsSelfContainedPayload {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-embedded-payload-inspection-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'
    $htmlPath = Join-Path $tempRoot 'dashboard.html'

    try {
        Write-GzipTextFile -Path $payloadPath -Content '{"vulnsFormat":"rows-v1","vulns":[[0,0,0,0,"2026-03-20","2026-03-21",null,null,null,null,null],[1,1,1,1,"2026-03-18","2026-03-19",null,null,null,null,null]],"lookups":{"devices":[{"id":"device-001"},{"id":"device-002"}],"cves":[{"id":"CVE-2026-1001"},{"id":"CVE-2026-1002"}]}}'
        $payloadSha256 = Get-FileSha256Hex -Path $payloadPath

        $template = @"
<html>
<head><script id="dataFormat" type="application/json">compressed</script></head>
<body>
<script id="vulnsData" type="application/json">__PAYLOAD__</script>
</body>
</html>
"@
        Write-TemplatedHtml -Template $template -Segments @(@{ Placeholder = '__PAYLOAD__'; Base64FilePath = $payloadPath }) -OutputPath $htmlPath -InsertBase64LineBreaks

        $inspection = Get-DashboardEmbeddedPayloadInspection -Path $htmlPath

        Assert-True ($inspection.DataFormat -eq 'compressed') 'Expected self-contained dashboard inspection to report compressed data format.'
        Assert-True ($inspection.PayloadRowCount -eq 2) 'Expected self-contained dashboard inspection to preserve the embedded payload row count.'
        Assert-True ($inspection.PayloadSha256 -eq $payloadSha256) 'Expected self-contained dashboard inspection to preserve the embedded payload SHA256.'
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

            $changedRow = Get-TestVulnRow -Id 'streaming-audit-001' -CveId 'CVE-2026-0321' -SnapshotDate '2026-03-20' -Version '9.9.9'
            $addedRow = Get-TestVulnRow -Id 'streaming-audit-002' -CveId 'CVE-2026-0322' -SnapshotDate '2026-03-21' -Version '4.1.0'
            Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($changedRow, $addedRow)

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
        Assert-True ((Test-Path -LiteralPath $payloadPath -PathType Leaf)) 'Expected the streaming audit to preserve externally referenced payload files after the priming pass.'
        Assert-True ($audit.PayloadParity.Match -eq $true) 'Expected dashboard payload bytes to remain equal to the cached normalized payload.'
        Assert-True ($audit.SemanticParity.PayloadByteParityMatch -eq $true) 'Expected streaming audit diagnostics to record dashboard payload byte parity.'
        Assert-True ($audit.RowComparison.Match -eq $false) 'Expected streaming semantic parity to fail when the source exports diverge from the dashboard payload.'
        Assert-True ($audit.RowComparison.MissingCount -eq 2) 'Expected the added row and changed row signature to be reported as missing from the dashboard payload.'
        Assert-True ($audit.RowComparison.ExtraCount -eq 1) 'Expected the dashboard version of the changed row to be reported as extra.'
        Assert-True ([string]$audit.SemanticParity.ComparisonPayloadSource -eq 'cached-payload') 'Expected source streaming audit to reuse the cached payload when byte parity proves dashboard equivalence.'
        Assert-True ($audit.SemanticParity.SourceSignatureCacheUsed -eq $false) 'Expected the streaming audit to bypass the cached source signature set after the source exports fingerprint changes.'
        Assert-True ((Test-Path -LiteralPath $payloadPath -PathType Leaf)) 'Expected the streaming audit to preserve externally referenced payload files after full comparison completes.'
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
        Write-GzipTextFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Content '[]'

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
        Write-GzipTextFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Content '[]'

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
    $expectedHostedAssetRelativePaths = @(
        'runtime\dashboard.css'
        'runtime\dashboard.js'
        'runtime\pako.js'
        'vendor\chart.js'
        'data\summary.json'
        'optional\pdf-export.runtime.js'
        'optional\pdf-export.bundle.js'
        'data\payload.json.gz'
    )

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

        foreach ($assetRelativePath in $expectedHostedAssetRelativePaths) {
            Assert-True ((Test-Path -LiteralPath (Join-Path $assetsPath $assetRelativePath) -PathType Leaf)) ("Expected split-assets generation to write '{0}'." -f $assetRelativePath)
        }

        $dashboardHtml = Get-Content -LiteralPath $outputPath -Raw
        Assert-True ($dashboardHtml.Contains('dashboard.assets/runtime/dashboard.css')) 'Expected split-assets dashboard HTML to reference the external stylesheet.'
        Assert-True ($dashboardHtml.Contains('dashboard.assets/runtime/dashboard.js')) 'Expected split-assets dashboard HTML to reference the external dashboard script.'
        Assert-True ($dashboardHtml.Contains('dashboard.assets/data/payload.json.gz')) 'Expected split-assets dashboard HTML to reference the external payload.'
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
    $validateStdoutPath = Join-Path $tempRoot 'validate-only.stdout.log'
    $validateStderrPath = Join-Path $tempRoot 'validate-only.stderr.log'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        & $dashboardScriptPath -DirectoryPath $tempRoot -OutputPath $outputPath -ExportMachineData:$false -SplitAssets | Out-Null

        $payloadAssetPath = Join-Path $assetsPath 'data\payload.json.gz'
        Assert-True ((Test-Path -LiteralPath $payloadAssetPath -PathType Leaf)) 'Expected split-assets generation to write a hosted payload before the negative validation step.'
        Remove-Item -LiteralPath $payloadAssetPath -Force

        $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction Stop
        $validationProcess = Start-Process -FilePath $pwshCommand.Source -ArgumentList @(
            '-NoProfile'
            '-File'
            $dashboardScriptPath
            '-DirectoryPath'
            $tempRoot
            '-OutputPath'
            $outputPath
            '-ValidateOnly'
            '-ValidationOutputPath'
            $auditPath
        ) -WorkingDirectory (Split-Path -Path $dashboardScriptPath -Parent) -RedirectStandardOutput $validateStdoutPath -RedirectStandardError $validateStderrPath -PassThru -Wait
        $validationExitCode = $validationProcess.ExitCode

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
    $packageStdoutPath = Join-Path $tempRoot 'package-only.stdout.log'
    $packageStderrPath = Join-Path $tempRoot 'package-only.stderr.log'

    try {
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $tempRoot -Recurse -Force
        $null = Publish-VulnStoreFromBulkSnapshot -BasePath $tempRoot -RemoveSnapshotFiles

        & $dashboardScriptPath -DirectoryPath $tempRoot -ExportMachineData:$false -NormalizeOnly -NormalizedPayloadOutputPath $normalizedPayloadPath -NormalizedPayloadManifestOutputPath $normalizedManifestPath | Out-Null
        Assert-True ((Test-Path -LiteralPath $normalizedPayloadPath -PathType Leaf)) 'Expected NormalizeOnly to materialize a payload for the package-only negative test.'
        Assert-True ((Test-Path -LiteralPath $normalizedManifestPath -PathType Leaf)) 'Expected NormalizeOnly to materialize a manifest for the package-only negative test.'

        Write-GzipTextFile -Path $tamperedPayloadPath -Content '{"lookups":{"devices":[],"cves":[]},"vulnsFormat":"rows-v1","vulns":[]}'

        $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction Stop
        $packageProcess = Start-Process -FilePath $pwshCommand.Source -ArgumentList @(
            '-NoProfile'
            '-File'
            $dashboardScriptPath
            '-DirectoryPath'
            $tempRoot
            '-OutputPath'
            $outputPath
            '-ExportMachineData:$false'
            '-PackageOnly'
            '-NormalizedPayloadInputPath'
            $tamperedPayloadPath
            '-NormalizedPayloadManifestInputPath'
            $normalizedManifestPath
        ) -WorkingDirectory (Split-Path -Path $dashboardScriptPath -Parent) -RedirectStandardOutput $packageStdoutPath -RedirectStandardError $packageStderrPath -PassThru -Wait
        $packageExitCode = $packageProcess.ExitCode

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
    $expectedHostedAssetRelativePaths = @(
        'runtime\dashboard.css'
        'runtime\dashboard.js'
        'runtime\pako.js'
        'vendor\chart.js'
        'data\summary.json'
        'optional\pdf-export.runtime.js'
        'optional\pdf-export.bundle.js'
        'data\payload.json.gz'
    )
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

        foreach ($assetRelativePath in $expectedHostedAssetRelativePaths) {
            Assert-True ((Test-Path -LiteralPath (Join-Path $hostedAssetsPath $assetRelativePath) -PathType Leaf)) ("Expected dual packaging to write '{0}' to the hosted asset directory." -f $assetRelativePath)
        }

        Assert-True ((Test-Path -LiteralPath ($selfContainedOutputPath + '.validation.json') -PathType Leaf)) 'Expected dual packaging to write a self-contained validation sidecar.'
        Assert-True ((Test-Path -LiteralPath ($hostedOutputPath + '.validation.json') -PathType Leaf)) 'Expected dual packaging to write a hosted validation sidecar.'

        $selfContainedHtml = Get-Content -LiteralPath $selfContainedOutputPath -Raw
        Assert-True ($selfContainedHtml.Contains('<script id="vulnsData" type="application/json">')) 'Expected the self-contained dashboard to embed the compressed payload script.'
        Assert-True ($selfContainedHtml.Contains('compressed')) 'Expected the self-contained dashboard to advertise the embedded compressed payload mode.'

        $hostedHtml = Get-Content -LiteralPath $hostedOutputPath -Raw
        Assert-True ($hostedHtml.Contains('dashboard.Hosted.assets/runtime/dashboard.css')) 'Expected the hosted dual-packaged dashboard to reference the hosted stylesheet.'
        Assert-True ($hostedHtml.Contains('dashboard.Hosted.assets/runtime/dashboard.js')) 'Expected the hosted dual-packaged dashboard to reference the hosted dashboard script.'
        Assert-True ($hostedHtml.Contains('dashboard.Hosted.assets/data/payload.json.gz')) 'Expected the hosted dual-packaged dashboard to reference the hosted payload.'
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

function Test-LiveDashboardTenantBinding {
    [CmdletBinding()]
    param()

    # Load only the named function definitions. Never dot-source or invoke the live entrypoint.
    $sourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'build/Invoke-LiveDashboardDryRun.ps1'
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) 'Expected the live wrapper to parse.'
    foreach ($name in @('Get-OwnerDemoTenantId', 'Assert-AzContextAvailable', 'Get-DefenderApiAccessToken')) {
        $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
        Assert-True ($null -ne $definition) "Missing tenant-binding function: $name"
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    $source = $ast.Extent.Text
    $policyPosition = $source.IndexOf('$Script:RequiredDefenderTenantId = Get-OwnerDemoTenantId -Repository $env:GITHUB_REPOSITORY -AuthenticationMode $PSCmdlet.ParameterSetName -TenantId $AzureTenantId')
    Assert-True ($policyPosition -ge 0 -and $policyPosition -lt $source.IndexOf('switch ($PSCmdlet.ParameterSetName)')) 'Tenant policy must run before authentication.'
    $expectedTenant = '11111111-1111-1111-1111-111111111111'
    $otherTenant = '22222222-2222-2222-2222-222222222222'
    $owner = 'nathanmcnulty/defender-reporting'
    $state = @{ TokenCalls = 0; CliCalls = 0; TokenAvailable = $true; ContextAvailable = $true; ThrowToken = $false; Tenant = $expectedTenant; LastTenant = $null; TokenText = 'synthetic-offline-token'; Context = $null }
    function Get-AzContext { return $state.Context }
    function Get-AzAccessToken {
        [CmdletBinding()]
        param([string]$ResourceUrl, [switch]$AsSecureString, [string]$TenantId)
        Assert-True ($ResourceUrl -ceq 'https://api.securitycenter.microsoft.com' -and $AsSecureString) 'Token resource/type changed.'
        $state.TokenCalls++
        $state.LastTenant = $TenantId
        if ($state.ThrowToken) { throw 'Synthetic token error detail must not escape the owner path.' }
        $secureToken = [System.Security.SecureString]::new()
        foreach ($character in $state.TokenText.ToCharArray()) { $secureToken.AppendChar($character) }
        $secureToken.MakeReadOnly()
        return [PSCustomObject]@{ TenantId = $state.Tenant; Token = $secureToken }
    }
    function Invoke-SyntheticAzCli { $state.CliCalls++; return 'synthetic-cli-token' }
    function Get-Command {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Test-local command discovery returns only synthetic Az/CLI functions and makes no service calls.')]
        [CmdletBinding()]
        param([string]$Name)
        if ($Name -ceq 'az') { return [PSCustomObject]@{ Source = 'Invoke-SyntheticAzCli' } }
        if (($Name -ceq 'Get-AzAccessToken' -and -not $state.TokenAvailable) -or
            ($Name -ceq 'Get-AzContext' -and -not $state.ContextAvailable)) { return $null }
        return Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
    }
    try {
        foreach ($mode in @('ExistingAzContext', 'GitHubOidc')) {
            foreach ($tenant in @('', 'example.invalid', [guid]::Empty.Guid)) {
                $failure = $null
                try { Get-OwnerDemoTenantId -Repository $owner -AuthenticationMode $mode -TenantId $tenant }
                catch { $failure = $_ }
                Assert-True ($null -ne $failure) 'Owner demo must reject missing/domain/empty tenant identifiers without lookup.'
            }
        }
        $failure = $null
        try { Get-OwnerDemoTenantId -Repository $owner -AuthenticationMode ExistingAzContext -TenantId $expectedTenant }
        catch { $failure = $_ }
        Assert-True ($null -ne $failure) 'An ambient existing context cannot select the owner demo tenant.'
        $Script:RequiredDefenderTenantId = Get-OwnerDemoTenantId -Repository $owner -AuthenticationMode GitHubOidc -TenantId $expectedTenant
        Assert-True ($Script:RequiredDefenderTenantId -ceq $expectedTenant) 'Expected configured tenant GUID.'
        Assert-True ($state.TokenCalls -eq 0 -and $state.CliCalls -eq 0) 'Configuration checks must be offline.'
        foreach ($context in @($null, [PSCustomObject]@{ Account = $null },
            [PSCustomObject]@{ Account = @{ Id = 'synthetic' }; Tenant = @{ Id = $otherTenant } },
            [PSCustomObject]@{ Account = @{ Id = 'synthetic' }; Tenant = @{ Id = '' } },
            [PSCustomObject]@{ Account = @{ Id = 'synthetic' } })) {
            $state.Context = $context
            $failure = $null
            try { Get-DefenderApiAccessToken }
            catch { $failure = $_ }
            Assert-True ($null -ne $failure -and $state.TokenCalls -eq 0 -and $state.CliCalls -eq 0) 'Wrong or unproven context must fail before token acquisition.'
        }
        $state.Context = [PSCustomObject]@{ Account = @{ Id = 'synthetic' }; Tenant = @{ Id = $expectedTenant } }
        $state.ContextAvailable = $false
        $failure = $null
        try { Get-DefenderApiAccessToken }
        catch { $failure = $_ }
        Assert-True ($null -ne $failure -and $state.TokenCalls -eq 0 -and $state.CliCalls -eq 0) 'Missing Az context command must fail before token acquisition.'
        $state.ContextAvailable = $true
        foreach ($tokenTenant in @($otherTenant, '', $null)) {
            $state.Tenant = $tokenTenant
            $failure = $null
            try { Get-DefenderApiAccessToken }
            catch { $failure = $_ }
            Assert-True ($null -ne $failure -and $state.CliCalls -eq 0) 'Wrong or unproven token tenant must never use ambient CLI.'
        }
        $state.Tenant = $expectedTenant
        $state.ThrowToken = $true
        $failure = $null
        try { Get-DefenderApiAccessToken }
        catch { $failure = $_ }
        Assert-True ($null -ne $failure -and $failure.Exception.Message -notlike '*Synthetic token error detail*' -and $state.CliCalls -eq 0) 'Owner token failures must be generic and cannot fall back.'
        $state.TokenAvailable = $false
        $failure = $null
        try { Get-DefenderApiAccessToken }
        catch { $failure = $_ }
        Assert-True ($null -ne $failure -and $state.CliCalls -eq 0) 'Missing Az token command must fail closed.'
        $state.TokenAvailable = $true
        $state.ThrowToken = $false
        $state.TokenText = ''
        $failure = $null
        try { Get-DefenderApiAccessToken }
        catch { $failure = $_ }
        Assert-True ($null -ne $failure -and $state.CliCalls -eq 0) 'An empty owner token must fail without fallback.'
        $state.TokenText = 'synthetic-offline-token'
        $token = Get-DefenderApiAccessToken
        Assert-True ($token -ceq 'synthetic-offline-token' -and $state.LastTenant -ceq $expectedTenant -and $state.CliCalls -eq 0) 'Matching context/token must explicitly request the configured tenant.'
        # Preserve the existing private/local ambient fallback outside the owner repository.
        $Script:RequiredDefenderTenantId = Get-OwnerDemoTenantId -Repository 'private/example' -AuthenticationMode ExistingAzContext -TenantId ''
        $state.ThrowToken = $true
        $token = Get-DefenderApiAccessToken -WarningAction SilentlyContinue
        Assert-True ($token -ceq 'synthetic-cli-token' -and $state.CliCalls -eq 1) 'Private/local fallback behavior changed.'
    }
    finally { Remove-Variable -Name RequiredDefenderTenantId -Scope Script -ErrorAction Ignore }
}

function Test-FunctionExecutionValidationRequiresTerminalEvidence {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Local network-free test doubles preserve production call signatures and cannot mutate external state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Local network-free test doubles preserve production call signatures and cannot mutate external state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Local network-free test doubles preserve production call signatures and cannot mutate external state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Local network-free test doubles preserve production call signatures and cannot mutate external state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Local network-free test doubles preserve production call signatures and cannot mutate external state.')]
    [CmdletBinding()]
    param()
    $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'build/Invoke-AzureDeploymentValidation.ps1'
    $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    foreach($name in @('Start-FunctionExecution','ConvertTo-FunctionTraceEvent','Get-FunctionTraceTerminalStatus','Get-FunctionExecutionStatusEvidence','Get-FunctionExecutionStatusSummaryText','Invoke-FunctionExecutionValidation')) {
        $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$false)
        . ([scriptblock]::Create($node.Extent.Text))
    }
    function Write-ValidationLogLine { param($Message,$ForegroundColor) }
    function Invoke-AzCliText {param($Arguments) if($Arguments -contains 'id'){'/test/resource'}else{'test.invalid'} }
    function Invoke-AzCliJson {param($Arguments) [pscustomobject]@{masterKey='test-only'} }
    function Get-FunctionAppSettingValue {param($FunctionAppName,$FunctionResourceGroup,$SettingName) $null }
    function Set-FunctionAppAppSettings {param($FunctionAppName,$FunctionResourceGroup,$Settings) $state.Settings++ }
    function Restart-FunctionAppInstance {param($FunctionAppName,$FunctionResourceGroup,$Reason) }
    function Refresh-FunctionExecutionTemplates {param($StorageAccountName) }
    function Clear-BlobContainer {param($AccountName,$ContainerName) $state.Clears++ }
    function Seed-ExportsContainer {param($AccountName,$DatasetPath) $state.Seeds++ }
    function Set-FunctionExecutionControlBlob {param($StorageAccountName,$UseExistingExportsOnly) }
    function Remove-FunctionExecutionControlBlob {param($StorageAccountName) }
    function Restore-FunctionAppSettingValue {param($FunctionAppName,$FunctionResourceGroup,$SettingName,$OriginalValue) $state.Restores++ }
    function Wait-FunctionHostReady {param($HostName,$MasterKey,$TimeoutMinutes) }
    function Wait-FunctionAdminFunctionReady {param($HostName,$MasterKey,$TimeoutMinutes) }
    function Invoke-FunctionTraceCleanup {param($HostName,$MasterKey) }
    function Get-FunctionTraceAccessState {param($HostName,$MasterKey) 'Forbidden' }
    function Get-FunctionExecutionActivity {param($ResourceId,$StartTimeUtc,$EndTimeUtc) [pscustomobject]@{total_count=10;latest_timestamp_utc=[datetime]::UtcNow} }
    function Get-FunctionMetricSummary {param($ResourceId,$StartTimeUtc,$EndTimeUtc) $null }
    function Invoke-FunctionAdminRequest {param($Method,$HostName,$MasterKey,$Path,$Body) $state.Posts++;$state.Started=[datetime]::UtcNow;if($state.Scenario -ceq 'post-uncertain'){throw 'response lost after accepted POST'};[pscustomobject]@{StatusCode=202} }
    function Get-BlobLastModifiedUtc {param($StorageAccountName,$ContainerName,$BlobName)
        if($null -eq $state.Started){return $null}
        if($state.Scenario -ceq 'stale-blob' -and [string]::IsNullOrEmpty($BlobName)){return $state.Started.AddSeconds(-10)}
        # Both running and terminal writes deliberately share this rounded HTTP timestamp.
        return $state.Started.AddTicks(-($state.Started.Ticks % [timespan]::TicksPerSecond))
    }
    function Get-FunctionTraceContent {param($HostName,$MasterKey)
        if($state.Scenario -ceq 'trace-failed'){return ('[{0}] Pipeline Failed!' -f [datetime]::UtcNow.ToString('o'))}
        if($state.Scenario -in @('trace-only','status-upload-failed')){return ('[{0}] Pipeline Complete!' -f [datetime]::UtcNow.ToString('o'))}
        return $null
    }
    function Get-FunctionExecutionStatus {param($StorageAccountName)
        $state.Reads++
        if($state.Scenario -in @('missing','trace-only')){return $null}
        $document=[pscustomobject]@{version=2;runId=('a'*32);status='succeeded';stage='Completed';executionHost='FunctionApp';storageAccountName='syntheticacct';dashboardDeliveryMode='SelfContained';useExistingExportsOnly=$true;includeAdvancedHunting=$true;exportTarget='BlobStorage';startedOnUtc=$state.Started;updatedOnUtc=$state.Started;completedOnUtc=$state.Started}
        switch($state.Scenario){
            'running' {$document.status='running'}
            'stale' {$document.startedOnUtc=$state.Started.AddMinutes(-1)}
            'wrong-scope' {$document.storageAccountName='otheracct'}
            'wrong-delivery' {$document.dashboardDeliveryMode='Hosted'}
            'wrong-version' {$document.version=1}
            'wrong-host' {$document.executionHost='Automation'}
            'wrong-mode' {$document.useExistingExportsOnly=$false}
            'wrong-export' {$document.exportTarget='SharePoint'}
            'wrong-stage' {$document.stage='Publishing'}
            'string-boolean' {$document.includeAdvancedHunting='true'}
            'invalid-date' {$document.startedOnUtc='not-a-date'}
            'future-date' {$document.completedOnUtc=$state.Started.AddMinutes(1)}
            'reversed-date' {$document.completedOnUtc=$state.Started.AddSeconds(-1)}
            'missing-completion' {$document.PSObject.Properties.Remove('completedOnUtc')}
            'array-scope' {$document.storageAccountName=@('syntheticacct','syntheticacct')}
            'failed' {$document.status='failed'}
            'status-upload-failed' {$document.status='failed';$document|Add-Member error 'DashboardPublishedStatusFailed'}
            'running-then-failed' {$document.status=if($state.Reads -eq 1){'running'}else{'failed'}}
            'running-then-success' {$document.status=if($state.Reads -eq 1){'running'}else{'succeeded'}}
            'run-id-changed' {if($state.Reads -eq 1){$document.status='running'}else{$document.runId=('b'*32)}}
        }
        # Exercise actual ConvertFrom-Json date typing, not just manually constructed strings.
        return ($document|ConvertTo-Json -Compress|ConvertFrom-Json)
    }
    function Start-Sleep {param($Seconds) if($state.Scenario -notin @('running-then-failed','running-then-success','run-id-changed')){throw 'CONTROL-POLL-STOP'} }
    $savedStatusContainer=Get-Variable FunctionExecutionStatusContainerName -Scope Script -ErrorAction SilentlyContinue
    $savedStatusBlob=Get-Variable FunctionExecutionStatusBlobName -Scope Script -ErrorAction SilentlyContinue
    $script:FunctionExecutionStatusContainerName='dashboards';$script:FunctionExecutionStatusBlobName='_diagnostics/ExportAndGenerate.status.json'
    try {
        foreach($scenario in @('succeeded','running-then-success','missing','running','stale','wrong-scope','wrong-delivery','wrong-version','wrong-host','wrong-mode','wrong-export','wrong-stage','string-boolean','invalid-date','future-date','reversed-date','missing-completion','array-scope','post-uncertain','failed','status-upload-failed','running-then-failed','trace-failed','trace-only','run-id-changed','stale-blob')) {
            $state=@{Scenario=$scenario;Posts=0;Settings=0;Clears=0;Seeds=0;Restores=0;Reads=0;Started=$null}
            $result=$null;$failure=$null
            try {$result=Invoke-FunctionExecutionValidation -FunctionAppName 'synthetic-function' -FunctionResourceGroup 'synthetic-group' -StorageAccountName 'syntheticacct' -DashboardDeliveryMode SelfContained -TimeoutMinutes 1 -UseExistingExportsOnly -DatasetPath 'synthetic-fixture'}catch{$failure=$_}
            if($scenario -in @('succeeded','running-then-success')) {
                Assert-True ($null -eq $failure -and $result.terminalStatus -ceq 'Completed' -and $result.completionSource -ceq 'status-and-blob') ('Matching terminal status must support unavailable VFS: '+$scenario)
            }else{Assert-True ($null -ne $failure -and $null -eq $result) ('Fresh blob/metrics must not accept nonterminal, stale, wrong-scope or failed work: '+$scenario)}
            Assert-True ($state.Posts -eq 1 -and $state.Settings -eq 1 -and $state.Clears -eq 1 -and $state.Seeds -eq 1 -and $state.Restores -eq 5) ('Validation must not replay mutations and must restore settings: '+$scenario)
            if($scenario -like 'running-then-*'){Assert-True ($state.Reads -eq 2) 'Same-second status writes must be re-read, not cached by Last-Modified.'}
        }
    }finally{
        foreach($entry in @(@('FunctionExecutionStatusContainerName',$savedStatusContainer),@('FunctionExecutionStatusBlobName',$savedStatusBlob))){if($null -eq $entry[1]){Remove-Variable $entry[0] -Scope Script}else{Set-Variable $entry[0] -Scope Script -Value $entry[1].Value}}
    }
}

function Test-AzureValidationHarnessRequiresExecutionGuardAndRestoration {
    [CmdletBinding()]
    param()

    $path = Join-Path $PSScriptRoot 'Invoke-AzureRunbookValidation.ps1'
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) 'Expected the guarded Azure validation harness.'
    $text = Get-Content -LiteralPath $path -Raw
    Assert-True ($text.Contains("if (-not `$Execute)")) 'Expected Azure validation to require the explicit Execute guard.'
    Assert-True ($text.Contains("Restore-ValidationContainer 'exports'")) 'Expected Azure validation finally cleanup to restore exports.'
    Assert-True ($text.Contains("Restore-ValidationContainer 'dashboards'")) 'Expected Azure validation finally cleanup to restore dashboards.'
    Assert-True ($text.Contains('Set-ValidationRunbookContent $originalRunbookPath')) 'Expected Azure validation to restore published runbook bytes.'
    Assert-True ($text.Contains("'--if-none-match','*'")) 'Expected Azure validation to acquire its lock atomically.'
    Assert-True ($text.Contains('ValidatePublishedSemanticParity')) 'Expected Azure validation to expose published source-to-dashboard semantic sign-off.'
    Assert-True ($text.Contains('-ForceFullValidation')) 'Expected published semantic sign-off to bypass prior attestations and perform a fresh comparison.'

    $caught = $null
    try {
        & $path -SubscriptionId 'test-subscription' -AutomationAccountName 'test-account' -AutomationResourceGroup 'test-group' -RunbookName 'test-runbook' -StorageAccountName 'test-storage' -DatasetPath $PSScriptRoot
    }
    catch { $caught = $_ }
    Assert-True ($null -ne $caught -and $caught.Exception.Message -like '*Re-run with -Execute*') 'Expected the Azure harness to reject mutation without -Execute before contacting Azure.'
}

function Test-AzureValidationRunbookByteRestoration {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('azure-byte-restoration-' + [guid]::NewGuid().ToString('N'))
    $datasetPath = Join-Path $tempRoot 'dataset'
    $candidatePath = Join-Path $tempRoot 'candidate.ps1'
    $state = @{}
    function az {
        $global:LASTEXITCODE = 0
        $command = $args[0..2] -join ' '
        if ($command -like 'account show*') { return '{"id":"test-subscription"}' }
        if ($command -eq 'account get-access-token --resource') { return 'mock-secret-token' }
        if ($command -eq 'automation runbook publish') {
            $state.Published = $state.Draft.Clone()
            return
        }
        if ($command -eq 'automation runbook replace-content') { throw 'Text-based runbook upload is forbidden.' }
        if ($command -eq 'storage blob download-batch') {
            $container = $args[[array]::IndexOf($args, '--source') + 1]
            $destination = $args[[array]::IndexOf($args, '--destination') + 1]
            foreach ($name in $state.Containers[$container].Keys) {
                $path = Join-Path $destination $name
                [void](New-Item -Path (Split-Path $path -Parent) -ItemType Directory -Force)
                [System.IO.File]::WriteAllBytes($path, $state.Containers[$container][$name])
            }
            return
        }
        if ($command -eq 'storage blob delete-batch') {
            $container = $args[[array]::IndexOf($args, '--source') + 1]
            $state.Containers[$container] = @{}
            return
        }
        if ($command -eq 'storage blob upload-batch') {
            $container = $args[[array]::IndexOf($args, '--destination') + 1]
            $source = $args[[array]::IndexOf($args, '--source') + 1]
            foreach ($file in Get-ChildItem -LiteralPath $source -File -Recurse) {
                $name = [System.IO.Path]::GetRelativePath($source, $file.FullName).Replace('\', '/')
                $state.Containers[$container][$name] = [System.IO.File]::ReadAllBytes($file.FullName)
            }
            return
        }
        if ($command -eq 'storage blob upload') {
            $name = $args[[array]::IndexOf($args, '--name') + 1]
            $file = $args[[array]::IndexOf($args, '--file') + 1]
            $state.Containers.dashboards[$name] = [System.IO.File]::ReadAllBytes($file)
            return
        }
        if ($command -eq 'storage blob delete') {
            $name = $args[[array]::IndexOf($args, '--name') + 1]
            $state.Containers.dashboards.Remove($name)
            return
        }
        if ($command -in @('automation runbook show', 'storage account show')) { return '{}' }
        throw "Unexpected Azure mock command: $command"
    }
    function Invoke-WebRequest {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Regression shim captures outbound bytes without contacting Azure.')]
        [CmdletBinding()]
        param($Uri, $Method, $Headers, $Body, $ContentType, $OutFile, [switch]$UseBasicParsing)
        Assert-True ([bool]$UseBasicParsing) 'Expected the production HTTP request signature.'
        Assert-True ($Headers.Authorization -eq 'Bearer mock-secret-token') 'Expected management-token authentication.'
        if ($Method -eq 'Put') {
            Assert-True ($Uri -eq 'https://management.azure.com/subscriptions/test-subscription/resourceGroups/test-group/providers/Microsoft.Automation/automationAccounts/test-account/runbooks/test-runbook/draft/content?api-version=2023-11-01') 'Expected the documented ARM draft endpoint.'
            Assert-True ($Body -is [byte[]] -and $ContentType -eq 'text/powershell') 'Expected raw PowerShell bytes as the outbound request body.'
            $state.Uploads.Add([Convert]::ToBase64String($Body))
            $state.Draft = $Body.Clone()
            if (($state.Failure -eq 'CandidateUpload' -and $state.Uploads.Count -eq 1) -or ($state.Failure -eq 'RestorationUpload' -and $state.Uploads.Count -eq 2)) {
                throw 'mock-secret-token sensitive-response-body'
            }
            return
        }
        Assert-True ($Uri -like '*/test-runbook/content?api-version=2023-11-01') 'Expected published content download.'
        [System.IO.File]::WriteAllBytes($OutFile, $state.Published)
    }
    try {
        [void](New-Item -Path $datasetPath -ItemType Directory -Force)
        foreach ($newline in @("`r`n", "`n")) {
            foreach ($bom in @($false, $true)) {
                foreach ($failure in @('AfterDeploy', 'CandidateUpload', 'RestorationUpload')) {
                    $encoding = [System.Text.UTF8Encoding]::new($bom)
                    $original = [byte[]]($encoding.GetPreamble() + $encoding.GetBytes("# original $([char]0x00e9)$newline'original'$newline"))
                    $candidate = [byte[]]($encoding.GetPreamble() + $encoding.GetBytes("# candidate $([char]0x03bb)$newline'candidate'$newline$newline"))
                    [System.IO.File]::WriteAllBytes($candidatePath, $candidate)
                    $state.Clear()
                    $state.Published = $original.Clone()
                    $state.Draft = $original.Clone()
                    $state.Uploads = [System.Collections.Generic.List[string]]::new()
                    $state.Failure = $failure
                    $state.Containers = @{ exports = @{ 'nested/export.gz' = [byte[]](0, 255, 13, 10) }; dashboards = @{ 'dashboard.html' = [byte[]](1, 2, 10); 'assets/data.gz' = [byte[]](128, 13, 10) } }
                    $before = @{}
                    foreach ($container in @('exports', 'dashboards')) {
                        $before[$container] = @($state.Containers[$container].Keys | Sort-Object | ForEach-Object { "$_|$([Convert]::ToBase64String($state.Containers[$container][$_]))" }) -join ';'
                    }
                    $caught = $null
                    $outputRoot = Join-Path $tempRoot ([guid]::NewGuid().ToString('N'))
                    try {
                        & (Join-Path $PSScriptRoot 'Invoke-AzureRunbookValidation.ps1') -SubscriptionId test-subscription -AutomationAccountName test-account -AutomationResourceGroup test-group -RunbookName test-runbook -StorageAccountName test-storage -DatasetPath $datasetPath -CandidateRunbookPath $candidatePath -OutputRoot $outputRoot -ExpectedTotalRows 1 -FailureInjectionPoint AfterDeploy -Execute -Confirm:$false
                    }
                    catch { $caught = $_ }
                    Assert-True ($null -ne $caught) 'Expected the injected failure.'
                    $expectedError = if ($failure -eq 'AfterDeploy') { 'Injected Azure validation failure after candidate deployment.' } else { 'Runbook draft content upload failed.' }
                    Assert-True ($caught.Exception.Message -eq $expectedError) 'Expected a deliberate failure without token or response-body disclosure.'
                    Assert-True ($state.Uploads.Count -eq 2) 'Expected candidate and finally restoration requests.'
                    Assert-True ($state.Uploads[0] -eq [Convert]::ToBase64String($candidate)) 'Expected byte-exact candidate upload.'
                    Assert-True ($state.Uploads[1] -eq [Convert]::ToBase64String($original)) 'Expected byte-exact backup upload.'
                    foreach ($container in @('exports', 'dashboards')) {
                        $after = @($state.Containers[$container].Keys | Sort-Object | ForEach-Object { "$_|$([Convert]::ToBase64String($state.Containers[$container][$_]))" }) -join ';'
                        Assert-True ($after -eq $before[$container]) 'Expected all canonical container bytes restored and the lock removed.'
                    }
                    if ($failure -ne 'RestorationUpload') {
                        Assert-True ([Convert]::ToBase64String($state.Published) -eq [Convert]::ToBase64String($original)) 'Expected published bytes restored after deployment or partial candidate upload failure.'
                        $restoredPath = @(Get-ChildItem -LiteralPath $outputRoot -Filter 'Invoke-DashboardPipeline.published.ps1' -File -Recurse | Where-Object FullName -Like '*restoration-verification*')[0].FullName
                        Assert-True ((Get-FileHash -LiteralPath $restoredPath).Hash -eq [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($original))) 'Expected downloaded published restoration hash evidence.'
                    }
                }
            }
        }
    }
    finally { if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force } }
}

function Test-AzureValidationExpectedProjectionCountPreflight {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('azure-count-preflight-' + [guid]::NewGuid().ToString('N'))
    $datasetPath = Join-Path $tempRoot 'dataset'
    $manifestPath = Join-Path $datasetPath 'synthetic-manifest.json'
    $outputRoot = Join-Path $tempRoot 'output'
    $azureCalls = [System.Collections.Generic.List[string]]::new()
    function az {
        $azureCalls.Add(($args -join ' '))
        throw 'Count preflight passed; Azure stub stopped before mutation.'
    }
    $cases = @(
        @{ Manifest = '{"actualDeviceCount":50000,"actualTotalVulnRows":1500000,"actualCurrentRows":500000}'; Expected = 0 }
        @{ Manifest = '{"actualTotalVulnRows":1500000}'; Override = 1187395; Expected = 1187395 }
        @{ Manifest = '{"actualCurrentRows":1187395}'; Expected = 0 }
        @{ Manifest = '{"actualTotalVulnRows":1500000,"actualCurrentRows":1187395}'; Expected = 0 }
        @{ Manifest = '{"expectedDashboardRows":1187395}'; Expected = 1187395 }
        @{ Manifest = '{"expectedDashboardRows":1}'; Expected = 1 }
        @{ Manifest = '{"expectedDashboardRows":50000000}'; Expected = 50000000 }
        @{ Manifest = '{"expectedDashboardRows":1500000}'; Override = 1187395; Expected = 1187395 }
        @{ Manifest = '{"expectedDashboardRows":"wrong"}'; Override = 1187395; Expected = 1187395 }
        @{ Manifest = '{broken'; Override = 1187395; Expected = 1187395 }
        @{ Manifest = $null; Override = 1187395; Expected = 1187395 }
        @{ Manifest = $null; Expected = 0 }
        @{ Manifest = '{broken'; Expected = 0 }
    )
    foreach ($validOverride in @(1, 50000000, '1', '50000000', '1187395', [decimal]1, [decimal]50000000)) {
        $cases += @{ Manifest = $null; Override = $validOverride; Expected = [int]$validOverride }
    }
    foreach ($invalidValue in @('null', 'true', 'false', '"1187395"', '"wrong"', '{}', '[]', '1.5', '50000000.4', '0', '-1', '50000001', '9223372036854775808')) {
        $cases += @{ Manifest = ('{"expectedDashboardRows":' + $invalidValue + '}'); Expected = 0 }
        $cases += @{ Manifest = ('{"expectedDashboardRows":' + $invalidValue + '}'); Override = 1187395; Expected = 1187395 }
    }
    foreach ($invalidOverride in @(0, -1, 50000001, 1.5, 50000000.4, [decimal]1.5, [decimal]50000000.4, '0', '-1', '50000001', '1.5', '50000000.4', '1.0', '50000000.0', $true, $false, $null)) {
        $cases += @{ Manifest = '{"expectedDashboardRows":1187395}'; Override = $invalidOverride; Expected = 0 }
    }
    try {
        [void](New-Item -Path $datasetPath -ItemType Directory -Force)
        foreach ($case in $cases) {
            if ($null -eq $case.Manifest) { Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue }
            else { Set-Content -LiteralPath $manifestPath -Value $case.Manifest -Encoding utf8 }
            $azureCalls.Clear()
            $parameters = @{
                SubscriptionId = 'test-subscription'; AutomationAccountName = 'test-account'; AutomationResourceGroup = 'test-group'
                RunbookName = 'test-runbook'; StorageAccountName = 'test-storage'; DatasetPath = $datasetPath
                OutputRoot = $outputRoot; Execute = $true; Confirm = $false
            }
            $resolverParameters = @{ DatasetPath = $datasetPath }
            if ($case.ContainsKey('Override')) {
                $parameters.ExpectedTotalRows = $case.Override
                $resolverParameters.ExpectedTotalRows = $case.Override
            }
            $caught = $null
            try { & (Join-Path $PSScriptRoot 'Invoke-AzureRunbookValidation.ps1') @parameters }
            catch { $caught = $_ }
            if ($case.Expected -gt 0) {
                Assert-True ((Resolve-AzureValidationExpectedRowCount @resolverParameters) -eq $case.Expected) 'Expected the authoritative projection count or explicit override without coercing observation counts.'
                Assert-True ($null -ne $caught -and $caught.Exception.Message -like 'Count preflight passed;*') 'Expected valid count preflight to reach only the Azure stub.'
                Assert-True ($azureCalls.Count -eq 1 -and $azureCalls[0] -like 'account show *') 'Expected the first Azure call to be a read, with no mutations.'
            }
            else {
                $resolverCaught = $null
                try { $null = Resolve-AzureValidationExpectedRowCount @resolverParameters }
                catch { $resolverCaught = $_ }
                Assert-True ($null -ne $resolverCaught) 'Expected the resolver to reject the original invalid count without integer coercion.'
                Assert-True ($null -ne $caught -and $caught.Exception.Message -notlike 'Count preflight passed;*') 'Expected invalid or observation-only counts to fail preflight.'
                Assert-True ($azureCalls.Count -eq 0) 'Expected count rejection before any Azure call.'
                Assert-True (-not (Test-Path -LiteralPath $outputRoot)) 'Expected count rejection before creating output or lock files.'
            }
            if (Test-Path -LiteralPath $outputRoot) { Remove-Item -LiteralPath $outputRoot -Recurse -Force }
        }
    }
    finally { if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force } }
}

function Test-AzureDashboardCandidateEvidenceRejectsIncompletePublication {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('azure-dashboard-evidence-' + [guid]::NewGuid().ToString('N'))
    $assetRoot = Join-Path $tempRoot 'VulnerabilityDashboard.assets'
    try {
        foreach ($relativePath in @('runtime\dashboard.css', 'runtime\dashboard.js', 'runtime\pako.js', 'vendor\chart.js', 'optional\pdf-export.bundle.js')) {
            $path = Join-Path $assetRoot $relativePath
            [void](New-Item -Path (Split-Path $path -Parent) -ItemType Directory -Force)
            [System.IO.File]::WriteAllText($path, 'fixture', [System.Text.UTF8Encoding]::new($false))
        }
        $payloadPath = Join-Path $assetRoot 'data\payload.json.gz'
        [void](New-Item -Path (Split-Path $payloadPath -Parent) -ItemType Directory -Force)
        Write-GzipTextFile -Path $payloadPath -Content '{"vulnsFormat":"rows-v1","lookups":{},"vulns":[[0]]}'
        $payloadSha = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $summary = [ordered]@{ version = 1; meta = [ordered]@{ payloadSha256 = $payloadSha; vulnCount = 1; deviceCount = 1; cveCount = 1 }; filterCatalog = [ordered]@{ groups = @(); tags = @(); devices = @() } }
        [System.IO.File]::WriteAllText((Join-Path $assetRoot 'data\summary.json'), ($summary | ConvertTo-Json -Compress -Depth 10), [System.Text.UTF8Encoding]::new($false))
        $config = @{ payloadUrl = 'VulnerabilityDashboard.assets/data/payload.json.gz'; payloadSummaryUrl = 'VulnerabilityDashboard.assets/data/summary.json'; chartJsUrl = 'VulnerabilityDashboard.assets/vendor/chart.js'; pdfExportBundleMode = 'external'; pdfExportBundleUrl = 'VulnerabilityDashboard.assets/optional/pdf-export.bundle.js' } | ConvertTo-Json -Compress
        $html = '<script id="dataFormat" type="application/json">external-compressed</script><script id="dashboardConfig" type="application/json">' + $config + '</script><script src="VulnerabilityDashboard.assets/runtime/dashboard.js"></script>'
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'VulnerabilityDashboard.html'), $html, [System.Text.UTF8Encoding]::new($false))
        $status = [PSCustomObject]@{ status = 'succeeded'; stage = 'Completed'; runId = 'fixture'; vulnerabilities = 1; devices = 1; cves = 1; dashboardBlobName = 'VulnerabilityDashboard.html'; hostedDashboardBlobName = $null }

        $valid = Assert-AzureDashboardCandidateEvidence -DashboardRootPath $tempRoot -RunbookStatus $status -DashboardDeliveryMode Hosted -ExpectedTotalRows 1 -PayloadRowCounter { param($Path) Get-CompressedPayloadVulnCount -Path $Path }
        Assert-True ($valid.hosted_assets_validated -eq $true -and $valid.payload_row_count -eq 1) 'Expected complete hosted candidate evidence to pass.'

        $comparisonPayloadPath = Join-Path $tempRoot 'comparison.json.gz'
        Write-GzipTextFile -Path $comparisonPayloadPath -Content '{"vulnsFormat":"rows-v1","lookups":{},"vulns":[[0]]}'
        $payloadContentEvidence = Get-GzipDecompressedContentEvidence -Path $payloadPath
        $comparisonContentEvidence = Get-GzipDecompressedContentEvidence -Path $comparisonPayloadPath
        Assert-True ($payloadContentEvidence.decompressed_sha256 -eq $comparisonContentEvidence.decompressed_sha256 -and $payloadContentEvidence.decompressed_bytes -eq $comparisonContentEvidence.decompressed_bytes) 'Expected streaming decompressed evidence to prove exact JSON equality independently of gzip bytes.'
        Write-GzipTextFile -Path $comparisonPayloadPath -Content '{"vulnsFormat":"rows-v1","lookups":{},"vulns":[[1]]}'
        $comparisonContentEvidence = Get-GzipDecompressedContentEvidence -Path $comparisonPayloadPath
        Assert-True ($payloadContentEvidence.decompressed_sha256 -ne $comparisonContentEvidence.decompressed_sha256) 'Expected streaming decompressed evidence to detect one changed row.'

        $summary.meta.payloadSha256 = ('0' * 64)
        [System.IO.File]::WriteAllText((Join-Path $assetRoot 'data\summary.json'), ($summary | ConvertTo-Json -Compress -Depth 10), [System.Text.UTF8Encoding]::new($false))
        $caught = $null
        try { $null = Assert-AzureDashboardCandidateEvidence -DashboardRootPath $tempRoot -RunbookStatus $status -DashboardDeliveryMode Hosted -ExpectedTotalRows 1 }
        catch { $caught = $_ }
        Assert-True ($null -ne $caught -and $caught.Exception.Message -like '*SHA-256*') 'Expected a stale summary payload hash to fail candidate acceptance.'

        Remove-Item -LiteralPath (Join-Path $assetRoot 'runtime\dashboard.js') -Force
        $caught = $null
        try { $null = Assert-AzureDashboardCandidateEvidence -DashboardRootPath $tempRoot -RunbookStatus $status -DashboardDeliveryMode Hosted -ExpectedTotalRows 1 }
        catch { $caught = $_ }
        Assert-True ($null -ne $caught -and $caught.Exception.Message -like '*asset*missing*') 'Expected a missing hosted asset to fail candidate acceptance.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Test-LargeDatasetValidationSemanticModeForcesFullReplay {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $validationScriptPath = Join-Path $repoRoot 'tests\Invoke-LargeDatasetValidation.ps1'
    Assert-True ((Test-Path -LiteralPath $validationScriptPath -PathType Leaf)) "Expected large-dataset validation script at '$validationScriptPath'."

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('large-dataset-forcefull-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)

        $syntheticOutputPath = Join-Path $tempRoot 'synthetic'
        $dashboardOutputPath = Join-Path $tempRoot 'dashboard.html'
        $validationOutputPath = Join-Path $tempRoot 'dashboard-audit.json'
        $diagnosticPhaseLogPath = Join-Path $tempRoot 'phase-log.tsv'

        & $validationScriptPath `
            -SourcePath $PSScriptRoot `
            -SyntheticOutputPath $syntheticOutputPath `
            -TargetDeviceCount 50 `
            -TargetTotalVulnRows 5000 `
            -MinimumAvailableMemoryGB 1 `
            -Validate `
            -ValidationMode semantic `
            -ForceFullValidation `
            -DashboardOutputPath $dashboardOutputPath `
            -ValidationOutputPath $validationOutputPath `
            -DiagnosticPhaseLogPath $diagnosticPhaseLogPath | Out-Null

        $reportPath = Join-Path $syntheticOutputPath 'stress-validation-report.json'
        Assert-True ((Test-Path -LiteralPath $reportPath -PathType Leaf)) 'Expected large-dataset validation to emit a stress-validation report.'
        Assert-True ((Test-Path -LiteralPath $validationOutputPath -PathType Leaf)) 'Expected large-dataset validation to emit a semantic audit.'

        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 20
        $audit = Get-Content -LiteralPath $validationOutputPath -Raw | ConvertFrom-Json -Depth 100

        Assert-True ($report.validation.validationMode -eq 'semantic') 'Expected the stress-validation report to record semantic validation mode.'
        Assert-True ($report.validation.forceFullValidation -eq $true) 'Expected the stress-validation report to record forced full semantic replay.'
        Assert-True ($report.validation.auditSummary.attestationUsed -eq $false) 'Expected semantic sign-off to avoid attestation reuse.'
        Assert-True ([string]$audit.AuditMode -notlike '*attested*') 'Expected semantic sign-off audit mode to reflect a fresh replay rather than attested validation.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-HotPhaseReviewArtifactsModeSmoke {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $reviewScriptPath = Join-Path $repoRoot 'tests\Invoke-HotPhaseReview.ps1'
    Assert-True ((Test-Path -LiteralPath $reviewScriptPath -PathType Leaf)) "Expected hot-phase review script at '$reviewScriptPath'."

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('hot-phase-review-smoke-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        $outputRoot = Join-Path $tempRoot 'review'
        $stdoutPath = Join-Path $tempRoot 'stdout.log'
        $stderrPath = Join-Path $tempRoot 'stderr.log'
        $datasetPath = Join-Path $tempRoot 'synthetic'
        & (Join-Path $PSScriptRoot 'Generate-SyntheticLargeExports.ps1') -SourcePath $PSScriptRoot -OutputPath $datasetPath -TargetDeviceCount 16 -TargetTotalVulnRows 240 -ContentTemplateCount 80 -Seed 4242 -GenerationDate '2026-07-11' -SnapshotCount 4 -ChurnRate 0.10 -OptionalFieldSparsity 0.05 -IncludeRawRows -MinimumAvailableMemoryGB 0.5 -MinimumFreeDiskGB 1 | Out-Null

        if (-not $IsWindows) {
            $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction Stop
            $argumentList = @(
                '-NoProfile'
                '-File'
                $reviewScriptPath
                '-DirectoryPath'
                $datasetPath
                '-OutputRoot'
                $outputRoot
                '-ValidationMode'
                'artifacts'
                '-PollIntervalSeconds'
                '1'
            )

            $process = Start-Process -FilePath $pwshCommand.Source -ArgumentList $argumentList -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
            $process.WaitForExit()

            $stdoutContent = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            $stderrContent = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            $processOutput = @($stdoutContent, $stderrContent) -join [Environment]::NewLine

            Assert-True ($process.ExitCode -ne 0) 'Expected Invoke-HotPhaseReview regression smoke to fail fast on non-Windows platforms.'
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $outputRoot 'hot-phase-review.json') -PathType Leaf)) 'Expected non-Windows hot-phase review execution to avoid writing a review report.'
            Assert-True ($processOutput.Contains('currently supports Windows only')) 'Expected non-Windows hot-phase review execution to explain the Windows-only platform guard.'
            return
        }

        & $reviewScriptPath `
            -DirectoryPath $datasetPath `
            -OutputRoot $outputRoot `
            -ValidationMode artifacts `
            -PollIntervalSeconds 1 | Out-Null

        $reportPath = Join-Path $outputRoot 'hot-phase-review.json'
        Assert-True ((Test-Path -LiteralPath $reportPath -PathType Leaf)) 'Expected hot-phase review smoke to emit a report.'

        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 20
        Assert-True ($report.status -eq 'success') 'Expected hot-phase review smoke to complete successfully.'
        Assert-True ($report.review.validationMode -eq 'artifacts') 'Expected hot-phase review smoke to record artifact validation mode.'
        Assert-True ($report.artifactValidationSummary.passed -eq $true) 'Expected artifact-mode hot-phase review smoke to validate hosted and self-contained outputs.'
        Assert-True (@($report.generatorPhases).Count -gt 0) 'Expected hot-phase review smoke to capture generator phase timings.'
        Assert-True ((Test-Path -LiteralPath $report.artifacts.hostedDashboardPath -PathType Leaf)) 'Expected hot-phase review smoke to emit the hosted dashboard artifact.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-GetDashboardTemplateContentAcceptsExplicitTemplatesPathWithEmptyDefaultRoot {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-template-path-' + [guid]::NewGuid().ToString('N'))

    try {
        $templatesPath = Join-Path $tempRoot 'templates'
        $moduleDirectoryPath = Join-Path $templatesPath 'dashboard'
        [void](New-Item -Path $templatesPath -ItemType Directory -Force)
        [void](New-Item -Path $moduleDirectoryPath -ItemType Directory -Force)
        [System.IO.File]::WriteAllText((Join-Path $templatesPath 'dashboard.html'), '<html></html>', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $templatesPath 'dashboard.css'), 'body { }', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $moduleDirectoryPath '00-core.js'), 'window.__templatePathRegression = true;', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $templatesPath 'dashboard.modules.json'), (@{ version = 1; modules = @('dashboard/00-core.js') } | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))

        $templates = Get-DashboardTemplateContent -TemplatesPath $templatesPath -DefaultRootPath ''

        Assert-True ($templates.Html -eq '<html></html>') 'Expected template loading to honor the explicit templates path when DefaultRootPath is blank.'
        Assert-True ($templates.Css -eq 'body { }') 'Expected CSS template loading to honor the explicit templates path when DefaultRootPath is blank.'
        Assert-True ($templates.Js -like '*window.__templatePathRegression = true;*') 'Expected template loading to bundle JavaScript modules from the explicit templates path.'
        Assert-True (($templates.JsModules.Keys -contains 'dashboard/00-core.js')) 'Expected template module map to preserve the declared dashboard module path.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-AtomicDashboardExecutableDiscovery {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Discovery variables are consumed by the extracted atomic regression startup statements.')]
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $atomicPath = Join-Path $PSScriptRoot 'Invoke-AtomicDashboardPublicationRegression.ps1'
    $parseErrors = $null
    $atomicAst = [System.Management.Automation.Language.Parser]::ParseFile($atomicPath, [ref]$null, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) 'Expected atomic regression startup to parse.'
    $statements = @($atomicAst.EndBlock.Statements)
    $start = $statements | Where-Object { $_.Extent.Text -like 'if (-not $JqPath)*' } | Select-Object -First 1
    $end = $statements | Where-Object { $_.Extent.Text -eq '$BashPath = (Resolve-Path -LiteralPath $BashPath).Path' }
    Assert-True ($null -ne $start -and $null -ne $end) 'Expected executable discovery startup boundaries.'
    $discovery = [scriptblock]::Create(($statements | Where-Object { $_.Extent.StartOffset -ge $start.Extent.StartOffset -and $_.Extent.EndOffset -le $end.Extent.EndOffset }).Extent.Text -join "`n")
    $realJq = Microsoft.PowerShell.Core\Get-Command jq -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('atomic-discovery-' + [guid]::NewGuid().ToString('N'))
    $savedPath = $env:PATH
    $savedJq = $env:DASHBOARD_SYNC_JQ
    $savedBash = $env:DASHBOARD_SYNC_BASH
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        $expectedJq = Join-Path $tempRoot $realJq.Name
        Copy-Item -LiteralPath $realJq.Source -Destination $expectedJq
        $env:PATH = $tempRoot + [System.IO.Path]::PathSeparator + $savedPath
        Remove-Item Env:DASHBOARD_SYNC_JQ, Env:DASHBOARD_SYNC_BASH -ErrorAction SilentlyContinue
        Assert-True (@(Microsoft.PowerShell.Core\Get-Command jq -CommandType Application).Count -ge 2) 'Expected multiple real jq PATH matches.'
        & {
            function Get-Command {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Child-scope Azure-only mock verifies that real executable discovery bypasses mocks.')]
                [CmdletBinding()]
                param([string]$Name)
                if ($Name -eq 'az') { return [pscustomobject]@{ Source = 'mock-az' } }
            }
            Assert-True ($null -eq (Get-Command jq)) 'Expected caller-scope mock to hide jq from unqualified lookup.'
            $JqPath = $env:DASHBOARD_SYNC_JQ
            $BashPath = $env:DASHBOARD_SYNC_BASH
            . $discovery
            Assert-True ($JqPath -eq (Resolve-Path -LiteralPath $expectedJq).Path) 'Expected exactly the first real jq PATH match despite the caller mock.'
            Assert-True (Test-Path -LiteralPath $BashPath -PathType Leaf) 'Expected one real Bash executable despite the caller mock.'
        }
        $fallback = $atomicAst.Find({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '-not $BashPath' -and $node.Extent.Text -like '*$bashCommand*' -and $node.Extent.Text -notlike '*$gitCommand*' }, $true)
        Assert-True ($null -ne $fallback) 'Expected non-Windows Bash PATH fallback.'
        $BashPath = ''
        . ([scriptblock]::Create($fallback.Extent.Text))
        $expectedBash = Microsoft.PowerShell.Core\Get-Command bash -CommandType Application -ErrorAction Stop | Select-Object -First 1
        Assert-True ($BashPath -eq $expectedBash.Source) 'Expected the non-Windows fallback to select exactly the first real Bash PATH match.'
    }
    finally {
        $env:PATH = $savedPath
        $env:DASHBOARD_SYNC_JQ = $savedJq
        $env:DASHBOARD_SYNC_BASH = $savedBash
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Test-DashboardReferencePathReader {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path $PSScriptRoot -Parent
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-reference-metadata-' + [guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($tempRoot)
    $check = {
        $rootName = 'Control.html'
        $prefix = 'Control.assets/generations/' + ('a' * 32) + '/'
        $config = [ordered]@{ payloadUrl = $prefix + 'data/payload.json.gz'; payloadSummaryUrl = $prefix + 'data/summary.json'; chartJsUrl = $prefix + 'runtime/chart.js'; pdfExportRuntimeMode = 'external'; pdfExportRuntimeUrl = $prefix + 'runtime/pdf.js'; pdfExportBundleMode = 'external'; pdfExportBundleUrl = $prefix + 'data/pdf.json.gz'; label = "escaped \ quote `" and unicode $([char]0x263a)" } | ConvertTo-Json -Compress
        $formatTag = '<script id="dataFormat">external-compressed</script>'
        $configTag = '<script id="dashboardConfig" type="application/json">' + $config + '</script>'
        $dependencyTag = '<link href="' + $prefix + 'runtime/dashboard.css"><script src="' + $prefix + 'runtime/dashboard.js"></script>'
        $inline = '<script id="compressedData">' + ('A' * (2MB + 8191)) + '</script><script id="pdfExportBundle">' + ('B' * 2MB) + '</script>'
        foreach ($bom in @($false, $true)) {
            foreach ($ending in @("`n", "`r`n", '')) {
                $html = @('<!doctype html>', $formatTag, $configTag, $dependencyTag, $inline) -join $ending
                $path = Join-Path $tempRoot 'control.html'
                [System.IO.File]::WriteAllText($path, $html, [System.Text.UTF8Encoding]::new($bom))
                $beforeHash = (Get-FileHash -LiteralPath $path).Hash
                $metadata = Get-DashboardReferenceHtmlFromPath -Path $path
                Assert-True ($metadata.Length -lt 4096) 'Expected bounded metadata without inline data or PDF bundle.'
                Assert-True ((Get-DashboardHtmlScriptContent -Html $metadata -ScriptId 'dashboardConfig') -ceq $config) 'Expected JSON escapes and Unicode to remain exact.'
                $expected = @(Get-DashboardRequiredAssetName -Html $html -HtmlBlobName $rootName | Sort-Object -CaseSensitive)
                $actual = @(Get-DashboardRequiredAssetName -Html $metadata -HtmlBlobName $rootName | Sort-Object -CaseSensitive)
                Assert-True (($actual -join "`n") -ceq ($expected -join "`n")) 'Expected exact path/string reference parity.'
                Assert-True ((Get-DashboardPublishedAssetPrefix -Html $metadata -HtmlBlobName $rootName) -ceq $prefix) 'Expected the immutable generation prefix.'
                Assert-True ((Get-FileHash -LiteralPath $path).Hash -ceq $beforeHash) 'Expected source HTML bytes to remain unchanged.'
            }
        }
        $variants = @(
            ('<SCRIPT ID="dashboardConfig" type="application/json">' + ($config | ConvertFrom-Json | ConvertTo-Json -Depth 20) + '</SCRIPT>'),
            ('<script id="dashboardConfig" data-note='' id="fake"'' type="application/json">' + $config + '</script>')
        )
        foreach ($variant in $variants) {
            $html = $formatTag + $variant + $dependencyTag
            [System.IO.File]::WriteAllText($path, $html)
            $metadata = Get-DashboardReferenceHtmlFromPath -Path $path
            Assert-True ($metadata.Contains([regex]::Replace($variant, '</script>$', '', 'IgnoreCase'))) 'Expected original metadata opening tag, attribute order, quoting and body.'
            $expected = @(Get-DashboardRequiredAssetName -Html $html -HtmlBlobName $rootName | Sort-Object -CaseSensitive)
            $actual = @(Get-DashboardRequiredAssetName -Html $metadata -HtmlBlobName $rootName | Sort-Object -CaseSensitive)
            Assert-True ($expected.Count -eq 8 -and ($actual -join "`n") -ceq ($expected -join "`n")) 'Expected exact normative string/file policy parity.'
        }
        foreach ($closing in @('</script >', "</ScRiPt`t>", '</script>')) {
            $html = '<!DOCTYPE html><!-- user''s note --><script data-note='' id="dashboardConfig"''>{}</script><script>const text="' + $closing + $formatTag + $configTag + $dependencyTag
            [System.IO.File]::WriteAllText($path, $html)
            $metadata = Get-DashboardReferenceHtmlFromPath -Path $path
            $expected = @(Get-DashboardRequiredAssetName -Html $html -HtmlBlobName $rootName | Sort-Object -CaseSensitive)
            $actual = @(Get-DashboardRequiredAssetName -Html $metadata -HtmlBlobName $rootName | Sort-Object -CaseSensitive)
            Assert-True ($expected.Count -eq 8 -and ($actual -join "`n") -ceq ($expected -join "`n")) 'Expected true HTML raw-text termination and both following asset tags.'
            Assert-True (-not $metadata.Contains('data-note')) 'Fake quoted ID leaked into metadata.'
        }
        $comment = '<!-- user''s <script id="dashboardConfig">{}</script><link href="Control.assets/fake.js"> -->'
        [System.IO.File]::WriteAllText($path, $comment + $formatTag + $configTag + $dependencyTag)
        $metadata = Get-DashboardReferenceHtmlFromPath -Path $path
        $expected = @(Get-DashboardRequiredAssetName -Html ($formatTag + $configTag + $dependencyTag) -HtmlBlobName $rootName | Sort-Object -CaseSensitive)
        $actual = @(Get-DashboardRequiredAssetName -Html $metadata -HtmlBlobName $rootName | Sort-Object -CaseSensitive)
        Assert-True (($actual -join "`n") -ceq ($expected -join "`n") -and -not $metadata.Contains('fake.js')) 'Comments must not select metadata or leak phantom references; intentionally differs from the string regex.'
        foreach ($boundary in @(8192, 65536)) {
            foreach ($offset in -32..3) {
                foreach ($validComment in @('<!---->', '<!-- user''s note -->', '<!-- single-hyphen - note -->')) {
                    $html = (' ' * ($boundary + $offset)) + $validComment + $formatTag + $configTag + $dependencyTag
                    [System.IO.File]::WriteAllText($path, $html, [System.Text.UTF8Encoding]::new($false))
                    $metadata = Get-DashboardReferenceHtmlFromPath -Path $path
                    $actual = @(Get-DashboardRequiredAssetName -Html $metadata -HtmlBlobName $rootName | Sort-Object -CaseSensitive)
                    Assert-True (($actual -join "`n") -ceq ($expected -join "`n")) "Valid comment lost config at boundary $boundary offset $offset."
                }
                foreach ($invalidComment in @('<!-->', '<!--->', '<!-- note --!>', '<!--<!-->', '<!-- nested <!-- note -->', '<!-- note -- x -->', '<!-- note --->')) {
                    $html = (' ' * ($boundary + $offset)) + $invalidComment + $formatTag + $configTag + $dependencyTag + '<!-- end -->'
                    [System.IO.File]::WriteAllText($path, $html, [System.Text.UTF8Encoding]::new($false))
                    $failed = $false
                    try { $null = Get-DashboardReferenceHtmlFromPath -Path $path } catch { $failed = $true }
                    Assert-True $failed "Invalid comment accepted at boundary $boundary offset $offset."
                }
            }
        }
        foreach ($legacy in @('<script id="dataFormat">compressed</script><script id="compressedData">AAAA</script>', '<html><body>unknown old dashboard</body></html>')) {
            [System.IO.File]::WriteAllText($path, $legacy)
            $metadata = Get-DashboardReferenceHtmlFromPath -Path $path
            Assert-True (-not [string]::IsNullOrEmpty($metadata)) 'Expected nonempty unknown roots to reach publisher validation.'
            $oldFailed = $false
            $newFailed = $false
            try { $null = @(Get-DashboardRequiredAssetName -Html $legacy -HtmlBlobName $rootName) } catch { $oldFailed = $true }
            try { $null = @(Get-DashboardRequiredAssetName -Html $metadata -HtmlBlobName $rootName) } catch { $newFailed = $true }
            Assert-True ($oldFailed -eq $newFailed) 'Expected unchanged legacy missing-config acceptance/rejection.'
        }
        foreach ($invalid in @(
            ('<script type="application/json" id=''dashboardConfig''>' + $config + '</script>'),
            ('<script type="application/json" id="dashboardConfig">' + $config + '</script>'),
            ('<script id=dashboardConfig>' + $config + '</script>'),
            ('<script id="DashboardConfig">' + $config + '</script>'),
            ($configTag + $configTag),
            '<script id="dashboardConfig" ID="other">{}</script>',
            $configTag.Replace('</script>', '</script >'),
            ($configTag + '<script>const phantom='' <link href="Control.assets/fake.js">'';</script>'),
            ($configTag + '<script src=Control.assets/unquoted.js></script>'),
            ($configTag + '<script src="Control.assets/real.js" data-note='' src="Control.assets/fake.js"''></script>'),
            ($configTag + '<script src="Control.assets/real.js" href="Control.assets/other.js"></script>'),
            '<!-- user''s unterminated note',
            ('<!--' + (' ' * 1MB) + '-->'),
            '<![CDATA[<script id="dashboardConfig">{}</script>]]>',
            ('<?xml version="1.0"?>' + $configTag),
            '<script id="dashboardConfig">{broken}</script>',
            '<script id="dashboardConfig">{"pdfExportBundleMode":"external"}</script>',
            '<script id="dashboardConfig">{"payloadUrl":"../unsafe.json.gz"}</script>',
            '<script id="dashboardConfig">{"pdfExportRuntimeUrl":"https://unsafe/pdf.js"}</script>',
            '<script id="dashboardConfig">{"payloadUrl":"Control.assets/data/payload.json.gz"}</script>',
            ('<script id="dashboardConfig">' + (' ' * 1MB) + '{}</script>'),
            '<script id="dashboardConfig">{"unfinished":true}',
            '<script id="dashboardConfig"'
        )) {
            [System.IO.File]::WriteAllText($path, $invalid)
            $failed = $false
            try { $metadata = Get-DashboardReferenceHtmlFromPath -Path $path; $null = @(Get-DashboardRequiredAssetName -Html $metadata -HtmlBlobName $rootName) } catch { $failed = $true }
            Assert-True $failed 'Expected malformed, over-limit or unsafe metadata to fail, never clip.'
        }
    }
    try {
        & $check
        & {
            . (Join-Path $repoRoot 'src/powershell/Shared/Dashboard/DashboardGeneration.ps1')
            & $check
        }
    }
    finally { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
