# Shared-helper regression fragment (Normalization). Dot-sourced by Run-SharedHelperRegression.ps1; not an entrypoint.

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
        Assert-True ('StreamContentStoreCurrentRefs' -in $phaseNames) 'Expected content-store normalization to split current ref streaming into its own normalization phase.'
        Assert-True ('StreamContentStoreHistoryRefs' -in $phaseNames) 'Expected content-store normalization to split history ref streaming into its own normalization phase.'
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
        $streamedDeviceProfiles = @(
            [PSCustomObject]@{
                id = [string]$currentRow.DeviceId
                n = [string]$currentRow.DeviceName
                g = [string]$currentRow.RbacGroupName
                o = [string]$currentRow.OSPlatform
                ov = [string]$currentRow.OSVersion
                t = @($currentRow.MachineTags)
                ob = ($currentRow.IsOnboarded -eq $true)
            }
            [PSCustomObject]@{
                id = [string]$historyRow.DeviceId
                n = [string]$historyRow.DeviceName
                g = [string]$historyRow.RbacGroupName
                o = [string]$historyRow.OSPlatform
                ov = [string]$historyRow.OSVersion
                t = @($historyRow.MachineTags)
                ob = ($historyRow.IsOnboarded -eq $true)
            }
        )
        $streamedContentTemplates = @(
            [PSCustomObject]@{
                c = [string]$currentRow.CveId
                sv = [string]$currentRow.SoftwareVendor
                sn = [string]$currentRow.SoftwareName
                ver = [string]$currentRow.SoftwareVersion
                sev = [string]$currentRow.VulnerabilitySeverityLevel
                sc = $currentRow.CvssScore
                ex = [string]$currentRow.ExploitabilityLevel
                rr = [string]$currentRow.RecommendationReference
                ru = [string]$currentRow.RecommendedSecurityUpdate
                rid = [string]$currentRow.RecommendedSecurityUpdateId
                url = [string]$currentRow.RecommendedSecurityUpdateUrl
                ua = ($currentRow.SecurityUpdateAvailable -eq $true)
                dp = @($currentRow.DiskPaths)
                rp = @($currentRow.RegistryPaths)
                bt = [string]$currentRow.CveBatchTitle
                bu = [string]$currentRow.CveBatchUrl
            }
            [PSCustomObject]@{
                c = [string]$historyRow.CveId
                sv = [string]$historyRow.SoftwareVendor
                sn = [string]$historyRow.SoftwareName
                ver = [string]$historyRow.SoftwareVersion
                sev = [string]$historyRow.VulnerabilitySeverityLevel
                sc = $historyRow.CvssScore
                ex = [string]$historyRow.ExploitabilityLevel
                rr = [string]$historyRow.RecommendationReference
                ru = [string]$historyRow.RecommendedSecurityUpdate
                rid = [string]$historyRow.RecommendedSecurityUpdateId
                url = [string]$historyRow.RecommendedSecurityUpdateUrl
                ua = ($historyRow.SecurityUpdateAvailable -eq $true)
                dp = @($historyRow.DiskPaths)
                rp = @($historyRow.RegistryPaths)
                bt = [string]$historyRow.CveBatchTitle
                bu = [string]$historyRow.CveBatchUrl
            }
        )

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

        $probeResult = Invoke-WithContentDictionaryStreamProbe -DeviceProfiles $streamedDeviceProfiles -ContentTemplates $streamedContentTemplates -Action {
            ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{} -SkipObservedWindowMerge -ConsumeLookupsOnPayloadClose -DisableCompiledContentNormalization
        }
        $result = $probeResult.Result
        $probeState = $probeResult.State

        Assert-True ($result.VulnCount -eq 2) 'Expected content-store normalization to preserve both current and history rows while bypassing the legacy dictionary reader.'
        Assert-True ([string]$result.PayloadPath -eq $payloadPath) 'Expected content-store normalization to still write the direct payload output.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected content-store streaming normalization to keep payload row count aligned with processed rows.'
        Assert-True ($probeState.FirstDeviceProfileProcessed -eq $true) 'Expected the streaming probe to observe the first content-store device profile being consumed.'
        Assert-True ($probeState.FirstContentTemplateProcessed -eq $true) 'Expected the streaming probe to observe the first content-store template being consumed.'
        Assert-True ($probeState.DeviceProfilesBuffered -eq $false) 'Expected content-store normalization to consume device profiles as they stream instead of buffering the full dictionary array first.'
        Assert-True ($probeState.ContentTemplatesBuffered -eq $false) 'Expected content-store normalization to consume content templates as they stream instead of buffering the full dictionary array first.'
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

function Test-ConvertToNormalizedDataSupportsDirectMergeDeviceLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-direct-merge-device-lookup-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'
    $payloadPath = Join-Path $tempRoot 'payload.json.gz'

    try {
        $firstRow = Get-TestVulnRow -Id 'direct-merge-001' -CveId 'CVE-2026-0154' -SnapshotDate '2026-03-20' -Version '2.0.2'
        $secondRow = Get-TestVulnRow -Id 'direct-merge-002' -CveId 'CVE-2026-0155' -SnapshotDate '2026-03-20' -Version '2.0.3'
        $firstRow.DeviceId = 'direct-merge-device-001'
        $firstRow.DeviceName = 'direct-merge-device-001.contoso.com'
        $secondRow.DeviceId = 'direct-merge-device-002'
        $secondRow.DeviceName = 'direct-merge-device-002.contoso.com'
        $machineRows = @(
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                computerDnsName = [string]$firstRow.DeviceName
                rbacGroupName = [string]$firstRow.RbacGroupName
                osPlatform = [string]$firstRow.OSPlatform
                osVersion = [string]$firstRow.OSVersion
                machineTags = @($firstRow.MachineTags)
                lastIpAddress = '10.0.0.11'
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
            [PSCustomObject]@{
                id = [string]$secondRow.DeviceId
                computerDnsName = [string]$secondRow.DeviceName
                rbacGroupName = [string]$secondRow.RbacGroupName
                osPlatform = [string]$secondRow.OSPlatform
                osVersion = [string]$secondRow.OSVersion
                machineTags = @($secondRow.MachineTags)
                lastIpAddress = '10.0.0.12'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Low'
                exposureLevel = 'Low'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-02'
            }
        )
        $deviceProfiles = @(
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                n = [string]$firstRow.DeviceName
                g = [string]$firstRow.RbacGroupName
                o = [string]$firstRow.OSPlatform
                ov = [string]$firstRow.OSVersion
                t = @($firstRow.MachineTags)
                ob = ($firstRow.IsOnboarded -eq $true)
            }
            [PSCustomObject]@{
                id = [string]$secondRow.DeviceId
                n = [string]$secondRow.DeviceName
                g = [string]$secondRow.RbacGroupName
                o = [string]$secondRow.OSPlatform
                ov = [string]$secondRow.OSVersion
                t = @($secondRow.MachineTags)
                ob = ($secondRow.IsOnboarded -eq $true)
            }
        )
        $contentTemplates = @(
            [PSCustomObject]@{
                c = [string]$firstRow.CveId
                sv = [string]$firstRow.SoftwareVendor
                sn = [string]$firstRow.SoftwareName
                ver = [string]$firstRow.SoftwareVersion
                sev = [string]$firstRow.VulnerabilitySeverityLevel
                sc = $firstRow.CvssScore
                ex = [string]$firstRow.ExploitabilityLevel
                rr = [string]$firstRow.RecommendationReference
                ru = [string]$firstRow.RecommendedSecurityUpdate
                rid = [string]$firstRow.RecommendedSecurityUpdateId
                url = [string]$firstRow.RecommendedSecurityUpdateUrl
                ua = ($firstRow.SecurityUpdateAvailable -eq $true)
                dp = @($firstRow.DiskPaths)
                rp = @($firstRow.RegistryPaths)
                bt = [string]$firstRow.CveBatchTitle
                bu = [string]$firstRow.CveBatchUrl
            }
            [PSCustomObject]@{
                c = [string]$secondRow.CveId
                sv = [string]$secondRow.SoftwareVendor
                sn = [string]$secondRow.SoftwareName
                ver = [string]$secondRow.SoftwareVersion
                sev = [string]$secondRow.VulnerabilitySeverityLevel
                sc = $secondRow.CvssScore
                ex = [string]$secondRow.ExploitabilityLevel
                rr = [string]$secondRow.RecommendationReference
                ru = [string]$secondRow.RecommendedSecurityUpdate
                rid = [string]$secondRow.RecommendedSecurityUpdateId
                url = [string]$secondRow.RecommendedSecurityUpdateUrl
                ua = ($secondRow.SecurityUpdateAvailable -eq $true)
                dp = @($secondRow.DiskPaths)
                rp = @($secondRow.RegistryPaths)
                bt = [string]$secondRow.CveBatchTitle
                bu = [string]$secondRow.CveBatchUrl
            }
        )

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($firstRow, $secondRow)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), ($machineRows | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $probeResult = Invoke-WithContentDictionaryStreamProbe -DeviceProfiles $deviceProfiles -ContentTemplates $contentTemplates -Action {
            ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -PayloadOutputPath $payloadPath -Machines @{} -AdvancedHuntingData @{} -AdvancedHuntingDeviceUsers @{} -AdvancedHuntingInventoryData @{} -NvdCveData @{} -SkipObservedWindowMerge -DirectMergeDeviceLookup
        }
        $result = $probeResult.Result
        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100

        Assert-True ($result.VulnCount -eq 2) 'Expected direct-merge device lookup projection to preserve all vulnerability rows.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $result.VulnCount) 'Expected direct-merge device lookup projection to keep payload row count aligned with processed rows.'
        Assert-True ($payload.lookups.devices.Count -eq 2) 'Expected direct-merge device lookup projection to materialize both device lookups from the current-machine stream.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataDirectMergeDeviceLookupRejectsOutOfOrderMachineStream {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-direct-merge-device-order-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $firstRow = Get-TestVulnRow -Id 'direct-merge-order-001' -CveId 'CVE-2026-0156' -SnapshotDate '2026-03-20' -Version '2.0.4'
        $secondRow = Get-TestVulnRow -Id 'direct-merge-order-002' -CveId 'CVE-2026-0157' -SnapshotDate '2026-03-20' -Version '2.0.5'
        $firstRow.DeviceId = 'direct-merge-order-device-001'
        $firstRow.DeviceName = 'direct-merge-order-device-001.contoso.com'
        $secondRow.DeviceId = 'direct-merge-order-device-002'
        $secondRow.DeviceName = 'direct-merge-order-device-002.contoso.com'
        $deviceProfiles = @(
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                n = [string]$firstRow.DeviceName
                g = [string]$firstRow.RbacGroupName
                o = [string]$firstRow.OSPlatform
                ov = [string]$firstRow.OSVersion
                t = @($firstRow.MachineTags)
                ob = ($firstRow.IsOnboarded -eq $true)
            }
            [PSCustomObject]@{
                id = [string]$secondRow.DeviceId
                n = [string]$secondRow.DeviceName
                g = [string]$secondRow.RbacGroupName
                o = [string]$secondRow.OSPlatform
                ov = [string]$secondRow.OSVersion
                t = @($secondRow.MachineTags)
                ob = ($secondRow.IsOnboarded -eq $true)
            }
        )
        $contentTemplates = @(
            [PSCustomObject]@{
                c = [string]$firstRow.CveId
                sv = [string]$firstRow.SoftwareVendor
                sn = [string]$firstRow.SoftwareName
                ver = [string]$firstRow.SoftwareVersion
                sev = [string]$firstRow.VulnerabilitySeverityLevel
                sc = $firstRow.CvssScore
                ex = [string]$firstRow.ExploitabilityLevel
                rr = [string]$firstRow.RecommendationReference
                ru = [string]$firstRow.RecommendedSecurityUpdate
                rid = [string]$firstRow.RecommendedSecurityUpdateId
                url = [string]$firstRow.RecommendedSecurityUpdateUrl
                ua = ($firstRow.SecurityUpdateAvailable -eq $true)
                dp = @($firstRow.DiskPaths)
                rp = @($firstRow.RegistryPaths)
                bt = [string]$firstRow.CveBatchTitle
                bu = [string]$firstRow.CveBatchUrl
            }
            [PSCustomObject]@{
                c = [string]$secondRow.CveId
                sv = [string]$secondRow.SoftwareVendor
                sn = [string]$secondRow.SoftwareName
                ver = [string]$secondRow.SoftwareVersion
                sev = [string]$secondRow.VulnerabilitySeverityLevel
                sc = $secondRow.CvssScore
                ex = [string]$secondRow.ExploitabilityLevel
                rr = [string]$secondRow.RecommendationReference
                ru = [string]$secondRow.RecommendedSecurityUpdate
                rid = [string]$secondRow.RecommendedSecurityUpdateId
                url = [string]$secondRow.RecommendedSecurityUpdateUrl
                ua = ($secondRow.SecurityUpdateAvailable -eq $true)
                dp = @($secondRow.DiskPaths)
                rp = @($secondRow.RegistryPaths)
                bt = [string]$secondRow.CveBatchTitle
                bu = [string]$secondRow.CveBatchUrl
            }
        )
        $machineRows = @(
            [PSCustomObject]@{
                id = [string]$secondRow.DeviceId
                computerDnsName = [string]$secondRow.DeviceName
                rbacGroupName = [string]$secondRow.RbacGroupName
                osPlatform = [string]$secondRow.OSPlatform
                osVersion = [string]$secondRow.OSVersion
                machineTags = @($secondRow.MachineTags)
            }
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                computerDnsName = [string]$firstRow.DeviceName
                rbacGroupName = [string]$firstRow.RbacGroupName
                osPlatform = [string]$firstRow.OSPlatform
                osVersion = [string]$firstRow.OSVersion
                machineTags = @($firstRow.MachineTags)
            }
        )

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($firstRow, $secondRow)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), ($machineRows | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $caught = $null
        try {
            $null = Invoke-WithContentDictionaryStreamProbe -DeviceProfiles $deviceProfiles -ContentTemplates $contentTemplates -Action {
                ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{} -AdvancedHuntingDeviceUsers @{} -AdvancedHuntingInventoryData @{} -NvdCveData @{} -SkipObservedWindowMerge -DirectMergeDeviceLookup
            }
        }
        catch {
            $caught = $_
        }

        Assert-True ($null -ne $caught) 'Expected direct-merge device lookup projection to fail fast when the machine stream order does not match content-store device profiles.'
        Assert-True ($caught.Exception.Message -like '*requires exact current machine order*') 'Expected direct-merge order mismatch to report the exact-order contract.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ConvertToNormalizedDataDirectMergeDeviceLookupRejectsBlankDeviceId {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalized-direct-merge-blank-device-id-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $outputPath = Join-Path $tempRoot 'normalized-vulns.json'

    try {
        $firstRow = Get-TestVulnRow -Id 'direct-merge-blank-001' -CveId 'CVE-2026-0158' -SnapshotDate '2026-03-20' -Version '2.0.6'
        $secondRow = Get-TestVulnRow -Id 'direct-merge-blank-002' -CveId 'CVE-2026-0159' -SnapshotDate '2026-03-20' -Version '2.0.7'
        $firstRow.DeviceId = 'direct-merge-blank-device-001'
        $firstRow.DeviceName = 'direct-merge-blank-device-001.contoso.com'
        $secondRow.DeviceId = ''
        $secondRow.DeviceName = 'direct-merge-blank-device-002.contoso.com'
        $deviceProfiles = @(
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                n = [string]$firstRow.DeviceName
                g = [string]$firstRow.RbacGroupName
                o = [string]$firstRow.OSPlatform
                ov = [string]$firstRow.OSVersion
                t = @($firstRow.MachineTags)
                ob = ($firstRow.IsOnboarded -eq $true)
            }
            [PSCustomObject]@{
                id = [string]$secondRow.DeviceId
                n = [string]$secondRow.DeviceName
                g = [string]$secondRow.RbacGroupName
                o = [string]$secondRow.OSPlatform
                ov = [string]$secondRow.OSVersion
                t = @($secondRow.MachineTags)
                ob = ($secondRow.IsOnboarded -eq $true)
            }
        )
        $contentTemplates = @(
            [PSCustomObject]@{
                c = [string]$firstRow.CveId
                sv = [string]$firstRow.SoftwareVendor
                sn = [string]$firstRow.SoftwareName
                ver = [string]$firstRow.SoftwareVersion
                sev = [string]$firstRow.VulnerabilitySeverityLevel
                sc = $firstRow.CvssScore
                ex = [string]$firstRow.ExploitabilityLevel
                rr = [string]$firstRow.RecommendationReference
                ru = [string]$firstRow.RecommendedSecurityUpdate
                rid = [string]$firstRow.RecommendedSecurityUpdateId
                url = [string]$firstRow.RecommendedSecurityUpdateUrl
                ua = ($firstRow.SecurityUpdateAvailable -eq $true)
                dp = @($firstRow.DiskPaths)
                rp = @($firstRow.RegistryPaths)
                bt = [string]$firstRow.CveBatchTitle
                bu = [string]$firstRow.CveBatchUrl
            }
            [PSCustomObject]@{
                c = [string]$secondRow.CveId
                sv = [string]$secondRow.SoftwareVendor
                sn = [string]$secondRow.SoftwareName
                ver = [string]$secondRow.SoftwareVersion
                sev = [string]$secondRow.VulnerabilitySeverityLevel
                sc = $secondRow.CvssScore
                ex = [string]$secondRow.ExploitabilityLevel
                rr = [string]$secondRow.RecommendationReference
                ru = [string]$secondRow.RecommendedSecurityUpdate
                rid = [string]$secondRow.RecommendedSecurityUpdateId
                url = [string]$secondRow.RecommendedSecurityUpdateUrl
                ua = ($secondRow.SecurityUpdateAvailable -eq $true)
                dp = @($secondRow.DiskPaths)
                rp = @($secondRow.RegistryPaths)
                bt = [string]$secondRow.CveBatchTitle
                bu = [string]$secondRow.CveBatchUrl
            }
        )
        $machineRows = @(
            [PSCustomObject]@{
                id = [string]$firstRow.DeviceId
                computerDnsName = [string]$firstRow.DeviceName
                rbacGroupName = [string]$firstRow.RbacGroupName
                osPlatform = [string]$firstRow.OSPlatform
                osVersion = [string]$firstRow.OSVersion
                machineTags = @($firstRow.MachineTags)
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
            [PSCustomObject]@{
                id = 'direct-merge-blank-device-002'
                computerDnsName = 'direct-merge-blank-device-002.contoso.com'
                rbacGroupName = [string]$secondRow.RbacGroupName
                osPlatform = [string]$secondRow.OSPlatform
                osVersion = [string]$secondRow.OSVersion
                machineTags = @($secondRow.MachineTags)
                lastIpAddress = '10.0.0.22'
                lastExternalIpAddress = ''
                healthStatus = 'Active'
                riskScore = 'Low'
                exposureLevel = 'Low'
                deviceValue = 'Normal'
                managedBy = 'Intune'
                isAadJoined = $true
                lastSeen = '2026-03-20'
                firstSeen = '2026-02-02'
            }
        )

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($firstRow, $secondRow)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), ($machineRows | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot

        $caught = $null
        try {
            Invoke-WithContentDictionaryStreamProbe -DeviceProfiles $deviceProfiles -ContentTemplates $contentTemplates -Action {
                ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $outputPath -Machines @{} -AdvancedHuntingData @{} -AdvancedHuntingDeviceUsers @{} -AdvancedHuntingInventoryData @{} -NvdCveData @{} -SkipObservedWindowMerge -DirectMergeDeviceLookup
            } | Out-Null
        }
        catch {
            $caught = $_
        }

        Assert-True ($null -ne $caught) 'Expected direct-merge device lookup to reject blank device IDs.'
        Assert-True ($caught.Exception.Message.Contains('requires non-empty device IDs')) 'Expected direct-merge device lookup blank device ID error to explain the exact-order requirement.'
    }
    finally {
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
    $originalWriteMemoryUsage = if (Test-Path -LiteralPath Function:\Write-MemoryUsage) {
        Get-Item -LiteralPath Function:\Write-MemoryUsage
    }
    else {
        $null
    }

    try {
        Set-Item -LiteralPath Function:\Write-MemoryUsage -Value {
            param(
                [Parameter(Mandatory = $false)]
                [string]$Label = ''
            )

            Write-Output ("mock memory usage: {0}" -f $Label)
        }

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
                machineTags = 'Prod'
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

        $result = @(Invoke-ContentStoreNormalization `
            -DataPath $tempRoot `
            -VulnOutputPath $outputPath `
            -Context $context `
            -Machines $machines `
            -AdvancedHuntingData $advancedHuntingData `
            -AdvancedHuntingDeviceUsers $advancedHuntingDeviceUsers `
            -AdvancedHuntingInventoryData $advancedHuntingInventoryData `
            -NvdCveData $nvdCveData `
            -PayloadOutputPath $payloadPath `
            -ConsumeLookupsOnPayloadClose)

        Assert-True ($result.Count -eq 1) 'Expected content-store normalization to suppress hosted memory diagnostics from the return pipeline.'

        $normalizationResult = $result[0]
        Assert-True ($normalizationResult.ProcessedCount -eq 1) 'Expected content-store context-release regression fixture to normalize one row.'
        Assert-True ([string]$normalizationResult.PayloadPath -eq $payloadPath) 'Expected content-store context-release regression fixture to write the direct payload output.'
        Assert-True ((Get-CompressedPayloadVulnCount -Path $payloadPath) -eq $normalizationResult.ProcessedCount) 'Expected content-store context-release regression payload row count to match the processed count.'
        Assert-True ($context.Machines.Count -eq 0) 'Expected content-store normalization to release machine lookups before payload close.'
        Assert-True ($context.AdvancedHuntingData.Count -eq 0) 'Expected content-store normalization to release Advanced Hunting CVE data before payload close.'
        Assert-True ($context.AdvancedHuntingDeviceUsers.Count -eq 0) 'Expected content-store normalization to release Advanced Hunting device-user data before payload close.'
        Assert-True ($context.NvdCveData.Count -eq 0) 'Expected content-store normalization to release NVD CVE data before payload close.'
        Assert-True ($context.AdvancedHuntingInventoryData.Count -eq 0) 'Expected content-store normalization to release inventory enrichment before payload close once ref streaming completes.'
    }
    finally {
        if ($null -ne $originalWriteMemoryUsage) {
            Set-Item -LiteralPath Function:\Write-MemoryUsage -Value $originalWriteMemoryUsage.ScriptBlock
        }
        elseif (Test-Path -LiteralPath Function:\Write-MemoryUsage) {
            Remove-Item -LiteralPath Function:\Write-MemoryUsage -Force -ErrorAction SilentlyContinue
        }

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

function Test-NormalizedPayloadPreservesSingletonLookupArray {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('singleton-lookup-arrays-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory)
    try {
        foreach ($values in @(@(), @(0), @(0, 1))) {
            foreach ($record in @(@{ t = $values }, [PSCustomObject]@{ t = $values })) {
                $actual = Get-NormalizedLookupPropertyValue -Value $record -Name 't'
                Assert-True ($actual -is [array]) 'Lookup property access must retain empty, singleton and multiple index arrays.'
                Assert-True (($actual | ConvertTo-Json -AsArray -Compress) -ceq ($values | ConvertTo-Json -AsArray -Compress)) 'Lookup property access must preserve index contents.'
            }
        }

        Copy-Item -Path (Join-Path $PSScriptRoot 'fixtures/legacy-migration/*') -Destination $tempRoot -Recurse
        $payloadPath = Join-Path $tempRoot 'payload.json.gz'
        $dashboardScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Generate-VulnerabilityDashboard.ps1'
        & $dashboardScript -DirectoryPath $tempRoot -ExportMachineData:$false -NormalizeOnly -NormalizedPayloadOutputPath $payloadPath | Out-Null
        $payload = Read-GzipTextFile -Path $payloadPath | ConvertFrom-Json -Depth 100 -AsHashtable
        $device = $payload.lookups.devices[0]
        Assert-True ($device.t -is [array] -and $device.t.Count -eq 1) 'Serialized singleton device tag indices must remain an array.'
        Assert-True ($payload.lookups.tags[$device.t[0]] -ceq 'Prod') 'Serialized device tag must retain its source content.'
        foreach ($cve in $payload.lookups.cves) {
            Assert-True ($cve.as -is [array] -and $cve.as.Count -eq 1) 'Serialized singleton affected-software indices must remain an array.'
            Assert-True ($payload.lookups.affSoftware[$cve.as[0]] -ceq 'Contoso: Legacy Agent') 'Serialized affected software must retain its source content.'
        }
        Assert-True ((Get-DashboardPayloadCacheVersion) -eq 'dashboard-payload-cache-v8') 'Invalidate normalized payloads with collapsed lookup arrays.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
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

function Test-ReadFileBackedNormalizationMachineLookupMatchesCompressedMachineLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-file-backed-reader-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $fileBackedMachines = $null

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

        $fileBackedMachines = Read-NormalizationMachineLookup -Path $tempRoot -FileBacked

        Assert-True (Test-FileBackedNormalizationMachineLookup -Machines $fileBackedMachines) 'Expected file-backed tuple-mode machine loading to return a file-backed lookup.'
        Assert-True ((Get-NormalizationMachineLookupCount -Machines $fileBackedMachines) -eq $compressedMachines.Count) 'Expected file-backed tuple-mode machine loading to preserve the same machine count as the compressed machine lookup path.'

        $expectedTuple = [object[]]$compressedMachines['device-live']
        $actualTuple = Read-FileBackedNormalizationMachineTuple -Machines $fileBackedMachines -DeviceId 'device-live'
        Assert-True ($actualTuple -is [System.Array]) 'Expected file-backed tuple-mode machine loading to materialize array-backed normalization tuples.'
        Assert-True ($actualTuple.Length -eq $expectedTuple.Length) 'Expected file-backed tuple-mode machine loading to preserve the normalization tuple shape.'

        $expectedSparseTuple = [object[]]$compressedMachines['device-sparse']
        $actualSparseTuple = Read-FileBackedNormalizationMachineTuple -Machines $fileBackedMachines -DeviceId 'device-sparse'
        Assert-True ($actualSparseTuple -is [System.Array]) 'Expected file-backed tuple-mode machine loading to materialize sparse machines as array-backed normalization tuples.'
        Assert-True ($actualSparseTuple.Length -eq $expectedSparseTuple.Length) 'Expected file-backed tuple-mode machine loading to preserve the sparse normalization tuple shape.'

        Assert-True ($null -eq (Read-FileBackedNormalizationMachineTuple -Machines $fileBackedMachines -DeviceId 'device-removed')) 'Expected file-backed tuple-mode machine loading to drop removed machines from the current lookup.'

        for ($tupleIndex = 0; $tupleIndex -lt $expectedTuple.Length; $tupleIndex++) {
            $expectedTupleValue = ConvertTo-Json -InputObject $expectedTuple[$tupleIndex] -Compress -Depth 20
            $actualTupleValue = ConvertTo-Json -InputObject $actualTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualTupleValue -eq $expectedTupleValue) "Expected file-backed tuple-mode machine loading to preserve tuple slot $tupleIndex."
        }

        for ($tupleIndex = 0; $tupleIndex -lt $expectedSparseTuple.Length; $tupleIndex++) {
            $expectedSparseTupleValue = ConvertTo-Json -InputObject $expectedSparseTuple[$tupleIndex] -Compress -Depth 20
            $actualSparseTupleValue = ConvertTo-Json -InputObject $actualSparseTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualSparseTupleValue -eq $expectedSparseTupleValue) "Expected file-backed tuple-mode machine loading to preserve sparse tuple slot $tupleIndex."
        }
    }
    finally {
        if ($null -ne $fileBackedMachines) {
            Remove-FileBackedNormalizationMachineLookup -Machines $fileBackedMachines
        }

        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-ReadBucketedFileBackedNormalizationMachineLookupMatchesCompressedMachineLookup {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-bucketed-reader-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $bucketedMachines = $null

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

        $bucketedMachines = Read-NormalizationMachineLookup -Path $tempRoot -FileBacked -Bucketed

        Assert-True (Test-FileBackedNormalizationMachineLookup -Machines $bucketedMachines) 'Expected bucketed file-backed tuple-mode machine loading to return a file-backed lookup.'
        Assert-True ((Get-NormalizationMachineLookupCount -Machines $bucketedMachines) -eq $compressedMachines.Count) 'Expected bucketed file-backed tuple-mode machine loading to preserve the same machine count as the compressed machine lookup path.'

        $expectedTuple = [object[]]$compressedMachines['device-live']
        $actualTuple = Read-FileBackedNormalizationMachineTuple -Machines $bucketedMachines -DeviceId 'device-live'
        Assert-True ($actualTuple -is [System.Array]) 'Expected bucketed file-backed tuple-mode machine loading to materialize array-backed normalization tuples.'
        Assert-True ($actualTuple.Length -eq $expectedTuple.Length) 'Expected bucketed file-backed tuple-mode machine loading to preserve the normalization tuple shape.'

        $expectedSparseTuple = [object[]]$compressedMachines['device-sparse']
        $actualSparseTuple = Read-FileBackedNormalizationMachineTuple -Machines $bucketedMachines -DeviceId 'device-sparse'
        Assert-True ($actualSparseTuple -is [System.Array]) 'Expected bucketed file-backed tuple-mode machine loading to materialize sparse machines as array-backed normalization tuples.'
        Assert-True ($actualSparseTuple.Length -eq $expectedSparseTuple.Length) 'Expected bucketed file-backed tuple-mode machine loading to preserve the sparse normalization tuple shape.'

        Assert-True ($null -eq (Read-FileBackedNormalizationMachineTuple -Machines $bucketedMachines -DeviceId 'device-removed')) 'Expected bucketed file-backed tuple-mode machine loading to drop removed machines from the current lookup.'

        for ($tupleIndex = 0; $tupleIndex -lt $expectedTuple.Length; $tupleIndex++) {
            $expectedTupleValue = ConvertTo-Json -InputObject $expectedTuple[$tupleIndex] -Compress -Depth 20
            $actualTupleValue = ConvertTo-Json -InputObject $actualTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualTupleValue -eq $expectedTupleValue) "Expected bucketed file-backed tuple-mode machine loading to preserve tuple slot $tupleIndex."
        }

        for ($tupleIndex = 0; $tupleIndex -lt $expectedSparseTuple.Length; $tupleIndex++) {
            $expectedSparseTupleValue = ConvertTo-Json -InputObject $expectedSparseTuple[$tupleIndex] -Compress -Depth 20
            $actualSparseTupleValue = ConvertTo-Json -InputObject $actualSparseTuple[$tupleIndex] -Compress -Depth 20
            Assert-True ($actualSparseTupleValue -eq $expectedSparseTupleValue) "Expected bucketed file-backed tuple-mode machine loading to preserve sparse tuple slot $tupleIndex."
        }
    }
    finally {
        if ($null -ne $bucketedMachines) {
            Remove-FileBackedNormalizationMachineLookup -Machines $bucketedMachines
        }

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

function Test-WriteCombinedPayloadGzipCanConsumeColumnLookupData {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('payload-consume-lookups-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $columnsOutputPath = Join-Path $tempRoot 'columns-normalized.json'
    $columnPath = Join-Path $tempRoot 'columns'
    $payloadPath = Join-Path $tempRoot 'columns-payload.json.gz'

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $currentRow = Get-TestVulnRow -Id 'payload-consume-001' -CveId 'CVE-2026-0411' -SnapshotDate '2026-03-20' -Version '4.0.0'
        $historyRow = Get-TestVulnRow -Id 'payload-consume-002' -CveId 'CVE-2026-0412' -SnapshotDate '2026-03-18' -Version '4.1.0'
        $historyRow.DeviceId = 'device-002'
        $historyRow.DeviceName = 'device02.contoso.com'

        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($currentRow)
        [void](New-Item -Path (Get-VulnHistoryPath -BasePath $tempRoot -PeriodKey '2026Q1') -ItemType File -Force)
        Write-NdjsonRecordsFile -Path (Get-VulnHistoryRowsPath -BasePath $tempRoot -PeriodKey '2026Q1') -Records @($historyRow)

        $columnsResult = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath $columnsOutputPath -VulnColumnDirectoryPath $columnPath -Machines @{} -AdvancedHuntingData @{}
        $deviceCountBeforeConsume = @($columnsResult.Lookups.devices).Count
        $cveCountBeforeConsume = @($columnsResult.Lookups.cves).Count

        Write-CombinedPayloadGzip -Lookups $columnsResult.Lookups -VulnColumnPaths $columnsResult.VulnColumnPaths -OutputPath $payloadPath -ConsumeLookups

        $payloadSignatures = @(Read-PayloadCanonicalSignatureStream -PayloadPath $payloadPath | Sort-Object)

        Assert-True ($deviceCountBeforeConsume -gt 0) 'Expected the payload fixture to start with populated device lookups before consuming them.'
        Assert-True ($cveCountBeforeConsume -gt 0) 'Expected the payload fixture to start with populated CVE lookups before consuming them.'
        Assert-True ($payloadSignatures.Count -eq 2) 'Expected the consumed-lookups payload fixture to preserve both vulnerability rows.'
        Assert-True ($null -eq $columnsResult.Lookups.devices) 'Expected payload gzip with -ConsumeLookups to release device lookups after serialization.'
        Assert-True ($null -eq $columnsResult.Lookups.software) 'Expected payload gzip with -ConsumeLookups to release software lookups after serialization.'
        Assert-True ($null -eq $columnsResult.Lookups.cves) 'Expected payload gzip with -ConsumeLookups to release CVE lookups after serialization.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-NormalizedPayloadCacheVersionPreservesSourceData {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('payload-cache-version-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $currentPath = Get-VulnCurrentPath -BasePath $tempRoot
        $currentRow = Get-TestVulnRow -Id 'cache-version-001' -CveId 'CVE-2026-0803' -SnapshotDate '2026-03-20' -Version '8.0.1'
        Write-NdjsonRecordsFile -Path $currentPath -Records @($currentRow)
        $sourceSha256Before = Get-FileSha256Hex -Path $currentPath

        $cacheDirectory = Get-DashboardCacheDirectory -BasePath $tempRoot -ChildPath 'payloads' -Create
        $legacyFingerprint = ('a' * 64)
        $legacyPayloadPath = Join-Path $cacheDirectory ("payload-{0}.json.gz" -f $legacyFingerprint)
        $legacyManifestPath = Join-Path $cacheDirectory ("payload-{0}.json" -f $legacyFingerprint)
        Write-GzipTextFile -Path $legacyPayloadPath -Content '{}'
        Set-Content -LiteralPath $legacyManifestPath -Value '{}' -NoNewline -Encoding utf8

        $payloadPath = Join-Path $tempRoot 'payload.json.gz'
        Write-GzipTextFile -Path $payloadPath -Content '{"lookups":{"devices":[],"cves":[]},"vulnsFormat":"rows-v1","vulns":[]}'
        $cacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $payloadPath -VulnCount 0 -DeviceCount 0 -CveCount 0

        $expectedVersion = Get-DashboardPayloadCacheVersion
        $expectedFingerprint = Get-FileSetFingerprint -Version $expectedVersion -Files @(Get-VulnerabilityPayloadFingerprintSourceFileSet -BasePath $tempRoot) -MetadataLines @('SkipObservedWindowMerge=False')
        Assert-True ($expectedVersion -eq 'dashboard-payload-cache-v8') 'Expected the normalization semantics change to advance the payload cache version.'
        Assert-True ($cacheEntry.Manifest.Version -eq $expectedVersion) 'Expected the payload manifest and cache fingerprint to share one version source.'
        Assert-True ($cacheEntry.Fingerprint -eq $expectedFingerprint) 'Expected the payload cache fingerprint to incorporate the current cache version.'
        Assert-True ((Test-Path -LiteralPath $currentPath -PathType Leaf) -and ((Get-FileSha256Hex -Path $currentPath) -eq $sourceSha256Before)) 'Expected replacing a stale payload cache to preserve source export bytes.'
        Assert-True ((-not (Test-Path -LiteralPath $legacyPayloadPath)) -and (-not (Test-Path -LiteralPath $legacyManifestPath))) 'Expected successful cache publication to remove stale derived payload artifacts.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
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
    $originalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $originalUiCulture = [System.Globalization.CultureInfo]::CurrentUICulture
    try {
        $nonEnglishCulture = [System.Globalization.CultureInfo]::GetCultureInfo('de-DE')
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $nonEnglishCulture
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $nonEnglishCulture

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
    }
    finally {
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $originalCulture
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $originalUiCulture
    }

    Assert-True ($summary -like '*arch=monolithic-v1*') 'Expected validation status summary text to retain architecture metadata.'
    Assert-True ($summary -like '*payloadCache=miss*') 'Expected validation status summary text to retain payload-cache metadata.'
    Assert-True ($summary -like '*subphase=StreamContentStoreRefs*') 'Expected validation status summary text to surface normalization subphase metadata.'
    Assert-True ($summary -like '*rows=125,000*') 'Expected validation status summary text to surface formatted normalization row counts.'
    Assert-True ($summary -notlike '*rows=125.000*') 'Expected validation status summary text to avoid host-culture row count formatting.'
}

function Test-NormalizationExecutionPlanUsesCardinalityAndLegacyFallback {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('normalization-plan-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'synthetic-manifest.json'), '{"actualDeviceCount":50000,"contentTemplateCount":5000}', [System.Text.UTF8Encoding]::new($false))
        $safe = Get-NormalizationExecutionPlan -Path $tempRoot -DeliveryMode Dual
        Assert-True ($safe.SafeToExecute -eq $true -and $safe.DeviceLookupMode -eq 'compiled-file-backed') 'Expected the production-representative manifest to select safe compiled file-backed normalization.'
        Assert-True ($safe.EstimatedPrivateMemoryMb -eq 260) 'Expected the estimate to remain calibrated to the measured 50k-device/5k-template Azure run.'
        $safeWithoutDictionary = Get-NormalizationExecutionPlan -Path $tempRoot -CompiledPayloadSupported
        Assert-True ($safeWithoutDictionary.ContentNormalizationMode -eq 'in-process-streaming' -and $safeWithoutDictionary.EstimatedPrivateMemoryMb -eq 260) 'Expected compiled-capable callers to fall back to in-process streaming when no content dictionary exists.'

        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'synthetic-manifest.json'), '{"actualDeviceCount":50000,"contentTemplateCount":187500}', [System.Text.UTF8Encoding]::new($false))
        $bounded = Get-NormalizationExecutionPlan -Path $tempRoot
        Assert-True ($bounded.SafeToExecute -eq $true -and $bounded.ContentNormalizationMode -eq 'compiled-bounded-standard-payload') 'Expected unenriched high content cardinality to select compiled bounded normalization.'
        Assert-True ($bounded.EstimatedPrivateMemoryMb -eq 435 -and $bounded.EstimatedWorkingSetMb -eq 345.6) 'Expected high-cardinality planning estimates to use the measured compiled envelope.'
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'Machines_Current.json'), '[]', [System.Text.UTF8Encoding]::new($false))
        $enriched = Get-NormalizationExecutionPlan -Path $tempRoot
        Assert-True ($enriched.SafeToExecute -eq $true -and $enriched.ContentNormalizationMode -eq 'compiled-bounded-standard-payload' -and $enriched.HasMachineInput) 'Expected enriched high content cardinality to select the enrichment-capable bounded normalizer.'

        Remove-Item -LiteralPath (Join-Path $tempRoot 'synthetic-manifest.json') -Force
        Write-GzipTextFile -Path (Get-VulnContentDictionaryPath -BasePath $tempRoot) -Content '{"version":"content-dictionary-v1","deviceProfiles":[{"id":"synthetic-device"}],"contentTemplates":[{"cveId":"CVE-2026-7001"}]}'
        $legacy = Get-NormalizationExecutionPlan -Path $tempRoot
        Assert-True ($legacy.SafeToExecute -eq $true -and $legacy.DeviceProfileCount -eq 1 -and $legacy.ContentTemplateCount -eq 1) 'Expected exact dictionary cardinalities without procedural metadata.'
        Assert-True ($legacy.ContentNormalizationMode -eq 'in-process-streaming' -and $legacy.CompiledPayloadSupported -eq $false) 'Expected callers without direct payload output to keep the in-process streaming fallback.'
        $compiledCapable = Get-NormalizationExecutionPlan -Path $tempRoot -CompiledPayloadSupported
        Assert-True ($compiledCapable.SafeToExecute -eq $true -and $compiledCapable.ContentNormalizationMode -eq 'compiled-bounded-standard-payload' -and $compiledCapable.CompiledPayloadSupported) 'Expected direct-payload callers to select the compiled bounded normalizer below the in-process cardinality ceiling.'
        Assert-True ($compiledCapable.EstimatedPrivateMemoryMb -eq 160 -and $compiledCapable.EstimatedWorkingSetMb -eq 260) 'Expected compiled low-cardinality estimates to use the compiled envelope.'
    }
    finally { if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } }
}

function Test-CompiledBoundedContentNormalizationExpandedParity {
    [CmdletBinding()]
    param()
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('compiled-content-parity-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        $first = Get-TestVulnRow -Id 'compiled-parity-1' -CveId 'CVE-2026-7001' -SnapshotDate '2026-07-10' -Version '1.0.0'
        $second = Get-TestVulnRow -Id 'compiled-parity-2' -CveId 'CVE-2026-7002' -SnapshotDate '2026-07-11' -Version '2.0.0'
        $unicodeRegistrySuffix = ([string][char]0x6D4B) + ([string][char]0x8BD5)
        $second.DiskPaths = @(); $second.RegistryPaths = @('HKLM:\Software\Unicode-' + $unicodeRegistrySuffix)
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $tempRoot) -Records @($first, $second)
        Publish-VulnContentStoreUnlocked -BasePath $tempRoot
        $newEnrichmentInputs = {
            $deviceId = [string]$first.DeviceId
            $inventoryKey = Get-AdvancedHuntingInventoryMatchKey -DeviceId $deviceId -SoftwareVendor ([string]$first.SoftwareVendor) -SoftwareName ([string]$first.SoftwareName) -SoftwareVersion ([string]$first.SoftwareVersion)
            return [PSCustomObject]@{
                Machines = @{ $deviceId = [PSCustomObject]@{ computerDnsName = 'compiled-enriched-device'; rbacGroupName = 'Compiled Group'; osPlatform = 'Windows11'; osVersion = '10.0.99999'; machineTags = @('compiled-tag'); lastIpAddress = '10.20.30.40'; lastExternalIpAddress = '203.0.113.40'; healthStatus = 'Active'; riskScore = 'High'; exposureLevel = 'Medium'; deviceValue = 'High'; managedBy = 'Intune'; isAadJoined = $true; lastSeen = '2026-07-12'; firstSeen = '2026-01-02' } }
                AdvancedHuntingData = @{ 'CVE-2026-7001' = @{ PublishedDate = '2026-02-03'; VulnerabilityDescription = 'Compiled enrichment parity'; EpssScore = 0.42; AffectedSoftware = @('Vendor:Product', 'contoso:legacy_agent', ' Contoso :other'); IsExploitAvailable = $true } }
                DeviceUsers = @{ $deviceId = @('user@example.test') }
                InventoryData = @{ $inventoryKey = @{ ProductCodeCpe = 'cpe:/a:vendor:product'; EndOfSupportStatus = 'Active'; EndOfSupportDate = '2027-01-01' } }
                NvdCveData = @{ 'CVE-2026-7001' = @{ PublishedDate = '2026-02-04'; VulnerabilityDescription = 'NVD fallback'; LastModifiedDate = '2026-07-01'; BaseScore = 8.8; BaseSeverity = 'HIGH'; Vector = 'CVSS:3.1/AV:N'; CisaExploitAdd = '2026-06-01'; CisaActionDue = '2026-06-20'; CisaRequiredAction = 'Apply updates'; Weaknesses = @('CWE-79') } }
            }
        }
        $baselineInputs = & $newEnrichmentInputs
        $baselinePath = Join-Path $tempRoot 'baseline.json.gz'
        $baseline = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath (Join-Path $tempRoot 'baseline.json') -PayloadOutputPath $baselinePath -Machines $baselineInputs.Machines -AdvancedHuntingData $baselineInputs.AdvancedHuntingData -AdvancedHuntingDeviceUsers $baselineInputs.DeviceUsers -AdvancedHuntingInventoryData $baselineInputs.InventoryData -NvdCveData $baselineInputs.NvdCveData -SkipObservedWindowMerge -ConsumeLookupsOnPayloadClose -DisableCompiledContentNormalization
        Assert-True (-not ($baseline -is [hashtable] -and $baseline.ContainsKey('CompiledMemoryTelemetry')) -and -not $baseline.PSObject.Properties['CompiledMemoryTelemetry']) 'Expected the compatibility opt-out to keep the in-process streaming normalizer.'
        $defaultInputs = & $newEnrichmentInputs
        $defaultPath = Join-Path $tempRoot 'default.json.gz'
        $default = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath (Join-Path $tempRoot 'default.json') -PayloadOutputPath $defaultPath -Machines $defaultInputs.Machines -AdvancedHuntingData $defaultInputs.AdvancedHuntingData -AdvancedHuntingDeviceUsers $defaultInputs.DeviceUsers -AdvancedHuntingInventoryData $defaultInputs.InventoryData -NvdCveData $defaultInputs.NvdCveData -SkipObservedWindowMerge -ConsumeLookupsOnPayloadClose
        Assert-True ($default -is [hashtable] -and $default.ContainsKey('CompiledMemoryTelemetry') -and $null -ne $default.CompiledMemoryTelemetry -and $default.VulnCount -eq 2) 'Expected low-cardinality direct payload output to select the compiled bounded normalizer by default.'
        & node (Join-Path $repoRoot 'tests\helpers\Assert-ExpandedPayloadParity.js') $baselinePath $defaultPath
        Assert-True ($LASTEXITCODE -eq 0) 'Expected default compiled and in-process payloads to have expanded enrichment parity.'
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'synthetic-manifest.json'), '{"actualDeviceCount":1,"contentTemplateCount":10001}', [System.Text.UTF8Encoding]::new($false))
        $compiledInputs = & $newEnrichmentInputs
        $compiledPath = Join-Path $tempRoot 'compiled.json.gz'
        $compiled = ConvertTo-NormalizedData -DataPath $tempRoot -VulnOutputPath (Join-Path $tempRoot 'compiled.json') -PayloadOutputPath $compiledPath -Machines $compiledInputs.Machines -AdvancedHuntingData $compiledInputs.AdvancedHuntingData -AdvancedHuntingDeviceUsers $compiledInputs.DeviceUsers -AdvancedHuntingInventoryData $compiledInputs.InventoryData -NvdCveData $compiledInputs.NvdCveData -SkipObservedWindowMerge -ConsumeLookupsOnPayloadClose
        Assert-True ($compiled.VulnCount -eq 2 -and $compiled.LookupsConsumed) 'Expected the compiled bounded path to publish both rows directly to the standard payload.'
        Assert-True ($null -ne $compiled.CompiledMemoryTelemetry) 'Expected the compiled path to report bounded transient-memory telemetry.'
        Assert-True ($compiled.CompiledMemoryTelemetry.peakWorkingSetMb -gt 0 -and $compiled.CompiledMemoryTelemetry.peakPrivateMemoryMb -gt 0 -and $compiled.CompiledMemoryTelemetry.peakGcHeapMb -gt 0) 'Expected compiled telemetry to capture positive pre-trim peaks.'
        Assert-True ($compiled.CompiledMemoryTelemetry.postTrimWorkingSetMb -le $compiled.CompiledMemoryTelemetry.preTrimWorkingSetMb) 'Expected post-trim working set not to exceed the pre-trim reading.'
        Assert-True ($compiled.CompiledMemoryTelemetry.sampleIntervalMilliseconds -eq 0) 'Expected compiled telemetry to record phase-checkpoint sampling without a contending background timer.'
        & node (Join-Path $repoRoot 'tests\helpers\Assert-ExpandedPayloadParity.js') $baselinePath $compiledPath
        Assert-True ($LASTEXITCODE -eq 0) 'Expected compiled and compatibility payloads to have expanded semantic parity.'
        $compiledPayload = Read-GzipTextFile -Path $compiledPath | ConvertFrom-Json -Depth 30
        Assert-True ($compiledPayload.lookups.devices[0].m.ip -eq '10.20.30.40' -and $compiledPayload.lookups.devices[0].m.u[0] -eq 'user@example.test') 'Expected compiled normalization to preserve machine and device-user enrichment.'
        Assert-True ($compiledPayload.lookups.cves[0].pd -eq '2026-02-03' -and $compiledPayload.lookups.cves[0].nlm -eq '2026-07-01' -and $compiledPayload.lookups.cves[0].nw[0] -eq 'CWE-79') 'Expected compiled normalization to preserve Advanced Hunting and NVD enrichment.'
        $expandedAffectedSoftware = @($compiledPayload.lookups.cves[0].as | ForEach-Object { $compiledPayload.lookups.affSoftware[[int]$_] })
        Assert-True (($expandedAffectedSoftware -join '|') -eq 'contoso:legacy_agent| Contoso :other') 'Expected compiled normalization to filter affected software to dataset vendors like the in-process normalizer.'
        $baselinePayload = Read-GzipTextFile -Path $baselinePath | ConvertFrom-Json -Depth 30
        Assert-True ((@($baselinePayload.lookups.cves[0].as | ForEach-Object { $baselinePayload.lookups.affSoftware[[int]$_] }) -join '|') -eq ($expandedAffectedSoftware -join '|')) 'Expected compiled and in-process affected-software filters to agree.'
        Assert-True (@($compiledPayload.lookups.inventory).Count -eq 1 -and $compiledPayload.vulns[0][10] -eq 0) 'Expected compiled normalization to preserve inventory enrichment and row references.'

        $baselineManifest = [PSCustomObject]@{ GeneratedOnUtc = '2026-07-12T00:00:00Z'; PayloadSha256 = (Get-FileSha256Hex -Path $baselinePath); VulnCount = 2; DeviceCount = 1; CveCount = 2 }
        $compiledManifest = [PSCustomObject]@{ GeneratedOnUtc = '2026-07-12T00:00:00Z'; PayloadSha256 = (Get-FileSha256Hex -Path $compiledPath); VulnCount = 2; DeviceCount = 1; CveCount = 2 }
        $baselineSummary = Get-DashboardPayloadSummaryJson -PayloadPath $baselinePath -PayloadManifest $baselineManifest | ConvertFrom-Json -Depth 30
        $compiledSummary = Get-DashboardPayloadSummaryJson -PayloadPath $compiledPath -PayloadManifest $compiledManifest | ConvertFrom-Json -Depth 30
        Assert-True ((@($baselineSummary.filterCatalog.groups) -join '|') -eq (@($compiledSummary.filterCatalog.groups) -join '|')) 'Expected legacy vuln-first and compiled lookup-first summaries to preserve group catalogs.'
        Assert-True ((@($baselineSummary.filterCatalog.devices | ConvertTo-Json -Compress -Depth 10) -join '') -eq (@($compiledSummary.filterCatalog.devices | ConvertTo-Json -Compress -Depth 10) -join '')) 'Expected both payload property orders to preserve summary device catalogs.'

        $cacheEntry = Publish-NormalizedPayloadCache -BasePath $tempRoot -PayloadPath $compiledPath -VulnCount 2 -DeviceCount 1 -CveCount 2 -SkipObservedWindowMerge
        $cacheHit = Get-NormalizedPayloadCacheEntry -BasePath $tempRoot -SkipObservedWindowMerge
        Assert-True ($null -ne $cacheEntry -and $null -ne $cacheHit) 'Expected a second compiled payload access to resolve through the normalized payload cache.'
        Assert-True ((Get-FileSha256Hex -Path $cacheHit.PayloadPath) -eq (Get-FileSha256Hex -Path $compiledPath)) 'Expected the cache-hit payload to preserve the compiled payload hash.'
        $cacheSummary = Get-DashboardPayloadSummaryJson -PayloadPath $cacheHit.PayloadPath -PayloadManifest $cacheHit.Manifest | ConvertFrom-Json -Depth 30
        Assert-True ($cacheSummary.meta.vulnCount -eq 2 -and @($cacheSummary.filterCatalog.devices).Count -eq 1) 'Expected cache-hit summary generation to preserve row and device counts.'

        $invalidTailPath = Join-Path $tempRoot 'lookup-first-invalid-tail.json.gz'
        Write-GzipTextFile -Path $invalidTailPath -Content '{"lookups":{"groups":["group"],"tags":[],"devices":[{"id":"device","n":"name","g":0,"t":[]}]},"vulns":[INVALID]}'
        $invalidTailSummary = Get-DashboardPayloadSummaryJson -PayloadPath $invalidTailPath | ConvertFrom-Json -Depth 20
        Assert-True (@($invalidTailSummary.filterCatalog.devices).Count -eq 1) 'Expected lookup-first summary generation to stop before tokenizing vulnerability rows.'
    }
    finally { if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } }
}
