# Shared-helper regression fragment (Benchmark). Dot-sourced by Run-SharedHelperRegression.ps1; not an entrypoint.

function Test-BenchmarkSeriesSummaryHandlesAzureOnlyRunMode {
    [CmdletBinding()]
    param()

    $azureOnlyRun = [PSCustomObject]@{
        include_local_benchmark = $false
        local_only = $false
        current = [PSCustomObject]@{
            local = $null
            runbook = [PSCustomObject]@{
                elapsed_seconds = 575.25
            }
            function_app = [PSCustomObject]@{
                active_elapsed_seconds = 530.51
                end_to_end_elapsed_seconds = 532.12
                pickup_delay_seconds = 1.61
            }
        }
    }

    $summary = Get-BenchmarkSeriesMetricSummary -RunResults @($azureOnlyRun) -LocalOnly:$false -IncludeLocalBenchmark:$false -IncludePersistentLocalWorkflow:$false

    Assert-True (-not (Test-BenchmarkIncludesLocalRun -BenchmarkObject $azureOnlyRun)) 'Expected Azure-only benchmark runs to report that no local benchmark was included.'
    Assert-True ($null -eq $summary.local_elapsed_seconds) 'Expected Azure-only benchmark summaries to omit local elapsed metrics.'
    Assert-True ($null -ne $summary.runbook_elapsed_seconds) 'Expected Azure-only benchmark summaries to retain runbook elapsed metrics.'
    Assert-True ($null -ne $summary.function_active_elapsed_seconds) 'Expected Azure-only benchmark summaries to retain Function App elapsed metrics.'
}

function Test-BenchmarkSeriesSummaryHandlesCombinedRunMode {
    [CmdletBinding()]
    param()

    $combinedRun = [PSCustomObject]@{
        include_local_benchmark = $true
        local_only = $false
        current = [PSCustomObject]@{
            local = [PSCustomObject]@{
                elapsed_seconds = 120.5
            }
            runbook = [PSCustomObject]@{
                elapsed_seconds = 575.25
            }
            function_app = [PSCustomObject]@{
                active_elapsed_seconds = 530.51
                end_to_end_elapsed_seconds = 532.12
                pickup_delay_seconds = 1.61
            }
        }
    }

    $summary = Get-BenchmarkSeriesMetricSummary -RunResults @($combinedRun) -LocalOnly:$false -IncludeLocalBenchmark:$true -IncludePersistentLocalWorkflow:$false

    Assert-True (Test-BenchmarkIncludesLocalRun -BenchmarkObject $combinedRun) 'Expected combined Azure plus local benchmark runs to report that a local benchmark was included.'
    Assert-True ($null -ne $summary.local_elapsed_seconds) 'Expected combined benchmark summaries to retain local elapsed metrics.'
}

function Test-BenchmarkSeriesSummaryHandlesLocalOnlyRunMode {
    [CmdletBinding()]
    param()

    $localOnlyRun = [PSCustomObject]@{
        local_only = $true
        current = [PSCustomObject]@{
            local = [PSCustomObject]@{
                elapsed_seconds = 98.75
            }
            runbook = $null
            function_app = $null
        }
    }

    $summary = Get-BenchmarkSeriesMetricSummary -RunResults @($localOnlyRun) -LocalOnly:$true -IncludeLocalBenchmark:$false -IncludePersistentLocalWorkflow:$false

    Assert-True (Test-BenchmarkIncludesLocalRun -BenchmarkObject $localOnlyRun) 'Expected local-only benchmark runs to report that a local benchmark was included even when the explicit include_local_benchmark flag is absent.'
    Assert-True ($null -ne $summary.local_elapsed_seconds) 'Expected local-only benchmark summaries to retain local elapsed metrics.'
    Assert-True ($null -eq $summary.runbook_elapsed_seconds) 'Expected local-only benchmark summaries to omit runbook elapsed metrics.'
    Assert-True ($null -eq $summary.function_active_elapsed_seconds) 'Expected local-only benchmark summaries to omit Function App elapsed metrics.'
}

function Test-BenchmarkIncludesLocalRunHandlesLegacyInferenceShape {
    [CmdletBinding()]
    param()

    $legacyRun = [PSCustomObject]@{
        local_only = $false
        persistent_local_workflow = $true
        current = [PSCustomObject]@{
            local = [PSCustomObject]@{
                elapsed_seconds = 142.25
            }
            runbook = [PSCustomObject]@{
                elapsed_seconds = 575.25
            }
            function_app = [PSCustomObject]@{
                active_elapsed_seconds = 530.51
                end_to_end_elapsed_seconds = 532.12
                pickup_delay_seconds = 1.61
            }
        }
    }

    Assert-True (Test-BenchmarkIncludesLocalRun -BenchmarkObject $legacyRun) 'Expected benchmark history helpers to infer local benchmark capture from legacy result shapes that include a local result but omit include_local_benchmark.'
}

function Test-BenchmarkModeScenarioKeyHandlesLegacyModeMapping {
    [CmdletBinding()]
    param()

    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'current-only') -eq 'current-only') 'Expected the legacy current-only benchmark mode to normalize to the current-only scenario.'
    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'azure-current-only') -eq 'current-only') 'Expected azure-current-only benchmark mode to normalize to the current-only scenario.'
    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'azure-plus-local-current-only') -eq 'current-only') 'Expected azure-plus-local-current-only benchmark mode to normalize to the current-only scenario.'
    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'branch-vs-main') -eq 'branch-vs-main') 'Expected the legacy branch-vs-main benchmark mode to normalize to the branch-vs-main scenario.'
    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'azure-branch-vs-main') -eq 'branch-vs-main') 'Expected azure-branch-vs-main benchmark mode to normalize to the branch-vs-main scenario.'
    Assert-True ((Get-BenchmarkModeScenarioKey -BenchmarkMode 'azure-plus-local-branch-vs-main') -eq 'branch-vs-main') 'Expected azure-plus-local-branch-vs-main benchmark mode to normalize to the branch-vs-main scenario.'
}

function Test-WriteProgressMarkerIncludesEtaWhenTotalCountKnown {
    [CmdletBinding()]
    param()

    $progressState = New-ProgressMarkerState -ActivityName 'ETA regression' -ProgressInterval 10 -HeartbeatIntervalSeconds 60 -CheckInterval 1 -TotalCount 100
    $outputRecords = @(& {
            Write-ProgressMarker -State $progressState -Count 10 -UnitLabel 'row(s)'
        } 6>&1)
    $outputText = (@($outputRecords | ForEach-Object { Get-OutputRecordText -Record $_ }) -join [Environment]::NewLine)

    Assert-True (-not [string]::IsNullOrWhiteSpace($outputText)) 'Expected Write-ProgressMarker to emit a progress message when the interval is reached.'
    Assert-True ($outputText.Contains('ETA ')) 'Expected Write-ProgressMarker to include ETA text when the total row count is known.'
    Assert-True ($outputText.Contains('10.0% complete')) 'Expected Write-ProgressMarker ETA output to preserve the percent complete marker.'
}

function Test-MeasureStressRunWritesProgressAndFinalReport {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('measure-stress-run-report-' + [guid]::NewGuid().ToString('N'))
    $datasetRoot = Join-Path $tempRoot 'dataset'
    $outputRoot = Join-Path $tempRoot 'output'
    [void](New-Item -Path $datasetRoot -ItemType Directory -Force)
    [void](New-Item -Path $outputRoot -ItemType Directory -Force)
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $measureScriptPath = Join-Path $repoRoot 'tests\Measure-StressRun.ps1'
    $dashboardPath = Join-Path $outputRoot 'dashboard.html'
    $reportPath = Join-Path $outputRoot 'stress-report.json'
    $stdoutPath = Join-Path $outputRoot 'measure.stdout.log'
    $stderrPath = Join-Path $outputRoot 'measure.stderr.log'
    $process = $null

    try {
        . (Join-Path $repoRoot 'build\Import-ValidationHelpers.ps1')

        $row = Get-TestVulnRow -Id 'stress-report-001' -CveId 'CVE-2026-0701' -SnapshotDate '2026-03-20' -Version '7.0.0'
        Write-NdjsonRecordsFile -Path (Get-VulnCurrentPath -BasePath $datasetRoot) -Records @($row)

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

        [System.IO.File]::WriteAllText((Join-Path $datasetRoot 'Machines_Current.json'), ($machines | ConvertTo-Json -Compress -Depth 20), [System.Text.UTF8Encoding]::new($false))
        Write-GzipTextFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $datasetRoot) -Content '[]'
        [System.IO.File]::WriteAllText((Join-Path $datasetRoot 'synthetic-manifest.json'), (([ordered]@{
            actualDeviceCount = 1
            actualCurrentRows = 1
            actualHistoryRows = 0
        }) | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))

        # Keep this regression hermetic. Dashboard generation normally reuses
        # these pinned client libraries from its dataset cache, so provide
        # minimal non-empty fixtures rather than depending on public CDNs.
        Initialize-RegressionDashboardLibraryCache -BasePath $datasetRoot

        $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction Stop
        $argumentList = @(
            '-NoProfile'
            '-File'
            $measureScriptPath
            '-Name'
            'stress-report-regression'
            '-SyntheticOutputPath'
            $datasetRoot
            '-DashboardOutputPath'
            $dashboardPath
            '-ReportOutputPath'
            $reportPath
            '-Validate'
            '-ValidationMode'
            'artifacts'
            '-PollIntervalSeconds'
            '1'
        )

        $process = Start-Process -FilePath $pwshCommand.Source -ArgumentList $argumentList -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru

        $reportSeenWhileRunning = $false
        $deadline = [datetime]::UtcNow.AddSeconds(30)
        while ([datetime]::UtcNow -lt $deadline) {
            $process.Refresh()
            if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
                if (-not $process.HasExited) {
                    $reportSeenWhileRunning = $true
                }
                break
            }

            if ($process.HasExited) {
                break
            }

            Start-Sleep -Milliseconds 200
        }

        $process.WaitForExit()

        if (-not $IsWindows) {
            $stdoutContent = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            $stderrContent = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            $processOutput = @($stdoutContent, $stderrContent) -join [Environment]::NewLine

            Assert-True ($process.ExitCode -ne 0) 'Expected Measure-StressRun regression fixture to fail fast on non-Windows platforms.'
            Assert-True (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) 'Expected non-Windows Measure-StressRun execution to avoid writing a stress report.'
            Assert-True ($processOutput.Contains('currently supports Windows only')) 'Expected non-Windows Measure-StressRun execution to explain the Windows-only platform guard.'
            return
        }

        if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
            $stdoutContent = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            $stderrContent = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            throw ("Measure-StressRun did not create its report (exit code {0}).`nSTDOUT:`n{1}`nSTDERR:`n{2}" -f $process.ExitCode, $stdoutContent, $stderrContent)
        }

        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 20

        Assert-True $reportSeenWhileRunning 'Expected Measure-StressRun to persist a progress report before the wrapper process exits.'
        Assert-True ($report.report_state -eq 'completed') 'Expected Measure-StressRun to finalize the persisted report after the child process exits.'
        if ($report.return_code -ne 0) {
            $childStdoutPath = [string]$report.stdout_path
            $childStderrPath = [string]$report.stderr_path
            $stdoutContent = if (Test-Path -LiteralPath $childStdoutPath -PathType Leaf) { Get-Content -LiteralPath $childStdoutPath -Raw } else { '' }
            $stderrContent = if (Test-Path -LiteralPath $childStderrPath -PathType Leaf) { Get-Content -LiteralPath $childStderrPath -Raw } else { '' }
            throw ("Expected Measure-StressRun regression fixture to complete successfully (exit code {0}).`nSTDOUT:`n{1}`nSTDERR:`n{2}" -f $report.return_code, $stdoutContent, $stderrContent)
        }
        Assert-True ($report.sample_count -gt 0) 'Expected Measure-StressRun regression fixture to record at least one process-tree sample.'
        Assert-True ($report.dashboard_exists -eq $true) 'Expected Measure-StressRun regression fixture to generate the dashboard output.'
        Assert-True ($report.benchmark_evidence.evidence_schema_version -eq 1) 'Expected Measure-StressRun to persist the versioned benchmark evidence envelope.'
        Assert-True ($report.benchmark_evidence.dataset.files.Count -gt 0) 'Expected Measure-StressRun benchmark evidence to include dataset artifact hashes.'
    }
    finally {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }

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
        Write-GzipTextFile -Path (Get-AdvancedHuntingCurrentPath -BasePath $tempRoot) -Content '[]'
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

function Test-ProceduralSyntheticDatasetGeneration {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('procedural-synthetic-' + [guid]::NewGuid().ToString('N'))
    $firstPath = Join-Path $tempRoot 'first'
    $secondPath = Join-Path $tempRoot 'second'
    $overlayPath = Join-Path $tempRoot 'overlay'
    $initialImportPath = Join-Path $tempRoot 'initial-import'
    try {
        [void](New-Item -Path $firstPath -ItemType Directory -Force)
        [void](New-Item -Path $secondPath -ItemType Directory -Force)
        $writerSource = Join-Path $PSScriptRoot 'helpers\SyntheticDatasetWriter.cs'
        if ($null -eq ('DefenderReporting.Synthetic.SyntheticDatasetWriter' -as [type])) { Add-Type -Path $writerSource }
        foreach ($path in @($firstPath, $secondPath)) {
            $result = [DefenderReporting.Synthetic.SyntheticDatasetWriter]::Generate($path, 16, 240, 4242, '2026-07-11', 4, 80, 0.10, 0.05, $true)
            Assert-True ($result.CurrentRows + $result.HistoryRows -eq 240) 'Expected procedural writer to emit the requested total row count.'
            ([ordered]@{
                manifestVersion = 2; generatorVersion = 'procedural-streaming-v1'; modelVersion = 'procedural-v1'; datasetId = 'procedural-test';
                preset = 'BalancedMediumHeavy'; seed = 4242; generationDate = '2026-07-11'; snapshotOrdinal = 0;
                actualDeviceCount = 16; actualCurrentRows = $result.CurrentRows; actualHistoryRows = $result.HistoryRows;
                actualTotalVulnRows = 240; targetDeviceCount = 16; targetTotalVulnRows = 240; contentTemplateCount = 80
            }) | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $path 'synthetic-manifest.json') -Encoding utf8
        }

        foreach ($firstFile in @(Get-ChildItem -LiteralPath $firstPath -Filter '*.json.gz' -File | Sort-Object Name)) {
            $secondFile = Join-Path $secondPath $firstFile.Name
            Assert-True ((Test-Path -LiteralPath $secondFile -PathType Leaf)) "Expected deterministic rerun artifact '$($firstFile.Name)'."
            Assert-True ((Get-FileHash $firstFile.FullName).Hash -eq (Get-FileHash $secondFile).Hash) "Expected byte-stable procedural artifact '$($firstFile.Name)'."
        }

        Assert-True (Test-VulnContentStoreExistence -BasePath $firstPath) 'Expected procedural seed to create a valid content store.'
        Assert-True (@(Read-VulnContentStoreRow -BasePath $firstPath).Count -eq 240) 'Expected procedural content refs to expand to every requested row.'
        foreach ($historyFile in @(Get-ChildItem -LiteralPath $firstPath -Filter 'VulnHistory_*.json.gz' -File)) {
            Assert-True ((Test-VulnHistoryFileLightweight -Path $historyFile.FullName) -ge 0) "Expected valid procedural history metadata in '$($historyFile.Name)'."
        }

        & (Join-Path $PSScriptRoot 'New-SyntheticSnapshotDelta.ps1') -SourcePath $firstPath -OutputPath $overlayPath -TargetLatestDate '2026-07-12'
        $overlayManifest = Get-Content -LiteralPath (Join-Path $overlayPath 'synthetic-manifest.json') -Raw | ConvertFrom-Json -Depth 30
        Assert-True ([string]$overlayManifest.incrementMode -eq 'AdvanceSnapshot') 'Expected procedural delta to use AdvanceSnapshot mode.'
        foreach ($category in @('added', 'changed', 'removed', 'reopened', 'persistent')) {
            Assert-True ([int]$overlayManifest.churn.$category -gt 0) "Expected deterministic overlay churn category '$category' to contain rows."
        }
        Assert-True (@(Get-ChildItem -LiteralPath $overlayPath -Filter 'VulnExport_*_2026-07-12.json.gz' -File).Count -gt 0) 'Expected procedural delta to emit grouped bulk snapshot files.'
        if ($IsWindows) { Assert-True ([int]$overlayManifest.hardLinkedSeedFiles -gt 0) 'Expected Windows procedural overlays to hard-link unchanged seed artifacts.' }
        Assert-True ((Get-FileHash (Join-Path $firstPath 'VulnContentDictionary.json.gz')).Hash -eq (Get-FileHash (Join-Path $overlayPath 'VulnContentDictionary.json.gz')).Hash) 'Expected overlay creation to preserve the base dictionary.'

        [void](New-Item -Path $initialImportPath -ItemType Directory -Force)
        Copy-Item -LiteralPath (Join-Path $overlayPath 'synthetic-manifest.json') -Destination $initialImportPath
        foreach ($snapshotFile in @(Get-ChildItem -LiteralPath $overlayPath -Filter 'VulnExport_*_2026-07-12.json.gz' -File)) {
            Copy-Item -LiteralPath $snapshotFile.FullName -Destination $initialImportPath
        }
        $initialResult = Publish-VulnStoreFromBulkSnapshot -BasePath $initialImportPath -SnapshotFilePaths @(
            Get-ChildItem -LiteralPath $initialImportPath -Filter 'VulnExport_*.json.gz' -File | ForEach-Object { $_.FullName }
        )
        Assert-True ($initialResult.CurrentRows -gt 0) 'Expected procedural initial import to publish current rows.'
        Assert-True (Test-VulnStoreExistence -BasePath $initialImportPath) 'Expected procedural initial import to create the canonical store.'
        Assert-True (Test-VulnContentStoreExistence -BasePath $initialImportPath) 'Expected procedural initial import to create content sidecars.'
        Assert-True (@(Read-VulnContentStoreRow -BasePath $initialImportPath).Count -eq $initialResult.CurrentRows) 'Expected procedural initial import refs to expand to every canonical current row.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Test-BenchmarkEvidenceEnvelopeWritesTransactionally {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path $PSScriptRoot 'helpers\BenchmarkEvidenceTools.ps1')
    $schemaPath = Join-Path $PSScriptRoot 'benchmark-evidence.schema.json'
    Assert-True (Test-Path -LiteralPath $schemaPath -PathType Leaf) 'Expected the benchmark evidence JSON schema to exist.'

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('benchmark-evidence-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'synthetic-manifest.json'), '{"datasetId":"evidence-test","actualTotalVulnRows":1}', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'VulnCurrentRefs.json'), '[0,0,0,"2026-01-01","2026-01-01"]', [System.Text.UTF8Encoding]::new($false))
        $dataset = Get-BenchmarkDatasetEvidence -DatasetPath $tempRoot
        $evidence = Get-BenchmarkEvidenceEnvelope -Kind 'regression' -RepoPath $repoRoot -Dataset $dataset -Execution ([PSCustomObject]@{ status = 'completed' })
        $outputPath = Join-Path $tempRoot 'result\evidence.json'
        Write-BenchmarkEvidenceEnvelope -Path $outputPath -Evidence $evidence

        $written = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json -Depth 50
        Assert-True ($written.evidence_schema_version -eq 1) 'Expected benchmark evidence schema version 1.'
        Assert-True ($written.dataset.files.Count -eq 2) 'Expected benchmark evidence to hash every source dataset artifact before writing its result.'
        Assert-True (-not [string]::IsNullOrWhiteSpace([string]$written.artifacts.runbook)) 'Expected benchmark evidence to capture the generated runbook fingerprint.'
        Assert-True (@(Get-ChildItem -LiteralPath (Split-Path $outputPath -Parent) -Filter '*.tmp-*' -File).Count -eq 0) 'Expected transactional benchmark evidence publication to clean staging files.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Test-RunbookBenchmarkPublicationReaderOptIn {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path $PSScriptRoot -Parent
    $benchmarkPath = Join-Path $PSScriptRoot 'Measure-RunbookOnlyAzureBenchmark.ps1'
    $benchmarkAst = [System.Management.Automation.Language.Parser]::ParseFile($benchmarkPath, [ref]$null, [ref]$null)
    $parameter = $benchmarkAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'UseBoundedPublicationMetadataReader' }
    Assert-True ($parameter.DefaultValue.Extent.Text -eq '$false') 'Benchmark reader flag must default false.'
    $startDefinition = $benchmarkAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-RunbookBenchmark' }, $true)
    . ([scriptblock]::Create($startDefinition.Extent.Text))
    . (Join-Path $PSScriptRoot 'helpers/TestScriptSupport.ps1')
    function Invoke-AzCli {
        param($Arguments, [switch]$ExpectJson)
        if (-not $ExpectJson) { throw 'Benchmark startup must request structured job evidence.' }
        $script:ReaderBenchmarkArguments = @($Arguments)
        [pscustomobject]@{ name = 'fixture'; jobId = 'fixture'; status = 'New'; creationTime = '2026-09-30T00:00:00Z' }
    }
    $script:AutomationAccountName = 'fixture'
    $script:AutomationResourceGroup = 'fixture'
    $script:RunbookName = 'fixture'
    $script:StorageAccountName = 'fixturestorage'
    $script:DashboardDeliveryMode = 'Dual'
    $script:UseExistingExportsOnly = $true
    $script:UseDirectMergeDeviceLookup = $true
    foreach ($enabled in @($false, $true)) {
        $script:UseBoundedPublicationMetadataReader = $enabled
        $script:UseExperimentalCompiledSmallPayload = $enabled
        $null = Start-RunbookBenchmark -Confirm:$false
        Assert-True (($script:ReaderBenchmarkArguments -contains 'UseBoundedPublicationMetadataReader=true') -eq $enabled) 'Benchmark job reader selection differs from requested treatment.'
        Assert-True (($script:ReaderBenchmarkArguments -contains 'UseExperimentalCompiledSmallPayload=true') -eq $enabled) 'Benchmark job compiled-small-payload selection differs from requested treatment.'
        Assert-True ($script:ReaderBenchmarkArguments -contains 'UseExistingExportsOnly=true' -and $script:ReaderBenchmarkArguments -contains 'UseDirectMergeDeviceLookup=true') 'Benchmark omitted replay/direct-merge trial flags.'
        Assert-True ($script:ReaderBenchmarkArguments -contains 'StorageAccountName=fixturestorage') 'Benchmark job must use the storage account selected for seeding and evidence.'
    }
    Assert-True ($benchmarkAst.Extent.Text.Contains('use_bounded_publication_metadata_reader = $script:UseBoundedPublicationMetadataReader')) 'Benchmark must record its reader selection.'
    Assert-True ($benchmarkAst.Extent.Text.Contains('use_experimental_compiled_small_payload = $script:UseExperimentalCompiledSmallPayload')) 'Benchmark must record its compiled-small-payload selection.'
    $validationAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-AzureRunbookValidation.ps1'), [ref]$null, [ref]$null)
    $validationParameter = $validationAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'UseBoundedPublicationMetadataReader' }
    Assert-True ($validationParameter.DefaultValue.Extent.Text -eq '$false') 'Guarded wrapper must default to legacy reading.'
    Assert-True ($validationAst.Extent.Text.Contains('-UseBoundedPublicationMetadataReader $UseBoundedPublicationMetadataReader -UseDirectMergeDeviceLookup:$UseDirectMergeDeviceLookup')) 'Guarded wrapper must forward trial treatment flags.'
    Assert-True ($validationAst.Extent.Text.Contains('-UseExperimentalCompiledSmallPayload:$UseExperimentalCompiledSmallPayload')) 'Guarded wrapper must forward the compiled-small-payload trial flag.'
    $functionBuilder = Get-Content (Join-Path $repoRoot 'build/azure/Build-FunctionApp.ps1') -Raw
    Assert-True ($functionBuilder.Contains('$UseBoundedPublicationMetadataReader = $false') -and -not $functionBuilder.Contains('$env:USE_BOUNDED_PUBLICATION_METADATA_READER')) 'Function must stay legacy without a new setting.'
    Assert-True ($functionBuilder.Contains('$UseExperimentalCompiledSmallPayload = $false') -and -not $functionBuilder.Contains('$env:USE_EXPERIMENTAL_COMPILED_SMALL_PAYLOAD')) 'Function must keep the experimental compiled-small-payload path disabled.'
}

function Test-BenchmarkComparisonUsesProcessHighWater {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('benchmark-high-water-' + [guid]::NewGuid().ToString('N'))
    $resultPath = Join-Path $tempRoot 'result.json'
    $comparisonPath = Join-Path $tempRoot 'comparison.json'
    $compareScript = Join-Path $PSScriptRoot 'Compare-BenchmarkEvidence.ps1'
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    try {
        $evidence = [ordered]@{
            evidence_schema_version = 1
            execution = [ordered]@{
                summary = @{ peak_working_set_mb = 302.1 }
                status = @{ memory = @{ processPeakWorkingSetMb = 400.1 } }
            }
        }
        [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
        $failed = $false
        try {
            $null = & $compareScript -CurrentPath $resultPath -MaximumWorkingSetMB 381.4 -RequireProcessWorkingSetPeak -StrictWorkingSetLimit -OutputPath $comparisonPath
        }
        catch { $failed = $true }
        Assert-True $failed 'A sampled peak below the limit must not hide a process high-water above it.'
        $comparison = Get-Content -LiteralPath $comparisonPath -Raw | ConvertFrom-Json
        Assert-True (-not $comparison.passed -and $comparison.current.peak_working_set_mb -eq 400.1 -and $comparison.current.process_peak_working_set_mb -eq 400.1) 'Comparison must report and enforce the process high-water.'

        $evidence.execution.status.memory.processPeakWorkingSetMb = 381.4
        [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
        $failed = $false
        try { $null = & $compareScript -CurrentPath $resultPath -MaximumWorkingSetMB 381.4 -StrictWorkingSetLimit }
        catch { $failed = $true }
        Assert-True $failed 'A strict working-set limit must reject equality.'
        $comparison = & $compareScript -CurrentPath $resultPath -MaximumWorkingSetMB 381.4
        Assert-True $comparison.passed 'The existing inclusive maximum must still accept equality by default.'

        $evidence.execution.status.memory.processPeakWorkingSetMb = 381.4001
        [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
        $failed = $false
        try { $null = & $compareScript -CurrentPath $resultPath -MaximumWorkingSetMB 381.4 }
        catch { $failed = $true }
        Assert-True $failed 'Memory evidence above the maximum must not be rounded down into a pass.'

        $evidence.execution.status = @{}
        [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
        $failed = $false
        try { $null = & $compareScript -CurrentPath $resultPath -MaximumWorkingSetMB 381.4 -RequireProcessWorkingSetPeak }
        catch { $failed = $true }
        Assert-True $failed 'A required process high-water must not be inferred from a sampled peak.'
        $comparison = & $compareScript -CurrentPath $resultPath -MaximumWorkingSetMB 381.4
        Assert-True ($comparison.passed -and $null -eq $comparison.current.process_peak_working_set_mb) 'Legacy sampled evidence must remain usable without the high-water requirement.'

        $evidence.execution.status = @{ memory = @{ processPeakWorkingSetMb = 0 } }
        [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
        $failed = $false
        try { $null = & $compareScript -CurrentPath $resultPath -MaximumWorkingSetMB 381.4 -RequireProcessWorkingSetPeak }
        catch { $failed = $true }
        Assert-True $failed 'A zero process high-water must not establish memory acceptance.'

        $evidence.execution.status.memory.processPeakWorkingSetMb = 'NaN'
        [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
        $failed = $false
        try { $null = & $compareScript -CurrentPath $resultPath -MaximumWorkingSetMB 381.4 }
        catch { $failed = $true }
        Assert-True $failed 'A non-finite metric must not pass a memory limit.'

        $evidence.execution.status = @{}
        $evidence.execution.summary = @{}
        [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
        $failed = $false
        try { $null = & $compareScript -CurrentPath $resultPath -MaximumWorkingSetMB 381.4 }
        catch { $failed = $true }
        Assert-True $failed 'A configured memory limit must fail when its evidence is unavailable.'

        $baselinePath = Join-Path $tempRoot 'baseline.json'
        $baseline = @{ evidence_schema_version = 1; execution = @{ summary = @{ elapsed_seconds = 100 } } }
        [System.IO.File]::WriteAllText($baselinePath, ($baseline | ConvertTo-Json -Depth 10))
        $evidence.execution.summary = @{ elapsed_seconds = 110 }
        [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
        $comparison = & $compareScript -CurrentPath $resultPath -BaselinePath $baselinePath -MaximumElapsedRegressionPercent 10
        Assert-True $comparison.passed 'The elapsed limit must accept its inclusive boundary.'

        $evidence.execution.summary.elapsed_seconds = 110.004
        [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
        $failed = $false
        try { $null = & $compareScript -CurrentPath $resultPath -BaselinePath $baselinePath -MaximumElapsedRegressionPercent 10 }
        catch { $failed = $true }
        Assert-True $failed 'Elapsed evidence above the limit must not be rounded down into a pass.'

        foreach ($boundary in @(@{ baseline = 0.03; current = 0.033 }, @{ baseline = 1.13; current = 1.243 })) {
            $baseline.execution.summary.elapsed_seconds = $boundary.baseline
            $evidence.execution.summary.elapsed_seconds = $boundary.current
            [System.IO.File]::WriteAllText($baselinePath, ($baseline | ConvertTo-Json -Depth 10))
            [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
            $comparison = & $compareScript -CurrentPath $resultPath -BaselinePath $baselinePath -MaximumElapsedRegressionPercent 10
            Assert-True $comparison.passed 'Decimal elapsed evidence at the inclusive boundary must not fail due to binary floating-point error.'
        }

        foreach ($missingSide in @('current', 'baseline')) {
            $evidence.execution.summary = if ($missingSide -eq 'current') { @{} } else { @{ elapsed_seconds = 100 } }
            $baseline.execution.summary = if ($missingSide -eq 'baseline') { @{ elapsed_seconds = 0 } } else { @{ elapsed_seconds = 100 } }
            [System.IO.File]::WriteAllText($resultPath, ($evidence | ConvertTo-Json -Depth 10))
            [System.IO.File]::WriteAllText($baselinePath, ($baseline | ConvertTo-Json -Depth 10))
            $failed = $false
            try { $null = & $compareScript -CurrentPath $resultPath -BaselinePath $baselinePath }
            catch { $failed = $true }
            Assert-True $failed "Missing or zero $missingSide elapsed evidence must not pass a baseline comparison."
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
    }
}

function Test-RunbookBenchmarkProcessHighWaterSummary {
    [CmdletBinding()]
    param()

    $benchmarkAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Measure-RunbookOnlyAzureBenchmark.ps1'), [ref]$null, [ref]$null)
    $definition = $benchmarkAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-RunbookProcessPeakWorkingSet' }, $true)
    Assert-True ($null -ne $definition) 'Expected a testable process high-water summary.'
    . ([scriptblock]::Create($definition.Extent.Text))
    $status = [PSCustomObject]@{
        memory = [PSCustomObject]@{ processPeakWorkingSetMb = 400.1 }
        memoryTimelineTail = @([PSCustomObject]@{ processPeakWorkingSetMb = 380.0 })
    }
    $timeline = @([PSCustomObject]@{ memory = [PSCustomObject]@{ processPeakWorkingSetMb = 405.3 } })
    Assert-True ((Get-RunbookProcessPeakWorkingSet -Status $status -StatusTimeline $timeline) -eq 405.3) 'Expected the largest process high-water from final, embedded, and polling samples.'
    Assert-True ($null -eq (Get-RunbookProcessPeakWorkingSet -Status ([PSCustomObject]@{ memory = [PSCustomObject]@{ workingSetMb = 302.1 } }))) 'A sampled working set must not stand in for a process high-water.'
    Assert-True ($null -eq (Get-RunbookProcessPeakWorkingSet -Status $null)) 'Missing status must not produce a success-shaped high-water.'
    $failed = $false
    try { $null = Get-RunbookProcessPeakWorkingSet -Status ([PSCustomObject]@{ memory = [PSCustomObject]@{ processPeakWorkingSetMb = -1 } }) }
    catch { $failed = $true }
    Assert-True $failed 'Invalid process high-water values must be rejected.'
}

function Test-BenchmarkPortableMemoryCountersRefresh {
    [CmdletBinding()]
    param()

    Initialize-CompiledVulnContentProjector
    $telemetry = [DefenderReporting.Store.MemoryTelemetrySession]::new(0)
    $portableReader = $telemetry.GetType().GetMethod('ReadPortableMemory', [System.Reflection.BindingFlags]'Instance,NonPublic')
    $allocation = [IntPtr]::Zero
    try {
        Assert-True ($null -ne $portableReader) 'Expected a testable portable process-memory reader.'
        $before = [object[]]@(0L, 0L)
        [void]$portableReader.Invoke($telemetry, $before)
        $allocation = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(32MB)
        for ($offset = 0; $offset -lt 32MB; $offset += 4096) {
            [System.Runtime.InteropServices.Marshal]::WriteByte($allocation, $offset, 1)
        }
        $after = [object[]]@(0L, 0L)
        [void]$portableReader.Invoke($telemetry, $after)
        Assert-True ([long]$before[0] -gt 0 -and [long]$before[1] -gt 0) 'Portable memory counters must report positive values.'
        Assert-True (([long]$after[1] - [long]$before[1]) -ge 8MB) 'Portable private memory must refresh after the process commits additional memory.'
    }
    finally {
        if ($allocation -ne [IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($allocation) }
        $telemetry.Dispose()
    }
}

function Test-RunbookBenchmarkStatusJobIdentity {
    [CmdletBinding()]
    param()

    . (Join-Path $PSScriptRoot 'helpers\TestScriptSupport.ps1')
    $benchmarkAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Measure-RunbookOnlyAzureBenchmark.ps1'), [ref]$null, [ref]$null)
    $definition = $benchmarkAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-RunbookStatusMatchesJob' }, $true)
    Assert-True ($null -ne $definition) 'Expected a testable runbook status identity check.'
    . ([scriptblock]::Create($definition.Extent.Text))
    $created = [datetime]::Parse('2026-11-25T18:00:00Z').ToUniversalTime()
    $matching = [PSCustomObject]@{ startedOnUtc = '2026-11-25T18:00:30Z'; automationJobId = 'job-a' }
    Assert-True (Test-RunbookStatusMatchesJob -Status $matching -JobId 'JOB-A' -JobCreationUtc $created) 'Expected a matching Automation job status.'
    Assert-True (-not (Test-RunbookStatusMatchesJob -Status $matching -JobId 'job-b' -JobCreationUtc $created)) 'A concurrent job status must not be attributed to this job.'
    $old = [PSCustomObject]@{ startedOnUtc = '2026-11-25T17:58:00Z'; automationJobId = 'job-a' }
    Assert-True (-not (Test-RunbookStatusMatchesJob -Status $old -JobId 'job-a' -JobCreationUtc $created)) 'An old status must not be attributed to a new job.'
    Assert-True (-not (Test-RunbookStatusMatchesJob -Status $null -JobId 'job-a' -JobCreationUtc $created)) 'Missing status must be rejected.'
    $legacy = [PSCustomObject]@{ startedOnUtc = '2026-11-25T18:00:30Z' }
    Assert-True (Test-RunbookStatusMatchesJob -Status $legacy -JobId 'job-a' -JobCreationUtc $created) 'Legacy status without job ID retains timestamp-only compatibility.'
}

function Test-AzureValidationSeedSelection {
    [CmdletBinding()]
    param()

    $validationAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-AzureRunbookValidation.ps1'), [ref]$null, [ref]$null)
    $definition = $validationAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-AzureValidationSeedFile' }, $true)
    Assert-True ($null -ne $definition) 'Expected a testable Azure replay seed selection function.'
    . ([scriptblock]::Create($definition.Extent.Text))
    foreach ($name in @('Machines_Current.json.gz', 'AdvancedHunting_Current.json.gz', 'NvdCve_Current.json.gz', 'synthetic-manifest.json', 'benchmark-dataset.json')) {
        Assert-True (Test-AzureValidationSeedFile -Name $name -Mode 'ContentReplay') "Expected content replay to include $name."
        Assert-True (Test-AzureValidationSeedFile -Name $name -Mode 'RawReplay') "Expected raw replay to include $name."
    }
    Assert-True (Test-AzureValidationSeedFile -Name 'VulnCurrentRefs.json.gz' -Mode 'ContentReplay') 'Expected content replay refs.'
    Assert-True (Test-AzureValidationSeedFile -Name 'VulnHistoryRefs_2026Q1.json.gz' -Mode 'ContentReplay') 'Expected content replay history refs.'
    Assert-True (-not (Test-AzureValidationSeedFile -Name 'VulnCurrentRefs.json.gz' -Mode 'RawReplay')) 'Raw replay must not seed content refs.'
    Assert-True (Test-AzureValidationSeedFile -Name 'VulnExport_2026-01-01.json.gz' -Mode 'RawReplay') 'Expected raw replay export.'
    Assert-True (-not (Test-AzureValidationSeedFile -Name 'VulnExport_current.json.gz' -Mode 'RawReplay')) 'Raw replay must not seed the current-store artifact.'
    Assert-True (-not (Test-AzureValidationSeedFile -Name 'unrelated.txt' -Mode 'ContentReplay')) 'Content replay must exclude unrelated files.'
    Assert-True (Test-AzureValidationSeedFile -Name 'unrelated.txt' -Mode 'Exact') 'Exact replay must include all root files.'
}

function Test-RunbookExperimentalNormalizationCacheIsolation {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path $PSScriptRoot -Parent
    $runbookPath = Join-Path $repoRoot 'build\azure\runbook-source.ps1'
    $runbookAst = [System.Management.Automation.Language.Parser]::ParseFile($runbookPath, [ref]$null, [ref]$null)
    $parameter = $runbookAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'UseExperimentalCompiledSmallPayload' }
    Assert-True ($parameter.DefaultValue.Extent.Text -eq '$false') 'Runbook compiled-small-payload flag must default false.'

    $lookupAssignments = @($runbookAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -eq 'payloadCacheEntry'
            }, $true))
    $publicationAssignments = @($runbookAst.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -eq 'cacheEntry'
            }, $true))
    Assert-True ($lookupAssignments.Count -eq 1 -and $publicationAssignments.Count -eq 1) 'Expected one runbook cache lookup and one publication decision.'

    function Get-NormalizedPayloadCacheEntry {
        param($BasePath, [switch]$SkipObservedWindowMerge)
        if ($BasePath -ne $tempExports -or [bool]$SkipObservedWindowMerge -ne $skipObservedWindowMerge) { throw 'Unexpected cache lookup arguments.' }
        $script:ExperimentalCacheLookupCalls++
        return [PSCustomObject]@{ Kind = 'lookup' }
    }
    function Publish-NormalizedPayloadCache {
        param($BasePath, $PayloadPath, $VulnCount, $DeviceCount, $CveCount, $Quality, $SourceMetadata, [switch]$SkipObservedWindowMerge)
        if ($BasePath -ne $tempExports -or $PayloadPath -ne $tempPayloadPath -or $VulnCount -ne 1 -or $DeviceCount -ne 1 -or $CveCount -ne 1 -or $Quality -ne $normalizedQuality -or $null -ne $SourceMetadata -or [bool]$SkipObservedWindowMerge -ne $skipObservedWindowMerge) { throw 'Unexpected cache publication arguments.' }
        $script:ExperimentalCachePublishCalls++
        return [PSCustomObject]@{ Kind = 'publication' }
    }
    $tempExports = 'fixture'
    $tempPayloadPath = 'fixture.json.gz'
    $skipObservedWindowMerge = $false
    $vulnCount = 1
    $deviceCount = 1
    $cveCount = 1
    $normalizedQuality = $null
    $sourceMetadata = $null
    foreach ($UseExperimentalCompiledSmallPayload in @($false, $true)) {
        $script:ExperimentalCacheLookupCalls = 0
        $script:ExperimentalCachePublishCalls = 0
        . ([scriptblock]::Create($lookupAssignments[0].Extent.Text))
        . ([scriptblock]::Create($publicationAssignments[0].Extent.Text))
        if ($UseExperimentalCompiledSmallPayload) {
            Assert-True ($script:ExperimentalCacheLookupCalls -eq 0 -and $null -eq $payloadCacheEntry) 'Experimental runs must not read the normal payload cache.'
            Assert-True ($script:ExperimentalCachePublishCalls -eq 0 -and $null -eq $cacheEntry) 'Experimental runs must not publish into the normal payload cache.'
        }
        else {
            Assert-True ($script:ExperimentalCacheLookupCalls -eq 1 -and $payloadCacheEntry.Kind -eq 'lookup') 'Default runs must retain payload cache lookup.'
            Assert-True ($script:ExperimentalCachePublishCalls -eq 1 -and $cacheEntry.Kind -eq 'publication') 'Default runs must retain payload cache publication.'
        }
    }
    Assert-True ($runbookAst.Extent.Text.Contains('-UseExperimentalCompiledSmallPayload:$UseExperimentalCompiledSmallPayload')) 'Runbook must forward the experimental flag.'
}

function Test-BenchmarkWorkloadProfilesArePinned {
    [CmdletBinding()]
    param()
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path $PSScriptRoot 'Import-BenchmarkDatasetCatalog.ps1')
    $catalog = @(Import-BenchmarkDatasetCatalog -RepoRoot $repoRoot)
    $expectedProfiles = @('ProductionRepresentative', 'RowVolumeStress', 'ContentCardinalityStress', 'DeviceCardinalityStress', 'HistoryChurnStress', 'UnicodeAndSparsityEdgeCases')
    foreach ($workloadName in $expectedProfiles) {
        $definition = @($catalog | Where-Object workloadProfile -eq $workloadName)
        Assert-True ($definition.Count -eq 1) "Expected exactly one pinned '$workloadName' workload definition."
        foreach ($propertyName in @('workloadProfileVersion', 'modelVersion', 'seed', 'targetDeviceCount', 'targetTotalVulnRows', 'contentTemplateCount', 'expectedEnvelope')) {
            Assert-True ($null -ne $definition[0].PSObject.Properties[$propertyName]) "Expected '$workloadName' to pin '$propertyName'."
        }
    }
}

function Test-SyntheticUploadManifestSelectsRawReplayArtifact {
    [CmdletBinding()]
    param()
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('upload-manifest-' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        foreach ($name in @('VulnExport_100_2026-07-12.json.gz', 'Machines_Current.json.gz', 'AdvancedHunting_Current.json.gz', 'VulnCurrentRefs.json.gz')) {
            [System.IO.File]::WriteAllText((Join-Path $tempRoot $name), $name, [System.Text.UTF8Encoding]::new($false))
        }
        $manifestPath = Join-Path $tempRoot 'upload.json'
        & (Join-Path $repoRoot 'tests\New-SyntheticUploadManifest.ps1') -DatasetPath $tempRoot -OutputPath $manifestPath -Mode RawReplay | Out-Null
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
        $names = @($manifest.artifacts | ForEach-Object name)
        Assert-True ('VulnExport_100_2026-07-12.json.gz' -in $names) 'Expected raw replay upload manifest to include dated vulnerability exports.'
        Assert-True ('Machines_Current.json.gz' -in $names) 'Expected raw replay upload manifest to include the machine snapshot.'
        Assert-True ('VulnCurrentRefs.json.gz' -notin $names) 'Expected raw replay upload manifest to exclude precomputed content refs.'
    }
    finally { if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } }
}

function Test-GenerateSyntheticLargeExportsUsesStablePlannerOrdering {
    [CmdletBinding()]
    param()

    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $generatorScriptPath = Join-Path $repoRoot 'tests\Generate-SyntheticLargeExports.ps1'
    Assert-True ((Test-Path -LiteralPath $generatorScriptPath -PathType Leaf)) "Expected synthetic large-export generator script at '$generatorScriptPath'."

    $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction Stop
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('synthetic-ordering-' + [guid]::NewGuid().ToString('N'))

    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)

        $runDirectories = @(
            (Join-Path $tempRoot 'run-a')
            (Join-Path $tempRoot 'run-b')
        )

        foreach ($runDirectory in $runDirectories) {
            # The generator atomically replaces OutputPath. Redirecting live
            # process logs inside that directory prevents the Windows rename.
            $runName = Split-Path -Path $runDirectory -Leaf
            $stdoutPath = Join-Path $tempRoot ($runName + '.stdout.log')
            $stderrPath = Join-Path $tempRoot ($runName + '.stderr.log')

            $argumentList = @(
                '-NoProfile'
                '-File'
                $generatorScriptPath
                '-SourcePath'
                $PSScriptRoot
                '-OutputPath'
                $runDirectory
                '-TargetDeviceCount'
                '12'
                '-TargetTotalVulnRows'
                '300'
                '-MinimumAvailableMemoryGB'
                '1'
                '-Seed'
                '20260322'
            )

            $process = Start-Process -FilePath $pwshCommand.Source -ArgumentList $argumentList -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
            $process.WaitForExit()

            $stdoutContent = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            $stderrContent = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            $processOutput = @($stdoutContent, $stderrContent) -join [Environment]::NewLine

            Assert-True ($process.ExitCode -eq 0) ("Expected deterministic generator smoke run to succeed. Output:`n{0}" -f $processOutput.Trim())
        }

        $manifestPropertyNames = @(
            'preset'
            'seed'
            'targetDeviceCount'
            'targetTotalVulnRows'
            'targetCurrentRows'
            'targetHistoryRows'
            'actualDeviceCount'
            'includeRawRows'
            'actualCurrentRows'
            'actualHistoryRows'
            'actualTotalVulnRows'
            'scaleFactor'
            'sourceCurrentRows'
            'sourceHistoryRows'
            'sourceRowProfiles'
            'historyPeriods'
            'advancedHuntingRows'
            'contentTemplateCount'
            'uniqueCveIdCount'
            'normalizedCveLookupCount'
        )

        $normalizedManifestJson = foreach ($runDirectory in $runDirectories) {
            $manifest = Get-Content -LiteralPath (Join-Path $runDirectory 'synthetic-manifest.json') -Raw | ConvertFrom-Json -Depth 20
            $normalizedManifest = [ordered]@{}
            foreach ($propertyName in $manifestPropertyNames) {
                $property = $manifest.PSObject.Properties[$propertyName]
                $normalizedManifest[$propertyName] = if ($null -ne $property) { $property.Value } else { $null }
            }

            $normalizedManifest | ConvertTo-Json -Depth 20 -Compress
        }

        Assert-True ($normalizedManifestJson[0] -eq $normalizedManifestJson[1]) 'Expected synthetic manifests to match across fresh PowerShell processes when using the same seed.'

        $gzipPaths = @(
            @{ RelativePath = 'Machines_Current.json.gz'; PathResolver = { param($basePath) (Get-MachineCurrentPath -BasePath $basePath) } }
            @{ RelativePath = 'VulnCurrentRefs.json.gz'; PathResolver = { param($basePath) (Get-VulnCurrentRefsPath -BasePath $basePath) } }
            @{ RelativePath = 'AdvancedHunting_Current.json.gz'; PathResolver = { param($basePath) (Get-AdvancedHuntingCurrentPath -BasePath $basePath) } }
            @{ RelativePath = 'VulnContentDictionary.json.gz'; PathResolver = { param($basePath) (Get-VulnContentDictionaryPath -BasePath $basePath) } }
        )

        foreach ($gzipPathInfo in $gzipPaths) {
            $firstPath = & $gzipPathInfo.PathResolver $runDirectories[0]
            $secondPath = & $gzipPathInfo.PathResolver $runDirectories[1]
            Assert-True ((Read-GzipTextFile -Path $firstPath) -eq (Read-GzipTextFile -Path $secondPath)) ("Expected {0} to be stable across fresh PowerShell processes." -f $gzipPathInfo.RelativePath)
        }

        $historyRefNamesA = @((Get-ChildItem -LiteralPath $runDirectories[0] -Filter 'VulnHistoryRefs_*.json.gz' -File | Sort-Object Name).Name)
        $historyRefNamesB = @((Get-ChildItem -LiteralPath $runDirectories[1] -Filter 'VulnHistoryRefs_*.json.gz' -File | Sort-Object Name).Name)

        Assert-True (($historyRefNamesA.Count -eq $historyRefNamesB.Count) -and ((@($historyRefNamesA) -join '|') -eq (@($historyRefNamesB) -join '|'))) 'Expected synthetic history ref file sets to match across fresh PowerShell processes.'

        foreach ($historyRefName in $historyRefNamesA) {
            $firstPath = Join-Path $runDirectories[0] $historyRefName
            $secondPath = Join-Path $runDirectories[1] $historyRefName
            Assert-True ((Read-GzipTextFile -Path $firstPath) -eq (Read-GzipTextFile -Path $secondPath)) ("Expected history ref file '{0}' to be stable across fresh PowerShell processes." -f $historyRefName)
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
