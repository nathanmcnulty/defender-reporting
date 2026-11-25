# Shared-helper regression fragment (Store). Dot-sourced by Run-SharedHelperRegression.ps1; not an entrypoint.

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

function Test-InitializeMachineHistoryStoreSupportsStateHashOnlyCurrentMap {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Regression test name intentionally refers to current records and metadata fields as a set.')]
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-store-statehash-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $machineRecord = Get-TestMachineRecord -Id 'machine-001'
        Write-NdjsonRecordsFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Records @(
            $machineRecord,
            [PSCustomObject]@{
                id = 'machine-002'
                removed = $true
            }
        )

        $store = Initialize-MachineHistoryStore -Path $tempRoot -LoadCurrentRecordsStateHashOnly
        $currentRecordStateHash = [string]$store.CurrentRecords['machine-001']

        Assert-True ($store.CurrentRecords.Count -eq 1) 'Expected removal records to be excluded from the current machine stateHash map.'
        Assert-True (-not [string]::IsNullOrWhiteSpace($currentRecordStateHash)) 'Expected stateHash-only initialization to preserve the surviving machine state hash.'
        Assert-True ($currentRecordStateHash -eq [string](Get-MachineStateHash -Machine $machineRecord)) 'Expected stateHash-only initialization to compute the same current-machine state hash as the full-record path.'
        Assert-True ($store.HistoryRecordsByPeriod.Count -eq 0) 'Expected stateHash-only initialization to skip synthetic history seeding when the current map does not retain full snapshot records.'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-MdeMachineRefreshPublishPlanSupportsStateHashOnlyCurrentMap {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-refresh-plan-statehash-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock

    try {
        Write-NdjsonRecordsFile -Path (Get-MachineCurrentPath -BasePath $tempRoot) -Records @(
            (Get-TestMachineRecord -Id 'machine-001'),
            (Get-TestMachineRecord -Id 'machine-002')
        )

        $store = Initialize-MachineHistoryStore -Path $tempRoot -LoadCurrentRecordsStateHashOnly
        $changedMachine = Get-TestMachineRecord -Id 'machine-002'
        $changedMachine.riskScore = 'High'
        $newMachine = Get-TestMachineRecord -Id 'machine-003'
        $script:MockMachineRefreshPlanResponses = @(
            [PSCustomObject]@{
                value = @(
                    Get-TestMachineRecord -Id 'machine-001'
                    $changedMachine
                    $newMachine
                )
            }
        )
        $script:MockMachineRefreshPlanIndex = 0

        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param(
                [string]$Uri,
                [hashtable]$Headers,
                [string]$Method
            )

            [void]$Uri
            [void]$Headers
            [void]$Method

            if ($script:MockMachineRefreshPlanIndex -ge $script:MockMachineRefreshPlanResponses.Count) {
                throw 'Mock machine refresh plan responses were exhausted unexpectedly.'
            }

            $response = $script:MockMachineRefreshPlanResponses[$script:MockMachineRefreshPlanIndex]
            $script:MockMachineRefreshPlanIndex++
            return $response
        }

        $stagedCurrentPath = Join-Path $tempRoot 'Machines_Current.staged.json.gz'
        $refreshPlan = Get-MdeMachineRefreshPublishPlan -Headers @{ Authorization = 'Bearer test' } -BaseApiUrl 'https://example.invalid' -ObservedOn '2026-05-10' -CurrentRecords $store.CurrentRecords -StagedCurrentPath $stagedCurrentPath
        $stagedCurrentRecords = @(Read-MachineRecordsFromFile -Path $refreshPlan.StagedCurrentPath)
        $stagedHistoryRecords = @(Read-MachineRecordsFromFile -Path $refreshPlan.StagedHistoryPath)

        Assert-True ($refreshPlan.MachineCount -eq 3) 'Expected the refresh plan to preserve all fetched machine rows when the current map is stateHash-only.'
        Assert-True ($refreshPlan.ChangeCount -eq 2) 'Expected the refresh plan to detect one changed machine and one new machine when current rows are represented by state hashes.'
        Assert-True ($refreshPlan.PageCount -eq 1) 'Expected the refresh plan to consume the mocked single-page machine response.'
        Assert-True ($store.CurrentRecords.Count -eq 0) 'Expected the refresh plan to remove every surviving current-machine entry from the stateHash-only map.'
        Assert-True ($stagedCurrentRecords.Count -eq 3) 'Expected the staged current machine file to include every fetched machine row.'
        Assert-True ($stagedHistoryRecords.Count -eq 2) 'Expected the staged history file to include only the changed and new machine rows.'
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Remove-Variable -Name MockMachineRefreshPlanResponses -Scope Script -ErrorAction SilentlyContinue
        Remove-Variable -Name MockMachineRefreshPlanIndex -Scope Script -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-MdeMachineRefreshFailureRemovesStagedFile {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-refresh-failure-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRestMethod = (Get-Command -Name Invoke-RestMethodWithRetry -CommandType Function).ScriptBlock
    $originalJsonWrite = (Get-Command -Name Write-JsonValueToWriter -CommandType Function).ScriptBlock

    try {
        $script:MockMachineRefreshOriginalJsonWrite = $originalJsonWrite
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value {
            param([string]$Uri, [hashtable]$Headers, [string]$Method)
            [void]$Uri
            [void]$Headers
            [void]$Method
            $script:MockMachineRefreshFailurePage++
            if ($script:MockMachineRefreshFailurePage -eq 1) {
                $response = [PSCustomObject]@{
                    value = @((Get-TestMachineRecord -Id 'machine-002'))
                }
                if ($script:MockMachineRefreshPageFailure) {
                    $response | Add-Member -NotePropertyName '@odata.nextLink' -NotePropertyValue 'https://example.invalid/api/machines?page=2'
                }
                return $response
            }
            throw 'Injected second-page failure'
        }
        Set-Item -Path Function:Write-JsonValueToWriter -Value {
            param([Newtonsoft.Json.JsonTextWriter]$Writer, [AllowNull()][object]$Value)
            if ($null -eq $Writer.PSObject.Properties['MockRefreshWriterIndex']) {
                $writerIndex = $script:MockMachineRefreshWriters.Count
                $script:MockMachineRefreshWriters.Add($Writer)
                $Writer | Add-Member -NotePropertyName MockRefreshWriterIndex -NotePropertyValue $writerIndex
                if ($script:MockMachineRefreshFailDisposeIndices -contains $writerIndex) {
                    $streamWriterField = [Newtonsoft.Json.JsonTextWriter].GetField('_writer', [System.Reflection.BindingFlags]'Instance,NonPublic')
                    $streamWriter = $streamWriterField.GetValue($Writer)
                    $streamWriter | Add-Member -MemberType ScriptMethod -Name Dispose -Force -Value {
                        $script:MockMachineRefreshDisposeFailureAttempted = $true
                        $this.psbase.Dispose()
                        throw 'Injected stream dispose failure'
                    }
                }
                $Writer | Add-Member -MemberType ScriptMethod -Name Close -Force -Value {
                    $script:MockMachineRefreshCloseAttempts.Add([int]$this.MockRefreshWriterIndex)
                    if ($script:MockMachineRefreshFailCloseIndices -contains [int]$this.MockRefreshWriterIndex) {
                        throw "Injected writer close failure $($this.MockRefreshWriterIndex)"
                    }
                    $this.psbase.Close()
                }
                foreach ($stagedFile in Get-ChildItem -LiteralPath $script:MockMachineRefreshFailureRoot -Filter '.*.json.gz' -File -Force) {
                    [void]$script:MockMachineRefreshStagedPaths.Add($stagedFile.FullName)
                }
            }
            & $script:MockMachineRefreshOriginalJsonWrite -Writer $Writer -Value $Value
        }
        $mockJsonWrite = (Get-Command -Name Write-JsonValueToWriter -CommandType Function).ScriptBlock

        foreach ($scenario in @(
            @{ Name = 'PageFailure'; PageFailure = $true; FailCloseIndices = @(); ExpectedError = 'Injected second-page failure' }
            @{ Name = 'PageAndBothCloseFailures'; PageFailure = $true; FailCloseIndices = @(0, 1); ExpectedError = 'Injected second-page failure' }
            @{ Name = 'CurrentCloseFailure'; PageFailure = $false; FailCloseIndices = @(0); ExpectedError = 'Injected writer close failure 0' }
            @{ Name = 'HistoryCloseFailure'; PageFailure = $false; FailCloseIndices = @(1); ExpectedError = 'Injected writer close failure 1' }
            @{ Name = 'BothCloseFailures'; PageFailure = $false; FailCloseIndices = @(0, 1); ExpectedError = 'Injected writer close failure 0' }
            @{ Name = 'StreamDisposeFailure'; PageFailure = $false; FailCloseIndices = @(); FailDisposeIndices = @(0); ExpectedError = 'Injected stream dispose failure' }
            @{ Name = 'PageAndStreamDisposeFailure'; PageFailure = $true; FailCloseIndices = @(); FailDisposeIndices = @(0); ExpectedError = 'Injected second-page failure' }
        )) {
            $scenarioRoot = Join-Path $tempRoot $scenario.Name
            [void](New-Item -Path $scenarioRoot -ItemType Directory -Force)
            $currentPath = Get-MachineCurrentPath -BasePath $scenarioRoot
            $historyPath = Get-MachineHistoryQuarterlyPath -BasePath $scenarioRoot -PeriodKey '2026Q2'
            $seedRecord = New-MachineSnapshotRecord -Machine (Get-TestMachineRecord -Id 'machine-001') -ObservedOn '2026-05-10'
            Set-Item -Path Function:Write-JsonValueToWriter -Value $originalJsonWrite
            Write-NdjsonRecordsFile -Path $currentPath -Records @($seedRecord)
            Write-NdjsonRecordsFile -Path $historyPath -Records @($seedRecord)
            $publishedBefore = @{}
            foreach ($publishedPath in @($currentPath, $historyPath)) {
                $publishedBefore[$publishedPath] = @{
                    Hash = (Get-FileHash -LiteralPath $publishedPath -Algorithm SHA256).Hash
                    Content = ConvertTo-Json -InputObject @(Read-MachineRecordsFromFile -Path $publishedPath) -Depth 20 -Compress
                }
            }
            $script:MockMachineRefreshFailureRoot = $scenarioRoot
            $script:MockMachineRefreshFailurePage = 0
            $script:MockMachineRefreshPageFailure = $scenario.PageFailure
            $script:MockMachineRefreshFailCloseIndices = $scenario.FailCloseIndices
            $script:MockMachineRefreshFailDisposeIndices = if ($scenario.ContainsKey('FailDisposeIndices')) { $scenario.FailDisposeIndices } else { @() }
            $script:MockMachineRefreshDisposeFailureAttempted = $false
            $script:MockMachineRefreshWriters = [System.Collections.Generic.List[object]]::new()
            $script:MockMachineRefreshCloseAttempts = [System.Collections.Generic.List[int]]::new()
            $script:MockMachineRefreshStagedPaths = [System.Collections.Generic.HashSet[string]]::new()
            Set-Item -Path Function:Write-JsonValueToWriter -Value $mockJsonWrite

            $failure = $null
            $refreshResult = $null
            try {
                $refreshResult = Invoke-MdeMachineStoreRefresh -Headers @{ Authorization = 'Bearer test' } -OutputPath $scenarioRoot -BaseApiUrl 'https://example.invalid'
            }
            catch {
                $failure = $_
            }

            Assert-True ($null -ne $failure -and $failure.Exception.Message -like "*$($scenario.ExpectedError)*") "Expected $($scenario.Name) to propagate its primary failure."
            Assert-True ($null -eq $refreshResult) "Expected $($scenario.Name) not to return a successful publish result."
            Assert-True (($script:MockMachineRefreshCloseAttempts -join ',') -eq '0,1') "Expected $($scenario.Name) to attempt both writer closes independently."
            if ($scenario.ContainsKey('FailDisposeIndices')) {
                Assert-True $script:MockMachineRefreshDisposeFailureAttempted "Expected $($scenario.Name) to exercise the underlying stream disposal failure."
            }
            Assert-True ($script:MockMachineRefreshStagedPaths.Count -eq 2) "Expected $($scenario.Name) to exercise staged current and history files."
            foreach ($stagedPath in $script:MockMachineRefreshStagedPaths) {
                Assert-True (-not (Test-Path -LiteralPath $stagedPath)) "Expected $($scenario.Name) to remove staged file '$stagedPath'."
            }
            Assert-True (@(Get-ChildItem -LiteralPath $scenarioRoot -Filter '*.json.gz' -File -Force).Count -eq 2) "Expected $($scenario.Name) to leave only the two seeded published files."
            foreach ($publishedPath in @($currentPath, $historyPath)) {
                Assert-True ((Get-FileHash -LiteralPath $publishedPath -Algorithm SHA256).Hash -ceq $publishedBefore[$publishedPath].Hash) "Expected $($scenario.Name) to preserve published bytes at '$publishedPath'."
                $publishedContent = ConvertTo-Json -InputObject @(Read-MachineRecordsFromFile -Path $publishedPath) -Depth 20 -Compress
                Assert-True ($publishedContent -ceq $publishedBefore[$publishedPath].Content) "Expected $($scenario.Name) to preserve published machine content at '$publishedPath'."
            }
            Write-Output "  $($scenario.Name): primary error preserved; both closes attempted; both staged files removed; current/history hashes and content unchanged."
        }
    }
    finally {
        Set-Item -Path Function:Invoke-RestMethodWithRetry -Value $originalRestMethod
        Set-Item -Path Function:Write-JsonValueToWriter -Value $originalJsonWrite
        Remove-Variable -Name MockMachineRefreshOriginalJsonWrite, MockMachineRefreshFailureRoot, MockMachineRefreshFailurePage, MockMachineRefreshPageFailure, MockMachineRefreshFailCloseIndices, MockMachineRefreshFailDisposeIndices, MockMachineRefreshDisposeFailureAttempted, MockMachineRefreshWriters, MockMachineRefreshCloseAttempts, MockMachineRefreshStagedPaths -Scope Script -ErrorAction SilentlyContinue
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

function Test-RestoreStoreTransactionRejectsInvalidJournalShape {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('store-transaction-invalid-' + [guid]::NewGuid().ToString('N'))
    $externalTransactionRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('store-transaction-external-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    [void](New-Item -Path $externalTransactionRoot -ItemType Directory -Force)

    try {
        $journalPath = Get-StoreTransactionJournalPath -BasePath $tempRoot -StoreName 'machines'
        Write-StoreTransactionState -Path $journalPath -State ([PSCustomObject]@{
                StoreName = 'machines'
                TransactionRoot = $externalTransactionRoot
                Phase = 'Prepared'
                Files = @([PSCustomObject]@{
                        TargetPath = Get-MachineCurrentPath -BasePath $tempRoot
                        StagePath = Join-Path $externalTransactionRoot 'Machines_Current.json.gz'
                        BackupPath = Join-Path $externalTransactionRoot 'replace-0-Machines_Current.json.gz.bak'
                        TargetExisted = $false
                    })
                RemovedFiles = @()
            })

        $failure = $null
        try {
            Restore-StoreTransaction -BasePath $tempRoot -StoreName 'machines'
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected invalid transaction journals to be rejected before rollback begins.'
        Assert-True ($failure.Exception.Message -like "*references transaction root*$externalTransactionRoot*outside*") 'Expected invalid transaction journal failures to explain that the transaction root escaped the store base path.'
        Assert-True ((Test-Path -LiteralPath $journalPath -PathType Leaf)) 'Expected invalid transaction journals to remain on disk for manual inspection.'
    }
    finally {
        foreach ($path in @($tempRoot, $externalTransactionRoot)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Test-InitializeMachineHistoryStoreRejectsExpiredLegacyMigration {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('machine-store-expired-legacy-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRemovalDate = $Script:LegacyVulnMigrationRemovalDate

    try {
        Write-NdjsonRecordsFile -Path (Join-Path $tempRoot 'Machines_2026-05-01.json') -Records @(
            (Get-TestMachineRecord -Id 'machine-001')
        )
        $Script:LegacyVulnMigrationRemovalDate = '2000-01-01'

        $failure = $null
        try {
            $null = Initialize-MachineHistoryStore -Path $tempRoot
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected expired machine legacy migration support to fail fast.'
        Assert-True ($failure.Exception.Message -like '*Legacy machine snapshot compatibility support expired on 2000-01-01*') 'Expected machine legacy migration failures to explain the compatibility cutoff date.'
    }
    finally {
        $Script:LegacyVulnMigrationRemovalDate = $originalRemovalDate
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-InitializeAdvancedHuntingStoreRejectsExpiredLegacyMigration {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('advancedhunting-store-expired-legacy-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRemovalDate = $Script:LegacyVulnMigrationRemovalDate

    try {
        Write-NdjsonRecordsFile -Path (Join-Path $tempRoot 'AdvancedHunting_123_2026-05-01.json') -Records @(
            [PSCustomObject]@{
                CveId = 'CVE-2026-0001'
                PublishedDate = '2026-05-01'
                VulnerabilityDescription = 'Expired legacy compatibility test'
                EpssScore = 0.42
                AffectedSoftware = @('Legacy App')
                LastModifiedTime = '2026-05-01T00:00:00Z'
            }
        )
        $Script:LegacyVulnMigrationRemovalDate = '2000-01-01'

        $failure = $null
        try {
            $null = Initialize-AdvancedHuntingStore -Path $tempRoot
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected expired Advanced Hunting legacy migration support to fail fast.'
        Assert-True ($failure.Exception.Message -like '*Legacy Advanced Hunting snapshot compatibility support expired on 2000-01-01*') 'Expected Advanced Hunting legacy migration failures to explain the compatibility cutoff date.'
    }
    finally {
        $Script:LegacyVulnMigrationRemovalDate = $originalRemovalDate
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-PublishVulnerabilityHistoryStoreRejectsExpiredImplicitLegacyMigration {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-store-expired-implicit-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRemovalDate = $Script:LegacyVulnMigrationRemovalDate

    try {
        Write-NdjsonRecordsFile -Path (Join-Path $tempRoot 'VulnExport_1_2026-05-01.json') -Records @(
            (Get-TestVulnRow -Id 'vuln-001' -CveId 'CVE-2026-0001' -SnapshotDate '2026-05-01' -Version '1.0.0')
        )
        $Script:LegacyVulnMigrationRemovalDate = '2000-01-01'

        $failure = $null
        try {
            $null = Publish-VulnerabilityHistoryStore -OutputPath $tempRoot
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected implicit vulnerability legacy migration to be blocked after the cutoff date.'
        Assert-True (($failure.Exception.Message -like '*legacy*') -and ($failure.Exception.Message -like '*2000-01-01*')) ("Expected vulnerability legacy migration failures to explain the compatibility cutoff date. Actual: {0}`nStack: {1}" -f $failure.Exception.Message, $failure.ScriptStackTrace)
    }
    finally {
        $Script:LegacyVulnMigrationRemovalDate = $originalRemovalDate
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-PublishVulnerabilityHistoryStoreAllowsExplicitDownloadedLegacyFilesAfterCutoff {
    [CmdletBinding()]
    param()

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('vuln-store-explicit-download-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)
    $originalRemovalDate = $Script:LegacyVulnMigrationRemovalDate

    try {
        $downloadedFile = Join-Path $tempRoot 'VulnExport_1_2026-05-01.json'
        Write-NdjsonRecordsFile -Path $downloadedFile -Records @(
            (Get-TestVulnRow -Id 'vuln-001' -CveId 'CVE-2026-0001' -SnapshotDate '2026-05-01' -Version '1.0.0')
        )
        $Script:LegacyVulnMigrationRemovalDate = '2000-01-01'

        $result = Publish-VulnerabilityHistoryStore -OutputPath $tempRoot -DownloadedFiles @($downloadedFile)

        Assert-True ($result.CurrentRows -eq 1) 'Expected explicitly downloaded vulnerability snapshots to continue canonicalizing after the legacy cutoff.'
        Assert-True ((Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $tempRoot) -PathType Leaf)) 'Expected the canonical vulnerability current store to be written for explicit downloaded snapshots.'
    }
    finally {
        $Script:LegacyVulnMigrationRemovalDate = $originalRemovalDate
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-GetMdeAccessTokenReportsMissingConfigurationDiagnostic {
    [CmdletBinding()]
    param()

    $failure = $null
    try {
        $null = Get-MdeAccessToken -AppId 'app-001' -AppSecret 'secret-value'
    }
    catch {
        $failure = $_
    }

    Assert-True ($null -ne $failure) 'Expected incomplete MDE credential configuration to fail.'
    Assert-True ($failure.Exception.Message -like '*TenantId is missing*') 'Expected missing-credential diagnostics to identify the specific missing MDE setting.'
    Assert-True ($failure.Exception.Message -like '*Provide -AccessToken or -TenantId/-AppId/-AppSecret*') 'Expected missing-credential diagnostics to preserve the remediation guidance.'
}

function Test-GetMdeAccessTokenReportsAuthenticationContext {
    [CmdletBinding()]
    param()

    Set-Item -Path Function:Invoke-RestMethod -Value {
        throw [System.Exception]::new('invalid_client')
    }

    try {
        $failure = $null
        try {
            $null = Invoke-MdeClientCredentialTokenRequest -TenantId 'tenant-001' -AppId 'app-001' -AppSecretText 'secret-value'
        }
        catch {
            $failure = $_
        }

        Assert-True ($null -ne $failure) 'Expected failed MDE authentication attempts to surface context-rich diagnostics.'
        $message = [string]$failure.Exception.Message
        Assert-True ($message.Contains("tenant 'tenant-001'")) 'Expected authentication failures to include the tenant identifier.'
        Assert-True ($message.Contains("app 'app-001'")) 'Expected authentication failures to include the app identifier.'
        Assert-True ($message.Contains("resource 'https://api.securitycenter.microsoft.com'")) 'Expected authentication failures to include the resource identifier.'
        Assert-True ($message.Contains('invalid_client')) 'Expected authentication failures to preserve the underlying error message.'
    }
    finally {
        Remove-Item -Path Function:Invoke-RestMethod -ErrorAction SilentlyContinue
    }
}

function Test-NewMdeAccessTokenContextRejectsMissingExpirationMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Test function name mirrors the scenario under test.')]
    [CmdletBinding()]
    param()

    $failure = $null
    try {
        $null = New-MdeTokenContext -AccessToken 'token-without-expiry' -CanRefresh $true -RefreshScript { return $null } -SourceDescription 'test context'
    }
    catch {
        $failure = $_
    }

    Assert-True ($null -ne $failure) 'Expected refreshable MDE token contexts to reject missing expiration metadata.'
    Assert-True ($failure.Exception.Message -like "*require expiration metadata*") 'Expected missing-expiration validation to explain why refreshable MDE token contexts cannot be created.'
}

function Test-MdeRequestHeaderRefreshesNearExpiryTokenContext {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Test function name mirrors the scenario under test.')]
    [CmdletBinding()]
    param()

    $script:MockMdeTokenRequestCount = 0
    Set-Item -Path Function:Invoke-RestMethod -Value {
        $script:MockMdeTokenRequestCount++
        if ($script:MockMdeTokenRequestCount -eq 1) {
            return [PSCustomObject]@{
                access_token = 'token-initial'
                expires_in   = 3600
            }
        }

        return [PSCustomObject]@{
            access_token = 'token-refreshed'
            expires_in   = 3600
        }
    }

    try {
        $tokenContext = New-MdeAccessTokenContext -TenantId 'tenant-001' -AppId 'app-001' -AppSecret 'secret-value'
        $headers = Get-MdeHeaderCollection -TokenContext $tokenContext
        Assert-True ($headers.Authorization -eq 'Bearer token-initial') 'Expected the initial MDE header collection to use the original token.'

        $tokenContext.ExpiresOnUtc = [datetime]::UtcNow.AddMinutes(4)
        $resolvedHeaders = Resolve-MdeHeaderCollection -Headers $headers

        Assert-True ($resolvedHeaders.Authorization -eq 'Bearer token-refreshed') 'Expected near-expiry MDE headers to refresh the bearer token before the next request.'
        Assert-True ($script:MockMdeTokenRequestCount -eq 2) 'Expected MDE token refresh to reacquire a token exactly once when the remaining lifetime drops below the refresh window.'
    }
    finally {
        Remove-Item -Path Function:Invoke-RestMethod -ErrorAction SilentlyContinue
        Remove-Variable -Name MockMdeTokenRequestCount -Scope Script -ErrorAction SilentlyContinue
    }
}

function Test-MdeRequestHeaderKeepsExplicitAccessTokenContextStable {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Test function name mirrors the scenario under test.')]
    [CmdletBinding()]
    param()

    $tokenContext = New-MdeAccessTokenContext -AccessToken 'token-explicit'
    $headers = Get-MdeHeaderCollection -TokenContext $tokenContext
    $resolvedHeaders = Resolve-MdeHeaderCollection -Headers $headers

    Assert-True ($tokenContext.CanRefresh -eq $false) 'Expected explicitly supplied access tokens to remain non-refreshable.'
    Assert-True ($resolvedHeaders.Authorization -eq 'Bearer token-explicit') 'Expected explicit MDE access tokens to remain usable without refresh metadata.'
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

function Test-BulkSnapshotFreshImportProfilerParityAndGuards {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Test function name mirrors the scenario under test.')]
    [CmdletBinding()]
    param()

    $harnessPath = Join-Path $PSScriptRoot 'Invoke-LargeImportCoverage.ps1'
    $tokens = $null
    $parseErrors = $null
    $harnessAst = [System.Management.Automation.Language.Parser]::ParseFile($harnessPath, [ref]$tokens, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) 'Expected the import profiler harness to parse.'
    foreach ($name in @('Invoke-LegacySnapshotImportValidation', 'Invoke-Issue67ProfileOperation', 'Get-Issue67StoreDigest',
        'Initialize-Issue67CompiledPartitionReader', 'Test-Issue67CompiledPartitionReaderParity',
        'Read-Issue67ProfilePartitionLines', 'Invoke-ProfiledFreshImport')) {
        $definition = $harnessAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('fresh-import-profile-' + [guid]::NewGuid().ToString('N'))
    $snapshots = Join-Path $tempRoot 'snapshots'
    $reference = Join-Path $tempRoot 'reference'
    [void](New-Item -Path $snapshots, $reference -ItemType Directory -Force)
    $originalOwner = (Get-Command Publish-VulnStoreFromBulkSnapshot).ScriptBlock.ToString()
    $profiledOriginals = @{}
    foreach ($name in @('Publish-VulnStoreFromBulkSnapshot', 'Split-VulnJsonPartition', 'Read-VulnPartitionMapFile',
        'Get-VulnCanonicalRowSignature', 'New-OpenVulnRecord', 'New-ClosedVulnEntry',
        'Add-VulnHistoryEntryToAppendStore', 'Write-VulnPartitionMapFile', 'Write-VulnCurrentFileFromPartition',
        'Test-VulnCurrentFile', 'Write-VulnHistoryDocumentFromAppendFile', 'Write-VulnHistoryRowsFileFromAppendFile',
        'Publish-StoreFilesTransactional', 'Publish-VulnContentStoreUnlocked', 'Initialize-CompiledVulnContentProjector')) {
        $profiledOriginals[$name] = (Get-Command $name).ScriptBlock.ToString()
    }
    try {
        $oldRow = Get-TestVulnRow -Id 'synthetic-old' -CveId 'CVE-2026-0001' -SnapshotDate '2026-01-01' -Version '1.0.0'
        $newRow = Get-TestVulnRow -Id 'synthetic-current' -CveId 'CVE-2026-0002' -SnapshotDate '2026-01-02' -Version '1.0.1'
        Add-Member -InputObject $newRow -NotePropertyName ProfileProbe -NotePropertyValue @{
            amount = [decimal]1.25; text = ('Case' + [char]0x03a9); values = @('UPPER', 'lower', $null); empty = $null
        }
        foreach ($fixture in @(
            @{ path = (Join-Path $snapshots 'VulnExport_1_2026-01-01.json.gz'); row = $oldRow }
            @{ path = (Join-Path $snapshots 'VulnExport_1_2026-01-02.json.gz'); row = $newRow }
            @{ path = (Get-VulnCurrentPath -BasePath $reference); row = $newRow }
        )) {
            $stream = [System.IO.File]::Create($fixture.path)
            $gzip = [System.IO.Compression.GZipStream]::new($stream, [System.IO.Compression.CompressionLevel]::Optimal)
            $writer = [System.IO.StreamWriter]::new($gzip)
            try { $writer.WriteLine(($fixture.row | ConvertTo-Json -Compress -Depth 20)) }
            finally { $writer.Dispose(); $gzip.Dispose(); $stream.Dispose() }
        }
        @{
            modelVersion = 'procedural-v1'; seed = 20260322; targetDeviceCount = 1
            targetTotalVulnRows = 2; contentTemplateCount = 2
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $reference 'synthetic-manifest.json') -Encoding utf8
        @{ snapshotDates = @('2026-01-01', '2026-01-02') } | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $snapshots 'synthetic-legacy-manifest.json') -Encoding utf8
        $validationPath = Join-Path $tempRoot 'profiled'
        $result = Invoke-ProfiledFreshImport -SnapshotSourcePath $snapshots -ValidationPath $validationPath -ReferencePath $reference
        $evidence = Get-Content -LiteralPath (Join-Path $validationPath 'fresh-import-profile.json') -Raw | ConvertFrom-Json -Depth 20
        Assert-True ($result.publishResult.CurrentRows -eq 1 -and $result.publishResult.HistoryYears -eq 1) 'Expected fresh import current and removed-history rows.'
        Assert-True ($evidence.parity -and $evidence.expectedCurrentIds -eq 1 -and $evidence.actualCurrentIds -eq 1) 'Expected full decompressed store parity and authoritative current-ID parity.'
        Assert-True (@($evidence.operations | Where-Object { $_.name -eq 'Json.Parse' -and $_.calls -gt 0 }).Count -eq 1) 'Expected scalar JSON parsing attribution.'
        Assert-True (@($evidence.operations | Where-Object { $_.name -eq 'Content.CompiledProject' -and $_.calls -eq 1 }).Count -eq 1) 'Expected scalar compiled projection attribution.'
        Assert-True ((Get-Command Publish-VulnStoreFromBulkSnapshot).ScriptBlock.ToString() -ceq $originalOwner) 'Expected profiler to restore the production owner after success.'
        foreach ($name in $profiledOriginals.Keys) {
            Assert-True ((Get-Command $name).ScriptBlock.ToString() -ceq $profiledOriginals[$name]) "Expected legacy profiler to restore $name."
        }
        $lineParity = Test-Issue67CompiledPartitionReaderParity
        Assert-True ($lineParity.passed -and $lineParity.cases -eq 16) 'Expected exact legacy line and parse parity for all compiled-reader fixtures.'
        $disposalPath = Join-Path $tempRoot 'disposal.ndjson'
        [IO.File]::WriteAllLines($disposalPath, @('{"Id":"first"}', '{"Id":"second"}'))
        foreach ($compiledReader in @($false, $true)) {
            $script:Issue67UseCompiledReader = $compiledReader
            $script:Issue67Profile = @{}
            $firstLine = @(Read-Issue67ProfilePartitionLines -Path $disposalPath | Select-Object -First 1)
            $exclusive = [IO.File]::Open($disposalPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { Assert-True ($firstLine.Count -eq 1 -and $firstLine[0] -ceq '{"Id":"first"}') "Expected early consumer stop for compiled=$compiledReader." }
            finally { $exclusive.Dispose() }
            $consumerFailure = $null
            try {
                Read-Issue67ProfilePartitionLines -Path $disposalPath | ForEach-Object { throw 'issue67-consumer-failure' }
            }
            catch { $consumerFailure = $_ }
            $exclusive = [IO.File]::Open($disposalPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { Assert-True ($null -ne $consumerFailure -and $consumerFailure.Exception.Message -ceq 'issue67-consumer-failure') "Expected unchanged consumer error for compiled=$compiledReader." }
            finally { $exclusive.Dispose() }
        }
        $compiledPath = Join-Path $tempRoot 'compiled-profiled'
        $compiledResult = Invoke-ProfiledFreshImport -SnapshotSourcePath $snapshots -ValidationPath $compiledPath -ReferencePath $reference -CompiledPartitionReader
        $compiledEvidence = Get-Content -LiteralPath (Join-Path $compiledPath 'fresh-import-profile.json') -Raw | ConvertFrom-Json -Depth 20
        Assert-True ($compiledEvidence.compiledPartitionReader -and $compiledEvidence.parity -and $compiledResult.publishResult.CurrentRows -eq 1) 'Expected opt-in compiled import parity.'
        Assert-True (@($compiledEvidence.operations | Where-Object { $_.name -eq 'Partition.Reader.Compiled' -and $_.calls -gt 0 }).Count -eq 1) 'Expected actual compiled partition reads, not fallback-only evidence.'
        Assert-True (($evidence.storeDigests | ConvertTo-Json -Compress) -ceq ($compiledEvidence.storeDigests | ConvertTo-Json -Compress)) 'Expected baseline/compiled exact decompressed store parity.'
        Assert-True ((Get-Command Publish-VulnStoreFromBulkSnapshot).ScriptBlock.ToString() -ceq $originalOwner) 'Expected compiled profiler to restore the owner after success.'
        foreach ($name in $profiledOriginals.Keys) {
            Assert-True ((Get-Command $name).ScriptBlock.ToString() -ceq $profiledOriginals[$name]) "Expected compiled profiler to restore $name."
        }
        $failure = $null
        try { Invoke-ProfiledFreshImport -SnapshotSourcePath $snapshots -ValidationPath $validationPath -ReferencePath $reference }
        catch { $failure = $_ }
        Assert-True ($null -ne $failure -and $failure.Exception.Message -like '*new validation directory*') 'Expected profiler to reject completed-store replay.'
        $failure = $null
        try { Invoke-ProfiledFreshImport -SnapshotSourcePath $snapshots -ValidationPath (Join-Path $tempRoot 'rejected') -ReferencePath $snapshots }
        catch { $failure = $_ }
        Assert-True ($null -ne $failure -and $failure.Exception.Message -like '*synthetic*manifests*') 'Expected profiler to reject non-procedural sources before import.'
        Assert-True ((Get-Command Publish-VulnStoreFromBulkSnapshot).ScriptBlock.ToString() -ceq $originalOwner) 'Expected rejected profiling to leave production functions unchanged.'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
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

function Test-VulnDeviceProfileProjectionParity {
    [CmdletBinding()]
    param()

    # Independent v1 field contract; RbacGroupId is intentionally unrepresented.
    $fields = @('Id','DeviceId','DeviceName','RbacGroupName','OSPlatform','OSVersion','MachineTags',
        'CveId','SoftwareVendor','SoftwareName','SoftwareVersion','VulnerabilitySeverityLevel','CvssScore',
        'ExploitabilityLevel','RecommendationReference','RecommendedSecurityUpdate','RecommendedSecurityUpdateId',
        'RecommendedSecurityUpdateUrl','SecurityUpdateAvailable','FirstSeenTimestamp','LastSeenTimestamp',
        'DiskPaths','RegistryPaths','CveBatchTitle','CveBatchUrl','IsOnboarded')
    function Get-ExpectedDeviceProjection($Row) {
        $projected = [ordered]@{}
        foreach ($field in $fields) {
            if ($field -eq 'OSVersion') { $projected[$field] = [string]$Row.PSObject.Properties[$field]?.Value }
            else { $projected[$field] = $Row.$field }
        }
        return [PSCustomObject]$projected
    }
    function Assert-DeviceProjectionValue($Expected, $Actual, [string]$At) {
        if ($null -eq $Expected -or $null -eq $Actual) {
            Assert-True ($null -eq $Expected -and $null -eq $Actual) "Null mismatch at $At"; return
        }
        if ($Expected -is [array]) {
            Assert-True ($Actual -is [array] -and $Expected.Count -eq $Actual.Count) "Array mismatch at $At"
            for ($i=0; $i -lt $Expected.Count; $i++) { Assert-DeviceProjectionValue $Expected[$i] $Actual[$i] "$At/$i" }
            return
        }
        if ($Expected -is [PSCustomObject]) {
            Assert-True ($Actual -is [PSCustomObject]) "Object mismatch at $At"
            Assert-True ((@($Expected.PSObject.Properties.Name) -join '|') -ceq (@($Actual.PSObject.Properties.Name) -join '|')) "Fields/order mismatch at $At"
            foreach ($field in $Expected.PSObject.Properties.Name) { Assert-DeviceProjectionValue $Expected.$field $Actual.$field "$At/$field" }
            return
        }
        Assert-True ($Expected.GetType() -eq $Actual.GetType() -and $Expected -ceq $Actual) "Scalar type/value mismatch at $At"
    }

    $rows = @(0..13 | ForEach-Object { Get-TestVulnRow -Id ('profile-{0:D2}' -f $_) -CveId 'CVE-2026-0101' -SnapshotDate '2026-03-20' -Version '1.0' })
    $rows[0].PSObject.Properties.Remove('OSVersion')
    $rows[2].OSVersion = '10.0.different'
    $rows[3].DeviceName = 'DEVICE01.contoso.com'
    $rows[4].RbacGroupName = 'Clients'
    $rows[5].OSPlatform = 'Linux'
    $rows[6].MachineTags = @('left','right')
    $rows[7].MachineTags = @("left$([char]0x1e)right")
    $rows[8].IsOnboarded = $false
    $rows[9].DeviceId = 'DEVICE-001'
    $rows[10].DeviceId = ''; $rows[10].DeviceName = "alpha$([char]0x1f)beta"; $rows[10].RbacGroupName = 'gamma'
    $rows[11].DeviceId = ''; $rows[11].DeviceName = 'alpha'; $rows[11].RbacGroupName = "beta$([char]0x1f)gamma"
    $rows[12].MachineTags = @('right','left')
    $rows[13] | Add-Member -NotePropertyName RbacGroupId -NotePropertyValue 9001
    $history = Get-TestVulnRow -Id 'profile-history' -CveId 'CVE-2026-0102' -SnapshotDate '2026-03-18' -Version '1.0'
    $history.OSVersion = 'history-version'
    $expected = @(@($rows)+@($history) | ForEach-Object { Get-ExpectedDeviceProjection $_ })
    $originalPartitions = $Script:VulnDiskPartitionCount
    $root = Join-Path ([IO.Path]::GetTempPath()) ('device-profile-parity-' + [guid]::NewGuid().ToString('N'))
    try {
        foreach ($mode in @('Compiled','Partitioned')) {
            $base = Join-Path $root $mode
            [void][IO.Directory]::CreateDirectory($base)
            $currentPath = Get-VulnCurrentPath -BasePath $base
            $historyPath = Get-VulnHistoryRowsPath -BasePath $base -PeriodKey '2026Q1'
            Write-NdjsonRecordsFile -Path $currentPath -Records $rows
            Write-NdjsonRecordsFile -Path $historyPath -Records @($history)
            $rawHashes = @((Get-FileHash $currentPath).Hash,(Get-FileHash $historyPath).Hash)
            if ($mode -eq 'Compiled') { Publish-VulnContentStoreUnlocked -BasePath $base }
            else {
                # Force case-distinct signatures into the same bucket.
                $Script:VulnDiskPartitionCount = 1
                Publish-VulnContentStorePartitioned -BasePath $base
            }
            $actual = @(Read-VulnContentStoreRow -BasePath $base)
            Assert-True ($actual.Count -eq $expected.Count) "$mode row count differs"
            for ($i=0; $i -lt $expected.Count; $i++) { Assert-DeviceProjectionValue $expected[$i] $actual[$i] "$mode/$i" }
            Assert-True ($rawHashes[0] -ceq (Get-FileHash $currentPath).Hash -and $rawHashes[1] -ceq (Get-FileHash $historyPath).Hash) "$mode changed raw canonical rows"
            $refs = @(Read-VulnNdjsonLinesFromPath -Path (Get-VulnCurrentRefsPath -BasePath $base) | ForEach-Object { ,($_ | ConvertFrom-Json) })
            $byId = @{}; foreach ($ref in $refs) { $byId[[string]$ref[0]] = $ref }
            Assert-True ($byId['profile-00'][1] -ne $byId['profile-01'][1]) "$mode merged missing and nonempty OSVersion"
            Assert-True ($byId['profile-01'][1] -eq $byId['profile-13'][1]) "$mode failed to reuse identical represented profiles"
        }
        Assert-True ((Get-VulnDeviceProfileSignature $rows[10]) -cne (Get-VulnDeviceProfileSignature $rows[11])) 'Value delimiter collision'
        Assert-True ((Get-VulnDeviceProfileSignature $rows[6]) -cne (Get-VulnDeviceProfileSignature $rows[7])) 'Tag delimiter collision'
        $legacy = Join-Path $PSScriptRoot 'fixtures/legacy-migration'
        $legacyPins = @(Get-ChildItem $legacy -File | Get-FileHash | Select-Object Path,Hash)
        $legacyRaw = @(@(Read-VulnNdjsonLinesFromPath -Path (Get-VulnCurrentPath $legacy)) +
            @(Read-VulnNdjsonLinesFromPath -Path (Get-VulnHistoryRowsPath $legacy '2026Q1')) |
            ForEach-Object { $_ | ConvertFrom-Json })
        $legacyRows = @(Read-VulnContentStoreRow -BasePath $legacy)
        Assert-True ($legacyRaw.Count -eq $legacyRows.Count) 'Legacy dictionary row count changed'
        for ($i=0; $i -lt $legacyRows.Count; $i++) {
            Assert-DeviceProjectionValue (Get-ExpectedDeviceProjection $legacyRaw[$i]) $legacyRows[$i] "legacy/$i"
        }
        Assert-True (($legacyPins | ConvertTo-Json -Compress) -ceq (@(Get-ChildItem $legacy -File | Get-FileHash | Select-Object Path,Hash) | ConvertTo-Json -Compress)) 'Legacy read mutated fixture'
    }
    finally {
        $Script:VulnDiskPartitionCount = $originalPartitions
        if (Test-Path -LiteralPath $root) {
            $fullRoot = [IO.Path]::GetFullPath($root)
            $tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar)
            if ([IO.Path]::GetDirectoryName($fullRoot) -cne $tempParent -or [IO.Path]::GetFileName($fullRoot) -notlike 'device-profile-parity-*') { throw 'Unexpected test cleanup path.' }
            Remove-Item -LiteralPath $fullRoot -Recurse -Force
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
        Assert-True ((Test-VulnContentStoreSupportsDirectMerge -BasePath $tempRoot) -eq $true) 'Expected compact source-order content dictionaries to remain eligible for direct merge.'
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

function Test-PipelineMemorySnapshotActualGcMetric {
    [CmdletBinding()]
    param()

    $sourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'build\azure\runbook-source.ps1'
    $parseErrors = $null
    $sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$null, [ref]$parseErrors)
    Assert-True ($parseErrors.Count -eq 0) 'Expected the diagnostic source to parse.'
    $definition = $sourceAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-PipelineMemorySnapshot' }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
    $originalStage = Get-Variable -Name PipelineCurrentStage -Scope Script -ErrorAction Ignore
    try {
        $Script:PipelineCurrentStage = 'diagnostic-test'
        $before = Get-PipelineMemorySnapshot -Label 'before'
        $allocation = [byte[]]::new(2097152)
        $allocation[0] = 1
        [System.GC]::Collect(2)
        $after = Get-PipelineMemorySnapshot -Label 'after'
        foreach ($field in @('allocatedBytes', 'gen0Collections', 'gen1Collections', 'gen2Collections', 'lastGcIndex', 'lastGcGeneration', 'lastGcHeapSizeBytes', 'lastGcFragmentedBytes', 'lastGcCommittedBytes', 'lastGcLohSizeBeforeBytes', 'lastGcLohSizeAfterBytes', 'lastGcLohFragmentationBeforeBytes', 'lastGcLohFragmentationAfterBytes')) {
            Assert-True ($null -ne $after.$field -and $after.$field -ge 0) "Expected a nonnegative actual GC field: $field."
        }
        Assert-True ($after.allocatedBytes -gt $before.allocatedBytes) 'Expected cumulative allocations to increase.'
        Assert-True ($after.gen2Collections -gt $before.gen2Collections) 'Expected the actual Gen2 collection count to increase.'
        Assert-True ($after.lastGcLohSizeAfterBytes -ge $allocation.Length) 'Expected the last-GC LOH size to include the retained buffer.'
        Assert-True ($after.stage -eq 'diagnostic-test' -and $after.label -eq 'after') 'Expected stage and sample labels to be preserved.'
        Assert-True (($after | ConvertTo-Json -Compress).Length -le 2048) 'Expected a bounded diagnostic snapshot.'
        Assert-True ($after.powershellVersion -eq $PSVersionTable.PSVersion.ToString() -and $after.runtimeVersion -eq [System.Environment]::Version.ToString()) 'Expected actual runtime identity.'
        [System.GC]::KeepAlive($allocation)
    }
    finally {
        if ($null -eq $originalStage) { Remove-Variable -Name PipelineCurrentStage -Scope Script -ErrorAction Ignore }
        else { $Script:PipelineCurrentStage = $originalStage.Value }
    }
}

function Test-VulnPartitionStreamingParity {
    [CmdletBinding()]
    param()
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('partition-streaming-' + [guid]::NewGuid().ToString('N'))
    $originalReader = ${function:Read-VulnNdjsonLinesFromPath}
    $originalIndex = ${function:Get-VulnPartitionIndex}
    $originalProperty = ${function:Get-VulnPropertyValue}
    try {
        [void](New-Item -Path $tempRoot -ItemType Directory -Force)
        $first = Get-TestVulnRow -Id 'synthetic-duplicate' -CveId 'CVE-2026-0001' -SnapshotDate '2026-01-01' -Version '1'
        $last = Get-TestVulnRow -Id 'synthetic-duplicate' -CveId 'CVE-2026-0001' -SnapshotDate '2026-01-02' -Version '2'
        $last.DeviceName = 'long-unicode-' + [char]0x6D4B + [char]0x8BD5 + ('x' * 70000)
        $missingId = Get-TestVulnRow -Id ' ' -CveId 'CVE-2026-0002' -SnapshotDate '2026-01-01' -Version '1'
        $offboarded = Get-TestVulnRow -Id 'synthetic-offboarded' -CveId 'CVE-2026-0003' -SnapshotDate '2026-01-01' -Version '1'
        $offboarded.IsOnboarded = $false
        $lines = @($first, $missingId, $offboarded, $last) | ForEach-Object { $_ | ConvertTo-Json -Depth 20 -Compress }
        foreach ($compressed in @($false, $true)) {
            $path = Join-Path $tempRoot $(if ($compressed) { 'input.ndjson.gz' } else { 'input.ndjson' })
            $text = "`r`n  `n" + ($lines -join "`r`n") # Deliberately no final newline.
            if ($compressed) {
                $file = [IO.File]::Create($path)
                $gzip = [IO.Compression.GZipStream]::new($file, [IO.Compression.CompressionLevel]::Optimal)
                $writer = [IO.StreamWriter]::new($gzip, [Text.UTF8Encoding]::new($false))
                try { $writer.Write($text) } finally { $writer.Dispose() }
            }
            else { [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false)) }
            $state = @{ Calls = 0; CheckInterleaving = $true }
            Set-Item Function:Get-VulnPartitionIndex -Value { param($Id, $PartitionCount) $state.Calls++; & $originalIndex -Id $Id -PartitionCount $PartitionCount }
            Set-Item Function:Get-VulnPropertyValue -Value { param($InputObject, $Name) $state.Calls++; & $originalProperty -InputObject $InputObject -Name $Name }
            Set-Item Function:Read-VulnNdjsonLinesFromPath -Value {
                param($Path)
                $firstLine = $true
                & $originalReader -Path $Path | ForEach-Object {
                    $_
                    if ($firstLine -and $state.CheckInterleaving) {
                        Assert-True ($state.Calls -gt 0) 'Expected the first record to be processed before reading the next line.'
                        $firstLine = $false
                    }
                }
            }
            $outputRoot = Join-Path $tempRoot "parts-$compressed"
            $indexes = @(Split-VulnJsonPartition -InputPaths @($path) -OutputRoot $outputRoot -Prefix 'test' -PartitionCount 4 -OnboardedOnly)
            Assert-True ($indexes.Count -eq 1) 'Expected only onboarded rows with an Id in one partition.'
            $partitionPath = Get-VulnPartitionFilePath -Root $outputRoot -Prefix 'test' -Index $indexes[0]
            $state.CheckInterleaving = $false
            $actualLines = @(Read-VulnNdjsonLinesFromPath -Path $partitionPath)
            Assert-True ($actualLines.Count -eq 2 -and $actualLines[0] -ceq $lines[0] -and $actualLines[1] -ceq $lines[3]) 'Expected exact row text and input ordering.'
            $state.Calls = 0; $state.CheckInterleaving = $true
            $map = Read-VulnPartitionMapFile -Path $path
            Assert-True ($map.Count -eq 2 -and $map['synthetic-duplicate'].Json -ceq $lines[3]) 'Expected duplicate last-wins behavior and offboarded map rows.'
            Assert-True ($map['synthetic-duplicate'].VersionStartDate -eq '2026-01-02') 'Expected last duplicate version date.'
            foreach ($entry in $map.Values) {
                $expectedSignature = Get-VulnCanonicalRowSignature -Row ($entry.Json | ConvertFrom-Json)
                Assert-True ($entry.Signature -ceq $expectedSignature) 'Expected canonical ID signature including the last duplicate casing.'
            }
            $state.CheckInterleaving = $false
            $casePath = Join-Path $tempRoot 'case-map.ndjson'
            $caseJson = $lines[3].Replace('synthetic-duplicate', 'SYNTHETIC-DUPLICATE')
            [IO.File]::WriteAllText($casePath, $lines[0] + "`n" + $caseJson)
            $caseMap = Read-VulnPartitionMapFile -Path $casePath
            Assert-True ($caseMap.Count -eq 1 -and $caseMap['synthetic-duplicate'].Json -ceq $caseJson -and $caseMap['synthetic-duplicate'].Signature -ceq 'SYNTHETIC-DUPLICATE') 'Expected case-insensitive duplicate IDs with exact last-row signature casing.'
            $badPath = Join-Path $tempRoot 'malformed.ndjson'
            [IO.File]::WriteAllText($badPath, $lines[0] + "`n{malformed")
            $failure = $null
            try { Split-VulnJsonPartition -InputPaths @($badPath) -OutputRoot (Join-Path $tempRoot 'bad') -Prefix 'bad' -PartitionCount 4 }
            catch { $failure = $_ }
            Assert-True ($null -ne $failure) 'Expected malformed JSON to fail.'
            # Exclusive opens prove the input and partition writer were disposed on failure.
            foreach ($ownedPath in @($badPath) + @(Get-ChildItem (Join-Path $tempRoot 'bad') -File | Select-Object -ExpandProperty FullName)) {
                $handle = [IO.File]::Open($ownedPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
                $handle.Dispose()
            }
        }
    }
    finally {
        Set-Item Function:Read-VulnNdjsonLinesFromPath -Value $originalReader
        Set-Item Function:Get-VulnPartitionIndex -Value $originalIndex
        Set-Item Function:Get-VulnPropertyValue -Value $originalProperty
        if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
    }
}
