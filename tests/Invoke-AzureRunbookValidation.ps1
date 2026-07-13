#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][string]$SubscriptionId,
    [Parameter(Mandatory = $true)][string]$AutomationAccountName,
    [Parameter(Mandatory = $true)][string]$AutomationResourceGroup,
    [Parameter(Mandatory = $true)][string]$RunbookName,
    [Parameter(Mandatory = $true)][string]$StorageAccountName,
    [Parameter(Mandatory = $true)][string]$DatasetPath,
    [Parameter(Mandatory = $false)][string]$CandidateRunbookPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'azure\Invoke-DashboardPipeline.ps1'),
    [Parameter(Mandatory = $false)][ValidateSet('Exact', 'RawReplay', 'ContentReplay')][string]$SeedMode = 'RawReplay',
    [Parameter(Mandatory = $false)][ValidateSet('SelfContained', 'Hosted', 'Dual')][string]$DashboardDeliveryMode = 'SelfContained',
    [Parameter(Mandatory = $false)][string]$OutputRoot = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\azure-validation'),
    [Parameter(Mandatory = $false)][ValidateRange(5, 120)][int]$PollIntervalSeconds = 15,
    [Parameter(Mandatory = $false)][ValidateRange(0, 50000000)][int]$ExpectedTotalRows = 0,
    [Parameter(Mandatory = $false)][ValidateRange(60, 86400)][int]$StallWarningSeconds = 300,
    [Parameter(Mandatory = $false)][ValidateRange(120, 172800)][int]$StallFailureSeconds = 1800,
    [Parameter(Mandatory = $false)][switch]$UseExistingExportsOnly,
    [Parameter(Mandatory = $false)][switch]$ValidatePublishedSemanticParity,
    [Parameter(Mandatory = $false)][ValidateSet('None', 'AfterBackup', 'AfterDeploy', 'AfterSeed')][string]$FailureInjectionPoint = 'None',
    [Parameter(Mandatory = $false)][switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'helpers\BenchmarkEvidenceTools.ps1')
. (Join-Path $repoRoot 'build\Import-SharedHelpers.ps1')

if (-not $Execute) { throw 'Azure validation is mutation-capable. Re-run with -Execute after reviewing the target parameters.' }
if (-not (Test-Path -LiteralPath $DatasetPath -PathType Container)) { throw "Dataset path '$DatasetPath' was not found." }
if (-not (Test-Path -LiteralPath $CandidateRunbookPath -PathType Leaf)) { throw "Candidate runbook '$CandidateRunbookPath' was not found." }
$manifestPath = Join-Path $DatasetPath 'synthetic-manifest.json'
$resolvedExpectedTotalRows = $ExpectedTotalRows
if ($resolvedExpectedTotalRows -le 0 -and (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    $datasetManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 30
    $resolvedExpectedTotalRows = if ($datasetManifest.PSObject.Properties['actualTotalVulnRows']) { [int]$datasetManifest.actualTotalVulnRows } elseif ($datasetManifest.PSObject.Properties['actualCurrentRows']) { [int]$datasetManifest.actualCurrentRows } else { 0 }
}
if ($resolvedExpectedTotalRows -le 0) { throw 'ExpectedTotalRows is required when the dataset does not provide row-count metadata.' }

function Invoke-AzValidationCli {
    param([Parameter(Mandatory = $true)][string[]]$Arguments, [switch]$Json, [switch]$AllowEmpty)
    if ($Arguments -notcontains '--subscription') { $Arguments = @($Arguments) + @('--subscription', $SubscriptionId) }
    if ($Arguments -notcontains '--only-show-errors') { $Arguments = @($Arguments) + '--only-show-errors' }
    $output = (& az @Arguments 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "az $($Arguments -join ' ') failed:`n$output" }
    if ([string]::IsNullOrWhiteSpace($output)) { if ($AllowEmpty) { return $null }; return '' }
    if ($Json) { return ($output | ConvertFrom-Json -Depth 100) }
    return $output
}

function Get-ValidationFileManifest([string]$Path) {
    return @(
        Get-ChildItem -LiteralPath $Path -File -Recurse | Sort-Object FullName | ForEach-Object {
            [PSCustomObject]@{ path = [System.IO.Path]::GetRelativePath($Path, $_.FullName).Replace('\', '/'); bytes = [int64]$_.Length; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
    )
}

function Save-PublishedRunbookContent([string]$Path) {
    $token = Invoke-AzValidationCli @('account','get-access-token','--resource','https://management.azure.com/','--query','accessToken','--output','tsv')
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$AutomationResourceGroup/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$RunbookName/content?api-version=2023-11-01"
    Invoke-WebRequest -Uri $uri -Headers @{ Authorization = "Bearer $token" } -OutFile $Path -UseBasicParsing
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Get-Item -LiteralPath $Path).Length -eq 0) { throw 'Published runbook content backup was empty.' }
}

function Backup-ValidationContainer([string]$Container, [string]$Path) {
    [void](New-Item -Path $Path -ItemType Directory -Force)
    Invoke-AzValidationCli @('storage','blob','download-batch','--account-name',$StorageAccountName,'--source',$Container,'--destination',$Path,'--auth-mode','login','--only-show-errors') -AllowEmpty | Out-Null
    return @(Get-ValidationFileManifest $Path)
}

function Restore-ValidationContainer([string]$Container, [string]$Path) {
    Invoke-AzValidationCli @('storage','blob','delete-batch','--account-name',$StorageAccountName,'--source',$Container,'--auth-mode','login','--only-show-errors') -AllowEmpty | Out-Null
    if (@(Get-ChildItem -LiteralPath $Path -File -Recurse).Count -gt 0) {
        Invoke-AzValidationCli @('storage','blob','upload-batch','--account-name',$StorageAccountName,'--destination',$Container,'--source',$Path,'--auth-mode','login','--overwrite','true','--only-show-errors') -AllowEmpty | Out-Null
    }
}

function Assert-ValidationManifestMatch($Expected, $Actual, [string]$Label) {
    $expectedJson = @($Expected | Sort-Object path | ForEach-Object { "{0}|{1}|{2}" -f $_.path, $_.bytes, $_.sha256 }) -join "`n"
    $actualJson = @($Actual | Sort-Object path | ForEach-Object { "{0}|{1}|{2}" -f $_.path, $_.bytes, $_.sha256 }) -join "`n"
    if ($expectedJson -ne $actualJson) { throw "Restored $Label content did not match its backup manifest." }
}

$runId = [guid]::NewGuid().ToString('N')
$runRoot = Join-Path ([System.IO.Path]::GetFullPath($OutputRoot)) ((Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $runId.Substring(0, 8))
$backupRoot = Join-Path $runRoot 'backup'
$lockPath = Join-Path $runRoot 'validation-lock.json'
$lockBlobName = '_validation/Invoke-AzureRunbookValidation.lock.json'
$lockAcquired = $false
$backupComplete = $false
$originalRunbookPath = Join-Path $backupRoot 'Invoke-DashboardPipeline.published.ps1'
$resultPath = Join-Path $runRoot 'benchmark-result.json'
[void](New-Item -Path $backupRoot -ItemType Directory -Force)

$lock = [PSCustomObject]@{ run_id = $runId; machine = [Environment]::MachineName; process_id = $PID; acquired_utc = [datetime]::UtcNow.ToString('o') }
[System.IO.File]::WriteAllText($lockPath, ($lock | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))

try {
    $account = Invoke-AzValidationCli @('account','show','--output','json') -Json
    if ([string]$account.id -ne $SubscriptionId) { throw "Azure CLI resolved subscription '$($account.id)', expected '$SubscriptionId'." }
    Invoke-AzValidationCli @('automation','runbook','show','--automation-account-name',$AutomationAccountName,'--resource-group',$AutomationResourceGroup,'--name',$RunbookName,'--output','json') -Json | Out-Null
    Invoke-AzValidationCli @('storage','account','show','--resource-group',$AutomationResourceGroup,'--name',$StorageAccountName,'--output','json') -Json | Out-Null

    Invoke-AzValidationCli @('storage','blob','upload','--account-name',$StorageAccountName,'--container-name','dashboards','--name',$lockBlobName,'--file',$lockPath,'--auth-mode','login','--if-none-match','*','--only-show-errors') -AllowEmpty | Out-Null
    $lockAcquired = $true

    Save-PublishedRunbookContent $originalRunbookPath
    $exportsManifest = Backup-ValidationContainer 'exports' (Join-Path $backupRoot 'exports')
    $dashboardBackupPath = Join-Path $backupRoot 'dashboards'
    $null = Backup-ValidationContainer 'dashboards' $dashboardBackupPath
    $backedUpLockPath = Join-Path $dashboardBackupPath ($lockBlobName.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
    if (Test-Path -LiteralPath $backedUpLockPath -PathType Leaf) { Remove-Item -LiteralPath $backedUpLockPath -Force }
    $dashboardsManifest = @(Get-ValidationFileManifest $dashboardBackupPath)
    $backupManifest = [PSCustomObject]@{ runbook_sha256 = (Get-FileHash $originalRunbookPath -Algorithm SHA256).Hash.ToLowerInvariant(); exports = $exportsManifest; dashboards = $dashboardsManifest }
    Write-BenchmarkEvidenceEnvelope -Path (Join-Path $backupRoot 'backup-manifest.json') -Evidence $backupManifest
    $backupComplete = $true
    if ($FailureInjectionPoint -eq 'AfterBackup') { throw 'Injected Azure validation failure after backup.' }

    if (-not $PSCmdlet.ShouldProcess("$AutomationAccountName/$RunbookName and $StorageAccountName", 'Deploy candidate, seed validation dataset, run benchmark, and restore original state')) { return }

    $candidateArg = '@' + [System.IO.Path]::GetFullPath($CandidateRunbookPath)
    Invoke-AzValidationCli @('automation','runbook','replace-content','--automation-account-name',$AutomationAccountName,'--resource-group',$AutomationResourceGroup,'--name',$RunbookName,'--content',$candidateArg) -AllowEmpty | Out-Null
    Invoke-AzValidationCli @('automation','runbook','publish','--automation-account-name',$AutomationAccountName,'--resource-group',$AutomationResourceGroup,'--name',$RunbookName) -AllowEmpty | Out-Null
    if ($FailureInjectionPoint -eq 'AfterDeploy') { throw 'Injected Azure validation failure after candidate deployment.' }

    Invoke-AzValidationCli @('storage','blob','delete-batch','--account-name',$StorageAccountName,'--source','exports','--auth-mode','login','--only-show-errors') -AllowEmpty | Out-Null
    $seedFiles = @(Get-ChildItem -LiteralPath $DatasetPath -File | Where-Object {
        if ($SeedMode -eq 'Exact') { return $true }
        if ($SeedMode -eq 'ContentReplay') { return $_.Name -in @('VulnContentDictionary.json.gz','VulnCurrentRefs.json.gz','Machines_Current.json.gz','benchmark-dataset.json','synthetic-manifest.json') -or $_.Name -like 'VulnHistoryRefs_*.json.gz' }
        return ($_.Name -in @('AdvancedHunting_Current.json.gz','Machines_Current.json.gz','benchmark-dataset.json','synthetic-manifest.json')) -or ($_.Name -like 'VulnExport_*.json*' -and $_.Name -notlike 'VulnExport_current*')
        })
    if ($seedFiles.Count -eq 0) { throw "Seed mode '$SeedMode' selected no files from '$DatasetPath'." }
    foreach ($file in $seedFiles) {
        $uploadError = $null
        for ($uploadAttempt = 1; $uploadAttempt -le 4; $uploadAttempt++) {
            try {
                Invoke-AzValidationCli @('storage','blob','upload','--account-name',$StorageAccountName,'--container-name','exports','--name',$file.Name,'--file',$file.FullName,'--auth-mode','login','--overwrite','true','--max-connections','4','--timeout','600','--only-show-errors') -AllowEmpty | Out-Null
                $uploadError = $null
                break
            }
            catch {
                $uploadError = $_
                if ($uploadAttempt -lt 4) { Start-Sleep -Seconds ([math]::Pow(2, $uploadAttempt)) }
            }
        }
        if ($null -ne $uploadError) { throw $uploadError }
    }
    $remoteNames = @(Invoke-AzValidationCli @('storage','blob','list','--account-name',$StorageAccountName,'--container-name','exports','--auth-mode','login','--query','[].name','--output','json') -Json)
    if (@($remoteNames).Count -ne $seedFiles.Count) { throw "Seed verification found $(@($remoteNames).Count) remote blobs, expected $($seedFiles.Count)." }
    if ($FailureInjectionPoint -eq 'AfterSeed') { throw 'Injected Azure validation failure after dataset seeding.' }

    & (Join-Path $PSScriptRoot 'Measure-RunbookOnlyAzureBenchmark.ps1') `
        -SubscriptionId $SubscriptionId -RepoPath $repoRoot -AutomationAccountName $AutomationAccountName -AutomationResourceGroup $AutomationResourceGroup `
        -RunbookName $RunbookName -StorageAccountName $StorageAccountName -UseExistingExportsOnly:$UseExistingExportsOnly `
        -DashboardDeliveryMode $DashboardDeliveryMode `
        -ExpectedTotalRows $resolvedExpectedTotalRows `
        -PollIntervalSeconds $PollIntervalSeconds -StallWarningSeconds $StallWarningSeconds -StallFailureSeconds $StallFailureSeconds `
        -SkipDeployRunbook -SkipTemplateUpload -ResultsOutputPath $resultPath

    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) { throw 'Azure benchmark completed without publishing its evidence record.' }
    $candidateDashboardPath = Join-Path $runRoot 'candidate-dashboards'
    $null = Backup-ValidationContainer 'dashboards' $candidateDashboardPath
    $benchmarkResult = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json -Depth 100
    $candidateValidation = Assert-AzureDashboardCandidateEvidence `
        -DashboardRootPath $candidateDashboardPath `
        -RunbookStatus $benchmarkResult.runbook_status `
        -DashboardDeliveryMode $DashboardDeliveryMode `
        -ExpectedTotalRows $resolvedExpectedTotalRows `
        -PayloadRowCounter { param($Path) Get-CompressedPayloadVulnCount -Path $Path }
    $benchmarkResult | Add-Member -NotePropertyName candidate_artifact_validation -NotePropertyValue $candidateValidation -Force
    if ($null -ne $benchmarkResult.benchmark_evidence -and $null -ne $benchmarkResult.benchmark_evidence.validation) {
        $benchmarkResult.benchmark_evidence.validation | Add-Member -NotePropertyName candidate_artifacts -NotePropertyValue $candidateValidation -Force
    }
    if ($ValidatePublishedSemanticParity) {
        $normalizationPlan = Get-NormalizationExecutionPlan -Path ([System.IO.Path]::GetFullPath($DatasetPath)) -DeliveryMode $DashboardDeliveryMode
        if ($DashboardDeliveryMode -in @('Hosted', 'Dual')) {
            $semanticStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $referencePayloadPath = Join-Path $runRoot 'source-reference-payload.json.gz'
            $referenceMachines = @{}
            $referenceAdvancedHuntingData = @{}
            $referenceDeviceUsers = @{}
            $referenceInventoryData = @{}
            $referenceNvdData = @{}
            try {
                if ($normalizationPlan.ContentNormalizationMode -ne 'compiled-bounded-standard-payload') {
                    $referenceMachines = Read-NormalizationMachineLookup -Path ([System.IO.Path]::GetFullPath($DatasetPath)) -FileBacked -Bucketed
                    $referenceAdvancedHuntingBundle = Read-AdvancedHuntingBundle -Path ([System.IO.Path]::GetFullPath($DatasetPath)) -IncludeDeviceUsers -IncludeInventoryData
                    $referenceAdvancedHuntingData = [hashtable]$referenceAdvancedHuntingBundle.AdvancedHuntingData
                    $referenceDeviceUsers = [hashtable]$referenceAdvancedHuntingBundle.DeviceUsers
                    $referenceInventoryData = [hashtable]$referenceAdvancedHuntingBundle.InventoryData
                    $referenceNvdData = Read-NvdCveData -Path ([System.IO.Path]::GetFullPath($DatasetPath))
                    $referenceAdvancedHuntingBundle = $null
                }
                $referenceResult = ConvertTo-NormalizedData `
                    -DataPath ([System.IO.Path]::GetFullPath($DatasetPath)) `
                    -VulnOutputPath (Join-Path $runRoot 'source-reference-vulns.json') `
                    -PayloadOutputPath $referencePayloadPath `
                    -Machines $referenceMachines -AdvancedHuntingData $referenceAdvancedHuntingData -AdvancedHuntingDeviceUsers $referenceDeviceUsers -AdvancedHuntingInventoryData $referenceInventoryData -NvdCveData $referenceNvdData `
                    -SkipObservedWindowMerge:([bool](Test-Path -LiteralPath (Join-Path $DatasetPath 'synthetic-manifest.json') -PathType Leaf)) -ConsumeLookupsOnPayloadClose
            }
            finally {
                if (Test-FileBackedNormalizationMachineLookup -Machines $referenceMachines) { Remove-FileBackedNormalizationMachineLookup -Machines $referenceMachines }
            }
            if ([int64]$referenceResult.VulnCount -ne $resolvedExpectedTotalRows) { throw 'Fresh source-reference projection row count does not match the expected Azure workload.' }
            $hostedAssetDirectory = [System.IO.Path]::GetFileNameWithoutExtension([string]$candidateValidation.hosted_blob_name) + '.assets'
            $publishedPayloadPath = Join-Path $candidateDashboardPath (Join-Path $hostedAssetDirectory 'data\payload.json.gz')
            $referenceContent = Get-GzipDecompressedContentEvidence -Path $referencePayloadPath
            $publishedContent = Get-GzipDecompressedContentEvidence -Path $publishedPayloadPath
            $expandedComparison = $null
            if ($referenceContent.decompressed_bytes -ne $publishedContent.decompressed_bytes -or $referenceContent.decompressed_sha256 -ne $publishedContent.decompressed_sha256) {
                if ($normalizationPlan.ContentNormalizationMode -eq 'compiled-bounded-standard-payload') {
                    throw ("Published compiled payload does not exactly match the fresh source-reference JSON. Reference={0}; published={1}." -f ($referenceContent | ConvertTo-Json -Compress), ($publishedContent | ConvertTo-Json -Compress))
                }
                # Lookup insertion order can legitimately differ when enrichment maps are materialized in
                # separate processes. Expand the modest compatibility workload and compare canonical rows;
                # high-cardinality compiled workloads retain the bounded byte-exact path above.
                . (Join-Path $repoRoot 'build\generated\validation-helpers.ps1')
                $referenceRows = Read-DashboardRow -Payload (Read-CompressedPayloadObject -Path $referencePayloadPath)
                $publishedRows = Read-DashboardRow -Payload (Read-CompressedPayloadObject -Path $publishedPayloadPath)
                $expandedComparison = Compare-RowSet -ExpectedRows $referenceRows -ActualRows $publishedRows
                if ($expandedComparison.Match -ne $true) {
                    throw ("Published payload does not semantically match the fresh normalized source reference: {0}" -f ($expandedComparison | ConvertTo-Json -Compress -Depth 20))
                }
            }
            $semanticStopwatch.Stop()
            $semanticEvidence = [PSCustomObject]@{
                audit_mode = if ($normalizationPlan.ContentNormalizationMode -eq 'compiled-bounded-standard-payload') { 'fresh-compiled-source-reference' } else { 'fresh-normalized-source-reference' }
                source_rows = [int64]$referenceResult.VulnCount
                dashboard_rows = [int64]$resolvedExpectedTotalRows
                missing_rows = 0
                extra_rows = 0
                comparison_storage = if ($null -eq $expandedComparison) { 'streaming-decompressed-sha256' } else { 'bounded-compatibility-row-map' }
                verification_mode = if ($null -eq $expandedComparison) { 'exact-standard-payload-json' } else { 'canonical-expanded-row-equivalence' }
                decompressed_bytes = [int64]$referenceContent.decompressed_bytes
                decompressed_sha256 = [string]$referenceContent.decompressed_sha256
                elapsed_seconds = [math]::Round($semanticStopwatch.Elapsed.TotalSeconds, 2)
            }
        }
        else {
            $semanticDashboardPath = if ($DashboardDeliveryMode -eq 'SelfContained') { Join-Path $candidateDashboardPath ([string]$candidateValidation.dashboard_blob_name) } else { Join-Path $candidateDashboardPath ([string]$candidateValidation.hosted_blob_name) }
            $semanticAuditPath = Join-Path $runRoot 'candidate-semantic-audit.json'
            & (Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1') -DirectoryPath ([System.IO.Path]::GetFullPath($DatasetPath)) -OutputPath $semanticDashboardPath -ValidateOnly -ForceFullValidation -ValidationOutputPath $semanticAuditPath
            if (-not (Test-Path -LiteralPath $semanticAuditPath -PathType Leaf)) { throw 'Published dashboard semantic validation did not produce an audit record.' }
            $semanticAudit = Get-Content -LiteralPath $semanticAuditPath -Raw | ConvertFrom-Json -Depth 100
            if ($semanticAudit.RowComparison.Match -ne $true -or [int64]$semanticAudit.RowComparison.MissingCount -ne 0 -or [int64]$semanticAudit.RowComparison.ExtraCount -ne 0) { throw ("Published dashboard semantic comparison failed: {0}" -f ($semanticAudit.RowComparison | ConvertTo-Json -Compress -Depth 20)) }
            $semanticEvidence = [PSCustomObject]@{
                audit_mode = [string]$semanticAudit.AuditMode; source_rows = [int64]$semanticAudit.RowComparison.ExpectedRows; dashboard_rows = [int64]$semanticAudit.RowComparison.ActualRows
                missing_rows = [int64]$semanticAudit.RowComparison.MissingCount; extra_rows = [int64]$semanticAudit.RowComparison.ExtraCount; comparison_storage = [string]$semanticAudit.RowComparison.ComparisonStorage
                verification_mode = [string]$semanticAudit.RowComparison.VerificationMode; elapsed_seconds = [double]$semanticAudit.PhaseTimings.TotalElapsedSeconds
                audit_sha256 = (Get-FileHash -LiteralPath $semanticAuditPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
        $benchmarkResult | Add-Member -NotePropertyName candidate_semantic_validation -NotePropertyValue $semanticEvidence -Force
        if ($null -ne $benchmarkResult.benchmark_evidence -and $null -ne $benchmarkResult.benchmark_evidence.validation) {
            $benchmarkResult.benchmark_evidence.validation | Add-Member -NotePropertyName semantic_parity -NotePropertyValue $semanticEvidence -Force
        }
    }
    Write-BenchmarkEvidenceEnvelope -Path $resultPath -Evidence $benchmarkResult
}
finally {
    if ($lockAcquired) {
        Invoke-AzValidationCli @('storage','blob','delete','--account-name',$StorageAccountName,'--container-name','dashboards','--name',$lockBlobName,'--auth-mode','login','--only-show-errors') -AllowEmpty | Out-Null
        $lockAcquired = $false
    }
    if ($backupComplete) {
        Restore-ValidationContainer 'exports' (Join-Path $backupRoot 'exports')
        Restore-ValidationContainer 'dashboards' (Join-Path $backupRoot 'dashboards')
        $originalArg = '@' + $originalRunbookPath
        Invoke-AzValidationCli @('automation','runbook','replace-content','--automation-account-name',$AutomationAccountName,'--resource-group',$AutomationResourceGroup,'--name',$RunbookName,'--content',$originalArg) -AllowEmpty | Out-Null
        Invoke-AzValidationCli @('automation','runbook','publish','--automation-account-name',$AutomationAccountName,'--resource-group',$AutomationResourceGroup,'--name',$RunbookName) -AllowEmpty | Out-Null
        $verifyRoot = Join-Path $runRoot 'restoration-verification'
        $restoredExports = Backup-ValidationContainer 'exports' (Join-Path $verifyRoot 'exports')
        $restoredDashboards = Backup-ValidationContainer 'dashboards' (Join-Path $verifyRoot 'dashboards')
        Assert-ValidationManifestMatch $exportsManifest $restoredExports 'exports'
        Assert-ValidationManifestMatch $dashboardsManifest $restoredDashboards 'dashboards'
        $restoredRunbookPath = Join-Path $verifyRoot 'Invoke-DashboardPipeline.published.ps1'
        Save-PublishedRunbookContent $restoredRunbookPath
        if ((Get-FileHash $restoredRunbookPath -Algorithm SHA256).Hash -ne (Get-FileHash $originalRunbookPath -Algorithm SHA256).Hash) { throw 'Restored published runbook did not match its backup hash.' }
    }
}

Write-Output "Azure validation completed and original state restored. Results: $resultPath"
