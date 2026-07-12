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
    [Parameter(Mandatory = $false)][ValidateSet('None', 'AfterBackup', 'AfterDeploy', 'AfterSeed')][string]$FailureInjectionPoint = 'None',
    [Parameter(Mandatory = $false)][switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot 'helpers\BenchmarkEvidenceTools.ps1')

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
