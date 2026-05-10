#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$RepoPath = (Split-Path -Path $PSScriptRoot -Parent),

    [Parameter(Mandatory = $false)]
    [string]$AutomationAccountName = 'aa-defender-reporting',

    [Parameter(Mandatory = $false)]
    [string]$AutomationResourceGroup = 'rg-defender-reporting',

    [Parameter(Mandatory = $false)]
    [string]$RunbookName = 'Invoke-DashboardPipeline',

    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName = 'stdefenderrepaad73',

    [Parameter(Mandatory = $false)]
    [ValidateSet('SelfContained', 'Hosted', 'Dual')]
    [string]$DashboardDeliveryMode = 'SelfContained',

    [Parameter(Mandatory = $false)]
    [switch]$UseExistingExportsOnly,

    [Parameter(Mandatory = $false)]
    [switch]$UseDirectMergeDeviceLookup,

    [Parameter(Mandatory = $false)]
    [int]$ExpectedTotalRows = 1500000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 120)]
    [int]$PollIntervalSeconds = 15,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDeployRunbook,

    [Parameter(Mandatory = $false)]
    [switch]$SkipTemplateUpload,

    [Parameter(Mandatory = $false)]
    [string]$ResultsOutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-azure-validation\runbook-only-current-ahbundle.result.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:AutomationAccountName = $AutomationAccountName
$script:AutomationResourceGroup = $AutomationResourceGroup
$script:RunbookName = $RunbookName
$script:StorageAccountName = $StorageAccountName
$script:DashboardDeliveryMode = $DashboardDeliveryMode
$script:UseExistingExportsOnly = if ($PSBoundParameters.ContainsKey('UseExistingExportsOnly')) { [bool]$UseExistingExportsOnly } else { $true }
$script:UseDirectMergeDeviceLookup = if ($PSBoundParameters.ContainsKey('UseDirectMergeDeviceLookup')) { [bool]$UseDirectMergeDeviceLookup } else { $false }
$script:ExpectedTotalRows = $ExpectedTotalRows
$script:PollIntervalSeconds = $PollIntervalSeconds
. (Join-Path $PSScriptRoot 'helpers\TestScriptSupport.ps1')

function Invoke-AzCli {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $false)]
        [switch]$ExpectJson,

        [Parameter(Mandatory = $false)]
        [switch]$AllowEmpty
    )

    $output = (& az @Arguments 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw ("az {0}`n{1}" -f ($Arguments -join ' '), $output.Trim())
    }

    $trimmed = $output.Trim()
    if (-not $ExpectJson) {
        return $trimmed
    }

    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        if ($AllowEmpty) {
            return $null
        }

        throw ("Expected JSON output from az {0}, but command returned nothing." -f ($Arguments -join ' '))
    }

    $jsonLines = @($trimmed -split "`r?`n")
    $jsonStartIndex = -1
    for ($index = 0; $index -lt $jsonLines.Count; $index++) {
        if ($jsonLines[$index] -match '^\s*[\[{]') {
            $jsonStartIndex = $index
            break
        }
    }

    if ($jsonStartIndex -ge 0) {
        $trimmed = (($jsonLines[$jsonStartIndex..($jsonLines.Count - 1)]) -join "`n").Trim()
    }

    return ($trimmed | ConvertFrom-Json -Depth 100)
}

function Get-RunbookExecutionStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) ('runbook-status-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        Invoke-AzCli -Arguments @(
            'storage', 'blob', 'download',
            '--account-name', $StorageAccountName,
            '--container-name', 'dashboards',
            '--name', '_diagnostics/ExportAndGenerate.status.json',
            '--file', $tempPath,
            '--overwrite', 'true',
            '--auth-mode', 'login',
            '-o', 'json'
        ) -ExpectJson -AllowEmpty | Out-Null

        if (-not (Test-Path -LiteralPath $tempPath -PathType Leaf)) {
            return $null
        }

        $content = Get-Content -LiteralPath $tempPath -Raw
        if ([string]::IsNullOrWhiteSpace($content)) {
            return $null
        }

        return ($content | ConvertFrom-Json -Depth 100)
    }
    catch {
        Write-Verbose ("Unable to download runbook status blob: {0}" -f $_.Exception.Message)
        return $null
    }
    finally {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-RepoScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string]$RelativeScriptPath,

        [Parameter(Mandatory = $false)]
        [hashtable]$Arguments = @{}
    )

    $scriptPath = Join-Path -Path $RepoPath -ChildPath $RelativeScriptPath
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Script not found: $scriptPath"
    }

    Push-Location $RepoPath
    try {
        & $scriptPath @Arguments | Out-Host
    }
    finally {
        Pop-Location
    }
}

function Build-AndDeploy-Runbook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath
    )

    Invoke-RepoScript -RepoPath $RepoPath -RelativeScriptPath 'build/azure/Build-Runbook.ps1'

    $artifactPath = Join-Path -Path $RepoPath -ChildPath 'azure/Invoke-DashboardPipeline.ps1'
    Invoke-AzCli -Arguments @(
        'automation', 'runbook', 'replace-content',
        '--automation-account-name', $script:AutomationAccountName,
        '--resource-group', $script:AutomationResourceGroup,
        '--name', $script:RunbookName,
        '--content', ("@{0}" -f $artifactPath)
    ) | Out-Null
    Invoke-AzCli -Arguments @(
        'automation', 'runbook', 'publish',
        '--automation-account-name', $script:AutomationAccountName,
        '--resource-group', $script:AutomationResourceGroup,
        '--name', $script:RunbookName
    ) | Out-Null
}

function Publish-RunbookTemplateBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    Invoke-RepoScript -RepoPath $RepoPath -RelativeScriptPath 'azure/Upload-Templates.ps1' -Arguments @{ StorageAccountName = $StorageAccountName }
}

function Start-RunbookBenchmark {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param()

    if (-not $PSCmdlet.ShouldProcess(("{0}/{1}" -f $script:AutomationAccountName, $script:RunbookName), 'Start Azure Automation runbook benchmark job')) {
        return $null
    }

    $parameterPairs = @("DashboardDeliveryMode=$script:DashboardDeliveryMode")
    if ($script:UseExistingExportsOnly) {
        $parameterPairs += 'UseExistingExportsOnly=true'
    }
    if ($script:UseDirectMergeDeviceLookup) {
        $parameterPairs += 'UseDirectMergeDeviceLookup=true'
    }

    $arguments = @(
        'automation', 'runbook', 'start',
        '--automation-account-name', $script:AutomationAccountName,
        '--resource-group', $script:AutomationResourceGroup,
        '--name', $script:RunbookName,
        '--parameters'
    )
    $arguments += $parameterPairs
    $arguments += @('-o', 'json')

    $job = Invoke-AzCli -Arguments $arguments -ExpectJson

    $creationTimeUtc = ConvertTo-UtcDateTime -Value $job.creationTime
    if ($null -eq $creationTimeUtc) {
        throw ("Azure Automation job '{0}' did not return a usable creationTime value." -f [string]$job.name)
    }

    return [PSCustomObject]@{
        name = [string]$job.name
        jobId = [string]$job.jobId
        status = [string]$job.status
        creationTimeUtc = $creationTimeUtc
    }
}

function Get-RunbookJobStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JobName
    )

    return (Invoke-AzCli -Arguments @(
        'automation', 'job', 'show',
        '--automation-account-name', $script:AutomationAccountName,
        '--resource-group', $script:AutomationResourceGroup,
        '--name', $JobName,
        '-o', 'json'
    ) -ExpectJson)
}

function Get-RunbookEventList {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JobName,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [datetime]$NotBeforeUtc
    )

    $uri = "/subscriptions/$SubscriptionId/resourceGroups/$script:AutomationResourceGroup/providers/Microsoft.Automation/automationAccounts/$script:AutomationAccountName/jobs/$JobName/streams?api-version=2019-06-01"
    $payload = Invoke-AzCli -Arguments @('rest', '--method', 'get', '--url', $uri, '-o', 'json') -ExpectJson
    $events = [System.Collections.Generic.List[object]]::new()

    foreach ($item in @($payload.value)) {
        $summary = [string]$item.properties.summary
        if ([string]::IsNullOrWhiteSpace($summary)) {
            continue
        }

        $timestamp = ([datetimeoffset]$item.properties.time).UtcDateTime
        if ($timestamp -lt $NotBeforeUtc.AddSeconds(-5)) {
            continue
        }

        $events.Add([PSCustomObject]@{
            timestamp_utc = $timestamp
            message = $summary
        }) | Out-Null
    }

    return @($events | Sort-Object -Property timestamp_utc, message -Unique)
}

function Get-PipelineEventSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events,

        [Parameter(Mandatory = $true)]
        [double]$TotalElapsedSeconds,

        [Parameter(Mandatory = $false)]
        [int]$TotalRows = 0,

        [Parameter(Mandatory = $false)]
        [string]$TerminalStatus = 'Completed'
    )

    $orderedEvents = @($Events | Sort-Object -Property timestamp_utc, message)
    $stageInfo = [ordered]@{}
    $peakWorkingSetMb = 0.0
    $peakGcHeapMb = 0.0
    $devices = 0
    $cves = 0
    $dashboardSizeMb = 0.0
    $usedCachedPayload = $false
    $skippedFreshExport = $false
    $sawFailure = $false

    foreach ($entry in $orderedEvents) {
        $message = [string]$entry.message
        if ($message -match '^\s*--- Stage (?<letter>[A-Z]): (?<name>.+) ---$') {
            $stageInfo[$matches.letter] = [PSCustomObject]@{
                letter = $matches.letter
                name = $matches.name
                started_utc = $entry.timestamp_utc
            }
            continue
        }

        if ($message -match 'Memory .*?Working set: (?<working>[0-9.]+)MB\s+\|\s+GC heap: (?<heap>[0-9.]+)MB') {
            $working = [double]$matches.working
            $heap = [double]$matches.heap
            if ($working -gt $peakWorkingSetMb) {
                $peakWorkingSetMb = $working
            }
            if ($heap -gt $peakGcHeapMb) {
                $peakGcHeapMb = $heap
            }
            continue
        }

        if ($message -match '^\s*Devices:\s*(?<count>\d+)') {
            $devices = [int]$matches.count
            continue
        }

        if ($message -match '^\s*CVEs:\s*(?<count>\d+)') {
            $cves = [int]$matches.count
            continue
        }

        if ($message -match '^\s*Dashboard size:\s*(?<size>[0-9.]+)MB') {
            $dashboardSizeMb = [double]$matches.size
            continue
        }

        if ($message -match 'Reusing cached normalized payload') {
            $usedCachedPayload = $true
            continue
        }

        if ($message -match 'Skipping fresh MDE export') {
            $skippedFreshExport = $true
            continue
        }

        if ($message -match 'Pipeline Failed!') {
            $sawFailure = $true
        }
    }

    $stageDurations = [ordered]@{}
    $stageKeys = @($stageInfo.Keys | Sort-Object)
    for ($index = 0; $index -lt $stageKeys.Count; $index++) {
        $currentKey = $stageKeys[$index]
        $currentStage = $stageInfo[$currentKey]
        $nextStage = if ($index + 1 -lt $stageKeys.Count) { $stageInfo[$stageKeys[$index + 1]] } else { $null }
        $endTime = if ($null -ne $nextStage) {
            $nextStage.started_utc
        }
        elseif ($orderedEvents.Count -gt 0) {
            $orderedEvents[-1].timestamp_utc
        }
        else {
            $currentStage.started_utc
        }

        $stageDurations[$currentStage.name] = [math]::Round((New-TimeSpan -Start $currentStage.started_utc -End $endTime).TotalSeconds, 2)
    }

    return [PSCustomObject]@{
        status = if ($sawFailure -or $TerminalStatus -eq 'Failed') { 'Failed' } else { $TerminalStatus }
        elapsed_seconds = [math]::Round($TotalElapsedSeconds, 2)
        stage_elapsed_seconds = $stageDurations
        peak_working_set_mb = [math]::Round($peakWorkingSetMb, 1)
        peak_gc_heap_mb = [math]::Round($peakGcHeapMb, 1)
        rows_per_second = if ($TotalElapsedSeconds -gt 0 -and $TotalRows -gt 0) { [math]::Round(($TotalRows / $TotalElapsedSeconds), 0) } else { 0 }
        devices = $devices
        cves = $cves
        dashboard_mb = $dashboardSizeMb
        used_cached_payload = $usedCachedPayload
        skipped_fresh_export = $skippedFreshExport
    }
}

$repoFullPath = [System.IO.Path]::GetFullPath($RepoPath)
$resultsFullPath = [System.IO.Path]::GetFullPath($ResultsOutputPath)
$resultsDirectory = Split-Path -Path $resultsFullPath -Parent
if (-not [string]::IsNullOrWhiteSpace($resultsDirectory)) {
    [void](New-Item -Path $resultsDirectory -ItemType Directory -Force)
}

$subscription = Invoke-AzCli -Arguments @('account', 'show', '-o', 'json') -ExpectJson

if (-not $SkipDeployRunbook) {
    Write-Host 'Deploying updated runbook artifact...' -ForegroundColor Yellow
    Build-AndDeploy-Runbook -RepoPath $repoFullPath
}

if (-not $SkipTemplateUpload) {
    Write-Host 'Uploading templates for the runbook benchmark...' -ForegroundColor Yellow
    Publish-RunbookTemplateBundle -RepoPath $repoFullPath -StorageAccountName $script:StorageAccountName
}

$runbookState = Start-RunbookBenchmark
if ($null -eq $runbookState) {
    throw 'Runbook benchmark start was skipped before a job was created.'
}

Write-Host ("Started runbook job {0}" -f $runbookState.name) -ForegroundColor Yellow

$runbookJob = $null
do {
    Start-Sleep -Seconds $script:PollIntervalSeconds
    $runbookJob = Get-RunbookJobStatus -JobName $runbookState.name
    Write-Host ("Runbook status: {0}" -f [string]$runbookJob.status) -ForegroundColor DarkGray
}
while ($runbookJob.status -notin @('Completed', 'Failed', 'Stopped', 'Suspended'))

$runbookEvents = @(Get-RunbookEventList -JobName $runbookState.name -SubscriptionId ([string]$subscription.id) -NotBeforeUtc $runbookState.creationTimeUtc)
$runbookCompletedUtc = ConvertTo-UtcDateTime -Value $runbookJob.lastModifiedTime
if ($null -eq $runbookCompletedUtc) {
    $runbookCompletedUtc = ConvertTo-UtcDateTime -Value $runbookJob.endTime
}
if ($null -eq $runbookCompletedUtc) {
    $runbookCompletedUtc = ConvertTo-UtcDateTime -Value $runbookJob.lastStatusModifiedTime
}
if ($null -eq $runbookCompletedUtc) {
    throw ("Azure Automation job '{0}' did not return a usable completion timestamp." -f [string]$runbookState.name)
}

$elapsedSeconds = [math]::Round((New-TimeSpan -Start $runbookState.creationTimeUtc -End $runbookCompletedUtc).TotalSeconds, 2)
$runbookSummary = Get-PipelineEventSummary -Events $runbookEvents -TotalElapsedSeconds $elapsedSeconds -TotalRows $script:ExpectedTotalRows -TerminalStatus ([string]$runbookJob.status)
$runbookStatus = Get-RunbookExecutionStatus -StorageAccountName $script:StorageAccountName
$runbookStatusSummary = $null
if ($null -ne $runbookStatus -and $runbookStatus.PSObject.Properties['memoryPeaks'] -and $null -ne $runbookStatus.memoryPeaks) {
    $runbookStatusSummary = [ordered]@{
        peak_working_set_mb = [math]::Round([double]$runbookStatus.memoryPeaks.peakWorkingSetMb, 1)
        peak_working_set_stage = [string]$runbookStatus.memoryPeaks.peakWorkingSetStage
        peak_private_memory_mb = [math]::Round([double]$runbookStatus.memoryPeaks.peakPrivateMemoryMb, 1)
        peak_private_memory_stage = [string]$runbookStatus.memoryPeaks.peakPrivateMemoryStage
        peak_gc_heap_mb = [math]::Round([double]$runbookStatus.memoryPeaks.peakGcHeapMb, 1)
        peak_gc_heap_stage = [string]$runbookStatus.memoryPeaks.peakGcHeapStage
    }
}

$repoCommit = Invoke-GitText -RepoPath $repoFullPath -Arguments @('rev-parse', 'HEAD')
if ([string]::IsNullOrWhiteSpace($repoCommit)) {
    $repoCommit = '<unknown>'
}

$repoBranch = Invoke-GitText -RepoPath $repoFullPath -Arguments @('branch', '--show-current')
if ([string]::IsNullOrWhiteSpace($repoBranch)) {
    $repoBranch = '<detached>'
}

$result = [ordered]@{
    generated_utc = (Get-Date).ToUniversalTime().ToString('o')
    repo = [ordered]@{
        path = $repoFullPath
        branch = $repoBranch
        commit = $repoCommit
    }
    subscription = [ordered]@{
        id = [string]$subscription.id
        name = [string]$subscription.name
        tenantId = [string]$subscription.tenantId
    }
    runbook = $runbookSummary
    runbook_job = [ordered]@{
        name = [string]$runbookState.name
        jobId = [string]$runbookState.jobId
        created_utc = $runbookState.creationTimeUtc.ToString('o')
        completed_utc = $runbookCompletedUtc.ToString('o')
        terminal_status = [string]$runbookJob.status
    }
    parameters = [ordered]@{
        dashboard_delivery_mode = $script:DashboardDeliveryMode
        use_existing_exports_only = $script:UseExistingExportsOnly
        use_direct_merge_device_lookup = $script:UseDirectMergeDeviceLookup
        expected_total_rows = $script:ExpectedTotalRows
    }
    runbook_events = @($runbookEvents)
    runbook_status = $runbookStatus
    runbook_status_summary = $runbookStatusSummary
}

[System.IO.File]::WriteAllText($resultsFullPath, ($result | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))

Write-Host ''
if ($null -ne $runbookStatusSummary) {
    Write-Host ("Runbook status-blob peak working set: {0}MB ({1})" -f $runbookStatusSummary.peak_working_set_mb, $runbookStatusSummary.peak_working_set_stage) -ForegroundColor Green
    Write-Host ("Runbook status-blob peak private memory: {0}MB ({1})" -f $runbookStatusSummary.peak_private_memory_mb, $runbookStatusSummary.peak_private_memory_stage) -ForegroundColor Green
    Write-Host ("Runbook status-blob peak GC heap: {0}MB ({1})" -f $runbookStatusSummary.peak_gc_heap_mb, $runbookStatusSummary.peak_gc_heap_stage) -ForegroundColor Green
}
else {
    Write-Host ("Runbook peak working set: {0}MB" -f $runbookSummary.peak_working_set_mb) -ForegroundColor Green
    Write-Host ("Runbook peak GC heap: {0}MB" -f $runbookSummary.peak_gc_heap_mb) -ForegroundColor Green
}
Write-Host ("Runbook elapsed: {0}s" -f $runbookSummary.elapsed_seconds) -ForegroundColor Green
Write-Host ("Results written to {0}" -f $resultsFullPath) -ForegroundColor Green
