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
    [switch]$UseExistingExportsOnly = $true,

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
        '--automation-account-name', $AutomationAccountName,
        '--resource-group', $AutomationResourceGroup,
        '--name', $RunbookName,
        '--content', ("@{0}" -f $artifactPath)
    ) | Out-Null
    Invoke-AzCli -Arguments @(
        'automation', 'runbook', 'publish',
        '--automation-account-name', $AutomationAccountName,
        '--resource-group', $AutomationResourceGroup,
        '--name', $RunbookName
    ) | Out-Null
}

function Upload-TemplatesForRunbook {
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
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $parameterPairs = @("DashboardDeliveryMode=$DashboardDeliveryMode")
    if ($UseExistingExportsOnly) {
        $parameterPairs += 'UseExistingExportsOnly=true'
    }

    $arguments = @(
        'automation', 'runbook', 'start',
        '--automation-account-name', $AutomationAccountName,
        '--resource-group', $AutomationResourceGroup,
        '--name', $RunbookName,
        '--parameters'
    )
    $arguments += $parameterPairs
    $arguments += @('-o', 'json')

    $job = Invoke-AzCli -Arguments $arguments -ExpectJson

    return [PSCustomObject]@{
        name = [string]$job.name
        jobId = [string]$job.jobId
        status = [string]$job.status
        creationTimeUtc = ([datetimeoffset]$job.creationTime).UtcDateTime
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
        '--automation-account-name', $AutomationAccountName,
        '--resource-group', $AutomationResourceGroup,
        '--name', $JobName,
        '-o', 'json'
    ) -ExpectJson)
}

function Get-RunbookEvents {
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

    $uri = "/subscriptions/$SubscriptionId/resourceGroups/$AutomationResourceGroup/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/$JobName/streams?api-version=2019-06-01"
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
    Upload-TemplatesForRunbook -RepoPath $repoFullPath -StorageAccountName $StorageAccountName
}

$runbookState = Start-RunbookBenchmark
Write-Host ("Started runbook job {0}" -f $runbookState.name) -ForegroundColor Yellow

$runbookJob = $null
do {
    Start-Sleep -Seconds $PollIntervalSeconds
    $runbookJob = Get-RunbookJobStatus -JobName $runbookState.name
    Write-Host ("Runbook status: {0}" -f [string]$runbookJob.status) -ForegroundColor DarkGray
}
while ($runbookJob.status -notin @('Completed', 'Failed', 'Stopped', 'Suspended'))

$runbookEvents = @(Get-RunbookEvents -JobName $runbookState.name -SubscriptionId ([string]$subscription.id) -NotBeforeUtc $runbookState.creationTimeUtc)
$runbookCompletedUtc = ([datetimeoffset]$runbookJob.lastModifiedTime).UtcDateTime
$elapsedSeconds = [math]::Round((New-TimeSpan -Start $runbookState.creationTimeUtc -End $runbookCompletedUtc).TotalSeconds, 2)
$runbookSummary = Get-PipelineEventSummary -Events $runbookEvents -TotalElapsedSeconds $elapsedSeconds -TotalRows $ExpectedTotalRows -TerminalStatus ([string]$runbookJob.status)

$repoCommit = (git -C $repoFullPath rev-parse HEAD).Trim()
$repoBranch = (git -C $repoFullPath branch --show-current).Trim()

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
        dashboard_delivery_mode = $DashboardDeliveryMode
        use_existing_exports_only = ($UseExistingExportsOnly -eq $true)
        expected_total_rows = $ExpectedTotalRows
    }
    runbook_events = @($runbookEvents)
}

[System.IO.File]::WriteAllText($resultsFullPath, ($result | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))

Write-Host ''
Write-Host ("Runbook peak working set: {0}MB" -f $runbookSummary.peak_working_set_mb) -ForegroundColor Green
Write-Host ("Runbook peak GC heap: {0}MB" -f $runbookSummary.peak_gc_heap_mb) -ForegroundColor Green
Write-Host ("Runbook elapsed: {0}s" -f $runbookSummary.elapsed_seconds) -ForegroundColor Green
Write-Host ("Results written to {0}" -f $resultsFullPath) -ForegroundColor Green
