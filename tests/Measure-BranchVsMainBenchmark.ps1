#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CurrentRepoPath = (Split-Path -Path $PSScriptRoot -Parent),

    [Parameter(Mandatory = $false)]
    [string]$MainRepoPath = (Join-Path $env:TEMP 'defender-reporting-main-bench'),

    [Parameter(Mandatory = $false)]
    [string]$DatasetPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports-synthetic'),

    [Parameter(Mandatory = $false)]
    [string]$AutomationAccountName = 'aa-defender-reporting',

    [Parameter(Mandatory = $false)]
    [string]$AutomationResourceGroup = 'rg-defender-reporting',

    [Parameter(Mandatory = $false)]
    [string]$RunbookName = 'Invoke-DashboardPipeline',

    [Parameter(Mandatory = $false)]
    [string]$RunbookStorageAccountName = 'stdefenderrepaad73',

    [Parameter(Mandatory = $false)]
    [string]$FunctionAppName = 'func-defender-reporting-parallel-0404a',

    [Parameter(Mandatory = $false)]
    [string]$FunctionAppResourceGroup = 'rg-defender-reporting-parallel',

    [Parameter(Mandatory = $false)]
    [string]$FunctionStorageAccountName = 'stdefrepaad730404a',

    [Parameter(Mandatory = $false)]
    [string]$ResultsOutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'reports' ('branch-vs-main-benchmark-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')),

    [Parameter(Mandatory = $false)]
    [string]$CurrentBaselineName = 'current-working-tree',

    [Parameter(Mandatory = $false)]
    [string]$MainBaselineName = 'main-clean',

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 60)]
    [int]$PollIntervalSeconds = 15,

    [Parameter(Mandatory = $false)]
    [switch]$CurrentOnly,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRestoreCurrentDeployment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:AutomationAccountName = $AutomationAccountName
$script:AutomationResourceGroup = $AutomationResourceGroup
$script:RunbookName = $RunbookName
$script:RunbookStorageAccountName = $RunbookStorageAccountName
$script:FunctionAppName = $FunctionAppName
$script:FunctionAppResourceGroup = $FunctionAppResourceGroup
$script:FunctionStorageAccountName = $FunctionStorageAccountName
$script:PollIntervalSeconds = $PollIntervalSeconds

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

function Get-DatasetFiles {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper intentionally returns a collection of dataset files.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return @(
        Get-ChildItem -LiteralPath $Path -File |
            Where-Object {
                $_.Name -match '\.json(\.gz)?$' -and
                $_.Name -notin @(
                    '.synthetic-progress.json',
                    '.synthetic-progress.json.gz',
                    'stress-validation-report.json',
                    'stress-validation-report.json.gz'
                )
            } |
            Sort-Object -Property Name
    )
}

function Clear-BlobContainer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName
    )

    $blobs = @(Invoke-AzCli -Arguments @('storage', 'blob', 'list', '--account-name', $AccountName, '--container-name', $ContainerName, '--auth-mode', 'login', '-o', 'json') -ExpectJson -AllowEmpty)
    foreach ($blob in $blobs) {
        Invoke-AzCli -Arguments @('storage', 'blob', 'delete', '--account-name', $AccountName, '--container-name', $ContainerName, '--name', $blob.name, '--auth-mode', 'login', '--output', 'none') | Out-Null
    }
}

function Seed-ExportsContainer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper prepares the benchmark exports container for a run.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$DatasetRoot
    )

    Clear-BlobContainer -AccountName $AccountName -ContainerName 'exports'
    foreach ($file in (Get-DatasetFiles -Path $DatasetRoot)) {
        $contentType = if ($file.Name.EndsWith('.gz')) { 'application/gzip' } else { 'application/json' }
        Invoke-AzCli -Arguments @(
            'storage', 'blob', 'upload',
            '--account-name', $AccountName,
            '--container-name', 'exports',
            '--name', $file.Name,
            '--file', $file.FullName,
            '--content-type', $contentType,
            '--auth-mode', 'login',
            '--overwrite',
            '--output', 'none'
        ) | Out-Null
    }
}

function Get-BlobDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName
    )

    try {
        return (Invoke-AzCli -Arguments @(
            'storage', 'blob', 'show',
            '--account-name', $AccountName,
            '--container-name', $ContainerName,
            '--name', $BlobName,
            '--auth-mode', 'login',
            '-o', 'json'
        ) -ExpectJson)
    }
    catch {
        if ($_.Exception.Message -match 'BlobNotFound|ResourceNotFound|The specified blob does not exist') {
            return $null
        }

        throw
    }
}

function Get-BlobLengthBytes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper returns one blob length value in bytes.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName
    )

    $blob = Get-BlobDetail -AccountName $AccountName -ContainerName $ContainerName -BlobName $BlobName
    if ($null -eq $blob) {
        return [int64]0
    }

    return [int64]$blob.properties.contentLength
}

function Build-AndDeploy-Runbook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath
    )

    Invoke-RepoScript -RepoPath $RepoPath -RelativeScriptPath 'azure/Build-Runbook.ps1'

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

function Build-AndDeploy-FunctionApp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath
    )

    Invoke-RepoScript -RepoPath $RepoPath -RelativeScriptPath 'azure/Build-FunctionApp.ps1'

    $functionAppDir = Join-Path -Path $RepoPath -ChildPath 'azure/function-app'
    $zipPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('funcapp-deploy-' + [guid]::NewGuid().ToString('N') + '.zip')

    Push-Location $functionAppDir
    try {
        Compress-Archive -Path '.\*' -DestinationPath $zipPath -Force
    }
    finally {
        Pop-Location
    }

    try {
        Invoke-AzCli -Arguments @(
            'functionapp', 'deployment', 'source', 'config-zip',
            '--src', $zipPath,
            '--name', $FunctionAppName,
            '--resource-group', $FunctionAppResourceGroup,
            '--output', 'none'
        ) | Out-Null
    }
    finally {
        Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-FunctionHostName {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Invoke-AzCli -Arguments @('functionapp', 'show', '--name', $FunctionAppName, '--resource-group', $FunctionAppResourceGroup, '--query', 'properties.defaultHostName', '-o', 'tsv'))
}

function Get-FunctionResourceId {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    return (Invoke-AzCli -Arguments @('functionapp', 'show', '--name', $FunctionAppName, '--resource-group', $FunctionAppResourceGroup, '--query', 'id', '-o', 'tsv'))
}

function Get-FunctionMasterKey {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $keys = Invoke-AzCli -Arguments @('functionapp', 'keys', 'list', '--name', $FunctionAppName, '--resource-group', $FunctionAppResourceGroup, '-o', 'json') -ExpectJson
    return [string]$keys.masterKey
}

function Get-FunctionMetricSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTimeUtc,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTimeUtc
    )

    $metrics = Invoke-AzCli -Arguments @(
        'monitor', 'metrics', 'list',
        '--resource', $ResourceId,
        '--start-time', $StartTimeUtc.ToString('o'),
        '--end-time', $EndTimeUtc.ToString('o'),
        '--interval', 'PT1M',
        '--aggregation', 'Average', 'Maximum', 'Total',
        '--metrics', 'MemoryWorkingSet', 'AverageMemoryWorkingSet', 'CpuPercentage', 'OnDemandFunctionExecutionUnits',
        '-o', 'json'
    ) -ExpectJson

    $peakWorkingSetMb = 0.0
    $averageWorkingSetMb = 0.0
    $peakCpuPercentage = 0.0
    $executionUnits = 0.0

    foreach ($metric in @($metrics.value)) {
        $metricName = [string]$metric.name.value
        $dataPoints = @($metric.timeseries | ForEach-Object { $_.data })
        foreach ($dataPoint in $dataPoints) {
            switch ($metricName) {
                'MemoryWorkingSet' {
                    if ($null -ne $dataPoint.maximum) {
                        $peakWorkingSetMb = [math]::Max($peakWorkingSetMb, ([double]$dataPoint.maximum / 1MB))
                    }
                    elseif ($null -ne $dataPoint.average) {
                        $peakWorkingSetMb = [math]::Max($peakWorkingSetMb, ([double]$dataPoint.average / 1MB))
                    }
                }
                'AverageMemoryWorkingSet' {
                    if ($null -ne $dataPoint.average) {
                        $averageWorkingSetMb = [math]::Max($averageWorkingSetMb, ([double]$dataPoint.average / 1MB))
                    }
                }
                'CpuPercentage' {
                    if ($null -ne $dataPoint.maximum) {
                        $peakCpuPercentage = [math]::Max($peakCpuPercentage, [double]$dataPoint.maximum)
                    }
                    elseif ($null -ne $dataPoint.average) {
                        $peakCpuPercentage = [math]::Max($peakCpuPercentage, [double]$dataPoint.average)
                    }
                }
                'OnDemandFunctionExecutionUnits' {
                    if ($null -ne $dataPoint.total) {
                        $executionUnits += [double]$dataPoint.total
                    }
                }
            }
        }
    }

    return [PSCustomObject]@{
        peak_working_set_mb = [math]::Round($peakWorkingSetMb, 1)
        average_working_set_mb = [math]::Round($averageWorkingSetMb, 1)
        peak_cpu_percentage = [math]::Round($peakCpuPercentage, 1)
        execution_units = [math]::Round($executionUnits, 2)
    }
}

function Get-FunctionExecutionActivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTimeUtc,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTimeUtc
    )

    $metrics = Invoke-AzCli -Arguments @(
        'monitor', 'metrics', 'list',
        '--resource', $ResourceId,
        '--start-time', $StartTimeUtc.ToString('o'),
        '--end-time', $EndTimeUtc.ToString('o'),
        '--interval', 'PT1M',
        '--aggregation', 'Total',
        '--metrics', 'OnDemandFunctionExecutionCount',
        '-o', 'json'
    ) -ExpectJson

    $totalCount = 0.0
    $latestTimestampUtc = $null

    foreach ($metric in @($metrics.value)) {
        foreach ($series in @($metric.timeseries)) {
            foreach ($dataPoint in @($series.data)) {
                if ($null -eq $dataPoint.total) {
                    continue
                }

                $pointTotal = [double]$dataPoint.total
                if ($pointTotal -le 0) {
                    continue
                }

                $totalCount += $pointTotal
                $pointTimestampUtc = ([datetimeoffset]$dataPoint.timeStamp).UtcDateTime
                if ($null -eq $latestTimestampUtc -or $pointTimestampUtc -gt $latestTimestampUtc) {
                    $latestTimestampUtc = $pointTimestampUtc
                }
            }
        }
    }

    return [PSCustomObject]@{
        total_count = [int][math]::Round($totalCount, 0)
        latest_timestamp_utc = $latestTimestampUtc
    }
}

function Get-FunctionTraceSetting {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $settings = @(Invoke-AzCli -Arguments @('functionapp', 'config', 'appsettings', 'list', '--name', $FunctionAppName, '--resource-group', $FunctionAppResourceGroup, '-o', 'json') -ExpectJson)
    $setting = $settings | Where-Object { $_.name -eq 'PIPELINE_FILE_TRACE_ENABLED' } | Select-Object -First 1
    if ($null -eq $setting) {
        return $null
    }

    return [string]$setting.value
}

function Set-FunctionAppBenchmarkSettings {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper updates Function App settings in a controlled script flow.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper applies a coordinated group of benchmark settings.')]
    [CmdletBinding()]
    param()

    Invoke-AzCli -Arguments @(
        'functionapp', 'config', 'appsettings', 'set',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionAppResourceGroup,
        '--settings',
        ("STORAGE_ACCOUNT_NAME={0}" -f $FunctionStorageAccountName),
        'DASHBOARD_DELIVERY_MODE=SelfContained',
        'INCLUDE_ADVANCED_HUNTING=true',
        'USE_EXISTING_EXPORTS_ONLY=true',
        'PIPELINE_FILE_TRACE_ENABLED=true',
        '--output', 'none'
    ) | Out-Null
}

function Restore-FunctionTraceSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$OriginalValue
    )

    if ($null -eq $OriginalValue) {
        Invoke-AzCli -Arguments @(
            'functionapp', 'config', 'appsettings', 'delete',
            '--name', $FunctionAppName,
            '--resource-group', $FunctionAppResourceGroup,
            '--setting-names', 'PIPELINE_FILE_TRACE_ENABLED',
            '--output', 'none'
        ) | Out-Null
        return
    }

    Invoke-AzCli -Arguments @(
        'functionapp', 'config', 'appsettings', 'set',
        '--name', $FunctionAppName,
        '--resource-group', $FunctionAppResourceGroup,
        '--settings', ("PIPELINE_FILE_TRACE_ENABLED={0}" -f $OriginalValue),
        '--output', 'none'
    ) | Out-Null
}

function Invoke-FunctionAdminRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'Post', 'Delete')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Body
    )

    $headers = @{ 'x-functions-key' = $MasterKey }
    if ($Method -eq 'Delete') {
        $headers['If-Match'] = '*'
    }

    $uri = "https://$HostName/$Path"
    $invokeParams = @{
        Method = $Method
        Uri = $uri
        Headers = $headers
        ErrorAction = 'Stop'
    }

    if ($Method -eq 'Post') {
        $invokeParams.ContentType = 'application/json'
        $invokeParams.Body = if ([string]::IsNullOrWhiteSpace($Body)) { '{}' } else { $Body }
    }

    try {
        return Invoke-WebRequest @invokeParams
    }
    catch {
        $response = $_.Exception.Response
        if ($null -ne $response -and [int]$response.StatusCode -eq 404) {
            return $null
        }

        throw
    }
}

function Wait-FunctionHostReady {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutMinutes = 10
    )

    $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
    while ([datetime]::UtcNow -lt $deadline) {
        try {
            $response = Invoke-FunctionAdminRequest -Method Get -HostName $HostName -MasterKey $MasterKey -Path 'admin/host/status'
            if ($null -ne $response -and $response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                return
            }
        }
        catch {
            Write-Verbose ("Function host not ready yet: {0}" -f $_.Exception.Message)
        }

        Start-Sleep -Seconds 10
    }

    throw "Timed out waiting for Function App host '$HostName' to become ready."
}

function Remove-FunctionTraceFiles {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper removes known trace files in a controlled script flow.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper targets a fixed set of trace files.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey
    )

    $paths = @(
        'admin/vfs/tmp/FunctionsData/ExportAndGenerate.trace.log',
        'admin/vfs/tmp/FunctionsData/FunctionProfile.trace.log'
    )

    foreach ($path in $paths) {
        try {
            $null = Invoke-FunctionAdminRequest -Method Delete -HostName $HostName -MasterKey $MasterKey -Path $path
        }
        catch {
            Write-Verbose ("Ignoring trace cleanup failure for {0}: {1}" -f $path, $_.Exception.Message)
        }
    }
}

function Get-TraceEventsFromContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [datetime]$NotBeforeUtc
    )

    $events = [System.Collections.Generic.List[object]]::new()
    foreach ($line in ($Content -split "`r?`n")) {
        if ($line -notmatch '^\[(?<timestamp>[^\]]+)\]\s?(?<message>.*)$') {
            continue
        }

        try {
            $timestamp = ([datetimeoffset]$matches.timestamp).UtcDateTime
        }
        catch {
            continue
        }

        if ($timestamp -lt $NotBeforeUtc.AddSeconds(-5)) {
            continue
        }

        $events.Add([PSCustomObject]@{
            timestamp_utc = $timestamp
            message = $matches.message
        }) | Out-Null
    }

    return @($events | Sort-Object -Property timestamp_utc, message -Unique)
}

function Get-FunctionTraceEvents {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper returns a collection of Function trace events.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$MasterKey,

        [Parameter(Mandatory = $true)]
        [datetime]$NotBeforeUtc
    )

    $response = Invoke-FunctionAdminRequest -Method Get -HostName $HostName -MasterKey $MasterKey -Path 'admin/vfs/tmp/FunctionsData/ExportAndGenerate.trace.log'
    if ($null -eq $response) {
        return @()
    }

    return @(Get-TraceEventsFromContent -Content $response.Content -NotBeforeUtc $NotBeforeUtc)
}

function Start-RunbookBenchmark {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper starts a runbook job as part of the scripted workflow.')]
    [CmdletBinding()]
    param()

    $job = Invoke-AzCli -Arguments @(
        'automation', 'runbook', 'start',
        '--automation-account-name', $AutomationAccountName,
        '--resource-group', $AutomationResourceGroup,
        '--name', $RunbookName,
        '--parameters', 'UseExistingExportsOnly=true', 'DashboardDeliveryMode=SelfContained',
        '-o', 'json'
    ) -ExpectJson

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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper returns a collection of runbook events.')]
    [CmdletBinding()]
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

function Get-AvailableMemoryGB {
    [CmdletBinding()]
    [OutputType([double])]
    param()

    $os = Get-CimInstance Win32_OperatingSystem
    return [math]::Round(($os.FreePhysicalMemory / 1MB), 2)
}

function Get-ProcessTree {
    [CmdletBinding()]
    [OutputType([System.Diagnostics.Process[]])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$RootProcessId
    )

    $processById = @{}
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        $processById[$process.Id] = $process
    }

    $childrenByParent = @{}
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $parentId = [int]$process.ParentProcessId
        if (-not $childrenByParent.ContainsKey($parentId)) {
            $childrenByParent[$parentId] = [System.Collections.Generic.List[int]]::new()
        }

        $childrenByParent[$parentId].Add([int]$process.ProcessId)
    }

    $queue = [System.Collections.Generic.Queue[int]]::new()
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    $queue.Enqueue($RootProcessId)

    while ($queue.Count -gt 0) {
        $currentId = $queue.Dequeue()
        if (-not $seen.Add($currentId)) {
            continue
        }

        if ($childrenByParent.ContainsKey($currentId)) {
            foreach ($childId in $childrenByParent[$currentId]) {
                $queue.Enqueue($childId)
            }
        }
    }

    $processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
    foreach ($processId in $seen) {
        if ($processById.ContainsKey($processId)) {
            $processes.Add($processById[$processId]) | Out-Null
        }
    }

    return @($processes | Sort-Object -Property Id)
}

function Start-LocalBenchmark {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper stages local files and launches the benchmark process.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$BenchmarkDatasetPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory
    )

    $localDatasetPath = Join-Path -Path $OutputDirectory -ChildPath ($Name + '.local.dataset')
    if (Test-Path -LiteralPath $localDatasetPath) {
        Remove-Item -LiteralPath $localDatasetPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    $null = New-Item -Path $localDatasetPath -ItemType Directory -Force
    foreach ($datasetFile in Get-DatasetFiles -Path $BenchmarkDatasetPath) {
        Copy-Item -LiteralPath $datasetFile.FullName -Destination (Join-Path -Path $localDatasetPath -ChildPath $datasetFile.Name) -Force
    }

    $cachePath = Join-Path -Path $localDatasetPath -ChildPath '.dashboard-cache'
    if (Test-Path -LiteralPath $cachePath) {
        Remove-Item -LiteralPath $cachePath -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        $null = New-Item -Path $OutputDirectory -ItemType Directory -Force
    }

    $stdoutPath = Join-Path -Path $OutputDirectory -ChildPath ($Name + '.local.stdout.log')
    $stderrPath = Join-Path -Path $OutputDirectory -ChildPath ($Name + '.local.stderr.log')
    $dashboardPath = Join-Path -Path $OutputDirectory -ChildPath ($Name + '.local.html')

    foreach ($path in @($stdoutPath, $stderrPath, $dashboardPath)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $scriptPath = Join-Path -Path $RepoPath -ChildPath 'tests/Invoke-LargeDatasetValidation.ps1'
    $argumentList = @(
        '-NoProfile',
        '-File', $scriptPath,
        '-SkipSyntheticGeneration',
        '-SyntheticOutputPath', $localDatasetPath,
        '-DashboardOutputPath', $dashboardPath
    )

    $process = Start-Process -FilePath 'pwsh' -ArgumentList $argumentList -WorkingDirectory $RepoPath -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
    return [ordered]@{
        name = $Name
        repoPath = $RepoPath
        sourceDatasetPath = $BenchmarkDatasetPath
        datasetPath = $localDatasetPath
        process = $process
        stdoutPath = $stdoutPath
        stderrPath = $stderrPath
        dashboardPath = $dashboardPath
        stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        samples = [System.Collections.Generic.List[object]]::new()
        peakRssBytes = [int64]0
        peakRssAtSeconds = [double]0
        peakPrivateBytes = [int64]0
        peakPrivateAtSeconds = [double]0
        completed = $false
        exitCode = $null
    }
}

function Update-LocalBenchmark {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal benchmark helper updates in-memory process sampling state.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$State
    )

    if ($State.completed) {
        return
    }

    try {
        $State.process.Refresh()
    }
    catch {
        Write-Verbose ("Ignoring process refresh failure: {0}" -f $_.Exception.Message)
    }

    $tree = @(Get-ProcessTree -RootProcessId $State.process.Id)
    if ($tree.Count -eq 0) {
        try {
            $null = $State.process.WorkingSet64
            $tree = @($State.process)
        }
        catch {
            $tree = @()
        }
    }

    if ($tree.Count -gt 0) {
        $rssBytes = [int64](($tree | Measure-Object -Property WorkingSet64 -Sum).Sum)
        $privateBytes = [int64](($tree | Measure-Object -Property PrivateMemorySize64 -Sum).Sum)
        $elapsedSeconds = [math]::Round($State.stopwatch.Elapsed.TotalSeconds, 2)

        if ($rssBytes -gt $State.peakRssBytes) {
            $State.peakRssBytes = $rssBytes
            $State.peakRssAtSeconds = $elapsedSeconds
        }

        if ($privateBytes -gt $State.peakPrivateBytes) {
            $State.peakPrivateBytes = $privateBytes
            $State.peakPrivateAtSeconds = $elapsedSeconds
        }

        $State.samples.Add([PSCustomObject]@{
            elapsed_seconds = $elapsedSeconds
            process_count = $tree.Count
            tree_rss_bytes = $rssBytes
            tree_private_bytes = $privateBytes
            available_memory_gb = Get-AvailableMemoryGB
        }) | Out-Null
    }

    if ($State.process.HasExited) {
        $State.stopwatch.Stop()
        $State.completed = $true
        $State.exitCode = [int]$State.process.ExitCode
    }
}

function Get-LocalBenchmarkResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$State,

        [Parameter(Mandatory = $true)]
        [int]$TotalRows
    )

    $result = [PSCustomObject]@{
        status = if ($State.exitCode -eq 0) { 'Completed' } else { 'Failed' }
        elapsed_seconds = [math]::Round($State.stopwatch.Elapsed.TotalSeconds, 2)
        peak_tree_rss_bytes = $State.peakRssBytes
        peak_tree_rss_gb = [math]::Round(($State.peakRssBytes / 1GB), 3)
        peak_tree_rss_at_seconds = $State.peakRssAtSeconds
        peak_tree_private_bytes = $State.peakPrivateBytes
        peak_tree_private_gb = [math]::Round(($State.peakPrivateBytes / 1GB), 3)
        peak_tree_private_at_seconds = $State.peakPrivateAtSeconds
        rows_per_second = if ($State.stopwatch.Elapsed.TotalSeconds -gt 0) { [math]::Round(($TotalRows / $State.stopwatch.Elapsed.TotalSeconds), 0) } else { 0 }
        sample_count = $State.samples.Count
        dashboard_bytes = if (Test-Path -LiteralPath $State.dashboardPath -PathType Leaf) { (Get-Item -LiteralPath $State.dashboardPath).Length } else { 0 }
        dashboard_mb = if (Test-Path -LiteralPath $State.dashboardPath -PathType Leaf) { [math]::Round(((Get-Item -LiteralPath $State.dashboardPath).Length / 1MB), 2) } else { 0 }
        stdout_path = $State.stdoutPath
        stderr_path = $State.stderrPath
        dashboard_path = $State.dashboardPath
    }

    if ($State.Contains('datasetPath') -and -not [string]::IsNullOrWhiteSpace([string]$State.datasetPath) -and (Test-Path -LiteralPath $State.datasetPath)) {
        Remove-Item -LiteralPath $State.datasetPath -Recurse -Force -ErrorAction SilentlyContinue
    }

    return $result
}

function Get-PipelineEventSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Events,

        [Parameter(Mandatory = $true)]
        [double]$TotalElapsedSeconds,

        [Parameter(Mandatory = $false)]
        [int64]$DashboardBytes = 0,

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

    if ($dashboardSizeMb -eq 0 -and $DashboardBytes -gt 0) {
        $dashboardSizeMb = [math]::Round(($DashboardBytes / 1MB), 2)
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
        dashboard_bytes = $DashboardBytes
        dashboard_mb = $dashboardSizeMb
        used_cached_payload = $usedCachedPayload
        skipped_fresh_export = $skippedFreshExport
    }
}

function Invoke-BaselineBenchmark {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaselineName,

        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string]$DatasetRoot,

        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [string]$FunctionHostName,

        [Parameter(Mandatory = $true)]
        [string]$FunctionResourceId,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [int]$TotalRows
    )

    Write-Host ''
    Write-Host ('=== {0} ===' -f $BaselineName) -ForegroundColor Cyan
    Write-Host ('Repo: {0}' -f $RepoPath)

    Write-Host 'Deploying runbook artifact...'
    Build-AndDeploy-Runbook -RepoPath $RepoPath
    Write-Host 'Deploying Function App package...'
    Build-AndDeploy-FunctionApp -RepoPath $RepoPath
    Write-Host 'Applying Function App benchmark settings...'
    Set-FunctionAppBenchmarkSettings

    Write-Host 'Uploading templates to both storage accounts...'
    Upload-TemplatesForBaseline -RepoPath $RepoPath -StorageAccountName $RunbookStorageAccountName
    Upload-TemplatesForBaseline -RepoPath $RepoPath -StorageAccountName $FunctionStorageAccountName

    Write-Host 'Seeding cold benchmark data into both storage accounts...'
    Seed-EnvironmentData -RunbookStorageAccountName $RunbookStorageAccountName -FunctionStorageAccountName $FunctionStorageAccountName -DatasetRoot $DatasetRoot

    $effectiveFunctionMasterKey = Get-FunctionMasterKey
    Write-Host 'Waiting for Function App host readiness...'
    Wait-FunctionHostReady -HostName $FunctionHostName -MasterKey $effectiveFunctionMasterKey

    $baselineOutputDirectory = Join-Path -Path $OutputRoot -ChildPath $BaselineName
    if (-not (Test-Path -LiteralPath $baselineOutputDirectory)) {
        $null = New-Item -Path $baselineOutputDirectory -ItemType Directory -Force
    }

    $localState = Start-LocalBenchmark -RepoPath $RepoPath -Name $BaselineName -BenchmarkDatasetPath $DatasetRoot -OutputDirectory $baselineOutputDirectory
    $runbookState = Start-RunbookBenchmark
    $functionInvokeStartedUtc = [datetime]::UtcNow
    $null = Invoke-FunctionAdminRequest -Method Post -HostName $FunctionHostName -MasterKey $effectiveFunctionMasterKey -Path 'admin/functions/ExportAndGenerate' -Body '{}'
    Write-Host 'Local, runbook, and Function App runs started.'

    $runbookCompleted = $false
    $runbookJob = $null
    $runbookEvents = @()
    $functionCompleted = $false
    $functionCompletedUtc = $null
    $functionStatus = 'Running'
    $functionDeadlineUtc = $functionInvokeStartedUtc.AddHours(2)
    $functionExecutionActivity = $null
    $functionLastMetricPollUtc = [datetime]::MinValue

    while (-not ($localState.completed -and $runbookCompleted -and $functionCompleted)) {
        Update-LocalBenchmark -State $localState

        if (-not $runbookCompleted) {
            $runbookJob = Get-RunbookJobStatus -JobName $runbookState.name
            $runbookCompleted = ($runbookJob.status -in @('Completed', 'Failed', 'Stopped', 'Suspended'))
            if ($runbookCompleted) {
                $runbookEvents = @(Get-RunbookEvents -JobName $runbookState.name -SubscriptionId $SubscriptionId -NotBeforeUtc $runbookState.creationTimeUtc)
            }
        }

        if (-not $functionCompleted) {
            $functionDashboardBlob = Get-BlobDetail -AccountName $FunctionStorageAccountName -ContainerName 'dashboards' -BlobName 'VulnerabilityDashboard.html'
            if ($null -ne $functionDashboardBlob) {
                $lastModifiedUtc = ([datetimeoffset]$functionDashboardBlob.properties.lastModified).UtcDateTime
                if ($lastModifiedUtc -ge $functionInvokeStartedUtc.AddSeconds(-5)) {
                    $functionCompletedUtc = $lastModifiedUtc
                    $functionCompleted = $true
                    $functionStatus = 'Completed'
                }
            }

            $nowUtc = [datetime]::UtcNow
            if ((-not $functionCompleted) -and $nowUtc -ge $functionLastMetricPollUtc.AddSeconds([math]::Max($PollIntervalSeconds, 30))) {
                $functionExecutionActivity = Get-FunctionExecutionActivity -ResourceId $FunctionResourceId -StartTimeUtc $functionInvokeStartedUtc.AddMinutes(-1) -EndTimeUtc $nowUtc
                $functionLastMetricPollUtc = $nowUtc
                if ($functionExecutionActivity.total_count -ge 1) {
                    $functionCompletedUtc = if ($null -ne $functionExecutionActivity.latest_timestamp_utc) { $functionExecutionActivity.latest_timestamp_utc } else { $nowUtc }
                    $functionCompleted = $true
                    $functionStatus = 'FailedNoDashboard'
                }
            }

            if ((-not $functionCompleted) -and [datetime]::UtcNow -ge $functionDeadlineUtc) {
                $functionCompletedUtc = [datetime]::UtcNow
                $functionCompleted = $true
                $functionStatus = 'TimedOut'
            }
        }

        if (-not ($localState.completed -and $runbookCompleted -and $functionCompleted)) {
            Start-Sleep -Seconds $PollIntervalSeconds
        }
    }

    Update-LocalBenchmark -State $localState

    $runbookElapsedSeconds = if ($null -ne $runbookJob -and $null -ne $runbookJob.startTime -and $null -ne $runbookJob.endTime) {
        [math]::Round((New-TimeSpan -Start ([datetimeoffset]$runbookJob.startTime).UtcDateTime -End ([datetimeoffset]$runbookJob.endTime).UtcDateTime).TotalSeconds, 2)
    }
    elseif ($runbookEvents.Count -gt 1) {
        [math]::Round((New-TimeSpan -Start $runbookEvents[0].timestamp_utc -End $runbookEvents[-1].timestamp_utc).TotalSeconds, 2)
    }
    else {
        0
    }

    $functionElapsedSeconds = if ($null -ne $functionCompletedUtc) {
        [math]::Round((New-TimeSpan -Start $functionInvokeStartedUtc -End $functionCompletedUtc).TotalSeconds, 2)
    }
    else {
        0
    }

    $functionMetricEndUtc = if ($null -ne $functionCompletedUtc) {
        $functionCompletedUtc.AddMinutes(1)
    }
    else {
        [datetime]::UtcNow
    }
    $functionMetricSummary = Get-FunctionMetricSummary -ResourceId $FunctionResourceId -StartTimeUtc $functionInvokeStartedUtc.AddMinutes(-1) -EndTimeUtc $functionMetricEndUtc

    $localResult = Get-LocalBenchmarkResult -State $localState -TotalRows $TotalRows
    $runbookResult = Get-PipelineEventSummary -Events $runbookEvents -TotalElapsedSeconds $runbookElapsedSeconds -DashboardBytes (Get-BlobLengthBytes -AccountName $RunbookStorageAccountName -ContainerName 'dashboards' -BlobName 'VulnerabilityDashboard.html') -TotalRows $TotalRows -TerminalStatus ([string]$runbookJob.status)
    $functionDashboardBytes = Get-BlobLengthBytes -AccountName $FunctionStorageAccountName -ContainerName 'dashboards' -BlobName 'VulnerabilityDashboard.html'
    $functionResult = [PSCustomObject]@{
        status = $functionStatus
        elapsed_seconds = $functionElapsedSeconds
        peak_working_set_mb = $functionMetricSummary.peak_working_set_mb
        average_working_set_mb = $functionMetricSummary.average_working_set_mb
        peak_cpu_percentage = $functionMetricSummary.peak_cpu_percentage
        execution_units = $functionMetricSummary.execution_units
        execution_count = if ($null -ne $functionExecutionActivity) { $functionExecutionActivity.total_count } else { 0 }
        rows_per_second = if ($functionElapsedSeconds -gt 0 -and $TotalRows -gt 0) { [math]::Round(($TotalRows / $functionElapsedSeconds), 0) } else { 0 }
        dashboard_bytes = $functionDashboardBytes
        dashboard_mb = [math]::Round(($functionDashboardBytes / 1MB), 2)
        completion_utc = $functionCompletedUtc
    }

    return [PSCustomObject]@{
        baseline = $BaselineName
        repo_path = $RepoPath
        local = $localResult
        runbook = $runbookResult
        function_app = $functionResult
        runbook_job_name = $runbookState.name
        function_invoked_at_utc = $functionInvokeStartedUtc
        runbook_events = $runbookEvents
        function_events = @()
    }
}

function Upload-TemplatesForBaseline {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper uploads benchmark template assets for a baseline run.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath,

        [Parameter(Mandatory = $true)]
        [string]$StorageAccountName
    )

    Invoke-RepoScript -RepoPath $RepoPath -RelativeScriptPath 'azure/Upload-Templates.ps1' -Arguments @{ StorageAccountName = $StorageAccountName }
}

function Seed-EnvironmentData {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Internal helper prepares storage data for a benchmark run.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunbookStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$FunctionStorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]$DatasetRoot
    )

    foreach ($accountName in @($RunbookStorageAccountName, $FunctionStorageAccountName)) {
        Clear-BlobContainer -AccountName $accountName -ContainerName 'dashboards'
        Seed-ExportsContainer -AccountName $accountName -DatasetRoot $DatasetRoot
    }
}

function Restore-CurrentAzureDeployment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoPath
    )

    Write-Host ''
    Write-Host 'Restoring current branch code to Azure...' -ForegroundColor Yellow
    Build-AndDeploy-Runbook -RepoPath $RepoPath
    Build-AndDeploy-FunctionApp -RepoPath $RepoPath
    Upload-TemplatesForBaseline -RepoPath $RepoPath -StorageAccountName $RunbookStorageAccountName
    Upload-TemplatesForBaseline -RepoPath $RepoPath -StorageAccountName $FunctionStorageAccountName
}

function Get-ComparisonBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Current,

        [Parameter(Mandatory = $true)]
        [psobject]$Main
    )

    return [PSCustomObject]@{
        local = [PSCustomObject]@{
            elapsed_seconds_delta = [math]::Round(($Current.local.elapsed_seconds - $Main.local.elapsed_seconds), 2)
            peak_rss_gb_delta = [math]::Round(($Current.local.peak_tree_rss_gb - $Main.local.peak_tree_rss_gb), 3)
            peak_private_gb_delta = [math]::Round(($Current.local.peak_tree_private_gb - $Main.local.peak_tree_private_gb), 3)
        }
        runbook = [PSCustomObject]@{
            elapsed_seconds_delta = [math]::Round(($Current.runbook.elapsed_seconds - $Main.runbook.elapsed_seconds), 2)
            peak_working_set_mb_delta = [math]::Round(($Current.runbook.peak_working_set_mb - $Main.runbook.peak_working_set_mb), 1)
            peak_gc_heap_mb_delta = [math]::Round(($Current.runbook.peak_gc_heap_mb - $Main.runbook.peak_gc_heap_mb), 1)
        }
        function_app = [PSCustomObject]@{
            elapsed_seconds_delta = [math]::Round(($Current.function_app.elapsed_seconds - $Main.function_app.elapsed_seconds), 2)
            peak_working_set_mb_delta = [math]::Round(($Current.function_app.peak_working_set_mb - $Main.function_app.peak_working_set_mb), 1)
            execution_units_delta = [math]::Round(($Current.function_app.execution_units - $Main.function_app.execution_units), 2)
        }
    }
}

$resolvedCurrentRepoPath = [System.IO.Path]::GetFullPath($CurrentRepoPath)
$resolvedDatasetPath = [System.IO.Path]::GetFullPath($DatasetPath)
$resolvedResultsOutputPath = [System.IO.Path]::GetFullPath($ResultsOutputPath)
$outputDirectory = Split-Path -Path $resolvedResultsOutputPath -Parent

$resolvedMainRepoPath = if ($CurrentOnly) {
    $null
}
else {
    [System.IO.Path]::GetFullPath($MainRepoPath)
}

foreach ($requiredPath in @($resolvedCurrentRepoPath, $resolvedDatasetPath, $resolvedMainRepoPath)) {
    if ([string]::IsNullOrWhiteSpace($requiredPath)) {
        continue
    }

    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required path not found: $requiredPath"
    }
}

if (-not (Test-Path -LiteralPath $outputDirectory)) {
    $null = New-Item -Path $outputDirectory -ItemType Directory -Force
}

$datasetManifestPath = Join-Path -Path $resolvedDatasetPath -ChildPath 'synthetic-manifest.json'
$datasetManifest = if (Test-Path -LiteralPath $datasetManifestPath -PathType Leaf) {
    Get-Content -LiteralPath $datasetManifestPath -Raw | ConvertFrom-Json -Depth 20
}
else {
    $null
}
$totalRows = if ($null -ne $datasetManifest -and $datasetManifest.PSObject.Properties['actualCurrentRows'] -and $datasetManifest.PSObject.Properties['actualHistoryRows']) {
    [int]$datasetManifest.actualCurrentRows + [int]$datasetManifest.actualHistoryRows
}
else {
    0
}

$subscription = Invoke-AzCli -Arguments @('account', 'show', '-o', 'json') -ExpectJson
$functionHostName = Get-FunctionHostName
$functionResourceId = Get-FunctionResourceId
$originalFunctionTraceSetting = Get-FunctionTraceSetting

$currentResult = $null
$mainResult = $null

try {
    $functionMasterKey = Get-FunctionMasterKey
    Wait-FunctionHostReady -HostName $functionHostName -MasterKey $functionMasterKey

    $currentResult = @(Invoke-BaselineBenchmark -BaselineName $CurrentBaselineName -RepoPath $resolvedCurrentRepoPath -DatasetRoot $resolvedDatasetPath -OutputRoot $outputDirectory -FunctionHostName $functionHostName -FunctionResourceId $functionResourceId -SubscriptionId ([string]$subscription.id) -TotalRows $totalRows) | Select-Object -Last 1
    $currentResult | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path -Path $outputDirectory -ChildPath ($CurrentBaselineName + '.result.json')) -Encoding utf8

    if (-not $CurrentOnly) {
        $functionMasterKey = Get-FunctionMasterKey
        Wait-FunctionHostReady -HostName $functionHostName -MasterKey $functionMasterKey

        $mainResult = @(Invoke-BaselineBenchmark -BaselineName $MainBaselineName -RepoPath $resolvedMainRepoPath -DatasetRoot $resolvedDatasetPath -OutputRoot $outputDirectory -FunctionHostName $functionHostName -FunctionResourceId $functionResourceId -SubscriptionId ([string]$subscription.id) -TotalRows $totalRows) | Select-Object -Last 1
        $mainResult | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path -Path $outputDirectory -ChildPath ($MainBaselineName + '.result.json')) -Encoding utf8
    }
}
finally {
    try {
        if (-not $SkipRestoreCurrentDeployment) {
            Restore-CurrentAzureDeployment -RepoPath $resolvedCurrentRepoPath
        }
    }
    finally {
        Restore-FunctionTraceSetting -OriginalValue $originalFunctionTraceSetting
    }
}

$result = [PSCustomObject]@{
    generated_utc = [datetime]::UtcNow.ToString('o')
    benchmark_mode = if ($CurrentOnly) { 'current-only' } else { 'branch-vs-main' }
    subscription = [PSCustomObject]@{
        id = [string]$subscription.id
        name = [string]$subscription.name
        tenantId = [string]$subscription.tenantId
    }
    dataset = [PSCustomObject]@{
        path = $resolvedDatasetPath
        files = @(Get-DatasetFiles -Path $resolvedDatasetPath | ForEach-Object { $_.Name })
        manifest = $datasetManifest
        total_rows = $totalRows
    }
    current = $currentResult
    main = $mainResult
    comparison = if ($null -ne $currentResult -and $null -ne $mainResult) { Get-ComparisonBlock -Current $currentResult -Main $mainResult } else { $null }
}

$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resolvedResultsOutputPath -Encoding utf8

Write-Host ''
Write-Host ('Benchmark report: {0}' -f $resolvedResultsOutputPath) -ForegroundColor Green
if ($null -ne $currentResult) {
    Write-Host ('{0} local/runbook/function elapsed: {1}s / {2}s / {3}s' -f $CurrentBaselineName, $currentResult.local.elapsed_seconds, $currentResult.runbook.elapsed_seconds, $currentResult.function_app.elapsed_seconds)
}
if ($null -ne $mainResult) {
    Write-Host ('{0} local/runbook/function elapsed: {1}s / {2}s / {3}s' -f $MainBaselineName, $mainResult.local.elapsed_seconds, $mainResult.runbook.elapsed_seconds, $mainResult.function_app.elapsed_seconds)
}
