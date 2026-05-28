Set-StrictMode -Version Latest

# Canonical shared helper surface for the Defender reporting scripts.
#
# This file is the authoritative source for reusable logic shared by:
# - Invoke-VulnerabilityExport.ps1
# - Generate-VulnerabilityDashboard.ps1
# - the generated Azure Automation runbook
#
# TEMPORARY THROUGH 2026-07-01:
# The vulnerability current/history migration and legacy compatibility paths
# remain here in a dedicated section so they can be removed cleanly once all
# callers have upgraded off the legacy VulnExport_<group>_<date>.json(.gz)
# snapshot layout.

$Script:VulnCurrentFileName = 'VulnExport_current.json.gz'
$Script:VulnHistoryFileNamePattern = 'VulnHistory_{0}.json.gz'
$Script:VulnHistoryRowsFileNamePattern = 'VulnHistoryRows_{0}.json.gz'
$Script:VulnContentDictionaryFileName = 'VulnContentDictionary.json.gz'
$Script:VulnCurrentRefsFileName = 'VulnCurrentRefs.json.gz'
$Script:VulnHistoryRefsFileNamePattern = 'VulnHistoryRefs_{0}.json.gz'
$Script:MachineCurrentFileName = 'Machines_Current.json.gz'
$Script:MachineHistoryFileName = 'Machines_History.json.gz'
$Script:MachineHistoryQuarterlyFileNamePattern = 'Machines_History_{0}.json.gz'
$Script:AdvancedHuntingCurrentFileName = 'AdvancedHunting_Current.json.gz'
$Script:NvdCveCurrentFileName = 'NvdCve_Current.json.gz'
$Script:LegacyVulnMigrationRemovalDate = '2026-07-01'
$Script:VulnDiskPartitionCount = 128

function Get-LegacyMigrationRemovalDateUtc {
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$RemovalDate = $Script:LegacyVulnMigrationRemovalDate
    )

    if ([string]::IsNullOrWhiteSpace($RemovalDate)) {
        throw 'Legacy migration removal date is not configured.'
    }

    try {
        return [datetime]::SpecifyKind([datetime]::ParseExact($RemovalDate, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture), [System.DateTimeKind]::Utc)
    }
    catch {
        throw "Legacy migration removal date '$RemovalDate' is not in the expected yyyy-MM-dd format."
    }
}

function Assert-LegacyMigrationAllowed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FeatureName,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$LegacyPaths = @(),

        [Parameter(Mandatory = $false)]
        [datetime]$CurrentUtc = ([datetime]::UtcNow)
    )

    $resolvedLegacyPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($legacyPath in @($LegacyPaths)) {
        if (-not [string]::IsNullOrWhiteSpace($legacyPath)) {
            $resolvedLegacyPaths.Add($legacyPath)
        }
    }

    if ($resolvedLegacyPaths.Count -eq 0) {
        return
    }

    $removalDateUtc = Get-LegacyMigrationRemovalDateUtc
    if ($CurrentUtc -lt $removalDateUtc) {
        return
    }

    $samplePaths = @($resolvedLegacyPaths | Select-Object -First 3 | ForEach-Object { Split-Path -Leaf $_ })
    $sampleSuffix = if ($samplePaths.Count -gt 0) {
        " Example legacy artifact(s): $($samplePaths -join ', ')."
    }
    else {
        ''
    }

    throw ("Legacy {0} support expired on {1}. Rebuild the canonical store and remove legacy compatibility artifacts before continuing.{2}" -f $FeatureName, $Script:LegacyVulnMigrationRemovalDate, $sampleSuffix)
}

function Get-StoreLockName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName
    )

    $storeKey = ([System.IO.Path]::GetFullPath($BasePath) + '|' + $StoreName).ToLowerInvariant()
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($storeKey))
    $hash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    return "Global\DefenderReporting.$hash"
}

function Invoke-WithStoreLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 300
    )

    $mutexName = Get-StoreLockName -BasePath $BasePath -StoreName $StoreName
    $mutex = [System.Threading.Mutex]::new($false, $mutexName)
    $acquired = $false

    try {
        $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
        if (-not $acquired) {
            throw "Timed out waiting for the '$StoreName' store lock in '$BasePath'."
        }

        return & $ScriptBlock
    }
    finally {
        if ($acquired) {
            [void]$mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
}

function Invoke-FullGarbageCollection {
    [CmdletBinding()]
    param()

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
}

function Invoke-PhaseTransitionGarbageCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$MemoryLabel
    )

    Invoke-FullGarbageCollection

    if (-not [string]::IsNullOrWhiteSpace($MemoryLabel) -and (Get-Command -Name Write-MemoryUsage -ErrorAction SilentlyContinue)) {
        Write-MemoryUsage -Label $MemoryLabel
    }
}

function Test-IsAzureHostedEnvironment {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    foreach ($environmentVariableName in @(
        'WEBSITE_INSTANCE_ID'
        'WEBSITE_HOSTNAME'
        'WEBSITE_SITE_NAME'
        'FUNCTIONS_WORKER_RUNTIME'
        'FUNCTIONS_EXTENSION_VERSION'
        'FUNCTIONS_WORKER_DIRECTORY'
        'FUNCTIONS_APPLICATION_DIRECTORY'
        'AUTOMATION_ASSET_ACCOUNTID'
        'AZUREPS_HOST_ENVIRONMENT'
    )) {
        $environmentValue = [System.Environment]::GetEnvironmentVariable($environmentVariableName)
        if (-not [string]::IsNullOrWhiteSpace([string]$environmentValue)) {
            return $true
        }
    }

    $psPrivateMetadataVariable = Get-Variable -Name PSPrivateMetadata -Scope Global -ErrorAction SilentlyContinue
    if ($null -ne $psPrivateMetadataVariable) {
        $psPrivateMetadata = $psPrivateMetadataVariable.Value
        $jobId = if ($null -ne $psPrivateMetadata) { [string]$psPrivateMetadata.PSObject.Properties['JobId']?.Value } else { '' }
        if (-not [string]::IsNullOrWhiteSpace($jobId)) {
            return $true
        }
    }

    return $false
}

function Resolve-RunspaceThrottleLimit {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 64)]
        [int]$RequestedThrottleLimit = 1,

        [Parameter(Mandatory = $false)]
        [string]$ActivityName = 'runspace workload',

        [Parameter(Mandatory = $false)]
        [switch]$DisableInAzure
    )

    if ($RequestedThrottleLimit -le 1) {
        return 1
    }

    if ($DisableInAzure -and (Test-IsAzureHostedEnvironment)) {
        Write-Information ("  {0}: forcing single-threaded execution in Azure-hosted environment." -f $ActivityName) -InformationAction Continue
        return 1
    }

    $processorCount = [Math]::Max(1, [System.Environment]::ProcessorCount)
    $effectiveThrottleLimit = [Math]::Min($RequestedThrottleLimit, $processorCount)
    if ($effectiveThrottleLimit -ne $RequestedThrottleLimit) {
        Write-Information ("  {0}: capping throttle from {1} to {2} based on local processor count." -f $ActivityName, $RequestedThrottleLimit, $effectiveThrottleLimit) -InformationAction Continue
    }

    return [int]$effectiveThrottleLimit
}

function New-ProgressMarkerState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only creates an in-memory progress tracking object.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ActivityName,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1000000)]
        [int]$ProgressInterval = 250000,

        [Parameter(Mandatory = $false)]
        [ValidateRange(15, 3600)]
        [int]$HeartbeatIntervalSeconds = 60,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1000000)]
        [int]$CheckInterval = 10000,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 9223372036854775807)]
        [long]$TotalCount = 0
    )

    return [PSCustomObject]@{
        ActivityName = $ActivityName
        ProgressInterval = $ProgressInterval
        HeartbeatIntervalSeconds = $HeartbeatIntervalSeconds
        CheckInterval = [Math]::Max(1, [Math]::Min($ProgressInterval, $CheckInterval))
        TotalCount = $TotalCount
        Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        LastHeartbeatSecond = -1
    }
}

function Format-ProgressRemainingTime {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [double]$Seconds
    )

    if ($Seconds -lt 1) {
        return '<1s'
    }

    $remaining = [TimeSpan]::FromSeconds([Math]::Ceiling($Seconds))
    if ($remaining.TotalDays -ge 1) {
        return ('{0}d {1}h {2}m' -f [int]$remaining.TotalDays, $remaining.Hours, $remaining.Minutes)
    }

    if ($remaining.TotalHours -ge 1) {
        return ('{0}h {1}m {2}s' -f [int]$remaining.TotalHours, $remaining.Minutes, $remaining.Seconds)
    }

    if ($remaining.TotalMinutes -ge 1) {
        return ('{0}m {1}s' -f [int]$remaining.TotalMinutes, $remaining.Seconds)
    }

    return ('{0}s' -f [int]$remaining.TotalSeconds)
}

function Write-ProgressMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $State,

        [Parameter(Mandatory = $true)]
        [long]$Count,

        [Parameter(Mandatory = $false)]
        [string]$UnitLabel = 'item(s)'
    )

    if ($null -eq $State -or $Count -le 0) {
        return
    }

    $markerType = 'progress'
    $shouldWrite = (($Count % [long]$State.ProgressInterval) -eq 0)
    if (-not $shouldWrite -and (($Count % [long]$State.CheckInterval) -eq 0)) {
        $elapsedWholeSeconds = [Math]::Floor($State.Stopwatch.Elapsed.TotalSeconds)
        if (($State.LastHeartbeatSecond + [int]$State.HeartbeatIntervalSeconds) -le $elapsedWholeSeconds) {
            $shouldWrite = $true
            $markerType = 'heartbeat'
        }
    }

    if (-not $shouldWrite) {
        return
    }

    $elapsedSeconds = [Math]::Max(0.001, $State.Stopwatch.Elapsed.TotalSeconds)
    $rawRate = ($Count / $elapsedSeconds)
    $rate = [Math]::Round($rawRate, 0)
    $markerSuffix = if ($markerType -eq 'heartbeat') { ' [heartbeat]' } else { '' }
    $totalCount = if ($State.PSObject.Properties['TotalCount']) { [long]$State.TotalCount } else { 0L }
    if ($totalCount -gt 0) {
        $boundedCount = [Math]::Min([long]$Count, $totalCount)
        $percentComplete = [Math]::Round(($boundedCount / [double]$totalCount) * 100.0, 1)
        $remainingCount = [Math]::Max(0L, ($totalCount - $boundedCount))
        $etaText = if ($remainingCount -gt 0 -and $rawRate -gt 0) {
            Format-ProgressRemainingTime -Seconds ($remainingCount / $rawRate)
        }
        else {
            $null
        }

        if ([string]::IsNullOrWhiteSpace($etaText)) {
            Write-Information ("  {0}: {1:N0}/{2:N0} {3} processed in {4:N1}s ({5:N0}/s, {6:N1}% complete){7}" -f $State.ActivityName, $boundedCount, $totalCount, $UnitLabel, [Math]::Round($elapsedSeconds, 1), $rate, $percentComplete, $markerSuffix) -InformationAction Continue
        }
        else {
            Write-Information ("  {0}: {1:N0}/{2:N0} {3} processed in {4:N1}s ({5:N0}/s, {6:N1}% complete, ETA {7}){8}" -f $State.ActivityName, $boundedCount, $totalCount, $UnitLabel, [Math]::Round($elapsedSeconds, 1), $rate, $percentComplete, $etaText, $markerSuffix) -InformationAction Continue
        }
    }
    else {
        Write-Information ("  {0}: {1:N0} {2} processed in {3:N1}s ({4:N0}/s){5}" -f $State.ActivityName, $Count, $UnitLabel, [Math]::Round($elapsedSeconds, 1), $rate, $markerSuffix) -InformationAction Continue
    }
    $State.LastHeartbeatSecond = [Math]::Floor($State.Stopwatch.Elapsed.TotalSeconds)
}

function Invoke-BoundedRunspacePool {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = 1,

        [Parameter(Mandatory = $false)]
        [string]$ActivityName = 'runspace workload',

        [Parameter(Mandatory = $false)]
        [switch]$DisableInAzure,

        [Parameter(Mandatory = $false)]
        [object[]]$ArgumentList = @()
    )

    $inputItems = @($InputObject)
    if ($inputItems.Count -eq 0) {
        return @()
    }

    $effectiveThrottleLimit = Resolve-RunspaceThrottleLimit -RequestedThrottleLimit $ThrottleLimit -ActivityName $ActivityName -DisableInAzure:$DisableInAzure
    if ($effectiveThrottleLimit -le 1 -or $inputItems.Count -eq 1) {
        $serialResults = [System.Collections.Generic.List[object]]::new()
        foreach ($inputItem in $inputItems) {
            $invocationResult = & $ScriptBlock $inputItem @ArgumentList
            foreach ($result in @($invocationResult)) {
                if ($null -ne $result) {
                    $serialResults.Add($result)
                }
            }
        }

        return @($serialResults)
    }

    Write-Information ("  {0}: using runspace pool x{1} for {2} work item(s)." -f $ActivityName, $effectiveThrottleLimit, $inputItems.Count) -InformationAction Continue

    $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $effectiveThrottleLimit, $initialSessionState, $Host)
    $runspacePool.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $runspacePool.ApartmentState = [System.Threading.ApartmentState]::MTA
    $runspacePool.Open()

    $pendingInvocations = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($inputItem in $inputItems) {
            $powershell = [System.Management.Automation.PowerShell]::Create()
            $powershell.RunspacePool = $runspacePool
            $null = $powershell.AddScript($ScriptBlock.ToString(), $true).AddArgument($inputItem)
            foreach ($argument in @($ArgumentList)) {
                $null = $powershell.AddArgument($argument)
            }

            $pendingInvocations.Add([PSCustomObject]@{
                    PowerShell = $powershell
                    AsyncResult = $powershell.BeginInvoke()
                })
        }
        $parallelResults = [System.Collections.Generic.List[object]]::new()
        foreach ($pendingInvocation in $pendingInvocations) {
            try {
                $invocationResult = $pendingInvocation.PowerShell.EndInvoke($pendingInvocation.AsyncResult)
                foreach ($result in @($invocationResult)) {
                    if ($null -ne $result) {
                        $parallelResults.Add($result)
                    }
                }
            }
            finally {
                $pendingInvocation.PowerShell.Dispose()
            }
        }

        return @($parallelResults)
    }
    finally {
        $runspacePool.Close()
        $runspacePool.Dispose()
    }
}

function Get-HttpHeaderStringValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        $Headers,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    if ($null -eq $Headers) {
        return ''
    }

    $headerEntries = @()
    try {
        $headerEntries = @($Headers.GetEnumerator())
    }
    catch {
        $headerEntries = @()
    }

    foreach ($name in $Names) {
        foreach ($entry in $headerEntries) {
            if (-not [string]::Equals([string]$entry.Key, $name, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            foreach ($value in @($entry.Value)) {
                $text = [string]$value
                if (-not [string]::IsNullOrWhiteSpace($text)) {
                    return $text
                }
            }
        }

        try {
            foreach ($value in @($Headers[$name])) {
                $text = [string]$value
                if (-not [string]::IsNullOrWhiteSpace($text)) {
                    return $text
                }
            }
        }
        catch {
            Write-Verbose "Could not read HTTP header '$name': $_"
        }
    }

    return ''
}

function ConvertTo-BoundedRetryDelayMillisecondsValue {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [long]$DelayMilliseconds
    )

    return [int][Math]::Min([long][int]::MaxValue, [Math]::Max(0L, $DelayMilliseconds))
}

function Get-HttpRetryDelayOverride {
    [CmdletBinding()]
    [OutputType([Nullable[int]])]
    param(
        [Parameter(Mandatory = $false)]
        $Headers,

        [Parameter(Mandatory = $false)]
        [datetimeoffset]$ReferenceTime = [datetimeoffset]::UtcNow
    )

    $retryAfterSecondsText = Get-HttpHeaderStringValue -Headers $Headers -Names @('Retry-After')
    if (-not [string]::IsNullOrWhiteSpace($retryAfterSecondsText)) {
        $retryAfterSeconds = 0L
        if ([long]::TryParse($retryAfterSecondsText, [ref]$retryAfterSeconds) -and $retryAfterSeconds -ge 0) {
            return (ConvertTo-BoundedRetryDelayMillisecondsValue -DelayMilliseconds ($retryAfterSeconds * 1000L))
        }

        $retryAfterTimestamp = [datetimeoffset]::MinValue
        if (
            [datetimeoffset]::TryParseExact(
                $retryAfterSecondsText,
                'r',
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AssumeUniversal,
                [ref]$retryAfterTimestamp
            )
        ) {
            $delayMilliseconds = [long][Math]::Ceiling(($retryAfterTimestamp.ToUniversalTime() - $ReferenceTime.ToUniversalTime()).TotalMilliseconds)
            return (ConvertTo-BoundedRetryDelayMillisecondsValue -DelayMilliseconds $delayMilliseconds)
        }
    }

    $retryAfterMillisecondsText = Get-HttpHeaderStringValue -Headers $Headers -Names @('retry-after-ms', 'x-ms-retry-after-ms')
    if (-not [string]::IsNullOrWhiteSpace($retryAfterMillisecondsText)) {
        $retryAfterMilliseconds = 0L
        if ([long]::TryParse($retryAfterMillisecondsText, [ref]$retryAfterMilliseconds) -and $retryAfterMilliseconds -ge 0) {
            return (ConvertTo-BoundedRetryDelayMillisecondsValue -DelayMilliseconds $retryAfterMilliseconds)
        }
    }

    return $null
}

function Get-SanitizedUriForLog {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Uri
    )

    if ([string]::IsNullOrWhiteSpace($Uri)) {
        return ''
    }

    $absoluteUri = $null
    if ([System.Uri]::TryCreate($Uri, [System.UriKind]::Absolute, [ref]$absoluteUri)) {
        if ($absoluteUri.IsFile) {
            return $absoluteUri.LocalPath
        }

        return $absoluteUri.GetLeftPart([System.UriPartial]::Path)
    }

    return $Uri
}

function Test-IsTransientTransportException {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [System.Exception]$Exception
    )

    if ($null -eq $Exception) {
        return $false
    }

    if ($Exception -is [System.TimeoutException] -or $Exception.InnerException -is [System.TimeoutException]) {
        return $true
    }

    $messageText = @(
        [string]$Exception.Message
        [string]$Exception.InnerException?.Message
    ) -join "`n"

    $transientPattern = 'ResponseEnded|response ended prematurely|An error occurred while sending the request|The underlying connection was closed|The request was canceled|timed out|A connection attempt failed|An existing connection was forcibly closed|connection reset|temporarily unavailable'
    if ($Exception -is [System.Net.Http.HttpRequestException]) {
        return ($messageText -match $transientPattern)
    }

    return ($messageText -match $transientPattern)
}

function Invoke-RestMethodWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = 'Get',

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false)]
        [object]$Body,

        [Parameter(Mandatory = $false)]
        [string]$ContentType,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [int]$InitialDelayMs = 1000,

        [Parameter(Mandatory = $false)]
        [double]$BackoffMultiplier = 2.0,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3600)]
        [int]$TimeoutSec,

        [Parameter(Mandatory = $false)]
        [switch]$RetryTransientTransportFailures
    )

    $attempt = 0
    $delay = $InitialDelayMs
    $requestUriForLog = Get-SanitizedUriForLog -Uri $Uri

    while ($true) {
        try {
            $attempt++
            $restParams = @{ Uri = $Uri; Method = $Method; ErrorAction = 'Stop' }
            if ($Headers) { $restParams['Headers'] = $Headers }
            if ($Body) { $restParams['Body'] = $Body }
            if ($ContentType) { $restParams['ContentType'] = $ContentType }
            if ($PSBoundParameters.ContainsKey('TimeoutSec')) { $restParams['TimeoutSec'] = $TimeoutSec }

            return Invoke-RestMethod @restParams
        }
        catch {
            $statusCode = $null
            if ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            elseif ($_.Exception -is [Microsoft.PowerShell.Commands.HttpResponseException]) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            $retryable = $statusCode -in @(408, 429, 500, 502, 503, 504)
            if (-not $retryable -and $RetryTransientTransportFailures) {
                $retryable = Test-IsTransientTransportException -Exception $_.Exception
            }

            if (-not $retryable -or $attempt -ge $MaxRetries) {
                throw
            }

            $waitMs = $delay
            try {
                if ($_.Exception.Response -and $_.Exception.Response.Headers) {
                    $retryDelayMilliseconds = Get-HttpRetryDelayOverride -Headers $_.Exception.Response.Headers
                    if ($null -ne $retryDelayMilliseconds) {
                        $waitMs = $retryDelayMilliseconds
                    }
                }
            }
            catch {
                Write-Verbose "Could not read retry delay headers: $_"
            }

            $failureLabel = if ($null -ne $statusCode) {
                "HTTP $statusCode"
            }
            else {
                $_.Exception.GetType().Name
            }

            Write-Warning ("API call failed for {0} (attempt {1}/{2}, {3}). Retrying in {4}s..." -f $requestUriForLog, $attempt, $MaxRetries, $failureLabel, [math]::Round($waitMs / 1000, 1))
            Start-Sleep -Milliseconds $waitMs
            $delay = [int]($delay * $BackoffMultiplier)
        }
    }
}

function Invoke-WebRequestWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$Method = 'Get',

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false)]
        [string]$OutFile,

        [Parameter(Mandatory = $false)]
        [string]$InFile,

        [Parameter(Mandatory = $false)]
        [string]$ContentType,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [int]$InitialDelayMs = 1000,

        [Parameter(Mandatory = $false)]
        [double]$BackoffMultiplier = 2.0,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3600)]
        [int]$TimeoutSec,

        [Parameter(Mandatory = $false)]
        [switch]$RetryTransientTransportFailures
    )

    $attempt = 0
    $delay = $InitialDelayMs
    $requestLabel = if ($Method -eq 'Get' -and $OutFile) {
        'Download'
    }
    else {
        'HTTP request'
    }
    $requestUriForLog = Get-SanitizedUriForLog -Uri $Uri

    while ($true) {
        try {
            $attempt++
            $webParams = @{ Uri = $Uri; Method = $Method; ErrorAction = 'Stop' }
            if ($Headers) { $webParams['Headers'] = $Headers }
            if ($OutFile) { $webParams['OutFile'] = $OutFile }
            if ($InFile) { $webParams['InFile'] = $InFile }
            if ($ContentType) { $webParams['ContentType'] = $ContentType }
            if ($PSBoundParameters.ContainsKey('TimeoutSec')) { $webParams['TimeoutSec'] = $TimeoutSec }

            return Invoke-WebRequest @webParams
        }
        catch {
            $statusCode = $null
            if ($_.Exception -is [System.Net.WebException] -and $_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            elseif ($_.Exception -is [Microsoft.PowerShell.Commands.HttpResponseException]) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            $retryable = $statusCode -in @(408, 429, 500, 502, 503, 504)
            if (-not $retryable -and $RetryTransientTransportFailures) {
                $retryable = Test-IsTransientTransportException -Exception $_.Exception
            }

            if (-not $retryable -or $attempt -ge $MaxRetries) {
                throw
            }

            $waitMs = $delay
            try {
                if ($_.Exception.Response -and $_.Exception.Response.Headers) {
                    $retryDelayMilliseconds = Get-HttpRetryDelayOverride -Headers $_.Exception.Response.Headers
                    if ($null -ne $retryDelayMilliseconds) {
                        $waitMs = $retryDelayMilliseconds
                    }
                }
            }
            catch {
                Write-Verbose "Could not read retry delay headers: $_"
            }

            $failureLabel = if ($null -ne $statusCode) {
                "HTTP $statusCode"
            }
            else {
                $_.Exception.GetType().Name
            }

            Write-Warning ("{0} failed for {1} (attempt {2}/{3}, {4}). Retrying in {5}s..." -f $requestLabel, $requestUriForLog, $attempt, $MaxRetries, $failureLabel, [math]::Round($waitMs / 1000, 1))
            Start-Sleep -Milliseconds $waitMs
            $delay = [int]($delay * $BackoffMultiplier)
        }
    }
}

function Get-StoreTransactionJournalPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName
    )

    return Join-Path -Path $BasePath -ChildPath (".{0}.transaction.json" -f $StoreName)
}

function Get-NormalizedAbsolutePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }

    return [System.IO.Path]::GetFullPath($Path)
}

function Test-PathIsUnderRoot {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$RootPath
    )

    $normalizedPath = Get-NormalizedAbsolutePath -Path $Path
    $normalizedRoot = Get-NormalizedAbsolutePath -Path $RootPath
    if ([string]::IsNullOrWhiteSpace($normalizedPath) -or [string]::IsNullOrWhiteSpace($normalizedRoot)) {
        return $false
    }

    $trimmedRoot = $normalizedRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    if ([string]::Equals($normalizedPath, $trimmedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    $rootPrefix = $trimmedRoot + [System.IO.Path]::DirectorySeparatorChar
    return $normalizedPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-StoreTransactionStateIsValid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $State,

        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName,

        [Parameter(Mandatory = $true)]
        [string]$JournalPath
    )

    if ($null -eq $State) {
        throw "Transaction journal '$JournalPath' is empty."
    }

    $journalLabel = "Transaction journal '$JournalPath'"
    $phase = [string]$State.PSObject.Properties['Phase']?.Value
    if ($phase -notin @('Prepared', 'Committed')) {
        throw "$journalLabel has invalid phase '$phase'."
    }

    $stateStoreName = [string]$State.PSObject.Properties['StoreName']?.Value
    if (-not [string]::IsNullOrWhiteSpace($stateStoreName) -and -not [string]::Equals($stateStoreName, $StoreName, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$journalLabel targets store '$stateStoreName' instead of '$StoreName'."
    }

    $transactionRoot = [string]$State.PSObject.Properties['TransactionRoot']?.Value
    if (-not (Test-PathIsUnderRoot -Path $transactionRoot -RootPath $BasePath)) {
        throw "$journalLabel references transaction root '$transactionRoot' outside '$BasePath'."
    }

    $targetPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $fileEntries = @($State.PSObject.Properties['Files']?.Value)
    $removedEntries = @($State.PSObject.Properties['RemovedFiles']?.Value)
    if (($fileEntries.Count + $removedEntries.Count) -eq 0) {
        throw "$journalLabel does not contain any staged or removed file entries."
    }

    foreach ($entry in $fileEntries) {
        $targetPath = [string]$entry.PSObject.Properties['TargetPath']?.Value
        $stagePath = [string]$entry.PSObject.Properties['StagePath']?.Value
        $backupPath = [string]$entry.PSObject.Properties['BackupPath']?.Value

        if (-not (Test-PathIsUnderRoot -Path $targetPath -RootPath $BasePath)) {
            throw "$journalLabel references staged target '$targetPath' outside '$BasePath'."
        }
        if (-not (Test-PathIsUnderRoot -Path $stagePath -RootPath $transactionRoot)) {
            throw "$journalLabel references staged file '$stagePath' outside '$transactionRoot'."
        }
        if (-not (Test-PathIsUnderRoot -Path $backupPath -RootPath $transactionRoot)) {
            throw "$journalLabel references backup file '$backupPath' outside '$transactionRoot'."
        }
        if (-not $targetPaths.Add((Get-NormalizedAbsolutePath -Path $targetPath))) {
            throw "$journalLabel contains duplicate target path '$targetPath'."
        }
    }

    foreach ($entry in $removedEntries) {
        $targetPath = [string]$entry.PSObject.Properties['TargetPath']?.Value
        $backupPath = [string]$entry.PSObject.Properties['BackupPath']?.Value

        if (-not (Test-PathIsUnderRoot -Path $targetPath -RootPath $BasePath)) {
            throw "$journalLabel references removed target '$targetPath' outside '$BasePath'."
        }
        if (-not (Test-PathIsUnderRoot -Path $backupPath -RootPath $transactionRoot)) {
            throw "$journalLabel references removed-file backup '$backupPath' outside '$transactionRoot'."
        }
        if (-not $targetPaths.Add((Get-NormalizedAbsolutePath -Path $targetPath))) {
            throw "$journalLabel contains duplicate target path '$targetPath'."
        }
    }
}

function Write-StoreTransactionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $State,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $State | ConvertTo-Json -Depth 20 | Set-Content -Path $Path -Encoding utf8
}

function Read-StoreTransactionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    return (Get-Content -Path $Path -Raw | ConvertFrom-Json -Depth 20)
}

function Remove-StoreTransactionArtifacts {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$JournalPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$TransactionRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($TransactionRoot) -and (Test-Path -LiteralPath $TransactionRoot)) {
        Remove-Item -LiteralPath $TransactionRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $JournalPath) {
        Remove-Item -LiteralPath $JournalPath -Force -ErrorAction SilentlyContinue
    }
}

function Restore-StoreTransaction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName
    )

    $journalPath = Get-StoreTransactionJournalPath -BasePath $BasePath -StoreName $StoreName
    $state = Read-StoreTransactionState -Path $journalPath
    if ($null -eq $state) {
        return
    }

    Assert-StoreTransactionStateIsValid -State $state -BasePath $BasePath -StoreName $StoreName -JournalPath $journalPath

    $phase = [string]$state.Phase
    if ($phase -eq 'Committed') {
        Remove-StoreTransactionArtifacts -JournalPath $journalPath -TransactionRoot ([string]$state.TransactionRoot)
        return
    }

    foreach ($file in @($state.Files)) {
        $targetPath = [string]$file.TargetPath
        $stagePath = [string]$file.StagePath
        $backupPath = [string]$file.BackupPath
        $targetExisted = ($file.TargetExisted -eq $true)

        if ($targetExisted -and (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
            if (Test-Path -LiteralPath $targetPath -PathType Leaf) {
                Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
            }
            Move-Item -LiteralPath $backupPath -Destination $targetPath -Force
        }
        elseif ((-not $targetExisted) -and (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
            Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
        }

        if (Test-Path -LiteralPath $stagePath -PathType Leaf) {
            Remove-Item -LiteralPath $stagePath -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($removed in @($state.RemovedFiles)) {
        $targetPath = [string]$removed.TargetPath
        $backupPath = [string]$removed.BackupPath

        if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
            if (Test-Path -LiteralPath $targetPath -PathType Leaf) {
                Remove-Item -LiteralPath $targetPath -Force -ErrorAction SilentlyContinue
            }
            Move-Item -LiteralPath $backupPath -Destination $targetPath -Force
        }
    }

    Remove-StoreTransactionArtifacts -JournalPath $journalPath -TransactionRoot ([string]$state.TransactionRoot)
}

function Publish-StoreFilesTransactional {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$StoreName,

        [Parameter(Mandatory = $true)]
        [object[]]$Files,

        [Parameter(Mandatory = $false)]
        [string[]]$RemovePaths
    )

    Restore-StoreTransaction -BasePath $BasePath -StoreName $StoreName

    $transactionRoot = Join-Path $BasePath ('.' + $StoreName + '-transaction-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $transactionRoot -ItemType Directory -Force)

    $journalPath = Get-StoreTransactionJournalPath -BasePath $BasePath -StoreName $StoreName
    $targetPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $fileEntries = [System.Collections.Generic.List[object]]::new()
    $removedEntries = [System.Collections.Generic.List[object]]::new()
    $index = 0

    foreach ($file in @($Files)) {
        $targetPath = [string]$file.TargetPath
        [void]$targetPaths.Add($targetPath)

        $fileEntries.Add([PSCustomObject]@{
            TargetPath = $targetPath
            StagePath = [string]$file.StagePath
            BackupPath = Join-Path $transactionRoot ('replace-' + $index + '-' + [System.IO.Path]::GetFileName($targetPath) + '.bak')
            TargetExisted = (Test-Path -LiteralPath $targetPath -PathType Leaf)
        })
        $index++
    }

    $removeIndex = 0
    foreach ($removePath in @($RemovePaths)) {
        if ([string]::IsNullOrWhiteSpace($removePath)) { continue }
        if ($targetPaths.Contains($removePath)) { continue }
        if (-not (Test-Path -LiteralPath $removePath -PathType Leaf)) { continue }

        $removedEntries.Add([PSCustomObject]@{
            TargetPath = $removePath
            BackupPath = Join-Path $transactionRoot ('remove-' + $removeIndex + '-' + [System.IO.Path]::GetFileName($removePath) + '.bak')
        })
        $removeIndex++
    }

    $state = [PSCustomObject]@{
        StoreName = $StoreName
        TransactionRoot = $transactionRoot
        Phase = 'Prepared'
        Files = @($fileEntries)
        RemovedFiles = @($removedEntries)
    }
    Write-StoreTransactionState -State $state -Path $journalPath

    try {
        foreach ($entry in @($fileEntries)) {
            if ($entry.TargetExisted) {
                [System.IO.File]::Replace($entry.StagePath, $entry.TargetPath, $entry.BackupPath, $true)
            }
            else {
                Move-Item -LiteralPath $entry.StagePath -Destination $entry.TargetPath -Force
            }
        }

        foreach ($entry in @($removedEntries)) {
            Move-Item -LiteralPath $entry.TargetPath -Destination $entry.BackupPath -Force
        }

        $state.Phase = 'Committed'
        Write-StoreTransactionState -State $state -Path $journalPath
        Remove-StoreTransactionArtifacts -JournalPath $journalPath -TransactionRoot $transactionRoot
    }
    catch {
        Restore-StoreTransaction -BasePath $BasePath -StoreName $StoreName
        throw
    }
}

function Get-VulnPropertyValue {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCmdletCorrectly', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [Newtonsoft.Json.Linq.JObject]) {
        $token = $InputObject[$Name]
        if ($null -eq $token) { return $null }
        if ($token -is [Newtonsoft.Json.Linq.JValue]) { return $token.Value }
        Write-Output -NoEnumerate $token
        return
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if (-not $InputObject.Contains($Name)) { return $null }
        $value = $InputObject[$Name]
        if ($value -is [Newtonsoft.Json.Linq.JValue]) { return $value.Value }
        if ($value -is [Newtonsoft.Json.Linq.JToken]) {
            Write-Output -NoEnumerate $value
            return
        }
        if ($value -is [System.Array]) {
            Write-Output -NoEnumerate $value
            return
        }
        return $value
    }

    $psProperties = $InputObject.PSObject.Properties
    if ($null -eq $psProperties) { return $null }

    $propertyMatches = $psProperties.Match($Name)
    if ($null -eq $propertyMatches -or $propertyMatches.Count -eq 0) { return $null }

    $property = $propertyMatches[0]
    if ($null -eq $property) { return $null }
    if ($property.Value -is [Newtonsoft.Json.Linq.JValue]) { return $property.Value.Value }
    if ($property.Value -is [Newtonsoft.Json.Linq.JToken]) {
        Write-Output -NoEnumerate $property.Value
        return
    }
    if ($property.Value -is [System.Array]) {
        Write-Output -NoEnumerate $property.Value
        return
    }
    return $property.Value
}

function Test-VulnPropertyPresence {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $false }

    if ($InputObject -is [Newtonsoft.Json.Linq.JObject]) {
        return ($null -ne $InputObject.Property($Name))
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject.Contains($Name)
    }

    $psProperties = $InputObject.PSObject.Properties
    if ($null -eq $psProperties) { return $false }

    $propertyMatches = $psProperties.Match($Name)
    return ($null -ne $propertyMatches -and $propertyMatches.Count -gt 0)
}

function Convert-VulnObjectToCompactJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $false)]
        [int]$Depth = 100
    )

    if ($null -eq $InputObject) {
        return 'null'
    }

    if ($InputObject -is [Newtonsoft.Json.Linq.JToken]) {
        return $InputObject.ToString([Newtonsoft.Json.Formatting]::None)
    }

    return ($InputObject | ConvertTo-Json -Compress -Depth $Depth)
}

function Get-VulnCurrentPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:VulnCurrentFileName
}

function Get-VulnContentDictionaryPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:VulnContentDictionaryFileName
}

function Get-VulnCurrentRefsPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return Join-Path -Path $BasePath -ChildPath $Script:VulnCurrentRefsFileName
}

function Get-VulnHistoryRefsPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    return Join-Path -Path $BasePath -ChildPath ([string]::Format($Script:VulnHistoryRefsFileNamePattern, $PeriodKey))
}

function Test-VulnStoreExistence {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if (Test-Path -Path (Get-VulnCurrentPath -BasePath $BasePath)) {
        return $true
    }

    $historyFiles = @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue)
    return $historyFiles.Count -gt 0
}

function Test-VulnContentStoreExistence {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $dictionaryPath = Get-VulnContentDictionaryPath -BasePath $BasePath
    if (-not (Test-Path -LiteralPath $dictionaryPath -PathType Leaf)) {
        return $false
    }

    $currentRefsPath = Get-VulnCurrentRefsPath -BasePath $BasePath
    if (-not (Test-Path -LiteralPath $currentRefsPath -PathType Leaf)) {
        return $false
    }

    $historyPeriodKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($historyRowsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $match = [regex]::Match($historyRowsFile.Name, '^VulnHistoryRows_(?<period>\d{4}Q[1-4]|\d{4})\.json\.gz$')
        if (-not $match.Success) { continue }
        [void]$historyPeriodKeys.Add($match.Groups['period'].Value)
    }

    foreach ($historyFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $match = [regex]::Match($historyFile.Name, '^VulnHistory_(?<period>\d{4}Q[1-4]|\d{4})\.json\.gz$')
        if (-not $match.Success) { continue }
        [void]$historyPeriodKeys.Add($match.Groups['period'].Value)
    }

    foreach ($periodKey in @($historyPeriodKeys | Sort-Object)) {
        $historyRefsPath = Get-VulnHistoryRefsPath -BasePath $BasePath -PeriodKey $periodKey
        if (-not (Test-Path -LiteralPath $historyRefsPath -PathType Leaf)) {
            return $false
        }
    }

    return $true
}

function Test-IsSyntheticDataset {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return (Test-Path -LiteralPath (Join-Path $BasePath 'synthetic-manifest.json') -PathType Leaf)
}

function New-QuarterPeriodKey {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Year,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 4)]
        [int]$Quarter
    )

    return ('{0:D4}Q{1}' -f $Year, $Quarter)
}

function Get-QuarterNumberFromDate {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    $month = ([datetime]$Date).Month
    return [int][math]::Ceiling($month / 3)
}

function Get-QuarterPeriodKeyFromDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    $dt = [datetime]$Date
    return (New-QuarterPeriodKey -Year $dt.Year -Quarter (Get-QuarterNumberFromDate -Date $Date))
}

function Get-QuarterPeriodInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    $match = [regex]::Match($PeriodKey, '^(?<year>\d{4})Q(?<quarter>[1-4])$')
    if (-not $match.Success) {
        throw "Invalid vulnerability history period key '$PeriodKey'."
    }

    return [PSCustomObject]@{
        PeriodKey = $PeriodKey
        Year = [int]$match.Groups['year'].Value
        Quarter = [int]$match.Groups['quarter'].Value
    }
}

function New-VulnHistoryPeriodKey {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Year,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 4)]
        [int]$Quarter
    )

    return (New-QuarterPeriodKey -Year $Year -Quarter $Quarter)
}

function Get-VulnHistoryQuarterFromDate {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    return (Get-QuarterNumberFromDate -Date $Date)
}

function Get-VulnHistoryPeriodKeyFromDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    return (Get-QuarterPeriodKeyFromDate -Date $Date)
}

function Get-VulnHistoryPeriodInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    return (Get-QuarterPeriodInfo -PeriodKey $PeriodKey)
}

function Get-VulnHistoryPeriodKeyFromDocument {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $period = [string](Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'period')
    if (-not [string]::IsNullOrWhiteSpace($period)) {
        return $period
    }

    $yearValue = Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'year'
    $quarterValue = Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'quarter'
    if ($null -ne $yearValue -and $null -ne $quarterValue) {
        return (New-VulnHistoryPeriodKey -Year ([int]$yearValue) -Quarter ([int]$quarterValue))
    }

    return $null
}

function Convert-VulnHistoryDocumentToQuarterlyDocuments {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $existingPeriodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $HistoryDocument
    if (-not [string]::IsNullOrWhiteSpace($existingPeriodKey)) {
        $periodInfo = Get-VulnHistoryPeriodInfo -PeriodKey $existingPeriodKey
        $latestDate = Get-VulnHistoryDocumentLatestDate -HistoryDocument $HistoryDocument
        $existingSnapshots = [System.Collections.Generic.List[object]]::new()
        foreach ($snapshot in @(Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'snapshots')) {
            if ($null -eq $snapshot) { continue }
            $existingSnapshots.Add($snapshot)
        }

        return @([PSCustomObject]@{
            year = $periodInfo.Year
            quarter = $periodInfo.Quarter
            period = $periodInfo.PeriodKey
            latestDate = $latestDate
            snapshots = @($existingSnapshots)
        })
    }

    $documentsByPeriod = @{}
    $latestByPeriod = @{}
    foreach ($snapshot in (Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'snapshots')) {
        if ($null -eq $snapshot) { continue }
        $snapshotDate = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
        if ([string]::IsNullOrWhiteSpace($snapshotDate)) { continue }

        $periodKey = Get-VulnHistoryPeriodKeyFromDate -Date $snapshotDate
        if (-not $documentsByPeriod.ContainsKey($periodKey)) {
            $periodInfo = Get-VulnHistoryPeriodInfo -PeriodKey $periodKey
            $documentsByPeriod[$periodKey] = [ordered]@{
                year = $periodInfo.Year
                quarter = $periodInfo.Quarter
                period = $periodInfo.PeriodKey
                latestDate = ''
                snapshots = [System.Collections.Generic.List[object]]::new()
            }
        }

        $documentsByPeriod[$periodKey].snapshots.Add($snapshot)
        $latestByPeriod[$periodKey] = Get-MaxVulnDate -Primary ([string]$latestByPeriod[$periodKey]) -Secondary $snapshotDate
    }

    foreach ($periodKey in @($documentsByPeriod.Keys)) {
        $periodDocument = $documentsByPeriod[$periodKey]
        $documentsByPeriod[$periodKey] = [PSCustomObject]@{
            year = $periodDocument.year
            quarter = $periodDocument.quarter
            period = $periodDocument.period
            latestDate = [string]$latestByPeriod[$periodKey]
            snapshots = @($periodDocument.snapshots)
        }
    }

    return @($documentsByPeriod.Values | Sort-Object period)
}

function Get-VulnHistoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$PeriodKey,

        [Parameter(Mandatory = $false)]
        [int]$Year
    )

    if ([string]::IsNullOrWhiteSpace($PeriodKey)) {
        $PeriodKey = [string]$Year
    }

    return Join-Path -Path $BasePath -ChildPath ([string]::Format($Script:VulnHistoryFileNamePattern, $PeriodKey))
}

function Get-VulnHistoryRowsPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$PeriodKey,

        [Parameter(Mandatory = $false)]
        [int]$Year
    )

    if ([string]::IsNullOrWhiteSpace($PeriodKey)) {
        $PeriodKey = [string]$Year
    }

    return Join-Path -Path $BasePath -ChildPath ([string]::Format($Script:VulnHistoryRowsFileNamePattern, $PeriodKey))
}

function Test-IsVulnHistoryFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^VulnHistory_(?:\d{4}Q[1-4]|\d{4})\.json\.gz$')
}

function Test-IsVulnHistoryRowsFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^VulnHistoryRows_(?:\d{4}Q[1-4]|\d{4})\.json\.gz$')
}

function Test-IsVulnHistoryRefsFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^VulnHistoryRefs_(?:\d{4}Q[1-4]|\d{4})\.json\.gz$')
}

function Get-VulnHistoryPublishedNameSet {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$PeriodKeys
    )

    $publishedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($periodKey in @($PeriodKeys | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($periodKey)) { continue }
        [void]$publishedNames.Add([string]::Format($Script:VulnHistoryFileNamePattern, $periodKey))
        [void]$publishedNames.Add([string]::Format($Script:VulnHistoryRowsFileNamePattern, $periodKey))
        [void]$publishedNames.Add([string]::Format($Script:VulnHistoryRefsFileNamePattern, $periodKey))
    }

    return ,$publishedNames
}

function Get-VulnHistoryRemovePaths {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.Generic.HashSet[string]]$PublishedHistoryNames
    )

    if ($null -eq $PublishedHistoryNames) {
        $PublishedHistoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    $removePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($path in @(
        Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue |
            Where-Object { -not $PublishedHistoryNames.Contains($_.Name) } |
            ForEach-Object { $_.FullName }
    )) {
        $removePaths.Add($path)
    }

    foreach ($path in @(
        Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue |
            Where-Object { -not $PublishedHistoryNames.Contains($_.Name) } |
            ForEach-Object { $_.FullName }
    )) {
        $removePaths.Add($path)
    }

    foreach ($path in @(
        Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue |
            Where-Object { -not $PublishedHistoryNames.Contains($_.Name) } |
            ForEach-Object { $_.FullName }
    )) {
        $removePaths.Add($path)
    }

    return [string[]]@($removePaths)
}

function Test-IsCanonicalExportStoreFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Name -in @(
        $Script:VulnCurrentFileName,
        $Script:VulnContentDictionaryFileName,
        $Script:VulnCurrentRefsFileName,
        $Script:MachineCurrentFileName,
        $Script:AdvancedHuntingCurrentFileName,
        $Script:NvdCveCurrentFileName
    )) {
        return $true
    }

    if ((Test-IsVulnHistoryFileName -Name $Name) -or (Test-IsVulnHistoryRowsFileName -Name $Name) -or (Test-IsVulnHistoryRefsFileName -Name $Name)) {
        return $true
    }

    if (Test-IsMachineHistoryQuarterlyFileName -Name $Name) {
        return $true
    }

    return $false
}

function Test-IsNativeCompressedStoreFileName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (Test-IsCanonicalExportStoreFileName -Name $Name) {
        return $true
    }

    if ((Test-IsMachineHistorySegmentFileName -Name $Name) -or ($Name -eq $Script:MachineHistoryFileName)) {
        return $true
    }

    return $false
}

function Get-CanonicalExportStoreFileNames {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    return [string[]]@(
        Get-ChildItem -Path $BasePath -File -ErrorAction SilentlyContinue |
            Where-Object { Test-IsCanonicalExportStoreFileName -Name $_.Name } |
            Sort-Object Name |
            ForEach-Object { $_.Name }
    )
}

function Resolve-RelativeExportArtifactName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $normalizedName = $Name.Replace('\', '/')
    while ($normalizedName.StartsWith('./', [System.StringComparison]::Ordinal)) {
        $normalizedName = $normalizedName.Substring(2)
    }

    return $normalizedName
}

function Test-IsExportTransferArtifactName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $normalizedName = Resolve-RelativeExportArtifactName -Name $Name
    if ([string]::IsNullOrWhiteSpace($normalizedName)) {
        return $false
    }

    return (
        (Test-IsCanonicalExportStoreFileName -Name $normalizedName) -or
        (Test-IsLegacyVulnSnapshotFileName -Name $normalizedName) -or
        ($normalizedName -eq 'synthetic-manifest.json')
    )
}

function Test-IsTransientExportArtifactName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $normalizedName = Resolve-RelativeExportArtifactName -Name $Name
    if ([string]::IsNullOrWhiteSpace($normalizedName)) {
        return $false
    }

    return (
        ($normalizedName -like '.dashboard-cache/*') -or
        ($normalizedName -match '(^|/)\.vuln-content-store-staging-[^/]+(?:/|$)') -or
        ($normalizedName -match '(^|/)\.VulnExport_\d+_\d{4}-\d{2}-\d{2}(?:_part_\d+)?\.json(?:\.gz)?\.partial$') -or
        ($normalizedName -in @(
            '.synthetic-progress.json',
            '.synthetic-progress.json.gz',
            'stress-validation-report.json',
            'stress-validation-report.json.gz'
        ))
    )
}

function Get-ExportTransferArtifactNames {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @(Get-CanonicalExportStoreFileNames -BasePath $BasePath)) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $names.Add($name)
        }
    }

    foreach ($name in @(
        Get-ChildItem -Path $BasePath -Filter 'VulnExport_*' -File -ErrorAction SilentlyContinue |
            Where-Object { Test-IsLegacyVulnSnapshotFileName -Name $_.Name } |
            Sort-Object Name |
            ForEach-Object { $_.Name }
    )) {
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $names.Add($name)
        }
    }

    $syntheticManifestPath = Join-Path -Path $BasePath -ChildPath 'synthetic-manifest.json'
    if (Test-Path -LiteralPath $syntheticManifestPath -PathType Leaf) {
        $names.Add('synthetic-manifest.json')
    }

    return [string[]]@($names | Sort-Object -Unique)
}

function Clear-StaleLocalExportArtifact {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$KeepNames = @()
    )

    if (-not (Test-Path -LiteralPath $BasePath -PathType Container)) {
        return
    }

    $keepNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($KeepNames)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        [void]$keepNameSet.Add((Resolve-RelativeExportArtifactName -Name $name))
    }

    $pathsToRemove = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(Get-ChildItem -Path $BasePath -Force -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
        $relativeName = [System.IO.Path]::GetRelativePath($BasePath, $item.FullName).Replace('\', '/')
        if ($keepNameSet.Contains($relativeName)) {
            continue
        }

        if ($item.PSIsContainer) {
            if (Test-IsTransientExportArtifactName -Name ($relativeName + '/')) {
                $pathsToRemove.Add($item.FullName)
            }
            continue
        }

        if ((Test-IsTransientExportArtifactName -Name $relativeName) -or ((Test-IsExportTransferArtifactName -Name $relativeName) -and -not $keepNameSet.Contains($relativeName))) {
            $pathsToRemove.Add($item.FullName)
        }
    }

    foreach ($path in @($pathsToRemove | Sort-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            continue
        }

        if ($item.PSIsContainer) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-StaleExportStoreArtifactNames {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ExistingNames,

        [Parameter(Mandatory = $true)]
        [string[]]$CanonicalNames
    )

    $canonicalNameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @($CanonicalNames)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        [void]$canonicalNameSet.Add($name)
    }

    $staleNames = [System.Collections.Generic.List[string]]::new()
    foreach ($name in @($ExistingNames | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($canonicalNameSet.Contains($name)) { continue }

        if (
            (Test-IsExportTransferArtifactName -Name $name) -or
            (Test-IsTransientExportArtifactName -Name $name) -or
            (Test-IsVulnHistoryFileName -Name $name) -or
            (Test-IsVulnHistoryRowsFileName -Name $name) -or
            (Test-IsVulnHistoryRefsFileName -Name $name) -or
            (Test-IsMachineHistoryQuarterlyFileName -Name $name) -or
            (Test-IsMachineHistorySegmentFileName -Name $name) -or
            ($name -eq $Script:MachineHistoryFileName)
        ) {
            $staleNames.Add($name)
        }
    }

    return [string[]]@($staleNames)
}

function Test-IsLegacyVulnSnapshotFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -match '^VulnExport_\d+_\d{4}-\d{2}-\d{2}(?:_part_\d+)?\.json(?:\.gz)?$')
}

function Get-VulnSnapshotDateFromName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $match = [regex]::Match($Name, '\d{4}-\d{2}-\d{2}')
    if (-not $match.Success) {
        throw "Unable to parse snapshot date from '$Name'."
    }

    return $match.Value
}

function Get-VulnLegacySnapshotFile {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$LegacyFilePaths
    )

    $resolvedLegacyFilePaths = @($LegacyFilePaths | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

    if ($resolvedLegacyFilePaths.Count -gt 0) {
        return [System.IO.FileInfo[]]@(
            $resolvedLegacyFilePaths |
                ForEach-Object {
                    if (Test-Path -LiteralPath $_ -PathType Leaf) {
                        Get-Item -LiteralPath $_
                    }
                } |
                Where-Object { $null -ne $_ -and (Test-IsLegacyVulnSnapshotFileName -Name $_.Name) } |
                Sort-Object Name
        )
    }

    return [System.IO.FileInfo[]]@(
        Get-ChildItem -Path $BasePath -Filter 'VulnExport_*' -File -ErrorAction SilentlyContinue |
            Where-Object { Test-IsLegacyVulnSnapshotFileName -Name $_.Name } |
            Sort-Object Name
    )
}

function Convert-VulnToYmdDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$DateValue
    )

    return (Convert-ToYmdDate -DateValue $DateValue)
}

function Get-VulnNextDay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    return ([datetime]$Date).AddDays(1).ToString('yyyy-MM-dd')
}

function Get-VulnPreviousDay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Date
    )

    return ([datetime]$Date).AddDays(-1).ToString('yyyy-MM-dd')
}

function Get-MaxVulnDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Primary,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Secondary
    )

    if ([string]::IsNullOrWhiteSpace($Primary)) { return $Secondary }
    if ([string]::IsNullOrWhiteSpace($Secondary)) { return $Primary }
    if ([datetime]$Primary -ge [datetime]$Secondary) { return $Primary }
    return $Secondary
}

function Get-MinVulnDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Primary,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Secondary
    )

    if ([string]::IsNullOrWhiteSpace($Primary)) { return $Secondary }
    if ([string]::IsNullOrWhiteSpace($Secondary)) { return $Primary }
    if ([datetime]$Primary -le [datetime]$Secondary) { return $Primary }
    return $Secondary
}

function Get-NormalizedVulnSeenWindow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$FirstSeenValue,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$LastSeenValue
    )

    $firstSeen = Convert-VulnToYmdDate -DateValue $FirstSeenValue
    $lastSeen = Convert-VulnToYmdDate -DateValue $LastSeenValue
    $wasReordered = $false

    if ($firstSeen -and $lastSeen -and [datetime]$firstSeen -gt [datetime]$lastSeen) {
        $temp = $firstSeen
        $firstSeen = $lastSeen
        $lastSeen = $temp
        $wasReordered = $true
    }

    return [PSCustomObject]@{
        FirstSeenTimestamp = $firstSeen
        LastSeenTimestamp = $lastSeen
        WasReordered = $wasReordered
    }
}

function Get-VulnCanonicalRowSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    # Use only the stable vulnerability identity for versioning. Volatile enrichment
    # fields such as OS version, recommendations, and paths can change between
    # snapshots without indicating that the vulnerability itself disappeared.
    $id = [string](Get-VulnPropertyValue -InputObject $Row -Name 'Id')
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        return $id
    }

    $payload = [ordered]@{
        DeviceId = [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceId')
        CveId = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveId')
        SoftwareVendor = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVendor')
        SoftwareName = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareName')
        SoftwareVersion = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVersion')
    }

    return ($payload | ConvertTo-Json -Compress -Depth 20)
}

function Copy-VulnRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Record
    )

    $copy = [ordered]@{}
    foreach ($prop in $Record.PSObject.Properties) {
        $copy[$prop.Name] = $prop.Value
    }
    return [PSCustomObject]$copy
}

function New-ClosedVulnEntry {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter(Mandatory = $true)]
        [ValidateSet('removed', 'changed')]
        [string]$Reason,

        [Parameter(Mandatory = $true)]
        [string]$ClosedOn,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$ReplacementId
    )

    $row = Copy-VulnRecord -Record $Record
    $seenWindow = Get-NormalizedVulnSeenWindow `
        -FirstSeenValue (Get-VulnPropertyValue -InputObject $row -Name 'FirstSeenTimestamp') `
        -LastSeenValue (Get-VulnPropertyValue -InputObject $row -Name 'LastSeenTimestamp')
    $boundedLastSeen = if ($seenWindow.LastSeenTimestamp) { Get-MinVulnDate -Primary $seenWindow.LastSeenTimestamp -Secondary $ClosedOn } else { $ClosedOn }
    $boundedFirstSeen = if ($seenWindow.FirstSeenTimestamp) { Get-MinVulnDate -Primary $seenWindow.FirstSeenTimestamp -Secondary $boundedLastSeen } else { $boundedLastSeen }
    $row.FirstSeenTimestamp = $boundedFirstSeen
    $row.LastSeenTimestamp = $boundedLastSeen

    $entry = [ordered]@{
        reason = $Reason
        row = $row
    }

    if (-not [string]::IsNullOrWhiteSpace($ReplacementId)) {
        $entry.replacementId = $ReplacementId
    }

    return [PSCustomObject]$entry
}

function New-OpenVulnRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Record,

        [Parameter(Mandatory = $true)]
        [string]$VersionStartDate
    )

    $open = Copy-VulnRecord -Record $Record
    $seenWindow = Get-NormalizedVulnSeenWindow `
        -FirstSeenValue (Get-VulnPropertyValue -InputObject $open -Name 'FirstSeenTimestamp') `
        -LastSeenValue (Get-VulnPropertyValue -InputObject $open -Name 'LastSeenTimestamp')
    $open.FirstSeenTimestamp = if ($seenWindow.FirstSeenTimestamp) { Get-MaxVulnDate -Primary $seenWindow.FirstSeenTimestamp -Secondary $VersionStartDate } else { $VersionStartDate }
    $open.LastSeenTimestamp = if ($seenWindow.LastSeenTimestamp) { Get-MaxVulnDate -Primary $seenWindow.LastSeenTimestamp -Secondary $open.FirstSeenTimestamp } else { $open.FirstSeenTimestamp }
    return $open
}

function Get-VulnHistorySeed {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    $periodInfo = Get-VulnHistoryPeriodInfo -PeriodKey $PeriodKey
    return [ordered]@{
        year = $periodInfo.Year
        quarter = $periodInfo.Quarter
        period = $periodInfo.PeriodKey
        latestDate = ''
        snapshots = @()
    }
}

function Get-VulnHistorySnapshotMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $map = @{}
    foreach ($snapshot in (Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'snapshots')) {
        if ($null -eq $snapshot) { continue }
        $map[[string](Get-VulnPropertyValue -InputObject $snapshot -Name 'date')] = $snapshot
    }
    return $map
}

function Read-GzipTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 2
        $bytesRead = $fileStream.Read($header, 0, $header.Length)
        $fileStream.Position = 0

        if (($bytesRead -ne 2) -or $header[0] -ne 0x1f -or $header[1] -ne 0x8b) {
            $plainReader = [System.IO.StreamReader]::new($fileStream, [System.Text.UTF8Encoding]::new($false), $true)
            try {
                return $plainReader.ReadToEnd()
            }
            finally {
                $plainReader.Dispose()
            }
        }

        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $reader = [System.IO.StreamReader]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                return $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Read-GzipTextFilePrefix {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [int]$MaxChars = 4096
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 2
        $bytesRead = $fileStream.Read($header, 0, $header.Length)
        $fileStream.Position = 0

        $contentStream = if (($bytesRead -eq 2) -and $header[0] -eq 0x1f -and $header[1] -eq 0x8b) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $buffer = New-Object char[] $MaxChars
                $charsRead = $reader.Read($buffer, 0, $buffer.Length)
                if ($charsRead -le 0) {
                    return ''
                }

                return [string]::new($buffer, 0, $charsRead)
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            if ($contentStream -ne $fileStream) {
                $contentStream.Dispose()
            }
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-GzipTextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $writer.Write($Content)
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Read-VulnNdjsonLinesFromPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        try {
            $buffer = New-Object byte[] 65536
            $carryStream = [System.IO.MemoryStream]::new()
            try {
                while (($bytesRead = $contentStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $segmentStart = 0
                    for ($index = 0; $index -lt $bytesRead; $index++) {
                        if ($buffer[$index] -ne 0x0A) { continue }

                        $segmentLength = $index - $segmentStart
                        if ($segmentLength -gt 0 -and $buffer[$index - 1] -eq 0x0D) {
                            $segmentLength--
                        }

                        if ($carryStream.Length -gt 0) {
                            if ($segmentLength -gt 0) {
                                $carryStream.Write($buffer, $segmentStart, $segmentLength)
                            }

                            if ($carryStream.Length -gt 0) {
                                $line = [System.Text.Encoding]::UTF8.GetString($carryStream.ToArray())
                                if (-not [string]::IsNullOrWhiteSpace($line)) {
                                    $line
                                }
                            }

                            $carryStream.SetLength(0)
                        }
                        elseif ($segmentLength -gt 0) {
                            $line = [System.Text.Encoding]::UTF8.GetString($buffer, $segmentStart, $segmentLength)
                            if (-not [string]::IsNullOrWhiteSpace($line)) {
                                $line
                            }
                        }

                        $segmentStart = $index + 1
                    }

                    $remainingLength = $bytesRead - $segmentStart
                    if ($remainingLength -gt 0) {
                        $carryStream.Write($buffer, $segmentStart, $remainingLength)
                    }
                }

                if ($carryStream.Length -gt 0) {
                    $lineBytes = $carryStream.ToArray()
                    $lineLength = $lineBytes.Length
                    if ($lineLength -gt 0 -and $lineBytes[$lineLength - 1] -eq 0x0D) {
                        $lineLength--
                    }

                    if ($lineLength -gt 0) {
                        $line = [System.Text.Encoding]::UTF8.GetString($lineBytes, 0, $lineLength)
                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            $line
                        }
                    }
                }
            }
            finally {
                $carryStream.Dispose()
            }
        }
        finally {
            if ($contentStream -ne $fileStream) {
                $contentStream.Dispose()
            }
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Invoke-VulnNdjsonLineAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        try {
            $buffer = New-Object byte[] 65536
            $carryStream = [System.IO.MemoryStream]::new()
            try {
                while (($bytesRead = $contentStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $segmentStart = 0
                    for ($index = 0; $index -lt $bytesRead; $index++) {
                        if ($buffer[$index] -ne 0x0A) { continue }

                        $segmentLength = $index - $segmentStart
                        if ($segmentLength -gt 0 -and $buffer[$index - 1] -eq 0x0D) {
                            $segmentLength--
                        }

                        $line = $null
                        if ($carryStream.Length -gt 0) {
                            if ($segmentLength -gt 0) {
                                $carryStream.Write($buffer, $segmentStart, $segmentLength)
                            }

                            if ($carryStream.Length -gt 0) {
                                $line = [System.Text.Encoding]::UTF8.GetString($carryStream.ToArray())
                            }
                            $carryStream.SetLength(0)
                        }
                        elseif ($segmentLength -gt 0) {
                            $line = [System.Text.Encoding]::UTF8.GetString($buffer, $segmentStart, $segmentLength)
                        }

                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            & $Action $line
                        }

                        $segmentStart = $index + 1
                    }

                    $remainingLength = $bytesRead - $segmentStart
                    if ($remainingLength -gt 0) {
                        $carryStream.Write($buffer, $segmentStart, $remainingLength)
                    }
                }

                if ($carryStream.Length -gt 0) {
                    $lineBytes = $carryStream.ToArray()
                    $lineLength = $lineBytes.Length
                    if ($lineLength -gt 0 -and $lineBytes[$lineLength - 1] -eq 0x0D) {
                        $lineLength--
                    }

                    if ($lineLength -gt 0) {
                        $line = [System.Text.Encoding]::UTF8.GetString($lineBytes, 0, $lineLength)
                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            & $Action $line
                        }
                    }
                }
            }
            finally {
                $carryStream.Dispose()
            }
        }
        finally {
            if ($contentStream -ne $fileStream) {
                $contentStream.Dispose()
            }
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Invoke-VulnNdjsonJsonRootAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    $rootAction = $Action

    Invoke-VulnNdjsonLineAction -Path $Path -Action {
        param([string]$JsonLine)

        $document = [System.Text.Json.JsonDocument]::Parse($JsonLine)
        try {
            if ($document.RootElement.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) {
                return
            }

            & $rootAction $document.RootElement
        }
        finally {
            $document.Dispose()
        }
    }
}

function Read-VulnNdjsonRecordsFromPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    # IMPORTANT: Use pipeline (| ForEach-Object) not foreach() to avoid
    # collecting all NDJSON lines into memory before JSON-parsing begins.
    Read-VulnNdjsonLinesFromPath -Path $Path | ForEach-Object {
        $record = $_ | ConvertFrom-Json -Depth 20
        if ($null -ne $record) {
            $record
        }
    }
}

function Write-VulnCurrentFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Records
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                foreach ($record in $Records) {
                    if ($null -eq $record) { continue }
                    $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 20))
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-VulnCurrentFileFromNdjson {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$JsonLines
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                foreach ($jsonLine in $JsonLines) {
                    if ([string]::IsNullOrWhiteSpace([string]$jsonLine)) { continue }
                    $writer.WriteLine([string]$jsonLine)
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Read-VulnHistoryDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 2
        $bytesRead = $fileStream.Read($header, 0, $header.Length)
        $fileStream.Position = 0

        $contentStream = if (($bytesRead -eq 2) -and $header[0] -eq 0x1f -and $header[1] -eq 0x8b) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($reader)
                try {
                    if (-not $jsonReader.Read()) {
                        throw "History file '$Path' is empty."
                    }

                    Write-Output -InputObject ([Newtonsoft.Json.Linq.JObject]::Load($jsonReader)) -NoEnumerate
                    return
                }
                finally {
                    $jsonReader.Close()
                }
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            if ($contentStream -ne $fileStream) {
                $contentStream.Dispose()
            }
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Read-VulnHistoryRowsFromPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 2
        $bytesRead = $fileStream.Read($header, 0, $header.Length)
        $fileStream.Position = 0

        $contentStream = if (($bytesRead -eq 2) -and $header[0] -eq 0x1f -and $header[1] -eq 0x8b) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        try {
            $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($reader)
                try {
                    while ($jsonReader.Read()) {
                        if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::PropertyName) { continue }
                        if ([string]$jsonReader.Value -ne 'row') { continue }
                        if (-not $jsonReader.Read()) { break }
                        if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::Null) { continue }

                        $rowToken = [Newtonsoft.Json.Linq.JToken]::ReadFrom($jsonReader)
                        if ($null -eq $rowToken) { continue }

                        $row = $rowToken
                        if ($null -ne $row) {
                            Write-Output -InputObject $row -NoEnumerate
                        }
                    }
                }
                finally {
                    $jsonReader.Close()
                }
            }
            finally {
                $reader.Dispose()
            }
        }
        finally {
            if ($contentStream -ne $fileStream) {
                $contentStream.Dispose()
            }
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-VulnHistoryDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $json = Convert-VulnObjectToCompactJson -InputObject $HistoryDocument -Depth 100
    Write-GzipTextFile -Path $Path -Content $json
}

function Write-VulnHistoryRowsFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                foreach ($snapshot in (Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'snapshots')) {
                    if ($null -eq $snapshot) { continue }
                    foreach ($entry in (Get-VulnPropertyValue -InputObject $snapshot -Name 'closed')) {
                        if ($null -eq $entry) { continue }
                        $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                        if ($null -eq $row) { continue }
                        $writer.WriteLine((Convert-VulnObjectToCompactJson -InputObject $row -Depth 20))
                    }
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Get-VulnHistoryFileLatestDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $prefix = Read-GzipTextFilePrefix -Path $Path -MaxChars 4096
    $latestMatch = [regex]::Match($prefix, '"latestDate"\s*:\s*"(?<date>\d{4}-\d{2}-\d{2})"')
    if ($latestMatch.Success) {
        return $latestMatch.Groups['date'].Value
    }

    $document = Read-VulnHistoryDocument -Path $Path
    return (Get-VulnHistoryDocumentLatestDate -HistoryDocument $document)
}

function Get-VulnHistoryDocumentLatestDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $HistoryDocument
    )

    $latestDate = [string](Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'latestDate')
    if (-not [string]::IsNullOrWhiteSpace($latestDate)) {
        return $latestDate
    }

    foreach ($snapshot in (Get-VulnPropertyValue -InputObject $HistoryDocument -Name 'snapshots')) {
        $snapshotDate = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $snapshot -Name 'date')
        if (-not [string]::IsNullOrWhiteSpace($snapshotDate)) {
            $latestDate = Get-MaxVulnDate -Primary $latestDate -Secondary $snapshotDate
        }
    }

    return $latestDate
}

function Add-VulnHistoryEntryToAppendStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AppendStateByPeriod,

        [Parameter(Mandatory = $true)]
        [string]$ScratchRoot,

        [Parameter(Mandatory = $true)]
        [string]$SnapshotDate,

        [Parameter(Mandatory = $true)]
        [string]$ClosedOn,

        [Parameter(Mandatory = $true)]
        $Entry
    )

    $periodKey = Get-VulnHistoryPeriodKeyFromDate -Date $ClosedOn
    if (-not $AppendStateByPeriod.ContainsKey($periodKey)) {
        $appendPath = Join-Path -Path $ScratchRoot -ChildPath ("VulnHistory_{0}.append.ndjson" -f $periodKey)
        $AppendStateByPeriod[$periodKey] = [PSCustomObject]@{
            AppendPath = $appendPath
            Writer = [System.IO.StreamWriter]::new($appendPath, $true, [System.Text.UTF8Encoding]::new($false))
            LatestDate = ''
        }
    }

    $state = $AppendStateByPeriod[$periodKey]
    $entryJson = $Entry | ConvertTo-Json -Compress -Depth 100
    $state.Writer.WriteLine($SnapshotDate + "`t" + $entryJson)
    $state.LatestDate = Get-MaxVulnDate -Primary ([string]$state.LatestDate) -Secondary $SnapshotDate
}

function Close-VulnHistoryAppendStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AppendStateByPeriod
    )

    foreach ($periodKey in @($AppendStateByPeriod.Keys)) {
        $state = $AppendStateByPeriod[$periodKey]
        if ($null -ne $state -and $null -ne $state.Writer) {
            $state.Writer.Dispose()
            $state.Writer = $null
        }
    }
}

function Write-VulnHistoryDocumentFromAppendFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$PeriodKey,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $ExistingDocument,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$AppendPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$LatestDate
    )

    $periodInfo = Get-VulnHistoryPeriodInfo -PeriodKey $PeriodKey
    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $writer.Write('{"year":')
                $writer.Write($periodInfo.Year)
                $writer.Write(',"quarter":')
                $writer.Write($periodInfo.Quarter)
                $writer.Write(',"period":')
                $writer.Write(($periodInfo.PeriodKey | ConvertTo-Json -Compress))
                $writer.Write(',"latestDate":')
                $writer.Write(($LatestDate | ConvertTo-Json -Compress))
                $writer.Write(',"snapshots":[')

                $existingSnapshots = if ($null -ne $ExistingDocument) {
                    Get-VulnPropertyValue -InputObject $ExistingDocument -Name 'snapshots'
                }
                else {
                    @()
                }

                $hasWrittenSnapshot = $false
                foreach ($snapshot in $existingSnapshots) {
                    if ($null -eq $snapshot) { continue }
                    if ($hasWrittenSnapshot) { $writer.Write(',') }
                    $writer.Write((Convert-VulnObjectToCompactJson -InputObject $snapshot -Depth 100))
                    $hasWrittenSnapshot = $true
                }

                if (-not [string]::IsNullOrWhiteSpace($AppendPath) -and (Test-Path -LiteralPath $AppendPath -PathType Leaf)) {
                    $currentSnapshotDate = $null
                    $wroteClosedEntry = $false

                    foreach ($appendLine in Read-VulnNdjsonLinesFromPath -Path $AppendPath) {
                        $tabIndex = $appendLine.IndexOf("`t")
                        if ($tabIndex -lt 10) {
                            throw "Invalid vulnerability history append line in '$AppendPath'."
                        }

                        $snapshotDate = $appendLine.Substring(0, $tabIndex)
                        $entryJson = $appendLine.Substring($tabIndex + 1)

                        if ($currentSnapshotDate -ne $snapshotDate) {
                            if (-not [string]::IsNullOrWhiteSpace($currentSnapshotDate)) {
                                $writer.Write(']}')
                                $hasWrittenSnapshot = $true
                            }

                            if ($hasWrittenSnapshot) { $writer.Write(',') }
                            $writer.Write('{"date":')
                            $writer.Write(($snapshotDate | ConvertTo-Json -Compress))
                            $writer.Write(',"closed":[')
                            $currentSnapshotDate = $snapshotDate
                            $wroteClosedEntry = $false
                        }

                        if ($wroteClosedEntry) { $writer.Write(',') }
                        $writer.Write($entryJson)
                        $wroteClosedEntry = $true
                    }

                    if (-not [string]::IsNullOrWhiteSpace($currentSnapshotDate)) {
                        $writer.Write(']}')
                    }
                }

                $writer.Write(']}')
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-VulnHistoryRowsFileFromAppendFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $ExistingDocument,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$AppendPath
    )

    $fileStream = [System.IO.File]::Create($Path)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                if ($null -ne $ExistingDocument) {
                    foreach ($snapshot in (Get-VulnPropertyValue -InputObject $ExistingDocument -Name 'snapshots')) {
                        if ($null -eq $snapshot) { continue }
                        foreach ($entry in (Get-VulnPropertyValue -InputObject $snapshot -Name 'closed')) {
                            if ($null -eq $entry) { continue }
                            $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                            if ($null -eq $row) { continue }
                            $writer.WriteLine(($row | ConvertTo-Json -Compress -Depth 20))
                        }
                    }
                }

                if (-not [string]::IsNullOrWhiteSpace($AppendPath) -and (Test-Path -LiteralPath $AppendPath -PathType Leaf)) {
                    foreach ($appendLine in Read-VulnNdjsonLinesFromPath -Path $AppendPath) {
                        $tabIndex = $appendLine.IndexOf("`t")
                        if ($tabIndex -lt 10) {
                            throw "Invalid vulnerability history append line in '$AppendPath'."
                        }

                        $entryJson = $appendLine.Substring($tabIndex + 1)
                        $entry = [Newtonsoft.Json.Linq.JObject]::Parse($entryJson)
                        $row = Get-VulnPropertyValue -InputObject $entry -Name 'row'
                        if ($null -eq $row) { continue }
                        $writer.WriteLine((Convert-VulnObjectToCompactJson -InputObject ([Newtonsoft.Json.Linq.JToken]$row) -Depth 20))
                    }
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Write-VulnHistoryRowsFileFromHistoryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HistoryPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $fileStream = [System.IO.File]::Create($OutputPath)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                foreach ($row in Read-VulnHistoryRowsFromPath -Path $HistoryPath) {
                    if ($null -eq $row) { continue }
                    $writer.WriteLine((Convert-VulnObjectToCompactJson -InputObject $row -Depth 20))
                }
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Get-VulnHistoryPeriodKeyFromFileName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $match = [regex]::Match($Name, '^VulnHistory_(?<period>\d{4}Q[1-4]|\d{4})\.json\.gz$')
    if ($match.Success) {
        return $match.Groups['period'].Value
    }

    return $null
}

function Read-VulnHistoryDocumentIfPresent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$PeriodKey
    )

    $historyPath = Get-VulnHistoryPath -BasePath $BasePath -PeriodKey $PeriodKey
    if (-not (Test-Path -LiteralPath $historyPath -PathType Leaf)) {
        return $null
    }

    return (Read-VulnHistoryDocument -Path $historyPath)
}

function Repair-VulnHistoryLayout {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $historyFiles = @(Get-ChildItem -Path $BasePath -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)
    if ($historyFiles.Count -eq 0) {
        return 0
    }

    $historyLayoutStates = @{}
    $requiresRepair = $false
    foreach ($historyFile in $historyFiles) {
        $historyLayoutState = Get-VulnHistoryLayoutState -BasePath $BasePath -HistoryFile $historyFile
        $historyLayoutStates[$historyFile.FullName] = $historyLayoutState
        if ($historyLayoutState.RequiresRepair) {
            $requiresRepair = $true
        }
    }

    if (-not $requiresRepair) {
        return $historyFiles.Count
    }

    $canonicalDocumentsByPeriod = @{}
    foreach ($historyFile in $historyFiles) {
        $sourcePeriodKey = Get-VulnHistoryPeriodKeyFromFileName -Name $historyFile.Name
        if (-not [string]::IsNullOrWhiteSpace($sourcePeriodKey) -and $sourcePeriodKey -match '^\d{4}Q[1-4]$') {
            $historyLayoutState = $historyLayoutStates[$historyFile.FullName]
            if (-not $historyLayoutState.HistoryFileValid) {
                $validationDetail = if (-not [string]::IsNullOrWhiteSpace($historyLayoutState.ValidationMessage)) {
                    " $($historyLayoutState.ValidationMessage)"
                }
                else {
                    ''
                }

                throw "History file '$($historyFile.FullName)' cannot be repaired in place because it is not a valid canonical quarterly history document.$validationDetail"
            }

            $canonicalDocumentsByPeriod[$sourcePeriodKey] = [PSCustomObject]@{
                SourcePath = $historyFile.FullName
                SourcePeriodKey = $sourcePeriodKey
                SourceIsCanonical = $true
                CopyRowsSidecar = $historyLayoutState.RowsSidecarValid
            }
            continue
        }

        $sourceDocument = Read-VulnHistoryDocument -Path $historyFile.FullName
        foreach ($historyDocument in Convert-VulnHistoryDocumentToQuarterlyDocuments -HistoryDocument $sourceDocument) {
            $periodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $historyDocument
            if ([string]::IsNullOrWhiteSpace($periodKey)) { continue }

            $canonicalDocumentsByPeriod[$periodKey] = [PSCustomObject]@{
                SourcePath = $historyFile.FullName
                SourcePeriodKey = $periodKey
                SourceIsCanonical = $false
                Document = $historyDocument
            }
        }

        $sourceDocument = $null
        Invoke-FullGarbageCollection
    }

    if ($canonicalDocumentsByPeriod.Count -eq 0) {
        return 0
    }

    $stageRoot = Join-Path $BasePath ('.vuln-history-layout-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $stageRoot -ItemType Directory -Force)

    try {
        $filesToPublish = [System.Collections.Generic.List[object]]::new()
        $publishedHistoryNames = if ($canonicalDocumentsByPeriod.Count -gt 0) {
            Get-VulnHistoryPublishedNameSet -PeriodKeys @($canonicalDocumentsByPeriod.Keys)
        }
        else {
            [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }

        foreach ($periodKey in @($canonicalDocumentsByPeriod.Keys | Sort-Object)) {
            $historySource = $canonicalDocumentsByPeriod[$periodKey]
            $historyStagePath = Get-VulnHistoryPath -BasePath $stageRoot -PeriodKey $periodKey
            $historyRowsStagePath = Get-VulnHistoryRowsPath -BasePath $stageRoot -PeriodKey $periodKey

            if ($historySource.SourceIsCanonical) {
                Copy-Item -LiteralPath $historySource.SourcePath -Destination $historyStagePath -Force

                $sourceRowsPath = Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodKey
                if ($historySource.CopyRowsSidecar -and (Test-Path -LiteralPath $sourceRowsPath -PathType Leaf)) {
                    Copy-Item -LiteralPath $sourceRowsPath -Destination $historyRowsStagePath -Force
                }
                else {
                    Write-VulnHistoryRowsFileFromHistoryPath -HistoryPath $historySource.SourcePath -OutputPath $historyRowsStagePath
                }
            }
            else {
                Write-VulnHistoryDocument -Path $historyStagePath -HistoryDocument $historySource.Document
                Write-VulnHistoryRowsFile -Path $historyRowsStagePath -HistoryDocument $historySource.Document
                $historySource.Document = $null
            }

            $filesToPublish.Add([PSCustomObject]@{
                StagePath = $historyStagePath
                TargetPath = Get-VulnHistoryPath -BasePath $BasePath -PeriodKey $periodKey
            })
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = $historyRowsStagePath
                TargetPath = Get-VulnHistoryRowsPath -BasePath $BasePath -PeriodKey $periodKey
            })
        }

        $historyFilesToRemove = Get-VulnHistoryRemovePaths -BasePath $BasePath -PublishedHistoryNames $publishedHistoryNames
        Publish-StoreFilesTransactional -BasePath $BasePath -StoreName 'vuln' -Files @($filesToPublish) -RemovePaths $historyFilesToRemove
        return $canonicalDocumentsByPeriod.Count
    }
    finally {
        if (Test-Path -LiteralPath $stageRoot) {
            Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-VulnPartitionIndex {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $false)]
        [int]$PartitionCount = $Script:VulnDiskPartitionCount
    )

    $hash = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Id))
    return ([int]$hash[0]) % $PartitionCount
}

function Get-VulnPartitionFilePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $true)]
        [int]$Index
    )

    return Join-Path -Path $Root -ChildPath ("{0}-{1:D2}.ndjson" -f $Prefix, $Index)
}

function Split-VulnJsonPartition {
    [CmdletBinding()]
    [OutputType([int[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$InputPaths,

        [Parameter(Mandatory = $true)]
        [string]$OutputRoot,

        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $false)]
        [switch]$OnboardedOnly,

        [Parameter(Mandatory = $false)]
        [int]$PartitionCount = $Script:VulnDiskPartitionCount
    )

    [void](New-Item -Path $OutputRoot -ItemType Directory -Force)

    $writers = @{}
    $writtenIndexes = [System.Collections.Generic.HashSet[int]]::new()
    try {
        foreach ($inputPath in @($InputPaths)) {
            if ([string]::IsNullOrWhiteSpace($inputPath) -or -not (Test-Path -LiteralPath $inputPath -PathType Leaf)) { continue }

            foreach ($jsonLine in Read-VulnNdjsonLinesFromPath -Path $inputPath) {
                $record = $jsonLine | ConvertFrom-Json -Depth 20
                $id = [string](Get-VulnPropertyValue -InputObject $record -Name 'Id')
                if ([string]::IsNullOrWhiteSpace($id)) { continue }
                if ($OnboardedOnly -and (Get-VulnPropertyValue -InputObject $record -Name 'IsOnboarded') -ne $true) { continue }

                $partitionIndex = Get-VulnPartitionIndex -Id $id -PartitionCount $PartitionCount
                if (-not $writers.ContainsKey($partitionIndex)) {
                    $partitionPath = Get-VulnPartitionFilePath -Root $OutputRoot -Prefix $Prefix -Index $partitionIndex
                    $writers[$partitionIndex] = [System.IO.StreamWriter]::new($partitionPath, $true, [System.Text.UTF8Encoding]::new($false))
                }

                $writers[$partitionIndex].WriteLine($jsonLine)
                [void]$writtenIndexes.Add($partitionIndex)
            }
        }
    }
    finally {
        foreach ($writer in @($writers.Values)) {
            if ($null -ne $writer) {
                $writer.Dispose()
            }
        }
    }

    return @($writtenIndexes | Sort-Object)
}

function Read-VulnPartitionMapFile {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $rows = @{}
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $rows
    }

    foreach ($jsonLine in Read-VulnNdjsonLinesFromPath -Path $Path) {
        $record = $jsonLine | ConvertFrom-Json -Depth 20
        $id = [string](Get-VulnPropertyValue -InputObject $record -Name 'Id')
        if ([string]::IsNullOrWhiteSpace($id)) { continue }

        $versionStartDate = Convert-VulnToYmdDate -DateValue (Get-VulnPropertyValue -InputObject $record -Name 'FirstSeenTimestamp')
        $rows[$id] = [PSCustomObject]@{
            Json = $jsonLine
            Signature = Get-VulnCanonicalRowSignature -Row $record
            VersionStartDate = $versionStartDate
        }
    }

    return $rows
}

function Write-VulnPartitionMapFile {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [hashtable]$RowsById
    )

    if ($RowsById.Count -eq 0) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
        return 0
    }

    $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        $rowCount = 0
        foreach ($id in @($RowsById.Keys | Sort-Object)) {
            $writer.WriteLine([string]$RowsById[$id].Json)
            $rowCount++
        }
        return $rowCount
    }
    finally {
        $writer.Dispose()
    }
}

function Write-VulnCurrentFileFromPartition {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PartitionRoot,

        [Parameter(Mandatory = $true)]
        [string]$PartitionPrefix,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [int]$PartitionCount = $Script:VulnDiskPartitionCount
    )

    $fileStream = [System.IO.File]::Create($OutputPath)
    try {
        $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
        try {
            $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))
            try {
                $rowCount = 0
                for ($partitionIndex = 0; $partitionIndex -lt $PartitionCount; $partitionIndex++) {
                    $partitionPath = Get-VulnPartitionFilePath -Root $PartitionRoot -Prefix $PartitionPrefix -Index $partitionIndex
                    if (-not (Test-Path -LiteralPath $partitionPath -PathType Leaf)) { continue }

                    foreach ($jsonLine in Read-VulnNdjsonLinesFromPath -Path $partitionPath) {
                        $writer.WriteLine($jsonLine)
                        $rowCount++
                    }
                }

                return $rowCount
            }
            finally {
                $writer.Dispose()
            }
        }
        finally {
            $gzipStream.Dispose()
        }
    }
    finally {
        $fileStream.Dispose()
    }
}

function Publish-VulnStoreUnlocked {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        $Store
    )

    $storeToPublish = $Store

    $stageRoot = Join-Path $BasePath ('.vuln-store-staging-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $stageRoot -ItemType Directory -Force)

    try {
        $stagedCurrentPath = Get-VulnCurrentPath -BasePath $stageRoot
        Write-VulnCurrentFile -Path $stagedCurrentPath -Records $storeToPublish.CurrentRecords
        Write-Information ("  Vulnerability store publish: {0} current row(s), {1} history period(s)" -f @($storeToPublish.CurrentRecords).Count, @($storeToPublish.HistoryDocuments).Count) -InformationAction Continue

        foreach ($historyDocument in @($storeToPublish.HistoryDocuments)) {
            $periodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $historyDocument
            $historyPath = Get-VulnHistoryPath -BasePath $stageRoot -PeriodKey $periodKey
            Write-VulnHistoryDocument -Path $historyPath -HistoryDocument $historyDocument
            $historyRowsPath = Get-VulnHistoryRowsPath -BasePath $stageRoot -PeriodKey $periodKey
            Write-VulnHistoryRowsFile -Path $historyRowsPath -HistoryDocument $historyDocument
        }

        $currentCount = Test-VulnCurrentFile -Path $stagedCurrentPath
        foreach ($historyFile in Get-ChildItem -Path $stageRoot -Filter 'VulnHistory_*.json.gz' -File -ErrorAction SilentlyContinue) {
            [void](Test-VulnHistoryFileLightweight -Path $historyFile.FullName)
        }

        $filesToPublish = [System.Collections.Generic.List[object]]::new()
        $filesToPublish.Add([PSCustomObject]@{
            StagePath = $stagedCurrentPath
            TargetPath = Get-VulnCurrentPath -BasePath $BasePath
        })

        $historyPeriodKeys = @(
            @($storeToPublish.HistoryDocuments) | ForEach-Object {
                Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $_
            }
        )
        $publishedHistoryNames = if ($historyPeriodKeys.Count -gt 0) {
            Get-VulnHistoryPublishedNameSet -PeriodKeys $historyPeriodKeys
        }
        else {
            [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        foreach ($historyDocument in @($storeToPublish.HistoryDocuments)) {
            $periodKey = Get-VulnHistoryPeriodKeyFromDocument -HistoryDocument $historyDocument
            $historyName = [string]::Format($Script:VulnHistoryFileNamePattern, $periodKey)
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = Join-Path $stageRoot $historyName
                TargetPath = Join-Path $BasePath $historyName
            })

            $historyRowsName = [string]::Format($Script:VulnHistoryRowsFileNamePattern, $periodKey)
            $filesToPublish.Add([PSCustomObject]@{
                StagePath = Join-Path $stageRoot $historyRowsName
                TargetPath = Join-Path $BasePath $historyRowsName
            })
        }

        $historyFilesToRemove = Get-VulnHistoryRemovePaths -BasePath $BasePath -PublishedHistoryNames $publishedHistoryNames
        Publish-StoreFilesTransactional -BasePath $BasePath -StoreName 'vuln' -Files @($filesToPublish) -RemovePaths $historyFilesToRemove
        $historyPeriodCount = Repair-VulnHistoryLayout -BasePath $BasePath
        Publish-VulnContentStoreUnlocked -BasePath $BasePath

        return [PSCustomObject]@{
            CurrentRows = $currentCount
            HistoryYears = if ($historyPeriodCount -gt 0) { $historyPeriodCount } else { @($storeToPublish.HistoryDocuments).Count }
            LatestSnapshotDate = $storeToPublish.LatestSnapshotDate
        }
    }
    finally {
        if (Test-Path -Path $stageRoot) {
            Remove-Item -Path $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Publish-VulnStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        $Store
    )

    $storeToPublish = $Store

    return Invoke-WithStoreLock -BasePath $BasePath -StoreName 'vuln' -ScriptBlock {
        Restore-StoreTransaction -BasePath $BasePath -StoreName 'vuln'
        Publish-VulnStoreUnlocked -BasePath $BasePath -Store $storeToPublish
    }
}

function Get-VulnDeviceProfileSignature {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $deviceId = [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceId')
    if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
        return $deviceId
    }

    $machineTags = @((Get-VulnPropertyValue -InputObject $Row -Name 'MachineTags'))
    $valueDelimiter = [string][char]0x001f
    $listDelimiter = [string][char]0x001e
    return @(
        $deviceId
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceName')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'RbacGroupName')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'OSPlatform')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'OSVersion')
        ($machineTags -join $listDelimiter)
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'IsOnboarded')
    ) -join $valueDelimiter
}

function Get-VulnContentTemplateSignature {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $diskPaths = @((Get-VulnPropertyValue -InputObject $Row -Name 'DiskPaths'))
    $registryPaths = @((Get-VulnPropertyValue -InputObject $Row -Name 'RegistryPaths'))

    $valueDelimiter = [string][char]0x001f
    $listDelimiter = [string][char]0x001e
    return @(
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveId')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVendor')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareName')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVersion')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'VulnerabilitySeverityLevel')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'CvssScore')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'ExploitabilityLevel')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendationReference')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdate')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdateId')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdateUrl')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'SecurityUpdateAvailable')
        ($diskPaths -join $listDelimiter)
        ($registryPaths -join $listDelimiter)
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveBatchTitle')
        [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveBatchUrl')
    ) -join $valueDelimiter
}

function ConvertTo-VulnDeviceProfileTemplate {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    return [PSCustomObject]@{
        id = [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceId')
        n = [string](Get-VulnPropertyValue -InputObject $Row -Name 'DeviceName')
        g = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RbacGroupName')
        o = [string](Get-VulnPropertyValue -InputObject $Row -Name 'OSPlatform')
        ov = [string](Get-VulnPropertyValue -InputObject $Row -Name 'OSVersion')
        t = @((Get-VulnPropertyValue -InputObject $Row -Name 'MachineTags'))
        ob = ((Get-VulnPropertyValue -InputObject $Row -Name 'IsOnboarded') -eq $true)
    }
}

function ConvertTo-VulnContentTemplate {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    return [PSCustomObject]@{
        c = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveId')
        sv = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVendor')
        sn = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareName')
        ver = [string](Get-VulnPropertyValue -InputObject $Row -Name 'SoftwareVersion')
        sev = [string](Get-VulnPropertyValue -InputObject $Row -Name 'VulnerabilitySeverityLevel')
        sc = (Get-VulnPropertyValue -InputObject $Row -Name 'CvssScore')
        ex = [string](Get-VulnPropertyValue -InputObject $Row -Name 'ExploitabilityLevel')
        rr = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendationReference')
        ru = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdate')
        rid = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdateId')
        url = [string](Get-VulnPropertyValue -InputObject $Row -Name 'RecommendedSecurityUpdateUrl')
        ua = ((Get-VulnPropertyValue -InputObject $Row -Name 'SecurityUpdateAvailable') -eq $true)
        dp = @((Get-VulnPropertyValue -InputObject $Row -Name 'DiskPaths'))
        rp = @((Get-VulnPropertyValue -InputObject $Row -Name 'RegistryPaths'))
        bt = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveBatchTitle')
        bu = [string](Get-VulnPropertyValue -InputObject $Row -Name 'CveBatchUrl')
    }
}

function Convert-ToJsonStringLiteral {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return 'null'
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        switch ($character) {
            '"' { [void]$builder.Append('\"') }
            '\' { [void]$builder.Append('\\') }
            "`b" { [void]$builder.Append('\b') }
            "`f" { [void]$builder.Append('\f') }
            "`n" { [void]$builder.Append('\n') }
            "`r" { [void]$builder.Append('\r') }
            "`t" { [void]$builder.Append('\t') }
            default {
                if ([int][char]$character -lt 32) {
                    [void]$builder.Append('\u')
                    [void]$builder.Append(([int][char]$character).ToString('x4'))
                }
                else {
                    [void]$builder.Append($character)
                }
            }
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Write-VulnObservationRefLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.StreamWriter]$Writer,

        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [int]$DeviceProfileIndex,

        [Parameter(Mandatory = $true)]
        [int]$ContentTemplateIndex,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$FirstSeenTimestamp,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$LastSeenTimestamp
    )

    $Writer.WriteLine((
        '[' +
        (Convert-ToJsonStringLiteral -Value $Id) + ',' +
        $DeviceProfileIndex + ',' +
        $ContentTemplateIndex + ',' +
        (Convert-ToJsonStringLiteral -Value $FirstSeenTimestamp) + ',' +
        (Convert-ToJsonStringLiteral -Value $LastSeenTimestamp) +
        ']'
    ))
}

function Read-VulnContentDictionary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Read-GzipTextFile -Path $Path | ConvertFrom-Json -Depth 20)
}

function Open-VulnJsonTextReader {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = $null
    $contentStream = $null
    $reader = $null
    $jsonReader = $null
    try {
        $fileStream = [System.IO.File]::OpenRead($Path)
        $contentStream = if ($Path.EndsWith('.gz', [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Decompress)
        }
        else {
            $fileStream
        }

        $reader = [System.IO.StreamReader]::new($contentStream, [System.Text.UTF8Encoding]::new($false))
        $jsonReader = [Newtonsoft.Json.JsonTextReader]::new($reader)

        $state = [PSCustomObject]@{
            Path = $Path
            FileStream = $fileStream
            ContentStream = $contentStream
            Reader = $reader
            JsonReader = $jsonReader
        }

        $jsonReader = $null
        $reader = $null
        $contentStream = $null
        $fileStream = $null
        return $state
    }
    finally {
        if ($jsonReader) {
            $jsonReader.Close()
        }
        elseif ($reader) {
            $reader.Dispose()
        }
        elseif ($contentStream -and $contentStream -ne $fileStream) {
            $contentStream.Dispose()
        }

        if ($fileStream) {
            $fileStream.Dispose()
        }
    }
}

function Close-VulnJsonTextReader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $State
    )

    if ($null -eq $State) {
        return
    }

    $jsonReader = $State.PSObject.Properties['JsonReader']?.Value
    if ($null -ne $jsonReader) {
        $jsonReader.Close()
        return
    }

    $reader = $State.PSObject.Properties['Reader']?.Value
    if ($null -ne $reader) {
        $reader.Dispose()
        return
    }

    $contentStream = $State.PSObject.Properties['ContentStream']?.Value
    $fileStream = $State.PSObject.Properties['FileStream']?.Value
    if ($null -ne $contentStream -and $contentStream -ne $fileStream) {
        $contentStream.Dispose()
    }

    if ($null -ne $fileStream) {
        $fileStream.Dispose()
    }
}

function Skip-VulnJsonReaderValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Newtonsoft.Json.JsonTextReader]$Reader
    )

    if ($Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray -and
        $Reader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartObject) {
        return
    }

    $depth = 1
    while ($depth -gt 0 -and $Reader.Read()) {
        switch ($Reader.TokenType) {
            ([Newtonsoft.Json.JsonToken]::StartArray) { $depth++ }
            ([Newtonsoft.Json.JsonToken]::StartObject) { $depth++ }
            ([Newtonsoft.Json.JsonToken]::EndArray) { $depth-- }
            ([Newtonsoft.Json.JsonToken]::EndObject) { $depth-- }
        }
    }
}

function Read-VulnContentDictionaryArrayEntries {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Streams multiple dictionary entries by design.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('deviceProfiles', 'contentTemplates')]
        [string]$PropertyName
    )

    $readerState = Open-VulnJsonTextReader -Path $Path
    try {
        $jsonReader = $readerState.JsonReader
        if (-not $jsonReader.Read() -or $jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartObject) {
            throw "Content dictionary '$Path' does not begin with a JSON object."
        }

        while ($jsonReader.Read()) {
            if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndObject) {
                break
            }

            if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::PropertyName) {
                continue
            }

            $currentPropertyName = [string]$jsonReader.Value
            if (-not $jsonReader.Read()) {
                throw "Unexpected end of content dictionary '$Path' while reading '$currentPropertyName'."
            }

            if ($currentPropertyName -ne $PropertyName) {
                Skip-VulnJsonReaderValue -Reader $jsonReader
                continue
            }

            if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartArray) {
                throw "Content dictionary '$Path' property '$PropertyName' is not a JSON array."
            }

            while ($jsonReader.Read()) {
                if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::EndArray) {
                    return
                }

                if ($jsonReader.TokenType -eq [Newtonsoft.Json.JsonToken]::Null) {
                    continue
                }

                if ($jsonReader.TokenType -ne [Newtonsoft.Json.JsonToken]::StartObject) {
                    throw "Content dictionary '$Path' property '$PropertyName' contains an unexpected token '$($jsonReader.TokenType)'."
                }

                Write-Output -InputObject ([Newtonsoft.Json.Linq.JObject]::Load($jsonReader)) -NoEnumerate
            }

            throw "Content dictionary '$Path' ended before closing '$PropertyName'."
        }

        throw "Content dictionary '$Path' is missing '$PropertyName'."
    }
    finally {
        Close-VulnJsonTextReader -State $readerState
    }
}

function Read-VulnContentDictionaryExpansionLookups {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Builds reduced lookup arrays for multiple dictionary sections by design.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $deviceProfiles = [System.Collections.Generic.List[object]]::new()
    Read-VulnContentDictionaryArrayEntries -Path $Path -PropertyName 'deviceProfiles' | ForEach-Object {
        $deviceProfile = $_
        $deviceProfiles.Add([PSCustomObject]@{
                id = [string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'id')
                n = [string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'n')
                g = [string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'g')
                o = [string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'o')
                ov = [string](Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ov')
                t = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $deviceProfile -Name 't'))
                ob = ((Get-VulnPropertyValue -InputObject $deviceProfile -Name 'ob') -eq $true)
            }) | Out-Null
    }

    $contentTemplates = [System.Collections.Generic.List[object]]::new()
    Read-VulnContentDictionaryArrayEntries -Path $Path -PropertyName 'contentTemplates' | ForEach-Object {
        $contentTemplate = $_
        $contentTemplates.Add([PSCustomObject]@{
                c = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'c')
                sv = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sv')
                sn = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sn')
                ver = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ver')
                sev = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sev')
                sc = (Get-VulnPropertyValue -InputObject $contentTemplate -Name 'sc')
                ex = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ex')
                rr = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'rr')
                ru = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ru')
                rid = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'rid')
                url = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'url')
                ua = ((Get-VulnPropertyValue -InputObject $contentTemplate -Name 'ua') -eq $true)
                dp = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $contentTemplate -Name 'dp'))
                rp = @(Get-StringArray -Value (Get-VulnPropertyValue -InputObject $contentTemplate -Name 'rp'))
                bt = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'bt')
                bu = [string](Get-VulnPropertyValue -InputObject $contentTemplate -Name 'bu')
            }) | Out-Null
    }

    return [PSCustomObject]@{
        DeviceProfiles = $deviceProfiles.ToArray()
        ContentTemplates = $contentTemplates.ToArray()
    }
}

function Convert-VulnContentRefToRow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Ref,

        [Parameter(Mandatory = $true)]
        [object[]]$DeviceProfiles,

        [Parameter(Mandatory = $true)]
        [object[]]$ContentTemplates
    )

    if ($null -eq $Ref -or @($Ref).Count -lt 5) {
        return $null
    }

    $device = $DeviceProfiles[[int]$Ref[1]]
    $content = $ContentTemplates[[int]$Ref[2]]

    return ([PSCustomObject]@{
            Id = [string]$Ref[0]
            DeviceId = [string]$device.id
            DeviceName = [string]$device.n
            RbacGroupName = [string]$device.g
            OSPlatform = [string]$device.o
            OSVersion = [string]$device.ov
            MachineTags = @($device.t)
            CveId = [string]$content.c
            SoftwareVendor = [string]$content.sv
            SoftwareName = [string]$content.sn
            SoftwareVersion = [string]$content.ver
            VulnerabilitySeverityLevel = [string]$content.sev
            CvssScore = $content.sc
            ExploitabilityLevel = [string]$content.ex
            RecommendationReference = [string]$content.rr
            RecommendedSecurityUpdate = [string]$content.ru
            RecommendedSecurityUpdateId = [string]$content.rid
            RecommendedSecurityUpdateUrl = [string]$content.url
            SecurityUpdateAvailable = ($content.ua -eq $true)
            FirstSeenTimestamp = [string]$Ref[3]
            LastSeenTimestamp = [string]$Ref[4]
            DiskPaths = @($content.dp)
            RegistryPaths = @($content.rp)
            CveBatchTitle = [string]$content.bt
            CveBatchUrl = [string]$content.bu
            IsOnboarded = ($device.ob -eq $true)
        })
}

function Read-VulnContentRefRows {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Streams multiple content reference rows by design.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DictionaryPath,

        [Parameter(Mandatory = $true)]
        [string[]]$RefPaths
    )

    $lookups = Read-VulnContentDictionaryExpansionLookups -Path $DictionaryPath

    foreach ($refPath in @($RefPaths)) {
        Read-VulnNdjsonLinesFromPath -Path $refPath | ForEach-Object {
            if ([string]::IsNullOrWhiteSpace($_)) { return }

            $ref = $_ | ConvertFrom-Json -Depth 10
            $row = Convert-VulnContentRefToRow -Ref $ref -DeviceProfiles $lookups.DeviceProfiles -ContentTemplates $lookups.ContentTemplates
            if ($null -ne $row) {
                $row
            }
        }
    }
}

function Read-VulnContentStoreRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $refPaths = [System.Collections.Generic.List[string]]::new()

    $currentRefsPath = Get-VulnCurrentRefsPath -BasePath $BasePath
    if (Test-Path -LiteralPath $currentRefsPath -PathType Leaf) {
        $refPaths.Add($currentRefsPath)
    }

    foreach ($historyRefsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        $refPaths.Add($historyRefsFile.FullName)
    }

    if ($refPaths.Count -eq 0) {
        return
    }

    Read-VulnContentRefRows -DictionaryPath (Get-VulnContentDictionaryPath -BasePath $BasePath) -RefPaths $refPaths.ToArray()
}

function Publish-VulnContentStoreUnlocked {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if (-not (Test-VulnStoreExistence -BasePath $BasePath)) {
        return
    }

    $stageRoot = Join-Path $BasePath ('.vuln-content-store-staging-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $stageRoot -ItemType Directory -Force)

    try {
        $deviceProfiles = [System.Collections.Generic.List[object]]::new()
        $deviceProfileIndex = @{}
        $contentTemplates = [System.Collections.Generic.List[object]]::new()
        $contentTemplateIndex = @{}
        $filesToPublish = [System.Collections.Generic.List[object]]::new()

        $writeObservationRefs = {
            param(
                [string]$InputPath,
                [string]$OutputPath
            )

            $fileStream = $null
            $gzipStream = $null
            $writer = $null
            $valueDelimiter = [string][char]0x001f
            $listDelimiter = [string][char]0x001e
            try {
                $fileStream = [System.IO.File]::Create($OutputPath)
                $gzipStream = [System.IO.Compression.GZipStream]::new($fileStream, [System.IO.Compression.CompressionMode]::Compress)
                $writer = [System.IO.StreamWriter]::new($gzipStream, [System.Text.UTF8Encoding]::new($false))

                Invoke-VulnNdjsonJsonRootAction -Path $InputPath -Action {
                    param([System.Text.Json.JsonElement]$root)

                    $deviceId = ''
                    $deviceName = ''
                    $groupName = ''
                    $osPlatform = ''
                    $osVersion = ''
                    $machineTags = @()
                    $isOnboarded = $false
                    $cveId = ''
                    $softwareVendor = ''
                    $softwareName = ''
                    $softwareVersion = ''
                    $severityLevel = ''
                    $cvssScore = $null
                    $exploitabilityLevel = ''
                    $recommendationReference = ''
                    $recommendedSecurityUpdate = ''
                    $recommendedSecurityUpdateId = ''
                    $recommendedSecurityUpdateUrl = ''
                    $securityUpdateAvailable = $false
                    $diskPaths = @()
                    $registryPaths = @()
                    $cveBatchTitle = ''
                    $cveBatchUrl = ''
                    $id = ''
                    $firstSeenTimestamp = ''
                    $lastSeenTimestamp = ''

                    foreach ($jsonProperty in $root.EnumerateObject()) {
                        $propertyValue = $jsonProperty.Value
                        switch ($jsonProperty.Name) {
                            'DeviceId' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $deviceId = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $deviceId = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'DeviceName' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $deviceName = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $deviceName = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'RbacGroupName' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $groupName = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $groupName = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'OSPlatform' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $osPlatform = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $osPlatform = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'OSVersion' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $osVersion = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $osVersion = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'MachineTags' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                                    $tagValues = [System.Collections.Generic.List[string]]::new()
                                    foreach ($tagValueElement in $propertyValue.EnumerateArray()) {
                                        $tagValue = if ($tagValueElement.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                            $tagValueElement.GetString()
                                        }
                                        else {
                                            Convert-JsonElementToScalarValue -Element $tagValueElement
                                        }
                                        if ($null -ne $tagValue -and -not [string]::IsNullOrWhiteSpace([string]$tagValue)) {
                                            [void]$tagValues.Add([string]$tagValue)
                                        }
                                    }
                                    $machineTags = [string[]]$tagValues.ToArray()
                                }
                            }
                            'IsOnboarded' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::True) {
                                    $isOnboarded = $true
                                }
                                elseif ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::False) {
                                    $isOnboarded = $false
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $isOnboarded = ((Convert-JsonElementToScalarValue -Element $propertyValue) -eq $true)
                                }
                            }
                            'CveId' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $cveId = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $cveId = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'SoftwareVendor' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $softwareVendor = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $softwareVendor = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'SoftwareName' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $softwareName = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $softwareName = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'SoftwareVersion' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $softwareVersion = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $softwareVersion = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'VulnerabilitySeverityLevel' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $severityLevel = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $severityLevel = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'CvssScore' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $cvssScore = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::Number) {
                                    $cvssInt64 = 0L
                                    if ($propertyValue.TryGetInt64([ref]$cvssInt64)) {
                                        $cvssScore = $cvssInt64
                                    }
                                    else {
                                        $cvssDouble = 0.0
                                        if ($propertyValue.TryGetDouble([ref]$cvssDouble)) {
                                            $cvssScore = $cvssDouble
                                        }
                                        else {
                                            $cvssScore = $propertyValue.GetRawText()
                                        }
                                    }
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $cvssScore = Convert-JsonElementToScalarValue -Element $propertyValue
                                }
                            }
                            'ExploitabilityLevel' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $exploitabilityLevel = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $exploitabilityLevel = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'RecommendationReference' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $recommendationReference = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $recommendationReference = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'RecommendedSecurityUpdate' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $recommendedSecurityUpdate = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $recommendedSecurityUpdate = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'RecommendedSecurityUpdateId' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $recommendedSecurityUpdateId = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $recommendedSecurityUpdateId = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'RecommendedSecurityUpdateUrl' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $recommendedSecurityUpdateUrl = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $recommendedSecurityUpdateUrl = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'SecurityUpdateAvailable' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::True) {
                                    $securityUpdateAvailable = $true
                                }
                                elseif ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::False) {
                                    $securityUpdateAvailable = $false
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $securityUpdateAvailable = ((Convert-JsonElementToScalarValue -Element $propertyValue) -eq $true)
                                }
                            }
                            'DiskPaths' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                                    $diskPathValues = [System.Collections.Generic.List[string]]::new()
                                    foreach ($diskPathElement in $propertyValue.EnumerateArray()) {
                                        $diskPathValue = if ($diskPathElement.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                            $diskPathElement.GetString()
                                        }
                                        else {
                                            Convert-JsonElementToScalarValue -Element $diskPathElement
                                        }
                                        if ($null -ne $diskPathValue -and -not [string]::IsNullOrWhiteSpace([string]$diskPathValue)) {
                                            [void]$diskPathValues.Add([string]$diskPathValue)
                                        }
                                    }
                                    $diskPaths = [string[]]$diskPathValues.ToArray()
                                }
                            }
                            'RegistryPaths' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                                    $registryPathValues = [System.Collections.Generic.List[string]]::new()
                                    foreach ($registryPathElement in $propertyValue.EnumerateArray()) {
                                        $registryPathValue = if ($registryPathElement.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                            $registryPathElement.GetString()
                                        }
                                        else {
                                            Convert-JsonElementToScalarValue -Element $registryPathElement
                                        }
                                        if ($null -ne $registryPathValue -and -not [string]::IsNullOrWhiteSpace([string]$registryPathValue)) {
                                            [void]$registryPathValues.Add([string]$registryPathValue)
                                        }
                                    }
                                    $registryPaths = [string[]]$registryPathValues.ToArray()
                                }
                            }
                            'CveBatchTitle' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $cveBatchTitle = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $cveBatchTitle = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'CveBatchUrl' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $cveBatchUrl = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $cveBatchUrl = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'Id' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $id = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $id = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'FirstSeenTimestamp' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $firstSeenTimestamp = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $firstSeenTimestamp = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                            'LastSeenTimestamp' {
                                if ($propertyValue.ValueKind -eq [System.Text.Json.JsonValueKind]::String) {
                                    $lastSeenTimestamp = $propertyValue.GetString()
                                }
                                elseif ($propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Null -and $propertyValue.ValueKind -ne [System.Text.Json.JsonValueKind]::Undefined) {
                                    $lastSeenTimestamp = [string](Convert-JsonElementToScalarValue -Element $propertyValue)
                                }
                            }
                        }
                    }

                    if (-not [string]::IsNullOrWhiteSpace($deviceId)) {
                        $deviceSignature = $deviceId
                    }
                    else {
                        $deviceSignature = @(
                            $deviceId
                            $deviceName
                            $groupName
                            $osPlatform
                            $osVersion
                            ($machineTags -join $listDelimiter)
                            [string]$isOnboarded
                        ) -join $valueDelimiter
                    }
                    if (-not $deviceProfileIndex.ContainsKey($deviceSignature)) {
                        $deviceProfileIndex[$deviceSignature] = $deviceProfiles.Count
                        [void]$deviceProfiles.Add([PSCustomObject]@{
                            id = $deviceId
                            n = $deviceName
                            g = $groupName
                            o = $osPlatform
                            ov = $osVersion
                            t = $machineTags
                            ob = $isOnboarded
                        })
                    }
                    $deviceIndexValue = [int]$deviceProfileIndex[$deviceSignature]

                    $contentSignature = @(
                        $cveId
                        $softwareVendor
                        $softwareName
                        $softwareVersion
                        $severityLevel
                        [string]$cvssScore
                        $exploitabilityLevel
                        $recommendationReference
                        $recommendedSecurityUpdate
                        $recommendedSecurityUpdateId
                        $recommendedSecurityUpdateUrl
                        [string]$securityUpdateAvailable
                        ($diskPaths -join $listDelimiter)
                        ($registryPaths -join $listDelimiter)
                        $cveBatchTitle
                        $cveBatchUrl
                    ) -join $valueDelimiter
                    if (-not $contentTemplateIndex.ContainsKey($contentSignature)) {
                        $contentTemplateIndex[$contentSignature] = $contentTemplates.Count
                        [void]$contentTemplates.Add([PSCustomObject]@{
                            c = $cveId
                            sv = $softwareVendor
                            sn = $softwareName
                            ver = $softwareVersion
                            sev = $severityLevel
                            sc = $cvssScore
                            ex = $exploitabilityLevel
                            rr = $recommendationReference
                            ru = $recommendedSecurityUpdate
                            rid = $recommendedSecurityUpdateId
                            url = $recommendedSecurityUpdateUrl
                            ua = $securityUpdateAvailable
                            dp = $diskPaths
                            rp = $registryPaths
                            bt = $cveBatchTitle
                            bu = $cveBatchUrl
                        })
                    }
                    $contentIndexValue = [int]$contentTemplateIndex[$contentSignature]
                    $writer.WriteLine((
                        '[' +
                        (Convert-ToJsonStringLiteral -Value $id) + ',' +
                        $deviceIndexValue + ',' +
                        $contentIndexValue + ',' +
                        (Convert-ToJsonStringLiteral -Value $firstSeenTimestamp) + ',' +
                        (Convert-ToJsonStringLiteral -Value $lastSeenTimestamp) +
                        ']'
                    ))
                }
            }
            finally {
                if ($writer) { $writer.Dispose() }
                elseif ($gzipStream) { $gzipStream.Dispose() }
                elseif ($fileStream) { $fileStream.Dispose() }
            }
        }

        $currentPath = Get-VulnCurrentPath -BasePath $BasePath
        if (Test-Path -LiteralPath $currentPath -PathType Leaf) {
            $stagedCurrentRefsPath = Get-VulnCurrentRefsPath -BasePath $stageRoot
            & $writeObservationRefs $currentPath $stagedCurrentRefsPath
            [void]$filesToPublish.Add([PSCustomObject]@{
                StagePath = $stagedCurrentRefsPath
                TargetPath = Get-VulnCurrentRefsPath -BasePath $BasePath
            })
        }

        $periodKeys = [System.Collections.Generic.List[string]]::new()
        foreach ($historyRowsFile in @(Get-ChildItem -Path $BasePath -Filter 'VulnHistoryRows_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
            $match = [regex]::Match($historyRowsFile.Name, '^VulnHistoryRows_(?<period>\d{4}Q[1-4]|\d{4})\.json\.gz$')
            if (-not $match.Success) { continue }

            $periodKey = [string]$match.Groups['period'].Value
            [void]$periodKeys.Add($periodKey)
            $stagedHistoryRefsPath = Get-VulnHistoryRefsPath -BasePath $stageRoot -PeriodKey $periodKey
            & $writeObservationRefs $historyRowsFile.FullName $stagedHistoryRefsPath
            [void]$filesToPublish.Add([PSCustomObject]@{
                StagePath = $stagedHistoryRefsPath
                TargetPath = Get-VulnHistoryRefsPath -BasePath $BasePath -PeriodKey $periodKey
            })
        }

        $dictionaryPath = Get-VulnContentDictionaryPath -BasePath $stageRoot
        $dictionaryFileStream = $null
        $dictionaryGzipStream = $null
        $dictionaryWriter = $null
        try {
            $dictionaryFileStream = [System.IO.File]::Create($dictionaryPath)
            $dictionaryGzipStream = [System.IO.Compression.GZipStream]::new($dictionaryFileStream, [System.IO.Compression.CompressionMode]::Compress)
            $dictionaryWriter = [System.IO.StreamWriter]::new($dictionaryGzipStream, [System.Text.UTF8Encoding]::new($false))
            $dictionaryWriter.Write('{"version":"content-dictionary-v1","deviceProfiles":[')
            for ($index = 0; $index -lt $deviceProfiles.Count; $index++) {
                if ($index -gt 0) { $dictionaryWriter.Write(',') }
                $dictionaryWriter.Write((ConvertTo-Json -InputObject $deviceProfiles[$index] -Compress -Depth 20))
            }
            $dictionaryWriter.Write('],"contentTemplates":[')
            for ($index = 0; $index -lt $contentTemplates.Count; $index++) {
                if ($index -gt 0) { $dictionaryWriter.Write(',') }
                $dictionaryWriter.Write((ConvertTo-Json -InputObject $contentTemplates[$index] -Compress -Depth 20))
            }
            $dictionaryWriter.Write(']}')
        }
        finally {
            if ($dictionaryWriter) { $dictionaryWriter.Dispose() }
            elseif ($dictionaryGzipStream) { $dictionaryGzipStream.Dispose() }
            elseif ($dictionaryFileStream) { $dictionaryFileStream.Dispose() }
        }
        $deviceProfiles.Clear()
        $contentTemplates.Clear()
        [void]$filesToPublish.Add([PSCustomObject]@{
            StagePath = $dictionaryPath
            TargetPath = Get-VulnContentDictionaryPath -BasePath $BasePath
        })

        $publishedHistoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($periodKey in @($periodKeys | Sort-Object -Unique)) {
            if ([string]::IsNullOrWhiteSpace($periodKey)) { continue }
            [void]$publishedHistoryNames.Add([string]::Format($Script:VulnHistoryFileNamePattern, $periodKey))
            [void]$publishedHistoryNames.Add([string]::Format($Script:VulnHistoryRowsFileNamePattern, $periodKey))
            [void]$publishedHistoryNames.Add([string]::Format($Script:VulnHistoryRefsFileNamePattern, $periodKey))
        }
        [void]$publishedHistoryNames.Add($Script:VulnCurrentRefsFileName)
        [void]$publishedHistoryNames.Add($Script:VulnContentDictionaryFileName)
        $removePaths = Get-VulnHistoryRemovePaths -BasePath $BasePath -PublishedHistoryNames $publishedHistoryNames
        if ((Test-Path -LiteralPath (Get-VulnCurrentRefsPath -BasePath $BasePath) -PathType Leaf) -and -not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
            $removePaths = @($removePaths) + (Get-VulnCurrentRefsPath -BasePath $BasePath)
        }

        Publish-StoreFilesTransactional -BasePath $BasePath -StoreName 'vuln' -Files @($filesToPublish) -RemovePaths @($removePaths)
    }
    finally {
        if (Test-Path -LiteralPath $stageRoot) {
            Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
