#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$AutomationAccountName,

    [Parameter(Mandatory = $true)]
    [string]$JobId,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [ValidateRange(5, 300)]
    [int]$PollIntervalSeconds = 15,

    [Parameter(Mandatory = $false)]
    [ValidateRange(60, 21600)]
    [int]$TimeoutSeconds = 7200,

    [Parameter(Mandatory = $false)]
    [string]$LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ArmAccessToken {
    $token = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Unable to acquire an Azure Resource Manager access token from Azure CLI.'
    }

    return $token.Trim()
}

function Invoke-AutomationRest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $headers = @{
        Authorization = "Bearer $(Get-ArmAccessToken)"
    }

    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -ContentType 'application/json'
}

function Write-LogLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamped = ('[{0}] {1}' -f (Get-Date).ToUniversalTime().ToString('u'), $Message)
    Write-Output $timestamped
    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        Add-Content -Path $LogPath -Value $timestamped -Encoding utf8
    }
}

if (-not $SubscriptionId) {
    $SubscriptionId = az account show --query id -o tsv
}

if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
    throw 'Unable to resolve subscription id from Azure CLI.'
}

$jobUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/${JobId}?api-version=2023-11-01"
$streamsUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/${JobId}/streams?api-version=2023-11-01"
$terminalStates = @('Completed', 'Failed', 'Stopped', 'Suspended', 'Disconnected', 'Blocked', 'Removing')
$seenStreamIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$lastStatus = $null

if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
    $logDirectory = Split-Path -Path $LogPath -Parent
    if ($logDirectory) {
        $null = New-Item -Path $logDirectory -ItemType Directory -Force
    }
}

Write-LogLine "Watching Azure Automation job $JobId in $AutomationAccountName / $ResourceGroupName"

while ($true) {
    if ($stopwatch.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
        throw "Timed out waiting for job '$JobId' after $TimeoutSeconds seconds."
    }

    $job = Invoke-AutomationRest -Method Get -Uri $jobUri
    $status = [string]$job.properties.status

    if ($status -ne $lastStatus) {
        $elapsed = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
        Write-LogLine ("Status: {0} at {1}s" -f $status, $elapsed)
        $lastStatus = $status
    }

    $streams = Invoke-AutomationRest -Method Get -Uri $streamsUri
    foreach ($stream in @($streams.value | Sort-Object { $_.properties.time })) {
        $streamId = [string]$stream.properties.jobStreamId
        if (-not $seenStreamIds.Add($streamId)) {
            continue
        }

        $time = [string]$stream.properties.time
        $streamType = [string]$stream.properties.streamType
        $summary = [string]$stream.properties.summary
        Write-LogLine ("{0} {1} {2}" -f $time, $streamType.ToUpperInvariant(), $summary.Trim())
    }

    if ($status -in $terminalStates) {
        $elapsed = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
        $exceptionText = [string]$job.properties.exception
        if (-not [string]::IsNullOrWhiteSpace($exceptionText)) {
            Write-LogLine ("Exception: {0}" -f $exceptionText.Trim())
        }

        Write-LogLine ("Final status: {0} after {1}s" -f $status, $elapsed)
        break
    }

    Start-Sleep -Seconds $PollIntervalSeconds
}
