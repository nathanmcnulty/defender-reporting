# Source-first Azure provisioning helpers used by Setup-AzureResources.ps1.

function Wait-WithPolling {
    <#
    .SYNOPSIS
        Polls a script block every $IntervalSeconds until it returns $true or timeout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Condition,

        [Parameter(Mandatory)]
        [string]$Description,

        [int]$IntervalSeconds = 5,
        [int]$TimeoutSeconds = 60
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if (& $Condition) {
            Write-Host "  $Description - confirmed" -ForegroundColor Green
            return $true
        }
        Write-Host "  Waiting for $Description... ($([int]$stopwatch.Elapsed.TotalSeconds)s)" -ForegroundColor Gray
        Start-Sleep -Seconds $IntervalSeconds
    }
    $stopwatch.Stop()
    Write-Warning "$Description did not complete within ${TimeoutSeconds}s"
    return $false
}

function Invoke-ArmApi {
    <#
    .SYNOPSIS
        Wrapper for Invoke-AzRestMethod with standardized error handling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [ValidateSet('GET', 'PUT', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,

        [string]$Payload,

        [string]$Description = 'ARM API call'
    )

    $params = @{
        Path = $Path
        Method = $Method
    }
    if ($Payload) { $params.Payload = $Payload }

    $response = Invoke-AzRestMethod @params

    if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
        if ($response.Content) {
            return $response.Content | ConvertFrom-Json
        }
        return $null
    }

    $errorDetail = ''
    if ($response.Content) {
        try {
            $errorBody = $response.Content | ConvertFrom-Json
            $errorDetail = if ($errorBody.error.message) { $errorBody.error.message }
            elseif ($errorBody.message) { $errorBody.message }
            else { $response.Content }
        }
        catch { $errorDetail = $response.Content }
    }

    throw "$Description failed (HTTP $($response.StatusCode)): $errorDetail"
}

function Get-ErrorMessageText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $parts = [System.Collections.Generic.List[string]]::new()
    if ($ErrorRecord.Exception -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.Exception.Message)) {
        $parts.Add($ErrorRecord.Exception.Message)
    }
    if ($ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        $parts.Add($ErrorRecord.ErrorDetails.Message)
    }

    return ($parts -join "`n")
}

function Test-IsArmNotFoundError {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $text = Get-ErrorMessageText -ErrorRecord $ErrorRecord
    return ($text -match '(?i)\b(HTTP\s*404|StatusCode\s*:?\s*404|ResourceGroupNotFound|ResourceNotFound|NotFound|could not be found|was not found)\b')
}

function Remove-AutomationJobSchedulesByScheduleName {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionPath,

        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$AutomationAccountName,

        [Parameter(Mandatory)]
        [string]$ScheduleName
    )

    $jobSchedulesPath = "$SubscriptionPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobSchedules?api-version=$($Script:ArmApiVersions.AutomationAccount)"
    $jobSchedulesResponse = Invoke-ArmApi -Path $jobSchedulesPath -Method GET -Description 'List Automation job schedules'
    $jobSchedules = if ($null -eq $jobSchedulesResponse) {
        @()
    }
    elseif ($jobSchedulesResponse.PSObject.Properties['value']) {
        @($jobSchedulesResponse.value)
    }
    else {
        @($jobSchedulesResponse)
    }

    foreach ($jobSchedule in $jobSchedules) {
        if ($null -eq $jobSchedule) { continue }

        $jobScheduleName = ''
        if ($jobSchedule.PSObject.Properties['name']) {
            $jobScheduleName = [string]$jobSchedule.PSObject.Properties['name'].Value
        }
        if ([string]::IsNullOrWhiteSpace($jobScheduleName)) {
            $jobScheduleName = [string]$jobSchedule.properties.jobScheduleId
        }
        if ([string]::IsNullOrWhiteSpace($jobScheduleName) -and -not [string]::IsNullOrWhiteSpace([string]$jobSchedule.id)) {
            $jobScheduleName = Split-Path -Path ([string]$jobSchedule.id) -Leaf
        }

        $linkedScheduleName = ''
        if ($null -ne $jobSchedule.properties -and $null -ne $jobSchedule.properties.schedule) {
            $linkedScheduleName = [string]$jobSchedule.properties.schedule.name
        }

        if ([string]::IsNullOrWhiteSpace($jobScheduleName) -or $linkedScheduleName -ne $ScheduleName) {
            continue
        }

        $deletePath = "$SubscriptionPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobSchedules/${jobScheduleName}?api-version=$($Script:ArmApiVersions.AutomationAccount)"
        Invoke-ArmApi -Path $deletePath -Method DELETE -Description "Delete Automation job schedule '$jobScheduleName'" | Out-Null
        Write-Host "  Removed existing job schedule link '$jobScheduleName' for schedule '$ScheduleName'" -ForegroundColor Gray
    }
}

function Get-ArmToken {
    <#
    .SYNOPSIS
        Gets a plain-text ARM bearer token (handles SecureString in newer Az.Accounts).
    #>
    [CmdletBinding()]
    param(
        [string]$ResourceUrl = 'https://management.azure.com/'
    )

    $tokenResponse = Get-AzAccessToken -ResourceUrl $ResourceUrl -AsSecureString
    $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResponse.Token)
    try { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr) }
}

function Get-JwtPayload {
    <#
    .SYNOPSIS
        Decodes the payload segment from a JWT bearer token.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Token
    )

    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) {
        throw 'Token is not a valid JWT.'
    }

    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
        0 { }
        default { throw 'JWT payload is not valid Base64Url.' }
    }

    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    return $json | ConvertFrom-Json
}

function Get-GrantedScopesFromToken {
    <#
    .SYNOPSIS
        Returns delegated scopes from a JWT's scp claim.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken
    )

    $payload = Get-JwtPayload -Token $AccessToken
    $scopeClaim = if ($payload.PSObject.Properties['scp']) { [string]$payload.scp } else { '' }
    if ([string]::IsNullOrWhiteSpace($scopeClaim)) {
        return @()
    }

    return @(
        $scopeClaim -split '\s+' |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )
}

function Test-GraphScopeRequirement {
    <#
    .SYNOPSIS
        Checks whether a granted scope set satisfies the requested requirements.
    #>
    [CmdletBinding()]
    param(
        [string[]]$GrantedScopes = @(),
        [string[]]$RequiredAllScopes = @(),
        [string[]]$RequiredAnyScopeSets = @()
    )

    $grantedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($scope in @($GrantedScopes)) {
        if (-not [string]::IsNullOrWhiteSpace($scope)) {
            [void]$grantedSet.Add($scope)
        }
    }

    $missingRequirements = [System.Collections.Generic.List[string]]::new()

    foreach ($scope in @($RequiredAllScopes)) {
        if (-not $grantedSet.Contains($scope)) {
            $missingRequirements.Add($scope)
        }
    }

    foreach ($scopeSet in @($RequiredAnyScopeSets)) {
        $candidateScopes = @(
            ([string]$scopeSet -split '\|') |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        if ($candidateScopes.Count -eq 0) {
            continue
        }

        $isSatisfied = $false
        foreach ($candidate in $candidateScopes) {
            if ($grantedSet.Contains($candidate)) {
                $isSatisfied = $true
                break
            }
        }

        if (-not $isSatisfied) {
            $missingRequirements.Add(($candidateScopes -join ' or '))
        }
    }

    return [PSCustomObject]@{
        IsSatisfied = ($missingRequirements.Count -eq 0)
        MissingRequirements = @($missingRequirements)
    }
}

function Get-GraphApiContext {
    <#
    .SYNOPSIS
        Creates a Graph API context using Az-issued tokens first, then falls back
        to Microsoft.Graph.Authentication when the Az token lacks required scopes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Scenario,

        [string[]]$RequiredAllScopes = @(),

        [string[]]$RequiredAnyScopeSets = @(),

        [string[]]$FallbackScopes = @()
    )

    $graphToken = Get-ArmToken -ResourceUrl $Script:GraphApiBaseUrl
    $grantedScopes = Get-GrantedScopesFromToken -AccessToken $graphToken
    $scopeStatus = Test-GraphScopeRequirement -GrantedScopes $grantedScopes -RequiredAllScopes $RequiredAllScopes -RequiredAnyScopeSets $RequiredAnyScopeSets

    if ($scopeStatus.IsSatisfied) {
        Write-Host "  Using Az-issued Microsoft Graph token for $Scenario" -ForegroundColor Green
        return [PSCustomObject]@{
            Mode = 'AzToken'
            AccessToken = $graphToken
            GrantedScopes = $grantedScopes
        }
    }

    $requiredScopeList = @($FallbackScopes | Sort-Object -Unique)
    $missingText = if ($scopeStatus.MissingRequirements.Count -gt 0) {
        $scopeStatus.MissingRequirements -join ', '
    }
    else {
        'unknown'
    }

    Write-Host "  Az-issued Microsoft Graph token is missing required delegated scopes for $Scenario." -ForegroundColor Yellow
    Write-Host "  Missing requirements: $missingText" -ForegroundColor Yellow

    if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        if ($requiredScopeList.Count -eq 0) {
            throw "Fallback scopes were not provided for Graph scenario '$Scenario'."
        }

        Write-Host '  Falling back to Microsoft.Graph.Authentication...' -ForegroundColor Gray
        Connect-MgGraph -Scopes $requiredScopeList -NoWelcome -ErrorAction Stop
        return [PSCustomObject]@{
            Mode = 'MgGraph'
            RequestedScopes = $requiredScopeList
        }
    }

    $scopeHint = $requiredScopeList -join ', '
    throw @"
Microsoft Graph delegated permissions are missing for $Scenario.
Az issued a Graph token without the required delegated scopes.
Missing requirements: $missingText

To continue, either:
  1. install the fallback module and re-run:
     Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  2. have an Entra admin grant these delegated Microsoft Graph permissions to the '$($Script:AzPowerShellGraphAppName)' enterprise application, then re-run:
     $scopeHint

The signed-in user still needs the appropriate Entra role, such as Application Administrator.
"@
}

function Invoke-GraphApi {
    <#
    .SYNOPSIS
        Wrapper for Microsoft Graph REST calls using either Az tokens or the
        Microsoft.Graph.Authentication fallback session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method,

        $Body,

        [string]$Description = 'Microsoft Graph API call'
    )

    $requestUri = if ($Uri -match '^https?://') { $Uri } else { "$($Script:GraphApiBaseUrl)$Uri" }

    try {
        if ($Context.Mode -eq 'AzToken') {
            $headers = @{
                Authorization = "Bearer $($Context.AccessToken)"
            }

            $invokeParams = @{
                Uri = $requestUri
                Method = $Method
                Headers = $headers
                ErrorAction = 'Stop'
            }

            if ($null -ne $Body) {
                $invokeParams.ContentType = 'application/json'
                $invokeParams.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 }
            }

            return Invoke-RestMethod @invokeParams
        }

        if ($Context.Mode -eq 'MgGraph') {
            $invokeParams = @{
                Uri = $Uri
                Method = $Method
                ErrorAction = 'Stop'
            }

            if ($null -ne $Body) {
                $invokeParams.Body = $Body
            }

            return Invoke-MgGraphRequest @invokeParams
        }

        throw "Unsupported Graph context mode '$($Context.Mode)'."
    }
    catch {
        $errorDetail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $errorDetail = $_.ErrorDetails.Message
        }

        throw "$Description failed: $errorDetail"
    }
}