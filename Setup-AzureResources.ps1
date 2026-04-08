<#
.SYNOPSIS
    Provisions Azure resources for the Defender vulnerability dashboard pipeline.

.DESCRIPTION
    Creates and configures the following Azure resources:
    - Resource Group (if not exists)
    - Azure Automation Account with System-Assigned Managed Identity (default),
      OR Azure Function App on Flex Consumption plan (with -ComputeType FunctionApp)
    - Azure Storage Account configured per Microsoft Security Benchmark
    - Blob containers (exports, templates, dashboards)
    - RBAC: Storage Blob Data Contributor (or Owner for Function App) for the
      compute Managed Identity
    - Custom PowerShell 7.4 runtime environment with latest Az.Accounts
      (Automation) or bundled modules (Function App)
    - Runbook and daily recurring schedule (Automation) or timer-triggered
      function (Function App)
    
    Automation Account and Function App are mutually exclusive compute options.
    Both can optionally include the Container App for web delivery.
    
    After provisioning, uploads dashboard templates and runs the pipeline
    end-to-end to validate the setup. Use -SkipValidation to skip this step.
    
    Optionally assigns MDE API app role permissions to the Managed Identity
    via Microsoft Graph. The script uses Get-AzAccessToken plus native Graph
    REST calls first, and falls back to Microsoft.Graph.Authentication only
    when the Az-issued Graph token lacks the required delegated scopes.

.PARAMETER SubscriptionId
    Azure subscription ID. Defaults to the current Az context subscription.

.PARAMETER ComputeType
    Compute backend for the pipeline. AutomationAccount (default) creates an
    Azure Automation runbook with a daily schedule.  FunctionApp creates an
    Azure Function App on the Flex Consumption plan with a timer trigger.
    The two are mutually exclusive — only one compute resource is provisioned.

.PARAMETER ResourceGroupName
    Name of the resource group. Created if it does not exist.
    Must be 1-90 characters: alphanumeric, hyphens, underscores, periods, parentheses.

.PARAMETER AutomationAccountName
    Name of the Azure Automation account. Created if it does not exist.
    Required when ComputeType is AutomationAccount.
    Must be 6-50 characters: alphanumeric and hyphens, starting with a letter.

.PARAMETER FunctionAppName
    Name of the Azure Function App. Created if it does not exist.
    Required when ComputeType is FunctionApp.
    Must be 2-60 characters: alphanumeric and hyphens.

.PARAMETER StorageAccountName
    Name of the Azure Storage account. Created if it does not exist.
    Must be 3-24 characters: lowercase letters and numbers only.

.PARAMETER Location
    Azure region for all resources. Default: westus2.

.PARAMETER SkipMdePermissions
    Skip the MDE API app role assignment step. Useful if you want to handle
    MDE permissions separately or don't have the required Entra ID role.

.PARAMETER SkipValidation
    Skip the end-to-end validation step (template upload, pipeline run, and
    result check). Useful for re-provisioning infrastructure without running
    the full pipeline.

.PARAMETER IncludeContainerApp
    Provision an Azure Container Apps environment and app to serve the
    dashboard HTML with Entra ID Easy Auth (tenant-restricted SSO).
    Requires -SecurityGroup. The container uses an init container to fetch
    the dashboard from blob storage on each cold start (scale-to-zero).

.PARAMETER DashboardDeliveryMode
    Controls which dashboard packaging mode the compute pipeline publishes.
    Auto uses Hosted when -IncludeContainerApp is set, otherwise SelfContained.
    Hosted publishes the HTML plus a sibling asset directory for same-origin
    delivery through the Container App or another HTTP host.

.PARAMETER SecurityGroup
    Entra ID security group that is allowed to access the Container App
    dashboard. Accepts either an Object ID (GUID) or a display name.
    If a display name matches multiple groups, you will be prompted to
    specify the Object ID instead. Required when -IncludeContainerApp is set.

.PARAMETER ContainerAppName
    Name for the Container App. Default: derived from ResourceGroupName.
    Must be 2-32 characters: lowercase alphanumeric and hyphens.

.EXAMPLE
    .\Setup-AzureResources.ps1 -ResourceGroupName "rg-defender-reporting" `
        -AutomationAccountName "aa-defender-reporting" `
        -StorageAccountName "stdefenderreporting"

.EXAMPLE
    .\Setup-AzureResources.ps1 -ResourceGroupName "rg-defender-reporting" `
        -StorageAccountName "stdefenderreporting" `
        -ComputeType FunctionApp -FunctionAppName "func-defender-reporting"

.EXAMPLE
    # Re-run against an existing Function App (resource group and storage
    # account are auto-detected from the deployed resource):
    .\Setup-AzureResources.ps1 -ComputeType FunctionApp `
        -FunctionAppName "func-defender-reporting"

.EXAMPLE
    .\Setup-AzureResources.ps1 -ResourceGroupName "rg-defender-reporting" `
        -AutomationAccountName "aa-defender-reporting" `
        -StorageAccountName "stdefenderreporting" `
        -SkipMdePermissions

.EXAMPLE
    .\Setup-AzureResources.ps1 -ResourceGroupName "rg-defender-reporting" `
        -AutomationAccountName "aa-defender-reporting" `
        -StorageAccountName "stdefenderreporting" `
        -IncludeContainerApp -SecurityGroup "Dashboard Viewers"

.NOTES
    Author: Nathan McNulty
    
    Prerequisites:
    - Az.Accounts PowerShell module (for Invoke-AzRestMethod)
    - Microsoft.Graph.Authentication module (optional fallback when the Az-issued
      Microsoft Graph token lacks the required delegated scopes)
    - Authenticated Azure session (Connect-AzAccount)
    
    MDE API app role assignment requires the Application Administrator role in 
    Entra ID. These are app role assignments on the WindowsDefenderATP service 
    principal, NOT Microsoft Graph API permissions. Application Administrator 
    (not Global Administrator) is sufficient for this operation.
    
    Required MDE app roles assigned to the Managed Identity:
    - Machine.Read.All       (for /api/machines endpoint)
    - Vulnerability.Read.All (for bulk vulnerability export)
    - AdvancedQuery.Read.All (for Advanced Hunting queries)
#>

#Requires -Modules Az.Accounts

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Azure subscription ID (defaults to current context)")]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false, HelpMessage = "Compute backend: AutomationAccount (default) or FunctionApp")]
    [ValidateSet('AutomationAccount', 'FunctionApp')]
    [string]$ComputeType = 'AutomationAccount',

    [Parameter(Mandatory = $false, HelpMessage = "Resource group name (auto-detected from existing compute resource if omitted)")]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false, HelpMessage = "Automation account name (required for AutomationAccount compute type)")]
    [string]$AutomationAccountName,

    [Parameter(Mandatory = $false, HelpMessage = "Function App name (required for FunctionApp compute type)")]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $false, HelpMessage = "Storage account name (auto-detected from existing compute resource if omitted)")]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false, HelpMessage = "Azure region for all resources")]
    [string]$Location = 'westus2',

    [Parameter(Mandatory = $false, HelpMessage = "Skip MDE API app role assignment")]
    [switch]$SkipMdePermissions,

    [Parameter(Mandatory = $false, HelpMessage = "Skip end-to-end validation (template upload, pipeline run, result check)")]
    [switch]$SkipValidation,

    [Parameter(Mandatory = $false, HelpMessage = "Timeout in seconds for the validation polling loop")]
    [ValidateRange(60, 7200)]
    [int]$ValidationTimeoutSeconds = 1800,

    [Parameter(Mandatory = $false, HelpMessage = "Dashboard packaging mode. Auto uses Hosted when -IncludeContainerApp is set, otherwise SelfContained")]
    [ValidateSet('Auto', 'SelfContained', 'Hosted')]
    [string]$DashboardDeliveryMode = 'Auto',

    [Parameter(Mandatory = $false, HelpMessage = "Include Azure Container Apps deployment with Easy Auth")]
    [switch]$IncludeContainerApp,

    [Parameter(Mandatory = $false, HelpMessage = "Entra ID security group (Object ID or display name) for Container App access")]
    [string]$SecurityGroup,

    [Parameter(Mandatory = $false, HelpMessage = "Container App name (default: derived from resource group name)")]
    [string]$ContainerAppName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
# COMPUTE TYPE VALIDATION
# =============================================================================

if ($ComputeType -eq 'AutomationAccount' -and -not $AutomationAccountName) {
    throw "-AutomationAccountName is required when -ComputeType is AutomationAccount."
}
if ($ComputeType -eq 'FunctionApp' -and -not $FunctionAppName) {
    throw "-FunctionAppName is required when -ComputeType is FunctionApp."
}

# =============================================================================
# NAME VALIDATION & SANITIZATION
# =============================================================================

# Resource Group: 1-90 chars, alphanumeric, hyphens, underscores, periods, parentheses
if ($ResourceGroupName) {
    $originalRG = $ResourceGroupName
    $ResourceGroupName = $ResourceGroupName -replace '[^a-zA-Z0-9._\-()]', ''
    if ($ResourceGroupName.Length -gt 90) { $ResourceGroupName = $ResourceGroupName.Substring(0, 90) }
    if ($ResourceGroupName.Length -eq 0) {
        throw "Resource group name '$originalRG' contains no valid characters. Use alphanumeric, hyphens, underscores, periods, or parentheses (1-90 chars)."
    }
    if ($ResourceGroupName -ne $originalRG) {
        Write-Host "Resource group name sanitized: '$originalRG' -> '$ResourceGroupName'" -ForegroundColor Yellow
        Write-Host "  Allowed: alphanumeric, hyphens, underscores, periods, parentheses (1-90 chars)" -ForegroundColor Gray
    }
}

# Automation Account: 6-50 chars, alphanumeric and hyphens, must start with a letter
if ($ComputeType -eq 'AutomationAccount') {
    $originalAA = $AutomationAccountName
    $AutomationAccountName = $AutomationAccountName -replace '[^a-zA-Z0-9\-]', ''
    $AutomationAccountName = $AutomationAccountName.TrimStart('0123456789-'.ToCharArray())
    if ($AutomationAccountName.Length -gt 50) { $AutomationAccountName = $AutomationAccountName.Substring(0, 50) }
    if ($AutomationAccountName.Length -lt 6) {
        throw "Automation account name '$originalAA' is too short after sanitization ('$AutomationAccountName'). Must be 6-50 chars: alphanumeric and hyphens, starting with a letter."
    }
    if ($AutomationAccountName -ne $originalAA) {
        Write-Host "Automation account name sanitized: '$originalAA' -> '$AutomationAccountName'" -ForegroundColor Yellow
        Write-Host "  Allowed: alphanumeric and hyphens, must start with a letter (6-50 chars)" -ForegroundColor Gray
    }
}

# Function App: 2-60 chars, alphanumeric and hyphens
if ($ComputeType -eq 'FunctionApp') {
    $originalFA = $FunctionAppName
    $FunctionAppName = $FunctionAppName.ToLower() -replace '[^a-z0-9\-]', ''
    $FunctionAppName = $FunctionAppName.Trim('-')
    if ($FunctionAppName.Length -gt 60) { $FunctionAppName = $FunctionAppName.Substring(0, 60).TrimEnd('-') }
    if ($FunctionAppName.Length -lt 2) {
        throw "Function App name '$originalFA' is too short after sanitization ('$FunctionAppName'). Must be 2-60 chars: lowercase alphanumeric and hyphens."
    }
    if ($FunctionAppName -ne $originalFA) {
        Write-Host "Function App name sanitized: '$originalFA' -> '$FunctionAppName'" -ForegroundColor Yellow
        Write-Host "  Allowed: lowercase alphanumeric and hyphens (2-60 chars)" -ForegroundColor Gray
    }
}

# Storage Account: 3-24 chars, lowercase alphanumeric only (most restrictive)
if ($StorageAccountName) {
    $originalSA = $StorageAccountName
    $StorageAccountName = $StorageAccountName.ToLower() -replace '[^a-z0-9]', ''
    if ($StorageAccountName.Length -gt 24) { $StorageAccountName = $StorageAccountName.Substring(0, 24) }
    if ($StorageAccountName.Length -lt 3) {
        throw "Storage account name '$originalSA' is too short after sanitization ('$StorageAccountName'). Must be 3-24 chars: lowercase letters and numbers only. No hyphens, underscores, or special characters."
    }
    if ($StorageAccountName -ne $originalSA) {
        Write-Host "Storage account name sanitized: '$originalSA' -> '$StorageAccountName'" -ForegroundColor Yellow
        Write-Host "  Allowed: lowercase letters and numbers only (3-24 chars). No hyphens or special characters." -ForegroundColor Gray
    }
}

# Container App validation
if ($IncludeContainerApp) {
    if (-not $SecurityGroup) {
        $SecurityGroup = Read-Host "Enter the Entra ID security group (Object ID or display name) for dashboard access"
        if (-not $SecurityGroup) {
            throw "-SecurityGroup is required when -IncludeContainerApp is specified. Provide an Entra ID security group Object ID (GUID) or display name."
        }
    }

    # Container App name: 2-32 chars, lowercase alphanumeric and hyphens, must start/end with alphanumeric
    if (-not $ContainerAppName) {
        $ContainerAppName = "ca-$($ResourceGroupName -replace '^rg-','')"
    }
    $originalCA = $ContainerAppName
    $ContainerAppName = $ContainerAppName.ToLower() -replace '[^a-z0-9\-]', ''
    $ContainerAppName = $ContainerAppName.Trim('-')
    if ($ContainerAppName.Length -gt 32) { $ContainerAppName = $ContainerAppName.Substring(0, 32).TrimEnd('-') }
    if ($ContainerAppName.Length -lt 2) {
        throw "Container App name '$originalCA' is too short after sanitization ('$ContainerAppName'). Must be 2-32 chars: lowercase alphanumeric and hyphens."
    }
    if ($ContainerAppName -ne $originalCA) {
        Write-Host "Container App name sanitized: '$originalCA' -> '$ContainerAppName'" -ForegroundColor Yellow
        Write-Host "  Allowed: lowercase alphanumeric and hyphens (2-32 chars)" -ForegroundColor Gray
    }

    # Derive environment name from container app name
    $ContainerAppEnvName = "cae-$($ContainerAppName -replace '^ca-','')"
    if ($ContainerAppEnvName.Length -gt 60) { $ContainerAppEnvName = $ContainerAppEnvName.Substring(0, 60).TrimEnd('-') }
}

$effectiveDashboardDeliveryMode = switch ($DashboardDeliveryMode) {
    'Auto' {
        if ($IncludeContainerApp) { 'Hosted' } else { 'SelfContained' }
    }
    default { $DashboardDeliveryMode }
}

Write-Host "Dashboard delivery mode resolved to '$effectiveDashboardDeliveryMode'" -ForegroundColor Cyan
Write-Host "Compute type: $ComputeType" -ForegroundColor Cyan

# =============================================================================
# CONSTANTS
# =============================================================================

$Script:ArmApiVersions = @{
    ResourceGroups     = '2021-04-01'
    AutomationAccount  = '2023-11-01'
    RuntimeEnvironment = '2024-10-23'
    StorageAccount     = '2023-05-01'
    RoleAssignment     = '2022-04-01'
    WebApp             = '2024-04-01'
}

$Script:RuntimeEnvName = 'PowerShell-74-AzAccounts'

$Script:StorageBlobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
$Script:StorageBlobDataOwnerRoleId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
$Script:StorageQueueDataContributorRoleId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
$Script:StorageTableDataContributorRoleId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
$Script:MdeAppId = 'fc780465-2017-40d4-a0c5-307022471b92'
$Script:GraphApiBaseUrl = 'https://graph.microsoft.com'
$Script:AzPowerShellGraphAppName = 'Microsoft Azure PowerShell'

$Script:MdeAppRoles = @(
    'Machine.Read.All',
    'Vulnerability.Read.All',
    'AdvancedQuery.Read.All'
)

$Script:BlobContainers = @('exports', 'templates', 'dashboards')
$Script:FunctionAppDeploymentContainer = 'app-package'
$Script:AutomationDailyScheduleName = 'DashboardPipeline-Daily'
$Script:AutomationLegacyWeeklyScheduleName = 'DashboardPipeline-Every7Days'

# Container Apps constants
$Script:ArmApiVersions.ContainerAppEnvironment = '2024-03-01'
$Script:ArmApiVersions.ContainerApp = '2024-03-01'
$Script:StorageBlobDataReaderRoleId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
$Script:CaddyImage = 'docker.io/library/caddy:alpine'
$Script:DashboardBlobName = 'VulnerabilityDashboard.html'
$Script:DashboardAssetsDirectoryName = ([System.IO.Path]::GetFileNameWithoutExtension($Script:DashboardBlobName) + '.assets')
$Script:DashboardHostedAssetFileNames = @('dashboard.css', 'dashboard.js', 'pako.js', 'chart.js', 'pdf-export.bundle.js', 'payload.json.gz')
$Script:ProvisioningTags = @{
    workload = 'defender-reporting'
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

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

        [string]$Description = "ARM API call"
    )

    $params = @{
        Path   = $Path
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

    $errorDetail = ""
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
        $jobSchedulesResponse = Invoke-ArmApi -Path $jobSchedulesPath -Method GET -Description "List Automation job schedules"
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
        throw "Token is not a valid JWT."
    }

    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
        0 { }
        default { throw "JWT payload is not valid Base64Url." }
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
        IsSatisfied         = ($missingRequirements.Count -eq 0)
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
            Mode         = 'AzToken'
            AccessToken  = $graphToken
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

        Write-Host "  Falling back to Microsoft.Graph.Authentication..." -ForegroundColor Gray
        Connect-MgGraph -Scopes $requiredScopeList -NoWelcome -ErrorAction Stop
        return [PSCustomObject]@{
            Mode          = 'MgGraph'
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
                Uri         = $requestUri
                Method      = $Method
                Headers     = $headers
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
                Uri         = $Uri
                Method      = $Method
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

# =============================================================================
# MAIN SCRIPT
# =============================================================================

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Azure Resource Setup" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # -------------------------------------------------------------------------
    # Step 1: Verify Azure connection and set subscription
    # -------------------------------------------------------------------------
    Write-Host "Step 1: Verifying Azure connection..." -ForegroundColor Cyan

    $context = Get-AzContext
    if (-not $context) {
        Write-Host "  Not connected to Azure. Launching Connect-AzAccount..." -ForegroundColor Yellow
        Connect-AzAccount -ErrorAction Stop | Out-Null
        $context = Get-AzContext
        if (-not $context) {
            throw "Failed to connect to Azure. Run Connect-AzAccount manually and try again."
        }
    }
    Write-Host "  Connected as: $($context.Account.Id)" -ForegroundColor Green

    if (-not $SubscriptionId) {
        $SubscriptionId = $context.Subscription.Id
        Write-Host "  Using current subscription: $SubscriptionId" -ForegroundColor Gray
    }
    else {
        Write-Host "  Setting subscription to: $SubscriptionId" -ForegroundColor Gray
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    }

    $subPath = "/subscriptions/$SubscriptionId"

    # -------------------------------------------------------------------------
    # Auto-discover ResourceGroupName and StorageAccountName from existing resource
    # (Read-only lookups — suppress WhatIf so Invoke-AzRestMethod executes)
    # -------------------------------------------------------------------------
    if (-not $ResourceGroupName -or -not $StorageAccountName) {
        $savedWhatIf = $WhatIfPreference
        $WhatIfPreference = $false
        try {
        $computeName = if ($ComputeType -eq 'FunctionApp') { $FunctionAppName } else { $AutomationAccountName }
        $providerType = if ($ComputeType -eq 'FunctionApp') { 'Microsoft.Web/sites' } else { 'Microsoft.Automation/automationAccounts' }
        Write-Host "`nLooking up existing $ComputeType '$computeName'..." -ForegroundColor Gray

        $found = $null
        $resources = Invoke-ArmApi -Path "$subPath/resources?`$filter=name eq '$computeName' and resourceType eq '$providerType'&api-version=2021-04-01" -Method GET -Description "Find existing $ComputeType"
        $found = $resources.value | Select-Object -First 1

        if ($found) {
            # Extract resource group from the resource ID: /subscriptions/.../resourceGroups/<RG>/providers/...
            $discoveredRG = ($found.id -split '/resourceGroups/|/providers/')[1]
            if (-not $ResourceGroupName) {
                $ResourceGroupName = $discoveredRG
                Write-Host "  Auto-detected resource group: $ResourceGroupName" -ForegroundColor Green
            }

            # Auto-detect location from existing resource if not explicitly provided
            if (-not $PSBoundParameters.ContainsKey('Location') -and $found.location) {
                $Location = $found.location
                Write-Host "  Auto-detected location: $Location" -ForegroundColor Green
            }

            if (-not $StorageAccountName) {
                if ($ComputeType -eq 'FunctionApp') {
                    $apiVer = $Script:ArmApiVersions.WebApp
                    $appSettings = Invoke-ArmApi -Path "$subPath/resourceGroups/$discoveredRG/providers/Microsoft.Web/sites/$FunctionAppName/config/appsettings/list?api-version=$apiVer" -Method POST -Description 'Read app settings'
                    $StorageAccountName = $appSettings.properties.STORAGE_ACCOUNT_NAME
                    if (-not $StorageAccountName) {
                        $StorageAccountName = $appSettings.properties.'AzureWebJobsStorage__accountName'
                    }
                } else {
                    # Automation Account: look up the StorageAccountName variable
                    try {
                        $apiVer = $Script:ArmApiVersions.AutomationAccount
                        $varPath = "$subPath/resourceGroups/$discoveredRG/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/variables/StorageAccountName?api-version=$apiVer"
                        $saVar = Invoke-ArmApi -Path $varPath -Method GET -Description 'Read StorageAccountName variable'
                        # Variable values are JSON-encoded strings (e.g. '"stname"')
                        $StorageAccountName = ($saVar.properties.value | ConvertFrom-Json)
                    } catch {
                        Write-Verbose "StorageAccountName variable not found on Automation Account: $_"
                    }
                }

                if ($StorageAccountName) {
                    Write-Host "  Auto-detected storage account: $StorageAccountName" -ForegroundColor Green
                } else {
                    throw "Could not auto-detect -StorageAccountName from existing $ComputeType '$computeName'. Please provide it explicitly."
                }
            }
        } else {
            # Resource doesn't exist yet — both params are required for first-time setup
            $missing = @()
            if (-not $ResourceGroupName) { $missing += '-ResourceGroupName' }
            if (-not $StorageAccountName) { $missing += '-StorageAccountName' }
            if ($missing) {
                throw "No existing $ComputeType '$computeName' found. For first-time setup, provide: $($missing -join ', ')"
            }
        }
        } finally { $WhatIfPreference = $savedWhatIf }
    }

    # -------------------------------------------------------------------------
    # Step 2: Create/verify Resource Group
    # -------------------------------------------------------------------------
    Write-Host "`nStep 2: Resource Group '$ResourceGroupName'..." -ForegroundColor Cyan

    $rgPath = "$subPath/resourceGroups/${ResourceGroupName}?api-version=$($Script:ArmApiVersions.ResourceGroups)"

    $rg = $null
    $rgExists = $false
    try {
        $rg = Invoke-ArmApi -Path $rgPath -Method GET -Description "Check resource group"
        $rgExists = $true
        Write-Host "  Resource group already exists in $($rg.location)" -ForegroundColor Green
    }
    catch {
        if (Test-IsArmNotFoundError -ErrorRecord $_) {
            Write-Host "  Resource group not found, creating..." -ForegroundColor Gray
        }
        else {
            throw
        }
    }

    $rgAction = if ($rgExists) { 'Update resource group tags' } else { 'Create resource group' }
    if ($PSCmdlet.ShouldProcess($ResourceGroupName, $rgAction)) {
        $rgTags = @{}
        $existingTags = if ($rgExists -and $null -ne $rg) { $rg.PSObject.Properties['tags']?.Value } else { $null }
        if ($rgExists -and $null -ne $existingTags) {
            foreach ($property in $existingTags.PSObject.Properties) {
                $rgTags[$property.Name] = [string]$property.Value
            }
        }
        foreach ($tagKey in $Script:ProvisioningTags.Keys) {
            $rgTags[$tagKey] = $Script:ProvisioningTags[$tagKey]
        }

        $rgPayload = @{
            location = if ($rgExists) { $rg.location } else { $Location }
            tags     = $rgTags
        } | ConvertTo-Json -Depth 5

        Invoke-ArmApi -Path $rgPath -Method PUT -Payload $rgPayload -Description "Create/update resource group" | Out-Null
        if ($rgExists) {
            Write-Host "  Resource group tags updated" -ForegroundColor Green
        }
        else {
            Write-Host "  Resource group created" -ForegroundColor Green
        }
    }

    # -------------------------------------------------------------------------
    # Step 3: Create/verify Compute Resource (Automation Account or Function App)
    # -------------------------------------------------------------------------
    if ($ComputeType -eq 'AutomationAccount') {
        Write-Host "`nStep 3: Automation Account '$AutomationAccountName'..." -ForegroundColor Cyan

        $aaPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/${AutomationAccountName}?api-version=$($Script:ArmApiVersions.AutomationAccount)"

        $aaPayload = @{
            location   = $Location
            tags       = $Script:ProvisioningTags
            identity   = @{
                type = "SystemAssigned"
            }
            properties = @{
                sku              = @{ name = "Basic" }
                disableLocalAuth = $true
            }
        } | ConvertTo-Json -Depth 5

        if ($PSCmdlet.ShouldProcess($AutomationAccountName, "Create/update automation account")) {
            $null = Invoke-ArmApi -Path $aaPath -Method PUT -Payload $aaPayload -Description "Create/update automation account"
            Write-Host "  Automation account ready with Managed Identity enabled" -ForegroundColor Green
        }

        # Step 4: Poll for Managed Identity principal ID (Automation Account)
        Write-Host "`nStep 4: Waiting for Managed Identity..." -ForegroundColor Cyan

        $miPrincipalId = $null
        $miReady = Wait-WithPolling -Description "Managed Identity principal ID" -IntervalSeconds 5 -TimeoutSeconds 60 -Condition {
            $aa = Invoke-ArmApi -Path $aaPath -Method GET -Description "Check MI"
            if ($aa.identity -and $aa.identity.principalId) {
                $script:miPrincipalId = $aa.identity.principalId
                return $true
            }
            return $false
        }

        if (-not $miReady -or -not $miPrincipalId) {
            throw "Managed Identity principal ID was not available after polling. Check the Automation Account in the portal."
        }
        Write-Host "  Managed Identity principal ID: $miPrincipalId" -ForegroundColor Green

    } elseif ($ComputeType -eq 'FunctionApp') {
        Write-Host "`nStep 3: Function App '$FunctionAppName' (Flex Consumption)..." -ForegroundColor Cyan

        # 3a: Create Flex Consumption App Service Plan
        $planName = "$FunctionAppName-plan"
        $planPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/serverfarms/${planName}?api-version=$($Script:ArmApiVersions.WebApp)"

        $planPayload = @{
            location   = $Location
            tags       = $Script:ProvisioningTags
            kind       = "functionapp"
            sku        = @{
                name = "FC1"
                tier = "FlexConsumption"
            }
            properties = @{
                reserved = $true
            }
        } | ConvertTo-Json -Depth 5

        if ($PSCmdlet.ShouldProcess($planName, "Create/update Flex Consumption plan")) {
            $null = Invoke-ArmApi -Path $planPath -Method PUT -Payload $planPayload -Description "Create/update Flex Consumption plan"
            Write-Host "  Flex Consumption plan '$planName' ready" -ForegroundColor Green
        }

        # 3b: Create Function App with system-assigned Managed Identity
        $functionAppPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/${FunctionAppName}?api-version=$($Script:ArmApiVersions.WebApp)"

        $functionAppPayload = @{
            location   = $Location
            tags       = $Script:ProvisioningTags
            kind       = "functionapp,linux"
            identity   = @{
                type = "SystemAssigned"
            }
            properties = @{
                serverFarmId    = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/serverfarms/$planName"
                siteConfig      = @{
                    appSettings = @(
                        @{ name = "AzureWebJobsStorage__accountName"; value = $StorageAccountName }
                        @{ name = "FUNCTIONS_EXTENSION_VERSION"; value = "~4" }
                        @{ name = "STORAGE_ACCOUNT_NAME"; value = $StorageAccountName }
                        @{ name = "DASHBOARD_DELIVERY_MODE"; value = $effectiveDashboardDeliveryMode }
                        @{ name = "INCLUDE_ADVANCED_HUNTING"; value = "true" }
                    )
                }
                functionAppConfig = @{
                    deployment     = @{
                        storage = @{
                            type  = "blobContainer"
                            value = "https://${StorageAccountName}.blob.core.windows.net/$($Script:FunctionAppDeploymentContainer)"
                            authentication = @{
                                type = "SystemAssignedIdentity"
                            }
                        }
                    }
                    scaleAndConcurrency = @{
                        instanceMemoryMB     = 2048
                        maximumInstanceCount = 100
                    }
                    runtime = @{
                        name    = "powershell"
                        version = "7.4"
                    }
                }
            }
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess($FunctionAppName, "Create/update Function App")) {
            $null = Invoke-ArmApi -Path $functionAppPath -Method PUT -Payload $functionAppPayload -Description "Create/update Function App"
            Write-Host "  Function App '$FunctionAppName' created with Managed Identity" -ForegroundColor Green
        }

        # Step 4: Poll for Managed Identity principal ID (Function App)
        Write-Host "`nStep 4: Waiting for Managed Identity..." -ForegroundColor Cyan

        $miPrincipalId = $null
        $miReady = Wait-WithPolling -Description "Managed Identity principal ID" -IntervalSeconds 5 -TimeoutSeconds 60 -Condition {
            $fa = Invoke-ArmApi -Path $functionAppPath -Method GET -Description "Check MI"
            if ($fa.identity -and $fa.identity.principalId) {
                $script:miPrincipalId = $fa.identity.principalId
                return $true
            }
            return $false
        }

        if (-not $miReady -or -not $miPrincipalId) {
            throw "Managed Identity principal ID was not available after polling. Check the Function App in the portal."
        }
        Write-Host "  Managed Identity principal ID: $miPrincipalId" -ForegroundColor Green
    }

    # -------------------------------------------------------------------------
    # Step 5: Create/verify Storage Account (Microsoft Security Benchmark)
    # -------------------------------------------------------------------------
    Write-Host "`nStep 5: Storage Account..." -ForegroundColor Cyan

    # If the resource group already existed, check for an existing storage account matching the provided name
    $storageNameFinal = $StorageAccountName
    $existingStorageFound = $false
    if ($rgExists) {
        # First, check if the exact name exists in this resource group
        $saCheckPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/${StorageAccountName}?api-version=$($Script:ArmApiVersions.StorageAccount)"
        try {
            Invoke-ArmApi -Path $saCheckPath -Method GET -Description "Check existing storage account" | Out-Null
            $storageNameFinal = $StorageAccountName
            $existingStorageFound = $true
            Write-Host "  Storage account '$StorageAccountName' already exists in resource group" -ForegroundColor Green
        }
        catch {
            if (-not (Test-IsArmNotFoundError -ErrorRecord $_)) {
                throw
            }

            # Exact name not found — only reuse a single tagged account that clearly belongs to this deployment.
            $saListPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts?api-version=$($Script:ArmApiVersions.StorageAccount)"
            $saList = Invoke-ArmApi -Path $saListPath -Method GET -Description "List storage accounts in RG"
            $matchingSa = @(
                @($saList.value) | Where-Object {
                    $_.name -like "${StorageAccountName}*" -and
                    $_.tags -and
                    $_.tags.workload -eq $Script:ProvisioningTags.workload
                }
            )

            if ($matchingSa.Count -eq 1) {
                $storageNameFinal = $matchingSa[0].name
                $existingStorageFound = $true
                Write-Host "  Reusing tagged storage account '$storageNameFinal' in resource group" -ForegroundColor Green
            }
            elseif ($matchingSa.Count -gt 1) {
                $candidateNames = ($matchingSa | ForEach-Object { $_.name }) -join ', '
                throw "Multiple tagged storage accounts matched prefix '$StorageAccountName' in '$ResourceGroupName': $candidateNames. Re-run with the exact -StorageAccountName you want to use."
            }
        }
    }

    if (-not $existingStorageFound) {
        # Check name availability; append 4 random digits if taken (up to 3 attempts)
        $maxAttempts = 3
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            $checkPath = "$subPath/providers/Microsoft.Storage/checkNameAvailability?api-version=$($Script:ArmApiVersions.StorageAccount)"
            $checkPayload = @{
                name = $storageNameFinal
                type = "Microsoft.Storage/storageAccounts"
            } | ConvertTo-Json

            $checkResult = Invoke-ArmApi -Path $checkPath -Method POST -Payload $checkPayload -Description "Check storage name availability"

            if ($checkResult.nameAvailable -eq $true) {
                Write-Host "  Name '$storageNameFinal' is available" -ForegroundColor Green
                break
            }

            # Name is taken
            $reason = $checkResult.reason
            $message = $checkResult.message
            Write-Host "  Name '$storageNameFinal' is not available ($reason): $message" -ForegroundColor Yellow

            if ($attempt -lt $maxAttempts) {
                # Append 4 random digits, truncating base name to stay within 24 char limit
                $suffix = (Get-Random -Minimum 1000 -Maximum 9999).ToString()
                $baseName = $StorageAccountName
                if (($baseName.Length + $suffix.Length) -gt 24) {
                    $baseName = $baseName.Substring(0, 24 - $suffix.Length)
                }
                $storageNameFinal = "$baseName$suffix"
                Write-Host "  Trying '$storageNameFinal' instead (attempt $($attempt + 1)/$maxAttempts)..." -ForegroundColor Gray
            }
            else {
                throw "Unable to find an available storage account name after $maxAttempts attempts. Try a different -StorageAccountName value."
            }
        }
    }

    # Update variable if name changed (so downstream steps and outputs use the final name)
    $StorageAccountName = $storageNameFinal
    Write-Host "  Using storage account name: $StorageAccountName" -ForegroundColor Cyan

    $saPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/${StorageAccountName}?api-version=$($Script:ArmApiVersions.StorageAccount)"

    $saPayload = @{
        location   = $Location
        kind       = "StorageV2"
        tags       = $Script:ProvisioningTags
        sku        = @{ name = "Standard_LRS" }
        properties = @{
            minimumTlsVersion          = "TLS1_2"
            supportsHttpsTrafficOnly   = $true
            allowBlobPublicAccess      = $false
            allowSharedKeyAccess       = $false
            defaultToOAuthAuthentication = $true
            networkAcls                = @{
                defaultAction = "Allow"
            }
        }
    } | ConvertTo-Json -Depth 5

    if ($PSCmdlet.ShouldProcess($StorageAccountName, "Create/update storage account")) {
        Invoke-ArmApi -Path $saPath -Method PUT -Payload $saPayload -Description "Create/update storage account" | Out-Null

        # Storage account creation is async - poll for provisioning state
        Wait-WithPolling -Description "Storage account provisioning" -IntervalSeconds 5 -TimeoutSeconds 120 -Condition {
            $sa = Invoke-ArmApi -Path $saPath -Method GET -Description "Check storage provisioning"
            return ($sa.properties.provisioningState -eq 'Succeeded')
        } | Out-Null

        Write-Host "  Storage account created with security best practices:" -ForegroundColor Green
        Write-Host "    - TLS 1.2 minimum" -ForegroundColor Gray
        Write-Host "    - HTTPS only" -ForegroundColor Gray
        Write-Host "    - No public blob access" -ForegroundColor Gray
        Write-Host "    - Shared key access disabled (Entra ID auth only)" -ForegroundColor Gray
    }

    # -------------------------------------------------------------------------
    # Step 6: Configure blob soft delete policies
    # -------------------------------------------------------------------------
    Write-Host "`nStep 6: Configuring blob soft delete..." -ForegroundColor Cyan

    $blobServicePath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/blobServices/default?api-version=$($Script:ArmApiVersions.StorageAccount)"

    $softDeletePayload = @{
        properties = @{
            deleteRetentionPolicy          = @{ enabled = $true; days = 7 }
            containerDeleteRetentionPolicy = @{ enabled = $true; days = 7 }
        }
    } | ConvertTo-Json -Depth 5

    if ($PSCmdlet.ShouldProcess($StorageAccountName, "Configure soft delete")) {
        Invoke-ArmApi -Path $blobServicePath -Method PUT -Payload $softDeletePayload -Description "Configure soft delete" | Out-Null
        Write-Host "  Blob soft delete: 7 days, Container soft delete: 7 days" -ForegroundColor Green
    }

    # Configure lifecycle management policy for access tier optimization
    Write-Host "  Configuring lifecycle management policy..." -ForegroundColor Gray

    $lifecyclePath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/managementPolicies/default?api-version=$($Script:ArmApiVersions.StorageAccount)"

    $lifecyclePayload = @{
        properties = @{
            policy = @{
                rules = @(
                    @{
                        name    = 'TierTemplatesToCool'
                        enabled = $true
                        type    = 'Lifecycle'
                        definition = @{
                            filters = @{
                                blobTypes   = @('blockBlob')
                                prefixMatch = @('templates/')
                            }
                            actions = @{
                                baseBlob = @{
                                    tierToCool = @{ daysAfterCreationGreaterThan = 1 }
                                }
                            }
                        }
                    }
                )
            }
        }
    } | ConvertTo-Json -Depth 10

    if ($PSCmdlet.ShouldProcess($StorageAccountName, "Configure lifecycle management policy")) {
        Invoke-ArmApi -Path $lifecyclePath -Method PUT -Payload $lifecyclePayload -Description "Configure lifecycle policy" | Out-Null
        Write-Host "  Lifecycle policy: templates -> Cool (1 day)" -ForegroundColor Green
        Write-Host "  Exports and dashboards stay Hot for daily overwrite/read patterns" -ForegroundColor Gray
    }

    # -------------------------------------------------------------------------
    # Step 7: Create blob containers
    # -------------------------------------------------------------------------
    Write-Host "`nStep 7: Creating blob containers..." -ForegroundColor Cyan

    foreach ($containerName in $Script:BlobContainers) {
        $containerPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/blobServices/default/containers/${containerName}?api-version=$($Script:ArmApiVersions.StorageAccount)"

        if ($PSCmdlet.ShouldProcess($containerName, "Create blob container")) {
            try {
                Invoke-ArmApi -Path $containerPath -Method PUT -Payload '{}' -Description "Create container '$containerName'" | Out-Null
                Write-Host "  Container '$containerName' created" -ForegroundColor Green
            }
            catch {
                if ($_.Exception.Message -match '409|Conflict|already exists') {
                    Write-Host "  Container '$containerName' already exists" -ForegroundColor Green
                }
                else { throw }
            }
        }
    }

    # Function App: also create deployment container for zip package
    if ($ComputeType -eq 'FunctionApp') {
        $deployContainerPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/blobServices/default/containers/$($Script:FunctionAppDeploymentContainer)?api-version=$($Script:ArmApiVersions.StorageAccount)"
        if ($PSCmdlet.ShouldProcess($Script:FunctionAppDeploymentContainer, "Create deployment container")) {
            try {
                Invoke-ArmApi -Path $deployContainerPath -Method PUT -Payload '{}' -Description "Create deployment container" | Out-Null
                Write-Host "  Container '$($Script:FunctionAppDeploymentContainer)' created (deployment)" -ForegroundColor Green
            }
            catch {
                if ($_.Exception.Message -match '409|Conflict|already exists') {
                    Write-Host "  Container '$($Script:FunctionAppDeploymentContainer)' already exists" -ForegroundColor Green
                }
                else { throw }
            }
        }
    }

    # -------------------------------------------------------------------------
    # Step 8: Assign Storage RBAC roles to Managed Identity
    # -------------------------------------------------------------------------
    if ($ComputeType -eq 'FunctionApp') {
        # Function App needs elevated roles: Blob Data Owner (runtime manages containers),
        # Queue Data Contributor (timer triggers), Table Data Contributor (host state)
        Write-Host "`nStep 8: Assigning Storage RBAC roles to Function App MI..." -ForegroundColor Cyan

        $storageRoles = @(
            @{ Name = 'Storage Blob Data Owner';          RoleId = $Script:StorageBlobDataOwnerRoleId }
            @{ Name = 'Storage Queue Data Contributor';   RoleId = $Script:StorageQueueDataContributorRoleId }
            @{ Name = 'Storage Table Data Contributor';   RoleId = $Script:StorageTableDataContributorRoleId }
        )

        foreach ($role in $storageRoles) {
            $roleAssignmentId = [guid]::NewGuid().ToString()
            $roleDefId = "$subPath/providers/Microsoft.Authorization/roleDefinitions/$($role.RoleId)"
            $roleAssignmentPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/providers/Microsoft.Authorization/roleAssignments/${roleAssignmentId}?api-version=$($Script:ArmApiVersions.RoleAssignment)"

            $rolePayload = @{
                properties = @{
                    principalId      = $miPrincipalId
                    roleDefinitionId = $roleDefId
                    principalType    = "ServicePrincipal"
                }
            } | ConvertTo-Json -Depth 5

            if ($PSCmdlet.ShouldProcess($role.Name, "Assign to Function App MI")) {
                try {
                    Invoke-ArmApi -Path $roleAssignmentPath -Method PUT -Payload $rolePayload -Description "Assign $($role.Name) role" | Out-Null
                    Write-Host "  $($role.Name) assigned" -ForegroundColor Green
                }
                catch {
                    if ($_.Exception.Message -match '409|already exists|RoleAssignmentExists') {
                        Write-Host "  $($role.Name) already assigned" -ForegroundColor Green
                    }
                    else { throw }
                }
            }
        }

        # Poll to verify role assignments are effective
        Wait-WithPolling -Description "RBAC propagation" -IntervalSeconds 5 -TimeoutSeconds 30 -Condition {
            $saResource = Invoke-ArmApi -Path "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/providers/Microsoft.Authorization/roleAssignments?api-version=$($Script:ArmApiVersions.RoleAssignment)&`$filter=principalId eq '$miPrincipalId'" -Method GET -Description "Check RBAC"
            return ($saResource.value.Count -ge 3)
        } | Out-Null

    } else {
        Write-Host "`nStep 8: Assigning Storage Blob Data Contributor role..." -ForegroundColor Cyan

        $roleAssignmentId = [guid]::NewGuid().ToString()
        $roleDefId = "$subPath/providers/Microsoft.Authorization/roleDefinitions/$($Script:StorageBlobDataContributorRoleId)"
        $roleAssignmentPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/providers/Microsoft.Authorization/roleAssignments/${roleAssignmentId}?api-version=$($Script:ArmApiVersions.RoleAssignment)"

        $rolePayload = @{
            properties = @{
                principalId      = $miPrincipalId
                roleDefinitionId = $roleDefId
                principalType    = "ServicePrincipal"
            }
        } | ConvertTo-Json -Depth 5

        if ($PSCmdlet.ShouldProcess("Storage Blob Data Contributor", "Assign to Managed Identity")) {
            try {
                Invoke-ArmApi -Path $roleAssignmentPath -Method PUT -Payload $rolePayload -Description "Assign RBAC role" | Out-Null
                Write-Host "  Role assigned successfully" -ForegroundColor Green
            }
            catch {
                if ($_.Exception.Message -match '409|already exists|RoleAssignmentExists') {
                    Write-Host "  Role assignment already exists" -ForegroundColor Green
                }
                else { throw }
            }

            # Poll to verify the role assignment is effective
            Wait-WithPolling -Description "RBAC propagation" -IntervalSeconds 5 -TimeoutSeconds 30 -Condition {
                $saResource = Invoke-ArmApi -Path "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/providers/Microsoft.Authorization/roleAssignments?api-version=$($Script:ArmApiVersions.RoleAssignment)&`$filter=principalId eq '$miPrincipalId'" -Method GET -Description "Check RBAC"
                return ($saResource.value.Count -gt 0)
            } | Out-Null
        }
    }

    # Also assign Storage Blob Data Contributor to the caller (needed for template uploads, downloads)
    Write-Host "  Assigning Storage Blob Data Contributor to current user..." -ForegroundColor Gray
    $callerObjectId = (Get-AzContext).Account.ExtendedProperties.HomeAccountId.Split('.')[0]
    if (-not $callerObjectId) {
        # Fallback: use Graph to resolve
        try {
            $graphToken = Get-ArmToken -ResourceUrl 'https://graph.microsoft.com/'
            $graphHeaders = @{ 'Authorization' = "Bearer $graphToken"; 'Content-Type' = 'application/json' }
            $meResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $graphHeaders -Method Get
            $callerObjectId = $meResponse.id
        }
        catch {
            Write-Warning "Could not determine current user's object ID. Assign Storage Blob Data Contributor manually."
        }
    }

    if ($callerObjectId) {
        $callerRoleAssignmentId = [guid]::NewGuid().ToString()
        $callerRoleDefId = "$subPath/providers/Microsoft.Authorization/roleDefinitions/$($Script:StorageBlobDataContributorRoleId)"
        $callerRolePath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/providers/Microsoft.Authorization/roleAssignments/${callerRoleAssignmentId}?api-version=$($Script:ArmApiVersions.RoleAssignment)"
        $callerRolePayload = @{
            properties = @{
                principalId      = $callerObjectId
                roleDefinitionId = $callerRoleDefId
                principalType    = "User"
            }
        } | ConvertTo-Json -Depth 5

        try {
            Invoke-ArmApi -Path $callerRolePath -Method PUT -Payload $callerRolePayload -Description "Assign RBAC to caller" | Out-Null
            Write-Host "  Role assigned to current user ($callerObjectId)" -ForegroundColor Green
        }
        catch {
            if ($_.Exception.Message -match '409|already exists|RoleAssignmentExists') {
                Write-Host "  Role already assigned to current user" -ForegroundColor Green
            }
            else {
                Write-Warning "Failed to assign role to current user: $_"
            }
        }

        # Poll for caller RBAC propagation
        Wait-WithPolling -Description "Caller RBAC propagation" -IntervalSeconds 5 -TimeoutSeconds 60 -Condition {
            $callerRoles = Invoke-ArmApi -Path "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/providers/Microsoft.Authorization/roleAssignments?api-version=$($Script:ArmApiVersions.RoleAssignment)&`$filter=principalId eq '$callerObjectId'" -Method GET -Description "Check caller RBAC"
            return ($callerRoles.value.Count -gt 0)
        } | Out-Null
    }

    # -------------------------------------------------------------------------
    # Steps 9-12: Compute-specific configuration
    # -------------------------------------------------------------------------
    if ($ComputeType -eq 'AutomationAccount') {

    # -------------------------------------------------------------------------
    # Step 9: Create custom runtime environment (PowerShell 7.4 + Az.Accounts)
    # -------------------------------------------------------------------------
    Write-Host "`nStep 9: Creating custom runtime environment..." -ForegroundColor Cyan

    $runtimeEnvPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runtimeEnvironments/$($Script:RuntimeEnvName)?api-version=$($Script:ArmApiVersions.RuntimeEnvironment)"

    $runtimeEnvPayload = @{
        location   = $Location
        tags       = $Script:ProvisioningTags
        properties = @{
            runtime         = @{
                language = 'PowerShell'
                version  = '7.4'
            }
            defaultPackages = @{}
            description     = 'PowerShell 7.4 with Az.Accounts only (no full Az module or Az CLI)'
        }
    } | ConvertTo-Json -Depth 5

    if ($PSCmdlet.ShouldProcess($Script:RuntimeEnvName, "Create runtime environment")) {
        Invoke-ArmApi -Path $runtimeEnvPath -Method PUT -Payload $runtimeEnvPayload -Description "Create runtime environment" | Out-Null
        Write-Host "  Runtime environment '$($Script:RuntimeEnvName)' created (PowerShell 7.4, no default packages)" -ForegroundColor Green

        # Add Az.Accounts package from PSGallery
        Write-Host "  Adding Az.Accounts package..." -ForegroundColor Gray
        $pkgPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runtimeEnvironments/$($Script:RuntimeEnvName)/packages/Az.Accounts?api-version=$($Script:ArmApiVersions.RuntimeEnvironment)"

        $pkgPayload = @{
            location   = $Location
            properties = @{
                contentLink = @{
                    uri = 'https://www.powershellgallery.com/api/v2/package/Az.Accounts'
                }
            }
        } | ConvertTo-Json -Depth 5

        Invoke-ArmApi -Path $pkgPath -Method PUT -Payload $pkgPayload -Description "Add Az.Accounts package" | Out-Null

        # Poll for package import completion
        Wait-WithPolling -Description "Az.Accounts package import" -IntervalSeconds 10 -TimeoutSeconds 300 -Condition {
            $pkg = Invoke-ArmApi -Path $pkgPath -Method GET -Description "Check package status"
            $state = $pkg.properties.provisioningState
            Write-Host "    Package state: $state" -ForegroundColor Gray
            return ($state -eq 'Succeeded' -or $state -eq 'Created')
        } | Out-Null

        Write-Host "  Az.Accounts package installed in runtime environment" -ForegroundColor Green
    }

    # -------------------------------------------------------------------------
    # Step 10: Create runbook
    # -------------------------------------------------------------------------
    Write-Host "`nStep 10: Creating runbook..." -ForegroundColor Cyan

    $runbookName = "Invoke-DashboardPipeline"
    $runbookPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/${runbookName}?api-version=$($Script:ArmApiVersions.RuntimeEnvironment)"

    $runbookPayload = @{
        location   = $Location
        tags       = $Script:ProvisioningTags
        properties = @{
            runbookType        = "PowerShell"
            runtimeEnvironment = $Script:RuntimeEnvName
            logProgress        = $true
            logVerbose         = $false
            description        = "Exports MDE vulnerability data, generates the HTML dashboard, and uploads results to blob storage."
        }
    } | ConvertTo-Json -Depth 5

    if ($PSCmdlet.ShouldProcess($runbookName, "Create runbook")) {
        Invoke-ArmApi -Path $runbookPath -Method PUT -Payload $runbookPayload -Description "Create runbook" | Out-Null
        Write-Host "  Runbook '$runbookName' created (PowerShell 7.4 / $($Script:RuntimeEnvName))" -ForegroundColor Green

        # Rebuild the generated runbook artifact before uploading it to Azure Automation.
        $runbookBuildPath = Join-Path -Path $PSScriptRoot -ChildPath 'azure' | Join-Path -ChildPath 'Build-Runbook.ps1'
        if (Test-Path -Path $runbookBuildPath) {
            Write-Host "  Rebuilding runbook artifact from shared helpers..." -ForegroundColor Gray
            & $runbookBuildPath
        }

        # Try to upload runbook content if the generated script exists alongside this setup script
        $runbookScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'azure' | Join-Path -ChildPath 'Invoke-DashboardPipeline.ps1'
        if (Test-Path -Path $runbookScriptPath) {
            Write-Host "  Uploading runbook content from $runbookScriptPath..." -ForegroundColor Gray

            $armToken = Get-ArmToken
            $runbookContent = Get-Content -Path $runbookScriptPath -Raw
            $draftContentUri = "https://management.azure.com$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$runbookName/draft/content?api-version=$($Script:ArmApiVersions.RuntimeEnvironment)"

            $draftHeaders = @{
                'Authorization' = "Bearer $armToken"
                'Content-Type'  = 'text/powershell'
            }
            Invoke-RestMethod -Uri $draftContentUri -Method Put -Headers $draftHeaders -Body $runbookContent | Out-Null
            Write-Host "  Draft content uploaded" -ForegroundColor Green

            # Publish the runbook
            $publishPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/runbooks/$runbookName/publish?api-version=$($Script:ArmApiVersions.RuntimeEnvironment)"
            Invoke-ArmApi -Path $publishPath -Method POST -Payload '{}' -Description "Publish runbook" | Out-Null
            Write-Host "  Runbook published" -ForegroundColor Green
        }
        else {
            Write-Host "  Runbook script not found at: $runbookScriptPath" -ForegroundColor Yellow
            Write-Host "  Run .\azure\Build-Runbook.ps1 locally or rerun this setup script to regenerate the artifact before uploading." -ForegroundColor Yellow
        }
    }

    # -------------------------------------------------------------------------
    # Step 11: Create Automation variables
    # -------------------------------------------------------------------------
    Write-Host "`nStep 11: Creating Automation variables..." -ForegroundColor Cyan

    $automationVariables = @(
        [PSCustomObject]@{
            Name = 'StorageAccountName'
            Value = $StorageAccountName
            Description = 'Storage account name for the dashboard pipeline'
        }
        [PSCustomObject]@{
            Name = 'DashboardDeliveryMode'
            Value = $effectiveDashboardDeliveryMode
            Description = 'Dashboard packaging mode for the pipeline (SelfContained or Hosted)'
        }
    )

    foreach ($automationVariable in $automationVariables) {
        $variablePath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/variables/$($automationVariable.Name)?api-version=$($Script:ArmApiVersions.AutomationAccount)"
        $variablePayload = @{
            properties = @{
                value       = "`"$($automationVariable.Value)`""
                isEncrypted = $false
                description = $automationVariable.Description
            }
        } | ConvertTo-Json -Depth 5

        if ($PSCmdlet.ShouldProcess($automationVariable.Name, "Create Automation variable")) {
            Invoke-ArmApi -Path $variablePath -Method PUT -Payload $variablePayload -Description "Create Automation variable '$($automationVariable.Name)'" | Out-Null
            Write-Host "  Variable '$($automationVariable.Name)' = '$($automationVariable.Value)'" -ForegroundColor Green
        }
    }

    # -------------------------------------------------------------------------
    # Step 12: Create schedule and link to runbook
    # -------------------------------------------------------------------------
    Write-Host "`nStep 12: Creating daily schedule..." -ForegroundColor Cyan

    $scheduleName = $Script:AutomationDailyScheduleName
    $schedulePath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/schedules/${scheduleName}?api-version=$($Script:ArmApiVersions.AutomationAccount)"
    $legacySchedulePath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/schedules/$($Script:AutomationLegacyWeeklyScheduleName)?api-version=$($Script:ArmApiVersions.AutomationAccount)"

    # Start time: tomorrow at 2:00 AM UTC
    $startTime = [DateTime]::UtcNow.Date.AddDays(1).AddHours(2).ToString("yyyy-MM-ddTHH:mm:ssZ")

    $schedulePayload = @{
        properties = @{
            description = "Runs the dashboard pipeline daily"
            startTime   = $startTime
            frequency   = "Day"
            interval    = 1
            isEnabled   = $true
            timeZone    = "UTC"
        }
    } | ConvertTo-Json -Depth 5

    if ($PSCmdlet.ShouldProcess($scheduleName, "Create schedule")) {
        Remove-AutomationJobSchedulesByScheduleName -SubscriptionPath $subPath -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ScheduleName $scheduleName
        Remove-AutomationJobSchedulesByScheduleName -SubscriptionPath $subPath -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ScheduleName $Script:AutomationLegacyWeeklyScheduleName

        try {
            Invoke-ArmApi -Path $legacySchedulePath -Method DELETE -Description "Delete legacy weekly schedule" | Out-Null
            Write-Host "  Removed legacy weekly schedule '$($Script:AutomationLegacyWeeklyScheduleName)'" -ForegroundColor Gray
        }
        catch {
            if ($_.Exception.Message -notmatch '404|NotFound') {
                throw
            }
        }

        Invoke-ArmApi -Path $schedulePath -Method PUT -Payload $schedulePayload -Description "Create schedule" | Out-Null
        Write-Host "  Schedule created: daily starting $startTime" -ForegroundColor Green

        # Link schedule to runbook
        $jobScheduleId = [guid]::NewGuid().ToString()
        $jobSchedulePath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobSchedules/${jobScheduleId}?api-version=$($Script:ArmApiVersions.AutomationAccount)"

        $jobSchedulePayload = @{
            properties = @{
                runbook    = @{ name = $runbookName }
                schedule   = @{ name = $scheduleName }
                parameters = @{
                    StorageAccountName = $StorageAccountName
                    DashboardDeliveryMode = $effectiveDashboardDeliveryMode
                }
            }
        } | ConvertTo-Json -Depth 5

        Invoke-ArmApi -Path $jobSchedulePath -Method PUT -Payload $jobSchedulePayload -Description "Link schedule to runbook" | Out-Null
        Write-Host "  Schedule linked to runbook '$runbookName'" -ForegroundColor Green
    }

    } elseif ($ComputeType -eq 'FunctionApp') {
        if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Build and deploy Function App code')) {
            # Steps 9-12 (FunctionApp): Build deployment zip and deploy
            Write-Host "`nSteps 9-12: Building and deploying Function App..." -ForegroundColor Cyan

            # Build the Function App from runbook-source.ps1
            Write-Host "  Building Function App from runbook-source.ps1..." -ForegroundColor Gray
            $buildScript = Join-Path $PSScriptRoot 'azure' 'Build-FunctionApp.ps1'
            if (-not (Test-Path $buildScript)) {
                throw "Build script not found: $buildScript. Run from the repository root."
            }
            & $buildScript
            # Build-FunctionApp.ps1 uses $ErrorActionPreference = 'Stop' and throws
            # on failure, so an explicit exit-code check is unnecessary.
            Write-Host "  Function App built successfully" -ForegroundColor Green

            # Deploy function app code via az CLI zip deployment (Flex Consumption
            # uses a Kudu-lite pipeline that packages and uploads to blob storage)
            Write-Host "  Deploying function app code via zip deployment..." -ForegroundColor Gray
            $functionAppDir = Join-Path $PSScriptRoot 'azure' 'function-app'
            $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) 'funcapp-deploy.zip'
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

            Push-Location $functionAppDir
            try {
                Compress-Archive -Path '.\*' -DestinationPath $zipPath -Force
            } finally {
                Pop-Location
            }

            az functionapp deployment source config-zip `
                --src $zipPath `
                --name $FunctionAppName `
                --resource-group $ResourceGroupName `
                --output none
            if ($LASTEXITCODE -ne 0) {
                throw "Function App zip deployment failed (exit code $LASTEXITCODE)."
            }
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            Write-Host "  Function App deployed successfully" -ForegroundColor Green
        }
    }

    # -------------------------------------------------------------------------
    # Step 13: Assign MDE API app roles via Microsoft Graph (optional)
    # -------------------------------------------------------------------------
    if (-not $SkipMdePermissions) {
        Write-Host "`nStep 13: Assigning MDE API app roles..." -ForegroundColor Cyan
        Write-Host "  This requires the Application Administrator role in Entra ID." -ForegroundColor Yellow
        Write-Host "  (These are app role assignments on WindowsDefenderATP, not Graph API permissions)" -ForegroundColor Yellow

        try {
            $mdeGraphContext = Get-GraphApiContext `
                -Scenario 'MDE app role assignment' `
                -RequiredAllScopes @('AppRoleAssignment.ReadWrite.All') `
                -RequiredAnyScopeSets @('Application.Read.All|Application.ReadWrite.All') `
                -FallbackScopes @('Application.Read.All', 'AppRoleAssignment.ReadWrite.All')

            # Find the WindowsDefenderATP service principal
            Write-Host "  Looking up WindowsDefenderATP service principal..." -ForegroundColor Gray
            $mdeSpResponse = Invoke-GraphApi -Context $mdeGraphContext -Method GET -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($Script:MdeAppId)'" -Description "Look up WindowsDefenderATP service principal"
            $mdeSp = $mdeSpResponse.value | Select-Object -First 1

            if (-not $mdeSp) {
                throw "WindowsDefenderATP service principal not found in tenant. Ensure Microsoft Defender for Endpoint is enabled."
            }

            $mdeSpObjectId = $mdeSp.id
            Write-Host "  Found MDE SP: $mdeSpObjectId" -ForegroundColor Gray

            # Assign each required app role
            foreach ($roleName in $Script:MdeAppRoles) {
                $appRole = $mdeSp.appRoles | Where-Object { $_.value -eq $roleName }
                if (-not $appRole) {
                    Write-Warning "App role '$roleName' not found on WindowsDefenderATP SP. Skipping."
                    continue
                }

                Write-Host "  Assigning $roleName..." -ForegroundColor Gray

                $body = @{
                    principalId = $miPrincipalId
                    resourceId  = $mdeSpObjectId
                    appRoleId   = $appRole.id
                }

                try {
                    Invoke-GraphApi -Context $mdeGraphContext -Method POST -Uri "/v1.0/servicePrincipals/$miPrincipalId/appRoleAssignments" -Body $body -Description "Assign MDE app role '$roleName'" | Out-Null
                    Write-Host "    $roleName assigned" -ForegroundColor Green
                }
                catch {
                    if ($_.Exception.Message -match 'Permission being assigned already exists') {
                        Write-Host "    $roleName already assigned" -ForegroundColor Green
                    }
                    else {
                        Write-Warning "Failed to assign $roleName`: $_"
                    }
                }
            }

            # Poll to verify at least one role assignment exists
            Wait-WithPolling -Description "MDE app role propagation" -IntervalSeconds 5 -TimeoutSeconds 30 -Condition {
                $assignments = Invoke-GraphApi -Context $mdeGraphContext -Method GET -Uri "/v1.0/servicePrincipals/$miPrincipalId/appRoleAssignments" -Description "Check MDE app role assignments"
                $mdeAssignments = $assignments.value | Where-Object { $_.resourceId -eq $mdeSpObjectId }
                return ($mdeAssignments.Count -ge $Script:MdeAppRoles.Count)
            } | Out-Null

            Write-Host "  MDE app roles assigned successfully" -ForegroundColor Green
        }
        catch {
            Write-Warning "MDE permission assignment failed: $_"
            Write-Host "`n  To assign manually, run:" -ForegroundColor Yellow
            Write-Host "  1. Acquire a Graph token with Application.Read.All and AppRoleAssignment.ReadWrite.All" -ForegroundColor Yellow
            Write-Host "     or use Connect-MgGraph -Scopes 'Application.Read.All','AppRoleAssignment.ReadWrite.All'" -ForegroundColor Yellow
            Write-Host "  2. Assign Machine.Read.All, Vulnerability.Read.All, AdvancedQuery.Read.All" -ForegroundColor Yellow
            Write-Host "     on the WindowsDefenderATP SP to principal: $miPrincipalId" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "`nStep 13: Skipping MDE permissions (use -SkipMdePermissions:`$false to enable)" -ForegroundColor Yellow
        Write-Host "  Managed Identity principal ID: $miPrincipalId" -ForegroundColor Gray
        Write-Host "  Assign these MDE app roles (Application Administrator required):" -ForegroundColor Gray
        foreach ($role in $Script:MdeAppRoles) {
            Write-Host "    - $role" -ForegroundColor Gray
        }
    }

    # -------------------------------------------------------------------------
    # Step 14: End-to-end validation - upload templates, run pipeline, verify
    # -------------------------------------------------------------------------
    if (-not $SkipValidation) {
        Write-Host "`nStep 14: Running end-to-end validation..." -ForegroundColor Cyan

        # 14a: Upload template files via Upload-Templates.ps1
        Write-Host "  Uploading template files..." -ForegroundColor Gray
        $uploadScript = Join-Path -Path $PSScriptRoot -ChildPath 'azure' | Join-Path -ChildPath 'Upload-Templates.ps1'
        if (-not (Test-Path -Path $uploadScript)) {
            Write-Warning "Upload-Templates.ps1 not found at: $uploadScript"
            Write-Host "  Run azure/Upload-Templates.ps1 manually before the pipeline." -ForegroundColor Yellow
        }
        else {
            & $uploadScript -StorageAccountName $StorageAccountName
        }

        if ($ComputeType -eq 'AutomationAccount') {
            # 14b: Start a runbook job
            Write-Host "  Starting validation job..." -ForegroundColor Gray
            $runbookName = 'Invoke-DashboardPipeline'
            $jobId = [guid]::NewGuid().ToString()
            $jobPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/${jobId}?api-version=$($Script:ArmApiVersions.AutomationAccount)"
            $jobPayload = @{
                properties = @{
                    runbook    = @{ name = $runbookName }
                    parameters = @{
                        StorageAccountName = $StorageAccountName
                        DashboardDeliveryMode = $effectiveDashboardDeliveryMode
                    }
                }
            } | ConvertTo-Json -Depth 5

            Invoke-ArmApi -Path $jobPath -Method PUT -Payload $jobPayload -Description "Start validation job" | Out-Null
            Write-Host "  Job $jobId started" -ForegroundColor Gray

            # 14c: Poll for completion
            $activeStates = @('New', 'Activating', 'Running', 'Queued')
            Wait-WithPolling -Description "validation job completion" -IntervalSeconds 15 -TimeoutSeconds $ValidationTimeoutSeconds -Condition {
                $jobRes = Invoke-ArmApi -Path "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/${jobId}?api-version=$($Script:ArmApiVersions.AutomationAccount)" -Method GET -Description "Poll job"
                $status = $jobRes.properties.status
                Write-Host "    Job status: $status" -ForegroundColor Gray
                return ($status -notin $activeStates)
            } | Out-Null

            # 14d: Get final status and report results
            $finalJob = Invoke-ArmApi -Path "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/${jobId}?api-version=$($Script:ArmApiVersions.AutomationAccount)" -Method GET -Description "Get final job status"
            $finalStatus = $finalJob.properties.status

            if ($finalStatus -eq 'Completed') {
                Write-Host "  Validation PASSED - runbook completed successfully" -ForegroundColor Green

                # Get summary from last few output streams
                $streamsPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/$jobId/streams?`$filter=properties/streamType eq 'Output'&api-version=$($Script:ArmApiVersions.AutomationAccount)"
                $streamsRes = Invoke-ArmApi -Path $streamsPath -Method GET -Description "Get job output"
                if ($streamsRes.value) {
                    $lastStreams = $streamsRes.value | Select-Object -Last 8
                    Write-Host "  --- Pipeline Summary ---" -ForegroundColor Cyan
                    foreach ($s in $lastStreams) {
                        try {
                            $streamDetail = Invoke-ArmApi -Path "$($s.id)?api-version=$($Script:ArmApiVersions.AutomationAccount)" -Method GET -Description "Read stream"
                            $raw = $streamDetail.properties.value
                            $val = if ($raw -is [string]) { $raw } elseif ($raw.value) { $raw.value } else { "$raw" }
                            if ($val) { Write-Host "  $val" -ForegroundColor Gray }
                        }
                        catch { $null = $_ <# Stream detail unavailable #> }
                    }
                }
            }
            else {
                Write-Warning "Validation FAILED - job status: $finalStatus"

                # Show error streams
                $errorStreamsPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/$jobId/streams?`$filter=properties/streamType eq 'Error'&api-version=$($Script:ArmApiVersions.AutomationAccount)"
                $errorRes = Invoke-ArmApi -Path $errorStreamsPath -Method GET -Description "Get error streams"
                if ($errorRes.value) {
                    foreach ($es in $errorRes.value) {
                        try {
                            $errDetail = Invoke-ArmApi -Path "$($es.id)?api-version=$($Script:ArmApiVersions.AutomationAccount)" -Method GET -Description "Read error"
                            $raw = $errDetail.properties.value
                            $msg = if ($raw -is [string]) { $raw } elseif ($raw.message) { $raw.message } elseif ($raw.value) { $raw.value } else { "$raw" }
                            Write-Host "  Error: $msg" -ForegroundColor Red
                        }
                        catch { $null = $_ <# Error detail unavailable #> }
                    }
                }

                # Also check last output streams for error context
                $outPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/$jobId/streams?`$filter=properties/streamType eq 'Output'&api-version=$($Script:ArmApiVersions.AutomationAccount)"
                $outRes = Invoke-ArmApi -Path $outPath -Method GET -Description "Get output streams"
                if ($outRes.value) {
                    $lastOut = $outRes.value | Select-Object -Last 5
                    Write-Host "  --- Last Output ---" -ForegroundColor Yellow
                    foreach ($o in $lastOut) {
                        try {
                            $oDetail = Invoke-ArmApi -Path "$($o.id)?api-version=$($Script:ArmApiVersions.AutomationAccount)" -Method GET -Description "Read output"
                            $raw = $oDetail.properties.value
                            $val = if ($raw -is [string]) { $raw } elseif ($raw.value) { $raw.value } else { "$raw" }
                            if ($val) { Write-Host "  $val" -ForegroundColor Gray }
                        }
                        catch { $null = $_ <# Stream detail unavailable #> }
                    }
                }

                throw "Validation job '$jobId' failed with status '$finalStatus'. Review the Automation job output above or re-run with -SkipValidation if you intentionally want to continue without a verified pipeline."
            }

        } elseif ($ComputeType -eq 'FunctionApp') {
            # 14b: Verify Function App is deployed and reachable
            Write-Host "  Verifying Function App deployment..." -ForegroundColor Gray

            $faCheckPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/${FunctionAppName}?api-version=$($Script:ArmApiVersions.WebApp)"
            $faCheck = Invoke-ArmApi -Path $faCheckPath -Method GET -Description "Verify Function App"

            if ($faCheck.properties.state -eq 'Running') {
                Write-Host "  Function App is running" -ForegroundColor Green
            } else {
                Write-Warning "Function App state: $($faCheck.properties.state)"
            }

            # Verify the timer function is registered
            $functionsPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/${FunctionAppName}/functions?api-version=$($Script:ArmApiVersions.WebApp)"
            try {
                $functionsRes = Invoke-ArmApi -Path $functionsPath -Method GET -Description "List functions"
                $functionCount = if ($functionsRes.value) { $functionsRes.value.Count } else { 0 }
                if ($functionCount -gt 0) {
                    Write-Host "  Function App has $functionCount function(s) deployed" -ForegroundColor Green
                    foreach ($fn in $functionsRes.value) {
                        Write-Host "    - $($fn.name)" -ForegroundColor Gray
                    }
                } else {
                    Write-Host "  No functions detected yet (may still be initializing)" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "  Could not list functions (app may still be initializing)" -ForegroundColor Yellow
            }

            Write-Host "  Validation complete - Function App deployed successfully" -ForegroundColor Green
        }
    }
    else {
        Write-Host "`nStep 14: Skipping end-to-end validation (remove -SkipValidation to enable)" -ForegroundColor Yellow
    }

    # =========================================================================
    # CONTAINER APPS DEPLOYMENT (OPTIONAL - Steps 15-20)
    # =========================================================================
    if ($IncludeContainerApp) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Container App Deployment" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan

        # -----------------------------------------------------------------
        # Step 15: Resolve security group (GUID or display name)
        # -----------------------------------------------------------------
        Write-Host "Step 15: Resolving security group '$SecurityGroup'..." -ForegroundColor Cyan

        $containerGraphContext = Get-GraphApiContext `
            -Scenario 'Container App Entra configuration' `
            -RequiredAllScopes @('AppRoleAssignment.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All') `
            -RequiredAnyScopeSets @('Application.ReadWrite.All', 'Group.Read.All|Group.ReadWrite.All') `
            -FallbackScopes @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'Group.Read.All')

        $securityGroupId = $null
        $securityGroupName = $null
        $testGuid = [guid]::Empty
        if ([guid]::TryParse($SecurityGroup, [ref]$testGuid)) {
            # Input is a GUID, verify it exists
            Write-Host "  Verifying group by Object ID: $SecurityGroup..." -ForegroundColor Gray
            try {
                $groupResult = Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/groups/$SecurityGroup" -Description "Look up security group by Object ID"
                $securityGroupId = $groupResult.id
                $securityGroupName = $groupResult.displayName
                Write-Host "  Found group: '$securityGroupName' ($securityGroupId)" -ForegroundColor Green
            }
            catch {
                throw "Security group with Object ID '$SecurityGroup' not found in Entra ID. Verify the ID is correct."
            }
        }
        else {
            # Input is a display name, search for it
            Write-Host "  Searching for group by display name: '$SecurityGroup'..." -ForegroundColor Gray
            $encodedName = [System.Uri]::EscapeDataString($SecurityGroup)
            $searchResult = Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/groups?`$filter=displayName eq '$encodedName'&`$select=id,displayName,securityEnabled" -Description "Search security group by display name"

            if (-not $searchResult.value -or $searchResult.value.Count -eq 0) {
                throw "No Entra ID group found with display name '$SecurityGroup'. Check the name or provide the Object ID (GUID) instead."
            }

            if ($searchResult.value.Count -gt 1) {
                Write-Host "`n  Multiple groups found matching '$SecurityGroup':" -ForegroundColor Yellow
                for ($i = 0; $i -lt $searchResult.value.Count; $i++) {
                    $g = $searchResult.value[$i]
                    Write-Host "    [$($i + 1)] $($g.displayName) | ID: $($g.id) | Security: $($g.securityEnabled)" -ForegroundColor Gray
                }
                $selection = Read-Host "`n  Enter the number of the group to use (1-$($searchResult.value.Count))"
                $selIndex = 0
                if (-not [int]::TryParse($selection, [ref]$selIndex) -or $selIndex -lt 1 -or $selIndex -gt $searchResult.value.Count) {
                    throw "Invalid selection '$selection'. Re-run with -SecurityGroup '<ObjectId>' to specify directly."
                }
                $searchResult = @{ value = @($searchResult.value[$selIndex - 1]) }
            }

            $securityGroupId = $searchResult.value[0].id
            $securityGroupName = $searchResult.value[0].displayName
            Write-Host "  Found group: '$securityGroupName' ($securityGroupId)" -ForegroundColor Green
        }

        # Get tenant ID for Easy Auth issuer URL
        $tenantId = (Get-AzContext).Tenant.Id
        if (-not $tenantId) {
            throw "Could not determine tenant ID from Azure context."
        }

        # -----------------------------------------------------------------
        # Step 16: Create Container Apps Environment
        # -----------------------------------------------------------------
        Write-Host "`nStep 16: Creating Container Apps Environment '$ContainerAppEnvName'..." -ForegroundColor Cyan

        $caEnvPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.App/managedEnvironments/${ContainerAppEnvName}?api-version=$($Script:ArmApiVersions.ContainerAppEnvironment)"

        $caEnvPayload = @{
            location   = $Location
            tags       = $Script:ProvisioningTags
            properties = @{
                appLogsConfiguration = @{
                    destination = ''
                }
                zoneRedundant    = $false
                workloadProfiles = @(
                    @{
                        name                = 'Consumption'
                        workloadProfileType = 'Consumption'
                    }
                )
            }
        } | ConvertTo-Json -Depth 5

        if ($PSCmdlet.ShouldProcess($ContainerAppEnvName, "Create Container Apps Environment")) {
            Invoke-ArmApi -Path $caEnvPath -Method PUT -Payload $caEnvPayload -Description "Create Container Apps Environment" | Out-Null

            # Environment creation can take 1-3 minutes
            $envDefaultDomain = $null
            Wait-WithPolling -Description "Container Apps Environment provisioning" -IntervalSeconds 10 -TimeoutSeconds 180 -Condition {
                $env = Invoke-ArmApi -Path $caEnvPath -Method GET -Description "Check environment"
                $state = $env.properties.provisioningState
                Write-Host "    Environment state: $state" -ForegroundColor Gray
                if ($state -eq 'Succeeded') {
                    $script:envDefaultDomain = $env.properties.defaultDomain
                    return $true
                }
                return $false
            } | Out-Null

            Write-Host "  Container Apps Environment created (no Log Analytics)" -ForegroundColor Green
        }

        # If environment already existed, fetch the default domain
        if (-not $envDefaultDomain) {
            $envResult = Invoke-ArmApi -Path $caEnvPath -Method GET -Description "Get environment default domain"
            $envDefaultDomain = $envResult.properties.defaultDomain
        }

        # Compute the stable app-level FQDN (not revision-specific)
        $caFqdn = "$ContainerAppName.$envDefaultDomain"

        $caEnvResourceId = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.App/managedEnvironments/$ContainerAppEnvName"

        # -----------------------------------------------------------------
        # Step 17: Create Container App (Caddy with blob download)
        # -----------------------------------------------------------------
        Write-Host "`nStep 17: Creating Container App '$ContainerAppName'..." -ForegroundColor Cyan

        $caPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.App/containerApps/${ContainerAppName}?api-version=$($Script:ArmApiVersions.ContainerApp)"

        # Build a startup script that downloads the dashboard blob using managed identity,
        # then starts Caddy to serve it. The script is base64-encoded to avoid JSON/shell
        # escaping issues. NOTE: We download in the main container (not an init container)
        # because the Container Apps identity sidecar is only available after init containers finish.
        $assetDownloadLines = @(
            foreach ($assetFileName in $Script:DashboardHostedAssetFileNames) {
                                '  download_blob /data/{0}/{1} "{0}/{1}" || true' -f $Script:DashboardAssetsDirectoryName, $assetFileName
            }
        ) -join "`n"

        $startupScript = @"
#!/bin/sh
SYNC_INTERVAL_SECONDS=60

get_token() {
    wget -qO- \
        --header "X-IDENTITY-HEADER: `$IDENTITY_HEADER" \
        "`${IDENTITY_ENDPOINT}?resource=https%3A%2F%2Fstorage.azure.com&api-version=2019-08-01" 2>/dev/null \
        | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

download_blob() {
    DEST_PATH="`$1"
    BLOB_PATH="`$2"
        TEMP_PATH="`${DEST_PATH}.tmp"
    mkdir -p "`$(dirname "`$DEST_PATH")"
        if wget -qO "`$TEMP_PATH" \
        --header "Authorization: Bearer `$TOKEN" \
        --header "x-ms-version: 2020-10-02" \
        "https://$StorageAccountName.blob.core.windows.net/dashboards/`$BLOB_PATH" 2>/dev/null; then
                mv "`$TEMP_PATH" "`$DEST_PATH"
        return 0
    fi
        rm -f "`$TEMP_PATH"
    return 1
}

sync_dashboard() {
        TOKEN="`$(get_token)"
        if [ -z "`$TOKEN" ]; then
                return 1
        fi

        download_blob /data/index.html "$($Script:DashboardBlobName)" || return 1
        mkdir -p "/data/$($Script:DashboardAssetsDirectoryName)"
$assetDownloadLines

        return 0
}

if ! sync_dashboard; then
    echo "Initial dashboard sync failed; serving the last available local copy if present." >&2
fi

(
    while true; do
        sleep "`$SYNC_INTERVAL_SECONDS"
        sync_dashboard || true
    done
) &

if [ ! -s /data/index.html ]; then
  cat > /data/index.html << 'PLACEHOLDER'
<!DOCTYPE html><html><head><title>Dashboard</title></head><body style="font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0"><div style="text-align:center"><h1>Vulnerability Dashboard</h1><p>The dashboard has not been generated yet.</p><p>Run the Automation runbook or wait for the next scheduled execution.</p></div></body></html>
PLACEHOLDER
fi

exec caddy file-server --root /data --listen :80
"@
        # Strip Windows \r\n → Unix \n so the shell script runs correctly on Linux
        $startupScriptB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($startupScript -replace "`r`n", "`n")))
        $caddyArg = "echo '$startupScriptB64' | base64 -d | sh"

        # Use System.Text.Json for reliable JSON serialization (avoids ConvertTo-Json
        # stripping args with special characters)
        $caObj = [ordered]@{
            location   = $Location
            tags       = $Script:ProvisioningTags
            identity   = @{ type = 'SystemAssigned' }
            properties = [ordered]@{
                managedEnvironmentId = $caEnvResourceId
                workloadProfileName  = 'Consumption'
                configuration        = @{
                    ingress             = @{
                        external      = $true
                        targetPort    = 80
                        transport     = 'auto'
                        allowInsecure = $false
                    }
                    activeRevisionsMode = 'Single'
                }
                template = @{
                    containers = @(
                        @{
                            image        = $Script:CaddyImage
                            name         = 'caddy'
                            command      = @('/bin/sh', '-c')
                            args         = [System.Collections.Generic.List[string]]@($caddyArg)
                            resources    = @{
                                cpu    = 0.25
                                memory = '0.5Gi'
                            }
                            volumeMounts = @(
                                @{
                                    volumeName = 'dashboard-data'
                                    mountPath  = '/data'
                                }
                            )
                        }
                    )
                    volumes = @(
                        @{
                            name        = 'dashboard-data'
                            storageType = 'EmptyDir'
                        }
                    )
                    scale = @{
                        minReplicas = 0
                        maxReplicas = 1
                    }
                }
            }
        }
        $caPayloadBytes = [System.Text.Json.JsonSerializer]::SerializeToUtf8Bytes($caObj, [System.Text.Json.JsonSerializerOptions]@{ WriteIndented = $false })
        $caPayload = [System.Text.Encoding]::UTF8.GetString($caPayloadBytes)

        if ($PSCmdlet.ShouldProcess($ContainerAppName, "Create Container App")) {
            Invoke-ArmApi -Path $caPath -Method PUT -Payload $caPayload -Description "Create Container App" | Out-Null

            # Poll for provisioning
            $camiPrincipalId = $null
            Wait-WithPolling -Description "Container App provisioning" -IntervalSeconds 10 -TimeoutSeconds 180 -Condition {
                $ca = Invoke-ArmApi -Path $caPath -Method GET -Description "Check Container App"
                $state = $ca.properties.provisioningState
                Write-Host "    Container App state: $state" -ForegroundColor Gray
                if ($state -eq 'Succeeded') {
                    $script:camiPrincipalId = $ca.identity.principalId
                    return $true
                }
                return $false
            } | Out-Null

            if (-not $camiPrincipalId) {
                throw "Container App created but Managed Identity principal ID not available."
            }

            Write-Host "  Container App created" -ForegroundColor Green
            Write-Host "    FQDN: $caFqdn" -ForegroundColor Gray
            Write-Host "    Managed Identity: $camiPrincipalId" -ForegroundColor Gray
        }

        # -----------------------------------------------------------------
        # Step 18: Assign Storage Blob Data Reader to Container App MI
        # -----------------------------------------------------------------
        Write-Host "`nStep 18: Assigning Storage Blob Data Reader to Container App MI..." -ForegroundColor Cyan

        $caRoleAssignmentId = [guid]::NewGuid().ToString()
        $caRoleDefId = "$subPath/providers/Microsoft.Authorization/roleDefinitions/$($Script:StorageBlobDataReaderRoleId)"
        $caRolePath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/providers/Microsoft.Authorization/roleAssignments/${caRoleAssignmentId}?api-version=$($Script:ArmApiVersions.RoleAssignment)"

        $caRolePayload = @{
            properties = @{
                principalId      = $camiPrincipalId
                roleDefinitionId = $caRoleDefId
                principalType    = 'ServicePrincipal'
            }
        } | ConvertTo-Json -Depth 5

        if ($PSCmdlet.ShouldProcess("Storage Blob Data Reader", "Assign to Container App MI")) {
            try {
                Invoke-ArmApi -Path $caRolePath -Method PUT -Payload $caRolePayload -Description "Assign RBAC to Container App MI" | Out-Null
                Write-Host "  Storage Blob Data Reader assigned" -ForegroundColor Green
            }
            catch {
                if ($_.Exception.Message -match '409|already exists|RoleAssignmentExists') {
                    Write-Host "  Role assignment already exists" -ForegroundColor Green
                }
                else { throw }
            }

            # Poll for RBAC propagation
            Wait-WithPolling -Description "Container App RBAC propagation" -IntervalSeconds 5 -TimeoutSeconds 60 -Condition {
                $roles = Invoke-ArmApi -Path "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/providers/Microsoft.Authorization/roleAssignments?api-version=$($Script:ArmApiVersions.RoleAssignment)&`$filter=principalId eq '$camiPrincipalId'" -Method GET -Description "Check Container App RBAC"
                return ($roles.value.Count -gt 0)
            } | Out-Null

            # Restart the Container App so it picks up the new RBAC permissions
            Write-Host "  Restarting Container App with updated permissions..." -ForegroundColor Gray
            Start-Sleep -Seconds 15

            $caBasePath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.App/containerApps/${ContainerAppName}"
            $caRevisionsList = Invoke-ArmApi -Path "${caBasePath}/revisions?api-version=$($Script:ArmApiVersions.ContainerApp)" -Method GET -Description "List revisions"
            $activeRevision = $caRevisionsList.value | Where-Object { $_.properties.active -eq $true } | Select-Object -First 1

            if ($activeRevision) {
                $revName = $activeRevision.name
                Invoke-ArmApi -Path "${caBasePath}/revisions/${revName}/deactivate?api-version=$($Script:ArmApiVersions.ContainerApp)" -Method POST -Description "Deactivate revision" | Out-Null
                Start-Sleep -Seconds 5
                Invoke-ArmApi -Path "${caBasePath}/revisions/${revName}/activate?api-version=$($Script:ArmApiVersions.ContainerApp)" -Method POST -Description "Activate revision" | Out-Null

                # Verify the Container App starts back up
                Wait-WithPolling -Description "Container App restart" -IntervalSeconds 10 -TimeoutSeconds 120 -Condition {
                    $rev = Invoke-ArmApi -Path "${caBasePath}/revisions/${revName}?api-version=$($Script:ArmApiVersions.ContainerApp)" -Method GET -Description "Check revision state"
                    $state = $rev.properties.runningState
                    Write-Host "    Revision state: $state" -ForegroundColor Gray
                    return ($state -eq 'Running' -or $state -eq 'RunningAtMaxScale')
                } | Out-Null
                Write-Host "  Container App restarted successfully" -ForegroundColor Green
            }
            else {
                Write-Host "  No active revision found to restart" -ForegroundColor Yellow
            }
        }

        # -----------------------------------------------------------------
        # Step 19: Create Entra ID App Registration for Easy Auth
        # -----------------------------------------------------------------
        Write-Host "`nStep 19: Creating Entra ID App Registration..." -ForegroundColor Cyan

        $redirectUri = "https://$caFqdn/.auth/login/aad/callback"

        # Microsoft Graph well-known IDs for openid, email, profile delegated permissions
        $msGraphResourceAppId = '00000003-0000-0000-c000-000000000000'
        $delegatedPermissions = @(
            @{ id = '37f7f235-527c-4136-accd-4a02d197296e'; type = 'Scope' }  # openid
            @{ id = '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0'; type = 'Scope' }  # email
            @{ id = '14dad69e-099b-42c9-810b-d002981feec1'; type = 'Scope' }  # profile
        )

        # Reuse an existing app registration when possible so reruns stay idempotent.
        $appDisplayName = 'Defender Reporting Dashboard'
        Write-Host "  Resolving app registration '$appDisplayName'..." -ForegroundColor Gray
        $existingApps = @(
            (Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/applications?`$filter=displayName eq '$appDisplayName'" -Description 'List matching Entra app registrations').value
        )
        $redirectMatchedApps = @(
            $existingApps | Where-Object { @($_.web.redirectUris) -contains $redirectUri }
        )

        $appResult = $null
        if ($redirectMatchedApps.Count -eq 1) {
            $appResult = $redirectMatchedApps[0]
            Write-Host "  Reusing existing app registration: $($appResult.appId)" -ForegroundColor Green
        }
        elseif ($redirectMatchedApps.Count -gt 1) {
            $candidateAppIds = ($redirectMatchedApps | ForEach-Object { $_.appId }) -join ', '
            throw "Multiple Entra app registrations named '$appDisplayName' already include redirect URI '$redirectUri': $candidateAppIds. Clean up duplicates or update the script to disambiguate before rerunning setup."
        }
        elseif ($existingApps.Count -eq 1) {
            $appResult = $existingApps[0]
            Write-Host "  Reusing existing app registration by display name: $($appResult.appId)" -ForegroundColor Green
        }
        elseif ($existingApps.Count -gt 1) {
            $candidateAppIds = ($existingApps | ForEach-Object { $_.appId }) -join ', '
            throw "Multiple Entra app registrations named '$appDisplayName' were found: $candidateAppIds. Clean up duplicates or update the script to disambiguate before rerunning setup."
        }

        $appBody = @{
            displayName    = $appDisplayName
            signInAudience = 'AzureADMyOrg'
            web            = @{
                redirectUris = @(
                    @($appResult.web.redirectUris) + @($redirectUri) |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                        Select-Object -Unique
                )
                implicitGrantSettings = @{
                    enableIdTokenIssuance = $true
                }
            }
            requiredResourceAccess = @(
                @{
                    resourceAppId  = $msGraphResourceAppId
                    resourceAccess = $delegatedPermissions
                }
            )
        }

        if ($null -eq $appResult) {
            $appResult = Invoke-GraphApi -Context $containerGraphContext -Method POST -Uri '/v1.0/applications' -Body $appBody -Description 'Create Entra app registration'
            Write-Host "  App registration created: $($appResult.appId)" -ForegroundColor Green
        }
        else {
            Invoke-GraphApi -Context $containerGraphContext -Method PATCH -Uri "/v1.0/applications/$($appResult.id)" -Body $appBody -Description 'Update Entra app registration' | Out-Null
            $appResult = Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/applications/$($appResult.id)" -Description 'Refresh Entra app registration'
            Write-Host "  App registration updated: $($appResult.appId)" -ForegroundColor Green
        }

        $appClientId = $appResult.appId

        # Create or reuse the service principal for the app.
        $existingServicePrincipals = @(
            (Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$appClientId'" -Description 'Look up service principal for app registration').value
        )
        if ($existingServicePrincipals.Count -gt 1) {
            $candidateSpIds = ($existingServicePrincipals | ForEach-Object { $_.id }) -join ', '
            throw "Multiple service principals were found for appId '$appClientId': $candidateSpIds. Resolve the duplicate principals before rerunning setup."
        }

        if ($existingServicePrincipals.Count -eq 1) {
            $spResult = $existingServicePrincipals[0]
            Write-Host "  Reusing existing service principal: $($spResult.id)" -ForegroundColor Green
        }
        else {
            Write-Host "  Creating service principal..." -ForegroundColor Gray
            $spBody = @{ appId = $appClientId }
            $spResult = Invoke-GraphApi -Context $containerGraphContext -Method POST -Uri '/v1.0/servicePrincipals' -Body $spBody -Description 'Create service principal'
            Write-Host "  Service principal created: $($spResult.id)" -ForegroundColor Green
        }

        $spObjectId = $spResult.id

        # Grant admin consent for the delegated permissions (prevents user consent prompt)
        Write-Host "  Granting admin consent for openid, email, profile..." -ForegroundColor Gray
        $msgraphSp = Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$msGraphResourceAppId'&`$select=id" -Description 'Look up Microsoft Graph service principal'
        $msgraphSpId = $msgraphSp.value[0].id

        $oauth2Body = @{
            clientId    = $spObjectId
            consentType = 'AllPrincipals'
            principalId = $null
            resourceId  = $msgraphSpId
            scope       = 'openid email profile'
        }
        try {
            Invoke-GraphApi -Context $containerGraphContext -Method POST -Uri '/v1.0/oauth2PermissionGrants' -Body $oauth2Body -Description 'Grant delegated admin consent' | Out-Null
            Write-Host "  Admin consent granted" -ForegroundColor Green
        }
        catch {
            if ($_.Exception.Message -match 'already exists') {
                Write-Host "  Admin consent already granted" -ForegroundColor Green
            }
            else {
                Write-Host "`n  Failed to grant admin consent automatically" -ForegroundColor Yellow
                Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "`n  Please open the following URL in your browser to grant admin consent:" -ForegroundColor Yellow
                $consentUrl = "https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$appClientId"
                Write-Host "  $consentUrl`n" -ForegroundColor Cyan
                
                # Wait for user to grant consent and verify
                $consentVerified = $false
                while (-not $consentVerified) {
                    $null = Read-Host "  Press Enter after you have granted consent to continue"
                    Write-Host "  Verifying consent..." -ForegroundColor Gray
                    
                    # Check if the permission grant now exists
                    $existingGrants = Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$spObjectId' and resourceId eq '$msgraphSpId'" -Description 'Verify delegated admin consent'
                    
                    if ($existingGrants.value -and $existingGrants.value.Count -gt 0) {
                        Write-Host "  Admin consent verified successfully" -ForegroundColor Green
                        $consentVerified = $true
                    }
                    else {
                        Write-Host "  Consent not detected. Please ensure you completed the consent process." -ForegroundColor Yellow
                        Write-Host "  URL: $consentUrl" -ForegroundColor Cyan
                        $retry = Read-Host "  Try again? (Y/n)"
                        if ($retry -eq 'n' -or $retry -eq 'N') {
                            throw "Admin consent required but not granted. Cannot continue deployment."
                        }
                    }
                }
            }
        }

        # Require assignment (restricts access to assigned users/groups only)
        Write-Host "  Enabling assignment requirement (group-restricted access)..." -ForegroundColor Gray
        $spPatchBody = @{ appRoleAssignmentRequired = $true }
        Invoke-GraphApi -Context $containerGraphContext -Method PATCH -Uri "/v1.0/servicePrincipals/$spObjectId" -Body $spPatchBody -Description 'Require app role assignment' | Out-Null

        # Assign the security group for default access
        Write-Host "  Assigning security group '$securityGroupName' to the app..." -ForegroundColor Gray
        $assignmentBody = @{
            principalId = $securityGroupId
            resourceId  = $spObjectId
            appRoleId   = '00000000-0000-0000-0000-000000000000'
        }
        try {
            Invoke-GraphApi -Context $containerGraphContext -Method POST -Uri "/v1.0/servicePrincipals/$spObjectId/appRoleAssignments" -Body $assignmentBody -Description 'Assign security group to app' | Out-Null
            Write-Host "  Security group assigned" -ForegroundColor Green
        }
        catch {
            if ($_.Exception.Message -match 'Permission being assigned already exists|EntitlementGrant entry already exists|already exists') {
                Write-Host "  Security group already assigned" -ForegroundColor Green
            }
            else { throw }
        }

        # -----------------------------------------------------------------
        # Step 20: Configure Easy Auth on Container App
        # -----------------------------------------------------------------
        Write-Host "`nStep 20: Configuring Easy Auth..." -ForegroundColor Cyan

        # Configure the auth config (implicit flow — no client secret needed for user authentication)
        Write-Host "  Enabling Entra ID authentication (implicit flow)..." -ForegroundColor Gray
        $authConfigPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.App/containerApps/$ContainerAppName/authConfigs/current?api-version=$($Script:ArmApiVersions.ContainerApp)"

        $authConfigPayload = @{
            properties = @{
                platform = @{
                    enabled = $true
                }
                globalValidation = @{
                    unauthenticatedClientAction = 'RedirectToLoginPage'
                }
                identityProviders = @{
                    azureActiveDirectory = @{
                        registration = @{
                            openIdIssuer              = "https://login.microsoftonline.com/$tenantId/v2.0"
                            clientId                  = $appClientId
                        }
                        validation = @{
                            allowedAudiences = @($appClientId)
                        }
                    }
                }
            }
        } | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess($ContainerAppName, "Configure Easy Auth")) {
            Invoke-ArmApi -Path $authConfigPath -Method PUT -Payload $authConfigPayload -Description "Configure Easy Auth" | Out-Null
            Write-Host "  Easy Auth configured with Entra ID (tenant-restricted)" -ForegroundColor Green
            Write-Host "    Issuer: https://login.microsoftonline.com/$tenantId/v2.0" -ForegroundColor Gray
            Write-Host "    Allowed group: $securityGroupName ($securityGroupId)" -ForegroundColor Gray
        }

        Write-Host "`n  Container App deployment complete!" -ForegroundColor Green
        Write-Host "  Dashboard URL: https://$caFqdn" -ForegroundColor Cyan
        Write-Host "  Note: First access may take ~60s (cold start: pull images, fetch blob, start Caddy)" -ForegroundColor Yellow
    }

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Setup Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "`nResources:" -ForegroundColor White
    Write-Host "  Resource Group:      $ResourceGroupName" -ForegroundColor Gray
    Write-Host "  Compute Type:        $ComputeType" -ForegroundColor Gray
    if ($ComputeType -eq 'AutomationAccount') {
        Write-Host "  Automation Account:  $AutomationAccountName" -ForegroundColor Gray
    } else {
        Write-Host "  Function App:        $FunctionAppName" -ForegroundColor Gray
    }
    Write-Host "  Storage Account:     $StorageAccountName" -ForegroundColor Gray
    Write-Host "  Dashboard Mode:      $effectiveDashboardDeliveryMode" -ForegroundColor Gray
    Write-Host "  Managed Identity:    $miPrincipalId" -ForegroundColor Gray
    Write-Host "  Blob Containers:     $($Script:BlobContainers -join ', ')" -ForegroundColor Gray
    if ($ComputeType -eq 'AutomationAccount') {
        Write-Host "  Schedule:            Daily" -ForegroundColor Gray
    } else {
        Write-Host "  Timer Trigger:       Daily at 2:00 AM UTC" -ForegroundColor Gray
    }
    if ($IncludeContainerApp) {
        Write-Host "  Container App Env:   $ContainerAppEnvName" -ForegroundColor Gray
        Write-Host "  Container App:       $ContainerAppName" -ForegroundColor Gray
        Write-Host "  Container App MI:    $camiPrincipalId" -ForegroundColor Gray
        Write-Host "  Dashboard URL:       https://$caFqdn" -ForegroundColor Cyan
        Write-Host "  App Registration:    $appClientId" -ForegroundColor Gray
        Write-Host "  Security Group:      $securityGroupName ($securityGroupId)" -ForegroundColor Gray
    }
    Write-Host "`nNext steps:" -ForegroundColor White
    if ($IncludeContainerApp) {
        Write-Host "  1. Open https://$caFqdn in a browser to access the dashboard" -ForegroundColor Gray
        Write-Host "  2. Sign in with a user in the '$securityGroupName' security group" -ForegroundColor Gray
        if ($ComputeType -eq 'AutomationAccount') {
            Write-Host "  3. The runbook will update the dashboard daily" -ForegroundColor Gray
        } else {
            Write-Host "  3. The function app will update the dashboard daily at 2:00 AM UTC" -ForegroundColor Gray
        }
        Write-Host "  4. Container App scales to zero when idle; cold starts fetch the latest blob`n" -ForegroundColor Gray
    }
    elseif (-not $SkipValidation) {
        Write-Host "  1. Download VulnerabilityDashboard.html from the 'dashboards' container" -ForegroundColor Gray
        if ($ComputeType -eq 'AutomationAccount') {
            Write-Host "  2. The runbook will run automatically every day`n" -ForegroundColor Gray
        } else {
            Write-Host "  2. The function app will run automatically every day at 2:00 AM UTC`n" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  1. Upload templates: .\azure\Upload-Templates.ps1 -StorageAccountName $StorageAccountName" -ForegroundColor Gray
        if ($ComputeType -eq 'AutomationAccount') {
            Write-Host "  2. Run the pipeline: start the runbook manually from the Azure portal" -ForegroundColor Gray
        } else {
            Write-Host "  2. Run the pipeline: trigger the function app manually from the Azure portal" -ForegroundColor Gray
        }
        Write-Host "  3. Download VulnerabilityDashboard.html from the 'dashboards' container`n" -ForegroundColor Gray
    }

}
catch {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "  Setup Failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "`nError: $_" -ForegroundColor Red
    Write-Host "`nStack trace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    exit 1
}
