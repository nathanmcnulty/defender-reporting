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
    Required when ComputeType is AutomationAccount. When ComputeType is
    FunctionApp, this can name an existing Automation Account whose resource
    group, location, and storage account should be reused for migration.
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
    delivery through the Container App or another HTTP host. Dual publishes
    both the self-contained dashboard and a hosted split-assets variant.

.PARAMETER SecurityGroup
    Entra ID security group that is allowed to access the Container App
    dashboard. Accepts either an Object ID (GUID) or a display name.
    If a display name matches multiple groups, you will be prompted to
    specify the Object ID instead. Required when -IncludeContainerApp is set.

.PARAMETER ContainerAppName
    Name for the Container App. Default: derived from ResourceGroupName.
    Must be 2-32 characters: lowercase alphanumeric and hyphens.

.PARAMETER EasyAuthAppClientId
    Optional client ID of an existing Entra app registration to use for
    Container App Easy Auth. Normally the script reuses the client ID already
    configured on the Container App. Use this only to disambiguate legacy
    deployments that contain duplicate app registrations and no existing auth
    configuration.

.EXAMPLE
    .\Setup-AzureResources.ps1 -ResourceGroupName "rg-defender-reporting" `
        -AutomationAccountName "aa-defender-reporting" `
        -StorageAccountName "stdefenderreporting"

.EXAMPLE
    .\Setup-AzureResources.ps1 -ResourceGroupName "rg-defender-reporting" `
        -StorageAccountName "stdefenderreporting" `
        -ComputeType FunctionApp -FunctionAppName "func-defender-reporting"

.EXAMPLE
    # Migrate from an existing Automation Account to a Function App while
    # auto-discovering and retaining its resource group and storage account:
    .\Setup-AzureResources.ps1 -ComputeType FunctionApp `
        -FunctionAppName "func-defender-reporting" `
        -AutomationAccountName "aa-defender-reporting"

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

    [Parameter(Mandatory = $false, HelpMessage = "Automation account name (required for AutomationAccount compute type; optional migration source for FunctionApp)")]
    [string]$AutomationAccountName,

    [Parameter(Mandatory = $false, HelpMessage = "Function App name (required for FunctionApp compute type)")]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $false, HelpMessage = "Storage account name (auto-detected from existing compute resource if omitted)")]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false, HelpMessage = "Azure region for all resources")]
    [string]$Location = 'westus2',

    [Parameter(Mandatory = $false, HelpMessage = "Skip MDE API app role assignment")]
    [switch]$SkipMdePermissions,

    [Parameter(Mandatory = $false, HelpMessage = "Optional local dataset path used to seed the exports container for deterministic validation when -SkipMdePermissions is set")]
    [string]$ValidationDatasetPath,

    [Parameter(Mandatory = $false, HelpMessage = "Skip end-to-end validation (template upload, pipeline run, result check)")]
    [switch]$SkipValidation,

    [Parameter(Mandatory = $false, HelpMessage = "Timeout in seconds for the validation polling loop")]
    [ValidateRange(60, 7200)]
    [int]$ValidationTimeoutSeconds = 1800,

    [Parameter(Mandatory = $false, HelpMessage = "Dashboard packaging mode. Auto uses Hosted when -IncludeContainerApp is set, otherwise SelfContained")]
    [ValidateSet('Auto', 'SelfContained', 'Hosted', 'Dual')]
    [string]$DashboardDeliveryMode = 'Auto',

    [Parameter(Mandatory = $false, HelpMessage = "Include Azure Container Apps deployment with Easy Auth")]
    [switch]$IncludeContainerApp,

    [Parameter(Mandatory = $false, HelpMessage = "Entra ID security group (Object ID or display name) for Container App access")]
    [string]$SecurityGroup,

    [Parameter(Mandatory = $false, HelpMessage = "Container App name (default: derived from resource group name)")]
    [string]$ContainerAppName,

    [Parameter(Mandatory = $false, HelpMessage = "Existing Entra app registration client ID for Container App Easy Auth")]
    [ValidateScript({ [string]::IsNullOrWhiteSpace($_) -or $_ -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' })]
    [string]$EasyAuthAppClientId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ValidationDatasetPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$RequestedPath
    )

    if ([string]::IsNullOrWhiteSpace($RequestedPath)) {
        return $null
    }

    $resolvedPath = if ([System.IO.Path]::IsPathRooted($RequestedPath)) {
        [System.IO.Path]::GetFullPath($RequestedPath)
    }
    else {
        [System.IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath $RequestedPath))
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Container)) {
        throw "Validation dataset path not found: $resolvedPath"
    }

    return $resolvedPath
}

function Get-ValidationDatasetFileList {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
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

function Get-StorageBlobRestHeaderSet {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $accessToken = (& az account get-access-token --resource https://storage.azure.com/ --query accessToken -o tsv 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($accessToken)) {
        throw 'Failed to acquire an Azure Storage access token for blob REST operations.'
    }

    return @{
        Authorization = "Bearer $accessToken"
        'x-ms-version' = '2023-11-03'
    }
}

function Get-BlobNamesViaRest {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName
    )

    $headers = Get-StorageBlobRestHeaderSet
    $requestUri = "https://$AccountName.blob.core.windows.net/${ContainerName}?restype=container&comp=list"
    $response = Invoke-WebRequest -Method Get -Uri $requestUri -Headers $headers -UseBasicParsing
    if ([string]::IsNullOrWhiteSpace([string]$response.Content)) {
        return @()
    }

    $blobNameMatches = [System.Text.RegularExpressions.Regex]::Matches([string]$response.Content, '<Blob>\s*<Name>([^<]+)</Name>')
    return @($blobNameMatches | ForEach-Object { $_.Groups[1].Value } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Remove-BlobViaRest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName
    )

    $headers = Get-StorageBlobRestHeaderSet
    $encodedBlobName = [System.Uri]::EscapeDataString($BlobName).Replace('%2F', '/')
    $requestUri = "https://$AccountName.blob.core.windows.net/${ContainerName}/$encodedBlobName"
    if ($PSCmdlet.ShouldProcess($requestUri, 'Delete blob via REST')) {
        Invoke-WebRequest -Method Delete -Uri $requestUri -Headers $headers -UseBasicParsing | Out-Null
    }
}

function Set-BlobViaRest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName,

        [Parameter(Mandatory = $true)]
        [string]$BlobName,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ContentType
    )

    $headers = Get-StorageBlobRestHeaderSet
    $headers['x-ms-blob-type'] = 'BlockBlob'
    $headers['Content-Type'] = $ContentType
    $encodedBlobName = [System.Uri]::EscapeDataString($BlobName).Replace('%2F', '/')
    $requestUri = "https://$AccountName.blob.core.windows.net/${ContainerName}/$encodedBlobName"
    if ($PSCmdlet.ShouldProcess($requestUri, 'Upload blob via REST')) {
        Invoke-WebRequest -Method Put -Uri $requestUri -Headers $headers -InFile $FilePath -UseBasicParsing | Out-Null
    }
}

function Clear-BlobContainerContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$ContainerName
    )

    $blobsJson = (& az storage blob list --account-name $AccountName --container-name $ContainerName --auth-mode login --output json 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0) {
        $blobs = if ([string]::IsNullOrWhiteSpace($blobsJson)) { @() } else { @($blobsJson | ConvertFrom-Json -Depth 20) }
        foreach ($blob in @($blobs)) {
            if ($null -eq $blob -or [string]::IsNullOrWhiteSpace([string]$blob.name)) {
                continue
            }

            & az storage blob delete --account-name $AccountName --container-name $ContainerName --name ([string]$blob.name) --auth-mode login --output none | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw ("Failed to delete blob '{0}' from container '{1}'." -f ([string]$blob.name), $ContainerName)
            }
        }

        return
    }

    Write-Warning ("Azure CLI blob listing failed for container '{0}'. Falling back to blob REST: {1}" -f $ContainerName, $blobsJson.Trim())
    foreach ($blobName in @(Get-BlobNamesViaRest -AccountName $AccountName -ContainerName $ContainerName)) {
        Remove-BlobViaRest -AccountName $AccountName -ContainerName $ContainerName -BlobName $blobName
    }
}

function Initialize-ValidationExportsContainer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,

        [Parameter(Mandatory = $true)]
        [string]$DatasetPath
    )

    $datasetFiles = @(Get-ValidationDatasetFileList -Path $DatasetPath)
    if ($datasetFiles.Count -eq 0) {
        throw "Validation dataset '$DatasetPath' does not contain any export files."
    }

    $missingFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($requiredName in @('Machines_Current.json.gz', 'VulnContentDictionary.json.gz', 'VulnCurrentRefs.json.gz')) {
        if (-not (Test-Path -LiteralPath (Join-Path -Path $DatasetPath -ChildPath $requiredName) -PathType Leaf)) {
            $missingFiles.Add($requiredName) | Out-Null
        }
    }

    if (@(Get-ChildItem -LiteralPath $DatasetPath -Filter 'VulnHistoryRefs_*.json.gz' -File -ErrorAction SilentlyContinue).Count -eq 0) {
        $missingFiles.Add('VulnHistoryRefs_*.json.gz') | Out-Null
    }

    if ($missingFiles.Count -gt 0) {
        throw ("Validation dataset is incomplete. Missing required file(s): {0}" -f ($missingFiles -join ', '))
    }

    Clear-BlobContainerContent -AccountName $AccountName -ContainerName 'exports'
    foreach ($file in $datasetFiles) {
        $contentType = if ($file.Name.EndsWith('.gz')) { 'application/gzip' } else { 'application/json' }
        & az storage blob upload --account-name $AccountName --container-name exports --name $file.Name --file $file.FullName --content-type $contentType --auth-mode login --overwrite --output none 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning ("Azure CLI blob upload failed for '{0}' in container 'exports'. Falling back to blob REST." -f $file.Name)
            Set-BlobViaRest -AccountName $AccountName -ContainerName 'exports' -BlobName $file.Name -FilePath $file.FullName -ContentType $contentType
        }
    }
}

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
$Script:HostedDashboardBlobName = 'VulnerabilityDashboard.Hosted.html'
$Script:HostedDashboardAssetsDirectoryName = ([System.IO.Path]::GetFileNameWithoutExtension($Script:HostedDashboardBlobName) + '.assets')
$Script:DashboardHostedAssetRelativePaths = @(
    'runtime/dashboard.css',
    'runtime/dashboard.js',
    'runtime/pako.js',
    'vendor/chart.js',
    'data/summary.json',
    'optional/pdf-export.runtime.js',
    'optional/pdf-export.bundle.js',
    'data/payload.json.gz'
)
$Script:ProvisioningTags = @{
    workload = 'defender-reporting'
}

$provisioningHelperCandidates = @(
    (Join-Path -Path $PSScriptRoot -ChildPath 'src\powershell\Provisioning\Azure\AzureProvisioning.ps1')
    (Join-Path -Path $PSScriptRoot -ChildPath 'azure\AzureProvisioning.ps1')
    (Join-Path -Path $PSScriptRoot -ChildPath 'AzureProvisioning.ps1')
)

$provisioningHelperPath = $provisioningHelperCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1

if (-not $provisioningHelperPath) {
    throw "Required provisioning helper script 'AzureProvisioning.ps1' was not found. Expected one of: $($provisioningHelperCandidates -join ', ')"
}

. $provisioningHelperPath

function Get-OptionalArmResource {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    try {
        return [PSCustomObject]@{
            Exists = $true
            Resource = (Invoke-ArmApi -Path $Path -Method GET -Description $Description)
        }
    }
    catch {
        if (Test-IsArmNotFoundError -ErrorRecord $_) {
            return [PSCustomObject]@{
                Exists = $false
                Resource = $null
            }
        }

        throw
    }
}

function Get-CreateOnlyProvisioningPayload {
    [CmdletBinding()]
    [OutputType([System.Collections.IDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Payload,

        [Parameter(Mandatory = $true)]
        [bool]$IsNewResource
    )

    if ($IsNewResource) {
        $Payload['tags'] = $Script:ProvisioningTags
    }
    elseif ($Payload.Contains('tags')) {
        [void]$Payload.Remove('tags')
    }

    return $Payload
}

function Get-OptionalObjectPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$PropertyPath
    )

    $current = $InputObject
    foreach ($propertyName in $PropertyPath) {
        if ($null -eq $current) {
            return $null
        }

        $property = $current.PSObject.Properties[$propertyName]
        if ($null -eq $property) {
            return $null
        }

        $current = $property.Value
    }

    return $current
}

# =============================================================================
# MAIN SCRIPT
# =============================================================================

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Azure Resource Setup" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $resourceGroupNameSource = if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) { 'pending auto-discovery or required input' } else { 'explicit parameter' }
    $storageAccountNameSource = if ([string]::IsNullOrWhiteSpace($StorageAccountName)) { 'pending auto-discovery or required input' } else { 'explicit parameter' }
    $locationSource = if ($PSBoundParameters.ContainsKey('Location')) { 'explicit parameter' } else { 'default parameter value' }

    # -------------------------------------------------------------------------
    # Step 1: Verify Azure connection and set subscription
    # -------------------------------------------------------------------------
    Write-Host "Step 1: Verifying Azure connection..." -ForegroundColor Cyan
    Write-Host ("  PowerShell runtime: {0} ({1})" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition) -ForegroundColor Gray

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
        $discoveredComputeType = $ComputeType
        Write-Host "`nLooking up existing $ComputeType '$computeName'..." -ForegroundColor Gray

        $found = $null
        $resources = Invoke-ArmApi -Path "$subPath/resources?`$filter=name eq '$computeName' and resourceType eq '$providerType'&api-version=2021-04-01" -Method GET -Description "Find existing $ComputeType"
        $found = $resources.value | Select-Object -First 1

        if (-not $found -and $ComputeType -eq 'FunctionApp' -and $AutomationAccountName) {
            Write-Host "  Target Function App does not exist yet; looking up migration source Automation Account '$AutomationAccountName'..." -ForegroundColor Gray
            $sourceProviderType = 'Microsoft.Automation/automationAccounts'
            $sourceResources = Invoke-ArmApi -Path "$subPath/resources?`$filter=name eq '$AutomationAccountName' and resourceType eq '$sourceProviderType'&api-version=2021-04-01" -Method GET -Description 'Find migration source Automation Account'
            $found = $sourceResources.value | Select-Object -First 1
            if ($found) {
                $computeName = $AutomationAccountName
                $discoveredComputeType = 'AutomationAccount'
                Write-Host "  Using Automation Account '$AutomationAccountName' as the migration source" -ForegroundColor Green
            }
        }

        if ($found) {
            # Extract resource group from the resource ID: /subscriptions/.../resourceGroups/<RG>/providers/...
            $discoveredRG = ($found.id -split '/resourceGroups/|/providers/')[1]
            if (-not $ResourceGroupName) {
                $ResourceGroupName = $discoveredRG
                $resourceGroupNameSource = "auto-discovered from existing $discoveredComputeType '$computeName'"
                Write-Host "  Auto-detected resource group: $ResourceGroupName" -ForegroundColor Green
            }

            # Auto-detect location from existing resource if not explicitly provided
            if (-not $PSBoundParameters.ContainsKey('Location') -and $found.location) {
                $Location = $found.location
                $locationSource = "auto-discovered from existing $discoveredComputeType '$computeName'"
                Write-Host "  Auto-detected location: $Location" -ForegroundColor Green
            }

            if (-not $StorageAccountName) {
                if ($discoveredComputeType -eq 'FunctionApp') {
                    $apiVer = $Script:ArmApiVersions.WebApp
                    $appSettings = Invoke-ArmApi -Path "$subPath/resourceGroups/$discoveredRG/providers/Microsoft.Web/sites/$FunctionAppName/config/appsettings/list?api-version=$apiVer" -Method POST -Description 'Read app settings'
                    $StorageAccountName = $appSettings.properties.STORAGE_ACCOUNT_NAME
                    if (-not $StorageAccountName) {
                        $StorageAccountName = $appSettings.properties.'AzureWebJobsStorage__accountName'
                        if ($StorageAccountName) {
                            $storageAccountNameSource = "auto-discovered from Function App setting 'AzureWebJobsStorage__accountName'"
                        }
                    }
                    else {
                        $storageAccountNameSource = "auto-discovered from Function App setting 'STORAGE_ACCOUNT_NAME'"
                    }
                } else {
                    # Automation Account: look up the StorageAccountName variable
                    try {
                        $apiVer = $Script:ArmApiVersions.AutomationAccount
                        $varPath = "$subPath/resourceGroups/$discoveredRG/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/variables/StorageAccountName?api-version=$apiVer"
                        $saVar = Invoke-ArmApi -Path $varPath -Method GET -Description 'Read StorageAccountName variable'
                        # Variable values are JSON-encoded strings (e.g. '"stname"')
                        $StorageAccountName = ($saVar.properties.value | ConvertFrom-Json)
                        if ($StorageAccountName) {
                            $storageAccountNameSource = "auto-discovered from Automation variable 'StorageAccountName'"
                        }
                    } catch {
                        Write-Warning ("StorageAccountName variable not found on Automation Account '{0}': {1}" -f $AutomationAccountName, $_.Exception.Message)
                    }
                }

                if ($StorageAccountName) {
                    Write-Host "  Auto-detected storage account: $StorageAccountName" -ForegroundColor Green
                } else {
                    throw "Could not auto-detect -StorageAccountName from existing $discoveredComputeType '$computeName'. Please provide it explicitly."
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

        Write-Host "  Parameter resolution summary:" -ForegroundColor Gray
        Write-Host ("    ResourceGroupName: {0} ({1})" -f $ResourceGroupName, $resourceGroupNameSource) -ForegroundColor Gray
        Write-Host ("    StorageAccountName: {0} ({1})" -f $StorageAccountName, $storageAccountNameSource) -ForegroundColor Gray
        Write-Host ("    Location: {0} ({1})" -f $Location, $locationSource) -ForegroundColor Gray
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

    if ($rgExists) {
        Write-Host "  Leaving existing resource group tags unchanged" -ForegroundColor Gray
    }
    elseif ($PSCmdlet.ShouldProcess($ResourceGroupName, 'Create resource group')) {
        $rgPayload = @{
            location = $Location
            tags     = $Script:ProvisioningTags
        } | ConvertTo-Json -Depth 5

        Invoke-ArmApi -Path $rgPath -Method PUT -Payload $rgPayload -Description 'Create resource group' | Out-Null
        Write-Host "  Resource group created" -ForegroundColor Green
    }

    # -------------------------------------------------------------------------
    # Step 3: Create/verify Compute Resource (Automation Account or Function App)
    # -------------------------------------------------------------------------
    if ($ComputeType -eq 'AutomationAccount') {
        Write-Host "`nStep 3: Automation Account '$AutomationAccountName'..." -ForegroundColor Cyan

        $aaPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/${AutomationAccountName}?api-version=$($Script:ArmApiVersions.AutomationAccount)"
        $aaState = Get-OptionalArmResource -Path $aaPath -Description 'Check automation account'

        $aaPayload = Get-CreateOnlyProvisioningPayload -Payload ([ordered]@{
            location   = $Location
            identity   = @{
                type = "SystemAssigned"
            }
            properties = @{
                sku              = @{ name = "Basic" }
                disableLocalAuth = $true
            }
        }) -IsNewResource (-not $aaState.Exists) | ConvertTo-Json -Depth 5

        if ($PSCmdlet.ShouldProcess($AutomationAccountName, "Create/update automation account")) {
            $null = Invoke-ArmApi -Path $aaPath -Method PUT -Payload $aaPayload -Description "Create/update automation account"
            if ($aaState.Exists) {
                Write-Host "  Automation account already exists; configuration and Managed Identity confirmed" -ForegroundColor Green
            }
            else {
                Write-Host "  Automation account created with Managed Identity enabled" -ForegroundColor Green
            }
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
        $planState = Get-OptionalArmResource -Path $planPath -Description 'Check Flex Consumption plan'

        $planPayload = Get-CreateOnlyProvisioningPayload -Payload ([ordered]@{
            location   = $Location
            kind       = "functionapp"
            sku        = @{
                name = "FC1"
                tier = "FlexConsumption"
            }
            properties = @{
                reserved = $true
            }
        }) -IsNewResource (-not $planState.Exists) | ConvertTo-Json -Depth 5

        if ($PSCmdlet.ShouldProcess($planName, "Create/update Flex Consumption plan")) {
            $null = Invoke-ArmApi -Path $planPath -Method PUT -Payload $planPayload -Description "Create/update Flex Consumption plan"
            if ($planState.Exists) {
                Write-Host "  Flex Consumption plan '$planName' already exists; configuration confirmed" -ForegroundColor Green
            }
            else {
                Write-Host "  Flex Consumption plan '$planName' created" -ForegroundColor Green
            }
        }

        # 3b: Create Function App with system-assigned Managed Identity
        $functionAppPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/${FunctionAppName}?api-version=$($Script:ArmApiVersions.WebApp)"
        $functionAppState = Get-OptionalArmResource -Path $functionAppPath -Description 'Check Function App'

        $functionAppPayload = Get-CreateOnlyProvisioningPayload -Payload ([ordered]@{
            location   = $Location
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
        }) -IsNewResource (-not $functionAppState.Exists) | ConvertTo-Json -Depth 10

        if ($PSCmdlet.ShouldProcess($FunctionAppName, "Create/update Function App")) {
            $null = Invoke-ArmApi -Path $functionAppPath -Method PUT -Payload $functionAppPayload -Description "Create/update Function App"
            if ($functionAppState.Exists) {
                Write-Host "  Function App '$FunctionAppName' already exists; configuration and Managed Identity confirmed" -ForegroundColor Green
            }
            else {
                Write-Host "  Function App '$FunctionAppName' created with Managed Identity" -ForegroundColor Green
            }
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

    $saPayload = Get-CreateOnlyProvisioningPayload -Payload ([ordered]@{
        location   = $Location
        kind       = "StorageV2"
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
    }) -IsNewResource (-not $existingStorageFound) | ConvertTo-Json -Depth 5

    if ($PSCmdlet.ShouldProcess($StorageAccountName, "Create/update storage account")) {
        Invoke-ArmApi -Path $saPath -Method PUT -Payload $saPayload -Description "Create/update storage account" | Out-Null

        # Storage account creation is async - poll for provisioning state
        Wait-WithPolling -Description "Storage account provisioning" -IntervalSeconds 5 -TimeoutSeconds 120 -Condition {
            $sa = Invoke-ArmApi -Path $saPath -Method GET -Description "Check storage provisioning"
            return ($sa.properties.provisioningState -eq 'Succeeded')
        } | Out-Null

        $storageStatus = if ($existingStorageFound) { 'Existing storage account security configuration confirmed:' } else { 'Storage account created with security best practices:' }
        Write-Host "  $storageStatus" -ForegroundColor Green
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
    Write-Host "`nStep 7: Blob containers..." -ForegroundColor Cyan

    foreach ($containerName in $Script:BlobContainers) {
        $containerPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/blobServices/default/containers/${containerName}?api-version=$($Script:ArmApiVersions.StorageAccount)"
        $containerState = Get-OptionalArmResource -Path $containerPath -Description "Check container '$containerName'"

        if ($PSCmdlet.ShouldProcess($containerName, "Create blob container")) {
            Invoke-ArmApi -Path $containerPath -Method PUT -Payload '{}' -Description "Create/update container '$containerName'" | Out-Null
            if ($containerState.Exists) {
                Write-Host "  Container '$containerName' already exists" -ForegroundColor Green
            }
            else {
                Write-Host "  Container '$containerName' created" -ForegroundColor Green
            }
        }
    }

    # Function App: also create deployment container for zip package
    if ($ComputeType -eq 'FunctionApp') {
        $deployContainerPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/blobServices/default/containers/$($Script:FunctionAppDeploymentContainer)?api-version=$($Script:ArmApiVersions.StorageAccount)"
        $deployContainerState = Get-OptionalArmResource -Path $deployContainerPath -Description "Check deployment container '$($Script:FunctionAppDeploymentContainer)'"
        if ($PSCmdlet.ShouldProcess($Script:FunctionAppDeploymentContainer, "Create deployment container")) {
            Invoke-ArmApi -Path $deployContainerPath -Method PUT -Payload '{}' -Description "Create/update deployment container" | Out-Null
            if ($deployContainerState.Exists) {
                Write-Host "  Container '$($Script:FunctionAppDeploymentContainer)' already exists (deployment)" -ForegroundColor Green
            }
            else {
                Write-Host "  Container '$($Script:FunctionAppDeploymentContainer)' created (deployment)" -ForegroundColor Green
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

        # Poll until ARM reflects the role assignment records. Storage data-plane
        # authorization can still lag behind ARM visibility, so the zip deployment
        # loop also retries storage 403s with backoff.
        Wait-WithPolling -Description "RBAC records visible in ARM" -IntervalSeconds 5 -TimeoutSeconds 120 -Condition {
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
    $callerObjectId = $null
    $currentContext = Get-AzContext
    $homeAccountId = $null
    if ($null -ne $currentContext -and $null -ne $currentContext.Account) {
        $extendedProperties = $currentContext.Account.ExtendedProperties
        if ($extendedProperties -is [System.Collections.IDictionary]) {
            $homeAccountId = [string]$extendedProperties['HomeAccountId']
        }
        elseif ($null -ne $extendedProperties -and $extendedProperties.PSObject.Properties['HomeAccountId']) {
            $homeAccountId = [string]$extendedProperties.PSObject.Properties['HomeAccountId'].Value
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($homeAccountId)) {
        $callerObjectId = $homeAccountId.Split('.')[0]
    }

    if (-not $callerObjectId) {
        # Fallback: use Graph to resolve
        try {
            $graphToken = Get-ArmToken -ResourceUrl 'https://graph.microsoft.com/'
            $graphHeaders = @{ 'Authorization' = "Bearer $graphToken"; 'Content-Type' = 'application/json' }
            $meResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $graphHeaders -Method Get
            $callerObjectId = $meResponse.id
        }
        catch {
            try {
                $callerObjectId = [string](& az ad signed-in-user show --query id -o tsv 2>$null)
                if ([string]::IsNullOrWhiteSpace($callerObjectId)) {
                    $callerObjectId = $null
                }
            }
            catch {
                $callerObjectId = $null
            }

            if (-not $callerObjectId) {
                Write-Warning "Could not determine current user's object ID. Assign Storage Blob Data Contributor manually."
            }
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
    $runtimeEnvState = Get-OptionalArmResource -Path $runtimeEnvPath -Description 'Check runtime environment'

    $runtimeEnvPayload = Get-CreateOnlyProvisioningPayload -Payload ([ordered]@{
        location   = $Location
        properties = @{
            runtime         = @{
                language = 'PowerShell'
                version  = '7.4'
            }
            defaultPackages = @{}
            description     = 'PowerShell 7.4 with Az.Accounts only (no full Az module or Az CLI)'
        }
    }) -IsNewResource (-not $runtimeEnvState.Exists) | ConvertTo-Json -Depth 5

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
    $runbookState = Get-OptionalArmResource -Path $runbookPath -Description 'Check runbook'

    $runbookPayload = Get-CreateOnlyProvisioningPayload -Payload ([ordered]@{
        location   = $Location
        properties = @{
            runbookType        = "PowerShell"
            runtimeEnvironment = $Script:RuntimeEnvName
            logProgress        = $true
            logVerbose         = $false
            description        = "Exports MDE vulnerability data, generates the HTML dashboard, and uploads results to blob storage."
        }
    }) -IsNewResource (-not $runbookState.Exists) | ConvertTo-Json -Depth 5

    if ($PSCmdlet.ShouldProcess($runbookName, "Create runbook")) {
        Invoke-ArmApi -Path $runbookPath -Method PUT -Payload $runbookPayload -Description "Create runbook" | Out-Null
        Write-Host "  Runbook '$runbookName' created (PowerShell 7.4 / $($Script:RuntimeEnvName))" -ForegroundColor Green

        # Rebuild the generated runbook artifact before uploading it to Azure Automation.
        $runbookBuildPath = Join-Path -Path $PSScriptRoot -ChildPath 'build\azure\Build-Runbook.ps1'
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
            Write-Host "  Run .\build\azure\Build-Runbook.ps1 locally or rerun this setup script to regenerate the artifact before uploading." -ForegroundColor Yellow
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
            Description = 'Dashboard packaging mode for the pipeline (SelfContained, Hosted, or Dual)'
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

            # Static path construction avoids relying on session-specific Join-Path command resolution.
            $packageScript = [System.IO.Path]::Combine($PSScriptRoot, 'build', 'Build-FunctionAppPackage.ps1')
            $buildScript = [System.IO.Path]::Combine($PSScriptRoot, 'build', 'azure', 'Build-FunctionApp.ps1')
            $functionAppDir = [System.IO.Path]::Combine($PSScriptRoot, 'azure', 'function-app')
            $functionAppEntryPoint = [System.IO.Path]::Combine($functionAppDir, 'ExportAndGenerate', 'run.ps1')
            $functionAppModulesPath = [System.IO.Path]::Combine($functionAppDir, 'Modules', 'Az.Accounts')
            $zipMetadataPath = $null
            $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) ('funcapp-deploy-' + [guid]::NewGuid().ToString('N') + '.zip')
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

            if (Test-Path $packageScript) {
                $zipMetadataPath = Join-Path ([System.IO.Path]::GetTempPath()) ('funcapp-deploy-' + [guid]::NewGuid().ToString('N') + '.manifest.json')
                Write-Host "  Building Function App deployment package..." -ForegroundColor Gray
                & $packageScript -OutputPath $zipPath -MetadataPath $zipMetadataPath
                Write-Host "  Function App package built successfully" -ForegroundColor Green
            }
            elseif (Test-Path $buildScript) {
                # Release packages do not ship build/Build-FunctionAppPackage.ps1, so preserve
                # the older source-build fallback when only the low-level build script is present.
                Write-Host "  Building Function App from build/azure/runbook-source.ps1..." -ForegroundColor Gray
                & $buildScript
                # Build-FunctionApp.ps1 uses $ErrorActionPreference = 'Stop' and throws
                # on failure, so an explicit exit-code check is unnecessary.
                Write-Host "  Function App built successfully" -ForegroundColor Green
            }
            elseif ((Test-Path $functionAppEntryPoint) -and (Test-Path $functionAppModulesPath)) {
                Write-Host "  Build script not present; using prebuilt Function App artifacts from azure/function-app." -ForegroundColor Gray
            }
            else {
                throw "Function App build script not found at $buildScript and prebuilt artifacts are incomplete. Expected '$functionAppEntryPoint' and '$functionAppModulesPath'."
            }

            # Deploy function app code via az CLI zip deployment (Flex Consumption
            # uses a Kudu-lite pipeline that packages and uploads to blob storage)
            Write-Host "  Deploying function app code via zip deployment..." -ForegroundColor Gray
            if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
                Push-Location $functionAppDir
                try {
                    Compress-Archive -Path '.\*' -DestinationPath $zipPath -Force
                }
                finally {
                    Pop-Location
                }
            }

            try {
                $maxAttempts = 5
                $deployed = $false
                for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                    $deployOutput = @(az functionapp deployment source config-zip `
                        --src $zipPath `
                        --name $FunctionAppName `
                        --resource-group $ResourceGroupName `
                        --output none 2>&1)

                    $deployText = (($deployOutput | ForEach-Object {
                        if ($_ -is [System.Management.Automation.ErrorRecord]) {
                            $_.Exception.Message
                        }
                        else {
                            [string]$_
                        }
                    }) -join [Environment]::NewLine).Trim()

                    if (-not [string]::IsNullOrWhiteSpace($deployText)) {
                        foreach ($line in ($deployText -split "`r?`n")) {
                            if ([string]::IsNullOrWhiteSpace($line)) {
                                continue
                            }

                            if ($line -match '^WARNING:\s*(.+)') {
                                Write-Host ("  Deployment status: {0}" -f $Matches[1]) -ForegroundColor Gray
                            }
                            else {
                                Write-Host ("  {0}" -f $line) -ForegroundColor Gray
                            }
                        }
                    }

                    if ($LASTEXITCODE -eq 0) {
                        $deployed = $true
                        break
                    }

                    if ($deployText -match 'Deployment was partially successful') {
                        Write-Warning 'Function App zip deployment reported partial success without retained logs. Continuing and relying on host readiness validation.'
                        $deployed = $true
                        break
                    }

                    if ($attempt -lt $maxAttempts -and $deployText -match 'BadGatewayConnection|Bad Gateway') {
                        Write-Warning ("Function App zip deployment hit a transient gateway error (attempt {0}/{1}). Retrying..." -f $attempt, $maxAttempts)
                        Start-Sleep -Seconds (5 * $attempt)
                        continue
                    }

                    if ($attempt -lt $maxAttempts -and $deployText -match 'InaccessibleStorageException|BlobUploadFailed|403|inaccessible') {
                        $waitSeconds = 60 * $attempt
                        Write-Warning ("Function App zip deployment hit a storage access error (attempt {0}/{1}). Waiting {2}s for storage RBAC propagation before retrying..." -f $attempt, $maxAttempts, $waitSeconds)
                        Start-Sleep -Seconds $waitSeconds
                        continue
                    }

                    throw "Function App zip deployment failed (exit code $LASTEXITCODE)."
                }

                if (-not $deployed) {
                    throw "Function App zip deployment failed for '$FunctionAppName' after $maxAttempts attempt(s)."
                }
            }
            finally {
                Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
                if (-not [string]::IsNullOrWhiteSpace($zipMetadataPath)) {
                    Remove-Item $zipMetadataPath -Force -ErrorAction SilentlyContinue
                }
            }

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

        # 14a: Upload template files via the package-safe Azure publish contract
        Write-Host "  Uploading template files..." -ForegroundColor Gray
        $uploadScript = Join-Path -Path $PSScriptRoot -ChildPath 'azure' | Join-Path -ChildPath 'Upload-Templates.ps1'

        if (-not (Test-Path -LiteralPath $uploadScript -PathType Leaf)) {
            Write-Warning "Package-safe template publish script not found at: $uploadScript"
            Write-Host "  Run .\azure\Upload-Templates.ps1 manually before the pipeline." -ForegroundColor Yellow
        }
        else {
            & $uploadScript -StorageAccountName $StorageAccountName
        }

        if ($ComputeType -eq 'AutomationAccount') {
            $resolvedValidationDatasetPath = $null
            if ($SkipMdePermissions) {
                $resolvedValidationDatasetPath = Resolve-ValidationDatasetPath -RequestedPath $ValidationDatasetPath
                if (-not [string]::IsNullOrWhiteSpace($resolvedValidationDatasetPath)) {
                    Write-Host ("  Seeding exports container from local validation dataset: {0}" -f $resolvedValidationDatasetPath) -ForegroundColor Gray
                    Initialize-ValidationExportsContainer -AccountName $StorageAccountName -DatasetPath $resolvedValidationDatasetPath
                }
                else {
                    Write-Host "  SkipMdePermissions validation is reusing whatever export blobs already exist in storage. Pass -ValidationDatasetPath for deterministic validation input." -ForegroundColor Yellow
                }
            }

            # 14b: Start a runbook job
            Write-Host "  Starting validation job..." -ForegroundColor Gray
            $runbookName = 'Invoke-DashboardPipeline'
            $jobId = [guid]::NewGuid().ToString()
            $jobPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.Automation/automationAccounts/$AutomationAccountName/jobs/${jobId}?api-version=$($Script:ArmApiVersions.AutomationAccount)"
            $validationParameters = @{
                StorageAccountName = $StorageAccountName
                DashboardDeliveryMode = $effectiveDashboardDeliveryMode
            }
            if ($SkipMdePermissions) {
                $validationParameters.UseExistingExportsOnly = $true
            }

            $jobPayload = @{
                properties = @{
                    runbook    = @{ name = $runbookName }
                    parameters = $validationParameters
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
        Write-Host "`nStep 16: Container Apps Environment '$ContainerAppEnvName'..." -ForegroundColor Cyan

        $caEnvPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.App/managedEnvironments/${ContainerAppEnvName}?api-version=$($Script:ArmApiVersions.ContainerAppEnvironment)"
        $caEnvState = Get-OptionalArmResource -Path $caEnvPath -Description 'Check Container Apps Environment'

        $caEnvPayload = Get-CreateOnlyProvisioningPayload -Payload ([ordered]@{
            location   = $Location
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
        }) -IsNewResource (-not $caEnvState.Exists) | ConvertTo-Json -Depth 5

        if ($PSCmdlet.ShouldProcess($ContainerAppEnvName, "Create/update Container Apps Environment")) {
            Invoke-ArmApi -Path $caEnvPath -Method PUT -Payload $caEnvPayload -Description "Create/update Container Apps Environment" | Out-Null

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

            if ($caEnvState.Exists) {
                Write-Host "  Container Apps Environment already exists; configuration confirmed (no Log Analytics)" -ForegroundColor Green
            }
            else {
                Write-Host "  Container Apps Environment created (no Log Analytics)" -ForegroundColor Green
            }
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
        Write-Host "`nStep 17: Container App '$ContainerAppName'..." -ForegroundColor Cyan

        $caPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.App/containerApps/${ContainerAppName}?api-version=$($Script:ArmApiVersions.ContainerApp)"
        $caState = Get-OptionalArmResource -Path $caPath -Description 'Check Container App'

        # Build a startup script that downloads the dashboard blob using managed identity,
        # then starts Caddy to serve it. The script is base64-encoded to avoid JSON/shell
        # escaping issues. NOTE: We download in the main container (not an init container)
        # because the Container Apps identity sidecar is only available after init containers finish.
        $containerAppDashboardBlobName = if ($effectiveDashboardDeliveryMode -eq 'Dual') {
            $Script:HostedDashboardBlobName
        }
        else {
            $Script:DashboardBlobName
        }
        $containerAppDashboardAssetsDirectoryName = if ($effectiveDashboardDeliveryMode -eq 'Dual') {
            $Script:HostedDashboardAssetsDirectoryName
        }
        else {
            $Script:DashboardAssetsDirectoryName
        }
        $containerAppDashboardAssetRelativePaths = if ($effectiveDashboardDeliveryMode -in @('Hosted', 'Dual')) {
            $Script:DashboardHostedAssetRelativePaths
        }
        else {
            @()
        }
        $assetDownloadLines = @(
            foreach ($assetRelativePath in $containerAppDashboardAssetRelativePaths) {
                                '  download_blob /data/{0}/{1} "{0}/{1}" || true' -f $containerAppDashboardAssetsDirectoryName, $assetRelativePath
            }
        ) -join "`n"
        $assetDownloadBlock = if ($containerAppDashboardAssetRelativePaths.Count -gt 0) {
@"
        mkdir -p "/data/$containerAppDashboardAssetsDirectoryName"
$assetDownloadLines
"@
        }
        else {
            ''
        }

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

        download_blob /data/index.html "$containerAppDashboardBlobName" || return 1
    $assetDownloadBlock

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
        $caObj = Get-CreateOnlyProvisioningPayload -Payload $caObj -IsNewResource (-not $caState.Exists)
        $caPayloadBytes = [System.Text.Json.JsonSerializer]::SerializeToUtf8Bytes($caObj, [System.Text.Json.JsonSerializerOptions]@{ WriteIndented = $false })
        $caPayload = [System.Text.Encoding]::UTF8.GetString($caPayloadBytes)

        if ($PSCmdlet.ShouldProcess($ContainerAppName, "Create/update Container App")) {
            Invoke-ArmApi -Path $caPath -Method PUT -Payload $caPayload -Description "Create/update Container App" | Out-Null

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
                throw "Container App provisioning succeeded but Managed Identity principal ID is not available."
            }

            if ($caState.Exists) {
                Write-Host "  Container App already exists; configuration and Managed Identity confirmed" -ForegroundColor Green
            }
            else {
                Write-Host "  Container App created" -ForegroundColor Green
            }
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
        $authConfigPath = "$subPath/resourceGroups/$ResourceGroupName/providers/Microsoft.App/containerApps/$ContainerAppName/authConfigs/current?api-version=$($Script:ArmApiVersions.ContainerApp)"

        # Microsoft Graph well-known IDs for openid, email, profile delegated permissions
        $msGraphResourceAppId = '00000003-0000-0000-c000-000000000000'
        $delegatedPermissions = @(
            @{ id = '37f7f235-527c-4136-accd-4a02d197296e'; type = 'Scope' }  # openid
            @{ id = '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0'; type = 'Scope' }  # email
            @{ id = '14dad69e-099b-42c9-810b-d002981feec1'; type = 'Scope' }  # profile
        )

        # Reuse the registration already wired to this Container App whenever
        # possible. This is the authoritative discriminator for legacy
        # deployments that accidentally created same-name registrations.
        $appDisplayName = 'Defender Reporting Dashboard'
        Write-Host "  Resolving app registration '$appDisplayName'..." -ForegroundColor Gray
        $appResult = $null
        $preferredAppClientId = $EasyAuthAppClientId
        $preferredAppSource = if ($preferredAppClientId) { '-EasyAuthAppClientId' } else { $null }

        if (-not $preferredAppClientId) {
            $existingAuthConfigState = Get-OptionalArmResource -Path $authConfigPath -Description 'Read existing Container App Easy Auth configuration'
            if ($existingAuthConfigState.Exists) {
                $preferredAppClientId = Get-OptionalObjectPropertyValue -InputObject $existingAuthConfigState.Resource -PropertyPath @('properties', 'identityProviders', 'azureActiveDirectory', 'registration', 'clientId')
                if ($preferredAppClientId) {
                    $preferredAppSource = "existing Easy Auth configuration on '$ContainerAppName'"
                }
            }
        }

        if ($preferredAppClientId) {
            $preferredApps = @(
                (Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/applications?`$filter=appId eq '$preferredAppClientId'" -Description 'Look up preferred Easy Auth app registration').value
            )
            if ($preferredApps.Count -eq 1) {
                $appResult = $preferredApps[0]
                Write-Host "  Reusing app registration $preferredAppClientId from $preferredAppSource" -ForegroundColor Green
            }
            elseif ($EasyAuthAppClientId) {
                throw "The app registration supplied with -EasyAuthAppClientId ('$EasyAuthAppClientId') was not found in the current tenant."
            }
            else {
                Write-Warning "Easy Auth references app client ID '$preferredAppClientId', but that app registration no longer exists. Resolving a replacement registration."
            }
        }

        if ($null -eq $appResult) {
            $existingApps = @(
                (Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/applications?`$filter=displayName eq '$appDisplayName'" -Description 'List matching Entra app registrations').value
            )
            $redirectMatchedApps = @(
                $existingApps | Where-Object { @($_.web.redirectUris) -contains $redirectUri }
            )
            $candidateApps = if ($redirectMatchedApps.Count -gt 0) { $redirectMatchedApps } else { $existingApps }

            if ($candidateApps.Count -eq 1) {
                $appResult = $candidateApps[0]
                Write-Host "  Reusing existing app registration: $($appResult.appId)" -ForegroundColor Green
            }
            elseif ($candidateApps.Count -gt 1) {
                # Prefer the registration whose enterprise application already
                # exists. Older setup versions could omit this service principal.
                $servicePrincipalBackedApps = @()
                foreach ($candidateApp in $candidateApps) {
                    $candidateServicePrincipals = @(
                        (Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($candidateApp.appId)'&`$select=id" -Description 'Check candidate Easy Auth service principal').value
                    )
                    if ($candidateServicePrincipals.Count -gt 0) {
                        $servicePrincipalBackedApps += $candidateApp
                    }
                }

                $preferredCandidates = if ($servicePrincipalBackedApps.Count -gt 0) { $servicePrincipalBackedApps } else { $candidateApps }
                $appResult = $preferredCandidates |
                    Sort-Object -Property @{ Expression = { $created = Get-OptionalObjectPropertyValue -InputObject $_ -PropertyPath @('createdDateTime'); if ($created) { [datetime]$created } else { [datetime]::MaxValue } } }, id |
                    Select-Object -First 1

                $candidateAppIds = ($candidateApps | ForEach-Object { $_.appId }) -join ', '
                Write-Warning "Multiple matching app registrations were found ($candidateAppIds). Reusing '$($appResult.appId)' deterministically; no registrations were deleted. Pass -EasyAuthAppClientId to select a different one."
            }
        }

        $resolvedAppDisplayName = if ($null -ne $appResult -and $appResult.displayName) { $appResult.displayName } else { $appDisplayName }
        $appBody = @{
            displayName    = $resolvedAppDisplayName
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

        # Grant admin consent for the delegated permissions (prevents user consent prompt).
        # Query first so reruns reuse the grant instead of relying on a
        # duplicate-create error from Graph.
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
        $existingGrants = @(
            (Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$spObjectId' and resourceId eq '$msgraphSpId'" -Description 'Look up delegated admin consent').value
        )
        try {
            if ($existingGrants.Count -gt 0) {
                $existingGrant = $existingGrants[0]
                $existingScopeNames = @(
                    @($existingGrant.scope -split ' ') |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                        Select-Object -Unique
                )
                $missingScopeNames = @(
                    @('openid', 'email', 'profile') |
                        Where-Object { $_ -notin $existingScopeNames }
                )
                if ($missingScopeNames.Count -gt 0) {
                    $mergedScopes = @($existingScopeNames + $missingScopeNames) -join ' '
                    Invoke-GraphApi -Context $containerGraphContext -Method PATCH -Uri "/v1.0/oauth2PermissionGrants/$($existingGrant.id)" -Body @{ scope = $mergedScopes } -Description 'Update delegated admin consent' | Out-Null
                    Write-Host "  Admin consent updated" -ForegroundColor Green
                }
                else {
                    Write-Host "  Admin consent already granted" -ForegroundColor Green
                }
            }
            else {
                Invoke-GraphApi -Context $containerGraphContext -Method POST -Uri '/v1.0/oauth2PermissionGrants' -Body $oauth2Body -Description 'Grant delegated admin consent' | Out-Null
                Write-Host "  Admin consent granted" -ForegroundColor Green
            }
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
                    $verifiedGrants = Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$spObjectId' and resourceId eq '$msgraphSpId'" -Description 'Verify delegated admin consent'
                    
                    if ($verifiedGrants.value -and $verifiedGrants.value.Count -gt 0) {
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
        $existingGroupAssignments = @(
            (Invoke-GraphApi -Context $containerGraphContext -Method GET -Uri "/v1.0/groups/$securityGroupId/appRoleAssignments" -Description 'Look up security group app assignment').value |
                Where-Object { $_.resourceId -eq $spObjectId -and $_.appRoleId -eq $assignmentBody.appRoleId }
        )
        if ($existingGroupAssignments.Count -gt 0) {
            Write-Host "  Security group already assigned" -ForegroundColor Green
        }
        else {
            Invoke-GraphApi -Context $containerGraphContext -Method POST -Uri "/v1.0/groups/$securityGroupId/appRoleAssignments" -Body $assignmentBody -Description 'Assign security group to app' | Out-Null
            Write-Host "  Security group assigned" -ForegroundColor Green
        }

        # -----------------------------------------------------------------
        # Step 20: Configure Easy Auth on Container App
        # -----------------------------------------------------------------
        Write-Host "`nStep 20: Configuring Easy Auth..." -ForegroundColor Cyan

        # Configure the auth config (implicit flow — no client secret needed for user authentication)
        Write-Host "  Enabling Entra ID authentication (implicit flow)..." -ForegroundColor Gray
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
        if ($effectiveDashboardDeliveryMode -eq 'Dual') {
            Write-Host "  4. The Container App serves the hosted dashboard while the self-contained HTML remains available in blob storage" -ForegroundColor Gray
            Write-Host "  5. Container App scales to zero when idle; cold starts fetch the latest blob`n" -ForegroundColor Gray
        }
        else {
            Write-Host "  4. Container App scales to zero when idle; cold starts fetch the latest blob`n" -ForegroundColor Gray
        }
    }
    elseif (-not $SkipValidation) {
        if ($effectiveDashboardDeliveryMode -eq 'Dual') {
            Write-Host "  1. Download VulnerabilityDashboard.html and VulnerabilityDashboard.Hosted.html from the 'dashboards' container" -ForegroundColor Gray
        }
        else {
            Write-Host "  1. Download VulnerabilityDashboard.html from the 'dashboards' container" -ForegroundColor Gray
        }
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
        if ($effectiveDashboardDeliveryMode -eq 'Dual') {
            Write-Host "  3. Download VulnerabilityDashboard.html and VulnerabilityDashboard.Hosted.html from the 'dashboards' container`n" -ForegroundColor Gray
        }
        else {
            Write-Host "  3. Download VulnerabilityDashboard.html from the 'dashboards' container`n" -ForegroundColor Gray
        }
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
