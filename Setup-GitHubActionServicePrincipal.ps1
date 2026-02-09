#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Creates an Entra service principal with federated credentials for GitHub Actions.

.DESCRIPTION
    This script creates an Azure AD application registration, service principal, and configures
    federated credentials for GitHub Actions OIDC authentication. It also assigns the necessary
    permissions for Microsoft Defender for Endpoint API access.

.PARAMETER AppName
    The name of the application registration (default: "defender-reporting-github-action")

.PARAMETER GitHubRepo
    The GitHub repository in format "owner/repo" (default: "nathanmcnulty/defender-reporting")

.PARAMETER Branch
    The branch name for the federated credential (default: "main")

.PARAMETER IncludeAdvancedHunting
    Include the AdvancedQuery.Read.All permission for MDE Advanced Hunting queries.

.EXAMPLE
    .\Setup-GitHubActionServicePrincipal.ps1
    
.EXAMPLE
    .\Setup-GitHubActionServicePrincipal.ps1 -AppName "MyApp" -GitHubRepo "myorg/myrepo" -Branch "production"

.EXAMPLE
    .\Setup-GitHubActionServicePrincipal.ps1 -IncludeAdvancedHunting
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$AppName = "defender-reporting-github-action",
    
    [Parameter()]
    [string]$GitHubRepo = "nathanmcnulty/defender-reporting",
    
    [Parameter()]
    [string]$Branch = "main",

    [Parameter()]
    [switch]$IncludeAdvancedHunting
)

# Ensure Microsoft.Graph module is installed
$requiredModule = 'Microsoft.Graph.Authentication'
if (-not (Get-Module -ListAvailable -Name $requiredModule)) {
    Write-Host "Installing module: $requiredModule" -ForegroundColor Yellow
    Install-Module -Name $requiredModule -Force -AllowClobber -Scope CurrentUser
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# Connect to Microsoft Graph
Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan
try {
    $context = Get-MgContext
    if (-not $context) {
        Connect-MgGraph -Scopes "Application.ReadWrite.All"
    }
    Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
    Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor Gray
    Write-Host "  Account: $($context.Account)" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

$tenantId = $context.TenantId

# Check if application already exists
Write-Host "`nChecking for existing application..." -ForegroundColor Cyan
try {
    $existingApps = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$AppName'"
    
    if ($existingApps.value.Count -gt 0) {
        $app = $existingApps.value[0]
        Write-Host "✓ Application '$AppName' already exists" -ForegroundColor Yellow
        Write-Host "  Application ID: $($app.appId)" -ForegroundColor Gray
    }
    else {
        # Create the application registration
        Write-Host "`nCreating application registration..." -ForegroundColor Cyan
        
        $appBody = @{
            displayName = $AppName
        } | ConvertTo-Json
        
        $app = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications" -Body $appBody -ContentType "application/json"
        
        Write-Host "✓ Application created successfully" -ForegroundColor Green
        Write-Host "  Application ID: $($app.appId)" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Failed to create/retrieve application: $_"
    exit 1
}

# Create service principal if it doesn't exist
Write-Host "`nChecking for service principal..." -ForegroundColor Cyan
try {
    $existingSPs = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($app.appId)'"
    
    if ($existingSPs.value.Count -gt 0) {
        Write-Host "✓ Service principal already exists" -ForegroundColor Yellow
    }
    else {
        Write-Host "Creating service principal..." -ForegroundColor Cyan
        
        $spBody = @{
            appId = $app.appId
        } | ConvertTo-Json
        
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" -Body $spBody -ContentType "application/json" | Out-Null
        
        Write-Host "✓ Service principal created successfully" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to create service principal: $_"
    exit 1
}

# Configure federated credential for GitHub Actions
Write-Host "`nConfiguring federated credential..." -ForegroundColor Cyan
$federatedCredentialName = "github-actions-$($Branch.Replace('/', '-'))"
$subject = "repo:$GitHubRepo:ref:refs/heads/$Branch"

try {
    # Check if federated credential already exists
    $existingCreds = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/federatedIdentityCredentials"
    
    $existingCred = $existingCreds.value | Where-Object { $_.subject -eq $subject }
    
    if ($existingCred) {
        Write-Host "✓ Federated credential already exists" -ForegroundColor Yellow
        Write-Host "  Name: $($existingCred.name)" -ForegroundColor Gray
        Write-Host "  Subject: $($existingCred.subject)" -ForegroundColor Gray
    }
    else {
        $credBody = @{
            name      = $federatedCredentialName
            issuer    = 'https://token.actions.githubusercontent.com'
            subject   = $subject
            audiences = @('api://AzureADTokenExchange')
        } | ConvertTo-Json
        
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/federatedIdentityCredentials" -Body $credBody -ContentType "application/json" | Out-Null
        
        Write-Host "✓ Federated credential created successfully" -ForegroundColor Green
        Write-Host "  Name: $federatedCredentialName" -ForegroundColor Gray
        Write-Host "  Subject: $subject" -ForegroundColor Gray
        Write-Host "  Issuer: https://token.actions.githubusercontent.com" -ForegroundColor Gray
        Write-Host "  Audience: api://AzureADTokenExchange" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Failed to create federated credential: $_"
    exit 1
}

# Add Microsoft Defender API permissions
Write-Host "`nConfiguring API permissions..." -ForegroundColor Cyan
$defenderApiId = "fc780465-2017-40d4-a0c5-307022471b92" # Microsoft Threat Protection API
$vulnerabilityPermissionId = "41269fc5-d04d-4bfd-bce7-43a51cea049a"  # Vulnerability.Read.All
$machinePermissionId = "ea8291d3-4b9a-44b5-bc3a-6cea3026dc79"        # Machine.Read.All
$advancedQueryPermissionId = "93489bf5-0fbc-4f2d-b901-33f2fe08ff05"  # AdvancedQuery.Read.All

$requiredPermissions = @($vulnerabilityPermissionId, $machinePermissionId)
if ($IncludeAdvancedHunting) {
    $requiredPermissions += $advancedQueryPermissionId
}

try {
    # Get current app details
    $currentApp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)"
    
    # Check if all permissions already exist
    $defenderResource = $currentApp.requiredResourceAccess | Where-Object { $_.resourceAppId -eq $defenderApiId }
    $existingPermissionIds = if ($defenderResource) { $defenderResource.resourceAccess.id } else { @() }
    $missingPermissions = $requiredPermissions | Where-Object { $_ -notin $existingPermissionIds }
    $hasPermission = $missingPermissions.Count -eq 0
    
    if ($hasPermission) {
        Write-Host "✓ API permissions already configured" -ForegroundColor Yellow
        Write-Host "  - Vulnerability.Read.All" -ForegroundColor Gray
        Write-Host "  - Machine.Read.All" -ForegroundColor Gray
        if ($IncludeAdvancedHunting) { Write-Host "  - AdvancedQuery.Read.All" -ForegroundColor Gray }
    }
    else {
        Write-Host "Adding API permissions..." -ForegroundColor Cyan
        Write-Host "  - Vulnerability.Read.All" -ForegroundColor Gray
        Write-Host "  - Machine.Read.All" -ForegroundColor Gray
        if ($IncludeAdvancedHunting) { Write-Host "  - AdvancedQuery.Read.All" -ForegroundColor Gray }
        
        # Build the required resource access
        $existingPermissions = $currentApp.requiredResourceAccess
        if (-not $existingPermissions) {
            $existingPermissions = @()
        }
        
        # Build the complete list of permissions for Defender API
        $defenderResourceAccess = $requiredPermissions | ForEach-Object {
            @{
                id   = $_
                type = "Role"
            }
        }
        
        # Remove existing Defender resource if present, then add complete one
        $newPermissions = @($existingPermissions | Where-Object { $_.resourceAppId -ne $defenderApiId })
        $newPermissions += @{
            resourceAppId  = $defenderApiId
            resourceAccess = $defenderResourceAccess
        }
        
        $permissionBody = @{
            requiredResourceAccess = $newPermissions
        } | ConvertTo-Json -Depth 10
        
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" -Body $permissionBody -ContentType "application/json"
        
        Write-Host "✓ API permissions added" -ForegroundColor Green
        Write-Host "`n⚠️  IMPORTANT: Admin consent is required!" -ForegroundColor Yellow
        Write-Host "   Please grant admin consent in the Azure Portal:" -ForegroundColor Yellow
        Write-Host "   1. Go to: https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($app.appId)" -ForegroundColor Gray
        Write-Host "   2. Click 'Grant admin consent for [Your Organization]'" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Failed to configure API permissions: $_"
    exit 1
}

# Output summary
Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "SETUP COMPLETE" -ForegroundColor Green
Write-Host ("=" * 80) -ForegroundColor Cyan

Write-Host "`nGitHub Secrets Configuration:" -ForegroundColor Cyan
Write-Host "Add these secrets to your GitHub repository:" -ForegroundColor White
Write-Host "  Repository: https://github.com/$GitHubRepo/settings/secrets/actions" -ForegroundColor Gray
Write-Host ""
Write-Host "  AZURE_CLIENT_ID: " -NoNewline -ForegroundColor White
Write-Host $app.appId -ForegroundColor Yellow
Write-Host "  AZURE_TENANT_ID: " -NoNewline -ForegroundColor White
Write-Host $tenantId -ForegroundColor Yellow

Write-Host "`nService Principal Details:" -ForegroundColor Cyan
Write-Host "  Display Name: $AppName" -ForegroundColor Gray
Write-Host "  Application (Client) ID: $($app.appId)" -ForegroundColor Gray
Write-Host "  Object ID: $($app.id)" -ForegroundColor Gray
Write-Host "  Tenant ID: $tenantId" -ForegroundColor Gray

Write-Host "`nFederated Credential:" -ForegroundColor Cyan
Write-Host "  Subject: $subject" -ForegroundColor Gray
Write-Host "  Issuer: https://token.actions.githubusercontent.com" -ForegroundColor Gray
Write-Host "  Audience: api://AzureADTokenExchange" -ForegroundColor Gray

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "  1. Grant admin consent for API permissions (see link above)" -ForegroundColor White
Write-Host "  2. Add the GitHub secrets to your repository" -ForegroundColor White
Write-Host "  3. Run your GitHub Action workflow" -ForegroundColor White

Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
