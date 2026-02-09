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
        Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"
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
        $sp = $existingSPs.value[0]
        Write-Host "✓ Service principal already exists" -ForegroundColor Yellow
        Write-Host "  Object ID: $($sp.id)" -ForegroundColor Gray
    }
    else {
        Write-Host "Creating service principal..." -ForegroundColor Cyan
        
        $spBody = @{
            appId = $app.appId
        } | ConvertTo-Json
        
        $sp = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" -Body $spBody -ContentType "application/json"
        
        Write-Host "✓ Service principal created successfully" -ForegroundColor Green
        Write-Host "  Object ID: $($sp.id)" -ForegroundColor Gray
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
    # Check if federated credential already exists (match on subject or name)
    $existingCreds = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/federatedIdentityCredentials"
    
    $existingCred = $existingCreds.value | Where-Object { $_.subject -eq $subject -or $_.name -eq $federatedCredentialName }
    
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
        
        try {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/federatedIdentityCredentials" -Body $credBody -ContentType "application/json" -ErrorAction Stop | Out-Null
            
            Write-Host "✓ Federated credential created successfully" -ForegroundColor Green
            Write-Host "  Name: $federatedCredentialName" -ForegroundColor Gray
            Write-Host "  Subject: $subject" -ForegroundColor Gray
            Write-Host "  Issuer: https://token.actions.githubusercontent.com" -ForegroundColor Gray
            Write-Host "  Audience: api://AzureADTokenExchange" -ForegroundColor Gray
        }
        catch {
            if ($_.Exception.Message -match 'Request_MultipleObjectsWithSameKeyValue|already exists') {
                Write-Host "✓ Federated credential already exists" -ForegroundColor Yellow
            }
            else {
                throw
            }
        }
    }
}
catch {
    Write-Error "Failed to create federated credential: $_"
    exit 1
}

# Grant Microsoft Defender API permissions via appRoleAssignment (admin consent)
Write-Host "`nConfiguring API permissions..." -ForegroundColor Cyan
$defenderApiId = "fc780465-2017-40d4-a0c5-307022471b92" # Microsoft Threat Protection API

$requiredRoles = @("Vulnerability.Read.All", "Machine.Read.All")
if ($IncludeAdvancedHunting) {
    $requiredRoles += "AdvancedQuery.Read.All"
}

try {
    # Find the WindowsDefenderATP service principal
    Write-Host "  Looking up WindowsDefenderATP service principal..." -ForegroundColor Gray
    $mdeSpResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$defenderApiId'"
    $mdeSp = $mdeSpResponse.value | Select-Object -First 1
    
    if (-not $mdeSp) {
        throw "WindowsDefenderATP service principal not found in tenant. Ensure Microsoft Defender for Endpoint is enabled."
    }
    
    $mdeSpObjectId = $mdeSp.id
    Write-Host "  Found MDE SP: $mdeSpObjectId" -ForegroundColor Gray
    
    # Assign each required app role
    foreach ($roleName in $requiredRoles) {
        $appRole = $mdeSp.appRoles | Where-Object { $_.value -eq $roleName }
        if (-not $appRole) {
            Write-Warning "App role '$roleName' not found on WindowsDefenderATP SP. Skipping."
            continue
        }
        
        Write-Host "  Assigning $roleName..." -ForegroundColor Gray
        
        $body = @{
            principalId = $sp.id
            resourceId  = $mdeSpObjectId
            appRoleId   = $appRole.id
        }
        
        try {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments" -Body $body -ErrorAction Stop | Out-Null
            Write-Host "    ✓ $roleName assigned" -ForegroundColor Green
        }
        catch {
            if ("$_" -match 'Permission being assigned already exists') {
                Write-Host "    ✓ $roleName already assigned" -ForegroundColor Green
            }
            else {
                Write-Warning "Failed to assign $roleName`: $_"
            }
        }
    }
    
    Write-Host "✓ API permissions configured (admin consent granted)" -ForegroundColor Green
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
Write-Host "  1. Add the GitHub secrets to your repository" -ForegroundColor White
Write-Host "  2. Run your GitHub Action workflow" -ForegroundColor White

Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
