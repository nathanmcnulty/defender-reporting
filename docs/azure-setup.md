# Azure Setup

This page covers the Azure-specific parts of the project: permissions, authentication choices, infrastructure provisioning, and the optional Entra-protected Container App host.

## What the Azure provisioning script creates

`Setup-AzureResources.ps1` provisions:

- A resource group
- An Azure Automation account with system-assigned managed identity
- A storage account with `exports`, `templates`, and `dashboards` containers
- RBAC for the Automation managed identity
- A PowerShell 7.4 runtime environment
- The dashboard runbook and daily schedule
- An optional Azure Container App protected by Entra ID Easy Auth

## Prerequisites

- PowerShell module: `Az.Accounts`
- An authenticated Azure session via `Connect-AzAccount`
- Application Administrator in Entra ID if you want the script to grant MDE app roles automatically

`Setup-AzureResources.ps1` uses `Get-AzAccessToken` plus native Microsoft Graph REST calls first. If the Az-issued Graph token does not contain the required delegated scopes, the script falls back to `Microsoft.Graph.Authentication` when that module is installed. If neither path is available, the script fails fast with guidance.

## Basic provisioning

```powershell
.\Setup-AzureResources.ps1 `
    -ResourceGroupName "rg-defender-reporting" `
    -AutomationAccountName "aa-defender-reporting" `
    -StorageAccountName "stdefenderreporting"
```

## Provisioning with a protected Container App

```powershell
.\Setup-AzureResources.ps1 `
    -ResourceGroupName "rg-defender-reporting" `
    -AutomationAccountName "aa-defender-reporting" `
    -StorageAccountName "stdefenderreporting" `
    -IncludeContainerApp `
    -SecurityGroup "Dashboard Viewers"
```

`-SecurityGroup` accepts either an Entra object ID or a display name.

## Common parameters

| Parameter | Required | Purpose |
|---|---|---|
| `-ResourceGroupName` | Yes | Resource group name |
| `-AutomationAccountName` | Yes | Automation account name |
| `-StorageAccountName` | Yes | Storage account name |
| `-Location` | No | Azure region, default `westus2` |
| `-SkipMdePermissions` | No | Skip automatic MDE app role assignment |
| `-SkipValidation` | No | Skip the post-provisioning validation run |
| `-IncludeContainerApp` | No | Deploy the Entra-protected Container App |
| `-SecurityGroup` | With `-IncludeContainerApp` | Group allowed to access the Container App |
| `-ContainerAppName` | No | Override the derived Container App name |

## Required Microsoft Defender app roles

These scripts rely on application permissions on the WindowsDefenderATP service principal:

- `Vulnerability.Read.All`
- `Machine.Read.All`
- `AdvancedQuery.Read.All` for Advanced Hunting enrichment

If you want to assign those roles to a managed identity or service principal manually, this Az-only helper snippet works:

```powershell
$MI = "34634404-8c0b-4141-a9dd-195fa6e6a51f"

$token = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/' -AsSecureString).Token
$ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
try {
    $graphToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
}
finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}

$headers = @{
    Authorization = "Bearer $graphToken"
    'Content-Type' = 'application/json'
}

$MdeSp = (Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq 'fc780465-2017-40d4-a0c5-307022471b92'" -Headers $headers).value
if ($null -eq $MdeSp) { Write-Output "The MDE workspace has not been provisioned. Please go to https://security.microsoft.com/securitysettings/endpoints/integration to provision"; exit }

"Vulnerability.Read.All","Machine.Read.All","AdvancedQuery.Read.All" | ForEach-Object {
   $permission = $_
   $AppRole = $MdeSp.AppRoles | Where-Object {$_.Value -eq $permission -and $_.AllowedMemberTypes -contains "Application"}
   $body = @{
    "principalId" = $MI
    "resourceId" = $MdeSp.Id
    "appRoleId" = $AppRole.Id
   }
   Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MI/appRoleAssignments" -Headers $headers -Body ($body | ConvertTo-Json -Depth 5)
}
```

## Authentication options for `Invoke-VulnerabilityExport.ps1`

### Service principal with client secret

```powershell
$secret = Read-Host -AsSecureString -Prompt 'Enter client secret'
.\Invoke-VulnerabilityExport.ps1 `
    -TenantId 'your-tenant-id' `
    -AppId 'your-app-id' `
    -AppSecret $secret `
    -OutputPath .\exports `
    -IncludeAdvancedHunting
```

### Existing Defender API token

```powershell
.\Invoke-VulnerabilityExport.ps1 `
    -AccessToken $accessToken `
    -OutputPath .\exports `
    -IncludeAdvancedHunting
```

### Managed identity

For Azure Automation or other managed identity hosts, sign in with the managed identity, request a Defender token, then pass it to the export script:

```powershell
Disable-AzContextAutosave -Scope Process
Connect-AzAccount -Identity

$secureAccessToken = (Get-AzAccessToken -ResourceUrl 'https://api.securitycenter.microsoft.com' -AsSecureString).Token
$ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAccessToken)
try {
    $accessToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
}
finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
}

.\Invoke-VulnerabilityExport.ps1 `
    -AccessToken $accessToken `
    -OutputPath .\exports `
    -IncludeAdvancedHunting
```

## Runbook source of truth

`azure/Invoke-DashboardPipeline.ps1` is generated. To change the Azure Automation runbook:

1. Edit `shared-helpers.ps1`
2. Edit `azure/runbook-source.ps1`
3. Rebuild with:

```powershell
.\azure\Build-Runbook.ps1
```

## Related docs

- [GitHub Actions setup](github-actions-setup.md)
- [Workflow notes](workflows.md)
