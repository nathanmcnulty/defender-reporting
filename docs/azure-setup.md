# Azure Setup

This page covers the Azure-specific parts of the project: permissions, authentication choices, infrastructure provisioning, and the optional Entra-protected Container App host.

## What the Azure provisioning script creates

`Setup-AzureResources.ps1` provisions infrastructure using one of two mutually exclusive compute types:

**Automation Account (default)**:
- A resource group
- An Azure Automation account with system-assigned managed identity
- A storage account with `exports`, `templates`, and `dashboards` containers
- RBAC for the Automation managed identity
- A PowerShell 7.4 runtime environment
- The dashboard runbook and daily schedule
- An optional Azure Container App protected by Entra ID Easy Auth

**Function App (Flex Consumption)**:
- A resource group
- An Azure Function App on a Flex Consumption plan (Linux, PowerShell 7.4)
- A storage account with `exports`, `templates`, `dashboards`, and `app-package` containers
- RBAC for the Function App managed identity (Blob Data Owner, Queue/Table Data Contributor)
- Timer-triggered function running daily at 2:00 AM UTC
- An optional Azure Container App protected by Entra ID Easy Auth

## When to choose each compute type

| Factor | Automation Account | Function App (Flex Consumption) |
|--------|-------------------|-------------------------------|
| **Best for** | Simple deployments, < 20K devices | Large environments, 20K–50K+ devices |
| **Scaling** | ~200 concurrent jobs | Up to 1000 instances, per-function scaling |
| **Cost (daily ~25 min run)** | ~$25–35/mo | ~$15–20/mo |
| **Monitoring** | Automation job logs | Application Insights (richer) |
| **Module management** | Managed runtime environment | Bundled in deployment zip |

## Prerequisites

- PowerShell module: `Az.Accounts`
- An authenticated Azure session via `Connect-AzAccount`
- Application Administrator in Entra ID if you want the script to grant MDE app roles automatically

`Setup-AzureResources.ps1` uses `Get-AzAccessToken` plus native Microsoft Graph REST calls first. If the Az-issued Graph token does not contain the required delegated scopes, the script falls back to `Microsoft.Graph.Authentication` when that module is installed. If neither path is available, the script fails fast with guidance.

## Basic provisioning (Automation Account)

```powershell
.\Setup-AzureResources.ps1 `
    -ResourceGroupName "rg-defender-reporting" `
    -AutomationAccountName "aa-defender-reporting" `
    -StorageAccountName "stdefenderreporting"
```

## Basic provisioning (Function App)

```powershell
.\Setup-AzureResources.ps1 `
    -ComputeType FunctionApp `
    -ResourceGroupName "rg-defender-reporting" `
    -FunctionAppName "func-defender-reporting" `
    -StorageAccountName "stdefenderreporting"
```

## Provisioning with a protected Container App

Either compute type works with the Container App:

```powershell
# With Automation Account (default)
.\Setup-AzureResources.ps1 `
    -ResourceGroupName "rg-defender-reporting" `
    -AutomationAccountName "aa-defender-reporting" `
    -StorageAccountName "stdefenderreporting" `
    -IncludeContainerApp `
    -SecurityGroup "Dashboard Viewers"

# With Function App
.\Setup-AzureResources.ps1 `
    -ComputeType FunctionApp `
    -ResourceGroupName "rg-defender-reporting" `
    -FunctionAppName "func-defender-reporting" `
    -StorageAccountName "stdefenderreporting" `
    -IncludeContainerApp `
    -SecurityGroup "Dashboard Viewers"
```

`-SecurityGroup` accepts either an Entra object ID or a display name.

## Hosted and dual packaging mode in Azure

`Setup-AzureResources.ps1` resolves the Azure dashboard packaging mode automatically:

- With `-IncludeContainerApp`, the default is `Hosted`.
- Without `-IncludeContainerApp`, the default is `SelfContained`.
- Use `-DashboardDeliveryMode` to override either default.
- `Dual` publishes both the self-contained dashboard and a hosted split-assets variant from the same normalized payload.

If you want to use the split-assets hosted dashboard in Azure, serve the hosted HTML and its sibling `.assets/` directory from the same HTTPS origin. That avoids browser cross-origin requests and keeps Easy Auth in front of the whole site.

When Azure runs in `Dual` mode, the dashboards container keeps both artifacts:

- `VulnerabilityDashboard.html` for the self-contained direct-open artifact.
- `VulnerabilityDashboard.Hosted.html` plus `VulnerabilityDashboard.Hosted.assets/` for hosted delivery.

If you provision a Container App with `Dual`, the Container App serves the hosted variant while the self-contained HTML remains available in blob storage for download or other non-hosted consumers.

Using blob CORS alone is not sufficient for the current secured setup:

- The provisioned storage account keeps blob public access disabled.
- The current Container App uses managed identity to fetch content server-side.
- A browser cannot reuse the Container App managed identity to fetch private blob assets directly.

For local validation of the hosted split-assets build, use a local HTTP server instead of opening the HTML with a `file://` URL.

## Common parameters

| Parameter | Required | Purpose |
|---|---|---|
| `-ComputeType` | No | `AutomationAccount` (default) or `FunctionApp` |
| `-ResourceGroupName` | First run only | Resource group name (auto-detected on re-runs) |
| `-AutomationAccountName` | When `AutomationAccount` | Automation account name |
| `-FunctionAppName` | When `FunctionApp` | Function App name |
| `-StorageAccountName` | First run only | Storage account name (auto-detected on re-runs) |
| `-Location` | No | Azure region, default `westus2` |
| `-SkipMdePermissions` | No | Skip automatic MDE app role assignment |
| `-SkipValidation` | No | Skip the post-provisioning validation run |
| `-DashboardDeliveryMode` | No | `Auto`, `SelfContained`, `Hosted`, or `Dual`; `Auto` chooses `Hosted` with `-IncludeContainerApp`, otherwise `SelfContained` |
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

## Pipeline source of truth

Both the Automation runbook and Function App derive from the same source file. `azure/Invoke-DashboardPipeline.ps1` is a tracked generated artifact that stays at its intentional repo path, while `azure/function-app/ExportAndGenerate/run.ps1` is generated on demand and ignored by git.

To change the pipeline logic:

1. Edit `src/powershell/Shared/**/*.ps1`
2. Edit `build/azure/runbook-source.ps1`
3. Rebuild with:

```powershell
# Rebuild the Automation runbook
.\build\azure\Build-Runbook.ps1

# Rebuild the Function App entry point
.\build\azure\Build-FunctionApp.ps1

# Build the stable Function App deployment zip + sidecar manifest
.\build\Build-FunctionAppPackage.ps1

# Publish dashboard templates through the supported build-layer contract
.\build\Publish-DashboardTemplates.ps1 -StorageAccountName <storage-account>
```

The Function App build transforms `runbook-source.ps1` into a timer-triggered function, replacing Automation Account variables with environment variable lookups and inlining the manifest-driven shared helper bundle generated from `src/powershell/Shared/`.

For memory-sensitive or normalization changes, validate the published Automation candidate with `tests/Invoke-AzureRunbookValidation.ps1` before leaving it deployed. Pass the subscription explicitly, use `-ValidatePublishedSemanticParity`, and run against both a high-cardinality content-only seed and the checked-in `exports` dataset. The harness backs up and restores the published runbook plus the `exports` and `dashboards` containers; it is the preferred way to perform temporary candidate validation against `aa-defender-reporting`.

The Azure runbook status evidence includes the selected normalization mode, input cardinalities, phase-boundary memory samples, and compiled pre-trim telemetry. A completed job is not sufficient acceptance by itself: require valid current/history/dictionary/ref/dashboard artifacts, expected row counts, zero missing or extra canonical rows, and a true working-set peak below the 400 MB Automation ceiling. See [the test validation guide](../tests/README.md#bounded-azure-acceptance) for the guarded command and dataset lanes.

`build/Build-FunctionAppPackage.ps1` is the supported packaging surface for CI and wrapper repositories. By default it rebuilds the generated Function App artifacts, stages `Az.Accounts`, writes a stable zip to `.local/local-reports/function-app-package/defender-reporting-function-app.zip`, and emits a sibling `.manifest.json` file that records the package path, SHA-256, and Function App artifact fingerprints.

`azure/Upload-Templates.ps1` now owns the package-safe template publishing implementation used by `Setup-AzureResources.ps1` and extracted Azure release bundles. `build/Publish-DashboardTemplates.ps1` remains the repo-owned wrapper surface for CI, wrapper repositories, and maintainer automation. Both entrypoints upload the canonical `templates/` tree to the `templates` blob container, emit the same stable tree fingerprint, and can optionally write a JSON manifest with the published file inventory.

## Related docs

- [GitHub Actions setup](github-actions-setup.md)
- [Workflow notes](workflows.md)
