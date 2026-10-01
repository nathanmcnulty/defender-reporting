# Dashboard Publication Guarantees

Automation and Function App builds use the same publisher and the same container-wide `_publication/publication.lock`. The lock is initialized with conditional creation (`If-None-Match: *`), leased for 60 seconds, and renewed every 15 seconds in a separate worker during uploads. A failed heartbeat aborts further publication. Entrypoint blobs additionally have bounded leases: every root PUT requires its lease ID and the snapshotted ETag (`If-Match`). A writer that loses ownership cannot replace an entrypoint. Deploy the updated publisher to every active writer; older deployed versions that do not acquire this lock are not covered by the cooperative serialization guarantee.

The publisher validates required dependencies from HTML and `dashboardConfig`, including CSS, scripts, pako, payload, summary, configured worker URLs and external PDF runtime/bundle URLs. It conditionally creates immutable generation assets, reads them back to verify SHA-256, and checks the staged count against its manifest before writing an entrypoint. Dependencies must remain within the matching `.assets/` subtree; arbitrary URLs and traversal paths are rejected. Blob hash metadata supports byte verification by the serving container.

The hosted entrypoint is the authoritative hosted commit point and is written last in Dual mode. Azure atomically replaces each individual blob, but there is **no distributed ACID transaction across the compressed and hosted roots**, exports, or status document. Each winning root references a complete staged bundle; Dual readers can briefly observe different generations between entrypoint writes. Failures before any root PUT leave prior usable roots unchanged. A failed root PUT can have committed remotely despite a lost response: the publisher attempts fenced restoration, then reads back and verifies the old root hash. Restoration errors are surfaced alongside the original error, not suppressed.

Before a root write, prior root bytes and SHA-256/ETag identities are saved under a unique `_publication/recovery/` prefix. Uncertain commit/restoration outcomes report `DashboardPublicationIndeterminate`, do not prune candidate or old assets, and retain durable recovery records for operator reconciliation. Recovery copies are removed only after verified successful publication; copies left by failed attempts are intentionally retained. Retention protects full reference sets from both current and previous roots and durable recovery roots, including references outside the payload generation. Unversioned legacy assets are conservatively retained. Only unreferenced versioned generations are eligible for cleanup.

If final status upload fails after verified publication, the pipeline reports `DashboardPublishedStatusFailed`; it does not roll back the verified published dashboard or claim the prior roots were unchanged. Status upload is not part of the root commit transaction. A secondary attempt to report this failure can itself fail; execution logs remain the failure evidence.

The Caddy startup script derives dependencies using the same shared dependency policy as publication and Setup verification. It downloads a candidate root and every required dependency into staging, verifies bytes, then atomically replaces the local index. Previous local generation bytes remain available. Legacy dependency paths are rewritten to content-identified local generation paths before index replacement, avoiding mutable-file rollover. The Alpine image installs curl, jq and coreutils at startup, so its package mirror must be reachable. On first-start failure without a prior local index there is no usable dashboard; subsequent sync failure retains the prior local dashboard. This local guarantee does not create a cross-root cloud transaction.

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
For an isolated deployment, pass a unique `-EasyAuthAppDisplayName` so setup
creates its own app registration instead of selecting an older registration
with the default display name. Reruns use the registration already configured
on that Container App.

For guest or cross-tenant administration, the Azure subscription tenant and
the active Microsoft Graph tenant can differ. Easy Auth uses the tenant of
the Graph session that manages the app registration and security group:
the Graph access token's `tid` in Az-token mode, or the connected
`Get-MgContext` tenant in SDK mode. Setup validates this tenant as a non-empty
GUID string immediately after selecting the Container App Graph context,
using strict UTF-8 decoding and a JSON object in Az-token mode. Malformed
UTF-8 (even in an unrelated claim), BOM-prefixed JSON, primitive or array
roots, and invalid tenant claims stop before any Graph lookup or Container
App ARM operation with a static, non-sensitive error. Valid UTF-8 Unicode
claims, including non-ASCII display names and emoji, remain supported.
Setup then validates any explicit `-EasyAuthAppClientId` with a read-only, filtered
application lookup in that same Graph tenant. The supplied GUID must be an
application client ID, not an object ID, and exactly one matching application
must exist. Invalid tenant claims, invalid client IDs, missing applications,
and failed application reads stop this Container App block before environment,
Container App, storage RBAC, identity, or Easy Auth writes. Read-only Graph
lookups are allowed only after tenant validation. This is not an all-Setup ARM preflight:
earlier resource-group, compute, and storage steps are outside this boundary
and are not rolled back. New app creation remains after the actual Container
App FQDN is available for its redirect URI.
There is no implicit Azure or home-tenant fallback. Select the intended Graph
session rather than relying on the Azure resource context to identify the
app-registration tenant.

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
| `-AutomationAccountName` | When `AutomationAccount`; optional for migration | Automation account name, or the existing source account to auto-discover shared resources when creating a Function App |
| `-FunctionAppName` | When `FunctionApp` | Function App name |
| `-StorageAccountName` | First run only | Storage account name (auto-detected on re-runs) |
| `-Location` | No | Azure region, default `westus2` |
| `-SkipMdePermissions` | No | Skip automatic MDE app role assignment |
| `-ValidationDatasetPath` | No | Local dataset to seed Automation validation with `-SkipMdePermissions` |
| `-ValidationExpectedTotalRows` | Seeded Automation validation unless authoritative metadata exists | Expected onboarded normalized dashboard rows, not raw source observations |
| `-SkipValidation` | No | Skip the post-provisioning validation run |
| `-DashboardDeliveryMode` | No | `Auto`, `SelfContained`, `Hosted`, or `Dual`; `Auto` chooses `Hosted` with `-IncludeContainerApp`, otherwise `SelfContained` |
| `-IncludeContainerApp` | No | Deploy the Entra-protected Container App |
| `-SecurityGroup` | With `-IncludeContainerApp` | Group allowed to access the Container App |
| `-ContainerAppName` | No | Override the derived Container App name |
| `-EasyAuthAppClientId` | No | Explicitly select an existing Easy Auth app registration when a legacy deployment has ambiguous duplicates and no usable Container App auth configuration |
| `-EasyAuthAppDisplayName` | No | Name for a new Easy Auth registration; defaults to `Defender Reporting Dashboard` for compatibility. Use a unique name for an isolated deployment. |

`-SkipMdePermissions` disables recurring execution for both compute types: the Automation daily schedule is explicitly disabled and verified through ARM, and the Function App sets and verifies `AzureWebJobs.ExportAndGenerate.Disabled=true`. Existing Function App settings, including secrets and unrelated function settings, are preserved; setup updates only its owned keys. After configuring the required MDE app roles, rerun setup without `-SkipMdePermissions` to explicitly enable the Automation schedule or set the Function disable setting to `false`.

Manual seeded validation can still use `UseExistingExportsOnly=true`. Disabling recurring execution does not force manual jobs into seeded mode. Use `-SkipValidation` to avoid starting a setup validation job, and specify `-DashboardDeliveryMode Dual` when retaining an existing Dual deployment without hosting configuration. Omit `-IncludeContainerApp` when only updating compute scheduling to leave hosting and Easy Auth untouched.

Seeded Automation setup (`-SkipMdePermissions` without `-SkipValidation`) requires `-ValidationExpectedTotalRows` or an authoritative JSON integer `expectedDashboardRows` in the dataset's `synthetic-manifest.json`. An explicit count takes precedence. Counts must be integers from 1 to 50,000,000; source fields such as `actualTotalVulnRows` and `actualCurrentRows` are not inferred as dashboard counts. Missing or invalid expectations fail before Azure provisioning or export seeding. `-SkipValidation` remains deployment-only and does not require a dataset or expected count. The deployment-validation wrapper accepts and forwards the same expected-count parameter.

A completed seeded job passes only after Entra-authenticated reads verify the current Automation job ID, run ID and start time, succeeded/Completed status, expected vulnerability count and positive device/CVE counts, required HTML/assets, and each artifact's SHA-256 against the completion status. External PDF runtime and bundle assets declared in the embedded `dashboardConfig` JSON are required, downloaded, and hash-checked even though they reside in the `optional` directory; configured paths must remain within the dashboard's asset directory, not remote URLs or traversal paths. Inline SelfContained PDF defaults do not require external files. Hosted summary counts and payload SHA-256 must match, and a streaming payload check must count the expected rows. Dual mode also requires byte-identical compressed payloads in the self-contained and hosted artifacts. The release includes the production provisioning validator and shared runtime helpers; no tests folder is required. These lightweight checks do not replace optional full source-row semantic replay.

When migrating an existing Automation Account deployment to a Function App,
pass `-AutomationAccountName` with the existing account and the script can
auto-discover the shared resource group, location, and storage account. You can
also pass the resource group and storage account names explicitly. The setup creates the
Function App and its managed-identity role assignments while retaining the
Automation Account, storage data, Container App, and Entra configuration. On
reruns, the Container App's configured Easy Auth client ID is treated as the
authoritative app registration. If legacy runs left duplicate registrations,
the script reuses that configured registration and creates its missing service
principal if necessary; it does not delete the duplicates.

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

`build/Publish-DashboardTemplates.ps1` is the canonical template-publishing implementation for CI, wrapper repositories, and maintainer automation. During packaging, `build/azure/Build-TemplatePublisher.ps1` inlines its focused helper and generates a self-contained `azure/Upload-Templates.ps1` for `Setup-AzureResources.ps1` and extracted release bundles. Both entrypoints upload the canonical `templates/` tree, emit the same stable tree fingerprint, and can optionally write a JSON manifest with the published inventory.

## Related docs

- [GitHub Actions setup](github-actions-setup.md)
- [Workflow notes](workflows.md)
