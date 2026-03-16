# Defender Vulnerability Reporting Dashboard

<img width="2785" height="1640" alt="image" src="https://github.com/user-attachments/assets/cc006078-530a-4587-924b-a94a9549a666" />


<br><br>

I wanted to practice a bit of AI coding to build a dashboard that did not have a dependency on Power BI or other tools. The concept was simple - export vulnerability data from the Defender for Endpoint APIs, then use PowerShell to create an HTML report from the data.

In this repo, I have provided the script, sample data, sample HTML page, sample PDF outputs, and the AI chat history in case you'd like to attempt your own dashboards with other data :)

Here was the prompt I started with in planning:

```plain
Goal: Create a vulnerability reporting dashboard that uses interactive charts to help visualize vulnerability change over time. For this data, firstSeenTimestamp is when a vulnerability was first discovered, and lastSeenTimestamp is when the vulnerability was resolved.

Filters will be provided toward the top allowing filtering based on attributes such as dates, rbacGroupName, vulnerabilitySeverityLevel, osVersion, etc. 

A chart will be rendered below the filters showing count of vulnerabilities per day based on the selected filters. This chart will show change per day with separate lines per vulnerabilitySeverityLevel

A table will be provided below the chart with the following columns:

Remediation = "softwareVendor - recommendedSecurityUpdate" (from JSON)
Assets = Count of unique DeviceName (from JSON) for the CveBatchTitle (use DeviceId in JSON)
Vulnerabilities = Count of unique Id (from JSON) for the CveBatchTitle
Exploits = Count of unique ExploitabilityLevel (from JSON) where the value is "ExploitIsVerified" for the CveBatchTitle
Kits = Count of unique ExploitabilityLevel (from JSON) where the value is "ExploitIsInKit" for the CveBatchTitle

Selecting a row from the table will open modal box or flyout that shows details about that remediation including list of deviceName, softwareVendor, softwareName, softwareVersion, cveId, vulnerabilitySeverityLevel,etc.


Data will be exported in the format found in vulnerabilities.json

A PowerShell script will ingest the data and produce an HTML report to render charts and tables
```

## API Permissions

This script helps set the API permissions for your Managed Identity or Service Principal (set $MI to the objectId of your MI/SP). 

For Azure automation tools, you need to enable the Managed Identity. For other scenarios, you need to create an app registration in Entra and either set up a certificate (preferred) or secret for authentication. For more details, see the docs: https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp?tabs=PowerShell

```powershell
$MI = "34634404-8c0b-4141-a9dd-195fa6e6a51f"

# Connect to Graph with scope to grant API permissions to Managed Identity
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All"

# Get SP for WindowsDefenderATP API
$MdeSp = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq 'fc780465-2017-40d4-a0c5-307022471b92'").value
if ($null -eq $MdeSp) { Write-Output "The MDE workspace has not been provisionged. Please go to https://security.microsoft.com/securitysettings/endpoints/integration to provision"; exit }

# Get each permission App Role ID and assign the App Role to the Managed Identity
"Vulnerability.Read.All","Machine.Read.All","AdvancedQuery.Read.All" | ForEach-Object {
   $permission = $_
   $AppRole = $MdeSp.AppRoles | Where-Object {$_.Value -eq $permission -and $_.AllowedMemberTypes -contains "Application"}
   $body = @{
    "principalId" = $MI
    "resourceId" = $MdeSp.Id
    "appRoleId" = $AppRole.Id
   }
   Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MI/appRoleAssignments" -Body ($body | ConvertTo-Json) -ContentType "application/json"
}
```

## Obtaining Vulnerability Mangaement data using Managed Identities

The script below uses a Managed Identity to connect to Azure, requests a token for the WindowsDefenderATP API, and saves the *.json.gz files to the current directory.

```powershell
# Authenticate
Disable-AzContextAutosave -Scope Process
Connect-AzAccount -Identity

# Get token
$secureAccessToken = (Get-AzAccessToken -ResourceUri 'https://api.securitycenter.microsoft.com/.default' -AsSecureString).token
$ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAccessToken)
try {
    $accessToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
}
finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
}

$headers = @{
    'Content-Type' = 'application/json'
    Accept         = 'application/json'
    Authorization  = "Bearer $accessToken"
}

$files = (Invoke-RestMethod -Uri "https://api-us.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesExport" -Headers $headers).exportFiles
$files | ForEach-Object {
    $date = $_.split('/')[6]
    $groupId = $_.Split('/')[9].Split('%3D')[-1]
    Invoke-WebRequest -Uri $_ -OutFile "./VulnExport_$groupId`_$date.json.gz"
}
```

## Obtaining Vulnerability Mangaement data using Service Principals with a secret

The script below uses a Service Principal to request a token for the WindowsDefenderATP API and saves the *.json.gz files to the current directory.

```powershell
## Service Principal Info
$tenantId = '847b5907-ca15-40f4-b171-eb18619dbfab'
$appId = '1c02e02c-59e6-4ff4-9e01-fea10c87f51f'
$appSecret = ''

## Get Token
$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$authBody = [Ordered] @{
    resource      = "$resourceAppIdUri"
    client_id     = "$appId"
    client_secret = "$appSecret"
    grant_type    = 'client_credentials'
}
$accessToken = (Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop).access_token

$headers = @{
    'Content-Type' = 'application/json'
    Accept         = 'application/json'
    Authorization  = "Bearer $accessToken"
}

$files = (Invoke-RestMethod -Uri "https://api-us.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesExport" -Headers $headers).exportFiles
$files | ForEach-Object {
    $date = $_.split('/')[6]
    $groupId = $_.Split('/')[9].Split('%3D')[-1]
    Invoke-WebRequest -Uri $_ -OutFile "./VulnExport_$groupId`_$date.json.gz"
}
```

For more details on this API, see the docs: https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities

## Exporting Dashboard Data

`Invoke-VulnerabilityExport.ps1` is now the main entrypoint for dashboard data export. It downloads the Defender bulk vulnerability export, immediately converts it into the canonical vulnerability current/history gzip store, exports machine data, and optionally exports Advanced Hunting enrichment.

After authenticating (using either method above), run:

```powershell
# Export the deduplicated machine store
.\Invoke-VulnerabilityExport.ps1 -TenantId $tenantId -AppId $appId -AppSecret $secret
```

This writes the canonical vulnerability files:

- `VulnExport_current.json.gz`: current open vulnerability row versions
- `VulnHistory_YYYY.json.gz`: historical row versions closed during that calendar year

It also writes the machine files:

- `Machines_Current.json.gz`: latest known state per `deviceId`
- `Machines_History.json.gz`: append-only state changes per `deviceId`

The export script automatically upgrades any legacy vulnerability snapshot files it finds while publishing the canonical store. Temporary legacy upgrade compatibility remains in the main scripts until `2026-07-01`, after which those compatibility paths should be removed.

The dashboard script automatically prefers `Machines_Current.json.gz`, falls back to `Machines_History.json.gz`, and still supports older plain canonical files plus legacy `Machines_*.json` snapshot files during migration.

## Obtaining Advanced Hunting Enrichment

Advanced Hunting enrichment is now maintained as a canonical cache file instead of accumulating dated snapshots. This preserves the latest known CVE metadata even after a vulnerability no longer appears in current Advanced Hunting results.

When you run:

```powershell
.\Invoke-VulnerabilityExport.ps1 -TenantId $tenantId -AppId $appId -AppSecret $secret -IncludeAdvancedHunting
```

the script upserts results into:

- `AdvancedHunting_Current.json.gz`: latest known enrichment per `CveId`, preserved even after remediation

The dashboard script automatically prefers `AdvancedHunting_Current.json.gz` and still supports the older plain canonical file plus legacy `AdvancedHunting_*_yyyy-MM-dd.json` files during migration.

## Vulnerability History Store

Vulnerability exports now support a canonical current/history store so repeated daily snapshots do not need to retain identical row versions forever.

The canonical files are:

- `VulnExport_current.json.gz`: current open vulnerability row versions
- `VulnHistory_YYYY.json.gz`: historical row versions closed during that calendar year

You should not need to run a separate migration command. The main scripts now auto-upgrade legacy `VulnExport_<group>_<date>.json(.gz)` files into the canonical layout when they encounter them.

This temporary upgrade path is scheduled for removal on `2026-07-01` after callers have been updated.

## Generating the report

Place your export files in the `/exports` folder. `Generate-VulnerabilityDashboard.ps1` now prefers the canonical vulnerability store when `VulnExport_current.json.gz` is present. If it only finds legacy `VulnExport_*.json(.gz)` snapshot files, it will temporarily auto-upgrade them into the canonical store before generating the dashboard. That compatibility path is scheduled for removal on `2026-07-01`.

After generating the dashboard, run the generator in validation mode to confirm the embedded payload and all report aggregates still match the source exports:

```powershell
.\Generate-VulnerabilityDashboard.ps1 -ExportMachineData $false -Validate
```

If you only want to validate an existing HTML file without regenerating it, use `-ValidateOnly` or the compatibility wrapper:

```powershell
.\Generate-VulnerabilityDashboard.ps1 -ExportMachineData $false -ValidateOnly
.\Validate-DashboardReports.ps1
```

By default validation prints the audit JSON to stdout and does not leave an audit file behind. If you want to keep a copy locally, pass `-KeepValidationAuditFile` to write the default audit file under `sample-reports`, or pass `-ValidationOutputPath` to choose an explicit path. The compatibility wrapper still accepts the older `-KeepAuditFile` and `-OutputPath` names.

For migration signoff, the validator can compare the current dashboard HTML against an older dashboard HTML without requiring the row counts to match exactly. This check is migration-only and temporary through `2026-07-01`: it is auto-enabled only when legacy `VulnExport_<group>_<date>.json(.gz)` snapshots are still present in `exports/` and a baseline dashboard exists at `sample-reports/migration-baseline-dashboard.html`. Once those legacy snapshot files are cleaned up, future validation runs stop using the migration baseline automatically.

If needed, you can still override the baseline path explicitly. In either mode, the validator confirms whether every vulnerability row from the old dashboard is still present in the new dashboard, while separately reporting any additional newer rows:

```powershell
.\Generate-VulnerabilityDashboard.ps1 -ExportMachineData $false -Validate -BaselineDashboardHtmlPath .\sample-reports\VulnerabilityDashboard.previous.html
```

Use `BaselineDashboardCoverage.ContainsAllBaselineRows` as the cleanup gate before deleting the legacy snapshot exports. The audit also includes `BaselineDashboardCoverage.RemovalDate` so the temporary nature of this check is visible in the output.

This repository also enforces that check in GitHub Actions after regenerating the dashboard, but the workflow no longer persists validation artifacts by default.

## Azure Resource Setup

`Setup-AzureResources.ps1` provisions the full pipeline infrastructure: Resource Group, Automation Account (with managed identity), Storage Account (with `exports`, `templates`, and `dashboards` containers), RBAC, a PowerShell 7.4 runtime environment, runbook, and a daily schedule.

The Azure Automation runbook committed at [azure/Invoke-DashboardPipeline.ps1](azure/Invoke-DashboardPipeline.ps1) is a generated artifact. Edit [shared-helpers.ps1](shared-helpers.ps1) and [azure/runbook-source.ps1](azure/runbook-source.ps1), then regenerate the public runbook with:

```powershell
.\azure\Build-Runbook.ps1
```

This keeps the copy/paste-ready runbook self-contained for Azure Automation users while the source stays split into reusable shared logic plus Azure-specific orchestration.

### Prerequisites

- PowerShell module: `Az.Accounts`
- PowerShell module: `Microsoft.Graph.Authentication` (only needed for MDE permissions)
- Authenticated session: `Connect-AzAccount`
- MDE permission step requires Application Administrator role in Entra ID

### Basic Usage

```powershell
.\Setup-AzureResources.ps1 -ResourceGroupName "rg-defender-reporting" `
    -AutomationAccountName "aa-defender-reporting" `
    -StorageAccountName "stdefenderreporting"
```

### With Container App (Entra ID-protected dashboard)

Adds an Azure Container App with Caddy serving the dashboard HTML, protected by Easy Auth (SSO restricted to members of the specified security group).

```powershell
.\Setup-AzureResources.ps1 -ResourceGroupName "rg-defender-reporting" `
    -AutomationAccountName "aa-defender-reporting" `
    -StorageAccountName "stdefenderreporting" `
    -IncludeContainerApp -SecurityGroup "Dashboard Viewers"
```

`-SecurityGroup` accepts either an Object ID (GUID) or display name.

### Parameters

| Parameter | Required | Description |
|---|---|---|
| `-ResourceGroupName` | Yes | Resource group name |
| `-AutomationAccountName` | Yes | Automation account name |
| `-StorageAccountName` | Yes | Storage account name (lowercase, 3-24 chars) |
| `-Location` | No | Azure region (default: `westus2`) |
| `-IncludeContainerApp` | No | Deploy Container App with Easy Auth |
| `-SecurityGroup` | With `-IncludeContainerApp` | Entra ID group allowed access |
| `-ContainerAppName` | No | Override Container App name (default: derived from RG name) |
| `-SkipMdePermissions` | No | Skip MDE API role assignment |
| `-SkipValidation` | No | Skip end-to-end validation after provisioning |

## GitHub Actions Setup

The included workflow (`.github/workflows/update-vulnerability-dashboard.yml`) runs daily, calls the main export, generate, and validate scripts directly, and commits the result. It authenticates via OIDC federated credentials (no secrets stored).

### Steps

1. **Fork the repository** (can be private)

2. **Create the service principal** — requires Application Administrator role (for `Application.ReadWrite.All` and `AppRoleAssignment.ReadWrite.All` Graph consent):

   ```powershell
   .\Setup-GitHubActionServicePrincipal.ps1 -GitHubRepo "yourorg/defender-reporting"
   ```

   The script creates an app registration, service principal, federated credential for GitHub Actions OIDC, and grants MDE API permissions (`Vulnerability.Read.All`, `Machine.Read.All`) with admin consent — no portal visit required.

3. **Add repository secrets** (Settings → Secrets and variables → Actions):

   | Secret | Value |
   |---|---|
   | `AZURE_CLIENT_ID` | Application (Client) ID from script output |
   | `AZURE_TENANT_ID` | Tenant ID from script output |

4. **Protect the main branch** — add a ruleset (Settings → Rules → Rulesets) to prevent force pushes, since the workflow commits export data directly to main

5. **Run the workflow** — trigger manually via Actions → "Update Vulnerability Dashboard" → Run workflow, or wait for the daily schedule
