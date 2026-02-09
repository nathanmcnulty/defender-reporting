# Defender Vulnerability Reporting Dashboard

<img width="3246" height="1953" alt="image" src="https://github.com/user-attachments/assets/9ef016fb-262f-476b-9d68-1fd81d21a9aa" />
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
"Vulnerability.Read.All","Machine.Read.All" | ForEach-Object {
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

## Obtaining Machine Data

The dashboard uses machine data to show tags as a filter option and likely more data in the future. This data comes from the `/api/machines` endpoint and is saved separately from vulnerability exports.

After authenticating (using either method above), add this to download the machine data:

```powershell
# Download machine data
$uri = "https://api.securitycenter.microsoft.com/api/machines?`$filter=onboardingStatus eq 'Onboarded'"
$allMachines = @()

do {
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    if ($response.value) { $allMachines += $response.value }
    $uri = if ($response.PSObject.Properties['@odata.nextLink']) { $response.'@odata.nextLink' } else { $null }
} while ($uri)

$timestamp = Get-Date -Format "yyyy-MM-dd"
$allMachines | ConvertTo-Json -Depth 10 | Out-File -FilePath "./exports/Machines_$timestamp.json" -Encoding UTF8
```

The dashboard script will automatically read any `Machines_*.json` files in the exports folder.

## Generating the report

You will need to extract the JSON files from the gzip files, and how you do this will likely depend on your environment (I'm open to clean, simple PowerShell methods that are cross-platform too!).

I recommend placing these in the /exports folder as this is the default path the Generate-VulnerabilityDashboard.ps1 uses. Running that script should output an updated VulnerabilityDashboard.html file.

## Azure Resource Setup

`Setup-AzureResources.ps1` provisions the full pipeline infrastructure: Resource Group, Automation Account (with managed identity), Storage Account (with `exports`, `templates`, and `dashboards` containers), RBAC, a PowerShell 7.4 runtime environment, runbook, and a weekly schedule.

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

The included workflow (`.github/workflows/update-vulnerability-dashboard.yml`) runs on a schedule (daily cron, but self-gates to every 7 days), exports vulnerability and machine data from MDE, generates the dashboard, and commits the result. It authenticates via OIDC federated credentials (no secrets stored).

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
