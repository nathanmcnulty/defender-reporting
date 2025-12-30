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

The script below is used to get the data from the API. You will need to create an app registration in Entra, then grant it Vulnerability.Read.All on the WindowsDefenderATP API. For more details, see the docs: https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp?tabs=PowerShell

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
$token = (Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop).access_token

$headers = @{
    'Content-Type' = 'application/json'
    Accept         = 'application/json'
    Authorization  = "Bearer $token"
}

$files = (Invoke-RestMethod -Uri "https://api-us.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesExport" -Headers $headers).exportFiles
$files | ForEach-Object {
    $date = $_.split('/')[6]
    $groupId = $_.Split('/')[9].Split('%3D')[-1]
    Invoke-WebRequest -Uri $_ -OutFile "./VulnExport_$groupId`_$date.json.gz"
}
```

For more details on this API, see the docs: https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities
