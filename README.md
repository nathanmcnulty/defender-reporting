# Defender Vulnerability Reporting Dashboard

<img width="3246" height="1953" alt="image" src="https://github.com/user-attachments/assets/9ef016fb-262f-476b-9d68-1fd81d21a9aa" />


I wanted to practice a bit of AI coding to build a dashboard that did not have a dependency on Power BI or other tools. The concept was simple - export vulnerability data from the Defender for Endpoint APIs, then use PowerShell to create an HTML report from the data.

In this repo, I have provided the script, sample data, sample HTML page, sample PDF outputs, and the AI chat history in case you'd like to attempt your own dashboards with other data :)

The script below is used to get the data from the API, and I will provide more detailed instructions later.

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
