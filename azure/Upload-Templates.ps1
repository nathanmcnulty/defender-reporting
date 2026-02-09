<#
.SYNOPSIS
    Uploads dashboard template files to Azure Blob Storage.

.DESCRIPTION
    One-time helper script to upload the HTML, CSS, and JavaScript template files
    from the local templates/ directory to the 'templates' blob container in Azure
    Blob Storage. Re-run this script after making changes to any template file.
    
    Uses Entra ID authentication (bearer token) since the storage account has
    shared key access disabled.

.PARAMETER StorageAccountName
    Name of the Azure Storage account.

.PARAMETER ContainerName
    Name of the blob container for templates. Default: templates

.PARAMETER TemplatesPath
    Path to the local templates directory. Default: ../templates (relative to this script)

.EXAMPLE
    .\Upload-Templates.ps1 -StorageAccountName "stdefenderreporting"

.EXAMPLE
    .\Upload-Templates.ps1 -StorageAccountName "stdefenderreporting" -TemplatesPath "C:\repo\templates"

.NOTES
    Author: Nathan McNulty
    
    Prerequisites:
    - Az.Accounts module
    - Authenticated Azure session (Connect-AzAccount)
    - Storage Blob Data Contributor role on the storage account
#>

#Requires -Modules Az.Accounts

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Azure Storage account name")]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false)]
    [string]$ContainerName = 'templates',

    [Parameter(Mandatory = $false)]
    [string]$TemplatesPath
)

$ErrorActionPreference = 'Stop'

# Resolve templates path
if (-not $TemplatesPath) {
    $TemplatesPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "templates"
}

if (-not (Test-Path -Path $TemplatesPath -PathType Container)) {
    throw "Templates directory not found: $TemplatesPath"
}

# Template files to upload with their content types
$templateFiles = @(
    @{ Name = "dashboard.html"; ContentType = "text/html" }
    @{ Name = "dashboard.css";  ContentType = "text/css" }
    @{ Name = "dashboard.js";   ContentType = "application/javascript" }
)

# Get bearer token for blob storage
Write-Host "Authenticating to Azure Storage..." -ForegroundColor Cyan
$tokenResponse = Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/' -AsSecureString
$ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResponse.Token)
try { $storageToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr) }
finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr) }

$baseUrl = "https://$StorageAccountName.blob.core.windows.net"
$blobApiVersion = '2021-12-02'

Write-Host "`nUploading templates to '$ContainerName' container..." -ForegroundColor Cyan

foreach ($file in $templateFiles) {
    $localPath = Join-Path -Path $TemplatesPath -ChildPath $file.Name

    if (-not (Test-Path -Path $localPath)) {
        Write-Warning "File not found, skipping: $localPath"
        continue
    }

    $blobUri = "$baseUrl/$ContainerName/$($file.Name)"
    $fileSize = [math]::Round((Get-Item $localPath).Length / 1KB, 1)

    Write-Host "  Uploading $($file.Name) (${fileSize}KB)..." -ForegroundColor Gray

    $headers = @{
        'Authorization'    = "Bearer $storageToken"
        'x-ms-version'     = $blobApiVersion
        'x-ms-blob-type'   = 'BlockBlob'
        'x-ms-access-tier' = 'Cool'
    }

    Invoke-RestMethod -Uri $blobUri -Method Put -Headers $headers -InFile $localPath -ContentType $file.ContentType

    Write-Host "    Uploaded" -ForegroundColor Green
}

Write-Host "`nAll templates uploaded to: $baseUrl/$ContainerName/" -ForegroundColor Green
Write-Host "The dashboard pipeline runbook will download these at generation time.`n" -ForegroundColor Gray
