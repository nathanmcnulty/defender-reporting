<#
.SYNOPSIS
    Uploads dashboard template files to Azure Blob Storage.

.DESCRIPTION
    One-time helper script to upload the dashboard template tree from the local
    templates/ directory to the 'templates' blob container in Azure Blob Storage.
    Re-run this script after making changes to any template file or JavaScript module.
    
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
    - Authenticated Azure session via Connect-AzAccount or az login
    - Storage Blob Data Contributor role on the storage account
#>

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

function ConvertTo-PlainTextToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Token
    )

    $tokenPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer)
    }
}

function Get-StorageAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $getAzAccessTokenCommand = Get-Command -Name 'Get-AzAccessToken' -ErrorAction SilentlyContinue
    if ($null -ne $getAzAccessTokenCommand) {
        $hasAzContext = $true
        $getAzContextCommand = Get-Command -Name 'Get-AzContext' -ErrorAction SilentlyContinue
        if ($null -ne $getAzContextCommand) {
            try {
                $azContext = Get-AzContext -ErrorAction Stop
                $hasAzContext = ($null -ne $azContext -and $null -ne $azContext.Account)
            }
            catch {
                $hasAzContext = $false
            }
        }

        if ($hasAzContext) {
            try {
                $tokenResponse = Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/' -AsSecureString -ErrorAction Stop
                return ConvertTo-PlainTextToken -Token $tokenResponse.Token
            }
            catch {
                Write-Verbose "Az PowerShell token acquisition failed: $_"
            }
        }
    }

    if ($null -ne (Get-Command -Name 'az' -CommandType Application -ErrorAction SilentlyContinue)) {
        try {
            $azAccessToken = (& az 'account' 'get-access-token' '--resource' 'https://storage.azure.com/' '--query' 'accessToken' '-o' 'tsv' 2>&1 | Out-String)
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($azAccessToken)) {
                return $azAccessToken.Trim()
            }

            if ($LASTEXITCODE -ne 0 -and -not [string]::IsNullOrWhiteSpace($azAccessToken)) {
                Write-Verbose ("Azure CLI token acquisition failed: {0}" -f $azAccessToken.Trim())
            }
        }
        catch {
            Write-Verbose "Azure CLI token acquisition failed: $_"
        }
    }

    throw "No Azure Storage token source available. Run Connect-AzAccount or az login, then retry."
}

# Resolve templates path
if (-not $TemplatesPath) {
    $TemplatesPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "templates"
}

if (-not (Test-Path -Path $TemplatesPath -PathType Container)) {
    throw "Templates directory not found: $TemplatesPath"
}

function Get-TemplateContentType {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$File
    )

    switch ($File.Extension.ToLowerInvariant()) {
        '.html' { return 'text/html' }
        '.css' { return 'text/css' }
        '.js' { return 'application/javascript' }
        '.json' { return 'application/json' }
        default { return 'application/octet-stream' }
    }
}

$templateFiles = Get-ChildItem -Path $TemplatesPath -File -Recurse | Sort-Object FullName
if ($templateFiles.Count -eq 0) {
    throw "No template files found under: $TemplatesPath"
}

# Get bearer token for blob storage
Write-Host "Authenticating to Azure Storage..." -ForegroundColor Cyan
$storageToken = Get-StorageAccessToken

$baseUrl = "https://$StorageAccountName.blob.core.windows.net"
$blobApiVersion = '2021-12-02'

Write-Host "`nUploading templates to '$ContainerName' container..." -ForegroundColor Cyan

foreach ($file in $templateFiles) {
    $relativePath = [System.IO.Path]::GetRelativePath($TemplatesPath, $file.FullName).Replace('\', '/')
    $blobUri = "$baseUrl/$ContainerName/$relativePath"
    $fileSize = [math]::Round($file.Length / 1KB, 1)
    $contentType = Get-TemplateContentType -File $file

    Write-Host "  Uploading $relativePath (${fileSize}KB)..." -ForegroundColor Gray

    $headers = @{
        'Authorization'    = "Bearer $storageToken"
        'x-ms-version'     = $blobApiVersion
        'x-ms-blob-type'   = 'BlockBlob'
        'x-ms-access-tier' = 'Cool'
    }

    $maxRetries = 3
    $retryDelay = 2
    for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
        try {
            Invoke-RestMethod -Uri $blobUri -Method Put -Headers $headers -InFile $file.FullName -ContentType $contentType
            Write-Host "    Uploaded" -ForegroundColor Green
            break
        }
        catch {
            if ($attempt -eq $maxRetries) {
                Write-Error "    Failed to upload $relativePath after $maxRetries attempts: $_"
                throw
            }
            Write-Host "    Attempt $attempt failed, retrying in ${retryDelay}s..." -ForegroundColor Yellow
            Start-Sleep -Seconds $retryDelay
            $retryDelay *= 2
        }
    }
}

Write-Host "`nAll templates uploaded to: $baseUrl/$ContainerName/" -ForegroundColor Green
Write-Host "The dashboard pipeline runbook will download these at generation time.`n" -ForegroundColor Gray
