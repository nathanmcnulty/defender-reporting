#Requires -Version 7.0

<#
.SYNOPSIS
    Uploads dashboard templates to Azure Blob Storage.

.DESCRIPTION
    Azure-side template publisher used by Setup-AzureResources.ps1 and release
    packages. This script is self-contained under the azure/ tree so extracted
    deployment packages do not depend on build/ artifacts being present.

.PARAMETER StorageAccountName
    Name of the Azure Storage account.

.PARAMETER ContainerName
    Name of the blob container for templates. Default: templates

.PARAMETER TemplatesPath
    Path to the local templates directory. Default: ../templates (relative to the repo root)

.PARAMETER MetadataPath
    Optional path for a JSON manifest describing the published template tree.

.EXAMPLE
    .\Upload-Templates.ps1 -StorageAccountName "stdefenderreporting"

.EXAMPLE
    .\Upload-Templates.ps1 -StorageAccountName "stdefenderreporting" -TemplatesPath "C:\repo\templates"

.NOTES
    Repo-owned wrappers can call build/Publish-DashboardTemplates.ps1, which now
    delegates to this Azure-shipped implementation.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, HelpMessage = 'Azure Storage account name')]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false)]
    [string]$ContainerName = 'templates',

    [Parameter(Mandatory = $false)]
    [string]$TemplatesPath,

    [Parameter(Mandatory = $false)]
    [string]$MetadataPath
)

$ErrorActionPreference = 'Stop'
$publishToolsPath = Join-Path -Path $PSScriptRoot -ChildPath 'private\DashboardTemplatePublishTools.ps1'
if (-not (Test-Path -LiteralPath $publishToolsPath -PathType Leaf)) {
    throw "Required dashboard template publish helper not found: $publishToolsPath"
}

. $publishToolsPath

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$resolvedTemplatesPath = Resolve-DashboardTemplatesPath -RepoRoot $repoRoot -TemplatesPath $TemplatesPath
$publishState = Get-DashboardTemplatePublishState -TemplatesPath $resolvedTemplatesPath -RepoRoot $repoRoot

Write-Output ("Preparing dashboard template publish contract from: {0}" -f $publishState.TemplatesDisplayPath)
Write-Output ("Template file count: {0}" -f $publishState.FileCount)
Write-Output ("Template fingerprint: {0}" -f $publishState.Fingerprint)

if ($PSBoundParameters.ContainsKey('MetadataPath')) {
    $publishManifest = [PSCustomObject]@{
        generatedOnUtc = [datetime]::UtcNow.ToString('o')
        publishScript = 'azure/Upload-Templates.ps1'
        storageAccountName = $StorageAccountName
        containerName = $ContainerName
        templatesPath = $publishState.TemplatesDisplayPath
        templateFingerprint = $publishState.Fingerprint
        templateFileCount = $publishState.FileCount
        totalSizeBytes = $publishState.TotalSizeBytes
        files = @(
            $publishState.Files |
                ForEach-Object {
                    [PSCustomObject]@{
                        path = $_.Path
                        sourcePath = $_.SourcePath
                        sha256 = $_.Sha256
                        contentType = $_.ContentType
                        sizeBytes = $_.SizeBytes
                    }
                }
        )
    }

    if ($PSCmdlet.ShouldProcess($MetadataPath, 'Write dashboard template publish manifest')) {
        Write-DashboardTemplatePublishUtf8BomFile -Path $MetadataPath -Content (($publishManifest | ConvertTo-Json -Depth 10) + [Environment]::NewLine)
        Write-Output ("Dashboard template publish manifest: {0}" -f $MetadataPath)
    }
}

if (-not $PSCmdlet.ShouldProcess(("$StorageAccountName/$ContainerName"), ("Upload {0} dashboard template file(s)" -f $publishState.FileCount))) {
    return
}

Write-Output 'Authenticating to Azure Storage...'
$storageToken = Get-DashboardTemplatePublishStorageAccessToken

Write-Output ("Uploading dashboard templates to '{0}' container..." -f $ContainerName)
foreach ($templateFile in $publishState.Files) {
    $fileSizeKb = [math]::Round($templateFile.SizeBytes / 1KB, 1)
    Write-Output ("  Uploading {0} ({1} KB)..." -f $templateFile.Path, $fileSizeKb)
    Publish-DashboardTemplateBlobFileWithRetry `
        -StorageAccountName $StorageAccountName `
        -ContainerName $ContainerName `
        -BlobName $templateFile.Path `
        -FilePath $templateFile.FullPath `
        -ContentType $templateFile.ContentType `
        -StorageToken $storageToken
    Write-Output '    Uploaded'
}

Write-Output ("Published dashboard templates to: https://{0}.blob.core.windows.net/{1}/" -f $StorageAccountName, $ContainerName)
Write-Output 'The dashboard pipeline runbook and Function App will download these templates at generation time.'
