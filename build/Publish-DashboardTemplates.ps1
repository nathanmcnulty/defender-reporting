#Requires -Version 7.0

<#
.SYNOPSIS
    Publishes dashboard templates to Azure Blob Storage.

.DESCRIPTION
    Supported repository contract for publishing the canonical templates tree.
    Build-TemplatePublisher.ps1 combines this script with its focused helper to
    produce the self-contained azure/Upload-Templates.ps1 release artifact.

.PARAMETER StorageAccountName
    Name of the Azure Storage account.

.PARAMETER ContainerName
    Name of the blob container for templates. Default: templates

.PARAMETER TemplatesPath
    Path to the local templates directory. Default: ../templates

.PARAMETER MetadataPath
    Optional path for a JSON manifest describing the published template tree.

.EXAMPLE
    .\build\Publish-DashboardTemplates.ps1 -StorageAccountName "stdefenderreporting"
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

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# DASHBOARD_TEMPLATE_PUBLISH_TOOLS_IMPORT_START
$publishToolsPath = Join-Path -Path $PSScriptRoot -ChildPath 'private' | Join-Path -ChildPath 'DashboardTemplatePublishTools.ps1'
if (-not (Test-Path -LiteralPath $publishToolsPath -PathType Leaf)) {
    throw "Required dashboard template publish helper not found: $publishToolsPath"
}
. $publishToolsPath
# DASHBOARD_TEMPLATE_PUBLISH_TOOLS_IMPORT_END

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$resolvedTemplatesPath = Resolve-DashboardTemplatesPath -RepoRoot $repoRoot -TemplatesPath $TemplatesPath
$publishState = Get-DashboardTemplatePublishState -TemplatesPath $resolvedTemplatesPath -RepoRoot $repoRoot
$publishScriptDisplayPath = 'build/Publish-DashboardTemplates.ps1'

Write-Output ("Preparing dashboard template publish contract from: {0}" -f $publishState.TemplatesDisplayPath)
Write-Output ("Template file count: {0}" -f $publishState.FileCount)
Write-Output ("Template fingerprint: {0}" -f $publishState.Fingerprint)

if ($PSBoundParameters.ContainsKey('MetadataPath')) {
    $publishManifest = [PSCustomObject]@{
        generatedOnUtc = [datetime]::UtcNow.ToString('o')
        publishScript = $publishScriptDisplayPath
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
