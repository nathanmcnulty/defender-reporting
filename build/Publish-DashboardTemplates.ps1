#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false)]
    [string]$ContainerName = 'templates',

    [Parameter(Mandatory = $false)]
    [string]$TemplatesPath,

    [Parameter(Mandatory = $false)]
    [string]$MetadataPath
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'private\AzureArtifactBuildTools.ps1')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$resolvedTemplatesPath = Resolve-DashboardTemplatesPath -RepoRoot $repoRoot -TemplatesPath $TemplatesPath
$publishState = Get-DashboardTemplatePublishState -TemplatesPath $resolvedTemplatesPath -RepoRoot $repoRoot

Write-Output ("Preparing dashboard template publish contract from: {0}" -f $publishState.TemplatesDisplayPath)
Write-Output ("Template file count: {0}" -f $publishState.FileCount)
Write-Output ("Template fingerprint: {0}" -f $publishState.Fingerprint)

if ($PSBoundParameters.ContainsKey('MetadataPath')) {
    $publishManifest = [PSCustomObject]@{
        generatedOnUtc = [datetime]::UtcNow.ToString('o')
        publishScript = 'build/Publish-DashboardTemplates.ps1'
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
        Write-Utf8BomFile -Path $MetadataPath -Content (($publishManifest | ConvertTo-Json -Depth 10) + [Environment]::NewLine)
        Write-Output ("Dashboard template publish manifest: {0}" -f $MetadataPath)
    }
}

if (-not $PSCmdlet.ShouldProcess(("$StorageAccountName/$ContainerName"), ("Upload {0} dashboard template file(s)" -f $publishState.FileCount))) {
    return
}

Write-Output 'Authenticating to Azure Storage...'
$storageToken = Get-StorageAccessToken

Write-Output ("Uploading dashboard templates to '{0}' container..." -f $ContainerName)
foreach ($templateFile in $publishState.Files) {
    $fileSizeKb = [math]::Round($templateFile.SizeBytes / 1KB, 1)
    Write-Output ("  Uploading {0} ({1} KB)..." -f $templateFile.Path, $fileSizeKb)
    Publish-BlobFileWithRetry `
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
