#Requires -Version 7.0

<#
.SYNOPSIS
    Compatibility wrapper for uploading dashboard templates to Azure Blob Storage.

.DESCRIPTION
    Delegates to the supported build-layer publish contract at
    build/Publish-DashboardTemplates.ps1 so existing callers can keep using the
    historical azure/Upload-Templates.ps1 path while wrappers and CI migrate to
    the documented build entrypoint.

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
    Prefer build/Publish-DashboardTemplates.ps1 for new automation and wrapper integrations.
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
$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$publishScriptPath = Join-Path -Path $repoRoot -ChildPath 'build\Publish-DashboardTemplates.ps1'

if (-not (Test-Path -LiteralPath $publishScriptPath -PathType Leaf)) {
    throw "Supported dashboard template publish script not found: $publishScriptPath"
}

& $publishScriptPath @PSBoundParameters
