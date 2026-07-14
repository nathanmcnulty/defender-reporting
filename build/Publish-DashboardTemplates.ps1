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

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$azurePublishScriptPath = Join-Path -Path $repoRoot -ChildPath 'azure\Upload-Templates.ps1'
if (-not (Test-Path -LiteralPath $azurePublishScriptPath -PathType Leaf)) {
    throw "Azure dashboard template publish script not found: $azurePublishScriptPath"
}

& $azurePublishScriptPath @PSBoundParameters
