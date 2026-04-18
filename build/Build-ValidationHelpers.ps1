#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$buildRoot = $PSScriptRoot
$repoRoot = Split-Path -Path $buildRoot -Parent
$manifestToolsPath = Join-Path -Path $buildRoot -ChildPath 'private\ArtifactManifestTools.ps1'
$manifestPath = Join-Path -Path $buildRoot -ChildPath 'manifests\validation-helpers.json'

if (-not (Test-Path -LiteralPath $manifestToolsPath -PathType Leaf)) {
    throw "Artifact manifest helper script not found: $manifestToolsPath"
}

. $manifestToolsPath

$artifactManifest = Build-PowerShellArtifactFromManifest -ManifestPath $manifestPath -RepoRoot $repoRoot
Write-Host "Generated validation helpers: $($artifactManifest.OutputPath)" -ForegroundColor Green