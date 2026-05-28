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

$artifactManifest = Build-PowerShellArtifactFromManifest -ManifestPath $manifestPath -RepoRoot $repoRoot -BuildScriptPath $PSCommandPath
if (-not (Test-Path -LiteralPath $artifactManifest.OutputPath -PathType Leaf)) {
    throw "Expected generated validation helpers at '$($artifactManifest.OutputPath)'."
}

$generatedArtifact = Get-Item -LiteralPath $artifactManifest.OutputPath
if ($generatedArtifact.Length -le 0) {
    throw "Generated validation helpers artifact is empty: '$($artifactManifest.OutputPath)'."
}

Write-Host "Generated validation helpers: $($artifactManifest.OutputPath)" -ForegroundColor Green
