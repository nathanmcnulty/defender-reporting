[CmdletBinding()]
param()

$__validationRepoRoot = Split-Path -Path $PSScriptRoot -Parent
$__validationBuildRoot = Join-Path $__validationRepoRoot 'build'
$__validationSharedImportPath = Join-Path $__validationRepoRoot 'build\Import-SharedHelpers.ps1'
$__validationManifestToolsPath = Join-Path $__validationBuildRoot 'private\ArtifactManifestTools.ps1'

if (-not (Test-Path -LiteralPath $__validationSharedImportPath -PathType Leaf)) {
    throw "Shared helper import script not found at '$__validationSharedImportPath'."
}

if (-not (Test-Path -LiteralPath $__validationManifestToolsPath -PathType Leaf)) {
    throw "Artifact manifest helper script not found at '$__validationManifestToolsPath'."
}

. $__validationSharedImportPath
. $__validationManifestToolsPath

$__validationGeneratedHelperPath = Resolve-PowerShellArtifactOutputPath -ManifestPath (Join-Path $__validationBuildRoot 'manifests\validation-helpers.json') -RepoRoot $__validationRepoRoot -BuildScriptPath (Join-Path $__validationBuildRoot 'Build-ValidationHelpers.ps1') -BuildScriptNotFoundMessage "Validation helper build script not found at '{0}'." -MissingOutputMessage "Validation helpers were not generated at '{0}'."

. $__validationGeneratedHelperPath
Remove-Variable -Name __validationRepoRoot -ErrorAction Ignore
Remove-Variable -Name __validationBuildRoot -ErrorAction Ignore
Remove-Variable -Name __validationSharedImportPath -ErrorAction Ignore
Remove-Variable -Name __validationManifestToolsPath -ErrorAction Ignore
Remove-Variable -Name __validationGeneratedHelperPath -ErrorAction Ignore