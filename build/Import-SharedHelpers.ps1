[CmdletBinding()]
param()

$__repoRoot = Split-Path -Path $PSScriptRoot -Parent
$__buildRoot = Join-Path $__repoRoot 'build'
$__manifestToolsPath = Join-Path $__buildRoot 'private\ArtifactManifestTools.ps1'

if (-not (Test-Path -LiteralPath $__manifestToolsPath -PathType Leaf)) {
    throw "Artifact manifest helper script not found at '$__manifestToolsPath'."
}

. $__manifestToolsPath

$__generatedHelperPath = Resolve-PowerShellArtifactOutputPath -ManifestPath (Join-Path $__buildRoot 'manifests\shared-helpers.json') -RepoRoot $__repoRoot -BuildScriptPath (Join-Path $__buildRoot 'Build-SharedHelpers.ps1') -BuildScriptNotFoundMessage "Shared helper build script not found at '{0}'." -MissingOutputMessage "Shared helpers were not generated at '{0}'."

. $__generatedHelperPath
Remove-Variable -Name __repoRoot -ErrorAction Ignore
Remove-Variable -Name __buildRoot -ErrorAction Ignore
Remove-Variable -Name __manifestToolsPath -ErrorAction Ignore
Remove-Variable -Name __generatedHelperPath -ErrorAction Ignore