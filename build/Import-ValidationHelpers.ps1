[CmdletBinding()]
param()

$__repoRoot = Split-Path -Path $PSScriptRoot -Parent
$__sharedImportPath = Join-Path $__repoRoot 'build\Import-SharedHelpers.ps1'

if (-not (Test-Path -LiteralPath $__sharedImportPath -PathType Leaf)) {
    throw "Shared helper import script not found at '$__sharedImportPath'."
}

. $__sharedImportPath

$__generatedHelperPath = & {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $buildRoot = Join-Path $RepoRoot 'build'
    $buildPath = Join-Path $RepoRoot 'build\Build-ValidationHelpers.ps1'
    $manifestToolsPath = Join-Path $buildRoot 'private\ArtifactManifestTools.ps1'
    $manifestPath = Join-Path $buildRoot 'manifests\validation-helpers.json'

    if (-not (Test-Path -LiteralPath $buildPath -PathType Leaf)) {
        throw "Validation helper build script not found at '$buildPath'."
    }

    if (-not (Test-Path -LiteralPath $manifestToolsPath -PathType Leaf)) {
        throw "Artifact manifest helper script not found at '$manifestToolsPath'."
    }

    . $manifestToolsPath

    $artifactManifest = Read-PowerShellArtifactManifest -ManifestPath $manifestPath -RepoRoot $RepoRoot
    $requiresBuild = Test-PowerShellArtifactRequiresBuild -ManifestPath $manifestPath -RepoRoot $RepoRoot -BuildScriptPath $buildPath

    if ($requiresBuild) {
        & $buildPath
    }

    if (-not (Test-Path -LiteralPath $artifactManifest.OutputPath -PathType Leaf)) {
        throw "Validation helpers were not generated at '$($artifactManifest.OutputPath)'."
    }

    return $artifactManifest.OutputPath
} $__repoRoot

. $__generatedHelperPath
Remove-Variable -Name __repoRoot -ErrorAction Ignore
Remove-Variable -Name __sharedImportPath -ErrorAction Ignore
Remove-Variable -Name __generatedHelperPath -ErrorAction Ignore