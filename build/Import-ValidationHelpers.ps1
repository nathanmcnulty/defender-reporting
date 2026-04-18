[CmdletBinding()]
param()

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
} (Split-Path -Path $PSScriptRoot -Parent)

. $__generatedHelperPath
Remove-Variable -Name __generatedHelperPath -ErrorAction Ignore