[CmdletBinding()]
param()

$__generatedHelperPath = & {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $buildPath = Join-Path $RepoRoot 'build\Build-ValidationHelpers.ps1'
    $sourceRoot = Join-Path $RepoRoot 'build\validation\source'
    $generatedPath = Join-Path $RepoRoot 'build\generated\validation-helpers.ps1'

    if (-not (Test-Path -LiteralPath $buildPath -PathType Leaf)) {
        throw "Validation helper build script not found at '$buildPath'."
    }

    if (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) {
        throw "Validation helper source directory not found at '$sourceRoot'."
    }

    $requiresBuild = -not (Test-Path -LiteralPath $generatedPath -PathType Leaf)
    if (-not $requiresBuild) {
        $generatedWriteTimeUtc = (Get-Item -LiteralPath $generatedPath).LastWriteTimeUtc
        $sourceFiles = @(
            Get-ChildItem -Path $sourceRoot -Filter '*.ps1' -File -ErrorAction Stop |
                Sort-Object Name
        )

        if ((Get-Item -LiteralPath $buildPath).LastWriteTimeUtc -gt $generatedWriteTimeUtc) {
            $requiresBuild = $true
        }
        else {
            foreach ($sourceFile in $sourceFiles) {
                if ($sourceFile.LastWriteTimeUtc -gt $generatedWriteTimeUtc) {
                    $requiresBuild = $true
                    break
                }
            }
        }
    }

    if ($requiresBuild) {
        & $buildPath
    }

    if (-not (Test-Path -LiteralPath $generatedPath -PathType Leaf)) {
        throw "Validation helpers were not generated at '$generatedPath'."
    }

    return $generatedPath
} (Split-Path -Path $PSScriptRoot -Parent)

. $__generatedHelperPath
Remove-Variable -Name __generatedHelperPath -ErrorAction Ignore