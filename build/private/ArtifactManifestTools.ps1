Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-RepoRelativePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    return [System.IO.Path]::GetFullPath((Join-Path -Path $RepoRoot -ChildPath $RelativePath))
}

function Read-PowerShellArtifactManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Artifact manifest not found: '$ManifestPath'."
    }

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -Depth 20
    if ([string]::IsNullOrWhiteSpace([string]$manifest.artifactName)) {
        throw "Artifact manifest '$ManifestPath' is missing artifactName."
    }

    if ([string]::IsNullOrWhiteSpace([string]$manifest.outputPath)) {
        throw "Artifact manifest '$ManifestPath' is missing outputPath."
    }

    $sourceFileEntries = @($manifest.sourceFiles)
    if ($sourceFileEntries.Count -eq 0) {
        throw "Artifact manifest '$ManifestPath' does not list any source files."
    }

    $sourceRoots = @($manifest.sourceRoots | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($sourceRoots.Count -eq 0) {
        throw "Artifact manifest '$ManifestPath' does not list any sourceRoots."
    }

    $resolvedSourceFiles = @(
        foreach ($sourceFile in $sourceFileEntries) {
            $relativePath = [string]$sourceFile
            $resolvedPath = Resolve-RepoRelativePath -RepoRoot $RepoRoot -RelativePath $relativePath
            if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
                throw "Artifact manifest '$ManifestPath' references a missing source file '$relativePath'."
            }

            $resolvedPath
        }
    )

    $resolvedSourceRoots = @(
        foreach ($sourceRoot in $sourceRoots) {
            $relativePath = [string]$sourceRoot
            $resolvedPath = Resolve-RepoRelativePath -RepoRoot $RepoRoot -RelativePath $relativePath
            if (-not (Test-Path -LiteralPath $resolvedPath -PathType Container)) {
                throw "Artifact manifest '$ManifestPath' references a missing source root '$relativePath'."
            }

            $resolvedPath
        }
    )

    return [PSCustomObject]@{
        ManifestPath = [System.IO.Path]::GetFullPath($ManifestPath)
        ArtifactName = [string]$manifest.artifactName
        Description = [string]$manifest.description
        OutputPath = Resolve-RepoRelativePath -RepoRoot $RepoRoot -RelativePath ([string]$manifest.outputPath)
        OutputRelativePath = [string]$manifest.outputPath
        SourceFiles = @($resolvedSourceFiles)
        SourceRelativePaths = @($sourceFileEntries | ForEach-Object { [string]$_ })
        SourceRoots = @($resolvedSourceRoots)
        SourceRootRelativePaths = @($sourceRoots | ForEach-Object { [string]$_ })
    }
}

function Test-PowerShellArtifactRequiresBuild {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$BuildScriptPath
    )

    $manifest = Read-PowerShellArtifactManifest -ManifestPath $ManifestPath -RepoRoot $RepoRoot
    if (-not (Test-Path -LiteralPath $BuildScriptPath -PathType Leaf)) {
        throw "Build script not found: '$BuildScriptPath'."
    }

    if (-not (Test-Path -LiteralPath $manifest.OutputPath -PathType Leaf)) {
        return $true
    }

    $generatedWriteTimeUtc = (Get-Item -LiteralPath $manifest.OutputPath).LastWriteTimeUtc
    if ((Get-Item -LiteralPath $BuildScriptPath).LastWriteTimeUtc -gt $generatedWriteTimeUtc) {
        return $true
    }

    if ((Get-Item -LiteralPath $ManifestPath).LastWriteTimeUtc -gt $generatedWriteTimeUtc) {
        return $true
    }

    foreach ($sourceFile in $manifest.SourceFiles) {
        if ((Get-Item -LiteralPath $sourceFile).LastWriteTimeUtc -gt $generatedWriteTimeUtc) {
            return $true
        }
    }

    return $false
}

function Resolve-PowerShellArtifactOutputPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$BuildScriptPath,

        [Parameter(Mandatory = $false)]
        [string]$BuildScriptNotFoundMessage = "Build script not found at '{0}'.",

        [Parameter(Mandatory = $false)]
        [string]$MissingOutputMessage = "Artifact output was not generated at '{0}'."
    )

    $artifactManifest = Read-PowerShellArtifactManifest -ManifestPath $ManifestPath -RepoRoot $RepoRoot
    if (-not (Test-Path -LiteralPath $BuildScriptPath -PathType Leaf)) {
        throw ($BuildScriptNotFoundMessage -f $BuildScriptPath)
    }

    $requiresBuild = Test-PowerShellArtifactRequiresBuild -ManifestPath $ManifestPath -RepoRoot $RepoRoot -BuildScriptPath $BuildScriptPath
    if ($requiresBuild) {
        & $BuildScriptPath
    }

    if (-not (Test-Path -LiteralPath $artifactManifest.OutputPath -PathType Leaf)) {
        throw ($MissingOutputMessage -f $artifactManifest.OutputPath)
    }

    return $artifactManifest.OutputPath
}

function Build-PowerShellArtifactFromManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $manifest = Read-PowerShellArtifactManifest -ManifestPath $ManifestPath -RepoRoot $RepoRoot
    $outputDirectory = Split-Path -Path $manifest.OutputPath -Parent
    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
    }

    $combined = [System.Text.StringBuilder]::new()
    for ($index = 0; $index -lt $manifest.SourceFiles.Count; $index++) {
        $content = Get-Content -LiteralPath $manifest.SourceFiles[$index] -Raw
        [void]$combined.Append($content.TrimEnd())
        if ($index -lt ($manifest.SourceFiles.Count - 1)) {
            [void]$combined.AppendLine()
            [void]$combined.AppendLine()
        }
        else {
            [void]$combined.AppendLine()
        }
    }

    [System.IO.File]::WriteAllText($manifest.OutputPath, $combined.ToString(), [System.Text.UTF8Encoding]::new($true))
    return $manifest
}

function Test-PowerShellArtifactManifestCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $manifest = Read-PowerShellArtifactManifest -ManifestPath $ManifestPath -RepoRoot $RepoRoot
    $relativePathCounts = @{}
    foreach ($relativePath in $manifest.SourceRelativePaths) {
        if ($relativePathCounts.ContainsKey($relativePath)) {
            $relativePathCounts[$relativePath]++
        }
        else {
            $relativePathCounts[$relativePath] = 1
        }
    }

    $duplicateEntries = @($relativePathCounts.GetEnumerator() | Where-Object { $_.Value -gt 1 } | Sort-Object Name)
    if ($duplicateEntries.Count -gt 0) {
        $duplicateList = @($duplicateEntries | ForEach-Object { $_.Name }) -join ', '
        throw "Artifact manifest '$ManifestPath' contains duplicate source entries: $duplicateList"
    }

    $manifestSourceSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($sourceFile in $manifest.SourceFiles) {
        [void]$manifestSourceSet.Add([System.IO.Path]::GetFullPath($sourceFile))
    }

    $discoveredSourceFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($sourceRoot in $manifest.SourceRoots) {
        foreach ($sourceFile in Get-ChildItem -LiteralPath $sourceRoot -Recurse -Filter '*.ps1' -File -ErrorAction Stop | Sort-Object FullName) {
            $discoveredSourceFiles.Add([System.IO.Path]::GetFullPath($sourceFile.FullName))
        }
    }

    $orphanedFiles = @($discoveredSourceFiles | Where-Object { -not $manifestSourceSet.Contains($_) })
    if ($orphanedFiles.Count -gt 0) {
        $orphanedList = @($orphanedFiles | ForEach-Object { $_.Substring($RepoRoot.Length + 1).Replace('\\', '/') }) -join ', '
        throw "Artifact manifest '$ManifestPath' does not include all source files under its sourceRoots. Missing entries: $orphanedList"
    }

    return $true
}
