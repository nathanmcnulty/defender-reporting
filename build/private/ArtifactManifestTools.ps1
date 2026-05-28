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

function Test-ArtifactPathWithinRoot {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $resolvedRoot = [System.IO.Path]::GetFullPath($Root)
    $comparison = [System.StringComparison]::OrdinalIgnoreCase

    if ($resolvedPath.Equals($resolvedRoot, $comparison)) {
        return $true
    }

    $rootWithSeparator = $resolvedRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    return $resolvedPath.StartsWith($rootWithSeparator, $comparison)
}

$script:PowerShellArtifactFingerprintPrefix = '# ArtifactFingerprint: '

function Get-TextSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    $hashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Text))
    return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
}

function Get-FileContentSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Fingerprint input file not found: '$Path'."
    }

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-RepoRelativeDisplayPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $resolvedRoot = [System.IO.Path]::GetFullPath($RepoRoot)
    if ($resolvedPath.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $resolvedPath.Substring($resolvedRoot.Length + 1).Replace('\', '/')
    }

    return $resolvedPath.Replace('\', '/')
}

function Read-PowerShellArtifactEmbeddedFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $tail = @(Get-Content -LiteralPath $Path -Tail 5 -ErrorAction Stop)
    for ($index = $tail.Count - 1; $index -ge 0; $index--) {
        $line = [string]$tail[$index]
        if (-not $line.StartsWith($script:PowerShellArtifactFingerprintPrefix, [System.StringComparison]::Ordinal)) {
            continue
        }

        $fingerprint = $line.Substring($script:PowerShellArtifactFingerprintPrefix.Length).Trim()
        if ($fingerprint -match '^[0-9a-f]{64}$') {
            return $fingerprint.ToLowerInvariant()
        }

        return $null
    }

    return $null
}

function Get-PowerShellArtifactFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
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

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.AppendLine("artifact:$($manifest.ArtifactName)")
    [void]$builder.AppendLine("output:$($manifest.OutputRelativePath)")
    [void]$builder.AppendLine("build:$((Get-RepoRelativeDisplayPath -Path $BuildScriptPath -RepoRoot $RepoRoot))")
    [void]$builder.AppendLine("build-hash:$(Get-FileContentSha256Hex -Path $BuildScriptPath)")
    [void]$builder.AppendLine("manifest-hash:$(Get-FileContentSha256Hex -Path $manifest.ManifestPath)")

    for ($index = 0; $index -lt $manifest.SourceFiles.Count; $index++) {
        $sourcePath = $manifest.SourceFiles[$index]
        $relativePath = $manifest.SourceRelativePaths[$index]
        [void]$builder.AppendLine("source:$relativePath")
        [void]$builder.AppendLine("source-hash:$(Get-FileContentSha256Hex -Path $sourcePath)")
    }

    return Get-TextSha256Hex -Text $builder.ToString()
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

    $relativeSourceRootCounts = @{}
    foreach ($relativePath in @($sourceRoots | ForEach-Object { [string]$_ })) {
        if ($relativeSourceRootCounts.ContainsKey($relativePath)) {
            $relativeSourceRootCounts[$relativePath]++
        }
        else {
            $relativeSourceRootCounts[$relativePath] = 1
        }
    }

    $duplicateSourceRoots = @($relativeSourceRootCounts.GetEnumerator() | Where-Object { $_.Value -gt 1 } | Sort-Object Name)
    if ($duplicateSourceRoots.Count -gt 0) {
        $duplicateList = @($duplicateSourceRoots | ForEach-Object { $_.Name }) -join ', '
        throw "Artifact manifest '$ManifestPath' contains duplicate sourceRoots: $duplicateList"
    }

    for ($leftIndex = 0; $leftIndex -lt $resolvedSourceRoots.Count; $leftIndex++) {
        for ($rightIndex = $leftIndex + 1; $rightIndex -lt $resolvedSourceRoots.Count; $rightIndex++) {
            $leftRoot = $resolvedSourceRoots[$leftIndex]
            $rightRoot = $resolvedSourceRoots[$rightIndex]
            if ((Test-ArtifactPathWithinRoot -Path $leftRoot -Root $rightRoot) -or (Test-ArtifactPathWithinRoot -Path $rightRoot -Root $leftRoot)) {
                $leftRelativeRoot = [string]$sourceRoots[$leftIndex]
                $rightRelativeRoot = [string]$sourceRoots[$rightIndex]
                throw "Artifact manifest '$ManifestPath' contains overlapping sourceRoots '$leftRelativeRoot' and '$rightRelativeRoot'."
            }
        }
    }

    foreach ($sourceFile in $resolvedSourceFiles) {
        $matchingRoots = @($resolvedSourceRoots | Where-Object { Test-ArtifactPathWithinRoot -Path $sourceFile -Root $_ })
        if ($matchingRoots.Count -eq 0) {
            $relativeFilePath = $sourceFile.Substring([System.IO.Path]::GetFullPath($RepoRoot).Length + 1).Replace('\', '/')
            throw "Artifact manifest '$ManifestPath' references source file '$relativeFilePath' outside the declared sourceRoots."
        }
    }

    $resolvedOutputPath = Resolve-RepoRelativePath -RepoRoot $RepoRoot -RelativePath ([string]$manifest.outputPath)
    foreach ($sourceRootPath in $resolvedSourceRoots) {
        if (Test-ArtifactPathWithinRoot -Path $resolvedOutputPath -Root $sourceRootPath) {
            $relativeRootPath = $sourceRoots[[array]::IndexOf($resolvedSourceRoots, $sourceRootPath)]
            throw "Artifact manifest '$ManifestPath' writes output '$($manifest.outputPath)' inside sourceRoot '$relativeRootPath'. Generated outputs must stay outside tracked source roots."
        }
    }

    if ($resolvedSourceFiles -contains $resolvedOutputPath) {
        throw "Artifact manifest '$ManifestPath' outputPath '$($manifest.outputPath)' conflicts with a source file entry."
    }

    return [PSCustomObject]@{
        ManifestPath = [System.IO.Path]::GetFullPath($ManifestPath)
        ArtifactName = [string]$manifest.artifactName
        Description = [string]$manifest.description
        OutputPath = $resolvedOutputPath
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
    $expectedFingerprint = Get-PowerShellArtifactFingerprint -ManifestPath $ManifestPath -RepoRoot $RepoRoot -BuildScriptPath $BuildScriptPath
    if (-not (Test-Path -LiteralPath $manifest.OutputPath -PathType Leaf)) {
        return $true
    }

    $embeddedFingerprint = Read-PowerShellArtifactEmbeddedFingerprint -Path $manifest.OutputPath
    return ($embeddedFingerprint -ne $expectedFingerprint)
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

    $generatedArtifact = Get-Item -LiteralPath $artifactManifest.OutputPath
    if ($generatedArtifact.Length -le 0) {
        throw "Artifact output is empty: '$($artifactManifest.OutputPath)'. Re-run '$((Get-RepoRelativeDisplayPath -Path $BuildScriptPath -RepoRoot $RepoRoot))'."
    }

    $expectedFingerprint = Get-PowerShellArtifactFingerprint -ManifestPath $ManifestPath -RepoRoot $RepoRoot -BuildScriptPath $BuildScriptPath
    $embeddedFingerprint = Read-PowerShellArtifactEmbeddedFingerprint -Path $artifactManifest.OutputPath
    $buildScriptDisplayPath = Get-RepoRelativeDisplayPath -Path $BuildScriptPath -RepoRoot $RepoRoot
    if ([string]::IsNullOrWhiteSpace($embeddedFingerprint)) {
        throw "Artifact output '$($artifactManifest.OutputPath)' is missing fingerprint metadata. Re-run '$buildScriptDisplayPath'."
    }

    if ($embeddedFingerprint -ne $expectedFingerprint) {
        throw "Artifact output '$($artifactManifest.OutputPath)' does not match the current manifest/source fingerprint. Re-run '$buildScriptDisplayPath'."
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
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$BuildScriptPath
    )

    $manifest = Read-PowerShellArtifactManifest -ManifestPath $ManifestPath -RepoRoot $RepoRoot
    $fingerprint = Get-PowerShellArtifactFingerprint -ManifestPath $ManifestPath -RepoRoot $RepoRoot -BuildScriptPath $BuildScriptPath
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

    [void]$combined.AppendLine("$($script:PowerShellArtifactFingerprintPrefix)$fingerprint")
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

function Test-PowerShellArtifactManifestConflict {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ManifestPaths,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $sourceFileOwners = @{}
    $outputPathOwners = @{}

    foreach ($manifestPath in $ManifestPaths) {
        $manifest = Read-PowerShellArtifactManifest -ManifestPath $manifestPath -RepoRoot $RepoRoot

        foreach ($sourceFile in $manifest.SourceFiles) {
            if ($sourceFileOwners.ContainsKey($sourceFile)) {
                $existingOwner = [string]$sourceFileOwners[$sourceFile]
                $relativeSourceFile = $sourceFile.Substring([System.IO.Path]::GetFullPath($RepoRoot).Length + 1).Replace('\', '/')
                throw "Artifact manifest '$manifestPath' reuses source file '$relativeSourceFile' already claimed by '$existingOwner'."
            }

            $sourceFileOwners[$sourceFile] = [System.IO.Path]::GetFullPath($manifestPath)
        }

        if ($outputPathOwners.ContainsKey($manifest.OutputPath)) {
            $existingOwner = [string]$outputPathOwners[$manifest.OutputPath]
            $relativeOutputPath = $manifest.OutputPath.Substring([System.IO.Path]::GetFullPath($RepoRoot).Length + 1).Replace('\', '/')
            throw "Artifact manifest '$manifestPath' reuses outputPath '$relativeOutputPath' already claimed by '$existingOwner'."
        }

        $outputPathOwners[$manifest.OutputPath] = [System.IO.Path]::GetFullPath($manifestPath)
    }

    return $true
}
