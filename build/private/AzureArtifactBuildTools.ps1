. (Join-Path -Path $PSScriptRoot -ChildPath 'ArtifactManifestTools.ps1')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AzureArtifactBuildContext {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildScriptRoot
    )

    $buildRoot = Split-Path -Path $BuildScriptRoot -Parent
    $repoRoot = Split-Path -Path $buildRoot -Parent

    return [PSCustomObject]@{
        BuildRoot = $buildRoot
        RepoRoot = $repoRoot
        BuildSharedHelpersPath = Join-Path -Path $buildRoot -ChildPath 'Build-SharedHelpers.ps1'
        SharedHelpersPath = Join-Path -Path $buildRoot -ChildPath 'generated\shared-helpers.ps1'
        RunbookSourcePath = Join-Path -Path $BuildScriptRoot -ChildPath 'runbook-source.ps1'
        RunbookOutputPath = Join-Path -Path $repoRoot -ChildPath 'azure\Invoke-DashboardPipeline.ps1'
        FunctionAppRoot = Join-Path -Path $repoRoot -ChildPath 'azure\function-app'
    }
}

function Assert-BuildPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Leaf', 'Container')]
        [string]$PathType
    )

    if (-not (Test-Path -LiteralPath $Path -PathType $PathType)) {
        throw "Required path not found: $Path"
    }
}

function Initialize-ParentDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parentPath = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -LiteralPath $parentPath -PathType Container)) {
        New-Item -Path $parentPath -ItemType Directory -Force | Out-Null
    }
}

function Get-AzureSharedAssemblyInput {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$BuildContext,

        [Parameter(Mandatory = $true)]
        [string]$Marker
    )

    Assert-BuildPath -Path $BuildContext.BuildSharedHelpersPath -PathType Leaf
    Assert-BuildPath -Path $BuildContext.RunbookSourcePath -PathType Leaf

    & $BuildContext.BuildSharedHelpersPath

    Assert-BuildPath -Path $BuildContext.SharedHelpersPath -PathType Leaf
    $sharedHelpersFingerprint = Read-PowerShellArtifactEmbeddedFingerprint -Path $BuildContext.SharedHelpersPath
    if ([string]::IsNullOrWhiteSpace($sharedHelpersFingerprint)) {
        throw "Generated shared helpers '$($BuildContext.SharedHelpersPath)' are missing fingerprint metadata. Re-run '$($BuildContext.BuildSharedHelpersPath)'."
    }

    $runbookSource = Get-Content -Path $BuildContext.RunbookSourcePath -Raw
    $sharedHelpers = Get-Content -Path $BuildContext.SharedHelpersPath -Raw
    $lineEnding = if ($runbookSource.Contains("`r`n")) { "`r`n" } else { "`n" }
    $normalizedMarker = $Marker -replace "`r?`n", $lineEnding
    $sharedHelpersText = if ($sharedHelpers -is [System.Array]) {
        @($sharedHelpers) -join $lineEnding
    }
    else {
        [string]$sharedHelpers
    }

    return [PSCustomObject]@{
        RunbookSource = $runbookSource
        LineEnding = $lineEnding
        NormalizedMarker = $normalizedMarker
        NormalizedSharedHelpers = ($sharedHelpersText -replace "`r?`n", $lineEnding).TrimEnd()
        SharedHelpersFingerprint = $sharedHelpersFingerprint
    }
}

function Assert-AzureArtifactFingerprint {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArtifactPath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedFingerprint,

        [Parameter(Mandatory = $true)]
        [string]$ArtifactDescription
    )

    Assert-BuildPath -Path $ArtifactPath -PathType Leaf
    $artifactContent = Get-Content -LiteralPath $ArtifactPath -Raw -ErrorAction Stop
    $embeddedFingerprint = $null
    $fingerprintMatches = [System.Text.RegularExpressions.Regex]::Matches($artifactContent, '(?m)^# ArtifactFingerprint:\s*([0-9a-f]{64})\s*$')
    if ($fingerprintMatches.Count -gt 0) {
        $embeddedFingerprint = $fingerprintMatches[$fingerprintMatches.Count - 1].Groups[1].Value.ToLowerInvariant()
    }
    if ([string]::IsNullOrWhiteSpace($embeddedFingerprint)) {
        throw "$ArtifactDescription '$ArtifactPath' is missing embedded fingerprint metadata."
    }

    if ($embeddedFingerprint -ne $ExpectedFingerprint) {
        throw "$ArtifactDescription '$ArtifactPath' does not match the current shared-helper fingerprint. Expected '$ExpectedFingerprint' but found '$embeddedFingerprint'."
    }

    return [PSCustomObject]@{
        ArtifactPath = $ArtifactPath
        Fingerprint = $embeddedFingerprint
    }
}

function Get-AzAccountsModuleStagingSummary {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleRoot,

        [Parameter(Mandatory = $false)]
        [string]$RepoRoot
    )

    Assert-BuildPath -Path $ModuleRoot -PathType Container
    $manifestCandidates = @(
        Get-ChildItem -LiteralPath $ModuleRoot -Filter 'Az.Accounts.psd1' -Recurse -File -ErrorAction Stop
    )
    if ($manifestCandidates.Count -eq 0) {
        throw "No Az.Accounts module manifest was found under '$ModuleRoot'."
    }

    $validManifests = foreach ($manifestCandidate in $manifestCandidates) {
        try {
            $moduleManifest = Test-ModuleManifest -Path $manifestCandidate.FullName -ErrorAction Stop
            [PSCustomObject]@{
                Path = $manifestCandidate.FullName
                ModuleVersion = [version]$moduleManifest.Version
            }
        }
        catch {
            continue
        }
    }

    $selectedManifest = $validManifests | Sort-Object -Property ModuleVersion -Descending | Select-Object -First 1
    if ($null -eq $selectedManifest) {
        throw "Az.Accounts staging under '$ModuleRoot' does not contain a valid module manifest."
    }

    $fileCount = @(Get-ChildItem -LiteralPath $ModuleRoot -Recurse -File -ErrorAction Stop).Count
    if ($fileCount -lt 5) {
        throw "Az.Accounts staging under '$ModuleRoot' is incomplete (found $fileCount file(s))."
    }

    $manifestDisplayPath = if (-not [string]::IsNullOrWhiteSpace($RepoRoot) -and (Test-ArtifactPathWithinRoot -Path $selectedManifest.Path -Root $RepoRoot)) {
        Get-RepoRelativeDisplayPath -Path $selectedManifest.Path -RepoRoot $RepoRoot
    }
    else {
        $selectedManifest.Path
    }

    return [PSCustomObject]@{
        ModuleRoot = $ModuleRoot
        ManifestPath = $selectedManifest.Path
        ManifestDisplayPath = $manifestDisplayPath
        ModuleVersion = $selectedManifest.ModuleVersion.ToString()
        FileCount = $fileCount
    }
}

function Write-Utf8BomFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )

    Initialize-ParentDirectory -Path $Path
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($true))
}