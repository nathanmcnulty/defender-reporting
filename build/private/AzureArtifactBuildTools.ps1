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