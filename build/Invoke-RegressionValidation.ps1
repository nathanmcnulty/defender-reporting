#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$SkipDashboardFixtureValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$buildRoot = $PSScriptRoot
$repoRoot = Split-Path -Path $buildRoot -Parent
$manifestToolsPath = Join-Path $buildRoot 'private\ArtifactManifestTools.ps1'
$settingsPath = Join-Path $buildRoot 'PSScriptAnalyzerSettings.psd1'
$artifactManifestPaths = @(
    Join-Path $buildRoot 'manifests\shared-helpers.json'
    Join-Path $buildRoot 'manifests\validation-helpers.json'
)
$generatedParseOnlyPaths = @(
    Join-Path $repoRoot 'azure\Invoke-DashboardPipeline.ps1'
    Join-Path $repoRoot 'azure\function-app\ExportAndGenerate\run.ps1'
)

if (-not (Test-Path -LiteralPath $manifestToolsPath -PathType Leaf)) {
    throw "Artifact manifest helper script not found: '$manifestToolsPath'"
}

. $manifestToolsPath

function Test-IsExcludedRepoScriptPath {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$ExcludeGeneratedOutputs
    )

    $normalizedPath = $Path -replace '\\', '/'
    if ($normalizedPath -match '/azure/function-app/Modules/') {
        return $true
    }

    if ($normalizedPath -match '/\.local/') {
        return $true
    }

    if (-not $ExcludeGeneratedOutputs) {
        return $false
    }

    return (
        $normalizedPath -match '/build/generated/' -or
        $normalizedPath -match '/azure/Invoke-DashboardPipeline\.ps1$' -or
        $normalizedPath -match '/azure/function-app/ExportAndGenerate/run\.ps1$'
    )
}

function Get-RepoPowerShellScriptPath {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeGeneratedOutputs
    )

    return @(
        Get-ChildItem -Path $repoRoot -Recurse -Filter '*.ps1' -File -ErrorAction Stop |
            Where-Object {
                -not (Test-IsExcludedRepoScriptPath -Path $_.FullName -ExcludeGeneratedOutputs:$ExcludeGeneratedOutputs)
            } |
            Sort-Object FullName |
            Select-Object -ExpandProperty FullName
    )
}

function Get-ParseValidationPath {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($path in (Get-RepoPowerShellScriptPath -ExcludeGeneratedOutputs)) {
        $paths.Add($path)
    }

    foreach ($generatedPath in $generatedParseOnlyPaths) {
        if (-not (Test-Path -LiteralPath $generatedPath -PathType Leaf)) {
            throw "Expected generated script was not produced: '$generatedPath'"
        }

        $paths.Add($generatedPath)
    }

    return @($paths | Sort-Object -Unique)
}

function Invoke-ParseValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths
    )

    foreach ($path in $Paths) {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
        if ($errors.Count -gt 0) {
            $messages = @($errors | ForEach-Object Message) -join '; '
            throw "Parse validation failed for '$path': $messages"
        }
    }
}

function Test-LastExitCodeFailed {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $exitCode = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction Ignore
    return ($null -ne $exitCode -and [int]$exitCode.Value -ne 0)
}

function Reset-LastExitCode {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only resets the session LASTEXITCODE used by regression wrapper checks.')]
    [CmdletBinding()]
    param()

    Set-Variable -Name LASTEXITCODE -Scope Global -Value 0
}

function Invoke-ArtifactManifestValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ManifestPaths
    )

    foreach ($manifestPath in $ManifestPaths) {
        [void](Test-PowerShellArtifactManifestCoverage -ManifestPath $manifestPath -RepoRoot $repoRoot)
    }
}

function Invoke-DashboardJavaScriptValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths
    )

    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    if ($null -eq $nodeCommand) {
        throw 'Node.js is required to run dashboard JavaScript regression tests.'
    }

    foreach ($path in $Paths) {
        Write-Output ("  Running $(Split-Path -Path $path -Leaf)...")
        Reset-LastExitCode
        & $nodeCommand.Source $path
        if (Test-LastExitCodeFailed) {
            throw "Dashboard JavaScript regression failed: '$path'"
        }
    }
}

Write-Output 'Validating build manifests...'
Invoke-ArtifactManifestValidation -ManifestPaths $artifactManifestPaths

Write-Output 'Building shared helpers...'
Reset-LastExitCode
& (Join-Path $buildRoot 'Build-SharedHelpers.ps1')
if (Test-LastExitCodeFailed) {
    throw 'build/Build-SharedHelpers.ps1 failed.'
}

Write-Output 'Building validation helpers...'
Reset-LastExitCode
& (Join-Path $buildRoot 'Build-ValidationHelpers.ps1')
if (Test-LastExitCodeFailed) {
    throw 'build/Build-ValidationHelpers.ps1 failed.'
}

Write-Output 'Building Azure runbook...'
Reset-LastExitCode
& (Join-Path $buildRoot 'azure\Build-Runbook.ps1')
if (Test-LastExitCodeFailed) {
    throw 'build/azure/Build-Runbook.ps1 failed.'
}

Write-Output 'Building Azure Function App entry point...'
Reset-LastExitCode
& (Join-Path $buildRoot 'azure\Build-FunctionApp.ps1') -SkipModuleStaging
if (Test-LastExitCodeFailed) {
    throw 'build/azure/Build-FunctionApp.ps1 failed.'
}

Write-Output 'Running parser validation...'
$parseValidationPaths = Get-ParseValidationPath
Invoke-ParseValidation -Paths $parseValidationPaths

Write-Output 'Running ScriptAnalyzer...'
$analyzerScriptPaths = Get-RepoPowerShellScriptPath -ExcludeGeneratedOutputs
$analyzerResults = foreach ($path in $analyzerScriptPaths) {
    Invoke-ScriptAnalyzer -Path $path -Settings $settingsPath -Severity Warning,Error
}
if ($analyzerResults) {
    $formatted = $analyzerResults | Select-Object RuleName, Severity, ScriptName, Line, Message | Format-Table -AutoSize | Out-String -Width 220
    throw "ScriptAnalyzer returned findings:`n$formatted"
}

Write-Output 'Running shared-helper regression tests...'
& (Join-Path $repoRoot 'tests\Run-SharedHelperRegression.ps1')

Write-Output 'Running dashboard JavaScript regression tests...'
$dashboardAssertionPaths = @(
    Get-ChildItem -Path (Join-Path $repoRoot 'tests') -Filter 'Assert-Dashboard*.js' -File -ErrorAction Stop |
        Sort-Object FullName |
        Select-Object -ExpandProperty FullName
)
Invoke-DashboardJavaScriptValidation -Paths $dashboardAssertionPaths

if (-not $SkipDashboardFixtureValidation) {
    $fixturePath = Join-Path $repoRoot 'tests\fixtures\legacy-migration'
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dashboard-fixture-validation-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $tempRoot -ItemType Directory -Force)

    try {
        $fixtureDataPath = Join-Path $tempRoot 'fixture-data'
        [void](New-Item -Path $fixtureDataPath -ItemType Directory -Force)
        Copy-Item -Path (Join-Path $fixturePath '*') -Destination $fixtureDataPath -Recurse -Force

        $fixtureCachePath = Join-Path $fixtureDataPath '.dashboard-cache'
        if (Test-Path -LiteralPath $fixtureCachePath) {
            Remove-Item -LiteralPath $fixtureCachePath -Recurse -Force -ErrorAction SilentlyContinue
        }

        $fixtureHtmlPath = Join-Path $tempRoot 'fixture-dashboard.html'
        $fixtureHostedHtmlPath = Join-Path $tempRoot 'fixture-dashboard.Hosted.html'
        Write-Output 'Running dashboard fixture smoke generation...'
        & (Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1') `
            -DirectoryPath $fixtureDataPath `
            -OutputPath $fixtureHtmlPath `
            -HostedOutputPath $fixtureHostedHtmlPath `
            -DualPackage `
            -ExportMachineData:$false
        if (Test-LastExitCodeFailed) {
            throw 'Generate-VulnerabilityDashboard.ps1 fixture smoke generation failed.'
        }

        $generatedArtifactsValidatorPath = Join-Path $repoRoot 'tests\Validate-DashboardGeneratedArtifacts.js'
        $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
        if ($null -eq $nodeCommand) {
            throw 'Node.js is required to validate generated dashboard artifacts.'
        }

        Write-Output 'Validating generated dashboard artifacts...'
        Reset-LastExitCode
        & $nodeCommand.Source $generatedArtifactsValidatorPath $fixtureHtmlPath $fixtureHostedHtmlPath
        if (Test-LastExitCodeFailed) {
            throw 'Generated dashboard artifact validation failed.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Output 'Regression validation completed successfully.'
