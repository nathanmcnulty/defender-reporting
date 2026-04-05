#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$SkipDashboardFixtureValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot
$scriptFiles = @(
    'Build-SharedHelpers.ps1',
    'shared-helpers.ps1',
    'Invoke-VulnerabilityExport.ps1',
    'Generate-VulnerabilityDashboard.ps1',
    'azure/Build-Runbook.ps1',
    'azure/runbook-source.ps1',
    'azure/Invoke-DashboardPipeline.ps1',
    'tests/Run-SharedHelperRegression.ps1'
) | ForEach-Object { Join-Path $repoRoot $_ }

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

Write-Output 'Building shared helpers...'
& (Join-Path $repoRoot 'Build-SharedHelpers.ps1')
if (Test-LastExitCodeFailed) {
    throw 'Build-SharedHelpers.ps1 failed.'
}

Write-Output 'Building Azure runbook...'
& (Join-Path $repoRoot 'azure\Build-Runbook.ps1')
if (Test-LastExitCodeFailed) {
    throw 'azure/Build-Runbook.ps1 failed.'
}

Write-Output 'Running parser validation...'
Invoke-ParseValidation -Paths $scriptFiles

Write-Output 'Running ScriptAnalyzer...'
$analyzerResults = foreach ($path in $scriptFiles) {
    Invoke-ScriptAnalyzer -Path $path -Severity Warning,Error
}
if ($analyzerResults) {
    $formatted = $analyzerResults | Select-Object RuleName, Severity, ScriptName, Line, Message | Format-Table -AutoSize | Out-String -Width 220
    throw "ScriptAnalyzer returned findings:`n$formatted"
}

Write-Output 'Running shared-helper regression tests...'
& (Join-Path $repoRoot 'tests\Run-SharedHelperRegression.ps1')

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
        Write-Output 'Running dashboard fixture smoke generation...'
        & (Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1') `
            -DirectoryPath $fixtureDataPath `
            -OutputPath $fixtureHtmlPath `
            -ExportMachineData:$false
        if (Test-LastExitCodeFailed) {
            throw 'Generate-VulnerabilityDashboard.ps1 fixture smoke generation failed.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Output 'Regression validation completed successfully.'
