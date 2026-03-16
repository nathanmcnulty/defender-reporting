<#
.SYNOPSIS
    Generates the self-contained Azure Automation runbook script.

.DESCRIPTION
    Assembles azure/runbook-source.ps1 with the canonical shared helper block
    from ../shared-helpers.ps1 and writes the public, copy/paste-ready
    azure/Invoke-DashboardPipeline.ps1 artifact.

.EXAMPLE
    .\azure\Build-Runbook.ps1
#>

#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$sharedHelpersPath = Join-Path -Path $repoRoot -ChildPath 'shared-helpers.ps1'
$runbookSourcePath = Join-Path -Path $PSScriptRoot -ChildPath 'runbook-source.ps1'
$outputPath = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-DashboardPipeline.ps1'
$marker = @'
# =============================================================================
# SHARED HELPERS INSERTED BY azure/Build-Runbook.ps1
# =============================================================================
'@

if (-not (Test-Path -Path $sharedHelpersPath -PathType Leaf)) {
    throw "Shared helper file not found: $sharedHelpersPath"
}

if (-not (Test-Path -Path $runbookSourcePath -PathType Leaf)) {
    throw "Runbook source file not found: $runbookSourcePath"
}

$sharedHelpers = Get-Content -Path $sharedHelpersPath -Raw
$runbookSource = Get-Content -Path $runbookSourcePath -Raw

if (-not $runbookSource.Contains($marker)) {
    throw 'Runbook source is missing the shared helper marker.'
}

$assembled = $runbookSource.Replace($marker, $sharedHelpers.TrimEnd() + "`r`n`r`n")
[System.IO.File]::WriteAllText($outputPath, $assembled, [System.Text.UTF8Encoding]::new($false))

Write-Host "Generated runbook: $outputPath" -ForegroundColor Green