<#
.SYNOPSIS
    Generates the self-contained Azure Automation runbook script.

.DESCRIPTION
    Assembles azure/runbook-source.ps1 with the canonical shared helper block
    from the generated ../shared-helpers.ps1 surface and writes the public,
    copy/paste-ready azure/Invoke-DashboardPipeline.ps1 artifact.

.EXAMPLE
    .\azure\Build-Runbook.ps1
#>

#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$buildSharedHelpersPath = Join-Path -Path $repoRoot -ChildPath 'Build-SharedHelpers.ps1'
$sharedHelpersPath = Join-Path -Path $repoRoot -ChildPath 'shared-helpers.ps1'
$runbookSourcePath = Join-Path -Path $PSScriptRoot -ChildPath 'runbook-source.ps1'
$outputPath = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-DashboardPipeline.ps1'
$marker = @'
# =============================================================================
# SHARED HELPERS INSERTED BY azure/Build-Runbook.ps1
# =============================================================================
'@

if (-not (Test-Path -Path $buildSharedHelpersPath -PathType Leaf)) {
    throw "Shared helper build script not found: $buildSharedHelpersPath"
}

if (-not (Test-Path -Path $runbookSourcePath -PathType Leaf)) {
    throw "Runbook source file not found: $runbookSourcePath"
}

& $buildSharedHelpersPath

if (-not (Test-Path -Path $sharedHelpersPath -PathType Leaf)) {
    throw "Shared helper file not found after build: $sharedHelpersPath"
}

$sharedHelpers = Get-Content -Path $sharedHelpersPath -Raw
$runbookSource = Get-Content -Path $runbookSourcePath -Raw
$lineEnding = if ($runbookSource.Contains("`r`n")) { "`r`n" } else { "`n" }
$normalizedMarker = $marker -replace "`r?`n", $lineEnding
$normalizedSharedHelpers = ($sharedHelpers -replace "`r?`n", $lineEnding).TrimEnd()

if (-not $runbookSource.Contains($normalizedMarker)) {
    throw 'Runbook source is missing the shared helper marker.'
}

$assembled = $runbookSource.Replace($normalizedMarker, $normalizedSharedHelpers + $lineEnding + $lineEnding)
[System.IO.File]::WriteAllText($outputPath, $assembled, [System.Text.UTF8Encoding]::new($true))

Write-Output "Generated runbook: $outputPath"
