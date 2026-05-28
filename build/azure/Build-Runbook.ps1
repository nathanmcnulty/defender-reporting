<#
.SYNOPSIS
    Generates the self-contained Azure Automation runbook script.

.DESCRIPTION
    Assembles build/azure/runbook-source.ps1 with the canonical shared helper block
    from the manifest-driven shared helper source tree via build/Build-SharedHelpers.ps1 and writes the public,
    copy/paste-ready azure/Invoke-DashboardPipeline.ps1 artifact.

.EXAMPLE
    .\build\azure\Build-Runbook.ps1
#>

#Requires -Version 7.0

[CmdletBinding()]
param()

. (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'private\AzureArtifactBuildTools.ps1')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$buildContext = Get-AzureArtifactBuildContext -BuildScriptRoot $PSScriptRoot
$marker = @'
# =============================================================================
# SHARED HELPERS INSERTED BY build/azure/Build-Runbook.ps1
# =============================================================================
'@

$assemblyInput = Get-AzureSharedAssemblyInput -BuildContext $buildContext -Marker $marker

if (-not $assemblyInput.RunbookSource.Contains($assemblyInput.NormalizedMarker)) {
    throw 'Runbook source is missing the shared helper marker.'
}

$assembled = $assemblyInput.RunbookSource.Replace($assemblyInput.NormalizedMarker, $assemblyInput.NormalizedSharedHelpers + $assemblyInput.LineEnding + $assemblyInput.LineEnding)
Write-Utf8BomFile -Path $buildContext.RunbookOutputPath -Content $assembled

$runbookFingerprintState = Assert-AzureArtifactFingerprint -ArtifactPath $buildContext.RunbookOutputPath -ExpectedFingerprint $assemblyInput.SharedHelpersFingerprint -ArtifactDescription 'Azure Automation runbook artifact'

Write-Output "Generated runbook: $($buildContext.RunbookOutputPath)"
Write-Output "Runbook shared-helper fingerprint: $($runbookFingerprintState.Fingerprint)"
