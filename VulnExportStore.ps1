Set-StrictMode -Version Latest

# TEMPORARY COMPATIBILITY SHIM
#
# shared-helpers.ps1 is now the canonical home for the shared helper logic.
# Keep this wrapper until the broader refactor is fully validated and any
# external callers still dot-sourcing VulnExportStore.ps1 have been updated.

$sharedHelpersPath = Join-Path $PSScriptRoot 'shared-helpers.ps1'
if (-not (Test-Path -Path $sharedHelpersPath -PathType Leaf)) {
	throw "Shared helper file not found: $sharedHelpersPath"
}

. $sharedHelpersPath