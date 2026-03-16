Set-StrictMode -Version Latest

# TEMPORARY COMPATIBILITY SHIM
#
# shared-helpers.ps1 is now the canonical home for the shared helper logic.
# Keep this wrapper until the broader refactor is fully validated and any
# external callers still dot-sourcing VulnExportStore.ps1 have been updated.

. (Join-Path $PSScriptRoot 'shared-helpers.ps1')