# Build Guide

This directory contains maintainer-facing build, validation, import, and packaging entrypoints.

## Structure

- `shared/source/`: canonical shared helper source fragments
- `validation/source/`: canonical validation helper source fragments
- `generated/`: derived helper outputs rebuilt on demand
- `azure/`: Azure-specific build sources and build entrypoints
- `Build-*.ps1`: top-level build scripts for generated helper files and release packaging
- `Import-*.ps1`: dot-sourcing wrappers that rebuild generated helper files when needed
- `Invoke-*.ps1`: maintainer validation and workflow-aligned execution entrypoints

## Common commands

```powershell
# Rebuild shared helper outputs under build/generated/
.\build\Build-SharedHelpers.ps1
.\build\Build-ValidationHelpers.ps1

# Rebuild Azure deployment artifacts under azure/
.\build\azure\Build-Runbook.ps1
.\build\azure\Build-FunctionApp.ps1

# Run the deterministic local and CI-aligned preflight path
.\build\Invoke-RegressionValidation.ps1

# Run the live export path locally against your current Az context
.\build\Invoke-LiveDashboardDryRun.ps1 -UseExistingAzContext

# Rebuild locally, redeploy Azure Automation + Function App, and execute both live validation paths
.\build\Invoke-AzureDeploymentValidation.ps1 -AutomationAccountName aa-defender-reporting -FunctionAppName func-defender-reporting -SkipMdePermissions

# Build the same Azure release zip used by the release workflow
.\build\Build-AzureReleasePackage.ps1
```

## User-facing scripts

The repository root keeps the scripts that new users are most likely to need directly:

- `Invoke-VulnerabilityExport.ps1`
- `Generate-VulnerabilityDashboard.ps1`
- `Setup-AzureResources.ps1`
- `Setup-GitHubActionServicePrincipal.ps1`