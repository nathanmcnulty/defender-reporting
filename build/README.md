# Build Guide

This directory contains maintainer-facing build, validation, import, and packaging entrypoints.

## Structure

- `manifests/`: explicit build manifests that define artifact inputs and ordering
- `private/`: shared build-system helper functions used by builders and import wrappers
- `generated/`: derived helper outputs rebuilt on demand
- `../src/powershell/Shared/`: canonical shared helper source organized by domain
- `../src/powershell/Validation/`: canonical validation helper source organized by domain
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
.\build\Invoke-AzureDeploymentValidation.ps1 -AutomationAccountName aa-defender-reporting -FunctionAppName func-defender-reporting -SkipMdePermissions -FunctionExecutionDatasetPath .\exports

# Build the same Azure release zip used by the release workflow
.\build\Build-AzureReleasePackage.ps1
```

When `-SkipMdePermissions` is paired with Function App execution validation, pass `-FunctionExecutionDatasetPath <dataset>` so the script can reseed the Function App exports container before invocation. Use `-SkipFunctionExecution` only when you intentionally want deployment validation without the final Function App run.

During seeded Function App validation, the script now writes a short-lived control blob at `dashboards/_diagnostics/ExportAndGenerate.control.json` and polls the runtime status blob at `dashboards/_diagnostics/ExportAndGenerate.status.json`. This makes Flex Consumption execution diagnosable even when admin VFS access and built-in log streaming are unavailable.

## User-facing scripts

The repository root keeps the scripts that new users are most likely to need directly:

- `Invoke-VulnerabilityExport.ps1`
- `Generate-VulnerabilityDashboard.ps1`
- `Setup-AzureResources.ps1`
- `Setup-GitHubActionServicePrincipal.ps1`

## Artifact manifests

The generated helper bundles are no longer assembled by scanning a flat source folder and sorting by filename. Instead, each artifact has an explicit manifest under `build/manifests/` that defines:

- the source roots owned by the artifact
- the ordered list of source files to concatenate
- the output path for the generated artifact

This makes dependency order explicit, lets the regression preflight catch orphaned source files, and makes the source tree easier for agents to navigate by domain instead of by numeric filename prefixes.

## Staged dashboard workflow

`Generate-VulnerabilityDashboard.ps1` now supports splitting the expensive normalization step from later packaging and validation work:

```powershell
# Reuse or create the normalized payload cache and optionally materialize it
.\Generate-VulnerabilityDashboard.ps1 -DirectoryPath .\exports -ExportMachineData:$false -NormalizeOnly -NormalizedPayloadOutputPath .\.local\payload\dashboard-payload.json.gz

# Build HTML later from that normalized payload without re-normalizing exports
.\Generate-VulnerabilityDashboard.ps1 -DirectoryPath .\exports -ExportMachineData:$false -PackageOnly -NormalizedPayloadInputPath .\.local\payload\dashboard-payload.json.gz -OutputPath .\VulnerabilityDashboard.html

# Re-run validation; use -ForceFullValidation to bypass the attested fast-path
.\Generate-VulnerabilityDashboard.ps1 -DirectoryPath .\exports -OutputPath .\VulnerabilityDashboard.html -ValidateOnly
```

Large-dataset validation writes and consumes a sibling `.validation.json` sidecar beside the HTML. Once a full semantic validation passes for a given source fingerprint and payload SHA, later `-ValidateOnly` runs can skip the full replay when the dashboard still embeds the same normalized payload bytes.