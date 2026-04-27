## Summary

-

## Validation

- [ ] Deterministic preflight: `pwsh -NoProfile -File .\build\Invoke-RegressionValidation.ps1`
- [ ] Live export dry run, when API export or shipped dashboard behavior changed: `pwsh -NoProfile -File .\build\Invoke-LiveDashboardDryRun.ps1 -UseExistingAzContext`
- [ ] Large-dataset artifact gate, when normalization, payload, validation, or packaging changed: `pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-50k-1_5m -Validate -ValidationMode artifacts`
- [ ] Large-dataset semantic sign-off, when semantics, validation, or perf-sensitive behavior changed: `pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-50k-1_5m -Validate -ValidationMode semantic`
- [ ] Azure deployment validation, when Azure deployment, packaging, Automation, Function App, or release packaging changed: `pwsh -NoProfile -File .\build\Invoke-AzureDeploymentValidation.ps1 <local parameters>`
- [ ] Hosted dashboard runtime smoke, when split-assets delivery changed: `pwsh -NoProfile -File .\tests\Invoke-HostedDashboardRuntimeSmoke.ps1 -DashboardPath <hosted-html>`
- [ ] Not applicable: explain skipped gates below.

## Gate Notes

- Dataset(s):
- Artifact path(s):
- Skipped gates and reason:
