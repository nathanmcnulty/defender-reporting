# Manual Test Harnesses

These scripts are intentionally separate from `build/Invoke-RegressionValidation.ps1`.

Use them when you need to probe a specific normalization or cache path during local troubleshooting.

Conventions:
- default synthetic input prefers `.local\exports-synthetic` when present, then falls back to `exports-synthetic`
- default output goes to `.local\stress-output`
- they may create temporary `.test-backup` folders under the working dataset root and clean them up when finished

Available scripts:
- `Invoke-DashboardPathCoverage.ps1`: runs the `P1` through `P5` normalization and cache-path scenarios against a synthetic dataset
- `Invoke-LegacyFallbackCachePath.ps1`: runs the targeted `P5` legacy fallback cache-build scenario only