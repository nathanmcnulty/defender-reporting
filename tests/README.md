# Tests

This folder contains lightweight PowerShell regression coverage for the Defender reporting pipeline.

## Layout

- `tests/fixtures/` contains committed, minimal regression datasets.
- `tests/manual/` contains ad hoc troubleshooting harnesses that are useful during development but are not part of `Invoke-RegressionValidation.ps1`.
- The top-level scripts in `tests/` are the supported automation entrypoints for regression validation, stress generation, benchmarking, and synthetic live-export creation.

## Runbook-safe regression entrypoint

Run the full local regression bundle with:

```powershell
pwsh -NoProfile -File .\Invoke-RegressionValidation.ps1
```

That script rebuilds the generated helper/runbook artifacts, runs parser and PSScriptAnalyzer checks, executes focused shared-helper regression tests, and performs a small dashboard fixture smoke generation.

## Legacy migration fixture

`tests/fixtures/legacy-migration` contains a tiny synthetic dataset used to exercise the temporary legacy vulnerability migration path.

Important note:
- the fixture files named `*.json` are intentionally a mix of formats
- `VulnExport_*.json` and `AdvancedHunting_Current.json` are NDJSON-style files, where each line is an individual JSON object
- `Machines_Current.json` is a single JSON object

These shapes match what the pipeline readers already support, even though NDJSON files are not a single valid JSON document when opened in a generic JSON validator.

The fixture smoke runs in `Invoke-RegressionValidation.ps1` and the legacy fixture regression path both execute against temp copies so derived `.dashboard-cache/` output does not pollute the committed fixture.

## Large synthetic stress dataset

Generate a large helper-compatible export set locally with:

```powershell
pwsh -NoProfile -File .\tests\Generate-SyntheticLargeExports.ps1
```

Defaults:
- preset: `BalancedMediumHeavy`
- target devices: `20,000`
- target vulnerability rows: `1,500,000`
- output path: `.\exports-synthetic`

Run a full local dashboard generation against that synthetic export set with:

```powershell
pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -Validate
```

That command:
- regenerates the synthetic exports
- runs `Generate-VulnerabilityDashboard.ps1` against them
- writes `synthetic-manifest.json` and `stress-validation-report.json` under `exports-synthetic/`

Supported presets:
- `DeviceCardinalityFirst`
- `BalancedMediumHeavy`
- `CurrentDensity`

## Synthetic live export

Create a shifted synthetic dataset that preserves the original export shape while moving the latest observation date forward:

```powershell
pwsh -NoProfile -File .\tests\New-SyntheticLiveExport.ps1 -SkipContentStoreSidecars
```

Defaults:
- source path: `.\exports-synthetic`
- output path: `.\exports-synthetic-live`
- target latest date: current UTC date

`-SkipContentStoreSidecars` keeps the output in raw-export form so downstream validation paths can rebuild sidecars on demand.

## Benchmarking

Capture a current-branch-only benchmark baseline with:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
pwsh -NoProfile -File .\tests\Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -CurrentBaselineName 'current-live' -DatasetPath .\exports-synthetic-live -ResultsOutputPath (Join-Path $PWD ('.local\current-baseline-live-' + $stamp + '.json'))
```

Recommendations:
- keep raw benchmark outputs under `.local/`
- use the staged local copy behavior in `Measure-BranchVsMainBenchmark.ps1` when benchmarking raw datasets without sidecars
- use `docs/performance-baselines.md` for the merge-tracked summary of recorded baseline numbers
