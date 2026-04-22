# Tests

This folder contains lightweight PowerShell regression coverage for the Defender reporting pipeline.

## Layout

- `tests/fixtures/` contains committed, minimal regression datasets.
- `tests/manual/` contains ad hoc troubleshooting harnesses that are useful during development but are not part of `build/Invoke-RegressionValidation.ps1`.
- The top-level scripts in `tests/` are the supported automation entrypoints for regression validation, stress generation, benchmarking, and synthetic live-export creation.

## Deterministic preflight entrypoint

Run the full local regression bundle with:

```powershell
pwsh -NoProfile -File .\build\Invoke-RegressionValidation.ps1
```

That script is the authoritative deterministic preflight used for local work and PR validation. It rebuilds the generated deployment artifacts, runs parser and PSScriptAnalyzer checks across source scripts, executes focused shared-helper regression tests, and performs a small dashboard fixture smoke generation.

## CI-aligned live dry run

Run the exact live export and dashboard-generation path locally against your current Az context with:

```powershell
pwsh -NoProfile -File .\build\Invoke-LiveDashboardDryRun.ps1 -UseExistingAzContext
```

Defaults:
- output root: `.local/local-reports/live-dashboard-dry-run/`
- includes Advanced Hunting by default
- writes `dashboard-audit.json` and `dashboard-live-run-manifest.json` alongside the generated HTML

Use `-UseRepositoryOutputPaths` only when you intentionally want the live dry run to write into the tracked `exports/` and `VulnerabilityDashboard.html` paths.

## Legacy migration fixture

`tests/fixtures/legacy-migration` contains a tiny synthetic dataset used to exercise the temporary legacy vulnerability migration path.

Important note:
- the fixture files named `*.json` are intentionally a mix of formats
- `VulnExport_*.json` and `AdvancedHunting_Current.json` are NDJSON-style files, where each line is an individual JSON object
- `Machines_Current.json` is a single JSON object

These shapes match what the pipeline readers already support, even though NDJSON files are not a single valid JSON document when opened in a generic JSON validator.

The fixture smoke runs in `build/Invoke-RegressionValidation.ps1` and the legacy fixture regression path both execute against temp copies so derived `.dashboard-cache/` output does not pollute the committed fixture.

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
- writes `dashboard-audit.json` under `exports-synthetic/` when `-Validate` is set

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

## Large import coverage

Large-dataset review now needs three separate lanes. Do not rely on completed, content-store-ready datasets alone.

### 1. Replay a completed dataset

Use this lane for steady-state normalization, packaging, and dashboard generation against a fully prepared export set.

Examples:

```powershell
pwsh -NoProfile -File .\tests\Measure-RunbookOnlyAzureBenchmark.ps1

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
pwsh -NoProfile -File .\tests\Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -DatasetPath .\exports-synthetic-live -ResultsOutputPath (Join-Path $PWD ('.local\current-baseline-live-' + $stamp + '.json'))
```

### 2. Replay a raw large dataset without sidecars

Use this lane when you want to catch hot paths hidden by already-materialized content-store artifacts. This is the preferred synthetic path for large import-like validation of Machines, Advanced Hunting, and canonical vulnerability current/history rows.

Recommended workflow:

```powershell
pwsh -NoProfile -File .\tests\Generate-SyntheticLargeExports.ps1 -OutputPath .\.local\large-datasets\synthetic-raw -IncludeRawRows -AllowLargeDataset

pwsh -NoProfile -File .\tests\New-SyntheticLiveExport.ps1 -SourcePath .\.local\large-datasets\synthetic-raw -OutputPath .\.local\large-datasets\synthetic-raw-live -SkipContentStoreSidecars -Force

pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-raw-live -Validate
```

If you need Azure replay against that raw dataset, seed it into storage through `Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -DatasetPath <raw-live-path>` so the benchmark harness stages the same files into the `exports` container before the runbook starts.

### 3. Run a live fresh-export Azure Automation job

Use this lane to exercise the real Stage C import path, including bulk vulnerability snapshot download, machine export refresh, and Advanced Hunting export refresh. This is the only supported large-scale path for fresh vulnerability snapshot import today.

Example:

```powershell
pwsh -NoProfile -File .\tests\Measure-RunbookOnlyAzureBenchmark.ps1 -UseExistingExportsOnly:$false
```

Important notes:
- `Measure-RunbookOnlyAzureBenchmark.ps1` defaults to `UseExistingExportsOnly = true` unless you explicitly pass `-UseExistingExportsOnly:$false`.
- `New-SyntheticLiveExport.ps1 -SkipContentStoreSidecars` forces sidecar rebuild and canonical raw-row replay, but it does not generate large synthetic legacy `VulnExport_*.json` snapshot sets.
- Large fresh vulnerability snapshot import is therefore validated today through live Azure Automation runs, not through a fully synthetic legacy-snapshot replay.

Recommended acceptance process for large import changes:
- one replay benchmark against a completed dataset
- one replay benchmark against a raw sidecar-free synthetic dataset
- one live Azure Automation fresh-export run
- record which lane each captured result belongs to so replay and fresh-import numbers are not compared as if they covered the same path

## Hot phase review

Review the local generator and validation hot phases with:

```powershell
pwsh -NoProfile -File .\tests\Invoke-HotPhaseReview.ps1 -DirectoryPath .\exports
```

That command:
- runs `Generate-VulnerabilityDashboard.ps1` with validation enabled
- captures local process memory samples plus the generator stdout and stderr logs
- parses the local phase markers emitted by `Generate-VulnerabilityDashboard.ps1`
- extracts the audit `PhaseTimings` block for any validation mode and falls back to `SemanticParity.PhaseTimings` for older audit shapes
- writes `hot-phase-review.json` under `.local/hot-phase-review/<timestamp>/`

Long-running review, stress, and benchmark wrappers now emit timestamped heartbeat lines at their poll interval so you can confirm they are still making progress even when the child process is temporarily quiet.

Use a smaller synthetic dataset while iterating, then move to the benchmark and Azure validation entrypoints once the local hot phases improve.

## Validation mode comparison

Split packaging, full validation, and attested validation into separate measured runs with:

```powershell
pwsh -NoProfile -File .\tests\Invoke-ValidationModeComparison.ps1 -DirectoryPath .\exports
```

That command:
- warms a reusable normalized payload artifact with `-NormalizeOnly`
- measures `-PackageOnly` against that payload artifact
- measures `-ValidateOnly -ForceFullValidation` and the attested `-ValidateOnly` fast path against the same packaged dashboard
- measures end-to-end `-Validate -ForceFullValidation` and the default `-Validate` path
- writes `validation-mode-comparison.json` under `.local/validation-mode-comparison/<timestamp>/`

Use this workflow when validation is the dominant hot phase and you need to distinguish package cost from semantic replay cost.

## Benchmarking

Create or refresh the durable benchmark dataset with:

```powershell
pwsh -NoProfile -File .\tests\New-BenchmarkDataset.ps1 -DatasetId benchmark-medium-v1
```

That dataset definition currently maps to:
- dataset id: `benchmark-medium-v1`
- preset: `BalancedMediumHeavy`
- target devices: `1,500`
- target vulnerability rows: `120,000`
- seed: `20260322`
- output path: `.local\benchmark-datasets\benchmark-medium-v1`

Capture a repeatable multi-run benchmark series against the standard dataset with:

```powershell
pwsh -NoProfile -File .\tests\Invoke-BenchmarkSeries.ps1 -BenchmarkDatasetId benchmark-medium-v1 -Iterations 3 -IncludePersistentLocalWorkflow
```

That command:
- ensures the durable benchmark dataset exists
- records each benchmark JSON under `.local\benchmark-series\`
- appends each run to `.local\benchmark-history\benchmark-history.jsonl`
- writes aggregate `series-summary.json` and `series-summary.md` artifacts

Function App timing semantics:
- `function_app.elapsed_seconds` now tracks active execution time when the runtime status blob is available
- `function_app.end_to_end_elapsed_seconds` retains invoke-to-finish timing for queue and cold-start review
- `function_app.pickup_delay_seconds` records the gap between admin invocation and active execution start

Capture a current-branch-only benchmark baseline with:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
pwsh -NoProfile -File .\tests\Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -CurrentBaselineName 'current-live' -DatasetPath .\exports-synthetic-live -ResultsOutputPath (Join-Path $PWD ('.local\current-baseline-live-' + $stamp + '.json'))
```

Append a normalized local history entry after a benchmark completes with:

```powershell
pwsh -NoProfile -File .\tests\Record-BenchmarkHistory.ps1 -BenchmarkResultPath .\.local\current-baseline-live-<timestamp>.json
```

Recommendations:
- keep raw benchmark outputs under `.local/`
- use `.local\benchmark-history\benchmark-history.jsonl` plus `.local\benchmark-history\latest-summary.md` for repeated review and Azure acceptance captures that you want to compare over time
- prefer `benchmark-medium-v1` plus `Invoke-BenchmarkSeries.ps1` when you need the durable, merge-tracked benchmark cadence instead of an ad hoc review capture
- use the staged local copy behavior in `Measure-BranchVsMainBenchmark.ps1` when benchmarking raw datasets without sidecars
- use `docs/performance-baselines.md` only for accepted durable datasets that should remain merge-tracked as baseline documentation
