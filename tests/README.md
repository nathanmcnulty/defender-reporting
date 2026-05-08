# Tests

This folder contains lightweight PowerShell regression coverage for the Defender reporting pipeline.

## Layout

- `tests/fixtures/` contains committed, minimal regression datasets.
- `tests/manual/` contains ad hoc troubleshooting harnesses that are useful during development but are not part of `build/Invoke-RegressionValidation.ps1`.
- The top-level scripts in `tests/` are the supported automation entrypoints for regression validation, stress generation, benchmarking, and synthetic live-export creation.

## Platform support

Some entrypoints are cross-platform and some depend on Windows memory-sampling primitives or Microsoft Edge.

| Entrypoint | Windows | macOS | Linux | Notes |
| --- | --- | --- | --- | --- |
| `build/Invoke-RegressionValidation.ps1` | Yes | Yes | Yes | Primary deterministic preflight |
| `build/Invoke-LiveDashboardDryRun.ps1` | Yes | Yes | Yes | Requires the right Az/auth context |
| `tests/Invoke-HotPhaseReview.ps1` | Yes | No | No | Uses Windows memory/process sampling |
| `tests/Invoke-ValidationModeComparison.ps1` | Yes | No | No | Uses Windows memory/process sampling |
| `tests/Measure-BranchVsMainBenchmark.ps1` | Yes | No | No | Uses Windows memory/process sampling |
| `tests/Measure-StressRun.ps1` | Yes | No | No | Uses Windows memory/process sampling |
| `tests/Invoke-WithPwshMemoryGuard.ps1` | Yes | No | No | Uses Windows memory/process sampling |
| `tests/Invoke-HostedDashboardRuntimeSmoke.ps1` | Yes | No | No | Requires Microsoft Edge; use `-AllowSkip` when optional |

## Deterministic preflight entrypoint

Run the full local regression bundle with:

```powershell
pwsh -NoProfile -File .\build\Invoke-RegressionValidation.ps1
```

That script is the authoritative deterministic preflight used for local work and PR validation. It rebuilds the generated deployment artifacts, runs parser and PSScriptAnalyzer checks across source scripts, executes focused shared-helper regression tests, and performs a small dashboard fixture smoke generation.

The shared-helper regression lane now logs `START <Test-Name>` and a per-test elapsed time. If the preflight looks slow, use that output to identify the active or expensive test before assuming the suite is hung.

## Test lanes at a glance

| Lane | Primary entrypoint | Use it for |
| --- | --- | --- |
| Deterministic regression gate | `build/Invoke-RegressionValidation.ps1` | Every PR and before heavier validation |
| Live export integration | `build/Invoke-LiveDashboardDryRun.ps1 -UseExistingAzContext` | Export/authentication/shipped-dashboard changes |
| Hosted browser/runtime smoke | `tests/Invoke-HostedDashboardRuntimeSmoke.ps1` | Split-assets delivery or hosted runtime changes |
| Local perf phase review | `tests/Invoke-HotPhaseReview.ps1` | Normalization, payload, validation, or packaging perf work |
| Routine semantic review | `tests/Invoke-RoutineSemanticReview.ps1` | Repeatable medium-dataset semantic review during iteration |
| Benchmarking and stress tools | `tests/Invoke-BenchmarkSeries.ps1`, `tests/Measure-BranchVsMainBenchmark.ps1`, `tests/Measure-StressRun.ps1` | Comparative or historical performance work |
| Manual diagnostics | `tests/manual/` | Ad hoc troubleshooting only |

Helper rule: if a new test or benchmark script needs shared utilities, put them in `tests/helpers/` instead of copying helper functions into multiple entrypoints.

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

Run an iterative local dashboard generation against that synthetic export set with:

```powershell
pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -Validate -ValidationMode artifacts
```

That command:
- regenerates the synthetic exports
- runs `Generate-VulnerabilityDashboard.ps1` against them
- validates the generated self-contained and hosted dashboard artifacts
- writes `synthetic-manifest.json` and `stress-validation-report.json` under `exports-synthetic/`

Reserve the semantic replay for milestone or final local sign-off:

```powershell
pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -Validate -ValidationMode semantic
```

That semantic mode additionally writes `dashboard-audit.json` under `exports-synthetic/`.

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

### One-command workflow

Use this entrypoint when you want the synthetic import lane prepared and locally checked end to end with one command:

```powershell
pwsh -NoProfile -File .\tests\Invoke-LargeImportCoverage.ps1
```

By default this workflow:
- generates a raw synthetic dataset with canonical current/history row files
- shifts that dataset forward to a live date without rebuilding content-store sidecars
- materializes deterministic legacy `VulnExport_<group>_<date>.json.gz` files from the raw live dataset
- builds `.local\large-import-coverage\azure-replay-existing-exports` with `Machines_Current.json.gz`, `AdvancedHunting_Current.json.gz`, and the synthetic legacy vulnerability snapshots for `UseExistingExportsOnly=true` Azure replay runs
- runs local raw replay validation and local legacy vulnerability import validation unless you explicitly skip them

Useful switches:
- `-SkipRawValidation` while iterating on dataset prep only
- `-SkipLegacyImportValidation` when you only need the replay dataset artifacts
- `-SnapshotCount <n>` or `-SnapshotDates <yyyy-MM-dd,...>` to control which synthetic legacy snapshot dates are emitted
- `-AllowLargeDataset` for unattended large captures beyond the default safety limits

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

pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-raw-live -Validate -ValidationMode artifacts
```

Switch that final command to `-ValidationMode semantic` only when you need the full streaming semantic replay before sign-off.

Standalone legacy vulnerability snapshot materialization from that raw live dataset:

```powershell
pwsh -NoProfile -File .\tests\New-SyntheticLegacyVulnSnapshotSet.ps1 -SourcePath .\.local\large-datasets\synthetic-raw-live -OutputPath .\.local\large-datasets\synthetic-legacy-vuln -SnapshotCount 2 -Force
```

If you need Azure replay against that raw dataset, prefer the composite dataset produced by `Invoke-LargeImportCoverage.ps1` under `.local\large-import-coverage\azure-replay-existing-exports`, then seed that path into storage before starting `Measure-RunbookOnlyAzureBenchmark.ps1` or `Measure-BranchVsMainBenchmark.ps1` with `UseExistingExportsOnly=true`.

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

## Routine semantic review

Run the routine medium-dataset semantic lane with:

```powershell
pwsh -NoProfile -File .\tests\Invoke-RoutineSemanticReview.ps1
```

That command:
- ensures the durable `benchmark-medium-v1` dataset is present
- runs `Invoke-HotPhaseReview.ps1` against that dataset in `semantic` mode with `-ForceFullValidation`
- writes the review artifacts under `.local\routine-semantic-review\<timestamp>\`
- gives you a repeatable semantic review path that is materially cheaper than the `synthetic-50k-1_5m` full sign-off lane

Use this workflow for routine semantic or validation review during iteration, then keep the full `synthetic-50k-1_5m` semantic gate for release sign-off and high-risk normalization changes.

## Hosted dashboard runtime smoke

Run the hosted dashboard through a non-visual Edge smoke when split-assets delivery changes or when you want an explicit browser-runtime check:

```powershell
pwsh -NoProfile -File .\tests\Invoke-HostedDashboardRuntimeSmoke.ps1 -DashboardPath <hosted-html-path>
```

Notes:
- this lane requires Windows and Microsoft Edge
- use `-AllowSkip` when you want optional local coverage on machines without Edge
- pair it with `build/Invoke-RegressionValidation.ps1`; it supplements the deterministic gate instead of replacing it

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

## Benchmark and stress tool selection

| Goal | Preferred entrypoint | Notes |
| --- | --- | --- |
| One-command repeated local benchmark on the durable dataset | `tests/Invoke-BenchmarkSeries.ps1` | Use when refreshing or comparing repeatable local baselines |
| Current branch vs. main or a one-off branch capture | `tests/Measure-BranchVsMainBenchmark.ps1` | Best for side-by-side local comparison |
| Phase-by-phase local review | `tests/Invoke-HotPhaseReview.ps1` | Start here before heavier benchmark or Azure work |
| Medium-dataset semantic validation during iteration | `tests/Invoke-RoutineSemanticReview.ps1` | Preferred semantic lane for routine branch work |
| Validation cost split between packaging and semantic replay | `tests/Invoke-ValidationModeComparison.ps1` | Use when validation time dominates |
| Custom stress capture | `tests/Measure-StressRun.ps1` | Reserve for targeted stress investigation, not routine branch validation |

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

For the larger reusable Azure stress seed, materialize or register the existing 50k-device dataset with:

```powershell
pwsh -NoProfile -File .\tests\New-BenchmarkDataset.ps1 -DatasetId benchmark-large-50k-v1
```

That dataset definition maps to:
- dataset id: `benchmark-large-50k-v1`
- preset: `BalancedMediumHeavy`
- target devices: `50,000`
- target vulnerability rows: `1,500,000`
- seed: `20260322`
- output path: `.local\large-datasets\synthetic-50k-1_5m`

When you want to keep the large seed current and exercise the vulnerability-store merge path without regenerating 1.5M rows, create a shifted current-snapshot delta overlay with:

```powershell
pwsh -NoProfile -File .\tests\New-SyntheticSnapshotDelta.ps1 -SourcePath .\.local\large-datasets\synthetic-50k-1_5m -OutputPath .\.local\large-datasets\synthetic-50k-1_5m-delta-<date> -TargetLatestDate <yyyy-MM-dd>
```

That command:
- reuses the large canonical store as the base seed instead of rebuilding it
- writes a fresh `Machines_Current.json.gz` with shifted observation dates
- writes a new `VulnExport_<group>_<date>.json.gz` snapshot representing the next full bulk export date
- is intended for Azure replay paths that merge incoming snapshots into the existing canonical store

Capture a repeatable multi-run benchmark series against the standard dataset with:

```powershell
pwsh -NoProfile -File .\tests\Invoke-BenchmarkSeries.ps1 -BenchmarkDatasetId benchmark-medium-v1 -Iterations 3 -IncludePersistentLocalWorkflow
```

That command:
- ensures the durable benchmark dataset exists
- records each benchmark JSON under `.local\benchmark-series\`
- appends each run to `.local\benchmark-history\benchmark-history.jsonl`
- writes aggregate `series-summary.json` and `series-summary.md` artifacts

`Measure-BranchVsMainBenchmark.ps1` and `Invoke-BenchmarkSeries.ps1` default to Azure-only capture. Add `-IncludeLocalBenchmark` when you also want local timings in the same run, or `-LocalOnly` when you want to skip Azure entirely.

Function App timing semantics:
- `function_app.elapsed_seconds` now tracks active execution time when the runtime status blob is available
- `function_app.end_to_end_elapsed_seconds` retains invoke-to-finish timing for queue and cold-start review
- `function_app.pickup_delay_seconds` records the gap between admin invocation and active execution start

Capture a current-branch-only benchmark baseline with:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
pwsh -NoProfile -File .\tests\Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -CurrentBaselineName 'current-live' -DatasetPath .\exports-synthetic-live -ResultsOutputPath (Join-Path $PWD ('.local\current-baseline-live-' + $stamp + '.json'))

pwsh -NoProfile -File .\tests\Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -IncludeLocalBenchmark -CurrentBaselineName 'current-live-with-local' -DatasetPath .\exports-synthetic-live -ResultsOutputPath (Join-Path $PWD ('.local\current-baseline-live-with-local-' + $stamp + '.json'))
```

Append a normalized local history entry after a benchmark completes with:

```powershell
pwsh -NoProfile -File .\tests\Record-BenchmarkHistory.ps1 -BenchmarkResultPath .\.local\current-baseline-live-<timestamp>.json
```

Recommendations:
- keep raw benchmark outputs under `.local/`
- use `.local\benchmark-history\benchmark-history.jsonl` plus `.local\benchmark-history\latest-summary.md` for repeated review and Azure acceptance captures that you want to compare over time
- prefer `benchmark-medium-v1` plus `Invoke-BenchmarkSeries.ps1` when you need the durable, merge-tracked benchmark cadence instead of an ad hoc review capture
- prefer `benchmark-medium-v1` plus `Invoke-RoutineSemanticReview.ps1` when you need repeatable semantic review coverage without paying for the 50k/1.5m local replay
- prefer `benchmark-large-50k-v1` plus `New-SyntheticSnapshotDelta.ps1` when you need a reusable large Azure seed with a fresh incoming snapshot date
- use the staged local copy behavior in `Measure-BranchVsMainBenchmark.ps1` when benchmarking raw datasets without sidecars
- use `docs/performance-baselines.md` only for accepted durable datasets that should remain merge-tracked as baseline documentation
