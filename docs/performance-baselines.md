# Performance Baselines

This repository keeps the merge-tracked performance baseline as documentation instead of committing raw machine-local benchmark output.

Use `.local\benchmark-history\benchmark-history.jsonl` for local longitudinal tracking across repeated benchmark captures. Only update this document after the dataset and command path are durable enough to serve as a merge-tracked baseline.

Performance acceptance should record which benchmark lane was used:
- completed-dataset replay
- raw sidecar-free replay
- live fresh export

Do not compare those lanes as if they were interchangeable. Replay benchmarks are useful for steady-state normalization and packaging cost, while live fresh-export runs are the only coverage for Stage C import behavior and large MDE download/publish hot paths.

The raw result JSON files from the April 5, 2026 capture remain local-only under `.local/`. The April 20, 2026 ad hoc hosted review captures remain local-only under `.local/perf-triage/`, and the April 20, 2026 durable benchmark series remains local-only under `.local/benchmark-series/benchmark-medium-v1-20260420-004103/`.

## Recorded baselines

| Dataset | Command mode | Local | Runbook | Function App headline | Function timing notes |
| --- | --- | ---: | ---: | ---: | --- |
| `benchmark-medium-v1` | `current-only` durable series, 3 captures | `137.28s to 139.19s` | `91.69s to 114.19s` | `41.37s to 42.18s` | `active-execution`; end-to-end `43.10s to 43.43s`; pickup delay `1.24s to 1.73s` |
| `exports-synthetic` | `current-only` | `476.63s` | `250.45s` | `239.45s` | legacy `invoke-to-finish` |
| `exports-synthetic-live` | `current-only` | `2081.27s` | `957.14s` | `683.21s` | legacy `invoke-to-finish` |
| `review-synthetic-medium` | `current-only` Azure acceptance replay, 2 captures | `153.06s to 177.83s` | `96.94s to 105.19s` | `41.59s to 43.32s` | legacy `invoke-to-finish` |

## Persistent local cache workflow

| Dataset | Prime local run | Reuse after payload-cache eviction | Reuse elapsed delta | Normalize phase delta |
| --- | ---: | ---: | ---: | ---: |
| `benchmark-medium-v1` | `136.13s to 136.34s` | `45.44s to 45.49s` | `-90.90s to -90.66s` | `-87.92s to -84.95s` |
| `review-synthetic-medium` | `136.17s to 167.08s` | `45.47s to 45.66s` | `-121.42s to -90.70s` | `-109.95s to -84.52s` |

## Resource summary

| Dataset | Local peak RSS | Local peak private | Runbook peak WS | Runbook peak GC heap | Function peak WS | Function avg WS | Function execution units |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `benchmark-medium-v1` | `335179776 to 336478208` bytes | `236740608 to 238395392` bytes | `399.2 to 420.8 MB` | `88.8 to 105.4 MB` | `581.7 to 599.3 MB` | `581.7 to 599.3 MB` | `0.0` |
| `exports-synthetic` | `966336512` bytes | `921878528` bytes | `569.5 MB` | `286.8 MB` | `1800.9 MB` | `1276.2 MB` | `504217600` |
| `exports-synthetic-live` | `710160384` bytes | `616402944` bytes | `593.3 MB` | `298.2 MB` | `1029.2 MB` | `1029.2 MB` | `1172889600` |
| `review-synthetic-medium` | `333520896 to 341286912` bytes | `236150784 to 242094080` bytes | `407.6 to 412.5 MB` | `85.2 to 95.0 MB` | `580.6 to 587.6 MB` | `580.2 to 587.6 MB` | `0.0` |

## Capture notes

- Date captured: `2026-04-05` for the original synthetic replay baselines.
- Date captured: `2026-04-20` for the hosted `review-synthetic-medium` Azure acceptance replay.
- Date captured: `2026-04-20` for the durable `benchmark-medium-v1` three-iteration hosted benchmark series.
- Branch intent: current branch only, no `main` comparison.
- Dataset shapes:
  - `benchmark-medium-v1`: standard durable benchmark dataset generated from the catalog entry in `tests/benchmark-datasets.json` with preset `BalancedMediumHeavy`, seed `20260322`, `120000` rows, and `1500` devices.
  - `exports-synthetic`: original `20K` synthetic replay dataset.
  - `exports-synthetic-live`: shifted synthetic live-export dataset with a latest snapshot date of `2026-04-05`.
  - `review-synthetic-medium`: `BalancedMediumHeavy` review dataset with `120000` rows and `1500` devices, validated against Azure Automation `aa-defender-reporting` and Function App `func-defender-reporting-parallel-0404a`.
- `benchmark-medium-v1` is now the standard durable dataset for merge-tracked baseline refreshes and supersedes `review-synthetic-medium` for future benchmark-series captures.
- `benchmark-medium-v1` Function App headline timing now uses active execution time from the runtime status blob; end-to-end invocation time and pickup delay are recorded separately for queue and cold-start review.
- The durable `benchmark-medium-v1` persistent local cache reuse pass was effectively stable across reruns (`45.44s` to `45.49s`) and is the preferred baseline for normalized-column cache reuse.
- The hosted review baseline was captured twice on the same dataset and command path. This document records ranges because the cold local normalization pass moved more than the hosted paths across reruns.
- The local benchmark harness stages a private dataset copy before validation so raw datasets do not get mutated by sidecar regeneration during baseline capture.

## Regenerating the baseline

Replay baseline:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
pwsh -NoProfile -File .\tests\Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -CurrentBaselineName 'current-20k' -DatasetPath .\exports-synthetic -ResultsOutputPath (Join-Path $PWD ('.local\current-baseline-20k-' + $stamp + '.json'))
```

Shifted live baseline:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
pwsh -NoProfile -File .\tests\Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -CurrentBaselineName 'current-live' -DatasetPath .\exports-synthetic-live -ResultsOutputPath (Join-Path $PWD ('.local\current-baseline-live-' + $stamp + '.json'))
```

Durable benchmark series:

```powershell
pwsh -NoProfile -File .\tests\New-BenchmarkDataset.ps1 -DatasetId benchmark-medium-v1
pwsh -NoProfile -File .\tests\Invoke-BenchmarkSeries.ps1 -BenchmarkDatasetId benchmark-medium-v1 -Iterations 3 -IncludePersistentLocalWorkflow
```

Import-path spot checks:

```powershell
pwsh -NoProfile -File .\tests\Generate-SyntheticLargeExports.ps1 -OutputPath .\.local\large-datasets\synthetic-raw -IncludeRawRows -AllowLargeDataset
pwsh -NoProfile -File .\tests\New-SyntheticLiveExport.ps1 -SourcePath .\.local\large-datasets\synthetic-raw -OutputPath .\.local\large-datasets\synthetic-raw-live -SkipContentStoreSidecars -Force
pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-raw-live -Validate
pwsh -NoProfile -File .\tests\Measure-RunbookOnlyAzureBenchmark.ps1 -UseExistingExportsOnly:$false
```