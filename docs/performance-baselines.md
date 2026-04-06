# Performance Baselines

This repository keeps the merge-tracked performance baseline as documentation instead of committing raw machine-local benchmark output.

The raw result JSON files from the April 5, 2026 capture remain local-only under `.local/`.

## Recorded baselines

| Dataset | Command mode | Local | Runbook | Function App |
| --- | --- | ---: | ---: | ---: |
| `exports-synthetic` | `current-only` | `476.63s` | `250.45s` | `239.45s` |
| `exports-synthetic-live` | `current-only` | `2081.27s` | `957.14s` | `683.21s` |

## Resource summary

| Dataset | Local peak RSS | Local peak private | Runbook peak WS | Runbook peak GC heap | Function peak WS | Function avg WS | Function execution units |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `exports-synthetic` | `966336512` bytes | `921878528` bytes | `569.5 MB` | `286.8 MB` | `1800.9 MB` | `1276.2 MB` | `504217600` |
| `exports-synthetic-live` | `710160384` bytes | `616402944` bytes | `593.3 MB` | `298.2 MB` | `1029.2 MB` | `1029.2 MB` | `1172889600` |

## Capture notes

- Date captured: `2026-04-05`
- Branch intent: current branch only, no `main` comparison
- Dataset shapes:
  - `exports-synthetic`: original `20K` synthetic replay dataset
  - `exports-synthetic-live`: shifted synthetic live-export dataset with a latest snapshot date of `2026-04-05`
- The local benchmark harness now stages a private dataset copy before validation so raw datasets do not get mutated by sidecar regeneration during baseline capture.

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