# Changelog

All notable changes to this project will be documented in this file.

## 2026-04-21

### Azure Automation memory hardening and Stage D normalization tuning

#### Changed
- Azure Automation machine refresh now stages current-machine snapshots and machine-history changes through streamed files instead of rebuilding the full in-memory store during publication.
- Runbook normalization instrumentation now captures the major Stage D memory checkpoints so Azure benchmark runs can isolate hot phases more reliably.
- Stage D machine normalization now carries a compact tuple form through the hot path before expanding the lookup structure consumed by payload generation.

#### Fixed
- Replaced whole-file vulnerability current-file duplicate validation with a partition-bounded path so large fresh exports no longer allocate one global duplicate-id set.
- Removed the Stage C machine-store publication failure that was rewriting large machine current/history outputs through the highest-memory path during fresh-export Azure runs.
- Added explicit regression coverage for duplicate vulnerability current-file ids and retained the shared-helper regression path after the store changes.

#### Validation
- `tests/Run-SharedHelperRegression.ps1` passed after the Stage C and Stage D store changes.
- `build/Invoke-RegressionValidation.ps1` passed on the merged Stage C base plus the restored Stage D experiment.
- Azure Automation fresh-export validation completed successfully after the Stage C store hardening changes.
- The recorded `50K` device / `1.5M` row Azure Automation stress benchmark for the Stage D tuple path reduced the instrumented Stage D peak from `670.6 MB` to `645.1 MB` and improved elapsed time from `570.43 s` to `510.76 s` versus the instrumentation-only baseline.

## 2026-04-05

### Benchmark and validation merge prep

#### Added
- Synthetic live-export generation for shifting a synthetic dataset forward to a target latest date.
- Current-only benchmark capture for the local runbook and Function App validation path.
- Streaming large-dataset dashboard audit helpers sourced from the validation helper source tree and emitted into `build/generated/validation-helpers.ps1`.
- Documented performance baselines for the recorded `20K` replay and shifted live synthetic datasets.

#### Changed
- Manual path-coverage harnesses were moved under `tests/manual/` and now default their outputs to ignored `.local` paths.
- Test documentation now distinguishes committed fixtures from manual harnesses and local-only benchmark output.

#### Fixed
- Current-only local benchmark runs now stage a private dataset copy so validation cannot mutate the source dataset in place.
- Regression fixture smoke runs now execute against temp copies so they do not recreate committed `.dashboard-cache` artifacts.
- Derived `.dashboard-cache` directories are now ignored consistently across the repository.

## 2026-03-26

### Stress-scale dashboard generation and pipeline hardening

#### Added
- Lossless vulnerability content-store sidecars:
  `VulnContentDictionary.json.gz`, `VulnCurrentRefs.json.gz`, and `VulnHistoryRefs_*.json.gz`.
- Synthetic large-dataset tooling for `20,000` and `50,000` device stress scenarios.
- Memory-guarded local stress execution, benchmark capture, and Azure job watch tooling.
- Cached normalization layers for observed-window results and normalized dashboard payloads.
- Release changelog tracking in this repository.

#### Changed
- Dashboard generation now supports content-store-backed normalization and compact embedded payloads.
- Embedded client libraries are assembled through lower-memory file-backed paths.
- PDF export continues to work through `pdfmake` and `html2canvas`; `html2pdf` is no longer embedded.
- Synthetic export generation now writes content-store artifacts directly and performs recursive cleanup of transient output.
- Azure Automation export synchronization now transfers only supported export artifacts instead of recursively syncing all `exports/` content.
- Local export refresh now keeps `exports/` self-maintaining by pruning stale derived artifacts after successful export.
- Sample PDF generation now replaces old dated samples transactionally after a successful full export run.

#### Fixed
- Reduced large-run memory pressure in local and Azure generation paths.
- Closed false-negative validation issues caused by the new payload shape.
- Hardened content-store preflight validation so partial dictionary-only outputs are rejected.
- Prevented stale `.dashboard-cache`, staging, and synthetic progress artifacts from polluting Azure stress runs.
- Fixed Azure runbook/watch issues discovered during `20K` and `50K` stress testing.

#### Validation
- Current-export optimized dashboard matched the legacy-format baseline exactly on key counts and row parity.
- PDF exports from optimized and legacy-format dashboards remained equivalent on meaningful output.
- Azure stress runs completed successfully for both `20K` and `50K` device datasets.

#### Operator notes
- `exports/.dashboard-cache` is a derived local build cache and is intentionally not committed.
- Consumers that parse the embedded dashboard payload directly must support the newer compact payload shape.
- Synthetic generation now defaults to content-store output.
- Azure runbook deployments should publish the updated runbook and matching template assets together.
