# Changelog

All notable changes to this project will be documented in this file.

## 2026-04-05

### Benchmark and validation merge prep

#### Added
- Synthetic live-export generation for shifting a synthetic dataset forward to a target latest date.
- Current-only benchmark capture for the local runbook and Function App validation path.
- Streaming large-dataset dashboard audit helpers sourced from `validation/source/` and emitted into `validation-helpers.ps1`.
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
