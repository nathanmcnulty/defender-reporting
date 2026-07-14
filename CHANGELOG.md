# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Azure release package self-containment

#### Fixed
- Azure release packages now receive a generated, self-contained template publisher instead of relying on repository-only `build/` files.
- Package validation now exercises the staged and extracted template publisher with `-WhatIf`, and package manifests record its source fingerprint and payload hash.

## 2026-07-13

### Function App large-dataset validation

#### Added
- `build/Invoke-AzureDeploymentValidation.ps1 -SkipAutomationValidation` for isolated Function App validation when the paired Automation lane is being measured separately.

#### Validation
- The specified `func-defender-reporting` Function App completed the materialized 50K-device / 1.5M-row dataset with 1,484,239 published rows, 50,000 devices, and 5,000 CVEs.
- Hosted dashboard artifacts were published successfully. Azure Monitor measured an 816.3 MB peak working set and approximately 1,238,425,600 execution units for the Flex Consumption invocation.
- Temporary Function App settings and pre-validation `exports`/`dashboards` storage were restored and verified by manifest comparison.

## 2026-07-12

### Bounded content-store publication and Azure acceptance hardening

#### Changed
- Content-store publication now scatters observations to disk partitions and processes one device/content partition at a time. Staged fragments carry unresolved references between passes, so retained dictionary state follows the largest partition rather than the total number of rows.
- Partitioned dictionaries are marked with `deviceProfileOrder = "partitioned"`; ordering-dependent direct merge is skipped and the existing file-backed lookup is selected instead.
- Dictionary, partition, ref-projection, lookup-assembly, and cleanup phases now emit progress and memory checkpoints. Compiled projection telemetry records true working-set, private-memory, GC-heap, and pre/post-trim values.
- Compiled payload assembly releases completed lookup collections before copying the high-cardinality vulnerability stream, reducing transient overlap without changing the payload wire format.
- Azure normalization now preserves Advanced Hunting CVE/device-user/inventory data and NVD data, including their source metadata and cache identity.

#### Fixed
- Compiled machine lookup now preserves scalar `machineTags` values as one-element tag arrays, matching the compatibility reader's support for both scalar and array forms.
- Azure validation now compares large compiled payloads with bounded decompressed-byte equality and uses canonical expanded-row equivalence for modest compatibility workloads when lookup insertion order differs between processes.

#### Validation
- The final 50,000-device / 1,500,000-row generated workload completed in Azure Automation with 1,187,395 published rows, a 365.1 MB true working-set peak, and a 42.34-second compiled projection.
- The final published payload matched a fresh source projection exactly across 133,633,728 decompressed bytes.
- The checked-in `exports` dataset produced 7,640 source and dashboard rows with zero missing or extra canonical rows.
- Full repository validation passed, and the Azure runbook, exports, and dashboard storage state were restored after validation.

## 2026-04-21

### Azure Automation memory hardening and Stage D normalization tuning

#### Added
- `tests/New-SyntheticLegacyVulnSnapshotSet.ps1` to reconstruct deterministic legacy `VulnExport_<group>_<date>.json.gz` files from a raw canonical synthetic dataset without mutating the source path.
- `tests/Invoke-LargeImportCoverage.ps1` to automate the raw sidecar-free replay lane, local legacy vulnerability import validation, and Azure existing-export dataset prep in one command.

#### Changed
- Azure Automation machine refresh now stages current-machine snapshots and machine-history changes through streamed files instead of rebuilding the full in-memory store during publication.
- Runbook normalization instrumentation now captures the major Stage D memory checkpoints so Azure benchmark runs can isolate hot phases more reliably.
- Stage D machine normalization now carries a compact tuple form through the hot path before expanding the lookup structure consumed by payload generation.
- Azure Automation now opportunistically forces garbage collection at safe Stage C and Stage D boundaries to trade some runtime for lower peak memory pressure in the runbook path.
- Test documentation now distinguishes completed-dataset replay benchmarks from raw sidecar-free replay and live fresh-export validation so large import hot paths are reviewed explicitly.
- Large fresh-import evaluation can now stage deterministic legacy vulnerability snapshots alongside raw machine and Advanced Hunting replay files for `UseExistingExportsOnly=true` Azure Automation runs.

#### Fixed
- Replaced whole-file vulnerability current-file duplicate validation with a partition-bounded path so large fresh exports no longer allocate one global duplicate-id set.
- Removed the Stage C machine-store publication failure that was rewriting large machine current/history outputs through the highest-memory path during fresh-export Azure runs.
- Added explicit regression coverage for duplicate vulnerability current-file ids and retained the shared-helper regression path after the store changes.

#### Validation
- `tests/Run-SharedHelperRegression.ps1` passed after the Stage C and Stage D store changes.
- `build/Invoke-RegressionValidation.ps1` passed on the merged Stage C base plus the restored Stage D experiment.
- Azure Automation fresh-export validation completed successfully after the Stage C store hardening changes.
- The recorded `50K` device / `1.5M` row Azure Automation stress benchmark for the Stage D tuple path reduced the instrumented Stage D peak from `670.6 MB` to `645.1 MB` and improved elapsed time from `570.43 s` to `510.76 s` versus the instrumentation-only baseline.
- The later runbook-only GC hardening runs reduced the large Azure Automation replay peak GC heap to roughly `145 MB to 147 MB`, with working-set pressure generally below the pre-GC replay path.

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
