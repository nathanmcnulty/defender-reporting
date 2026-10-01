# Tests

This folder contains lightweight PowerShell regression coverage for the Defender reporting pipeline.

## Layout

- `tests/fixtures/` contains committed, minimal synthetic regression datasets, never live exports.
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

## Guarded worker-transfer measurements

`Measure-DashboardWorkerTransfer.js` is a Windows/Edge measurement harness, not a worker-transfer optimization. Its browser-free safety probes also run through the existing telemetry regression in deterministic preflight:

```powershell
node .\tests\Measure-DashboardWorkerTransfer.js --mock
node .\tests\Measure-DashboardWorkerTransfer.js --ownership
node .\tests\Measure-DashboardWorkerTransfer.js --privacy
node .\tests\Assert-DashboardTelemetry.js
```

For an actual measurement, set `PLAYWRIGHT_MODULE` to an installed Playwright module and supply the retained Hosted dashboard directory, a private evidence destination, repeats (1-10), and an explicit expected normalized row count:

```powershell
node .\tests\Measure-DashboardWorkerTransfer.js .\.local\two-row-control .\.local\worker-control.json 1 2 --positive-control
```

Use the committed `fixtures/legacy-migration` dataset through the normal generator for the two-row control; never infer a large normalized count from raw source observations. Run full deterministic preflight first. A smaller PowerShell preflight memory guard does not lower the browser guard. Existing automation Edge sessions must be cleared by their owner before starting a separate measurement; personal browsers must remain untouched.

Actual browser controls require real Chart.js and pako libraries. Offline regression placeholder assets intentionally do not initialize those globals and are rejected before measurement; do not reuse preflight placeholder output as a live browser control. Payload provenance is streamed through gzip validation and SHA-256 hashing, retaining compressed/decompressed byte counts and hashes without a full payload parse in Node. The retained HTML and immutable asset paths stay unchanged; only the current manifest-assembled dashboard runtime is served in place of the retained runtime script.

The harness requires at least 2 GiB free RAM before launch and throughout sampling, caps the owned Edge family at 3 GiB, and bounds readiness at 120 seconds. Inventory is asynchronous, single-flight, fail-closed, and starts before launch, then immediately after spawn before CDP polling. Every successful run must pass an awaited final resource sample. Caps, floor breaches, inventory exceptions, and other aborts immediately request bounded termination of only the spawned/profile-owned family. Cleanup attempts process termination, launcher exit, CDP/browser closure, final inventory, profile removal, and HTTP server closure independently. Unknown remaining process state is not zero or success. Original measurement errors remain separate from fixed cleanup failure labels; raw stacks, command lines, and profile paths are not evidence fields.

`ttiBrowserMs` records the first browser `dashboard-ready` event using `performance.now()` from navigation time origin; it is a readiness measure, not interaction latency. Host observation wall time and later snapshot time are separate. Memory samples carry host monotonic and epoch timestamps, with browser phase/message epoch timestamps for correlation. Phase observations and process working-set peaks are sampled, not instantaneous boundaries or proven absolute peaks. Heap scope is the main renderer only. Heap/readiness instrumentation adds measurement overhead. Worker return format labels distinguish phase messages, legacy arrays, row envelopes, and lookup/raw-column envelopes without changing the runtime payload contract.

Family private memory is also sampled, but the unchanged family cap applies to working set. Observational CDP heap/readiness probes are single-flight and may stall during main-thread work; they do not impose a separate five-second initialization deadline. Final probe drain is bounded to five seconds before cleanup proceeds; a drain timeout sets `incompleteHeapSample` rather than manufacturing a heap measurement or a resource-guard failure. The independent process inventory retains its own timeout and fail-closed guards. Scalar initialization traces fail promptly on a caught initialization error and retain only error class, function names, and source positions, never raw messages, stacks, or payload records. Worker markers are retained at the first valid readiness snapshot even if a later report/guard check fails. A partial readiness snapshot is not a passed run, and its `activeRows` means filtered source rows, not grouped active report rows.

Normalized counts must equal the explicit expectation and agree across cold/reload runs. Required report renders, impact/filtered-source counts, severity-card hashes, and `readinessCacheDigest` must agree; this is readiness/cache consistency, not report-content semantic validation. Equal zero counts alone do not establish report coverage. The explicit two-row `--positive-control` clears both date fields through the existing date popover (unrestricted custom range), requires both source rows selected and bounded positive impact/card totals, and compares those observations across cold/reload. This avoids fixture dates falling outside today's default history window; it does not validate every grouped report field. The harness inspects the matching compressed-fingerprint IndexedDB entry and the runtime's row/entry limits. Eligible reloads must actually hit cache; ineligible reloads are labelled `cachedEligible: false` with an explicit reason, never forced into the cached lane. There is currently no separate byte soft limit or cache feature flag. Production cache writes remain disabled at 500,000 rows and above. A passed mock, small control, or full preflight cannot establish a large-data performance result.

Profile ownership uses native Windows argument parsing, a single exact profile switch (equals or separate-value form), fully qualified path normalization, slash normalization and ordinal case-insensitive comparison. Prefix neighbors, literals inside other arguments, relative paths and duplicate profile switches are excluded. Descendant closure retains root creation provenance; fresh snapshots and process start identities are checked before each kill. No unchecked `taskkill /T` or launcher-PID kill is used. Windows browser-free probes run the actual PowerShell code against mocked process APIs, including surviving neighbors and root PID reuse; they never kill real processes. All command-entry and evidence-write failures emit fixed labels with allowlisted phase/reason/code fields, never raw messages, exception names, stacks, URLs, query keys, tokens or paths. Instrumentation retains only allowlisted function/phase names and numeric positions. Metric snapshots are copied so later mutations remain observable; absent optional instrumentation is tolerated.

## Hosted smoke diagnostics

Run the isolated two-row Hosted dashboard control, generated from synthetic data without root exports, authentication, or cloud writes:

```powershell
pwsh -NoProfile -File .\tests\Invoke-HostedDashboardRuntimeSmoke.ps1 -ControlFixture
pwsh -NoProfile -File .\tests\Invoke-HostedSmokeDiagnosticsRegression.ps1
```

The control copies the committed two-row synthetic legacy fixture into temporary storage and generates Hosted output through the normal generator with machine export disabled. The browser smoke first runs a JavaScript canary, then the real dashboard readiness/report-switching/filter-popover probe, sequentially with the same unique temporary Edge profile. An existing extension/automation Edge session blocks new launches; personal browsers are never terminated. Arguments use .NET `ProcessStartInfo.ArgumentList`, including profile paths containing spaces. An exit code of zero with empty or whitespace DOM is a failure, not a pass or skip. Probe state, phase, reason, and class (`timeout`, `assertion`, `operation`, or `none`) are allowlisted enums, never literal DOM, exception types, or error messages. Markers are assigned before readiness, payload, inflate, count, report-switch, and filter-popover operations; setup failures retain fixed phase/class labels and a source line number.

Every started run retains sanitized diagnostics, on failure and success, in ignored `.local/hosted-smoke-diagnostics/hosted-smoke-<UTC timestamp>-<random ID>/`. `-DiagnosticsPath <directory>` selects a caller-owned root using the same deterministic prefix; keep that root private and out of version control. Errors print only the run ID and fixed outcome. `run.json` records outcome and cleanup; `canary.json` and `dashboard.json` retain exit codes, byte counts, capture limits, conventional scrubbed flags, and fixed states. Sibling `*.stderr.sanitized.log` files contain at most 128 category/redacted-example/SHA-256 records. Recognized Chromium sources map to fixed categories; unknown lines are hashed, never copied. No raw stderr examples, URLs, user paths, project metadata, DOM, stdout, or profile content is retained in these artifacts.

Streams drain concurrently in memory: stdout retains at most 64 MiB for assertions; stderr retains at most 64 KiB for sanitization while byte counting continues. Truncated DOM or incomplete drains fail. Process enumeration/termination, server stop/wait/removal, profile removal, site removal, and final diagnostic write are independently guarded. `run.json` retains `originalOutcome`, `processCleanupConfirmed`, and fixed `cleanupFailures`; unknown process state is not a clean result. Diagnostic write failure emits only `diagnostic-write-failure`; when the destination is unavailable, the final record cannot be retained. Cleanup never replaces a pending original exception, and success is emitted only after cleanup. The PowerShell regression exercises the actual helper and extracted entire `finally`, including a real missing-directory provider write. The extracted-probe JavaScript regression uses a virtual clock to distinguish readiness timeout from payload assertion and operation failures. SHA-256 records are fingerprints, not reversible examples, but low-entropy text can still be guessed; treat diagnostics as private. Raw captured text is transient managed memory, not guaranteed cryptographically erased.

`headless-control-failure` means the canary failed too; `dashboard-probe-failure` means the canary passed but the dashboard did not; `command-forwarding-suspected` requires recognized forwarding stderr. A missing forwarding hint does not rule forwarding out. These controls diagnose an empty-DOM environment; they do not turn a blocked browser launch into a dashboard pass. The browser-free injected-process/privacy regression is part of deterministic preflight; actual Edge remains a separate optional Windows gate.

## CI-aligned live dry run

Run the exact live export and dashboard-generation path locally against your current Az context with:

```powershell
pwsh -NoProfile -File .\build\Invoke-LiveDashboardDryRun.ps1 -UseExistingAzContext
```

Defaults:
- output root: `.local/local-reports/live-dashboard-dry-run/`
- includes Advanced Hunting by default
- writes `dashboard-audit.json` and `dashboard-live-run-manifest.json` alongside the generated HTML

Use `-UseRepositoryOutputPaths` only when you intentionally want the live dry run to write into the ignored local `exports/` and `VulnerabilityDashboard.html` paths. Keep all live outputs private and out of logs and PR evidence.

## Legacy migration fixture

`tests/fixtures/legacy-migration` contains a tiny synthetic dataset used to exercise the temporary legacy vulnerability migration path.

Important note:
- the fixture files named `*.json` are intentionally a mix of formats
- `VulnExport_*.json` and `AdvancedHunting_Current.json` are NDJSON-style files, where each line is an individual JSON object
- `Machines_Current.json` is a single JSON object

These shapes match what the pipeline readers already support, even though NDJSON files are not a single valid JSON document when opened in a generic JSON validator.

The fixture smoke runs in `build/Invoke-RegressionValidation.ps1` and the legacy fixture regression path both execute against temp copies so derived `.dashboard-cache/` output does not pollute the committed fixture.

Automated regression checks do not require root `exports/`, a generated root dashboard, or report PDFs. Cardinality fallback uses a temporary one-device/one-template dictionary without a synthetic manifest. Procedural ordering keeps two fresh-process 12-device/300-row runs; semantic replay keeps 50 devices/5,000 observations. Hot-phase smoke generates a pinned 16-device/240-observation dataset (seed 4242, date 2026-07-11) in temp storage. All temporary datasets and dashboards are cleaned up after the checks.

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

The procedural generator defaults `-SourcePath` to `tests/`, an existing neutral directory; it does not read source exports. Use an explicit synthetic fixture path with `-UseLegacyGenerator`, which does read its source. Benchmark workload definitions also use the neutral `tests/` directory. Memory and disk guards for large workloads remain enabled.

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
pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -Validate -ValidationMode semantic -ForceFullValidation
```

That semantic mode additionally writes `dashboard-audit.json` under `exports-synthetic/` and forces a fresh full semantic replay instead of reusing an attested validation sidecar.

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

Switch that final command to `-ValidationMode semantic -ForceFullValidation` only when you need the full streaming semantic replay before sign-off.

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

## Bounded Azure acceptance

For a final large-data acceptance run, use the guarded validation harness rather than invoking a runbook job manually. It backs up the published runbook and the `exports`/`dashboards` containers, deploys the generated candidate, seeds the selected dataset, downloads the published dashboard, verifies required artifacts and counts, performs source-to-dashboard parity, and restores the previous state in `finally` cleanup. Every Azure CLI operation must target the intended subscription explicitly.

Candidate deployment and restoration send the file's raw bytes to the ARM runbook draft-content endpoint (`2023-11-01`, `text/powershell`), then publish. This preserves CRLF/LF, UTF-8 BOMs, and trailing newlines that CLI text ingestion can normalize. Restoration downloads the published content and checks its SHA-256 against the backup, along with every export/dashboard file's bytes and hash. `-FailureInjectionPoint AfterDeploy -ExpectedTotalRows 1 -Execute -Confirm:$false` exercises backup, deployment, and restoration without seeding exports or starting a runbook job; the injected error is expected only when restoration evidence also matches.

Example for the prepared generated 50K raw replay seed (the raw replay lane publishes 1,187,395 onboarded rows):

Count preflight accepts only an explicitly supplied `-ExpectedTotalRows` or authoritative numeric `expectedDashboardRows` in `synthetic-manifest.json` (for example, `"expectedDashboardRows": 1187395`). Counts must be whole numbers from 1 through 50,000,000. An explicit parameter takes priority, even when manifest metadata is malformed or has the wrong type. `actualTotalVulnRows` and `actualCurrentRows` count source observations, not onboarded normalized dashboard rows, and are never inferred as the expectation. Observation-only manifests, including existing generated datasets, require the parameter; determine it from a verified projection for the exact dataset and replay lane, not device ratios. Missing or invalid expectations fail before output/lock creation or Azure calls; preflight does not normalize the dataset.

```powershell
pwsh -NoProfile -File .\tests\Invoke-AzureRunbookValidation.ps1 `
  -SubscriptionId '43babb60-9e73-4dc8-b769-4401c01aad73' `
  -AutomationAccountName 'aa-defender-reporting' `
  -AutomationResourceGroup 'rg-defender-reporting' `
  -RunbookName 'Invoke-DashboardPipeline' `
  -StorageAccountName 'stdefenderrepaad73' `
  -DatasetPath .\.local\fast-large-import `
  -SeedMode ContentReplay `
  -DashboardDeliveryMode Hosted `
  -ExpectedTotalRows 1187395 `
  -UseExistingExportsOnly `
  -ValidatePublishedSemanticParity `
  -Execute -Confirm:$false
```

The harness uses exact decompressed payload bytes for the high-cardinality compiled path. For modest compatibility workloads, enrichment lookup insertion order may legitimately change the serialized bytes, so parity falls back to canonical expanded-row equivalence. A successful acceptance must still have zero missing and zero extra rows, valid current/history/dictionary/ref artifacts, and a true pre-trim working-set peak below the 400 MB Automation ceiling. The status evidence records working set, private memory, GC heap, phase, row count, and compiled telemetry; keep the timestamped result under `.local\azure-validation\`.

Compatibility gates use synthetic enrichment regressions and temporary copies of the minimal legacy fixtures, not checked-in live exports. When changing enrichment or machine lookup code, retain coverage for Advanced Hunting CVE/device-user/inventory data, NVD data, scalar and array machine tags, Unicode, and optional properties; a content-only synthetic dataset alone is insufficient.

When the Function App is the isolated subject of a test, add `-SkipAutomationValidation` to the build validation command. The default still validates both compute paths; the switch only avoids running the paired Automation deployment/validation while preserving Function App deployment, seeding, execution, status polling, and temporary-setting cleanup.

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
pwsh -NoProfile -File .\tests\New-BenchmarkDataset.ps1 -DatasetId benchmark-large-50k-v1 -AllowLargeDataset
```

Benchmark seeds now use the deterministic `procedural-v1` model and compiled streaming writer by default. The seed, model version, cardinalities, generation date, churn, and sparsity settings are recorded in `synthetic-manifest.json`; repeat runs with the same settings produce byte-stable gzip data artifacts.

The procedural writer is intentionally streaming: it derives devices, templates, observations, and edge cases from `seed + ordinal + snapshot`, writes JSON/gzip artifacts directly through the embedded writer, and avoids a global source-row or signature cache. Use `-GenerationDate`, `-SnapshotCount`, `-ChurnRate`, `-ContentTemplateCount`, and `-OptionalFieldSparsity` to vary a reproducible dataset without changing the public entrypoint. Keep `-UseLegacyGenerator` only for comparison runs; it is not the bounded-memory acceptance path.

That dataset definition maps to:
- dataset id: `benchmark-large-50k-v1`
- preset: `BalancedMediumHeavy`
- target devices: `50,000`
- target vulnerability rows: `1,500,000`
- seed: `20260322`
- output path: `.local\large-datasets\synthetic-50k-1_5m`

Each generated benchmark dataset now records durable breadth counters in both `synthetic-manifest.json` and `benchmark-dataset.json`:
- `uniqueCveIdCount`: distinct raw `CveId` values present in the compact content dictionary
- `normalizedCveLookupCount`: distinct normalized CVE lookup entries (`CveId` + score/severity/exploitability/url/title), which is the same breadth surfaced as `CVEs` in dashboard and Azure acceptance summaries
- `contentTemplateCount`: distinct compact vulnerability content templates in the dataset

Use those counters when you need to compare regenerated benchmark breadth over time without unpacking the dataset by hand.

When you want to keep the large seed current and exercise the vulnerability-store merge path without regenerating 1.5M rows, create a shifted current-snapshot delta overlay with:

```powershell
pwsh -NoProfile -File .\tests\New-SyntheticSnapshotDelta.ps1 -SourcePath .\.local\large-datasets\synthetic-50k-1_5m -OutputPath .\.local\large-datasets\synthetic-50k-1_5m-delta-<date> -TargetLatestDate <yyyy-MM-dd>
```

That command:
- reuses the large canonical store as the base seed instead of rebuilding it
- writes a fresh `Machines_Current.json.gz` with shifted observation dates
- writes a new `VulnExport_<group>_<date>.json.gz` snapshot representing the next full bulk export date
- is intended for Azure replay paths that merge incoming snapshots into the existing canonical store
- defaults to `AdvanceSnapshot`, which hard-links unchanged seed artifacts and procedurally writes only `Machines_Current.json.gz`, new grouped `VulnExport_*_<date>.json.gz` snapshots, and overlay metadata
- supports `-Mode ShiftAllDates` for legacy datasets that do not contain `procedural-v1` model metadata

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

For branch-vs-main captures, `Measure-BranchVsMainBenchmark.ps1` now records both the requested and effective baseline execution order plus `comparison.delta_basis = current-minus-main`.

- `-BaselineExecutionOrder Alternate` (default) flips who runs first across repeated captures so one branch is not always measured first.
- `-BaselineExecutionOrder CurrentThenMain` always runs the current branch first.
- `-BaselineExecutionOrder MainThenCurrent` always runs main first.
- Negative elapsed or memory deltas favor the current branch; positive deltas mean the branch was slower or used more memory.

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
