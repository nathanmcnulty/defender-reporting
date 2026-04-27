# Test Coverage and Validation Review

This review focuses on the export, normalization, payload preparation, packaging, validation, Azure runtime, and performance validation surfaces. It intentionally leaves dashboard template, layout, and visual HTML review to a separate process.

## Executive Summary

The project already has a solid validation spine: a deterministic preflight, helper regression tests, generated artifact rebuild checks, dashboard JavaScript assertions, fixture smoke generation, live dry-run tooling, large synthetic validation lanes, benchmark harnesses, and Azure deployment validation scripts.

The biggest cache-integrity issue found during the pipeline review has been addressed on this branch: normalized payload cache hits now validate payload bytes against the manifest hash, package-only payloads fail fast on mismatch, normal cached reuse falls back to live normalization if a cache entry changes after lookup, and zero-byte JavaScript library cache files are refreshed instead of reused.

The main remaining risks are process and breadth gaps rather than a missing core validator:

1. Heavy live, large-dataset, and Azure acceptance gates are manual by design, with PR checklist attestation added on this branch.
2. Operator-facing freshness and enrichment metadata now exists in payload manifests, validation sidecars, and audits, but strict policy controls are still deferred.
3. Browser-level runtime smoke coverage for hosted output is available as an optional local Edge smoke, outside the default CI preflight.
4. Negative validation fixtures cover the highest-risk payload/package failures, with more attestation and baseline cases still available for future expansion.

## Current Coverage

### Deterministic Preflight

Entrypoint: `build/Invoke-RegressionValidation.ps1`

Covered today:

- Build manifest coverage for generated shared and validation helpers.
- Shared helper generation.
- Validation helper generation.
- Azure Automation runbook generation.
- Azure Function App entrypoint generation.
- PowerShell parser validation across source scripts and generated Azure runtime scripts.
- PSScriptAnalyzer warnings and errors across non-generated scripts.
- `tests/Run-SharedHelperRegression.ps1` focused helper and pipeline regression checks.
- `tests/Assert-Dashboard*.js` dashboard runtime logic assertions in the Node harness.
- Legacy migration fixture dashboard generation in both self-contained and hosted modes.
- Generated dashboard artifact structure checks through `tests/Validate-DashboardGeneratedArtifacts.js`.

Recent branch improvement:

- `.github/workflows/validate-dashboard.yml` now triggers this gate for changes under `tests/**`, `build/manifests/**`, `src/**`, and `azure/**`, in addition to the existing PowerShell, template, export, dashboard, and workflow paths. These inputs were already part of the gate's real dependency surface, but not all of them previously triggered the PR workflow.
- `tests/Run-SharedHelperRegression.ps1` now includes negative checks for hosted output with a missing payload asset and package-only payload/manifest mismatch.
- Payload manifests, validation sidecars, and audit outputs now carry source metadata for machine data, Advanced Hunting, NVD, normalization mode, and source file freshness.

### Live Export Dry Run

Entrypoint: `build/Invoke-LiveDashboardDryRun.ps1`

Covered today:

- Azure authentication path used by the scheduled update workflow.
- Defender API export path.
- Dashboard generation and validation from live exports.
- `dashboard-audit.json`, `dashboard-live-run-manifest.json`, and generated dashboard artifact capture.

Recommended use:

- Run before merging changes that affect live API export, authentication, scheduled workflow behavior, generated dashboard delivery, or shipped dashboard artifacts.

### Large Dataset and Import Lanes

Entrypoints:

- `tests/Invoke-LargeDatasetValidation.ps1`
- `tests/Invoke-LargeImportCoverage.ps1`
- `tests/New-BenchmarkDataset.ps1`
- `tests/New-SyntheticSnapshotDelta.ps1`

Covered today:

- Large synthetic generation.
- Raw sidecar-free replay.
- Artifact validation mode for faster iteration.
- Full semantic validation mode for final local sign-off.
- Legacy vulnerability snapshot replay preparation.
- Durable benchmark dataset registration.

Recommended use:

- For normalization, cache, payload, or validation changes, run the artifact gate during iteration and semantic validation before sign-off.
- For import-path changes, include a raw sidecar-free replay and legacy snapshot replay lane.
- For perf-sensitive changes, capture a benchmark series against `benchmark-medium-v1` before escalating to Azure acceptance.

### Azure Runtime Validation

Entrypoints:

- `build/Invoke-AzureDeploymentValidation.ps1`
- `tests/Measure-RunbookOnlyAzureBenchmark.ps1`
- `tests/Measure-BranchVsMainBenchmark.ps1`

Covered today:

- Azure deployment package rebuild.
- Automation runbook deployment and execution.
- Function App deployment and seeded execution.
- Runtime status blob diagnostics for Function App execution.
- Azure benchmark capture for elapsed time, memory, and Function execution-unit review.

Recommended use:

- Run before merging Azure packaging, Automation, Function App, release packaging, or perf-sensitive large-dataset changes.
- Prefer seeded deterministic exports when validating runtime behavior without depending on fresh API data.

## Gaps Worth Tackling

### 1. Freshness and Enrichment Metadata

Current state:

- Machine export failures during dashboard generation can still be warning-only.
- Advanced Hunting and NVD enrichment can still be intentionally absent.
- Payload manifests, validation sidecars, and audit outputs now expose source file freshness, record counts, and normalization mode.

Remaining recommendation:

- Add optional strict controls, such as `-RequireFreshMachineData` and `-RequireAdvancedHunting`, without changing default compatibility behavior.
- Add dashboard-facing operator summaries only after the separate template/HTML review decides how that information should be displayed.

### 2. Browser Runtime Smoke for Hosted Output

Current state:

- Node assertions and generated artifact checks catch many runtime and packaging regressions.
- Hosted split-assets output is structurally validated in the deterministic gate.
- `tests/Invoke-HostedDashboardRuntimeSmoke.ps1` can serve hosted output over HTTP and run a non-visual Microsoft Edge headless DOM smoke locally.

Remaining recommendation:

- Keep the smoke outside the default Ubuntu CI preflight unless a stable cross-platform browser dependency is introduced.
- Consider expanding the smoke to inspect report switching and console logs if a future Playwright dependency is accepted.

### 3. Negative Validation Fixtures

Current state:

- The regression suite covers important negative cases such as payload/manifest hash mismatch and empty library cache reuse.
- Fixture smoke generation validates a small legacy dataset, including hosted and self-contained packaging.
- The regression suite now validates missing hosted payload failure and package-only manifest mismatch failure.

Remaining recommendation:

- Add small, intentionally corrupted fixtures for validation-only behavior:
  - embedded payload SHA mismatch;
  - validation sidecar payload SHA mismatch;
  - stale attestation that should force full validation;
  - baseline audit row mismatch.
- These should be tiny and deterministic so they can run inside preflight without large-data cost.

### 4. Manual Gate Attestation

Current state:

- The docs clearly describe when to run large-dataset, live dry-run, and Azure validation gates.
- CI cannot cheaply run all heavy lanes on every PR.
- `.github/PULL_REQUEST_TEMPLATE.md` now records deterministic, live, large-dataset, Azure, and hosted-smoke gate decisions.

Remaining recommendation:

- Consider a future optional workflow that compares uploaded benchmark JSON against thresholds, without running the benchmark itself in CI.

### 5. Large Semantic Validation Cost

Current state:

- The full `synthetic-50k-1_5m` semantic sign-off provides high confidence, but it can take several hours on a local workstation.
- The current hot spots are signature generation for the source dataset and normalized payload, not the final partition comparison.
- The semantic lane now caches source and payload signature sets during a run, but routine branch validation still pays the full cost when those artifacts are not already available.

Remaining recommendation:

- Add a cheaper routine semantic-review lane that uses a deterministic medium or stratified dataset, then reserve the 50k/1.5m full semantic gate for release sign-off and high-risk normalization changes.
- Investigate durable signature cache artifacts keyed by source fingerprint, normalized payload `PayloadSha256`, semantic canonicalizer version, and validation helper version so repeat validations can reuse unchanged signatures safely.
- Evaluate whether source and payload signature partitioning can be parallelized without increasing memory pressure or destabilizing Azure Automation/Function App parity.
- Record phase timings from several local and Azure runs before setting thresholds, because the observed cost is dominated by host performance and dataset size.

## Recommended Review Exercises

Use these as a menu based on the changed surface.

| Changed surface | Minimum review | Expanded review |
| --- | --- | --- |
| Shared PowerShell helpers | `build/Invoke-RegressionValidation.ps1` | Focused helper tests plus large artifact gate if normalization, payload, cache, or validation behavior changed |
| Validation helpers | `build/Invoke-RegressionValidation.ps1` | `tests/Invoke-ValidationModeComparison.ps1` and large semantic validation |
| API export logic | `build/Invoke-RegressionValidation.ps1` | `build/Invoke-LiveDashboardDryRun.ps1 -UseExistingAzContext` and Azure fresh-export run |
| Normalization or payload shaping | `build/Invoke-RegressionValidation.ps1` | Large artifacts gate, large semantic sign-off, and benchmark series |
| Package-only or split-assets behavior | `build/Invoke-RegressionValidation.ps1` | Materialize with `-NormalizeOnly`, package with `-PackageOnly -DualPackage`, validate self-contained and hosted outputs |
| Azure runbook or Function App runtime | `build/Invoke-RegressionValidation.ps1` | `build/Invoke-AzureDeploymentValidation.ps1` with seeded Function App execution |
| Performance-sensitive changes | deterministic preflight | hot phase review, validation mode comparison, benchmark series, and Azure acceptance |

## Recommended Priority

1. Keep the workflow trigger broadening from this branch.
2. Keep the manifest, sidecar, and audit source metadata from this branch, then add strict freshness/enrichment controls in a separate behavior-focused change.
3. Keep the new negative hosted-payload and package-only mismatch checks, then add stale-attestation and baseline mismatch fixtures separately.
4. Keep the non-visual hosted browser runtime smoke as a local/manual gate until a cross-platform browser dependency is accepted.
5. Add a cheaper routine semantic-review lane and investigate durable signature cache reuse before making the 50k/1.5m semantic gate part of frequent validation.
6. Keep the PR checklist for manual heavy gates and revisit benchmark artifact threshold automation after several recorded runs establish normal variance.
