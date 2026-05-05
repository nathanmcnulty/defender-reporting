# Performance Gate Playbook

This playbook keeps performance work measurable while preserving memory headroom for Azure Automation and Function App deployments.

## Gate cadence

| Gate | When | Command | Primary output | Review threshold |
| --- | --- | --- | --- | --- |
| Deterministic preflight | Every PR and before any perf run | `pwsh -NoProfile -File .\build\Invoke-RegressionValidation.ps1` | parser, ScriptAnalyzer, fixture smoke | Must pass |
| Hot phase review | Every refactor that touches normalization, payload generation, validation, or Azure packaging | `pwsh -NoProfile -File .\tests\Invoke-HotPhaseReview.ps1 -DirectoryPath <dataset>` | `hot-phase-review.json`, stdout log, validation audit | Investigate generator or validation phases that regress by more than `5%` or materially shift relative ordering |
| Synthetic benchmark | After a change that appears to improve or regress performance | `pwsh -NoProfile -File .\tests\Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -DatasetPath <dataset> -ResultsOutputPath <path>` | branch benchmark JSON | Investigate local elapsed or peak memory regressions above `10%` |
| Local history capture | After any benchmark you expect to compare again later | `pwsh -NoProfile -File .\tests\Record-BenchmarkHistory.ps1 -BenchmarkResultPath <path>` | `.local\benchmark-history\benchmark-history.jsonl`, `latest-summary.md` | Use for longitudinal local tracking; do not update merge-tracked docs for one-off review datasets |
| Azure acceptance | Before merging perf-sensitive changes and before release packaging changes | `pwsh -NoProfile -File .\build\Invoke-AzureDeploymentValidation.ps1 -AutomationAccountName <name> -FunctionAppName <name>` | live Azure validation artifacts | Investigate runbook or Function App regressions above `10%`; investigate Function execution-unit growth above `15%` |
| Baseline refresh | After an accepted improvement or a durable dataset change | update `docs/performance-baselines.md` and keep raw JSON under `.local/` | doc summary plus local raw artifacts | Capture only after the new behavior is accepted |

## Dataset cadence

- Use `tests/fixtures/legacy-migration` only for correctness smoke checks.
- Use a smaller synthetic dataset for fast local hot-phase review while iterating.
- Use `benchmark-medium-v1` as the standard durable benchmark dataset for merge-tracked baseline work.
- Use ad hoc larger synthetic or shifted live synthetic datasets only for one-off investigation or stress review.
- Always use Azure for the final large-dataset acceptance check because local results do not predict Function App memory or execution-unit behavior well enough.
- When Azure acceptance runs with `-SkipMdePermissions`, pass `-FunctionExecutionDatasetPath <dataset>` so the Function App execution step reseeds deterministic exports before invocation.

Standard benchmark dataset:
- Dataset id: `benchmark-medium-v1`
- Generator: `pwsh -NoProfile -File .\tests\New-BenchmarkDataset.ps1 -DatasetId benchmark-medium-v1`
- Series capture: `pwsh -NoProfile -File .\tests\Invoke-BenchmarkSeries.ps1 -BenchmarkDatasetId benchmark-medium-v1 -Iterations 3 -IncludePersistentLocalWorkflow`
- Shape: `BalancedMediumHeavy`, `1,500` devices, `120,000` vulnerability rows, seed `20260322`

## Recommended workflow

1. Run the deterministic preflight.
2. Run `tests/Invoke-HotPhaseReview.ps1` on the representative local dataset you are using for the refactor.
3. If validation dominates, run `tests/Invoke-ValidationModeComparison.ps1` to split package-only, force-full validation, and attested validation into separate measured runs.
4. Review the top generator phases plus the audit `PhaseTimings` values from the hot-phase or validation-mode report.
5. Make one focused change at a time and re-run the relevant local review command.
6. Once the local review looks better, refresh `benchmark-medium-v1` if needed and capture a benchmark result with `tests/Measure-BranchVsMainBenchmark.ps1` or `tests/Invoke-BenchmarkSeries.ps1`.
7. If the change is still favorable, validate the large dataset in Azure.
8. Append the benchmark JSON to `.local` history with `tests/Record-BenchmarkHistory.ps1`.
9. Record accepted durable baselines in `docs/performance-baselines.md` and keep raw JSON artifacts under `.local/`.

Guardrails:
- `tests/Invoke-HotPhaseReview.ps1` now defaults to artifact parity review instead of semantic replay.
- Use `-ValidationMode semantic` only when you are intentionally investigating semantic audit cost or validating semantic changes.
- Large local semantic runs above the configured row limit require `-AllowLargeSemanticValidation` so they are not started accidentally.

Timing interpretation:
- Azure Automation already tracks active execution time from job start to job end.
- Function App benchmark summaries now treat `function_app.elapsed_seconds` as active execution time when the runtime status blob is available.
- Function App invoke-to-finish time remains available as `function_app.end_to_end_elapsed_seconds` so queue delay and cold-start variance can still be reviewed separately.

## Hot phase interpretation

- If `Load source data` dominates, focus on source readers, decompression paths, and unnecessary materialization.
- If `Normalize source data` dominates, focus on canonicalization, lookup creation, and repeated transforms.
- If `Prepare normalized payload` dominates, focus on payload compression, fallback serialization, and cache publication churn.
- If `Write dashboard` dominates, focus on payload embedding, split-assets behavior, and repeated template work.
- If validation dominates as a whole, run `tests/Invoke-ValidationModeComparison.ps1` before changing audit logic so you can separate package cost from semantic replay cost.
- If validation `Source signatures`, `Payload signatures`, or `Comparison` dominate, focus on attestation reuse, partition sizing, and unnecessary full semantic replays.

## Artifact checklist

- Keep raw review and benchmark output under `.local/`.
- Use `.local\benchmark-history\benchmark-history.jsonl` for repeated local and Azure benchmark captures that are useful for trend review but not yet durable enough for merge-tracked documentation.
- Treat `benchmark-medium-v1` as the durable baseline identity when you are updating merge-tracked baseline documentation.
- Treat `dashboard-audit.json`, `stress-validation-report.json`, and `hot-phase-review.json` as the canonical local review artifacts.
- Use the audit summary to explain why a validation run was slow before changing comparison logic.
- Do not tighten CI thresholds until the same dataset and command path have been repeated enough times to understand normal variance.