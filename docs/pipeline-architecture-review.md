# Pipeline Architecture Review

This review captures the post-merge architecture decision after PR #37 and the subsequent bounded-content-store acceptance work. Its acceptance results describe that historical configuration, not later changes. The compiled projector also supports machine and enrichment inputs; routing eligible smaller direct-payload workloads through it is an opt-in experiment whose broader acceptance remains separate. See the [roadmap](roadmap.md) for current status.

## Validated State at Review

At this review, the monolithic pipeline had a bounded high-cardinality content path and passed the Azure acceptance gate for the tested configuration.

- The disk-partitioned content-store publisher retains one device/content partition's maps and templates at a time and preserves the existing dictionary/ref wire formats.
- The compiled standard-payload projector releases completed lookup collections before vulnerability assembly and reports true transient memory telemetry.
- Azure Automation passed on the 50k device / 1.5M row hosted dataset with 1,187,395 onboarded rows, a 365.1 MB true working-set peak, and exact source/payload equality.
- The checked-in `exports` compatibility replay passed with 7,640 rows, including Advanced Hunting/NVD enrichment and scalar/array machine tags.
- The hosted Function App validation also completed successfully on the same dataset during the keeper merge acceptance run.
- The latest hosted Function App acceptance invocation was accepted at `2026-05-06T06:26:05Z` and wrote the dashboard blob at `2026-05-06T06:33:39Z`.
- Recent keeper changes already reduced transient normalization state, reused shared library caches, and hardened blob validation against Azure CLI data-plane failures on this machine.

That changes the architecture decision. A high-risk sharded rewrite is no longer the right immediate next step.

## Decision

Keep the runtime architecture as the accepted baseline and name it `monolithic-v1`. At this review, its accepted high-cardinality content-only normalization mode was `compiled-bounded-standard-payload`, while enriched or machine-backed workloads used the compatibility normalizer.

Treat a staged, shard-oriented rewrite as a contingency path, not the active implementation scope for this branch.

The next work should keep observability, planning metadata, and escalation criteria durable so we can prove when a larger rewrite is actually required.

## Pipeline Map

1. API export
   - [Invoke-VulnerabilityExport.ps1](../Invoke-VulnerabilityExport.ps1) authenticates to Defender for Endpoint, downloads bulk vulnerability snapshots, refreshes machine data, optionally refreshes Advanced Hunting enrichment, and writes canonical gzip stores under `exports/`.
   - Shared export helpers live under `src/powershell/Shared/DefenderApi`, `src/powershell/Shared/Core`, and `src/powershell/Shared/Stores`.

2. Normalization
   - [Generate-VulnerabilityDashboard.ps1](../Generate-VulnerabilityDashboard.ps1) reads canonical stores, loads machine and enrichment data, and calls `ConvertTo-NormalizedData` from [DashboardGeneration.ps1](../src/powershell/Shared/Dashboard/DashboardGeneration.ps1).
   - Normalization can run from content-store sidecars or raw current/history rows and can reuse normalized column and payload caches under `.dashboard-cache/`.
   - Large content-store publication is disk-partitioned. High-cardinality content stores use the compiled streaming projector with machine and Advanced Hunting/NVD inputs. Smaller workloads use the compatibility normalizer by default; eligible direct-payload workloads may opt into the compiled path for controlled validation.

3. Payload preparation
   - The generator writes a compressed payload with lookup tables plus vulnerability rows or columns.
   - `-NormalizeOnly` materializes the payload and manifest; `-PackageOnly` packages a previously materialized payload.

4. Dashboard packaging
   - `Write-DashboardArtifactBundle` combines templates, payload, pako, Chart.js, and the PDF export bundle into self-contained or hosted split-assets output.
   - `-DualPackage` writes both delivery modes from the same normalized payload.

5. Validation and delivery
   - `Invoke-DashboardValidation` and the audit helpers validate payload/source parity, enrichment, report semantics, and legacy fixture behavior.
   - Azure Automation and Function App entrypoints are built from [runbook-source.ps1](../build/azure/runbook-source.ps1) plus the manifest-driven helper bundle.

## Locked Plan

### Stage 0: Observability and Architecture Scaffolding

Completed. The runtime status includes `pipelineArchitectureVersion = monolithic-v1`, `pipelineArchitectureTrack = stage0-observability`, finer Stage D transitions, input cardinalities, and memory checkpoints.

1. Stamp the runtime path with explicit architecture metadata.
   - Emit `pipelineArchitectureVersion = monolithic-v1` in the Azure pipeline status blob.
   - Keep the current pipeline behavior unchanged.

2. Make Stage D diagnosable without a debugger.
   - Replace the single coarse `GenerateDashboard` runtime status with finer status transitions for cache reuse, normalization inputs, normalization, payload preparation, library preparation, template loading, and hosted/self-contained assembly.
   - When a normalized payload cache hit is available, the pipeline intentionally skips the normalization-input and normalization stages. Status reporting must make that path explicit instead of leaving operators to infer it.
   - Preserve the existing success/failure contract for the status blob so current tooling keeps working.

3. Surface the new metadata in the validation path.
   - Keep the current heartbeat and timeout logic.
   - Include architecture-version context in the Function App status summary so future Azure regressions are attributable to a known execution model.

4. Record the decision in tracked docs.
   - This file is the decision record for keeping `monolithic-v1` as the accepted baseline until a concrete trigger forces a larger rewrite.

### Stage 1: Bounded-path acceptance and triggering

The bounded content-store and compiled standard-payload path is now accepted. Continue to refresh durable baselines after behavior or dataset changes.

1. Capture durable post-acceptance benchmark baselines.
   - Use the repo performance workflow and guarded Azure validation artifacts to record separate completed-replay, raw sidecar-free, and fresh-export envelopes.

2. Add explicit rewrite triggers.
   - Escalate only if repeated Azure acceptance runs regress materially or fail.
   - Use the existing repo thresholds as the minimum review bar: investigate elapsed or working-set regressions above `10%`, and investigate Azure Function execution-unit growth above `15%`.

### Stage 2: Resume-Oriented Enhancements

Only start this if Stage 1 shows that observability is not enough.

1. Add source fingerprint and payload lineage metadata to the runtime status or sidecar path.
2. Add explicit resume checkpoints around already-materialized payload reuse.
3. Keep the current payload contract unchanged.

### Stage 3: Staged Rewrite Contingency

Only start this if the accepted `monolithic-v1` path regresses again.

1. Introduce durable shard planning and shard-local normalization artifacts.
2. Stream the global reduce and final materialization phases.
3. Gate the staged path behind an explicit architecture-version setting and preserve the current payload contract until parity is proven.

## Escalation Triggers

Start the staged rewrite only when at least one of these conditions becomes true:

1. Two consecutive hosted Function App Azure acceptance runs fail on the standard 50k / 1.5M dataset.
2. Hosted Function App Azure acceptance regresses materially beyond the accepted baseline and keeps doing so after localized fixes.
3. Operational requirements demand resumability across invocations rather than a single successful monolithic run.

## Current implementation record

The accepted implementation includes the original Stage 0 observability work plus:

1. disk-partitioned transactional content-store publication with partition-order metadata
2. compiled streaming standard-payload projection with pre-trim telemetry and early lookup release
3. Azure source-artifact validation and bounded source-to-dashboard semantic comparison
4. compatibility preservation for machine/enrichment inputs, optional fields, Unicode, legacy arrays/NDJSON, and scalar or array machine tags

## Review Notes

- The export phase already uses staged partial vulnerability downloads and transactional machine store publishing, so this review does not replace those mechanisms.
- The generated runbook remains derived from `build/azure/runbook-source.ps1`; deployment validation backs up and restores the published runbook and storage state.
- The validation attestation fast path remains payload-oriented. Dashboard runtime behavior is still covered by the Node dashboard assertion suite, semantic validation, and Azure acceptance runs.
- If `monolithic-v1` remains within the accepted Azure envelope, prefer smaller focused improvements over a speculative rewrite.
