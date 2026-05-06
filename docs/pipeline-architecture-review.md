# Pipeline Architecture Review

This review captures the post-merge architecture decision after PR #37. It is based on the tracked source and maintainer docs, with generated outputs and local history treated as non-authoritative.

## Current Validated State

The current monolithic pipeline is no longer failing its Azure acceptance gate.

- Azure Automation passed on the 50k device / 1.5M row hosted dataset.
- The hosted Function App validation also completed successfully on the same dataset during the keeper merge acceptance run.
- The latest hosted Function App acceptance invocation was accepted at `2026-05-06T06:26:05Z` and wrote the dashboard blob at `2026-05-06T06:33:39Z`.
- Recent keeper changes already reduced transient normalization state, reused shared library caches, and hardened blob validation against Azure CLI data-plane failures on this machine.

That changes the architecture decision. A high-risk sharded rewrite is no longer the right immediate next step.

## Decision

Keep the current runtime architecture as the accepted baseline and name it `monolithic-v1`.

Treat a staged, shard-oriented rewrite as a contingency path, not the active implementation scope for this branch.

The next work should lock in observability, planning metadata, and escalation criteria so we can prove when a larger rewrite is actually required.

## Pipeline Map

1. API export
   - [Invoke-VulnerabilityExport.ps1](../Invoke-VulnerabilityExport.ps1) authenticates to Defender for Endpoint, downloads bulk vulnerability snapshots, refreshes machine data, optionally refreshes Advanced Hunting enrichment, and writes canonical gzip stores under `exports/`.
   - Shared export helpers live under `src/powershell/Shared/DefenderApi`, `src/powershell/Shared/Core`, and `src/powershell/Shared/Stores`.

2. Normalization
   - [Generate-VulnerabilityDashboard.ps1](../Generate-VulnerabilityDashboard.ps1) reads canonical stores, loads machine and enrichment data, and calls `ConvertTo-NormalizedData` from [DashboardGeneration.ps1](../src/powershell/Shared/Dashboard/DashboardGeneration.ps1).
   - Normalization can run from content-store sidecars or raw current/history rows and can reuse normalized column and payload caches under `.dashboard-cache/`.

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

This is the active branch scope.

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

### Stage 1: Baseline Capture and Triggering

Do this after Stage 0 is merged.

1. Capture durable post-acceptance benchmark baselines.
   - Use the repo performance workflow and Azure acceptance artifacts to record the accepted envelope for the current monolithic pipeline.

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

## First Implementation on This Branch

This branch implements Stage 0 only:

1. add architecture-version metadata to the pipeline status blob
2. add finer status transitions inside Stage D
3. surface the architecture version in the validation status summary

## Review Notes

- The export phase already uses staged partial vulnerability downloads and transactional machine store publishing, so this review does not replace those mechanisms.
- The validation attestation fast path remains payload-oriented. Dashboard runtime behavior is still covered by the Node dashboard assertion suite, semantic validation, and Azure acceptance runs.
- If `monolithic-v1` remains within the accepted Azure envelope, prefer smaller focused improvements over a speculative rewrite.
