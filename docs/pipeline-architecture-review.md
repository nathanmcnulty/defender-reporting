# Pipeline Architecture Review

This review covers the Defender reporting data path from API export through dashboard generation. It is based on the tracked source and maintainer docs, with generated outputs and local history treated as non-authoritative.

## Pipeline Map

1. API export
   - [Invoke-VulnerabilityExport.ps1](../Invoke-VulnerabilityExport.ps1) authenticates to Defender for Endpoint, downloads bulk vulnerability snapshots, refreshes machine data, optionally refreshes Advanced Hunting enrichment, and writes canonical gzip stores under `exports/`.
   - The shared export helpers live in [MdeExport.ps1](../src/powershell/Shared/DefenderApi/MdeExport.ps1), with store layout helpers in [Core.ps1](../src/powershell/Shared/Core/Core.ps1), [VulnerabilityStore.ps1](../src/powershell/Shared/Stores/VulnerabilityStore.ps1), [VulnerabilitySnapshotImport.ps1](../src/powershell/Shared/Stores/VulnerabilitySnapshotImport.ps1), and [MachineStore.ps1](../src/powershell/Shared/Stores/MachineStore.ps1).

2. Normalization
   - [Generate-VulnerabilityDashboard.ps1](../Generate-VulnerabilityDashboard.ps1) reads canonical stores, optionally refreshes machine data, loads Advanced Hunting and NVD enrichment, and calls `ConvertTo-NormalizedData` from [DashboardGeneration.ps1](../src/powershell/Shared/Dashboard/DashboardGeneration.ps1).
   - Normalization can run from content-store sidecars or raw current/history rows. It can also reuse normalized column caches and normalized payload caches under `.dashboard-cache/`.

3. Payload preparation
   - The generator writes a compressed payload with lookup tables plus vulnerability rows or columns. `-NormalizeOnly` can materialize this payload and its manifest; `-PackageOnly` can package a previously materialized payload.
   - Cache identity comes from `Get-DashboardPayloadCacheFingerprint`, which depends on vulnerability, machine, Advanced Hunting, NVD, and normalization-mode inputs.

4. Dashboard packaging
   - `Write-DashboardArtifactBundle` combines templates, payload, pako, Chart.js, and the PDF export bundle into either a self-contained HTML file or a hosted split-assets directory.
   - `-DualPackage` writes both delivery modes from the same normalized payload.

5. Validation and delivery
   - `Invoke-DashboardValidation` and the audit helpers validate payload/source parity, enrichment, report semantics, and legacy fixture behavior.
   - Azure Automation and Function App entrypoints are built from [runbook-source.ps1](../build/azure/runbook-source.ps1) plus the manifest-driven helper bundle.

## Findings

### Addressed on This Branch

1. Cache fingerprints include file timestamps after computing content hashes.
   - `Get-FileSetFingerprint` already computes SHA-256 for every source file, but it also includes `LastWriteTimeUtc.Ticks` in the fingerprint material.
   - Result: identical export content with a different timestamp misses the normalized payload, observed-window, and related caches. This is inefficient and especially expensive for large datasets because cache lookup already paid the cost of content hashing.
   - Branch result: file-set fingerprints are now content-addressed by file identity, length, and SHA-256. A regression proves timestamp-only changes do not invalidate cache identity while content changes still do.

2. Normalized payload cache entries are trusted without verifying the cached payload bytes against the manifest hash.
   - `Get-NormalizedPayloadCacheEntry` checks the cache fingerprint and manifest fingerprint, but it does not verify that `PayloadSha256` still matches the payload file.
   - Result: a partial or corrupted cached payload can be reused until a later phase happens to detect it.
   - Branch result: cached payload bytes are validated against manifest `PayloadSha256` before returning a cache hit. Normal generation treats mismatches as cache misses and rechecks after copy; `-PackageOnly` fails fast when a provided manifest hash does not match the provided payload.

3. JavaScript library cache reuse accepts zero-byte files.
   - `Save-JSLibraryFile` reuses any cached library path that exists.
   - Result: a failed or interrupted previous download can poison later self-contained and hosted dashboard packages.
   - Branch result: empty cached library files are rejected and refreshed, and new downloads are verified as non-empty before caching or packaging.

4. Operator-visible data freshness and enrichment metadata is thin.
   - Machine export failures during dashboard generation are warning-only and reuse existing machine data. Advanced Hunting enrichment is optional and may be intentionally absent.
   - Result: operators need better metadata to distinguish intentional offline generation from degraded freshness or enrichment.
   - Branch result: payload manifests, validation sidecars, and audit outputs now carry source summaries for machine data, Advanced Hunting, NVD, normalization mode, and source file freshness. Strict freshness/enrichment policy remains a compatibility-preserving follow-up.

### Deferred Follow-Ups

1. Add a strict freshness mode for machine data.
   - Candidate: `-RequireFreshMachineData` or `-AllowStaleMachineData` with a configurable maximum age and validation-sidecar metadata.

2. Add explicit Advanced Hunting expectation controls.
   - Candidate: `-RequireAdvancedHunting` plus policy around the source count metadata now emitted in manifests, sidecars, and audits.

3. Expand JavaScript fixture coverage for `columns-v1` payloads.
   - Validation helper coverage already canonicalizes rows and columns, but the browser-side assertion scripts should exercise column payloads too.

4. Add machine-history continuity diagnostics.
   - Candidate: warn when quarterly history files have unexpected gaps, overlaps, or out-of-order observed dates.

## Implementation Plan

1. Harden cache identity and cache hit validation.
   - Remove timestamp material from `Get-FileSetFingerprint`.
   - Add normalized payload manifest hash confirmation and use it in cache lookup plus package-only manifest handling.

2. Harden dashboard library caching.
   - Refresh empty cached library files.
   - Treat empty fresh downloads as failed downloads before cache publish.

3. Add focused regression coverage.
   - Fingerprint stability for timestamp-only changes.
   - Normalized payload cache miss on payload/manifest hash mismatch.
   - Library cache refresh when an empty cached file exists.

4. Rebuild generated helper artifacts.
   - Run the shared helper build because [DashboardGeneration.ps1](../src/powershell/Shared/Dashboard/DashboardGeneration.ps1) changes feed [shared-helpers.ps1](../build/generated/shared-helpers.ps1), Azure runbook, and Function App artifacts.

5. Validate.
   - Run the focused shared-helper regression test first.
   - Run the deterministic preflight before final review.

## Review Notes

- The export phase already uses staged partial vulnerability downloads and transactional machine store publishing, so this branch does not replace those mechanisms.
- The validation attestation fast path is intentionally payload-oriented. Dashboard runtime behavior remains covered by the Node dashboard assertion suite and browser inspection gates rather than by semantic payload replay.
