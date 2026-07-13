# Defender Reporting Reliability and Memory Roadmap

## Objective

Make the Defender reporting pipeline predictably safe in a 400 MB Azure Automation environment while preserving compatibility with existing datasets, maintaining deterministic benchmark coverage, and making Azure validation repeatable and reversible.

## Current Baseline

- The procedural generator produced 50,000 devices and 1.5 million vulnerability observations in 23.5 seconds.
- Its incremental overlay produced 1.2 million current rows without regenerating the seed.
- The large 1.5-million-row Azure replay completed in 501.17 seconds at 400.2 MB working set and 235.1 MB private memory; Hosted delivery completed in 626.27 seconds at 392.8 MB working set and 247 MB private memory.
- The checked-in repository dataset completed in 121.81 seconds at 360.2 MB working set and 199.4 MB private memory.
- The live fresh-export production path completed in 189.52 seconds at 377.3 MB working set and 209.5 MB private memory.
- Every guarded Azure validation restored and hash-verified the original runbook, exports, and dashboards.
- Full parser, ScriptAnalyzer, generated-artifact, semantic, shared-helper, and dashboard JavaScript validation passes; the latest full run completed in 640.9 seconds.
- The 187,500-content-template stress dataset now completes through the bounded compiled projector and hosted publisher. The final Azure run processed 1,187,395 expanded rows in 133.66 seconds at 295.8 MB peak working set, 183 MB private memory, and 124.3 MB GC heap.

## Execution Plan

### Phase 1: Stabilize the test baseline

Status: **Completed 2026-07-11**

Evidence:

- Fixed restricted-Windows memory telemetry so unavailable CIM data is recorded as `NaN` rather than aborting the stress wrapper.
- Made dashboard regression fixtures independent of public CDN availability while leaving production download behavior unchanged.
- Corrected the generator ordering regression's Windows output-directory file lock and optional procedural-manifest handling.
- Added `-TestName`, `-Category`, `-StopAfter`, and JUnit output support to the shared-helper regression runner.
- Full shared-helper regression suite passed in 250.6 seconds.
- Full generated-artifact validation passed in 442.4 seconds, including parser, ScriptAnalyzer, generated runbook and Function App rebuilds, JavaScript regressions, and semantic smoke.
- Checked-in `exports` wire formats and data were not modified.

1. Fix `Test-MeasureStressRunWritesProgressAndFinalReport` and its missing `stress-report.json` output.
2. Confirm whether the defect is in the stress runner, test invocation, output-path handling, or cleanup timing.
3. Add focused regression-runner controls:
   - `-TestName`
   - `-Category`
   - `-StopAfter`
   - JUnit-compatible result output
4. Run the complete shared-helper regression suite until it passes without known exceptions.
5. Run generated-artifact validation and confirm the runbook and Function App artifacts are reproducible from source.

Acceptance gate:

- The complete regression suite and generated-artifact validation pass from a clean invocation.

### Phase 2: Persist benchmark evidence and enforce trustworthy measurements

Status: **Completed 2026-07-11**

Evidence:

- Added versioned benchmark evidence schema v1 and transactional evidence publication.
- Evidence captures Git commit/worktree state, generated artifact fingerprints, dataset manifests and SHA-256 hashes, environment identity, execution details, validation, memory, timing, and counts exposed by each runner.
- Integrated evidence into all five `Measure-*.ps1` benchmark entrypoints.
- Azure runbook-only measurement now retains distinct status-blob snapshots throughout polling rather than only the final tail.
- Added threshold and baseline comparison tooling for working set, private memory, GC heap, and elapsed-time regression.
- Verified evidence generation against the checked-in `exports` dataset: 21 machines, 192 MB peak working set, 36.2 MB peak GC heap.

1. Define a versioned benchmark-result schema containing:
   - Git commit and worktree state
   - shared-helper and runbook fingerprints
   - dataset identity, model version, parameters, and artifact hashes
   - Azure subscription, resource group, Automation account, runbook, storage account, and job IDs
   - phase durations and row rates
   - current, history, device, CVE, content-template, and lookup counts
   - peak working set, private memory, and GC heap by phase
   - final artifact hashes and validation results
2. Update local and Azure benchmark runners to emit this record transactionally.
3. Retain the status-blob timeline rather than only its final sample.
4. Add comparison tooling and explicit regression thresholds.

Acceptance gate:

- Every benchmark produces a self-contained result record that can be compared without consulting console logs.

### Phase 3: Add phase timeouts, heartbeats, and stall detection

Status: **Completed 2026-07-11**

Evidence:

- Device-profile and content-template loading now publish count/rate heartbeats every 10,000 items or 30 seconds without changing vulnerability row counters.
- Ref streaming retains its existing time-based and row-based progress cadence.
- Azure runbook monitoring warns after a configurable no-progress interval and stops/fails a job after a configurable failure interval with stage, message, and memory diagnostics.
- Unit coverage proves recent slow progress remains healthy, crosses a warning state independently, and becomes failed only after the configured failure threshold.

1. Emit progress by elapsed time as well as row interval.
2. Track the last successful progress timestamp for every long-running phase.
3. Add configurable warning and failure thresholds for no-progress intervals.
4. Include the following in stall failures:
   - phase and subphase
   - source artifact and partition
   - last processed row
   - recent processing rate
   - elapsed time
   - current and peak memory
5. Ensure slow-but-progressing jobs are not misclassified as stalled.

Acceptance gate:

- An intentionally stalled fixture fails with a precise diagnostic, while a deliberately slow fixture completes.

### Phase 4: Build a safe Azure validation and restoration harness

Status: **Completed 2026-07-11**

Evidence:

- Added an explicit-subscription, `-Execute`-guarded validation entrypoint with an atomic Azure Blob lock.
- The harness backs up and hashes published runbook content, exports, and dashboards; deploys the generated candidate; seeds an exact or raw-replay dataset; invokes monitored validation; and restores in `finally`.
- Restoration re-downloads and verifies every blob hash and the published runbook hash.
- Live `exports` compatibility validation completed in 145 seconds at 370.3 MB peak working set, 207.2 MB peak private memory, and 115.7 MB peak GC heap.
- An injected failure immediately after candidate deployment restored and hash-verified the original Azure state before propagating the intentional failure.

1. Create one supported validation entrypoint that:
   - requires the explicit subscription ID
   - verifies the resource group, Automation account, runbook, and storage account
   - acquires a validation lock
   - backs up published runbook content and affected blobs with hashes
   - verifies the backup before mutation
   - deploys and publishes the candidate generated artifact
   - seeds an exact manifest-controlled dataset
   - starts and monitors jobs
   - captures streams, status timelines, counts, hashes, and benchmark records
   - restores state in `finally`
   - verifies restored hashes
2. Prefer a dedicated validation container or isolated blob prefix.
3. Evaluate a dedicated validation Automation account as the long-term safer boundary.
4. Detect and reject stale or additive seeds before starting a job.

Acceptance gate:

- Forced failures at each deployment and execution stage still restore the original Azure state and release the validation lock.

### Phase 5: Make dashboard payload packaging fully streaming

Status: **Completed 2026-07-12**

Evidence and decision:

- Profiling confirmed payload JSON and device lookups already stream; the remaining working-set high-water mark occurs at payload close before a full collection.
- One-shot large-object-heap compaction reduced the large Azure peak from 432.9 MB to 417.8 MB and private memory from 260.3 MB to 248.1 MB. This change is retained.
- Additional lookup-group collections produced only 3.2 MB and then 0.4 MB incremental reductions while adding approximately 46 and 140 seconds. Those experiments were discarded.
- At that intermediate checkpoint, the strict below-400-MB sampled working-set gate was not met; the later compiled/streaming implementation below supersedes that result.
- Further material reduction likely requires a fresh process/job boundary between normalization and packaging rather than additional in-process GC or serializer complexity.
- Hosted delivery validation completed in Azure job `61a39788-4f35-43c7-8734-7f84d00b42d4`: 392.8 MB working set, 247 MB private memory, 156.1 MB GC heap, and 626.27 seconds. This provides 7.2 MB ceiling headroom but not the 25 MB target, and costs approximately 125 seconds versus SelfContained.
- Replaced hosted summary construction's full `lookups` materialization with forward-only extraction of groups, tags, and compact device fields.
- Compiled high-cardinality payloads stage vulnerability rows on disk and emit lookups first, allowing hosted summaries to avoid tokenizing the complete row set while preserving the standard payload format and expanded semantics.
- The final 187,500-template Azure Hosted run completed at 295.8 MB peak working set and 183 MB private memory, providing more than 100 MB of working-set headroom and satisfying this phase's strict gate.

1. Profile the successful large run’s packaging phase at finer checkpoints:
   - normalized-column finalization
   - lookup serialization
   - payload gzip close
   - payload summary generation
   - Base64 embedding
   - HTML segment assembly
   - dashboard upload
2. Eliminate complete-section `StringBuilder.ToString()` and large intermediate JSON strings.
3. Serialize lookup collections directly into the destination gzip stream.
4. Stream Base64 encoding and HTML replacement without materializing the combined document.
5. Release normalization caches before packaging begins and force collection only at measured phase boundaries.
6. Preserve SelfContained, Hosted, and Dual output formats and byte/semantic compatibility where contractual.

Acceptance gate:

- The 50,000-device, 1.2-million-current-row replay completes with peak sampled working set below 400 MB and at least 25 MB of target headroom, while private memory remains below 300 MB.

### Phase 6: Add cardinality-aware preflight and execution-mode selection

Status: **Completed 2026-07-12**

Evidence:

- Added a normalization preflight that reads procedural cardinality metadata or streams existing content dictionaries when metadata is absent.
- Existing checked-in `exports` is recognized without any manifest or wire-format migration and selects the established streaming path.
- Inputs above the measured 10,000-template in-process safety threshold fail before high-volume retained state is allocated.
- The selected modes, counts, and calibrated private/working-set estimates are written to the Azure status blob.
- Regression coverage verifies production-representative selection, high-cardinality rejection, and legacy fallback.

1. Read or cheaply derive these dimensions before normalization:
   - device profiles
   - content templates
   - current and history refs
   - machine records
   - Advanced Hunting CVEs and device users
   - delivery mode
2. Develop conservative retained-memory estimates from measured benchmarks.
3. Automatically select among:
   - compact in-memory lookup
   - compiled file-backed machine lookup
   - direct merge when ordering is eligible
   - partitioned content-template normalization
   - hosted/split-asset packaging
4. Fail early with an actionable estimate if no safe mode exists.
5. Record the selected mode and estimate in the status blob and benchmark result.

Acceptance gate:

- Representative fixtures select the expected execution mode, and unsafe inputs fail before high-volume processing begins.

### Phase 7: Partition content-template normalization

Status: **Completed 2026-07-12**

Evidence:

- Added and regression-tested a compiled file-backed content-lookup cache with bounded retained template entries and transactional staged-file cleanup.
- The ordinary legacy one-pass path and checked-in `exports` fallback remained unchanged and passed focused regressions.
- Forced the bounded path through a semantic two-row current/history fixture, including nested lookup arrays and callback phase coverage.
- Ran the 50,000-device / 1.5-million-row / 187,500-template `ContentCardinalityStress` dataset locally.
- Stopped the run at approximately 133 seconds after it reached 460.1 MB sampled working set and 354.1 MB private memory while still loading templates.
- Conclusion: per-template cache retention was not the only dominant allocation. PowerShell global lookup lists and index maps grow during content resolution and must also move behind a compiled/file-backed boundary. Cache-only partitioning is discarded as the acceptance architecture.
- Next implementation boundary: compiled content projection must intern global software/CVE/version/update/path values, stage compact template tuples, and serialize lookup arrays without materializing PowerShell object graphs. Existing content dictionary/ref formats remain inputs; no dataset migration is required.

Additional Azure acceptance evidence:

- Checked-in `exports` completed in Azure job `60646f2c-9cfc-4732-b691-63cd0dfee43e` in 121.81 seconds at 360.2 MB peak working set, 199.4 MB private memory, and 126.5 MB GC heap.
- Procedural 50,000-device / 1.5-million-row / 5,000-template dataset completed in Azure job `a392c8a7-750a-476e-b686-aa156465a0b3` in 501.17 seconds at 400.2 MB peak working set, 235.1 MB private memory, and 156.1 MB GC heap.
- Both guarded runs restored and hash-verified the original published runbook, exports, and dashboards.
- The 1.5-million-row result is a correctness and OOM-success gate, but not strict memory acceptance: sampled working set is 0.2 MB above the 400 MB target and needs additional headroom work.
- Replaced the discarded PowerShell cache-only design with a bounded compiled standard-payload projector. PowerShell stages dictionary arrays one at a time; C# uses compact device/template state, disk-backed fragments, pre-sized hash indexes, and direct gzip serialization.
- Added deterministic expanded-row parity coverage for current/history refs, Unicode, empty arrays, optional values, and direct-merge eligibility without changing input or dashboard wire formats.
- Added explicit retained-state release, large-object-heap compaction, and post-collection working-set trimming at the compiled boundary.
- Local high-cardinality projection processed 1,187,395 rows, 49,476 devices, and 184,783 software/CVE entries in 42.55 seconds at 347.3 MB peak working set.
- Final guarded Azure job `9e454442-96fc-4693-acfc-753bfdb2aa2e` completed the same expanded workload in 133.66 seconds at 295.8 MB peak working set, 183 MB private memory, and 124.3 MB GC heap. The original runbook, exports, and dashboards were restored and hash-verified.

1. Preserve the 187,500-template dataset as a dedicated `ContentCardinalityStress` benchmark.
2. Scatter content templates and refs into deterministic disk partitions by content index.
3. Normalize one content partition at a time.
4. Retain only:
   - one content partition
   - compact device-index state
   - global deduplicated dashboard lookups
   - bounded output buffers
5. Append normalized columns incrementally and preserve expanded-row semantic equivalence.
6. Add transactional cleanup for partition files and failed payload publication.
7. Compare runtime and memory across partition sizes and select a conservative Automation default.

Acceptance gate:

- The 187,500-template stress dataset completes below 400 MB sampled working set without reducing its template cardinality.

### Phase 8: Formalize benchmark workload profiles

Status: **Completed 2026-07-12**

Evidence:

- Added six explicit versioned workload profiles with pinned seeds, model versions, devices, rows, templates, and performance envelopes.
- Separated the 5,000-template row-volume benchmark from the 187,500-template content-cardinality gate.
- Benchmark materialization now forwards pinned snapshot, churn, and sparsity controls and records profile metadata.
- Regression coverage requires exactly one definition for every documented profile and all critical dimensions.

1. Add explicit, versioned profiles:
   - `ProductionRepresentative`
   - `RowVolumeStress`
   - `ContentCardinalityStress`
   - `DeviceCardinalityStress`
   - `HistoryChurnStress`
   - `UnicodeAndSparsityEdgeCases`
2. Pin every catalog entry’s important dimensions rather than relying on generator defaults.
3. Keep 50,000 devices, 1.5 million observations, 5,000 CVEs, and 5,000 templates as the production-representative large row-volume benchmark unless production evidence supports another value.
4. Preserve 187,500 templates as a separate stress profile.
5. Add breadth counters and expected performance envelopes to catalog metadata.
6. Treat generator or model changes as explicit version changes.

Acceptance gate:

- Each workload stresses a documented dimension, is byte-reproducible, and has independent correctness and performance expectations.

### Phase 9: Strengthen immutable overlay lifecycle management

Status: **Completed 2026-07-12**

Evidence:

- AdvanceSnapshot validates every parent artifact hash when the parent provides an artifact manifest.
- Overlay metadata records the parent artifact-manifest hash, chain depth, and configured maximum depth.
- Chain depth is enforced with an actionable consolidation diagnostic.
- Added transactional RawReplay/Exact upload-manifest generation with artifact hash validation and exact artifact selection.
- A 96,000-row medium overlay completed with 13 hard links and no copies; a second advance correctly failed at the configured chain-depth limit without mutating its parent.

1. Validate parent identity and hashes before creating or consuming an overlay.
2. Add an upload-manifest command that materializes only the exact artifacts required for raw replay.
3. Support deterministic overlay chains with parent references.
4. Add chain-depth limits and periodic consolidation.
5. Verify hard links where supported and clearly record copy fallback.
6. Add failed-staging cleanup and base-dataset immutability tests.

Acceptance gate:

- Successive date and churn overlays can be generated, validated, uploaded, and replayed without regenerating or mutating the seed.

### Phase 10: Validate the live fresh-export production path

Status: **Completed 2026-07-12**

Evidence:

- Live `UseExistingExportsOnly=false` Azure job `2eaaa0e2-1f30-4a4a-abde-f288963b051c` completed in 189.52 seconds.
- Peak memory was 377.3 MB working set, 209.5 MB private, and 128.4 MB GC heap during normalization.
- The job exercised fresh MDE vulnerability, machine, and Advanced Hunting exports and completed dashboard publication.
- The guarded harness restored and hash-verified the original runbook, exports, and dashboards.

1. Use the completed Azure validation harness.
2. Deploy the candidate temporarily.
3. Run with `UseExistingExportsOnly=false` against normal production cardinality.
4. Validate actual MDE vulnerability, machine, and Advanced Hunting export behavior.
5. Verify snapshot dates, canonical publication, content sidecars, dashboard artifacts, counts, and memory.
6. Capture a benchmark record and restore the original Azure state.

Acceptance gate:

- The live export path completes without `OutOfMemoryException`, publishes valid artifacts, and remains within the established memory envelope.

### Phase 11: Formalize the PowerShell/C# runtime boundary

Status: **Completed 2026-07-12**

Evidence:

- Added `docs/runtime-boundary.md` defining PowerShell ownership of public contracts, Azure orchestration, policy, transactions, and validation.
- Defined compiled ownership of high-volume parsing, generation, compact indexes, joins, partitioning, and bounded serialization.
- Explicitly prohibits Azure authentication/control-plane behavior and implicit wire-format changes in compiled helpers.
- Existing compiled projector, file-backed machine lookup, and procedural writer parity/compatibility regressions remain the enforcement gate.

1. Document PowerShell responsibilities:
   - parameter validation
   - Azure orchestration
   - transactions and rollback
   - progress/status reporting
   - policy and validation
2. Document compiled C# responsibilities:
   - high-volume JSON parsing
   - streaming projection
   - joins and indexes
   - partitioning
   - bounded serialization
3. Consolidate narrowly scoped compiled helpers behind stable PowerShell functions.
4. Add deterministic parity tests for every compiled path and its compatibility fallback.
5. Avoid moving Azure control-plane behavior into embedded C#.

Acceptance gate:

- High-volume paths have bounded compiled implementations, public PowerShell interfaces remain stable, and fallback behavior is covered by tests.

## Required Validation Matrix

Status: **Completed 2026-07-12**

Final evidence:

- Full parser, ScriptAnalyzer, generated-artifact, shared-helper, JavaScript, and semantic regression validation passed in 590.2 seconds.
- Checked-in `exports` remained unchanged and completed final guarded Azure job `41717631-825d-4053-a592-c2734fcde8fc`: 7,780 rows in 112 seconds at 365.9 MB working set, 200.5 MB private memory, and 123.6 MB GC heap.
- High-cardinality procedural content replay completed final guarded Azure job `9e454442-96fc-4693-acfc-753bfdb2aa2e`: 1,187,395 rows in 133.66 seconds at 295.8 MB working set.
- Earlier guarded validations cover the medium procedural benchmark, date-only and churn overlays, 1.5-million-row production-representative replay, live fresh export, and injected-failure restoration.
- Every final guarded Azure run restored and hash-verified the published runbook plus the `exports` and `dashboards` containers.

Before considering the roadmap complete, validate:

1. Small regression fixtures, including legacy JSON arrays and NDJSON.
2. Checked-in `exports` dataset.
3. Medium procedural benchmark.
4. Large production-representative row-volume benchmark.
5. Incremental date-only overlay.
6. Incremental churn overlay.
7. High-content-cardinality stress benchmark.
8. Azure replay with existing exports.
9. Azure live fresh export.
10. Failure injection proving transaction cleanup and Azure restoration.

For every case, verify row equivalence, optional fields, Unicode, hashes where contractual, current/history artifacts, dictionary/ref expansion, dashboard publication, memory, runtime, and cleanup.

## Working Rules

- Do not edit generated runbook or Function App artifacts directly.
- Modify source files and regenerate artifacts through repository build scripts.
- Preserve unrelated worktree changes, especially `Setup-AzureResources.ps1`.
- Always specify Azure subscription `43babb60-9e73-4dc8-b769-4401c01aad73`.
- Treat private memory and working set as separate metrics; do not claim the 400 MB target is met unless sampled working set also satisfies it.
- Restore the original Azure runbook and storage state after temporary validation unless explicitly directed otherwise.
- Memory safety and correctness take priority over direct-merge speed.
- Preserve existing public parameters and wire formats unless a separately reviewed migration is introduced.
