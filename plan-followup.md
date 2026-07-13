# Defender Reporting Follow-up Correctness and Observability Plan

## Objective

Close the remaining proof gaps in the high-cardinality pipeline without changing existing dataset or dashboard wire formats, exceeding the 400 MB Azure Automation ceiling, or materially regressing the accepted runtime baselines.

## Baselines and quality gates

- High-cardinality Azure ContentReplay: 1,187,395 expanded rows, 133.66 seconds, 295.8 MB sampled working set, 183 MB private memory, 124.3 MB GC heap.
- Checked-in `exports` Azure replay: 7,640 source rows (measured from the current checkout; the earlier 7,780 expectation was stale), 112-second historical baseline, 365.9 MB sampled working set, 200.5 MB private memory, 123.6 MB GC heap.
- Local high-cardinality compiled projection: 42.55 seconds, 347.3 MB externally sampled working set.
- Full repository validation: 590.2 seconds.
- Memory acceptance: below 400 MB sampled Azure working set; target at least 25 MB headroom. Private memory must not regress materially.
- Runtime acceptance: no more than 15% regression for the high-cardinality replay unless a correctness requirement has no cheaper implementation. Target less than 5%.
- Compatibility acceptance: checked-in `exports`, legacy arrays/NDJSON, current/history dictionary/ref expansion, and dashboard wire formats require no migration.

## Phase 1: Make Azure benchmark acceptance authoritative

Status: **Completed 2026-07-12**

Evidence:

- Reused `BenchmarkEvidenceTools.ps1` for a testable post-publication assertion rather than adding another runner.
- The guarded harness now downloads candidate dashboards before restoration and requires succeeded/completed status, exact vulnerability counts, positive device/CVE counts, required hosted artifacts, summary/status count agreement, payload SHA agreement, actual compressed-payload row count, and HTML asset references.
- Candidate artifact validation is persisted into the benchmark evidence before Azure restoration.
- Focused corruption coverage proves stale hashes and missing assets are rejected.
- No production runbook code or Automation execution path changed in this phase.

1. Extend the existing Azure validation harness and benchmark evidence rather than introduce a second runner.
2. Capture and require actual normalized row/device/CVE counts from the status document.
3. Verify dashboard HTML, hosted assets, payload, summary, manifest/validation sidecars, and payload hashes after the run.
4. Make terminal success insufficient when required artifacts, counts, or hashes are missing.
5. Add focused offline regressions for successful, missing, stale, and mismatched evidence.

Acceptance gate:

- A completed job with missing or incorrect dashboard evidence fails before restoration is reported as successful.

## Phase 2: Add bounded source-to-dashboard semantic comparison

Status: **Completed 2026-07-12**

Evidence:

- The high-cardinality Azure payload exactly matched a fresh source projection across 1,187,395 rows and 133,633,728 decompressed JSON bytes (SHA-256 `745180e85d22e1132574857636fd9fd5a56865b466b15001af82c11f33a5b385`).
- The checked-in `exports` candidate expanded to exactly 7,640 source and dashboard rows with zero missing and zero extra rows after the scalar machine-tag compatibility fix.
- Large compiled workloads use bounded streaming decompressed SHA-256 equality. Modest enriched compatibility workloads fall back to canonical expanded-row equivalence only when semantically irrelevant lookup insertion order changes the payload bytes.
- Missing, changed, and added-row corruption regressions all fail as expected.

1. Reuse the existing semantic audit/signature machinery where possible.
2. Compare canonical expanded source rows with the published dashboard payload using disk partitions and bounded buffers.
3. Record missing, extra, duplicate, and malformed rows plus comparison counts and hashes.
4. Add a small deterministic corruption test proving the audit detects one missing and one modified row.
5. Integrate optional full semantic sign-off into the guarded Azure harness and require it for the high-cardinality acceptance run.

Acceptance gate:

- The actual Azure-published high-cardinality dashboard payload has zero missing and zero extra canonical rows against its seeded source.

## Phase 3: Capture true transient compiled memory

Status: **Completed 2026-07-12**

Evidence and keep/discard decisions:

- A 100 ms timer sampler caused severe contention and a 175.37-second run; discarded.
- A one-second timer could queue overlapping process refreshes under pressure; discarded.
- Kept synchronous phase-checkpoint telemetry using native `GetProcessMemoryInfo`, covering dictionary staging, template interning, ref projection, pre-assembly cleanup, lookup/payload assembly, and final cleanup.
- Telemetry retains maxima and stage labels only and records pre/post-trim working set, private memory, GC heap, and elapsed time.
- Replaced per-row `MemoryStream`/JSON-writer projection with direct invariant numeric NDJSON writes, released template/ref state before assembly, and used raw emission for trusted internal fragments.
- Final fresh local run processed 1,187,395 rows in 40.63 seconds versus the 42.55-second baseline, with a true 346.0 MB working-set peak. Expanded semantic parity passed.
- Final Azure true compiled telemetry peaked at 365.1 MB working set (34.9 MB below the ceiling), with the compiled projection completing in 42.34 seconds. The complete job finished in 114.34 seconds versus the 133.66-second baseline.
- A pre-final run exposed a variable 387.4 MB assembly/cleanup peak. Releasing completed lookup lists before vulnerability-array assembly reduced local peak working set to 296.5 MB and the final Azure peak to 365.1 MB without changing the payload hash.

1. Add low-overhead compiled-phase telemetry at dictionary staging, template interning, ref projection, lookup assembly, payload close, cleanup, and working-set trim.
2. Capture working set, private memory, GC heap, elapsed time, and processed counts without retaining samples in the high-volume process.
3. Persist the maximum pre-trim and post-trim readings in status/benchmark evidence.
4. Ensure the acceptance decision uses the true pre-trim high-water mark rather than only PowerShell phase-boundary samples.

Acceptance gate:

- Azure evidence reports true pre-trim and post-trim peaks, and the true peak remains below 400 MB.

## Phase 4: Make compiled interning collision-exact

Status: **Deferred after measured experiments**

Evidence and decision:

- Prototyped exact collision chains backed by canonical disk keys. Forced-collision parity passed, but the high workload took 65.43 seconds, a 54% regression.
- Prototyped temporary in-memory canonical keys. It took 71.57 seconds and raised local working set to approximately 340 MB before the later transient-memory fixes.
- Both implementations were discarded. The retained production index continues to use two independent 64-bit hashes with no additional memory/runtime cost.
- Exact collision handling remains desirable, but it must be integrated with the existing fragment write rather than maintaining a second key representation. Shipping either measured prototype would violate the user’s runtime or memory quality gate.

1. Preserve the compact 128-bit hash fast path.
2. Resolve equal-hash candidates by exact component comparison through bounded collision storage.
3. Add a deterministic injectable collision test without weakening production hashing.
4. Verify expanded parity and measure memory/runtime impact on the high-cardinality local workload.

Acceptance gate:

- Forced collisions deduplicate only exactly equal values; local high-cardinality memory stays below 400 MB and runtime regression stays within 5% unless separately justified.

## Phase 5: Prove cache-hit and legacy payload-order behavior

Status: **Completed 2026-07-12**

Evidence:

- Added semantic summary comparison between the legacy vuln-first payload and compiled lookup-first payload.
- Added normalized-payload cache publication/hit coverage with payload hash, row count, and device catalog checks.
- Added a lookup-first payload with an intentionally invalid vulnerability tail; summary extraction succeeds, proving it stops after the lookup catalog instead of scanning rows.
- Existing hosted/split-assets regressions continue to cover legacy payload summary and dashboard validation behavior.

1. Add a compiled lookup-first cache-hit regression.
2. Verify hosted summary generation does not scan vulnerability rows for lookup-first payloads.
3. Verify legacy vuln-first payloads continue to generate equivalent summaries.
4. Verify cached payload hash, row count, and summary catalog remain stable across reruns.

Acceptance gate:

- Both payload orders and a second cached run produce semantically equivalent dashboards with bounded memory.

## Phase 6: Evaluate high-cardinality enrichment support

Status: **Completed for existing low-cardinality enrichment; high-cardinality compiled enrichment remains explicitly deferred**

Evidence and decision:

- Device enrichment requires keyed machine overrides for name, group, platform, OS version, tags, onboarding state, health/risk/exposure, and user metadata.
- Content enrichment requires CVE-keyed Advanced Hunting and NVD fields plus device/software inventory joins and affected-software vendor filtering.
- The bounded architecture is a three-way disk merge: sorted device-id machine tuples, sorted CVE enrichment tuples, and sorted device/software inventory tuples consumed by the compiled projector without PowerShell hashtables.
- No representative high-content enriched benchmark is currently pinned, so implementing this join now would add substantial unmeasured semantic surface.
- Kept the cardinality-aware early rejection for nonempty machine/enrichment input. It fails before unsafe retained state is allocated and explains that a compiled enrichment-capable projection is required.
- Corrected the Azure compatibility path to load Advanced Hunting CVE, device-user, inventory, and NVD data and pass all of it into normalization and source metadata. The Advanced Hunting inputs remain a single scan.
- Found and fixed a compiled machine-index compatibility defect where scalar `machineTags` values were dropped even though the canonical format supports scalar and array forms.
- The checked-in `exports` Azure dashboard now has canonical expanded-row equivalence: 7,640 expected, 7,640 actual, zero missing, zero extra. Dashboard generation took 76.17 seconds versus 79.73 seconds before enrichment was restored; status peak working set was 370.4 MB, leaving 29.6 MB headroom.

1. Inventory the exact machine, Advanced Hunting, inventory, and NVD fields required by normalization.
2. Prefer disk-indexed or merge-stream enrichment over loading PowerShell hashtables.
3. Prototype the smallest compiled enrichment join behind the existing PowerShell interface.
4. Keep only implementations that pass parity and remain within memory/runtime gates; otherwise document a precise deferred architecture and retain the safe preflight rejection.

Acceptance gate:

- Either a high-content workload with representative enrichment passes bounded semantic parity, or the limitation remains an explicit early failure with a measured, actionable follow-up design.

## Phase 7: Final validation and promotion

Status: **Completed 2026-07-12**

Final evidence:

- Final full regression validation passed in 499.8 seconds, including build manifests, generated artifacts, parser validation, ScriptAnalyzer, semantic review, shared-helper regressions, and dashboard JavaScript regressions.
- Final Azure high-cardinality job `d479d86a-dc42-4c4a-9d30-05b91cedd126` completed in 114.34 seconds with 1,187,395 rows, 365.1 MB true peak working set, and exact decompressed payload SHA-256 `745180e85d22e1132574857636fd9fd5a56865b466b15001af82c11f33a5b385`.
- Checked-in `exports` produced 7,640 canonical rows locally and in Azure with zero missing and zero extra rows. Scalar and array machine-tag forms are both covered.
- Every Azure run restored the prior runbook and exports/dashboard blob manifests. The repository `exports` directory remained unchanged.

1. Run focused regressions after each kept phase.
2. Regenerate tracked artifacts only through repository build scripts.
3. Run complete parser, ScriptAnalyzer, generated-artifact, shared-helper, JavaScript, and semantic validation.
4. Run guarded Azure validation for checked-in `exports` and the high-cardinality procedural dataset.
5. Require full semantic comparison for the high-cardinality Azure result.
6. Verify Azure runbook/storage restoration by hashes and confirm no changes under `exports`.
7. Record keep/discard/defer decisions and final evidence in this file.

Acceptance gate:

- All correctness, compatibility, memory, runtime, publication, and restoration gates pass on the final generated candidate.

## Working rules

- Treat this untracked file as the execution scratchpad.
- Do not edit generated runbook or Function App artifacts directly.
- Preserve `PLAN.md` and unrelated user changes.
- Keep public PowerShell parameters and existing wire formats stable.
- Prefer deletion/reuse over new helpers; add narrowly scoped helpers only where streaming correctness requires them.
- Discard changes that create correctness ambiguity, exceed 400 MB, or materially regress runtime without a compelling correctness benefit.
- Always target Azure subscription `43babb60-9e73-4dc8-b769-4401c01aad73` and restore original state after validation.
