# Original-session validation receipt: 2026-10-22

Repository: standalone nathanmcnulty/defender-reporting. Candidate base: pinned main `f8a1f2837f56086f20bf6df0b931f36245da6ba0`. Use the exact candidate revision supplied with the PR or handoff for continuation. These are original-session observations, not checks on a future VM. See the [portable handoff](codex-handoff-2026-10-22.md).

## Source review and rollout

Astra completed exact-source review with no blocking findings for correctness patch SHA-256 `5457f8bd02d4fe235958da3aa4163b875ddaf795a871f91115985df725d3ab36` and streaming patch SHA-256 `02be4e47dce37346e72b84bf5e719b37a0844f703c860302e65b3e5cd59bac98`. This covers the bounded source candidate; it is not merge/deployment approval. The six reviewed source/test files remain unchanged. Generated derivation and the final publication set require separate review.

Browser schema invalidation cannot restore scalar values lost in previously generated content sidecars; those require normal authorized regeneration from canonical inputs.

## Passed

- Six focused PowerShell tests in fresh processes: Test-VulnPartitionStreamingParity; Test-CompiledContentStringArrayRoundTrip; Test-CompiledBoundedContentNormalizationExpandedParity; Test-BulkSnapshotFreshImportProfilerParityAndGuards; Test-DashboardSplitAssetsGenerationAndValidation; Test-DashboardDualPackagingGenerationAndValidation.
- All 13 Assert-Dashboard*.js scripts with Node `--max-old-space-size=256`. The worker test executes actual generated code and denormalizeInWorker across a Node thread/structured clone, adapting browser transport and cache storage; it is not native Edge/IndexedDB acceptance.
- Scalar, streaming and generated-worker regressions failed on the original defects and passed on candidate source. Separate patches apply sequentially to copied base source and reproduce the six files, allowing CRLF normalization only.
- Focused run: exit 0, 120.77 seconds, sampled family peak 402.30 MiB, minimum free physical memory 5.19 GiB.
- Parser and PSScriptAnalyzer passed in the second offline full-preflight attempt.
- Local release ZIP build/extraction and extracted publisher WhatIf passed with installed Az.Accounts 5.5.0: exit 0, 15.53 seconds. This result applies to that rebuilt ZIP; generated tracked outputs were temporarily restored afterward and were not then a complete loose-artifact candidate.
- Subsequently, the four required checked-in shared-helper/runbook/Function/publisher builds were rerun locally; the tracked runbook change is retained and ignored helper/Function outputs regenerated without adding ignored bundles. The generated-artifact manifest records exact hashes and same-checkout derivation parity. Final generated-set review remains separate from the earlier ZIP smoke.
- Publisher disposition was proved with an isolated same-machine base build: all three publisher inputs and both builder dependencies matched checked-out base bytes; the build exited 0 and exactly reproduced the candidate publisher bytes/fingerprint. Substantive text matches committed base after CR normalization and removal of only the fingerprint line. Publisher-only platform/banner churn was omitted by restoring the unchanged baseline publisher, without hand-editing generated output. The final included diff passes whitespace checks.
- Shared/runbook fingerprints and raw hashes depend on checkout bytes and platform-specific StringBuilder.AppendLine. Complete reviewed-code embedding and same-checkout derivation were verified, but raw Windows hashes/markers are not promised to survive Git LF normalization or Ubuntu regeneration. Final publication identity must separately verify actual Git blob IDs or normalized content; the publication manifest provides both forms alongside original-session raw hashes. CI rebuilds before fingerprint checks.

## Tiny synthetic diagnostic observations

Two snapshots, 200 normalized rows, 20 devices, 200 CVEs. Fresh profiled/unprofiled import retained full decompressed-store parity and 200/200 authoritative current IDs. Times were 5.584/4.208 seconds, measuring profiler overhead rather than base/candidate speed. Separate completed-store normalization without raw snapshots took 4.638 seconds; it is a different workload from fresh import.

Hosted/Dual packaging reused one payload/manifest in Hosted/Dual/Dual/Hosted order: 1.618/1.908/1.877/1.683 seconds. All hosted payloads matched SHA-256 `c4d2d930ddd63ae61745f7214a57657ff30b440ac6f8288af7f332a36201921d` (3,886 compressed bytes). Entire baseline: exit 0, 26.82 seconds, sampled family peak 286.65 MiB, minimum free memory 5.26 GiB. Libraries were offline placeholders. No browser-performance or statistical improvement claim follows. The excluded local measurement harness and fixtures must be recreated under the handoff contract.

## Open gates and boundaries

- Full preflight did not complete: the unchanged 1 GiB family cap stopped the second offline attempt after 188.28 seconds at Test-MeasureStressRunWritesProgressAndFinalReport. Sampled family memory was 1086.20 MiB; minimum free memory 4.87 GiB. This is an incomplete bounded gate, not a passed suite or established product failure. No guard was weakened.
- Native real-library Edge/IndexedDB acceptance, controlled large Hosted/Dual comparison, large fresh import versus replay, worker first-load/reload qualification and live Azure acceptance remain open.
- Original supervision sampled about every 500 ms with session-selected settings: 4 GiB free-memory floor, 1 GiB family cap, time limits 300 seconds focused/180 seconds tiny baseline and release/600 seconds preflight. These settings are distinct from checked-in repository benchmark guards. Plan and record an appropriate bounded full-preflight budget on the receiving VM; repeating the known-failing cap is not an acceptance strategy. Preserve repository safety floors/benchmark guards, and do not directly compare results across different budgets. Adjusting temporary supervision requires approval only when outside the receiving session's actual authority or material resource/cost scope. Sampled peaks are not OS reservations or instantaneous peaks. That supervisor is not checked in.
- Original tools included PowerShell 7.6.6/.NET 10.0.12, Node 26.7.0, installed PSScriptAnalyzer/Az.Accounts, Edge 155.0.4283.62 and loadable Playwright 1.62.1. Browser launch was not tested. Discover tools and paths anew; these observations are not portable availability guarantees.
- #82 diagnostics and historical dashboard measurements do not establish a current performance fix. Draft runtime #93 remains separate. Retention/disclosure #68 and merged containment/replacement #71/#72 were unchanged.
- Synthetic inputs only. No push, PR, merge, installation, sign-in, Azure/Graph/XDR access, permission change, real-data workflow or azd-project change occurred. GitHub publication remains pending user approval.

The proposed publication set includes the six reviewed source/test files, these two documents and the regenerated tracked runbook. The unchanged baseline publisher is excluded from the candidate diff. Raw logs, benchmark payloads/fixtures, local wrappers and ignored generated bundles are excluded. Fresh checkouts must regenerate ignored outputs and verify local artifact parity before using generated entrypoints.
