# Performance Baselines

This repository keeps the merge-tracked performance baseline as documentation instead of committing raw machine-local benchmark output.

Use `.local\benchmark-history\benchmark-history.jsonl` for local longitudinal tracking across repeated benchmark captures. Only update this document after the dataset and command path are durable enough to serve as a merge-tracked baseline.

Performance acceptance should record which benchmark lane was used:
- completed-dataset replay
- raw sidecar-free replay
- live fresh export

Do not compare those lanes as if they were interchangeable. Replay benchmarks are useful for steady-state normalization and packaging cost, while live fresh-export runs are the only coverage for Stage C import behavior and large MDE download/publish hot paths.

`tests/Invoke-LargeImportCoverage.ps1` is the preferred deterministic prep entrypoint for large import-path spot checks. It produces both a raw sidecar-free replay dataset and an Azure-ready existing-export dataset that combines `Machines_Current.json.gz`, `AdvancedHunting_Current.json.gz`, and synthetic legacy `VulnExport_*.json.gz` files.

The current bounded-content-store acceptance is recorded below. The older tables and triage entries remain useful historical comparisons, but they predate the disk-partitioned publisher and compiled streaming standard-payload path.

## Issue 67 fresh-import phase baseline (2026-09-30)

**Partial investigation, not an optimization or closure. Refs #67.** Production helpers, compile thresholds, templates, and performance defaults are unchanged. No candidate was deployed and no new Automation job was started.

### Original synthetic snapshot import

Original job `5ff9dd3f-f773-4856-bbc2-8b376cd613d2` completed on 2026-09-29. Its archived status reports Automation, `UseExistingExportsOnly=true`, and a fresh legacy-snapshot canonicalization inside Stage C. This is **not** completed-store replay and **not** an MDE API download: synthetic legacy snapshots were already in Blob storage. The reference declares 50,000 target machines and 1,500,000 source observations; the published projection has 1,187,395 current rows and 49,476 devices. Source observations are not expected dashboard rows.

Read-only GET recovery of this exact job preserved its status and both stream pages (196 streams). No other cloud jobs, resources, permissions, schedules, or authentication settings were queried or changed. Historical source commit/helper fingerprint was not recovered from the stream summaries; current source must not be represented as byte-identical to that job.

| Original interval | Start UTC | End UTC | Seconds |
| --- | --- | --- | ---: |
| Job start to completion | 19:12:21.902 | 19:54:56.382 | 2554.48 |
| Snapshot loop, sampled VulnStore Start/End | 19:12:49.216 | 19:39:21.259 | 1592.04 |
| Unlabelled post-loop/pre-projection gap | 19:39:21.259 | 19:46:52.074 | 450.81 |
| Compiled content projection, sampled Start/End | 19:46:52.074 | 19:47:33.718 | 41.64 |
| Sampled store window, Start/Post-VulnStorePublish | 19:12:49.216 | 19:47:34.585 | 2085.37 |

These are wall-clock sample boundaries, not exclusive method timings. In particular, the approximately seven-minute gap is **not** measured compiled projection time. The current owner performs current-file assembly/validation, history materialization, transaction publication, and projector setup between those labels; the old job cannot distinguish their individual costs. The status sampled peak is 373.0 MiB in normalization, not a verified process high-water or a strict sub-400 MiB acceptance result.

Original archived status SHA-256: `75abcd865615a31dd0faa9a948f98a56cd2fb0c2b7497d5ce8eab3457544daee`. Reference manifest SHA-256: `766cc3e2890b0c3707c3a4e9ccf904b194f11e387b218a2505e57ac8542d45e0`. Both hashes were independently verified against retained local bytes on 2026-09-30: the parent workspace's `.local/review-50k-status-20260929.json` and `.local/large-datasets/review-50k-20260929/synthetic-manifest.json`, respectively. This verifies file identity, not historical source identity. Private evidence in the issue-67 worktree is `.local/original-job/{job.json,streams.json,streams-page-2.json,baseline-scalars.json}`. Raw job responses and datasets must remain ignored.

### Bounded local owner profile

Owning paths at base `3ed6bd7` are `build/azure/runbook-source.ps1` Stage C, `src/powershell/Shared/Stores/VulnerabilitySnapshotImport.ps1` (`Publish-VulnStoreFromBulkSnapshot`), and `src/powershell/Shared/Core/Core.ps1` (`Split-VulnJsonPartition`, `Read-VulnPartitionMapFile`, `New-OpenVulnRecord`, `Publish-VulnContentStoreUnlocked`). The current signature helper is `Get-VulnCanonicalRowSignature`, which uses a nonblank ID; no `Get-VulnCanonicalStateHash` exists in this source. No historical full-state-hash cost is inferred.

Hypothesis: repeated partition-map parsing/property/date/signature work and owner parse/open/serialize operations dominate local fresh import. Cheap check: run the real publisher from an empty store using deterministic synthetic changed-date snapshots, attribute operation calls/time/allocations, and compare every decompressed output file with an unprofiled twin. The test-only `-ProfileFreshImport` flag rewrites functions in memory and restores originals in `finally`; no production callback, per-row timer, or performance behavior changes were added.

Both local samples use procedural seed `20260322`, 50 machines, 5,000 templates, a reference generated for 2026-09-29, a one-day immutable-reference overlay, snapshot dates 2026-09-29/30, ten legacy files, and 128 partitions. Generator safety controls require at least 1 GiB available RAM and 1 GiB disk. Each reference contains 80% current and 20% historical source observations. Expected current IDs come from the authoritative onboarded reference projection, not source observation counts. Both imports start without a canonical store or content sidecars; the procedural initial-import shortcut is absent from the import directories.

| Local synthetic observations | Expected/actual current IDs | Profiled seconds | Unprofiled seconds | Store parity |
| ---: | ---: | ---: | ---: | --- |
| 5000 | 3455 / 3455 | 27.90 | 18.87 | All decompressed current/history/content files identical |
| 10000 | 6889 / 6889 | 45.46 | 33.62 | All decompressed current/history/content files identical |

| Operation | 5k calls | 5k seconds | 10k calls | 10k seconds | 10k allocated MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Read-VulnPartitionMapFile | 512 | 9.13 | 512 | 15.24 | 4373.74 |
| Split-VulnJsonPartition | 2 | 5.74 | 2 | 9.12 | 2641.18 |
| New-OpenVulnRecord | 6895 | 4.73 | 13749 | 8.36 | 2596.05 |
| Json.Parse | 25217 | 3.70 | 50334 | 6.49 | 2168.47 |
| Test-VulnCurrentFile | 1 | 2.18 | 1 | 3.18 | 922.10 |
| Get-VulnCanonicalRowSignature | 10335 | 1.42 | 20609 | 2.49 | 438.09 |
| Json.Serialize | 6903 | 0.92 | 13762 | 1.69 | 483.65 |
| Content.CompiledProject | 1 | 0.07 | 1 | 0.12 | 78.33 |

Timings and current-thread allocations are **inclusive and nested; do not sum them**. Allocation churn is not resident memory. The profiler adds per-call overhead: profiled/unprofiled totals differ substantially. Order, warm compilation/filesystem caches, local CPU, runtime, and single samples prevent causal optimization claims. The observation supports local repeated-row-work pressure, not an extrapolation to a 2,700-second cloud run or attribution of the original 27-minute loop to a particular method. Full pipeline normalization/dashboard parity and Azure process high-water are not measured here.

Private evidence: `.local/profile-5k/verified-profiled/fresh-import-profile.json` and `.local/profile-10k/profiled/fresh-import-profile.json`, with immutable references, overlays, snapshots and unprofiled twins alongside. Each JSON records source commit/runtime, model controls, manifest/input hashes, authoritative ID counts, all decompressed output hashes, and scalar operation measurements. The earlier `.local/profile-5k/profiled/` capture lacks the strengthened ID/projection checks and is superseded. The existing shared suite covers current/history parity, decimal/Unicode/case/array/null probe fields, scalar attribution, owner restoration, and rejection of completed stores/non-procedural inputs. The older `.local/preflight/full-preflight.txt` is not hash-bound to the final four-file patch and is not acceptance evidence for it. Final validation uses `.local/preflight/hash-bound-provenance.json` and its timestamped full-preflight log: acceptance requires a fresh, unskipped `build/Invoke-RegressionValidation.ps1` exit of zero, the success marker, and identical before/after SHA-256 for `tests/Invoke-LargeImportCoverage.ps1`, `tests/Run-SharedHelperRegression.ps1`, `tests/README.md`, and this document. The record includes UTC start/end, exact command, log SHA-256, and independently checked original-file hashes. Freeze all four files before capture; any subsequent source or documentation edit invalidates that acceptance and requires repeating the gate. Generated fingerprint/encoding-only churn is excluded from the patch. No production helper changed, so a release build was not required.

**Decision:** retain the profile harness and documentation only. There is no measured candidate with enough evidence to justify even a long cloud trial. Issue #67 stays open. The issue-69 controlled Dual 769.42-second completed-store replay is not comparable; its failed 875.39-second/413.8-MiB candidate remains default-off. Any future production candidate needs exact store/history/current-ID/output parity, parent Astra review, separate authorization for a guarded actual fresh-import job, and strict sampled/process-high-water memory below 400 MiB before changing a default. This work made no agents, commits, main-worktree edits, browser changes, process termination, cloud writes, MDE calls, login, or schedule changes.

## Issue 69 controlled baseline (2026-09-30)

This is a measured **baseline, not an optimization result or a sub-400 MiB acceptance pass**. The lane is retained synthetic existing-export replay, cold normalized-payload cache, `UseExistingExportsOnly=true`, `UseDirectMergeDeviceLookup=false`, source base `8317b76`. It contains 1,187,395 current references and zero references in the five history files; output has 49,476 devices and 5,000 CVEs. It is not a fresh MDE export or Function App measurement. Both Automation workers reported PowerShell 7.4.6, .NET 8.0.28, X64, one processor, and workstation GC.

| Mode | Job creation-to-completion | Sampled peak WS | Process high-water WS | Peak private | Peak GC heap | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Hosted | 786.80 s | 421.2 MiB, normalization | 569.9 MiB | 716.4 MiB, Completed | 180.0 MiB, normalization | Completed; artifact validation passed |
| Dual | 769.42 s | 681.3 MiB, Completed | 681.3 MiB | 704.8 MiB, Completed | 373.8 MiB, Completed | Completed; recovered artifact validation passed |

The two modes are controls, not baseline/candidate variants. Their elapsed difference is not evidence of an improvement. Both exceed 400 MiB. Hosted's 569.9 MiB process high-water was not captured as an instantaneous working-set sample: no method-level attribution is possible. At its final sample WS was only 194.1 MiB. Dual's final sample is the observed 681.3 MiB crest. Event-derived headlines under-report memory (Dual reports 379.0 MiB), so use status snapshots and process high-water values. Hosted event-derived stage durations are incomplete (its reported Generate dashboard duration is only 10.91 s); do not use them as exclusive phase timings. The recovered Dual lacks the original local polling timeline, but preserves all 104 final cloud snapshots and job events; Hosted also preserves 104 snapshots.

### Controlled identity and parity

- Dataset manifest SHA-256: `3c8b18135dd2af0df8bd837b905644541621e43b95870c4e29073b5ea467d9e3`.
- Template manifest SHA-256: `c08987a504a22c8d1e530d69e0a62e83af98f13d72b38b83ac89b2f4ba11d932`.
- Instrumented deployed source SHA-256: `dffdaa04368a38cd3362e6bb45340c1558e82bf91abb96a227d489fbb2b4d577` (same in both modes).
- Exact decompressed Hosted/Dual payload equality: 65,580,317 bytes, SHA-256 `764d32ef55b7188dbc4d0b56b5bf358192824ccf1261aed0157e0c56e33aaf56`. Gzip payload: 15,351,202 bytes, SHA-256 `cd928b05840107bd9a694ec3c17030e5569300999115e40160c316dcaa6a9740`.
- Hosted primary HTML: 21,637 bytes; Hosted generation summary: 3,486,143 bytes. Dual self-contained primary HTML: 22,575,578 bytes. These are artifact sizes, not heap-retention measurements.
- Hosted job resource: `15a4b9fa-b17b-4c83-98b3-4359f208d495`; runtime job: `b0b069cd-d8bc-4822-9963-d489c6c724cf`. Dual job resource: `69d08e91-315f-4868-b4b5-8dd1e1ec024d`; runtime job: `3ab07c2b-a5a2-4d96-a4c1-7553b6eb38a6`.

Raw machine-local evidence is under `.local/controlled-20260930-run3/{Hosted,Dual}/`: `experiment-result.json`, `benchmark-result.json`, `candidate-dashboards/`, exact backups and restored files. Each benchmark's `runbook_status.memoryTimelineTail` retains every phase snapshot, including UTC time, process peak, cumulative allocation bytes, Gen0/1/2 counts, last-GC heap/fragmentation/committed bytes, and LOH before/after size and fragmentation. Do not commit raw tenant artifacts.

### All-stage snapshot summary

Each row covers every saved sample in that stage. WS, private and GC are independent sampled maxima, not necessarily simultaneous. Allocation and GC deltas span the first to last sample **within** the stage and exclude inter-stage gaps; zero means a single sample, not zero work. LOH is the last sample's last-GC size after collection, not an instantaneous live heap. All memory is MiB; allocations are GiB. These counters characterize allocation pressure and collection activity, not exclusive method allocations or proven retained objects.

| Mode | Stage | Max WS | Max private | Max GC | Allocation delta | Gen0/1/2 delta | Last-GC LOH after |
| --- | --- | ---: | ---: | ---: | ---: | --- | ---: |
| Hosted | Authentication | 242.8 | 117.8 | 61.2 | 0.113 | 7/3/0 | 16.28 |
| Hosted | DownloadHistoricalData | 303.7 | 163.8 | 73.8 | 0.380 | 26/8/1 | 18.08 |
| Hosted | ExportFreshMdeData (skipped) | 303.9 | 163.8 | 88.5 | 0.025 | 4/2/2 | 17.19 |
| Hosted | GenerateDashboard | 290.3 | 149.8 | 85.1 | 0 | 0/0/0 | 17.19 |
| Hosted | CheckDashboardPayloadCache | 291.9 | 151.2 | 75.2 | 0.008 | 2/2/2 | 17.19 |
| Hosted | ReadNormalizationInputs | 333.5 | 188.4 | 94.7 | 0.768 | 52/14/4 | 20.22 |
| Hosted | NormalizeDashboardData | 421.2 | 250.3 | 180.0 | 181.287 | 11672/564/50 | 11.64 |
| Hosted | PrepareDashboardPayload | 370.5 | 199.0 | 93.6 | 0.032 | 6/4/4 | 11.90 |
| Hosted | PrepareDashboardLibraries | 372.3 | 200.8 | 93.7 | 0.023 | 3/2/2 | 12.15 |
| Hosted | LoadDashboardTemplates | 375.2 | 203.2 | 96.7 | 0.031 | 4/2/2 | 13.26 |
| Hosted | WriteHostedDashboard | 378.7 | 205.8 | 98.8 | 5.131 | 329/6/4 | 22.29 |
| Hosted | ExportResults | 378.6 | 205.5 | 98.1 | 0 | 0/0/0 | 22.29 |
| Hosted | Completed | 194.1 | 716.4 | 168.0 | 0 | 0/0/0 | 86.79 |
| Dual | Authentication | 237.7 | 114.6 | 55.8 | 0.123 | 8/3/0 | 16.50 |
| Dual | DownloadHistoricalData | 301.2 | 161.4 | 88.6 | 0.362 | 24/8/1 | 18.30 |
| Dual | ExportFreshMdeData (skipped) | 301.5 | 161.5 | 87.6 | 0.025 | 4/3/2 | 17.31 |
| Dual | GenerateDashboard | 287.7 | 147.1 | 84.6 | 0 | 0/0/0 | 17.31 |
| Dual | CheckDashboardPayloadCache | 289.3 | 148.5 | 74.8 | 0.008 | 2/2/2 | 17.31 |
| Dual | ReadNormalizationInputs | 335.9 | 187.9 | 94.2 | 0.751 | 51/14/4 | 20.35 |
| Dual | NormalizeDashboardData | 421.1 | 249.4 | 179.8 | 181.090 | 11658/605/49 | 11.64 |
| Dual | PrepareDashboardPayload | 370.6 | 198.4 | 93.6 | 0.032 | 6/4/4 | 11.90 |
| Dual | PrepareDashboardLibraries | 372.2 | 199.5 | 93.6 | 0.023 | 3/2/2 | 12.15 |
| Dual | LoadDashboardTemplates | 374.8 | 201.9 | 96.7 | 0.031 | 4/2/2 | 13.26 |
| Dual | WriteHostedDashboard | 379.0 | 204.8 | 94.3 | 5.131 | 330/6/4 | 22.39 |
| Dual | WriteSelfContainedDashboard | 379.0 | 204.7 | 108.5 | 0.068 | 7/4/4 | 13.91 |
| Dual | ExportResults | 339.1 | 163.0 | 90.1 | 0 | 0/0/0 | 13.91 |
| Dual | Completed | 681.3 | 704.8 | 373.8 | 0 | 0/0/0 | 293.96 |

Start-to-final cumulative allocation deltas were 188.622 GiB (Hosted) and 189.082 GiB (Dual), with Gen0/1/2 deltas 12124/613/73 and 12123/666/79 respectively. Those large allocation totals are not resident memory. Normalization dominates allocation churn, but does not explain the final Dual working-set crest on its own.

### Peak localization and next proposal

The pre-lookup payload crest (`PayloadClose PreLookupGc batchTitles`) was 421.2/421.1 MiB WS and 180.0/179.8 MiB GC for Hosted/Dual. The existing lookup GC reduced GC to 107.7 MiB in both modes; normalization cleanup reached 79.3 MiB GC in both. The transient-context release before payload close already exists and is covered by `Test-InvokeContentStoreNormalizationReleasesTransientContextBeforePayloadClose`; repeating it is not a new candidate.

Hosted assembly ended at 378.7 MiB WS; Dual hosted assembly at 378.9 MiB and self-contained assembly at 342.4 MiB. Both still reported a process high-water of 421.2 MiB through assembly. Dual's process peak rose only in the later publication/completion interval, so these measurements do not justify changing generator base64/template substitution.

| ExportResults sample to Completed sample | Hosted | Dual |
| --- | ---: | ---: |
| Sample-to-sample seconds (not exclusive export time) | 23.981 | 39.543 |
| Allocation delta, bytes | 727,889,536 | 1,364,492,472 |
| Gen0/1/2 delta | 14/6/2 | 20/12/5 |
| Final last-GC generation | 2 | 1 |
| Final last-GC heap, bytes | 170,907,328 | 390,400,672 |
| Final last-GC committed, bytes | 676,880,384 | 441,217,024 |
| Final last-GC total fragmentation, bytes | 1,543,320 | 4,276,312 |
| Final last-GC LOH before/after, bytes | 542,519,848 / 91,007,640 | 308,243,672 / 308,243,672 |
| Final last-GC LOH fragmentation before/after, bytes | 1,214,032 / 1,213,712 | 2,262,360 / 2,262,360 |

The Astra-approved baseline led to the network-free exact-owner probe below. The final cloud stage also includes uploads, verification, hashing and status serialization, so its snapshots alone cannot causally identify a specific call. The later strict-comment candidate trial is recorded separately below.

### Local reference-reader candidate (2026-09-30)

The actual policy owners are `Get-DashboardRequiredAssetName`, `Get-DashboardPublishedAssetPrefix`, and `Get-DashboardDependencyPolicy`. The baseline used byte-exact pre-agent `DashboardGeneration.ps1` (SHA-256 `e19d2413ea973dca3af55b1a601245440360fc7a10311dc0a18a6f605b896eac`), not a reconstructed approximation. Before any canonical edit, the first probe established meaningful whole-HTML read/reference allocation pressure; its corrected final replay supplies the numbers below. Initial LOH readings were superseded after discovering that PowerShell could not expose the span-backed generation statistics; the final harness reads those statistics in C#.

Each lane used a fresh, sequential `pwsh -NoProfile` child, both saved Dual backup roots (including the 22,575,578-byte self-contained root), and its own saved run-3 candidate roots. Prior/candidate string lifetimes follow the publisher loops: prior roots use the tracked-root order; candidates use the actual recursive file enumeration, not that prior-root list. There was no payload decode or cloud access. Guards required at least 2 GiB free RAM before launch and throughout execution, and child process high-water WS at most 2 GiB; no concurrent children or unrelated process termination occurred. Every read, required-reference call, format call and applicable prefix call recorded allocation bytes, elapsed time, instantaneous/process-peak WS, private/peak-commit bytes, GC heap/collection counters and last-GC LOH. End-of-interval OS high-water and independent 20-ms sampled maxima are retained separately. Logs contain scalars, counts and hashes only.

| Local lane | Allocated MiB, old/new | Process-peak WS MiB, old/new | Sampled-peak private MiB, old/new | Max last-GC LOH MiB, old/new | Relevant-call seconds, old/new |
| --- | ---: | ---: | ---: | ---: | ---: |
| Hosted | 545.33 / 16.98 | 724.20 / 183.55 | 667.33 / 90.96 | 498.73 / 4.14 | 2.509 / 0.387 |
| Dual | 1147.98 / 16.78 | 866.52 / 184.22 | 799.65 / 91.53 | 240.37 / 4.14 | 5.666 / 0.578 |

Sampled WS maxima were 724.19/183.55 MiB (Hosted old/new) and 866.52/184.21 MiB (Dual old/new), within 0.01 MiB of the independently recorded OS high-water. Last-GC LOH is not an instantaneous retained-object measurement. These are single local reference-resolution comparisons, not full-pipeline timing, Azure memory, or acceptance claims.

`Get-DashboardReferenceHtmlFromPath` uses a buffered `TextReader` scanner, retaining only `dashboardConfig`/`dataFormat` script bodies and external script/link tags. It never materializes the embedded compressed payload or PDF bundle. Markup/config/aggregate metadata limits fail explicitly rather than clipping. The compact metadata goes through the **unchanged** string policy and structured JSON parser. Publication replaces only the recovery/prior/candidate reference reads; lease, ETag, recovery identities, rollback and artifact checks are unchanged. The string API and service validator remain available unchanged.

Exact root-byte hashes, required-reference counts/hashes, formats and asset prefixes matched for all saved old/new generated roots. All other canonical source/template bytes matched the pre-agent inventory except the intended owning helper and publisher call sites. These historical measurements precede the parser blocker repair below; the earlier single-quoted/reordered-ID acceptance was unsafe normalization, not compatibility evidence. A separately guarded streamed 64-MiB inline-PDF control produced 149 metadata characters from 67,109,095 HTML bytes with zero references and unchanged file SHA-256; read/policy allocation was 344,704 bytes (Hosted child) and 330,744 bytes (Dual child). Its full HTML was never read into a string.

Full deterministic preflight and Azure release build passed. AST comparisons confirmed source/generated/extracted-package helper and publisher identity and unchanged original string-policy bodies. Extracted release probes also preserved exact root/reference parity: process peaks were 190.16/190.16 MiB for Hosted/Dual, allocations 17.04/16.81 MiB. Shared/runbook/Function fingerprint is `e13fc2a49f98f595e658b50ec0709749133ea66fb3e12d0ad69713fb1d8e528e`; release ZIP SHA-256 is `45a2c7a1c05c522146b7cc72e8afde7af676ee41414b25149057f76e8d0a3976`. The generated template publisher was normalized mechanically to BOM+LF, preserving regenerated fingerprint `707ad804c822de4fe14de82f611f963e4d4ed8e60e7aab3439155efc51ce207c`; only that fingerprint differs from its Git baseline. Its supported `-WhatIf` smoke passed after formatting. The release retains the builder's original artifact bytes, with its own raw-hash manifest.

Evidence: `.local/reference-probe/` contains immutable pre-agent hashes, exact baseline source copy, per-call `Baseline-*`, `Candidate-*` and `Packaged-*` scalar JSON, separate `LargeInline-*` controls, `comparison.json`, full preflight/release logs and the extracted release. The harness is `.local/Probe-Issue69References.ps1`. Raw HTML remains private.

**Next cloud gate, separate authorization required:** use the same retained synthetic dataset/template identities, cold payload cache, existing-export/no-direct-merge flags and instrumentation, comparing the candidate against the controlled Dual 769.42-second baseline. The 10% ceiling is **846.36 seconds**. Review all phases, sampled WS and true process high-water independently; both must be **below 400 MiB**, with exact payload/reference parity and byte-exact restoration. Earlier normalization/assembly already reached about 421.2 MiB, so eliminating publication pressure alone does not establish that target. No cloud writes, new jobs, commits, agents or main-worktree changes were made for this candidate. **Issue 69 remains open; the memory target is not met.**

### Bounded reader compatibility contract

The reader is opt-in. Runbook and publisher `UseBoundedPublicationMetadataReader` default to `false`: production continues to use whole-HTML `Get-Content -Raw` for recovery, prior and candidate roots. The Function App fixes this flag to `false`, with no new environment setting. Unsupported comment variants, including internal double hyphens, are outside this reader's contract; rejection does not imply every such input is invalid browser HTML.

The file reader is a bounded projection for generated dashboard HTML, not an arbitrary HTML parser or an equivalent replacement for the unsafe string regex on every possible input. The original string-policy functions remain unchanged. Selected metadata opening tags and JSON bodies are preserved verbatim, including order, quoting and case of HTML tag/attribute names. Metadata IDs are case-sensitive and must be exactly `dashboardConfig` or `dataFormat`, unique, first attributes, and double-quoted as required by the existing string policy. Reordered, single-quoted, unquoted, encoded, wrong-case, duplicate or external metadata declarations are rejected rather than normalized into a newly accepted contract.

Actual script/link attributes are tokenized outside quoted values, including ordinary quoted/unquoted and boolean attributes; text such as `data-note=' id="dashboardConfig"'` is not an ID. External reference attributes must be quoted, singular per tag, and match the existing regex's exact result; ignored unquoted references, conflicting src/href and reference-like text inside another attribute are rejected. Supported comments terminate on `-->` independently of quotes and cannot select metadata or emit references. Internal double hyphens, nested comment openings (including partial nested openings that reach an internal double hyphen), abrupt `<!-->`/`<!--->` openings, unterminated comments and over-limit comments are rejected, not normalized as arbitrary browser HTML. HTML DOCTYPE is supported; XML processing instructions, CDATA and other declarations are rejected. This does not support arbitrary foreign content, alternate raw-text elements, browser error recovery or scripting-generated metadata.

Skipped script raw text terminates at case-insensitive `</script>` or `</script` followed by HTML whitespace and `>`, even inside JavaScript quotes. Following script/link asset tags are retained. Metadata-body whitespace closing tags are rejected because the original string policy cannot extract them. Script bodies are not harvested for phantom references: reference-like script/link markup in a skipped body is rejected conservatively because removing it could change the old regex's result. Comments intentionally differ from the string API's unsafe false positives; normative generated variants require exact string/file required-reference sets, not merely successful parsing or equal counts.

Malformed/over-limit tags, comments, metadata bodies or aggregate metadata throw without clipping. Existing publication failure handling prevents pruning or candidate root commit when prior-root inspection fails, preserves all prior-generation bytes, and releases the lease in `finally`; Dual may already have written a durable recovery backup for its first valid root. The existing atomic publisher regression exercises the actual in-memory publisher with external PDF prior roots, fake quoted IDs, apostrophe comments, both whitespace closers, duplicate IDs, raw-text phantom markup and bounded failures. Valid cases retain both PDF assets and the complete generation; rejected cases preserve all prior blobs and publish no candidate blobs.

Final repaired-source full deterministic preflight and release build passed, including the source/generated exact-reference matrix and actual publisher reproductions in SelfContained, Hosted and Dual (four valid and seven rejected prior-root cases per mode). Editor diagnostics and `git diff --check` were clean. The exact embedded C# reader compiled with C# 12 against managed .NET 8 runtime assemblies only, then executed on installed .NET 8.0.31 with runtime roll-forward disabled: six normative and fifteen rejection controls passed, and all six saved-root metadata hashes matched a fresh PowerShell process. This validates the reader on .NET 8 locally, not PowerShell 7.4 Azure imports, Automation 8.0.28, or a deployed publisher. Persistent PowerShell `Add-Type` caching required fresh processes; an initial stale-session hash mismatch is not runtime evidence.

Fresh sequential source and extracted-release probes preserved exact saved-root bytes, required-reference sets, formats and prefixes against the original baseline. These final comparisons exclude the separate 64-MiB control from their measured call sequence.

| Repaired local lane | Implementation | Allocated MiB | Process-peak WS MiB | Sampled-peak WS MiB | Relevant-call seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| Hosted | Source | 17.47 | 185.81 | 185.77 | 0.674 |
| Dual | Source | 16.80 | 189.56 | 189.50 | 1.139 |
| Hosted | Extracted release | 16.93 | 193.64 | 193.61 | 0.694 |
| Dual | Extracted release | 16.78 | 191.45 | 191.40 | 1.080 |

The separate repaired-source streamed 64-MiB controls returned 149 metadata characters and zero references with unchanged file hashes. Source/generated/extracted-release helper and publisher AST identity passed, and all four original string-policy function bodies matched the pre-agent baseline exactly. Final shared/runbook/Function fingerprint: `67055bbd8ae03d895652fe22e4c7317fb1c75016a87a1ff45b9367954544817d`. Repaired release ZIP SHA-256: `3791173b33525942724e1b66acb96e459bf24d0964c8b33a57d8e664c92517e2`. Evidence is under `.local/reference-probe/`: `repair-preflight.txt`, `repair-release.txt`, `repair-comparison.json`, `Repair-{Candidate,Packaged,LargeInline}-{Hosted,Dual}.json`, `net8-repair/result.txt`, and `Azure-issue69-parser-repair.zip`. The historical candidate files/package above are superseded for parser safety. No cloud writes/jobs, agents, commits or main edits occurred; issue 69's Azure memory target remains unverified and unmet.

The third-review strict-comment release supersedes the parser-repair release above. Its current shared/runbook/Function fingerprint is `5c7aa687b2bbc44401555d679fe3c6655e79465e48fcb318ef96889bbebf8276`, ZIP SHA-256 is `04266253d265c89b4ba40bb3ea7d9e7fd506b8add4a7b24afeb16b8c4d6a4c61`, and manifest-recorded runbook SHA-256 is `723e706466c26fdde7d7cee3598aefb2e72f1803805849d0a7cd31b16112ef2f`. Evidence: `.local/reference-probe/net8-strict-comment/{Azure-issue69-strict-comment.manifest.json,final-preflight.txt,packaged-publisher.txt,release-build.txt}`. Normative generated-root string/file reference equality remains required; comment rejection controls do not imply arbitrary HTML compatibility. The candidate trial below uses these reviewed bytes without source optimization.

### Strict-comment Dual trial and default-off gate

The saved candidate completed with artifact validation passed, exact compressed/decompressed payload parity (1,187,395 rows), `restored_exactly=true`, and zero restoration errors. These are **not performance acceptance**. Independent local hashing revalidated all 23 exports, 11 dashboards and 23 templates against the captured original manifest, plus the saved original/restored runbook SHA-256 `9c8d25a60ef44b035042ad078a8f702fe4110bfb007552d6b093ff6dfb32b3df`. This verification did not restore anything or start another job. Raw identities and evidence remain private under `.local/candidate-strict-comment-20260930-144011/Dual/`; the comparison also rechecks all 27 control-stage rows and exact generated-root reference sets.

| Measure | Controlled Dual | Strict-comment candidate | Gate |
| --- | ---: | ---: | --- |
| Creation-to-completion | 769.42 s | 875.39 s (+13.77%) | Failed: ceiling 846.36 s |
| Sampled peak WS | 681.3 MiB | 413.8 MiB, NormalizeDashboardData | Failed: below 400 MiB required |
| True process high-water WS | 681.3 MiB | 413.8 MiB | Failed: below 400 MiB required |
| Artifact/payload parity | Passed | Passed | Separate artifact gate passed |
| Captured byte-exact restoration | Passed | Passed; independently rehashed | Separate restoration gate passed |

The within-stage normalization sample span increased by 105.96 s; the ExportResults-to-Completed sample interval shortened by 24.09 s (39.543 to 15.457 s). These are phase observations, not exclusive method timings or causal reader costs. The workers have the same reported runtime class (PowerShell 7.4.6, .NET 8.0.28, X64, one processor, workstation GC), but are different pooled workers with one measurement each. This does not establish why normalization timing varied. **The full-pipeline memory target remains unmet and issue 69 remains open.**

The gate preserves the publisher's existing API: omitting the new optional boolean selects the original whole-HTML reader. Bounded-reader parser/retention tests explicitly opt in; the default legacy upload-fault matrix remains required for source, generated runbook, Function and extracted package. The reader/parser and original string policy are unchanged by this gate.

For a separately authorized, temporarily deployed candidate, the explicit benchmark reader selection is reproducible as follows (not executed in this continuation):

```powershell
& .\tests\Measure-RunbookOnlyAzureBenchmark.ps1 `
  -SubscriptionId $subscriptionId -AutomationAccountName $automationAccount `
  -AutomationResourceGroup $resourceGroup -RunbookName $runbookName `
  -StorageAccountName $storageAccount -DashboardDeliveryMode Dual `
  -UseExistingExportsOnly:$true -UseBoundedPublicationMetadataReader $true `
  -UseDirectMergeDeviceLookup:$false -ExpectedTotalRows 1187395 `
  -SkipDeployRunbook -SkipTemplateUpload -ResultsOutputPath $privateResultPath
```

This benchmark alone does not own backup/restoration: use it only inside the approved guarded trial, after matching retained dataset/template identities, cold payload cache and candidate bytes. Permanent defaults remain unchanged. The guarded `Invoke-AzureRunbookValidation.ps1` wrapper forwards both experimental flags and keeps bounded reading default-off.

**Next planned trial, blocked pending parent Astra gate review, treatment eligibility and separate cloud authorization:** Dual, `UseExistingExportsOnly=true`, `UseBoundedPublicationMetadataReader=true`, `UseDirectMergeDeviceLookup=true`, matched 1,187,395-row dataset/templates and cold payload cache. The read-only streaming precheck on the actual saved gzip machine snapshot and current dictionary **failed at profile index 0**; no IDs were logged and profiles were not reordered. Removed machine entries are ignored exactly as in the existing helper. Do not launch this combined trial on the current dataset. A partitioned dictionary, blank/mismatched ID, unavailable direct path or `Post-DirectMergeFallbackMachineRead` outcome fails treatment eligibility even if a job completes. Keep the original 846.36-second ceiling, both sub-400-MiB memory gates, exact artifact parity and independent restoration requirements. The existing 10,000-template compiled-selection threshold is unchanged; this 5,000-template lane must not be forced onto a new compiled path.

### Earlier control restoration

Default-off gate validation passed: focused benchmark argument/evidence forwarding, full `build/Invoke-RegressionValidation.ps1`, local `build/Build-AzureReleasePackage.ps1`, and the same atomic publisher matrix in source, generated runbook, generated Function and both extracted package entry points. Each mode passed six opted-in valid prior-root PDF retention cases and eleven opted-in fail-closed rejections; default legacy SelfContained/Hosted/Dual retained 4/14/15 upload-fault controls, recovery, hashes, leases and pruning checks. The unchanged reviewed reader passed actual .NET 8.0.31 with 8 normative, 22 rejection, 1,080 boundary checks and six saved-root exact metadata hashes. This is local validation, not new cloud acceptance.

The gate release is private at `.local/reference-probe/default-off-release/Azure-issue69-default-off.zip`, SHA-256 `cb4eb2dbeadb3fc064d0b8819182a04873b12f64c4292c9c556f061a7dd2cf18`; manifest-recorded runbook SHA-256 is `539f020c79da10abc00fb42b6dc9803b6451e6abf958585dfd14292ba6240bf3`. The shared/parser fingerprint remains `5c7aa687b2bbc44401555d679fe3c6655e79465e48fcb318ef96889bbebf8276`. Logs are `.local/reference-probe/default-off-{preflight,release-build,evidence-check,net8}.txt` and the release directory's per-artifact publisher logs. The package retains builder bytes; workspace template-publisher newline-only churn was removed with its fingerprint preserved. No cloud writes, jobs, repeated restoration, agents, commits or main-worktree edits occurred. Parent Astra review remains pending.

Both saved results are `passed`, `restored_exactly=true`, with no restoration errors. Original published runbook SHA-256 is `9c8d25a60ef44b035042ad078a8f702fe4110bfb007552d6b093ff6dfb32b3df`; all original exports, dashboards and templates, status inventory, auth, resources, runtime and disabled schedules were restored/verified. Dual recovery reused the already-completed job; it did not create another job. The read-only final parity task completed successfully in terminal `f5dc647b-47f6-4666-aac3-82dec2b03b88`. Restoration must not be repeated.

Continuation read-only cloud checks found zero `_validation/` or `_publication/recovery/` blobs, zero active jobs, and `DashboardPipeline-Daily` disabled. Local available RAM was 7.20 GiB after the parent's cleanup. No process termination, deployment, new job, schedule change, commit, agent launch or main-worktree edit was performed in this continuation. Parent Astra review and any later candidate authorization remain separate gates.

## Issue 70 worker-transfer evidence (2026-09-30)

**Large baseline: incomplete, RAM-blocked.** The prior capture stopped at 1,745,756,160 bytes free RAM (about 1.63 GiB), below the unchanged 2 GiB floor. No large browser run was launched during this repair. There is no completed large readiness measurement, cold/reload parity result, baseline/candidate comparison, or worker-timeout diagnosis. No transfer candidate or performance fix is claimed. The 3 GiB owned-family cap and production worker timeout remain unchanged.

The harness repair adds final-sample completion gating, asynchronous prelaunch/pre-CDP fail-closed inventory, browser-clock readiness instrumentation, independent owned cleanup with actual final inventory, and explicit count/cache eligibility assertions. Browser-free probes cover a final-sample cap breach, inventory exceptions including before CDP, final-sample minimum RAM, non-overlapping asynchronous sampling, bounded owned-root termination and already-exited races, missing Edge/server closure, owned profile removal, actual nonzero remaining process counts, and zero-row/cache-miss rejection. The existing telemetry lane also checks worker phase messages and backward-compatible payload envelopes.

Validation: full deterministic preflight completed successfully with no skip switch under a separate 1 GiB PowerShell memory guard (573.17 seconds). Browser limits were not reduced. Focused telemetry/cache/report-semantic regressions passed. Two actual two-row diagnostic controls timed out before dashboard readiness and are not acceptance passes. Both final inventories recorded zero owned processes and removed their profiles; their HTTP servers closed. The second recorded a guard-stop termination race; the subsequent already-exited repair is covered by mocks, not another browser run. Final external inventory must remain part of any renewed capture. Raw machine-local diagnostics, stacks, and profiles are not public evidence.

Large performance acceptance still requires an adequately provisioned session that maintains at least 2 GiB free RAM throughout the run. Keep eligible small-cache controls separate from large cache-ineligible reloads. See `tests/README.md` for the guarded command and timing/cleanup limitations.

### Renewed local Edge capture (2026-09-30)

**Large acceptance remains blocked; no transfer optimization or baseline/candidate comparison is claimed.** The clean measurement worktree started at `35379ff` after PR83. Actual isolated Microsoft Edge captures used the current manifest-assembled runtime and the unchanged immutable-generation Hosted assets from the controlled Issue 69 Dual archive. There were no Azure writes, commits, or changes to production worker/cache limits.

Streamed provenance: gzip size `15,351,202` bytes, SHA-256 `cd928b05840107bd9a694ec3c17030e5569300999115e40160c316dcaa6a9740`; decompressed size `65,580,317` bytes, SHA-256 `764d32ef55b7188dbc4d0b56b5bf358192824ccf1261aed0157e0c56e33aaf56`. The harness fingerprints the gzip and decompressed content without parsing or retaining the full payload in its Node process.

The earlier small controls contained inert regression Chart.js and pako placeholders, not real browser libraries. Replacing those libraries in a private control copy resolved initialization and cache-hit reload failures. The harness now rejects those placeholders before launch, retains scalar initialization/failure frames, tolerates a temporarily locked CDP port file within the existing startup deadline, and separates single-flight observational CDP probes from the bounded fail-closed resource inventory. The former five-second heap-probe abort was a harness failure, not a production worker timeout. Family private-memory samples are now recorded alongside working set; CDP heap samples remain main-renderer-only and exclude worker heaps.

| Capture | Cold readiness event / host observation | Reload readiness | Result |
| --- | ---: | ---: | --- |
| Earlier real-library two-row control, one pair | `404.6 ms` | `302.2 ms` | Readiness/cache consistency only: exact normalized rows, five report render markers, equal summary digests, real compressed-cache hit; filtered/impact/card counts were zero, not semantic coverage |
| Large diagnostic before final streaming harness | `5,392.6 ms` / `12,127.5 ms` | Not reached | Failed during report validation: free RAM `1,999,192,064` bytes, below the unchanged 2 GiB floor |
| Final large capture, one cold attempt | `5,729.4 ms` / `13,621.0 ms` | Not reached | Failed during report validation: owned-family working set `3,226,218,496` bytes, above the unchanged 3 GiB cap |

Final large partial timings: worker inflate `227.7 ms`, worker JSON parse `939.0 ms`, worker wait `2,515.1 ms`, and posted-to-received delivery `1,306.2 ms`. The return format was `lookups-raw-columns`; no worker timeout or main-thread fallback was observed in the readiness snapshot. Delivery includes structured serialization, queueing, and deserialization, not a pure clone benchmark. Total denormalization was `4,856.9 ms`; init total was `5,581.2 ms`. The readiness event preceded the first report render, so neither event time nor host observation is a measured interaction latency.

The final partial snapshot verified `1,187,395` raw and normalized rows and severity cards `291,787 / 293,136 / 295,682 / 306,790`, summing to the same total. Its `activeRows` field is the history-filtered source-row count, not the grouped active-report count. The requested grouped active count `53,279`, impact count `25`, all-report parity, and large cold/reload parity remain unverified. Production cache eligibility was false at the unchanged `500,000`-row boundary; no large cache hit or reload improvement is claimed.

Final large sampled peaks: main-renderer JS heap `1,092,701,100` bytes, owned-family working set `3,226,218,496` bytes, family private memory `2,782,855,168` bytes. Minimum sampled free RAM was `2,774,929,408` bytes. These are sampled observations across initialization and report validation, not exact instantaneous peaks or worker-only memory. Additional host RAM did not remove the owned-family cap breach; completing this all-report workflow requires bounded runtime/report memory work, not a raised guard or worker deadline.

Historical validation: focused telemetry/provenance/lifecycle probes and full deterministic preflight passed with no skip switch. The earlier real-library Edge control established readiness/cache consistency, not report-content semantics. A subsequent final-review repair bounded the observational probe drain before cleanup; its focused telemetry/lifecycle regression passed, including a never-resolving probe. Those launched captures reported zero owned processes, removed their profiles, and closed their HTTP servers. These cleanup claims predate the exact-argument ownership repair and are not proof of safe neighbor selection. Raw captures and the preflight log remain private under the measurement worktree's ignored `.local/measurements/` directory. No production runtime change was made, so release artifacts and template fingerprints are unchanged.

The renewed harness-only repair uses native Windows argv parsing and exact normalized profile ownership, root creation provenance and fresh pre-kill identity checks. Mocked actual-PowerShell probes cover prefix/literal/duplicate exclusions, owned-root/descendant-only termination and PID reuse without real neighbor kills. Failure output is fixed-label and allowlisted, including command parsing, provenance, malformed payloads and evidence writes. `readinessCacheDigest` explicitly names the limited consistency check. The two-row positive control uses an unrestricted custom date range and requires positive bounded impact/card totals; large report semantics and all large acceptance gates remain unverified. Browser thresholds remain 3 GiB family working set and 2 GiB free RAM. No worker-transfer, typed-column, production or Azure change is part of this repair.

Renewed repair validation: focused ownership, privacy and telemetry/lifecycle checks passed, followed by full deterministic preflight with no skip switch. Exactly one real small Edge control was attempted afterward. Cold readiness was `458.3 ms`; the unrestricted custom date range selected `2` source rows, with impact count `1` and severity-card total `1`. The run failed its process-inventory check before completion/reload. This is a positive partial observation, not a passed control, cold/reload consistency result, report-content semantic proof or performance result. Only prelaunch resource inventory completed, so no owned-family peak is established by this attempt. Cleanup independently reported zero remaining owned processes, profile removed and HTTP server closed; a subsequent external inventory found zero Issue 70/headless/debugging automation Edge processes, without terminating personal Edge. The private evidence is `.local/measurements/control-safety-repair.json`. No second browser attempt or large capture was made.

Next actual-run gate: diagnose and stabilize the process inventory, then obtain a complete real-library two-row positive-control cold/reload pass, including final resource samples and successful cleanup, before another large capture. Keep the existing memory guards unchanged. This is partial measurement work for Refs #70, not issue closure or large-performance acceptance.

### Inventory diagnostic expectation follow-up (2026-09-30)

**One small control blocked; performance acceptance remains unverified.** The sole additional harness edit corrected the invalid-C# `Add-Type` diagnostic expectation to `unclassified`, retained the compile phase and fixed private error, and added a real `System.InvalidOperationException` label check. The allowlist, ownership selection, timeouts and resource guards were not changed. Ownership, privacy, mock self-test and telemetry checks each exited 0; full deterministic preflight passed without skip switches. Its generated Azure-script churn was discarded.

Fresh exact-profile inventory completed in `1690.0 ms` with zero owned processes, below the unchanged `5000 ms` timeout. Exactly one real-library Edge control was attempted using the existing measurement worktree's two-row historical fixture and the manual `2026-01-01/2026-01-02` range. The requested recent generation-2 fixture could not be identified from the supplied shorthand, so this retained fixture is not proof of that fixture's behavior. Private evidence: `.local/issue-70-measurement/.local/measurements/control-inventory-diagnostic-only.json` relative to the parent workspace.

Cold readiness was observed at `387.8 ms`, with exactly `2` raw and normalized rows, successful initialization, all five report markers and a matching compressed-cache entry. The positive-control assertions failed: selected active rows, impact rows and severity-card total were each `2`, not the required `1`. The public failure remained `operation-failed` / `unclassified`; these observations do not make the control pass. Reload, real reload cache hit, cold/reload parity and final resource resampling were not reached. Final cap/floor acceptance and performance metrics remain unchecked. Partial resource samples are not final acceptance evidence.

No sampler timed out. Host inventory durations were `1733.2`, `3593.4` and `1542.1 ms`, all exit 0; termination calls took `2092.7 ms` (exit 1, phase `termination`) and `1336.0 ms` (exit 0). These are whole-call durations, not separate compile/CIM/selection timings. Cleanup retained a `Guard stop` error but verified zero owned processes, profile removal and HTTP server closure. Independent external inventory found zero automation Edge processes and preserved all eight unrelated Edge process identities. This candidate's actual enforced limits were the stricter `2 GiB` family cap and `3 GiB` free-memory floor, unchanged from its existing code. No retry, second source correction, large capture, production/Azure edit, commit, agent or main-worktree change was made.

### Fixture-only positive-control preparation (2026-09-30)

The named ignored fixture `.local/two-row-positive-control` in the parent workspace was generated with existing canonical shared writers, `New-SyntheticLiveExport.ps1` and `Generate-VulnerabilityDashboard.ps1`. Its two temporal observations share one CVE, device, software and remediation target but have different software versions. The historical observation has supported `None` severity; the current observation has `High` severity. Both overlap the unchanged `2026-01-01/2026-01-02` custom range. Card total one depends on these severity states, not CVE deduplication.

Artifact-only preflight decoded and materialized the generated columnar payload through existing runtime APIs: raw rows `2`, normalized rows `2`, selected source rows `2`, distinct CVEs/devices `1/1`, active-table rows `1`, impact rows `1`, severity-card total `1`. Chart.js and pako were copied only into ignored generated assets after matching their hashes to prior actual real-library evidence. The private fixture manifest records declared row IDs/ordinals, row/group hashes, artifact digests, expected counts and the scope of this non-browser check. Payload SHA-256: `f5c8d18bb322f076d16c9e1d321c44b7ee8f74c55b84ce18567a106f23560d3d`.

**Blocked before Edge; no cold/reload pass claimed.** The requested `3 GiB` family cap and `2 GiB` free-memory floor differ from the unchanged inventory harness's `2 GiB` cap and `3 GiB` floor. No harness, production, selector, ownership, timeout or expectation changes were made to resolve that constraint conflict. No browser, profile or HTTP server was created. The external resource sample recorded zero automation/Issue 70 Edge processes and `5020463104` free-memory bytes. Live cache-hit/parity, final browser-family resource acceptance and performance remain unverified. The earlier focused/full preflight results were not rerun or relabeled as this fixture's live acceptance.

### Authorized strict fixture-only actual control (2026-09-30; capture 2026-10-01 UTC)

**Overall failed: actual Node exit 1; no successful control acceptance claimed.** Parent authorization resolved the earlier configuration conflict by accepting the current, unchanged harness defaults at `tests/Measure-DashboardWorkerTransfer.js:748`: owned-family working set cap `2147483648` bytes (2 GiB), free-memory floor `3221225472` bytes (3 GiB), readiness `120000 ms`, inventory `5000 ms`, termination `15000 ms`. Earlier references to an unchanged 3 GiB cap / 2 GiB floor describe prior capture configuration, not this inventory harness. The guarded-command README's 3/2 description is also historical and does not override the current 2/3 source bounds. No threshold was raised or switched.

Exactly one actual attempt used the existing documented CLI shape, explicit positive-control mode, the prepared parent-workspace fixture and existing cached Playwright:

```powershell
$env:PLAYWRIGHT_MODULE = 'C:/Users/NathanMcNulty/AppData/Local/npm-cache/_npx/9833c18b2d85bc59/node_modules/playwright'
& 'C:/Program Files/nodejs/node.exe' .local/issue-70-inventory/tests/Measure-DashboardWorkerTransfer.js .local/two-row-positive-control .local/two-row-positive-control/actual-strict-control.json 1 2 --positive-control
```

The command was run from the parent workspace; Node was resolved with `Get-Command -CommandType Application | Select-Object -First 1`, and the prior environment value was restored afterward. Prelaunch verification matched eight manifest hashes, including real Chart.js/pako and assembled runtime; independent preflight free RAM was `4943732736` bytes. Harness SHA-256 remained `a42b1675448fc1120e51441c7173027f93d690556b705550998516ccf23ee9c3`, and assembled-runtime SHA-256 remained `248630e168d864943fa8a1be5fd04d89348057038f7cb54672f33bef3e496467` before/after.

| Observation | Cold | Reload |
| --- | ---: | ---: |
| Per-load assertion status | passed | passed |
| Browser readiness ms / host observation ms | 466.5 / 560.2 | 267.3 / 306.6 |
| Raw / normalized / selected source rows | 2 / 2 / 2 | 2 / 2 / 2 |
| Active-table / impact / severity-card total | 1 / 1 / 1 | 1 / 1 / 1 |
| Eligible cache state / compressed-cache hits | cold / 0 | hit / 1 |
| IndexedDB entries / matching compressed-entry rows | 2 / 2 | 2 / 2 |
| External requests / page errors / failed resources / failed responses | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |

Both loads completed initialization, selected `2026-01-01/2026-01-02`, rendered all five required reports, passed positive-control observations and awaited separate successful final resource samples. Their identical `readinessCacheDigest` is `372693ce28c6993afec25e2b0cef3dce7f141ac101a60d6274b9f4e640f804c3`. This is limited readiness/cache consistency, not full report-content semantic proof or large-data performance acceptance. Browser readiness is not interaction latency.

| Actual resource sample stage | Owned processes | Family working-set bytes | Family private bytes | Free-memory bytes |
| --- | ---: | ---: | ---: | ---: |
| prelaunch | 0 | 0 | 0 | 4800880640 |
| post-spawn | 15 | 880865280 | 356913152 | 4542459904 |
| cold final | 17 | 988372992 | 391127040 | 4512215040 |
| reload:readiness | 17 | 1011015680 | 404590592 | 4475097088 |
| reload final | 17 | 1008312320 | 404742144 | 4489273344 |

Every recorded sample stayed strictly below the 2 GiB family cap and above the 3 GiB free floor. Sampled family peak was `1011015680` bytes; sampled minimum free RAM was `4475097088` bytes. These are sampled bounds, not continuous or absolute high-water proof. No actual resource-guard breach is recorded, and there is no `Guard stop` cleanup error. After both valid final samples, teardown reported the fixed cleanup label `Owned family termination`; the allowlisted failure was phase `browser`, reason `cleanup`, code `unclassified`. No raw dynamic error message or more specific underlying inventory diagnostic was retained; do not infer one. This cleanup failure makes overall status `blocked-or-failed` and Node exit 1 despite both per-load passes.

Cleanup and independent final inventory nevertheless verified zero remaining owned/automation Edge processes, removed profiles (zero before/after), and closed HTTP server. All eight unrelated Edge PID/creation-time identities survived unchanged (eight before/after); no unrelated browser was terminated. Independent final sample at `2026-10-01T01:39:00.2369815Z` recorded owned-family bytes `0` and free RAM `5037191168` bytes. Private raw evidence is `.local/two-row-positive-control/actual-strict-control.json` relative to the parent workspace, SHA-256 `05f45241566ab18dc85465e5b5e9dab78821591cfeccf73b51e8c53b9d6eb7af`. The fixture manifest's earlier blocked-before-browser entry remains a historical preparation record, superseded for this attempt by this evidence and outcome. No blind rerun, simulation, source/test/fixture/harness patch, main-worktree edit, agent, Azure write or commit occurred. Only this documentation follow-up was made; successful overall small-control acceptance and all large acceptance gates remain unverified.

### Narrow teardown diagnostic probe (2026-09-30)

**Root cause unresolved; no repair or new actual-control acceptance claimed.** The retained strict actual control still has Node exit 1 and the fixed `Owned family termination` failure. Its original serialized record has no underlying termination diagnostic, so neither a deadline nor an exit race can be established from that record. Final owned count zero does not turn this failed cleanup into success.

The isolated inventory harness now retains fixed cleanup labels, numeric elapsed milliseconds, and an allowlisted `deadline`, `process-inventory`, or `unclassified` code. Existing allowlisted inventory category, exception type, exit code and phase are retained when available; raw error messages, stacks and private paths are not serialized. This is a reversible diagnostic probe, not a termination-policy change.

Focused `node tests/Measure-DashboardWorkerTransfer.js --mock` passed after three harness patches, including one correction to the nested mock's diagnostic-phase expectation. Actual PowerShell probes verified legitimate empty-family termination, selected processes disappearing before fresh inventory, fresh unknown-root rejection, independent snapshots, root PID reuse and exact profile selection. Synthetic timeout, cancellation and shutdown failures remained cleanup errors even when a separate final inventory returned zero. A never-resolving promise remained bounded, and private sentinel messages were excluded. Disposable non-browser process probes did not reproduce a StartTime exit failure; a read-only fresh CIM query did not establish a command deadline failure.

No fourth harness patch, full deterministic preflight, new browser attempt, large capture, threshold override, production/Azure edit, agent or commit was made. The named actual evidence was not overwritten or relabeled. Current limits remain the 2 GiB family cap / 3 GiB free-memory floor, 5000 ms inventory bound and 15000 ms outer termination bound; historical 3/2 limits do not override them. The next controlling evidence must identify the helper's actual structured failure before a grounded termination repair and the authorized single small-control rerun. Overall successful small-control acceptance and all large acceptance gates remain unverified.

### Guarded large characterization (2026-10-01 UTC)

**GUARD_REJECTED, actual Node exit 1; not a performance pass.** Exactly one actual Edge CLI launch used the clean `perf/issue-70-guarded-characterization` worktree at merged source `b88695d8d196fd6f1a58181ce497a4e35055b2c4`, with one cold attempt and no reload or retry. Capture window: `2026-10-01T05:09:29.796Z` to `2026-10-01T05:09:50.197Z`. The unchanged guards were owned-family working set `2147483648` bytes, free RAM `3221225472` bytes, readiness `120000 ms`, inventory `5000 ms`, and termination `15000 ms`. No JS heap flags or timeout changes were used. The first rejecting sample was the free-memory floor, not the family cap or teardown.

The prerequisite positive final attestation was independently bound to current harness SHA-256 `c1c552a55f5af13c580e9ba5028ee685eee3e043e1fcfebb42d331d73fc03b12` and assembled runtime SHA-256 `248630e168d864943fa8a1be5fd04d89348057038f7cb54672f33bef3e496467`. Its retained small-control capture SHA-256 `372746d9cf283d2597c9ce0b6c56018b1ece93e41168c1d11b52a2b3fb04bf10` and fixture-manifest SHA-256 `402b34aa5284249488e39d3e59a3c602e619efbb1119023d062770ab649c5bfd` matched actual files. That control exited 0: cold/reload readiness `731.2 / 280.7 ms`, compressed-cache hits `0 / 1`, all five render markers, zero owned processes, profile removed, server closed and all eight unrelated Edge identities preserved. This establishes small-control lifecycle/readiness/cache consistency, not large performance or five grouped-report semantic parity. It was not relaunched here.

The exact retained synthetic Hosted root and payload were resolved from the prior measurement fingerprints, not the live root dashboard or MDE. Before capture, independent streamed gzip validation/hash verification matched compressed `15351202` bytes / SHA-256 `cd928b05840107bd9a694ec3c17030e5569300999115e40160c316dcaa6a9740` and decompressed `65580317` bytes / SHA-256 `764d32ef55b7188dbc4d0b56b5bf358192824ccf1261aed0157e0c56e33aaf56`. The hash-bound summary declares `1187395` rows, `49476` devices and `5000` CVEs; no full payload parse was done in Node. Actual large normalized/report counts were not reached and remain unverified. The retained HTML, summary and compressed payload were unchanged afterward. Pre-wrapper free RAM was `4342018048` bytes; there were zero automation families and zero prior harness profiles. No personal Edge or PowerShell process was terminated.

| Resource sampler label | Host start/end ms | Sample UTC (2026-10-01) | Owned processes | Family WS bytes | Family private bytes | Free RAM bytes |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| prelaunch | 991.4727 / 2419.8260 | 05:09:32.294 | 0 | 0 | 0 | 4195581952 |
| post-spawn | 2432.6861 / 7002.8223 | 05:09:36.877 | 17 | 1246150656 | 752144384 | 3476504576 |
| first:readiness | 8474.4455 / 11283.1858 | 05:09:41.157 | 19 | 1595678720 | 1052418048 | 3273240576 |
| first:readiness, first floor crossing | 11481.6743 / 13839.7366 | 05:09:43.714 | 18 | 1716019200 | 1188487168 | 3210092544 |

These are asynchronous, single-flight process-family samples: host monotonic intervals bracket inventory, and UTC marks sample completion. The rejecting sample completed `9673.9902 ms` after host navigation start, not after browser readiness. Family WS/private include the owned browser, renderers, workers and descendants; they are not main-JS heap, causal allocation attribution or continuous high-water measurements. Sampled family WS/private maxima were `1716019200 / 1188487168` bytes; minimum sampled free RAM was `3210092544` bytes. Main-renderer CDP `JSHeapUsedSize` sampled maximum was `457228804` bytes; this scalar has no retained sample timestamp, cannot be attached to a particular table row, and excludes worker heaps. Renderer probes can stall independently of the resource guard.

| Partial retained phase | Duration ms | Evidence scope |
| --- | ---: | --- |
| workerInflateMs | 389.4 | Worker phase message |
| workerParseMs | 731.0 | Worker phase message |
| workerWaitMs | 2457.5 | Host-runtime worker wait, overlaps delivery |
| workerDeliveryMs | 1262.4 | Posted-to-received interval; serialization, queueing and deserialization |

The last observational snapshot retained the `lookups-raw-columns` envelope. `denormalizeWithCaching` was marked completed while `init` and `ensureChartJsLoaded` were still running; ready-event/dashboard-ready flags were false, filter applications and active-report renders were zero. No completed readiness snapshot, readiness/interaction latency, final resource acceptance, all-five-report parity, or reload was obtained. Initial zero phase placeholders are not completed timings. Final timeout/fallback counters were not captured: envelope receipt is not proof of their absence throughout initialization. Delivery exceeds either retained inflate or parse duration in this sample, but does not isolate transfer allocation cost or establish that transfer dominates the full workflow.

Large datasets at or above the unchanged `500000`-row cache boundary are ineligible for normalized IndexedDB cache writes. Any future reload on this payload belongs to the **uncached large reload** lane, not the small cached-reload lane; no large cache-hit or reload-improvement claim is made here. Five grouped-report semantic parity remains unverified.

The local owners are `templates/dashboard/06-worker-runtime.js` (compressed decompress-only envelope) and `templates/dashboard/08-data-loading.js` (retained raw columns/lookups plus main-thread expanded row allocation). This overlapping representation is a plausible memory cost to investigate, not a causal conclusion from family WS. Worker termination already occurs before resolving the received result; there is no termination optimization to apply. A hypothetical `Int16` conversion of the three indexed number arrays `v/f/l`, assuming eight-byte old slots and two-byte new slots, saves only `21373110` bytes (about 20.38 MiB, roughly 21 MB), not a GiB. Actual V8 slot representation, index/sentinel ranges, conversion overlap, transfer behavior and grouped-report parity need separate evidence; no typed-array or production experiment was added.

Cleanup independently confirmed `remainingOwned=0`, profile absent, HTTP server closed, no cleanup errors, zero automation/new Edge processes and zero harness profiles afterward. All `8 / 8` unrelated PID/creation-time identities survived unchanged. Actual Node exit 1 is retained as an intentional guard rejection, not hidden as a passed test; teardown succeeded separately. All tracked files were unchanged through sampling. Only this documentation changed afterward; production, harness, cache/worker limits, Azure, schedules and MDE were untouched. No agents, commits, pushes, cloud jobs/writes or original dirty-worktree edits occurred.

Private root paths, payload location, process identities, exact commands, phase trace and sampler timeline remain ignored under the characterization worktree's `.local/characterization/`: `binding.json`, `launch-record.json`, `capture.json`, `capture.log`, `private-edge-after.json` and `result.json`. Capture SHA-256: `cf3771c13b822120825f660a53e621d7672d590f04c1eb09021391fdf7597489`. The structured scalar/source/provenance check is `validate-scalars.js`, with result `scalar-validation.json`; a docs-only result does not require another full preflight. Issue #70 stays open pending parent Astra review before publication and separate evidence for any runtime candidate.

## Current bounded-path acceptance (2026-07-12)

| Dataset / lane | Rows | Azure elapsed | True compiled peak WS | Private / GC peak | Semantic proof |
| --- | ---: | ---: | ---: | ---: | --- |
| `.local\fast-large-import` ContentReplay, Hosted | `1,187,395` | `114.34s` | `365.1 MB` | `438.2 MB` / `244.9 MB` | Exact decompressed payload equality; SHA-256 `745180e85d22e1132574857636fd9fd5a56865b466b15001af82c11f33a5b385` |
| checked-in `exports`, Hosted compatibility replay | `7,640` | `157.42s` | N/A (compatibility path) | `203.2 MB` / `129.1 MB` status peak | Canonical expanded-row equivalence; zero missing and zero extra |
| `.local\large-datasets\synthetic-50k-1_5m` Function App, Hosted compatibility replay | `1,484,239` | `~544s` active | N/A (compatibility path) | `816.3 MB` Azure Monitor WS; `449.5 MB` / `106.5 MB` status sample | Published summary/status agree: 50,000 devices and 5,000 CVEs |

The large seed contains 50,000 devices and 1,500,000 generated vulnerability rows; the raw replay lane's onboarded dashboard count is 1,187,395. The 365.1 MB value is the compiled projector's true pre-trim working-set high-water mark, not the lower status-boundary sample. The 400 MB Automation ceiling therefore had 34.9 MB of measured headroom. The compatibility replay intentionally includes Advanced Hunting CVE/device-user/inventory data, NVD data, and real scalar/array machine-tag forms.

The acceptance harness backed up and restored the published runbook and `exports`/`dashboards` blob manifests after each run. Raw evidence remains under `.local\azure-validation\`; use the guarded harness and preserve the same lane labels when refreshing these numbers.

Function App execution uses Flex Consumption metrics and is not subject to the Automation account's 400 MB working-set ceiling. Keep its Azure Monitor working-set and execution-unit values as a separate Function App baseline; do not compare them directly with the compiled Automation peak.

The raw result JSON files from the April 5, 2026 capture remain local-only under `.local/`. The April 20, 2026 ad hoc hosted review captures remain local-only under `.local/perf-triage/`, and the April 20, 2026 durable benchmark series remains local-only under `.local/benchmark-series/benchmark-medium-v1-20260420-004103/`.

## Recorded baselines

| Dataset | Command mode | Local | Runbook | Function App headline | Function timing notes |
| --- | --- | ---: | ---: | ---: | --- |
| `benchmark-medium-v1` | `current-only` durable series, 3 captures | `137.28s to 139.19s` | `91.69s to 114.19s` | `41.37s to 42.18s` | `active-execution`; end-to-end `43.10s to 43.43s`; pickup delay `1.24s to 1.73s` |
| `exports-synthetic` | `current-only` | `476.63s` | `250.45s` | `239.45s` | legacy `invoke-to-finish` |
| `exports-synthetic-live` | `current-only` | `2081.27s` | `957.14s` | `683.21s` | legacy `invoke-to-finish` |
| `review-synthetic-medium` | `current-only` Azure acceptance replay, 2 captures | `153.06s to 177.83s` | `96.94s to 105.19s` | `41.59s to 43.32s` | legacy `invoke-to-finish` |
| `benchmark-large-50k-v1` | `current-only` large-lane instrumentation series, 2 runbook captures + 1 function app capture | N/A | `689.73s to 733.05s` total; Generate dashboard `644.52s to 644.58s` (very consistent) | `597.66s` | `active-execution`; end-to-end `599.56s`; pickup delay `1.90s`; 50K devices / 1.5M rows |

## Persistent local cache workflow

| Dataset | Prime local run | Reuse after payload-cache eviction | Reuse elapsed delta | Normalize phase delta |
| --- | ---: | ---: | ---: | ---: |
| `benchmark-medium-v1` | `136.13s to 136.34s` | `45.44s to 45.49s` | `-90.90s to -90.66s` | `-87.92s to -84.95s` |
| `review-synthetic-medium` | `136.17s to 167.08s` | `45.47s to 45.66s` | `-121.42s to -90.70s` | `-109.95s to -84.52s` |
| `synthetic-50k-1_5m` | `1504.41s` | `414.98s` | `-1089.43s` | `-1015.27s` |

## Resource summary

| Dataset | Local peak RSS | Local peak private | Runbook peak WS | Runbook peak GC heap | Function peak WS | Function avg WS | Function execution units |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `benchmark-medium-v1` | `335179776 to 336478208` bytes | `236740608 to 238395392` bytes | `399.2 to 420.8 MB` | `88.8 to 105.4 MB` | `581.7 to 599.3 MB` | `581.7 to 599.3 MB` | `0.0` |
| `exports-synthetic` | `966336512` bytes | `921878528` bytes | `569.5 MB` | `286.8 MB` | `1800.9 MB` | `1276.2 MB` | `504217600` |
| `exports-synthetic-live` | `710160384` bytes | `616402944` bytes | `593.3 MB` | `298.2 MB` | `1029.2 MB` | `1029.2 MB` | `1172889600` |
| `review-synthetic-medium` | `333520896 to 341286912` bytes | `236150784 to 242094080` bytes | `407.6 to 412.5 MB` | `85.2 to 95.0 MB` | `580.6 to 587.6 MB` | `580.2 to 587.6 MB` | `0.0` |
| `benchmark-large-50k-v1` | N/A | N/A | `525.9 to 537.1 MB` | `113.8 to 113.9 MB` | `820.1 MB` | `820.1 MB` | `1,158,758,400` |

## Historical Stage 1 large Azure acceptance

| Dataset | Shape | Architecture | Azure path | Acceptance markers | Review notes |
| --- | --- | --- | --- | --- | --- |
| `synthetic-50k-1_5m` | `50,000` devices, `1,500,000` rows, `3,097` normalized CVE lookup entries | `monolithic-v1` | Azure Automation plus hosted Function App (`Dual`) | Function App execution accepted `2026-05-06T06:26:05Z`; dashboard blob written `2026-05-06T06:33:39Z`; blob-write interval `454s` | Historical Stage 1 anchor. Use the 2026-07-12 bounded-path acceptance above for the current Automation working-set gate, and retain this row for Function App comparison until a new Function App capture is accepted. |

## Recent memory triage notes

These notes capture recent memory experiments, including dead ends that should not be repeated and the machine-store prototype that survived large-lane validation.

| Date | Experiment | Dataset / lane | Result | Keep? |
| --- | --- | --- | --- | --- |
| `2026-05-08` | Machine-field pooling inside `MachineStore.ps1` | `benchmark-medium-v1-cold` hot-phase review | End-to-end peak worsened from `280936448` to `285462528` bytes RSS and from `173973504` to `177254400` bytes private. | No |
| `2026-05-08` | Advanced Hunting tuple compaction after bundle load | `benchmark-medium-v1-cold` input-load review | Post-compaction working set stayed flat at `191.0` to `191.1 MB`; GC heap moved from `60.0 MB` to `57.8 MB`, which was too small to change end-to-end normalization pressure. | No |
| `2026-05-08` | Azure replay with `tests\Measure-RunbookOnlyAzureBenchmark.ps1 -UseExistingExportsOnly` against shared storage | Existing-export replay | The blob set drifted and replayed only a much smaller lane, so the resulting ~`300 MB` runs were not comparable to the accepted `50k / 1.5M` envelope. | No |
| `2026-05-09` | ID-only machine index lower bound | `synthetic-50k-1_5m` large input-load review | After the same forced GC used by the runbook, retained state stayed at `437.0 MB` working set / `295.2 MB` GC heap, so it was not a useful lower-retention target. | No |
| `2026-05-09` | File-backed normalization machine lookup using buffered `offset + length` tuple reads | `synthetic-50k-1_5m` large input-load review plus local hot-phase review | Post-machine-read GC dropped retained machine lookup state from `415.0 MB` working set / `73.4 MB` GC heap to `407.4 MB` / `31.5 MB`. The full dual-package hot-phase review then completed successfully at `0.764 GB` peak tree RSS / `0.667 GB` peak private, with `Normalize source data = 1263.71s` and `Prepare normalized payload = 116.98s`. | Yes |
| `2026-05-09` | Dictionary-backed file-backed machine index | `synthetic-50k-1_5m` large input-load review | Clean isolated rerun landed at `406.1 MB` working set / `33.7 MB` GC heap after forced GC versus the accepted hashtable-backed file-backed baseline at `396.6 MB` / `33.0 MB`, so the alternate index shape lost memory headroom. | No |
| `2026-05-09` | Packed scalar `offset + length` entries for file-backed machine tuples | `synthetic-50k-1_5m` large input-load review | Peak load nudged down slightly to `436.6 MB`, but retained state after forced GC jumped to `429.6 MB` working set / `32.4 MB` GC heap versus the accepted `396.6 MB` / `33.0 MB` baseline, so the packed-entry variant was discarded. | No |
| `2026-05-09` | Bucketed file-backed machine lookup | `synthetic-50k-1_5m` large input-load review plus uncached local hot-phase review | Isolated load looked excellent at `189.4 MB` peak working set / `47.1 MB` GC heap and `183.8 MB` / `25.8 MB` after forced GC, but the uncached large hot-phase run stalled in normalization for more than `3128s` without finishing. | No |
| `2026-05-09` | Sequential profile-access probe over file-backed machine tuples | `synthetic-50k-1_5m` large profile-order review | On the exact `deviceProfiles` access pattern, the sequential cursor cut elapsed time from `188.84s` to `89.94s` with `0` misses / `0` pending spill entries, but peak memory stayed effectively flat (`446.7 MB` working set / `315.3 MB` GC heap). | Investigate |
| `2026-05-09` | Streamed array-file parser swap for `Machines_Current.json.gz` | `synthetic-50k-1_5m` large machine-input review | Replacing the array-document parse path with per-entry streaming did not materially move the accepted load benchmarks (`441.9 MB` / `306.0 MB` on `machine-file-backed`, `444.2 MB` / `304.0 MB` on merge-style profile access), so the change was reverted. | No |
| `2026-05-09` | Current-snapshot staged sequential machine lookup with bucket fallback | `synthetic-50k-1_5m` large profile-order review | The first implementation cut profile access time from `180.53s` to `101.48s` with `50000` sequential hits and `0` fallbacks, but peak memory regressed from `447.3 MB` / `305.5 MB` to `458.5 MB` / `311.3 MB`. A follow-up lower-allocation byte-stream reader then failed to finish the same access pass after more than `660s`, so the experiment was reverted. | No |
| `2026-05-09` | Mismatch-only merge path with bucketed spill fallback | `synthetic-50k-1_5m` large profile-order review plus local `exports` fallback review | On the seeded large lane, exact-order merge kept spill at `0` and finished in `77.86s`, but peak still regressed slightly to `448.0 MB` / `308.0 MB` versus the fresh file-backed baseline at `444.9 MB` / `305.7 MB`. A periodic-GC follow-up held GC slightly lower (`300.5 MB`) but worsened working set to `461.7 MB`. On the local real `exports` lane, fallback worked (`20` spills across `18` buckets; `19` spill resolutions, `0` misses) but stayed near parity at `142.9 MB` / `30.0 MB` / `0.64s` versus `139.6 MB` / `30.5 MB` / `0.59s`. | No |
| `2026-05-09` | Direct current-snapshot device-lookup projection | `synthetic-50k-1_5m` large device-profile projection review | On the real `Add-NormalizedDevice` file-backed baseline, the device-profile pass landed at `190.7 MB` working set / `56.0 MB` GC heap / `287.00s`. Replacing the machine lookup with a direct merge over the current machine snapshot plus immediate file-backed device-lookup projection cut that to `175.2 MB` / `48.2 MB` / `154.44s`. The spill-enabled wrapper preserved the same ordered-lane win at `172.1 MB` / `47.4 MB` / `152.54s` with `0` spills. | Investigate |
| `2026-05-09` | Local source-path direct-merge device projection switch | `synthetic-50k-1_5m` large dual-package hot-phase review | Promoting the exact-order direct merge behind `-DirectMergeDeviceLookup` cut `Load source data` from `77.16s` to `2.66s` and `Normalize source data` from `1263.71s` to `1210.94s`, but the overall dual-package envelope still peaked in `Write dashboard` and regressed slightly to `0.778 GB` tree RSS / `0.682 GB` private versus the accepted file-backed hot-phase at `0.764 GB` / `0.667 GB`. `Write dashboard` stayed effectively flat at `66.03s` versus `67.37s`, so the experiment is a throughput win only and not worth keeping as the next accepted memory step by itself. | No |
| `2026-05-09` | Chunked raw JSON streaming for file-backed payload fragments | `benchmark-medium-v1-cold` forced-live payload replay | Replacing the file-backed `JsonTextReader` token copy with chunked raw writes preserved payload bytes but worsened the payload-close crest from `264.2 MB` / `112.4 MB` to `296.6 MB` / `142.6 MB` at `PayloadLookup devices End`, so the change was reverted. | No |
| `2026-05-09` | Pre-device payload-close GC after early lookup release | `benchmark-medium-v1-cold` forced-live payload replay plus `synthetic-50k-1_5m` uncached local hot-phase review | New payload-close markers showed `Update-NormalizedAffectedSoftwareLookup` was not the spike; the real climb came from early lookup families before `devices`. A single GC after `batchTitles` cut the medium payload crest from `265.0 MB` / `105.9 MB` to `255.5 MB` / `97.5 MB`, then improved the large uncached dual-package hot phase from `0.764 GB` / `0.667 GB` to `0.756 GB` / `0.663 GB` with `Load source data = 76.87s`, `Normalize source data = 1241.35s`, `Prepare normalized payload = 113.82s`, and `Write dashboard = 64.46s`. | Yes |
| `2026-05-09` | Clear cached normalized-column restore references after payload close | `synthetic-50k-1_5m` cached-column-reuse dual-package hot-phase review | The cache-reuse path was accidentally holding `restoredLookups` and `restoredColumnPaths` through `Write dashboard`. Clearing them after payload close collapsed the cached control lane from `1.278 GB` peak tree RSS / `1.181 GB` private / `455.82s` to `0.815 GB` / `0.719 GB` / `435.35s`, with `Write dashboard` dropping from `76.20s` to `65.18s`. Payload-close markers stayed effectively flat (`PayloadLookup devices End` remained about `795-799 MB` working set / `634.6 MB` GC heap), proving the giant spike was post-payload retention rather than device serialization itself. | Yes |
| `2026-05-09` | File-back restored `devices` during normalized-column cache reuse | `synthetic-50k-1_5m` cached-column-reuse dual-package hot-phase review | Mirroring the live normalization path by restoring `lookups.devices` into a file-backed temp store collapsed the same cached control lane again from `0.815 GB` / `0.719 GB` / `435.35s` to `0.491 GB` / `0.394 GB` / `414.98s`. `Prepare normalized payload` fell from `121.03s` to `39.02s`, and the payload markers dropped from roughly `246-269 MB` working set / `94-108 MB` GC heap instead of the earlier `795-816 MB` / `635-645 MB`. The tradeoff is that cache-restore normalization work rose from `166.89s` to `226.08s`, but the reuse lane is still dramatically faster than a full uncached rerun and now behaves much more like the real file-backed payload path. | Yes |
| `2026-05-09` | Rebuild compact lookups before payload write | `synthetic-50k-1_5m` uncached large dual-package hot-phase review | After live normalization completed, rebuilding the lookup record from the content dictionary before payload write cut the real uncached large lane from `0.756 GB` peak tree RSS / `0.663 GB` private / `1504.41s` to `0.560 GB` / `0.466 GB` / `1519.89s`. `Prepare normalized payload` fell from `113.82s` to `39.92s`, and the payload-side markers collapsed from about `467-776 MB` working set / `250-604 MB` GC heap to about `269-293 MB` / `99-113 MB`. The tradeoff is only about `+15.48s` in `Normalize source data`, which is easily worth the roughly `196 MB` RSS / `197 MB` private reduction on the actual uncached path. | Yes |
| `2026-05-09` | Recheck direct-merge after separating the cache-reuse bug | `synthetic-50k-1_5m` large dual-package hot-phase review | Rerunning `-DirectMergeDeviceLookup` after fixing the cache-reuse retention issue landed at `0.768 GB` peak tree RSS / `0.672 GB` private / `1401.76s`. Versus the accepted file-backed + pre-device-GC baseline at `0.756 GB` / `0.663 GB` / `1504.41s`, that is roughly `+12 MB` tree RSS and `+9 MB` private for `-102.65s` elapsed. The switch still bypasses normalized-column cache reuse and still is not the next accepted memory reduction, but it is now a more credible exact-order throughput tradeoff dial than the earlier `0.778 GB` / `0.682 GB` result suggested. | Investigate |
| `2026-05-10` | Mutate AH data via `.Clear()` before pre-streaming GC (`-EarlyReleaseInputData` switch) | Hosted fresh export (2 reruns) with `UseDirectMergeDeviceLookup=true` (always-failing on live) | `Clear-NormalizationInputContext` previously only replaced the context's own references (`$Context.AdvancedHuntingData = @{}`), leaving outer-scope refs in `Invoke-ContentStoreNormalization`, `ConvertTo-NormalizedData`, and the Azure pipeline closure pointing to the original hashtables. All three held CVE descriptions and device-user maps alive through ref streaming and payload close. The new `-EarlyReleaseInputData` switch calls `.Clear()` on the originals first, so every scope sees an empty collection before the pre-streaming GC fires. This mirrors the existing machine-lookup disposal pattern in `Remove-FileBackedNormalizationMachineLookup`. Gate is `$consumeLookups` so the fix activates only on the Azure payload-close path; `Generate-VulnerabilityDashboard.ps1` is unaffected. `AdvancedHuntingInventoryData` is exempted via the existing `-PreserveInventoryData` guard since it is consumed during streaming. Measured against the accepted `341.9–352.5 MB` WS / `229.1–234.2 MB` private / `142.8–148.5 MB` GC baseline (same Hosted+fresh-export+DM-fallback conditions): two runs landed at **`342.6–348.2 MB`** WS / **`225.1–226.5 MB`** private / **`144.7–146.8 MB`** GC / `101.59–118.57 s` (run 1 had a 43 s export outlier). Private bytes improved by **`~3–8 MB`** consistently below the lower bound of the baseline range. GC heap overlaps the baseline noise range but the peak stage shifted from `NormalizeDashboardData` to `Completed` in run 1, suggesting normalization GC pressure was reduced and the absolute peak moved later. No time regression (run 2 at `101.59 s` is within the baseline). Full regression suite clean; `Test-InvokeContentStoreNormalizationReleasesTransientContextBeforePayloadClose` and `Test-ConvertToNormalizedDataCanConsumeLookupsOnPayloadClose` both pass. **Note**: this measurement used `UseDirectMergeDeviceLookup=true` (non-default, always-failing on live) to match the stateHash-index baseline. The production-path (no-DM) measurements are recorded in the two entries below. | Yes |
| `2026-05-10` | Live-lane configuration audit: `UseDirectMergeDeviceLookup=true` always fails on live, doubles machine load | Hosted fresh export (no-DM production default) vs. DM-always-failing comparison | All prior fresh-export baselines (`341.9–352.5 MB` WS / `229.1–234.2 MB` private) were measured with `UseDirectMergeDeviceLookup=true`, which always trips the exact-order guard on live exports — `deviceProfiles` order in the vuln content store does not match the machine export order. When the guard trips, the runbook first loads `$machines = @{}`, loads AH data, attempts normalization, fails at the first device ID mismatch, then re-reads machines as file-backed — loading machine data twice. The result is `~44 MB` extra private bytes and `~43 MB` extra GC heap throughout the entire normalization phase versus loading file-backed upfront. The per-stage timeline shows the fallback machine read at `Post-DirectMergeFallbackMachineRead` (+`44.7 MB` private spike), and this overhead persists through `Post-NormalizationCleanup` (+`40 MB` retained vs no-DM). A no-DM fresh-export run (production default) peaked at **`324.6 MB`** WS / **`181.0 MB`** private / **`102.3 MB`** GC / `91.23 s` on PR #47; a no-DM run on `main` peaked at **`338 MB`** WS / **`182.4 MB`** private / **`109.9 MB`** GC / `105.59 s`. The runbook default is correctly `$UseDirectMergeDeviceLookup = $false`; benchmark scripts must not pass `-UseDirectMergeDeviceLookup` unless specifically testing the DM-fallback path. | Yes — use no-DM as standard live benchmark going forward |
| `2026-05-10` | AH early-release (`-EarlyReleaseInputData`) measured on production path (no-DM), main vs PR #47 | Hosted fresh export (no-DM production default) | On the production-default no-DM path, `main` (without AH early-release) peaked at **`338 MB`** WS / **`182.4 MB`** private / **`109.9 MB`** GC / `105.59 s`; PR #47 (with AH early-release) peaked at **`324.6 MB`** WS / **`181.0 MB`** private / **`102.3 MB`** GC / `91.23 s`. The clearest per-stage signal is at `PayloadClose PreDeviceGc` — exactly where EarlyRelease fires — where GC dropped from `107.9 MB` to `100.8 MB` (−`7.1 MB`) and private dropped from `177.0 MB` to `167.5 MB` (−`9.5 MB`). At `Post-ConvertToNormalizedData`, GC dropped from `109.9 MB` to `92.6 MB` (−`17.3 MB` — most significant single-point GC improvement). Private at `PayloadLookup cves End` fell from `179.5 MB` to `167.1 MB` (−`12.4 MB`). Overall private peak difference (1.4 MB) is within single-run noise, but the −`7 to −17 MB` GC reduction at the EarlyRelease call site is consistent with the mechanism: AH hashtables are cleared before the pre-streaming GC so all three outer-scope references see empty collections and the GC can reclaim CVE descriptions and device-user maps earlier. | Yes |

The next machine-store experiment should build on the stronger diagnostics instead:

- On `benchmark-medium-v1-cold`, streamed vulnerability rows were **98.69%** same-device as the immediately previous row, and even an LRU cache of `1` hit the same **98.69%** rate as caches of `4`, `16`, and `64`.
- On the same pinned synthetic dataset, content-store `deviceProfiles` matched machine-store order **exactly** (`1500 / 1500` same-position matches).
- On the large seeded synthetic lane, that same order relationship also held exactly (`50000 / 50000` same-position matches, `100%` monotonic), and a merge-style machine walk finished the profile pass in **`77.71s`** versus **`175.84s`** for the accepted file-backed random lookup path.
- That order relationship did **not** hold on the local real `exports` lane (`0 / 24` same-position matches; only `20.83%` monotonic), so future machine-store offload work must tolerate out-of-order device profiles instead of assuming a pure merge stream.
- With the buffered file-backed machine lookup in place, richer payload-close markers corrected the local peak story: the next large local cliff is inside `Prepare normalized payload`, not `Write dashboard`.
- On both the forced-live medium payload replay and the uncached large dual-package hot phase, `Update-NormalizedAffectedSoftwareLookup` did **not** create the spike; memory stayed flat or improved immediately after it.
- The local climb happens while serializing the earlier high-cardinality lookup families ahead of `devices`, and the `devices` write still forms the dominant local payload crest.
- A targeted pre-device GC after those early lookup families are consumed is now the first keepable local packaging-side win: the uncached large dual-package hot phase improved to `0.756 GB` tree RSS / `0.663 GB` private versus the accepted `0.764 GB` / `0.667 GB` file-backed baseline, while also trimming elapsed time slightly.
- A later cached-column-reuse replay exposed a separate retained-reference bug rather than a worse payload writer:
  - the bad cached control lane reached `1.278 GB` tree RSS / `1.181 GB` private because `restoredLookups` and `restoredColumnPaths` were still live after payload close
  - clearing those references dropped the same lane to `0.815 GB` / `0.719 GB` and shortened `Write dashboard` from `76.20s` to `65.18s`
  - the payload-close markers themselves barely moved, so the true remaining local crest is still `PayloadLookup devices End` / `PayloadClose PostLookups`, not the old cache-reuse cliff
- Mirroring the live path's file-backed `devices` store during normalized-column cache reuse then made that local harness much closer to the real payload flow:
  - the cached reuse lane fell again from `0.815 GB` / `0.719 GB` / `435.35s` to `0.491 GB` / `0.394 GB` / `414.98s`
  - `Prepare normalized payload` collapsed from `121.03s` to `39.02s`, and the payload-side markers dropped to roughly `246-269 MB` working set / `94-108 MB` GC heap
  - `Normalize source data` on the reuse lane rose from `166.89s` to `226.08s` because the cache restore now writes the file-backed device store up front, but the total reuse run is still over `18` minutes faster than the uncached `1504.41s` baseline
- With those two fixes in place, the cached-column-reuse lane is now the preferred fast local harness for payload-side tradeoff review because it no longer carries an artificial in-memory `devices` array through payload close.
- The most promising new uncached large-lane result now comes from reusing that same compact-lookup idea on the real live path:
  - rebuilding compact lookups from the content dictionary before payload write cut the uncached large lane from `0.756 GB` / `0.663 GB` / `1504.41s` to `0.560 GB` / `0.466 GB` / `1519.89s`
  - `Prepare normalized payload` fell from `113.82s` to `39.92s`, and the payload-side markers dropped from about `467-776 MB` working set / `250-604 MB` GC heap to about `269-293 MB` / `99-113 MB`
  - the added rebuild pass cost only about `15.48s` total on this lane, which is easily favorable given the roughly `196 MB` RSS / `197 MB` private reduction
  - because the peak now moved back to `Load source data`, the next meaningful validation step should be Azure replay rather than another local payload-only tweak
- Seeded current-only self-contained validation now confirms that the buffered file-backed machine lookup carries through the shared self-contained path:
  - Azure Automation self-contained replay: **501.6 MB** working set / **123.4 MB** GC heap / **766.74 s**
  - Function App self-contained replay: **814.8 MB** working set / **573.76 s**
- A follow-up packaging experiment that skipped the immediate self-contained embedded-payload reinspection was measured and then discarded:
  - rerun result: **516.3 MB** working set / **124.2 MB** GC heap / **752.80 s** in Azure Automation, and **800.1 MB** working set / **581.15 s** in Function App
  - while Function App working set improved by about **14.7 MB**, Azure Automation working set regressed by about **14.7 MB**, and the net change was too small to justify weakening packaging-time payload validation
- Peak-label extraction from the seeded self-contained replay showed the real Azure self-contained high-water marks still cluster around machine input preparation (`Post-MachineRead`, `Post-MachineLookupCompression`, `Post-NormalizationInputs`) rather than bundle compression or final HTML assembly, so the next meaningful Azure target should pivot back toward machine input load/compression rather than packaging shortcuts.
- Fresh large-lane Advanced Hunting bundle reviews suggest the bundle is secondary to the remaining machine/post-normalization cliffs:
  - on `bundle-only`, the delta from `PostMachineLoad` to `PostAdvancedHuntingBundle` was about **+26.6 MB** working set / **+19.4 MB** GC heap
  - on `bundle-precompact`, the retained delta after machine compaction stayed in the same neighborhood at about **+19.4 MB** GC heap
  - this is worth tracking, but it is not large enough to justify another AH-specific rewrite before we get better Azure visibility into retained post-normalization lookups
- A follow-up seeded current-only Azure self-contained replay with richer retained-lookup telemetry confirmed that the remaining Azure cliff is still pre-normalization machine input work, not late payload retention:
  - replay envelope stayed effectively flat at **504.0 MB** runbook working set / **124.9 MB** GC heap / **752.65 s**, with Function App at **814.4 MB** / **575.22 s**
  - the labeled peak still occurred at `Post-MachineRead` / `Post-MachineLookupCompression` (~**504 MB**), while memory dropped to about **343.5 MB** / **79.9 MB** by `Post-NormalizationCleanup` and about **341.3 MB** / **87.4 MB** by `Post-PayloadCachePublish`
  - that drop means retained post-normalization lookups and packaging are no longer the dominant self-contained memory cliff on the seeded Azure lane; the next architecture pass should stay focused on machine-input staging/retention before normalization begins
- The new large-lane profile-order probes changed the shape of the next machine-input theory:
  - low-memory bucket staging proved that deferring machine materialization can be worthwhile, but the random bucket lookup path was far too slow
  - exact-order merge/profile passes were much faster than random file-backed lookups, but by themselves they did not lower the machine-read peak enough to keep
  - a current-snapshot staged sequential hybrid confirmed that order-aware staged access can be fast, but not yet memory-positive: the fast version increased peak working set / GC, and the lower-allocation reader became too slow to keep
  - a mismatch-only merge-plus-spill hybrid showed that bounded out-of-order fallback can preserve the fast ordered path and still complete the disorder case, but it still did not reduce peak memory on either lane
  - a more aggressive direct-projection cut finally produced a simultaneous memory-and-time win on the exact-order seeded lane: skipping the machine lookup index entirely and projecting device lookups directly while streaming the current machine snapshot lowered the isolated device-profile pass by about `15.5 MB` working set / `7.8 MB` GC and about `132.56s`
  - promoting that exact-order direct merge into the real local hot path confirmed that the isolated win does **not** translate into a better large dual-package peak by itself: the run sped up, but the accepted large local peak still regressed slightly overall
  - the next credible local architecture target is therefore lower-allocation payload-close/device serialization rather than another machine-input rewrite on this lane; if the direct-merge idea is revisited later, it should be as one dial inside a larger combination or as a tradeoff pass on the now-fixed cached-column lane
  - if this line is revisited, it should only be with a lower-allocation machine/device-profile streaming path; changing fallback policy alone was not enough
- the current spill-enabled direct-projection harness still needs a better disorder strategy before it can be treated as production-shape: the exact-order seeded lane stayed at `0` spills and won cleanly, but the first concurrent spill-reader attempt on the local `exports` lane still needs redesign
- after separating the cached-column retention bug, the full large hot-phase tradeoff looks slightly better than the earlier direct-merge replay suggested:
  - rerunning `-DirectMergeDeviceLookup` landed at `0.768 GB` tree RSS / `0.672 GB` private / `1401.76s`
  - relative to the accepted file-backed + pre-device-GC baseline (`0.756 GB` / `0.663 GB` / `1504.41s`), that means about `+12 MB` RSS / `+9 MB` private for `-102.65s`
  - that is still not the next accepted memory reduction, but it is a legitimate exact-order throughput dial if later payload-side work needs to spend a small amount of memory to buy back time
- on the true production no-DM path, a full per-stage hotspot analysis of both the `main` and PR #47 no-DM timelines identified the four dominant memory spikes inside `NormalizeDashboardData`:
  - **VulnCurrentRefs.json.gz streaming** (+`26.1 MB` private / +`8.1 MB` GC from file Start to End, ~`18.7 MB` private retained after the between-file GC): this is the largest single spike and is primarily .NET GC pressure from temporary object accumulation (date strings, PSObject loop variables) between the every-100K-record GC cycles; after the between-file Gen2 collect, the retained `18.7 MB` is committed pages held by the GC for future allocation plus genuine live set (date dedup index, GZip stream working state); not actionable without data-model or streaming-path changes
  - **VulnHistoryRefs_2026Q2.json.gz** (+`10.0 MB` private / +`12.4 MB` GC): Q2 is the most recent quarter and adds new `(device, CVE, date)` triplets not yet indexed during Current refs; Q1 by contrast shows effectively zero growth because its device-CVE pairs are already covered by the Current snapshot; this spike is data-driven and will naturally shift forward as new quarters are added
  - **PayloadLookup cves** (+`18.2 MB` private / +`9.9 MB` GC transient, 921 entries via recursive `Write-JsonValueToWriter`): the `ConsumeLookups` GC fires immediately after the CVE lookup write completes and reclaims this transient load; not an architectural concern
  - **PayloadClose PostAffectedSoftware → PayloadLookup devices** (+~`10 MB` private): affected-software and device-lookup serialization overhead; expected
  - the post-analysis conclusion is that the production no-DM private peak of `181–182 MB` (at VulnCurrentRefs End and Q2 End) is dominated by the pre-normalization live set (~`164 MB`) plus the inherent streaming overhead; no single code-level change is expected to cut more than `5–10 MB` from this without architectural changes to data volume or dedup structure
- to enable future streaming spike characterization, intra-streaming `Write-MemoryUsage` markers were added every `500K` onboarded records inside the `100K` GC cycle (firing at `500K`, `1M`, `1.5M`, …) so each file's memory profile can be seen as a series of post-GC snapshots rather than just Start/End; the pipeline memory sample cap was simultaneously raised from `64` to `128` to preserve the full timeline across runs with expanded instrumentation
- a subsequent fresh-export monitoring run on the live tenant confirmed the instrumentation adds no measurable overhead (325.9 MB WS / 180.0 MB private / 103.2 MB GC / 88.28 s — essentially identical to the PR #47 no-DM baseline at 324.6 / 181.0 / 102.3 / 91.23 s); the `500K` milestone markers did not fire because the live tenant's VulnCurrentRefs has fewer than `100K` onboarded records — the marker threshold is only relevant for large tenants with `500K+` onboarded device-CVE pairs, such as those run through the `synthetic-50k-1_5m` or `benchmark-medium-v1` large dataset lanes; the live tenant completes VulnCurrentRefs in a single burst with no intra-streaming GC triggers, and both the VulnCurrentRefs spike (+`29.2 MB` private, `150.2` → `179.4 MB`) and the Q2 spike (+`12.6 MB` private, `167.4` → `180.0 MB`) are data-driven and consistent with the prior per-stage hotspot analysis
- a two-run `benchmark-large-50k-v1` instrumentation baseline was established on the Azure large lane (50K devices / 1.5M rows); the Generate dashboard stage clocked at `644.52–644.58 s` across both runbook runs — extremely consistent — with peak WS `525.9–537.1 MB` and peak GC heap `113.8–113.9 MB`; runbook total elapsed varied between `689.73 s` and `733.05 s` because auth and download stage latency was noisier in run 2 (Azure service variance), not normalization; Function App run 1 failed immediately due to a pre-existing strict-mode bug in `Build-FunctionApp.ps1` (`$UseDirectMergeDeviceLookup` was not initialized in the function app entry-point header — fixed in PR #48); Function App run 2 completed in `597.66 s` active / `599.56 s` end-to-end with peak WS `820.1 MB` via Azure Monitor; the Function App is measurably faster than the runbook on this lane (`597.66 s` vs `644.5 s` dashboard stage), consistent with the pattern observed on smaller datasets; the `500K` intra-streaming markers are embedded in the code path and will activate for large deployments but the current benchmark harness captures only peak values from the output stream, not marker-labeled timeline samples — future large-lane comparisons should use the series dir `.local/benchmark-series/benchmark-large-50k-v1-streaming-monitors-20260510-204728/` as the reference envelope

## Multi-dial experiment review

Use `tests\Measure-RunbookInputLoadExperiment.ps1 -CompareToPath <prior-result.json>` when comparing machine-input prototypes on the same dataset and command path.

The harness now records a few derived tradeoff metrics in addition to peak memory and elapsed time:

- `work_units_per_second` to show whether a slower storage strategy is recovering throughput elsewhere
- `disk_footprint_mb` to quantify how much cold state moved off-heap
- `peak_working_set_mb_seconds` / `peak_gc_heap_mb_seconds` as a quick peak-memory x time exposure check
- `snapshot_working_set_area_mb_seconds` / `snapshot_gc_heap_area_mb_seconds` as a coarse time-weighted memory exposure summary across the captured phase snapshots
- comparison deltas plus `*_mb_saved_per_added_second` when a candidate deliberately trades latency for memory

Treat those derived metrics as lane-local diagnostics, not universal scores. They are most useful when the dataset, experiment mode, and storage path are otherwise held constant.

## Memory reduction progression

This table is the compact "how far have we moved?" view for the standard large Azure replay lane. The first row is the effective starting point before the meaningful memory reductions landed; later rows add each accepted architectural change.

| Step | Change | Replay path | Peak WS | Peak private | Peak GC heap | Elapsed | Notes |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| Starting point | Pre-offload replay after parser cleanup | Azure Automation replay | `579.6 MB` | `481.9 MB` | `336.8 MB` | `490.84s` | Parser cleanup improved throughput, but the true status-blob peak did not materially move. |
| Change 1 | File-backed device lookup offload | Hosted replay | `539.7 MB` | `388.0 MB` | `173.3 MB` | `596.94s` | First meaningful normalization-memory win; peak stayed in normalization input loading. |
| Change 1 | File-backed device lookup offload | Dual replay | `549.9 MB` | `398.7 MB` | `173.6 MB` | `672.67s` | Packaging added about `10 MB` WS and `75.73s` over hosted on the same architecture. |
| Change 2 | Buffered file-backed machine lookup | Hosted replay | `494.7 MB` | `351.2 MB` | `123.9 MB` | `750.52s` | Another `45.0 MB` WS / `36.8 MB` private / `49.4 MB` GC improvement versus the hosted device-lookup offload run. |
| Change 2 | Buffered file-backed machine lookup | Dual replay | `504.0 MB` | `351.8 MB` | `119.7 MB` | `1008.66s` | Another `45.9 MB` WS / `46.9 MB` private / `53.9 MB` GC improvement versus the dual device-lookup offload run, but packaging time grew sharply. |

Measured but not yet promoted to the default path:

| Step | Change | Replay path | Peak WS | Peak private | Peak GC heap | Elapsed | Notes |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| Experiment | Azure-only `UseDirectMergeDeviceLookup` | Hosted replay (warm reruns) | `358.9-368.4 MB` | `207.3-210.4 MB` | `137.2-138.2 MB` | `461.05-586.12s` | Both warm reruns beat the accepted hosted file-backed machine lookup run on working set, private bytes, and elapsed (`-126.3` to `-135.8 MB` WS, `-140.8` to `-143.9 MB` private, `-289.47` to `-164.40 s`), but GC rose by about `13-14 MB` and the first post-deploy replay was a `1325.57s` outlier. Keep this as a promising Azure-specific mode until the latency variance story is better understood. |
| Validation | Azure-only `UseDirectMergeDeviceLookup` on latest deployed artifact | Hosted replay (deployed latest) | `317.3 MB` | `198.1 MB` | `125.5 MB` | `172.30s` | Re-deploying the latest runbook artifact after the strict-mode-safe machine `stateHash` fix still completed cleanly on the seeded `synthetic-50k-1_5m` hosted Azure lane. This latest-branch replay now beats the accepted hosted file-backed baseline by `177.4 MB` WS / `153.1 MB` private / `-148.22 s` and sits below the earlier warm-rerun direct-merge envelope as well. |
| Experiment | Azure-only `UseDirectMergeDeviceLookup` | Dual replay | `370.4 MB` | `213.3 MB` | `137.3 MB` | `699.84s` | Beat the accepted dual file-backed machine lookup run on working set, private bytes, and elapsed (`-133.6 MB` WS / `-138.5 MB` private / `-308.82 s`), but GC rose by `17.6 MB`. This suggests the Azure-specific direct-merge win survives packaging on the seeded replay lane. |
| Experiment | Azure-only `UseDirectMergeDeviceLookup` with targeted fallback | Hosted fresh export | `507.7 MB` | `452.0 MB` | `151.2 MB` | `243.18s` | The true fresh-export lane hit an exact-order mismatch immediately, logged the guard failure, and retried normalization with the file-backed machine lookup instead of failing the runbook. Peak working/private memory came earlier in `ExportFreshMdeData`, so the direct-merge gain is currently replay-specific while the fresh-export bottleneck remains export-stage memory. |
| Experiment | Fresh-export machine `stateHash` index + direct-merge fallback | Hosted fresh export (reruns) | `341.9-352.5 MB` | `229.1-234.2 MB` | `142.8-148.5 MB` | `102.95-104.74s` | Replacing the full existing machine current-record map with a compact `id -> stateHash` index cut the live fallback lane by `155.2-165.8 MB` WS / `217.8-222.9 MB` private / `2.7-8.4 MB` GC / `138.44-140.23 s` versus the first fallback run. The direct-merge order guard still tripped, but export-stage memory no longer dominated and the peak stayed in or near `NormalizeDashboardData`/final packaging. |
| Experiment | Fresh-export machine `stateHash` index + direct-merge fallback | Dual fresh export | `342.3 MB` | `234.2 MB` | `149.5 MB` | `108.98s` | Packaging stayed close to the new hosted live envelope: working set remained effectively flat, private bytes stayed within the hosted rerun range, GC rose only slightly, and elapsed increased by just a few seconds. |
| Experiment | AH early-release via `.Clear()` (`-EarlyReleaseInputData`) on top of stateHash index | Hosted fresh export (2 reruns), `UseDirectMergeDeviceLookup=true` | `342.6-348.2 MB` | `225.1-226.5 MB` | `144.7-146.8 MB` | `101.59-118.57s` | Private bytes improved by **`~3–8 MB`** relative to the accepted stateHash-index hosted fresh-export baseline (`229.1–234.2 MB`); both runs landed consistently below the lower bound of that baseline range. GC heap overlaps baseline noise but peak stage shifted from `NormalizeDashboardData` to `Completed` in run 1, suggesting normalization GC pressure was reduced. WS flat. No time regression (run 1 export was a 43 s outlier; run 2 at 101.59 s is within baseline). Regression suite clean. **Note**: measured with always-failing DM (`UseDirectMergeDeviceLookup=true`); see production-path rows below. |
| Baseline | True production baseline (no-DM, `main`) | Hosted fresh export, production-default (`UseDirectMergeDeviceLookup=false`) | `338 MB` | `182.4 MB` | `109.9 MB` | `105.59s` | Production-default configuration without AH early-release. Previous stateHash-index baselines (`341.9–352.5 MB` WS / `229.1–234.2 MB` private) used `UseDirectMergeDeviceLookup=true` which always fails on live data and loads machines twice (+`~44 MB` private penalty). This is the correct reference for production performance without PR #47. Key normalization stages: `Post-NormalizationInputs` = `159.7 MB` private; `VulnHistoryRefs_2026Q2 End` = `181.1 MB` private / `105.8 MB` GC (normalization peak); `PayloadClose PreDeviceGc` = `177.0 MB` private / `107.9 MB` GC (pre-release state); `Post-ConvertToNormalizedData` = `109.9 MB` GC (peak GC). |
| Experiment | AH early-release (`-EarlyReleaseInputData`) on production path, PR #47 | Hosted fresh export, production-default (`UseDirectMergeDeviceLookup=false`) | `324.6 MB` | `181.0 MB` | `102.3 MB` | `91.23s` | PR #47 vs `main` on the true production path. At `PayloadClose PreDeviceGc` (the EarlyRelease call site), GC dropped from `107.9 MB` → `100.8 MB` (−`7.1 MB`) and private from `177.0 MB` → `167.5 MB` (−`9.5 MB`). At `Post-ConvertToNormalizedData`, GC dropped from `109.9 MB` → `92.6 MB` (−`17.3 MB` — largest single-point GC improvement). Private at `PayloadLookup cves End` dropped from `179.5 MB` → `167.1 MB` (−`12.4 MB`). Overall private peak delta is 1.4 MB (within single-run noise); WS and elapsed improvements are within variability. The GC reduction at the EarlyRelease call site is the primary signal: AH hashtables are cleared before the pre-streaming GC, so the GC can reclaim CVE descriptions and device-user maps before ref streaming begins. |

## Capture notes

- Date captured: `2026-04-05` for the original synthetic replay baselines.
- Date captured: `2026-04-20` for the hosted `review-synthetic-medium` Azure acceptance replay.
- Date captured: `2026-04-20` for the durable `benchmark-medium-v1` three-iteration hosted benchmark series.
- Date captured: `2026-05-06` for the accepted standard large-dataset Azure envelope on `synthetic-50k-1_5m`.
- Date captured: `2026-05-10` for the hosted and dual `UseDirectMergeDeviceLookup` Azure experiment series on `synthetic-50k-1_5m` (one slow post-deploy hosted replay, two warm hosted reruns, and one dual replay).
- Date captured: `2026-05-10` for the latest deployed hosted `UseDirectMergeDeviceLookup` replay validation after the strict-mode-safe machine `stateHash` fix.
- Date captured: `2026-05-10` for the true fresh-export hosted `UseDirectMergeDeviceLookup` validation with the targeted Azure fallback enabled.
- Date captured: `2026-05-10` for the fresh-export hosted and dual machine `stateHash` index validation with the targeted Azure fallback still enabled.
- Date captured: `2026-05-10` for the AH early-release (`-EarlyReleaseInputData`) hosted fresh-export validation against the stateHash-index baseline; two reruns captured. All these runs used `UseDirectMergeDeviceLookup=true` (non-production).
- Date captured: `2026-05-10` for the live-lane configuration audit: production-default no-DM runs on both `main` and PR #47, revealing all prior stateHash-index baselines used a non-production always-failing DM configuration.
- Date captured: `2026-05-10` for the production-path EarlyRelease comparison: no-DM `main` at `338 MB` / `182.4 MB` private / `109.9 MB` GC vs no-DM PR #47 at `324.6 MB` / `181.0 MB` private / `102.3 MB` GC.
- From this point forward, production-default (`UseDirectMergeDeviceLookup=false`) is the required configuration for all standard fresh-export live benchmarks. Only use `UseDirectMergeDeviceLookup=true` when explicitly testing the DM-fallback behavior.
- Dataset shapes:
  - `benchmark-medium-v1`: standard durable benchmark dataset generated from the catalog entry in `tests/benchmark-datasets.json` with preset `BalancedMediumHeavy`, seed `20260322`, `120000` rows, and `1500` devices.
  - `exports-synthetic`: original `20K` synthetic replay dataset.
  - `exports-synthetic-live`: shifted synthetic live-export dataset with a latest snapshot date of `2026-04-05`.
  - `review-synthetic-medium`: `BalancedMediumHeavy` review dataset with `120000` rows and `1500` devices, validated against Azure Automation `aa-defender-reporting` and Function App `func-defender-reporting-parallel-0404a`.
  - `synthetic-50k-1_5m`: standard large Azure acceptance dataset rooted at `.local\large-datasets\synthetic-50k-1_5m`.
  - `benchmark-large-50k-v1`: durable large benchmark catalog entry (preset `BalancedMediumHeavy`, seed `20260322`, `1,500,000` rows, `50,000` devices) that resolves to the same `.local\large-datasets\synthetic-50k-1_5m` path. Use the manifest breadth counters rather than assuming a fixed CVE count across captures.
- `benchmark-medium-v1` is now the standard durable dataset for merge-tracked baseline refreshes and supersedes `review-synthetic-medium` for future benchmark-series captures.
- `benchmark-medium-v1` Function App headline timing now uses active execution time from the runtime status blob; end-to-end invocation time and pickup delay are recorded separately for queue and cold-start review.
- The durable `benchmark-medium-v1` persistent local cache reuse pass was effectively stable across reruns (`45.44s` to `45.49s`) and is the preferred baseline for normalized-column cache reuse.
- The hosted review baseline was captured twice on the same dataset and command path. This document records ranges because the cold local normalization pass moved more than the hosted paths across reruns.
- The local benchmark harness stages a private dataset copy before validation so raw datasets do not get mutated by sidecar regeneration during baseline capture.
- Synthetic benchmark artifacts now publish `uniqueCveIdCount`, `normalizedCveLookupCount`, and `contentTemplateCount` in both `synthetic-manifest.json` and `benchmark-dataset.json`. `normalizedCveLookupCount` is the same breadth surfaced as `CVEs` in the Azure acceptance summaries above.
- `benchmark-large-50k-v1` regenerates from the mutable `exports` source path, so its breadth counters can drift even when the dataset id, seed, device target, and row target stay fixed. Use the manifest breadth counters rather than assuming the accepted May 6 anchor's normalized CVE count will remain constant across later refreshes.
- The standard large Azure entry intentionally records the accepted invocation and blob-write markers that are already tracked in-repo. Preserve the raw Azure validation artifacts under `.local/` when refreshing this section so future updates can add comparable working-set or execution-unit detail without reconstructing the run later.
- Prefer the persisted `runbook_status.memoryPeaks` metrics from the benchmark result JSON when comparing Azure envelopes. The event-summary headline can under-report the true sampled status-blob peak on long runs.
- A follow-up attempt to reuse a single projected-machine hashtable inside the exact-order direct-merge loop was measured locally and reverted after regressing the isolated `device-lookup-direct-merge` pass from **`175.2 MB` / `48.2 MB` / `154.44 s`** to **`177.8 MB` / `55.1 MB` / `157.68 s`**.
- Date captured: `2026-05-11` for the streaming-monitors fresh-export confirmation run on the live tenant: `325.9 MB` WS / `180.0 MB` private / `103.2 MB` GC / `88.28 s`. The `500K` intra-streaming milestone markers did not fire (live tenant has fewer than `100K` onboarded records in VulnCurrentRefs); the markers are intended for large-deployment observability only. No instrumentation overhead. Per-file private deltas: VulnCurrentRefs +`29.2 MB` (`150.2` → `179.4 MB`), Q1 `0.0 MB`, Q2 +`12.6 MB` (`167.4` → `180.0 MB`).
- Date captured: `2026-05-11` for the large-lane instrumentation baseline on `benchmark-large-50k-v1` (50K devices / 1.5M rows): 2 runbook runs (`689.73 s` and `733.05 s` total; Generate dashboard `644.52–644.58 s`; peak WS `525.9–537.1 MB`; peak GC `113.8–113.9 MB`) and 1 successful Function App run (`597.66 s` active; peak WS `820.1 MB`). Run 1 Function App failed due to a pre-existing `$UseDirectMergeDeviceLookup` strict-mode bug in `Build-FunctionApp.ps1`, fixed in PR #48. Raw series artifacts under `.local/benchmark-series/benchmark-large-50k-v1-streaming-monitors-20260510-204728/`.

## Regenerating the baseline

Replay baseline:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
pwsh -NoProfile -File .\tests\Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -CurrentBaselineName 'current-20k' -DatasetPath .\exports-synthetic -ResultsOutputPath (Join-Path $PWD ('.local\current-baseline-20k-' + $stamp + '.json'))
```

Shifted live baseline:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
pwsh -NoProfile -File .\tests\Measure-BranchVsMainBenchmark.ps1 -CurrentOnly -CurrentBaselineName 'current-live' -DatasetPath .\exports-synthetic-live -ResultsOutputPath (Join-Path $PWD ('.local\current-baseline-live-' + $stamp + '.json'))
```

Durable benchmark series:

```powershell
pwsh -NoProfile -File .\tests\New-BenchmarkDataset.ps1 -DatasetId benchmark-medium-v1
pwsh -NoProfile -File .\tests\Invoke-BenchmarkSeries.ps1 -BenchmarkDatasetId benchmark-medium-v1 -Iterations 3 -IncludePersistentLocalWorkflow
```

Import-path spot checks:

```powershell
pwsh -NoProfile -File .\tests\Generate-SyntheticLargeExports.ps1 -OutputPath .\.local\large-datasets\synthetic-raw -IncludeRawRows -AllowLargeDataset
pwsh -NoProfile -File .\tests\New-SyntheticLiveExport.ps1 -SourcePath .\.local\large-datasets\synthetic-raw -OutputPath .\.local\large-datasets\synthetic-raw-live -SkipContentStoreSidecars -Force
pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-raw-live -Validate -ValidationMode artifacts
pwsh -NoProfile -File .\tests\Measure-RunbookOnlyAzureBenchmark.ps1 -UseExistingExportsOnly:$false
```

Use `-ValidationMode semantic` only for the final local replay when you need the full semantic audit before Azure or merge validation.
