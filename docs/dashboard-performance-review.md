# Dashboard Architecture And Performance Review

Reviewed on 2026-09-30 against local commit `a2f4880abd1dfb2f8ac7654e1873372599aae8cd`.
GPT-6 Astra performed the architecture review and a separate independent plan review.
The local worktree was 16 commits behind its remote and contained existing deployment
changes; neither those changes nor the deployed dashboard were assumed to match HEAD.

## Integration Provenance

On 2026-10-01, the reviewed browser changes were applied to detached `origin/main`
baseline `b6526b6` in `.local/dashboard-main-integration`. Conflict resolution retained
upstream worker transfer phases and cache/fallback timings alongside the reviewed
loading deadlines, cancellation, canonical identity, lazy materialization, cache writes,
and worker cleanup. Generation-atomic hosted publication is already merged in #80;
it is not deferred work on this baseline.

The measurements and local acceptance results below remain historical evidence from
the original reviewed checkout at baseline `a2f4880abd1dfb2f8ac7654e1873372599aae8cd`.
No new comparative performance measurements are claimed for `b6526b6`. Independent
Astra review approved the integration after correcting the worker test VM to provide
the performance clock required by upstream instrumentation.

Fresh integrated preflight, release build/extraction, and extracted-publisher dry run
passed on 2026-10-01 with all 23 reviewed source hashes unchanged. Fresh Edge acceptance
passed generated standalone and hosted Dual artifacts, all five reports, actual
IndexedDB upgrade and cold/warm hits, worker-disabled fallback, readiness, PDF/modal
workflows, desktop/mobile layout, and nonblank canvases. Six generated-fixture and two
12,000-row cache-subset runs had zero browser errors or remote requests; owned process,
profile, and HTTP-server cleanup passed. These are functional acceptance results, not
a renewed performance comparison. Source-pinned records are local to the integration
checkout under `.local/integration-validation.json` and
`.local/dashboard-review/acceptance-summary.json`. Live Azure acceptance remains separate.

## Architecture

Retain the ordered dashboard modules, compact columnar payload, cooperative row
expansion, sweep-line chart aggregations, paginated reports, and virtualized ordinary
detail tables. Standalone, hosted, and Dual packaging remain supported. Historical
overlap, point-in-time activity, patch evidence, inactivity, and environment first-seen
are separate contracts and must not be conflated.

The hosted browser loads runtime, summary and payload, fingerprint/cache, worker
decompression, expansion, chart library, then the initial report. Report interactions
do not call Defender. PDF libraries remain optional and on demand.

## Hosted Observation

Read-only observations from the shared Edge page, not a controlled benchmark:

| Observation | Value |
| --- | --- |
| Navigation authentication redirect | approximately 439 ms |
| HTML response start / end | 806 / 818 ms |
| First contentful paint | 1,036 ms |
| Payload gzip transferred body | 15,351,202 bytes |
| Payload request duration | 1,253 ms |
| Summary encoded / decoded body | 343,372 / 3,486,143 bytes |
| Dashboard runtime encoded / decoded body | 80,739 / 398,979 bytes |
| Chart request start | 5,722 ms |
| Additional cached Pako fetch | 4.3 ms |
| Settled reported renderer JS heap | approximately 608 MiB |

Text compression was observed, including zstd on HTML. Do not recommend missing
compression from source inspection alone. Settled renderer heap is not peak memory
and excludes worker/process overhead. The approximately 3.15 seconds between payload
completion and chart request requires phase decomposition, not attribution to one
operation. These observations do not establish Core Web Vitals or a before/after gain.

## Reviewed Implementation Plan

Each slice starts with a local regression or discriminating check and runs its owning
Node assertion immediately after editing. Independent review required the corrections
listed below before implementation.

| Slice | Implementation | Focused checks |
| --- | --- | --- |
| Issue identity | Unambiguous CVE/vendor/product/version tuple, equivalent lookup entries coalesce; replace remediation radix key | large initialization, historical semantics, compressed cache |
| Lazy aggregates | Resolve remediation metadata and OS version without evidence/description expansion; retain eventual detail materialization | remediation views, compressed cache |
| Bounded loading | Cover fetch headers and body, caller cancellation and sibling failure; bound script loading and retry; clean workers and Blob URLs | compressed cache, telemetry |
| Cache correction | Version derived schema, reuse fingerprints, one entry per representation, metadata-only eviction; retain 500,000-row cutoff | compressed cache |
| Chart reuse | Refresh projection tooltip state without replacing chart or visibility | active chart series |
| Modal lifecycle | Invalidate queued render generations and disposed scroll callbacks | modal scheduling, responsiveness |
| Impact details | Paginate 50 devices while preserving all wrapped CVE lists | modal scheduling, Edge desktop/mobile |
| PDF lifecycle | Snapshot before report mutation, protect preparation through restoration, always release UI | PDF preflight and lifecycle |
| Filter facets | Remove duplicate pill refreshes; reuse scoped results only within an operation | telemetry scoped-equivalence checks |
| Readiness | Signal once after successful current report rendering; distinguish computation, rendering, paint opportunity | telemetry ordering, failure, supersession |

Do not use fixed-height virtualization for arbitrary wrapped impact CVE lists. Do not
transfer the only fallback buffer to a worker. Do not introduce a long-lived facet
cache without complete dataset/state invalidation. PDF restoration failures must not
prevent button/progress cleanup. Paint opportunity is not actual presentation or INP.

## Evidence And Acceptance

All eleven dashboard assertion scripts passed in the original reviewed checkout.
Historical deterministic probes:

- Aggregate construction on 6,000 rows: fully materialized rows 6,000 to 0;
  evidence arrays 12,000 to 0. The timing probe did not demonstrate a speedup.
- Repeated scoped facet reads: row visits 9 to 3, retaining equivalent results.
- Identity tests cover numeric boundaries, delimiter characters, equivalent lookup
  entries, missing values, invalid references, reordered rows, and cold/warm parity.
- Lifecycle tests cover stale modal work, chart reuse, PDF failure/cancel/retry,
  loading deadlines, cache errors, and readiness ordering/supersession.

### Final Local Edge Acceptance

Edge 154.0.4258.37 compared HEAD and candidate runtime against identical retained
synthetic HTML, summary, and payload: 1,187,395 rows, 49,476 devices, 5,000 CVEs. Payload SHA256
was `cd928b05840107bd9a694ec3c17030e5569300999115e40160c316dcaa6a9740`.
Three cold and three same-profile warm loads per lane ran sequentially with alternating
lane order. Large warm loads do not use expanded IndexedDB rows because of the cutoff.

| Median metric | Cold change | Warm change |
| --- | --- | --- |
| Actual first report completion | +0.8% (12.904 to 13.008 s) | -0.1% (13.883 to 13.863 s) |
| Sampled main-renderer JS heap | -17.5% | -16.0% |
| Sampled owned Edge-family working set | -7.9% | -11.1% |
| Denormalization phase | +9.0% | +6.4% |
| Initial active-report rendering | -5.3% | -3.6% |

The initial full-tuple-per-row implementation regressed denormalization approximately
22%. Investigation replaced it with canonical lookup IDs and lookup-sized numeric
keys, with a tuple fallback when the domain exceeds safe integers. Scratch keys are
released after first-seen assignment. Collision/equivalence tests cover both branches.
The remaining phase overhead is a correctness cost; no overall load-speed improvement
or statistical significance is claimed. All final median review metrics stayed inside
the 10% regression-investigation threshold. Raw failed iterations remain preserved.

Real Edge acceptance passed all five reports, semantic parity, v1-to-v2 IndexedDB
upgrade with stale-schema rejection, cold/warm cache hits on a 12,000-row subset,
fresh standalone/hosted Dual generation, disabled-worker fallback, PDF cancellation,
modal pagination and lifecycle, filter/share workflows, and desktop/mobile layout and
nonblank canvas checks. Browser errors and remote requests were zero; owned processes,
profiles, and HTTP servers were cleaned up. The generated fixture had 5,643 normalized
rows and passed fresh semantic audits in both packaging modes.

Final source-pinned evidence is in `.local/dashboard-review/acceptance-summary.json`,
with twelve large runs and separate medium/fixture records. All eleven Node assertions,
deterministic preflight, release build/extraction, and extracted-publisher dry run passed.
Existing generated deployment changes were restored byte-for-byte after each build.

Before accepting a browser speed or memory claim, pin source/HTML/runtime/payload
hashes, normalized rows/devices/CVEs, Edge version, machine resources, report/window,
and cache mode. Capture at least three comparable cold and warm runs per lane.
Measure targeted phases, long tasks, input-to-result, renderer heap and worker-inclusive
process memory separately. Require exact semantic parity and zero new browser errors;
investigate elapsed or peak-memory regressions above 10 percent. Existing readiness
baselines need re-baselining because readiness now follows report completion.

Required local gates are all dashboard assertions, deterministic
`build/Invoke-RegressionValidation.ps1`, release-package construction/extraction and
publisher dry run. Generated standalone/hosted/Dual fixtures must load in Edge. Use
fresh semantic/artifact lanes where payload or packaging changes trigger them, as
described in the performance gate playbook. Do not substitute fixture smoke for
large-data performance evidence.

## Deferred Work

- Persistent worker aggregation, typed-array/bitmap rewrites, cross-format cache
  deduplication, native-only worker loading, adaptive chunk sizes, and server-side
  reports need comparative phase/memory evidence before implementation.
- The cached Pako fetch is low priority given the observed 4.3 ms duration.
- Impact grouping/sorting remains synchronous; pagination bounds DOM work, not that
  computation. PDF watchdog cleanup cannot cancel late third-party library work.
- Cloud deployment, jobs, authentication/resource changes, and Azure acceptance are
  not part of this local implementation. Live Azure release acceptance and durable
  standard-dataset browser baselines remain pending; the retained-data local comparison
  above is not a substitute for either.

Raw agent reviews and experimental artifacts remain local. This review is not a
claim that the deployed revision contains these changes. Historical and latest-main
local integration gates passed; live Azure release acceptance remains pending.