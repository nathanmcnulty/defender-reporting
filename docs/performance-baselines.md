# Performance Baselines

This repository keeps the merge-tracked performance baseline as documentation instead of committing raw machine-local benchmark output.

Use `.local\benchmark-history\benchmark-history.jsonl` for local longitudinal tracking across repeated benchmark captures. Only update this document after the dataset and command path are durable enough to serve as a merge-tracked baseline.

Performance acceptance should record which benchmark lane was used:
- completed-dataset replay
- raw sidecar-free replay
- live fresh export

Do not compare those lanes as if they were interchangeable. Replay benchmarks are useful for steady-state normalization and packaging cost, while live fresh-export runs are the only coverage for Stage C import behavior and large MDE download/publish hot paths.

`tests/Invoke-LargeImportCoverage.ps1` is the preferred deterministic prep entrypoint for large import-path spot checks. It produces both a raw sidecar-free replay dataset and an Azure-ready existing-export dataset that combines `Machines_Current.json.gz`, `AdvancedHunting_Current.json.gz`, and synthetic legacy `VulnExport_*.json.gz` files.

The raw result JSON files from the April 5, 2026 capture remain local-only under `.local/`. The April 20, 2026 ad hoc hosted review captures remain local-only under `.local/perf-triage/`, and the April 20, 2026 durable benchmark series remains local-only under `.local/benchmark-series/benchmark-medium-v1-20260420-004103/`.

## Recorded baselines

| Dataset | Command mode | Local | Runbook | Function App headline | Function timing notes |
| --- | --- | ---: | ---: | ---: | --- |
| `benchmark-medium-v1` | `current-only` durable series, 3 captures | `137.28s to 139.19s` | `91.69s to 114.19s` | `41.37s to 42.18s` | `active-execution`; end-to-end `43.10s to 43.43s`; pickup delay `1.24s to 1.73s` |
| `exports-synthetic` | `current-only` | `476.63s` | `250.45s` | `239.45s` | legacy `invoke-to-finish` |
| `exports-synthetic-live` | `current-only` | `2081.27s` | `957.14s` | `683.21s` | legacy `invoke-to-finish` |
| `review-synthetic-medium` | `current-only` Azure acceptance replay, 2 captures | `153.06s to 177.83s` | `96.94s to 105.19s` | `41.59s to 43.32s` | legacy `invoke-to-finish` |

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

## Standard large Azure acceptance

| Dataset | Shape | Architecture | Azure path | Acceptance markers | Review notes |
| --- | --- | --- | --- | --- | --- |
| `synthetic-50k-1_5m` | `50,000` devices, `1,500,000` rows, `3,097` normalized CVE lookup entries | `monolithic-v1` | Azure Automation plus hosted Function App (`Dual`) | Function App execution accepted `2026-05-06T06:26:05Z`; dashboard blob written `2026-05-06T06:33:39Z`; blob-write interval `454s` | Treat this as the accepted Stage 1 large Azure envelope anchor until a newer accepted run replaces it. Compare future standard-dataset Azure runs against this record plus the review thresholds in `docs/performance-gate-playbook.md`, and keep the raw Azure validation artifacts local under `.local/`. |

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

## Capture notes

- Date captured: `2026-04-05` for the original synthetic replay baselines.
- Date captured: `2026-04-20` for the hosted `review-synthetic-medium` Azure acceptance replay.
- Date captured: `2026-04-20` for the durable `benchmark-medium-v1` three-iteration hosted benchmark series.
- Date captured: `2026-05-06` for the accepted standard large-dataset Azure envelope on `synthetic-50k-1_5m`.
- Branch intent: current branch only, no `main` comparison.
- Dataset shapes:
  - `benchmark-medium-v1`: standard durable benchmark dataset generated from the catalog entry in `tests/benchmark-datasets.json` with preset `BalancedMediumHeavy`, seed `20260322`, `120000` rows, and `1500` devices.
  - `exports-synthetic`: original `20K` synthetic replay dataset.
  - `exports-synthetic-live`: shifted synthetic live-export dataset with a latest snapshot date of `2026-04-05`.
  - `review-synthetic-medium`: `BalancedMediumHeavy` review dataset with `120000` rows and `1500` devices, validated against Azure Automation `aa-defender-reporting` and Function App `func-defender-reporting-parallel-0404a`.
  - `synthetic-50k-1_5m`: standard large Azure acceptance dataset rooted at `.local\large-datasets\synthetic-50k-1_5m`.
- `benchmark-medium-v1` is now the standard durable dataset for merge-tracked baseline refreshes and supersedes `review-synthetic-medium` for future benchmark-series captures.
- `benchmark-medium-v1` Function App headline timing now uses active execution time from the runtime status blob; end-to-end invocation time and pickup delay are recorded separately for queue and cold-start review.
- The durable `benchmark-medium-v1` persistent local cache reuse pass was effectively stable across reruns (`45.44s` to `45.49s`) and is the preferred baseline for normalized-column cache reuse.
- The hosted review baseline was captured twice on the same dataset and command path. This document records ranges because the cold local normalization pass moved more than the hosted paths across reruns.
- The local benchmark harness stages a private dataset copy before validation so raw datasets do not get mutated by sidecar regeneration during baseline capture.
- Synthetic benchmark artifacts now publish `uniqueCveIdCount`, `normalizedCveLookupCount`, and `contentTemplateCount` in both `synthetic-manifest.json` and `benchmark-dataset.json`. `normalizedCveLookupCount` is the same breadth surfaced as `CVEs` in the Azure acceptance summaries above.
- `benchmark-large-50k-v1` regenerates from the mutable `exports` source path, so its breadth counters can drift even when the dataset id, seed, device target, and row target stay fixed. Use the manifest breadth counters rather than assuming the accepted May 6 anchor's normalized CVE count will remain constant across later refreshes.
- The standard large Azure entry intentionally records the accepted invocation and blob-write markers that are already tracked in-repo. Preserve the raw Azure validation artifacts under `.local/` when refreshing this section so future updates can add comparable working-set or execution-unit detail without reconstructing the run later.

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
