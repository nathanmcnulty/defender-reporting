# Reporting reliability review, November 6, 2026

Starting point: main `e58a39e4b9465490197ed9f4dfd41537a6a856a0`, including
[#105](https://github.com/nathanmcnulty/defender-reporting/pull/105).
The original checkouts, intentional demo data and private evidence are preserved.

## Existing work and acceptance

| Work | Reconciled result | Remaining gate |
| --- | --- | --- |
| #105 | Merged local transaction/journal recovery correction; this is the baseline. | Does not make Azure export uploads atomic. |
| #98 / #68 | Draft #98 owns the owner-demo publishing exception and public-fork protection. | Review/rebase/merge remain separate. This work does not reproduce its workflow or staging changes, remove the intentional demo, or enable publishing. |
| #99 / #100 | Individually empty enrichment queries and missing first-run output directories are reproducible correctness gaps. | Exercise real entrypoint with mocked authentication/download boundaries and real enrichment-store publication. |
| #101–#103 | Scoped deselection, empty PDF tables and asynchronous export state are reproducible dashboard gaps. | Verify selected scope, every report family, actual PDF generation and lifecycle restoration. |
| #104 | Azure export roots were overwritten sequentially, outside the HTML transaction. | Readers must observe a complete generation or fail closed, including upload interruption, retry and competing publishers. |
| #67 | The narrow import optimization in #97 is already merged. No accepted complete fresh-import Automation cohort exists. | Full plaintext import exceeds the unchanged 1 GiB scratch cap by 17,750,597 bytes before other costs. A new candidate needs measured benefit and admitted small comparisons before another full campaign. |
| #69 | Six full Automation **PackageOnly** cells passed on identical normalized input: 1,187,395 rows, 49,476 devices, 5,000 CVEs. Maximum lifetime OS working set was 311,836,672 bytes. Median generation was 129.0784605 seconds Dual and 87.6023396 seconds Hosted. | Full completed-store replay failed during source loading, before normalization. Observed lifetime OS peak was 600,547,328 bytes. Packaging acceptance does not qualify import, replay or normalization. |
| #92 | #95 source/native/package qualification remains accepted. The October 30 read-only attempt stopped before creation. | Authoritative selected-subscription westus2 Flex quota/usage remains unproven. Host startup, runtime binding, workload, permission denial and deployment recovery remain unperformed. |
| #70 | Existing source and Chrome functional evidence remain useful. | New hosted performance measurements and the separate Edge containment gate remain distinct. |

The #67/#69 decision uses the final November 6 review and offline reproduction,
superseding the earlier incomplete live-campaign decision. The final reproduction
verified 740 objects, 984 aliases and 187 preserved private blobs. The evidence
archive SHA-256 is
`000f7bb6a69606f9f99ea6b9495b67d4e48f0fe880e5402ff0a9233cf7edb4c7`.
Final cleanup verification at November 6, 18:04:21 UTC confirmed the owned resources
and temporary custom role/assignment absent and 22 inherited assignments preserved.
The campaign is closed to further execution. The private A6 importer and rejected
normalizer are not production candidates.

## Validation boundaries

Keep FreshImport, CompletedStoreReplay, PackageOnly and browser measurements
separate. Automation acceptance remains strictly below **400,000,000 bytes**, with
both controlled memory and generation elapsed comparisons within **110% of Dual**.
Local and VM correctness limits do not replace those gates.

Reuse the existing browser harness and synthetic fixtures. Preserve its native
process ownership, exact profile, cleanup and resource checks. Browser admission
requires five fresh samples above 5.25 GiB free; runtime limits remain 2 GiB owned
family memory and a 3 GiB free-memory floor. A resource-admission failure is an
unperformed browser check, not a dashboard pass or evidence of a dashboard defect.

## Future live validation

No Azure deployment, paid operation, permission change or live export is authorized
by this source work. Prepare a hash-bound candidate and baseline, exact synthetic
inputs/templates/runtime, selected tenant/subscription/region/hosts, resource and
cost envelope, failure probes and cleanup plan before requesting approval.

Do not repeat the accepted PackageOnly campaign just to obtain another pass.
Import/replay requires a measured candidate, independent review, focused parity
and a complete admitted small alternating cohort before proposing a full attempt.
Keep stop, scratch, telemetry and memory limits unchanged; stop on the first
invalid measured cell instead of stitching a partial cohort into a pass.

The old #92 approval packet is a reference, not current authorization. A renewed
attempt must resolve the quota gate, refresh timing/cost assumptions and carry
forward all **44** prior explicit ARM requests; the sealed old amendment counted
only 15. Any changed observation order requires review before execution.

## Current source checks

Focused first-export coverage runs the real entrypoint in a clean temporary
checkout with authentication and export boundaries mocked. It covers both token
and credentials parameter sets, paths with spaces, default output, provider/file
rejection before authentication, all eight Advanced Hunting empty subsets, and
byte-preserving all-empty refresh of an existing enrichment store.

The atomic export regression passed nine file boundaries plus the pointer,
committed-response-loss reconciliation, stale publishers, held prior readers,
gzip/plain transfer and fail-closed corruption checks. The existing HTML
transaction regression passed SelfContained, Hosted and Dual checks. Independent
review found and corrected integer-length validation precedence, same-second
workspace collisions and a pending-navigation/PDF race.

The PDF lifecycle and scope checks passed, including actual pinned pdfmake
generation for all five empty report families. Canvas capture is stubbed in
those Node checks; this is not visual or final-download acceptance.

The integrated preflight passed build, parser and analyzer stages, then stopped
at the existing synthetic-generator disk gate: C: had 7.52 GiB free against a
10 GB requirement. E: had 1.56 GiB free. Browser admission also remains unmet
(observed free memory below 3 GiB, versus five samples above 5.25 GiB for launch).
No threshold was lowered and no unrelated files/processes were removed. Full
preflight, representative large browser measurements, visual PDF review and
measured bottleneck improvements remain open; no new speedup is claimed.

This document records acceptance boundaries; it does not close any issue.
