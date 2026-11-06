# Browser and administrator validation, November 6, 2026

This is a validation snapshot with open gates. Corrected small Hosted PDFs have
passed real download, text/table comparison and rendered review. The final
cache-only performance cohort passed all six cells. Small self-contained PDFs
also passed real downloads, semantic checks and rendered review. The larger
scoped admin/PDF checks passed. Browser lab Azure resource cleanup was verified
at 23:18 UTC: the owned resource group and all planned resources are absent.

## Source and workload boundaries

| Source | Role |
| --- | --- |
| `e58a39e` | Original main after [#105](https://github.com/nathanmcnulty/defender-reporting/pull/105). |
| `373df9e` / [#106](https://github.com/nathanmcnulty/defender-reporting/pull/106) | Atomic export generations, first-export/empty-enrichment corrections, scoped filtering and PDF snapshot fixes. |
| `5b5dc2f` / [#108](https://github.com/nathanmcnulty/defender-reporting/pull/108) | Corrected PDF card metadata and resolved-vulnerability scope; the corrected product baseline for comparisons. |
| `ecae168` / [#107](https://github.com/nathanmcnulty/defender-reporting/pull/107) | Candidate confined to cached-row derived refresh. The global date formatter is restored to its prior exact bytes. |
| `99b4662` | Harness adds an explicitly labelled scoped-first workflow. Each running cohort retains its own frozen common harness; later source does not rewrite its receipts. |
| `120614b` | Corrected export-table receipt captures collapsed overflow text; no production code changed. |

Deterministic CI passed for the corrected PDF source, `ecae168`, `99b4662` and
`120614b` (full preflight and Azure package smoke).
CI does not establish browser measurements or Azure deployment acceptance. The PRs
remain reviewable work; this report does not close issues or merge changes.
Intentional demo data and the owner/public-fork publishing work in draft
[#98](https://github.com/nathanmcnulty/defender-reporting/pull/98) are preserved.
That workflow work has not been duplicated, enabled or folded into these changes.

The browser runs use an isolated authorized Windows VM, one pinned Chrome/runtime
and synthetic inputs. Preparation uses the existing canonical fixture and
normalized payloads; PackageOnly generation is not an import or replay benchmark.
Hosted products are served over guest loopback. These timings do not measure
public hosting, authentication, WAN transfer or production cold starts.

## Accepted checks and remaining gates

| Check | Result at this snapshot |
| --- | --- |
| Native ownership and two-row Hosted control | Passed startup, cold/reload readiness, report/cache consistency and process/profile/server cleanup checks. |
| 19,677-row Hosted load | Accepted diagnostic cells completed cold/reload, fixed-date filtering and all five unfiltered report switches with input/product hashes and cleanup preserved. This establishes that workload at this scale, not a tenant maximum. |
| Corrected two-row Hosted PDFs | Passed 24 actual browser downloads across cold/reload: all five representative and empty reports, plus both device-report range modes. Exact filter/card/mode text and complete table rows/order matched the captured scope receipts. Thirteen rendered page images, including a continuation page, were reviewed. Two filter lines continue onto page 2 in one report; this was readable and nonblocking. |
| Final cache-only comparison, cohort 03 | Passed all six alternating cells with identical inputs/engine/common harness, unchanged hashes, matching payload/summary/card/count/navigation digests and accepted resource/cleanup receipts. Those digests do not compare every rendered table value; temporal/cache semantic regressions provide separate source-level coverage. |
| Corrected two-row self-contained PDFs | Passed 24 actual downloads from the executed inline HTML at its file URL, across cold/reload. Exact scope/card/mode text and table rows/order matched receipts. All 13 first-load rendered pages independently reviewed, with the same readable continuation as Hosted. Severity None stayed empty; this fixture could not exercise hidden-group intersections or long tables. Whole outer peak was 1,652,482,048 B; inputs and process cleanup passed. |
| 19,677-row scoped administrator timing | Passed cold/reload with a 15-source-row selected device, all five representative/empty reports, all three actual modal detail families and device inline cards. Twenty real PDF buffers completed; final download was replaced by getBuffer in this timing lane. Source/report/card digests agreed across loads, scope restored, inputs unchanged, outer peak 1,917,571,072 B and cleanup verified. This does not qualify an initial unfiltered report tour. |
| Larger scoped PDFs and filter UI | Passed 26 actual downloads across cold/reload with 19,677 rows loaded. Representative scope was 15 source rows, empty scope zero, and the bounded long-table scope 250 source rows/229 distinct CVEs. All exact filter/card/mode and table row/order checks passed. All 33 final first-load rendered page images are byte-identical to the independently reviewed pages. Real group/platform controls retained the hidden selected group, stayed empty after visible deselection, and revealed only its 15 rows after removing Platform; severity None stayed empty. Outer peak 1,937,772,544 B; input hashes, scope restoration, cold/reload digests and process cleanup passed. |
| Azure browser-lab cleanup | Verified at 23:18 UTC after recovery/hash verification of all command evidence. The exact owned resource group and all ten planned VM/disk/network/NAT/IP/storage/schedule/deployment resources returned expected resource-not-found responses. The VM was deallocated before deletion. No role or policy changes were performed. The earlier rejected VM attempt was also deleted and its evidence retained. |

The private final evidence archive contains 417 members (52,389,313 bytes),
SHA-256 `f21093fb4ba63860cefd1ec872aabfe4006f00fe9dab849cd777fc10516716fb`.
It retains recovered original evidence ZIPs, rendered pages, immutable driver
archives, source/runtime/input pins, request accounting, failed attempts,
independent reviews and cleanup proof. Runtime/fixture archives remain separately
preserved; they were not duplicated into this archive. No private cloud records
or input payloads are published with this report. Public whitelisted metrics are
linked below. Issues remain open and PRs remain unmerged for review.

The first prototype cohort completed six valid cells, but it combined cached-row
work with a global formatter change and had mixed report-switch results. Its
measurements are retained as prototype evidence, not final performance claims.
The formatter change was removed. Cohort 02 stopped at the provider's 25-command
RunCommand limit; its partial cells are not stitched into cohort 03.

### Final measured comparison

Three alternating baseline/candidate pairs compare `5b5dc2f` with `ecae168` on
the same pinned Chrome 156.0.8078.80 and 19,677-row input. The
[whitelisted raw metrics and source/engine pins](browser-performance-results-2026-11-06.json)
allow the medians and mixed results to be reviewed without publishing private
cloud records. Observed medians:

| Metric | Baseline | Candidate |
| --- | ---: | ---: |
| Cold browser readiness | 798.3 ms | 788.2 ms |
| Warm browser readiness | 719.5 ms | 681.9 ms |
| Warm cached-row derived refresh | 134.6 ms | 101.1 ms |
| Warm denormalization | 298.7 ms | 236.5 ms |
| Cold / warm initial filter phase | 6.7 / 13.5 ms | 6.9 / 12.3 ms |
| Whole-cell sampled browser-family peak | 1,326,215,168 B | 1,096,761,344 B |
| Whole-cell outer-family peak | 1,984,765,952 B | 1,939,435,520 B |

The targeted warm derived refresh improved by 24.9% and warm readiness by 5.2%
in this small cohort. Cache-read timing also varied (121.7 to 89.6 ms); attribute
only the derived-refresh work to the source change. These are observations,
not statistical significance or universal speedup claims. Cold report-switch
medians ranged from 29.0–315.5 ms baseline and 29.9–290.1 ms candidate; warm
medians ranged from 71.9–484.5 ms and 42.7–472.8 ms. Warm Impact Analysis,
Remediation Activity and Devices by Remediation were about 4–9% slower, while
the other switches improved. Memory figures are whole-cell peaks across both
loads, not separate cold/warm peaks. Every individual cell stayed under the
unchanged 2 GiB outer limit; the highest candidate cell reached 2,056,871,936 B.

The change caches each occurrence's issue key across two derived-field passes
and reuses normalized dates locally. It does not change cache admission/eviction
(500,000-row exclusion boundary, four entries), report semantics, framework or
Hosted/self-contained packaging. Large unfiltered rendering remains a measured
cost; a frontend rewrite is not supported by this narrow experiment.

The separate scoped administrator timing cell loaded all 19,677 rows and then
selected one device (15 rows). Observed cold/reload filter completion was
63.0/74.7 ms; representative report switches took 33.0–78.2 ms and modal detail
opening 66.2–67.4 ms. Representative PDF preparation took 539.1–814.5 ms, empty
PDFs 344.1–572.9 ms. Lazy PDF runtime/library preparation was 7.0/115.3 ms cold
and 6.2/40.3 ms on reload. These are one cell's host-observed completion timings,
including polling/paint opportunities, not a baseline comparison or INP.

The 1,187,395-row load attempt and the 19,677-row unfiltered-tour-to-PDF stress
attempts hit the unchanged **whole process-family** 2 GiB budget. Owned cleanup
was verified and the failures remain preserved. Browser sampling did not prove
that the browser alone reached 2 GiB; these are not application OOM diagnoses,
browser-only memory defects or full-scale acceptance. Preparation and helper
compiler memory were isolated into terminating child processes for later cells;
that test-driver correction is not a dashboard performance improvement.

The scoped-first sequence is deliberately different: load, establish the selected
device/filter scope, then visit reports, details and PDFs, and finally restore the
original scope. It avoids an initial unfiltered report tour and cannot qualify
that tour. Its representative PDF scope remains at most 250 source rows while
the full input is loaded and filtered. Missing detail or long-table coverage is
labelled rather than inferred from equal zero counts.

The first larger saved-artifact cell completed 26 real downloads, but exposed a
receipt defect: visible `innerText` omitted five rows inside closed overflow
details, while PDF extraction correctly included their `textContent`. The receipt
now reads table cells from the captured export snapshot. Independent comparison
with the canonical raw payload confirmed exactly 10 snapshot and 15 range
remediations for the selected device, matching those PDFs without extra IDs.
Blank IP labels represent absent addresses and are omitted intentionally. A
229-row table also produces three page-boundary row fragments: the verifier now
requires exact column-wise reassembly in order, consuming every fragment and
rejecting missing, duplicate or extra rows. Original flagged evidence is retained.
The corrected frozen-harness rerun passed all 26 PDFs; all 33 final rendered
first-load pages matched the independently reviewed images byte for byte.
Independent raw-data selection also confirmed the long-table scope's 250 rows,
229 distinct CVEs and severity counts 23/70/97/60. Page-boundary continuation
fragments are readable, including the repeated column headers. These checks do
not qualify arbitrary unbounded PDFs, large self-contained loading or every
reload page visually; reload content was checked semantically.

## Reproduction

Use the existing approved Windows owned-process supervisor, pinned runtimes,
real libraries, immutable generated products and fresh private output paths.
Admission remains five fresh samples **above 5.25 GiB** free with no preexisting
Chrome/Edge; runtime limits remain a **3 GiB** free-memory floor, **2 GiB** family
cap and **240-second** outer deadline. Native ownership and cleanup proofs remain
mandatory. The following is the guarded inner browser workflow, not a deployment
or permission-change command:

```powershell
$env:DASHBOARD_BROWSER_ENGINE = 'chrome'
$env:PLAYWRIGHT_MODULE = '<pinned-playwright-module>'
& $python $supervisor --cwd $repo --out $freshOuter `
  --seconds 240 --cap-gib 2 --floor-gib 3 `
  node tests/Measure-DashboardWorkerTransfer.js $products $freshEvidence 1 19677 `
  --generated-runtime --progress-journal --date-range=2025-01-01/2026-10-22 `
  --admin-exercise --scoped-admin-first
```

For actual saved PDFs/screenshots, replace `--admin-exercise` with
`--saved-artifacts`; the getBuffer timing and real-download lanes are separate.
Add `--self-contained` to execute the retained embedded HTML through its exact
`file://` URL with no source overlay. For the two-row control, use expected count
`2` and `--positive-control` instead of the larger fixture's date range. Omitting
both exercise flags and `--scoped-admin-first` retains the ordinary unfiltered
report-tour workload. Keep its results separate from the scoped workflow.

Progress journals preserve the last observed phase if the outer guard terminates
a run. A journal or individual PDF does not establish a pass without the complete
containing run, unchanged input/product inventories and native cleanup proof.
See [the test guide](../tests/README.md) for artifact receipts and semantic/visual
review requirements. All captured content in this campaign is synthetic.

## Existing backend and runtime evidence

[#67](https://github.com/nathanmcnulty/defender-reporting/issues/67) and
[#69](https://github.com/nathanmcnulty/defender-reporting/issues/69) retain separate
FreshImport, CompletedStoreReplay and PackageOnly gates. Six historical full
Automation PackageOnly cells passed for the identical 1,187,395-row normalized
input; their maximum lifetime OS working set was 311,836,672 bytes. Full fresh
import has no accepted complete Automation cohort, and full replay stopped in
source loading before normalization completed. Neither these browser tests nor
PackageOnly results close those gaps. Automation still requires peak strictly
below **400,000,000 bytes** and the controlled memory and generation comparisons
within **110% of Dual**.

The canonical preserved backend evidence archive is identified by SHA-256
`000f7bb6a69606f9f99ea6b9495b67d4e48f0fe880e5402ff0a9233cf7edb4c7`.
Its accepted results and failed experiments remain distinct; no sealed historical
campaign actor is rerun by this browser validation.

[#92](https://github.com/nathanmcnulty/defender-reporting/issues/92) remains **HOLD**.
The established source/native/package qualification is retained, while the
separately prepared historical live packet still lacks its selected-scope quota
and hosted deployment/runtime/workload evidence. That packet targets a different
scope from this temporary browser VM. Authorization and success for this lab do
not qualify Flex/Automation startup, runtime binding, effective permissions,
deployment failure recovery, rollback or cleanup under #92. Any such execution
needs a refreshed, concrete approved plan. Actual Azure blob conditional-request
and interruption acceptance for #104 is also separate from its offline protocol
tests and this browser campaign.
