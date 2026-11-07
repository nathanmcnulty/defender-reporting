# Full-scale browser diagnostics — 6 November 2026

This records synthetic Windows VM evidence from 7 November UTC. It is not full-scale acceptance. The baseline product is main `4988c5f47a0f674c63a62800e7a0a901233b9067`, after #106, #108 and #107. Initial diagnostics use #109's `a8ca828`; the later header-attribution run uses `aa1a018` as the common harness while retaining the unchanged main product.

The guest has four CPUs and 16 GiB RAM, Windows Server 2025, PowerShell 7.6.9/.NET 10.0.14, Node 26.7.0 and Chrome 156.0.8078.80. Native ownership, five launch samples above 5.25 GiB available, a 3 GiB runtime floor, the 2 GiB owned-family cap, 240-second containing deadline and cleanup gates remain unchanged. Working-set sums include shared pages and launcher helpers; they are not physical RAM consumption or browser JavaScript heap measurements.

## Baseline evidence

| Workload | Result | Scope |
| --- | --- | --- |
| Chrome native canary | Passed, cleanup confirmed | Launch, assignment, sealing, live query and original-handle cleanup only |
| Edge 156.0.4314.58 canary | Failed before first live inventory, root exit 1002; cleanup confirmed | Cause unknown; no Edge dashboard qualification |
| Small Chrome Hosted | Passed 24 real PDF downloads over cold/reload | All five empty reports, representative/range reports, exact filter/card/table checks and 13 rendered first-load pages |
| Small Chrome self-contained | Passed 24 real PDF downloads over cold/reload | Same checks; 10 rendered pages match Hosted exactly and three differ by reviewed tied-row order |
| Full Hosted load: 1,187,395 rows, 49,476 devices, 5,000 CVEs | Failed family cap at 2,161,229,824 bytes | Last observed initialization completed, but no accepted full tour, reload, detail or PDF result |
| 19,677-row unfiltered report tour, then selected-device PDF | Failed family cap at 2,154,770,432 bytes | First PDF did not complete; failed parent and partial journal retained |
| Same PDF case with header/buffer diagnostics | Failed family cap at 2,156,642,304 bytes | Exactly 15 source rows and 15 report rows; header capture started, never completed, and buffer generation never started |

All containing failures are retained as failures. Original artifacts and byte/hash recovery receipts are kept before terminal command maintenance. The small controls do not qualify the full population. Edge's earlier documented `identity_helper.exe` ownership failure is different from this natural early exit; neither the meaning of 1002 nor an unsupported OS is established here.

The small PDF review compared each file with its own selected-scope receipt, including exact table row order. Cross-delivery content matches, but independently generated equal-score/equal-key rows can have different tie order. Do not claim byte or order parity for those three differing pages.

## What the profiles establish

The full-load cap sample contains 1,482,588,160 bytes in Chrome processes and 678,641,664 bytes in PowerShell, Node and console helpers. Available guest memory remained 12,422,676,480 bytes. This is a containing-family budget failure, not evidence of physical RAM exhaustion. The observed 21 Chrome processes have no recorded subtype/command-line attribution; they do not establish 21 tabs, workers or a leak.

The last full-load journal reports 4,326.2 ms at readiness, 385,596,856 bytes of main-renderer heap, worker inflation 255.6 ms, worker parsing 375.1 ms and posted-to-received delivery 662.2 ms. These are partial diagnostics from a failed run. Delivery includes serialization, scheduling and dispatch; it is not isolated clone CPU time. The final cap occurs about 2.3 seconds after worker termination, so the trace alone does not prove that a live worker graph caused final resident memory.

The additional PDF run resolves a different question: the selected report has only 15 rows, and the failure occurs during `capturePdfHeaderImage`, before `getBuffer`. The pinned html2canvas 1.4.1 implementation clones the target's whole document. A header attached to the live dashboard therefore brings visited report DOM into the clone even when the selected export is small. The source plus phase trace supports testing a narrowly scoped header clone.

## Candidates and required checks

The combined worker/header candidate `77d672b` passed 48 actual small PDF exports across Hosted and self-contained modes. Independent checks covered exact captured filters, cards and complete table order, including all five empty reports on both loads. All 26 rendered first-load pages matched the previously reviewed baseline Hosted pages byte for byte.

A complete three-pair alternating Hosted comparison used 19,677 rows, identical data/runtime pins and common harness `77d672b`. Each containing run passed cold/reload, filtering, all five report switches and native cleanup. Generated HTML was separately recovered and checked against its original inventory hashes: the only within-product difference was the single validated `dataQualityMeta.generatedOnUtc` timestamp. All other HTML bytes, data and runtime assets were preserved in the comparison.

Observed baseline-to-candidate cold medians were 171.5 to 136.0 ms for denormalization and 25.5 to 1.0 ms for worker delivery. Overall initialization was mixed, warm results overlapped, and whole-family peak memory increased in every pair (median 2,030,149,632 to 2,040,623,104 bytes). This supports a narrower handoff improvement, not a memory or overall readiness improvement.

The subsequent full Hosted candidate still failed during initial readiness at 2,189,185,024 family working-set bytes. Cleanup passed. Its last main-heap observation was 379,864,012 bytes; initialization completed, but no accepted full reload, filter/report tour, detail or PDF result followed. Worker delivery was 1 ms; main decoding/parsing took 41.8/239.2 ms. These partial diagnostics from failed parents cannot establish a full-scale speedup.

The next row-allocation candidate predeclares the final environment-first-seen date and recomputes its temporary canonical issue key from the original raw index in the second pass. It avoids retaining a scratch field and adding a new field to every completed row. Existing cache/worker rows still have their old scratch cleared when present. This is a measured-phase hypothesis, not an established allocation-size or memory improvement; exact identity/date/materialization parity and new guarded measurements are required.

The worker candidate transfers inflated UTF-8 bytes, terminates the worker, then decodes/parses on main before building rows. It retains compressed input for fallback and leaves schema, lazy fields and cache eligibility unchanged. Parsing moves to main rather than disappearing; assess whole initialization latency, main-thread work and native memory together. Its memory benefit is unproven until measured.

The header candidate keeps the header subtree, its ancestors and the document head/styles in html2canvas's clone, excluding unrelated body branches. It does not remove live dashboard content, change selected data, reduce resolution or change the PDF snapshot lifecycle. Validate actual header raster, table/filter/card content, pagination and failure cleanup in Hosted and self-contained modes.

Before promotion, use immutable source/runtime/data pins, the same common harness on both sides, positive controls, valid controlled comparisons and admitted representative runs. Keep initialization, filtering, switching, detail, header capture and PDF buffer preparation separate. Do not calculate improvement percentages from failed parents, stitch partial attempts into a pass or replace the unfiltered tour with scoped-first acceptance.

Small Windows import/replay diagnostics, PackageOnly, Automation's 400,000,000-byte and 110% comparison gates, actual Storage publication #104 and Functions/Automation #92 acceptance remain separate. This browser evidence does not close #67, #69, #70, #92 or #104.
