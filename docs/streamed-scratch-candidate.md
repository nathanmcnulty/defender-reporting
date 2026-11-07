# Optional streamed temporary partitions

`Publish-VulnerabilityHistoryStore` and `Publish-VulnStoreFromBulkSnapshot` accept
`-CompressTemporaryPartitions` as an opt-in capacity experiment. It wraps each
open snapshot/current-map partition writer in GZip Fastest and reuses the existing
GZip NDJSON reader. Defaults, import comparison/order, canonical GZip files,
dictionary/ref schema, transaction handling and raw retention are unchanged.
The existing procedural initial-import shortcut is preserved. The plain ID
validation partition path remains plain. No runbook, export entrypoint or schedule
automatically enables the option.

The hypothesis is reduced temporary disk occupancy under the unchanged 1 GiB
scratch limit. It is not a measured speedup, memory improvement or full-scale
admission result. There can be 128 simultaneously open encoders; native codec
state and extra compression/decompression may increase memory or elapsed time.
Compression also does not bound later history/content-projection staging.

## Prior rejected experiment

The retained private A6 compression experiment buffered up to 16 MiB of plaintext
partition chunks, then reread/compressed/deleted those chunks into appended GZip
members. Current-map writes already streamed directly. Both measured arms used
A6; this was not A6 versus production. Two observed plaintext/compressed body
pairs were 62.2733218/73.5933592 seconds and, in reversed order,
55.7735391/71.2521627 seconds: compression was 18.18% and 27.75% slower, with no
consistent memory or sampled scratch benefit. Only the first pair was admitted;
the second containing parent remains failed and cells 5–6 were not run. These
receipts do not identify the causal cost of each implementation step.

This option uses the stock importer and omits A6's plaintext spool, second disk
pass, per-row byte counting and repeated chunk codec creation. It introduces no
private importer or alternate normalizer. That difference supports a new capacity
hypothesis, not reuse or promotion of the rejected A6 result.

## Checks and acceptance still required

`pwsh -NoProfile -File tests/Invoke-StreamedScratchRegression.ps1` uses tiny fixtures
with exact complete canonical bytes, expanded full rows/order and typed return
summary comparisons. It covers multiple files/dates, case/duplicate IDs,
changes/removals, empty maps, overwrite and concatenated-member append,
Unicode/long/final lines, corrupt compression, disposal on parse failure and real
transaction rollback/raw-retention/retry after a commit-marker failure. The
collision fixture deliberately uses one partition; production remains at 128.
These are correctness tests, not resource measurements.

Before promotion, independently review exact source/runtime/fixture pins and
focused parity, then complete an admitted alternating small cohort with exact
output parity and both memory and elapsed time at most 110% of the same-input
baseline. Preserve every failed containing run and stop on the first invalid
cell. Keep Windows supervision at its established limits and qualify Automation
separately, with peak strictly below 400,000,000 bytes. Existing Dual/Hosted
memory and generation gates remain at most 110% of the same-input Dual baseline.
Any future full proposal
needs an actual complete-stage capacity argument and separately approved bounded
execution. The known stock full lower bound remains 100,538,099 retained GZip +
990,954,322 plaintext spool = 1,091,492,421 bytes, already 17,750,597 above 1 GiB
before other staging. Do not rerun that inadmissible path or infer acceptance
from PackageOnly, a small diagnostic or this source change. #67/#69 remain open.
