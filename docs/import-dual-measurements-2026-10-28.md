# Import and Dual measurements, 2026-10-28

Scope: standalone `defender-reporting`, issues #67 and #69. Base main is
`ec2b0e2311be713c0eb2dd1a42c71ad02666abe4`. Work is isolated on
`codex/import-dual-optimization-20261028`. Existing #95 qualification and original
worktrees were preserved. No merge, issue closure, authentication, deployment,
live export, dependency installation or operational-data publication occurred.

## Decision and limits

The measured import change avoids a redundant canonical-signature lookup after
the partition reader has already validated a nonblank ID. In that branch the
signature helper returns exactly that ID. Case-insensitive duplicate IDs retain
the last row; this behavior and streaming remain covered by regression tests.

There is no measured justification for a new packaging optimization. Current
main already streams its HTML/base64 output. Automation acceptance still requires
an authorized Azure run below **400 MB** and within **10% of the controlled Dual
baseline**, with the same inputs, runtime, templates, output mode and limits.
Local measurements cannot certify either Azure requirement.

**Final merge decision: HOLD.** Independent review accepts the narrow import code
and controlled backend evidence. Required offline browser acceptance failed at a
real containment boundary, and live Azure acceptance is unrun. Neither #67 nor #69
is closed. No production packaging change is justified by these measurements.

## Controlled lanes

These are three different workloads; their times must not be compared as if they
were interchangeable.

| Lane | Input and measured operation | Cells |
| --- | --- | --- |
| FreshImport | Copy/setup excluded; one raw snapshot import into a fresh store | 3 base + 3 candidate |
| CompletedStoreReplay | Canonical completed-store sidecars; raw snapshots and payload cache excluded; normalization and preparation | 3 base + 3 candidate |
| PackageOnly | One byte-identical already-normalized payload and manifest; Hosted or Dual generation | 3 per source and mode, 12 total |

Within each lane, source order alternates base/candidate, candidate/base,
base/candidate. Packaging mode order reverses on the middle pair. All cells are
serialized with the #70 browser chat. Backend limits remain 180 seconds,
3 GiB process-family memory and 3 GiB free-memory floor, sampled every 500 ms.
These sampled family peaks are neither exact instantaneous peaks nor the root
PowerShell process's OS peak. Allocations are cumulative allocated bytes, not
retained memory. Last-GC heap/LOH snapshots are not instantaneous stage peaks.
Short phases without a sample retain null peaks.

Inputs: synthetic seed 20260322, 500 devices, 2,000 CVE templates, 20,000 source
observations (16,000 current and 4,000 history). Two dated snapshot sets contain
31,922 rows across ten group files; 31,438 onboarded open observations are
processed, producing 15,758 current IDs. Replay produces 19,677 normalized rows.
This receipt establishes **only this scale**. It establishes no 120,000-row
completion, supported tenant maximum, production throughput or Azure memory bound.

Pinned runtime: PowerShell 7.6.9 / .NET 10.0.14. Every comparison records complete
source, installed PowerShell files, executable, supervisor, driver, template,
library and input SHA-256 inventories before and after. The baseline receives the
same measurement instrumentation. The original outer supervisor SHA-256 is
`bd7938d5a6b5f5809e9d9765822158f44568d29c68f54ac1f417c216afe3f87e`.

## Import diagnosis and results

The prior 120k base/candidate attempts hit the unchanged 180-second cap at
181.547/180.344 seconds. They invoked the profiled import plus its unprofiled
parity twin and checks, rather than timing one import. Neither reached packaging
or produced a completed profile. They cannot identify one expensive operation or
establish packaging memory. No 120k attempt was repeated.

At the bounded scale above, current main's profile completed in 94.574 seconds;
its unprofiled parity twin took 67.248 seconds. The signature helper accounted for
47,118 calls, 5.439 inclusive seconds and 1,052,496,512 allocated bytes. Inclusive
streaming-reader timings include consumer work and must not be summed as exclusive
costs. This measurement supports only the narrow redundant-lookup change.

| Fresh-import median | Base | Candidate | Change |
| --- | ---: | ---: | ---: |
| Import seconds | 65.901 | 61.866 | -6.12% |
| Import allocated bytes | 26,733,903,320 | 25,269,420,824 | -5.48% |
| Whole cell seconds | 66.556 | 62.535 | -6.04% |
| Sampled family working-set bytes | 273,829,888 | 278,269,952 | +1.62% |
| Gen0 / Gen1 / Gen2 collections | 3209 / 89 / 7 | 3033 / 89 / 6 | |

Three pairs are descriptive evidence, not a statistical performance guarantee.
One candidate pair was slower. The change reduces allocations and median elapsed
time here; it does not establish lower peak memory.

Every fresh-import cell retains all 16 decompressed store files identically,
including the ten raw snapshots. Each checks all 15,758 current IDs and 393,481
raw field values. No generated fixture was overwritten.

## Replay and packaging results

Replay whole-cell medians are 35.931 versus 36.887 seconds (+2.66%); allocated
bytes are 5,954,992,960 versus 5,950,036,712. This is not a normalization speedup.
Base stage medians: load 3.136 seconds / 422,724,496 allocated bytes;
normalize 24.377 seconds / 4,166,922,632 bytes; prepare 6.603 seconds /
1,272,333,224 bytes. Sampled normalization and preparation family working sets
are 282,558,464 and 304,574,464 bytes. These are separate from PackageOnly.

The replay phase parser originally overwrote previously collected counters at
phase-end. The original receipt and parser remain preserved. Corrected phase
values were projected from the original raw TSVs and supervision receipts, with
their SHA-256 identities, **without rerunning any cell**.

| PackageOnly median | Base | Candidate |
| --- | ---: | ---: |
| Hosted whole-cell seconds | 7.028 | 6.895 |
| Hosted allocated bytes | 399,449,184 | 398,954,344 |
| Hosted sampled family working-set bytes | 240,095,232 | 242,204,672 |
| Dual whole-cell seconds | 8.305 | 8.277 |
| Dual allocated bytes | 622,252,152 | 621,366,072 |
| Dual sampled family working-set bytes | 255,787,008 | 261,238,784 |

Stage-specific checkpoints separate hosted generation from the additional
self-contained generation in Dual. Base Hosted's hosted stage is approximately
4.646 seconds / 285.32 MB allocated; base Dual's hosted stage is 4.59 seconds /
285.33 MB, followed by self-contained generation at 1.479 seconds / 221.40 MB.
The added Dual output costs additional work; these measurements do not establish
a packaging defect. Full per-stage GC, allocated-byte, heap/LOH and elapsed
observations are retained in `package01/comparison.json` and raw `phases.tsv`.

All twelve products have byte-identical payloads and assets. Compressed payload
SHA-256 is `92e76d87e5886f83ca6cdb42e8a388e0b4daa74115be2d6f0d612d742d07f0f0`;
decompressed SHA-256 is
`51a15a447ebd62c2d5dc9b39cff31e2562b1e89c19f13444409ebd0f0414a565`.
The strict artifact audit permits only the actual generated timestamp, mapped
hosted root paths and an exact two-key JSON-order variation also reproduced
between unchanged baseline cells. It compares all remaining HTML, summaries and
structured sidecar values. Failed earlier audit attempts remain retained.

## Validation and reproduction

Focused validation passed the partition-streaming/deduplication, fresh-import
profiler/parity/guards, split-assets and Dual-generation regressions, diagnostic
counter and path/junction guards. Changed sources have no parser or analyzer errors.
Canonical source, generated shared helpers, runbook and Function map-reader ASTs
match. No broad completed #95 qualification was rerun.

Run `tests/Invoke-OfflinePerformanceLane.ps1` only inside an external owned-process
supervisor; it deliberately does not enforce limits itself. Use a fresh output
directory per cell. `-ProfileImport` includes a parity twin and must not be treated
as an ordinary single-import cell. Supply real preexisting offline libraries;
this workflow does not download dependencies.

The preserved, local synthetic evidence root is
`E:\defender-reporting-worktrees\import-dual-20261028\.local\optimization`.
Its `scripts/compare.py` accepts `--base`, `--candidate`, `--fixture`, `--templates`,
`--libraries`, `--supervisor`, `--output`, and `--lane` (one of the three table
names). PackageOnly additionally requires explicit `--payload` and `--manifest`.
Pin the same fixture/templates/libraries and normalized payload as the original
receipt. Baseline requires the common diagnostic instrumentation and lane harness
overlay recorded by the comparison inventories. Preserve those bytes before
starting and reject source/input/runtime drift afterward. Compare normalized
semantics separately from permissible generated timestamps.

Primary receipts relative to that root:

- `evidence/main-profile20k.json`, `main-profile20k/store/fresh-import-profile.json`
- `fresh02/comparison.json`, `replay01/comparison.json`, `package01/comparison.json`
- `evidence/replay-phase-reprojection.json`, `evidence/artifact-parity03.json`
- `evidence/focused-final01.json`

The unchanged #95 evidence is not replaced by this receipt. Browser diagnostics,
including failed attempts, remain a separate gate and must not be counted as a
successful browser or Azure qualification.

A browser-free retained-handle lifecycle probe completed under unchanged browser
admission and 240-second / 2 GiB family / 3 GiB free-floor limits. The two live
control processes were observed in the exact outer job; the live inner-job
nonmember was rejected. A naturally exited process with real exit code 259 had a
signaled wait handle, demonstrating why exit code alone is insufficient. The owned
root retained job membership after termination. This does not reproduce or explain
the browser guard failure. Separate CIM timestamps had lower precision than native
creation FILETIME; no approximate timestamp was accepted as identity. Final outer
membership was empty, cleanup was verified, the temporary profile was removed and
source/runtime pins were unchanged. The executed launcher did not assert the outer
`remainingAtRootExit` field; its actual empty value was independently verified in
`identity-probe01/terminal-verification.json` without another run.

One subsequent baseline SelfContained diagnostic captured the actual first failing
membership check (`browser-identity04`). The original retained query handle
identified Edge 156.0.4314.50's `identity_helper.exe`. A separately opened handle
matched its exact native creation FILETIME and reported live waits before and after
the membership query (258/258), membership false and no native errors. The original
and fresh CIM records both matched the exact test profile. The existing guard
correctly rejected this live process outside the inner job. This observation is
not an exit race, PID reuse or owner-response timeout; the failed response arrived
at 0.540 seconds against its unchanged 5-second budget. Diagnostics can affect
timing, so they are not performance evidence and do not establish how Windows or
Edge created the process outside the job.

That single case stopped at the first failure: no reload, candidate or remaining
mode was attempted. The outer run failed after 21.542 seconds, below its unchanged
240-second/2-GiB/3-GiB bounds. Outer terminal membership was empty and outer cleanup
was verified, but inner completion remained unknown and the profile was retained.
These are separate facts: outer cleanup cannot retroactively prove inner
containment. A later all-image exact-profile census found zero matching processes,
zero Edge processes and zero identity helpers; no PID-based termination was used.
Source/input/runtime pins remained unchanged. Full-field browser parity was not
completed and must not be inferred from five-report readiness or artifact parity.

The passive native/CIM observers exist only in the private diagnostic harness.
Production ownership helpers and the #95 accepted qualification are unchanged.
No process was exempted from the guard, and no browser policy or security setting
was changed to obtain a pass. Further browser acceptance needs an independently
reviewed way to run the actual browser workload with the required containment;
repeating the same failed launch or ignoring the live helper is not an acceptance
strategy. The remaining Azure acceptance additionally requires explicit approval
for the selected environment and the issue's unchanged memory targets.
