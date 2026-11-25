# Reviewed inventory and canary-cleanup fixes — 2026-10-24

## Source checkpoint for dot

This handoff accompanies reviewed source `03ae6da3310fa3ccb3b564e2df1baa567bdcba1b` on the existing owning branch `fix/issue-70-reviewed-cleanup-20261023`. Its parent is cleanup fix `1cd49af7d4b2515f9598229c0faf664e5dcddefa`; their baseline is `94bd81e889ae62ffa88dd3559116ab3c39f4c23d`. The final published handoff commit is a documentation-only descendant of 03ae6da and is returned separately after exact remote readback.

Only five test/harness paths changed in those two source commits. Product templates, import/generation/runtime code and generated distributions remain unchanged from the accepted source checkpoint `9c240298b2feb9c2d5698fcd179296b37d30d78c`. Do not qualify or merge the older runtime on the documentation-review branch. The accepted earlier cleanup/singleton milestone remains accepted; these changes address newly demonstrated standalone-helper defects and memory accounting.

## Demonstrated defects and narrow changes

The old standalone cleanup selected neighboring profiles through substring matching and could report a false termination failure when one tree-kill removed a later snapshot entry. Both behaviors were reproduced using offline process mocks; no unrelated real process was terminated in the reproduction.

Cleanup now requires exactly one normalized, exact `--user-data-dir`, checks PID/creation/root and Process.StartTime identities again before termination, and directly stops verified processes child-first. It preserves descendant accountability discovered from a verified initial root, distinguishes benign exit races from access-denied/live failures with fixed codes, deduplicates diagnostics, and retains a profile when cleanup is unconfirmed. Termination waits and verification share one monotonic five-second wait/poll budget; no separate verification window is added. Non-cancellable CIM/Get-Process/Kill calls are not guaranteed to finish in that wall-clock interval; the unchanged outer supervisor remains the hard bound.

`DrainIncomplete` remains a failure and propagates accounting-incomplete through immediate and final cleanup. This conservative fallback covers the observed incomplete-stream shape; it is not a general capture/launcher-ownership proof for a root that vanished before initial inventory when drainage completed. Capture.Run's drain windows and timeout fallback were not changed. An offline inherited-stream fixture demonstrated exit-zero plus incomplete drainage; it does not identify the historical native cause.

Inventory now projects the seven required properties from the full Win32_Process population, preserving non-Edge descendant discovery. Working-set and private-memory counters come from the same creation-bound CIM snapshot. Missing, negative, nonnumeric or overflowing counters fail closed. This removes redundant per-PID process opens and fixes the previous silent private-memory omission when an open raced or failed. It does **not** establish that the intermittent five-second inventory timeout is fixed.

## Validation: preserve every result

| Check | Reviewed outcome |
|---|---|
| Old helper under new safety assertions | Expected FAIL: neighbor selected; exit-race failure separately reproduced |
| Revised offline repro and cleanup/probe regressions | PASS; final regression run 24.547s |
| Affected PowerShell analysis | PASS, 9.532s |
| JavaScript ownership fixtures | PASS, 94.187s |
| Full telemetry assertions | PASS, 126.047s; component gate only |
| First actual standalone rerun | FAIL, 11.031s, at dashboard wait-ready; canary and cleanup passed |
| Final actual standalone on shared-budget source | PASS, 11.609s; canary/dashboard ready, complete streams, profile/site removed, inner and outer cleanup verified |
| Actual uninstrumented candidate 20k rerun | BLOCKED, 14.547s, by five-second process-inventory timeout after readiness and before field verification |
| First instrumented diagnostic | BLOCKED, 15.937s; inventory call timed out at 5,078.875ms |
| Final discriminating diagnostic | PASS, 30.719s; cold/reload each verified 19,677 rows × 42 fields = 826,434 values, matching digest and cold→cache-hit behavior; page errors/remote requests zero; cleanup verified |

The final standalone retained the original `--disable-gpu`. No GPU-flag repair was made; a later pass does not erase earlier readiness failures or prove a launch-flag cause. The final instrumented field pass is diagnostic evidence, not a replacement for the actual uninstrumented timeout, a stability claim or a fair performance series. No further candidate run followed the final agreed diagnostic.

Phase markers identify phase **beginnings**. In the failing observed call, compile began at 13ms, CIM at 1947ms, selection at 2438ms and memory at 2716ms; the remaining failed interval was not localized further. The final diagnostic's maximum call was 4426.225ms, leaving only about 574ms below the same deadline. In that passing call, memory work took about 18ms and JSON construction 14ms; compilation and combined startup/completion/stdout/scheduling overhead contributed much more. This supports continued investigation, not a proven single root cause or permanently adequate deadline margin. Persistent helpers or parser-assembly caching were not introduced speculatively.

All native attempts retained outer 240s/2-GiB family cap/3-GiB physical-free floor. Playwright retained 120s readiness, five-second inventory and 15s termination; standalone retained its original 45s virtual/probe budget and capture windows. No cap, timeout or floor was relaxed. Exact source/input maps, commands, resource samples and cleanup accounting were checked. No dependency, credential, tenant, live Azure/Graph/XDR, resource-resize, PR/workflow, deployment or merge operation was performed during this work.

## Independent review and private evidence preservation

The two source commits were independently reviewed as exact commits, including their five-path scope and unchanged application files. The final private report/archive were independently verified: 129 unique ZIP entries, clean CRCs and all 127 indexed payload hashes matched. All 21 earlier reports/archives/review artifacts retained their hashes. Intermediate assertion/analyzer failures, initial and later native failures, capped/refused/unrun cells and observer variants are preserved with their original statuses. Public hashes identify private artifacts; they do not provide outside reviewers direct access to those artifacts.

- Private consolidated report SHA-256: `6e512582d0159dd72efced4e14f15cb1a0d835c30b8e5a3b01422a55c54cafe6`
- Private archive SHA-256: `c9db6c007e72cebdc86ea4a231df109776c77805a120a3fcbc054bbfeaec7655`
- Combined exact-commit review SHA-256: `9c06b14ebaa964985e894e1e09ad75c64893628d59c5ade928b521d6a55b1f02`
- Inventory exact-commit review SHA-256: `a07ce535bf07d1d2f0b020fc01dab61da04ebab96d9fc7b8d8999bf3836aeaff`
- Final report/archive review SHA-256: `e93c23c91a440312519e79aefde7b1085f02a8df7aaa3a3875c40287cae8407a`

No operational report, raw observation, machine path, process identity, historical input, browser profile or credential is published with this handoff. Original private reports still describe their creation-time local/unpushed state; publication is recorded separately without rewriting them.

## Reproduction and remaining acceptance gates

Read the guards and provide fresh output paths before executing native commands. The focused commands were:

```powershell
pwsh -NoProfile -File tests/Invoke-HostedSmokeDiagnosticsRegression.ps1
node tests/Assert-DashboardHostedSmokeProbe.js
node tests/Measure-DashboardWorkerTransfer.js --ownership
node tests/Assert-DashboardTelemetry.js
pwsh -NoProfile -File tests/Invoke-HostedDashboardRuntimeSmoke.ps1 -DashboardPath <retained-synthetic-HTML> -DiagnosticsPath <fresh-directory>
```

These commands require the same bounded supervision; native execution is not authorized merely by reading this handoff. The instrumented semantic copies, raw-field oracle and exact private command receipts remain local. Review can inspect the committed bespoke regressions and source diff without requesting raw data publication.

**#67/#69/#70/#92 remain open; PR #93 stays separate.** The monolithic preflight remains time-capped (earlier 900.438s and later 900.375s attempts), not passed, and was not rerun for these focused changes. Component passes do not substitute for it. Representative larger worker/cache-ineligible envelopes, native 120k and historical 50k-device/1.5M-observation/live-platform gates remain unqualified. Keep fresh import separate from completed-store replay, renderer heap from process-family memory, and full-field evidence from counts.

Preserve the previous 120k fresh-import caps, raw HTML comparison failure with its separate generatedOnUtc/exact-key-order review, retained interrupted profile, refused-admission attempts, and +6.61%/+6.69% versus later +3.51% replay series. Hosted CI `39735467316` passed original `f341fdd2` after its dated receipt; it remains separate from earlier capped Windows attempts and is not exact-head CI proof.

The next unresolved local question is the variable subprocess startup/compilation/completion budget under the existing five-second guard. Do not repeat unchanged retries, lower limits, refresh baselines, or infer a performance resolution from the diagnostic pass. Any further work should start from the final owning head, check overlapping changes/headroom and adopt a bounded scope. No merge or live-Azure work is authorized by this publication.
