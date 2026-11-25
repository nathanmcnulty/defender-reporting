# Bounded qualification checkpoint — 2026-10-24

## Source and authority

This session adopted [the goal at d988826](https://github.com/nathanmcnulty/defender-reporting/blob/d988826c2bd154c1879e374260f7f5609300c952/docs/handoffs/2026-10-24-cleanup-checkpoint-review/next-goal.md) and qualified the owning checkpoint `9c240298b2feb9c2d5698fcd179296b37d30d78c` on `fix/issue-70-reviewed-cleanup-20261023`. The documentation branch's older code was never used as the candidate or merged. The accepted cleanup-accounting/singleton milestone remains accepted. No application, measurement-harness, test or generated source was changed; this checkpoint adds sanitized documentation only. No reproduced defect justified a production repair.

Runtime: Windows `Microsoft Windows 10.0.28000`, PowerShell `7.6.6`, `.NET 10.0.12`, Node `v26.7.0`, installed Edge `155.0.4283.62`. No dependency was installed or downloaded.

## Monolithic preflight diagnosis

The retained run stopped at its **900.438-second time cap**, with family working set 1,168,084,992 bytes, private memory 879,263,744 bytes, minimum physical free memory 3,373,256,704 bytes and verified empty-job cleanup. It was not stopped by a memory guard. All 134 shared-helper tests and subsequent PowerShell/publication stages completed; output reached dashboard telemetry, then remained silent for 52.439 seconds before the cap. That silence alone does not prove a deadlock or ordinary progress.

The 134 shared-test body durations sum to 425.624 seconds versus 360.716 seconds in the earlier 808.328-second passing run. The 64.908-second difference is historical context: the earlier run used a different source/wrapper/floor, and its completed outcome is not directly comparable to a censored run. These are neither a fair performance baseline nor proof of a source regression.

Two new sequential fresh-process runs use the **same exact 9c240298 source and same 13 assertion files**, with timestamped per-file starts/ends. The only Node argument difference is the prior partition's 256-MiB heap option. Each used the reviewed supervisor with unchanged 180-second/3-GiB family cap/3-GiB physical-free floor; both passed all assertions and verified empty-job cleanup.

| Node invocation | Stage elapsed s | Telemetry s | Peak family WS bytes | Minimum free bytes |
|---|---:|---:|---:|---:|
| plain | 112.656 | 106.030 | 363855872 | 3639820288 |
| 256 | 114.187 | 107.973 | 386985984 | 3881844736 |

Plain Node telemetry passed in 106.030 seconds, longer than the retained run's final 52.439-second silent interval. This and the earlier shared-test duration growth support cumulative elapsed-budget exhaustion more strongly than a deadlock. They do not establish the exact state of the original final interval, same-session continuity, or a passing monolithic gate. One run per invocation is diagnostic evidence, not a performance baseline or proof that the heap setting caused a timing difference. No timeout/cap was raised and no code was optimized to hide the cap. A further monolithic run was not admitted during the component comparison. Independent review recommends against an unchanged opaque rerun for this finite goal: it would not resolve the original silent interval. A future required single-command gate needs one timestamp-observed same-source attempt, unchanged 900-second/3-GiB/3-GiB limits and adequate admission, without concurrent qualification work.

## Standalone dump-DOM diagnosis

The retained canary passed synchronous JS/DOM/dump capture. The dashboard process exited zero with nontruncated DOM and an injected `readiness-timeout` marker: DOMContentLoaded and timers ran, but dashboard readiness was not observed. `run.json.failureClass=runtime` classifies the PowerShell throw; it does **not** prove a JavaScript runtime exception.

The hosted HTML SHA-256 is `c941b04a92ced469b3e76ab2227bca97f1bcaf0f0ebeb8108cdeba3220975379`. The earlier Playwright two-row control used that HTML but served manifest-assembled runtime source. Its runtime is not byte-identical to the generated runtime: excluding only `dashboard/90-pdf-export.js` makes the assembled runtime equal to the generated runtime after newline normalization. Initial readiness logic matches, but matching HTML alone does not establish full runtime equivalence or exonerate the application.

Headroom later recovered enough to admit three small native **scratch diagnostic** cells. Each pinned the same 9c source, generated HTML and complete asset-tree hashes before/after, used fresh isolated profiles, retained original virtual/readiness/termination budgets and ran under unchanged 240-second/2-GiB family cap/3-GiB physical-free floor. Scratch observers delegated requestAnimationFrame/cancelAnimationFrame without changing callback scheduling; they recorded only allowlisted numeric counters and boolean state. The observer's model assertions, including the existing 14 probe cases, passed. No checked-in source was modified.

| Scratch cell | Outcome | Wall s | Peak family WS bytes | Minimum free bytes | Observed frame/render boundary |
|---|---|---:|---:|---:|---|
| Original flags + observer | Readiness timeout | 11.610 | 865177600 | 4300734464 | 1 requested / 0 fired / 1 pending; 0 renders |
| Add only compositor-stages flag | Readiness timeout | 9.609 | 1040039936 | 4312383488 | 1 requested / 0 fired / 1 pending; 0 renders |
| Remove only explicit disable-GPU flag | PASS | 10.641 | 835080192 | 4134375424 | 5 requested / 4 fired / 1 pending; 5 renders, ready |

Both failing cells completed data-load, denormalization and filter phases, observed DOMContentLoaded and probe start, and recorded no error event, unhandled rejection or error-status marker. Readiness remained false. This localizes the observed boundary to an unserved initial animation frame in these dump-DOM invocations. The compositor flag did not fix it. The successful cell completed the original scratch-copied harness readiness and interactions. Phase durations are virtual-time diagnostics, not performance measurements.

A finite default-GPU → disabled-GPU → default-GPU confirmation was planned. After the first default-GPU pass, the disabled cell was **not admitted**: minimum free memory 4,562,862,080 bytes was below the fixed 4,563,402,752-byte planning threshold. The sequence stopped; the disabled confirmation and subsequent default recovery were both not run. Later samples fluctuated just above that threshold; no repeated admission loop was pursued. The partial result supports a candidate launch-flag association, not demonstrated causality, repeatability or a justified source repair. No production or harness flag was changed. The default receipt's sanitized flags array contains a null placeholder; the explicit `qualificationDisableGpuFlag=false`, pinned script hash and command construction establish the flag state.

All three native cells confirmed process cleanup, profile removal, temporary-site removal and empty outer jobs, with no cleanup failures. Original readiness failures remain failures; scratch success does not make the checked-in standalone gate pass. Raw DOM was discarded as designed. The accepted cleanup milestone is unchanged.

## Headroom and lane admission

Five samples taken before the comparison had minimum available physical memory **3990941696 bytes (3.717 GiB)**; five after both child jobs exited had **4348948480 bytes (4.050 GiB)**. Total physical RAM was 17109004288 bytes. No process was stopped to manufacture headroom.

Admission planning adds expected workload plus 0.25-GiB external-variation allowance above the unchanged 3-GiB floor: 3.6 GiB for the previously sampled ~0.35-GiB JS stage; 4.25 GiB for the small native smoke; 4.5 GiB for the previously sampled ~1.09-GiB monolithic job; and 5.25 GiB for a native scale job up to its 2-GiB cap. These conservative admission checks do not change runtime caps/floors. Those initial before/after measurements admitted only the JS comparison. A subsequent five-sample minimum of 4,580,929,536 bytes (4.266 GiB) admitted the small diagnostics above; individual cells rechecked admission. Final samples had minimum 4,565,606,400 bytes (4.252 GiB): marginally above small-smoke admission, below monolithic and native-scale admission. They do not establish sustained scale headroom. The blocked 20k cell was not repeated unchanged.

| Lane | Result in this session |
|---|---|
| Exact-source plain Node / 256-MiB JS stages | PASS / PASS, all 13 files; hashes unchanged |
| Monolithic preflight | NOT RUN again; prior 900-second cap retained |
| Standalone dump-DOM | Checked-in gate remains unresolved; scratch original/compositor timeout, one default-GPU PASS; two confirmation cells NOT RUN |
| Native full-field cold/reload, 20k/120k timing, cache-ineligible worker | NOT RUN; headroom blocked |
| Fresh import / completed-store replay / Hosted-Dual scale | No new comparisons; retained valid exact-source evidence remains separate |
| Live Automation/Function/Azure, PR #93/#92 integration, CI | NOT RUN; outside this authority |

The smaller native control, field proofs, fresh-import and identical-input packaging observations from [the prior owning receipt](../2026-10-24-cleanup-finish/README.md) retain their original source and scope. They were not rerun or promoted here. Preserve the failed raw HTML comparison, its separate generatedOnUtc-only artifact review, the retained interrupted profile, all 120k fresh-import caps, and the +6.61%/+6.69% versus later +3.51% replay series. No baseline was refreshed and no historical performance issue is declared solved.

## Consolidated blockers and issue dispositions

Remaining gates need at least **5.25 GiB sustained free physical RAM** in the existing authorized VM for native scale lanes (about 5.5 GiB preferred), 4.25 GiB for the unfinished small flag-confirmation cells, and 4.5 GiB for a future observed monolithic attempt. Admission is a prerequisite, not authorization to enlarge resources, stop unrelated processes or lower a floor. Before a flag repair, complete the two missing controlled cells and independently review/retest any minimal justified harness change. Before claiming a full preflight pass, complete the single-command gate under the existing 900-second cap. The present finite session ends with these bundled blockers, rather than retrying unchanged blocked work.

**#67, #69 and #70 remain open.** Historical 50k-device/1.5M-observation import, Automation below-400-MB, representative packaging/LOH and worker/cache-ineligible envelopes are not qualified. The standalone smoke and full monolithic gate remain unresolved. PR #93 and issue #92 remain separate; retain bespoke tests. Live Azure needs separate target/access/action authorization. Exact-head CI is not claimed; no workflow/CI/PR update, sign-in, Azure/Graph/XDR operation, dependency installation, resource expansion or merge occurred.

## Reproduction and identities

Inner commands require bounded owned-process supervision. The new comparison used `pwsh -NoProfile` with a fresh script for each mode, enumerating the same sorted assertion inventory and checking each exit code:

```powershell
Get-ChildItem tests/Assert-Dashboard*.js | Sort-Object Name | ForEach-Object {
    & node $_.FullName                         # plain run
    # paired run substitutes: node --max-old-space-size=256 $_.FullName
    if ($LASTEXITCODE -ne 0) { throw 'Assertion failed' }
}
```

The controlled native commands were scratch copies of `Invoke-HostedDashboardRuntimeSmoke.ps1 -DashboardPath <same-generated-HTML> -DiagnosticsPath <fresh-directory>`, executed with `pwsh -NoProfile` under the 240-second/2-GiB/3-GiB supervisor. Baseline retained every original flag; compositor added only `--run-all-compositor-stages-before-draw`; default-GPU removed only `--disable-gpu`. Original virtual-time and probe deadlines were unchanged. Scratch sources, exact commands, admission samples, full asset hashes, observer model and all failed/pass/unrun records remain in the private evidence package. No raw operational paths are published.

Exact source: `9c240298b2feb9c2d5698fcd179296b37d30d78c`. Unchanged harness Windows SHA-256: `427ee2d7a2b1712bd0ef9af8effebfcc0a1a1cfed1a847ab906b9e5ebc9dad88`. Reviewed supervisor SHA-256: `bd7938d5a6b5f5809e9d9765822158f44568d29c68f54ac1f417c216afe3f87e`. Comparison receipt SHA-256: `c6cc68d74167eea85dbfa5c7b054b281997cd844a85fa7ec45523b4d49769a72`. Retained preflight-analysis receipt: `49690471c944f36d1bc6e5768799772cf60208f7a91fefce3afdd453a9cb094b`. Smoke-analysis receipt: `4d253fa9db4a4c57fa3eb0268918afbab98db29986e8065f2e599938754fdcaa`. Phase-A audit: `23842c7abac7a6f6d861c209d46a8433d18a3113fe85b4c4768c6ac9d8528803`. Phase-B consolidated audit: `1617134201832bf856447f8b72cdf32a303210d1eeb97493c7586e76dd3f2489`. Exact commands, all 13 file hashes, memory samples, private paths/process records and old/new receipts remain in the local evidence package, not this publication. The final pushed documentation revision is returned after independent review and overlap checks. This documentation-only result preserves the earlier frozen phase-A report/archive and leaves application/harness source at 9c240298. A separately indexed consolidated report/archive must be generated and verified before publication.
