# Bounded qualification checkpoint review

Read-only review completed 24 October 2026 at approximately 16:35 UTC. Target: [1cb958bf513f034a5aabbae293ff43581490bbb5](https://github.com/nathanmcnulty/defender-reporting/commit/1cb958bf513f034a5aabbae293ff43581490bbb5).

## Acceptance

Accept this as a bounded diagnostic/documentation checkpoint, not completed runtime qualification. The earlier cleanup-accounting and singleton source-fix milestone remains accepted. No new blocking source finding was identified.

Independent Git checks established the owning branch at 1cb958bf. Since source checkpoint 9c240298b2feb9c2d5698fcd179296b37d30d78c, two commits add/update only docs/handoffs/2026-10-24-bounded-qualification/README.md. All 173 pre-existing file entries retain identical bytes, modes and types. The tree contains exactly 13 Assert-Dashboard*.js files. The final README Git blob is 855e4b0a0f3ea0ce5d910b053bf92a62bb7da644, SHA-256 ec93c0da39b77a7f52af60d67be242159595fbb17e698cf7952e401aa2446c06.

The public [receipt](https://github.com/nathanmcnulty/defender-reporting/blob/1cb958bf513f034a5aabbae293ff43581490bbb5/docs/handoffs/2026-10-24-bounded-qualification/README.md) and its linked prior goal/owning receipt were inspected. It links no public scratch scripts, raw observations or consolidated audit archive. Hashes identify claimed private artifacts; they do not independently verify those artifacts or native cleanup. No new tests, native execution, installations, resource changes, process stops, public writes, merges or Azure actions were performed during the read-only review. This sanitized documentation was authorized for publication separately afterward.

## Findings and limits

1. **No source acceptance blocker.** The underlying application, generated code, tests and measurement harness remain identical to the accepted 9c240298 source. This does not turn outstanding gates into passes.
2. **Native launch-flag lead, not a fix.** The receipt reports two scratch timeouts with one requested animation frame, zero callbacks and zero renders; removing only explicit --disable-gpu passed once. The compositor flag did not fix those observed cells. This is a useful association, not demonstrated repeatability, causality, a hardware-GPU diagnosis or grounds for changing application scheduling. The two confirmation cells were not run.
3. **Static source supports the proposed boundary, not the native outcome.** The [checked-in smoke flags](https://github.com/nathanmcnulty/defender-reporting/blob/1cb958bf513f034a5aabbae293ff43581490bbb5/tests/Invoke-HostedDashboardRuntimeSmoke.ps1#L555-L568) still include --disable-gpu, virtual time and dump-DOM. [Initial filtering](https://github.com/nathanmcnulty/defender-reporting/blob/1cb958bf513f034a5aabbae293ff43581490bbb5/templates/dashboard/30-filters-and-stats.js#L515-L517) schedules rendering through requestAnimationFrame. This makes the reported no-callback boundary meaningful, but scratch observer behavior, exact argument construction and before/after asset identities are not independently inspectable here. In particular, the null sanitized flag entry is not itself a complete argument receipt.
4. **Monolithic preflight remains capped, not passed.** Reported new plain/256-MiB Node runs both passed all 13 files in fresh processes. Their telemetry durations exceed the earlier final silent interval, so ordinary unfinished work is a plausible explanation without requiring a deadlock. The original interval's actual state remains unproved. The old 900.438-second stop was a time cap, not a memory-guard stop. Neither component passes nor the older differently configured 808.328-second run prove current monolithic continuity or performance equivalence.
5. **Headroom is an admission prerequisite, not new authority or a test failure.** The blocked confirmation was 540,672 bytes below the conservative 4.25-GiB planning threshold, still above the runtime 3-GiB floor. Final samples were only about 2.102 MiB above admission, not evidence of sustained headroom. The published 4.25-GiB small-cell, 4.5-GiB monolithic and 5.25-GiB sustained scale estimates (5.5 preferred) are coherent planning margins, not safety guarantees or permission to enlarge resources, stop unrelated processes, lower floors or poll indefinitely.
6. **Evidence-packaging caveat, not a source defect.** The README's final sentence still says a separately indexed consolidated report/archive must be generated and verified before publication. The public record does not establish whether that local artifact was completed. Have the existing owner verify/index its final local evidence in the same finishing session; do not request raw private data publication or another manual upload relay.

The receipt correctly narrows the earlier Playwright comparison: matching HTML does not mean identical runtime bytes. Its assembled/generated runtime difference and three scratch cleanup results remain owner-reported. All original failures, the retained interrupted profile, unrun full-field/scale cells, old capped fresh imports, raw HTML comparison failure and timing series retain their original status.

Current read-only status checks: #67/#69/#70/#92 remain open; PR #93 remains draft at e18bb9bdcc01e456daa5e5519f2655b3f538f7d1; PR #94 remains draft at f341fdd2cf634451a909b69da5ee636dba02fb9f. No workflow run was found for the documentation head. No merge or exact-head CI acceptance is claimed.

## One consolidated next scope

Only if Nathan wants to resume the unfinished local qualification, adopt one bounded owner session from current owning head 1cb958bf, verifying that the runtime source still matches 9c240298 and checking overlapping changes. Do not use the documentation branch's older runtime.

First establish a sufficiently stable execution window in the already authorized VM under the existing admission and runtime guards. Complete a coherent controlled flag-confirmation sequence with identical source, full asset tree, observations, timeouts and isolated profiles; if the gap between sessions breaks comparability, refresh the starting control rather than stitch unmatched cells together. Removing --disable-gpu remains a candidate, not a preselected fix. Only a reproduced discriminating result can justify a minimal harness change; independently review it and pass the actual checked-in standalone gate, not only an instrumented scratch copy.

In that same session, complete one timestamp-observed monolithic attempt under the unchanged 900-second cap when admitted, without concurrent qualification work. Then complete only feasible full-field cold/reload, representative worker/cache-ineligible and fair same-input scale comparisons. Keep fresh import separate from replay and reuse valid exact-source evidence. Do not repeat known capped or blocked cells unchanged, refresh baselines, optimize speculatively or relax limits.

Return once with the exact checkpoint, independent review, local evidence index and passed/failed/capped/not-run matrix, bundling remaining blockers. Preserve #67/#69/#70 historical/live gates and keep PR #93/#92 separate. A new execution session, any publication, CI/PR changes, new resources, authentication, Azure, deployment or merge are not authorized by this review.

## Genuine human decisions

No human action is needed to accept this diagnostic checkpoint. Resuming native qualification requires a decision to continue and an available execution window in the existing authorized environment with measured admission headroom; its current availability is unverified. Do not equate this with a request to buy RAM or stop unrelated work. If those prerequisites cannot be met within existing authority, pause and bundle the exact environmental choices once.

Live Automation/Function qualification remains a separate target/access/action authorization decision. No credential sharing or broader platform migration is needed for the current read-only acceptance.


The separately proposed [next goal](next-goal.md) requires Nathan's future explicit adoption. Publishing this review does not adopt or execute it.
