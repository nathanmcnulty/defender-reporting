# Defender cleanup checkpoint review

Source review completed on 24 October 2026 at approximately 07:10 UTC. Target: [9c240298b2feb9c2d5698fcd179296b37d30d78c](https://github.com/nathanmcnulty/defender-reporting/commit/9c240298b2feb9c2d5698fcd179296b37d30d78c).

## Decision

**Accept the cleanup and singleton source-fix milestone. The previous cleanup-accounting P1 is resolved; no new blocking source finding was identified in the six-file change.** This is not approval to merge, close #67/#69/#70, accept historical-scale performance, or call the full preflight passed.

The published [finishing receipt](https://github.com/nathanmcnulty/defender-reporting/blob/9c240298b2feb9c2d5698fcd179296b37d30d78c/docs/handoffs/2026-10-24-cleanup-finish/README.md) accurately distinguishes bounded passes, failures and unrun work. Its native and operational observations remain owner-reported: private receipts, historical inputs and Windows execution were not independently accessed in this review. Their hashes identify claimed artifacts, not independently establish their contents.

## Exact scope and provenance

The owning branch was independently verified at the target. It is two commits ahead of the previously reviewed 5fdd5de9a2b0a048dea1235313472d4e5041c7b2:

1. dd1b4fba87d18cf4688784f864f7b1a6626138d9: singleton serialization, normalized payload cache v8 and regressions.
2. 9c240298b2feb9c2d5698fcd179296b37d30d78c: cleanup accounting, integrated regressions and sanitized results.

The [comparison](https://github.com/nathanmcnulty/defender-reporting/compare/5fdd5de9a2b0a048dea1235313472d4e5041c7b2...9c240298b2feb9c2d5698fcd179296b37d30d78c) contains exactly six files, including the new handoff README, not six source files plus an additional README:

| File | Git blob |
|---|---|
| azure/Invoke-DashboardPipeline.ps1 | 2efb5cbdf5496ad179dcde7b2b0724846821e51b |
| src/powershell/Shared/Dashboard/DashboardGeneration.ps1 | 88d6a38f15c7a6a3eab55fc78b7e5f68e4ba7065 |
| tests/Run-SharedHelperRegression.ps1 | f80bed96c38fe2b5229d68e64e1f2838bd7cc5cc |
| tests/Measure-DashboardWorkerTransfer.js | 818f87d7be51be7b984e445da70089544c31c182 |
| tests/README.md | 121d408168ebef12565abc2e9868ae73b0dcfad5 |
| docs/handoffs/2026-10-24-cleanup-finish/README.md | 1e91c632719aa8c63b6798721a157bda499d5d77 |

All six fetched files matched their Git blobs. Thirty-four unchanged supporting files were checked against the exact-head tree before reuse. All forty remained byte-identical after checks. The five working SHA-256 values in the published receipt reproduce exactly after LF-to-CRLF conversion, consistent with its explicit distinction between Windows working bytes and Git blobs. No raw operational records, private paths, credentials or tenant data were found in this delta. This statement concerns these changes, not an audit of all historical repository content.

## Severity-ranked source review

### Resolved P1: surviving descendants no longer produce a false cleanup pass

[Inventory-only accounting](https://github.com/nathanmcnulty/defender-reporting/blob/9c240298b2feb9c2d5698fcd179296b37d30d78c/tests/Measure-DashboardWorkerTransfer.js#L269-L320) retains a previously selected same-identity child even when its root has vanished or been replaced. Retained children also seed descendant accounting.

[Termination](https://github.com/nathanmcnulty/defender-reporting/blob/9c240298b2feb9c2d5698fcd179296b37d30d78c/tests/Measure-DashboardWorkerTransfer.js#L323-L378) returns all selected identities, including a child discovered only at termination. These are validated and merged into retained state before final inventory. Unknown identities fail closed. A failed or partially completed termination permanently marks this owner instance's accounting incomplete, preventing a later empty inventory from authorizing profile removal.

Kill authorization remains conservative: accounting is enabled only for inventory. Fresh process/root identity checks, skipped-unverified counters and process start checks remain in the termination path. The change does not authorize killing an unverifiable child or an unrelated replacement root.

All seven [integrated modes](https://github.com/nathanmcnulty/defender-reporting/blob/9c240298b2feb9c2d5698fcd179296b37d30d78c/tests/Measure-DashboardWorkerTransfer.js#L995-L1075) passed in a review-only Linux adaptation:

| Mode | Required outcome observed |
|---|---|
| Newly discovered orphan | Survivor counted; profile retained |
| Known child with reused root PID | Survivor counted; profile retained |
| Child actually disappeared | Zero owned; profile removed |
| Child's own PID reused | Unrelated replacement excluded; profile removed |
| Unknown final child identity | Inventory fails; profile retained |
| Orphan's new descendant | Both survivors counted; profile retained |
| Failure after partial termination | Accounting incomplete; profile retained |

Every mode asserted that only the original root was killed, no unverified child handle was opened for termination, and the synthetic neighbor survived. The exact checked-in test was executed with real JS cleanup and generated PowerShell selection/termination logic, but process APIs and Windows root matching were mocked. Twenty PowerShell invocations completed. Replacing only the accounting function with the previous exact source makes the new orphan regression fail as expected. **This is synthetic integrated confirmation, not a Windows/native-process claim.**

### Accepted source repair: singleton arrays and cache invalidation

The [getter's unary commas](https://github.com/nathanmcnulty/defender-reporting/blob/9c240298b2feb9c2d5698fcd179296b37d30d78c/src/powershell/Shared/Dashboard/DashboardGeneration.ps1#L733-L758) prevent PowerShell pipeline enumeration from collapsing empty or singleton array properties. The [affected-software assignment](https://github.com/nathanmcnulty/defender-reporting/blob/9c240298b2feb9c2d5698fcd179296b37d30d78c/src/powershell/Shared/Dashboard/DashboardGeneration.ps1#L2450-L2484) preserves the filtered array rather than emitting its elements through an if-expression.

Focused execution confirmed dictionary and object getters preserve [], [0] and [0,1], without changing scalar/null/missing behavior; generic lists retain identity/count. The actual device writer emits t:[0]. Affected-software zero/single/multiple/out-of-range controls behave as expected. In-memory rollback mutations reproduce the prior collapsed values. All three changed functions are text-identical in the generated Azure script, and both scripts parse.

The [v8 version feeds the payload fingerprint](https://github.com/nathanmcnulty/defender-reporting/blob/9c240298b2feb9c2d5698fcd179296b37d30d78c/src/powershell/Shared/Dashboard/DashboardGeneration.ps1#L5440-L5479), and [cache lookup uses fingerprint-derived paths and validates the manifest fingerprint](https://github.com/nathanmcnulty/defender-reporting/blob/9c240298b2feb9c2d5698fcd179296b37d30d78c/src/powershell/Shared/Dashboard/DashboardGeneration.ps1#L5924-L5942). Direct hashing with identical file inputs confirmed v7/v8 fingerprints differ. Ordinary old v7 caches therefore cannot be accepted as v8. This is a correctness repair, not evidence of improved performance.

The [new payload regression](https://github.com/nathanmcnulty/defender-reporting/blob/9c240298b2feb9c2d5698fcd179296b37d30d78c/tests/Run-SharedHelperRegression.ps1#L4009-L4036) checks serialized singleton contents as well as types. The cache/source-preservation regression seeds an arbitrary stale fingerprint, not an actual valid v7 cache. Its scope is stale-cache replacement; source inspection and direct versioned hashing establish the v7 rejection path. This coverage distinction is not a blocking finding.

## Evidence matrix

| Evidence | Review status |
|---|---|
| Exact commit lineage, six-file scope, forty local blob identities | Independently verified |
| Harness Node syntax and Linux --mock branches | Independently passed |
| Seven integrated cleanup cases plus old-source negative control | Independently passed, synthetic Linux adaptation |
| Dashboard telemetry, one-row worker semantics, compressed-cache materialization | Independently passed; injected worker fallback is expected |
| Focused singleton/writer/filter/version probes and generated-function parity | Independently passed on existing PowerShell 7.6.6 |
| Full shared-helper fixture suite, full preflight, release build and WhatIf | Not rerun by this review |
| Windows mock suite, release/WhatIf/browser build, native two-row cold/reload | Published owner-reported passes, not independently rerun |
| Exact-head Actions/check runs/statuses | None; combined status is pending with no statuses |
| Prior f341fdd2 hosted CI | Separate prior-revision evidence, not exact-head CI |

Review execution used existing Node 24.19.0 and Linux PowerShell 7.6.6. During source review, no browser, VM, live Azure, authentication, dependency installation, resource increase, repository source edit, public write or merge occurred. Publication of this sanitized documentation was authorized separately afterward. One standalone runtime-version query initially failed because its default PowerShell cache location was read-only; using an owned writable temporary cache resolved that environment-only probe. It did not affect the integrated tests, which already used owned cache directories.

## Failures and limits that remain open

These are retained from the published receipt and must not be promoted to passes:

- **Monolithic preflight: TIME-CAPPED at 900.438 seconds during telemetry.** Reported bounded component partitions passed, but they used separate processes and tighter Node heap settings. They do not establish same-session state continuity or a passing single-command gate.
- **Standalone dump-DOM hosted smoke: FAILED with readiness-timeout.** The canary and Playwright two-row control passed. Scheduling/virtual-time behavior is a hypothesis, not a proven cause, and unchanged source alone does not exonerate the application.
- **20k native baseline: stopped at the unchanged 3-GiB physical free-memory floor.** No completed comparison or final browser cleanup receipt exists for that cell. Outer cleanup reportedly removed all owned processes, but its profile was retained. Do not count the interruption as final-harness cleanup acceptance.
- **Final-harness 20k full-field rerun, comparable 20k/120k timing series and larger native lanes: NOT RUN.** Earlier field evidence used an older cleanup harness and cannot validate the repair's cleanup.
- **Two-row native control:** one cold/reload pair proves only the exercised lifecycle/readiness/cache behavior. Zero identity skips and zero unrelated Edge identities mean incomplete-identity faults and native neighbor preservation were not exercised there. Integrated mocks cover those branches, not native occurrence.
- **Historical-scale/live qualification remains open.** The 120k fresh imports previously hit their 180-second limit. #67's 50k-device/1.5M-observation and Automation envelope, #69's historical packaging/LOH and fair comparable performance attribution, and #70's representative worker/cache-ineligible scale are unfinished.
- Preserve the failed raw HTML comparison on generatedOnUtc, the separately justified field-excluding artifact review, the +6.61%/+6.69% and later +3.51% replay series, and diagnostic traces. Localization of diagnostic overhead is not proof of the cause of the historical delta or a performance fix.

The branch's current workflow only triggers push validation on main or pull-request events. Its lack of exact-head CI is not itself a test failure, but no prior CI result can fill this gap. PR #94 remains an unchanged open draft at f341fdd2; PR #93 remains an unchanged open draft at e18bb9bd. Issues #67/#69/#70/#92 remain open. Retain the bespoke tests; do not convert to Pester.

## One consolidated next decision

**Close this bounded cleanup/source-review milestone now. Do not send another cleanup-fix relay.** The repair is accepted within the evidence above; broader qualification is a separate unfinished milestone, not a reason to pretend the repair failed.

If continuing qualification, adopt one owner session that first diagnoses the monolithic-preflight stall and dump-DOM readiness failure using the retained logs and controlled same-source comparisons. Preserve every unsuccessful attempt; change production behavior only if a reproducible defect is isolated. Do not increase timeouts, lower memory floors, refresh a baseline, or optimize lookup serialization to make a failed measurement disappear.

Before resuming scale, confirm that an already authorized Windows environment has adequate available headroom under the existing limits. The 20k floor breach is a real stop condition, not a request to repeat unchanged. Complete feasible full-field cold/reload, cache-ineligible worker, fresh-import and identical-input Hosted/Dual comparisons only after their prerequisites are met. Reuse exact-source valid evidence and keep fresh import separate from replay.

Return one exact revision with passed/failed/capped/not-run results and a bundled decision on remaining gates. No further user input is needed merely to accept this source milestone. Historical completion needs an available qualifying environment or an explicitly approved resource change; live Automation/Function qualification needs separately scoped target/access/action approval. Any PR integration, workflow dispatch or merge needs its own authorization. PR #93/#92 runtime/live-Azure work remains separate. Nothing in this review grants those permissions.

## Reproduction and evidence boundaries

The integrated cleanup cases are checked into the reviewed source's tests/Measure-DashboardWorkerTransfer.js and run as part of its Windows --mock path. The source links above pin their exact implementation. The review-only adaptation and focused PowerShell probes remain local, together with their logs and blob manifest; they are not packaged in this documentation-only update. The focused singleton stdout was faithfully transcribed from the successful tool result rather than separately rerun. Native Windows acceptance and the complete fixture-based helper suite were not rerun by this review.

Read [the proposed consolidated qualification goal](next-goal.md) before further work. It starts from the owning checkpoint 9c240298b2feb9c2d5698fcd179296b37d30d78c, never from the older source on this documentation branch. Publication of the review does not adopt or execute that goal.
