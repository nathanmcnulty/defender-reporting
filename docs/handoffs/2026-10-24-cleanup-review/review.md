# Defender Reporting cleanup review and finishing checkpoint

Reviewed 24 October 2026. Repository: [nathanmcnulty/defender-reporting](https://github.com/nathanmcnulty/defender-reporting).

## Decision

Request changes for one P1 cleanup-accounting defect in revision `5fdd5de9a2b0a048dea1235313472d4e5041c7b2`. A skipped owned child can survive while cleanup reports zero remaining processes and removes its profile. The defect was reproduced with the actual fetched ownership and cleanup code under controlled, mocked process APIs. This is not a native Windows reproduction or an exploit claim.

The prerequisite commit `63bf26ad27a274cd84aefc47f1f0779b4d397956` has no additional blocking finding from this review. Its runtime-fingerprint and two-row-control corrections are supported by the source and affected offline tests.

Do not use the latest cleanup result as a reliable acceptance gate until the accounting defect is fixed. The proposed goal below lets Nathan authorize that repair, remaining feasible validation, and one final sanitized source publication as a single owner session. Return one exact pushed checkpoint or one consolidated set of genuine blockers, not a separate request merely to push.

## Source and publication boundaries

Verified the remote branch `fix/issue-70-reviewed-cleanup-20261023` and this ancestry:

1. [PR #94 source baseline f341fdd2](https://github.com/nathanmcnulty/defender-reporting/commit/f341fdd2cf634451a909b69da5ee636dba02fb9f).
2. [Harness prerequisite 63bf26ad](https://github.com/nathanmcnulty/defender-reporting/commit/63bf26ad27a274cd84aefc47f1f0779b4d397956).
3. [Cleanup revision 5fdd5de9](https://github.com/nathanmcnulty/defender-reporting/commit/5fdd5de9a2b0a048dea1235313472d4e5041c7b2).

Each of the two new commits changes only `tests/Measure-DashboardWorkerTransfer.js` and `tests/README.md`. Forty downloaded source blobs, including the changed files at all three revisions and relevant runtime/test dependencies, were checked against their Git blob identities. The reviewed head harness blob is `4f84acfe1b2df36f4719c449233175746596aa9b`; its SHA-256 is `1a82b09fa1a902ab5859ec19711d676e9e7cab471dc81f268c442c79580e01c9`.

The technical review did not change application source, merge, dispatch workflows, install software, launch a browser, perform a new sign-in, or access Azure/private operational evidence. This authorized handoff publication adds only text files in its dedicated directory. Publication of the eventual implementation checkpoint remains conditional on Nathan adopting [the finishing goal](finish-goal.md); this packet is not an implementation or native acceptance result.

## Severity ranked finding

### P1 Retain unresolved owned descendants independently of root kill eligibility

**Location:** [new skip branches, lines 307–344](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/tests/Measure-DashboardWorkerTransfer.js#L307-L344), [identity retention, lines 230–305](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/tests/Measure-DashboardWorkerTransfer.js#L230-L305), and [final inventory/profile removal, lines 393–403](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/tests/Measure-DashboardWorkerTransfer.js#L393-L403).

The new `continue` branches correctly avoid obtaining a process handle or killing an item whose fresh identity is incomplete. However, success now depends on final inventory accounting for every unresolved selected process. That invariant does not hold.

**Reproduced sequence A: newly discovered orphan**

1. The last successful inventory records owned root 101.
2. Child 102 starts afterward, with a renderer command line that has no profile switch.
3. Termination's full snapshot discovers 102 through the parent closure.
4. The fresh filtered snapshot lacks 102's creation time. The new branch skips it.
5. Root 101 is then killed.
6. Termination returns only counters. It does not preserve its newly discovered child record in JavaScript `known`; only `inventory()` updates that state.
7. The final snapshot contains the still-live child, but no live matching root or retained child identity. Selection returns an empty set.
8. Cleanup reports `remainingOwned: 0`, `profileExists: false`, and `errors: []`. The temporary profile is actually deleted, although synthetic child 102 survives.

**Reproduced sequence B: known child and root PID reuse**

The child is already present in the last inventory. After its fresh identity is skipped and its root is killed, root PID 101 is reused by a different synthetic process. The final inventory rejects the old root provenance and drops the child's retained record, even though the child's own creation identity is unchanged. Again it reports zero and deletes the profile.

Root provenance rejection is conservative for deciding whom it is safe to kill. It is not proof that a previously selected child has exited. Simply saving newly discovered children would fix sequence A but leave sequence B.

**Parent control:** under both injected sequences, `63bf26ad` throws on the incomplete fresh identity before killing the root. Cleanup retains failure labels and the profile. Thus the new nonfatal skip behavior exposes an acceptance regression.

| Scenario | Parent 63bf26ad | Head 5fdd5de9 |
| --- | --- | --- |
| New child discovered only at termination | 2 remaining, profile retained, cleanup fails | 0 reported, profile removed, no errors; child 102 survives |
| Known child, root PID reused after termination | 2 remaining, profile retained, cleanup fails | 0 reported, profile removed, no errors; child 102 and unrelated replacement root survive |

The scope is a process leak, profile deletion despite an unresolved survivor, and a false successful cleanup receipt. No unverified native kill was observed or claimed.

**Why current tests miss it:** [ownership probes](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/tests/Measure-DashboardWorkerTransfer.js#L899-L956) inventory both identities before termination. [New skip cleanup tests](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/tests/Measure-DashboardWorkerTransfer.js#L1185-L1197) stub the desired final PID array rather than exercising selection across snapshots. Both can pass while integrated accounting is wrong.

**Required outcome:** preserve accountability for every selected unresolved process across termination and final inspection, while keeping kill authorization conservative. A missing/reused root must not convert a same-identity unresolved child into proof of zero survivors. Do not kill a replacement root, kill an unverified child, or weaken ownership rules. Add integrated negative controls for both sequences, plus controls where the child really disappears or its own PID is reused. Keep the profile when a tracked survivor exists or final identity is uncertain; allow success only after verified absence. A bounded safe redesign is acceptable; no particular implementation is mandated.

Update the README's final-inventory guarantee to match the repaired implementation. The current sentence that a skipped item cannot produce a cleanup pass is stronger than the code establishes.

## Other source review results

- **Prerequisite fingerprint correction is sound in the reviewed path.** The old harness constructed `cfp_<length>_<sha>`, while production uses the derived-schema prefix. The prerequisite captures the actual [runtime computation](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/templates/dashboard/05-indexeddb-cache.js#L94-L98), preserves invocation receiver/arguments and rejection, requires one key per navigation, and uses that key for IndexedDB inspection and cold/reload agreement. Missing/ambiguous keys fail rather than manufacturing a cache hit.
- **Two-row expectation is supported.** The committed January 1–2 fixture contains distinct CVEs/software versions and the harness explicitly applies that date range. The new exact two-row/impact/card checks reject zero, undercount, overcount, and the wrong range. They are a positive lifecycle/readiness control, not full report-field proof.
- **Skip receipts are appropriately narrow.** They contain numeric allowlisted counters. The new branches precede `Get-Process` and `Kill`. Missing identity fields encountered while proving recognized ownership still fail closed. Unexpected kill errors and prior cleanup failures remain failures in the reviewed code; the unresolved-survivor accounting gap above is separate.
- **No production performance change is present.** Worker timeout, resource caps, cache limits, and application runtime files are unchanged by these two commits.
- **README limitations are otherwise useful.** It distinguishes native controls, sampled memory/phase observations, renderer-only heap, cache eligibility, and large-data qualification. Its change from “uninstrumented” to “non-mock native” accurately acknowledges instrumentation.
- **Tests are connected to preflight.** The [telemetry regression invokes `mockProbes()`](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/tests/Assert-DashboardTelemetry.js#L514), and deterministic preflight selects `Assert-Dashboard*.js`. Linux skips the Windows-only ownership and inventory branches; a hosted Ubuntu pass cannot qualify those branches.

No additional blocking defect was identified in the two published deltas. That is not a claim that all pre-existing harness behavior or every repository subsystem was exhaustively verified.

## Independent validation and limits

Executed after source inspection, using existing Node 24.19.0 and existing Linux PowerShell 7.6.6. No dependency installation was needed.

| Check | Result | Scope |
| --- | --- | --- |
| Exact source/blob verification | Passed | Forty downloaded files, including changed files at head/parent/baseline |
| `node --check tests/Measure-DashboardWorkerTransfer.js` | Passed | JavaScript syntax |
| `Measure-DashboardWorkerTransfer.js --mock` | Passed | Linux/browser-free branches, not Windows CIM/argv |
| `Assert-DashboardTelemetry.js` | Passed | Includes the mock harness through the real preflight integration |
| `Assert-DashboardWorkerSemantics.js` | Passed | One synthetic row across Node worker transport/materialization/cache model |
| `Assert-DashboardCompressedCacheMaterialization.js` | Passed | Synthetic cache/fallback cases; injected worker failure is expected |
| Integrated orphan diagnostic, parent and head | Reproduced defect | Actual fetched selection/termination/cleanup, mocked process APIs and root matching |
| Full PowerShell preflight and release/package rebuild | Not rerun here | Prior hosted CI is separately verified below |
| Native Windows Edge/CIM/IndexedDB, real-library controls | Not run here | Existing owner must qualify final repaired source |
| Historical-scale or live Azure validation | Not run here | No scale-performance or platform acceptance claim |

The integrated diagnostic ran the generated PowerShell selection and termination logic and JavaScript cleanup, with `Get-CimInstance`, `Get-Process`, process methods, and Windows root matching replaced by deterministic synthetic behavior. It never enumerated or killed a real process. Temporary profile deletion was exercised only in reviewer-owned temporary directories. Native argument parsing and operating-system race frequency are outside this evidence.

Private local operational reports were not inspected or included. Native controls and performance observations from those reports are not independent evidence for this published review. Preserve original failed and successful measurements locally; do not infer performance causation from allocation location alone.

## Current PR and issue state

- [PR #94](https://github.com/nathanmcnulty/defender-reporting/pull/94) is open and draft at `f341fdd2cf634451a909b69da5ee636dba02fb9f`. [Run 39735467316](https://github.com/nathanmcnulty/defender-reporting/actions/runs/39735467316) completed successfully, including deterministic preflight and Azure package smoke.
- [PR #93](https://github.com/nathanmcnulty/defender-reporting/pull/93) is open and draft at `e18bb9bdcc01e456daa5e5519f2655b3f538f7d1`. [Run 38808563050](https://github.com/nathanmcnulty/defender-reporting/actions/runs/38808563050) likewise passed. It remains a separate PowerShell 7.6/.NET 10 runtime change.
- Neither new harness commit has an Actions run in the current exact-SHA query. Head also has no check runs or commit statuses. The [workflow](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/.github/workflows/validate-dashboard.yml) runs on PRs and qualifying pushes to main, not every feature-branch push. No workflow was started by this review. Older green CI must not be relabelled as exact-head CI.
- [#67](https://github.com/nathanmcnulty/defender-reporting/issues/67), [#69](https://github.com/nathanmcnulty/defender-reporting/issues/69), [#70](https://github.com/nathanmcnulty/defender-reporting/issues/70), and [#92](https://github.com/nathanmcnulty/defender-reporting/issues/92) remain open.
- Issue #92 explicitly preserves bespoke PowerShell/.NET tests and says not to introduce Pester. PR #93's old unchecked “Pester 6.2” description is not the current migration instruction. Repository-wide baseline cleanup and live runtime qualification cannot be declared complete from this harness review.

## One finishing goal

Use [finish-goal.md](finish-goal.md). It is a proposed complete owner-session instruction for Nathan to adopt, including one final sanitized source publication, not a sequence of small relays.

## What finished means

### Cleanup and source acceptance

Close the cleanup repair only when the integrated survivor controls fail safely, disappeared/reused-child controls remain conservative, all affected bespoke/offline tests pass, and a non-mock Windows cold/reload control on the final repaired source ends with Node exit zero, no cleanup errors, verified zero owned survivors, removed owned profile, closed server, unchanged fixture hashes, and preserved unrelated process identities. Recheck affected native behavior after any later fix.

The original local receipts can reduce redundant work only when the owner can establish exact source/artifact/runtime correspondence. They do not validate the new repair or erase previously failed runs.

### Feasible native and historical scale work

Use the [existing handoff](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/docs/codex-handoff-2026-10-22.md), [performance playbook](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/docs/performance-gate-playbook.md), and [dashboard review](https://github.com/nathanmcnulty/defender-reporting/blob/5fdd5de9a2b0a048dea1235313472d4e5041c7b2/docs/dashboard-performance-review.md) without turning each inner command into a user handoff.

- **#67:** discriminate fresh snapshot import from completed-store replay. Use identical source-pinned synthetic inputs and authoritative normalized counts; retain store/content/row parity, phase timings, and at least three alternating comparable baseline/candidate runs where the existing budget allows. A local result does not establish the Automation below-400-MB acceptance target.
- **#69:** compare Hosted and Dual packaging from one identical normalized payload/manifest and templates, in independent roots and alternating order. Inspect working set/private memory/GC/allocation and stage time with semantic/artifact parity. Do not revive the obsolete whole-file base64 hypothesis or rewrite a pipeline based only on allocation location. The controlled Dual wall-time criterion remains within 10%; Automation memory qualification still needs the applicable authorized environment.
- **#70:** exercise real libraries and native Edge, full-field/report semantics on cold and actual eligible-cache reloads, and large first-load/reload measurement on the historical shape where safe. Preserve the 3-GiB free-memory floor, 2-GiB owned Edge-family cap, 120-second readiness bound, and production 500,000-row cache cutoff. Large reloads above that cutoff are expanded-cache-ineligible, not cache-hit failures to “fix.” Measure fallback, worker phases, total readiness/load behavior, and renderer versus family memory separately; full report parity cannot be inferred from readiness digests.
- **Across lanes:** current source, runtime, generated artifacts, payload identity, device/CVE/row counts, commands, limits, and machine conditions must accompany evidence. Investigate above-10% comparable time/peak-memory regressions and the playbook's separate above-5% hot-phase threshold. Preserve failures and do not refresh accepted baselines from one-off or unaccepted measurements.

The adopted milestone may finish with one reviewed, published sanitized source checkpoint and a clear “local/native qualified; Azure gate remains open” disposition. Publication is limited to the public nathanmcnulty/defender-reporting repository and existing fix/issue-70-reviewed-cleanup-20261023 branch, with overlap checks and a non-forced update. Keep raw private operational reports, tenant data, and historical inputs local. Include the exact pushed revision in the final handoff; do not stop solely to request another push authorization within this adopted scope. It must not falsely close #67/#69/#70 where their required scale or platform acceptance is unmet. Repository playbook Azure acceptance remains a separately authorized merge gate, not an instruction to deploy now.

### Real blockers that may still need a decision

No additional user input is needed to understand the reproduced defect or prepare the bounded repair. The existing owner should first use the tools, synthetic datasets, and limits already available. Request only a concrete missing prerequisite or authority, bundled after completing independent work:

- A suitable connected Windows environment or existing real runtime libraries/Playwright, only if missing or inaccessible.
- The specific retained synthetic fixture/manifest or a permitted deterministic regeneration path, if the historical comparison cannot otherwise be reproduced. No raw private evidence needs to be published or transferred to this reviewer.
- A specific resource or time-budget decision if the current safe limits prevent a necessary scale lane. Do not keep retrying unchanged after a known bound or silently widen it.
- Separately scoped Azure tenant/subscription/resources, rollback/cleanup plan, and explicit authorization if the user wants the live platform gates completed. Until then, leave those gates open without blocking unrelated local work.
- A genuine repository access or overlap conflict that prevents the adopted bounded publication. Reconcile the actual remote state and preserve others’ work; do not force-push, substitute another repository, or treat an uncertain push as unexecuted. Adoption covers the single final sanitized checkpoint, so ordinary publication does not require another relay. Merge remains outside this milestone and is not a reason to stop local validation or authorized source publication.

Do not ask Nathan to choose routine test order, relay each result, approve each in-scope fix, or reconfirm unchanged existing limits. Stop dependent work only for a genuine safety/resource/access/authorization boundary, and continue unaffected work.

## Published reproduction and evidence

- [reproduce-cleanup.js](reproduce-cleanup.js) runs the integrated offline diagnostic against the two exact historical harness revisions in Git.
- [synthetic-results.json](synthetic-results.json) preserves the four observed parent/head outcomes and mocked snapshot traces. These are synthetic review results, not operational process records.
- [source-identities.json](source-identities.json) records the original baseline, prerequisite, reviewed head, and changed-file byte identities.
- [README.md](README.md) gives fetch/run steps, interpretation, and scope.

The driver requires existing Git, Node, and PowerShell. It makes no network calls, installs nothing, and does not launch Edge or enumerate/kill real processes. Windows root matching and process APIs are mocked; unused dashboard-loading helpers are deliberately unavailable. Source is loaded by pinned Git object and checked against SHA-256 before evaluation. Temporary profiles and runtime directories are confined to a newly created diagnostic-owned temporary directory and removed in finally blocks.

Exit zero means the known false-pass cases were reproduced, not that cleanup is correct. Runtime elapsed values in the synthetic receipt are incidental and not performance measurements. See README for execution/validation limits. No raw local operational report, private account information, credential identifier, machine path, or historical input payload is included.
