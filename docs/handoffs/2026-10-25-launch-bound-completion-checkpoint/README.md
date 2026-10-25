# Launch-bound completion: reviewed blocked checkpoint

Adopted goal: [7061855](https://github.com/nathanmcnulty/defender-reporting/commit/706185584c1a45126005381909257761f0d35b1a). Owning start: `340898ac0fbb1fb614f95ee4ccd7bf7d47849092`. Reviewed source: `5a8ba29e7393fb9e7addcd122d10c514bad08686` on `fix/issue-70-reviewed-cleanup-20261023`. This packet is a documentation-only child of that source, not a replacement runtime branch.

**Partial: native mechanism passed; Node integration failed and dependent lanes stopped. Overall launch-bound, browser and large-data qualification remains blocked.** No merge. Issues #67/#69/#70 remain open, runtime PR #93 stays separate, and #92's bespoke tests remain intact.

## Implemented source

Both dashboard harnesses now share a run-scoped Windows job owner. It creates the exact browser executable suspended, assigns it to an exclusive unnamed non-inheritable KILL_ON_JOB_CLOSE job, verifies membership, seals assignment and only then resumes the original retained primary-thread handle. Breakaway is disabled. The owner stays outside the inner job and inside the existing outer supervisor. Native entry points require that outer supervision; an incompatible or unsupervised launch fails closed. No persistent service, credentials, security/privilege change or alternative uncontained launch is provided.

Preassignment rollback uses the original suspended-process handle; disposal retries a failed rollback. Assigned rollback targets only the owned job. Normal completion requires a retained-job active-count/complete-PID-list/active-count bracket of zero plus stdout and stderr EOF. Root exit, owner loss, job-close containment and later outer cleanup cannot produce a successful inner receipt.

The PowerShell consumer uses the shared engine in-process. The Node consumer uses a private sole-client anonymous-pipe JSONL host with nonce/run/profile binding, strict sequence, bounded messages/deadlines and one launch. Browser output is drained with bounded retention inside the engine and never mixed into protocol stdout. Wrong, stale, lost or late replies remain unknown. Family working set/private counters come from retained process handles verified against the inner job; helpers are excluded from the browser sum and included in the unchanged outer cap. The old snapshot owner and its sticky failures remain separately intact.

Profiles require exact-run terminal confirmation, stream completion and server closure. Standalone canary/dashboard attempts use separate one-launch owners and both must confirm. Unknown setup, query, owner or aggregate state retains the profile. Previously retained directories are untouched; this mechanism cannot retroactively certify their cleanup.

## Reviewed checks and preserved failures

Independent source reviews approved the native core/rollback paths, adapters/protocol, read-only exit observer and exact pre-execution controller. Review fixes addressed retained-root rollback disposal, late clean replies, a bound guard receiver, deferred cleanup evidence and failure-result ordering. These were source findings before native execution. Reviewers inspected native receipts afterward; native runs are producer observations, not independent reruns.

| Check | Outcome |
|---|---|
| Compilation / affected ScriptAnalyzer | PASS, final 14.532 s |
| Protocol, guard integration, retention and two-owner aggregate regressions | PASS, latest 2.531 s |
| Retained standalone ownership/safety/diagnostics regressions | PASS, 76.125 s |
| Full affected telemetry/handle/counter/privacy suite | PASS, 146.344 s |
| Earlier 11-case lifetime/accounting regression | PASS, 35.484 s; its unobserved-orphan snapshot boundary remains explicit |
| Native shared-engine mechanism | PASS, 5.516 s, ten scoped controls |
| Native Node IPC consumer | **FAIL**, 7.047 s, additional unclassified job member |
| Small browser, standalone browser, affected 20k | **NOT RUN**, dependent gates stopped |

Earlier analysis-first and legacy-ps-first failures are retained with their original receipts and rejected source snapshot; they are not rewritten as successes. The first was an analyzer warning before a narrowly scoped suppression; the second was an outdated profile-removal expectation corrected to require retention on server cleanup failure. All runs and exact numeric metrics appear in [results.json](results.json). [Source identities](source-identities.json) distinguish reviewed working-byte and normalized Git-blob hashes. Whitespace checks passed on the staged source. No full exact-head CI pass is asserted.

## Native result and actual blocker

The shared C# engine passed root exit before first census with live child/grandchild, late birth, failed assignment with no resume and a failed-first rollback followed by disposal retry, 40-process PID-buffer growth, late/query/negative-counter failure remaining unconfirmed, native argv quoting, bounded stdout/stderr capture and breakaway denial. The unrelated neighbor survived and its own retained-handle cleanup confirmed. Peak outer working set/private bytes were 561,442,816 / 431,071,232; minimum free bytes 8,142,848,000. This is mechanism evidence using disposable fixtures, not Edge acceptance.

The Node gate exited 1 at the exact `Unexpected native fixture member` assertion. Before that assertion it had observed root exit and included both recorded child and grandchild in the job census. The census also contained at least one member outside the root/child/grandchild marker set. The failed proof PID list was not retained, so the cause cannot be classified as an implementation error, harmless runtime descendant, console/broker behavior, PID reuse or a defective fixture assumption.

Failure occurred **before the read-only observer was created and before helper crash was induced**. The client-EOF case did not start. Normal-branch assertions had progressed sufficiently to reach the next case, but no aggregate Node result.json was emitted; the Node gate remains failed as a whole. Peak outer working set/private bytes were 268,517,376 / 124,874,752; minimum free bytes 8,252,993,536. No cap, floor or time breach was reported. Outer remainingAtRootExit was empty and outer cleanup verified; those observations do not prove the unexecuted owner-loss contract.

The admitted controller stopped after these two cells. No small Edge, standalone, affected20k, base or larger workload followed, and no unchanged retry occurred. The narrow next investigation is bounded identity/creation/ancestry capture for every returned job member before deciding whether source or fixture needs repair. Removing the membership assertion would discard the discriminator. A future confirmation requires resolving and reviewing that gap first; this checkpoint authorizes no automatic rerun or expanded ladder.

## Limits and reproducible commands

All existing bounds were preserved: offline checks 180 s / 3 GiB family / 3 GiB physical-free floor; native cells 240 s / 2 GiB family / 3 GiB floor, 500-ms outer sampling, 120-s readiness, 5-s query, 15-s termination. Five fresh admission samples exceeded 5.25 GiB before each native cell. Supervisor SHA-256: `bd7938d5a6b5f5809e9d9765822158f44568d29c68f54ac1f417c216afe3f87e`. Native controller SHA-256: `b79201e6b53c59f9c0c4a3d472be8c0c083139d7cc19be21a9af6693737dbace`. The original controller pins the precommit head and exact dirty allowlist; preserve it as evidence, do not bypass its pins to repeat it.

With the existing installed runtimes, source checks were run under the bounded supervisor:

```powershell
node tests/Assert-DashboardLaunchBoundOwner.js
node tests/Assert-DashboardTelemetry.js
node tests/Assert-DashboardCleanupAccounting.js
pwsh -NoProfile -File tests/Invoke-HostedSmokeOwnershipRegression.ps1
pwsh -NoProfile -File tests/Invoke-HostedSmokeSafetyRegression.ps1
pwsh -NoProfile -File tests/Invoke-HostedSmokeDiagnosticsRegression.ps1
```

Explicit native entry points below describe the attempted cells and require the unchanged outer supervisor and fresh evidence paths. They are not instructions for an unchanged retry:

```powershell
pwsh -NoProfile -File tests/Invoke-LaunchBoundNativeControls.ps1 -PythonPath $existingPython -EvidencePath $freshEvidence
node tests/Assert-DashboardLaunchBoundNative.js $existingPython $freshEvidence
```

No-argument discovery of the native JS entry point explicitly prints SKIP and performs no native control; it is not native acceptance. The local sealed report includes complete literal supervisor command arrays, receipts, review records, fixture markers and exact tested source. No dependency was installed.

## Historical qualification remains open

Fresh import, completed-store replay, PackageOnly packaging and browser reload remain distinct. No import/replay/performance workload was run in this milestone. Earlier 20k store/raw-field parity, 120k replay/packaging evidence and the older f0 candidate/base cold/reload correctness pair remain evidence for their recorded revisions only. Both 120k fresh-import 180-second caps, the 900.438/900.375-second monolithic caps, readiness/inventory variability, separate +6.61%/+6.69%/+3.51% replay series and the failed later 20k cache-stage confirmation remain preserved. No historical envelope or large-data issue is resolved by the new tiny process controls.

Hosted [CI 39735467316](https://github.com/nathanmcnulty/defender-reporting/actions/runs/39735467316) passed deterministic preflight and Azure package smoke at original f341fdd2 **after the dated receipt**. That remains distinct from the capped Windows attempts and does not validate this source. PRs #93/#94 were freshly checked as unchanged open drafts. No workflow/PR mutation, Actions activation, asset publication, Azure/auth/tenant operation, installation, resource resize or merge occurred. Only this sanitized owning-branch source/results checkpoint is published under the adopted goal; operational reports/evidence stay local.
