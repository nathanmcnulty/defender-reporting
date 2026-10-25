# Defender JS lifetime-accounting review and completion design

Reviewed head: [340898ac0fbb1fb614f95ee4ccd7bf7d47849092](https://github.com/nathanmcnulty/defender-reporting/commit/340898ac0fbb1fb614f95ee4ccd7bf7d47849092). Source: [dfd2e7d24df71d1e095ea868550610e544c36b26](https://github.com/nathanmcnulty/defender-reporting/commit/dfd2e7d24df71d1e095ea868550610e544c36b26), directly above f0dd25699f310647c763c29c92aeb250493f5c39. Review date: 25 October 2026 UTC.

## Decision

**Accept the narrow P2 false-clean repair. No new material defect was found within that change. Keep native qualification blocked and stop snapshot-patching/native-retry loops.** The repair deliberately refuses a clean verdict after an observed root disappears. It does not create a complete browser-family lifetime proof.

The next useful milestone is one bounded launch-bound ownership/completion implementation, not another unchanged 20k confirmation or a relaxed guard. A small shared, per-run Windows Job Object owner is the recommended mechanism, subject to design/source review and later adoption. It is not implemented or authorized for execution by this review.

## Independently verified source and tests

- Source commit dfd2e7d2 has sole parent f0dd2569; head 340898ac is its documentation-only child. Exactly two harness/test files changed, plus three new handoff documents. All other files retain their prior identities, including the earlier standalone repairs and product/runtime/build source at 9c240298.
- Both published Git blobs/SHA-256 values match the receipt. Both reviewed-working-byte hashes match the corresponding CRLF forms. That establishes byte correspondence, not the private review sessions or native execution provenance.
- The embedded PowerShell selection, memory and termination bodies are byte-for-byte unchanged from f0dd2569, and all three receipt body hashes match. SafeHandle-before-StartTime, disposal, fresh identity/profile checks and same-CIM counter validation remain intact.
- The exact new source-driven regression passed all 11 cases under existing Linux Node/PowerShell tooling. Against exact f0 source it failed at the intended assertion, `0 !== null`, rather than a setup error.
- Node syntax checks and Linux `--mock` passed, including the deterministic inventory/post-work timestamp control. Windows-only aggregate branches were not claimed as independently run. The existing preflight discovers `Assert-Dashboard*.js`, so the new test is included without a workflow change.
- All 54 fetched/copied exact-head files retained their Git blob identities after checks.
- Owning head was 340898ac and the handoff branch remained f609acf2. PR #93/#94 remained unchanged open drafts, #67/#69/#70/#92 remained open, and no workflow runs were found for either source commit dfd2e7d2 or head 340898ac.

Source was inspected before execution. The new test replaces native Windows argv/platform behavior and all process APIs with explicit mocks; actual filesystem operations affect only its freshly created temporary fixtures. No native browser, process inventory/termination, VM, Azure, installation, resource change, implementation edit, publication or merge occurred during the independent review. This later documentation-only handoff publication does not authorize implementation or native execution.

## Why the narrow P2 closes

At [lines 300–308](https://github.com/nathanmcnulty/defender-reporting/blob/340898ac0fbb1fb614f95ee4ccd7bf7d47849092/tests/Measure-DashboardWorkerTransfer.js#L300-L308), validated self-root identities enter a private monotonic `observedRoots` set. At [lines 332–345](https://github.com/nathanmcnulty/defender-reporting/blob/340898ac0fbb1fb614f95ee4ccd7bf7d47849092/tests/Measure-DashboardWorkerTransfer.js#L332-L345), a missing/reused observed identity or failed inventory makes accounting permanently incomplete for that owner. A later empty inventory cannot reset it. Termination also remembers positively selected identities at [lines 407–410](https://github.com/nathanmcnulty/defender-reporting/blob/340898ac0fbb1fb614f95ee4ccd7bf7d47849092/tests/Measure-DashboardWorkerTransfer.js#L407-L410).

The new lifetime set is not serialized in the PowerShell [environment/selection inputs](https://github.com/nathanmcnulty/defender-reporting/blob/340898ac0fbb1fb614f95ee4ccd7bf7d47849092/tests/Measure-DashboardWorkerTransfer.js#L299-L306). It cannot add a PID, ancestry link or kill authorization. Existing selection and fresh termination eligibility are unchanged; this is accounting evidence only.

The repaired late-birth test returns remainingOwned=null and retains its real fixture profile and sentinel. Repeated empty cleanup remains unresolved. Root reuse, unreadable profile/identity and termination failure do not broaden the kill list. The [profile-removal gate](https://github.com/nathanmcnulty/defender-reporting/blob/340898ac0fbb1fb614f95ee4ccd7bf7d47849092/tests/Measure-DashboardWorkerTransfer.js#L468-L476) is therefore no longer reached with a false zero in the previously reproduced observed-root case.

## The fundamental limit is now explicit, not solved

Two situations must stay separate:

1. **A previously observed root exits normally.** The code cannot distinguish harmless completion from an unseen descendant that outlived it, so it refuses confirmation. This is intentional. Any self-root recorded by the exact-profile selection can trigger the rule, not only the originally launched browser PID. Source supports normal process churn as a possible trigger; the private native trace does not identify which identity disappeared.
2. **The root vanishes before the first successful snapshot.** No historical root is recorded. The explicit `unobserved-orphan-boundary` case still obtains zero/no errors and removes its fixture profile while an unseen orphan exists. The test labels this outside proof, not acceptance. This is the known launch-to-first-snapshot blind spot, not a newly introduced defect.

More polling, broader PID ancestry inference or clearing sticky state cannot turn these snapshots into lifetime proof. Holding only the original root handle proves that root's identity/exit, not that all descendants are gone. Accept the fail-closed safety increment without claiming that arbitrary profile deletion is generally safe.

## Native evidence: failure stays failure

The [published producer receipt](https://github.com/nathanmcnulty/defender-reporting/blob/340898ac0fbb1fb614f95ee4ccd7bf7d47849092/docs/handoffs/2026-10-25-js-accounting-qualification/results.json) reports one candidate-only affected confirmation failing after 24.187 seconds with process-accounting. Its first-load field oracle compared 19,677 × 42 = 826,434 values, but the run failed at the cache stage and never reached reload. This is neither first-load acceptance nor a cold/reload pass.

Inner cleanup reported remainingOwned=null, profileExists=true and final-inventory/profile-removal errors. Later outer-job cleanup and zero matching families are separate observations. They cannot retroactively certify inner absence, imply profile deletion, or prove a particular leak/no-leak account. Do not delete retained directories using timing/name heuristics.

Four successful host-awaited inventory intervals were about 1.851, 2.124, 3.198 and 3.825 seconds. Separately measured post-inventory validation/free-memory work was small in those samples. The new [timestamp boundaries](https://github.com/nathanmcnulty/defender-reporting/blob/340898ac0fbb1fb614f95ee4ccd7bf7d47849092/tests/Measure-DashboardWorkerTransfer.js#L82-L100) are correctly placed, but awaited intervals still include response processing and scheduling. There is no completion timestamp for the failing call and no identity diagnostic proving its specific cause. These observations do not explain the earlier five-second timeout, prove future stability or supply an old timeout margin.

The retained dump-DOM/animation-frame failures and previous passes establish variability, not GPU/virtual-time/product causality. Preserve the older f0 correctness pair, monolithic 900-second caps, 120k import caps and separate replay series. No new standalone/base/large-data/performance run is justified before the completion mechanism changes. Native observations, private controller source, admission evidence and raw/reduced evidence reviews were not independently accessed here.

## Minimal practical mechanism: a shared run-scoped Job Object owner

This is a design recommendation inferred from Windows' documented process/job model, not a claim that the existing private supervisor already implements it correctly.

### 1. Bind ownership before browser code can execute

Use one small shared launcher/owner for both harnesses, reusing audited native launch primitives from the existing supervisor where possible. Create an exclusive browser-family job and create the browser suspended; assign it successfully before resuming its primary thread. `CREATE_SUSPENDED` prevents the primary thread running until resumed. Assignment after an ordinary Node/Process.Start launch leaves the same creation race. [Process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags), [AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject).

If assignment/resume/setup fails, terminate only that newly created suspended process through its original retained handle, dispose owned resources and fail closed. Never fall back to an uncontained launch, PID-tree kill or a privilege change. Keep exact executable/argument/profile binding and record creation/assignment/resume outcomes.

### 2. Keep the job exclusive and compatible with the outer supervisor

Prefer an unnamed, non-inheritable job handle held by the trusted run owner. Do not enable breakaway or silent breakaway. Use a dedicated browser-family child job rather than interpreting the broad outer test job's eventual emptiness as inner completion. Windows supports nested jobs on compatible systems; their hierarchy and existing restrictions must be checked, and incompatibility is a blocker, not permission to escape the outer job. [Nested jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs).

Normal CreateProcess descendants inherit job membership, but Windows documents exceptions, including brokered `Win32_Process.Create`. Therefore prove the actual Edge launch/subprocess route is contained; a job is not a claim to capture every process a separate service might launch. Unexpected outside-family behavior remains unconfirmed. [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

### 3. Use job membership/completion as authority, not process-name snapshots

Expose a small run-bound start/query/terminate/completion contract through owned local IPC, with run/profile identity and ordered state transitions. The owner must stay outside the browser-family job so it can attest completion. A stale receipt, failed query, disconnected owner, timeout or wrong-run response means unknown cleanup, never zero. Do not install a service or create persistent credentials.

Query the retained job handle for membership and terminal active count. `QueryInformationJobObject` supplies job accounting; `ActiveProcesses` describes current job membership. After further assignment is disabled and all assigned processes are gone, an observed zero supplies a different kind of evidence from a missing-root census. Retain the job handle until this check completes. [QueryInformationJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject), [basic job accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information).

Job completion-port messages may help wake a waiter but must not be the sole proof: ordinary notifications are not guaranteed, and message PIDs can be recycled. Do not assume waiting on the job handle means ordinary all-processes completion. Use bounded authoritative queries and retain necessary handle identity. [Completion-port notification semantics](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port), [job-object signaling semantics](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

### 4. Make failure containment distinct from clean confirmation

Use `KILL_ON_JOB_CLOSE` as owner-loss containment, not as a fabricated success receipt. When cleanup is requested, terminate only the owned job if graceful exit does not complete, then query to bounded zero before permitting profile removal. Job termination covers its assigned processes and nested child jobs. [Job close behavior](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information), [TerminateJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject).

Keep profile removal conditional on that exact run's proved terminal state plus existing stream/server requirements. A lost completion response or unverified owner state retains the profile even if the OS probably terminated the job. Do not use the new design to retroactively certify old retained profiles.

### 5. Preserve resource semantics and measure architecture overhead separately

Membership must cover processes born before the first census and survive normal root/child exit. Integrate that authority into the guard rather than resetting the current sticky heuristic. Keep identity-safe process operations, fail-closed invalid/unreadable counters and the existing working-set/private-byte distinctions. Do not silently substitute job committed memory for the family working-set cap, or include the owner/helper in browser-only measurements without explicitly changing and reviewing the evidence definition. No raised limits, relaxed cadence, persistent cache or speculative performance optimization belongs in this repair.

The small owner may remain alive only for its test run because it owns the job handle. That lifecycle necessity is not a general persistent-service or performance-refactor mandate. Reuse one implementation across both harnesses rather than adding another independent cleanup heuristic.

## Acceptance contract for a later adopted milestone

Before native qualification, source-review the owner, protocol, handle ownership and every rollback path. Bespoke synthetic controls must cover assignment failure without resume, root exit before first census with live children/grandchildren, ordinary empty completion, late birth, PID reuse, owner crash/EOF/query failure, stale/wrong-run receipt, double cleanup, profile retention and unrelated-neighbor exclusion. Include all earlier handle/counter/privacy regressions.

Only after adoption, design/source approval and unchanged admission succeeds should the owner run small bounded Windows job-contract controls, then one affected 20k cold/reload confirmation if those controls pass. These would be new-mechanism tests, not retries of this failed snapshot-only run. Demonstrate inner job zero and profile handling separately from outer cleanup. Any containment, memory, readiness or completion failure stops dependent lanes and returns one bundled blocker report. No large/historical/performance ladder is automatically unlocked.

## Copy-ready proposed consolidated goal

Proposed for later adoption. Publishing this document authorizes neither execution nor a future source/results push; the bounded source/results push below is conditional on adoption of the goal:

Continue from owning 340898ac0fbb1fb614f95ee4ccd7bf7d47849092. Retain the accepted fail-closed repair and replace snapshot-only completion with one shared run-scoped Windows Job Object owner for both harnesses. Bind the browser to an exclusive job before resume, preserve nested outer supervision/no breakaway, and expose a run-bound completion contract. Unknown setup, identity, query or owner state must retain the profile; no broad PID killing or success inferred from later outer absence.

In one bounded milestone, implement and independently review the mechanism and rollback paths, add discriminating bespoke lifetime/failure controls, and preserve existing memory units, limits and all prior safety regressions. Only after source approval and unchanged admission, run the small native mechanism controls and one affected 20k cold/reload confirmation if gates pass. Stop rather than repeat unchanged failures or expand lanes.

Adoption includes one final sanitized owning-branch source/results push after overlap checks, without force, returning its exact revision and complete outcome matrix or one bundled blocker report. Keep operational evidence local, historical failures and #67/#69/#70 open, PR #93 separate and #92's bespoke tests intact. No resource expansion, privilege/security changes, installation, persistent service/credentials, Azure, workflow/PR change, deployment or merge. No new native action or implementation is authorized by this review itself.

## Actual remaining decisions and evidence

The owner needs adoption of this bounded mechanism change, not another unchanged confirmation or additional RAM to resolve the proof problem. Actual nested-job/browser compatibility and existing admission are implementation gates; refusal requires a precise blocker, not elevation or breakaway changes. No private raw-evidence upload is necessary for this source/design review.

The independent synthetic-test logs, expected baseline failure, source/hash checks and remote-state receipts remain retained with the review. This packet publishes only the sanitized review and proposed goal, not local operational records or credentials. The exact public regression source and producer receipts are linked from the [packet README](README.md); producer reports remain distinct from independent synthetic verification.
