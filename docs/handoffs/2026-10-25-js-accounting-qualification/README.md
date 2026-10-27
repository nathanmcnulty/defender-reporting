# JS lifetime-accounting qualification checkpoint — 25 October 2026 UTC

**Decision: approve the narrow JS false-clean repair; native qualification remains blocked.** The affected confirmation failed closed. Do not close #67/#69/#70, accept a performance envelope, or merge from this checkpoint.

Adopted goal: [f609acf24](https://github.com/nathanmcnulty/defender-reporting/blob/f609acf24b8ce0cb8528f72fbe5bd30d2d3d0e54/docs/handoffs/2026-10-25-consolidated-cleanup-review/review-and-goal.md). Start was owning `f0dd25699f310647c763c29c92aeb250493f5c39`, not the documentation branch's older runtime. Reviewed source commit is **`dfd2e7d24df71d1e095ea868550610e544c36b26`**, its direct child, on `fix/issue-70-reviewed-cleanup-20261023`. Only two test/harness files changed. Product/runtime/build remains `9c240298b2feb9c2d5698fcd179296b37d30d78c`.

## Repair and preserved boundaries

The JS harness now remembers validated, positively observed self-root identities in an internal lifetime set, separate from its current selection ledger. That set is never serialized into PowerShell and cannot add processes, ancestry or kill authority. If a previously observed root identity is missing/reused in a later returned inventory, or an inventory fails, accounting becomes sticky-incomplete. A later empty inventory cannot restore a clean result. Actual cleanup keeps remainingOwned unknown and retains the profile.

This closes the inherited child-born-during-root-Kill counterexample conservatively. Both earlier heads reproduced the defect: the fixture child survived while actual cleanup returned zero/errors=[] and removed the freshly created fixture profile. That diagnostic's PASS means the defect was observed, not accepted cleanup. The new integrated regression fails the owning baseline at the intended false-zero assertion and passes the repaired source.

The three accepted c0cedf59 repairs remain intact. Embedded PowerShell selection, same-CIM byte counters and termination bodies are identical to f0dd2569, including exact profile parsing, fresh identity checks, retained SafeHandle-before-StartTime, disposal and kill eligibility. No historical inference grants termination authority. Independent read-only source review approved both exact changed-file hashes.

**Tradeoff and remaining proof boundary:** normal successful termination of an observed root also makes snapshot-only descendant absence unprovable. Retaining the profile is intentional, not evidence that a process leaked. A root that disappears before the first successful snapshot, leaving an unseen orphan, remains outside this proof. The regression explicitly demonstrates that boundary; its empty result is not general owned-family acceptance. A stronger launch-bound completion mechanism would be needed for a general clean verdict; no such architecture was introduced in this bounded repair.

## Existing traces were analyzed before confirmation

Retained dump-DOM failures reached DOMContentLoaded, completed denormalization and stalled with a requested-but-unfired animation frame and no surfaced application error. The compositor variant also failed; one default-GPU cell passed; a later dump-DOM invocation with the original disable-GPU/virtual-time mode passed. This does not establish a GPU, virtual-time, cache or product cause.

The passing CDP/Playwright 20k path uses a different execution mode and artifact from the small dump-DOM probe. Its success does not explain the standalone failure. Older 4,874.966/4,165.942-ms ResourceGuard samples include inventory plus subsequent work. Earlier child-phase observations likewise leave variable host overhead unresolved. No existing trace measures an isolated old inventory-timeout margin.

ResourceGuard now records host timestamps immediately before the inventory invocation, after its awaited resolution, and after free-memory reading/data validation, while preserving the original whole-sample timestamp. A deterministic clock control distinguishes 0→11 inventory from 11→31 post-work. These host-awaited intervals still include execution, response handling and scheduling; they are not isolated CIM or compilation time. No deadline, frequency, memory rule or phase observer was added or relaxed.

## Checks and the single affected confirmation

| Check | Result |
|---|---|
| Pinned public reproduction on f0/e4 | Diagnostic PASS 6.016 s: inherited false-clean defect reproduced on both |
| New 11-case source-driven regression | PASS 32.062 s |
| New regression against exact f0 source | Expected FAIL 3.016 s at remainingOwned 0 !== null; retained |
| Full affected telemetry suite | PASS 137.203 s, including ownership/handle/counter/privacy/cleanup and timestamp controls |
| Node syntax and diff whitespace | PASS |
| One candidate-only 20k affected confirmation | **FAIL 24.187 s**, process-accounting; no retry |

The new test is automatically discovered by the existing Assert-Dashboard*.js preflight gate. Windows argv/platform and all process APIs are explicitly mocked in this portable regression; filesystem profile retention/removal uses freshly created fixture directories. Cases cover birth during Kill, external root exit, root and child PID reuse, unreadable identity/profile, child disappearance while root remains, termination failure, sticky repeated empty cleanup, genuine-empty/unrelated controls and the unobserved-before-first-snapshot boundary. It asserts one full CIM snapshot per operation, no inventory Get-Process opens, exact disposal and unchanged restricted kill lists. This is synthetic proof, not native fault injection.

The native controller was independently reviewed before execution, pins source/provenance/inputs/oracle/guard, admits only one candidate20k cell and has no retry path. Five samples exceeded the unchanged 5.25-GiB scale admission threshold. Native bounds remained 240 s / 2 GiB family / 3 GiB physical-free floor, 120 s readiness, 5 s inventory and 15 s termination. Offline checks remained 180 s / 3 GiB / 3 GiB. No environment or limit change occurred.

The confirmation used the same retained real-library candidate package, ordinary dashboard observers and independent field oracle as the preceding checkpoint, with the three verbatim canonical helper/class replacements only. There was no child-phase observer or base comparison. The first load checked **19,677 × 42 = 826,434 values**, digest `1e5fe66de3260dc5223651cc8c110c9eab2019dee9a29a6aa814956dc955d5e2`, with zero page errors/external requests. The run then failed at the cache-stage guard path with reason process-accounting. It is not a passed first-load acceptance or cold/reload pair; reload was not reached.

Inner cleanup returned remainingOwned=null, profileExists=true and Final owned inventory/Profile removal errors. The server closed. Supervisor remainingAtRootExit was empty, job cleanup verified, and the later external check counted zero matching harness families. Those are later outer-cleanup observations, not inner absence confirmation, profile deletion or proof of either a leak or no leak. The retained directory was left untouched; local time-window profile candidates are explicitly not ownership/deletion authority.

Peak outer working set/private bytes were 1,830,162,432 / 1,105,309,696, minimum physical-free bytes 7,617,462,272. Four successful samples had monotonic boundaries:

| Stage | Host-awaited inventory ms | Post-inventory to data-validated ms |
|---|---:|---:|
| Prelaunch | 1,850.5043 | 0.0538 |
| Post-spawn | 2,123.7097 | 0.0231 |
| Startup | 3,198.3804 | 0.0197 |
| First reports | 3,824.9460 | 0.0227 |

No completion timestamp exists for the failed call, and no root PID/identity diagnostic identifies a specific disappearance. These successful samples separate present post-work cost from awaited inventory; they do not explain earlier timeouts or prove stability. The independent evidence review checked raw/reduced values and recommended stopping without another standalone/base/120k/timing lane.

## Consolidated blockers and retained evidence

| Area | Current bounded evidence | Remaining blocker |
|---|---|---|
| JS cleanup / #70 | False-clean counterexample closed by sticky lifetime accounting; synthetic controls pass | Current native run remains unconfirmed and retains profile; snapshot-only accounting cannot provide general completion proof |
| Readiness / inventory | Existing traces analyzed; new successful inventory/post-work boundaries measured | Dump-DOM readiness variability and historical five-second timeout cause/stability remain unresolved |
| #67 fresh import | Prior 20k full-store/raw-field parity preserved | Both 120k fresh-import 180 s caps and historical 50k-device/1.5M-observation envelope remain unqualified |
| #69 replay / packaging | Prior 120k replay, 4,980,486 candidate fields and identical-payload Hosted/Dual packaging retained | Old +6.61%/+6.69% and later +3.51% replay series remain separate; no justified product optimization or large memory/LOH/Automation acceptance |
| Required / historical gates | Prior narrow checks and receipts preserved | Monolithic 900.438/900.375 s caps, larger/cache-ineligible native envelope, exact-head CI and separately authorized live gates remain open |

Fresh import, completed-store replay, PackageOnly packaging and browser reload remain separate. Do not call the prior 120k successful single replays fresh import, pool old successful/failed/instrumented runs, replace failed raw-HTML comparison with its separate generatedOnUtc/exact-key-order review, or infer performance from one correctness observation. The earlier plain-inventory f0 candidate/base cold/reload correctness pair remains preserved as evidence for that source, not for this failed affected run.

Hosted [CI 39735467316](https://github.com/nathanmcnulty/defender-reporting/actions/runs/39735467316) passed deterministic preflight and Azure package smoke on original f341fdd2 after the dated receipt. That is distinct from capped Windows attempts and this source revision. No unchanged monolithic, standalone, larger-native or already-passing pair was repeated by inertia.

No merge, workflow/PR change, Actions enablement, dependency install, tenant data, credentials, Azure operation or resource resize occurred. PR #93 remains separate, #92's bespoke tests remain, and #67/#69/#70 stay open. Adoption authorizes only the final sanitized push on the existing owning branch; raw operational evidence remains local.

## Review / resume evidence

[Source identities](source-identities.json) pin exact reviewed working bytes, published blobs and unchanged PowerShell bodies. [Numeric results](results.json) preserve the current pass/fail/not-run matrix. Independent source, pre-execution tooling and raw/reduced evidence reviews are retained locally; native runs are producer observations, not reviewer reruns. Public hashes do not expose or independently verify private traces.

With existing dependencies, the affected source checks are:

```powershell
node tests/Assert-DashboardCleanupAccounting.js
node tests/Assert-DashboardTelemetry.js
```

Use the unchanged 180 s / 3 GiB / 3 GiB bounded supervisor and fresh evidence destinations. Exact executable/argument arrays, revisions, input hashes, admission samples and all failed results are in the local report/archive. The sealed private confirmation controller pins the pre-commit head and exact reviewed dirty bytes; do not rerun it in place on the committed checkpoint. A later confirmation needs a fresh reviewed plan, not a relaxed rule or unchanged retry.
