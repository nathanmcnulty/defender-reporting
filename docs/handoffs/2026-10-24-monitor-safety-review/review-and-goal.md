# Defender monitor and cleanup safety review

Exact reviewed head: [e4da5bdfa9487eac7f18c193c12245716edd1c38](https://github.com/nathanmcnulty/defender-reporting/commit/e4da5bdfa9487eac7f18c193c12245716edd1c38). Review completed 24 October 2026. Source commits: cleanup 1cd49af7d4b2515f9598229c0faf664e5dcddefa and inventory 03ae6da3310fa3ccb3b564e2df1baa567bdcba1b, following 94bd81e889ae62ffa88dd3559116ab3c39f4c23d.

## Decision

**Do not accept the combined cleanup-safety checkpoint yet. One P1 and two P2 safety/accounting findings remain.** Accept the single-snapshot memory-accounting correction narrowly: no blocking finding was identified in that change, and discriminating offline checks passed. That acceptance does not establish five-second native inventory stability.

All findings below distinguish synthetic execution and upstream source reasoning from native observations. No browser, native process inventory/termination, VM operation, Azure action, installation, resource change, public write or merge was performed by this review. Temporary-profile deletion in the reproduction affected only a directory created by that diagnostic.

## Exact scope

The owning branch was verified at e4da5bdf. The comparison from 94bd81e8 contains five test/harness paths plus one sanitized README. Application templates, generation/import code and generated distributions remain unchanged from 9c240298. The three commits have the expected single-parent chain. Forty-six fetched/copied exact-head files were checked against Git blob identities and remained unchanged after review checks.

Changed source:
- tests/helpers/HostedSmokeDiagnostics.ps1
- tests/Invoke-HostedDashboardRuntimeSmoke.ps1
- tests/Invoke-HostedSmokeDiagnosticsRegression.ps1
- tests/Invoke-HostedSmokeOwnershipRegression.ps1
- tests/Measure-DashboardWorkerTransfer.js

The [producer handoff](https://github.com/nathanmcnulty/defender-reporting/blob/e4da5bdfa9487eac7f18c193c12245716edd1c38/docs/handoffs/2026-10-24-monitor-fix-review/README.md) preserves its unsuccessful measurements and private-evidence boundary. Its prior independent-review and archive-verification claims are producer-reported to this review. Public hashes do not expose or independently verify private evidence.

## Severity-ranked findings

### P1 1: StartTime validation does not pin the process subsequently killed

At [HostedSmokeDiagnostics.ps1 lines 253–262](https://github.com/nathanmcnulty/defender-reporting/blob/e4da5bdfa9487eac7f18c193c12245716edd1c38/tests/helpers/HostedSmokeDiagnostics.ps1#L253-L262), the code gets a Process object by PID, checks StartTime and calls Kill. The comment says it kills a verified handle, but no persistent handle is acquired before validation.

Exact upstream versions matching the reported runtime establish the distinction:
- [PowerShell 7.6.6 Get-Process by ID](https://github.com/PowerShell/PowerShell/blob/f260eb9c31ec72c5282f98e5ea24d9be4f8d7536/src/Microsoft.PowerShell.Commands.Management/commands/management/Process.cs#L215-L244) uses Process.GetProcessById.
- [.NET 10.0.12 GetProcessById](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/libraries/System.Diagnostics.Process/src/System/Diagnostics/Process.cs#L1035-L1053) creates a PID-associated object, not a permanently pinned process handle.
- [StartTime's GetProcessTimes](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/libraries/System.Diagnostics.Process/src/System/Diagnostics/Process.Windows.cs#L695-L714) obtains and disposes a short-term handle.
- [Kill](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/libraries/System.Diagnostics.Process/src/System/Diagnostics/Process.Windows.cs#L92-L115) obtains another handle; [GetProcessHandle](https://github.com/dotnet/runtime/blob/4271d88e0aebf3d04f188f1334c2220d80555ef6/src/libraries/System.Diagnostics.Process/src/System/Diagnostics/Process.Windows.cs#L761-L803) reopens by PID unless the object already holds a handle.

If the original process exits and its PID is reused after StartTime returns, Kill can target the replacement. The fresh CIM checks precede this window and do not close it.

A synthetic process adapter modeling those documented handle lifetimes made the unchanged helper terminate a replacement named unrelated.exe and return Confirmed=true with no failures. **This is a primary-source-supported race and a synthetic modeled transition, not an observed Windows exploit or native unrelated-process termination.**

The analogous [JS-harness termination pattern at lines 354–358](https://github.com/nathanmcnulty/defender-reporting/blob/e4da5bdfa9487eac7f18c193c12245716edd1c38/tests/Measure-DashboardWorkerTransfer.js#L354-L358) is pre-existing, not introduced by the memory correction, but needs the same targeted repair. The earlier singleton and memory-calculation benefits are unaffected.

Required repair: bind creation-time validation and termination to the same retained OS process handle, acquired before identity validation, or an equivalent identity-safe primitive. Fail closed if it cannot be acquired or validated. Keep root/profile checks, disposal, deadlines and conservative kill eligibility. Add a discriminator for reuse after StartTime, not only reuse before the fresh CIM read.

### P2 2: a late-born descendant can survive a clean result

The helper seeds a local ledger from [one initial snapshot](https://github.com/nathanmcnulty/defender-reporting/blob/e4da5bdfa9487eac7f18c193c12245716edd1c38/tests/helpers/HostedSmokeDiagnostics.ps1#L232-L244), kills only that initial list, then [re-inventories with surviving known records](https://github.com/nathanmcnulty/defender-reporting/blob/e4da5bdfa9487eac7f18c193c12245716edd1c38/tests/helpers/HostedSmokeDiagnostics.ps1#L281-L298). Descendant discovery requires a currently selected parent in [lines 201–220](https://github.com/nathanmcnulty/defender-reporting/blob/e4da5bdfa9487eac7f18c193c12245716edd1c38/tests/helpers/HostedSmokeDiagnostics.ps1#L201-L220).

Reproduced sequence: initial snapshot contains root 1001; child 1002 is born after that snapshot and fresh root validation, immediately before root termination. The root exits. Final inventory sees the child without a profile argument but no selected parent, drops it and returns Confirmed=true, Failures=[] while 1002 remains alive in the synthetic process model.

This differs from the receipt's acknowledged root-vanished-before-initial-inventory limitation: here the helper positively observed and terminated the root itself. Replacing unrestricted tree-kill with direct verified kills is appropriate, but the resulting accounting must not declare undiscovered descendants absent.

Required repair: preserve enough per-run ancestry/ownership evidence to account conservatively for descendants created during cleanup and retained ancestry after parent disappearance. Do not authorize killing an uncertain process merely to make cleanup pass. If absence cannot be established, keep cleanup unconfirmed and retain the profile. Add the late-birth transition as an integrated regression.

### P2 3: failed canary cleanup loses its ledger on final cleanup and deletes a live child's profile

The [canary path at lines 582–587](https://github.com/nathanmcnulty/defender-reporting/blob/e4da5bdfa9487eac7f18c193c12245716edd1c38/tests/Invoke-HostedDashboardRuntimeSmoke.ps1#L582-L587) saves diagnostic/failure codes, not the helper's known identities. The [finally path at lines 615–631](https://github.com/nathanmcnulty/defender-reporting/blob/e4da5bdfa9487eac7f18c193c12245716edd1c38/tests/Invoke-HostedDashboardRuntimeSmoke.ps1#L615-L631) calls the helper afresh; AccountingIncomplete reflects only stream-drain state.

Reproduced with the unchanged helper and AST-extracted actual finally block:
1. Root 1001 and child 1002 are known. The child's mock Kill returns access denied; root termination succeeds.
2. First cleanup reports Confirmed=false, process-access-denied and owned-process-remains.
3. Final cleanup begins with no root and no retained child ledger. It reports processCleanupConfirmed=true.
4. The actual finalizer removes the diagnostic's newly created temporary profile while synthetic child 1002 remains alive.

The final run record still says outcome=cleanup-failure and retains the prior failure codes. **This is false process-cleanup confirmation and unsafe profile removal, not a reproduced whole-run pass.**

Required repair: preserve ownership/accounting state across canary and final cleanup, or propagate unresolved/incomplete accounting fail-closed. A new empty root scan must not erase a previously known live descendant. Add an integration regression spanning both cleanup calls and the real profile-removal branch, plus positive controls for genuinely absent/reused identities.

## What is sound and what current tests miss

Exact native argument parsing replaces substring profile selection, excludes neighbors/literals/duplicates/relative paths, and uses normalized exact matching. Full-population descendant discovery includes non-Edge children. Direct kill avoids blindly terminating unverified subtrees. Benign exit races and access failures are separately diagnosed; unknown identity is generally retained as failure. These are valuable improvements, not reasons to waive the gaps above.

The new tests cover nine single-call ownership scenarios and finalizer failures, but their Process.StartTime is a fixed property and they do not span a failed first cleanup plus a second ledger reset or child birth during root termination. Passing those tests therefore does not discriminate the three findings.

The five-second stopwatch shares termination waits and verification polling; there is no extra five-second verification window. Initial enumeration and synchronous CIM/Get-Process/Kill calls are not hard-cancellable by that stopwatch. The README discloses that limitation and the unchanged outer supervisor remains the wall-clock bound. Do not describe this as an absolute five-second cleanup wall-time guarantee.

DrainIncomplete remains a failure and is propagated through immediate/final cleanup. It is not a general lifetime ownership proof, and it does not cover the failed-cleanup ledger loss when both streams drained completely.

## Memory correction accepted narrowly

[Inventory lines 230 and 309–321](https://github.com/nathanmcnulty/defender-reporting/blob/e4da5bdfa9487eac7f18c193c12245716edd1c38/tests/Measure-DashboardWorkerTransfer.js#L309-L321) project seven properties from all Win32_Process records and take working-set/private counters from each selected identity-bearing CIM object. Inventory no longer reopens processes, eliminating the old silent omission on an unavailable Get-Process. This is one enumeration, not a claim of a globally atomic machine-wide snapshot.

Both fields reject absent/null/empty, negative, nonnumeric and individually overflowing Int64 inputs. Microsoft's [Win32_Process diagnostic script](https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/scripts-list-running-wmi-providers) divides PrivatePageCount directly by 1 KB for private-KB reporting; no page-size multiplication belongs here. Private committed bytes and working set remain different metrics.

Independent extracted-code checks passed 34 bounded PowerShell mock invocations, including 26 invalid-counter cases, distinct counters, non-Edge descendants, root reuse/orphan retention and no-reopen discrimination. Previous inventory fails the same forbidden-open case. The actual extracted ResourceGuard rejects a mocked inventory timeout and requests termination once. Default inventory timeout remains 5,000 ms.

Nonblocking numeric boundary: aggregate sums can promote beyond Int64 to an inexact Double. The extreme synthetic sum still trips the unchanged 2-GiB working-set guard; no realistic cap bypass was demonstrated. Individual overflow rejection is established, arbitrary exact aggregate arithmetic is not.

## Independent checks and producer-only evidence

Independently completed:
- Exact source/ancestry/tree/blob checks; Node syntax check.
- Fourteen extracted hosted-probe virtual-clock cases.
- Linux --mock and telemetry assertions (their Windows branches do not run on Linux).
- Memory and timeout-guard diagnostics described above.
- Three source-driven synthetic cleanup counterexamples, including real deletion of only a diagnostic-owned temporary profile.

The cleanup diagnostics replace Windows platform/native argv matching and process APIs explicitly. No native CIM, process handle, PID-reuse event or browser was exercised. Exact .NET 10.0.12 / PowerShell 7.6.6 upstream source was inspected, not the owner's Windows binaries.

The producer reports:
- Standalone FAIL at 11.031 seconds, then PASS at 11.609 seconds with the original --disable-gpu flag.
- Actual uninstrumented 20k candidate BLOCKED by five-second process inventory timeout.
- First instrumented diagnostic BLOCKED at 5,078.875 ms.
- Later instrumented diagnostic PASS verifying 19,677 rows × 42 fields = 826,434 values per cold/reload load.
- A slow passing call at 4,426.225 ms, only about 574 ms below deadline.
- Private archive/report/source evidence checked locally.

These are not independently rerun native results here. The instrumented semantic pass does not replace the uninstrumented failure, prove timeout stability or establish a fair performance series. Phase markers denote beginnings; the failed interval remains incompletely localized. The standalone pass with unchanged GPU flag supersedes a simple flag-causality explanation, but erases no earlier failure. Do not resume the old GPU-fix goal by inertia.

The monolithic 900.438/900.375-second caps, larger/native 120k and historical/live gates remain open. PR #93/#94 remain unchanged open drafts and #67/#69/#70/#92 remain open. No exact-head workflow run was found.

## One consolidated next scope

Proposed for Nathan to adopt, not current execution or publication authorization:

Continue from owning checkpoint e4da5bdfa9487eac7f18c193c12245716edd1c38, retaining runtime 03ae6da3310fa3ccb3b564e2df1baa567bdcba1b, after overlap and admission checks. In one bounded finishing session, repair all three cleanup gaps: bind validation/termination to one process handle in both harnesses; preserve conservative ownership through root exit, late births and repeated cleanup; retain profiles whenever absence is unresolved. Add integrated regressions that fail the reviewed head, positive absence/reuse controls and independent final review. Keep the accepted single-CIM memory correction and bespoke tests.

Only after source safety passes, localize the five-second inventory timeout using bounded observations that distinguish startup, compilation, CIM, selection, serialization and completion costs. Preserve plain, instrumented and failed results and observer overhead. No speculative caching, persistent helper or optimization. Within already authorized resources and unchanged limits, complete actual standalone and uninstrumented cold/reload/full-field acceptance plus feasible remaining comparisons. An instrumented-only pass is not qualification; stop on failed admission rather than repeat unchanged attempts.

Adopting this goal includes one final sanitized source/results push to the existing owning branch, after overlap checks, without force. Return its exact revision, independent review and passed/failed/capped/refused/not-run matrix, or one bundled account of genuine blockers. Keep raw operational evidence local, all historical failures preserved, issues #67/#69/#70 open, PR #93 separate and #92's bespoke-test constraint intact. No new resources, process stops beyond owned test cleanup, installs, credentials, Azure, PR/workflow changes, deployment or merge. This proposal authorizes none of those actions now.

## Published evidence and limits

- [Runnable synthetic reproduction](Invoke-CleanupOwnershipGapRepro.ps1), covering all three cleanup findings.
- [Sanitized synthetic results](synthetic-results.json). Random temporary-directory names are replaced with explicit synthetic labels; no operational result is included.
- [Exact source identities](source-identities.json) and [immutable upstream identities](upstream-source-identities.json).
- [Package hashes](SHA256SUMS).

The memory and other offline checks described above were performed during review. Their local runner/log collection is not included in this minimal handoff; it is not private native operational evidence. The three cleanup counterexamples are runnable from the public exact source. The source review was read-only; this documentation package was subsequently authorized for publication on the handoff branch only. Adoption of the next goal remains a separate decision.
