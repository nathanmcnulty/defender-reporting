# Defender consolidated cleanup checkpoint review

Reviewed head: [f0dd25699f310647c763c29c92aeb250493f5c39](https://github.com/nathanmcnulty/defender-reporting/commit/f0dd25699f310647c763c29c92aeb250493f5c39). Source commit: [c0cedf5902e47d1386620ee30479e55fc1ace17a](https://github.com/nathanmcnulty/defender-reporting/commit/c0cedf5902e47d1386620ee30479e55fc1ace17a). Review date: 24 October 2026.

## Decision

**Accept the three previously identified narrow repairs. Do not yet accept comprehensive cleanup safety or native qualification: one newly identified P2 gap remains in the JavaScript sibling harness.** It is inherited from the previous head, not introduced by c0cedf59. The reported plain-inventory 20k correctness pair is meaningful bounded evidence, but neither a performance series nor proof of five-second inventory stability.

This review inspected source before bounded offline diagnostics. No native process inventory/termination, browser, VM, Azure action, install, resource change, public write or merge occurred. Actual filesystem removal in the diagnostic affected only newly created fixture directories. Native outcomes and private-evidence verification remain producer-reported.

## Verified source and receipt boundaries

- Source commit c0cedf59 is the direct child of e4da5bdf. Head f0dd2569 is its direct documentation-only child, adding the README, numeric results and source-identities manifest.
- Exactly six harness/test paths changed from e4da5bdf: the standalone smoke, diagnostics regression, ownership regression, new safety regression, JavaScript measurement harness and diagnostics helper.
- Every published source Git blob and SHA-256 in the six-file receipt matches the fetched bytes. Each claimed reviewed-working-byte SHA-256 also matches the CRLF form of the published source. This verifies byte correspondence, not the private review sessions themselves.
- Full tree comparison confirms application, runtime, build and other non-test/non-document files remain unchanged from 9c240298. No old documentation-branch runtime was substituted.
- Owning head was f0dd2569; the handoff branch remained 8dea7861. PR #93 and #94 were still unchanged open drafts. Issues #67/#69/#70/#92 remained open. No workflow run was found for either c0cedf59 or f0dd2569.

The [producer README](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/docs/handoffs/2026-10-24-consolidated-cleanup-qualification/README.md), [numeric results](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/docs/handoffs/2026-10-24-consolidated-cleanup-qualification/results.json) and [source identities](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/docs/handoffs/2026-10-24-consolidated-cleanup-qualification/source-identities.json) retain the distinction between public receipts and inaccessible private operational evidence.

## Previously reported findings: disposition

### Prior P1: post-StartTime PID reopening — repaired

Both termination paths now obtain and validate Process.SafeHandle before reading StartTime: [PowerShell helper lines 299–306](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/tests/helpers/HostedSmokeDiagnostics.ps1#L299-L306) and [JavaScript-embedded PowerShell lines 358–368](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/tests/Measure-DashboardWorkerTransfer.js#L358-L368). The same Process remains alive through termination and exit/wait checks, then is disposed on managed paths. Invalid/closed/null/acquisition-failed handles do not fall back to unchecked PID termination.

Immutable .NET 10.0.12 source confirms that SafeHandle establishes the stored handle used by subsequent operations, unlike the previous temporary StartTime handle. Independent old/new mock discrimination preserved a replacement process on current source and selected it on baseline source. All nine newly embedded handle scenarios passed under explicit synthetic Windows-parser/platform substitution. Additional checks covered genuine already-exited Kill exceptions, unreadable StartTime/HasExited, null handle and simultaneous primary/disposal failure. These are source-supported synthetic results, not native Windows fault injection.

SafeHandle's all-access request can conservatively cause cleanup refusal; it is not a reason to weaken handle identity. Forced host exit cannot promise managed Dispose, as the receipt acknowledges. Existing creation-time comparison precision is unchanged and is not presented as a newly proved exact-timestamp guarantee.

### Prior P2: standalone late-born descendant forgotten — repaired fail-closed

The standalone [snapshot separates current termination records from accounting history](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/tests/helpers/HostedSmokeDiagnostics.ps1#L213-L241). An observed root's disappearance makes accounting incomplete; possible historical descendants are not silently treated as absent or newly authorized for termination. Uncertainty remains sticky through [final verification](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/tests/helpers/HostedSmokeDiagnostics.ps1#L328-L346).

Independent baseline/current diagnostics reproduced the original clean verdict with a surviving child on baseline and an unresolved verdict with the child retained on current source. This is a conservative accounting repair, not proof that every descendant has been discovered or terminated. Normal completion can retain a profile when unseen-descendant absence remains unproved.

### Prior P2: standalone second cleanup forgets first failure — repaired

The [immediate cleanup saves its ledger and unconfirmed flag](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/tests/Invoke-HostedDashboardRuntimeSmoke.ps1#L581-L591). The [actual finalizer carries both forward](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/tests/Invoke-HostedDashboardRuntimeSmoke.ps1#L618-L637). It sets uncertainty before invoking cleanup, so an exception cannot leave an accidentally clean state.

The exact finalizer retained a real diagnostic-owned profile after a failed child cleanup and after a later empty scan. The genuinely empty positive control removed its fixture profile. Baseline removed the profile while the synthetic child remained. Seven malformed/wrong-profile ledger cases failed before inventory, and structurally valid forged history produced no process opens or kills. Saved history is accounting evidence, not kill authority. No newly introduced material flaw was found in this standalone repair.

## New material finding

### P2: JavaScript cleanup still forgets a child born during root termination

Affected source: [snapshot-selected termination records, lines 329–340](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/tests/Measure-DashboardWorkerTransfer.js#L329-L340); [live-identity retention and descendant expansion, lines 239–292](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/tests/Measure-DashboardWorkerTransfer.js#L239-L292); [final inventory/profile-removal gate, lines 448–456](https://github.com/nathanmcnulty/defender-reporting/blob/f0dd25699f310647c763c29c92aeb250493f5c39/tests/Measure-DashboardWorkerTransfer.js#L448-L456).

The standalone's new conservative history does not exist in this sibling harness. Its retained records and descendant closure depend on currently present selected identities. Termination captures its record list before Kill. A child born afterward is never recorded; after the root disappears, the final inventory cannot reach that child through a live selected parent. No termination exception occurs, so the separate accountingComplete failure flag remains true.

Independently reproduced through actual extracted ownedProcesses selection/termination and unmodified cleanupOwned:

1. Initial inventory and termination snapshot see owned root 101.
2. The mocked root Kill creates non-profile child 102, then removes the root.
3. Final selection sees child 102 but returns empty pids/records and zero memory totals.
4. Actual cleanupOwned returns remainingOwned=0, profileExists=false and errors=[]. It removes the newly created fixture profile and sentinel while the synthetic child remains alive.

The same counterexample occurs on e4da5bdf and f0dd2569. **This is a newly identified inherited gap, not a regression from handle binding.** It does not invalidate the three narrow repairs above or establish that the producer's ordinary native run leaked a process. It does invalidate a general claim that the JS final empty inventory proves owned-family absence.

The existing JS new-child regression introduces its child before the termination snapshot, so it tests a different boundary. Add a discriminator for birth during root Kill, including the actual profile-removal branch, plus genuine absence and PID-reuse controls. Preserve observed-root lifetime/ancestry as conservative accounting evidence or use an equivalent launch-bound completion mechanism. If absence is unprovable, refuse clean confirmation and retain the profile. Do not turn inferred historical relationships into broader kill authority. Repeated snapshots alone merely narrow the race.

Evidence: [portable reproduction](run-js-late-child-repro.js) and [sanitized synthetic results](synthetic-results.json). All process APIs and Windows-native parsing/platform behavior were explicitly mocked. No real process was stopped. The real filesystem effect was confined to newly created diagnostic directories.

## Independent checks and limitations

- Exact ancestry, tree, Git blob, published SHA-256 and CRLF working-byte correspondence checks passed.
- Node syntax and 14 extracted hosted-probe virtual-clock cases passed.
- Linux --mock passed its privacy/lifecycle/resource-guard paths; Windows-only paths were not represented as passed by that command.
- Standalone independent diagnostics produced 26 current-source records and 13 baseline discriminators, covering original defects, handle/error transitions, malformed/forged ledgers, current versus historical authority, real finalizer retention and positive absence.
- Current embedded handle tests passed nine cases; baseline failed their discriminator. Sixteen targeted old/current mock records additionally cover edge/error and unchanged same-snapshot memory behavior.
- The original single-CIM inventory implementation is byte-for-byte unchanged. This review does not repeat its earlier accepted 34-case coverage or invent new memory/performance qualification.
- The JS late-birth counterexample reproduced on both revisions and deleted only fixture-owned directories.

The five-second standalone polling/wait budget does not hard-cancel synchronous enumeration/handle operations. The JS process wrapper and outer native supervisor remain separate deadlines. No native timeout-stability or Windows handle-race test was performed here. Private operational reports, payloads, raw-field oracle and archived review receipts were not accessed.

## What the producer's latest runs establish

The reported plain-inventory candidate and base cold/reload runs each checked 19,677 rows × 42 fields = 826,434 values per load, with identical ordered digests, cold-to-hit cache behavior and normal-path cleanup. That is a meaningful single sequential correctness pair. Ordinary dashboard measurement observers remained; there was no inventory phase observer. It is not an alternating performance series, a scaling result or a reason to compare those wall times as a speedup/regression.

Actual standalone readiness still failed at 12.890 seconds, despite a ready canary and reported complete streams/normal cleanup. The three idle phase diagnostics passed but had zero owned processes. The 4,874.966-ms candidate ResourceGuard interval includes inventory, free-memory reading, validation and scheduling; 125 ms is not a proved inventory-timeout margin. Earlier inventory timeouts remain relevant and their under-browser-load cause is not localized.

Keep the 900.438/900.375-second monolithic caps, 120k fresh-import caps, historical-scale/live gates and prior replay increases separate and preserved. No unchanged monolithic or larger-native retry is justified by this harness-only change. CI on f341fdd2 is not CI evidence for c0cedf59/f0dd2569. Exact-head hosted CI and live Azure were not run.

## One consolidated next decision and proposed scope

Accept and retain the three source repairs now. Keep comprehensive cleanup and #70 qualification open for the inherited JS gap and the distinct readiness/inventory blockers. No immediate native rerun is needed to reconfirm the source findings.

**Proposed for later adoption, not current execution/publication authorization:** Continue from owning f0dd25699f310647c763c29c92aeb250493f5c39 with source c0cedf59, not the older documentation-branch runtime. In one bounded session, close the JS late-birth accounting/profile-removal gap with conservative lifetime evidence and integrated old/new regressions, without weakening handle binding, exact profile matching, memory accounting or kill eligibility. Obtain final source review before native execution.

Then use the existing local failed/successful traces first to isolate standalone dump-DOM readiness versus the passing plain-inventory path, and to distinguish actual inventory-call duration from free-memory/validation/scheduling costs. Run only discriminating confirmations justified by a changed hypothesis or fix, within existing admission, time and memory limits. Recheck affected semantic acceptance after relevant changes; do not repeat already-passing pairs, old capped preflight or larger lanes by inertia. No speculative flag/cache/persistent-helper optimization or relaxed limit.

Adoption would include one final sanitized source/results push on the existing owning branch after overlap checks, without force, followed by one exact checkpoint with independent review and a passed/failed/capped/refused/not-run matrix, or one bundled account of genuine blockers. Preserve private evidence locally, all unsuccessful measurements, #67/#69/#70, PR #93 separation and #92's bespoke tests. No new environment, resource expansion, unrelated process stops, installations, credential/Azure action, workflow/PR change, deployment or merge is implied. Stable admission and existing native access belong to the owner; this review requires neither a new resource grant nor publication of private raw evidence.

## Published evidence

- [Runnable JavaScript late-child reproduction](run-js-late-child-repro.js), guarded to exact reviewed source bytes.
- [Sanitized synthetic current/baseline results](synthetic-results.json). Only fixture-profile paths were replaced; all process actions were synthetic.
- [Source and original-artifact identities](source-identities.json).
- [Package SHA-256 manifest](SHA256SUMS), covering every other file in this directory.

Other bounded review checks described above remain local and are not included in this minimal handoff. No private operational evidence, payload, credential, tenant data or historical input is published. The source review was read-only; publication of this documentation/synthetic-evidence package was subsequently authorized separately. The proposed next implementation/qualification goal still requires future adoption.
