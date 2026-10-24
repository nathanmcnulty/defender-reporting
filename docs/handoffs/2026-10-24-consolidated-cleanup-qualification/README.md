# Consolidated cleanup qualification checkpoint — 24 October 2026

**Decision: accept the three narrow cleanup repairs for review; retain qualification blockers. Do not close #67, #69 or #70.** This is a bounded checkpoint, not large-data performance acceptance or a merge recommendation.

The adopted goal is [8dea7861](https://github.com/nathanmcnulty/defender-reporting/blob/8dea7861fd138a10f4ebea3fd772b997c5e45510/docs/handoffs/2026-10-24-monitor-safety-review/review-and-goal.md). Work started from owning checkpoint `e4da5bdfa9487eac7f18c193c12245716edd1c38`. Reviewed source is **`c0cedf5902e47d1386620ee30479e55fc1ace17a`**, its direct child, on `fix/issue-70-reviewed-cleanup-20261023`. Application/runtime/build source remains unchanged from `9c240298b2feb9c2d5698fcd179296b37d30d78c`; the documentation branch's older runtime was not used.

## Repairs and independent review

1. Both PowerShell termination paths acquire and validate `Process.SafeHandle` before reading `StartTime`, retaining the same Process through Kill/exit checks/Wait. Every acquired Process is disposed exactly once on managed paths. Failed acquisition/invalid/closed handles fail closed without fallback. SafeHandle requests all-access, so access denial can conservatively reduce cleanup success. Forced host termination relies on OS handle closure, not managed disposal.
2. The standalone helper retains root/descendant history and marks accounting incomplete when an observed root disappears or a possible late-born descendant remains unresolved. It never kills a newly inferred historical descendant. History is accounting-only; only current exact-profile roots and descendants linked in that current snapshot form termination records.
3. Canary and final cleanup share the ledger and sticky unconfirmed state. A later empty scan cannot erase a failed first cleanup or permit profile removal. Malformed/wrong-profile state fails before inventory. Even structurally valid historical state cannot grant kill authority.

Two independent read-only reviewers approved the exact final source hashes. Initial review rejected a saved-state kill-authority path; that path was narrowed before qualification. Review also required a test variable rename to avoid the automatic PowerShell PROFILE variable. Fifteen safety scenarios include reuse after StartTime, handle failures, exact-once disposal, late birth, repeated cleanup through the actual AST-extracted finalizer and real fixture profile-removal branch, positive empty absence, and malformed/forged/wrong-profile state. The retained reviewed-head reproduction demonstrated all three original defects with synthetic process adapters; it did not terminate native unrelated processes.

Normal-path native cleanup passed, but late birth, access denial, malformed state and unresolved repeated cleanup were exercised synthetically; no native fault injection proves those transitions.

The historical scan is O(history × inventory) per poll within one smoke run. Deliberately conservative accounting can retain a profile after verified process termination because unseen descendant absence remains unproved. The helper's shared five-second wait/poll budget does not hard-cancel synchronous CIM/Get-Process/Kill calls; the unchanged outer supervisor remains the wall-clock bound.

## Current evidence

All measurements below are producer observations with raw evidence retained locally. Independent review of source/tooling and receipts is distinct from independently rerunning native workloads.

| Check | Result |
|---|---|
| Three original defects on exact reviewed-head source | Reproduced; diagnostic PASS 7.515 s means defects observed, not cleanup accepted |
| JS ownership/handle binding | PASS 115.250 s |
| PowerShell complete diagnostics, all 15 safety cases before cosmetic rename | PASS 75.672 s |
| Final safety regression on final reviewed bytes | PASS 53.078 s |
| Final affected ScriptAnalyzer | PASS 10.531 s; earlier failed analysis preserved |
| Full telemetry, including cleanup/accounting/privacy/real empty-profile inventory | PASS 143.860 s |
| Extracted hosted probe | PASS 0.515 s, 14 virtual-clock cases |
| Native read-only phase diagnostic | PASS 5.016 s total; three inventory calls 1,712.885 / 1,365.973 / 1,429.584 ms |
| Actual standalone dashboard | **FAIL 12.890 s**, dashboard wait-ready timeout; canary ready, both drains complete; process absence confirmed, profile/site removed, no cleanup failures, outer job empty |
| Plain-inventory candidate 20k cold/reload | **PASS 33.437 s**, all 826,434 values per load, cache cold→hit, all five report actions |
| Plain-inventory base 20k cold/reload | **PASS 29.938 s**, same oracle/field digest/cache checks |

Offline checks used the unchanged 180 s / 3 GiB family / 3 GiB physical-free floor. Native cells used 240 s / 2 GiB family / 3 GiB floor, readiness 120 s, inventory 5 s and termination 15 s. Five fresh admission samples exceeded the existing 4.25-GiB small / 5.25-GiB scale thresholds before each cell. Each native cell began and ended with zero matching harness process families. No limit was lowered or resource resized during this work.

The base is `f8a1f2837f56086f20bf6df0b931f36245da6ba0`. Both 20k lanes used retained, hash-verified Dual packages from identical synthetic raw inputs, the common repaired payload, real Chart.js/pako, and the same independently derived raw-field oracle. Each navigation compared 19,677 rows × 42 fields = 826,434 values. All four ordered digests were `1e5fe66de3260dc5223651cc8c110c9eab2019dee9a29a6aa814956dc955d5e2`. Cold loads returned the worker envelope; reloads used one matching IndexedDB entry without another worker return. External requests/page errors were zero. Each profile was removed, server closed, owned process count zero, and outer job verified empty. Full input trees, including the four known diagnostic extras, were pinned before and after both lanes.

These semantic runs retain ordinary dashboard measurement observers but **no inventory phase observer**. The harness serves the manifest-assembled runtime with the established PDF-module difference; generated HTML hash equality is not runtime byte equality. This is one sequential candidate/base correctness pair, not an alternating performance series or a scaling claim.

Candidate outer peak working set/private bytes were 1,636,024,320 / 1,072,082,944; base 1,773,498,368 / 1,161,428,992. Minimum free bytes were 9,003,016,192 / 9,093,197,824. Browser readiness observations were candidate 862.6 / 760.2 ms and base 936.1 / 774.6 ms for cold/reload; these are dashboard-ready observations, not interaction latency or import/packaging time.

**Five-second inventory stability remains unproved.** The maximum candidate ResourceGuard sample host interval was 4,874.966 ms; base maximum was 4,165.942 ms. These intervals include inventory plus subsequent free-memory reading, validation and scheduling. The candidate interval was about 125 ms below five seconds; that is not an isolated inventory-call duration or a proved inventory-timeout margin. Idle phase diagnostics had zero owned processes: startup-to-first-marker 407–471 ms, compilation 422–727 ms, CIM 205–213 ms, selection 63–70 ms, memory 0–1 ms, serialization 6–11 ms, and done-to-completion about 246–256 ms. BEGIN markers and streaming observer overhead are disclosed. These idle observations do not localize the slow under-browser-load call or explain the earlier timeout. No speculative cache, persistent helper or performance optimization was introduced. No unchanged retry followed the standalone failure.

## Acceptance by issue and retained blockers

| Issue | Bounded evidence | Remaining acceptance |
|---|---|---|
| #67 | Prior alternating 20k fresh-import full-store/raw-field parity preserved | Both 120k fresh-import 180 s caps and historical 50k-device / 1.5M-observation envelope remain unqualified |
| #69 | Prior 120k completed-store replay/4,980,486 candidate field comparisons and identical-payload Hosted/Dual packaging preserved | Replay increases +6.61%/+6.69% and later +3.51% remain separate series; diagnostic lookup-writer localization did not justify a production optimization; representative memory/LOH/Automation envelope remains open |
| #70 | Three reviewed cleanup repairs, integrated regressions, and one current plain-inventory base/candidate cold/reload full-field pair passed | Actual standalone readiness failed; inventory is near deadline and historically intermittent; full comparable timing series, 120k native, cache-ineligible and larger worker/historical envelopes remain open |

Fresh raw import, completed-store normalization/replay, PackageOnly packaging and browser reload remain separate evidence categories. Prior base/candidate 120k fresh imports capped at 181.547 / 180.344 s; single completed-store replays passed at 121.234 / 109.187 s. Replay is not fresh import, and censored imports are not performance successes. Prior raw-HTML comparison remains failed; the separate strict review omits only generatedOnUtc and canonicalizes exact-key metadata order. Original payloads, failed/capped/refused/not-run results, prior interrupted profile evidence and all earlier reports remain local and unchanged.

The prior monolithic deterministic preflight caps at 900.438 / 900.375 s remain unpassed and were not repeated for this harness-only repair. Larger native scaling was not started while standalone readiness and inventory-stability gates remained open. Exact-head hosted CI was not run. Hosted CI [39735467316](https://github.com/nathanmcnulty/defender-reporting/actions/runs/39735467316) passed full deterministic preflight and Azure package smoke on original `f341fdd2cf634451a909b69da5ee636dba02fb9f` after the dated receipt; preserve that distinction from capped Windows attempts and from this source revision.

PR #94 remains an unchanged draft at f341fdd2; PR #93 stays separate. Bespoke tests remain; no Pester substitution. No merge, Actions enablement, dependencies installed, tenant data, credentials, live Azure work or publication outside the adopted owning-branch push occurred.

## Reproduce source checks and review boundaries

From this owning source with existing dependencies (install nothing without approval):

```powershell
pwsh -NoProfile -File tests/Invoke-HostedSmokeSafetyRegression.ps1
pwsh -NoProfile -File tests/Invoke-HostedSmokeDiagnosticsRegression.ps1
node tests/Measure-DashboardWorkerTransfer.js --ownership
node tests/Assert-DashboardTelemetry.js
node tests/Assert-DashboardHostedSmokeProbe.js
```

Run them inside the unchanged bounded supervisor; bare commands alone do not provide admission or resource supervision. The local native controller pins exact source, complete base/candidate trees, oracle and guard; it runs one admitted phase cell, one standalone and one cold/reload pair per lane. Any failed phase/resource/cleanup gate stops it. Private operational paths, raw logs/payloads and controller receipts are deliberately not published.

[Source identities](source-identities.json) pin published Git blobs and reviewed working bytes. [Numeric results](results.json) preserve the current pass/fail/not-run matrix, including the non-product launcher setup failure. Public hashes and producer summaries do not independently expose or verify private native evidence. A local report/archive preserves source-review snapshots, rejected reviews/tooling corrections, commands, receipts and the prior sealed evidence bundle. No further resource expansion, live operation or merge is implied by this checkpoint.
