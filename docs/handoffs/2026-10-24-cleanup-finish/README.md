# Bounded cleanup finishing checkpoint — 2026-10-24

The cleanup-accounting defect reviewed against `5fdd5de9a2b0a048dea1235313472d4e5041c7b2` is repaired and independently reviewed. This checkpoint also includes the previously reviewed singleton-array/payload-cache-v8 product repair so the source matches the qualified synthetic candidate. PR #93 and issue #92 remain separate. No merge, live Azure action, workflow dispatch, dependency installation or sign-in was performed. Operational reports, process inventories and raw datasets remain local.

Runtime: Windows `Microsoft Windows 10.0.28000`, PowerShell `7.6.6`, `.NET 10.0.12`, Node `v26.7.0`, Edge `155.0.4283.62`. Installed ScriptAnalyzer and Az.Accounts inventories are retained in the local runtime receipt; no dependency was installed.

## Repair

Termination returns every identity selected in its full snapshot, including descendants first discovered there. JavaScript validates and retains those identity tuples until final inventory verifies their absence or their own PID reuse. Inventory accounts for same-identity survivors and their descendants independently of root disappearance or root PID reuse. This conservative accounting is enabled only for inventory; it never authorizes termination. Fresh root/profile/creation/handle checks, neighbor exclusions, deadlines and resource guards remain unchanged. A failed termination permanently marks that owner instance's accounting incomplete, preventing a later false zero and profile deletion.

Integrated Windows regressions execute the real PowerShell selection, termination and final inventory with mocked process APIs: new-child orphan, known child/root reuse, actual disappearance, own-PID reuse, uncertain identity, orphan descendants and failure after partial termination. Survivors/uncertainty retain the profile; absence/reuse permits success; unverified child handles/kills and neighbor kills are rejected. The pinned historical diagnostic still reproduces the prior false pass. The new integrated test fails against old source and passes against this repair.

The product repair preserves singleton arrays while serializing normalized lookup content, invalidates stale normalized payload caches with v8, and includes the generated runbook and discriminating regressions. No production performance optimization is asserted.

## Validation matrix

The monolithic preflight was TIME-CAPPED after 900.438 s during dashboard telemetry, with verified empty-job cleanup. Parser, ScriptAnalyzer, shared-helper, hosted diagnostics, scheduling/artifact and atomic-publication regressions had completed. The same 13 JavaScript assertion files, invoked with the tighter `--max-old-space-size=256` setting, then PASSED in 122.750 s, and the exact remaining fixture-generation/validation block PASSED in 6.532 s under separate 180-second/3-GiB/3-GiB-free jobs. Thus preflight components completed in bounded partitions; same-session state continuity and the single-command 900-second gate remain unproved. The monolithic command is capped, not passed. Windows mock suite: PASS in 116.203 s. Native checks below use real cached Chart.js/pako and installed Edge/Playwright. All accepted child jobs verified empty cleanup.

| Check | Result | Elapsed | Exit / bound |
|---|---|---:|---|
| finish24-regression-before | EXPECTED FAIL | 4.531 s | exit 1 |
| finish24-release | PASS | 14.047 s | exit 0 |
| finish24-browser-build | PASS | 9.531 s | exit 0 |
| finish24-neighbor-before | PASS | 1.515 s | exit 0 |
| finish24-hosted-smoke | FAILED | 16.297 s | exit 1 |
| finish24-native-control | PASS | 32.750 s | exit 0 |
| finish24-native20k-base | FAILED | 10.438 s | free-memory floor |

The passing two-row native cold/reload control runs the checked-in repaired harness. It proves the exercised lifecycle/readiness/cache behavior, not full report-field parity. The attempted larger probe transplants the exact reviewed ownership/cleanup functions into the previously reviewed timing/full-field probes; their runtime helper and payload hashes are pinned. Cold and actual eligible IndexedDB reloads are separate. Renderer heap and sampled process-family memory are separate metrics. A digest/count is not full-field proof. Prior bound-oracle 20k cold/reload field checks retain their exact application runtime/payload correspondence, but ran with the earlier cleanup harness. Their field evidence is retained separately; their cleanup success cannot validate this repair. The final-harness 20k full-field rerun was NOT RUN after the floor breach. The passing native control recorded zero identity-skip attempts; incomplete-identity branches were exercised by fault tests, not observed again natively.

Larger native lane: NOT RUN: escalation stopped after the 20k baseline breached the unchanged 3-GiB free-memory floor. No comparable final-harness 20k or 120k timing series was completed.

The 20k baseline was stopped after 10.438 seconds with minimum sampled physical free memory 3,082,629,120 bytes (below 3 GiB); outer Job Object cleanup verified zero survivors. No final browser detail/cleanup receipt was produced before termination, so the interrupted cell is not native cleanup acceptance. Its temporary profile remains retained locally; profile removal is not claimed for that cell. Older temporary profiles were left untouched. The independent final inventory found zero owned profile processes. It observed 0 unrelated Edge identities before/after; with none present, native neighbor preservation was not exercised (the integrated mocks cover it). The separate standalone dump-DOM hosted smoke FAILED with dashboard-probe-failure / wait-ready / readiness-timeout; its canary passed and its process/profile/site cleanup was confirmed. Its source is unchanged from the prior baseline; the current Playwright control passed. The standalone smoke cause remains unproved; virtual-time/dump-DOM scheduling is a hypothesis, not a demonstrated application regression. No production runtime change or timeout increase was made to conceal the failure. Failed/capped attempts remain evidence, not passing or censored measurements. Expanded caching is ineligible at 500,000 rows; that production cutoff is unchanged.

Native two-row observations (one cold/reload pair; descriptive, not a performance baseline):

| Navigation | Readiness ms | Main-renderer heap bytes | Edge-family WS bytes | Edge-family private bytes |
|---|---:|---:|---:|---:|
| first | 507.7 | 5610788 | 891072512 | 381124608 |
| reload | 270.3 | 8713564 | 960241664 | 410505216 |

Payload SHA-256 `40dec7f73e6c1695793f648f690ebf088fa461a1d59b54e0855143cd61a95c76`; runtime SHA-256 `6cc494fe2e99e614cdf8c782f1ceb680620765df401678e416a9ca82ec9f0bd2`. Real Chart.js SHA-256 `74401d738dd3e03ee5dfb3b6841210fe2c4ead8a960c4011ca4ba0b78a9fd8f3`; pako SHA-256 `ede2693a4a6a5126b9d35669062b358ecab6ae7b9b86a1cf302feb45a8514907`. Both loads used one matching two-row IndexedDB entry; cold returned one worker envelope, eligible reload returned none. All browser/resource error and remote-request counts were zero. Profile removal, server closure and zero owned survivors passed.

## Performance evidence and open gates

The six alternating 20k fresh-import controls and twelve alternating 120k Hosted/Dual packaging cells are retained after rechecking their relevant source, inputs and artifacts. Fresh import remains separate from completed-store replay. Packaging uses one identical normalized payload/manifest and templates in independent roots. The original raw HTML comparison failed on generatedOnUtc; the retained independent artifact review omits only that validated field and verifies every remaining byte/asset. It is not silently relabeled an exact-HTML pass.

The previous replay preparation series measured +6.61%/+6.69%; a later uninstrumented series measured +3.51%. Diagnostic traces localized their own extra time/allocation to lookup serialization, without proving the cause of the historical timing delta. No baseline refresh or performance fix is claimed.

| Issue | Bounded evidence | Remaining acceptance |
|---|---|---|
| #67 | Prior 20k fresh-import store/content/row parity retained with exact source/input correspondence | Both prior 120k fresh imports hit the unchanged 180-second bound; no unchanged retry. Historical 50k-device/1.5M-observation and Automation below-400-MB gates remain open. |
| #69 | Prior 120k same-input Hosted/Dual packaging and artifact review retained; replay remains separate | Historical artifact/LOH envelope, attribution of prior +6.6% phase delta, and authorized Automation/Function qualification remain open. |
| #70 | Repaired integrated cleanup controls and passing two-row native cold/reload; prior field evidence retained separately | Any bounded failure above, representative historical worker/cache-ineligible scale, and applicable live/platform gates remain open. |

## Reproduction and limits

Use existing dependencies only. The inner commands below require an owned-process supervisor with fail-closed memory sampling, deadlines and verified descendant cleanup. New full preflight used the existing 900-second/3-GiB family budget and a 3-GiB free-memory floor. Offline focused/build/package children used 180 seconds/3 GiB/3 GiB free; native children used 240 seconds/2 GiB/3 GiB free. Inner Edge-family WS cap is 2 GiB; readiness is 120 seconds; inventory is 5 seconds. No guard was relaxed. Older receipt budgets remain distinct.

```powershell
node --check tests/Measure-DashboardWorkerTransfer.js
node tests/Measure-DashboardWorkerTransfer.js --mock
pwsh -NoProfile -File build/Invoke-RegressionValidation.ps1
pwsh -NoProfile -File build/Build-AzureReleasePackage.ps1 -OutputPath <fresh-local-zip>
# Extract that ZIP; run its publisher with -StorageAccountName validationstorageaccount
# -TemplatesPath <extracted-templates> -WhatIf only.
$env:PLAYWRIGHT_MODULE = '<existing-installed-module>'
node tests/Measure-DashboardWorkerTransfer.js <two-row-hosted-directory> <fresh-local-receipt> 1 2 --positive-control
```

Attempted/not-run full-field/scale probes and exact argument arrays, timings, GC/allocation and sampled-memory observations are retained privately. No operational logs or raw inputs are published here. Source identities below bind this sanitized checkpoint to the tested files; Git's LF-normalized blobs distinguish them from Windows working-byte hashes. The final pushed commit is returned by the owner session.

| File | Git blob | Working SHA-256 |
|---|---|---|
| `azure/Invoke-DashboardPipeline.ps1` | `2efb5cbdf5496ad179dcde7b2b0724846821e51b` | `a59488abe3d81e79d1c01c7896e15602d736bbe50ade0b80b0971d1e6c3d758e` |
| `src/powershell/Shared/Dashboard/DashboardGeneration.ps1` | `88d6a38f15c7a6a3eab55fc78b7e5f68e4ba7065` | `aba21ddbdcfa5cfdd844532af314aeff9e770c303dd075e502732248a5b6df4d` |
| `tests/Run-SharedHelperRegression.ps1` | `f80bed96c38fe2b5229d68e64e1f2838bd7cc5cc` | `9b1f57b43adb231e195cc9de37d1cabd6c432b5fa54e909207b917f4c7c0957f` |
| `tests/Measure-DashboardWorkerTransfer.js` | `818f87d7be51be7b984e445da70089544c31c182` | `427ee2d7a2b1712bd0ef9af8effebfcc0a1a1cfed1a847ab906b9e5ebc9dad88` |
| `tests/README.md` | `121d408168ebef12565abc2e9868ae73b0dcfad5` | `7092ec42629230ceb747a386267bc34a245ebc2787bd60597c915bf9b29b3db4` |

Independent source review receipt SHA-256: `fab41ecb16ac3ddda003670c7dfd459b129d371b40d1309c4da57e6308d4409b`. Preflight receipt SHA-256: `f05961598207a9b6f7f2b8c893d1f59d4b6ed6138e29648dbf4c5a15fe418acb`. Final local audit SHA-256: `6a3853733bf6292ba0f011412e0776b46782f8181b24ed8fca5d36aa2cf2bf8e`. Hosted run 39735467316 passed at original f341 after the dated receipt; it is separate from the earlier capped Windows attempt and is not exact-head CI for this repair. No workflow was dispatched for this checkpoint.
