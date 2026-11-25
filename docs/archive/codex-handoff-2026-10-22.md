# Standalone defender-reporting: next-session goal

Qualify the bounded candidate for issues #67, #69 and #70 using synthetic inputs. Keep this repository separate from azd-defender-reporting. See the companion [validation receipt](codex-validation-receipt-2026-10-22.md) for original-session results and evidence limits.

## Base, candidate and review

The candidate is based on pinned `main` revision `f8a1f2837f56086f20bf6df0b931f36245da6ba0`. The next session must use the exact candidate revision supplied with the PR or handoff, verify its ancestry, and read current repository instructions before continuing. The original validation session used a clean isolated checkout with local uncommitted candidate edits; that is historical session state, not a requirement or claim about the published candidate. Preserve unrelated work.

Current main already includes later dashboard loading, memory and lifecycle integration. Read `docs/dashboard-performance-review.md`, `docs/performance-gate-playbook.md` and `build/README.md`. Their historical measurements are not new candidate measurements. Diagnostic PR #82 is merged as ancestor `8317b76550aa0b73d544e1d7a983adeeeec6c477`, not proof of a performance fix. Runtime draft #93 was inspected separately at `e18bb9bdcc01e456daa5e5519f2655b3f538f7d1`, based on this same main; it was not applied. Reconcile it explicitly before any future integration.

Astra completed exact-source review with no blocking findings for these patch SHA-256 values:

- Correctness: `5457f8bd02d4fe235958da3aa4163b875ddaf795a871f91115985df725d3ab36`.
- Streaming: `02be4e47dce37346e72b84bf5e719b37a0844f703c860302e65b3e5cd59bac98`.

That review covers the bounded source candidate, not merge/deployment approval or large-scale qualification. The six reviewed source/test files remain unchanged. Generated-artifact derivation and the final publication set require separate review.

The correctness slice retains scalar tags/paths in compiled content projection, fixes date-regex escaping in generated worker code, preserves worker-produced AffectedSoftware during later materialization, and bumps derived cache schema from 2 to 3. Tests check field contents, scalar/array/null/missing/whitespace behavior, generated-worker dates, materialization and a cached-reload model. Worker timeout and the 500,000-row cache cutoff are unchanged.

Browser cache invalidation cannot restore scalar values already lost in previously generated content sidecars. Those sidecars need normal, separately authorized regeneration from canonical inputs; a browser reload does not repair stored content.

The independent streaming slice changes only Split-VulnJsonPartition and Read-VulnPartitionMapFile to use the established pipeline reader. Tests discriminate eager collection from streaming and cover row text/order, filtering, duplicate last-wins behavior, gzip/plain input, long Unicode lines and error cleanup. Other eager history/reassembly readers and raw-store/content-sidecar recovery remain follow-up hypotheses.

## Portable prerequisites and generated artifacts

Use existing PowerShell, Node, Git and PSScriptAnalyzer. Release packaging additionally needs installed Az.Accounts. Native acceptance needs installed Edge, a resolvable installed Playwright module for the worker harness, and real Chart.js/pako libraries. Discover paths on the new machine. Stop if dependencies are missing; do not install or download them without authorization.

`build/README.md` requires generated artifacts and fingerprints refreshed after shared-source changes. The required local builds were rerun, and the tracked runbook change is retained. Ignored shared-helper/Function outputs were regenerated but are not proposed Git content. The publisher-only churn is omitted: all three inputs and both builder dependencies matched checked-out base bytes, and an isolated build of those base inputs on the same Windows machine exactly reproduced the new publisher. Its substantive text equals the committed publisher after CR normalization and removal of only the fingerprint line. The unchanged baseline publisher is therefore retained; no candidate publisher dependency is hidden. The final included diff passes whitespace checks.

Shared/runbook/publisher fingerprints use raw input bytes and platform-dependent newline construction. The manifests' raw Windows SHA-256 values and markers establish same-checkout derivation, not cross-platform identity: Git LF normalization or Ubuntu regeneration may change them. Before publication, separately verify actual candidate Git blob IDs or normalized content against the final publication manifest. On another platform, rebuild before checking locally computed fingerprints; do not require raw Windows hashes to survive checkout conversion.

On a fresh checkout, regenerate ignored outputs before using them; do not run stale generated entrypoints. The earlier transient release ZIP smoke applies only to that rebuilt ZIP, not to the temporarily restored loose runbook. Final loose-artifact parity and the complete preflight remain distinct gates.

## Finite next-session checks

Before running the command block, the receiving session must select and record an appropriate bounded owned-process supervisor for its machine and authority, including time/memory limits, fail-closed sampling and cleanup. The commands below are inner operations to run under that supervision, not a substitute for it. Run them from the repository root and execute focused tests in separate processes; the original session's external supervisor is not checked in.

```powershell
pwsh -NoProfile -File build/Build-SharedHelpers.ps1
pwsh -NoProfile -File build/azure/Build-Runbook.ps1
pwsh -NoProfile -File build/azure/Build-FunctionApp.ps1 -SkipModuleStaging
pwsh -NoProfile -File build/azure/Build-TemplatePublisher.ps1
pwsh -NoProfile -File tests/Run-SharedHelperRegression.ps1 -TestName Test-CompiledContentStringArrayRoundTrip
pwsh -NoProfile -File tests/Run-SharedHelperRegression.ps1 -TestName Test-VulnPartitionStreamingParity
pwsh -NoProfile -File tests/Run-SharedHelperRegression.ps1 -TestName Test-CompiledBoundedContentNormalizationExpandedParity
pwsh -NoProfile -File tests/Run-SharedHelperRegression.ps1 -TestName Test-BulkSnapshotFreshImportProfilerParityAndGuards
pwsh -NoProfile -File tests/Run-SharedHelperRegression.ps1 -TestName Test-DashboardSplitAssetsGenerationAndValidation
pwsh -NoProfile -File tests/Run-SharedHelperRegression.ps1 -TestName Test-DashboardDualPackagingGenerationAndValidation
Get-ChildItem tests/Assert-Dashboard*.js | Sort-Object Name | ForEach-Object {
    & node --max-old-space-size=256 $_.FullName
    if ($LASTEXITCODE -ne 0) { throw "Dashboard assertion failed: $($_.Name)" }
}
pwsh -NoProfile -File build/Invoke-RegressionValidation.ps1
pwsh -NoProfile -File build/Build-AzureReleasePackage.ps1
```

Resolve the ZIP path from the new build, extract into a fresh directory, and run the extracted publisher with `-StorageAccountName validationstorageaccount -TemplatesPath <actual-extracted-templates> -WhatIf` only. No release ZIP or extraction tree is included with the source candidate. Do not invoke deployment or live publication.

Full preflight remains open: the original session selected an external 1 GiB family cap and 4 GiB free-memory floor, and that capped attempt stopped before completion. These are session-specific supervision settings, distinct from checked-in benchmark guards. The dedicated VM should plan and record an appropriate bounded full-preflight memory/time budget for its resources; merely repeating the known-failing 1 GiB cap is not an acceptance strategy. Investigate retained suite state or split execution where useful, while preserving repository safety floors and benchmark guards. Do not treat focused passes as the whole gate or compare results across different budgets as equivalent. The checked-in `tests/Invoke-WithPwshMemoryGuard.ps1` provides a Windows available-memory guard, but not the original external time/family-cap contract.

## Recreate bounded measurements before scaling

Session-local measurement wrappers, fixtures and logs are excluded from publication and cannot be executed from Git. First recreate a supervisor/fixture harness with fresh owned destinations, synthetic inputs only, no downloads/network calls, sequential lanes, captured commands/source/runtime/payload hashes and authoritative counts, fail-closed process-family sampling, explicit memory/time limits and verified cleanup of only owned processes. The original session selected a 4 GiB free-memory floor, 1 GiB family cap, and 300-second focused/180-second tiny baseline and release/600-second preflight limits. Preserve those historical budgets with their results; choose and record an appropriate bounded budget for the receiving machine rather than treating them as repository requirements. Do not silently lower repository safety floors or weaken benchmark guards, and do not directly compare measurements from different budgets. Approval is needed only for actions outside the receiving session's actual authority or material resource/cost scope, not automatically for adjusting a temporary supervisor setting. Preserve failed evidence.

For #67, use the existing `tests/Invoke-LargeImportCoverage.ps1` ProfileFreshImport lane after preparing explicit procedural raw/live/snapshot directories and manifests. Recreate a tiny two-snapshot, 20-device, 200-row reference first; do not launch its large defaults to get a result. Compare fresh store digests and authoritative IDs, then base/candidate on identical inputs with at least three alternating bounded runs. Keep completed-store normalization separate from fresh import. A checked-in reader-probe check is:

```powershell
pwsh -NoProfile -File tests/Invoke-LargeImportCoverage.ps1 -TestCompiledPartitionReaderParity
```

For #69, recreate one normalized payload/manifest with `Generate-VulnerabilityDashboard.ps1 -NormalizeOnly`, then compare `-PackageOnly -NormalizedPayloadInputPath ... -NormalizedPayloadManifestInputPath ...` using either `-SplitAssets` or `-DualPackage`, identical templates and independent output roots. Alternate at least three runs per lane. Capture stage time, working set/private bytes, GC/allocation observations and semantic/summary/hash parity. Main already streams base64 and templated HTML; do not reapply the obsolete ReadAllBytes hypothesis.

For #70, generate a tiny hosted control from `tests/fixtures/legacy-migration` with existing real libraries; placeholder regression libraries cannot establish browser behavior. After full preflight, use the following checked-in entrypoints, resolving variables to newly generated artifacts and installed tools:

```powershell
pwsh -NoProfile -File tests/Invoke-HostedDashboardRuntimeSmoke.ps1 -DashboardPath $hostedHtml -EdgePath $edgeExecutable -DiagnosticsPath $freshDiagnostics
$env:PLAYWRIGHT_MODULE = $existingPlaywrightModule
node tests/Measure-DashboardWorkerTransfer.js $hostedDirectory $freshEvidencePath 1 2 --positive-control
```

The expected count of 2 applies only to the independently verified two-row control. Use the authoritative count and appropriate mode for later workloads. Preserve the worker harness's current 3 GiB free-memory floor, 2 GiB Edge-family cap and 120-second readiness bound. Measure first load versus an actual eligible IndexedDB hit, worker phases/fallback, readiness, renderer heap and worker-inclusive memory. At 500,000 rows and above, label reload expanded-cache-ineligible.

## Acceptance and stopping conditions

Require content semantics as well as row/count parity, zero new browser errors/remote requests, successful cleanup, regenerated artifact parity and completed full preflight. Investigate comparable time/peak-memory regressions above 10%, retaining the playbook's separate 5% hot-phase threshold. Tiny synthetic and Node-thread tests do not qualify real-library Edge, large scale or Azure behavior. Live Azure acceptance needs separate authorization.

Stop on resource/time/cap breaches, failed sampling, missing dependencies/assets, malformed input/parity failure, uncertain process ownership/cleanup, or an authorization boundary. Do not push, open PRs, merge, deploy, enable Actions, sign in, access Azure/Graph/XDR, change permissions, install dependencies or use tenant datasets while approval is pending. Keep retention/disclosure #68 separate; containment #71 and synthetic replacement #72 are merged. Do not purge history or repeat containment.
