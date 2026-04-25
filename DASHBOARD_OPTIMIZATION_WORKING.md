# Dashboard Optimization Working Plan

Last updated: 2026-04-25
Status: Item 1 completed and validated; large-result modal stability, devices-by-remediation density, and impact-analysis data-path slices implemented; deterministic preflight, large-dataset artifact replay, live dry run, Edge inspection, and final large-dataset semantic replay all passed

## Goals

- Reduce large-dataset dashboard time-to-usable and report-switch latency for both hosted and self-contained packaging.
- Preserve dashboard semantics and visible structure across all five report modes.
- Capture repeatable validation and perf evidence after every implementation slice.

## Review Outcomes Applied

- Item 1 now explicitly owns the telemetry contract and the first round of browser-level invariant validation.
- Item ordering has been adjusted so worker-oriented filter preparation happens before generator-side precomputed aggregates, and card virtualization happens after those data-shape changes settle.
- Success criteria now use explicit outputs or measurable targets instead of qualitative language only.
- Validation gates now distinguish between always-on checks and the new checks that Item 1 must add before later slices proceed.

## Baseline

Dataset baseline:

- 50,000 devices
- 1,500,000 vulnerability rows
- 3,097 CVEs

Browser baseline from Edge local artifact profiling:

| Metric | Hosted split-assets | Self-contained |
| --- | ---: | ---: |
| Init total | 3.97 s | 3.57 s |
| LCP | 11.10 s | 5.88 s |
| Long-task total | 9.55 s | 9.31 s |
| Max long task | 3.46 s | 3.53 s |
| JS heap used | 679.45 MB | 679.42 MB |
| DOM nodes | 997,558 | 997,562 |
| Devices by remediation first open | 4.42 s | 4.38 s |
| Remediations by device first open | 1.91 s | 1.75 s |

## Invariants To Preserve

The dashboard is not considered valid after a change unless these remain present and functional:

- Main heading, report selector, and Export to PDF button.
- Summary cards for Critical, High, Medium, and Low counts.
- Filter bar controls for Date, Device Groups, Device Tags, Platform, Severity, Device, and Clear All.
- Report selector options for Active Vulnerabilities, Remediation Activity, Impact Analysis, Devices by Remediation, and Remediations by Device.
- Active Vulnerabilities table with Vendor, Software, Remediation, Update Details, Assets, Vulnerabilities, Exploits, and Kits columns.
- Remediation Activity report chart and details table.
- Impact Analysis chart and table.
- Devices by Remediation card view.
- Remediations by Device card view.

## Validation Gate After Every Item

From Item 2 onward, every slice must pass the iterative gate below before the next change starts. The expensive semantic replay now moves to milestone or pre-commit local sign-off instead of every small slice.

1. Deterministic preflight:

   `pwsh -NoProfile -File .\build\Invoke-RegressionValidation.ps1`

2. Targeted dashboard regression scripts relevant to the touched slice.

3. Large-dataset packaging and artifact-parity replay:

   `pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-50k-1_5m -Validate -ValidationMode artifacts`

4. Performance regression comparison against a checked-in baseline for the large dataset.

5. Dual-package asset and parity checks when packaging or browser-runtime assets are touched.

6. Browser invariant validation against both hosted and self-contained generated outputs.

7. Manual visual verification only when the slice changes CSS, layout, or report presentation.

8. Record outcome, validation status, and metric deltas in this document before starting the next slice.

Milestone or pre-commit local sign-off:

- `pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-50k-1_5m -Validate -ValidationMode semantic`

## Item 1 Telemetry Contract

Item 1 must establish the minimum client-side observability contract used by later work:

- `window.dashboardMetrics` object with numeric millisecond values for `loadDataMs`, `denormalizeMs`, `applyFiltersMs`, `initTotalMs`, and per-report render timings.
- `window.dashboardValidation` object with the current `activeReportId`, summary-card values, available report ids, and a compact element/invariant snapshot.
- `dashboard-ready` browser event fired after initialization and first filter application settle.
- No reliance on console output as the only machine-readable perf source after Item 1.

## Implementation Order

### Item 1: Structured telemetry and validation foundation

Status: Completed

Objective:

- Emit structured client-side timings and readiness markers instead of relying only on console timers.
- Add repo-local automated checks for invariant elements, browser readiness, and package-asset correctness.

Why first:

- Later performance changes need better measurements, parity checks, and repeatable page verification.

Likely files:

- `templates/dashboard.js`
- `tests/helpers/dashboard-test-harness.js`
- `tests/` validation entrypoints
- optional `build/` validation helpers if asset checks fit better there

Success criteria:

- Generated dashboards expose `window.dashboardMetrics` and `window.dashboardValidation` using the contract above.
- Hosted and self-contained generated outputs can be checked automatically for invariant elements.
- Asset-path validation exists for split-assets output.
- This item adds the automated checks required before Item 2 can begin.

### Priority Insert: Large-result remediation modal stability fallback

Status: In progress

Objective:

- Prevent large remediation detail drills from locking the browser when the grouped modal layout degenerates into thousands of per-device sections.
- Preserve modal semantics while switching large result sets to a dense virtualized layout.

Why inserted here:

- Live Edge repro on the hosted dashboard showed the Windows 11 April 2026 remediation row taking about 229 seconds to open.
- The modal path created 16,594 tables, 16,594 device-bubble groups, and about 3.25 million DOM nodes for that single interaction.

Likely files:

- `templates/dashboard.js`
- `tests/Assert-DashboardModalResponsiveness.js`

Success criteria:

- Large remediation detail sets stop building one virtualized table per CVE-signature group.
- The same Edge repro opens the modal in under 1 second on the local hosted artifact built from the live payload snapshot.
- Deterministic regression validation passes with the new modal fallback path.

### Priority Insert: Devices-by-remediation card density guard

Status: In progress

Objective:

- Prevent the devices-by-remediation report from inflating the DOM by rendering every device row for the largest remediation cards.
- Preserve access to the full device list in both hosted and self-contained packaging without regressing PDF export.

Why inserted here:

- After the modal fix, Edge profiling still showed the devices-by-remediation report adding about 972,329 DOM nodes and 64,924 table rows across the first 20 cards.
- The worst card was still trying to materialize more than 11,000 device rows inside a single remediation card.

Likely files:

- `templates/dashboard.js`
- `templates/dashboard.css`

Success criteria:

- Oversized devices-by-remediation cards render bounded virtualized device tables during normal interactive browsing.
- The regenerated hosted and self-contained artifacts both keep the report under 10,000 added DOM nodes on the first 20 cards.
- PDF export still forces a full-row render path before capture.

### Item 2: Explicit empty states and layout-stability guards

Status: Planned

Objective:

- Make zero-result or filtered-empty reports unambiguous.
- Reserve space or otherwise reduce avoidable layout shift in heavy sections.

Likely files:

- `templates/dashboard.html`
- `templates/dashboard.css`
- `templates/dashboard.js`

Success criteria:

- Every report can distinguish between loading, empty result, and rendered result states.
- No heavy report section appears blank without explanatory copy.
- Layout-shift score improves versus the current large-dataset baseline in both package modes.

### Item 3: Move filter and report preparation further off the main thread

Status: Planned

Objective:

- Shift expensive filtering, grouping, and report-preparation work away from the UI thread where possible.
- Reduce long tasks during initialization and report switching.

Likely files:

- `templates/dashboard.js`
- any new worker-side helper assets required by the current packaging model

Success criteria:

- Large-dataset long-task total falls below 7 seconds in local Edge profiling.
- Largest single long task falls below 2.5 seconds.
- Switching between reports remains semantically identical under validation.

### Item 4: Precompute browser-ready aggregates during generation

Status: Planned

Objective:

- Push more normalization and aggregate shaping into generation so the browser consumes prepared structures instead of rebuilding them at load time.

Likely files:

- `src/powershell/Shared/Dashboard/DashboardGeneration.ps1`
- `Generate-VulnerabilityDashboard.ps1`
- `templates/dashboard.js`

Success criteria:

- Large-dataset denormalization time drops by at least 40 percent from the current baseline.
- Cache versioning or invalidation is updated so old normalized artifacts cannot be misread as the new payload shape.
- Browser payload remains semantically equivalent under validation.

### Item 5: Card-report virtualization and DOM reduction

Status: Planned

Objective:

- Replace the current batch-only strategy with true viewport-aware virtualization for card-heavy reports.
- Reduce live DOM node count and first-open latency for Devices by Remediation and Remediations by Device.

Likely files:

- `templates/dashboard.js`
- `templates/dashboard.css`
- targeted dashboard tests

Success criteria:

- Devices by Remediation first-open time falls below 1.5 seconds on the large dataset.
- Remediations by Device first-open time falls below 1.0 second on the large dataset.
- Live DOM node count falls below 300,000 after both card reports have been visited.

### Item 6: Repeatable hosted profiling lane

Status: Planned

Objective:

- Turn the ad hoc Edge profiling work into a supported repo workflow for hosted and local artifacts.
- Allow future optimization work to compare like-for-like runs without rebuilding temporary tools.

Likely files:

- `tests/` profiling entrypoints
- optional helper scripts under `build/` or `tests/manual/`
- documentation if needed

Success criteria:

- The repo contains a documented, repeatable profiling path for hosted and self-contained artifacts.
- Hosted profiling explicitly documents the auth or session prerequisite instead of failing opaquely.

   - confirm the invariant element checklist above
   - switch across all five reports
   - confirm the dashboard reaches ready state
   - compare summary-card counts against the baseline dataset expectations for the run

6. Record outcome, validation status, and any metric deltas in this document before starting the next slice.

## Implementation Order

### Item 1: Structured telemetry and repeatable browser validation

Status: Planned

Objective:

- Emit structured client-side timings and readiness markers instead of relying only on console timers.
- Add a repo-local validation harness that can assert the required dashboard elements on generated hosted and self-contained artifacts.

Why first:

- Later performance changes need better measurements and a stable page-check lane.

Likely files:

- `templates/dashboard.js`
- `tests/helpers/dashboard-test-harness.js`
- `tests/` browser or validation entrypoints

Success criteria:

- Generated dashboard exposes structured telemetry for init, load, denormalization, filter application, and report rendering.
- A repeatable validation script can verify core elements across both packaging modes.

### Item 2: Explicit empty states and layout-stability guards

Status: Planned

Objective:

- Make zero-result or filtered-empty reports unambiguous.
- Reserve space or otherwise reduce avoidable layout shift in heavy sections.

Likely files:

- `templates/dashboard.html`
- `templates/dashboard.css`
- `templates/dashboard.js`

Success criteria:

- Empty reports explain whether the filter window or dataset produced zero rows.
- Layout shift drops measurably during first load and report switching.

### Item 3: Card-report virtualization and DOM reduction

Status: Planned

Objective:

- Replace the current batch-only strategy with true viewport-aware virtualization for card-heavy reports.
- Reduce live DOM node count and first-open latency for Devices by Remediation and Remediations by Device.

Likely files:

- `templates/dashboard.js`
- `templates/dashboard.css`
- targeted dashboard tests

Success criteria:

- Card-report first-open time improves materially.
- Live DOM node count drops substantially from the current baseline.

### Item 4: Move filter and report preparation further off the main thread

Status: Planned

Objective:

- Shift expensive filtering, grouping, and report-preparation work away from the UI thread where possible.
- Reduce long tasks during initialization and report switching.

Likely files:

- `templates/dashboard.js`
- any new worker-side helper assets required by the current packaging model

Success criteria:

- Long-task total and max long task improve on the large dataset.
- Switching between reports remains semantically identical.

### Item 5: Precompute browser-ready aggregates during generation

Status: Planned

Objective:

- Push more normalization and aggregate shaping into generation so the browser consumes prepared structures instead of rebuilding them at load time.

Likely files:

- `src/powershell/Shared/Dashboard/DashboardGeneration.ps1`
- `Generate-VulnerabilityDashboard.ps1`
- `templates/dashboard.js`

Success criteria:

- Init-time denormalization cost drops measurably.
- Browser payload remains semantically equivalent under validation.

### Item 6: Repeatable hosted profiling lane

Status: Planned

Objective:

- Turn the ad hoc Edge profiling work into a supported repo workflow for hosted and local artifacts.
- Allow future optimization work to compare like-for-like runs without rebuilding temporary tools.

Likely files:

- `tests/` profiling entrypoints
- optional helper scripts under `build/` or `tests/manual/`
- documentation if needed

Success criteria:

- The repo contains a documented, repeatable profiling path for hosted and self-contained artifacts.
- Hosted profiling explicitly documents the auth/session prerequisite instead of failing opaquely.

## Progress Log

| Item | Status | Notes |
| --- | --- | --- |
| Plan draft | Complete | Initial plan created from current dashboard profiling and repo validation entrypoints. |
| Agent review | Complete | Incorporated review feedback on sequencing, telemetry contract, and validation gaps. |
| Validation workflow tightening | Complete | `tests/Invoke-LargeDatasetValidation.ps1` now supports `-ValidationMode artifacts` for iterative dual-package artifact parity checks; the 50k-device, 1.5M-row replay completed in about 71 seconds and `-ValidationMode semantic` remains available for final local sign-off. |
| Item 1 | Complete | Added `window.dashboardMetrics`, `window.dashboardValidation`, and `dashboard-ready`; added `tests/Assert-DashboardTelemetry.js`; added `tests/Validate-DashboardGeneratedArtifacts.js`; fixture smoke generation now validates hosted and self-contained outputs. |
| Priority insert: modal stability | Complete | Large-result remediation details now switch to a dense virtualized layout instead of creating one grouped section per device-signature bucket; focused harness tests, deterministic preflight, iterative large-dataset artifact replay, live dry run, Edge inspection, and final 50k-device semantic sign-off all passed. |
| Priority insert: devices-by-remediation density | Complete | Oversized remediation cards now render virtualized device tables during interactive browsing and temporarily force full rows for PDF export; deterministic preflight, large-dataset artifact replay, Edge parity checks, and final semantic sign-off all passed. |
| Priority insert: impact-analysis data-path reuse | Complete | Impact-analysis now reuses per-row formatted software, split eligibility, and raw remediation keys across its ranking passes; deterministic preflight, live dry run, Edge report sweeps, and final semantic sign-off all passed. |
| Item 2 | Pending | Empty-state and layout-stability work paused until the modal stability slice clears the full validation gate. |
| Item 3 | Pending | Not started. |
| Item 4 | Pending | Not started. |
| Item 5 | Pending | Not started. |
| Item 6 | Pending | Not started. |

## Validation History

### Item 1

Status: Passed

Checks run:

- `node .\tests\Assert-DashboardTelemetry.js`
- fixture Dual-package generation plus `node .\tests\Validate-DashboardGeneratedArtifacts.js <self> <hosted>`
- `pwsh -NoProfile -File .\build\Invoke-RegressionValidation.ps1`

Outcome:

- telemetry contract validated through the existing Node harness
- generated hosted and self-contained outputs validated for invariant elements and hosted asset references
- full deterministic repo preflight passed, including the new dual-package fixture validation

### Priority insert: modal stability

Status: In progress

Checks run:

- `node .\tests\Assert-DashboardModalResponsiveness.js`
- `node .\tests\Assert-DashboardRemediationViews.js`
- `pwsh -NoProfile -File .\build\Invoke-RegressionValidation.ps1`
- Edge + Playwright repro against `http://127.0.0.1:41731/VulnerabilityDashboard.Hosted.html` after refreshing `VulnerabilityDashboard.Hosted.assets\dashboard.js`
- `pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-50k-1_5m -Validate -ValidationMode artifacts`

Outcome so far:

- the modal no longer builds 16,594 grouped tables for the Windows 11 April 2026 row
- local Edge repro dropped from about 228.9 s modal-ready latency to about 127.8 ms
- `attachVirtualTables` dropped from 151,490 ms across 16,594 tables to 13.3 ms across 2 tables
- local repro DOM node delta dropped from about 3,253,939 nodes to 1,556 nodes
- iterative 50k-device, 1.5M-row large-dataset replay rebuilt and validated hosted plus self-contained artifacts in about 71.09 seconds without invoking the full semantic audit
- 2026-04-25 live dry run generated and validated a fresh dashboard from current exports in about 89 seconds total, and Edge inspection confirmed all five reports render with the updated telemetry and modal helpers

### Priority insert: devices-by-remediation density

Status: In progress

Checks run:

- `node .\tests\Assert-DashboardModalResponsiveness.js`
- `node .\tests\Assert-DashboardRemediationViews.js`
- `pwsh -NoProfile -File .\build\Invoke-RegressionValidation.ps1`
- `pwsh -NoProfile -File .\Generate-VulnerabilityDashboard.ps1 -DirectoryPath .\.local\large-datasets\synthetic-50k-1_5m -OutputPath .\.local\live-dashboard\2026-04-24-dual-run\VulnerabilityDashboard.html -HostedOutputPath .\.local\live-dashboard\2026-04-24-dual-run\VulnerabilityDashboard.Hosted.html -DualPackage -PackageOnly -ExportMachineData:$false`
- Edge + Playwright report and modal parity checks against regenerated hosted and self-contained outputs

Outcome so far:

- devices-by-remediation no longer materializes the full device list for oversized cards during interactive browsing
- hosted devices-by-remediation first open dropped from about 972,329 added DOM nodes and 64,924 rendered rows to about 8,876 nodes and 500 rows on the first 20 cards
- self-contained devices-by-remediation matched the hosted density guard with about 8,876 nodes, 500 rows, and 20 virtualized tables on the regenerated artifact
- hosted modal open on the regenerated dual-package artifact stayed fast at about 67 ms modal-ready latency, and self-contained matched at about 71 ms

### Priority insert: impact-analysis data-path reuse

Status: In progress

Checks run:

- `pwsh -NoProfile -File .\Generate-VulnerabilityDashboard.ps1 -DirectoryPath .\.local\large-datasets\synthetic-50k-1_5m -OutputPath .\.local\live-dashboard\2026-04-24-dual-run\VulnerabilityDashboard.html -HostedOutputPath .\.local\live-dashboard\2026-04-24-dual-run\VulnerabilityDashboard.Hosted.html -DualPackage -PackageOnly -ExportMachineData:$false`
- self-contained Edge helper timing pass against regenerated `VulnerabilityDashboard.html`
- self-contained Edge full report sweep against regenerated `VulnerabilityDashboard.html`
- `pwsh -NoProfile -File .\build\Invoke-RegressionValidation.ps1`

Outcome so far:

- `getImpactAnalysisData()` on the regenerated self-contained artifact dropped from about 3284.9 ms to about 2178.7 ms for the 3-month large-dataset window
- self-contained impact-analysis report render dropped from about 2855.1 ms to about 2449.2 ms in the consistent full report sweep
- self-contained impact-analysis report switch dropped from about 4397 ms to about 3998 ms in the same sweep order
- deterministic regression validation completed successfully after the change

### Current sign-off state

Status: Passed

Checks completed on 2026-04-25:

- `pwsh -NoProfile -File .\tests\Run-SharedHelperRegression.ps1`
- `pwsh -NoProfile -File .\build\Invoke-RegressionValidation.ps1`
- `pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-50k-1_5m -Validate -ValidationMode artifacts`
- `pwsh -NoProfile -File .\build\Invoke-LiveDashboardDryRun.ps1 -UseExistingAzContext`
- Edge inspection against `.local\local-reports\live-dashboard-dry-run\VulnerabilityDashboard.html`
- Edge inspection against `C:\Users\NathanMcNulty\AppData\Local\Temp\stress-dashboard-cf0ea392fb3b44cf9041d6d0ac3ba241.html`

Remaining check:

- none

Final semantic replay result:

- `pwsh -NoProfile -File .\tests\Invoke-LargeDatasetValidation.ps1 -SkipSyntheticGeneration -SyntheticOutputPath .\.local\large-datasets\synthetic-50k-1_5m -Validate -ValidationMode semantic`
- completed successfully on 2026-04-25
- row parity matched: 1,500,000 expected / 1,500,000 actual
- payload byte parity matched cached payload
- total audit time: about 10,852 seconds
- stress validation elapsed time: about 10,966 seconds