# Roadmap

The goal is a simple, clean, efficient vulnerability-reporting experience for admins. An admin should be able to deploy the pipeline in their own Azure environment, open a self-contained HTML report or use the hosted dashboard, narrow the view to the question they need to answer, and export that view to PDF.

This is a priority order, not a release schedule. Finish the current work and its review before starting the next improvement. There are no target dates or commitments to a framework rewrite.

## What stays

- Self-contained HTML, hosted split assets, and Dual packaging remain supported. The hosted app should not become a requirement for opening an offline report.
- Filtering and flexible reporting are core features. PDF export should use the selected report and page filters, including the date window.
- Keep the optimized pipeline and existing data contracts unless evidence supports a focused change. A working pipeline does not need a new architecture to improve the dashboard.
- The owner's public lab data and CI-generated demo PDFs are intentional demonstrations. That does not make another admin's tenant data public by default.
- Keep deployment, routine operation, and troubleshooting understandable without requiring admins to learn the repository's internal test machinery.

## 1. Finish current work and review the baseline

**Outcome:** A clear starting point with completed work, verified defects, and remaining acceptance gates recorded separately.

- Finish and reconcile in-flight work before adding features. Review the exact resulting revision rather than treating an older report or an unmerged branch as current behavior.
- Complete separate pipeline and dashboard reviews. Open issues for reproducible defects with the affected revision, expected and actual behavior, and a bounded reproduction. Review topics remain questions until verified.
- Reconcile the existing performance issues [#67](https://github.com/nathanmcnulty/defender-reporting/issues/67), [#69](https://github.com/nathanmcnulty/defender-reporting/issues/69), and [#70](https://github.com/nathanmcnulty/defender-reporting/issues/70) against the latest evidence. Keep fresh import, completed-store replay, packaging, and browser work separate.
- Finish the remaining hosted runtime acceptance tracked in [#92](https://github.com/nathanmcnulty/defender-reporting/issues/92). Offline checks and package validation do not establish live Azure behavior.
- Resolve the owner-demo publication work in [PR #98](https://github.com/nathanmcnulty/defender-reporting/pull/98), then align the current setup and workflow documentation with the accepted behavior. Do not treat the intentional demo as an accidental disclosure or extend its publishing exception to other public forks.

**Completion check:** Each current item has a verified result or an explicit remaining gate. Merging, deploying, and running live acceptance remain separate decisions. New review findings are pending at the time of this roadmap; none are asserted here.

## 2. Make the hosted dashboard feel fast

**Outcome:** Admins can load a dashboard, change filters, switch reports, and open details without unexplained pauses.

The hosted app is the main improvement area. Start with measurements of the current implementation, then change the slowest meaningful part.

- Record cold and warm loading, first completed report, filter-to-result time, report switching, detail opening, PDF preparation, and browser memory on representative small and large datasets.
- Separate transfer, decompression, worker messaging, row materialization, filtering, aggregation, and rendering. A worker timeout or a slow page is a starting observation, not proof of one cause.
- Prefer small changes that avoid repeated scans, unnecessary row expansion, duplicate allocations, or excessive DOM work. Keep optional PDF libraries off the initial load path.
- Show useful loading, empty-result, failure, and retry states. Rapid filter changes, report switches, and cancelled work should not leave stale results or a stuck interface.
- Reuse the existing browser checks and performance guidance rather than introducing a second benchmark system.

**Completion check:** A proposed change has comparable before/after measurements, unchanged report semantics, no new browser errors, and working self-contained and hosted outputs. Set specific latency targets after measuring the current baseline. Existing regression thresholds in the [performance gate playbook](performance-gate-playbook.md) remain the review bar, not a promise that every dashboard loads within one universal time.

## 3. Make filtering and PDF output predictable

**Outcome:** An admin can tell exactly which devices and vulnerabilities a report covers, and produce a readable PDF of that scope.

- Review the existing filter behavior against common tasks: scope to a group or tag, find a device, focus on severity or platform, compare a date window, and identify remediation work.
- Make selected filters, reset actions, date semantics, and no-result states easy to understand. Preserve the difference between current activity, historical overlap, and remediation evidence.
- Revisit the [filter interaction options](filter-redesign-spikes.md) using the current code and measured interaction cost. Choose the simpler model when a more complex one has no clear usability benefit.
- Keep one consistent report/filter state across the page, hosted view links, and PDF export. Verify all five existing report families, including the device/remediation views.
- Expand PDF checks around filtered content and totals, long tables, charts, pagination, and readable headings. Exercise cancellation, failure, retry, and restoration of the original page state.
- Keep CI-generated demo PDFs useful as examples of the real export path. Validate them against a known demo scope, and distinguish demo generation from regression tests using deterministic synthetic fixtures.
- Keep remediation claims within the available evidence. Advisory and patch-reference summaries can improve without claiming a latest or minimum sufficient patch that the data does not establish. See the [remediation data boundary](remediation-rollup-spike.md).

**Completion check:** The same known filter state produces matching report scope and totals in the browser and exported PDF. Export does not silently reset filters or leave the page changed, and the PDFs remain readable beyond a small happy-path example.

## 4. Simplify deployment and routine operation

**Outcome:** An admin can choose a delivery mode, deploy it, confirm that it works, and diagnose a failed refresh with a short, clear path.

- Make the setup guide lead with the choices an admin actually needs: their Azure environment, self-contained versus hosted delivery, and the supported runtime.
- Explain the required permissions, expected resources and costs, refresh schedule, output locations, and how to confirm the first successful run.
- Make last successful refresh, source freshness, missing optional enrichment, and failure state understandable. Treat missing data differently from a healthy report with no findings.
- Document update, rollback, and retry procedures using the existing pipeline controls. Preserve transactional publication so a failed refresh does not replace a good dashboard with a partial result.
- Keep private tenant output separate from the explicitly approved public demo. A private repository alone does not secure a separately public hosting or storage destination.
- Use separately approved live Azure checks to validate the documented path, including repeat deployment and failure recovery. Preserve the existing performance and memory limits when testing.

**Completion check:** A fresh deployment walkthrough reaches the expected report using the documented steps, and an admin can identify and recover from a failed refresh without guessing which outputs are trustworthy. Mark untested deployment options clearly.

## Later decisions

These are options to evaluate after the work above, not selected implementations.

- **Dashboard framework:** React is an option if a small, measured comparison shows a worthwhile improvement in maintainability or interaction design. It is not a prerequisite for performance work. Any migration must preserve filtering, PDF behavior, offline HTML, hosted packaging, and the existing data contract.
- **Larger pipeline changes:** Keep the [current pipeline architecture decision](pipeline-architecture-review.md). Consider sharding or new resumability machinery only when measured limits or a concrete operational requirement justify it.
- **Richer remediation guidance:** Add patch lineage or minimum/latest-fix claims only with a reliable supporting data source.
- **Azure deployment wrapper:** Review the separate wrapper after the standalone pipeline and dashboard work is settled. Keep wrapper changes out of this roadmap's initial implementation work.

## Keeping this useful

The [November 6 reliability reconciliation](reliability-review-2026-11-06.md)
starts from main after #105, records the distinct #99–#104 correctness gaps,
preserves #98's demo/fork-protection ownership, and separates accepted full-scale
PackageOnly evidence from the remaining #67/#69 import/replay and #92 live gates.
Its source checks do not close those acceptance gates.

Use issues for concrete work and this document for order and product direction. Link verified review findings as they arrive; do not turn every idea into a promised feature. Update the roadmap when a decision or accepted result changes the next useful step.

Planning snapshot: current main `69e5cfd53e5f1e6c8b762c86cb5b3967b3359e98`, open issues #67/#68/#69/#70/#92, and draft PR #98. The [October import/Dual measurements](import-dual-measurements-2026-10-28.md), [dashboard review](dashboard-performance-review.md), and [test guide](../tests/README.md) provide context with their own evidence limits. Older observations are not current performance guarantees, and this roadmap does not close any issue.
