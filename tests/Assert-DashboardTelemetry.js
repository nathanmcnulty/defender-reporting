const assert = require('assert');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

async function main() {
    let currentNow = 0;
    let worker;
    class TestWorker {
        constructor() { worker = this; }
        postMessage() {}
        terminate() { this.terminated = true; }
    }
    const dashboard = loadDashboardHarness(`
module.exports = {
    document,
    window,
    buildDashboardValidationSnapshot,
    getDashboardMetricsSnapshot,
    publishDashboardDiagnostics,
    recordDashboardPhaseTiming,
    recordDashboardRenderTiming,
    markDashboardReady,
    denormalizeInWorker,
    setActiveReportIdForTest(value) {
        activeReportId = value;
    }
};
`, {
    Worker: TestWorker,
    Blob,
    URL: { createObjectURL() { return 'blob:test'; }, revokeObjectURL() {} },
        performance: {
        timeOrigin: 1000,
            now() {
                currentNow += 10;
                return currentNow;
            }
        }
    });

    dashboard.window.dispatchEvent = event => {
        dashboard.window.__lastEvent = event;
    };

    const selector = dashboard.document.getElementById('reportSelector');
    selector.value = 'impact-analysis';
    selector.options = {
        0: { value: 'active-vulnerabilities', textContent: 'Active Vulnerabilities' },
        1: { value: 'remediation-activity', textContent: 'Remediation Activity' },
        2: { value: 'impact-analysis', textContent: 'Impact Analysis' },
        length: 3
    };

    dashboard.document.getElementById('criticalCount').textContent = '12';
    dashboard.document.getElementById('highCount').textContent = '34';
    dashboard.document.getElementById('mediumCount').textContent = '56';
    dashboard.document.getElementById('lowCount').textContent = '78';

    dashboard.setActiveReportIdForTest('impact-analysis');
    dashboard.recordDashboardPhaseTiming('loadDataMs', 123.4567);
    dashboard.recordDashboardPhaseTiming('denormalizeMs', 456.7891);
    dashboard.recordDashboardPhaseTiming('applyFiltersMs', 12.3456);
    dashboard.recordDashboardRenderTiming('impact-analysis', 78.9012);

    const published = dashboard.publishDashboardDiagnostics();
    assert.strictEqual(published.metrics.deliveryMode, 'self-contained');
    assert.strictEqual(published.metrics.activeReportId, 'impact-analysis');
    assert.strictEqual(published.metrics.phases.loadDataMs, 123.457);
    assert.strictEqual(published.metrics.phases.denormalizeMs, 456.789);
    assert.strictEqual(published.metrics.phases.applyFiltersMs, 12.346);
    assert.strictEqual(published.metrics.reports['impact-analysis'].count, 1);
    assert.strictEqual(published.metrics.reports['impact-analysis'].lastMs, 78.901);
    assert.strictEqual(published.validation.activeReportId, 'impact-analysis');
    assert.strictEqual(published.validation.summaryCards.critical, '12');
    assert.strictEqual(published.validation.summaryCards.high, '34');
    assert.strictEqual(published.validation.summaryCards.medium, '56');
    assert.strictEqual(published.validation.summaryCards.low, '78');
    assert.strictEqual(published.validation.reportSelectorOptions.length, 3);
    assert.strictEqual(published.validation.reportSelectorOptions[2].value, 'impact-analysis');

    dashboard.markDashboardReady();

    assert.strictEqual(dashboard.window._dashboardReady, true);
    assert.ok(dashboard.window.dashboardMetrics);
    assert.ok(dashboard.window.dashboardValidation);
    assert.strictEqual(dashboard.window.dashboardMetrics.ready, true);
    assert.strictEqual(dashboard.window.__lastEvent.type, 'dashboard-ready');
    assert.strictEqual(dashboard.window.__lastEvent.detail.metrics.ready, true);
    assert.strictEqual(dashboard.window.__lastEvent.detail.validation.activeReportId, 'impact-analysis');

    const legacy = { rows: [], lookups: {}, rawVulns: {} };
    const legacyOperation = dashboard.denormalizeInWorker();
    worker.onmessage({ data: { phase: 'workerInflateMs', duration: 12.5 } });
    assert(!worker.terminated, 'A phase message must not complete the worker operation.');
    worker.onmessage({ data: { phase: 'workerParseMs', duration: 7.25 } });
    worker.onmessage({ data: legacy });
    assert.strictEqual(await legacyOperation, legacy, 'Legacy worker envelope must remain unchanged.');
    assert(worker.terminated);
    let metrics = dashboard.getDashboardMetricsSnapshot();
    assert.strictEqual(metrics.phases.workerInflateMs, 12.5);
    assert.strictEqual(metrics.phases.workerParseMs, 7.25);
    assert(Number.isFinite(metrics.phases.workerWaitMs));

    const timed = { rows: null, lookups: {}, rawVulns: {}, postedAt: 1000 + currentNow };
    const timedOperation = dashboard.denormalizeInWorker();
    worker.onmessage({ data: timed });
    assert.strictEqual(await timedOperation, timed, 'Timed worker envelope must retain its payload shape.');
    metrics = dashboard.getDashboardMetricsSnapshot();
    assert(metrics.phases.workerDeliveryMs >= 0);

    await require('./Measure-DashboardWorkerTransfer').mockProbes();
}

main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});