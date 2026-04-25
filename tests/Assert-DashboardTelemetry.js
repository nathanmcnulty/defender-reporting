const assert = require('assert');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

function main() {
    let currentNow = 0;
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
    setActiveReportIdForTest(value) {
        activeReportId = value;
    }
};
`, {
        performance: {
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
}

main();