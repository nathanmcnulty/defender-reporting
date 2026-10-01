const assert = require('assert');
const { loadDashboardHarness, createDocumentStub, createStubElement } = require('./helpers/dashboard-test-harness');

async function assertExportLifecycle() {
    const reports = ['active-vulnerabilities', 'remediation-activity', 'impact-analysis',
        'devices-by-remediation', 'remediations-by-device'];
    const expansionStates = [false, true].flatMap(expanded =>
        [false, true].map(forceFull => ({ expanded, forceFull })));
    for (const report of reports) {
        for (const { expanded, forceFull } of expansionStates) {
            for (const failure of ['preparation', 'libraries', 'confirmation', 'expansion', 'generation',
                'filters', 'createPdf', 'download', 'download-rejection', 'download-timeout', 'restoration', 'cancel', null]) {
                if (expanded && failure === 'expansion' && report !== 'devices-by-remediation') continue;
                const document = createDocumentStub();
                const button = createStubElement({ textContent: 'Original export label' });
                const progress = createStubElement({ remove() { this.removed = true; } });
                const classes = new Set();
                document.querySelector = () => button;
                document.createElement = () => progress;
                document.body.classList = { add(value) { classes.add(value); }, remove(value) { classes.delete(value); } };
                Object.assign(document.getElementById('reportSelector'), {
                    value: report, selectedIndex: 0, options: [{ text: 'Current Report' }]
                });
                const hooks = {
                    failure,
                    phase: 'expansion',
                    statuses: [],
                    downloads: 0,
                    run(stage) { if (this.failure === stage) throw new Error(`Injected ${stage}`); }
                };
                const dashboard = loadDashboardHarness(`
remediationExpanded = remediationDetailsExpanded = impactAnalysisExpanded = devicesByRemediationExpanded = remediationsByDeviceExpanded = ${expanded};
forceFullDevicesByRemediationRows = ${forceFull};
loadPdfLibraries = async () => testHooks.run('libraries');
renderReport = () => testHooks.run('preparation');
maybeConfirmLargePdfExport = async () => { testHooks.run('confirmation'); return testHooks.failure !== 'cancel'; };
const originalRestore = restoreReportState;
restoreReportState = (...args) => {
    testHooks.phase = 'restoration';
    originalRestore(...args);
    testHooks.run('restoration');
};
renderRemediationTablePage = renderRemediationDetailsTablePage = renderImpactAnalysisTablePage = renderDevicesByRemediationTablePage = renderRemediationsByDeviceTablePage = () => testHooks.run(testHooks.phase);
exportCardBasedReportToPdf = exportTableBasedReportToPdf = async () => { testHooks.run('generation'); return { content: [] }; };
getExportFilterText = () => { testHooks.run('filters'); return 'All'; };
setDashboardStatus = (message, kind) => testHooks.statuses.push({ message, kind });
clearDashboardStatus = () => testHooks.statuses.push({ message: 'complete' });
module.exports = {
    exportToPDF,
    state: () => [remediationExpanded, remediationDetailsExpanded, impactAnalysisExpanded,
        devicesByRemediationExpanded, remediationsByDeviceExpanded, forceFullDevicesByRemediationRows]
};
`, {
                    document,
                    testHooks: hooks,
                    console: { ...console, error() {} },
                    setTimeout(callback, delay) {
                        if (delay === 100 || delay === 1500 || delay === 3000) { queueMicrotask(callback); return 0; }
                        if (delay === 300000 && hooks.failure === 'download-timeout') { queueMicrotask(callback); return 0; }
                        return setTimeout(callback, delay);
                    },
                    pdfMake: {
                        createPdf() {
                            hooks.run('createPdf');
                            return {
                                download(filename, callback) {
                                    hooks.run('download');
                                    assert.ok(filename.endsWith('.pdf'));
                                    assert.strictEqual(typeof callback, 'function', 'pdfmake 0.2.7 requires a completion callback, not an awaited return value.');
                                    assert.strictEqual(button.disabled, true, 'UI must remain busy until download completes.');
                                    assert.ok(classes.has('pdf-export-active'));
                                    assert.ok(!hooks.statuses.some(status => status.message === 'complete'));
                                    if (hooks.failure === 'download-rejection') return Promise.reject(new Error('Injected download-rejection'));
                                    if (hooks.failure === 'download-timeout') return undefined;
                                    queueMicrotask(() => { hooks.downloads++; callback(); });
                                    return undefined;
                                }
                            };
                        }
                    }
                });
                const previousState = Array.from(dashboard.state());
                await dashboard.exportToPDF();
                assert.deepStrictEqual(Array.from(dashboard.state()), previousState, `${report}/${failure}: expansion state must be restored.`);
                assert.strictEqual(button.disabled, false, `${report}/${failure}: button must be enabled.`);
                assert.strictEqual(button.textContent, 'Original export label');
                assert.strictEqual(progress.removed, true, `${report}/${failure}: progress must be removed.`);
                assert.strictEqual(classes.size, 0);
                if (failure && failure !== 'cancel') {
                    assert.ok(hooks.statuses.some(status => status.kind === 'error'), `${failure}: failure must be visible.`);
                }
                if (failure === null) assert.strictEqual(hooks.downloads, 1);
                if (failure === 'cancel') assert.strictEqual(hooks.downloads, 0);
                hooks.failure = null;
                hooks.phase = 'expansion';
                hooks.statuses.length = 0;
                progress.removed = false;
                const previousDownloads = hooks.downloads;
                await dashboard.exportToPDF();
                assert.strictEqual(hooks.downloads, previousDownloads + 1, 'Retry must complete a download.');
                assert.strictEqual(progress.removed, true, 'Retry must clean up.');
                assert.strictEqual(button.disabled, false);
                assert.deepStrictEqual(Array.from(dashboard.state()), previousState);
            }
        }
    }
}

async function main() {
    const dashboard = loadDashboardHarness(`
devicesByRemediationAllData = [{
    deviceCount: 3000,
    cveCount: 50,
    devices: new Map(),
    cveDetails: new Map()
}];
remediationsByDeviceAllData = [{
    remediationCount: 240,
    cveCount: 20,
    remediations: new Map()
}];

module.exports = {
    estimateCardBasedPdfPageCount,
    estimatePdfPageCount,
    maybeConfirmLargePdfExport,
    window,
    getForceFullDevicesByRemediationRows: () => forceFullDevicesByRemediationRows
};
`);

    const devicePageEstimate = dashboard.estimatePdfPageCount('devices-by-remediation');
    assert.ok(devicePageEstimate > 100, 'Expected data-based device export estimate to exceed warning threshold.');
    assert.strictEqual(
        dashboard.getForceFullDevicesByRemediationRows(),
        false,
        'Page estimation should not disable card virtualization.'
    );

    let confirmCalls = 0;
    dashboard.window.confirm = message => {
        confirmCalls++;
        assert.ok(message.includes('Devices by Remediation'));
        return false;
    };

    const shouldContinue = await dashboard.maybeConfirmLargePdfExport('devices-by-remediation', 'Devices by Remediation');
    assert.strictEqual(shouldContinue, false, 'Expected preflight cancellation to be honored.');
    assert.strictEqual(confirmCalls, 1, 'Expected exactly one pre-expansion warning prompt.');
    assert.strictEqual(
        dashboard.getForceFullDevicesByRemediationRows(),
        false,
        'Preflight warning should happen before export expansion disables virtualization.'
    );

    const remediationPageEstimate = dashboard.estimateCardBasedPdfPageCount('remediations-by-device');
    assert.ok(remediationPageEstimate > 20, 'Expected remediations-by-device estimate to be data based.');

    await assertExportLifecycle();
    console.log('Dashboard PDF export preflight and lifecycle assertions passed.');
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});