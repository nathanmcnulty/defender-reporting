const assert = require('assert');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

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

    console.log('Dashboard PDF export preflight assertions passed.');
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});