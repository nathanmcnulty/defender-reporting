const assert = require('assert');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

function createDetail(index, overrides = {}) {
    const suffix = String(index).padStart(4, '0');

    return {
        DeviceId: `device-${suffix}`,
        DeviceName: `device-${suffix}.contoso.com`,
        CveId: `CVE-2026-${suffix}`,
        SoftwareVersion: `10.0.${index}`,
        VulnerabilitySeverityLevel: 'High',
        CvssScore: 7.1,
        EpssScore: 0.00042,
        ExploitabilityLevel: 'ExploitIsNotPubliclyKnown',
        PublishedDate: '2026-04-14',
        FirstSeenTimestamp: '2026-04-15',
        LastSeenTimestamp: '2026-04-16',
        MachineInfo: {
            ip: `10.0.0.${(index % 250) + 1}`,
            ls: '2026-04-16'
        },
        ...overrides
    };
}

function main() {
    const dashboard = loadDashboardHarness(`
module.exports = {
    buildDetailsModalSections,
    buildRemediationDetailsModalSections
};
`);

    const groupedDetails = [
        createDetail(1, { DeviceId: 'device-a', DeviceName: 'device-a.contoso.com', CveId: 'CVE-2026-1001' }),
        createDetail(2, { DeviceId: 'device-a', DeviceName: 'device-a.contoso.com', CveId: 'CVE-2026-1002' }),
        createDetail(3, { DeviceId: 'device-b', DeviceName: 'device-b.contoso.com', CveId: 'CVE-2026-1001' })
    ];

    const groupedResult = dashboard.buildDetailsModalSections({
        modalTitle: 'Small grouped remediation',
        details: groupedDetails,
        devices: new Set(groupedDetails.map(detail => detail.DeviceId)),
        vulnerabilities: new Set(groupedDetails.map(detail => detail.CveId)),
        updateEntries: []
    });

    assert.strictEqual(groupedResult.layoutMode, 'grouped');
    assert.ok(Object.keys(groupedResult.vtRowData).length >= 1);

    const mediumDetails = Array.from({ length: 600 }, (_, index) => createDetail(index + 1));
    const mediumResult = dashboard.buildDetailsModalSections({
        modalTitle: 'Medium remediation set',
        details: mediumDetails,
        devices: new Set(mediumDetails.map(detail => detail.DeviceId)),
        vulnerabilities: new Set(mediumDetails.map(detail => detail.CveId)),
        updateEntries: []
    });

    assert.strictEqual(
        mediumResult.layoutMode,
        'grouped',
        'Expected moderate remediation modal sizes to retain the grouped layout instead of defaulting to dense mode.'
    );

    const denseDetails = Array.from({ length: 2600 }, (_, index) => createDetail(index + 1));
    const denseResult = dashboard.buildDetailsModalSections({
        modalTitle: 'Windows 11: April 2026 Security Updates',
        details: denseDetails,
        devices: new Set(denseDetails.map(detail => detail.DeviceId)),
        vulnerabilities: new Set(denseDetails.map(detail => detail.CveId)),
        updateEntries: []
    });

    assert.strictEqual(denseResult.layoutMode, 'dense');
    assert.deepStrictEqual(Object.keys(denseResult.vtRowData).sort(), ['det_dense_details', 'det_dense_devices']);
    assert.strictEqual(denseResult.vtRowData.det_dense_devices.items.length, 2600);
    assert.strictEqual(denseResult.vtRowData.det_dense_details.items.length, 2600);
    assert.ok(denseResult.parts.join('').includes('virtualized flat view'));

    const sampleDeviceRow = denseResult.vtRowData.det_dense_devices.rowBuilder(denseResult.vtRowData.det_dense_devices.items[0]);
    assert.ok(sampleDeviceRow.includes('device-0001.contoso.com'));

    const sampleDetailRow = denseResult.vtRowData.det_dense_details.rowBuilder(denseResult.vtRowData.det_dense_details.items[0]);
    assert.ok(sampleDetailRow.includes('device-0001.contoso.com'));
    assert.ok(sampleDetailRow.includes('CVE-2026-0001'));

    const denseRemediationResult = dashboard.buildRemediationDetailsModalSections({
        date: '2026-04-16',
        remediation: 'Windows 11: April 2026 Security Updates',
        details: denseDetails,
        devices: new Set(denseDetails.map(detail => detail.DeviceId)),
        vulnerabilities: new Set(denseDetails.map(detail => detail.CveId)),
        updateEntries: []
    });

    assert.strictEqual(denseRemediationResult.layoutMode, 'dense');
    assert.deepStrictEqual(Object.keys(denseRemediationResult.vtRowData).sort(), ['rem_dense_details', 'rem_dense_devices']);
    assert.strictEqual(denseRemediationResult.vtRowData.rem_dense_devices.items.length, 2600);
    assert.strictEqual(denseRemediationResult.vtRowData.rem_dense_details.items.length, 2600);
    assert.ok(denseRemediationResult.parts.join('').includes('virtualized flat view'));

    const sampleRemediationRow = denseRemediationResult.vtRowData.rem_dense_details.rowBuilder(denseRemediationResult.vtRowData.rem_dense_details.items[0]);
    assert.ok(sampleRemediationRow.includes('device-0001.contoso.com'));
    assert.ok(sampleRemediationRow.includes('CVE-2026-0001'));

    console.log('Dashboard modal responsiveness assertions passed.');
}

main();