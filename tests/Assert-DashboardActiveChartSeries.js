const assert = require('assert');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

function createTestRow(overrides = {}) {
    return {
        _index: 0,
        DeviceId: 'device-001',
        DeviceName: 'device-001.contoso.com',
        RbacGroupName: 'Servers',
        MachineTags: ['Prod'],
        OSPlatform: 'Windows 11',
        VulnerabilitySeverityLevel: 'High',
        CveId: 'CVE-2026-0001',
        SoftwareVendor: 'contoso',
        SoftwareName: 'widget',
        RecommendedSecurityUpdate: 'KB500000',
        RecommendedSecurityUpdateId: '500000',
        FirstSeenTimestamp: '2026-01-01',
        LastSeenTimestamp: '2026-01-03',
        MachineInfo: {
            ls: '2026-01-05',
            ip: '10.0.0.10'
        },
        ...overrides
    };
}

function main() {
    const dashboard = loadDashboardHarness(`
module.exports = {
    applyDerivedVulnerabilityFields,
    buildActiveChartSeries
};
`);
    const rows = [
        createTestRow({
            _index: 0,
            DeviceId: 'device-a',
            DeviceName: 'device-a.contoso.com',
            CveId: 'CVE-2026-1000',
            VulnerabilitySeverityLevel: 'High',
            FirstSeenTimestamp: '2026-01-01',
            LastSeenTimestamp: '2026-01-03',
            MachineInfo: {
                ls: '2026-01-05',
                ip: '10.0.0.10'
            }
        }),
        createTestRow({
            _index: 1,
            DeviceId: 'device-a',
            DeviceName: 'device-a.contoso.com',
            CveId: 'CVE-2026-1001',
            VulnerabilitySeverityLevel: 'Medium',
            FirstSeenTimestamp: '2026-01-02',
            LastSeenTimestamp: '2026-01-02',
            MachineInfo: {
                ls: '2026-01-03',
                ip: '10.0.0.10'
            }
        }),
        createTestRow({
            _index: 2,
            DeviceId: 'device-b',
            DeviceName: 'device-b.contoso.com',
            CveId: 'CVE-2026-1002',
            VulnerabilitySeverityLevel: 'Critical',
            FirstSeenTimestamp: '2025-12-31',
            LastSeenTimestamp: '2026-01-01',
            MachineInfo: {
                ls: '2026-01-02',
                ip: '10.0.0.11'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(rows);

    const series = dashboard.buildActiveChartSeries(rows, '2026-01-01', '2026-01-04');

    assert.deepStrictEqual(
        Array.from(series.sortedDates),
        ['2026-01-01', '2026-01-02', '2026-01-03', '2026-01-04']
    );

    assert.deepStrictEqual(
        Array.from(series.totalCounts),
        [2, 2, 1, 0],
        'Expected total counts to include rows that started before the visible range and to drop rows after their exclusive end date.'
    );

    assert.deepStrictEqual(
        Array.from(series.deviceCounts),
        [2, 1, 1, 0],
        'Expected device counts to represent unique active devices even when multiple rows are active for the same device.'
    );

    assert.deepStrictEqual(Array.from(series.severityCounts.Critical), [1, 0, 0, 0]);
    assert.deepStrictEqual(Array.from(series.severityCounts.High), [1, 1, 1, 0]);
    assert.deepStrictEqual(Array.from(series.severityCounts.Medium), [0, 1, 0, 0]);
    assert.deepStrictEqual(Array.from(series.severityCounts.Low), [0, 0, 0, 0]);

    console.log('Active chart series aggregation checks passed.');
}

main();