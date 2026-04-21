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
            ls: '2026-01-03',
            ip: '10.0.0.10'
        },
        ...overrides
    };
}

function main() {
    const dashboard = loadDashboardHarness(`
module.exports = {
    applyDerivedVulnerabilityFields,
    buildImpactChartSeries
};
`);
    const rows = [
        createTestRow({
            _index: 0,
            DeviceId: 'device-top25',
            DeviceName: 'device-top25.contoso.com',
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
            DeviceId: 'device-critical',
            DeviceName: 'device-critical.contoso.com',
            CveId: 'CVE-2026-1001',
            VulnerabilitySeverityLevel: 'Critical',
            FirstSeenTimestamp: '2026-01-02',
            LastSeenTimestamp: '2026-01-04',
            MachineInfo: {
                ls: '2026-01-06',
                ip: '10.0.0.11'
            }
        }),
        createTestRow({
            _index: 2,
            DeviceId: 'device-medium',
            DeviceName: 'device-medium.contoso.com',
            CveId: 'CVE-2026-1002',
            VulnerabilitySeverityLevel: 'Medium',
            FirstSeenTimestamp: '2026-01-03',
            LastSeenTimestamp: '2026-01-03',
            MachineInfo: {
                ls: '2026-01-04',
                ip: '10.0.0.12'
            }
        }),
        createTestRow({
            _index: 3,
            DeviceId: 'device-low',
            DeviceName: 'device-low.contoso.com',
            CveId: 'CVE-2026-1003',
            VulnerabilitySeverityLevel: 'Low',
            FirstSeenTimestamp: '2025-12-31',
            LastSeenTimestamp: '2026-01-02',
            MachineInfo: {
                ls: '2026-01-04',
                ip: '10.0.0.13'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(rows);

    const series = dashboard.buildImpactChartSeries(
        rows,
        new Set([0]),
        ['2026-01-01', '2026-01-02', '2026-01-03', '2026-01-04']
    );

    const currentTotalCounts = Array.from(series.currentTotalCounts);
    const projectedTotalCounts = Array.from(series.projectedTotalCounts);
    const currentHigh = Array.from(series.currentSeverityCounts.High);
    const currentCritical = Array.from(series.currentSeverityCounts.Critical);
    const currentMedium = Array.from(series.currentSeverityCounts.Medium);
    const currentLow = Array.from(series.currentSeverityCounts.Low);
    const projectedHigh = Array.from(series.projectedSeverityCounts.High);
    const projectedCritical = Array.from(series.projectedSeverityCounts.Critical);
    const projectedMedium = Array.from(series.projectedSeverityCounts.Medium);
    const projectedLow = Array.from(series.projectedSeverityCounts.Low);

    assert.deepStrictEqual(
        currentTotalCounts,
        [2, 3, 3, 1],
        'Expected current totals to include rows that started before the visible range and to drop rows after their exclusive end date.'
    );

    assert.deepStrictEqual(
        projectedTotalCounts,
        [1, 2, 2, 1],
        'Expected projected totals to exclude the selected top-25 remediation rows while preserving all other active rows.'
    );

    assert.deepStrictEqual(currentHigh, [1, 1, 1, 0]);
    assert.deepStrictEqual(currentCritical, [0, 1, 1, 1]);
    assert.deepStrictEqual(currentMedium, [0, 0, 1, 0]);
    assert.deepStrictEqual(currentLow, [1, 1, 0, 0]);

    assert.deepStrictEqual(projectedHigh, [0, 0, 0, 0]);
    assert.deepStrictEqual(projectedCritical, [0, 1, 1, 1]);
    assert.deepStrictEqual(projectedMedium, [0, 0, 1, 0]);
    assert.deepStrictEqual(projectedLow, [1, 1, 0, 0]);

    console.log('Impact chart series aggregation checks passed.');
}

main();