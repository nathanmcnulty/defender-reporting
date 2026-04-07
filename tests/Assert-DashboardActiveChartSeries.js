const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function createStubElement() {
    return {
        textContent: '',
        innerHTML: '',
        value: '',
        checked: false,
        disabled: false,
        style: {},
        dataset: {},
        classList: {
            add() {},
            remove() {},
            contains() { return false; }
        },
        appendChild() {},
        removeChild() {},
        remove() {},
        setAttribute() {},
        getAttribute() { return null; },
        addEventListener() {},
        removeEventListener() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
        closest() { return null; },
        focus() {},
        click() {},
        getBoundingClientRect() {
            return { top: 0, bottom: 0, left: 0, width: 0, height: 0 };
        }
    };
}

function createDocumentStub() {
    const elements = new Map();

    function getOrCreateElement(id) {
        if (!elements.has(id)) {
            const element = createStubElement();
            if (id === 'dataFormat') {
                element.textContent = 'normalized';
            }
            elements.set(id, element);
        }

        return elements.get(id);
    }

    return {
        body: {
            classList: {
                add() {},
                remove() {}
            },
            appendChild() {}
        },
        getElementById(id) {
            return getOrCreateElement(id);
        },
        querySelector() {
            return null;
        },
        querySelectorAll() {
            return [];
        },
        createElement() {
            return createStubElement();
        },
        createDocumentFragment() {
            return createStubElement();
        },
        addEventListener() {},
        removeEventListener() {}
    };
}

function loadDashboardHarness() {
    const dashboardPath = path.join(__dirname, '..', 'templates', 'dashboard.js');
    const dashboardSource = fs.readFileSync(dashboardPath, 'utf8');
    const exportSource = `
module.exports = {
    applyDerivedVulnerabilityFields,
    buildActiveChartSeries
};
`;

    const sandbox = {
        console,
        require,
        module: { exports: {} },
        exports: {},
        document: createDocumentStub(),
        window: {
            addEventListener() {},
            removeEventListener() {},
            innerHeight: 1080,
            innerWidth: 1920
        },
        navigator: {
            clipboard: {
                writeText: async () => {}
            }
        },
        performance: {
            now() { return 0; }
        },
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
        alert() {},
        confirm() { return true; }
    };

    vm.runInNewContext(`${dashboardSource}\n${exportSource}`, sandbox, { filename: dashboardPath });
    return sandbox.module.exports;
}

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
    const dashboard = loadDashboardHarness();
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