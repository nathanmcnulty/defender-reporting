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
    createEmptyFilterState,
    applyDerivedVulnerabilityFields,
    matchesFilterState,
    getPointInTimeActiveRows,
    getActiveRowsForCurrentSelection,
    getEffectiveOpenEndDate,
    getEnvironmentFirstSeenDate,
    groupDevicesByCveSignature,
    invalidateAggregateCache,
    setDashboardState(state, rows, latestObservedDate) {
        filterState = state;
        vulnerabilityData = rows;
        filteredData = rows.filter(v => matchesFilterState(v, state));
        mostRecentLastSeenDate = latestObservedDate || '';
        invalidateAggregateCache();
    },
    getFilteredRows() {
        return filteredData;
    }
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
        DeviceId: 'device-001',
        DeviceName: 'device-001.contoso.com',
        RbacGroupName: 'Servers',
        MachineTags: ['Prod'],
        OSPlatform: 'Windows 11',
        VulnerabilitySeverityLevel: 'High',
        CveId: 'CVE-2025-9999',
        SoftwareVendor: 'contoso',
        SoftwareName: 'widget',
        RecommendedSecurityUpdate: 'KB500000',
        RecommendedSecurityUpdateId: '500000',
        FirstSeenTimestamp: '2025-09-15',
        LastSeenTimestamp: '2025-09-20',
        MachineInfo: {
            ls: '2025-09-20',
            ip: '10.0.0.10'
        },
        ...overrides
    };
}

function main() {
    const dashboard = loadDashboardHarness();
    const rows = [
        createTestRow()
    ];

    dashboard.applyDerivedVulnerabilityFields(rows);

    const historicalRangeState = dashboard.createEmptyFilterState();
    historicalRangeState.startDate = '2025-09-01';
    historicalRangeState.endDate = '2025-12-01';
    historicalRangeState.key = 'historical-2025-09-01-to-2025-12-01';

    dashboard.setDashboardState(historicalRangeState, rows, '2025-12-01');

    assert.strictEqual(
        dashboard.getFilteredRows().length,
        1,
        'Expected the historical date filter to retain rows that overlap the selected period.'
    );

    assert.strictEqual(
        dashboard.getPointInTimeActiveRows().length,
        0,
        'Sanity check failed: the end-of-range snapshot should not keep rows that aged out before 2025-12-01.'
    );

    assert.strictEqual(
        dashboard.getActiveRowsForCurrentSelection().length,
        1,
        'Expected historical reports to use rows active anywhere in the selected period instead of only the range end date.'
    );

    const singleDayState = dashboard.createEmptyFilterState();
    singleDayState.startDate = '2025-09-20';
    singleDayState.endDate = '2025-09-20';
    singleDayState.key = 'single-day-2025-09-20';

    dashboard.setDashboardState(singleDayState, rows, '2025-12-01');
    assert.strictEqual(
        dashboard.getActiveRowsForCurrentSelection().length,
        1,
        'Expected a single-day historical selection to still behave like an accurate point-in-time report for that day.'
    );

    const repeatedObservationRows = [
        createTestRow({
            DeviceId: 'device-repeat',
            DeviceName: 'device-repeat.contoso.com',
            CveId: 'CVE-2025-4242',
            FirstSeenTimestamp: '2025-11-27',
            LastSeenTimestamp: '2025-11-27',
            MachineInfo: {
                ls: '2025-11-27',
                ip: '10.0.0.20'
            },
            DiskPaths: ['C:\\Program Files\\Contoso\\agent-old.exe']
        }),
        createTestRow({
            DeviceId: 'device-repeat',
            DeviceName: 'device-repeat.contoso.com',
            CveId: 'CVE-2025-4242',
            FirstSeenTimestamp: '2026-03-22',
            LastSeenTimestamp: '2026-03-24',
            MachineInfo: {
                ls: '2026-03-24',
                ip: '10.0.0.20'
            },
            DiskPaths: ['C:\\Program Files\\Contoso\\agent-new.exe']
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(repeatedObservationRows);
    const grouped = dashboard.groupDevicesByCveSignature(repeatedObservationRows);

    assert.strictEqual(
        grouped.length,
        1,
        'Expected modal grouping to keep a single device group for repeated observations of the same CVE.'
    );

    assert.strictEqual(
        grouped[0].vulns.length,
        1,
        'Expected modal grouping to collapse repeated device+CVE observations into one displayed row.'
    );

    assert.strictEqual(
        grouped[0].vulns[0].FirstSeenTimestamp,
        '2025-11-27',
        'Expected the modal row to preserve the earliest first-seen date across repeated observations.'
    );

    assert.strictEqual(
        grouped[0].vulns[0].LastSeenTimestamp,
        '2026-03-24',
        'Expected the modal row to preserve the latest last-seen date across repeated observations.'
    );

    assert.strictEqual(
        Array.from(grouped[0].vulns[0].DiskPaths).sort().join('|'),
        ['C:\\Program Files\\Contoso\\agent-new.exe', 'C:\\Program Files\\Contoso\\agent-old.exe'].sort().join('|'),
        'Expected the modal row to retain evidence from all matching observation windows.'
    );

    const multiDeviceRows = [
        createTestRow({
            DeviceId: 'device-a',
            DeviceName: 'device-a.contoso.com',
            CveId: 'CVE-2026-1111',
            SoftwareVendor: 'microsoft',
            SoftwareName: 'edge_chromium-based',
            SoftwareVersion: '143.0.3650.96',
            FirstSeenTimestamp: '2026-01-08',
            LastSeenTimestamp: '2026-01-10'
        }),
        createTestRow({
            DeviceId: 'device-b',
            DeviceName: 'device-b.contoso.com',
            CveId: 'CVE-2026-1111',
            SoftwareVendor: 'microsoft',
            SoftwareName: 'edge_chromium-based',
            SoftwareVersion: '143.0.3650.96',
            FirstSeenTimestamp: '2026-01-04',
            LastSeenTimestamp: '2026-01-09'
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(multiDeviceRows);

    assert.strictEqual(
        dashboard.getEnvironmentFirstSeenDate(multiDeviceRows[0]),
        '2026-01-04',
        'Expected the dashboard to derive the earliest environment-first-seen date across devices for the same issue.'
    );

    assert.strictEqual(
        dashboard.getEnvironmentFirstSeenDate(multiDeviceRows[1]),
        '2026-01-04',
        'Expected every row for the same issue to share the same environment-first-seen date.'
    );

    assert.strictEqual(
        multiDeviceRows[0].FirstSeenTimestamp,
        '2026-01-08',
        'Expected the underlying per-device first-seen timestamp to remain unchanged.'
    );
}

main();
