const assert = require('assert');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

async function main() {
    const dashboard = loadDashboardHarness(`
lookups = {
    devices: [{ id: 'device-1', n: 'Device 1', g: 0, o: 0, ov: '10.0', t: [], m: { ls: '2026-03-26' } }],
    cves: [{ id: 'CVE-2026-0001', sc: 7.5, sv: 0, ex: -1, u: null, bt: -1, pd: '2026-03-01', ep: null, ea: false, nbs: null, nsv: null, nvec: null, nkev: null, ndu: null, nact: null, nw: [], as: [] }],
    software: [{ v: 0, n: 'Widget App', r: null }],
    groups: ['Engineering'],
    platforms: ['Windows'],
    tags: [],
    versions: ['1.0.0'],
    dates: ['2026-03-01', '2026-03-26'],
    updates: [{ n: 'Security Update', id: '5000001', url: 'https://example.com/update' }],
    vendors: ['Contoso'],
    severities: ['High'],
    exploitLevels: [],
    batchTitles: ['Security Update'],
    affSoftware: [],
    inventory: [],
    diskPaths: [],
    regPaths: []
};
rawVulns = {
    d: [0, 0, 0, 0, 0, 0],
    c: [0, 0, 0, 0, 0, 0],
    s: [0, 0, 0, 0, 0, 0],
    v: [0, 0, 0, 0, 0, 0],
    f: [0, 0, 0, 0, 0, 0],
    l: [1, 1, 1, 1, 1, 1],
    ua: [1, 1, 1, 1, 1, 1],
    u: [0, 0, 0, 0, 0, 0],
    dp: [[], [], [], [], [], []],
    rp: [[], [], [], [], [], []],
    iv: [-1, -1, -1, -1, -1, -1]
};

let yieldCalls = 0;
window.setTimeout = function (callback) {
    yieldCalls++;
    return setTimeout(callback, 0);
};

module.exports = {
    createEmptyFilterState,
    denormalizeAllVulns,
    getRows: () => vulnerabilityData,
    getYieldCalls: () => yieldCalls,
    getMetrics: () => dashboardMetrics,
    matchesFilterStateNonDate
};
`);

    await dashboard.denormalizeAllVulns({ allowYield: true, yieldEveryRows: 2, yieldThreshold: 0 });

    const rows = dashboard.getRows();
    assert.strictEqual(rows.length, 6, 'Expected all synthetic rows to be denormalized.');
    assert.ok(dashboard.getYieldCalls() >= 3, 'Expected large denormalization to yield cooperatively.');
    assert.strictEqual(rows[0].DeviceId, 'device-1');
    assert.strictEqual(rows[0]._deviceSearchText, 'Device 1 device-1'.toLowerCase());
    assert.strictEqual(rows[0]._environmentFirstSeenDate, '2026-03-01');
    assert.ok(
        dashboard.getMetrics().counts.denormalizeYields >= 3,
        'Expected denormalization yield count to be recorded in dashboard metrics.'
    );

    const filterState = dashboard.createEmptyFilterState();
    filterState.deviceSearchNormalized = 'device-1';
    assert.strictEqual(dashboard.matchesFilterStateNonDate(rows[0], filterState), true);
    filterState.deviceSearchNormalized = 'missing-device';
    assert.strictEqual(dashboard.matchesFilterStateNonDate(rows[0], filterState), false);

    console.log('Dashboard large initialization responsiveness assertions passed.');
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});