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
    matchesFilterStateNonDate,
    setIdentityFixture: (software, cves, versions, vendors, records) => {
        lookups.software = software;
        lookups.cves = cves;
        lookups.versions = versions;
        lookups.vendors = vendors;
        lookups.dates = ['2026-03-01', '2026-03-15', '2026-03-26'];
        rawVulns = records;
    },
    setRemediationFixture: () => {
        lookups.updates = [{ n: 'First Update', id: '1' }, { n: 'Second Update', id: '2' }];
        lookups.batchTitles = Array.from({ length: 100001 }, (_, index) => 'Batch ' + index);
        lookups.cves = [{ id: 'A', bt: 100000 }, { id: 'B', bt: 0 }];
        rawVulns = [[0, 0, 0, 0, 0, 2, 1, 0, [], [], -1], [0, 1, 0, 0, 1, 2, 1, 1, [], [], -1]];
    },
    setColumnarFixture: records => {
        rawVulns = Object.fromEntries(['d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp', 'iv'].map((key, index) => [key, records.map(row => row[index])]));
    },
    applyDerivedVulnerabilityFields,
    getEnvironmentIssueKey,
    runTupleFallback: async () => {
        const original = Number.isSafeInteger;
        Number.isSafeInteger = () => false;
        try { await denormalizeAllVulns(); }
        finally { Number.isSafeInteger = original; }
    },
    runWorkerFixture: async compressed => {
        let result;
        const workerContext = {
            self: { postMessage: value => { result = value; } },
            performance: require('perf_hooks').performance,
            pako: { inflate: () => JSON.stringify({ lookups, vulns: rawVulns }) }
        };
        require('vm').runInNewContext(buildWorkerSource(), workerContext);
        await workerContext.self.onmessage({ data: compressed
            ? { compressedBytes: new Uint8Array([1]), decompressOnly: true }
            : { lookups, rawVulns } });
        if (result.rows) {
            vulnerabilityData = result.rows;
            applyDerivedVulnerabilityFields(vulnerabilityData);
        } else {
            lookups = result.lookups;
            rawVulns = result.rawVulns;
            await denormalizeAllVulns();
        }
    }
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

    const record = (cve, software, version, first) => [0, cve, software, version, first, 2, 1, 0, [], [], -1];
    const cve = id => ({ id, sc: 7.5, sv: 0, ex: -1, bt: -1 });
    const software = Array.from({ length: 101 }, (_, index) => ({ v: 0, n: `Product ${index}` }));
    const cases = [
        { name: 'software radix boundary', software, cves: [cve('A'), cve('B')], versions: ['1'], vendors: ['Vendor'], records: [record(0, 100, 0, 0), record(1, 0, 0, 1)], expected: ['2026-03-01', '2026-03-15'] },
        { name: 'version radix boundary', software: software.slice(0, 2), cves: [cve('A')], versions: Array.from({ length: 10001 }, (_, index) => String(index)), vendors: ['Vendor'], records: [record(0, 0, 10000, 0), record(0, 1, 0, 1)], expected: ['2026-03-01', '2026-03-15'] },
        { name: 'equivalent lookup entries', software: [{ v: 0, n: 'Product', r: 'a' }, { v: 0, n: 'Product', r: 'b' }], cves: [cve('A'), cve('A')], versions: ['1', '1'], vendors: ['Vendor'], records: [record(0, 0, 0, 0), record(1, 1, 1, 1)], expected: ['2026-03-01', '2026-03-01'] },
        { name: 'delimiter identity', software: [{ v: 0, n: 'b|c' }, { v: 1, n: 'c' }], cves: [cve('A')], versions: ['1'], vendors: ['a', 'a|b'], records: [record(0, 0, 0, 0), record(0, 1, 0, 1)], expected: ['2026-03-01', '2026-03-15'] },
        { name: 'empty identity and invalid references', software: [{ v: -1, n: null }, { v: 0, n: '' }], cves: [cve(null), cve('')], versions: [null, ''], vendors: [''], records: [record(1, 1, 1, 1), record(0, 0, 0, 0), record(99, 0, 0, 0)], expected: ['2026-03-01', '2026-03-01'] }
    ];
    for (const fixture of cases) {
        dashboard.setIdentityFixture(fixture.software, fixture.cves, fixture.versions, fixture.vendors, fixture.records);
        await dashboard.denormalizeAllVulns();
        const cold = dashboard.getRows();
        assert.deepStrictEqual(Array.from(cold, row => row._environmentFirstSeenDate), fixture.expected, fixture.name);
        assert.ok(cold.every(row => row._issueKey === null), `${fixture.name} releases cold scratch keys`);
        cold.forEach(row => { row._issueKey = dashboard.getEnvironmentIssueKey(row); });
        dashboard.applyDerivedVulnerabilityFields(cold);
        assert.deepStrictEqual(Array.from(cold, row => row._environmentFirstSeenDate), fixture.expected, `${fixture.name} warm parity`);
        assert.ok(cold.every(row => row._issueKey === null), `${fixture.name} releases restored scratch keys`);
        dashboard.setColumnarFixture(fixture.records);
        await dashboard.denormalizeAllVulns();
        assert.deepStrictEqual(Array.from(dashboard.getRows(), row => row._environmentFirstSeenDate), fixture.expected, `${fixture.name} columnar parity`);
        await dashboard.runTupleFallback();
        assert.deepStrictEqual(Array.from(dashboard.getRows(), row => row._environmentFirstSeenDate), fixture.expected, `${fixture.name} oversized-domain fallback parity`);
        assert.ok(dashboard.getRows().every(row => row._issueKey === null), `${fixture.name} releases fallback scratch keys`);
        for (const compressed of [false, true]) {
            await dashboard.runWorkerFixture(compressed);
            assert.deepStrictEqual(Array.from(dashboard.getRows(), row => row._environmentFirstSeenDate), fixture.expected, `${fixture.name} worker compressed=${compressed}`);
        }
        dashboard.setIdentityFixture(fixture.software, fixture.cves, fixture.versions, fixture.vendors, fixture.records.slice().reverse());
        await dashboard.denormalizeAllVulns();
        assert.deepStrictEqual(Array.from(dashboard.getRows(), row => row._environmentFirstSeenDate), fixture.expected.slice().reverse(), `${fixture.name} reversed order`);
    }
    dashboard.setRemediationFixture();
    await dashboard.denormalizeAllVulns();
    assert.deepStrictEqual(Array.from(dashboard.getRows(), row => row._remediationString), ['Batch 100000 (KB1)', 'Batch 0 (KB2)'], 'Independent update/batch radix boundary');
    console.log('Dashboard large initialization responsiveness assertions passed.');
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});