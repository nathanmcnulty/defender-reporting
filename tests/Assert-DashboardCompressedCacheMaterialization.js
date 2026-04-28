const assert = require('assert');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

async function main() {
    const dashboard = loadDashboardHarness(`
const payload = {
    lookups: {
        devices: [{ id: 'device-1', n: 'Device 1', g: 0, o: 0, ov: '10.0.22631', t: [], m: { ls: '2026-03-26' } }],
        cves: [{ id: 'CVE-2026-0001', sc: 7.5, sv: 0, ex: -1, u: 'https://updates.example/cve', bt: 0, pd: '2026-03-01', desc: 'Summary: cached detail', ep: null, ea: false, nbs: null, nsv: null, nvec: null, nkev: null, ndu: null, nact: null, nw: [], as: [] }],
        software: [{ v: 0, n: 'Widget App', r: 'recommendation-1' }],
        groups: ['Engineering'],
        platforms: ['Windows'],
        tags: [],
        versions: ['1.0.0'],
        dates: ['2026-03-01', '2026-03-26'],
        updates: [{ n: 'Security Update', id: '5000001', url: 'https://updates.example/kb/5000001' }],
        vendors: ['Contoso'],
        severities: ['High'],
        exploitLevels: [],
        batchTitles: ['March 2026 Update'],
        affSoftware: [],
        inventory: [],
        diskPaths: ['C:/Program Files/Widget/widget.exe'],
        regPaths: ['HKLM/Software/Widget']
    },
    vulns: {
        d: [0],
        c: [0],
        s: [0],
        v: [0],
        f: [0],
        l: [1],
        ua: [1],
        u: [0],
        dp: [[0]],
        rp: [[0]],
        iv: [-1]
    }
};

async function runCompressedCacheHit() {
    lookups = payload.lookups;
    rawVulns = payload.vulns;
    await denormalizeAllVulns();
    const cachedRows = vulnerabilityData.map(row => ({ ...row }));

    lookups = null;
    rawVulns = null;
    vulnerabilityData = [];
    pendingCompressedBytes = new Uint8Array([1, 2, 3]);
    let inflateCount = 0;

    globalThis.pako = {
        inflate() {
            inflateCount++;
            return JSON.stringify(payload);
        }
    };
    getCachedData = async () => ({ data: cachedRows, lookups: payload.lookups });
    setCachedData = async () => { throw new Error('Cache-hit path should not write cache data.'); };

    await denormalizeWithCaching();
    const row = vulnerabilityData[0];
    materializeRow(row);

    return {
        inflateCount,
        rawCount: getRawVulnCount(),
        row
    };
}

module.exports = { runCompressedCacheHit };
`);

    const result = await dashboard.runCompressedCacheHit();
    assert.strictEqual(result.inflateCount, 1, 'Expected compressed cache hit to decompress once to restore raw columns.');
    assert.strictEqual(result.rawCount, 1, 'Expected raw vulnerability columns to be restored after compressed cache hit.');
    assert.strictEqual(result.row.CveBatchUrl, 'https://updates.example/cve');
    assert.strictEqual(result.row.CveBatchTitle, 'March 2026 Update');
    assert.strictEqual(result.row.VulnerabilityDescription, 'Summary: cached detail');
    assert.strictEqual(result.row.RecommendedSecurityUpdateId, '5000001');
    assert.strictEqual(result.row.RecommendedSecurityUpdateUrl, 'https://updates.example/kb/5000001');
    assert.deepStrictEqual(Array.from(result.row.DiskPaths), ['C:/Program Files/Widget/widget.exe']);
    assert.deepStrictEqual(Array.from(result.row.RegistryPaths), ['HKLM/Software/Widget']);
    assert.strictEqual(result.row.OSVersion, '10.0.22631');

    console.log('Dashboard compressed cache materialization assertions passed.');
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});