const assert = require('assert');
const {loadDashboardHarness}=require('./helpers/dashboard-test-harness');
// Full-field oracle captured from immutable 77d672b source. Only the internal
// issue scratch property is excluded; undefined values and array order remain.
const fixtureGolden=require('./fixtures/dashboard-row-shape-77d672b.json');
const golden=Object.fromEntries(Object.entries(fixtureGolden.cases).map(([name,stages])=>[name,Object.fromEntries(Object.entries(stages).map(([stage,indexes])=>[stage,indexes.map(index=>fixtureGolden.rows[index])]))]));
const dashboard=loadDashboardHarness(`
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
    setDates: value => { lookups.dates = value; },
    materializeRow,
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
            pako: { inflate: () => new TextEncoder().encode(JSON.stringify({ lookups, vulns: rawVulns })) }
        };
        require('vm').runInNewContext(buildWorkerSource(), workerContext);
        await workerContext.self.onmessage({ data: compressed
            ? { compressedBytes: new Uint8Array([1]), decompressOnly: true }
            : { lookups, rawVulns } });
        result = readWorkerPayload(result);
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
function canonical(value) {
 if (value === undefined) return {$undefined:true};
 if (Array.isArray(value)) return Array.from(value,canonical);
 if (value && typeof value==='object') return Object.fromEntries(Object.keys(value).filter(k=>k!=='_issueKey').sort().map(k=>[k,canonical(value[k])]));
 return value;
}
async function main(){
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

cases.push({name:'invalid prefix preserves raw index',software:[{v:0,n:'Product'}],cves:[cve('A')],versions:['1'],vendors:['Vendor'],records:[record(99,0,0,0),record(0,0,0,1)]});
cases.push({name:'empty earliest date and numeric-zero key',software:[{v:0,n:'Product'}],cves:[cve('A')],versions:['1'],vendors:['Vendor'],records:[record(0,0,0,0),record(0,0,0,1)],dates:['','2026-03-15','2026-03-26']});
const captured={};
for(const fixture of cases){
 dashboard.setIdentityFixture(fixture.software,fixture.cves,fixture.versions,fixture.vendors,fixture.records);
 if(fixture.dates) dashboard.setDates(fixture.dates);
 const stages={};
 const capture=name=>{const rows=dashboard.getRows(); stages[name]=canonical(rows); assert(rows.every(row=>!Object.hasOwn(row,'_issueKey')),fixture.name+' '+name+' must not allocate issue scratch');};
 await dashboard.denormalizeAllVulns();capture('matrix');
 assert.deepStrictEqual(Array.from(dashboard.getRows(),row=>row._index),fixture.records.map((r,i)=>i).filter(i=>fixture.records[i][1]<fixture.cves.length),fixture.name+' preserves original raw indexes');
 dashboard.applyDerivedVulnerabilityFields(dashboard.getRows());capture('warm');
 dashboard.getRows().forEach(row=>row._issueKey=dashboard.getEnvironmentIssueKey(row));
 dashboard.applyDerivedVulnerabilityFields(dashboard.getRows());
 assert(dashboard.getRows().every(row=>row._issueKey===null),'Legacy injected keys must be cleared.');
 stages.legacy=canonical(dashboard.getRows());
 dashboard.setColumnarFixture(fixture.records);await dashboard.denormalizeAllVulns();capture('columnar');
 await dashboard.runTupleFallback();capture('overflow');
 for(const compressed of [false,true]){await dashboard.runWorkerFixture(compressed);capture('worker'+compressed);}
 dashboard.getRows().forEach(dashboard.materializeRow);capture('materialized');
 captured[fixture.name]=stages;
}
assert.deepStrictEqual(captured,golden,'All row fields must match pinned77d672b baseline; only _issueKey is excluded.');
console.log('Dashboard row shape full-field baseline parity passed.');
}
main().catch(e=>{console.error(e);process.exitCode=1;});
