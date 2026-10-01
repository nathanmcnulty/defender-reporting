const assert = require('assert');
const { createDocumentStub, loadDashboardHarness } = require('./helpers/dashboard-test-harness');

function createCacheDatabase() {
    const entries = new Map();
    const state = { entries, closes: 0, bodyScans: 0, deleted: [], puts: 0, schema: null, mode: 'normal' };
    const indexNames = new Set();
    const store = {
        indexNames: { contains: name => indexNames.has(name) },
        createIndex(name) { indexNames.add(name); },
        get(key) {
            const request = {};
            if (state.mode !== 'stall') queueMicrotask(() => { request.result = entries.get(key); request.onsuccess(); });
            return request;
        },
        put(entry) {
            if (state.mode === 'quota') throw new Error('Quota exceeded');
            state.puts++;
            state.schema = entry.schema;
            entries.set(entry.fingerprint, entry);
        },
        delete(key) { state.deleted.push(key); entries.delete(key); },
        getAll() { state.bodyScans++; throw new Error('Full row-body scans are forbidden'); },
        index() {
            return {
                openKeyCursor() {
                    const request = {};
                    const sorted = Array.from(entries.values()).sort((left, right) => right.ts - left.ts);
                    let position = 0;
                    const next = () => queueMicrotask(() => {
                        const entry = sorted[position++];
                        request.result = entry ? { primaryKey: entry.fingerprint, continue: next } : null;
                        request.onsuccess();
                        if (!entry && state.transaction.oncomplete) state.transaction.oncomplete();
                    });
                    next();
                    return request;
                }
            };
        }
    };
    const db = {
        objectStoreNames: { contains: () => true },
        close() { state.closes++; },
        transaction() {
            const transaction = { objectStore: () => store, abort() { if (transaction.onabort) transaction.onabort(); } };
            state.transaction = transaction;
            return transaction;
        }
    };
    const indexedDB = {
        open() {
            const request = { result: db, transaction: { objectStore: () => store } };
            queueMicrotask(() => {
                if (state.mode === 'blocked') {
                    request.onblocked();
                    queueMicrotask(() => request.onsuccess());
                } else if (state.mode !== 'open-stall') {
                    request.onupgradeneeded();
                    request.onsuccess();
                }
            });
            return request;
        }
    };
    return { indexedDB, state };
}

async function assertCacheGuards() {
    const { indexedDB, state } = createCacheDatabase();
    const dashboard = loadDashboardHarness(`module.exports = { computeCompressedFingerprint, getCachedData, setCachedData, openVulnDB };`, {
        indexedDB,
        setTimeout: (callback, delay) => setTimeout(callback, delay === 2000 ? 10 : delay)
    });
    const fingerprint = await dashboard.computeCompressedFingerprint(new Uint8Array([1, 2, 3]));
    assert.match(fingerprint, /^derived_\d+_cfp_/, 'Derived schema must namespace fingerprints.');
    for (let index = 0; index < 5; index++) state.entries.set(`old-${index}`, { fingerprint: `old-${index}`, data: [{}], ts: index });
    await dashboard.setCachedData(fingerprint, [{ CveId: 'A' }]);
    assert.strictEqual(state.bodyScans, 0);
    assert.strictEqual(state.entries.size, 4);
    assert.deepStrictEqual(state.deleted, ['old-1', 'old-0']);
    assert.ok((await dashboard.getCachedData(fingerprint)).data);
    const puts = state.puts;
    await dashboard.setCachedData('oversize', new Array(500000));
    assert.strictEqual(state.puts, puts, 'Preserve the 500000-row write cutoff.');
    state.entries.set('stale', { data: [{}], schema: -1 });
    assert.strictEqual(await dashboard.getCachedData('stale'), null);
    state.entries.set('malformed', { data: [null], schema: state.schema });
    assert.strictEqual(await dashboard.getCachedData('malformed'), null);
    state.mode = 'quota';
    await dashboard.setCachedData('quota', [{}]);
    state.mode = 'stall';
    assert.strictEqual(await dashboard.getCachedData(fingerprint), null);
    state.mode = 'open-stall';
    await assert.rejects(dashboard.openVulnDB(), /timed out/);
    state.mode = 'blocked';
    const closes = state.closes;
    await assert.rejects(dashboard.openVulnDB(), /blocked/);
    await new Promise(resolve => setImmediate(resolve));
    assert.ok(state.closes > closes, 'Late successful open after rejection must close its database.');
}

async function assertFetchDeadlines() {
    let mode = 'body';
    let rejectPayload;
    const signals = [];
    const document = createDocumentStub();
    document.getElementById('dataFormat').textContent = 'external-compressed';
    const dashboard = loadDashboardHarness(`
Object.assign(dashboardConfig, { payloadUrl: 'payload', payloadSummaryUrl: 'summary' });
module.exports = { loadExternalCompressedPayloadBytes, loadData, getPakoSource, ensurePendingCompressedBytesLoaded };
`, {
        document,
        AbortController,
        setTimeout: (callback, delay) => setTimeout(callback, delay === 30000 ? 10 : delay),
        fetch: (url, options) => {
            signals.push(options && options.signal);
            if (mode === 'headers' || (mode === 'sibling' && url === 'summary')) return new Promise(() => {});
            if (mode === 'sibling') return Promise.reject(new Error('Payload failed early'));
            if (mode === 'late-payload' && url === 'payload') return new Promise((resolve, reject) => { rejectPayload = reject; });
            return Promise.resolve({
                ok: true,
                arrayBuffer: () => mode === 'success' ? Promise.resolve(new Uint8Array([1, 2]).buffer) : new Promise(() => {}),
                json: () => mode === 'success' || mode === 'late-payload' ? Promise.resolve({ filterCatalog: { devices: [], groups: [], tags: [] } }) : new Promise(() => {}),
                text: () => new Promise(() => {})
            });
        }
    });
    const bounded = promise => {
        let timer;
        return Promise.race([promise, new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('Test watchdog expired')), 100); })])
            .finally(() => clearTimeout(timer));
    };
    await assert.rejects(bounded(dashboard.loadExternalCompressedPayloadBytes('payload')), /Timed out loading dashboard payload/);
    assert.strictEqual(signals.at(-1).aborted, true, 'Stalled body must abort its request.');
    mode = 'headers';
    await assert.rejects(bounded(dashboard.loadExternalCompressedPayloadBytes('payload')), /Timed out/);
    const caller = new AbortController();
    const callerRequest = bounded(dashboard.loadExternalCompressedPayloadBytes('payload', caller.signal));
    caller.abort(new Error('Caller cancelled'));
    await assert.rejects(callerRequest, /Caller cancelled/);
    const activeCaller = new AbortController();
    mode = 'body';
    const activeRequest = bounded(dashboard.loadExternalCompressedPayloadBytes('payload', activeCaller.signal));
    await new Promise(resolve => setImmediate(resolve));
    activeCaller.abort(new Error('Body caller cancelled'));
    await assert.rejects(activeRequest, /Body caller cancelled/);
    assert.strictEqual(signals.at(-1).aborted, true);
    const timeoutCaller = new AbortController();
    await assert.rejects(bounded(dashboard.loadExternalCompressedPayloadBytes('payload', timeoutCaller.signal)), /Timed out/);
    assert.strictEqual(signals.at(-1).aborted, true, 'Timeout must abort even with a caller signal.');
    assert.strictEqual(timeoutCaller.signal.aborted, false, 'Do not mutate the caller controller.');
    mode = 'sibling';
    await assert.rejects(bounded(dashboard.loadData()), /Payload failed early/);
    assert.strictEqual(signals.at(-1).aborted, true, 'Early payload rejection must abort the summary sibling.');
    mode = 'body';
    await assert.rejects(bounded(dashboard.loadData()), /Timed out/);
    document.querySelectorAll = () => [{ src: 'pako.js' }];
    assert.strictEqual(await bounded(dashboard.getPakoSource()), null, 'Pako body timeout must fall back.');
    mode = 'success';
    assert.deepStrictEqual(Array.from(await dashboard.loadExternalCompressedPayloadBytes('payload')), [1, 2]);
    await dashboard.loadData();
    mode = 'late-payload';
    await dashboard.loadData();
    rejectPayload(new Error('Delayed payload failure'));
    await new Promise(resolve => setImmediate(resolve));
    await assert.rejects(dashboard.ensurePendingCompressedBytesLoaded(), /Delayed payload failure/);
    const inlineSource = 'pako inflate ' + ' '.repeat(10001);
    document.querySelectorAll = () => [{ textContent: inlineSource }];
    assert.strictEqual(await dashboard.getPakoSource(), inlineSource, 'Retain standalone inline Pako loading.');
}

async function assertWorkerCleanup() {
    let mode = 'constructor';
    let terminated = 0;
    let created = 0;
    let revoked = 0;
    let postedBytes = null;
    const dashboard = loadDashboardHarness(`
getPakoSource = async () => 'worker pako source';
module.exports = { denormalizeInWorker };
`, {
        Blob,
        URL: { createObjectURL() { created++; return 'blob:worker'; }, revokeObjectURL() { revoked++; } },
        setTimeout: (callback, delay) => setTimeout(callback, delay === 10000 ? 10 : delay),
        Worker: class {
            constructor() { if (mode === 'constructor') throw new Error('Constructor failed'); }
            terminate() { terminated++; }
            postMessage(message, transfer) {
                assert.strictEqual(transfer, undefined, 'Do not transfer the sole fallback buffer.');
                postedBytes = message.compressedBytes;
                if (mode === 'post') throw new Error('Post failed');
                if (mode === 'error') queueMicrotask(() => this.onerror(new Error('Worker error')));
                if (mode === 'success') queueMicrotask(() => this.onmessage({ data: { rows: [] } }));
            }
        }
    });
    const bytes = new Uint8Array([1, 2, 3]);
    await assert.rejects(dashboard.denormalizeInWorker(bytes), /Constructor failed/);
    assert.strictEqual(revoked, created, 'Constructor failure must revoke the owned blob URL.');
    for (mode of ['post', 'error', 'timeout']) {
        const before = terminated;
        await assert.rejects(dashboard.denormalizeInWorker(bytes));
        assert.strictEqual(terminated, before + 1, `${mode} must terminate its worker exactly once.`);
        assert.strictEqual(revoked, created, `${mode} must revoke its URL.`);
        assert.strictEqual(bytes.byteLength, 3, 'Fallback bytes must remain owned and readable.');
    }
    mode = 'success';
    await dashboard.denormalizeInWorker(bytes);
    assert.strictEqual(postedBytes, bytes);
    assert.strictEqual(revoked, created);
}

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
    const lazyAfterDerived = !row._mat && !('DiskPaths' in row) && !('RegistryPaths' in row) && !('VulnerabilityDescription' in row);
    const descriptor = buildRemediationDescriptor(row);
    const lazyAfterDescriptor = !row._mat && !('DiskPaths' in row) && !('RegistryPaths' in row) && !('VulnerabilityDescription' in row);
    materializeRow(row);

    return {
        lazyAfterDerived,
        lazyAfterDescriptor,
        descriptor,
        inflateCount,
        rawCount: getRawVulnCount(),
        row
    };
}

async function runCacheMiss(useCompressed, failWorker) {
    lookups = payload.lookups;
    rawVulns = payload.vulns;
    pendingCompressedBytes = useCompressed ? new Uint8Array([1, 2, 3]) : null;
    const bytes = pendingCompressedBytes;
    let compressedDigests = 0;
    let normalizedDigests = 0;
    const writes = [];
    computeCompressedFingerprint = async () => { compressedDigests++; return 'compressed'; };
    computeDataFingerprint = async () => { normalizedDigests++; return 'normalized'; };
    getCachedData = async () => null;
    setCachedData = async (fingerprint, rows) => { writes.push({ fingerprint, count: rows.length }); };
    globalThis.pako = { inflate: () => JSON.stringify(payload) };
    denormalizeInWorker = async () => {
        if (failWorker) {
            lookups = null;
            rawVulns = null;
            throw new Error('Injected worker failure');
        }
        return { lookups: payload.lookups, rawVulns: payload.vulns };
    };
    await denormalizeWithCaching();
    return { writes, compressedDigests, normalizedDigests, intactBytes: !bytes || bytes.byteLength === 3, firstSeen: vulnerabilityData[0]._environmentFirstSeenDate, lazy: !vulnerabilityData[0]._mat };
}

module.exports = { runCompressedCacheHit, runCacheMiss };
`);

    const result = await dashboard.runCompressedCacheHit();
    assert.strictEqual(result.lazyAfterDerived, true, 'Warm derived fields must not allocate detail evidence.');
    assert.strictEqual(result.lazyAfterDescriptor, true, 'Aggregate descriptors must not allocate detail evidence.');
    assert.strictEqual(result.row._issueKey, null, 'Warm cache rows must release issue identity scratch strings.');
    assert.strictEqual(result.descriptor.updateUrl, 'https://updates.example/kb/5000001');
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
    for (const [compressed, failWorker] of [[true, false], [true, true], [false, false]]) {
        const miss = await dashboard.runCacheMiss(compressed, failWorker);
        assert.strictEqual(miss.writes.length, 1, 'Write one expanded entry per representation.');
        assert.strictEqual(miss.writes[0].fingerprint, compressed ? 'compressed' : 'normalized');
        assert.strictEqual(miss.compressedDigests, Number(compressed));
        assert.strictEqual(miss.normalizedDigests, Number(!compressed), 'Reuse the initial fingerprint instead of digesting again.');
        assert.strictEqual(miss.intactBytes, true);
        assert.strictEqual(miss.lazy, true);
        assert.strictEqual(miss.firstSeen, '2026-03-01');
    }
    await assertCacheGuards();
    await assertFetchDeadlines();
    await assertWorkerCleanup();

    console.log('Dashboard compressed cache materialization assertions passed.');
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});