const assert = require('assert');
const { Worker: NodeWorker } = require('worker_threads');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

async function main() {
    // Adapt only browser transport APIs. The real denormalizeInWorker and its
    // generated program execute across a Node worker thread/structured clone.
    const blobs = new Map();
    let workerCount = 0;
    class WorkerTransport {
        constructor(url) {
            workerCount++;
            this.ready = blobs.get(url).text().then(source => {
                if (this.terminated) return null;
                const worker = this.worker = new NodeWorker(`
                    const { parentPort } = require('worker_threads');
                    global.self = { postMessage: data => parentPort.postMessage(data) };
                    ${source}
                    parentPort.on('message', data => self.onmessage({ data }).catch(error => { throw error; }));
                `, { eval: true });
                worker.on('message', data => { if (this.onmessage) this.onmessage({ data }); });
                worker.on('error', error => { if (this.onerror) this.onerror(error); });
                return worker;
            });
        }
        postMessage(data, transfer) { this.ready.then(worker => { if (worker) worker.postMessage(data, transfer); }); }
        terminate() { this.terminated = true; if (this.worker) this.worker.terminate(); }
    }
    const payload = {
        lookups: {
            devices: [{ id: 'synthetic-device', n: 'Synthetic', g: 0, o: 0, t: [0], ov: '1' }],
            cves: [{ id: 'CVE-2026-0001', sc: 7, sv: 0, ex: -1, bt: 0, as: [0],
                pd: '3/1/2026', nlm: '3/2/2026', nkev: '3/3/2026', ndu: '3/4/2026', desc: 'Synthetic detail' }],
            software: [{ v: 0, n: 'Synthetic App', r: 'Synthetic recommendation' }],
            groups: ['Synthetic group'], platforms: ['Windows'], tags: ['Synthetic tag'],
            vendors: ['Synthetic vendor'], severities: ['High'], exploitLevels: [],
            versions: ['1'], dates: ['3/1/2026', '3/5/2026'],
            batchTitles: ['Synthetic batch'], affSoftware: ['Synthetic affected product'],
            inventory: [{ eod: '3/6/2026' }], updates: [],
            diskPaths: ['C:/Synthetic'], regPaths: ['HKLM/Synthetic']
        },
        vulns: [[0, 0, 0, 0, 0, 1, 0, -1, [0], [0], 0]]
    };
    const dashboard = loadDashboardHarness(`
module.exports = async function(payload) {
    lookups = structuredClone(payload.lookups);
    rawVulns = structuredClone(payload.vulns);
    await denormalizeAllVulns();
    materializeRow(vulnerabilityData[0]);
    const baseline = structuredClone(vulnerabilityData[0]);
    lookups = structuredClone(payload.lookups);
    rawVulns = structuredClone(payload.vulns);
    vulnerabilityData = [];
    let cache;
    getCachedData = async () => cache || null;
    setCachedData = async (fingerprint, rows) => {
        cache = structuredClone({ data: rows, lookups });
    };
    await denormalizeWithCaching();
    const coldBefore = structuredClone(vulnerabilityData[0]);
    materializeRow(vulnerabilityData[0]);
    const cold = structuredClone(vulnerabilityData[0]);
    vulnerabilityData = [];
    lookups = structuredClone(payload.lookups);
    rawVulns = structuredClone(payload.vulns);
    await denormalizeWithCaching();
    materializeRow(vulnerabilityData[0]);
    return { baseline, coldBefore, cold, warm: vulnerabilityData[0] };
};`, {
        structuredClone, Blob, Worker: WorkerTransport,
        URL: {
            createObjectURL(blob) { const url = `blob:synthetic-${blobs.size}`; blobs.set(url, blob); return url; },
            revokeObjectURL(url) { blobs.delete(url); }
        }
    });
    const result = await dashboard(payload);
    assert.strictEqual(workerCount, 1, 'Cached reload must reuse rows without launching another worker.');
    assert.strictEqual(blobs.size, 0, 'Worker Blob URL must be revoked.');
    if (!process.argv.includes('--details-only')) {
        for (const field of ['PublishedDate', 'NvdLastModifiedDate', 'NvdKevDate', 'NvdActionDue', 'EndOfSupportDate', '_lastSeenDate']) {
            for (const lane of ['coldBefore', 'cold', 'warm']) {
                assert.strictEqual(result[lane][field], result.baseline[field], `${lane} ${field} must match main-thread normalization`);
            }
        }
    }
    for (const lane of ['coldBefore', 'cold', 'warm']) {
        for (const field of ['AffectedSoftware', 'DiskPaths', 'RegistryPaths', 'MachineTags']) {
            assert.deepStrictEqual(Array.from(result[lane][field] || []), Array.from(result.baseline[field] || []), `${lane} ${field} must survive materialization and cached reload`);
        }
    }
    console.log('Generated worker cold/materialized/cached semantic parity passed (one synthetic row).');
}

main().catch(error => { console.error(error); process.exit(1); });
