const assert = require('assert');
const zlib = require('zlib');
const { Worker: NodeWorker } = require('worker_threads');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

const payload = {
    lookups: {
        devices: [{ id: 'device-1', n: '日本語 😀', g: 0, o: 0, t: [0], ov: '1' }],
        cves: [{ id: 'CVE-2026-0001', sc: 7, sv: 0, ex: -1, bt: 0, as: [0],
            pd: '3/1/2026', nlm: '3/2/2026', nkev: '3/3/2026', ndu: '3/4/2026', desc: 'Detail \\" <&> 😀' }],
        software: [{ v: 0, n: 'Application', r: 'Recommendation' }],
        groups: ['Group'], platforms: ['Windows'], tags: ['Tag'], vendors: ['Vendor'],
        severities: ['High'], exploitLevels: [], versions: ['1'], dates: ['3/1/2026', '3/5/2026'],
        batchTitles: ['Batch'], affSoftware: ['Affected'], inventory: [{ eod: '3/6/2026' }],
        updates: [{ id: 'KB1', url: 'https://example.invalid/update', n: 'Update' }],
        diskPaths: ['C:/日本語'], regPaths: ['HKLM/Synthetic']
    },
    vulns: [[0, 0, 0, 0, 0, 1, 1, 0, [0], [0], 0]]
};

async function exercise(input, { pakoOnly = false, failWorker = false, bom = false, malformed = false } = {}) {
    const blobs = new Map();
    const events = [];
    const proofs = [];
    const bytes = zlib.gzipSync(Buffer.from(malformed ? '{' : (bom ? '\ufeff' : '') + JSON.stringify(input)));
    const original = Buffer.from(bytes);
    class WorkerTransport {
        constructor(url) {
            this.ready = blobs.get(url).text().then(source => {
                if (this.terminated) return null;
                const worker = this.worker = new NodeWorker(`
                    const { parentPort } = require('worker_threads');
                    ${pakoOnly ? 'globalThis.DecompressionStream = undefined;' : ''}
                    ${failWorker ? 'throw new Error("Injected worker failure");' : ''}
                    global.self = { postMessage(data, transfer) {
                        if (!data.jsonUtf8) return parentPort.postMessage(data, transfer);
                        const buffer = data.jsonUtf8;
                        const before = buffer.byteLength;
                        const correctList = transfer.length === 1 && transfer[0] === buffer;
                        parentPort.postMessage(data, transfer);
                        parentPort.postMessage({ transportProof: { before, after: buffer.byteLength, correctList } });
                    }};
                    ${source}
                    parentPort.on('message', data => self.onmessage({ data }).catch(error => { throw error; }));
                `, { eval: true });
                let pending;
                worker.on('message', data => {
                    if (data.jsonUtf8) { pending = data; return; }
                    if (data.transportProof) {
                        proofs.push(data.transportProof);
                        if (this.onmessage) this.onmessage({ data: pending });
                    } else if (this.onmessage) this.onmessage({ data });
                });
                worker.on('error', error => { if (this.onerror) this.onerror(error); });
                return worker;
            });
        }
        postMessage(data, transfer) { this.ready.then(worker => { if (worker) worker.postMessage(data, transfer); }); }
        terminate() { events.push('terminate'); this.terminated = true; if (this.worker) this.worker.terminate(); }
    }
    class ObservedDecoder extends TextDecoder {
        decode(...args) { events.push('decode'); return super.decode(...args); }
    }
    const run = loadDashboardHarness(`
module.exports = async function(input, bytes, malformed) {
    lookups = input.lookups;
    rawVulns = input.vulns;
    await denormalizeAllVulns();
    vulnerabilityData.forEach(materializeRow);
    const baseline = JSON.stringify(vulnerabilityData);
    lookups = { groups: [] };
    rawVulns = null;
    vulnerabilityData = [];
    pendingCompressedBytes = bytes;
    computeCompressedFingerprint = async () => 'compressed';
    computeDataFingerprint = async () => 'normalized';
    getCachedData = async () => null;
    setCachedData = async () => {};
    // Adapt only the compression dependency. Both branches execute the actual
    // generated worker, real gzip decompression and a real transferable buffer.
    getPakoSource = async () => 'globalThis.pako = { inflate(bytes) { const raw = require("zlib").gunzipSync(bytes); const padded = Buffer.concat([Buffer.from("xx"), raw, Buffer.from("yy")]); return new Uint8Array(padded.buffer, padded.byteOffset + 2, raw.length); } };';
    try { await denormalizeWithCaching(); }
    catch (error) { if (malformed) return { error: error.name }; throw error; }
    vulnerabilityData.forEach(materializeRow);
    return { baseline, actual: JSON.stringify(vulnerabilityData), phases: dashboardMetrics.phases,
        fallbacks: dashboardMetrics.counts.workerFallbacks || 0, raw: JSON.stringify(rawVulns) };
};`, {
        structuredClone, Blob, Worker: WorkerTransport, TextDecoder: ObservedDecoder,
        pako: { inflate(buffer) { return zlib.gunzipSync(buffer).toString('utf8'); } },
        URL: {
            createObjectURL(blob) { const id = `blob:buffer-${blobs.size}`; blobs.set(id, blob); return id; },
            revokeObjectURL(id) { blobs.delete(id); }
        }
    });
    const result = await run(input, bytes, malformed);
    assert.deepStrictEqual(bytes, original, 'Compressed fallback input must remain readable and undetached.');
    assert.strictEqual(blobs.size, 0, 'Worker URL must be revoked.');
    assert(events.includes('terminate'), 'Worker must be terminated on success and failure.');
    if (malformed) {
        assert.strictEqual(result.error, 'SyntaxError', 'Malformed JSON must fail instead of becoming an empty report.');
    } else {
        assert.strictEqual(result.actual, result.baseline, 'All materialized fields must match main-thread normalization.');
        assert.strictEqual(result.raw, JSON.stringify(input.vulns), 'Matrix/columnar data must retain its exact JSON representation.');
        assert.strictEqual(result.fallbacks, failWorker ? 1 : 0);
    }
    if (!failWorker) {
        assert.strictEqual(proofs.length, 1);
        assert(proofs[0].before > 0 && proofs[0].after === 0 && proofs[0].correctList,
            'The actual worker reply buffer must transfer ownership and detach.');
        assert(events.indexOf('terminate') < events.indexOf('decode'), 'Decode must occur after worker termination.');
        if (!malformed) {
            assert(!('workerParseMs' in result.phases), 'Parsing moved to main; a worker-parse zero would be misleading.');
            assert('mainDecodeMs' in result.phases && 'mainParseMs' in result.phases);
        }
    }
}

async function main() {
    await exercise(payload);
    await exercise(payload, { pakoOnly: true });
    const columns = ['d', 'c', 's', 'v', 'f', 'l', 'ua', 'u', 'dp', 'rp', 'iv'];
    const columnar = { ...payload, vulns: Object.fromEntries(columns.map((key, index) => [key, payload.vulns.map(row => row[index])])) };
    await exercise(columnar);
    await exercise(columnar, { pakoOnly: true });
    await exercise({ ...payload, vulns: [] });
    await exercise(payload, { bom: true });
    await exercise(payload, { failWorker: true });
    await exercise(payload, { malformed: true });
    console.log('PASS real worker UTF-8 transfer/detachment, decode lifecycle, native/pako-view routes, Unicode/BOM, matrix/columnar/empty full-field parity and retained-input error fallback.');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
