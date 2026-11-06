const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const vm = require('vm');
const { pathToFileURL } = require('url');
const { isAllowedDashboardRequest: allowed } = require('./helpers/offline-request-policy');
const { readDashboardInput } = require('./helpers/dashboard-artifact-input');
const { captureRealDownload, withDeadline, assertArtifactAcceptance, fileReceipt, expectedDownloadNames } = require('./helpers/dashboard-artifact-acceptance');

async function run() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dashboard-artifact-control-'));
    try {
        const file = pathToFileURL(path.join(root, 'VulnerabilityDashboard.html')).href;
        for (const suffix of ['', '?view=encoded', '?view=encoded#fragment', '#fragment']) assert(allowed(file + suffix, 'http://127.0.0.1:99', file));
        for (const actual of [file + '?token=no', file + '?view=a&view=b', file.replace('.html', '-neighbor.html'),
            pathToFileURL(path.join(root, '..', 'neighbor.html')).href, 'file:///C:/unrelated.html', 'https://example.invalid/', 'blob:null/foreign']) assert(!allowed(actual, 'http://127.0.0.1:99', file));
        assert(allowed('http://127.0.0.1:99/assets/data', 'http://127.0.0.1:99', null));
        assert(!allowed('http://127.0.0.1:999/assets/data', 'http://127.0.0.1:99', null));
        assert(!allowed(file, 'http://127.0.0.1:99', null));

        const payload = zlib.gzipSync(Buffer.from('{"lookups":{},"vulns":[[0]]}'));
        const chart = zlib.gzipSync(Buffer.from('/* synthetic parser control, never a runnable browser library */' + 'x'.repeat(1100)));
        const runtime = 'let vulnerabilityData = []; function init() {}';
        const config = { chartJsMode: 'embedded', pdfExportBundleMode: 'embedded', pdfExportRuntimeMode: 'embedded' };
        const html = `<script>${'/* pako parser control */' + 'x'.repeat(1100)}</script>
            <script id="dashboardConfig" type="application/json">${JSON.stringify(config)}</script>
            <script id="dataFormat">compressed</script>
            <script id="vulnsData">${payload.toString('base64')}</script>
            <script id="chartJsLib">${chart.toString('base64')}</script>
            <script id="pdfExportBundleLib">${chart.toString('base64')}</script>
            <script>${runtime}</script>`;
        const filename = path.join(root, 'VulnerabilityDashboard.html');
        fs.writeFileSync(filename, html);
        const sourceForbidden = () => { throw new Error('Source overlay must not execute for retained HTML.'); };
        const input = readDashboardInput(root, true, true, sourceForbidden);
        assert(input.payload.equals(payload)); assert.strictEqual(input.runtime, runtime);
        assert.strictEqual(input.fileUrl, file); assert.strictEqual(input.runtimeMode, 'generated-inline-assets');
        assert.throws(() => readDashboardInput(root, true, false, sourceForbidden), /generated-runtime/);
        fs.writeFileSync(filename, html.replace(payload.toString('base64'), '%%%invalid%%%'));
        assert.throws(() => readDashboardInput(root, true, true, sourceForbidden), /base64/);
        fs.writeFileSync(filename, html.replace('"chartJsMode":"embedded"', '"chartJsMode":"external"'));
        assert.throws(() => readDashboardInput(root, true, true, sourceForbidden), /external delivery/);

        const timers = new Map(); let timerId = 0;
        const deadline = vm.runInNewContext(`(${withDeadline.toString()})`, { assert,
            setTimeout(fn) { timers.set(++timerId, fn); return timerId; }, clearTimeout(id) { timers.delete(id); } });
        assert.strictEqual(await deadline(Promise.resolve('success'), 25), 'success'); assert.strictEqual(timers.size, 0);
        await assert.rejects(deadline(Promise.reject(new Error('Synthetic rejection')), 25), /Synthetic rejection/); assert.strictEqual(timers.size, 0);
        const missingCallback = deadline(new Promise(() => {}), 25);
        timers.values().next().value(); await assert.rejects(missingCallback, /deadline/); assert.strictEqual(timers.size, 0);
        await assert.rejects(deadline(Promise.resolve(), 120001), /Invalid artifact deadline/);

        const events = [];
        const pdf = Buffer.from('%PDF-1.7\n' + 'synthetic-content\n'.repeat(15) + '%%EOF\n');
        const interval = { utcDayBefore: '2026-11-06', utcDayAfter: '2026-11-06' };
        const label = 'Active Vulnerabilities';
        const expectedName = 'Vulnerability_Dashboard_Active_Vulnerabilities_2026-11-06.pdf';
        assert.deepStrictEqual(expectedDownloadNames(label, interval), [expectedName, expectedName]);
        assert(expectedDownloadNames(label, { ...interval, utcDayAfter: '2026-11-07' }).includes('Vulnerability_Dashboard_Active_Vulnerabilities_2026-11-07.pdf'));
        assert.throws(() => expectedDownloadNames(label, { ...interval, utcDayAfter: '2026-11-08' }), /bounded interval/);
        const download = { suggestedFilename: () => expectedName, failure: async () => null, saveAs: async destination => { events.push('save'); fs.writeFileSync(destination, pdf); } };
        const page = { waitForEvent: (name, options) => { events.push('wait'); assert.strictEqual(name, 'download'); assert.strictEqual(options.timeout, 120000); return Promise.resolve(download); } };
        const wait = operation => withDeadline(operation, 1000);
        const receipt = await captureRealDownload(page, async () => { events.push('trigger'); return interval; }, path.join(root, 'real.pdf'), wait, label);
        assert.deepStrictEqual(events, ['wait', 'trigger', 'save']); assert.strictEqual(receipt.bytes, pdf.length);
        assert.strictEqual(receipt.suggestedFilename, expectedName);
        let wrongSaved = false;
        await assert.rejects(captureRealDownload({ waitForEvent: async () => ({ ...download,
            suggestedFilename: () => 'Vulnerability_Dashboard_Impact_Analysis_2026-11-06.pdf', saveAs: async () => { wrongSaved = true; } }) },
        async () => interval, path.join(root, 'wrong-report.pdf'), wait, label), /filename does not match/);
        assert(!wrongSaved && !fs.existsSync(path.join(root, 'wrong-report.pdf')), 'An unrelated valid PDF must not be saved or receipted for the selected report.');
        await assert.rejects(captureRealDownload(page, async () => { throw new Error('Synthetic export failure'); }, path.join(root, 'failed.pdf'), wait), /Synthetic export failure/);
        await assert.rejects(captureRealDownload({ waitForEvent: async () => ({ ...download, failure: async () => 'canceled' }) }, async () => interval, path.join(root, 'canceled.pdf'), wait, label), /download failed/);
        const neverDownloaded = captureRealDownload({ waitForEvent: () => new Promise(() => {}) }, async () => {}, path.join(root, 'missing.pdf'), operation => deadline(operation, 25));
        assert.strictEqual(timers.size, 1);
        timers.values().next().value();
        await assert.rejects(neverDownloaded, /deadline/);
        assert.strictEqual(timers.size, 0);
        assert(!fs.existsSync(path.join(root, 'missing.pdf')), 'Missing browser download must never produce a saved-PDF receipt.');
        fs.writeFileSync(path.join(root, 'bad.pdf'), Buffer.from('%PDF-' + 'x'.repeat(120)));
        assert.throws(() => fileReceipt(path.join(root, 'bad.pdf'), 'pdf'), /Incomplete/);
        const reports = ['active-vulnerabilities', 'impact-analysis', 'remediation-activity', 'devices-by-remediation', 'remediations-by-device'];
        const fileEvidence = { bytes: 150, sha256: 'a'.repeat(64) };
        const result = { status: 'captured', restored: true, representativeRows: 2,
            reports: ['representative', 'empty'].flatMap(scope => reports.map(report => {
                const before = { report, reportLabel: report, sourceRows: scope === 'empty' ? 0 : 2, expandedText: 'Synthetic exact report text', filter: { key: scope }, reportRows: scope === 'empty' ? 0 : 2 };
                return { scope, report, before, after: structuredClone(before),
                    pdf: { ...fileEvidence, suggestedFilename: `Vulnerability_Dashboard_${report}_2026-11-06.pdf`, exportUtcDayBefore: interval.utcDayBefore, exportUtcDayAfter: interval.utcDayAfter },
                    screenshot: fileEvidence, receipt: fileEvidence };
            })) };
        assertArtifactAcceptance(result);
        for (const mutate of [value => { value.restored = false; }, value => { value.reports[0].after.filter.key = 'broadened'; },
            value => { value.reports[5].before.sourceRows = 1; value.reports[5].after.sourceRows = 1; },
            value => { value.reports[1] = value.reports[0]; }, value => { value.reports[0].pdf.sha256 = 'missing'; },
            value => { value.reports[0].pdf.suggestedFilename = 'unrelated.pdf'; }]) {
            const invalid = structuredClone(result); mutate(invalid); assert.throws(() => assertArtifactAcceptance(invalid));
        }
        console.log('PASS exact file URL/view policy, actual inline provenance, bounded callback operations, real-download ordering/failure, PDF truncation and scope/receipt invalidation controls (no browser launched)');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

module.exports = { run };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
