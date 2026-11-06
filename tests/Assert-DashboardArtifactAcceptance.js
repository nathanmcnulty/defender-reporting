const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const vm = require('vm');
const { pathToFileURL } = require('url');
const { isAllowedDashboardRequest: allowed } = require('./helpers/offline-request-policy');
const { readDashboardInput } = require('./helpers/dashboard-artifact-input');
const { captureRealDownload, withDeadline, assertArtifactAcceptance, fileReceipt, expectedDownloadNames, captureReportScope, loadScopedPdfRuntime } = require('./helpers/dashboard-artifact-acceptance');
const { planFacetUi, selectReportWithUi, selectRemediationModeWithUi, setFacetWithUi, clickExportWithUi, assertFacetSelection, assertUiExercise } = require('./helpers/dashboard-ui-exercise');

async function assertUiControls() {
    const calls = [];
    let state = { values: ['Low'], hasAny: true, rows: 2 };
    let draft;
    let mode = 'snapshot';
    let disabledMode = false;
    const page = {
        locator(selector) {
            return {
                async click() {
                    if (selector === '#filterPopoverResetButton') {
                        assert(!(draft.hasAny && draft.values.length === 0), 'A default facet has a disabled Reset button.');
                        draft = { values: [], hasAny: true };
                    }
                    calls.push(selector + ':click');
                    if (selector.endsWith('#remediationModeRangeButton')) mode = 'range';
                    if (selector.endsWith('#remediationModeSnapshotButton')) mode = 'snapshot';
                    if (selector === '#filterPillSeverity') draft = structuredClone(state);
                    if (selector === '#filterPopoverApplyButton') state = { ...draft, rows: draft.hasAny ? 2 : 0 };
                },
                async check() { calls.push(selector + ':check'); draft = { values: [], hasAny: true }; },
                async uncheck() { calls.push(selector + ':uncheck'); draft = { values: [], hasAny: false }; },
                async count() { return 0; }, async isEnabled() {
                    if (selector.includes('#remediationReportToolbar')) return !disabledMode;
                    if (selector === '#filterPopoverResetButton') return !(draft.hasAny && draft.values.length === 0);
                    if (selector === '#filterPopoverApplyButton') return draft.hasAny !== state.hasAny || JSON.stringify(draft.values) !== JSON.stringify(state.values);
                    return true;
                },
                async getAttribute() { return selector.endsWith(mode === 'range' ? '#remediationModeRangeButton' : '#remediationModeSnapshotButton') ? 'true' : 'false'; },
                async evaluateAll() { return ['High', 'Low']; },
                nth(index) { return { async check() { calls.push('option:' + index); draft = { values: [['High', 'Low'][index]], hasAny: true }; } }; }
            };
        },
        async evaluate(callback, argument) {
            assert(!String(callback).includes('exportToPDF('), 'The UI lane must not invoke the export API directly.');
            return argument === 'filterSeverity' ? structuredClone(state) : '2026-11-06';
        },
        async waitForFunction() { calls.push('ready'); }
    };
    const wait = operation => operation;
    await setFacetWithUi(page, wait, 1000, 'filterSeverity', { values: ['High'], hasAny: true });
    assert.deepStrictEqual(state, { values: ['High'], hasAny: true, rows: 2 });
    await setFacetWithUi(page, wait, 1000, 'filterSeverity', { values: [], hasAny: false });
    assert.strictEqual(state.rows, 0);
    await setFacetWithUi(page, wait, 1000, 'filterSeverity', { values: [], hasAny: true });
    const resetClicks = calls.filter(call => call === '#filterPopoverResetButton:click').length;
    await setFacetWithUi(page, wait, 1000, 'filterSeverity', { values: [], hasAny: true });
    assert.strictEqual(calls.filter(call => call === '#filterPopoverResetButton:click').length, resetClicks);
    assert(calls.includes('#filterPopoverCancelButton:click'), 'An unchanged All selection closes through Cancel.');
    await selectReportWithUi(page, wait, 1000, 'impact-analysis');
    const interval = await clickExportWithUi(page, wait, 1000, { report: 'impact-analysis', reportLabel: 'Impact Analysis' });
    assert.strictEqual(interval.utcDayBefore, '2026-11-06');
    assert(calls.includes('#reportSelectorButton:click') && calls.includes('#reportSelectorOptions button[data-report-id="impact-analysis"]:click'));
    assert(calls.includes('#exportPdfButton:click') && calls.includes('option:0'));
    await selectRemediationModeWithUi(page, wait, 1000, 'devices-by-remediation', 'range');
    assert.strictEqual(mode, 'range');
    const rangeSelector = '#remediationReportToolbar #remediationModeRangeButton:click';
    const rangeClicks = calls.filter(call => call === rangeSelector).length;
    assert.strictEqual(rangeClicks, 1, 'Observed-range mode must use the actual mode button.');
    disabledMode = true;
    await selectRemediationModeWithUi(page, wait, 1000, 'devices-by-remediation', 'range');
    assert.strictEqual(calls.filter(call => call === rangeSelector).length, rangeClicks, 'Already-selected mode must not be clicked again.');
    await assert.rejects(selectRemediationModeWithUi(page, wait, 1000, 'devices-by-remediation', 'snapshot'), /disabled/);
    disabledMode = false;
    await selectRemediationModeWithUi(page, wait, 1000, 'remediations-by-device', 'snapshot');
    assert.strictEqual(mode, 'snapshot');
    await assert.rejects(selectRemediationModeWithUi(page, wait, 1000, 'active-vulnerabilities', 'range'), /Invalid/);
    assert.throws(() => assertFacetSelection({ values: [], hasAny: true, rows: 2 }, { values: ['High'], hasAny: true }), /broadened/);
    assert.throws(() => assertFacetSelection({ values: [], hasAny: false, rows: 2 }, { values: [], hasAny: false }), /empty/);
    const ui = { status: 'exercised', path: 'locator-facet-click-check-apply', selectedFacet: 'filterSeverity', deselectionRows: 0, hiddenSelection: { status: 'unavailable-fixture-intersection' } };
    assertUiExercise(ui);
    assert.throws(() => assertUiExercise({ ...ui, deselectionRows: 1 }));
    const hiddenUi = { ...ui, hiddenSelection: { status: 'exercised', deviceSubsetCount: 2, selectedGroupsAfter: ['Group A'], scopedRows: 0, reopenedRows: 1 } };
    assertUiExercise(hiddenUi);
    assert.throws(() => assertUiExercise({ ...hiddenUi, hiddenSelection: { ...hiddenUi.hiddenSelection, deviceSubsetCount: 1 } }));
    const plan = rows => vm.runInNewContext(`(${planFacetUi.toString()})()`, {
        filterState: {}, cloneFilterState: value => ({ ...value }), finalizeFilterState: value => value,
        getScopedFilterOptions: () => [{ value: 'High' }], matchesFilterState: () => true,
        getDeviceNameFilterValue: row => row.id, vulnerabilityData: rows
    });
    const row = (id, group, platform) => ({ id, _normalizedGroup: group, OSPlatform: platform });
    // Both full groups span both OSes: only a subset of existing devices can
    // expose the hidden-selection case, without changing any fixture bytes.
    const fixture = [row('a-win', 'A', 'Windows'), row('a-linux', 'A', 'Linux'), row('b-win', 'B', 'Windows'), row('b-linux', 'B', 'Linux')];
    const subset = plan(fixture).hidden;
    assert.strictEqual(subset.devices.length, 2);
    const chosen = subset.devices.map(id => fixture.find(row => row.id === id));
    assert.notStrictEqual(chosen[0]._normalizedGroup, chosen[1]._normalizedGroup);
    assert.notStrictEqual(chosen[0].OSPlatform, chosen[1].OSPlatform);
    assert.strictEqual(plan([fixture[0]]).hidden, null, 'One-device control must label the intersection unavailable.');
    assert.strictEqual(plan([row('mixed', 'A', 'Windows'), row('mixed', 'A', 'Linux'), row('other', 'B', 'Windows'), row('other', 'B', 'Linux')]).hidden, null,
        'A changing device cannot be treated as a stable OS subset.');
    await assert.rejects(selectReportWithUi(page, wait, 1000, 'unknown'), /Unknown/);
    return ui;
}

function assertCardScopeCapture() {
    const metadata = ['Platform: Windows 11', 'Published: 2025-12-20', 'Patch: KB000001', 'Patch: KB000002', 'Update: legacy-reference'];
    const stats = [...metadata, 'Devices: 1', 'CVEs: 2'];
    const badges = values => values.map(innerText => ({ innerText }));
    const card = { querySelector: () => ({ innerText: 'Synthetic remediation' }),
        querySelectorAll: selector => badges(selector === '.cve-details .stat-badge' ? metadata : stats) };
    const section = { innerText: 'Synthetic expanded report', querySelectorAll: selector => selector === '.remediation-card' ? [card] : [] };
    const summary = 'Showing only vulnerabilities still open on 2026-01-02. Resolved items from earlier in the range are excluded.';
    let visibleSummary = summary;
    let restorations = 0;
    let expansions = 0;
    const context = {
        activeReportId: 'devices-by-remediation', filterState: { startDate: '2026-01-01', endDate: '2026-01-02' }, remediationReportMode: 'snapshot', REMEDIATION_REPORT_MODE_RANGE: 'range',
        document: { getElementById: id => id.endsWith('-section') ? section : id === 'remediationModeSummary' ? { innerText: visibleSummary } : { selectedOptions: [{ text: 'Devices by Remediation' }] } },
        expandReportForPdf: () => { expansions++; return { wasExpanded: false }; }, restoreReportState: () => { restorations++; },
        remediationAllData: [], impactAnalysisAllData: [], remediationDetailsAllData: [], devicesByRemediationAllData: [{}], remediationsByDeviceAllData: [],
        cloneFilterState: value => ({ ...value }), filteredData: [{}, {}], buildDashboardValidationSnapshot: () => ({ summaryCards: { high: '2' } }),
        getExportFilterText: () => 'All', isRemediationScopeReport: () => true, getRemediationReportModeSummaryText: () => summary
    };
    const capture = () => vm.runInNewContext(`(${captureReportScope.toString()})()`, context);
    const receipt = capture();
    assert.strictEqual(receipt.cardDetails[0].title, 'Synthetic remediation');
    assert.deepStrictEqual(Array.from(receipt.cardDetails[0].metadata), metadata);
    assert.deepStrictEqual(Array.from(receipt.cardDetails[0].statBadges), stats);
    assert.strictEqual(receipt.modeSummary, summary); assert.strictEqual(receipt.includeResolvedText, 'No');
    assert.strictEqual(restorations, 1);
    visibleSummary = 'A different selected scope';
    assert.throws(capture, /Visible mode summary/); assert.strictEqual(restorations, 2);
    context.devicesByRemediationAllData = [{}, {}, {}];
    assert.throws(capture, /before PDF expansion/);
    assert.strictEqual(expansions, 2, 'A broadened report must fail before expanding its DOM.');
}

async function run() {
    const uiExercise = await assertUiControls();
    assertCardScopeCapture();
    let runtimeCalls = 0;
    const scopedRuntimeContext = { filteredData: [{}], ensurePdfExportRuntimeLoaded: async () => { runtimeCalls++; } };
    const prepareScopedRuntime = () => vm.runInNewContext(`(${loadScopedPdfRuntime.toString()})()`, scopedRuntimeContext);
    assert.strictEqual(await prepareScopedRuntime(), 1);
    assert.strictEqual(runtimeCalls, 1, 'Only the runtime is loaded; no PDF library function is supplied by this control.');
    for (const size of [0, 251]) {
        scopedRuntimeContext.filteredData = new Array(size);
        await assert.rejects(prepareScopedRuntime(), /selected 1-250/);
        assert.strictEqual(runtimeCalls, 1, 'An unadmitted scope must not load the runtime.');
    }
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
        const makeReport = (scope, report) => {
                const deviceReport = ['devices-by-remediation', 'remediations-by-device'].includes(report);
                const mode = scope === 'representative-range' ? 'range' : 'snapshot';
                const reportRows = scope === 'empty' ? 0 : 2;
                const before = { report, reportLabel: report, sourceRows: scope === 'empty' ? 0 : 2, expandedText: 'Synthetic exact report text', filter: { key: scope }, reportRows,
                    mode, modeSummary: deviceReport ? `Synthetic exact ${mode} UI scope explanation` : null,
                    includeResolvedText: deviceReport ? mode === 'range' ? 'Yes' : 'No' : null,
                    cardDetails: deviceReport ? Array.from({ length: reportRows }, () => ({ title: 'Synthetic card', metadata: ['Patch: KB000001', 'Platform: Windows 11'], statBadges: ['Devices: 1'] })) : [] };
                return { scope, report, before, after: structuredClone(before),
                    modeAction: deviceReport ? { mode, path: 'shared-toolbar-button', action: 'clicked' } : null,
                    pdf: { ...fileEvidence, suggestedFilename: `Vulnerability_Dashboard_${report}_2026-11-06.pdf`, exportUtcDayBefore: interval.utcDayBefore, exportUtcDayAfter: interval.utcDayAfter },
                    screenshot: fileEvidence, receipt: fileEvidence };
        };
        const result = { status: 'captured', restored: true, representativeRows: 2, runtimePreloadSourceRows: 2, uiExercise,
            reports: ['representative', 'empty'].flatMap(scope => reports.map(report => makeReport(scope, report)))
                .concat(['devices-by-remediation', 'remediations-by-device'].map(report => makeReport('representative-range', report))) };
        assertArtifactAcceptance(result);
        for (const mutate of [value => { value.restored = false; }, value => { value.reports[0].after.filter.key = 'broadened'; },
            value => { value.reports[5].before.sourceRows = 1; value.reports[5].after.sourceRows = 1; },
            value => { value.reports[1] = value.reports[0]; }, value => { value.reports[0].pdf.sha256 = 'missing'; },
            value => { value.reports[0].pdf.suggestedFilename = 'unrelated.pdf'; },
            value => { value.reports.pop(); },
            value => { value.reports[10].before.mode = value.reports[10].after.mode = 'snapshot'; },
            value => { value.reports[3].before.modeSummary = value.reports[3].after.modeSummary = ''; },
            value => { value.reports.filter(row => row.scope === 'representative-range').forEach(row => { row.modeAction.action = 'already-selected'; }); },
            value => { value.reports[3].before.cardDetails[0].title = value.reports[3].after.cardDetails[0].title = ''; }]) {
            const invalid = structuredClone(result); mutate(invalid); assert.throws(() => assertArtifactAcceptance(invalid));
        }
        console.log('PASS exact file URL/view policy, actual inline provenance, bounded callback operations, real-download ordering/failure, PDF truncation and scope/receipt invalidation controls (no browser launched)');
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

module.exports = { run };
if (require.main === module) run().catch(error => { console.error(error); process.exitCode = 1; });
