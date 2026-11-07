const assert = require('assert');
const fs = require('fs');
const crypto = require('crypto');
const { loadDashboardHarness, createDocumentStub, createStubElement } = require('./helpers/dashboard-test-harness');

function assertHiddenSelections() {
    const dashboard = loadDashboardHarness(`
updateFilterPopoverSummary = updateFilterPopoverFooterState = () => {};
module.exports = {
    toggleFilterPopoverOptionSelection, setAllFilterPopoverOptionsSelected, getDraftSelectedCount,
    configure(values, visible, hasAny = true) {
        activeFilterPopoverKey = 'filterRbacGroup';
        filterPopoverDraftState = { rbacGroups: values, hasRbacGroups: hasAny };
        activeFilterPopoverOptions = visible.map(value => ({ value }));
    },
    values: () => Array.from(filterPopoverDraftState.rbacGroups),
    any: () => filterPopoverDraftState.hasRbacGroups,
    checked: () => document.getElementById('filterPopoverAllCheckbox').checked,
};`);
    dashboard.configure(['A', 'B'], ['B']);
    dashboard.toggleFilterPopoverOptionSelection('B', false);
    assert.deepStrictEqual(Array.from(dashboard.values()), ['A'], 'deselection retains hidden explicit A');
    assert.strictEqual(dashboard.any(), true);
    assert.strictEqual(dashboard.getDraftSelectedCount('filterRbacGroup'), 0);
    assert.strictEqual(dashboard.checked(), false, 'hidden selection cannot mark visible B checked');
    dashboard.toggleFilterPopoverOptionSelection('B', true);
    assert.deepStrictEqual(Array.from(dashboard.values()), ['A', 'B'], 'individual selection never becomes All');
    dashboard.configure(dashboard.values(), ['A', 'B', 'C']);
    dashboard.toggleFilterPopoverOptionSelection('B', false);
    assert.deepStrictEqual(Array.from(dashboard.values()), ['A'], 'reopened scope never admits C');
    dashboard.configure(['A'], []);
    dashboard.toggleFilterPopoverOptionSelection('A', false);
    assert.deepStrictEqual(Array.from(dashboard.values()), []);
    assert.strictEqual(dashboard.any(), false, 'zero selections means None');
    dashboard.setAllFilterPopoverOptionsSelected(true);
    assert.strictEqual(dashboard.any(), true, 'only explicit All admits all values');
    dashboard.configure([], ['B']);
    dashboard.toggleFilterPopoverOptionSelection('B', false);
    assert.strictEqual(dashboard.any(), false, 'deselect last visible value from All becomes None');
}

// A valid image keeps actual pdfmake checks separate from the deliberately stubbed capture.
const png = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a5XcAAAAASUVORK5CYII=';
function element(textContent = '', selectors = {}) {
    return createStubElement({
        textContent,
        cloneNode() {
            const copied = {};
            for (const [key, value] of Object.entries(selectors)) {
                copied[key] = Array.isArray(value) ? value.map(item => item.cloneNode(true)) : value.cloneNode(true);
            }
            const clone = element(this.textContent, copied);
            clone.colSpan = this.colSpan;
            return clone;
        },
        querySelector(selector) { return selectors[selector] || null; },
        querySelectorAll(selector) { return selectors[selector] || []; }
    });
}
function tableSection(columns, text, empty = false) {
    const cells = empty ? [Object.assign(element(text), { colSpan: columns })]
        : Array.from({ length: columns }, (_, i) => element(i === 0 ? text : `value-${i}`));
    const row = element('', { td: cells });
    const table = element('', {
        'thead th': Array.from({ length: columns }, (_, i) => element(`Heading ${i}`)),
        'tbody tr': [row]
    });
    return element('', { table });
}

async function assertSnapshotAndEmptyPdf() {
    const document = createDocumentStub();
    document.body.removeChild = () => {};
    const stats = element('initial-statistics');
    const main = element('', { '.stats-summary': stats });
    document.querySelector = selector => selector === '.container' ? main : null;
    document.createElement = () => createStubElement();
    let pendingCapture;
    const dashboard = loadDashboardHarness(`module.exports = { exportTableBasedReportToPdf, exportCardBasedReportToPdf };`, {
        document,
        html2canvas: () => new Promise(resolve => { pendingCapture = resolve; })
    });
    const definitions = [];
    for (const [report, columns] of [['active-vulnerabilities', 8], ['remediation-activity', 6], ['impact-analysis', 6]]) {
        const original = tableSection(columns, 'No matching results.', true);
        document.elements.set(`${report}-section`, original);
        const pending = dashboard.exportTableBasedReportToPdf(report, report);
        original.querySelector('table').querySelectorAll('tbody tr')[0].querySelectorAll('td')[0].textContent = 'new scope';
        document.elements.set(`${report}-section`, tableSection(columns, 'new report'));
        pendingCapture({ toDataURL: () => png });
        const result = await pending;
        const table = result.content.find(item => item.table).table;
        assert.deepStrictEqual(Array.from(table.body, row => row.length), [columns, columns]);
        assert.strictEqual(table.body[1][0].text, 'No matching results.');
        assert.strictEqual(table.body[1][0].colSpan, columns);
        definitions.push(result);
    }
    for (const report of ['devices-by-remediation', 'remediations-by-device']) {
        document.elements.set(`${report}-section`, element());
        const pending = dashboard.exportCardBasedReportToPdf(report, report);
        pendingCapture({ toDataURL: () => png });
        const result = await pending;
        assert.ok(result.content.some(item => item.text === 'No matching results.'));
        definitions.push(result);
    }
    // Pin library hashes in the invocation receipt; CI can supply its existing cache.
    const library = process.env.PDFMAKE_TEST_LIBRARY;
    const fonts = process.env.PDFMAKE_TEST_FONTS;
    assert.strictEqual(Boolean(library), Boolean(fonts), 'supply both real pdfmake and font paths');
    if (library) {
        assert.strictEqual(crypto.createHash('sha256').update(fs.readFileSync(library)).digest('hex'),
            '2cbaf08351e7fdbcd657e3a81f11430d7a89357ba8f02da6dd0b54a0c29b785f', 'expected pinned pdfmake 0.2.7');
        assert.strictEqual(crypto.createHash('sha256').update(fs.readFileSync(fonts)).digest('hex'),
            '845bef69547f3aabfa0441ab2547f20c04efd82188bd794ebdf74157467e4315', 'expected pinned pdfmake fonts');
        const pdfmake = require(require('path').resolve(library));
        pdfmake.vfs = require(require('path').resolve(fonts)).pdfMake.vfs;
        for (const definition of definitions) {
            const bytes = await new Promise(resolve => pdfmake.createPdf(definition).getBuffer(resolve));
            assert.ok(Buffer.from(bytes).subarray(0, 5).equals(Buffer.from('%PDF-')));
        }
        console.log('PASS real pdfmake document generation for all five empty report families.');
    } else {
        console.log('Real pdfmake generation not run: set PDFMAKE_TEST_LIBRARY and PDFMAKE_TEST_FONTS to pinned cached libraries.');
    }
}

async function assertExportScopeLock() {
    for (const report of ['active-vulnerabilities', 'remediation-activity', 'impact-analysis',
        'devices-by-remediation', 'remediations-by-device']) {
        const document = createDocumentStub();
        const attributes = new Map();
        const listeners = new Map();
        const button = createStubElement();
        const main = element('', { '.stats-summary': element('initial statistics') });
        main.getAttribute = name => attributes.get(name) ?? null;
        main.setAttribute = (name, value) => attributes.set(name, value);
        main.removeAttribute = name => attributes.delete(name);
        document.querySelector = selector => selector === '.container' ? main : button;
        document.body.removeChild = () => {};
        document.addEventListener = (type, listener) => listeners.set(type, listener);
        document.removeEventListener = type => listeners.delete(type);
        Object.assign(document.getElementById('reportSelector'), {
            value: report, selectedIndex: 0, options: [{ text: 'Original Report' }]
        });
        const columns = report === 'active-vulnerabilities' ? 8 : 6;
        document.elements.set(`${report}-section`, report.includes('-by-') ? element() : tableSection(columns, 'original row'));
        let captured;
        let dashboard;
        let boundaryCount = 0;
        let flushCount = 0;
        const boundary = () => {
            boundaryCount++;
            assert.strictEqual(attributes.get('inert'), '');
            let prevented = false;
            let stopped = false;
            listeners.get('click')({ preventDefault() { prevented = true; }, stopImmediatePropagation() { stopped = true; } });
            assert.ok(prevented && stopped, 'capture listener blocks direct mouse/keyboard activation');
            const previous = JSON.stringify(dashboard.state());
            dashboard.selectReportById('impact-analysis');
            dashboard.handleClearAllFilters();
            dashboard.setDateRange('12m');
            dashboard.setRemediationReportMode('snapshot');
            dashboard.handleFilterPopoverClick({ target: { id: 'filterPopoverApplyButton' } });
            dashboard.applyUrlViewState();
            assert.strictEqual(JSON.stringify(dashboard.state()), previous, 'public navigation/filter/mode changes are blocked');
        };
        dashboard = loadDashboardHarness(`
activeReportId = ${JSON.stringify(report)};
filterState = finalizeFilterState({ ...createEmptyFilterState(), rbacGroups: ['Original group'] });
applyFiltersTimer = 123;
applyFilters = () => testFlush();
loadPdfLibraries = async () => testBoundary();
maybeConfirmLargePdfExport = async () => { testBoundary(); return true; };
renderReport = renderRemediationTablePage = renderRemediationDetailsTablePage = renderImpactAnalysisTablePage = renderDevicesByRemediationTablePage = renderRemediationsByDeviceTablePage = () => {};
getExportFilterText = () => filterState.rbacGroups.join(',');
setDashboardStatus = clearDashboardStatus = () => {};
module.exports = { exportToPDF, selectReportById, handleClearAllFilters, setDateRange,
    setRemediationReportMode, handleFilterPopoverClick, applyUrlViewState,
    state: () => [document.getElementById('reportSelector').value, filterState.key, remediationReportMode],
    locked: () => pdfExportInProgress
};`, {
            document, HTMLElement: Object, testBoundary: boundary, testFlush: () => flushCount++,
            html2canvas: async () => { boundary(); return { toDataURL: () => png }; },
            setTimeout(callback, delay) {
                if (delay === 100) { boundary(); queueMicrotask(callback); return 0; }
                return setTimeout(callback, delay);
            },
            pdfMake: { createPdf(definition) {
                captured = definition;
                return { download(filename, done) { boundary(); assert.ok(filename.includes('Original_Report')); done(); } };
            } }
        });
        await dashboard.exportToPDF();
        assert.ok(boundaryCount >= 5, 'libraries, confirmation, expansion, capture and download are exercised');
        assert.ok(captured.content.some(item => item.text?.[0]?.text === 'Groups: ' && item.text[1].text === 'Original group'));
        assert.strictEqual(dashboard.locked(), false);
        assert.strictEqual(attributes.has('inert'), false);
        assert.strictEqual(listeners.size, 0);
        assert.strictEqual(button.disabled, false);
        assert.strictEqual(flushCount, 1, 'pending filter application is flushed once before locking');
    }
}

async function assertPendingNavigationAndChart() {
    const document = createDocumentStub();
    const main = element('', { '.stats-summary': element('statistics') });
    main.removeAttribute = () => {};
    document.querySelector = () => main;
    let release;
    const loading = new Promise(resolve => { release = resolve; });
    const statuses = [];
    const navigation = loadDashboardHarness(`
ensureChartJsLoaded = () => testLoading;
setDashboardStatus = message => testStatuses.push(message);
clearDashboardStatus = updateRemediationReportModeUi = syncReportNavigationUi = syncUrlViewState = publishDashboardDiagnostics = scheduleVisibleReportRender = () => {};
module.exports = { handleReportChange, handleExportPdfClick, exportToPDF, lockDashboardForPdf,
    active: () => activeReportId, locked: () => pdfExportInProgress };
`, { document, testLoading: loading, testStatuses: statuses });
    document.getElementById('reportSelector').value = 'remediation-activity';
    const pending = navigation.handleReportChange();
    await navigation.handleExportPdfClick();
    await navigation.exportToPDF();
    assert.strictEqual(statuses.filter(message => message.includes('Wait for the selected report')).length, 2);
    assert.strictEqual(navigation.locked(), false, 'pending navigation refuses both export entrypoints before acquiring the lock');
    release();
    await pending;
    assert.strictEqual(navigation.active(), 'remediation-activity', 'original navigation must finish after export was refused');

    document.getElementById('reportSelector').value = 'impact-analysis';
    const pendingDuringLock = navigation.handleReportChange();
    const unlock = navigation.lockDashboardForPdf();
    await pendingDuringLock;
    assert.strictEqual(navigation.active(), 'remediation-activity', 'pending chart-load navigation cannot switch mid-export');
    unlock();

    const events = [];
    const chartCanvas = { toDataURL() { events.push('image'); return png; } };
    document.elements.set('active-vulnerabilities-section', element('', { '.chart-container canvas': chartCanvas }));
    // Canvas clone is irrelevant to the copied chart image; emulate DOM cloneNode.
    chartCanvas.cloneNode = () => element();
    const snapshotHarness = loadDashboardHarness('module.exports = { capturePdfReportSnapshot };', {
        document, Chart: { getChart: () => ({ stop() { events.push('stop'); }, update(mode) { events.push(mode); } }) }
    });
    const snapshot = snapshotHarness.capturePdfReportSnapshot('active-vulnerabilities');
    assert.strictEqual(snapshot.chartImage, png);
    assert.deepStrictEqual(events, ['stop', 'none', 'image'], 'chart final data must paint before snapshot');
}

(async () => {
    assertHiddenSelections();
    await assertSnapshotAndEmptyPdf();
    await assertExportScopeLock();
    await assertPendingNavigationAndChart();
    console.log('Dashboard scoped selection and PDF snapshot/empty assertions passed.');
})().catch(error => { console.error(error); process.exit(1); });
