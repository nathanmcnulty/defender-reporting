const assert = require('assert');
const { createStubElement, loadDashboardHarness } = require('./helpers/dashboard-test-harness');

function assertSinglePillRefresh() {
    const dashboard = loadDashboardHarness(`
let pillRefreshes = 0;
renderFilterPills = () => { pillRefreshes++; };
applyFilters = () => updateFilterSummary();
module.exports = {
    document,
    handleClearAllFilters,
    closeActiveFilterPopover,
    applyDraft(target) {
        activeFilterPopoverKey = 'filterSeverity';
        filterPopoverDraftState = createEmptyFilterState();
        handleFilterPopoverClick({ target });
    },
    getRefreshes: () => pillRefreshes
};
`, { HTMLElement: Object });
    dashboard.document.elements.set('filterPopover', createStubElement({ removeAttribute() {} }));
    dashboard.applyDraft({ id: 'filterPopoverApplyButton' });
    assert.strictEqual(dashboard.getRefreshes(), 1, 'Applying a draft refreshes pills once');
    dashboard.handleClearAllFilters();
    assert.strictEqual(dashboard.getRefreshes(), 2, 'Clearing filters refreshes pills once');
    dashboard.closeActiveFilterPopover();
    assert.strictEqual(dashboard.getRefreshes(), 3, 'Cancel still refreshes open-pill state');
}

async function assertRenderReadiness() {
    function createFixture() {
        const frames = [];
        const timers = [];
        const events = [];
        let now = 0;
        const dashboard = loadDashboardHarness(`
let renderCalls = 0;
let renderFailure = false;
loadData = async () => {};
denormalizeWithCaching = async () => {};
buildDeviceFilterCatalog = () => {};
populateFilters = () => { filterState = finalizeFilterState(createEmptyFilterState()); };
updateDataQualitySummary = () => {};
initializeReportNavigationControls = () => {};
applyUrlViewState = () => {};
syncReportNavigationUi = () => {};
ensureChartJsLoaded = async () => {};
attachEventListeners = () => {};
setupInfiniteScroll = () => {};
updateViewShareButtonVisibility = () => {};
updateRemediationReportModeUi = () => {};
renderFilterPills = () => {};
syncUrlViewState = () => {};
scheduleReportDataWarmup = () => {};
renderDevicesByRemediationReport = () => {
    renderCalls++;
    if (renderFailure) throw new Error('injected render failure');
};
renderRemediationsByDeviceReport = () => { renderCalls++; };
module.exports = {
    document, window, init, applyFilters, scheduleApplyFilters, markDashboardReady,
    getDashboardMetricsSnapshot,
    setState(overrides) { filterState = finalizeFilterState({ ...createEmptyFilterState(), ...overrides }); },
    selectPendingReport() { document.getElementById('reportSelector').value = 'remediations-by-device'; },
    switchReport() {
        activeReportId = 'remediations-by-device';
        document.getElementById('reportSelector').value = activeReportId;
        scheduleVisibleReportRender(activeReportId, true);
    },
    useBrokenChart() {
        activeReportId = 'active-vulnerabilities';
        document.getElementById('reportSelector').value = activeReportId;
        renderChart = () => {};
        renderTable = () => {};
        chartInstance = null;
    },
    repairChart() {
        Chart.getChart = () => chartInstance;
        renderChart = () => { chartInstance = { ctx: {} }; };
    },
    failLoad() { loadData = async () => { throw new Error('injected load failure'); }; },
    failRender() { renderFailure = true; },
    getRenderCalls: () => renderCalls
};
`, {
            performance: { now: () => ++now },
            requestAnimationFrame: callback => { frames.push(callback); return frames.length; },
            console: { log() {}, error() {}, time() {}, timeEnd() {} },
            Chart: { getChart: () => undefined }
        });
        dashboard.window.setTimeout = callback => { timers.push(callback); return timers.length; };
        dashboard.window.dispatchEvent = event => events.push(event);
        dashboard.document.elements.set('dashboardStatus', createStubElement({ removeAttribute() {} }));
        dashboard.document.getElementById('reportSelector').value = 'devices-by-remediation';
        return {
            dashboard, frames, timers, events,
            flushFrame() { const batch = frames.splice(0); batch.forEach(callback => callback()); }
        };
    }

    const normal = createFixture();
    await normal.dashboard.init();
    assert.strictEqual(normal.events.length, 0, 'init must wait for queued rendering');
    assert.strictEqual(normal.dashboard.window._dashboardReady, false);
    normal.flushFrame();
    assert.strictEqual(normal.events.length, 1);
    assert.strictEqual(normal.dashboard.getRenderCalls(), 1);
    const rendered = normal.dashboard.getDashboardMetricsSnapshot();
    assert.ok(rendered.phases.initTotalMs > rendered.phases.filterComputationMs);
    assert.ok(rendered.phases.filterRenderCompletionMs > rendered.phases.filterComputationMs);
    assert.strictEqual(rendered.phases.applyFiltersMs, rendered.phases.filterComputationMs);
    assert.strictEqual(rendered.phases.filterPaintOpportunityMs, 0);
    normal.flushFrame();
    assert.strictEqual(normal.dashboard.getDashboardMetricsSnapshot().phases.filterPaintOpportunityMs, 0);
    normal.flushFrame();
    assert.ok(normal.dashboard.getDashboardMetricsSnapshot().phases.filterPaintOpportunityMs > rendered.phases.filterRenderCompletionMs);
    normal.dashboard.markDashboardReady();
    normal.dashboard.applyFilters();
    normal.flushFrame();
    assert.strictEqual(normal.events.length, 1, 'readiness is emitted once');

    const empty = createFixture();
    await empty.dashboard.init();
    empty.dashboard.setState({ hasDeviceNames: false });
    empty.dashboard.applyFilters();
    assert.strictEqual(empty.events.length, 1, 'empty selection completes synchronously');
    empty.flushFrame();
    assert.strictEqual(empty.dashboard.getRenderCalls(), 1, 'obsolete nonempty render is skipped');

    const superseded = createFixture();
    await superseded.dashboard.init();
    superseded.dashboard.setState({ deviceSearch: 'new selection' });
    superseded.dashboard.scheduleApplyFilters();
    superseded.flushFrame();
    assert.strictEqual(superseded.events.length, 0, 'debounced requests invalidate prior frames immediately');
    superseded.timers.shift()();
    superseded.flushFrame();
    assert.strictEqual(superseded.events.length, 1);
    assert.strictEqual(superseded.dashboard.getRenderCalls(), 1);

    const switched = createFixture();
    await switched.dashboard.init();
    switched.dashboard.switchReport();
    assert.strictEqual(switched.events.length, 1, 'navigation completes the current initial report');
    assert.strictEqual(switched.events[0].detail.validation.activeReportId, 'remediations-by-device');
    switched.flushFrame();
    assert.strictEqual(switched.dashboard.getRenderCalls(), 1, 'completed navigation supersedes the queued render');

    const pendingNavigation = createFixture();
    await pendingNavigation.dashboard.init();
    pendingNavigation.dashboard.selectPendingReport();
    pendingNavigation.flushFrame();
    assert.strictEqual(pendingNavigation.events.length, 0, 'pending report selection cannot report the old report as ready');
    pendingNavigation.dashboard.switchReport();
    assert.strictEqual(pendingNavigation.events.length, 1);
    assert.strictEqual(pendingNavigation.dashboard.getRenderCalls(), 1);

    const failure = createFixture();
    await failure.dashboard.init();
    failure.dashboard.failRender();
    failure.flushFrame();
    assert.strictEqual(failure.events.length, 0, 'failed rendering cannot signal readiness');
    assert.strictEqual(failure.dashboard.window._dashboardReady, false);
    assert.strictEqual(failure.dashboard.document.getElementById('dashboardStatus').dataset.statusKind, 'error');

    const chartFailure = createFixture();
    await chartFailure.dashboard.init();
    chartFailure.dashboard.setState({ startDate: '2026-01-01', endDate: '2026-01-31' });
    chartFailure.dashboard.useBrokenChart();
    chartFailure.dashboard.applyFilters();
    chartFailure.flushFrame();
    assert.strictEqual(chartFailure.events.length, 0, 'swallowed Chart construction failure cannot signal readiness');
    assert.strictEqual(chartFailure.dashboard.window._dashboardReady, false);
    chartFailure.dashboard.repairChart();
    chartFailure.dashboard.applyFilters();
    chartFailure.flushFrame();
    assert.strictEqual(chartFailure.events.length, 1, 'successful current retry can complete initialization');

    const emptyFailure = createFixture();
    await emptyFailure.dashboard.init();
    emptyFailure.dashboard.setState({ hasDeviceNames: false });
    emptyFailure.dashboard.failRender();
    emptyFailure.dashboard.applyFilters();
    emptyFailure.flushFrame();
    assert.strictEqual(emptyFailure.events.length, 0, 'synchronous empty render failures cannot signal success');

    const loadFailure = createFixture();
    loadFailure.dashboard.failLoad();
    await assert.rejects(loadFailure.dashboard.init(), /injected load failure/);
    assert.strictEqual(loadFailure.events.length, 0);
    assert.strictEqual(loadFailure.frames.length, 0);
}

function assertScopedFacetEquivalence() {
    let scannedRows = 0;
    const dashboard = loadDashboardHarness(`
module.exports = {
    document, window,
    createEmptyFilterState, finalizeFilterState, cloneFilterState, resetFilterInState,
    getScopedFilterOptions, getScopedFilterOptionCount, withScopedFilterOptionsCache,
    buildUrlViewStatePayload, parseUrlViewState, applyUrlViewState,
    closeActiveFilterPopover, handleFilterPopoverClick, handleFilterPopoverInput,
    setRows(rows) { vulnerabilityData = rows; },
    setLabels(labels) { deviceFilterLabelByKey = new Map(labels); },
    renameLabel(key, label) { deviceFilterLabelByKey.set(key, label); },
    setState(state) { filterState = state; },
    getState: () => filterState,
    startDraft(key) {
        activeFilterPopoverKey = key;
        filterPopoverDraftState = cloneFilterState(filterState);
        activeFilterPopoverOptions = getScopedFilterOptions(key);
    },
    changeDraft(state) { filterPopoverDraftState = state; },
    getDraft: () => filterPopoverDraftState,
    getFilteredOptionValues: () => activeFilterPopoverFilteredOptions.map(option => option.value),
    refreshDraft: renderActiveFilterPopover,
    getCacheSize: () => scopedFilterOptionsCache?.entries.size || 0
};
`, { HTMLElement: Object, URLSearchParams });
    dashboard.document.body.dataset = {};
    dashboard.document.getElementById('reportSelector').options = [];
    dashboard.document.elements.set('filterPopover', createStubElement({ removeAttribute() {} }));
    const rows = [
        { _deviceFilterKey: 'a', _deviceSearchText: 'duplicate a', _normalizedGroup: 'Servers', _tagValues: ['Prod'], OSPlatform: 'Windows', VulnerabilitySeverityLevel: 'High', _firstSeenDate: '2026-01-01', _effectiveOpenEndDate: '2026-01-10' },
        { _deviceFilterKey: 'b', _deviceSearchText: 'duplicate b', _normalizedGroup: '(none)', _tagValues: ['(No Tags)'], OSPlatform: 'Linux', VulnerabilitySeverityLevel: 'Low', _firstSeenDate: '2026-01-10', _effectiveOpenEndDate: '2026-02-01' },
        { _deviceFilterKey: 'a', _deviceSearchText: 'duplicate a', _normalizedGroup: 'Servers', _tagValues: ['Prod', 'Blue'], OSPlatform: 'Windows', VulnerabilitySeverityLevel: 'Critical', _firstSeenDate: '2025-12-01', _effectiveOpenEndDate: '2026-03-01' }
    ];
    for (const row of rows) {
        const date = row._firstSeenDate;
        Object.defineProperty(row, '_firstSeenDate', { configurable: true, get() { scannedRows++; return date; } });
    }
    dashboard.setRows(rows);
    dashboard.setLabels([['a', 'duplicate (a)'], ['b', 'duplicate (b)']]);
    const makeState = overrides => dashboard.finalizeFilterState({ ...dashboard.createEmptyFilterState(), startDate: '2026-01-01', endDate: '2026-01-31', ...overrides });
    const plain = options => JSON.parse(JSON.stringify(options));
    const facetKeys = ['filterDeviceName', 'filterRbacGroup', 'filterDeviceTags', 'filterOSPlatform', 'filterSeverity'];
    const cases = [
        {}, { hasDeviceNames: false }, { hasRbacGroups: false }, { hasDeviceTags: false },
        { hasSeverities: false }, { hasOsPlatforms: false },
        { deviceNames: ['a'] }, { rbacGroups: ['Servers'] }, { deviceTags: ['Prod'] },
        { severities: ['High'] }, { osPlatforms: ['Linux'] },
        { rbacGroups: ['(none)'], deviceTags: ['(No Tags)'] },
        { startDate: '2026-01-10', endDate: '2026-01-10' },
        { startDate: '2024-01-01', endDate: '2024-02-01' },
        { startDate: '', endDate: '', deviceSearch: 'DUPLICATE B' },
        { deviceSearch: 'no matches' },
        { deviceTags: ['Prod\u001fBlue'] }, { deviceTags: ['Prod', 'Blue'] }
    ];
    for (const overrides of cases) {
        const state = makeState(overrides);
        dashboard.setState(state);
        const expected = facetKeys.map(key => plain(dashboard.getScopedFilterOptions(key, state)));
        dashboard.withScopedFilterOptionsCache(() => {
            facetKeys.forEach((key, index) => {
                const first = dashboard.getScopedFilterOptions(key, state);
                const second = dashboard.getScopedFilterOptions(key, state);
                assert.strictEqual(first, second, 'repeat reads reuse scoped results, including zero options');
                assert.deepStrictEqual(plain(second), expected[index]);
            });
            assert.ok(dashboard.getCacheSize() <= facetKeys.length);
        });
        assert.strictEqual(dashboard.getCacheSize(), 0, 'no results survive the synchronous operation');
    }

    const subset = makeState({ rbacGroups: ['Servers'] });
    const scopedStates = [makeState({}), makeState({ hasRbacGroups: false }), makeState({ rbacGroups: ['Servers'] }), makeState({ startDate: '2024-01-01', endDate: '2024-02-01' }), makeState({ deviceSearch: 'duplicate b', severities: ['Low'] })];
    const scopedExpected = scopedStates.map(state => plain(dashboard.getScopedFilterOptions('filterDeviceTags', state)));
    dashboard.withScopedFilterOptionsCache(() => {
        scopedStates.forEach((state, index) => assert.deepStrictEqual(plain(dashboard.getScopedFilterOptions('filterDeviceTags', state)), scopedExpected[index], 'dates/search/selections/all-none distinguish cache entries'));
    });
    assert.deepStrictEqual(plain(dashboard.getScopedFilterOptions('filterRbacGroup', subset)).map(option => option.value), ['(none)', 'Servers'], 'facet reset clears derived selection Sets');
    const all = makeState({});
    assert.strictEqual(dashboard.getScopedFilterOptions('filterDeviceName', all).length, 2, 'duplicate device names preserve distinct identities');
    scannedRows = 0;
    for (let iteration = 0; iteration < 3; iteration++) dashboard.getScopedFilterOptions('filterDeviceName', all);
    const uncachedScans = scannedRows;
    scannedRows = 0;
    dashboard.withScopedFilterOptionsCache(() => {
        for (let iteration = 0; iteration < 3; iteration++) dashboard.getScopedFilterOptions('filterDeviceName', all);
    });
    const cachedScans = scannedRows;
    assert.strictEqual(uncachedScans, rows.length * 3);
    assert.strictEqual(cachedScans, rows.length);
    console.log(`[facet] repeated scoped reads: ${uncachedScans} -> ${cachedScans} row visits`);

    dashboard.withScopedFilterOptionsCache(() => dashboard.getScopedFilterOptions('filterDeviceName', all));
    rows[0]._normalizedGroup = 'Changed';
    assert.deepStrictEqual(plain(dashboard.withScopedFilterOptionsCache(() => dashboard.getScopedFilterOptions('filterRbacGroup', all))), plain(dashboard.getScopedFilterOptions('filterRbacGroup', all)), 'in-place data changes are visible in the next operation');
    dashboard.renameLabel('a', 'in-place label');
    assert.ok(dashboard.withScopedFilterOptionsCache(() => dashboard.getScopedFilterOptions('filterDeviceName', all)).some(option => option.label === 'in-place label'), 'in-place catalog edits are visible in the next operation');
    dashboard.setLabels([['a', 'renamed'], ['b', 'duplicate (b)']]);
    assert.ok(dashboard.withScopedFilterOptionsCache(() => dashboard.getScopedFilterOptions('filterDeviceName', all)).some(option => option.label === 'renamed'));
    dashboard.withScopedFilterOptionsCache(() => {
        dashboard.getScopedFilterOptions('filterDeviceName', all);
        dashboard.setRows([]);
        assert.strictEqual(dashboard.getScopedFilterOptions('filterDeviceName', all).length, 0, 'dataset replacement invalidates active scope');
    });
    dashboard.setRows(rows);
    assert.throws(() => dashboard.withScopedFilterOptionsCache(() => { throw new Error('scope failure'); }), /scope failure/);
    assert.strictEqual(dashboard.getCacheSize(), 0);

    dashboard.setState(subset);
    dashboard.startDraft('filterRbacGroup');
    dashboard.changeDraft(makeState({ hasRbacGroups: false }));
    dashboard.closeActiveFilterPopover();
    assert.strictEqual(dashboard.getState(), subset, 'draft cancellation retains committed state');
    dashboard.startDraft('filterRbacGroup');
    dashboard.handleFilterPopoverClick({ target: { id: 'filterPopoverResetButton' } });
    assert.strictEqual(dashboard.getDraft().rbacGroupSet.size, 0);
    assert.strictEqual(dashboard.getDraft().hasRbacGroups, true);
    assert.strictEqual(dashboard.getState(), subset, 'draft reset does not commit');
    dashboard.document.getElementById('filterPopoverSearchInput').value = 'changed';
    dashboard.handleFilterPopoverInput({ target: { id: 'filterPopoverSearchInput' } });
    assert.deepStrictEqual(Array.from(dashboard.getFilteredOptionValues()), ['Changed'], 'popover search filters scoped options');
    dashboard.closeActiveFilterPopover();

    const urlState = makeState({ startDate: '2025-12-01', endDate: '2026-01-10', deviceSearch: 'duplicate', deviceNames: ['b'], hasSeverities: false });
    const payload = dashboard.buildUrlViewStatePayload(urlState);
    dashboard.window.location = { search: `?view=${encodeURIComponent(JSON.stringify(payload))}` };
    const restored = dashboard.parseUrlViewState().filterState;
    facetKeys.forEach(key => assert.deepStrictEqual(plain(dashboard.getScopedFilterOptions(key, restored)), plain(dashboard.getScopedFilterOptions(key, urlState))));
    assert.strictEqual(dashboard.applyUrlViewState(), true);
    assert.strictEqual(dashboard.getState().hasSeverities, false);
}

async function assertExternalScriptDeadlines() {
    const timers = new Map();
    const scripts = [];
    let nextTimer = 0;
    const dashboard = loadDashboardHarness(`
module.exports = {
    document, window, loadExternalScript, unloadExternalScript,
    getPendingCount: () => loadedScriptCleanups.size,
    getCachedCount: () => loadedScriptPromises.size
};
`, { clearTimeout: handle => timers.delete(handle) });
    dashboard.window.setTimeout = (callback, milliseconds) => {
        assert.strictEqual(milliseconds, 15000);
        timers.set(++nextTimer, callback);
        return nextTimer;
    };
    dashboard.document.createElement = () => {
        const script = createStubElement({ removed: false, remove() { this.removed = true; } });
        scripts.push(script);
        return script;
    };
    dashboard.document.head = { appendChild() {} };
    dashboard.document.querySelectorAll = () => scripts.filter(script => !script.removed);
    await assert.rejects(dashboard.loadExternalScript(''), /URL is required/);

    const first = dashboard.loadExternalScript('/runtime.js');
    assert.strictEqual(dashboard.loadExternalScript('/runtime.js'), first, 'concurrent loads share one attempt');
    const firstScript = scripts[0];
    const lateLoad = firstScript.onload;
    const lateError = firstScript.onerror;
    const firstFailure = assert.rejects(first, /timed out/);
    Array.from(timers.values())[0]();
    await firstFailure;
    assert.strictEqual(firstScript.removed, true);
    assert.strictEqual(firstScript.onload, null);
    assert.strictEqual(firstScript.onerror, null);
    assert.strictEqual(timers.size, 0);
    assert.strictEqual(dashboard.getPendingCount(), 0);
    assert.strictEqual(dashboard.getCachedCount(), 0);

    const retry = dashboard.loadExternalScript('/runtime.js');
    let retrySettled = false;
    retry.then(() => { retrySettled = true; });
    lateLoad();
    lateError();
    await Promise.resolve();
    assert.strictEqual(retrySettled, false, 'late callbacks cannot settle the retry');
    assert.strictEqual(dashboard.loadExternalScript('/runtime.js'), retry, 'late failure cannot evict the retry');
    scripts[1].onload();
    await retry;
    assert.strictEqual(timers.size, 0);
    assert.strictEqual(dashboard.getPendingCount(), 0);
    assert.strictEqual(dashboard.loadExternalScript('/runtime.js'), retry, 'success remains deduplicated');
    dashboard.unloadExternalScript('/runtime.js');
    assert.strictEqual(scripts[1].removed, true);
    assert.strictEqual(dashboard.getCachedCount(), 0);

    const errorAttempt = dashboard.loadExternalScript('/runtime.js');
    const errorAssertion = assert.rejects(errorAttempt, /Failed to load script/);
    scripts[2].onerror();
    await errorAssertion;
    assert.strictEqual(timers.size, 0);
    assert.strictEqual(scripts[2].removed, true);
    const cancelled = dashboard.loadExternalScript('/runtime.js');
    const cancelledAssertion = assert.rejects(cancelled, /cancelled/);
    const cancelledLateLoad = scripts[3].onload;
    dashboard.unloadExternalScript('/runtime.js');
    await cancelledAssertion;
    const afterCancel = dashboard.loadExternalScript('/runtime.js');
    cancelledLateLoad();
    assert.strictEqual(dashboard.loadExternalScript('/runtime.js'), afterCancel);
    scripts[4].onload();
    await afterCancel;
    dashboard.unloadExternalScript('/runtime.js');

    dashboard.document.head.appendChild = () => { throw new Error('injected append failure'); };
    await assert.rejects(dashboard.loadExternalScript('/append.js'), /injected append failure/);
    assert.strictEqual(timers.size, 0);
    assert.strictEqual(dashboard.getPendingCount(), 0);
    assert.strictEqual(dashboard.getCachedCount(), 0);
}

async function main() {
    let currentNow = 0;
    let worker;
    class TestWorker {
        constructor() { worker = this; }
        postMessage() {}
        terminate() { this.terminated = true; }
    }
    const dashboard = loadDashboardHarness(`
module.exports = {
    document,
    window,
    buildDashboardValidationSnapshot,
    getDashboardMetricsSnapshot,
    publishDashboardDiagnostics,
    recordDashboardPhaseTiming,
    recordDashboardRenderTiming,
    markDashboardReady,
    denormalizeInWorker,
    setActiveReportIdForTest(value) {
        activeReportId = value;
    }
};
`, {
    Worker: TestWorker,
    Blob,
    URL: { createObjectURL() { return 'blob:test'; }, revokeObjectURL() {} },
        performance: {
        timeOrigin: 1000,
            now() {
                currentNow += 10;
                return currentNow;
            }
        }
    });

    dashboard.window.dispatchEvent = event => {
        dashboard.window.__lastEvent = event;
    };

    const selector = dashboard.document.getElementById('reportSelector');
    selector.value = 'impact-analysis';
    selector.options = {
        0: { value: 'active-vulnerabilities', textContent: 'Active Vulnerabilities' },
        1: { value: 'remediation-activity', textContent: 'Remediation Activity' },
        2: { value: 'impact-analysis', textContent: 'Impact Analysis' },
        length: 3
    };

    dashboard.document.getElementById('criticalCount').textContent = '12';
    dashboard.document.getElementById('highCount').textContent = '34';
    dashboard.document.getElementById('mediumCount').textContent = '56';
    dashboard.document.getElementById('lowCount').textContent = '78';

    dashboard.setActiveReportIdForTest('impact-analysis');
    dashboard.recordDashboardPhaseTiming('loadDataMs', 123.4567);
    dashboard.recordDashboardPhaseTiming('denormalizeMs', 456.7891);
    dashboard.recordDashboardPhaseTiming('applyFiltersMs', 12.3456);
    dashboard.recordDashboardRenderTiming('impact-analysis', 78.9012);

    const published = dashboard.publishDashboardDiagnostics();
    assert.strictEqual(published.metrics.deliveryMode, 'self-contained');
    assert.strictEqual(published.metrics.activeReportId, 'impact-analysis');
    assert.strictEqual(published.metrics.phases.loadDataMs, 123.457);
    assert.strictEqual(published.metrics.phases.denormalizeMs, 456.789);
    assert.strictEqual(published.metrics.phases.applyFiltersMs, 12.346);
    assert.strictEqual(published.metrics.reports['impact-analysis'].count, 1);
    assert.strictEqual(published.metrics.reports['impact-analysis'].lastMs, 78.901);
    assert.strictEqual(published.validation.activeReportId, 'impact-analysis');
    assert.strictEqual(published.validation.summaryCards.critical, '12');
    assert.strictEqual(published.validation.summaryCards.high, '34');
    assert.strictEqual(published.validation.summaryCards.medium, '56');
    assert.strictEqual(published.validation.summaryCards.low, '78');
    assert.strictEqual(published.validation.reportSelectorOptions.length, 3);
    assert.strictEqual(published.validation.reportSelectorOptions[2].value, 'impact-analysis');

    dashboard.markDashboardReady();

    assert.strictEqual(dashboard.window._dashboardReady, true);
    assert.ok(dashboard.window.dashboardMetrics);
    assert.ok(dashboard.window.dashboardValidation);
    assert.strictEqual(dashboard.window.dashboardMetrics.ready, true);
    assert.strictEqual(dashboard.window.__lastEvent.type, 'dashboard-ready');
    assert.strictEqual(dashboard.window.__lastEvent.detail.metrics.ready, true);
    assert.strictEqual(dashboard.window.__lastEvent.detail.validation.activeReportId, 'impact-analysis');

    const legacy = { rows: [], lookups: {}, rawVulns: {} };
    const legacyOperation = dashboard.denormalizeInWorker();
    worker.onmessage({ data: { phase: 'workerInflateMs', duration: 12.5 } });
    assert(!worker.terminated, 'A phase message must not complete the worker operation.');
    worker.onmessage({ data: { phase: 'workerParseMs', duration: 7.25 } });
    worker.onmessage({ data: legacy });
    assert.strictEqual(await legacyOperation, legacy, 'Legacy worker envelope must remain unchanged.');
    assert(worker.terminated);
    let metrics = dashboard.getDashboardMetricsSnapshot();
    assert.strictEqual(metrics.phases.workerInflateMs, 12.5);
    assert.strictEqual(metrics.phases.workerParseMs, 7.25);
    assert(Number.isFinite(metrics.phases.workerWaitMs));

    const timed = { rows: null, lookups: {}, rawVulns: {}, postedAt: 1000 + currentNow };
    const timedOperation = dashboard.denormalizeInWorker();
    worker.onmessage({ data: timed });
    assert.strictEqual(await timedOperation, timed, 'Timed worker envelope must retain its payload shape.');
    metrics = dashboard.getDashboardMetricsSnapshot();
    assert(metrics.phases.workerDeliveryMs >= 0);

    await require('./Measure-DashboardWorkerTransfer').mockProbes();
}

async function run() {
    assertSinglePillRefresh();
    await main();
    await assertRenderReadiness();
    assertScopedFacetEquivalence();
    await assertExternalScriptDeadlines();
}

run().catch(error => {
    console.error(error);
    process.exitCode = 1;
});