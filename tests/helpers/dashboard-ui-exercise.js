const assert = require('assert');

const FACETS = {
    filterRbacGroup: 'filterPillRbacGroup', filterOSPlatform: 'filterPillOSPlatform',
    filterSeverity: 'filterPillSeverity', filterDeviceName: 'filterPillDeviceName'
};
const REPORTS = ['active-vulnerabilities', 'impact-analysis', 'remediation-activity', 'devices-by-remediation', 'remediations-by-device'];

async function facetOption(page, wait, key, value) {
    const search = page.locator('#filterPopoverSearchInput');
    if (await wait(search.count())) {
        const label = await wait(page.evaluate(({ key, value }) => getFilterOptionLabel(key, value), { key, value }));
        await wait(search.fill(label));
    }
    const options = page.locator('#filterPopoverOptions input[data-option-value]');
    const values = await wait(options.evaluateAll(elements => elements.map(element => element.dataset.optionValue)));
    const index = values.indexOf(value);
    assert(index >= 0 && values.lastIndexOf(value) === index, 'Requested UI option is not uniquely offered.');
    return options.nth(index);
}

async function waitForUiReport(page, wait, timeout, report = null) {
    await wait(page.waitForFunction(expected => {
        const report = expected || activeReportId;
        const section = document.getElementById(report + '-section');
        return activeReportId === report && document.getElementById('reportSelector').value === report
            && initializedReports.has(report) && !dirtyReports.has(report)
            && section?.classList.contains('active') && section.getAttribute('aria-busy') !== 'true';
    }, report, { timeout }));
}

async function selectReportWithUi(page, wait, timeout, report) {
    assert(REPORTS.includes(report), 'Unknown UI report.');
    await wait(page.locator('#reportSelectorButton').click());
    await wait(page.locator(`#reportSelectorOptions button[data-report-id="${report}"]`).click());
    await waitForUiReport(page, wait, timeout, report);
}

async function setFacetWithUi(page, wait, timeout, key, selection) {
    assert(Object.hasOwn(FACETS, key) && Array.isArray(selection.values) && typeof selection.hasAny === 'boolean', 'Invalid UI facet selection.');
    assert(selection.hasAny || selection.values.length === 0, 'None must have no explicit values.');
    await wait(page.locator('#' + FACETS[key]).click());
    if (selection.hasAny && !selection.values.length) {
        const reset = page.locator('#filterPopoverResetButton');
        if (await wait(reset.isEnabled())) await wait(reset.click());
    } else {
        // A mixed checkbox can already be unchecked; check then uncheck to
        // deliberately use the shipped explicit None action in every state.
        await wait(page.locator('#filterPopoverAllCheckbox').check());
        await wait(page.locator('#filterPopoverAllCheckbox').uncheck());
        for (const value of selection.values) {
            await wait((await facetOption(page, wait, key, value)).check());
        }
    }
    const apply = page.locator('#filterPopoverApplyButton');
    await wait((await wait(apply.isEnabled()) ? apply : page.locator('#filterPopoverCancelButton')).click());
    await waitForUiReport(page, wait, timeout);
    const committed = await wait(page.evaluate(key => {
        const config = FILTER_POPOVER_CONFIG[key];
        return { values: Array.from(filterState[config.stateKey]), hasAny: filterState[config.hasAnyKey], rows: filteredData.length };
    }, key));
    assertFacetSelection(committed, selection);
    return committed;
}

function assertFacetSelection(actual, expected) {
    assert.strictEqual(actual.hasAny, expected.hasAny, 'UI changed All/None semantics.');
    assert.deepStrictEqual([...actual.values].sort(), [...expected.values].sort(), 'UI broadened or discarded explicit selections.');
    assert(Number.isSafeInteger(actual.rows) && actual.rows >= 0);
    if (!expected.hasAny) assert.strictEqual(actual.rows, 0, 'None must produce a valid empty scope.');
}

function planFacetUi() {
    const state = cloneFilterState(filterState);
    const severity = getScopedFilterOptions('filterSeverity')[0]?.value;
    const base = finalizeFilterState({ ...state, rbacGroups: [], hasRbacGroups: true, osPlatforms: [], hasOsPlatforms: true });
    const groups = new Map(); const platforms = new Set(); const devices = new Map();
    for (const row of vulnerabilityData) if (matchesFilterState(row, base)) {
        if (!groups.has(row._normalizedGroup)) groups.set(row._normalizedGroup, new Set());
        groups.get(row._normalizedGroup).add(row.OSPlatform); platforms.add(row.OSPlatform);
        const id = getDeviceNameFilterValue(row);
        if (id) {
            if (!devices.has(id)) devices.set(id, { id, groups: new Set(), platforms: new Set() });
            devices.get(id).groups.add(row._normalizedGroup); devices.get(id).platforms.add(row.OSPlatform);
        }
    }
    // Prefer two existing stable device identities. This creates a genuine
    // group/platform intersection even when every full group spans all OSes.
    const stable = Array.from(devices.values()).filter(device => device.groups.size === 1 && device.platforms.size === 1)
        .map(device => ({ id: device.id, group: [...device.groups][0], platform: [...device.platforms][0] }));
    let pair = null; let differentGroup = null; let differentPlatform = null;
    const anchor = stable[0];
    for (let index = 1; index < stable.length; index++) {
        const device = stable[index];
        if (device.group !== anchor.group && device.platform !== anchor.platform) { pair = [anchor, device]; break; }
        if (device.group !== anchor.group) differentGroup ||= device;
        if (device.platform !== anchor.platform) differentPlatform ||= device;
        if (differentGroup && differentPlatform) { pair = [differentGroup, differentPlatform]; break; }
    }
    let hidden = pair ? { invisible: pair[0].group, visible: pair[1].group, platform: pair[1].platform, devices: pair.map(device => device.id) } : null;
    if (!hidden && groups.size >= 2) for (const platform of platforms) {
        const visible = Array.from(groups).find(([, values]) => values.has(platform))?.[0];
        const invisible = Array.from(groups).find(([, values]) => !values.has(platform))?.[0];
        if (visible && invisible) { hidden = { visible, invisible, platform }; break; }
    }
    return { state, severity, hidden };
}

async function exerciseFacetUi(page, wait, timeout) {
    const plan = await wait(page.evaluate(planFacetUi));
    assert(plan.severity, 'Representative UI severity is missing.');
    const result = { status: 'exercised', path: 'locator-facet-click-check-apply', selectedFacet: 'filterSeverity', deselectionRows: null,
        hiddenSelection: { status: 'unavailable-fixture-intersection' } };
    try {
        await setFacetWithUi(page, wait, timeout, 'filterSeverity', { values: [plan.severity], hasAny: true });
        // Reopen and deselect only the selected option, rather than using All.
        await wait(page.locator('#filterPillSeverity').click());
        const options = page.locator('#filterPopoverOptions input[data-option-value]');
        const values = await wait(options.evaluateAll(elements => elements.map(element => element.dataset.optionValue)));
        assert(values.includes(plan.severity));
        await wait(options.nth(values.indexOf(plan.severity)).uncheck());
        await wait(page.locator('#filterPopoverApplyButton').click());
        await waitForUiReport(page, wait, timeout);
        const empty = await wait(page.evaluate(() => ({ values: filterState.severities, hasAny: filterState.hasSeverities, rows: filteredData.length })));
        assertFacetSelection(empty, { values: [], hasAny: false }); result.deselectionRows = empty.rows;
        // Restore fixture scope before the optional intersection exercise.
        await wait(page.evaluate(state => { filterState = finalizeFilterState(state); applyFilters(); }, plan.state));
        await waitForUiReport(page, wait, timeout);
        if (plan.hidden) {
            const { visible, invisible, platform } = plan.hidden;
            await setFacetWithUi(page, wait, timeout, 'filterOSPlatform', { values: [], hasAny: true });
            await setFacetWithUi(page, wait, timeout, 'filterRbacGroup', { values: [], hasAny: true });
            if (plan.hidden.devices) await setFacetWithUi(page, wait, timeout, 'filterDeviceName', { values: plan.hidden.devices, hasAny: true });
            await setFacetWithUi(page, wait, timeout, 'filterRbacGroup', { values: [invisible, visible], hasAny: true });
            await setFacetWithUi(page, wait, timeout, 'filterOSPlatform', { values: [platform], hasAny: true });
            await wait(page.locator('#filterPillRbacGroup').click());
            const offered = await wait(page.evaluate(({ visible, invisible }) => ({
                visible: activeFilterPopoverOptions.some(option => option.value === visible),
                invisible: activeFilterPopoverOptions.some(option => option.value === invisible)
            }), { visible, invisible }));
            assert(offered.visible && !offered.invisible, 'Fixture did not hide the selected group.');
            await wait((await facetOption(page, wait, 'filterRbacGroup', visible)).uncheck());
            await wait(page.locator('#filterPopoverApplyButton').click());
            await waitForUiReport(page, wait, timeout);
            const scoped = await wait(page.evaluate(() => ({ values: filterState.rbacGroups, hasAny: filterState.hasRbacGroups, rows: filteredData.length })));
            assertFacetSelection(scoped, { values: [invisible], hasAny: true });
            assert.strictEqual(scoped.rows, 0, 'A group absent from this platform must stay empty.');
            await setFacetWithUi(page, wait, timeout, 'filterOSPlatform', { values: [], hasAny: true });
            const reopened = await wait(page.evaluate(() => ({ values: filterState.rbacGroups, hasAny: filterState.hasRbacGroups, rows: filteredData.length })));
            assertFacetSelection(reopened, { values: [invisible], hasAny: true });
            assert(reopened.rows > 0, 'Removing the platform must reveal only the retained group.');
            result.hiddenSelection = { status: 'exercised', deviceSubsetCount: plan.hidden.devices?.length || 0, selectedGroupsAfter: reopened.values, scopedRows: scoped.rows, reopenedRows: reopened.rows };
        }
        return result;
    } finally {
        // Setup/restoration uses the saved synthetic fixture state; every action
        // claimed by this receipt above uses actual browser event wiring.
        await wait(page.evaluate(state => { closeActiveFilterPopover(false); filterState = finalizeFilterState(state); applyFilters(); }, plan.state));
        await waitForUiReport(page, wait, timeout);
    }
}

async function clickExportWithUi(page, wait, timeout, expected) {
    const utcDayBefore = await wait(page.evaluate(expected => {
        const selector = document.getElementById('reportSelector');
        if (activeReportId !== expected.report || selector.value !== expected.report || selector.selectedOptions[0].text !== expected.reportLabel) throw new Error('Report changed before the export-button click.');
        return new Date().toISOString().slice(0, 10);
    }, expected));
    await wait(page.locator('#exportPdfButton').click());
    await wait(page.waitForFunction(() => !pdfExportInProgress && !document.querySelector('.export-pdf-btn').disabled, null, { timeout }));
    const utcDayAfter = await wait(page.evaluate(() => new Date().toISOString().slice(0, 10)));
    return { utcDayBefore, utcDayAfter };
}

function assertUiExercise(result) {
    assert(result && result.status === 'exercised' && result.path === 'locator-facet-click-check-apply');
    assert.strictEqual(result.selectedFacet, 'filterSeverity'); assert.strictEqual(result.deselectionRows, 0);
    assert(['exercised', 'unavailable-fixture-intersection'].includes(result.hiddenSelection.status));
    if (result.hiddenSelection.status === 'exercised') {
        assert.strictEqual(result.hiddenSelection.selectedGroupsAfter.length, 1);
        assert([0, 2].includes(result.hiddenSelection.deviceSubsetCount));
        assert.strictEqual(result.hiddenSelection.scopedRows, 0); assert(result.hiddenSelection.reopenedRows > 0);
    }
}

module.exports = { planFacetUi, selectReportWithUi, setFacetWithUi, exerciseFacetUi, clickExportWithUi, assertFacetSelection, assertUiExercise };
