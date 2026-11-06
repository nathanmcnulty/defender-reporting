const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { selectReportWithUi, selectRemediationModeWithUi, setFacetWithUi, exerciseFacetUi, clickExportWithUi, assertUiExercise } = require('./dashboard-ui-exercise');

const REPORTS = ['active-vulnerabilities', 'impact-analysis', 'remediation-activity', 'devices-by-remediation', 'remediations-by-device'];
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function withDeadline(operation, timeoutMs) {
    assert(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 120000, 'Invalid artifact deadline.');
    let timer;
    try {
        return await Promise.race([operation, new Promise((resolve, reject) => {
            timer = setTimeout(() => reject(new Error('Artifact operation exceeded its deadline.')), timeoutMs);
        })]);
    } finally { clearTimeout(timer); }
}

function fileReceipt(filename, kind) {
    const length = fs.statSync(filename).size;
    assert(length > 100 && length <= 64 * 1024 ** 2, 'Artifact size is outside its bound.');
    const bytes = fs.readFileSync(filename);
    if (kind === 'pdf') assert(bytes.subarray(0, 5).toString() === '%PDF-' && bytes.subarray(-128).includes(Buffer.from('%%EOF')), 'Incomplete PDF download.');
    else assert(bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])), 'Invalid screenshot.');
    return { file: path.basename(filename), bytes: length, sha256: sha256(bytes) };
}

function expectedDownloadNames(reportLabel, interval) {
    assert(typeof reportLabel === 'string' && reportLabel.length > 0 && !/[\\/]/.test(reportLabel), 'Expected report label is required.');
    const dates = [interval?.utcDayBefore, interval?.utcDayAfter];
    for (const day of dates) assert(typeof day === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(day) && new Date(day).toISOString().slice(0, 10) === day, 'Invalid browser export date.');
    const days = (Date.parse(dates[1]) - Date.parse(dates[0])) / 86400000;
    assert(days >= 0 && days <= 1, 'Browser export date changed outside its bounded interval.');
    return dates.map(day => `Vulnerability_Dashboard_${reportLabel.replace(/\s+/g, '_')}_${day}.pdf`);
}

async function loadScopedPdfRuntime() {
    if (!filteredData.length || filteredData.length > 250) throw new Error('PDF runtime preparation requires the selected 1-250 row scope.');
    const sourceRows = filteredData.length;
    await ensurePdfExportRuntimeLoaded();
    // Library loading belongs to the real Export PDF button, after this scope
    // has been selected. Only expansion/scope-capture helpers are needed here.
    return sourceRows;
}

async function captureRealDownload(page, trigger, filename, wait, reportLabel) {
    // Register the event before the real exporter can start a download.
    const pending = page.waitForEvent('download', { timeout: 120000 });
    const [download, interval] = await wait(Promise.all([pending, Promise.resolve().then(trigger)]));
    const suggestedFilename = download.suggestedFilename();
    assert(expectedDownloadNames(reportLabel, interval).includes(suggestedFilename), 'Browser download filename does not match the selected report and export date.');
    assert.strictEqual(await wait(download.failure()), null, 'Browser download failed.');
    await wait(download.saveAs(filename));
    return { ...fileReceipt(filename, 'pdf'), suggestedFilename, exportUtcDayBefore: interval.utcDayBefore, exportUtcDayAfter: interval.utcDayAfter };
}

// Runs in the actual dashboard context. Capture the exact expanded DOM that the
// PDF exporter will read, then restore its page expansion before starting export.
function captureReportScope() {
    const report = activeReportId;
    const section = document.getElementById(report + '-section');
    const previous = expandReportForPdf(report);
    try {
        const text = section.innerText;
        if (text.length > 500000) throw new Error('Expanded report receipt exceeds its text bound.');
        const tables = Array.from(section.querySelectorAll('table')).map(table => ({
            headers: Array.from(table.querySelectorAll('thead th')).map(cell => cell.innerText.trim()),
            rows: Array.from(table.querySelectorAll('tbody tr')).map(row => Array.from(row.querySelectorAll('td')).map(cell => cell.innerText.trim()))
        }));
        const counts = {
            'active-vulnerabilities': remediationAllData.length,
            'impact-analysis': impactAnalysisAllData.length,
            'remediation-activity': remediationDetailsAllData.length,
            'devices-by-remediation': devicesByRemediationAllData.length,
            'remediations-by-device': remediationsByDeviceAllData.length
        };
        const cardDetails = Array.from(section.querySelectorAll('.remediation-card')).map(card => ({
            title: card.querySelector('.remediation-card-header h3')?.innerText.trim() || '',
            metadata: Array.from(card.querySelectorAll('.cve-details .stat-badge')).map(badge => badge.innerText.trim()).filter(Boolean),
            statBadges: Array.from(card.querySelectorAll('.stat-badge')).map(badge => badge.innerText.trim()).filter(Boolean)
        }));
        const modeSummary = isRemediationScopeReport(report) ? getRemediationReportModeSummaryText(filterState) : null;
        if (modeSummary !== null && document.getElementById('remediationModeSummary').innerText.trim() !== modeSummary) {
            throw new Error('Visible mode summary differs from the selected report scope.');
        }
        return {
            report, reportLabel: document.getElementById('reportSelector').selectedOptions[0].text,
            filter: JSON.parse(JSON.stringify(cloneFilterState(filterState))), mode: remediationReportMode,
            sourceRows: filteredData.length, reportRows: counts[report], cards: buildDashboardValidationSnapshot().summaryCards,
            appliedFilters: ['filterRbacGroup', 'filterDeviceTags', 'filterDeviceName', 'filterOSPlatform', 'filterSeverity'].map(id => ({ id, text: getExportFilterText(id, 'All') })),
            expandedText: text, tables, cardDetails, modeSummary,
            includeResolvedText: modeSummary === null ? null : remediationReportMode === REMEDIATION_REPORT_MODE_RANGE ? 'Yes' : 'No',
            pdfExcludedText: Array.from(section.querySelectorAll('.pdf-exclude')).map(element => element.innerText),
            expansion: previous
        };
    } finally { restoreReportState(report, previous); }
}

function assertArtifactAcceptance(result) {
    assert(result && result.restored === true && result.status === 'captured', 'Artifact acceptance did not restore scope.');
    assert(Number.isSafeInteger(result.representativeRows) && result.representativeRows > 0 && result.representativeRows <= 250);
    assert.strictEqual(result.runtimePreloadSourceRows, result.representativeRows, 'PDF runtime must be prepared after selecting the bounded scope.');
    assertUiExercise(result.uiExercise);
    assert(result.reports.length === 12 || result.reports.length === 13);
    const pairs = new Set();
    for (const row of result.reports) {
        assert(REPORTS.includes(row.report) && ['representative', 'empty', 'representative-range', 'long-table'].includes(row.scope));
        assert(!pairs.has(`${row.scope}/${row.report}`)); pairs.add(`${row.scope}/${row.report}`);
        assert.strictEqual(row.before.report, row.report);
        assert.deepStrictEqual(row.after, row.before, 'Saved PDF changed report/filter/expanded DOM scope.');
        assert.strictEqual(row.before.sourceRows, row.scope === 'empty' ? 0 : row.scope === 'long-table' ? result.longTable.sourceRows : result.representativeRows);
        assert(row.before.sourceRows <= 250 && row.before.expandedText.length <= 500000);
        const deviceReport = ['devices-by-remediation', 'remediations-by-device'].includes(row.report);
        assert(Array.isArray(row.before.cardDetails));
        assert.strictEqual(row.before.cardDetails.length, deviceReport ? row.before.reportRows : 0);
        for (const card of row.before.cardDetails) {
            assert(typeof card.title === 'string' && card.title.length > 0);
            for (const badges of [card.metadata, card.statBadges]) assert(Array.isArray(badges) && badges.every(value => typeof value === 'string' && value.length > 0));
        }
        if (deviceReport) {
            assert.strictEqual(row.before.mode, row.scope === 'representative-range' ? 'range' : 'snapshot');
            assert.strictEqual(row.before.includeResolvedText, row.before.mode === 'range' ? 'Yes' : 'No');
            assert(typeof row.before.modeSummary === 'string' && row.before.modeSummary.length > 0);
            assert(row.modeAction && row.modeAction.mode === row.before.mode && row.modeAction.path === 'shared-toolbar-button'
                && ['clicked', 'already-selected'].includes(row.modeAction.action));
        } else {
            assert.strictEqual(row.before.modeSummary, null);
            assert.strictEqual(row.before.includeResolvedText, null);
            assert.strictEqual(row.modeAction, null);
        }
        if (row.scope === 'representative-range') assert(deviceReport, 'Range coverage belongs to the device report families.');
        for (const file of [row.pdf, row.screenshot, row.receipt]) assert(file && file.bytes > 0 && /^[a-f0-9]{64}$/.test(file.sha256));
        assert(expectedDownloadNames(row.before.reportLabel, { utcDayBefore: row.pdf.exportUtcDayBefore, utcDayAfter: row.pdf.exportUtcDayAfter }).includes(row.pdf.suggestedFilename), 'Saved PDF filename identity differs from its scope receipt.');
        if (row.scope === 'long-table') assert(row.report === 'active-vulnerabilities' && row.before.reportRows > 100, 'Long-table receipt must exceed the normal page size.');
    }
    for (const scope of ['representative', 'empty']) for (const report of REPORTS) assert(pairs.has(`${scope}/${report}`));
    for (const report of ['devices-by-remediation', 'remediations-by-device']) assert(pairs.has(`representative-range/${report}`));
    assert(result.reports.some(row => row.scope === 'representative-range' && row.modeAction.action === 'clicked'), 'Range coverage must exercise an actual mode-button transition.');
}

async function exerciseSavedArtifacts(page, guard, timeout, directory) {
    const wait = operation => guard.wait(withDeadline(operation, timeout));
    fs.mkdirSync(directory);
    const result = { status: 'capturing', restored: false, representativeRows: 0, reports: [], viewport: { width: 1440, height: 1000 }, longTable: { status: 'unavailable-within-250-source-row-bound' },
        scope: 'Actual browser download/saveAs and expanded DOM receipts; PDF semantic parsing and rendered-page visual review remain required.' };
    let started = false;
    try {
        await wait(page.setViewportSize({ width: 1440, height: 1000 }));
        await wait(page.evaluate(async () => {
            if (window.__savedArtifactSession) throw new Error('Artifact scope is already owned.');
            if (!filteredData.length) throw new Error('Set a fixture date range with matching rows before artifact acceptance.');
            const state = cloneFilterState(filterState);
            const counts = new Map();
            for (const row of filteredData) {
                const id = getDeviceNameFilterValue(row);
                if (id) counts.set(id, (counts.get(id) || 0) + 1);
            }
            const first = Array.from(counts).find(([, count]) => count > 0 && count <= 250);
            if (!first) throw new Error('No representative device fits the PDF source-row bound.');
            window.__savedArtifactSession = { state, report: activeReportId, mode: remediationReportMode,
                hadWarning: Object.prototype.hasOwnProperty.call(window, '__skipPdfExportPageWarning'), warning: window.__skipPdfExportPageWarning,
                representative: { ...state, deviceNames: [first[0]], hasDeviceNames: true }, deviceCounts: Array.from(counts) };
            window.__skipPdfExportPageWarning = true;
        }));
        started = true;
        result.uiExercise = await exerciseFacetUi(page, wait, timeout);
        const apply = async (scope, report) => {
            const selections = await wait(page.evaluate(scope => {
                const session = window.__savedArtifactSession;
                const state = scope === 'long-table' ? session.longTable : session.representative;
                return { device: { values: state.deviceNames, hasAny: state.hasDeviceNames },
                    severity: { values: state.severities, hasAny: state.hasSeverities },
                    currentDevice: { values: filterState.deviceNames, hasAny: filterState.hasDeviceNames } };
            }, scope));
            if (JSON.stringify(selections.device) !== JSON.stringify(selections.currentDevice)) {
                // A None severity scope offers no device options; restore its
                // fixture severity through the UI before choosing other devices.
                await setFacetWithUi(page, wait, timeout, 'filterSeverity', selections.severity);
                await setFacetWithUi(page, wait, timeout, 'filterDeviceName', selections.device);
            }
            await setFacetWithUi(page, wait, timeout, 'filterSeverity', scope === 'empty' ? { values: [], hasAny: false } : selections.severity);
            await selectReportWithUi(page, wait, timeout, report);
            if (['devices-by-remediation', 'remediations-by-device'].includes(report)) {
                return selectRemediationModeWithUi(page, wait, timeout, report, scope === 'representative-range' ? 'range' : 'snapshot');
            }
            return null;
        };
        await apply('representative', 'active-vulnerabilities');
        result.runtimePreloadSourceRows = await wait(page.evaluate(loadScopedPdfRuntime));
        const capture = async (scope, report) => {
            const modeAction = await apply(scope, report);
            const before = await wait(page.evaluate(captureReportScope));
            assert(before.sourceRows <= 250 && (scope !== 'empty' || before.sourceRows === 0), 'Artifact scope broadened beyond its bound.');
            if (scope === 'representative') result.representativeRows ||= before.sourceRows;
            const stem = `${scope}-${report}`;
            const imageFile = path.join(directory, stem + '.png');
            await wait(page.screenshot({ path: imageFile, fullPage: false }));
            const screenshot = fileReceipt(imageFile, 'png');
            const pdf = await captureRealDownload(page,
                () => clickExportWithUi(page, wait, timeout, { report, reportLabel: before.reportLabel }),
                path.join(directory, stem + '.pdf'), wait, before.reportLabel);
            await wait(page.waitForFunction(() => !pdfExportInProgress && !document.querySelector('.export-pdf-btn').disabled, null, { timeout }));
            const after = await wait(page.evaluate(captureReportScope));
            assert.deepStrictEqual(after, before, 'Real PDF download changed the selected scope.');
            const receiptFile = path.join(directory, stem + '.json');
            const receiptBytes = Buffer.from(JSON.stringify({ status: 'captured-pending-run-completion', scope, report, modeAction, before, after, pdf, screenshot }, null, 2));
            fs.writeFileSync(receiptFile, receiptBytes, { flag: 'wx' });
            result.reports.push({ scope, report, modeAction, before, after, pdf, screenshot, receipt: { file: path.basename(receiptFile), bytes: receiptBytes.length, sha256: sha256(receiptBytes) } });
        };
        for (const scope of ['representative', 'empty']) for (const report of REPORTS) await capture(scope, report);
        for (const report of ['devices-by-remediation', 'remediations-by-device']) await capture('representative-range', report);
        // Try one known device subset that fits the same source-row bound and
        // exceeds TABLE_PAGE_SIZE. No larger dataset or bound is substituted.
        const longCandidate = await wait(page.evaluate(() => {
            const session = window.__savedArtifactSession;
            const devices = []; let rows = 0;
            for (const [id, count] of session.deviceCounts) { if (count + rows <= 250) { devices.push(id); rows += count; } }
            session.longTable = { ...session.state, deviceNames: devices, hasDeviceNames: devices.length > 0 };
            return rows;
        }));
        if (longCandidate > 100) {
            await apply('long-table', 'active-vulnerabilities');
            const check = await wait(page.evaluate(() => ({ sourceRows: filteredData.length, reportRows: remediationAllData.length })));
            if (check.sourceRows <= 250 && check.reportRows > 100) {
                result.longTable = { status: 'captured', ...check };
                await capture('long-table', 'active-vulnerabilities');
            } else result.longTable = { status: 'not-enough-distinct-report-rows', ...check };
        }
    } finally {
        if (started) {
            await wait(page.evaluate(() => {
                const session = window.__savedArtifactSession;
                filterState = cloneFilterState(session.state); remediationReportMode = session.mode;
                if (session.hadWarning) window.__skipPdfExportPageWarning = session.warning; else delete window.__skipPdfExportPageWarning;
                applyFilters(); selectReportById(session.report); closeModal();
            }));
            await wait(page.waitForFunction(() => {
                const session = window.__savedArtifactSession;
                return activeReportId === session.report && initializedReports.has(session.report) && !dirtyReports.has(session.report)
                    && document.getElementById(session.report + '-section').getAttribute('aria-busy') !== 'true'
                    && JSON.stringify(cloneFilterState(filterState)) === JSON.stringify(cloneFilterState(session.state));
            }, null, { timeout }));
            await wait(page.evaluate(() => { delete window.__savedArtifactSession; }));
            result.restored = true;
        }
    }
    result.status = 'captured';
    assertArtifactAcceptance(result);
    return result;
}

module.exports = { exerciseSavedArtifacts, assertArtifactAcceptance, captureRealDownload, withDeadline, fileReceipt, captureReportScope, expectedDownloadNames, loadScopedPdfRuntime };
