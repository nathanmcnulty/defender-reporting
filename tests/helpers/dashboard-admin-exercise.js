const assert = require('assert');

async function getPdfBuffer(document, timeoutMs) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) throw new Error('Invalid PDF callback deadline.');
    let timer;
    try {
        return await new Promise((resolve, reject) => {
            timer = setTimeout(() => reject(new Error('PDF buffer callback did not complete before its deadline.')), timeoutMs);
            const result = document.getBuffer(resolve);
            if (result && typeof result.then === 'function') result.then(undefined, reject);
        });
    } finally {
        clearTimeout(timer);
    }
}

// Opt-in synthetic admin exercise inside the existing owned browser. Timings
// include browser polling/paint opportunities; they are not CPU-only timings.
async function exerciseAdmin(page, guard, timeout) {
    assert(Number.isSafeInteger(timeout) && timeout > 0 && timeout <= 120000, 'Invalid admin action deadline.');
    const runAdmin = async timeoutMs => {
        const reports = ['active-vulnerabilities', 'impact-analysis', 'remediation-activity', 'devices-by-remediation', 'remediations-by-device'];
        const original = cloneFilterState(filterState);
        const originalReport = activeReportId;
        const originalMode = remediationReportMode;
        let originalDownload;
        let downloadHookCaptured = false;
        let originalHeaderCapture;
        let headerHookCaptured = false;
        const hadSkipWarning = Object.prototype.hasOwnProperty.call(window, '__skipPdfExportPageWarning');
        const originalSkipWarning = window.__skipPdfExportPageWarning;
        const results = [];
        const need = (value, reason) => { if (!value) throw new Error(reason); };
        const checkpoint = (name, state, report = null, counts) => window.__issue70?.checkpoint?.(name, state, report, null, counts);
        const settle = async predicate => {
            const start = performance.now();
            while (!predicate()) {
                need(performance.now() - start < timeoutMs, 'Admin action did not settle.');
                await new Promise(resolve => setTimeout(resolve, 10));
            }
            await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        };
        const ready = report => activeReportId === report && initializedReports.has(report) && !dirtyReports.has(report)
            && document.getElementById(report + '-section')?.classList.contains('active')
            && document.getElementById(report + '-section')?.getAttribute('aria-busy') !== 'true';
        const apply = async state => {
            const start = performance.now();
            checkpoint('admin-filter', 'start', activeReportId);
            filterState = finalizeFilterState(cloneFilterState(state));
            applyFilters();
            await settle(() => ready(activeReportId));
            checkpoint('admin-filter', 'completed', activeReportId);
            return performance.now() - start;
        };
        try {
            need(filteredData.length > 0, 'Admin representative scope must contain rows; set fixture date range explicitly.');
            const device = getDeviceNameFilterValue(filteredData[0]);
            need(device, 'Representative device identity is required.');
            const representative = { ...original, deviceNames: [device], hasDeviceNames: true };
            const filterMs = await apply(representative);
            // Real PDF generation is deliberately bounded independently of the
            // representative large payload used for loading/filter measurements.
            need(filteredData.length > 0 && filteredData.length <= 250, 'Selected device PDF scope must have 1-250 source rows.');
            const representativeRows = filteredData.length;
            const runtimeStart = performance.now();
            checkpoint('admin-runtime', 'start');
            await ensurePdfExportRuntimeLoaded();
            checkpoint('admin-runtime', 'completed');
            if (typeof window.__issue70?.checkpoint === 'function') {
                originalHeaderCapture = capturePdfHeaderImage;
                headerHookCaptured = true;
                capturePdfHeaderImage = async function(...args) {
                    checkpoint('admin-pdf-header', 'start', activeReportId);
                    try {
                        const result = await originalHeaderCapture.apply(this, args);
                        checkpoint('admin-pdf-header', 'completed', activeReportId);
                        return result;
                    } catch (error) {
                        checkpoint('admin-pdf-header', 'failed', activeReportId);
                        throw error;
                    }
                };
            }
            const pdfRuntimeLoadMs = performance.now() - runtimeStart;
            const librariesStart = performance.now();
            checkpoint('admin-libraries', 'start');
            await loadPdfLibraries();
            checkpoint('admin-libraries', 'completed');
            const pdfLibrariesLoadMs = performance.now() - librariesStart;
            originalDownload = downloadPdfDocument;
            downloadHookCaptured = true;
            // Same noninteractive synthetic-PDF convention as the shipped PDF
            // workflow; source-row and native memory/time bounds still apply.
            window.__skipPdfExportPageWarning = true;
            for (const scope of ['representative', 'empty']) {
                const state = scope === 'empty' ? { ...representative, severities: [], hasSeverities: false } : representative;
                const scopedFilterMs = await apply(state);
                need(scope !== 'empty' || filteredData.length === 0, 'Empty filter broadened scope.');
                for (const report of reports) {
                    const switchStart = performance.now();
                    checkpoint('admin-switch', 'start', report);
                    selectReportById(report);
                    await settle(() => ready(report));
                    checkpoint('admin-switch', 'completed', report);
                    const switchMs = performance.now() - switchStart;
                    let detailMs = null;
                    let detailKind = scope === 'empty' ? 'empty-scope' : 'no-matching-data';
                    const section = document.getElementById(report + '-section');
                    const reportRows = {
                        'active-vulnerabilities': remediationAllData.length,
                        'impact-analysis': impactAnalysisAllData.length,
                        'remediation-activity': remediationDetailsAllData.length,
                        'devices-by-remediation': devicesByRemediationAllData.length,
                        'remediations-by-device': remediationsByDeviceAllData.length
                    }[report];
                    need(Number.isSafeInteger(reportRows) && reportRows >= 0 && reportRows <= filteredData.length, 'Report rows exceed the selected source scope before PDF preparation.');
                    const usesModal = ['active-vulnerabilities', 'remediation-activity', 'impact-analysis'].includes(report);
                    const detailRow = usesModal ? section.querySelector('tbody tr[data-row-index]') : null;
                    if (scope === 'representative' && detailRow) {
                        const detailStart = performance.now();
                        checkpoint('admin-detail', 'start', report);
                        // Exercise the real delegated row handler, including its
                        // report-specific payload mapping and deferred rendering.
                        detailRow.click();
                        await settle(() => document.getElementById('detailModal').classList.contains('active')
                            && !document.getElementById('modalBody').querySelector('.loading'));
                        detailMs = performance.now() - detailStart;
                        checkpoint('admin-detail', 'completed', report);
                        detailKind = 'modal';
                        closeModal();
                    } else if (scope === 'representative' && !usesModal) {
                        // The two device reports show their details inline. Their
                        // completion cost is already included in switchMs.
                        detailKind = section.querySelector('.remediation-card') ? 'inline-card' : 'no-matching-data';
                    }
                    const before = JSON.stringify(cloneFilterState(filterState));
                    let pdf;
                    // Retain the real exporter, html2canvas, pdfmake layout and
                    // fonts. Replace only the final user download with getBuffer.
                    downloadPdfDocument = async document => {
                        checkpoint('admin-pdf-buffer', 'start', report);
                        let buffer;
                        try {
                            buffer = await getPdfBuffer(document, timeoutMs);
                            checkpoint('admin-pdf-buffer', 'completed', report);
                        } catch (error) {
                            checkpoint('admin-pdf-buffer', 'failed', report);
                            throw error;
                        }
                        const bytes = new Uint8Array(buffer);
                        const header = String.fromCharCode(...bytes.subarray(0, 5));
                        const tail = String.fromCharCode(...bytes.subarray(Math.max(0, bytes.length - 128)));
                        need(header === '%PDF-' && tail.includes('%%EOF'), 'Generated PDF bytes are incomplete.');
                        const hash = await crypto.subtle.digest('SHA-256', bytes);
                        pdf = { bytes: bytes.length, sha256: Array.from(new Uint8Array(hash), value => value.toString(16).padStart(2, '0')).join('') };
                    };
                    const pdfStart = performance.now();
                    checkpoint('admin-pdf', 'start', report, { sourceRows: filteredData.length, reportRows });
                    await exportToPDF();
                    checkpoint('admin-pdf', 'completed', report);
                    need(pdf && !pdfExportInProgress, 'Real PDF export failed or did not restore controls.');
                    need(before === JSON.stringify(cloneFilterState(filterState)) && activeReportId === report, 'PDF changed selected scope.');
                    const summaryCards = JSON.parse(JSON.stringify(buildDashboardValidationSnapshot().summaryCards));
                    results.push({ scope, report, sourceRows: filteredData.length, reportRows, summaryCards, switchMs, detailMs, detailKind,
                        scopedFilterMs, pdfPreparationMs: performance.now() - pdfStart, pdf });
                }
            }
            return { restored: true, representativeRows, pdfLibrarySourceRows: representativeRows, filterMs, pdfRuntimeLoadMs, pdfLibrariesLoadMs, pdfPageWarningSuppressed: true, reports: results, detailScope: 'All three modal report families when matching data exists; device-report inline detail cost is included in report switching. Missing detail data is labelled explicitly.', pdfScope: 'Real PDF bytes/layout; final user download replaced by getBuffer; no visual/readability or semantic-content proof.' };
        } finally {
            if (headerHookCaptured) capturePdfHeaderImage = originalHeaderCapture;
            if (downloadHookCaptured) downloadPdfDocument = originalDownload;
            remediationReportMode = originalMode;
            if (hadSkipWarning) window.__skipPdfExportPageWarning = originalSkipWarning;
            else delete window.__skipPdfExportPageWarning;
            closeModal();
            await apply(original);
            selectReportById(originalReport);
            await settle(() => ready(originalReport));
        }
    };
    // Serialize the exact callback wrapper exercised by browser-free controls.
    // Only checked numeric timeout and these fixed functions enter this source.
    return guard.wait(page.evaluate(`(async () => {
        const getPdfBuffer = ${getPdfBuffer.toString()};
        return (${runAdmin.toString()})(${JSON.stringify(timeout)});
    })()`));
}

function assertAdminExercise(result) {
    const reports = ['active-vulnerabilities', 'impact-analysis', 'remediation-activity', 'devices-by-remediation', 'remediations-by-device'];
    assert(result && result.restored === true && Number.isSafeInteger(result.representativeRows) && result.representativeRows > 0 && result.representativeRows <= 250);
    assert.strictEqual(result.pdfLibrarySourceRows, result.representativeRows, 'PDF library loading must follow the admitted representative scope.');
    assert.strictEqual(result.reports.length, 10);
    for (const row of result.reports) {
        assert(['representative', 'empty'].includes(row.scope));
        assert(Number.isSafeInteger(row.reportRows) && row.reportRows >= 0, 'Missing or invalid scoped report row count.');
        assert(row.reportRows <= row.sourceRows, 'Grouped report rows exceed the selected source scope.');
        assert(row.summaryCards && Object.keys(row.summaryCards).length > 0, 'Missing scoped summary cards.');
        for (const value of Object.values(row.summaryCards)) {
            assert((typeof value === 'number' || typeof value === 'string' && value.trim() !== '') && Number.isSafeInteger(Number(value)) && Number(value) >= 0, 'Invalid scoped summary count.');
            if (row.scope === 'empty') assert.strictEqual(Number(value), 0, 'Empty scope summary broadened.');
        }
        if (row.scope === 'empty') assert.strictEqual(row.reportRows, 0, 'Empty report broadened.');
        assert(reports.includes(row.report));
        assert(Number.isFinite(row.switchMs) && row.switchMs >= 0);
        assert(Number.isFinite(row.scopedFilterMs) && row.scopedFilterMs >= 0);
        assert(Number.isFinite(row.pdfPreparationMs) && row.pdfPreparationMs >= 0);
        assert(['modal', 'inline-card', 'empty-scope', 'no-matching-data'].includes(row.detailKind));
        if (row.scope === 'representative') {
            assert.strictEqual(row.sourceRows, result.representativeRows, 'Every report must retain the selected representative scope.');
            assert.notStrictEqual(row.detailKind, 'empty-scope');
        }
        if (row.detailKind === 'modal') {
            assert(['active-vulnerabilities', 'impact-analysis', 'remediation-activity'].includes(row.report));
            assert(Number.isFinite(row.detailMs) && row.detailMs >= 0);
        } else {
            assert.strictEqual(row.detailMs, null, 'Unmeasured detail actions must not be assigned a latency.');
        }
        if (row.scope === 'empty') assert.strictEqual(row.detailKind, 'empty-scope');
        if (row.detailKind === 'inline-card') assert(['devices-by-remediation', 'remediations-by-device'].includes(row.report));
        assert(row.pdf.bytes > 100 && /^[a-f0-9]{64}$/.test(row.pdf.sha256));
        if (row.scope === 'empty') assert.strictEqual(row.sourceRows, 0);
    }
    assert.strictEqual(new Set(result.reports.map(row => `${row.scope}/${row.report}`)).size, 10);
}

module.exports = { exerciseAdmin, assertAdminExercise, getPdfBuffer };
