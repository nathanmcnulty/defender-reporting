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
        const runtimeStart = performance.now();
        await ensurePdfExportRuntimeLoaded();
        const pdfRuntimeLoadMs = performance.now() - runtimeStart;
        const librariesStart = performance.now();
        await loadPdfLibraries();
        const pdfLibrariesLoadMs = performance.now() - librariesStart;
        const originalDownload = downloadPdfDocument;
        const hadSkipWarning = Object.prototype.hasOwnProperty.call(window, '__skipPdfExportPageWarning');
        const originalSkipWarning = window.__skipPdfExportPageWarning;
        const results = [];
        const need = (value, reason) => { if (!value) throw new Error(reason); };
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
            filterState = finalizeFilterState(cloneFilterState(state));
            applyFilters();
            await settle(() => ready(activeReportId));
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
            // Same noninteractive synthetic-PDF convention as the shipped PDF
            // workflow; source-row and native memory/time bounds still apply.
            window.__skipPdfExportPageWarning = true;
            for (const scope of ['representative', 'empty']) {
                const state = scope === 'empty' ? { ...representative, severities: [], hasSeverities: false } : representative;
                const scopedFilterMs = await apply(state);
                need(scope !== 'empty' || filteredData.length === 0, 'Empty filter broadened scope.');
                for (const report of reports) {
                    const switchStart = performance.now();
                    selectReportById(report);
                    await settle(() => ready(report));
                    const switchMs = performance.now() - switchStart;
                    let detailMs = null;
                    if (scope === 'representative' && report === 'active-vulnerabilities' && remediationAllData.length) {
                        const detailStart = performance.now();
                        showDetails(remediationAllData[0]);
                        await settle(() => document.getElementById('detailModal').classList.contains('active')
                            && !document.getElementById('modalBody').querySelector('.loading'));
                        detailMs = performance.now() - detailStart;
                        closeModal();
                    }
                    const before = JSON.stringify(cloneFilterState(filterState));
                    let pdf;
                    // Retain the real exporter, html2canvas, pdfmake layout and
                    // fonts. Replace only the final user download with getBuffer.
                    downloadPdfDocument = async document => {
                        const buffer = await getPdfBuffer(document, timeoutMs);
                        const bytes = new Uint8Array(buffer);
                        const header = String.fromCharCode(...bytes.subarray(0, 5));
                        const tail = String.fromCharCode(...bytes.subarray(Math.max(0, bytes.length - 128)));
                        need(header === '%PDF-' && tail.includes('%%EOF'), 'Generated PDF bytes are incomplete.');
                        const hash = await crypto.subtle.digest('SHA-256', bytes);
                        pdf = { bytes: bytes.length, sha256: Array.from(new Uint8Array(hash), value => value.toString(16).padStart(2, '0')).join('') };
                    };
                    const pdfStart = performance.now();
                    await exportToPDF();
                    need(pdf && !pdfExportInProgress, 'Real PDF export failed or did not restore controls.');
                    need(before === JSON.stringify(cloneFilterState(filterState)) && activeReportId === report, 'PDF changed selected scope.');
                    results.push({ scope, report, sourceRows: filteredData.length, switchMs, detailMs,
                        scopedFilterMs, pdfPreparationMs: performance.now() - pdfStart, pdf });
                }
            }
            return { representativeRows, filterMs, pdfRuntimeLoadMs, pdfLibrariesLoadMs, pdfPageWarningSuppressed: true, reports: results, detailScope: 'Active Vulnerabilities remediation detail only; other detail views unmeasured.', pdfScope: 'Real PDF bytes/layout; final user download replaced by getBuffer; no visual/readability or semantic-content proof.' };
        } finally {
            downloadPdfDocument = originalDownload;
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
    assert(result && Number.isSafeInteger(result.representativeRows) && result.representativeRows > 0 && result.representativeRows <= 250);
    assert.strictEqual(result.reports.length, 10);
    for (const row of result.reports) {
        assert(['representative', 'empty'].includes(row.scope));
        assert(reports.includes(row.report));
        assert(Number.isFinite(row.switchMs) && row.switchMs >= 0);
        assert(Number.isFinite(row.scopedFilterMs) && row.scopedFilterMs >= 0);
        assert(Number.isFinite(row.pdfPreparationMs) && row.pdfPreparationMs >= 0);
        assert(row.pdf.bytes > 100 && /^[a-f0-9]{64}$/.test(row.pdf.sha256));
        if (row.scope === 'empty') assert.strictEqual(row.sourceRows, 0);
    }
    assert.strictEqual(new Set(result.reports.map(row => `${row.scope}/${row.report}`)).size, 10);
}

module.exports = { exerciseAdmin, assertAdminExercise, getPdfBuffer };
