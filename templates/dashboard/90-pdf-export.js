// =============================================================================
// PDF EXPORT
// =============================================================================

// Track whether PDF libraries have been loaded
let pdfLibrariesLoaded = false;

function hasPdfLibrariesAvailable() {
    return typeof pdfMake !== 'undefined'
        && typeof pdfMake.createPdf === 'function'
        && typeof html2canvas === 'function';
}

function resetPdfLibraryLoadState() {
    pdfLibrariesLoaded = false;
    if ((dashboardConfig.pdfExportBundleMode || 'embedded') === 'external') {
        unloadExternalScript(dashboardConfig.pdfExportBundleUrl);
    }
}

/**
 * Load PDF libraries on demand.
 * The embedded bundle contains html2canvas + pdfmake + vfs_fonts.
 */
function loadPdfLibraries() {
    if (pdfLibrariesLoaded) {
        return Promise.resolve();
    }

    if (pdfLibrariesLoadPromise) {
        return pdfLibrariesLoadPromise;
    }

    pdfLibrariesLoadPromise = new Promise((resolve, reject) => {
        try {
            const pdfBundleMode = dashboardConfig.pdfExportBundleMode || 'embedded';
            if (pdfBundleMode === 'external') {
                loadExternalScript(dashboardConfig.pdfExportBundleUrl)
                    .then(() => {
                        if (!hasPdfLibrariesAvailable()) {
                            resetPdfLibraryLoadState();
                            throw new Error('PDF export bundle did not initialize correctly.');
                        }
                        pdfLibrariesLoaded = true;
                        logDebug('PDF libraries loaded successfully');
                        resolve();
                    })
                    .catch(error => {
                        resetPdfLibraryLoadState();
                        reject(error);
                    });
                return;
            }

            if (typeof window.__inflateEmbeddedScript !== 'function') {
                throw new Error('Embedded script inflater is unavailable');
            }

            window.__inflateEmbeddedScript('pdfExportBundleLib');

            // Wait for pdfMake to be available (it may take a moment to initialize)
            let attempts = 0;
            const checkPdfMake = setInterval(() => {
                attempts++;
                if (hasPdfLibrariesAvailable()) {
                    clearInterval(checkPdfMake);
                    pdfLibrariesLoaded = true;
                    logDebug('PDF libraries loaded successfully');
                    resolve();
                } else if (attempts > 50) { // 5 seconds timeout
                    clearInterval(checkPdfMake);
                    reject(new Error('PDF export bundle failed to initialize after 5 seconds'));
                }
            }, 100);
        } catch (error) {
            resetPdfLibraryLoadState();
            console.error('Failed to load PDF libraries:', error);
            reject(error);
        }
    }).catch(error => {
        if (!hasPdfLibrariesAvailable()) {
            resetPdfLibraryLoadState();
        }
        pdfLibrariesLoadPromise = null;
        throw error;
    });

    return pdfLibrariesLoadPromise;
}

/**
 * Export current view to PDF using pdfmake
 */
/**
 * Expand all data for the active report before PDF export
 * @param {string} selectedReport - The report type identifier
 * @returns {boolean} The previous expansion state
 */
function expandReportForPdf(selectedReport) {
    const previousState = {
        wasExpanded: false,
        forceFullDevicesByRemediationRows
    };
    
    switch (selectedReport) {
        case 'active-vulnerabilities':
            previousState.wasExpanded = remediationExpanded;
            if (!remediationExpanded) {
                remediationExpanded = true;
                renderRemediationTablePage();
            }
            break;
        case 'remediation-activity':
            previousState.wasExpanded = remediationDetailsExpanded;
            if (!remediationDetailsExpanded) {
                remediationDetailsExpanded = true;
                renderRemediationDetailsTablePage();
            }
            break;
        case 'impact-analysis':
            previousState.wasExpanded = impactAnalysisExpanded;
            if (!impactAnalysisExpanded) {
                impactAnalysisExpanded = true;
                renderImpactAnalysisTablePage();
            }
            break;
        case 'devices-by-remediation':
            previousState.wasExpanded = devicesByRemediationExpanded;
            forceFullDevicesByRemediationRows = true;
            if (!devicesByRemediationExpanded) {
                devicesByRemediationExpanded = true;
            }
            renderDevicesByRemediationTablePage();
            break;
        case 'remediations-by-device':
            previousState.wasExpanded = remediationsByDeviceExpanded;
            if (!remediationsByDeviceExpanded) {
                remediationsByDeviceExpanded = true;
                renderRemediationsByDeviceTablePage();
            }
            break;
    }
    
    return previousState;
}

/**
 * Restore report to previous expansion state
 * @param {string} selectedReport - The report type identifier
 * @param {boolean} wasExpanded - The previous expansion state
 */
function restoreReportState(selectedReport, previousState) {
    const state = typeof previousState === 'object' && previousState !== null
        ? previousState
        : {
            wasExpanded: Boolean(previousState),
            forceFullDevicesByRemediationRows
        };
    
    switch (selectedReport) {
        case 'active-vulnerabilities':
            if (state.wasExpanded) return;
            remediationExpanded = false;
            renderRemediationTablePage();
            break;
        case 'remediation-activity':
            if (state.wasExpanded) return;
            remediationDetailsExpanded = false;
            renderRemediationDetailsTablePage();
            break;
        case 'impact-analysis':
            if (state.wasExpanded) return;
            impactAnalysisExpanded = false;
            renderImpactAnalysisTablePage();
            break;
        case 'devices-by-remediation':
            forceFullDevicesByRemediationRows = state.forceFullDevicesByRemediationRows;
            devicesByRemediationExpanded = state.wasExpanded;
            renderDevicesByRemediationTablePage();
            break;
        case 'remediations-by-device':
            if (state.wasExpanded) return;
            remediationsByDeviceExpanded = false;
            renderRemediationsByDeviceTablePage();
            break;
    }
}

/**
 * Export card-based report layouts using visual capture
 * @param {string} selectedReport - The report type
 * @param {string} reportName - Display name for the report
 * @returns {Object} PDF document definition
 */
async function exportCardBasedReportToPdf(selectedReport, reportName) {
    const container = document.querySelector('.container');
    const activeSection = document.querySelector('.report-section.active');
    
    // Capture title and stats as image
    const headerDiv = document.createElement('div');
    headerDiv.style.backgroundColor = 'white';
    headerDiv.style.padding = '20px';
    headerDiv.style.fontFamily = 'Arial, sans-serif';
    headerDiv.style.width = '1000px';
    
    const title = document.createElement('h1');
    title.textContent = `🛡️ Vulnerability Dashboard - ${reportName}`;
    title.style.fontSize = '36px';
    title.style.color = '#0078d4';
    title.style.marginBottom = '20px';
    headerDiv.appendChild(title);
    
    const statsClone = container.querySelector('.stats-summary').cloneNode(true);
    headerDiv.appendChild(statsClone);
    
    document.body.appendChild(headerDiv);
    const headerCanvas = await html2canvas(headerDiv, {
        scale: 2.5,
        backgroundColor: '#ffffff'
    });
    const headerImg = headerCanvas.toDataURL('image/png');
    document.body.removeChild(headerDiv);
    
    // Extract data from cards instead of capturing as images
    const cardsContainer = activeSection.querySelector('.remediation-cards-container');
    const cards = cardsContainer ? cardsContainer.querySelectorAll('.remediation-card') : [];
    
    const docContent = [
        {
            image: headerImg,
            width: 780,
            margin: [0, 0, 0, 15]
        }
    ];
    
    // Extract and render each card as structured PDF content
    const isDevicesByRemediation = selectedReport === 'devices-by-remediation';
    
    for (let i = 0; i < cards.length; i++) {
        const card = cards[i];
        
        // Extract card header
        const cardHeader = card.querySelector('.remediation-card-header h3');
        const headerText = cardHeader ? cardHeader.textContent.trim() : '';
        
        // Extract CVE details or device info
        const cveDetails = card.querySelector('.cve-details');
        let deviceInfo = {};
        let publishedDate = '';
        let updateInfo = '';
        
        if (cveDetails) {
            const statBadges = cveDetails.querySelectorAll('.stat-badge');
            statBadges.forEach(badge => {
                const text = badge.textContent.trim();
                if (text.startsWith('Published:')) {
                    publishedDate = text.replace('Published:', '').trim();
                } else if (text.startsWith('Update:')) {
                    updateInfo = text.replace('Update:', '').trim();
                } else if (text.startsWith('IP:')) {
                    deviceInfo.ip = text.replace('IP:', '').trim();
                } else if (text.startsWith('Group:')) {
                    deviceInfo.group = text.replace('Group:', '').trim();
                } else if (text.startsWith('Tags:')) {
                    deviceInfo.tags = text.replace('Tags:', '').trim();
                }
            });
        }
        
        // Extract severity badges
        const severityBadges = card.querySelectorAll('.severity-badge');
        const severityText = Array.from(severityBadges)
            .map(badge => badge.textContent.trim())
            .join(', ');
        
        // Extract CVE count and device/remediation count
        const statBadges = card.querySelectorAll('.remediation-stats .stat-badge');
        let countInfo = {};
        statBadges.forEach(badge => {
            const text = badge.textContent.trim();
            if (text.startsWith('Devices:')) countInfo.devices = text;
            if (text.startsWith('Remediations:')) countInfo.remediations = text;
            if (text.startsWith('CVEs:')) countInfo.cves = text;
        });
        
        // Extract CVE badges (only for devices-by-remediation)
        const cveBadges = card.querySelectorAll('.cve-severity-badge');
        const cveList = Array.from(cveBadges).map(badge => badge.textContent.trim());
        
        // Extract table
        const tables = card.querySelectorAll('.devices-table');
        let tableBody = [];
        let tableHeaders = [];
        let tableWidths = [];
        
        if (tables.length > 0) {
            const headerCells = tables[0].querySelectorAll('thead th');
            tableHeaders = Array.from(headerCells).map(th => ({
                text: th.textContent.trim(),
                fontSize: 9,
                bold: true,
                fillColor: '#f0f0f0'
            }));
            
            // Set column widths based on report type
            if (isDevicesByRemediation) {
                // Devices by Remediation: Name, IP, Group, Tags
                tableWidths = [180, 85, 160, '*'];
            } else {
                // Remediations by Device: Remediation, Update, Severities, CVEs, Published
                tableWidths = ['*', 140, 200, 50, 80];
            }
            
            tables.forEach(table => {
                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {
                    const cells = row.querySelectorAll('td');
                    const rowData = [];
                    cells.forEach(cell => {
                        // For severity cells, extract just text, not HTML
                        const severityBadges = cell.querySelectorAll('.severity-badge');
                        let cellText;
                        if (severityBadges.length > 0) {
                            cellText = Array.from(severityBadges).map(b => b.textContent.trim()).join(', ');
                        } else {
                            cellText = cell.textContent.trim();
                        }
                        rowData.push({ text: cellText, fontSize: 9 });
                    });
                    if (rowData.length > 0) {
                        tableBody.push(rowData);
                    }
                });
            });
        }
        
        // Build PDF content for this card
        const cardContent = [];
        
        // Card header
        cardContent.push({
            text: headerText,
            fontSize: 13,
            bold: true,
            color: '#0078d4',
            margin: [0, i > 0 ? 12 : 0, 0, 4]
        });
        
        // Device info (for remediations by device) or CVE details (for devices by remediation)
        if (deviceInfo.ip) {
            const deviceInfoParts = [];
            if (deviceInfo.ip) deviceInfoParts.push(`IP: ${deviceInfo.ip}`);
            if (deviceInfo.group) deviceInfoParts.push(`Group: ${deviceInfo.group}`);
            if (deviceInfo.tags) deviceInfoParts.push(`Tags: ${deviceInfo.tags}`);
            
            if (deviceInfoParts.length > 0) {
                cardContent.push({
                    text: deviceInfoParts.join('  |  '),
                    fontSize: 9,
                    color: '#666666',
                    margin: [0, 0, 0, 3]
                });
            }
        } else {
            // CVE details line for devices by remediation
            const detailsParts = [];
            if (publishedDate) detailsParts.push(`Published: ${publishedDate}`);
            if (updateInfo) detailsParts.push(`Update: ${updateInfo}`);
            if (detailsParts.length > 0) {
                cardContent.push({
                    text: detailsParts.join('  |  '),
                    fontSize: 9,
                    color: '#666666',
                    margin: [0, 0, 0, 3]
                });
            }
        }
        
        // Stats line - ONLY show counts, no severities
        const statsLine = [];
        if (countInfo.devices) statsLine.push(countInfo.devices);
        if (countInfo.remediations) statsLine.push(countInfo.remediations);
        if (countInfo.cves) statsLine.push(countInfo.cves);
        
        if (statsLine.length > 0) {
            cardContent.push({
                text: statsLine.join('  |  '),
                fontSize: 9,
                margin: [0, 0, 0, 3]
            });
        }
        
        // CVE list (only for devices by remediation)
        if (isDevicesByRemediation && cveList.length > 0) {
            if (cveList.length <= 15) {
                cardContent.push({
                    text: 'CVEs: ' + cveList.join(', '),
                    fontSize: 8,
                    color: '#333333',
                    margin: [0, 0, 0, 4]
                });
            } else {
                cardContent.push({
                    text: `CVEs: ${cveList.length} CVEs (too many to list)`,
                    fontSize: 8,
                    color: '#333333',
                    margin: [0, 0, 0, 4]
                });
            }
        }
        
        // Table
        if (tableBody.length > 0 && tableHeaders.length > 0) {
            cardContent.push({
                table: {
                    headerRows: 1,
                    widths: tableWidths,
                    body: [tableHeaders, ...tableBody]
                },
                layout: {
                    hLineWidth: () => 0.5,
                    vLineWidth: () => 0.5,
                    hLineColor: () => '#dddddd',
                    vLineColor: () => '#dddddd',
                    paddingLeft: () => 4,
                    paddingRight: () => 4,
                    paddingTop: () => 3,
                    paddingBottom: () => 3
                },
                margin: [0, 0, 0, 8]
            });
        }
        
        docContent.push(...cardContent);
    }
    
    return {
        pageSize: 'A4',
        pageOrientation: 'landscape',
        pageMargins: [20, 20, 20, 20],
        content: docContent
    };
}

/**
 * Export table-based report layouts using structured data extraction
 * @param {string} selectedReport - The report type
 * @param {string} reportName - Display name for the report
 * @returns {Object} PDF document definition
 */
async function exportTableBasedReportToPdf(selectedReport, reportName) {
    const container = document.querySelector('.container');
    const activeSection = document.querySelector('.report-section.active');
    
    // Capture title and stats as image
    const headerDiv = document.createElement('div');
    headerDiv.style.backgroundColor = 'white';
    headerDiv.style.padding = '0';
    headerDiv.style.fontFamily = 'Arial, sans-serif';
    headerDiv.style.width = '1000px';
    
    const title = document.createElement('h1');
    title.textContent = `🛡️ Vulnerability Dashboard - ${reportName}`;
    title.style.fontSize = '36px';
    title.style.color = '#0078d4';
    title.style.marginBottom = '20px';
    headerDiv.appendChild(title);
    
    const statsClone = container.querySelector('.stats-summary').cloneNode(true);
    headerDiv.appendChild(statsClone);
    
    document.body.appendChild(headerDiv);
    const headerCanvas = await html2canvas(headerDiv, {
        scale: 2.5,
        backgroundColor: '#ffffff'
    });
    const headerImg = headerCanvas.toDataURL('image/png');
    document.body.removeChild(headerDiv);
    
    // Capture chart as image
    let chartImg = null;
    const chartContainer = activeSection.querySelector('.chart-container');
    if (chartContainer) {
        const canvas = chartContainer.querySelector('canvas');
        if (canvas) {
            chartImg = canvas.toDataURL('image/png');
        }
    }
    
    // Extract table data
    const table = activeSection.querySelector('table');
    let tableBody = [];
    let tableHeaders = [];
    
    if (table) {
        const headers = table.querySelectorAll('thead th');
        headers.forEach(th => {
            tableHeaders.push({
                text: th.textContent.trim(),
                style: 'tableHeader',
                fillColor: '#0078d4',
                color: '#ffffff'
            });
        });
        
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach((row, idx) => {
            const cells = row.querySelectorAll('td');
            const rowData = [];
            cells.forEach(td => {
                rowData.push({
                    text: td.textContent.trim(),
                    fillColor: idx % 2 === 0 ? '#f9f9f9' : '#ffffff'
                });
            });
            if (rowData.length > 0 && rowData[0].text !== 'Loading data...') {
                tableBody.push(rowData);
            }
        });
    }
    
    const docDefinition = {
        pageSize: 'A4',
        pageOrientation: 'portrait',
        pageMargins: [25, 25, 25, 25],
        content: [
            {
                image: headerImg,
                width: 540,
                margin: [0, 0, 0, 12]
            }
        ],
        styles: {
            tableHeader: {
                bold: true,
                fontSize: 11,
                color: 'white',
                fillColor: '#0078d4'
            }
        }
    };
    
    if (chartImg) {
        docDefinition.content.push({
            table: {
                body: [[{
                    image: chartImg,
                    width: 540
                }]]
            },
            layout: {
                hLineWidth: () => 1,
                vLineWidth: () => 1,
                hLineColor: () => '#cccccc',
                vLineColor: () => '#cccccc',
                paddingLeft: () => 0,
                paddingRight: () => 0,
                paddingTop: () => 0,
                paddingBottom: () => 0
            },
            margin: [0, 0, 0, 12]
        });
    }
    
    if (tableBody.length > 0) {
        let columnWidths;
        switch (selectedReport) {
            case 'active-vulnerabilities':
                columnWidths = [60, 70, '*', 92, 40, 40, 40, 30];
                break;
            case 'remediation-activity':
                columnWidths = [55, '*', 92, 60, 69, 69];
                break;
            case 'impact-analysis':
                columnWidths = [36, '*', 92, 40, 40, 66];
                break;
            default:
                columnWidths = Array(tableHeaders.length).fill('*');
                break;
        }
        
        docDefinition.content.push({
            table: {
                headerRows: 1,
                widths: columnWidths,
                body: [tableHeaders, ...tableBody]
            },
            layout: {
                fillColor: (rowIndex) => rowIndex === 0 ? '#0078d4' : null,
                hLineWidth: () => 0.5,
                vLineWidth: () => 0.5,
                hLineColor: () => '#dddddd',
                vLineColor: () => '#dddddd',
                paddingLeft: () => 6,
                paddingRight: () => 6,
                paddingTop: () => 5,
                paddingBottom: () => 5
            },
            fontSize: 10,
            margin: [0, 0, 0, 12]
        });
    }
    
    return docDefinition;
}

function shouldSkipPdfPageWarning() {
    return Boolean(window.__skipPdfExportPageWarning || dashboardConfig.skipPdfExportPageWarning);
}

function estimateTableBasedPdfPageCount(selectedReport) {
    let rowCount = 0;

    switch (selectedReport) {
        case 'active-vulnerabilities':
            rowCount = remediationAllData.length;
            break;
        case 'remediation-activity':
            rowCount = remediationDetailsAllData.length;
            break;
        case 'impact-analysis':
            rowCount = impactAnalysisAllData.length;
            break;
        default:
            rowCount = 0;
            break;
    }

    if (rowCount <= 0) {
        return 1;
    }

    const rowsPerPage = selectedReport === 'active-vulnerabilities' ? 26 : 30;
    return 2 + Math.ceil(rowCount / rowsPerPage);
}

function estimateCardBasedPdfPageCount(selectedReport) {
    const estimatedFromData = estimateCardBasedPdfPageCountFromData(selectedReport);
    if (Number.isFinite(estimatedFromData) && estimatedFromData > 0) {
        return estimatedFromData;
    }

    const activeSection = document.querySelector('.report-section.active');
    const cards = activeSection ? Array.from(activeSection.querySelectorAll('.remediation-card')) : [];

    if (cards.length === 0) {
        return 1;
    }

    const rowsPerPage = selectedReport === 'devices-by-remediation' ? 14 : 10;
    let pageCount = 2;

    cards.forEach(card => {
        const rowCount = card.querySelectorAll('.devices-table tbody tr').length;
        const cveBadgeCount = card.querySelectorAll('.cve-severity-badge').length;
        const supplementalRows = cveBadgeCount > 15
            ? 2
            : (cveBadgeCount > 0 ? 1 : 0);
        const estimatedRows = Math.max(1, rowCount + supplementalRows);
        pageCount += Math.max(1, Math.ceil(estimatedRows / rowsPerPage));
    });

    return pageCount;
}

function estimateCardBasedPdfPageCountFromData(selectedReport) {
    const reportRows = selectedReport === 'devices-by-remediation'
        ? devicesByRemediationAllData
        : selectedReport === 'remediations-by-device'
            ? remediationsByDeviceAllData
            : [];

    if (!Array.isArray(reportRows) || reportRows.length === 0) {
        return null;
    }

    const rowsPerPage = selectedReport === 'devices-by-remediation' ? 14 : 10;
    let pageCount = 2;

    reportRows.forEach(row => {
        let rowCount = 0;
        let cveBadgeCount = 0;

        if (selectedReport === 'devices-by-remediation') {
            rowCount = Number(row.deviceCount) || (row.devices instanceof Map ? row.devices.size : 0);
            cveBadgeCount = Number(row.cveCount) || (row.cveDetails instanceof Map ? row.cveDetails.size : 0);
        } else {
            rowCount = Number(row.remediationCount) || (row.remediations instanceof Map ? row.remediations.size : 0);
            cveBadgeCount = Number(row.cveCount) || 0;
        }

        const supplementalRows = cveBadgeCount > 15
            ? 2
            : (cveBadgeCount > 0 ? 1 : 0);
        const estimatedRows = Math.max(1, rowCount + supplementalRows);
        pageCount += Math.max(1, Math.ceil(estimatedRows / rowsPerPage));
    });

    return pageCount;
}

function estimatePdfPageCount(selectedReport) {
    if (selectedReport === 'devices-by-remediation' || selectedReport === 'remediations-by-device') {
        return estimateCardBasedPdfPageCount(selectedReport);
    }

    return estimateTableBasedPdfPageCount(selectedReport);
}

function getPdfPageCount(pdfDoc) {
    return new Promise(resolve => {
        let settled = false;
        const finish = (value) => {
            if (settled) {
                return;
            }

            settled = true;
            resolve(Number.isFinite(value) && value > 0 ? value : null);
        };

        try {
            if (!pdfDoc || typeof pdfDoc._getPages !== 'function') {
                finish(null);
                return;
            }

            const timeoutHandle = window.setTimeout(() => finish(null), PDF_PAGE_COUNT_TIMEOUT_MS);
            pdfDoc._getPages({}, (pages) => {
                window.clearTimeout(timeoutHandle);

                if (Array.isArray(pages)) {
                    finish(pages.length);
                    return;
                }

                if (pages && typeof pages.length === 'number') {
                    finish(pages.length);
                    return;
                }

                if (typeof pages === 'number') {
                    finish(pages);
                    return;
                }

                finish(null);
            });
        } catch (error) {
            logDebug('Unable to calculate PDF page count', error);
            finish(null);
        }
    });
}

async function resolvePdfPageCount(selectedReport, pdfDoc) {
    const exactPageCount = await getPdfPageCount(pdfDoc);
    if (Number.isFinite(exactPageCount) && exactPageCount > 0) {
        return {
            pageCount: exactPageCount,
            exact: true
        };
    }

    return {
        pageCount: estimatePdfPageCount(selectedReport),
        exact: false
    };
}

async function maybeConfirmLargePdfExport(selectedReport, reportName, pdfDoc) {
    if (shouldSkipPdfPageWarning()) {
        return true;
    }

    const { pageCount, exact } = await resolvePdfPageCount(selectedReport, pdfDoc);
    if (!Number.isFinite(pageCount) || pageCount <= PDF_EXPORT_PAGE_WARNING_THRESHOLD) {
        return true;
    }

    const countDescription = exact
        ? `${pageCount} pages`
        : `about ${pageCount} pages`;

    return window.confirm(
        `PDF export warning: ${reportName} is expected to generate ${countDescription}, which exceeds the ${PDF_EXPORT_PAGE_WARNING_THRESHOLD}-page warning threshold.\n\nLarge exports can take longer to build and may use significant memory.\n\nSelect OK to continue or Cancel to stop the export.`
    );
}

function ensurePdfReportDataReady(selectedReport) {
    if (!initializedReports.has(selectedReport) || dirtyReports.has(selectedReport)) {
        renderReport(selectedReport, true);
    }
}

async function exportToPDF() {
    const button = document.querySelector('.export-pdf-btn');
    button.disabled = true;

    // Create progress bar
    const progressDiv = document.createElement('div');
    progressDiv.className = 'pdf-export-progress';
    progressDiv.innerHTML = '<div class="pdf-progress-container"><div class="pdf-progress-fill" style="width: 0%"></div></div><div class="pdf-progress-text">Loading libraries... 0%</div>';
    document.body.appendChild(progressDiv);

    const updateProgress = (percent, text) => {
        const fill = progressDiv.querySelector('.pdf-progress-fill');
        const label = progressDiv.querySelector('.pdf-progress-text');
        if (fill) fill.style.width = Math.max(0, Math.min(100, percent)) + '%';
        if (label) label.textContent = text + ' ' + Math.round(percent) + '%';
    };

    updateProgress(5, 'Loading libraries...');
    button.textContent = '📄 Loading libraries...';
    setDashboardStatus('Preparing PDF export...');
    
    try {
        await loadPdfLibraries();
    } catch (error) {
        console.error('Failed to load PDF libraries:', error);
        setDashboardStatus('Failed to load PDF export libraries. Please try again from a hosted dashboard or retry the export.', 'error');
        button.disabled = false;
        button.textContent = '📄 Export to PDF';
        progressDiv.remove();
        return;
    }
    
    updateProgress(20, 'Libraries loaded.');

    const selector = document.getElementById('reportSelector');
    const selectedReport = selector.value;
    const reportName = selector.options[selector.selectedIndex].text;
    
    updateProgress(25, 'Checking export size...');
    button.textContent = '📄 Checking size...';
    ensurePdfReportDataReady(selectedReport);
    const shouldContinuePreflight = await maybeConfirmLargePdfExport(selectedReport, reportName);
    if (!shouldContinuePreflight) {
        setDashboardStatus('PDF export canceled.', 'info');
        button.disabled = false;
        button.textContent = '📄 Export to PDF';
        progressDiv.remove();
        return;
    }

    updateProgress(30, 'Expanding data...');
    button.textContent = '📄 Expanding data...';
    
    const wasExpanded = expandReportForPdf(selectedReport);
    await new Promise(resolve => setTimeout(resolve, 100));
    
    updateProgress(35, 'Generating PDF...');
    button.textContent = '📄 Generating PDF...';
    document.body.classList.add('pdf-export-active');
    
    try {
        const fileName = `Vulnerability_Dashboard_${reportName.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.pdf`;
        
        // Choose export strategy based on report type
        let docDefinition;
        if (selectedReport === 'devices-by-remediation' || selectedReport === 'remediations-by-device') {
            docDefinition = await exportCardBasedReportToPdf(selectedReport, reportName);
        } else {
            docDefinition = await exportTableBasedReportToPdf(selectedReport, reportName);
        }
        
        updateProgress(70, 'Adding filters...');
        
        // Add filter information  
        const startDate = filterState.startDate;
        const endDate = filterState.endDate;
        const dateRangeText = formatDateLabel(filterState);
        const deviceGroupsText = getExportFilterText('filterRbacGroup', 'All Groups');
        const deviceTagsText = getExportFilterText('filterDeviceTags', 'All Tags');
        const deviceNamesText = getExportFilterText('filterDeviceName', 'All Devices');
        const osPlatformsText = getExportFilterText('filterOSPlatform', 'All Platforms');
        const severitiesText = getExportFilterText('filterSeverity', 'All Severities');
        
        const filterContent = [];
        
        filterContent.push({
            text: 'Applied Filters',
            fontSize: 13,
            bold: true,
            color: '#0078d4',
            margin: [0, 10, 0, 5]
        });
        
        if (startDate && endDate) {
            filterContent.push({
                text: [
                    { text: 'Date Range: ', bold: true },
                    { text: `${startDate} to ${endDate}` }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 10
            });
        } else {
            filterContent.push({
                text: [
                    { text: 'Date Range: ', bold: true },
                    { text: dateRangeText }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 10
            });
        }
        
        filterContent.push({
            text: [
                { text: 'Groups: ', bold: true },
                { text: deviceGroupsText }
            ],
            margin: [0, 2, 0, 2],
            fontSize: 10
        });

        filterContent.push({
            text: [
                { text: 'Tags: ', bold: true },
                { text: deviceTagsText }
            ],
            margin: [0, 2, 0, 2],
            fontSize: 10
        });
        
        filterContent.push({
            text: [
                { text: 'Devices: ', bold: true },
                { text: deviceNamesText }
            ],
            margin: [0, 2, 0, 2],
            fontSize: 10
        });
        
        filterContent.push({
            text: [
                { text: 'OS Platforms: ', bold: true },
                { text: osPlatformsText }
            ],
            margin: [0, 2, 0, 2],
            fontSize: 10
        });
        
        filterContent.push({
            text: [
                { text: 'Severities: ', bold: true },
                { text: severitiesText }
            ],
            margin: [0, 2, 0, 2],
            fontSize: 10
        });
        
        docDefinition.content.push(...filterContent);

        updateProgress(80, 'Creating PDF...');
        const pdfDoc = pdfMake.createPdf(docDefinition);

        updateProgress(90, 'Downloading PDF...');
        pdfDoc.download(fileName);
        updateProgress(100, 'Complete!');
        clearDashboardStatus();
        setTimeout(() => { if (progressDiv.parentNode) progressDiv.remove(); }, 1500);
    } catch (err) {
        console.error('PDF generation failed:', err);
        setDashboardStatus('Failed to generate PDF: ' + err.message, 'error');
    } finally {
        document.body.classList.remove('pdf-export-active');
        restoreReportState(selectedReport, wasExpanded);
        button.disabled = false;
        button.textContent = '📄 Export to PDF';
        setTimeout(() => { if (progressDiv.parentNode) progressDiv.remove(); }, 3000);
    }
}