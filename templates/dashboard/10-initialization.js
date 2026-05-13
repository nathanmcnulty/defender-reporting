// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize the dashboard on page load
 */
async function init() {
    const initStart = performance.now();
    console.time('[perf] init total');
    setDashboardStatus('Loading dashboard data...');

    // Load and process data
    const loadDataStart = performance.now();
    console.time('[perf] loadData');
    await loadData();
    console.timeEnd('[perf] loadData');
    recordDashboardPhaseTiming('loadDataMs', performance.now() - loadDataStart);

    if (lookups && dashboardPayloadSummary && dashboardConfig.payloadSummaryUrl) {
        buildDeviceFilterCatalog();
        populateFilters();
        setDashboardStatus('Loading detailed vulnerability data...');
    }

    const denormalizeStart = performance.now();
    console.time('[perf] denormalize');
    await denormalizeWithCaching();
    console.timeEnd('[perf] denormalize');
    recordDashboardPhaseTiming('denormalizeMs', performance.now() - denormalizeStart);
    
    logDebug('Initializing dashboard with', vulnerabilityData.length, 'vulnerabilities');
    if (!lookups || !dashboardPayloadSummary || !dashboardConfig.payloadSummaryUrl) {
        buildDeviceFilterCatalog();
        populateFilters();
    }
    updateDataQualitySummary();
    initializeReportNavigationControls();
    applyUrlViewState();
    activeReportId = getCurrentReportId();
    syncReportNavigationUi();
    if (reportRequiresChartRuntime(activeReportId)) {
        await ensureChartJsLoaded();
    }
    attachEventListeners();
    setupInfiniteScroll();
    updateViewShareButtonVisibility();
    updateRemediationReportModeUi(activeReportId);
    scheduleApplyFilters(true);
    clearDashboardStatus();
    console.timeEnd('[perf] init total');
    recordDashboardPhaseTiming('initTotalMs', performance.now() - initStart);
    markDashboardReady();
}

function renderActiveVulnerabilitiesReport() {
    renderChart();
    renderTable();
}

function renderRemediationActivityReport() {
    renderRemediationChart();
    renderRemediationDetailsTable();
}

function renderImpactAnalysisReport() {
    renderImpactChart();
    renderImpactAnalysisTable();
}

function renderDevicesByRemediationReport() {
    renderDevicesByRemediationTable();
}

function renderRemediationsByDeviceReport() {
    renderRemediationsByDeviceTable();
}

function renderReport(reportId, force = false) {
    if (!force && !dirtyReports.has(reportId) && initializedReports.has(reportId)) {
        publishDashboardDiagnostics();
        return;
    }

    const renderStart = performance.now();

    switch (reportId) {
        case 'active-vulnerabilities':
            renderActiveVulnerabilitiesReport();
            break;
        case 'remediation-activity':
            renderRemediationActivityReport();
            break;
        case 'impact-analysis':
            renderImpactAnalysisReport();
            break;
        case 'devices-by-remediation':
            renderDevicesByRemediationReport();
            break;
        case 'remediations-by-device':
            renderRemediationsByDeviceReport();
            break;
        default:
            publishDashboardDiagnostics();
            return;
    }

    initializedReports.add(reportId);
    dirtyReports.delete(reportId);
    recordDashboardRenderTiming(reportId, performance.now() - renderStart);
}

function renderActiveReport(force = false) {
    renderReport(activeReportId, force);
}

function cancelDeferredVisibleReportRender() {
    if (deferredVisibleReportRenderHandle != null) {
        clearTimeout(deferredVisibleReportRenderHandle);
        deferredVisibleReportRenderHandle = null;
    }

    if (deferredVisibleReportRenderReportId) {
        const deferredSection = document.getElementById(deferredVisibleReportRenderReportId + '-section');
        if (deferredSection) {
            deferredSection.removeAttribute('aria-busy');
        }
    }

    if (deferredVisibleReportRenderOwnsStatus) {
        clearDashboardStatus();
    }

    deferredVisibleReportRenderReportId = '';
    deferredVisibleReportRenderOwnsStatus = false;
}

function shouldDeferVisibleReportRender(reportId, force = false) {
    if (force) {
        return false;
    }

    return DEFERRED_VISIBLE_REPORT_IDS.has(reportId) && !initializedReports.has(reportId);
}

function scheduleVisibleReportRender(reportId, force = false) {
    cancelDeferredVisibleReportRender();

    if (!shouldDeferVisibleReportRender(reportId, force)) {
        renderReport(reportId, force);
        return;
    }

    const reportSection = document.getElementById(reportId + '-section');
    if (reportSection) {
        reportSection.setAttribute('aria-busy', 'true');
    }

    deferredVisibleReportRenderReportId = reportId;
    deferredVisibleReportRenderOwnsStatus = true;
    setDashboardStatus(`Preparing ${REPORT_LABELS[reportId] || 'report'}...`);
    deferredVisibleReportRenderHandle = window.setTimeout(() => {
        deferredVisibleReportRenderHandle = null;

        if (activeReportId !== reportId) {
            cancelDeferredVisibleReportRender();
            return;
        }

        try {
            renderReport(reportId, force);
        } finally {
            const activeSection = document.getElementById(reportId + '-section');
            if (activeSection) {
                activeSection.removeAttribute('aria-busy');
            }

            deferredVisibleReportRenderReportId = '';
            if (deferredVisibleReportRenderOwnsStatus) {
                clearDashboardStatus();
            }
            deferredVisibleReportRenderOwnsStatus = false;
        }
    }, 0);
}

/**
 * Set up infinite scroll event listeners using window scroll
 */
let scrollLoadScheduled = false;

function setupInfiniteScroll() {
    // Use window scroll since tables don't have fixed height containers
    window.addEventListener('scroll', handleWindowScroll, { passive: true });
}

/**
 * Handle window scroll for infinite loading
 */
function handleWindowScroll() {
    if (scrollLoadScheduled) {
        return;
    }

    scrollLoadScheduled = true;
    window.requestAnimationFrame(() => {
        scrollLoadScheduled = false;
        processInfiniteScroll();
    });
}

function processInfiniteScroll() {
    // Check if we're near the bottom of the page (within 200px)
    const scrollBottom = document.documentElement.scrollHeight - window.scrollY - window.innerHeight;
    
    if (scrollBottom < 200) {
        // Determine which section is currently visible and load more for that table
        const activeVulnsSection = document.getElementById('active-vulnerabilities-section');
        const remediationActivitySection = document.getElementById('remediation-activity-section');
        const impactAnalysisSection = document.getElementById('impact-analysis-section');
        const devicesByRemediationSection = document.getElementById('devices-by-remediation-section');
        const remediationsByDeviceSection = document.getElementById('remediations-by-device-section');
        
        if (activeVulnsSection && activeVulnsSection.classList.contains('active')) {
            if (!remediationExpanded && remediationLoadedCount < remediationAllData.length) {
                loadMoreRemediationRows();
            }
        } else if (remediationActivitySection && remediationActivitySection.classList.contains('active')) {
            if (!remediationDetailsExpanded && remediationDetailsLoadedCount < remediationDetailsAllData.length) {
                loadMoreRemediationDetailsRows();
            }
        } else if (impactAnalysisSection && impactAnalysisSection.classList.contains('active')) {
            if (!impactAnalysisExpanded && impactAnalysisLoadedCount < impactAnalysisAllData.length) {
                loadMoreImpactAnalysisRows();
            }
        } else if (devicesByRemediationSection && devicesByRemediationSection.classList.contains('active')) {
            if (!devicesByRemediationExpanded && devicesByRemediationLoadedCount < devicesByRemediationAllData.length) {
                loadMoreDevicesByRemediationRows();
            }
        } else if (remediationsByDeviceSection && remediationsByDeviceSection.classList.contains('active')) {
            if (!remediationsByDeviceExpanded && remediationsByDeviceLoadedCount < remediationsByDeviceAllData.length) {
                loadMoreRemediationsByDeviceRows();
            }
        }
    }
}

/**
 * Build the device facet catalog used by the cascading device filters.
 */
function buildDeviceFilterCatalog() {
    deviceFilterCatalog = lookups.devices.map(device => ({
        deviceId: device.id,
        deviceName: device.n,
        rbacGroup: device._normalizedGroup || getDeviceGroupName(device),
        deviceTags: device._tagValues || (device.t && device.t.length > 0
            ? device.t.map(tagIndex => lookups.tags[tagIndex])
            : NO_TAGS_ARRAY)
    }));

    deviceDuplicateNameCounts = deviceFilterCatalog.reduce((counts, device) => {
        const key = device.deviceName || device.deviceId || '';
        counts.set(key, (counts.get(key) || 0) + 1);
        return counts;
    }, new Map());

    deviceFilterLabelByKey = deviceFilterCatalog.reduce((labels, device) => {
        const key = getDeviceIdentityKey(device);
        if (!key) {
            return labels;
        }

        const duplicateCount = deviceDuplicateNameCounts.get(device.deviceName || device.deviceId || '') || 0;
        const label = duplicateCount > 1 && device.deviceName && device.deviceId
            ? `${device.deviceName} (${device.deviceId})`
            : (device.deviceName || device.deviceId);
        labels.set(key, label);
        return labels;
    }, new Map());
}
