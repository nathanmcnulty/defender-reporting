/**
 * Vulnerability Dashboard - Main JavaScript
 *
 * This file contains all the client-side logic for the vulnerability dashboard.
 * It handles data filtering, chart rendering, table management, and PDF export.
 *
 * Data is stored in a normalized format for optimal file size:
 * - lookups: Reference tables for devices, CVEs, software, etc.
 * - vulns: Compact array records with indices into lookup tables
 */

// =============================================================================
// GLOBAL STATE
// =============================================================================

function getScriptElementText(id) {
    const element = document.getElementById(id);
    return element ? element.textContent.trim() : '';
}

function parseDashboardConfig() {
    const configText = getScriptElementText('dashboardConfig');
    if (!configText) {
        return {
            deliveryMode: 'self-contained',
            chartJsMode: 'embedded',
            pdfExportBundleMode: 'embedded'
        };
    }

    try {
        return JSON.parse(configText);
    } catch (error) {
        console.error('Failed to parse dashboard configuration:', error);
        return {
            deliveryMode: 'self-contained',
            chartJsMode: 'embedded',
            pdfExportBundleMode: 'embedded'
        };
    }
}

const dashboardConfig = parseDashboardConfig();
const debugLoggingEnabled = Boolean(dashboardConfig.debugLogging);

function logDebug(...args) {
    if (debugLoggingEnabled) {
        console.log(...args);
    }
}

// Data format: 'normalized', 'compressed', or 'external-compressed'
const dataFormat = getScriptElementText('dataFormat');
const reportNavigationMode = 'popover';

// Lookup tables and raw vulnerability array (loaded from embedded data)
let lookups = null;
let rawVulns = null;
let dataQualityMeta = { firstLastSwapped: 0, generatedOnUtc: null };
let dataQualitySummary = createEmptyDataQualitySummary();

// Denormalized vulnerability data (expanded from normalized format)
let vulnerabilityData = [];

// Filtered data based on current filter selections
let filteredData = [];

// Latest dataset boundary used by time-series charts
let mostRecentLastSeenDate = '';

// Chart instances (for cleanup on re-render)
let chartInstance = null;
let remediationChartInstance = null;
let impactChartInstance = null;
let chartJsLoadPromise = null;
let pdfLibrariesLoadPromise = null;
let pdfExportRuntimeLoadPromise = null;
const loadedScriptPromises = new Map();

// Device facet catalog used by filtering
let deviceFilterCatalog = [];
let deviceFilterLabelByKey = new Map();
let deviceDuplicateNameCounts = new Map();
let cascadingFilterOptions = {};
let cascadingFilterState = {};

// Constant for devices without tags
const NO_TAGS_VALUE = '(No Tags)';
const NO_TAGS_ARRAY = [NO_TAGS_VALUE];

// Constant for devices without an RBAC group
const NO_GROUP_VALUE = '(none)';
const DEVICE_INACTIVITY_WINDOW_DAYS = 30;
const VIEW_STATE_PARAM = 'view';

const CASCADING_FILTER_IDS = ['filterRbacGroup', 'filterDeviceTags', 'filterDeviceName'];
const CASCADING_FILTER_CONFIG = {
    filterRbacGroup: {
        allLabel: 'All Groups',
        getValuesForVuln: v => [v._normalizedGroup]
    },
    filterDeviceTags: {
        allLabel: 'All Tags',
        getValuesForVuln: v => v._tagValues
    },
    filterDeviceName: {
        allLabel: 'All Devices',
        getValuesForVuln: v => [v._deviceFilterKey]
    }
};

/**
 * Normalize RBAC group names so null/blank values are represented consistently.
 * @param {string|null|undefined} value - Raw group name
 * @returns {string} Normalized group name
 */
function normalizeGroupName(value) {
    if (typeof value === 'string') {
        const trimmed = value.trim();
        if (trimmed.length > 0) return trimmed;
    }
    return NO_GROUP_VALUE;
}

/**
 * Resolve and normalize a device's group name from lookups.
 * @param {Object} device - Normalized device record
 * @returns {string} Normalized group name
 */
function getDeviceGroupName(device) {
    if (!device || !lookups || !Array.isArray(lookups.groups)) return NO_GROUP_VALUE;
    const groupValue = (typeof device.g === 'number' && device.g >= 0 && device.g < lookups.groups.length)
        ? lookups.groups[device.g]
        : null;
    return normalizeGroupName(groupValue);
}

function getDeviceNameFilterValue(deviceLike) {
    return getDeviceIdentityKey(deviceLike);
}

function getDeviceIdentityKey(deviceLike) {
    return deviceLike.DeviceId || deviceLike.deviceId || deviceLike.DeviceName || deviceLike.deviceName || '';
}

// Table sort state
let sortDirection = {};
let sortRemediationDetailsDirection = {};
let sortImpactAnalysisDirection = {};

// Render and filter state
const TABLE_PAGE_SIZE = 100;
const CARD_PAGE_SIZE = 20;
const CARD_RENDER_BATCH_SIZE = 50;
const DEVICE_CARD_VIRTUALIZATION_THRESHOLD = 250;
const DEVICE_CARD_VIRTUALIZATION_ROW_HEIGHT = 44;
const configuredPdfPageWarningThreshold = Number(dashboardConfig.pdfExportPageWarningThreshold);
const configuredReportDataWarmupRowLimit = Number(dashboardConfig.reportDataWarmupRowLimit);
const configuredReportDataWarmupMode = typeof dashboardConfig.reportDataWarmupMode === 'string'
    ? dashboardConfig.reportDataWarmupMode.toLowerCase()
    : 'auto';
const configuredDenormalizeYieldRowThreshold = Number(dashboardConfig.denormalizeYieldRowThreshold);
const configuredDenormalizeYieldRowInterval = Number(dashboardConfig.denormalizeYieldRowInterval);
const PDF_EXPORT_PAGE_WARNING_THRESHOLD = Number.isFinite(configuredPdfPageWarningThreshold) && configuredPdfPageWarningThreshold > 0
    ? Math.floor(configuredPdfPageWarningThreshold)
    : 100;
const REPORT_DATA_WARMUP_ROW_LIMIT = Number.isFinite(configuredReportDataWarmupRowLimit) && configuredReportDataWarmupRowLimit >= 0
    ? Math.floor(configuredReportDataWarmupRowLimit)
    : 1000;
const REPORT_DATA_WARMUP_MODE = ['always', 'auto', 'never'].includes(configuredReportDataWarmupMode)
    ? configuredReportDataWarmupMode
    : 'auto';
const DENORMALIZE_YIELD_ROW_THRESHOLD = Number.isFinite(configuredDenormalizeYieldRowThreshold) && configuredDenormalizeYieldRowThreshold >= 0
    ? Math.floor(configuredDenormalizeYieldRowThreshold)
    : 50000;
const DENORMALIZE_YIELD_ROW_INTERVAL = Number.isFinite(configuredDenormalizeYieldRowInterval) && configuredDenormalizeYieldRowInterval > 0
    ? Math.floor(configuredDenormalizeYieldRowInterval)
    : 25000;
const PDF_PAGE_COUNT_TIMEOUT_MS = 10000;
const APPLY_FILTER_DEBOUNCE_MS = 50;
const FACET_SEARCH_MIN_OPTIONS = 8;
const FILTER_POPOVER_BATCH_FLOOR = 100;
const FILTER_POPOVER_BATCH_CEILING = 250;
const FILTER_POPOVER_BATCH_PERCENTAGE = 0.01;
const FILTER_POPOVER_SCROLL_PRELOAD_PX = 96;
const DATE_PRESET_CONFIG = {
    '1w': '1 Week',
    '1m': '1 Month',
    '3m': '3 Months',
    '6m': '6 Months',
    '12m': '12 Months'
};
const FILTER_POPOVER_CONFIG = {
    date: {
        buttonId: 'filterPillDate',
        label: 'Date'
    },
    filterRbacGroup: {
        buttonId: 'filterPillRbacGroup',
        label: 'Groups',
        stateKey: 'rbacGroups',
        hasAnyKey: 'hasRbacGroups',
        allText: 'All',
        summaryNoun: 'groups'
    },
    filterDeviceTags: {
        buttonId: 'filterPillDeviceTags',
        label: 'Tags',
        stateKey: 'deviceTags',
        hasAnyKey: 'hasDeviceTags',
        allText: 'All',
        summaryNoun: 'tags'
    },
    filterOSPlatform: {
        buttonId: 'filterPillOSPlatform',
        label: 'Platform',
        stateKey: 'osPlatforms',
        hasAnyKey: 'hasOsPlatforms',
        allText: 'All',
        summaryNoun: 'platforms'
    },
    filterSeverity: {
        buttonId: 'filterPillSeverity',
        label: 'Severity',
        stateKey: 'severities',
        hasAnyKey: 'hasSeverities',
        allText: 'All',
        summaryNoun: 'severities'
    },
    filterDeviceName: {
        buttonId: 'filterPillDeviceName',
        label: 'Device',
        stateKey: 'deviceNames',
        hasAnyKey: 'hasDeviceNames',
        allText: 'All',
        summaryNoun: 'devices',
        searchable: true
    }
};
const FILTER_POPOVER_KEYS = Object.keys(FILTER_POPOVER_CONFIG);
const FILTER_MULTISELECT_KEYS = FILTER_POPOVER_KEYS.filter(filterKey => filterKey !== 'date');
const REPORT_IDS = [
    'active-vulnerabilities',
    'remediation-activity',
    'impact-analysis',
    'devices-by-remediation',
    'remediations-by-device'
];
const DEFERRED_VISIBLE_REPORT_IDS = new Set(REPORT_IDS.filter(reportId => reportId !== 'active-vulnerabilities'));
const CHART_REPORT_IDS = new Set([
    'active-vulnerabilities',
    'remediation-activity',
    'impact-analysis'
]);
const REPORT_LABELS = {
    'active-vulnerabilities': 'Active Vulnerabilities',
    'remediation-activity': 'Remediation Activity',
    'impact-analysis': 'Impact Analysis',
    'devices-by-remediation': 'Devices by Remediation',
    'remediations-by-device': 'Remediations by Device'
};
const REMEDIATION_SCOPE_REPORT_IDS = ['devices-by-remediation', 'remediations-by-device'];
const REMEDIATION_REPORT_MODE_RANGE = 'range';
const REMEDIATION_REPORT_MODE_SNAPSHOT = 'snapshot';
const MAX_VISIBLE_DEVICE_REMEDIATIONS = 10;

let applyFiltersTimer = null;
let activeReportId = 'active-vulnerabilities';
let remediationReportMode = REMEDIATION_REPORT_MODE_SNAPSHOT;
const initializedReports = new Set();
const dirtyReports = new Set(REPORT_IDS);
let deferredVisibleReportRenderHandle = null;
let deferredVisibleReportRenderReportId = '';
let deferredVisibleReportRenderOwnsStatus = false;

let filterState = createEmptyFilterState();
let filterPopoverDraftState = null;
let activeFilterPopoverKey = null;
let reportSelectorPopoverOpen = false;
let activeFilterPopoverOptions = [];
let activeFilterPopoverFilteredOptions = [];
let activeFilterPopoverRenderedCount = 0;
let activeFilterPopoverSearchTerm = '';
let activeFilterPopoverBatchSize = 0;
let aggregateCacheKey = null;
let aggregateCache = createEmptyAggregateCache();
let cascadingFilterCountCacheKey = null;
let cascadingFilterCountCache = null;
let chartDataCacheKey = null;
let chartDataCache = null;
let reportDataWarmupHandle = null;
let reportDataWarmupUsesIdleCallback = false;
let reportDataWarmupToken = 0;

// Remediation table scroll state
let remediationLoadedCount = 0;
let remediationAllData = [];
let remediationExpanded = false;

// Remediation details table scroll state
let remediationDetailsLoadedCount = 0;
let remediationDetailsAllData = [];
let remediationDetailsExpanded = false;

// Impact analysis table scroll state
let impactAnalysisLoadedCount = 0;
let impactAnalysisAllData = [];
let impactAnalysisExpanded = false;

// Devices by remediation table scroll state
let devicesByRemediationLoadedCount = 0;
let devicesByRemediationAllData = [];
let devicesByRemediationExpanded = false;
let devicesByRemediationSortDirection = {};
let expandedRemediations = {};

// Remediations by device table scroll state
let remediationsByDeviceLoadedCount = 0;
let remediationsByDeviceAllData = [];
let remediationsByDeviceExpanded = false;
let remediationsByDeviceSortDirection = {};
let expandedDevices = {};
let lastFocusedElementBeforeModal = null;
let forceFullDevicesByRemediationRows = false;

function getDashboardGlobalScope() {
    if (typeof window !== 'undefined' && window) {
        return window;
    }

    return globalThis;
}

function createEmptyDashboardMetricsState() {
    return {
        version: 1,
        deliveryMode: dashboardConfig.deliveryMode || 'self-contained',
        activeReportId,
        ready: false,
        lastUpdatedUtc: '',
        phases: {
            loadDataMs: 0,
            denormalizeMs: 0,
            applyFiltersMs: 0,
            initTotalMs: 0
        },
        reports: {},
        counts: {
            applyFilters: 0,
            renders: 0,
            denormalizeYields: 0
        }
    };
}

let dashboardMetrics = createEmptyDashboardMetricsState();

function cloneDashboardMetricsSnapshot() {
    const reports = {};
    Object.keys(dashboardMetrics.reports).forEach(reportId => {
        reports[reportId] = { ...dashboardMetrics.reports[reportId] };
    });

    return {
        version: dashboardMetrics.version,
        deliveryMode: dashboardMetrics.deliveryMode,
        activeReportId: dashboardMetrics.activeReportId,
        ready: dashboardMetrics.ready,
        lastUpdatedUtc: dashboardMetrics.lastUpdatedUtc,
        phases: { ...dashboardMetrics.phases },
        reports,
        counts: { ...dashboardMetrics.counts }
    };
}

function getDashboardMetricsSnapshot() {
    dashboardMetrics.activeReportId = getCurrentReportId();
    dashboardMetrics.ready = Boolean(getDashboardGlobalScope()._dashboardReady);
    dashboardMetrics.lastUpdatedUtc = new Date().toISOString();
    return cloneDashboardMetricsSnapshot();
}

function hasDashboardElement(id) {
    return Boolean(document.getElementById(id));
}

function getDashboardElementText(id) {
    const element = document.getElementById(id);
    return element ? String(element.textContent || '').trim() : '';
}

function getDashboardSelectOptions(id, fallbackEntries = []) {
    const element = document.getElementById(id);
    if (element && element.options) {
        return Array.from(element.options).map(option => ({
            value: option.value,
            label: String(option.textContent || option.label || '').trim()
        }));
    }

    return fallbackEntries.map(entry => ({ ...entry }));
}

function buildDashboardValidationSnapshot() {
    return {
        deliveryMode: dashboardConfig.deliveryMode || 'self-contained',
        reportNavigationMode,
        activeReportId: getCurrentReportId(),
        ready: Boolean(getDashboardGlobalScope()._dashboardReady),
        statusMessage: getDashboardElementText('dashboardStatus'),
        summaryCards: {
            critical: getDashboardElementText('criticalCount'),
            high: getDashboardElementText('highCount'),
            medium: getDashboardElementText('mediumCount'),
            low: getDashboardElementText('lowCount')
        },
        reportSelectorOptions: getDashboardSelectOptions(
            'reportSelector',
            REPORT_IDS.map(reportId => ({ value: reportId, label: REPORT_LABELS[reportId] || reportId }))
        ),
        filterControls: {
            date: hasDashboardElement('filterPillDate'),
            deviceGroups: hasDashboardElement('filterPillRbacGroup'),
            deviceTags: hasDashboardElement('filterPillDeviceTags'),
            platform: hasDashboardElement('filterPillOSPlatform'),
            severity: hasDashboardElement('filterPillSeverity'),
            device: hasDashboardElement('filterPillDeviceName'),
            clearAll: hasDashboardElement('clearAllFiltersButton')
        },
        reportSections: REPORT_IDS.reduce((sections, reportId) => {
            sections[reportId] = hasDashboardElement(reportId + '-section');
            return sections;
        }, {}),
        reportSurfaces: {
            activeVulnerabilitiesTable: hasDashboardElement('remediationTable'),
            remediationActivityTable: hasDashboardElement('remediationDetailsTable'),
            impactAnalysisTable: hasDashboardElement('impactAnalysisTable'),
            devicesByRemediationContainer: hasDashboardElement('devicesByRemediationContainer'),
            remediationsByDeviceContainer: hasDashboardElement('remediationsByDeviceContainer')
        }
    };
}

function publishDashboardDiagnostics() {
    const dashboardScope = getDashboardGlobalScope();
    const metrics = getDashboardMetricsSnapshot();
    const validation = buildDashboardValidationSnapshot();
    dashboardScope.dashboardMetrics = metrics;
    dashboardScope.dashboardValidation = validation;
    return { metrics, validation };
}

function recordDashboardPhaseTiming(name, durationMs) {
    if (!Number.isFinite(durationMs) || durationMs < 0) {
        return;
    }

    dashboardMetrics.phases[name] = Number(durationMs.toFixed(3));
    publishDashboardDiagnostics();
}

function recordDashboardRenderTiming(reportId, durationMs) {
    if (!Number.isFinite(durationMs) || durationMs < 0 || !reportId) {
        return;
    }

    const roundedDuration = Number(durationMs.toFixed(3));
    const currentMetrics = dashboardMetrics.reports[reportId] || {
        label: REPORT_LABELS[reportId] || reportId,
        count: 0,
        lastMs: 0,
        maxMs: 0
    };
    currentMetrics.count += 1;
    currentMetrics.lastMs = roundedDuration;
    currentMetrics.maxMs = Math.max(currentMetrics.maxMs, roundedDuration);
    dashboardMetrics.reports[reportId] = currentMetrics;
    dashboardMetrics.counts.renders += 1;
    publishDashboardDiagnostics();
}

function dispatchDashboardEvent(name, detail) {
    const dashboardScope = getDashboardGlobalScope();
    if (typeof dashboardScope.dispatchEvent !== 'function') {
        return;
    }

    if (typeof CustomEvent === 'function') {
        dashboardScope.dispatchEvent(new CustomEvent(name, { detail }));
        return;
    }

    if (typeof Event === 'function') {
        const event = new Event(name);
        event.detail = detail;
        dashboardScope.dispatchEvent(event);
        return;
    }

    dashboardScope.dispatchEvent({ type: name, detail });
}

function markDashboardReady() {
    const dashboardScope = getDashboardGlobalScope();
    dashboardScope._dashboardReady = true;
    const detail = publishDashboardDiagnostics();
    dispatchDashboardEvent('dashboard-ready', detail);
}

getDashboardGlobalScope()._dashboardReady = false;
publishDashboardDiagnostics();

function createEmptyFilterState() {
    return {
        datePreset: '',
        startDate: '',
        endDate: '',
        deviceSearch: '',
        deviceSearchNormalized: '',
        deviceNames: [],
        rbacGroups: [],
        deviceTags: [],
        severities: [],
        osPlatforms: [],
        hasDeviceNames: true,
        hasRbacGroups: true,
        hasDeviceTags: true,
        hasSeverities: true,
        hasOsPlatforms: true,
        deviceNameSet: new Set(),
        rbacGroupSet: new Set(),
        deviceTagSet: new Set(),
        severitySet: new Set(),
        osPlatformSet: new Set(),
        key: ''
    };
}

function normalizeFilterValueArray(values) {
    return Array.isArray(values)
        ? values.filter(value => typeof value === 'string' && value.length > 0)
        : [];
}

function normalizeFilterDateValue(value) {
    if (typeof value !== 'string') {
        return '';
    }

    const trimmedValue = value.trim();
    return /^\d{4}-\d{2}-\d{2}$/.test(trimmedValue) ? trimmedValue : '';
}

function normalizeFilterDateRange(startDate, endDate, swapInverted = false) {
    const normalizedStartDate = normalizeFilterDateValue(startDate);
    const normalizedEndDate = normalizeFilterDateValue(endDate);
    const isInverted = Boolean(normalizedStartDate && normalizedEndDate && normalizedStartDate > normalizedEndDate);

    if (!isInverted || !swapInverted) {
        return {
            startDate: normalizedStartDate,
            endDate: normalizedEndDate,
            isInverted,
            wasInverted: false
        };
    }

    return {
        startDate: normalizedEndDate,
        endDate: normalizedStartDate,
        isInverted: false,
        wasInverted: true
    };
}

function getDateRangeValidationMessage(state = filterState) {
    const normalizedDateRange = normalizeFilterDateRange(state?.startDate, state?.endDate, false);
    return normalizedDateRange.isInverted
        ? 'Start date must be on or before end date.'
        : '';
}

function finalizeFilterState(state) {
    const nextState = createEmptyFilterState();
    const normalizedDateRange = normalizeFilterDateRange(state.startDate, state.endDate, true);

    nextState.datePreset = typeof state.datePreset === 'string' ? state.datePreset : '';
    if (nextState.datePreset !== 'custom' && !DATE_PRESET_CONFIG[nextState.datePreset]) {
        nextState.datePreset = (normalizedDateRange.startDate || normalizedDateRange.endDate) ? 'custom' : '';
    }
    if (normalizedDateRange.wasInverted) {
        nextState.datePreset = 'custom';
    }
    nextState.startDate = normalizedDateRange.startDate;
    nextState.endDate = normalizedDateRange.endDate;
    nextState.deviceSearch = state.deviceSearch || '';
    nextState.deviceSearchNormalized = nextState.deviceSearch.toLowerCase();
    nextState.deviceNames = normalizeFilterValueArray(state.deviceNames);
    nextState.rbacGroups = normalizeFilterValueArray(state.rbacGroups);
    nextState.deviceTags = normalizeFilterValueArray(state.deviceTags);
    nextState.severities = normalizeFilterValueArray(state.severities);
    nextState.osPlatforms = normalizeFilterValueArray(state.osPlatforms);

    nextState.hasDeviceNames = state.hasDeviceNames !== undefined ? Boolean(state.hasDeviceNames) : true;
    nextState.hasRbacGroups = state.hasRbacGroups !== undefined ? Boolean(state.hasRbacGroups) : true;
    nextState.hasDeviceTags = state.hasDeviceTags !== undefined ? Boolean(state.hasDeviceTags) : true;
    nextState.hasSeverities = state.hasSeverities !== undefined ? Boolean(state.hasSeverities) : true;
    nextState.hasOsPlatforms = state.hasOsPlatforms !== undefined ? Boolean(state.hasOsPlatforms) : true;

    if (nextState.deviceNames.length > 0) nextState.hasDeviceNames = true;
    if (nextState.rbacGroups.length > 0) nextState.hasRbacGroups = true;
    if (nextState.deviceTags.length > 0) nextState.hasDeviceTags = true;
    if (nextState.severities.length > 0) nextState.hasSeverities = true;
    if (nextState.osPlatforms.length > 0) nextState.hasOsPlatforms = true;

    nextState.deviceNameSet = new Set(nextState.deviceNames);
    nextState.rbacGroupSet = new Set(nextState.rbacGroups);
    nextState.deviceTagSet = new Set(nextState.deviceTags);
    nextState.severitySet = new Set(nextState.severities);
    nextState.osPlatformSet = new Set(nextState.osPlatforms);
    nextState.key = buildFilterStateKey(nextState);
    return nextState;
}

function cloneFilterState(state = filterState) {
    return finalizeFilterState({
        datePreset: state.datePreset,
        startDate: state.startDate,
        endDate: state.endDate,
        deviceSearch: state.deviceSearch,
        deviceNames: [...state.deviceNames],
        rbacGroups: [...state.rbacGroups],
        deviceTags: [...state.deviceTags],
        severities: [...state.severities],
        osPlatforms: [...state.osPlatforms],
        hasDeviceNames: state.hasDeviceNames,
        hasRbacGroups: state.hasRbacGroups,
        hasDeviceTags: state.hasDeviceTags,
        hasSeverities: state.hasSeverities,
        hasOsPlatforms: state.hasOsPlatforms
    });
}

function createDefaultFilterState() {
    return finalizeFilterState(assignDatePreset(createEmptyFilterState(), '1w'));
}

function buildUrlViewStatePayload(state = filterState) {
    return {
        version: 1,
        report: activeReportId,
        remediationMode: remediationReportMode,
        filters: {
            datePreset: state.datePreset,
            startDate: state.startDate,
            endDate: state.endDate,
            deviceSearch: state.deviceSearch,
            deviceNames: [...state.deviceNames],
            rbacGroups: [...state.rbacGroups],
            deviceTags: [...state.deviceTags],
            severities: [...state.severities],
            osPlatforms: [...state.osPlatforms],
            hasDeviceNames: state.hasDeviceNames,
            hasRbacGroups: state.hasRbacGroups,
            hasDeviceTags: state.hasDeviceTags,
            hasSeverities: state.hasSeverities,
            hasOsPlatforms: state.hasOsPlatforms
        }
    };
}

function isDefaultViewState(state = filterState, reportId = activeReportId, mode = remediationReportMode) {
    const defaultState = createDefaultFilterState();
    return reportId === 'active-vulnerabilities'
        && mode === REMEDIATION_REPORT_MODE_SNAPSHOT
        && state.key === defaultState.key;
}

function syncUrlViewState() {
    if (typeof window === 'undefined' || !window.location || !window.history || typeof URL !== 'function') {
        return;
    }

    const url = new URL(window.location.href);
    if (isDefaultViewState()) {
        url.searchParams.delete(VIEW_STATE_PARAM);
    } else {
        url.searchParams.set(VIEW_STATE_PARAM, JSON.stringify(buildUrlViewStatePayload()));
    }

    const nextUrl = `${url.pathname}${url.search}${url.hash}`;
    const currentUrl = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    if (nextUrl !== currentUrl) {
        window.history.replaceState(null, '', nextUrl);
    }
}

function canShowViewShareButton() {
    if (typeof window === 'undefined' || !window.location) {
        return false;
    }

    const protocol = window.location.protocol || '';
    return dashboardConfig.deliveryMode === 'split-assets'
        && (protocol === 'http:' || protocol === 'https:');
}

function updateViewShareButtonVisibility() {
    const button = document.getElementById('copyViewLinkButton');
    if (!button) {
        return;
    }

    button.hidden = !canShowViewShareButton();
}

async function copyTextToClipboard(text) {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        await navigator.clipboard.writeText(text);
        return;
    }

    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', 'true');
    textarea.style.position = 'absolute';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    textarea.remove();
}

async function handleCopyViewLinkClick() {
    syncUrlViewState();

    try {
        await copyTextToClipboard(window.location.href);
        setDashboardStatus('View link copied.', 'info');
    } catch (error) {
        console.error('Failed to copy view link:', error);
        setDashboardStatus('Failed to copy the view link. Copy the URL from the address bar instead.', 'error');
    }
}

function parseUrlViewState() {
    if (typeof window === 'undefined' || !window.location || typeof URLSearchParams !== 'function') {
        return null;
    }

    const rawValue = new URLSearchParams(window.location.search).get(VIEW_STATE_PARAM);
    if (!rawValue) {
        return null;
    }

    try {
        const parsed = JSON.parse(rawValue);
        const filters = parsed && typeof parsed.filters === 'object' && parsed.filters ? parsed.filters : {};
        return {
            report: REPORT_IDS.includes(parsed?.report) ? parsed.report : 'active-vulnerabilities',
            remediationMode: parsed?.remediationMode === REMEDIATION_REPORT_MODE_RANGE
                ? REMEDIATION_REPORT_MODE_RANGE
                : REMEDIATION_REPORT_MODE_SNAPSHOT,
            filterState: finalizeFilterState({
                datePreset: typeof filters.datePreset === 'string' ? filters.datePreset : '',
                startDate: typeof filters.startDate === 'string' ? filters.startDate : '',
                endDate: typeof filters.endDate === 'string' ? filters.endDate : '',
                deviceSearch: typeof filters.deviceSearch === 'string' ? filters.deviceSearch : '',
                deviceNames: normalizeFilterValueArray(filters.deviceNames),
                rbacGroups: normalizeFilterValueArray(filters.rbacGroups),
                deviceTags: normalizeFilterValueArray(filters.deviceTags),
                severities: normalizeFilterValueArray(filters.severities),
                osPlatforms: normalizeFilterValueArray(filters.osPlatforms),
                hasDeviceNames: filters.hasDeviceNames !== undefined ? Boolean(filters.hasDeviceNames) : true,
                hasRbacGroups: filters.hasRbacGroups !== undefined ? Boolean(filters.hasRbacGroups) : true,
                hasDeviceTags: filters.hasDeviceTags !== undefined ? Boolean(filters.hasDeviceTags) : true,
                hasSeverities: filters.hasSeverities !== undefined ? Boolean(filters.hasSeverities) : true,
                hasOsPlatforms: filters.hasOsPlatforms !== undefined ? Boolean(filters.hasOsPlatforms) : true
            })
        };
    } catch (error) {
        console.warn('Ignoring invalid dashboard view state from URL.', error);
        return null;
    }
}

function applyUrlViewState() {
    const viewState = parseUrlViewState();
    if (!viewState) {
        return false;
    }

    remediationReportMode = viewState.remediationMode;
    filterState = viewState.filterState;
    activeReportId = viewState.report;

    const selector = document.getElementById('reportSelector');
    if (selector) {
        selector.value = activeReportId;
    }

    renderFilterPills(filterState);
    syncReportNavigationUi();
    return true;
}

function getDateRangeValues(range) {
    const endDate = new Date();
    const startDate = new Date();

    switch (range) {
        case '1w':
            startDate.setDate(startDate.getDate() - 7);
            break;
        case '1m':
            startDate.setMonth(startDate.getMonth() - 1);
            break;
        case '3m':
            startDate.setMonth(startDate.getMonth() - 3);
            break;
        case '6m':
            startDate.setMonth(startDate.getMonth() - 6);
            break;
        case '12m':
            startDate.setFullYear(startDate.getFullYear() - 1);
            break;
        default:
            break;
    }

    return {
        startDate: startDate.toISOString().split('T')[0],
        endDate: endDate.toISOString().split('T')[0]
    };
}

function assignDatePreset(state, range) {
    const nextState = state;
    const { startDate, endDate } = getDateRangeValues(range);
    nextState.datePreset = range;
    nextState.startDate = startDate;
    nextState.endDate = endDate;
    return nextState;
}

function resetFilterInState(state, filterKey) {
    const nextState = state;
    if (filterKey === 'date') {
        return assignDatePreset(nextState, '1w');
    }

    const config = FILTER_POPOVER_CONFIG[filterKey];
    if (!config || !config.stateKey) {
        return nextState;
    }

    nextState[config.stateKey] = [];
    if (config.hasAnyKey) {
        nextState[config.hasAnyKey] = true;
    }
    if (filterKey === 'filterDeviceName') {
        nextState.deviceSearch = '';
        nextState.deviceSearchNormalized = '';
    }
    return nextState;
}

function formatDateLabel(state = filterState) {
    if (state.datePreset && DATE_PRESET_CONFIG[state.datePreset]) {
        return DATE_PRESET_CONFIG[state.datePreset];
    }
    return 'Custom';
}

function isDateFilterDefault(state = filterState) {
    return state.datePreset === '1w';
}

function getDeviceSelectionLabelCount(state = filterState) {
    return state.deviceNames.length;
}

function formatFilterSelectionProgress(selectedCount, totalCount) {
    return `${selectedCount.toLocaleString()} of ${totalCount.toLocaleString()} selected`;
}

function getScopedFilterOptionCount(filterKey, state = filterState) {
    if (state === filterState && activeFilterPopoverKey === filterKey && activeFilterPopoverOptions.length > 0) {
        return activeFilterPopoverOptions.length;
    }

    return getScopedFilterOptions(filterKey, state).length;
}

function getFilterSelectionCount(filterKey, state = filterState, totalCount = null) {
    const config = FILTER_POPOVER_CONFIG[filterKey];
    if (!config || !config.stateKey || filterKey === 'date') {
        return 0;
    }

    if (!state[config.hasAnyKey]) {
        return 0;
    }

    const values = state[config.stateKey] || [];
    if (values.length > 0) {
        return values.length;
    }

    if (typeof totalCount === 'number') {
        return totalCount;
    }

    return getScopedFilterOptionCount(filterKey, state);
}

function getFilterPillValue(filterKey, state = filterState) {
    if (filterKey === 'date') {
        return formatDateLabel(state);
    }

    if (filterKey === 'filterDeviceName') {
        const totalCount = getScopedFilterOptionCount(filterKey, state);
        const selectedCount = getFilterSelectionCount(filterKey, state, totalCount);
        if (selectedCount === totalCount && totalCount > 0) {
            return `All (${totalCount.toLocaleString()})`;
        }

        return formatFilterSelectionProgress(selectedCount, totalCount);
    }

    const config = FILTER_POPOVER_CONFIG[filterKey];
    const values = config && config.stateKey ? state[config.stateKey] : [];
    if (config && config.hasAnyKey && !state[config.hasAnyKey]) {
        return 'None';
    }
    if (!values || values.length === 0) {
        return config ? config.allText : 'All';
    }
    if (values.length === 1) {
        return values[0];
    }
    return `${values.length} selected`;
}

function isFilterActive(filterKey, state = filterState) {
    if (filterKey === 'date') {
        return !isDateFilterDefault(state);
    }

    const config = FILTER_POPOVER_CONFIG[filterKey];
    return Boolean(
        config && config.stateKey && (
            !state[config.hasAnyKey] || state[config.stateKey].length > 0
        )
    );
}

function renderFilterPills(state = filterState) {
    FILTER_POPOVER_KEYS.forEach(filterKey => {
        const config = FILTER_POPOVER_CONFIG[filterKey];
        const button = document.getElementById(config.buttonId);
        if (!button) return;

        const value = button.querySelector('.filter-pill-value');
        const pillValue = getFilterPillValue(filterKey, state);
        if (value) {
            value.textContent = pillValue;
        }

        button.title = `${config.label}: ${pillValue}`;

        button.classList.toggle('is-active', isFilterActive(filterKey, state));
        button.classList.toggle('is-open', activeFilterPopoverKey === filterKey);
        button.setAttribute('aria-expanded', activeFilterPopoverKey === filterKey ? 'true' : 'false');
    });
}

function createEmptyDataQualitySummary() {
    return {
        totalRecords: 0,
        uniqueDevices: 0,
        uniqueCves: 0,
        missingPublished: 0,
        nonYmdPublished: 0,
        invertedRanges: 0
    };
}

function createEmptySeverityCounts() {
    return {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0
    };
}

function createEmptySeveritySeries() {
    return {
        Critical: [],
        High: [],
        Medium: [],
        Low: []
    };
}

function createEmptyAggregateCache() {
    return {
        activeRowsAsOfDate: null,
        activeRowsAsOfDateKey: null,
        activeRowsForCurrentSelection: null,
        activeRowsForCurrentSelectionKey: null,
        remediationReportRows: null,
        remediationReportRowsKey: null,
        selectionSeverityCounts: null,
        selectionSeverityCountsKey: null,
        provenRemediationRows: null,
        provenRemediationRowsKey: null,
        remediationChartData: null,
        remediationChartDataKey: null,
        remediationTableData: null,
        remediationDetailsData: null,
        impactData: null,
        impactChartData: null,
        impactChartDataKey: null,
        impactAnalysisTableData: null,
        devicesByRemediationData: null,
        remediationsByDeviceData: null
    };
}

function createDefaultCascadingFilterState() {
    return Object.fromEntries(CASCADING_FILTER_IDS.map(filterId => [filterId, {
        mode: 'all',
        selectedValues: new Set(),
        searchTerm: ''
    }]));
}

function getOrderedCascadingFilterValues(filterId, selectedValues) {
    const options = cascadingFilterOptions[filterId] || [];
    return options.filter(option => selectedValues.has(option.value)).map(option => option.value);
}

function getOrderedCascadingFilterLabels(filterId, selectedValues) {
    const options = cascadingFilterOptions[filterId] || [];
    return options.filter(option => selectedValues.has(option.value)).map(option => option.label);
}

function normalizeCascadingFilterSelection(filterId) {
    const filterEntry = cascadingFilterState[filterId];
    const options = cascadingFilterOptions[filterId] || [];
    const optionSet = new Set(options.map(option => option.value));

    filterEntry.selectedValues.forEach(value => {
        if (!optionSet.has(value)) {
            filterEntry.selectedValues.delete(value);
        }
    });

    if (filterEntry.mode === 'subset' && filterEntry.selectedValues.size === options.length) {
        filterEntry.mode = 'all';
        filterEntry.selectedValues.clear();
    }
}

function setCascadingFilterAllMode(filterId, isAllMode) {
    const filterEntry = cascadingFilterState[filterId];
    if (isAllMode) {
        filterEntry.mode = 'all';
        filterEntry.selectedValues.clear();
        return;
    }

    filterEntry.mode = 'subset';
    filterEntry.selectedValues.clear();
}

function toggleCascadingFilterValue(filterId, value, isChecked) {
    const filterEntry = cascadingFilterState[filterId];
    if (filterEntry.mode === 'all') {
        filterEntry.mode = 'subset';
        filterEntry.selectedValues = new Set((cascadingFilterOptions[filterId] || []).map(option => option.value));
    }

    if (isChecked) filterEntry.selectedValues.add(value);
    else filterEntry.selectedValues.delete(value);

    normalizeCascadingFilterSelection(filterId);
}

function getCascadingFilterSelectionValues(filterId) {
    const filterEntry = cascadingFilterState[filterId];
    if (!filterEntry || filterEntry.mode === 'all') return [];
    return getOrderedCascadingFilterValues(filterId, filterEntry.selectedValues);
}

function getCascadingFilterSelectionLabels(filterId) {
    const filterEntry = cascadingFilterState[filterId];
    if (!filterEntry || filterEntry.mode === 'all') return [];
    return getOrderedCascadingFilterLabels(filterId, filterEntry.selectedValues);
}

function hasAnyCascadingFilterSelection(filterId) {
    const filterEntry = cascadingFilterState[filterId];
    return !filterEntry || filterEntry.mode === 'all' || filterEntry.selectedValues.size > 0;
}

function invalidateAggregateCache() {
    cancelReportDataWarmup();
    aggregateCacheKey = null;
    aggregateCache = createEmptyAggregateCache();
    cascadingFilterCountCacheKey = null;
    cascadingFilterCountCache = null;
    chartDataCacheKey = null;
    chartDataCache = null;
}

function markAllReportsDirty() {
    REPORT_IDS.forEach(reportId => dirtyReports.add(reportId));
}

function getCurrentReportId() {
    const selector = document.getElementById('reportSelector');
    return selector ? selector.value : activeReportId;
}

function measureTextWidth(text, styles) {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    if (!context) {
        return 0;
    }

    context.font = `${styles.fontWeight} ${styles.fontSize} ${styles.fontFamily}`;
    return context.measureText(text).width;
}

function updateReportSelectorWidth() {
    const selector = document.getElementById('reportSelector');
    const button = document.getElementById('reportSelectorButton');
    const shell = document.getElementById('reportSelectorShell');
    if (!selector || !button || !shell) {
        return;
    }

    const computedStyles = window.getComputedStyle(button);
    const labelText = String(button.querySelector('.filter-pill-label')?.textContent || '').trim() + ':';
    const longestOptionLabel = Array.from(selector.options).reduce((longest, option) => {
        const label = String(option.textContent || option.label || '').trim();
        return label.length > longest.length ? label : longest;
    }, '');
    const chromeWidth = 64;
    const measuredWidth = Math.ceil(
        measureTextWidth(labelText, computedStyles)
        + measureTextWidth(longestOptionLabel, computedStyles)
        + chromeWidth
    );

    shell.style.setProperty('--report-selector-width', `${Math.max(measuredWidth, 240)}px`);
}

function syncReportNavigationUi() {
    if (document.body) {
        document.body.dataset.reportNavigationMode = reportNavigationMode;
    }

    const selector = document.getElementById('reportSelector');
    const reportSelectorButton = document.getElementById('reportSelectorButton');
    const reportSelectorValue = document.getElementById('reportSelectorValue');
    const reportSelectorPopover = document.getElementById('reportSelectorPopover');
    const reportSelectorOptions = document.querySelectorAll('#reportSelectorOptions .report-selector-option');

    if (selector && reportSelectorValue) {
        const selectedOption = selector.selectedOptions && selector.selectedOptions.length > 0
            ? selector.selectedOptions[0]
            : selector.options[selector.selectedIndex];
        reportSelectorValue.textContent = String(
            selectedOption?.textContent || selectedOption?.label || REPORT_LABELS[activeReportId] || activeReportId
        ).trim();
    }

    if (reportSelectorButton) {
        reportSelectorButton.setAttribute('aria-expanded', reportSelectorPopoverOpen ? 'true' : 'false');
    }

    if (reportSelectorPopover) {
        reportSelectorPopover.hidden = !reportSelectorPopoverOpen;
        reportSelectorPopover.setAttribute('aria-hidden', reportSelectorPopoverOpen ? 'false' : 'true');
    }

    reportSelectorOptions.forEach(button => {
        const isActive = button.dataset.reportId === activeReportId;
        button.classList.toggle('is-active', isActive);
        button.classList.toggle('selected', isActive);
        button.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });
}

function reportRequiresChartRuntime(reportId) {
    return CHART_REPORT_IDS.has(reportId);
}

function buildReportSelectorOptions() {
    const selector = document.getElementById('reportSelector');
    const reportSelectorOptions = document.getElementById('reportSelectorOptions');
    if (!selector || !reportSelectorOptions) {
        return;
    }

    reportSelectorOptions.innerHTML = '';
    const fragment = document.createDocumentFragment();
    Array.from(selector.options).forEach(option => {
        const optionButton = document.createElement('button');
        optionButton.type = 'button';
        optionButton.className = 'date-range-option report-selector-option';
        optionButton.dataset.reportId = option.value;
        optionButton.textContent = String(option.textContent || option.label || '').trim();
        optionButton.setAttribute('role', 'option');
        fragment.appendChild(optionButton);
    });

    reportSelectorOptions.appendChild(fragment);
    updateReportSelectorWidth();
    syncReportNavigationUi();
}

function initializeReportNavigationControls() {
    buildReportSelectorOptions();
    syncReportNavigationUi();
}

function selectReportById(reportId) {
    if (!REPORT_IDS.includes(reportId)) {
        return;
    }

    const selector = document.getElementById('reportSelector');
    if (!selector) {
        return;
    }

    if (selector.value !== reportId) {
        selector.value = reportId;
    }

    handleReportChange();
}

function closeReportSelectorPopover(options = {}) {
    reportSelectorPopoverOpen = false;
    syncReportNavigationUi();

    if (options.restoreFocus) {
        document.getElementById('reportSelectorButton')?.focus();
    }
}

function openReportSelectorPopover() {
    closeActiveFilterPopover();
    reportSelectorPopoverOpen = true;
    syncReportNavigationUi();

    const activeButton = document.querySelector('#reportSelectorOptions .report-selector-option.is-active')
        || document.querySelector('#reportSelectorOptions .report-selector-option');
    activeButton?.focus();
}

function toggleReportSelectorPopover() {
    if (reportSelectorPopoverOpen) {
        closeReportSelectorPopover({ restoreFocus: true });
        return;
    }

    openReportSelectorPopover();
}

function isRemediationScopeReport(reportId = activeReportId) {
    return REMEDIATION_SCOPE_REPORT_IDS.includes(reportId);
}

function getRemediationReportModeSummaryText(state = filterState) {
    const snapshotDate = formatDateYMD(getPointInTimeReferenceDate(state)) || 'the latest open snapshot';

    if (!hasSelectedDateWindow(state)) {
        return `No date range is selected, so this setting has no effect and the reports show the latest open snapshot on ${snapshotDate}.`;
    }

    if (remediationReportMode === REMEDIATION_REPORT_MODE_SNAPSHOT) {
        return `Showing only vulnerabilities still open on ${snapshotDate}. Resolved items from earlier in the range are excluded.`;
    }

    const rangeStart = formatDateYMD(state.startDate) || snapshotDate;
    const rangeEnd = formatDateYMD(state.endDate) || snapshotDate;
    return `Including vulnerabilities observed from ${rangeStart} through ${rangeEnd}, even if they were resolved before ${snapshotDate}.`;
}

function updateRemediationReportModeUi(reportId = activeReportId) {
    const toolbar = document.getElementById('remediationReportToolbar');
    if (!toolbar) {
        return;
    }

    const shouldShow = isRemediationScopeReport(reportId);
    toolbar.hidden = !shouldShow;

    const rangeButton = document.getElementById('remediationModeRangeButton');
    const snapshotButton = document.getElementById('remediationModeSnapshotButton');
    const summary = document.getElementById('remediationModeSummary');
    const isRange = remediationReportMode === REMEDIATION_REPORT_MODE_RANGE;

    if (rangeButton) {
        rangeButton.classList.toggle('is-active', isRange);
        rangeButton.setAttribute('aria-pressed', isRange ? 'true' : 'false');
    }

    if (snapshotButton) {
        snapshotButton.classList.toggle('is-active', !isRange);
        snapshotButton.setAttribute('aria-pressed', isRange ? 'false' : 'true');
    }

    if (summary) {
        summary.textContent = shouldShow ? getRemediationReportModeSummaryText() : '';
    }
}

function setRemediationReportMode(mode) {
    const nextMode = mode === REMEDIATION_REPORT_MODE_SNAPSHOT
        ? REMEDIATION_REPORT_MODE_SNAPSHOT
        : REMEDIATION_REPORT_MODE_RANGE;

    if (remediationReportMode === nextMode) {
        updateRemediationReportModeUi();
        return;
    }

    remediationReportMode = nextMode;
    invalidateAggregateCache();
    dirtyReports.add('devices-by-remediation');
    dirtyReports.add('remediations-by-device');
    updateRemediationReportModeUi();
    syncUrlViewState();

    if (isRemediationScopeReport(activeReportId)) {
        renderActiveReport(true);
    }
}

function handleRemediationReportModeChange(event) {
    const button = event.currentTarget;
    if (!button) {
        return;
    }

    setRemediationReportMode(button.dataset.remediationReportMode);
}

function buildFilterStateKey(state) {
    return [
        state.datePreset,
        state.startDate,
        state.endDate,
        state.deviceSearchNormalized,
        state.hasDeviceNames ? '1' : '0',
        state.deviceNames.join('\u001f'),
        state.hasRbacGroups ? '1' : '0',
        state.rbacGroups.join('\u001f'),
        state.hasDeviceTags ? '1' : '0',
        state.deviceTags.join('\u001f'),
        state.hasSeverities ? '1' : '0',
        state.severities.join('\u001f'),
        state.hasOsPlatforms ? '1' : '0',
        state.osPlatforms.join('\u001f')
    ].join('\u001e');
}

function syncFilterStateFromDom() {
    return filterState;
}

function scheduleApplyFilters(immediate = false) {
    if (applyFiltersTimer) {
        clearTimeout(applyFiltersTimer);
        applyFiltersTimer = null;
    }

    if (immediate) {
        applyFilters();
        return;
    }

    applyFiltersTimer = window.setTimeout(() => {
        applyFiltersTimer = null;
        applyFilters();
    }, APPLY_FILTER_DEBOUNCE_MS);
}

function cancelReportDataWarmup() {
    if (reportDataWarmupHandle == null) {
        return;
    }

    if (reportDataWarmupUsesIdleCallback && typeof window.cancelIdleCallback === 'function') {
        window.cancelIdleCallback(reportDataWarmupHandle);
    } else {
        clearTimeout(reportDataWarmupHandle);
    }

    reportDataWarmupHandle = null;
    reportDataWarmupUsesIdleCallback = false;
}

function getReportDataWarmupCandidateRowCount() {
    const cache = getAggregateCache();
    if (Array.isArray(cache.activeRowsForCurrentSelection)) {
        return cache.activeRowsForCurrentSelection.length;
    }
    return filteredData.length;
}

function shouldWarmReportData() {
    if (REPORT_DATA_WARMUP_MODE === 'never') {
        return false;
    }

    if (REPORT_DATA_WARMUP_MODE === 'always') {
        return true;
    }

    return getReportDataWarmupCandidateRowCount() <= REPORT_DATA_WARMUP_ROW_LIMIT;
}

function scheduleReportDataWarmup() {
    cancelReportDataWarmup();

    if (!shouldWarmReportData()) {
        logDebug('Skipping report data warmup for', getReportDataWarmupCandidateRowCount(), 'rows');
        return;
    }

    const scheduledFilterKey = filterState.key;
    const scheduledMostRecentLastSeenDate = mostRecentLastSeenDate;
    const warmupToken = ++reportDataWarmupToken;
    const runWarmup = () => {
        reportDataWarmupHandle = null;
        reportDataWarmupUsesIdleCallback = false;

        if (warmupToken !== reportDataWarmupToken) return;
        if (filterState.key !== scheduledFilterKey) return;
        if (mostRecentLastSeenDate !== scheduledMostRecentLastSeenDate) return;

        getRemediationDetailsData();
        getImpactAnalysisData();
        getImpactAnalysisTableData();
        getRemediationChartData();
        getImpactChartData();
    };

    if (typeof window.requestIdleCallback === 'function') {
        reportDataWarmupUsesIdleCallback = true;
        reportDataWarmupHandle = window.requestIdleCallback(runWarmup, { timeout: 200 });
        return;
    }

    reportDataWarmupHandle = window.setTimeout(runWarmup, 0);
}

function getAggregateCache() {
    if (aggregateCacheKey !== filterState.key) {
        aggregateCacheKey = filterState.key;
        aggregateCache = createEmptyAggregateCache();
    }
    return aggregateCache;
}

function clearTooltipCaches() {
    for (const key of Object.keys(cveTooltipData)) {
        delete cveTooltipData[key];
    }
    for (const key of Object.keys(severityTooltipData)) {
        delete severityTooltipData[key];
    }
    cveTooltipIdCounter = 0;
    severityBadgeIdCounter = 0;

    hideGlobalTooltip();
}

function hideGlobalTooltip() {
    const tooltip = document.getElementById('cve-global-tooltip');
    if (tooltip) {
        tooltip.style.display = 'none';
        tooltip.innerHTML = '';
    }
}

function setDashboardStatus(message, kind = 'info') {
    const status = document.getElementById('dashboardStatus');
    if (!status) {
        return;
    }

    if (!message) {
        status.hidden = true;
        status.removeAttribute('data-status-kind');
        status.textContent = '';
        publishDashboardDiagnostics();
        return;
    }

    status.hidden = false;
    status.dataset.statusKind = kind;
    status.textContent = message;
    publishDashboardDiagnostics();
}

function clearDashboardStatus() {
    setDashboardStatus('');
}

function unloadExternalScript(url) {
    if (!url) {
        return;
    }

    loadedScriptPromises.delete(url);
    Array.from(document.querySelectorAll('script[data-runtime-src]')).forEach(script => {
        if (script.dataset.runtimeSrc === url) {
            script.remove();
        }
    });
}

function loadExternalScript(url) {
    if (!url) {
        return Promise.reject(new Error('A script URL is required.'));
    }

    if (loadedScriptPromises.has(url)) {
        return loadedScriptPromises.get(url);
    }

    const promise = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = url;
        script.async = false;
        script.dataset.runtimeSrc = url;
        script.onload = () => resolve();
        script.onerror = () => {
            loadedScriptPromises.delete(url);
            script.remove();
            reject(new Error(`Failed to load script: ${url}`));
        };
        document.head.appendChild(script);
    });

    loadedScriptPromises.set(url, promise);
    return promise;
}

function ensureChartJsLoaded() {
    if (typeof Chart !== 'undefined') {
        return Promise.resolve();
    }

    if (chartJsLoadPromise) {
        return chartJsLoadPromise;
    }

    const chartJsMode = dashboardConfig.chartJsMode || 'embedded';
    chartJsLoadPromise = (chartJsMode === 'external'
        ? loadExternalScript(dashboardConfig.chartJsUrl)
        : Promise.resolve().then(() => {
            if (typeof window.__inflateEmbeddedScript !== 'function') {
                throw new Error('Embedded script inflater is unavailable');
            }

            window.__inflateEmbeddedScript('chartJsLib');
        }))
        .then(() => {
            if (typeof Chart === 'undefined') {
                throw new Error('Chart.js did not initialize correctly.');
            }
            Chart.defaults.animation = false;
        })
        .catch(error => {
            if (chartJsMode === 'external') {
                unloadExternalScript(dashboardConfig.chartJsUrl);
            }
            chartJsLoadPromise = null;
            throw error;
        });

    return chartJsLoadPromise;
}

function ensurePdfExportRuntimeLoaded() {
    if (typeof exportToPDF === 'function') {
        return Promise.resolve();
    }

    if (pdfExportRuntimeLoadPromise) {
        return pdfExportRuntimeLoadPromise;
    }

    const pdfExportRuntimeMode = dashboardConfig.pdfExportRuntimeMode || 'embedded';
    if (pdfExportRuntimeMode !== 'external') {
        return Promise.reject(new Error('PDF export runtime is unavailable.'));
    }

    pdfExportRuntimeLoadPromise = loadExternalScript(dashboardConfig.pdfExportRuntimeUrl)
        .then(() => {
            if (typeof exportToPDF !== 'function') {
                throw new Error('PDF export runtime did not initialize correctly.');
            }
        })
        .catch(error => {
            unloadExternalScript(dashboardConfig.pdfExportRuntimeUrl);
            pdfExportRuntimeLoadPromise = null;
            throw error;
        });

    return pdfExportRuntimeLoadPromise;
}
