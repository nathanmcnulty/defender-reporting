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
const configuredPdfPageWarningThreshold = Number(dashboardConfig.pdfExportPageWarningThreshold);
const PDF_EXPORT_PAGE_WARNING_THRESHOLD = Number.isFinite(configuredPdfPageWarningThreshold) && configuredPdfPageWarningThreshold > 0
    ? Math.floor(configuredPdfPageWarningThreshold)
    : 100;
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
        label: 'Device Groups',
        stateKey: 'rbacGroups',
        hasAnyKey: 'hasRbacGroups',
        allText: 'All',
        summaryNoun: 'groups'
    },
    filterDeviceTags: {
        buttonId: 'filterPillDeviceTags',
        label: 'Device Tags',
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
const REMEDIATION_SCOPE_REPORT_IDS = ['devices-by-remediation', 'remediations-by-device'];
const REMEDIATION_REPORT_MODE_RANGE = 'range';
const REMEDIATION_REPORT_MODE_SNAPSHOT = 'snapshot';
const MAX_VISIBLE_DEVICE_REMEDIATIONS = 10;

let applyFiltersTimer = null;
let activeReportId = 'active-vulnerabilities';
let remediationReportMode = REMEDIATION_REPORT_MODE_SNAPSHOT;
const initializedReports = new Set();
const dirtyReports = new Set(REPORT_IDS);

let filterState = createEmptyFilterState();
let filterPopoverDraftState = null;
let activeFilterPopoverKey = null;
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

function scheduleReportDataWarmup() {
    cancelReportDataWarmup();

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
        return;
    }

    status.hidden = false;
    status.dataset.statusKind = kind;
    status.textContent = message;
}

function clearDashboardStatus() {
    setDashboardStatus('');
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
            chartJsLoadPromise = null;
            throw error;
        });

    return chartJsLoadPromise;
}

// =============================================================================
// INDEXEDDB CACHE
// =============================================================================

const VULNDB_NAME = 'VulnDashboardCache';
const VULNDB_VERSION = 1;
const VULNDB_STORE = 'denormalized';

function bytesToHex(bytes) {
    let output = '';
    for (let index = 0; index < bytes.length; index++) {
        output += bytes[index].toString(16).padStart(2, '0');
    }
    return output;
}

function computeFallbackDigestHex(bytes) {
    let hash = 0xcbf29ce484222325n;
    const prime = 0x100000001b3n;
    for (let index = 0; index < bytes.length; index++) {
        hash ^= BigInt(bytes[index]);
        hash = BigInt.asUintN(64, hash * prime);
    }
    return hash.toString(16).padStart(16, '0');
}

async function computeDigestHex(bytes) {
    const subtle = globalThis.crypto && globalThis.crypto.subtle ? globalThis.crypto.subtle : null;
    if (subtle) {
        const digest = await subtle.digest('SHA-256', bytes);
        return bytesToHex(new Uint8Array(digest));
    }

    if (typeof require === 'function') {
        try {
            const nodeCrypto = require('crypto');
            return nodeCrypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');
        } catch (error) {
            console.warn('Node SHA-256 fallback unavailable, using deterministic fallback digest.', error);
        }
    }

    return computeFallbackDigestHex(bytes);
}

function getEmbeddedPayloadFingerprintInput() {
    const lookupsText = getScriptElementText('lookupsData');
    const vulnsText = getScriptElementText('vulnsData');

    if (lookupsText || vulnsText) {
        return `${lookupsText.length}:${lookupsText}\n${vulnsText.length}:${vulnsText}`;
    }

    const fallbackLookups = lookups ? JSON.stringify(lookups) : '';
    const fallbackVulns = rawVulns ? JSON.stringify(rawVulns) : '';
    return `${fallbackLookups.length}:${fallbackLookups}\n${fallbackVulns.length}:${fallbackVulns}`;
}

/**
 * Compute a fingerprint for the embedded dataset using the full payload.
 * @returns {Promise<string>}
 */
async function computeDataFingerprint() {
    const len = getRawVulnCount();
    if (len === 0) return 'empty';

    const input = getEmbeddedPayloadFingerprintInput();
    const bytes = new TextEncoder().encode(input);
    const hash = await computeDigestHex(bytes);
    return `fp_${len}_${hash}`;
}

/**
 * Compute a fingerprint from raw compressed bytes so we can check the
 * IndexedDB cache *before* decompressing / denormalizing.
 * @param {Uint8Array} bytes
 * @returns {Promise<string>}
 */
async function computeCompressedFingerprint(bytes) {
    const len = bytes.length;
    const hash = await computeDigestHex(bytes);
    return `cfp_${len}_${hash}`;
}

/**
 * Open (or create) the IndexedDB cache database.
 * @returns {Promise<IDBDatabase>}
 */
function openVulnDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(VULNDB_NAME, VULNDB_VERSION);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(VULNDB_STORE)) {
                db.createObjectStore(VULNDB_STORE, { keyPath: 'fingerprint' });
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

/**
 * Retrieve cached denormalized data from IndexedDB.
 * @param {string} fingerprint
 * @returns {Promise<Array|null>}
 */
async function getCachedData(fingerprint) {
    try {
        const db = await openVulnDB();
        return new Promise((resolve) => {
            const tx = db.transaction(VULNDB_STORE, 'readonly');
            const store = tx.objectStore(VULNDB_STORE);
            const req = store.get(fingerprint);
            req.onsuccess = () => {
                if (!req.result) return resolve(null);
                // Return both data and cached lookups (if available)
                return resolve({ data: req.result.data, lookups: req.result.lookups || null });
            };
            req.onerror = () => resolve(null);
        });
    } catch {
        return null;
    }
}

/**
 * Store denormalized data in IndexedDB cache.
 * Clears old entries first to avoid unbounded growth.
 * @param {string} fingerprint
 * @param {Array} data
 */
async function setCachedData(fingerprint, data) {
    try {
        const db = await openVulnDB();
        const tx = db.transaction(VULNDB_STORE, 'readwrite');
        const store = tx.objectStore(VULNDB_STORE);
        store.clear(); // Keep only the latest dataset
        store.put({ fingerprint, data, lookups: lookups || null, ts: Date.now() });
    } catch {
        // Cache failure is non-fatal
    }
}

// =============================================================================
// WEB WORKER (Blob-based, self-contained)
// =============================================================================

/**
 * Build a Worker source that decompresses (if given compressed bytes) and denormalizes.
 * When compressed bytes are provided via Transferable, pako.inflate runs off-main-thread.
 */
function buildWorkerSource() {
    return `
'use strict';
self.onmessage = async function(e) {
    var lookups = e.data.lookups;
    var rawVulns = e.data.rawVulns;
    var decompressOnly = !!e.data.decompressOnly;

    // If compressed data was transferred, decompress it first
    if (e.data.compressedBytes) {
        var data;
        if (typeof DecompressionStream !== 'undefined') {
            // Native gzip decompression — significantly faster than pako
            var ds = new DecompressionStream('gzip');
            var blob = new Blob([e.data.compressedBytes]);
            var decompressedStream = blob.stream().pipeThrough(ds);
            var text = await new Response(decompressedStream).text();
            data = JSON.parse(text);
        } else {
            var decompressed = pako.inflate(e.data.compressedBytes, { to: 'string' });
            data = JSON.parse(decompressed);
        }
        lookups = data.lookups;
        rawVulns = data.vulns;
    }

    // For large compressed datasets, return raw data without denormalizing
    // to avoid structured-clone memory limits on postMessage
    if (decompressOnly) {
        self.postMessage({ rows: null, lookups: lookups, rawVulns: rawVulns });
        return;
    }

    function isColumnarRawVulnData(value) {
        return !!(value && !Array.isArray(value) && Array.isArray(value.d));
    }
    function getRawVulnCount() {
        if (!rawVulns) return 0;
        if (Array.isArray(rawVulns)) return rawVulns.length;
        if (isColumnarRawVulnData(rawVulns)) return rawVulns.d.length;
        return 0;
    }
    function getRawVulnRecord(index) {
        if (Array.isArray(rawVulns)) return rawVulns[index];
        return [
            rawVulns.d[index],
            rawVulns.c[index],
            rawVulns.s[index],
            rawVulns.v[index],
            rawVulns.f[index],
            rawVulns.l[index],
            rawVulns.ua[index],
            rawVulns.u[index],
            rawVulns.dp[index],
            rawVulns.rp[index],
            rawVulns.iv ? rawVulns.iv[index] : -1
        ];
    }
    function normalizeDateYMD(value) {
        if (!value) return null;
        var datePart = String(value).split(/[T ]/)[0];
        if (/^\d{4}-\d{2}-\d{2}$/.test(datePart)) return datePart;
        var slash = datePart.split('/');
        if (slash.length === 3) {
            var m = slash[0].padStart(2, '0');
            var d = slash[1].padStart(2, '0');
            var y = slash[2].slice(0, 4);
            if (/^\d{4}$/.test(y)) return y + '-' + m + '-' + d;
        }
        return datePart;
    }
    function getLookupValue(lookup, index) {
        if (!lookup || index == null || index < 0 || index >= lookup.length) {
            return null;
        }
        return lookup[index];
    }
    function getLookupRecord(lookup, index) {
        var value = getLookupValue(lookup, index);
        return value == null ? null : value;
    }
    var rawCount = getRawVulnCount();
    var result = new Array(rawCount);
    var resultCount = 0;
    var skippedInvalidRows = 0;
    for (var i = 0; i < rawCount; i++) {
        var v = getRawVulnRecord(i);
        var device = getLookupRecord(lookups.devices, v[0]);
        var cve = getLookupRecord(lookups.cves, v[1]);
        var software = getLookupRecord(lookups.software, v[2]);
        if (!device || !cve || !software) {
            skippedInvalidRows++;
            continue;
        }

        var tagNames;
        if (device.t && device.t.length > 0) {
            tagNames = [];
            for (var ti = 0; ti < device.t.length; ti++) {
                var tagName = getLookupValue(lookups.tags, device.t[ti]);
                if (tagName != null) {
                    tagNames.push(tagName);
                }
            }
        } else {
            tagNames = [];
        }

        var vendorName = getLookupValue(lookups.vendors, software.v);
        var softwareName = software.n;
        var updateObj = v[7] >= 0 ? lookups.updates[v[7]] : null;
        var inventory = (v.length > 10 && v[10] >= 0 && lookups.inventory) ? getLookupValue(lookups.inventory, v[10]) : null;
        var updateName = updateObj ? (updateObj.n || updateObj) : null;
        var updateId = updateObj ? updateObj.id : null;
        var updateUrl = updateObj ? updateObj.url : null;

        // Resolve version from lookup
        var version = v[3] >= 0 ? getLookupValue(lookups.versions, v[3]) : null;
        // Resolve dates from lookup
        var firstSeenValue = v[4] >= 0 ? getLookupValue(lookups.dates, v[4]) : null;
        var lastSeenValue = v[5] >= 0 ? getLookupValue(lookups.dates, v[5]) : null;
        var firstSeen = firstSeenValue ? normalizeDateYMD(firstSeenValue) : '';
        var lastSeen = lastSeenValue ? normalizeDateYMD(lastSeenValue) : '';
        // Resolve evidence paths from lookup indices
        var diskPaths = [];
        if (v[8] && v[8].length > 0) {
            for (var di = 0; di < v[8].length; di++) {
                var diskPath = getLookupValue(lookups.diskPaths, v[8][di]);
                if (diskPath != null) {
                    diskPaths.push(diskPath);
                }
            }
        }
        var regPathsArr = [];
        if (v[9] && v[9].length > 0) {
            for (var ri = 0; ri < v[9].length; ri++) {
                var regPath = getLookupValue(lookups.regPaths, v[9][ri]);
                if (regPath != null) {
                    regPathsArr.push(regPath);
                }
            }
        }
        // Resolve batch title from lookup
        var batchTitle = cve.bt >= 0 ? getLookupValue(lookups.batchTitles, cve.bt) : null;
        // Resolve affected software from lookup indices
        var affSoftware = null;
        if (cve.as && cve.as.length > 0) {
            affSoftware = [];
            for (var ai = 0; ai < cve.as.length; ai++) {
                var affectedSoftwareValue = getLookupValue(lookups.affSoftware, cve.as[ai]);
                if (affectedSoftwareValue != null) {
                    affSoftware.push(affectedSoftwareValue);
                }
            }
            if (affSoftware.length === 0) affSoftware = null;
        }

        var groupName = getLookupValue(lookups.groups, device.g);
        result[resultCount++] = {
            DeviceId: device.id,
            DeviceName: device.n,
            RbacGroupName: (groupName && String(groupName).trim() !== '') ? groupName : '(none)',
            OSPlatform: getLookupValue(lookups.platforms, device.o),
            OSVersion: device.ov,
            MachineTags: tagNames,
            MachineInfo: device.m || null,
            CveId: cve.id,
            CvssScore: cve.sc,
            VulnerabilitySeverityLevel: getLookupValue(lookups.severities, cve.sv),
            ExploitabilityLevel: cve.ex >= 0 ? getLookupValue(lookups.exploitLevels, cve.ex) : null,
            CveBatchUrl: cve.u,
            CveBatchTitle: batchTitle,
            PublishedDate: normalizeDateYMD(cve.pd) || null,
            VulnerabilityDescription: cve.desc || null,
            EpssScore: cve.ep != null ? cve.ep : null,
            AffectedSoftware: affSoftware,
            IsExploitAvailable: cve.ea == null ? null : cve.ea === true,
            NvdLastModifiedDate: normalizeDateYMD(cve.nlm) || null,
            NvdBaseScore: cve.nbs != null ? cve.nbs : null,
            NvdBaseSeverity: cve.nsv || null,
            NvdVector: cve.nvec || null,
            NvdKevDate: normalizeDateYMD(cve.nkev) || null,
            NvdActionDue: normalizeDateYMD(cve.ndu) || null,
            NvdRequiredAction: cve.nact || null,
            NvdWeaknesses: cve.nw && cve.nw.length > 0 ? cve.nw.slice() : null,
            SoftwareVendor: vendorName,
            SoftwareName: softwareName,
            SoftwareVersion: version,
            RecommendationReference: software.r,
            ProductCodeCpe: inventory ? (inventory.cpe || null) : null,
            EndOfSupportStatus: inventory ? (inventory.eos || null) : null,
            EndOfSupportDate: inventory ? (normalizeDateYMD(inventory.eod) || null) : null,
            _firstSeenDate: firstSeen,
            _lastSeenDate: lastSeen,
            FirstSeenTimestamp: firstSeen,
            LastSeenTimestamp: lastSeen,
            SecurityUpdateAvailable: v[6] === 1,
            RecommendedSecurityUpdate: updateName,
            RecommendedSecurityUpdateId: updateId || null,
            RecommendedSecurityUpdateUrl: updateUrl || null,
            DiskPaths: diskPaths,
            RegistryPaths: regPathsArr,
            _remediationKey: updateName
                ? vendorName + ' ' + softwareName + ' - ' + updateName
                : vendorName + ' ' + softwareName,
            _index: i
        };
    }
    result.length = resultCount;
    self.postMessage({ rows: result, lookups: lookups, rawVulns: rawVulns, skippedInvalidRows: skippedInvalidRows });
};
`;
}

/**
 * Run denormalization in a Web Worker.
 * When compressedBytes is provided, decompression also runs in the Worker (off main thread).
 * Falls back to main-thread if Worker is unavailable.
 * @param {Uint8Array} [compressedBytes] - Optional compressed payload bytes
 * @returns {Promise<{rows: Array, lookups?: Object, rawVulns?: Object}>}
 */
async function denormalizeInWorker(compressedBytes) {
    // When decompressing in Worker, include pako source in the blob
    let workerParts = [];
    if (compressedBytes) {
        const pakoSource = await getPakoSource();
        if (pakoSource) {
            workerParts.push(pakoSource + '\n');
        } else {
            // pako source unavailable for Worker — fall back to main-thread decompression
            const decompressed = pako.inflate(compressedBytes, { to: 'string' });
            const data = JSON.parse(decompressed);
            lookups = data.lookups;
            rawVulns = data.vulns;
            compressedBytes = null;
        }
    }
    workerParts.push(buildWorkerSource());

    return new Promise((resolve, reject) => {
        try {
            const blob = new Blob(workerParts, { type: 'application/javascript' });
            const url = URL.createObjectURL(blob);
            const worker = new Worker(url);

            worker.onmessage = function(e) {
                worker.terminate();
                URL.revokeObjectURL(url);
                resolve(e.data);
            };
            worker.onerror = function(err) {
                worker.terminate();
                URL.revokeObjectURL(url);
                reject(err);
            };

            if (compressedBytes) {
                // For compressed data, use decompress-only mode to avoid
                // structured-clone memory limits on postMessage with 1M+ records.
                // Main thread will denormalize after receiving lookups + rawVulns.
                worker.postMessage({ compressedBytes, decompressOnly: true });
            } else {
                worker.postMessage({ lookups, rawVulns });
            }
        } catch (err) {
            reject(err);
        }
    });
}

/**
 * Get pako library source code for injection into a Worker.
 * Checks external scripts first (split-assets mode), then inline (embedded mode).
 * Inline match requires 10KB+ to avoid false positives from small helper scripts.
 * @returns {Promise<string|null>}
 */
async function getPakoSource() {
    const scripts = document.querySelectorAll('script');
    // Try fetching external pako script (split-assets / hosted mode)
    for (const script of scripts) {
        if (script.src && script.src.indexOf('pako') !== -1) {
            try {
                const response = await fetch(script.src);
                if (response.ok) return await response.text();
            } catch (e) { /* ignore — will try inline or fall back */ }
        }
    }
    // Try inline script (embedded mode) — require 10KB+ to skip small helper scripts
    for (const script of scripts) {
        if (script.textContent && script.textContent.length > 10000 && script.textContent.indexOf('pako') !== -1 && script.textContent.indexOf('inflate') !== -1 && !script.id) {
            return script.textContent;
        }
    }
    return null;
}

// =============================================================================
// VIRTUAL SCROLL FOR MODALS
// =============================================================================

/**
 * Lightweight virtual scroll for modal table bodies.
 * Only renders visible rows + a buffer, swapping rows on scroll.
 */
class VirtualModalTable {
    /**
     * @param {HTMLElement} scrollContainer - The scrollable parent (.modal-content)
     * @param {HTMLElement} tbody - The <tbody> element to virtualize
     * @param {Array} items - Source items for the virtualized table
     * @param {Function} rowBuilder - Builds a <tr> HTML string for an item
     * @param {number} rowHeight - Estimated row height in px
     */
    constructor(scrollContainer, tbody, items, rowBuilder, rowHeight = 36) {
        this.container = scrollContainer;
        this.tbody = tbody;
        this.items = items;
        this.rowBuilder = rowBuilder;
        this.rowHeight = rowHeight;
        this.bufferRows = 20;
        this.renderedStart = -1;
        this.renderedEnd = -1;

        // Spacer rows for maintaining scroll height
        this.topSpacer = document.createElement('tr');
        this.bottomSpacer = document.createElement('tr');
        this.topSpacer.className = 'virtual-spacer';
        this.bottomSpacer.className = 'virtual-spacer';

        this._onScroll = this._onScroll.bind(this);
        this.container.addEventListener('scroll', this._onScroll, { passive: true });

        this.render();
    }

    _onScroll() {
        requestAnimationFrame(() => this.render());
    }

    render() {
        const totalRows = this.items.length;
        if (totalRows === 0) return;

        const totalHeight = totalRows * this.rowHeight;
        const scrollTop = this.container.scrollTop;
        const viewHeight = this.container.clientHeight;

        // Find the table's offset relative to scroll container
        const tableRect = this.tbody.parentElement.getBoundingClientRect();
        const containerRect = this.container.getBoundingClientRect();
        const tableOffset = tableRect.top - containerRect.top + this.container.scrollTop;

        // Visible range within this table
        const relativeTop = Math.max(0, scrollTop - tableOffset);
        const relativeBottom = relativeTop + viewHeight;

        let startIdx = Math.floor(relativeTop / this.rowHeight) - this.bufferRows;
        let endIdx = Math.ceil(relativeBottom / this.rowHeight) + this.bufferRows;
        startIdx = Math.max(0, startIdx);
        endIdx = Math.min(totalRows, endIdx);

        // Skip re-render if range hasn't changed
        if (startIdx === this.renderedStart && endIdx === this.renderedEnd) return;
        this.renderedStart = startIdx;
        this.renderedEnd = endIdx;

        // Build visible rows
        const fragment = document.createDocumentFragment();

        // Top spacer
        const topH = startIdx * this.rowHeight;
        this.topSpacer.innerHTML = `<td colspan="99" class="virtual-spacer-cell" style="height:${topH}px;"></td>`;
        fragment.appendChild(this.topSpacer);

        // Visible rows
        const template = document.createElement('template');
        template.innerHTML = this.items.slice(startIdx, endIdx).map(this.rowBuilder).join('');
        fragment.appendChild(template.content);

        // Bottom spacer
        const bottomH = (totalRows - endIdx) * this.rowHeight;
        this.bottomSpacer.innerHTML = `<td colspan="99" class="virtual-spacer-cell" style="height:${bottomH}px;"></td>`;
        fragment.appendChild(this.bottomSpacer);

        this.tbody.innerHTML = '';
        this.tbody.appendChild(fragment);
    }

    destroy() {
        this.container.removeEventListener('scroll', this._onScroll);
    }
}

// Track active virtual tables so we can clean up when modal closes
let activeVirtualTables = [];

// =============================================================================
// DATA LOADING AND DENORMALIZATION
// =============================================================================

/**
 * Load and decompress data from embedded scripts.
 * For compressed formats, stores raw bytes for Worker-based decompression.
 */
let pendingCompressedBytes = null;

async function loadData() {
    logDebug('Loading data, format:', dataFormat);

    if (dataFormat === 'external-compressed') {
        if (!dashboardConfig.payloadUrl) {
            throw new Error('Split-assets mode requires dashboardConfig.payloadUrl.');
        }

        const response = await fetch(dashboardConfig.payloadUrl, { cache: 'no-cache' });
        if (!response.ok) {
            throw new Error(`Failed to load dashboard payload (${response.status} ${response.statusText}).`);
        }

        pendingCompressedBytes = new Uint8Array(await response.arrayBuffer());
    } else if (dataFormat === 'compressed') {
        // Base64 decode on main thread (fast), defer inflate to Worker
        const compressedBase64 = document.getElementById('vulnsData').textContent.replace(/\s+/g, '');
        const binaryString = atob(compressedBase64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = binaryString.charCodeAt(i);
        pendingCompressedBytes = bytes;
    } else {
        // Normalized but not compressed
        lookups = JSON.parse(document.getElementById('lookupsData').textContent);
        rawVulns = JSON.parse(document.getElementById('vulnsData').textContent);
    }

    // Optional generation-time quality metadata
    try {
        const metaElement = document.getElementById('dataQualityMeta');
        if (metaElement && metaElement.textContent.trim()) {
            const parsedMeta = JSON.parse(metaElement.textContent);
            dataQualityMeta = {
                firstLastSwapped: Number(parsedMeta.firstLastSwapped || 0),
                generatedOnUtc: parsedMeta.generatedOnUtc || null
            };
        }
    } catch (err) {
        console.warn('Failed to parse data quality metadata:', err);
    }

    if (lookups) {
        logDebug('Loaded lookups:', Object.keys(lookups));
        logDebug('Loaded', getRawVulnCount(), 'vulnerability records');
    } else {
        logDebug('Compressed data loaded, will decompress in Worker');
    }
}

function isColumnarRawVulnData(value) {
    return !!(value && !Array.isArray(value) && Array.isArray(value.d));
}

function getRawVulnCount() {
    if (!rawVulns) {
        return 0;
    }

    if (Array.isArray(rawVulns)) {
        return rawVulns.length;
    }

    if (isColumnarRawVulnData(rawVulns)) {
        return rawVulns.d.length;
    }

    return 0;
}

function getRawVulnRecord(index) {
    if (Array.isArray(rawVulns)) {
        return rawVulns[index];
    }

    if (!isColumnarRawVulnData(rawVulns)) {
        return null;
    }

    return [
        rawVulns.d[index],
        rawVulns.c[index],
        rawVulns.s[index],
        rawVulns.v[index],
        rawVulns.f[index],
        rawVulns.l[index],
        rawVulns.ua[index],
        rawVulns.u[index],
        rawVulns.dp[index],
        rawVulns.rp[index],
        rawVulns.iv ? rawVulns.iv[index] : -1
    ];
}

function getLookupRecord(lookup, index) {
    const value = getLookupValue(lookup, index);
    return value == null ? null : value;
}

/**
 * Denormalize a single vulnerability record from compact array format
 * @param {Array} v - Compact vulnerability record [devIdx, cveIdx, swIdx, version, firstSeen, lastSeen, updateAvail, updIdx, diskPaths, regPaths, inventoryIdx]
 * @param {number} index - Index in the array
 * @returns {Object} Expanded vulnerability object
 */
/**
 * Denormalize all vulnerability records (main-thread fallback)
 */
function denormalizeAllVulns() {
    const rawCount = getRawVulnCount();
    logDebug('Denormalizing', rawCount, 'records (main thread)...');
    const startTime = performance.now();

    vulnerabilityData = new Array(rawCount);
    let rowCount = 0;
    let skippedInvalidRows = 0;

    // Direct column references for hot loop — avoids getRawVulnRecord overhead
    const isColumnar = isColumnarRawVulnData(rawVulns);
    const dCol = isColumnar ? rawVulns.d : null;
    const cCol = isColumnar ? rawVulns.c : null;
    const sCol = isColumnar ? rawVulns.s : null;
    const vCol = isColumnar ? rawVulns.v : null;
    const fCol = isColumnar ? rawVulns.f : null;
    const lCol = isColumnar ? rawVulns.l : null;
    const uCol = isColumnar ? rawVulns.u : null;
    const ivCol = isColumnar ? rawVulns.iv : null;

    // Cache lookup arrays locally
    const lkDevices = lookups.devices;
    const lkCves = lookups.cves;
    const lkSoftware = lookups.software;
    const lkGroups = lookups.groups;
    const lkPlatforms = lookups.platforms;
    const lkTags = lookups.tags;
    const lkVersions = lookups.versions;
    const lkDates = lookups.dates;
    const lkUpdates = lookups.updates;
    const lkVendors = lookups.vendors;
    const lkSeverities = lookups.severities;
    const lkExploitLevels = lookups.exploitLevels;
    const lkBatchTitles = lookups.batchTitles;
    const lkAffSoftware = lookups.affSoftware;
    const lkInventory = lookups.inventory || [];

    // Pre-format all date strings once (lkDates typically has ~365 entries)
    const preFormattedDates = new Array(lkDates ? lkDates.length : 0);
    for (let di = 0; di < preFormattedDates.length; di++) {
        const d = formatDateYMD(lkDates[di]);
        preFormattedDates[di] = d === '-' ? '' : d;
    }

    // Pre-compute addDays(date, DEVICE_INACTIVITY_WINDOW_DAYS) for every date index
    const addDaysByDateIdx = new Array(preFormattedDates.length);
    for (let di = 0; di < preFormattedDates.length; di++) {
        addDaysByDateIdx[di] = preFormattedDates[di]
            ? addDaysYmd(preFormattedDates[di], DEVICE_INACTIVITY_WINDOW_DAYS)
            : '';
    }

    // Pre-compute per-device values (one per unique device, ~20K)
    const noTagsArr = NO_TAGS_ARRAY;
    const EMPTY_PATHS = [];
    for (let di = 0; di < lkDevices.length; di++) {
        const dev = lkDevices[di];
        if (!dev) continue;
        const mi = dev.m;
        const ls = mi ? (mi.ls || mi.lastSeen || '') : '';
        const fmt = formatDateYMD(ls);
        dev._mlsFmt = fmt === '-' ? '' : fmt;
        dev._mlsInactivity = dev._mlsFmt
            ? addDaysYmd(dev._mlsFmt, DEVICE_INACTIVITY_WINDOW_DAYS)
            : '';
        // Tag names
        const deviceTags = dev.t;
        if (deviceTags && deviceTags.length > 0) {
            dev._tagNames = new Array(deviceTags.length);
            for (let ti = 0; ti < deviceTags.length; ti++) dev._tagNames[ti] = lkTags[deviceTags[ti]];
        } else {
            dev._tagNames = [];
        }
        dev._tagValues = dev._tagNames.length > 0 ? dev._tagNames : noTagsArr;
        dev._deviceFilterKey = dev.id || dev.n || '';
        // RBAC group
        const gVal = (dev.g >= 0 && dev.g < lkGroups.length) ? lkGroups[dev.g] : null;
        dev._rbacGroupName = (gVal && String(gVal).trim() !== '') ? gVal : '(none)';
        dev._normalizedGroup = normalizeGroupName(dev._rbacGroupName);
    }

    // Pre-compute per-CVE values (~30K items)
    for (let ci = 0; ci < lkCves.length; ci++) {
        const cve = lkCves[ci];
        if (!cve) continue;
        cve._pdFmt = cve.pd ? (formatDateYMD(cve.pd) || null) : null;
        cve._isExploitAvailable = cve.ea == null ? null : cve.ea === true;
        const nvdLastModified = cve.nlm ? formatDateYMD(cve.nlm) : '-';
        cve._nvdLastModifiedFmt = nvdLastModified === '-' ? null : nvdLastModified;
        const nvdKevDate = cve.nkev ? formatDateYMD(cve.nkev) : '-';
        cve._nvdKevFmt = nvdKevDate === '-' ? null : nvdKevDate;
        const nvdActionDue = cve.ndu ? formatDateYMD(cve.ndu) : '-';
        cve._nvdActionDueFmt = nvdActionDue === '-' ? null : nvdActionDue;
        cve._nvdWeaknesses = cve.nw && cve.nw.length > 0 ? cve.nw : null;
        const cveAs = cve.as;
        if (cveAs && cveAs.length > 0) {
            cve._affSw = new Array(cveAs.length);
            for (let ai = 0; ai < cveAs.length; ai++) cve._affSw[ai] = lkAffSoftware[cveAs[ai]];
        } else {
            cve._affSw = null;
        }
    }

    for (let ii = 0; ii < lkInventory.length; ii++) {
        const inventory = lkInventory[ii];
        if (!inventory) continue;
        const eod = inventory.eod ? formatDateYMD(inventory.eod) : '-';
        inventory._endOfSupportDateFmt = eod === '-' ? null : eod;
    }

    // Pre-compute per-(software, update) remediation key is no longer needed
    // (_remediationKey was set but never read)

    // Pre-compute per-(update, batchTitle) remediation string
    const remStrCache = new Map();
    function getRemediationStrCached(updIdx, btIdx) {
        const ck = (updIdx + 1) * 100000 + (btIdx + 1);
        let cached = remStrCache.get(ck);
        if (cached !== undefined) return cached;
        const uo = updIdx >= 0 ? lkUpdates[updIdx] : null;
        const un = uo ? (uo.n || uo) : null;
        const uid = uo ? (uo.id || null) : null;
        const bt = btIdx >= 0 ? lkBatchTitles[btIdx] : null;
        const kb = uid ? (String(uid).startsWith('KB') ? uid : 'KB' + uid) : null;
        if (bt) { cached = kb ? bt + ' (' + kb + ')' : bt; }
        else if (un && kb) { cached = un + ' (' + kb + ')'; }
        else if (un) { cached = un; }
        else if (kb) { cached = kb; }
        else { cached = 'Not Specified'; }
        remStrCache.set(ck, cached);
        return cached;
    }

    const earliestFirstSeenByIssue = new Map();
    const qualitySummary = createEmptyDataQualitySummary();
    const qualityDeviceKeys = new Set();
    const qualityCveIds = new Set();
    let _maxLatestActivity = '';

    for (let i = 0; i < rawCount; i++) {
        let devIdx, cveIdx, swIdx, verIdx, fsIdx, lsIdx, updIdx, invIdx;
        if (isColumnar) {
            devIdx = dCol[i]; cveIdx = cCol[i]; swIdx = sCol[i]; verIdx = vCol[i];
            fsIdx = fCol[i]; lsIdx = lCol[i]; updIdx = uCol[i]; invIdx = ivCol ? ivCol[i] : -1;
        } else {
            const row = rawVulns[i];
            devIdx = row[0]; cveIdx = row[1]; swIdx = row[2]; verIdx = row[3];
            fsIdx = row[4]; lsIdx = row[5]; updIdx = row[7]; invIdx = row.length > 10 ? row[10] : -1;
        }

        const device = getLookupRecord(lkDevices, devIdx);
        const cve = getLookupRecord(lkCves, cveIdx);
        const software = getLookupRecord(lkSoftware, swIdx);
        if (!device || !cve || !software) {
            skippedInvalidRows++;
            continue;
        }
        const inventory = invIdx >= 0 && invIdx < lkInventory.length ? lkInventory[invIdx] : null;

        const vendorName = software.v >= 0 && software.v < lkVendors.length ? lkVendors[software.v] : null;
        const updateObj = updIdx >= 0 ? lkUpdates[updIdx] : null;
        const updateName = updateObj ? (updateObj.n || updateObj) : null;

        const firstSeen = fsIdx >= 0 ? preFormattedDates[fsIdx] : '';
        const lastSeen = lsIdx >= 0 ? preFormattedDates[lsIdx] : '';

        // --- Inline derived fields using pre-computed device/cve values ---
        const machineLastSeen = device._mlsFmt;
        const latestActivity = (!machineLastSeen) ? lastSeen
            : (!lastSeen) ? machineLastSeen
            : (machineLastSeen > lastSeen ? machineLastSeen : lastSeen);
        const hasPatchEvidence = !!(lastSeen && latestActivity && latestActivity > lastSeen);
        if (latestActivity > _maxLatestActivity) _maxLatestActivity = latestActivity;
        let effectiveOpenEndDate = '';
        if (lastSeen) {
            if (latestActivity > lastSeen) {
                effectiveOpenEndDate = lastSeen;
            } else if (latestActivity === machineLastSeen && machineLastSeen) {
                effectiveOpenEndDate = device._mlsInactivity;
            } else {
                effectiveOpenEndDate = lsIdx >= 0 ? addDaysByDateIdx[lsIdx] : '';
            }
        }

        // Track earliest first-seen per environment issue key (numeric key avoids string concat)
        const issueKey = cveIdx * 1000000 + swIdx * 10000 + (verIdx + 1);
        if (firstSeen) {
            const existing = earliestFirstSeenByIssue.get(issueKey);
            if (!existing || firstSeen < existing) {
                earliestFirstSeenByIssue.set(issueKey, firstSeen);
            }
        }

        vulnerabilityData[rowCount++] = {
            DeviceId: device.id,
            DeviceName: device.n,
            RbacGroupName: device._rbacGroupName,
            OSPlatform: device.o >= 0 && device.o < lkPlatforms.length ? lkPlatforms[device.o] : null,
            MachineTags: device._tagNames,
            MachineInfo: device.m || null,
            CveId: cve.id,
            CvssScore: cve.sc,
            VulnerabilitySeverityLevel: cve.sv >= 0 && cve.sv < lkSeverities.length ? lkSeverities[cve.sv] : null,
            ExploitabilityLevel: cve.ex >= 0 ? lkExploitLevels[cve.ex] : null,
            PublishedDate: cve._pdFmt,
            EpssScore: cve.ep != null ? cve.ep : null,
            IsExploitAvailable: cve._isExploitAvailable,
            NvdLastModifiedDate: cve._nvdLastModifiedFmt,
            NvdBaseScore: cve.nbs != null ? cve.nbs : null,
            NvdBaseSeverity: cve.nsv || null,
            NvdVector: cve.nvec || null,
            NvdKevDate: cve._nvdKevFmt,
            NvdActionDue: cve._nvdActionDueFmt,
            NvdRequiredAction: cve.nact || null,
            NvdWeaknesses: cve._nvdWeaknesses,
            SoftwareVendor: vendorName,
            SoftwareName: software.n,
            SoftwareVersion: verIdx >= 0 ? lkVersions[verIdx] : null,
            ProductCodeCpe: inventory ? (inventory.cpe || null) : null,
            EndOfSupportStatus: inventory ? (inventory.eos || null) : null,
            EndOfSupportDate: inventory ? (inventory._endOfSupportDateFmt || null) : null,
            _firstSeenDate: firstSeen,
            _lastSeenDate: lastSeen,
            RecommendedSecurityUpdate: updateName,
            _index: i,
            _issueKey: issueKey,
            // Derived fields (inlined, using pre-computed device values)
            _machineLastSeenDate: machineLastSeen,
            _latestActivityDate: latestActivity,
            _hasPatchEvidence: hasPatchEvidence,
            _effectiveOpenEndDate: effectiveOpenEndDate,
            _remediationDate: hasPatchEvidence ? lastSeen : '',
            _remediationString: getRemediationStrCached(updIdx, cve.bt),
            _deviceFilterKey: device._deviceFilterKey,
            _normalizedGroup: device._normalizedGroup,
            _tagValues: device._tagValues
        };
    }

    vulnerabilityData.length = rowCount;

    // Second pass: assign _environmentFirstSeenDate (uses stored _issueKey)
    for (let i = 0; i < vulnerabilityData.length; i++) {
        const v = vulnerabilityData[i];
        v._environmentFirstSeenDate = earliestFirstSeenByIssue.get(v._issueKey) || v._firstSeenDate;

        qualitySummary.totalRecords++;
        const deviceKey = getDeviceIdentityKey(v);
        if (deviceKey) qualityDeviceKeys.add(deviceKey);
        if (v.CveId) qualityCveIds.add(v.CveId);

        if (!v.PublishedDate) {
            qualitySummary.missingPublished++;
        } else if (!/^\d{4}-\d{2}-\d{2}$/.test(v.PublishedDate)) {
            qualitySummary.nonYmdPublished++;
        }

        if (v._firstSeenDate && v._lastSeenDate && v._firstSeenDate > v._lastSeenDate) {
            qualitySummary.invertedRanges++;
        }
    }

    qualitySummary.uniqueDevices = qualityDeviceKeys.size;
    qualitySummary.uniqueCves = qualityCveIds.size;
    dataQualitySummary = qualitySummary;
    mostRecentLastSeenDate = _maxLatestActivity;
    if (skippedInvalidRows > 0) {
        console.warn('Skipped', skippedInvalidRows, 'vulnerability records with missing lookup references during denormalization.');
    }
    const elapsed = Math.round(performance.now() - startTime);
    logDebug('Denormalization complete in', elapsed, 'ms');
}

/**
 * Lazily resolve deferred detail properties on a vulnerability row.
 * Properties like DiskPaths, RegistryPaths, CveBatchUrl, etc. are only
 * needed for table/card/modal detail views (not for filtering or charts).
 * This avoids 1.5M array allocations during denormalization.
 * @param {Object} v - Vulnerability row object
 * @returns {Object} The same object, enriched with deferred properties
 */
function materializeRow(v) {
    if (v._mat) return v;
    // For rows loaded from IndexedDB cache, properties are already set;
    // rawVulns may not be available in that case
    if (!rawVulns || v._index == null || getRawVulnCount() === 0) {
        v._mat = true;
        return v;
    }
    const idx = v._index;
    if (idx < 0 || idx >= getRawVulnCount()) {
        v._mat = true;
        return v;
    }
    const rec = getRawVulnRecord(idx);
    const device = getLookupRecord(lookups.devices, rec[0]);
    const cve = getLookupRecord(lookups.cves, rec[1]);
    const software = getLookupRecord(lookups.software, rec[2]);
    if (!device || !cve || !software) {
        v.DiskPaths = v.DiskPaths || [];
        v.RegistryPaths = v.RegistryPaths || [];
        v.CveBatchUrl = v.CveBatchUrl || null;
        v.CveBatchTitle = v.CveBatchTitle || null;
        v.VulnerabilityDescription = v.VulnerabilityDescription || null;
        v.AffectedSoftware = v.AffectedSoftware || null;
        v.RecommendedSecurityUpdateId = v.RecommendedSecurityUpdateId || null;
        v.RecommendedSecurityUpdateUrl = v.RecommendedSecurityUpdateUrl || null;
        v.OSVersion = v.OSVersion || null;
        v.SecurityUpdateAvailable = v.SecurityUpdateAvailable === true;
        v.RecommendationReference = v.RecommendationReference || null;
        v._mat = true;
        return v;
    }
    const updIdx = rec[7];
    const updateObj = updIdx >= 0 ? getLookupValue(lookups.updates, updIdx) : null;

    // Evidence paths (resolved from lookup indices)
    const dpArr = rec[8];
    const rpArr = rec[9];
    if (dpArr && dpArr.length > 0) {
        v.DiskPaths = [];
        for (let i = 0; i < dpArr.length; i++) {
            const diskPath = getLookupValue(lookups.diskPaths, dpArr[i]);
            if (diskPath != null) v.DiskPaths.push(diskPath);
        }
    } else {
        v.DiskPaths = [];
    }
    if (rpArr && rpArr.length > 0) {
        v.RegistryPaths = [];
        for (let i = 0; i < rpArr.length; i++) {
            const regPath = getLookupValue(lookups.regPaths, rpArr[i]);
            if (regPath != null) v.RegistryPaths.push(regPath);
        }
    } else {
        v.RegistryPaths = [];
    }

    // Detail-only properties
    v.CveBatchUrl = cve.u;
    v.CveBatchTitle = cve.bt >= 0 ? getLookupValue(lookups.batchTitles, cve.bt) : null;
    v.VulnerabilityDescription = cve.desc || null;
    v.AffectedSoftware = cve._affSw;
    v.RecommendedSecurityUpdateId = updateObj ? (updateObj.id || null) : null;
    v.RecommendedSecurityUpdateUrl = updateObj ? (updateObj.url || null) : null;
    v.OSVersion = device.ov;
    v.SecurityUpdateAvailable = rec[6] === 1;
    v.RecommendationReference = software.r;

    v._mat = true;
    return v;
}

/**
 * Denormalize with Worker + IndexedDB caching.
 * Falls back to main-thread denormalization on any failure.
 * @returns {Promise<void>}
 */
async function denormalizeWithCaching() {
    const hasCompressed = !!pendingCompressedBytes;
    let compressedFp = null;
    let fingerprint = null;

    // For compressed data, try cache using a fingerprint of the raw compressed bytes
    if (hasCompressed) {
        compressedFp = await computeCompressedFingerprint(pendingCompressedBytes);
        logDebug('Compressed fingerprint:', compressedFp);
        const cached = await getCachedData(compressedFp);
        if (cached && cached.data && cached.data.length > 0) {
            logDebug('Loaded', cached.data.length, 'records from IndexedDB cache (compressed fingerprint)');
            vulnerabilityData = cached.data;
            if (cached.lookups) {
                lookups = cached.lookups;
                logDebug('Restored lookups from IndexedDB cache');
            } else {
                // Fallback: decompress to get lookups
                const decompressed = pako.inflate(pendingCompressedBytes, { to: 'string' });
                const payload = JSON.parse(decompressed);
                lookups = payload.lookups;
                rawVulns = payload.vulns;
            }
            pendingCompressedBytes = null;
            applyDerivedVulnerabilityFields(vulnerabilityData);
            return;
        }
    }

    if (!hasCompressed) {
        fingerprint = await computeDataFingerprint();
        const rawCount = getRawVulnCount();
        logDebug('Data fingerprint:', fingerprint);

        // 1. Try IndexedDB cache
        const cached = await getCachedData(fingerprint);
        if (cached && cached.data && cached.data.length === rawCount) {
            logDebug('Loaded', cached.data.length, 'records from IndexedDB cache');
            if (cached.lookups) lookups = cached.lookups;
            vulnerabilityData = cached.data;
            applyDerivedVulnerabilityFields(vulnerabilityData);
            return;
        }
    }

    // 2. Try Web Worker (with optional decompression)
    const compBytes = pendingCompressedBytes;
    pendingCompressedBytes = null;
    try {
        const label = compBytes ? 'decompressing' : 'denormalizing';
        logDebug(label, compBytes ? '(compressed bytes via Worker)' : getRawVulnCount(), 'records via Web Worker...');
        const startTime = performance.now();
        const result = await denormalizeInWorker(compBytes);
        if (result.lookups) lookups = result.lookups;
        if (result.rawVulns) rawVulns = result.rawVulns;
        if (result.skippedInvalidRows > 0) {
            console.warn('Skipped', result.skippedInvalidRows, 'vulnerability records with missing lookup references during Worker denormalization.');
        }
        if (result.rows) {
            // Worker returned fully denormalized rows (non-compressed path)
            vulnerabilityData = result.rows;
        } else {
            // Decompress-only path: Worker returned lookups + rawVulns, denormalize here
            const decompElapsed = Math.round(performance.now() - startTime);
            console.log('[perf] Worker decompress: ' + decompElapsed + 'ms');
            denormalizeAllVulns();
        }
        const elapsed = Math.round(performance.now() - startTime);
        logDebug('Worker + denormalize complete in', elapsed, 'ms');
    } catch (err) {
        console.warn('Web Worker failed, falling back to main thread:', err);
        // Decompress on main thread if we have compressed bytes and lookups weren't set
        if (compBytes && !lookups) {
            const decompressed = pako.inflate(compBytes, { to: 'string' });
            const data = JSON.parse(decompressed);
            lookups = data.lookups;
            rawVulns = data.vulns;
        }
        denormalizeAllVulns();
    }

    // Derived fields are now computed inline in denormalizeAllVulns();
    // only call applyDerivedVulnerabilityFields for IndexedDB-cached data (above)

    // Log counts after data is available
    logDebug('Loaded lookups:', lookups ? Object.keys(lookups) : 'none');
    logDebug('Loaded', getRawVulnCount(), 'vulnerability records');

    // 3. Cache the result (fire-and-forget) — skip for very large datasets
    // IndexedDB structured clone fails with out-of-memory for 500K+ records
    if (vulnerabilityData.length < 500000) {
        if (!fingerprint) {
            fingerprint = await computeDataFingerprint();
        }
        logDebug('Data fingerprint:', fingerprint);
        setCachedData(fingerprint, vulnerabilityData);
        if (compressedFp) {
            setCachedData(compressedFp, vulnerabilityData);
        }
    } else {
        console.log('[perf] Skipping IndexedDB cache for', vulnerabilityData.length, 'records (too large for structured clone)');
    }
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize the dashboard on page load
 */
async function init() {
    console.time('[perf] init total');
    setDashboardStatus('Loading dashboard data...');

    // Load and process data
    console.time('[perf] loadData');
    await loadData();
    console.timeEnd('[perf] loadData');
    console.time('[perf] denormalize');
    await denormalizeWithCaching();
    console.timeEnd('[perf] denormalize');
    await ensureChartJsLoaded();
    
    logDebug('Initializing dashboard with', vulnerabilityData.length, 'vulnerabilities');
    buildDeviceFilterCatalog();
    populateFilters();
    updateDataQualitySummary();
    attachEventListeners();
    setupInfiniteScroll();
    activeReportId = getCurrentReportId();
    setDateRange('1w');
    updateRemediationReportModeUi(activeReportId);
    scheduleApplyFilters(true);
    clearDashboardStatus();
    console.timeEnd('[perf] init total');
    window._dashboardReady = true;
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
        return;
    }

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
            return;
    }

    initializedReports.add(reportId);
    dirtyReports.delete(reportId);
}

function renderActiveReport(force = false) {
    renderReport(activeReportId, force);
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

// =============================================================================
// EVENT HANDLERS
// =============================================================================

/**
 * Handle report view change from dropdown
 */
function handleReportChange() {
    const selector = document.getElementById('reportSelector');
    const selectedReport = selector.value;
    activeReportId = selectedReport;

    // Hide all report sections
    document.querySelectorAll('.report-section').forEach(section => {
        section.classList.remove('active');
    });

    // Show selected report section
    const activeSection = document.getElementById(selectedReport + '-section');
    if (activeSection) {
        activeSection.classList.add('active');
    }

    updateRemediationReportModeUi(selectedReport);
    renderReport(selectedReport);
}

/**
 * Handle date range preset selection
 */
function handleDateRangeChange(event) {
    const button = event.currentTarget;
    const range = button.getAttribute('data-range');
    
    document.querySelectorAll('.date-range-option').forEach(option => {
        option.classList.remove('selected');
        option.setAttribute('aria-pressed', 'false');
    });
    
    button.classList.add('selected');
    button.setAttribute('aria-pressed', 'true');
    
    // Update dates based on selection
    setDateRange(range);
}

/**
 * Handle manual date input change
 */
function handleManualDateChange() {
    document.querySelectorAll('.date-range-option').forEach(option => {
        option.classList.remove('selected');
        option.setAttribute('aria-pressed', 'false');
    });
    scheduleApplyFilters(true);
}

/**
 * Handle device group filter change
 */
function handleDeviceGroupChange() {
    scheduleApplyFilters();
}

/**
 * Handle device tags filter change
 */
function handleDeviceTagsChange() {
    scheduleApplyFilters();
}

/**
 * Handle device name filter change
 */
function handleDeviceNameChange() {
    scheduleApplyFilters();
}

function handleDeviceSearchInput() {
    scheduleApplyFilters();
}

function handleFilterChipClick(event) {
    const chip = event.target.closest('.filter-chip');
    if (!chip) return;

    const { containerId, filterValue } = chip.dataset;
    if (!containerId) return;

    if (containerId === 'filterDeviceSearch') {
        const searchInput = document.getElementById('filterDeviceSearch');
        if (searchInput) searchInput.value = '';
        scheduleApplyFilters(true);
        return;
    }

    const container = document.getElementById(containerId);
    if (!container) return;

    const checkbox = Array.from(container.querySelectorAll('input[type="checkbox"]')).find(cb => cb.value === filterValue);
    if (!checkbox) return;
    checkbox.checked = false;
    updateAllCheckbox(containerId);
    scheduleApplyFilters(true);
}

function handleClearAllFilters() {
    closeActiveFilterPopover();
    filterState = finalizeFilterState(assignDatePreset(createEmptyFilterState(), '1w'));
    renderFilterPills(filterState);
    scheduleApplyFilters(true);
}

/**
 * Handle OS platform filter change (no cascade, just apply filters)
 */
function handleOSPlatformChange() {
    scheduleApplyFilters();
}

/**
 * Handle severity filter change (no cascade, just apply filters)
 */
function handleSeverityChange() {
    scheduleApplyFilters();
}

function areStringArraysEqual(left, right) {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
    }
    return true;
}

function getFilterOptionLabel(filterKey, value) {
    if (filterKey === 'filterDeviceName') {
        return deviceFilterLabelByKey.get(value) || value;
    }
    return value;
}

function getFilterOptionSearchText(filterKey, value) {
    const label = getFilterOptionLabel(filterKey, value);
    return `${label} ${value}`.trim().toLowerCase();
}

function getScopedFilterOptions(filterKey, state = filterState) {
    const scopedState = cloneFilterState(state);
    resetFilterInState(scopedState, filterKey);

    if (filterKey === 'filterDeviceName') {
        const devicesByKey = new Map();
        for (let index = 0; index < vulnerabilityData.length; index++) {
            const vuln = vulnerabilityData[index];
            if (!matchesFilterStateDate(vuln, scopedState)) continue;
            if (!matchesFilterStateNonDate(vuln, scopedState, filterKey)) continue;

            if (!devicesByKey.has(vuln._deviceFilterKey)) {
                const label = getFilterOptionLabel(filterKey, vuln._deviceFilterKey);
                devicesByKey.set(vuln._deviceFilterKey, {
                    value: vuln._deviceFilterKey,
                    label,
                    searchText: getFilterOptionSearchText(filterKey, vuln._deviceFilterKey),
                    count: null
                });
            }
        }

        return Array.from(devicesByKey.values()).sort((left, right) => left.label.localeCompare(right.label));
    }

    const deviceSetCounts = new Map();
    const rowCounts = new Map();
    for (let index = 0; index < vulnerabilityData.length; index++) {
        const vuln = vulnerabilityData[index];
        if (!matchesFilterStateDate(vuln, scopedState)) continue;
        if (!matchesFilterStateNonDate(vuln, scopedState, filterKey)) continue;

        switch (filterKey) {
            case 'filterRbacGroup': {
                const key = vuln._normalizedGroup;
                if (!deviceSetCounts.has(key)) deviceSetCounts.set(key, new Set());
                deviceSetCounts.get(key).add(vuln._deviceFilterKey);
                break;
            }
            case 'filterDeviceTags': {
                for (let tagIndex = 0; tagIndex < vuln._tagValues.length; tagIndex++) {
                    const key = vuln._tagValues[tagIndex];
                    if (!deviceSetCounts.has(key)) deviceSetCounts.set(key, new Set());
                    deviceSetCounts.get(key).add(vuln._deviceFilterKey);
                }
                break;
            }
            case 'filterOSPlatform': {
                const key = vuln.OSPlatform;
                if (!deviceSetCounts.has(key)) deviceSetCounts.set(key, new Set());
                deviceSetCounts.get(key).add(vuln._deviceFilterKey);
                break;
            }
            case 'filterSeverity': {
                const key = vuln.VulnerabilitySeverityLevel;
                rowCounts.set(key, (rowCounts.get(key) || 0) + 1);
                break;
            }
        }
    }

    if (filterKey === 'filterSeverity') {
        return ['Critical', 'High', 'Medium', 'Low']
            .filter(value => rowCounts.has(value))
            .map(value => ({ value, label: value, count: rowCounts.get(value) || 0 }));
    }

    const values = Array.from(deviceSetCounts.keys()).sort((left, right) => {
        if (filterKey === 'filterRbacGroup') {
            if (left === NO_GROUP_VALUE && right !== NO_GROUP_VALUE) return -1;
            if (right === NO_GROUP_VALUE && left !== NO_GROUP_VALUE) return 1;
        }
        if (filterKey === 'filterDeviceTags') {
            if (left === NO_TAGS_VALUE && right !== NO_TAGS_VALUE) return -1;
            if (right === NO_TAGS_VALUE && left !== NO_TAGS_VALUE) return 1;
        }
        return left.localeCompare(right);
    });

    return values.map(value => ({
        value,
        label: value,
        count: deviceSetCounts.get(value)?.size || 0,
        searchText: value.toLowerCase()
    }));
}

function isDraftOptionSelected(filterKey, optionValue) {
    const config = FILTER_POPOVER_CONFIG[filterKey];
    const values = filterPopoverDraftState?.[config.stateKey] || [];
    const hasAny = filterPopoverDraftState?.[config.hasAnyKey];
    if (!hasAny) return false;
    if (values.length === 0) return true;
    return values.includes(optionValue);
}

function getDraftSelectedCount(filterKey) {
    const config = FILTER_POPOVER_CONFIG[filterKey];
    if (!config) return 0;

    const values = filterPopoverDraftState?.[config.stateKey] || [];
    const hasAny = filterPopoverDraftState?.[config.hasAnyKey];
    if (!hasAny) return 0;
    if (values.length === 0) return activeFilterPopoverOptions.length;
    return values.length;
}

function isFilterDefaultState(filterKey, state = filterState) {
    if (filterKey === 'date') {
        return isDateFilterDefault(state);
    }

    const config = FILTER_POPOVER_CONFIG[filterKey];
    if (!config) return true;
    return state[config.hasAnyKey] && state[config.stateKey].length === 0;
}

function isActiveFilterPopoverDirty() {
    if (!activeFilterPopoverKey || !filterPopoverDraftState) {
        return false;
    }

    if (activeFilterPopoverKey === 'date') {
        return filterPopoverDraftState.datePreset !== filterState.datePreset
            || filterPopoverDraftState.startDate !== filterState.startDate
            || filterPopoverDraftState.endDate !== filterState.endDate;
    }

    const config = FILTER_POPOVER_CONFIG[activeFilterPopoverKey];
    return filterPopoverDraftState[config.hasAnyKey] !== filterState[config.hasAnyKey]
        || !areStringArraysEqual(filterPopoverDraftState[config.stateKey], filterState[config.stateKey]);
}

function updateFilterPopoverFooterState() {
    const applyButton = document.getElementById('filterPopoverApplyButton');
    const resetButton = document.getElementById('filterPopoverResetButton');
    if (!applyButton || !resetButton || !activeFilterPopoverKey) {
        return;
    }

    const validationMessage = activeFilterPopoverKey === 'date'
        ? updateDateFilterPopoverValidationState()
        : '';

    applyButton.disabled = Boolean(validationMessage) || !isActiveFilterPopoverDirty();
    resetButton.disabled = isFilterDefaultState(activeFilterPopoverKey, filterPopoverDraftState);
}

function updateDateFilterPopoverValidationState(state = filterPopoverDraftState) {
    const validationMessage = activeFilterPopoverKey === 'date'
        ? getDateRangeValidationMessage(state)
        : '';
    const isInvalid = Boolean(validationMessage);
    const startInput = document.getElementById('filterPopoverStartDate');
    const endInput = document.getElementById('filterPopoverEndDate');
    const validationElement = document.getElementById('filterPopoverDateValidation');

    if (startInput) {
        startInput.setAttribute('aria-invalid', isInvalid ? 'true' : 'false');
    }
    if (endInput) {
        endInput.setAttribute('aria-invalid', isInvalid ? 'true' : 'false');
    }
    if (validationElement) {
        validationElement.textContent = validationMessage;
    }

    return validationMessage;
}

function updateDatePresetButtonState() {
    document.querySelectorAll('#filterPopoverBody [data-date-preset]').forEach(button => {
        const isSelected = filterPopoverDraftState?.datePreset === button.dataset.datePreset;
        button.classList.toggle('selected', Boolean(isSelected));
        button.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
    });
}

function getFilterPopoverBatchSize(filterKey, optionCount) {
    if (filterKey !== 'filterDeviceName') {
        return optionCount;
    }

    const percentageBatchSize = Math.ceil(optionCount * FILTER_POPOVER_BATCH_PERCENTAGE);
    return Math.min(
        optionCount,
        Math.max(FILTER_POPOVER_BATCH_FLOOR, Math.min(FILTER_POPOVER_BATCH_CEILING, percentageBatchSize))
    );
}

function shouldIncrementallyRenderFilterPopover(filterKey = activeFilterPopoverKey) {
    return filterKey === 'filterDeviceName' && activeFilterPopoverOptions.length > activeFilterPopoverBatchSize;
}

function resetActiveFilterPopoverState() {
    activeFilterPopoverOptions = [];
    activeFilterPopoverFilteredOptions = [];
    activeFilterPopoverRenderedCount = 0;
    activeFilterPopoverSearchTerm = '';
    activeFilterPopoverBatchSize = 0;
}

function buildFilterPopoverOptionMarkup(option, index) {
    const checked = isDraftOptionSelected(activeFilterPopoverKey, option.value) ? 'checked' : '';
    const countMarkup = option.count !== null && option.count !== undefined
        ? `<span class="checkbox-count">${option.count}</span>`
        : '';

    return `
        <div class="checkbox-item" data-search-text="${escapeHtml(option.searchText || option.label.toLowerCase())}">
            <input type="checkbox" id="filterPopoverOption_${index}" data-option-value="${escapeHtml(option.value)}" ${checked}>
            <label for="filterPopoverOption_${index}">
                <span class="checkbox-label-text">${escapeHtml(option.label)}</span>
                ${countMarkup}
            </label>
        </div>`;
}

function getRenderedFilterPopoverOptionCount() {
    return Math.min(activeFilterPopoverRenderedCount, activeFilterPopoverFilteredOptions.length);
}

function getMatchingFilterPopoverOptions() {
    if (!activeFilterPopoverSearchTerm) {
        return activeFilterPopoverOptions;
    }

    return activeFilterPopoverOptions.filter(option => {
        const searchText = option.searchText || option.label.toLowerCase();
        return searchText.includes(activeFilterPopoverSearchTerm);
    });
}

function updateRenderedFilterPopoverOptionSelection() {
    if (!activeFilterPopoverKey || activeFilterPopoverKey === 'date') {
        return;
    }

    document.querySelectorAll('#filterPopoverOptions input[data-option-value]').forEach(checkbox => {
        checkbox.checked = isDraftOptionSelected(activeFilterPopoverKey, checkbox.dataset.optionValue);
    });
}

function renderFilterPopoverOptionRows(resetScroll = false) {
    const optionsContainer = document.getElementById('filterPopoverOptions');
    const rowsContainer = document.getElementById('filterPopoverOptionRows');
    if (!optionsContainer || !rowsContainer) {
        return;
    }

    const renderedCount = getRenderedFilterPopoverOptionCount();
    rowsContainer.innerHTML = activeFilterPopoverFilteredOptions
        .slice(0, renderedCount)
        .map((option, index) => buildFilterPopoverOptionMarkup(option, index))
        .join('');

    if (resetScroll) {
        optionsContainer.scrollTop = 0;
    }

    updateRenderedFilterPopoverOptionSelection();
    updateFilterPopoverSummary();
    updateFilterPopoverAllCheckbox();
}

function refreshFilterPopoverOptionRows(resetScroll = false) {
    activeFilterPopoverFilteredOptions = getMatchingFilterPopoverOptions();
    const batchSize = shouldIncrementallyRenderFilterPopover()
        ? activeFilterPopoverBatchSize
        : activeFilterPopoverFilteredOptions.length;
    activeFilterPopoverRenderedCount = Math.min(activeFilterPopoverFilteredOptions.length, batchSize);
    renderFilterPopoverOptionRows(resetScroll);
}

function appendNextFilterPopoverOptionBatch() {
    if (!shouldIncrementallyRenderFilterPopover()) {
        return;
    }

    const optionsContainer = document.getElementById('filterPopoverOptions');
    const rowsContainer = document.getElementById('filterPopoverOptionRows');
    if (!optionsContainer || !rowsContainer) {
        return;
    }

    const currentRenderedCount = getRenderedFilterPopoverOptionCount();
    if (currentRenderedCount >= activeFilterPopoverFilteredOptions.length) {
        return;
    }

    const nextRenderedCount = Math.min(
        activeFilterPopoverFilteredOptions.length,
        currentRenderedCount + activeFilterPopoverBatchSize
    );
    rowsContainer.insertAdjacentHTML(
        'beforeend',
        activeFilterPopoverFilteredOptions
            .slice(currentRenderedCount, nextRenderedCount)
            .map((option, index) => buildFilterPopoverOptionMarkup(option, currentRenderedCount + index))
            .join('')
    );
    activeFilterPopoverRenderedCount = nextRenderedCount;

    updateRenderedFilterPopoverOptionSelection();
    updateFilterPopoverSummary();
    updateFilterPopoverAllCheckbox();
}

function handleFilterPopoverOptionsScroll(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement) || target.id !== 'filterPopoverOptions') {
        return;
    }

    if (!shouldIncrementallyRenderFilterPopover()) {
        return;
    }

    const threshold = target.scrollHeight - FILTER_POPOVER_SCROLL_PRELOAD_PX;
    if (target.scrollTop + target.clientHeight >= threshold) {
        appendNextFilterPopoverOptionBatch();
    }
}

function setAllFilterPopoverOptionsSelected(isSelected) {
    if (!activeFilterPopoverKey || activeFilterPopoverKey === 'date' || !filterPopoverDraftState) {
        return;
    }

    const config = FILTER_POPOVER_CONFIG[activeFilterPopoverKey];
    filterPopoverDraftState[config.stateKey] = [];
    filterPopoverDraftState[config.hasAnyKey] = isSelected;

    updateRenderedFilterPopoverOptionSelection();
    updateFilterPopoverSummary();
    updateFilterPopoverAllCheckbox();
    updateFilterPopoverFooterState();
}

function toggleFilterPopoverOptionSelection(optionValue, isSelected) {
    if (!activeFilterPopoverKey || activeFilterPopoverKey === 'date' || !filterPopoverDraftState) {
        return;
    }

    const config = FILTER_POPOVER_CONFIG[activeFilterPopoverKey];
    const selectedValues = filterPopoverDraftState[config.hasAnyKey]
        ? (filterPopoverDraftState[config.stateKey].length === 0
            ? new Set(activeFilterPopoverOptions.map(option => option.value))
            : new Set(filterPopoverDraftState[config.stateKey]))
        : new Set();

    if (isSelected) {
        selectedValues.add(optionValue);
    } else {
        selectedValues.delete(optionValue);
    }

    if (selectedValues.size === 0) {
        filterPopoverDraftState[config.stateKey] = [];
        filterPopoverDraftState[config.hasAnyKey] = false;
    } else if (selectedValues.size === activeFilterPopoverOptions.length) {
        filterPopoverDraftState[config.stateKey] = [];
        filterPopoverDraftState[config.hasAnyKey] = true;
    } else {
        filterPopoverDraftState[config.stateKey] = activeFilterPopoverOptions
            .map(option => option.value)
            .filter(value => selectedValues.has(value));
        filterPopoverDraftState[config.hasAnyKey] = true;
    }

    updateFilterPopoverSummary();
    updateFilterPopoverAllCheckbox();
    updateFilterPopoverFooterState();
}

function updateFilterPopoverSummary() {
    const subtitle = document.getElementById('filterPopoverSubtitle');
    const summary = document.getElementById('filterPopoverSummary');
    if (subtitle) {
        subtitle.textContent = '';
    }
    if (summary) {
        summary.textContent = '';
    }

    if (!activeFilterPopoverKey || activeFilterPopoverKey === 'date' || !filterPopoverDraftState || activeFilterPopoverKey !== 'filterDeviceName') {
        return;
    }

    const totalCount = activeFilterPopoverOptions.length;
    const selectedCount = getDraftSelectedCount(activeFilterPopoverKey);
    if (subtitle) {
        subtitle.textContent = formatFilterSelectionProgress(selectedCount, totalCount);
    }

    if (!summary) {
        return;
    }

    if (totalCount === 0) {
        summary.textContent = 'No devices are available in the current scope.';
        return;
    }

    const filteredCount = activeFilterPopoverFilteredOptions.length;
    const renderedCount = getRenderedFilterPopoverOptionCount();
    if (activeFilterPopoverSearchTerm) {
        if (filteredCount === 0) {
            summary.textContent = `No devices match "${activeFilterPopoverSearchTerm}".`;
            return;
        }

        summary.textContent = renderedCount < filteredCount
            ? `Showing ${renderedCount.toLocaleString()} of ${filteredCount.toLocaleString()} matching devices. Scroll to load more.`
            : `Showing ${filteredCount.toLocaleString()} matching devices.`;
        return;
    }

    summary.textContent = renderedCount < filteredCount
        ? `Showing ${renderedCount.toLocaleString()} of ${filteredCount.toLocaleString()} devices. Scroll to load more.`
        : `Showing all ${filteredCount.toLocaleString()} devices.`;
}

function updateFilterPopoverAllCheckbox() {
    const allCheckbox = document.getElementById('filterPopoverAllCheckbox');
    if (!allCheckbox || !activeFilterPopoverKey || activeFilterPopoverKey === 'date') {
        return;
    }

    const selectedCount = getDraftSelectedCount(activeFilterPopoverKey);
    const optionCount = activeFilterPopoverOptions.length;
    allCheckbox.disabled = optionCount === 0;
    allCheckbox.indeterminate = selectedCount > 0 && selectedCount < optionCount;
    allCheckbox.checked = optionCount > 0 && selectedCount === optionCount;
}

function applyFilterPopoverSearch() {
    const searchInput = document.getElementById('filterPopoverSearchInput');
    activeFilterPopoverSearchTerm = (searchInput?.value || '').trim().toLowerCase();
    refreshFilterPopoverOptionRows(true);
}

function renderActiveFilterPopover() {
    const popover = document.getElementById('filterPopover');
    const title = document.getElementById('filterPopoverTitle');
    const subtitle = document.getElementById('filterPopoverSubtitle');
    const body = document.getElementById('filterPopoverBody');
    if (!popover || !title || !subtitle || !body || !activeFilterPopoverKey || !filterPopoverDraftState) {
        return;
    }

    const config = FILTER_POPOVER_CONFIG[activeFilterPopoverKey];
    title.textContent = config.label;
    subtitle.textContent = '';

    body.className = 'filter-popover-body';

    popover.dataset.filterKey = activeFilterPopoverKey;
    activeFilterPopoverOptions = activeFilterPopoverKey === 'date'
        ? []
        : getScopedFilterOptions(activeFilterPopoverKey, filterState);
    activeFilterPopoverFilteredOptions = activeFilterPopoverOptions;
    activeFilterPopoverBatchSize = getFilterPopoverBatchSize(activeFilterPopoverKey, activeFilterPopoverOptions.length);
    activeFilterPopoverRenderedCount = 0;

    if (activeFilterPopoverKey === 'date') {
        body.classList.add('filter-popover-body--date');
        body.innerHTML = `
            <div class="filter-popover-date-presets">
                ${Object.entries(DATE_PRESET_CONFIG).map(([value, label]) => `
                    <button type="button" class="date-range-option${filterPopoverDraftState.datePreset === value ? ' selected' : ''}" data-date-preset="${value}" aria-pressed="${filterPopoverDraftState.datePreset === value ? 'true' : 'false'}">${label}</button>
                `).join('')}
            </div>
            <div class="filter-popover-date-inputs">
                <div class="filter-popover-date-field">
                    <label for="filterPopoverStartDate">Start Date</label>
                    <input type="date" id="filterPopoverStartDate" value="${escapeHtml(filterPopoverDraftState.startDate)}" aria-describedby="filterPopoverDateValidation">
                </div>
                <div class="filter-popover-date-field">
                    <label for="filterPopoverEndDate">End Date</label>
                    <input type="date" id="filterPopoverEndDate" value="${escapeHtml(filterPopoverDraftState.endDate)}" aria-describedby="filterPopoverDateValidation">
                </div>
            </div>
            <div id="filterPopoverDateValidation" class="filter-popover-date-validation" role="status" aria-live="polite"></div>`;
        updateFilterPopoverFooterState();
        return;
    }

    const optionCount = activeFilterPopoverOptions.length;
    const selectedCount = getDraftSelectedCount(activeFilterPopoverKey);
    const shouldShowSearch = config.searchable || optionCount > FACET_SEARCH_MIN_OPTIONS;
    const searchPlaceholder = activeFilterPopoverKey === 'filterDeviceName'
        ? 'Search device name or id'
        : 'Filter options';

    body.classList.add('filter-popover-body--options');
    body.innerHTML = `
        ${shouldShowSearch ? `<input type="text" id="filterPopoverSearchInput" class="filter-search filter-popover-search" placeholder="${searchPlaceholder}" value="${escapeHtml(activeFilterPopoverSearchTerm)}">` : ''}
        <div id="filterPopoverSummary" class="filter-popover-summary"></div>
        <div class="filter-popover-options" id="filterPopoverOptions">
            <div class="checkbox-item checkbox-item-all">
                <input type="checkbox" id="filterPopoverAllCheckbox" ${optionCount > 0 && selectedCount === optionCount ? 'checked' : ''} ${optionCount === 0 ? 'disabled' : ''}>
                <label for="filterPopoverAllCheckbox">All</label>
            </div>
            <div id="filterPopoverOptionRows"></div>
            ${optionCount === 0 ? `<div class="filter-popover-empty">No ${config.summaryNoun} are available in the current scope.</div>` : ''}
        </div>`;

    document.getElementById('filterPopoverOptions')?.addEventListener('scroll', handleFilterPopoverOptionsScroll);
    refreshFilterPopoverOptionRows(true);
    updateFilterPopoverFooterState();
}

function positionFilterPopover(anchorButton) {
    const toolbar = document.getElementById('filterToolbar');
    const popover = document.getElementById('filterPopover');
    if (!toolbar || !popover || !anchorButton) {
        return;
    }

    const toolbarRect = toolbar.getBoundingClientRect();
    const anchorRect = anchorButton.getBoundingClientRect();
    const popoverWidth = popover.offsetWidth || Math.min(
        activeFilterPopoverKey === 'filterDeviceName' ? 520 : 400,
        toolbar.clientWidth
    );
    const anchorCenter = (anchorRect.left - toolbarRect.left) + (anchorRect.width / 2);
    const maxLeft = Math.max(0, toolbar.clientWidth - popoverWidth);
    const offset = Math.min(Math.max(0, anchorCenter - (popoverWidth / 2)), maxLeft);
    popover.style.left = `${offset}px`;
}

function closeActiveFilterPopover() {
    const popover = document.getElementById('filterPopover');
    const subtitle = document.getElementById('filterPopoverSubtitle');
    const body = document.getElementById('filterPopoverBody');
    if (popover) {
        popover.hidden = true;
        popover.setAttribute('aria-hidden', 'true');
        popover.removeAttribute('data-filter-key');
        popover.style.left = '0px';
    }
    if (subtitle) {
        subtitle.textContent = '';
    }
    if (body) {
        body.className = 'filter-popover-body';
        body.innerHTML = '';
    }

    activeFilterPopoverKey = null;
    filterPopoverDraftState = null;
    resetActiveFilterPopoverState();
    renderFilterPills(filterState);
}

function openFilterPopover(filterKey, anchorButton) {
    if (activeFilterPopoverKey === filterKey) {
        closeActiveFilterPopover();
        return;
    }

    activeFilterPopoverKey = filterKey;
    filterPopoverDraftState = cloneFilterState(filterState);
    activeFilterPopoverSearchTerm = '';
    renderActiveFilterPopover();

    const popover = document.getElementById('filterPopover');
    if (popover) {
        popover.hidden = false;
        popover.setAttribute('aria-hidden', 'false');
    }

    positionFilterPopover(anchorButton);
    renderFilterPills(filterState);

    const autofocusTarget = document.getElementById('filterPopoverSearchInput')
        || document.querySelector('#filterPopoverBody .date-range-option.selected')
        || document.getElementById('filterPopoverApplyButton');
    autofocusTarget?.focus();
}

function handleFilterPopoverClick(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
        return;
    }

    if (target.id === 'filterPopoverCloseButton' || target.id === 'filterPopoverCancelButton') {
        closeActiveFilterPopover();
        return;
    }

    if (target.id === 'filterPopoverResetButton') {
        filterPopoverDraftState = finalizeFilterState(resetFilterInState(cloneFilterState(filterPopoverDraftState), activeFilterPopoverKey));
        renderActiveFilterPopover();
        return;
    }

    if (target.id === 'filterPopoverApplyButton') {
        if (activeFilterPopoverKey === 'date' && updateDateFilterPopoverValidationState(filterPopoverDraftState)) {
            return;
        }
        filterState = finalizeFilterState(filterPopoverDraftState);
        closeActiveFilterPopover();
        renderFilterPills(filterState);
        scheduleApplyFilters(true);
        return;
    }

    if (target.matches('[data-date-preset]')) {
        filterPopoverDraftState = finalizeFilterState(assignDatePreset(cloneFilterState(filterPopoverDraftState), target.dataset.datePreset));
        renderActiveFilterPopover();
    }
}

function handleFilterPopoverInput(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement) || !activeFilterPopoverKey) {
        return;
    }

    if (target.id === 'filterPopoverSearchInput') {
        applyFilterPopoverSearch();
        return;
    }

    if (target.id === 'filterPopoverAllCheckbox') {
        setAllFilterPopoverOptionsSelected(target.checked);
        return;
    }

    if (target.id === 'filterPopoverStartDate' || target.id === 'filterPopoverEndDate') {
        const startDate = document.getElementById('filterPopoverStartDate')?.value || '';
        const endDate = document.getElementById('filterPopoverEndDate')?.value || '';
        filterPopoverDraftState.startDate = startDate;
        filterPopoverDraftState.endDate = endDate;
        filterPopoverDraftState.datePreset = 'custom';
        updateDatePresetButtonState();
        updateFilterPopoverFooterState();
        return;
    }

    if (target.matches('#filterPopoverOptions input[data-option-value]')) {
        toggleFilterPopoverOptionSelection(target.dataset.optionValue, target.checked);
    }
}

function handleFilterPillClick(event) {
    const button = event.currentTarget;
    const filterKey = button.dataset.filterKey;
    if (!filterKey) {
        return;
    }

    openFilterPopover(filterKey, button);
}

function handleDocumentPointerDown(event) {
    const popover = document.getElementById('filterPopover');
    if (!activeFilterPopoverKey || !popover) {
        return;
    }

    const target = event.target;
    if (!(target instanceof Element)) {
        closeActiveFilterPopover();
        return;
    }

    if (popover.contains(target)) {
        return;
    }

    if (target.closest('.filter-pill')) {
        return;
    }

    closeActiveFilterPopover();
}

function handleDocumentKeyDown(event) {
    if (event.key === 'Escape' && activeFilterPopoverKey) {
        closeActiveFilterPopover();
    }
}

function handleSortButtonClick(event) {
    const button = event.currentTarget;
    const columnIndex = Number(button.dataset.columnIndex);

    switch (button.dataset.sortTable) {
        case 'remediation':
            sortTable(columnIndex);
            break;
        case 'remediation-details':
            sortRemediationDetailsTable(columnIndex);
            break;
        case 'impact-analysis':
            sortImpactAnalysisTable(columnIndex);
            break;
    }
}

/**
 * Attach event listeners to filter controls
 */
function attachEventListeners() {
    document.getElementById('reportSelector').addEventListener('change', handleReportChange);
    document.getElementById('exportPdfButton').addEventListener('click', exportToPDF);
    document.querySelectorAll('.report-mode-button').forEach(button => {
        button.addEventListener('click', handleRemediationReportModeChange);
    });
    document.getElementById('clearAllFiltersButton')?.addEventListener('click', handleClearAllFilters);
    document.querySelectorAll('.filter-pill').forEach(button => {
        button.addEventListener('click', handleFilterPillClick);
    });
    document.getElementById('filterPopover')?.addEventListener('click', handleFilterPopoverClick);
    document.getElementById('filterPopover')?.addEventListener('input', handleFilterPopoverInput);
    document.getElementById('filterPopover')?.addEventListener('change', handleFilterPopoverInput);
    document.addEventListener('pointerdown', handleDocumentPointerDown);
    document.addEventListener('keydown', handleDocumentKeyDown);
    window.addEventListener('resize', () => {
        if (!activeFilterPopoverKey) {
            return;
        }

        const buttonId = FILTER_POPOVER_CONFIG[activeFilterPopoverKey]?.buttonId;
        const anchorButton = buttonId ? document.getElementById(buttonId) : null;
        if (anchorButton) {
            positionFilterPopover(anchorButton);
        }
    });
    document.getElementById('closeModalButton').addEventListener('click', closeModal);
    document.querySelectorAll('.sort-button').forEach(button => {
        button.addEventListener('click', handleSortButtonClick);
    });

    document.getElementById('remediationTableBody').addEventListener('click', function(event) {
        if (event.target.closest('a')) return;
        const row = event.target.closest('tr[data-row-index]');
        if (!row) return;
        const index = Number(row.dataset.rowIndex);
        const remediation = remediationAllData[index];
        if (remediation) showDetails(remediation);
    });

    document.getElementById('remediationDetailsTableBody').addEventListener('click', function(event) {
        if (event.target.closest('a')) return;
        const row = event.target.closest('tr[data-row-index]');
        if (!row) return;
        const index = Number(row.dataset.rowIndex);
        const remediation = remediationDetailsAllData[index];
        if (remediation) showRemediationDetails(remediation);
    });

    document.getElementById('impactAnalysisTableBody').addEventListener('click', function(event) {
        if (event.target.closest('a')) return;
        const row = event.target.closest('tr[data-row-index]');
        if (!row) return;
        const index = Number(row.dataset.rowIndex);
        const item = impactAnalysisAllData[index];
        if (item) showImpactAnalysisDetails(item.details);
    });
}

// =============================================================================
// DATE RANGE MANAGEMENT
// =============================================================================

/**
 * Set date range based on preset selection
 * @param {string} range - The range preset (1w, 1m, 3m, 6m, 12m)
 */
function setDateRange(range) {
    filterState = finalizeFilterState(assignDatePreset(cloneFilterState(filterState), range));
    renderFilterPills(filterState);
}

// =============================================================================
// FILTER MANAGEMENT
// =============================================================================

/**
 * Populate all filter dropdowns with unique values from lookups
 * Uses normalized lookups for efficiency instead of iterating all records
 */
function populateFilters() {
    filterState = finalizeFilterState(assignDatePreset(createEmptyFilterState(), '1w'));
    renderFilterPills(filterState);
}

function buildStaticFilterOptions() {
    return {};
}

function updateDeviceSearchSummary(rows = filteredData) {
    return rows;
}

function updateFilterSummary(state = filterState) {
    renderFilterPills(state);
}

/**
 * Populate a checkbox filter container
 * @param {string} containerId - The container element ID
 * @param {Array} values - The values to create checkboxes for
 * @param {string} allLabel - Label for the "All" checkbox
 * @param {Function} onChange - Optional callback for change events
 */
function populateCheckboxes(containerId, values, allLabel, onChange) {
    void containerId;
    void values;
    void allLabel;
    void onChange;
}

/**
 * Fast in-place count update for a cascading filter.
 * Walks the existing DOM items, updating count labels and zero-class styling
 * without tearing down and rebuilding the entire DOM.
 * For filterDeviceName, if the visible set changed (items with count becoming 0
 * or gaining count), falls back to full render by returning false.
 * @param {string} containerId - The filter container ID
 * @param {Map<string, number>} countMap - New device counts
 * @returns {boolean} true if fast update succeeded, false if full render needed
 */
function updateCascadingFilterCounts(containerId, countMap) {
    const container = document.getElementById(containerId);
    const filterEntry = cascadingFilterState[containerId];
    const isSubset = filterEntry.mode === 'subset';
    const isDeviceName = containerId === 'filterDeviceName';
    const items = container.querySelectorAll('.checkbox-item:not(.checkbox-item-all)');

    if (isDeviceName) {
        // For device name, visible set may change when counts flip 0↔non-zero.
        // Count how many options would be visible with new counts.
        const options = cascadingFilterOptions[containerId] || [];
        let newVisible = 0;
        for (let i = 0; i < options.length; i++) {
            const count = countMap.get(options[i].value) || 0;
            const isExplicitlySelected = isSubset && filterEntry.selectedValues.has(options[i].value);
            if (count > 0 || isExplicitlySelected) newVisible++;
        }
        if (newVisible !== items.length) return false; // visible set changed, need full rebuild
    }

    // Walk DOM items and update counts + zero-class in-place
    for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const cb = item.querySelector('input[type="checkbox"]');
        if (!cb || !cb.value) continue;
        const count = countMap.get(cb.value) || 0;
        const countSpan = item.querySelector('.checkbox-count');
        if (countSpan) countSpan.textContent = count;
        if (count === 0) {
            item.classList.add('checkbox-item-zero');
        } else {
            item.classList.remove('checkbox-item-zero');
        }
    }

    return true;
}

/**
 * Render a cascading device filter from explicit UI state and computed counts.
 * @param {string} containerId - The filter container ID
 * @param {Map<string, number>} countMap - Device counts for each option
 */
function renderCascadingFilter(containerId, countMap = new Map()) {
    const container = document.getElementById(containerId);
    const filterGroup = container.parentElement;
    const filterEntry = cascadingFilterState[containerId];
    const options = cascadingFilterOptions[containerId] || [];

    // ── Fast-update path ──
    // If the container already has rendered options, try to update counts in-place
    // instead of tearing down and rebuilding the entire DOM tree.
    if (container._renderedOptions && countMap.size > 0) {
        const fastOk = updateCascadingFilterCounts(containerId, countMap);
        if (fastOk) return;
    }

    const existingSearch = filterGroup.querySelector('.filter-search');
    if (existingSearch) existingSearch.remove();

    if (options.length > 1) {
        filterGroup.setAttribute('data-has-search', 'true');
        const searchInput = document.createElement('input');
        searchInput.type = 'text';
        searchInput.className = 'filter-search';
        searchInput.placeholder = 'Filter...';
        searchInput.id = `${containerId}_search`;
        searchInput.value = filterEntry.searchTerm;
        let searchTimer = null;
        searchInput.addEventListener('input', function() {
            if (searchTimer) clearTimeout(searchTimer);
            const nextTerm = this.value;
            searchTimer = window.setTimeout(() => {
                cascadingFilterState[containerId].searchTerm = nextTerm;
                applyCascadingFilterSearch(containerId);
            }, APPLY_FILTER_DEBOUNCE_MS);
        });
        filterGroup.insertBefore(searchInput, container);
    }

    // Build checkbox HTML via string concatenation — much faster than individual
    // createElement/appendChild calls when the option list is large (e.g. 20K devices).
    const h = [];
    const allChecked = filterEntry.mode === 'all';
    const isSubset = filterEntry.mode === 'subset';
    const allIndeterminate = isSubset && filterEntry.selectedValues.size > 0;
    h.push('<div class="checkbox-item checkbox-item-all"><input type="checkbox" id="',
        containerId, '_all"', allChecked ? ' checked' : '',
        '><label for="', containerId, '_all">',
        escapeHtml(CASCADING_FILTER_CONFIG[containerId].allLabel),
        '</label></div>');

    for (let i = 0; i < options.length; i++) {
        const { value, label: optionLabel, searchText, showCount } = options[i];
        const count = countMap.get(value) || 0;
        const isExplicitlySelected = isSubset && filterEntry.selectedValues.has(value);
        if (containerId === 'filterDeviceName' && count === 0 && !isExplicitlySelected) continue;

        const zeroClass = count === 0 ? ' checkbox-item-zero' : '';
        const filterLabel = (searchText || optionLabel).toLowerCase();
        const checked = allChecked || filterEntry.selectedValues.has(value);
        h.push('<div class="checkbox-item', zeroClass, '" data-filter-label="',
            escapeHtml(filterLabel), '"><input type="checkbox" value="',
            escapeHtml(value), '" id="', containerId, '_', i, '"',
            checked ? ' checked' : '',
            '><label for="', containerId, '_', i,
            '"><span class="checkbox-label-text">', escapeHtml(optionLabel), '</span>');
        if (showCount) {
            h.push('<span class="checkbox-count">', count, '</span>');
        }
        h.push('</label></div>');
    }

    container.innerHTML = h.join('');

    // Remember what we rendered so the fast-update path can compare
    container._renderedOptions = true;

    // Set indeterminate state (cannot be expressed as an HTML attribute)
    if (allIndeterminate) {
        const allCb = container.querySelector(`#${containerId}_all`);
        if (allCb) allCb.indeterminate = true;
    }

    // Attach a single delegated change listener once per container.
    // It survives innerHTML replacements because it is on the container itself.
    if (!container._cascadeDelegation) {
        container._cascadeDelegation = true;
        container.addEventListener('change', function(e) {
            const cb = e.target;
            if (cb.type !== 'checkbox') return;
            if (cb.id === containerId + '_all') {
                setCascadingFilterAllMode(containerId, cb.checked);
            } else {
                toggleCascadingFilterValue(containerId, cb.value, cb.checked);
            }
            scheduleApplyFilters(true);
        });
    }

    applyCascadingFilterSearch(containerId);
}

/**
 * Apply the current search term to a rendered cascading filter.
 * @param {string} containerId - The filter container ID
 */
function applyCascadingFilterSearch(containerId) {
    const container = document.getElementById(containerId);
    const filterEntry = cascadingFilterState[containerId];
    const searchTerm = (filterEntry.searchTerm || '').trim().toLowerCase();
    const items = container.querySelectorAll('.checkbox-item:not(.checkbox-item-all)');

    items.forEach(item => {
        const text = item.dataset.filterLabel || '';
        item.style.display = text.includes(searchTerm) ? 'flex' : 'none';
    });
}

/**
 * Update the "All" checkbox state based on individual checkboxes
 * @param {string} containerId - The container element ID
 */
function updateAllCheckbox(containerId) {
    const container = document.getElementById(containerId);
    const allCheckbox = container.querySelector(`#${containerId}_all`);
    const otherCheckboxes = container.querySelectorAll('input[type="checkbox"]:not(#' + allCheckbox.id + ')');
    const selectableCheckboxes = Array.from(otherCheckboxes).filter(cb => !cb.disabled);
    const checkedCount = selectableCheckboxes.filter(cb => cb.checked).length;
    allCheckbox.checked = selectableCheckboxes.length > 0 && checkedCount === selectableCheckboxes.length;
    allCheckbox.indeterminate = checkedCount > 0 && checkedCount < selectableCheckboxes.length;
}

/**
 * Re-render the cascading device filters using the current explicit state.
 */
function refreshCascadingFilters() {
    const countMaps = cascadingFilterCountCacheKey === filterState.key && cascadingFilterCountCache
        ? cascadingFilterCountCache
        : buildCascadingFilterCountMaps();

    cascadingFilterCountCacheKey = filterState.key;
    cascadingFilterCountCache = countMaps;
    CASCADING_FILTER_IDS.forEach(filterId => {
        renderCascadingFilter(filterId, countMaps[filterId]);
    });
}

/**
 * Build unique-device counts for each cascading filter option.
 * Counts respect date, OS platform, severity, and the other device filters.
 * @returns {Object<string, Map<string, number>>} Option counts by filter
 */
function buildCascadingFilterCountMaps() {
    const deviceSetsByFilter = Object.fromEntries(CASCADING_FILTER_IDS.map(filterId => [
        filterId,
        new Map((cascadingFilterOptions[filterId] || []).map(option => [option.value, new Set()]))
    ]));

    const baseRows = vulnerabilityData.filter(v => {
        if (filterState.startDate && v._effectiveOpenEndDate < filterState.startDate) return false;
        if (filterState.endDate && v._firstSeenDate > filterState.endDate) return false;
        if (filterState.severitySet.size > 0 && !filterState.severitySet.has(v.VulnerabilitySeverityLevel)) return false;
        if (filterState.osPlatformSet.size > 0 && !filterState.osPlatformSet.has(v.OSPlatform)) return false;
        return true;
    });

    baseRows.forEach(v => {
        CASCADING_FILTER_IDS.forEach(targetFilterId => {
            if (!matchesFiltersForFacetCount(v, targetFilterId)) return;

            const deviceKey = v._deviceFilterKey;
            CASCADING_FILTER_CONFIG[targetFilterId].getValuesForVuln(v).forEach(value => {
                if (!deviceSetsByFilter[targetFilterId].has(value)) {
                    deviceSetsByFilter[targetFilterId].set(value, new Set());
                }
                deviceSetsByFilter[targetFilterId].get(value).add(deviceKey);
            });
        });
    });

    return Object.fromEntries(CASCADING_FILTER_IDS.map(filterId => [
        filterId,
        new Map(Array.from(deviceSetsByFilter[filterId].entries()).map(([value, deviceSet]) => [value, deviceSet.size]))
    ]));
}

function matchesFiltersForFacetCount(v, targetFilterId) {
    if (targetFilterId !== 'filterDeviceName' && filterState.deviceNameSet.size > 0 && !filterState.deviceNameSet.has(v._deviceFilterKey)) {
        return false;
    }

    if (targetFilterId !== 'filterRbacGroup' && filterState.rbacGroupSet.size > 0 && !filterState.rbacGroupSet.has(v._normalizedGroup)) {
        return false;
    }

    if (targetFilterId !== 'filterDeviceTags' && filterState.deviceTagSet.size > 0) {
        const vulnTags = v._tagValues;
        if (!vulnTags.some(tag => filterState.deviceTagSet.has(tag))) return false;
    }

    return true;
}

/**
 * Get selected checkbox values from a filter container
 * @param {string} containerId - The container element ID
 * @returns {Array} Array of selected values
 */
function getSelectedCheckboxValues(containerId) {
    const container = document.getElementById(containerId);
    const checkboxes = container.querySelectorAll('input[type="checkbox"]:checked:not(#' + containerId + '_all)');
    return Array.from(checkboxes).map(cb => cb.value);
}

function getSelectedFilterValuesForExport(containerId) {
    switch (containerId) {
        case 'filterRbacGroup':
            return filterState.hasRbacGroups ? [...filterState.rbacGroups] : ['None'];
        case 'filterDeviceTags':
            return filterState.hasDeviceTags ? [...filterState.deviceTags] : ['None'];
        case 'filterOSPlatform':
            return filterState.hasOsPlatforms ? [...filterState.osPlatforms] : ['None'];
        case 'filterSeverity':
            return filterState.hasSeverities ? [...filterState.severities] : ['None'];
        case 'filterDeviceName':
            if (!filterState.hasDeviceNames) {
                return ['None'];
            }
            return filterState.deviceNames.map(value => getFilterOptionLabel('filterDeviceName', value));
        default:
            return [];
    }
}

function getExportFilterText(filterKey, allLabel) {
    const config = FILTER_POPOVER_CONFIG[filterKey];
    if (!config || !config.stateKey) {
        return allLabel;
    }

    if (!filterState[config.hasAnyKey]) {
        return 'None';
    }

    const values = filterState[config.stateKey];
    if (!values || values.length === 0) {
        return allLabel;
    }

    if (filterKey === 'filterDeviceName') {
        return values.map(value => getFilterOptionLabel(filterKey, value)).join(', ');
    }

    return values.join(', ');
}

/**
 * Check if the 'All' checkbox is checked in a filter container
 * @param {string} containerId - The container element ID
 * @returns {boolean} True if the 'All' checkbox is checked
 */
function isAllChecked(containerId) {
    const container = document.getElementById(containerId);
    const allCheckbox = container.querySelector(`#${containerId}_all`);
    return allCheckbox ? allCheckbox.checked : false;
}

/**
 * Check if any checkbox is checked in a filter container
 * @param {string} containerId - The container element ID
 * @returns {boolean} True if any checkbox is checked
 */
function hasAnyChecked(containerId) {
    const container = document.getElementById(containerId);
    const checkboxes = container.querySelectorAll('input[type="checkbox"]:not(#' + containerId + '_all)');
    return Array.from(checkboxes).some(cb => cb.checked);
}

function matchesFilterStateNonDate(v, state = filterState, excludedFilterKey = '') {
    if (state.deviceSearchNormalized && !v._deviceSearchText.includes(state.deviceSearchNormalized)) return false;

    if (excludedFilterKey !== 'filterDeviceName') {
        if (!state.hasDeviceNames) return false;
        if (state.deviceNameSet.size > 0 && !state.deviceNameSet.has(v._deviceFilterKey)) return false;
    }

    if (excludedFilterKey !== 'filterRbacGroup') {
        if (!state.hasRbacGroups) return false;
        if (state.rbacGroupSet.size > 0 && !state.rbacGroupSet.has(v._normalizedGroup)) return false;
    }

    if (excludedFilterKey !== 'filterDeviceTags') {
        if (!state.hasDeviceTags) return false;
        if (state.deviceTagSet.size > 0) {
            const vulnTags = v._tagValues;
            if (!vulnTags.some(tag => state.deviceTagSet.has(tag))) return false;
        }
    }

    if (excludedFilterKey !== 'filterSeverity') {
        if (!state.hasSeverities) return false;
        if (state.severitySet.size > 0 && !state.severitySet.has(v.VulnerabilitySeverityLevel)) return false;
    }

    if (excludedFilterKey !== 'filterOSPlatform') {
        if (!state.hasOsPlatforms) return false;
        if (state.osPlatformSet.size > 0 && !state.osPlatformSet.has(v.OSPlatform)) return false;
    }

    return true;
}

function matchesFilterStateDate(v, state = filterState) {
    if (!state.startDate && !state.endDate) return true;
    if (state.startDate && v._effectiveOpenEndDate < state.startDate) return false;
    if (state.endDate && v._firstSeenDate > state.endDate) return false;
    return true;
}

function matchesFilterState(v, state = filterState) {
    return matchesFilterStateNonDate(v, state) && matchesFilterStateDate(v, state);
}

/**
 * Apply all filters to the vulnerability data.
 * Keeps cascading counts/options aligned with the current full filter state.
 * Uses requestAnimationFrame to yield to the browser before rendering.
 */
function applyFilters() {
    const _t0 = performance.now();
    invalidateAggregateCache();

    if (!filterState.hasDeviceNames || !filterState.hasRbacGroups || !filterState.hasDeviceTags || !filterState.hasSeverities || !filterState.hasOsPlatforms) {
        filteredData = [];
        updateDeviceSearchSummary([]);
        updateFilterSummary(filterState);
        updateStats();
        updateRemediationReportModeUi(activeReportId);
        markAllReportsDirty();
        renderActiveReport(true);
        return;
    }

    const result = [];
    const data = vulnerabilityData;
    const len = data.length;
    const fs = filterState;
    const startDate = fs.startDate;
    const endDate = fs.endDate;
    const hasDateWindow = hasSelectedDateWindow(fs);
    const currentSelectionKey = getCurrentSelectionCacheKey(fs);
    const pointInTimeAsOfDate = hasDateWindow ? '' : getPointInTimeReferenceDate(fs);
    const selectionSeverityCounts = createEmptySeverityCounts();
    const pointInTimeRows = hasDateWindow ? null : [];

    for (let i = 0; i < len; i++) {
        const v = data[i];
        if (startDate && v._effectiveOpenEndDate < startDate) continue;
        if (endDate && v._firstSeenDate > endDate) continue;
        if (!matchesFilterStateNonDate(v, fs)) continue;

        result.push(v);
        if (hasDateWindow) {
            if (selectionSeverityCounts[v.VulnerabilitySeverityLevel] !== undefined) {
                selectionSeverityCounts[v.VulnerabilitySeverityLevel]++;
            }
        } else if (isVulnerabilityActiveOnDate(v, pointInTimeAsOfDate)) {
            pointInTimeRows.push(v);
            if (selectionSeverityCounts[v.VulnerabilitySeverityLevel] !== undefined) {
                selectionSeverityCounts[v.VulnerabilitySeverityLevel]++;
            }
        }
    }

    filteredData = result;
    updateDeviceSearchSummary(result);
    updateFilterSummary(fs);

    const cache = getAggregateCache();
    if (hasDateWindow) {
        cache.activeRowsForCurrentSelectionKey = currentSelectionKey;
        cache.activeRowsForCurrentSelection = result;
    } else {
        cache.activeRowsAsOfDateKey = pointInTimeAsOfDate;
        cache.activeRowsAsOfDate = pointInTimeRows;
        cache.activeRowsForCurrentSelectionKey = currentSelectionKey;
        cache.activeRowsForCurrentSelection = pointInTimeRows;
    }
    cache.selectionSeverityCountsKey = currentSelectionKey;
    cache.selectionSeverityCounts = selectionSeverityCounts;
    updateStats();
    updateRemediationReportModeUi(activeReportId);
    markAllReportsDirty();
    requestAnimationFrame(() => {
        renderActiveReport(true);
        scheduleReportDataWarmup();
    });
    console.log(`[perf] applyFilters: ${(performance.now() - _t0).toFixed(1)}ms  (${result.length}/${len} rows passed)`);
}

// =============================================================================
// STATISTICS
// =============================================================================

/**
 * Update the statistics summary cards
 */
let _statElements = null;
function getStatElements() {
    if (!_statElements) {
        _statElements = {
            critical: document.getElementById('criticalCount'),
            high: document.getElementById('highCount'),
            medium: document.getElementById('mediumCount'),
            low: document.getElementById('lowCount')
        };
    }
    return _statElements;
}

function updateStats() {
    const cache = getAggregateCache();
    const cacheKey = getCurrentSelectionCacheKey();
    let counts = cache.selectionSeverityCountsKey === cacheKey ? cache.selectionSeverityCounts : null;

    if (!counts) {
        counts = createEmptySeverityCounts();
        const statsRows = getActiveRowsForCurrentSelection();
        for (let i = 0, len = statsRows.length; i < len; i++) {
            switch (statsRows[i].VulnerabilitySeverityLevel) {
                case 'Critical': counts.Critical++; break;
                case 'High': counts.High++; break;
                case 'Medium': counts.Medium++; break;
                case 'Low': counts.Low++; break;
            }
        }
        cache.selectionSeverityCountsKey = cacheKey;
        cache.selectionSeverityCounts = counts;
    }

    const els = getStatElements();
    els.critical.textContent = counts.Critical;
    els.high.textContent = counts.High;
    els.medium.textContent = counts.Medium;
    els.low.textContent = counts.Low;
}

/**
 * Render data quality summary for the loaded dataset.
 */
function updateDataQualitySummary() {
    if (!document.querySelector('.data-quality-panel')) return;
    if (!Array.isArray(vulnerabilityData) || vulnerabilityData.length === 0) return;

    const setText = (id, value) => {
        const element = document.getElementById(id);
        if (element) element.textContent = value.toLocaleString();
    };

    setText('dqTotalRecords', dataQualitySummary.totalRecords);
    setText('dqUniqueDevices', dataQualitySummary.uniqueDevices);
    setText('dqUniqueCves', dataQualitySummary.uniqueCves);
    setText('dqMissingPublished', dataQualitySummary.missingPublished);
    setText('dqNonYmdPublished', dataQualitySummary.nonYmdPublished);
    setText('dqInvertedRanges', dataQualitySummary.invertedRanges);
    setText('dqCorrectedRanges', Number(dataQualityMeta.firstLastSwapped || 0));
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Format software name from vendor and product
 * @param {string} vendor - The software vendor
 * @param {string} product - The software product name
 * @returns {string} Formatted software name
 */
function formatSoftwarePart(text) {
    if (!text) return '';

    return String(text)
        .trim()
        .split('_')
        .filter(Boolean)
        .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
        .join(' ');
}

function formatSoftwareName(vendor, product) {
    const vendorPart = formatSoftwarePart(vendor);
    const productPart = formatSoftwarePart(product);

    if (!vendorPart && !productPart) return 'Unknown';
    if (!vendorPart) return productPart;
    if (!productPart) return vendorPart;

    return `${vendorPart} - ${productPart}`;
}

function normalizeOsVersionGroupingLabel(osPlatform, osVersion) {
    const versionText = normalizeRemediationText(osVersion);
    if (!versionText || versionText === 'Unknown') {
        return '';
    }

    const versionParts = versionText
        .split('.')
        .map(part => part.trim())
        .filter(part => /^\d+$/.test(part));

    if (versionParts.length === 0) {
        return versionText;
    }

    const normalizedParts = versionParts.slice(0, Math.min(3, versionParts.length));
    const platformText = normalizeRemediationText(osPlatform).toLowerCase();

    if (!platformText.startsWith('windows')) {
        while (normalizedParts.length > 1 && normalizedParts[normalizedParts.length - 1] === '0') {
            normalizedParts.pop();
        }
    }

    return normalizedParts.join('.');
}

function getVersionAwareSoftwareLabel(software, osPlatform, osVersion, splitByVersion) {
    if (!splitByVersion) {
        return software;
    }

    const versionLabel = normalizeOsVersionGroupingLabel(osPlatform, osVersion);
    if (!versionLabel || !software || software === 'Unknown') {
        return software;
    }

    return `${software} (${versionLabel})`;
}

function getOsFamilyComparisonKey(text) {
    return normalizeRemediationText(text)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '');
}

function shouldSplitRemediationByOsVersion(software, osPlatform) {
    const softwareKey = getOsFamilyComparisonKey(software);
    const platformKey = getOsFamilyComparisonKey(osPlatform);

    if (!softwareKey || !platformKey) {
        return false;
    }

    return softwareKey === platformKey
        || softwareKey.startsWith(platformKey)
        || platformKey.startsWith(softwareKey);
}

function getVersionAwareImpactDisplayName(descriptor, software, osPlatform, osVersion, splitByVersion) {
    const baseName = getScopedRemediationDisplayTitle(descriptor);
    if (!splitByVersion) {
        return baseName;
    }

    const baseSoftwareLabel = formatSoftwarePart(software)
        || normalizeRemediationText(descriptor?.softwareLabel)
        || normalizeRemediationText(descriptor?.scopeLabel)
        || 'Unknown';
    const versionedSoftwareLabel = getVersionAwareSoftwareLabel(baseSoftwareLabel, osPlatform, osVersion, true);

    if (!versionedSoftwareLabel || versionedSoftwareLabel === baseSoftwareLabel) {
        return baseName;
    }

    const separatorIndex = baseName.indexOf(':');
    if (separatorIndex >= 0) {
        const suffix = baseName.slice(separatorIndex + 1).trim();
        return suffix ? `${versionedSoftwareLabel}: ${suffix}` : versionedSoftwareLabel;
    }

    return `${versionedSoftwareLabel}: ${baseName}`;
}

function getPointInTimeReferenceDate(state = filterState) {
    return state.endDate || mostRecentLastSeenDate;
}

function hasSelectedDateWindow(state = filterState) {
    return Boolean(state.startDate || state.endDate);
}

function getCurrentSelectionCacheKey(state = filterState) {
    return hasSelectedDateWindow(state)
        ? `range:${state.startDate || ''}:${state.endDate || ''}`
        : `point:${getPointInTimeReferenceDate(state)}`;
}

function getPointInTimeActiveRows(asOfDate = getPointInTimeReferenceDate()) {
    const cache = getAggregateCache();
    if (cache.activeRowsAsOfDateKey === asOfDate && cache.activeRowsAsOfDate) {
        return cache.activeRowsAsOfDate;
    }

    cache.activeRowsAsOfDateKey = asOfDate;
    cache.activeRowsAsOfDate = filteredData.filter(v => isVulnerabilityActiveOnDate(v, asOfDate));
    return cache.activeRowsAsOfDate;
}

function getActiveRowsForCurrentSelection() {
    const cache = getAggregateCache();
    const cacheKey = getCurrentSelectionCacheKey();

    if (cache.activeRowsForCurrentSelectionKey === cacheKey && cache.activeRowsForCurrentSelection) {
        return cache.activeRowsForCurrentSelection;
    }

    cache.activeRowsForCurrentSelectionKey = cacheKey;
    cache.activeRowsForCurrentSelection = hasSelectedDateWindow()
        ? filteredData
        : getPointInTimeActiveRows();
    return cache.activeRowsForCurrentSelection;
}

function getRemediationReportRows() {
    const cache = getAggregateCache();
    const cacheKey = `${getCurrentSelectionCacheKey()}|${remediationReportMode}`;

    if (cache.remediationReportRowsKey === cacheKey && cache.remediationReportRows) {
        return cache.remediationReportRows;
    }

    cache.remediationReportRowsKey = cacheKey;
    cache.remediationReportRows = (remediationReportMode === REMEDIATION_REPORT_MODE_RANGE && hasSelectedDateWindow())
        ? filteredData
        : getPointInTimeActiveRows();
    return cache.remediationReportRows;
}

function getProvenRemediationRows() {
    const cache = getAggregateCache();
    const cacheKey = filterState.key;
    if (cache.provenRemediationRowsKey === cacheKey && cache.provenRemediationRows) {
        return cache.provenRemediationRows;
    }

    cache.provenRemediationRowsKey = cacheKey;
    cache.provenRemediationRows = filteredData.filter(v => Boolean(v._remediationDate));
    return cache.provenRemediationRows;
}

/**
 * Generate array of dates between start and end
 * @param {string} startDate - Start date in YYYY-MM-DD format
 * @param {string} endDate - End date in YYYY-MM-DD format
 * @returns {Array} Array of date strings
 */
function generateDateRange(startDate, endDate) {
    const sortedDates = [];
    let currentDate = parseYmdDateAsUtc(startDate);
    const end = parseYmdDateAsUtc(endDate);
    
    while (currentDate <= end) {
        sortedDates.push(formatUtcDateAsYmd(currentDate));
        currentDate = addDaysToUtcDate(currentDate, 1);
    }
    return sortedDates;
}

/**
 * Get the next day as a YYYY-MM-DD string
 * @param {string} dateStr - Date in YYYY-MM-DD format
 * @returns {string} Next day in YYYY-MM-DD format
 */
const _nextDayCache = new Map();
function nextDay(dateStr) {
    let result = _nextDayCache.get(dateStr);
    if (result === undefined) {
        result = formatUtcDateAsYmd(addDaysToUtcDate(parseYmdDateAsUtc(dateStr), 1));
        _nextDayCache.set(dateStr, result);
    }
    return result;
}

function addDaysYmd(dateStr, dayCount) {
    if (!dateStr || dateStr === '-') return '';
    const parsed = parseYmdDateAsUtc(dateStr);
    if (Number.isNaN(parsed.getTime())) return '';
    return formatUtcDateAsYmd(addDaysToUtcDate(parsed, dayCount));
}

function parseYmdDateAsUtc(dateStr) {
    const parts = typeof dateStr === 'string' ? dateStr.split('-').map(Number) : [];
    if (parts.length !== 3 || parts.some(part => !Number.isInteger(part))) {
        return new Date(NaN);
    }

    return new Date(Date.UTC(parts[0], parts[1] - 1, parts[2]));
}

function addDaysToUtcDate(date, dayCount) {
    const next = new Date(date.getTime());
    next.setUTCDate(next.getUTCDate() + dayCount);
    return next;
}

function formatUtcDateAsYmd(date) {
    return [
        date.getUTCFullYear(),
        String(date.getUTCMonth() + 1).padStart(2, '0'),
        String(date.getUTCDate()).padStart(2, '0')
    ].join('-');
}

function getMachineLastSeenDate(v) {
    const normalized = formatDateYMD(v?.MachineInfo?.ls || v?.MachineInfo?.lastSeen || '');
    return normalized === '-' ? '' : normalized;
}

function getRowLatestActivityDate(v) {
    const vulnLastSeen = getLastSeenDate(v);
    const machineLastSeen = getMachineLastSeenDate(v);
    if (!machineLastSeen) return vulnLastSeen;
    if (!vulnLastSeen) return machineLastSeen;
    return machineLastSeen > vulnLastSeen ? machineLastSeen : vulnLastSeen;
}

function hasKnownPatchEvidence(v) {
    const vulnLastSeen = getLastSeenDate(v);
    const latestActivity = getRowLatestActivityDate(v);
    return Boolean(vulnLastSeen && latestActivity && latestActivity > vulnLastSeen);
}

function getEffectiveOpenEndDate(v) {
    const vulnLastSeen = getLastSeenDate(v);
    if (!vulnLastSeen) return '';

    const latestActivity = getRowLatestActivityDate(v) || vulnLastSeen;
    if (latestActivity > vulnLastSeen) {
        return vulnLastSeen;
    }

    return addDaysYmd(latestActivity, DEVICE_INACTIVITY_WINDOW_DAYS);
}

function getRemediationDate(v) {
    return hasKnownPatchEvidence(v) ? getLastSeenDate(v) : '';
}

function isVulnerabilityActiveOnDate(v, dateStr) {
    if (!dateStr || dateStr === '-') return false;
    const firstSeen = v._firstSeenDate;
    const effectiveEnd = v._effectiveOpenEndDate;
    if (!firstSeen || !effectiveEnd) return false;
    return firstSeen <= dateStr && effectiveEnd >= dateStr;
}

function applyDerivedVulnerabilityFields(rows) {
    if (!Array.isArray(rows)) return;

    const earliestEnvironmentFirstSeenByIssue = new Map();
    const qualitySummary = createEmptyDataQualitySummary();
    const qualityDeviceKeys = new Set();
    const qualityCveIds = new Set();

    rows.forEach(v => {
        const issueKey = getEnvironmentIssueKey(v);
        const firstSeenDate = getFirstSeenDate(v);
        if (!issueKey || !firstSeenDate) return;

        const existing = earliestEnvironmentFirstSeenByIssue.get(issueKey);
        if (!existing || firstSeenDate < existing) {
            earliestEnvironmentFirstSeenByIssue.set(issueKey, firstSeenDate);
        }
    });

    let _maxLatest = '';
    rows.forEach(v => {
        const machineLastSeenDate = getMachineLastSeenDate(v);
        const latestActivityDate = getRowLatestActivityDate(v);
        if (latestActivityDate > _maxLatest) _maxLatest = latestActivityDate;
        const remediationEvidence = hasKnownPatchEvidence(v);
        const firstSeenDate = getFirstSeenDate(v);
        const lastSeenDate = getLastSeenDate(v);
        const effectiveOpenEndDate = getEffectiveOpenEndDate(v);
        const environmentFirstSeenDate = earliestEnvironmentFirstSeenByIssue.get(getEnvironmentIssueKey(v)) || firstSeenDate;

        v._firstSeenDate = firstSeenDate;
        v._machineLastSeenDate = machineLastSeenDate;
        v._latestActivityDate = latestActivityDate;
        v._hasPatchEvidence = remediationEvidence;
        v._effectiveOpenEndDate = effectiveOpenEndDate;
        v._remediationDate = remediationEvidence ? lastSeenDate : '';
        v._remediationString = buildRemediationString(v);
        v._environmentFirstSeenDate = environmentFirstSeenDate;
        v._deviceFilterKey = v.DeviceId || v.DeviceName || '';
        v._deviceSearchText = `${v.DeviceName || ''} ${v.DeviceId || ''}`.toLowerCase();
        v._normalizedGroup = normalizeGroupName(v.RbacGroupName);
        v._tagValues = v.MachineTags && v.MachineTags.length > 0 ? v.MachineTags : NO_TAGS_ARRAY;

        qualitySummary.totalRecords++;
        if (v._deviceFilterKey) qualityDeviceKeys.add(v._deviceFilterKey);
        if (v.CveId) qualityCveIds.add(v.CveId);

        if (!v.PublishedDate) {
            qualitySummary.missingPublished++;
        } else if (!/^\d{4}-\d{2}-\d{2}$/.test(v.PublishedDate)) {
            qualitySummary.nonYmdPublished++;
        }

        if (firstSeenDate && lastSeenDate && firstSeenDate > lastSeenDate) {
            qualitySummary.invertedRanges++;
        }
    });
    qualitySummary.uniqueDevices = qualityDeviceKeys.size;
    qualitySummary.uniqueCves = qualityCveIds.size;
    dataQualitySummary = qualitySummary;
    mostRecentLastSeenDate = _maxLatest;
}

/**
 * Create segment styling function for dashed lines after cutoff date
 * @param {number} cutoffIdx - Index where data transitions to projected
 * @returns {Object} Segment style configuration
 */
function createSegmentStyle(cutoffIdx) {
    return {
        borderDash: (ctx) => {
            const index = ctx.p0DataIndex;
            return (cutoffIdx !== -1 && index >= cutoffIdx - 1) ? [5, 5] : [];
        }
    };
}

/**
 * Build the active vulnerabilities chart time series.
 * @param {Array} rows
 * @param {string} startDate
 * @param {string} endDate
 * @returns {{sortedDates: Array<string>, severityCounts: Object, totalCounts: Array<number>, deviceCounts: Array<number>}}
 */
function buildActiveChartSeries(rows, startDate, endDate) {
    const sortedDates = generateDateRange(startDate, endDate);
    const severityCounts = createEmptySeveritySeries();
    const totalCounts = [];
    const deviceCounts = [];

    if (!Array.isArray(sortedDates) || sortedDates.length === 0) {
        return {
            sortedDates,
            severityCounts,
            totalCounts,
            deviceCounts
        };
    }

    const chartEvents = new Map();
    const getChartEventBucket = (date) => {
        let bucket = chartEvents.get(date);
        if (!bucket) {
            bucket = {
                totalDelta: 0,
                severityDelta: createEmptySeverityCounts(),
                deviceDeltas: new Map()
            };
            chartEvents.set(date, bucket);
        }
        return bucket;
    };

    rows.forEach(v => {
        const severity = v.VulnerabilitySeverityLevel;
        const rowStartDate = v._firstSeenDate;
        let rowEndDate = nextDay(v._effectiveOpenEndDate);

        if (!rowStartDate || !rowEndDate) {
            return;
        }

        if (rowEndDate <= rowStartDate) {
            rowEndDate = nextDay(rowStartDate);
        }

        const deviceKey = v.DeviceId || v.DeviceName;
        const startBucket = getChartEventBucket(rowStartDate);
        startBucket.totalDelta++;
        if (startBucket.severityDelta[severity] !== undefined) {
            startBucket.severityDelta[severity]++;
        }
        if (deviceKey) {
            startBucket.deviceDeltas.set(deviceKey, (startBucket.deviceDeltas.get(deviceKey) || 0) + 1);
        }

        const endBucket = getChartEventBucket(rowEndDate);
        endBucket.totalDelta--;
        if (endBucket.severityDelta[severity] !== undefined) {
            endBucket.severityDelta[severity]--;
        }
        if (deviceKey) {
            endBucket.deviceDeltas.set(deviceKey, (endBucket.deviceDeltas.get(deviceKey) || 0) - 1);
        }
    });

    let sweepTotal = 0;
    const sweepSeverity = createEmptySeverityCounts();
    const deviceActive = new Map();
    const applyChartEvent = (bucket) => {
        sweepTotal += bucket.totalDelta;
        sweepSeverity.Critical += bucket.severityDelta.Critical;
        sweepSeverity.High += bucket.severityDelta.High;
        sweepSeverity.Medium += bucket.severityDelta.Medium;
        sweepSeverity.Low += bucket.severityDelta.Low;

        bucket.deviceDeltas.forEach((delta, deviceKey) => {
            const nextCount = (deviceActive.get(deviceKey) || 0) + delta;
            if (nextCount <= 0) {
                deviceActive.delete(deviceKey);
            } else {
                deviceActive.set(deviceKey, nextCount);
            }
        });
    };

    const rangeStart = sortedDates[0];
    const allChartDates = [...chartEvents.keys()].sort();
    for (const eventDate of allChartDates) {
        if (eventDate >= rangeStart) break;
        applyChartEvent(chartEvents.get(eventDate));
    }

    sortedDates.forEach(date => {
        const bucket = chartEvents.get(date);
        if (bucket) {
            applyChartEvent(bucket);
        }

        totalCounts.push(sweepTotal);
        deviceCounts.push(deviceActive.size);
        severityCounts.Critical.push(sweepSeverity.Critical);
        severityCounts.High.push(sweepSeverity.High);
        severityCounts.Medium.push(sweepSeverity.Medium);
        severityCounts.Low.push(sweepSeverity.Low);
    });

    return {
        sortedDates,
        severityCounts,
        totalCounts,
        deviceCounts
    };
}

/**
 * Map ExploitabilityLevel to a friendly display name
 * @param {string} level - Raw ExploitabilityLevel value
 * @returns {string} Human-readable exploitability description
 */
function formatExploitLevel(level) {
    switch (level) {
        case 'NoExploit': return 'No known exploits';
        case 'ExploitIsVerified': return 'Exploit verified by vendor';
        case 'ExploitIsPublic': return 'Exploit publicly available';
        case 'ExploitIsInKit': return 'Exploit in attacker toolkits';
        default: return level || '-';
    }
}

/**
 * Format a date string to YYYY-MM-DD, handling ISO ('T') and space-separated timestamps.
 * @param {string|null} dateStr - Raw date string
 * @returns {string} YYYY-MM-DD or '-'
 */
function formatDateYMD(dateStr) {
    if (!dateStr) return '-';
    // Strip time portion from ISO or space-separated timestamps
    const datePart = dateStr.split(/[T ]/)[0];
    // If already YYYY-MM-DD, return as-is
    if (/^\d{4}-\d{2}-\d{2}$/.test(datePart)) return datePart;
    // Handle M/D/YYYY format → YYYY-MM-DD
    const slash = datePart.split('/');
    if (slash.length === 3) {
        return slash[2] + '-' + slash[0].padStart(2, '0') + '-' + slash[1].padStart(2, '0');
    }
    return datePart;
}

function getLookupValue(lookup, index) {
    if (!lookup || index == null || index < 0 || index >= lookup.length) {
        return null;
    }
    return lookup[index];
}

/**
 * Get first-seen date as normalized YYYY-MM-DD (or empty string).
 * @param {Object} v - Vulnerability object
 * @returns {string}
 */
function getFirstSeenDate(v) {
    const normalized = formatDateYMD(v._firstSeenDate || v.FirstSeenTimestamp);
    return normalized === '-' ? '' : normalized;
}

function getEnvironmentIssueKey(v) {
    return [
        v.CveId || '',
        v.SoftwareVendor || '',
        v.SoftwareName || '',
        v.SoftwareVersion || ''
    ].join('|');
}

function getEnvironmentFirstSeenDate(v) {
    const normalized = formatDateYMD(v._environmentFirstSeenDate || v.EnvironmentFirstSeenTimestamp || v._firstSeenDate || v.FirstSeenTimestamp);
    return normalized === '-' ? '' : normalized;
}

/**
 * Get last-seen date as normalized YYYY-MM-DD (or empty string).
 * @param {Object} v - Vulnerability object
 * @returns {string}
 */
function getLastSeenDate(v) {
    const normalized = formatDateYMD(v._lastSeenDate || v.LastSeenTimestamp);
    return normalized === '-' ? '' : normalized;
}

/**
 * Return the most recent date from a list of date-like values, normalized to YYYY-MM-DD.
 * @param {Array<string>} dates
 * @returns {string|null}
 */
function getMostRecentYmdDate(dates) {
    if (!dates || dates.length === 0) return null;
    let maxDate = null;
    for (let i = 0; i < dates.length; i++) {
        const normalized = formatDateYMD(dates[i]);
        if (!normalized || normalized === '-') continue;
        if (!maxDate || normalized > maxDate) {
            maxDate = normalized;
        }
    }
    return maxDate;
}

function getEarliestYmdDate(dates) {
    if (!dates || dates.length === 0) return null;
    let minDate = null;
    for (let i = 0; i < dates.length; i++) {
        const normalized = formatDateYMD(dates[i]);
        if (!normalized || normalized === '-') continue;
        if (!minDate || normalized < minDate) {
            minDate = normalized;
        }
    }
    return minDate;
}

/**
 * Format affected software string for display.
 * Transforms CPE-like strings (e.g., 'microsoft:windows_server_2012_r2')
 * into human-readable format (e.g., 'Microsoft Windows Server 2012 R2').
 * @param {string} softwareStr - Raw software string
 * @returns {string} Formatted software name
 */
function formatAffectedSoftware(softwareStr) {
    if (!softwareStr) return softwareStr;
    
    // Split by colon to separate vendor and product
    const parts = softwareStr.split(':');
    
    // Capitalize first letter of each part and replace underscores with spaces
    const formatted = parts.map(part => {
        return part
            .split('_')
            .map(word => {
                // Special handling for version numbers and abbreviations
                if (/^[0-9]/.test(word)) return word.toUpperCase();
                if (word === 'r2' || word === 'esr' || word === 'esxi') return word.toUpperCase();
                // Capitalize first letter
                return word.charAt(0).toUpperCase() + word.slice(1);
            })
            .join(' ');
    }).join(' ');
    
    return formatted;
}

/**
 * Build remediation string from vulnerability data.
 * Prefers CveBatchTitle as the primary text (groups all CVEs in the same batch).
 * Appends KB number when available. Falls back to RecommendedSecurityUpdate + KB
 * if CveBatchTitle is absent.
 * @param {Object} v - Vulnerability object
 * @returns {string} Formatted remediation string
 */
function buildRemediationString(v) {
    materializeRow(v);
    const kbId = v.RecommendedSecurityUpdateId
        ? (v.RecommendedSecurityUpdateId.toString().startsWith('KB') ? v.RecommendedSecurityUpdateId : 'KB' + v.RecommendedSecurityUpdateId)
        : null;
    // Prefer CveBatchTitle — it groups all CVEs for the same vendor advisory
    if (v.CveBatchTitle) {
        return kbId ? `${v.CveBatchTitle} (${kbId})` : v.CveBatchTitle;
    }
    // Fallback: use RecommendedSecurityUpdate + KB
    if (v.RecommendedSecurityUpdate && kbId) {
        return `${v.RecommendedSecurityUpdate} (${kbId})`;
    } else if (v.RecommendedSecurityUpdate) {
        return v.RecommendedSecurityUpdate;
    } else if (kbId) {
        return kbId;
    }
    return 'Not Specified';
}

function normalizeRemediationText(value) {
    if (value === null || value === undefined) return '';

    const text = String(value).trim();
    if (!text || text.toLowerCase() === 'unknown') {
        return '';
    }

    return text;
}

function normalizeKbId(value, allowNumeric = true) {
    const text = normalizeRemediationText(value);
    if (!text) return '';

    const explicitKbMatch = text.match(/\bKB\d+\b/i);
    if (explicitKbMatch) {
        return explicitKbMatch[0].toUpperCase();
    }

    return allowNumeric && /^\d+$/.test(text) ? 'KB' + text : '';
}

function isNumericRemediationReference(value) {
    return /^\d+$/.test(value) || /^KB\d+$/i.test(value);
}

function isCveRemediationReference(value) {
    return /^CVE-\d{4}-\d+$/i.test(value);
}

function isUrlLikeText(value) {
    return /^https?:\/\//i.test(normalizeRemediationText(value));
}

function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isOpaqueRemediationReference(value) {
    const text = normalizeRemediationText(value);
    return text.includes('_-_');
}

function getFriendlyRecommendationReference(value) {
    const text = normalizeRemediationText(value);
    if (!text || isOpaqueRemediationReference(text)) {
        return '';
    }

    return text;
}

function extractScopedRemediationReference(updateName, scopeLabels) {
    const text = normalizeRemediationText(updateName);
    if (!text || !scopeLabels || scopeLabels.length === 0) {
        return null;
    }

    const labels = Array.from(new Set(scopeLabels
        .map(label => normalizeRemediationText(label))
        .filter(Boolean)));

    for (let i = 0; i < labels.length; i++) {
        const scopeLabel = labels[i];
        const pattern = new RegExp(`^${escapeRegExp(scopeLabel)}\\s*[-:]\\s*(.+)$`, 'i');
        const match = pattern.exec(text);
        if (!match) continue;

        const reference = normalizeRemediationText(match[1]);
        if (!reference) continue;

        if (isNumericRemediationReference(reference)) {
            return {
                scopeLabel: scopeLabel,
                reference: reference,
                title: `${scopeLabel} patch ${reference}`
            };
        }

        if (isCveRemediationReference(reference)) {
            return {
                scopeLabel: scopeLabel,
                reference: reference,
                title: `${scopeLabel} advisory ${reference}`
            };
        }
    }

    return null;
}

function getRemediationDisplayRank(descriptor) {
    if (!descriptor) return 0;
    if (descriptor.advisoryTitle) return 4;
    if (descriptor.scopedUpdateReference) return 3;
    if (descriptor.updateName && !isNumericRemediationReference(descriptor.updateName) && !isCveRemediationReference(descriptor.updateName)) {
        return 3;
    }
    if (descriptor.friendlyRecommendationReference) return 2;
    if (descriptor.kbId || descriptor.updateName || descriptor.recommendationReference) return 1;
    return 0;
}

function shouldPreferRemediationDescriptor(candidate, current) {
    if (!current) return true;

    const candidateRank = candidate.displayRank || 0;
    const currentRank = current.displayRank || 0;
    if (candidateRank !== currentRank) {
        return candidateRank > currentRank;
    }

    if (!!candidate.updateUrl !== !!current.updateUrl) {
        return !!candidate.updateUrl;
    }

    return (candidate.title || '').length > (current.title || '').length;
}

function getRemediationDescriptorObservationKey(descriptor) {
    return normalizeRemediationText(descriptor?.title)
        || normalizeRemediationText(descriptor?.familyTitle)
        || 'Not Specified';
}

function observeRemediationDescriptor(target, descriptor) {
    if (!target || !descriptor) {
        return;
    }

    if (!(target.descriptorObservationMap instanceof Map)) {
        target.descriptorObservationMap = new Map();
    }

    const observationKey = getRemediationDescriptorObservationKey(descriptor);
    const existing = target.descriptorObservationMap.get(observationKey);

    if (!existing) {
        target.descriptorObservationMap.set(observationKey, {
            descriptor: descriptor,
            count: 1
        });
        return;
    }

    existing.count++;
    if (shouldPreferRemediationDescriptor(descriptor, existing.descriptor)) {
        existing.descriptor = descriptor;
    }
}

function getDominantRemediationDescriptor(target) {
    if (!target) {
        return null;
    }

    let dominantDescriptor = target.remediationDescriptor || null;
    let dominantCount = -1;
    const observations = target.descriptorObservationMap instanceof Map
        ? Array.from(target.descriptorObservationMap.values())
        : [];

    observations.forEach(observation => {
        if (!observation || !observation.descriptor) {
            return;
        }

        if (observation.count > dominantCount) {
            dominantDescriptor = observation.descriptor;
            dominantCount = observation.count;
            return;
        }

        if (observation.count === dominantCount && shouldPreferRemediationDescriptor(observation.descriptor, dominantDescriptor)) {
            dominantDescriptor = observation.descriptor;
        }
    });

    return dominantDescriptor;
}

function mergeDescriptorObservationMaps(targetMap, sourceMap) {
    if (!(targetMap instanceof Map) || !(sourceMap instanceof Map)) {
        return;
    }

    sourceMap.forEach((observation, key) => {
        if (!observation || !observation.descriptor) {
            return;
        }

        const existing = targetMap.get(key);
        if (!existing) {
            targetMap.set(key, {
                descriptor: observation.descriptor,
                count: observation.count || 0
            });
            return;
        }

        existing.count += observation.count || 0;
        if (shouldPreferRemediationDescriptor(observation.descriptor, existing.descriptor)) {
            existing.descriptor = observation.descriptor;
        }
    });
}

function mergeRemediationUpdateEntryMaps(targetMap, sourceMap) {
    if (!(targetMap instanceof Map) || !(sourceMap instanceof Map)) {
        return;
    }

    sourceMap.forEach((entry, key) => {
        if (!entry) {
            return;
        }

        const existing = targetMap.get(key);
        if (!existing) {
            targetMap.set(key, {
                referenceText: entry.referenceText,
                referenceUrl: entry.referenceUrl || ''
            });
            return;
        }

        if (!existing.referenceUrl && entry.referenceUrl) {
            existing.referenceUrl = entry.referenceUrl;
        }
    });
}

function getRemediationAdvisoryFamilyMergeKey(target, fallbackKey = '') {
    if (!target) {
        return fallbackKey;
    }

    const descriptor = getDominantRemediationDescriptor(target) || target.remediationDescriptor;
    const recommendationReference = normalizeRemediationText(descriptor?.recommendationReference);
    const advisoryTitle = normalizeRemediationText(descriptor?.advisoryTitle);
    const updateName = normalizeRemediationText(descriptor?.updateName);
    if (!recommendationReference || !advisoryTitle || !updateName) {
        return fallbackKey;
    }

    if (!isCveRemediationReference(updateName) && !isNumericRemediationReference(updateName)) {
        return fallbackKey;
    }

    const datePart = normalizeRemediationText(target?.date);
    const mergeKey = `${recommendationReference}|${advisoryTitle}`;
    return datePart ? `${datePart}|${mergeKey}` : mergeKey;
}

function mergeRemediationObjectBuckets(bucketObject, mergeBucket) {
    const mergedBuckets = {};

    Object.entries(bucketObject || {}).forEach(([key, bucket]) => {
        const mergeKey = getRemediationAdvisoryFamilyMergeKey(bucket, key);
        if (!mergedBuckets[mergeKey]) {
            mergedBuckets[mergeKey] = bucket;
            return;
        }

        mergeBucket(mergedBuckets[mergeKey], bucket);
    });

    return mergedBuckets;
}

function mergeRemediationMapBuckets(bucketMap, mergeBucket) {
    const mergedBuckets = new Map();

    Array.from((bucketMap || new Map()).entries()).forEach(([key, bucket]) => {
        const mergeKey = getRemediationAdvisoryFamilyMergeKey(bucket, key);
        if (!mergedBuckets.has(mergeKey)) {
            mergedBuckets.set(mergeKey, bucket);
            return;
        }

        mergeBucket(mergedBuckets.get(mergeKey), bucket);
    });

    return mergedBuckets;
}

function mergeRemediationDetailMaps(targetMap, sourceMap) {
    if (!(targetMap instanceof Map) || !(sourceMap instanceof Map)) {
        return;
    }

    sourceMap.forEach((detail, key) => {
        if (!detail) {
            return;
        }

        const existing = targetMap.get(key);
        if (!existing) {
            targetMap.set(key, detail);
            return;
        }

        if (detail.firstSeenTimestamp || existing.firstSeenTimestamp) {
            existing.firstSeenTimestamp = getEarliestYmdDate([existing.firstSeenTimestamp, detail.firstSeenTimestamp]);
        }

        if (detail.lastSeenTimestamp || existing.lastSeenTimestamp) {
            existing.lastSeenTimestamp = getMostRecentYmdDate([existing.lastSeenTimestamp, detail.lastSeenTimestamp]);
        }

        if (detail.versions instanceof Set) {
            if (!(existing.versions instanceof Set)) {
                existing.versions = new Set();
            }

            detail.versions.forEach(version => existing.versions.add(version));
        }

        [
            'cveBatchUrl',
            'publishedDate',
            'description',
            'affectedSoftware',
            'severityLevel',
            'cvssScore',
            'epssScore',
            'exploitabilityLevel',
            'softwareVendor',
            'softwareName'
        ].forEach(property => {
            if ((existing[property] === undefined || existing[property] === null || existing[property] === '')
                && detail[property] !== undefined) {
                existing[property] = detail[property];
            }
        });
    });
}

function mergeActiveRemediationBuckets(target, source) {
    mergeDescriptorObservationMaps(target.descriptorObservationMap, source.descriptorObservationMap);
    mergeRemediationUpdateEntryMaps(target.updateEntryMap, source.updateEntryMap);
    source.devices.forEach(device => target.devices.add(device));
    source.vulnerabilities.forEach(vulnerability => target.vulnerabilities.add(vulnerability));
    source.exploits.forEach(exploit => target.exploits.add(exploit));
    source.kits.forEach(kit => target.kits.add(kit));
    target.details.push(...source.details);
    if (shouldPreferRemediationDescriptor(source.remediationDescriptor, target.remediationDescriptor)) {
        target.remediationDescriptor = source.remediationDescriptor;
    }
}

function mergeRemediationDetailsBuckets(target, source) {
    mergeDescriptorObservationMaps(target.descriptorObservationMap, source.descriptorObservationMap);
    mergeRemediationUpdateEntryMaps(target.updateEntryMap, source.updateEntryMap);
    source.devices.forEach(device => target.devices.add(device));
    source.vulnerabilities.forEach(vulnerability => target.vulnerabilities.add(vulnerability));
    target.details.push(...source.details);
    if (shouldPreferRemediationDescriptor(source.remediationDescriptor, target.remediationDescriptor)) {
        target.remediationDescriptor = source.remediationDescriptor;
    }
}

function mergeImpactRemediationBuckets(target, source) {
    mergeDescriptorObservationMaps(target.descriptorObservationMap, source.descriptorObservationMap);
    mergeRemediationUpdateEntryMaps(target.updateEntryMap, source.updateEntryMap);
    source.devices.forEach(device => target.devices.add(device));
    target.vulnerabilities.push(...source.vulnerabilities);
    if (shouldPreferRemediationDescriptor(source.remediationDescriptor, target.remediationDescriptor)) {
        target.remediationDescriptor = source.remediationDescriptor;
    }
}

function mergeDevicesByRemediationBuckets(target, source) {
    mergeDescriptorObservationMaps(target.descriptorObservationMap, source.descriptorObservationMap);
    mergeRemediationUpdateEntryMaps(target.updateEntryMap, source.updateEntryMap);
    source.osPlatforms.forEach(platform => target.osPlatforms.add(platform));
    source.devices.forEach((device, key) => {
        if (!target.devices.has(key)) {
            target.devices.set(key, device);
        }
    });
    source.cves.forEach(cveId => target.cves.add(cveId));
    mergeRemediationDetailMaps(target.cveDetails, source.cveDetails);
    if (shouldPreferRemediationDescriptor(source.remediationDescriptor, target.remediationDescriptor)) {
        target.remediationDescriptor = source.remediationDescriptor;
    }
}

function mergeDeviceRemediationBuckets(target, source) {
    mergeDescriptorObservationMaps(target.descriptorObservationMap, source.descriptorObservationMap);
    mergeRemediationUpdateEntryMaps(target.updateEntryMap, source.updateEntryMap);
    source.cves.forEach(cveId => target.cves.add(cveId));
    mergeRemediationDetailMaps(target.cveDetails, source.cveDetails);
    target.publishedDates.push(...source.publishedDates);
    if (shouldPreferRemediationDescriptor(source.remediationDescriptor, target.remediationDescriptor)) {
        target.remediationDescriptor = source.remediationDescriptor;
    }
}

function getMatchingRemediationUrlFallback(updateName, updateId, advisoryUrl) {
    const normalizedUrl = normalizeRemediationText(advisoryUrl);
    if (!normalizedUrl) {
        return '';
    }

    const lowerUrl = normalizedUrl.toLowerCase();
    const tokens = Array.from(new Set([
        normalizeKbId(updateId),
        normalizeRemediationText(updateId),
        normalizeRemediationText(updateName)
    ].filter(Boolean).map(token => token.toLowerCase())));

    if (tokens.length === 0) {
        return '';
    }

    return tokens.some(token => lowerUrl.includes(token) || lowerUrl.includes(encodeURIComponent(token)))
        ? normalizedUrl
        : '';
}

function getCompactRemediationTitle(descriptor) {
    if (!descriptor) return 'Not Specified';

    if (descriptor.advisoryTitle) {
        return descriptor.familyTitle;
    }

    if (descriptor.scopedUpdateReference) {
        return descriptor.familyTitle;
    }

    if (descriptor.kbId) {
        return descriptor.familyTitle;
    }

    if (descriptor.updateName && !isOpaqueRemediationReference(descriptor.updateName)) {
        return descriptor.familyTitle;
    }

    if (descriptor.friendlyRecommendationReference) {
        return descriptor.familyTitle;
    }

    return descriptor.title;
}

function getRemediationFamilyKey(recommendationReference, advisoryTitle, updateName, kbId, friendlyRecommendationReference, scopeLabel) {
    const familyIdentity = updateName
        || advisoryTitle
        || kbId
        || friendlyRecommendationReference
        || recommendationReference
        || scopeLabel
        || 'Not Specified';

    if (recommendationReference && familyIdentity && familyIdentity !== recommendationReference) {
        return `${recommendationReference}|${familyIdentity}`;
    }

    return familyIdentity;
}

function buildRemediationDescriptor(v) {
    materializeRow(v);

    const rawVendor = normalizeRemediationText(v.SoftwareVendor);
    const rawSoftware = normalizeRemediationText(v.SoftwareName);
    const advisoryTitle = normalizeRemediationText(v.CveBatchTitle);
    const updateName = normalizeRemediationText(v.RecommendedSecurityUpdate);
    const updateId = normalizeRemediationText(v.RecommendedSecurityUpdateId);
    const kbId = normalizeKbId(updateId) || normalizeKbId(updateName, false) || normalizeKbId(v.RecommendedSecurityUpdateUrl, false);
    const updateUrl = normalizeRemediationText(v.RecommendedSecurityUpdateUrl)
        || getMatchingRemediationUrlFallback(updateName, updateId, v.CveBatchUrl);
    const osPlatform = normalizeRemediationText(v.OSPlatform) || 'Unknown';
    const recommendationReference = normalizeRemediationText(v.RecommendationReference);
    const vendorPart = formatSoftwarePart(rawVendor);
    const productPart = formatSoftwarePart(rawSoftware);
    const productLabel = formatSoftwareName(v.SoftwareVendor, v.SoftwareName);
    const scopeLabel = productPart || productLabel || vendorPart || 'Unknown';
    const friendlyRecommendationReference = getFriendlyRecommendationReference(recommendationReference);
    const combinedProductLabel = [vendorPart, productPart].filter(Boolean).join(' ');
    const scopedUpdateReference = extractScopedRemediationReference(updateName, [combinedProductLabel, productLabel, scopeLabel, vendorPart]);
    const scopeKey = recommendationReference
        || [rawVendor, rawSoftware].filter(Boolean).join('|')
        || scopeLabel;
    const familyKey = getRemediationFamilyKey(
        recommendationReference,
        advisoryTitle,
        updateName,
        kbId,
        friendlyRecommendationReference,
        scopeLabel
    );
    const familyTitle = advisoryTitle
        || friendlyRecommendationReference
        || (scopedUpdateReference ? scopedUpdateReference.reference : '')
        || updateName
        || kbId
        || recommendationReference
        || 'Not Specified';

    let title = familyTitle;
    if (scopeLabel !== 'Unknown') {
        const lowerScopeLabel = scopeLabel.toLowerCase();
        const lowerProductLabel = productLabel.toLowerCase();
        if (advisoryTitle) {
            title = advisoryTitle.toLowerCase().includes(lowerScopeLabel)
                || (productLabel && advisoryTitle.toLowerCase().includes(lowerProductLabel))
                ? advisoryTitle
                : `${scopeLabel}: ${advisoryTitle}`;
        } else if (scopedUpdateReference) {
            title = scopedUpdateReference.title;
        } else if (updateName) {
            if (isNumericRemediationReference(updateName)) {
                title = `${scopeLabel} patch ${updateName}`;
            } else if (isCveRemediationReference(updateName)) {
                title = `${scopeLabel} advisory ${updateName}`;
            } else if (updateName.toLowerCase().includes(lowerScopeLabel)
                || (productLabel && updateName.toLowerCase().includes(lowerProductLabel))) {
                title = updateName;
            } else {
                title = `${scopeLabel}: ${updateName}`;
            }
        } else if (kbId) {
            title = `${scopeLabel} patch ${kbId}`;
        } else if (friendlyRecommendationReference && friendlyRecommendationReference !== scopeLabel) {
            title = friendlyRecommendationReference.toLowerCase().includes(lowerScopeLabel)
                || (productLabel && friendlyRecommendationReference.toLowerCase().includes(lowerProductLabel))
                ? friendlyRecommendationReference
                : `${scopeLabel}: ${friendlyRecommendationReference}`;
        } else {
            title = scopeLabel;
        }
    }

    let patchReference = '';
    if (kbId && !remediationTitleIncludesReference(title, kbId) && !remediationTitleIncludesReference(familyTitle, kbId)) {
        patchReference = kbId;
    } else if (scopedUpdateReference) {
        patchReference = scopedUpdateReference.reference !== familyTitle ? scopedUpdateReference.reference : '';
    } else if (updateName && updateName !== familyTitle && !isUrlLikeText(updateName)) {
        patchReference = updateName;
    }

    const descriptor = {
        key: `${scopeKey}|${familyKey}`,
        title: title,
        familyKey: familyKey,
        familyTitle: familyTitle,
        productLabel: productLabel,
        vendorLabel: vendorPart,
        softwareLabel: productPart,
        rawVendor: rawVendor,
        rawSoftware: rawSoftware,
        scopeLabel: scopeLabel,
        patchReference: patchReference,
        updateName: updateName || 'Unknown',
        updateId: updateId,
        updateUrl: updateUrl,
        osPlatform: osPlatform,
        advisoryTitle: advisoryTitle,
        kbId: kbId,
        recommendationReference: recommendationReference,
        friendlyRecommendationReference: friendlyRecommendationReference,
        scopedUpdateReference: scopedUpdateReference
    };

    descriptor.displayRank = getRemediationDisplayRank(descriptor);

    return descriptor;
}

function buildRemediationTitleHtml(text, url) {
    if (!text) {
        return '-';
    }

    if (url) {
        return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)}</a>`;
    }

    return escapeHtml(text);
}

function buildRemediationReferenceHtml(referenceText, referenceUrl) {
    if (!referenceText) {
        return '-';
    }

    return buildRemediationUpdateBadgeHtml(referenceText, referenceUrl);
}

function getRemediationUpdateReferenceText(remediation) {
    if (!remediation) {
        return '';
    }

    if (remediation.kbId) {
        return remediation.kbId;
    }

    if (remediation.patchReference) {
        return remediation.patchReference;
    }

    if (remediation.updateName && remediation.updateName !== 'Unknown' && !isUrlLikeText(remediation.updateName)) {
        return remediation.updateName;
    }

    if (remediation.updateUrl || isUrlLikeText(remediation.updateName)) {
        return 'Update Details';
    }

    return '';
}

function addRemediationUpdateEntry(updateEntryMap, remediation) {
    if (!(updateEntryMap instanceof Map) || !remediation) {
        return;
    }

    let referenceText = normalizeRemediationText(getRemediationUpdateReferenceText(remediation));
    let referenceUrl = normalizeRemediationText(remediation.updateUrl);

    if (!referenceUrl && isUrlLikeText(remediation.updateName)) {
        referenceUrl = normalizeRemediationText(remediation.updateName);
    }

    if (!referenceUrl && /^KB\d+$/i.test(referenceText)) {
        referenceUrl = `https://catalog.update.microsoft.com/v7/site/Search.aspx?q=${encodeURIComponent(referenceText.toUpperCase())}`;
    }

    if (!referenceText && referenceUrl) {
        referenceText = 'Update Details';
    }

    if (!referenceText && !referenceUrl) {
        return;
    }

    const entryKey = referenceText || referenceUrl;
    const existing = updateEntryMap.get(entryKey);

    if (!existing) {
        updateEntryMap.set(entryKey, {
            referenceText: referenceText || 'Update Details',
            referenceUrl: referenceUrl || '',
            observationCount: 1
        });
        return;
    }

    existing.observationCount = (existing.observationCount || 0) + 1;

    if (!existing.referenceUrl && referenceUrl) {
        existing.referenceUrl = referenceUrl;
    }
}

function finalizeRemediationUpdateEntries(updateEntryMap) {
    const entries = Array.from((updateEntryMap || new Map()).values())
        .filter(entry => entry && entry.referenceText)
        .map(entry => ({
            referenceText: entry.referenceText,
            referenceUrl: entry.referenceUrl || '',
            observationCount: entry.observationCount > 0 ? entry.observationCount : 1
        }));

    let filteredEntries = entries;
    const kbEntries = entries.filter(entry => /^KB\d+$/i.test(entry.referenceText || ''));
    if (entries.length > 1 && kbEntries.length === entries.length) {
        const sortedByCount = [...entries].sort((a, b) => b.observationCount - a.observationCount);
        const dominantEntry = sortedByCount[0];
        const totalObservations = sortedByCount.reduce((sum, entry) => sum + entry.observationCount, 0);

        if (dominantEntry && totalObservations > 0 && (dominantEntry.observationCount / totalObservations) >= 0.9) {
            filteredEntries = sortedByCount.filter(entry => entry.observationCount === dominantEntry.observationCount);
        }
    }

    return filteredEntries
        .sort((a, b) => {
            const referenceCompare = a.referenceText.localeCompare(
                b.referenceText,
                undefined,
                { numeric: true, sensitivity: 'base' }
            );

            if (referenceCompare !== 0) {
                return referenceCompare;
            }

            return (a.referenceUrl || '').localeCompare(
                b.referenceUrl || '',
                undefined,
                { numeric: true, sensitivity: 'base' }
            );
        })
        .map(entry => ({
            referenceText: entry.referenceText,
            referenceUrl: entry.referenceUrl || ''
        }));
}

function summarizeRemediationUpdateEntries(updateEntries) {
    return summarizeRemediationReferences(
        new Set((updateEntries || []).map(entry => entry.referenceText).filter(Boolean))
    );
}

function getSingleRemediationUpdateUrlFromEntries(updateEntries) {
    const entries = (updateEntries || []).filter(entry => entry && entry.referenceText);

    if (entries.length !== 1) {
        return '';
    }

    return entries[0].referenceUrl || '';
}

function remediationTitleIncludesReference(title, referenceText) {
    if (!title || !referenceText) {
        return false;
    }

    const normalizedTitle = normalizeRemediationText(title).toLowerCase();
    const normalizedReference = normalizeRemediationText(referenceText).toLowerCase();

    return normalizedTitle === normalizedReference
        || normalizedTitle.endsWith(normalizedReference)
        || normalizedTitle.endsWith(`: ${normalizedReference}`)
        || normalizedTitle.endsWith(` patch ${normalizedReference}`)
        || normalizedTitle.endsWith(` advisory ${normalizedReference}`)
        || normalizedTitle.includes(`(${normalizedReference})`);
}

function getRemediationTitleWithReferenceSuffix(title, updateEntries) {
    const entries = (updateEntries || []).filter(entry => entry && /^KB\d+$/i.test(entry.referenceText || ''));

    if (entries.length !== 1) {
        return title;
    }

    const kbId = entries[0].referenceText;
    if (remediationTitleIncludesReference(title, kbId)) {
        return title;
    }

    return `${title} (${kbId})`;
}

function buildRemediationUpdateBadgeHtml(referenceText, referenceUrl, prefix = '') {
    const badgeText = prefix ? `${prefix}${referenceText}` : referenceText;

    if (referenceUrl) {
        return `<a href="${escapeHtml(referenceUrl)}" target="_blank" rel="noopener noreferrer" class="stat-badge remediation-update-badge">
                 <span>${escapeHtml(badgeText)}</span>
                 <svg class="link-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                     <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                     <polyline points="15 3 21 3 21 9"></polyline>
                     <line x1="10" y1="14" x2="21" y2="3"></line>
                 </svg>
               </a>`;
    }

    return `<span class="stat-badge">${escapeHtml(badgeText)}</span>`;
}

function buildRemediationUpdateBadgesHtml(updateEntries, prefix = '', containerClass = 'remediation-update-entry-list') {
    const entries = (updateEntries || []).filter(entry => entry && entry.referenceText);

    if (entries.length === 0) {
        return '';
    }

    return `<div class="${escapeHtml(containerClass)}">${entries.map(entry => buildRemediationUpdateBadgeHtml(entry.referenceText, entry.referenceUrl, prefix)).join('')}</div>`;
}

function buildRemediationUpdateCellHtml(updateEntries, fallbackText = '', fallbackUrl = '') {
    const entries = (updateEntries || []).filter(entry => entry && entry.referenceText);

    if (entries.length === 0) {
        return fallbackText
            ? buildRemediationReferenceHtml(fallbackText, fallbackUrl)
            : '-';
    }

    if (entries.length === 1) {
        return buildRemediationReferenceHtml(entries[0].referenceText, entries[0].referenceUrl);
    }

    return buildRemediationUpdateBadgesHtml(entries);
}

function buildRemediationCellHtml(title, titleUrl, updateEntries) {
    const entries = (updateEntries || []).filter(entry => entry && entry.referenceText);
    const titleHtml = buildRemediationTitleHtml(title, '');

    if (entries.length === 0) {
        return titleHtml;
    }

    return `<div class="remediation-title-with-updates"><div>${titleHtml}</div>${buildRemediationUpdateBadgesHtml(entries, 'Patch: ')}</div>`;
}

function buildRemediationTitleCellHtml(title, titleUrl = '') {
    return buildRemediationTitleHtml(title, titleUrl);
}

function stripLeadingRemediationPrefix(title, prefix) {
    const text = normalizeRemediationText(title);
    const normalizedPrefix = normalizeRemediationText(prefix);

    if (!text || !normalizedPrefix) {
        return text;
    }

    const scopedPattern = new RegExp(`^${escapeRegExp(normalizedPrefix)}\\s*[:\\-]\\s*`, 'i');
    if (scopedPattern.test(text)) {
        return normalizeRemediationText(text.replace(scopedPattern, ''));
    }

    const wordPattern = new RegExp(`^${escapeRegExp(normalizedPrefix)}\\s+`, 'i');
    if (wordPattern.test(text)) {
        return normalizeRemediationText(text.replace(wordPattern, ''));
    }

    return text;
}

function getRemediationTitlePrefixCandidates(descriptor) {
    if (!descriptor) {
        return [];
    }

    return Array.from(new Set([
        descriptor.scopeLabel,
        descriptor.productLabel,
        descriptor.softwareLabel,
        descriptor.vendorLabel,
        descriptor.rawSoftware,
        descriptor.rawVendor
    ].map(value => normalizeRemediationText(value)).filter(Boolean)));
}

function stripLeadingRemediationPrefixes(title, prefixes) {
    let cleanedTitle = normalizeRemediationText(title);
    if (!cleanedTitle) {
        return cleanedTitle;
    }

    (prefixes || []).forEach(prefix => {
        cleanedTitle = stripLeadingRemediationPrefix(cleanedTitle, prefix) || cleanedTitle;
    });

    return cleanedTitle;
}

function getScopedRemediationDisplayTitle(descriptor) {
    if (!descriptor) {
        return 'Not Specified';
    }

    const title = normalizeRemediationText(descriptor.title) || 'Not Specified';
    const prefixCandidates = getRemediationTitlePrefixCandidates(descriptor);
    const vendorLabel = normalizeRemediationText(descriptor.vendorLabel);
    const softwareLabel = normalizeRemediationText(descriptor.softwareLabel);
    const scopeLabel = normalizeRemediationText(descriptor.scopeLabel);
    const advisoryTitle = normalizeRemediationText(descriptor.advisoryTitle);
    if (!vendorLabel || !title.includes(':')) {
        if (advisoryTitle
            && title === advisoryTitle
            && (!softwareLabel || softwareLabel === vendorLabel || scopeLabel === vendorLabel)) {
            return title;
        }

        return stripLeadingRemediationPrefixes(title, prefixCandidates) || title;
    }

    const separatorIndex = title.indexOf(':');
    const scopePrefix = title.slice(0, separatorIndex).trim();
    const scopedTitle = title.slice(separatorIndex + 1).trim();
    const withoutVendor = stripLeadingRemediationPrefixes(scopedTitle, prefixCandidates);

    return withoutVendor ? `${scopePrefix}: ${withoutVendor}` : title;
}

function getActiveRemediationTableTitle(descriptor) {
    if (!descriptor) {
        return 'Not Specified';
    }

    const baseTitle = normalizeRemediationText(getCompactRemediationTitle(descriptor))
        || normalizeRemediationText(descriptor.familyTitle)
        || normalizeRemediationText(descriptor.title)
        || 'Not Specified';
    const cleanedTitle = stripLeadingRemediationPrefixes(baseTitle, getRemediationTitlePrefixCandidates(descriptor));

    return cleanedTitle || baseTitle;
}

function buildSeparatedRemediationUpdateDisplay(title, descriptor, updateEntries) {
    const normalizedTitle = normalizeRemediationText(title);
    const entries = (updateEntries || []).filter(entry => entry && entry.referenceText);

    if (entries.length === 0) {
        const fallbackText = normalizeRemediationText(getRemediationUpdateReferenceText(descriptor));
        const fallbackUrl = normalizeRemediationText(descriptor?.updateUrl);

        if (!fallbackText) {
            return {
                value: '',
                html: '-'
            };
        }

        if (!fallbackUrl && remediationTitleIncludesReference(normalizedTitle, fallbackText)) {
            return {
                value: '',
                html: '-'
            };
        }

        return {
            value: fallbackText,
            html: buildRemediationReferenceHtml(fallbackText, fallbackUrl)
        };
    }

    if (entries.length === 1) {
        const [entry] = entries;

        if (!entry.referenceUrl && remediationTitleIncludesReference(normalizedTitle, entry.referenceText)) {
            return {
                value: '',
                html: '-'
            };
        }

        return {
            value: entry.referenceText,
            html: buildRemediationReferenceHtml(entry.referenceText, entry.referenceUrl)
        };
    }

    return {
        value: summarizeRemediationUpdateEntries(entries),
        html: buildRemediationUpdateBadgesHtml(entries)
    };
}

function buildRemediationModalUpdateLinksHtml(updateEntries) {
    const badgesHtml = buildRemediationUpdateBadgesHtml(updateEntries, 'Patch: ');

    if (!badgesHtml) {
        return '';
    }

    return `<div class="modal-update-link-row"><strong>Update Details:</strong>${badgesHtml}</div>`;
}

function buildRemediationUpdateEntriesFromDetails(details) {
    const updateEntryMap = new Map();

    (details || []).forEach(detail => {
        addRemediationUpdateEntry(updateEntryMap, buildRemediationDescriptor(detail));
    });

    return finalizeRemediationUpdateEntries(updateEntryMap);
}

function summarizeRemediationReferences(referenceSet) {
    const values = Array.from(referenceSet || [])
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));

    if (values.length === 0) {
        return '';
    }

    if (values.length === 1) {
        return values[0];
    }

    if (values.length === 2) {
        return `${values[0]}, ${values[1]}`;
    }

    return `${values[0]} +${values.length - 1} more`;
}

function summarizeRemediationPlatforms(platformSet) {
    const values = Array.from(platformSet || [])
        .map(value => normalizeRemediationText(value))
        .filter(value => value && value !== 'Unknown')
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));

    if (values.length === 0) {
        return '';
    }

    if (values.length === 1) {
        return values[0];
    }

    if (values.length === 2) {
        return `${values[0]}, ${values[1]}`;
    }

    return `${values[0]}, ${values[1]} +${values.length - 2} more`;
}

function getSingleRemediationUpdateUrl(urlSet, referenceSet) {
    const urls = Array.from(urlSet || []).filter(Boolean);
    const references = Array.from(referenceSet || []).filter(Boolean);

    if (urls.length !== 1 || references.length !== 1) {
        return '';
    }

    return urls[0];
}

/**
 * Build remediation HTML with link from vulnerability data.
 * Returns an <a> tag linking to RecommendedSecurityUpdateUrl when available,
 * otherwise returns plain escaped text.
 * @param {Object} v - Vulnerability object (or any object with RecommendedSecurityUpdate/Id/Url)
 * @returns {string} HTML string for the remediation cell
 */
function buildRemediationHtml(v) {
    const remediation = buildRemediationDescriptor(v);
    const updateEntryMap = new Map();
    addRemediationUpdateEntry(updateEntryMap, remediation);
    return buildRemediationCellHtml(
        remediation.title,
        remediation.updateUrl,
        finalizeRemediationUpdateEntries(updateEntryMap)
    );
}

// =============================================================================
// ACTIVE VULNERABILITIES CHART
// =============================================================================

/**
 * Render the main vulnerability chart with custom styling
 */
function renderChart() {
    const canvas = document.getElementById('vulnerabilityChart');
    if (!canvas) return;
    
    const context = canvas.getContext('2d');
    
    const { startDate, endDate } = filterState;
    
    if (!startDate || !endDate) {
        logDebug('No date range selected');
        return;
    }

    // Check chart data cache — reuse sweep-line result when filter state is unchanged
    const cacheKey = filterState.key + '|' + mostRecentLastSeenDate;
    let sortedDates, severityCounts, totalCounts, deviceCounts;

    if (chartDataCacheKey === cacheKey && chartDataCache) {
        sortedDates = chartDataCache.sortedDates;
        severityCounts = chartDataCache.severityCounts;
        totalCounts = chartDataCache.totalCounts;
        deviceCounts = chartDataCache.deviceCounts;
    } else {
        chartDataCache = buildActiveChartSeries(filteredData, startDate, endDate);
        chartDataCacheKey = cacheKey;
        sortedDates = chartDataCache.sortedDates;
        severityCounts = chartDataCache.severityCounts;
        totalCounts = chartDataCache.totalCounts;
        deviceCounts = chartDataCache.deviceCounts;
    }

    const cutoffIndex = sortedDates.findIndex(date => date > mostRecentLastSeenDate);
    const dataArrays = [severityCounts.Critical, severityCounts.High, severityCounts.Medium, severityCounts.Low, totalCounts, deviceCounts];

    if (chartInstance && chartInstance.data.datasets.length === dataArrays.length) {
        chartInstance.data.labels = sortedDates;
        dataArrays.forEach((arr, idx) => {
            chartInstance.data.datasets[idx].data = arr;
            chartInstance.data.datasets[idx].segment = createSegmentStyle(cutoffIndex);
        });
        chartInstance.update('none');
    } else {
        if (chartInstance) chartInstance.destroy();
        try {
            chartInstance = new Chart(context, {
            type: 'line',
            data: {
                labels: sortedDates,
                datasets: [
                    {
                        label: 'Critical',
                        data: severityCounts.Critical,
                        borderColor: '#d13438',
                        backgroundColor: 'rgba(209, 52, 56, 0.3)',
                        tension: 0.3,
                        yAxisID: 'y',
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'High',
                        data: severityCounts.High,
                        borderColor: '#ff6b35',
                        backgroundColor: 'rgba(255, 107, 53, 0.3)',
                        tension: 0.3,
                        yAxisID: 'y',
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Medium',
                        data: severityCounts.Medium,
                        borderColor: '#ffa500',
                        backgroundColor: 'rgba(255, 165, 0, 0.3)',
                        tension: 0.3,
                        yAxisID: 'y',
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Low',
                        data: severityCounts.Low,
                        borderColor: '#4caf50',
                        backgroundColor: 'rgba(76, 175, 80, 0.3)',
                        tension: 0.3,
                        yAxisID: 'y',
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Total',
                        data: totalCounts,
                        borderColor: '#9c27b0',
                        backgroundColor: 'rgba(156, 39, 176, 0.3)',
                        tension: 0.3,
                        yAxisID: 'y',
                        borderWidth: 3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex),
                        hidden: true
                    },
                    {
                        label: 'Devices',
                        data: deviceCounts,
                        borderColor: '#000000',
                        backgroundColor: 'rgba(0, 0, 0, 0.2)',
                        tension: 0.3,
                        yAxisID: 'y1',
                        borderWidth: 2,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex)
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Open Vulnerabilities Over Time',
                        font: { size: 16 }
                    },
                    legend: {
                        position: 'top'
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            footer: function(tooltipItems) {
                                const dateIndex = tooltipItems[0].dataIndex;
                                const date = sortedDates[dateIndex];
                                if (cutoffIndex !== -1 && dateIndex >= cutoffIndex) {
                                    return '\n⚠ Projected data (no recent scans)';
                                }
                                return '';
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        stacked: false,
                        title: {
                            display: true,
                            text: 'Vulnerabilities'
                        },
                        position: 'left'
                    },
                    y1: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Devices'
                        },
                        position: 'right',
                        grid: {
                            drawOnChartArea: false
                        }
                    }
                }
            }
        });
        } catch (error) {
            console.error('Error creating vulnerability chart:', error);
        }
    }
}

// =============================================================================
// ACTIVE VULNERABILITIES TABLE
// =============================================================================

function getRemediationTableData() {
    const cache = getAggregateCache();
    if (cache.remediationTableData) return cache.remediationTableData;

    const remediationMap = {};
    const activeRows = getActiveRowsForCurrentSelection();
    const remediationDescriptors = new Array(activeRows.length);
    const versionBucketsByBaseKey = new Map();

    const formatCache = new Map();
    const formatPart = (text) => {
        if (!text) return 'Unknown';
        let result = formatCache.get(text);
        if (result === undefined) {
            result = text.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()).join(' ');
            formatCache.set(text, result);
        }
        return result;
    };

    for (let i = 0, len = activeRows.length; i < len; i++) {
        const v = activeRows[i];
        const remediation = buildRemediationDescriptor(v);
        const vendor = formatPart(v.SoftwareVendor);
        const software = formatPart(v.SoftwareName);
        const baseKey = `${vendor}|${software}|${remediation.key}`;
        const canSplitByOsVersion = shouldSplitRemediationByOsVersion(software, v.OSPlatform);
        const versionBucket = normalizeOsVersionGroupingLabel(v.OSPlatform, v.OSVersion);

        remediationDescriptors[i] = remediation;

        if (!canSplitByOsVersion || !versionBucket) {
            continue;
        }

        let versionBuckets = versionBucketsByBaseKey.get(baseKey);
        if (!versionBuckets) {
            versionBuckets = new Set();
            versionBucketsByBaseKey.set(baseKey, versionBuckets);
        }

        versionBuckets.add(versionBucket);
    }

    for (let i = 0, len = activeRows.length; i < len; i++) {
        const v = activeRows[i];
        const remediation = remediationDescriptors[i];
        const compactRemediation = getCompactRemediationTitle(remediation);
        const vendor = formatPart(v.SoftwareVendor);
        const software = formatPart(v.SoftwareName);
        const baseKey = `${vendor}|${software}|${remediation.key}`;
        const splitByVersion = shouldSplitRemediationByOsVersion(software, v.OSPlatform)
            && (versionBucketsByBaseKey.get(baseKey)?.size || 0) > 1;
        const softwareLabel = getVersionAwareSoftwareLabel(software, v.OSPlatform, v.OSVersion, splitByVersion);
        const key = splitByVersion ? `${baseKey}|${softwareLabel}` : baseKey;

        if (!remediationMap[key]) {
            remediationMap[key] = {
                vendor: vendor,
                software: softwareLabel,
                remediationDescriptor: remediation,
                descriptorObservationMap: new Map(),
                remediation: compactRemediation,
                modalTitle: remediation.title,
                updateEntryMap: new Map(),
                devices: new Set(),
                vulnerabilities: new Set(),
                exploits: new Set(),
                kits: new Set(),
                details: [],
                _modalCache: null
            };
        }

        const entry = remediationMap[key];
        observeRemediationDescriptor(entry, remediation);
        addRemediationUpdateEntry(entry.updateEntryMap, remediation);
        entry.devices.add(v.DeviceId || v.DeviceName);
        entry.vulnerabilities.add(v.CveId);

        if (v.ExploitabilityLevel === 'ExploitIsVerified' || v.ExploitabilityLevel === 'ExploitIsPublic' || v.ExploitabilityLevel === 'ExploitIsInKit') {
            entry.exploits.add(v.CveId);
        }

        if (v.ExploitabilityLevel === 'ExploitIsInKit') {
            entry.kits.add(v.CveId);
        }

        entry.details.push(v);
    }

    const mergedRemediationMap = mergeRemediationObjectBuckets(remediationMap, mergeActiveRemediationBuckets);

    cache.remediationTableData = Object.values(mergedRemediationMap)
        .map(data => {
            data.remediationDescriptor = getDominantRemediationDescriptor(data) || data.remediationDescriptor;
            data.updateEntries = finalizeRemediationUpdateEntries(data.updateEntryMap);
            data.updateUrl = getSingleRemediationUpdateUrlFromEntries(data.updateEntries) || data.remediationDescriptor.updateUrl;
            data.remediation = getActiveRemediationTableTitle(data.remediationDescriptor);
            const modalBaseTitle = data.software && data.software !== 'Unknown'
                ? `${data.software}: ${data.remediation}`
                : getScopedRemediationDisplayTitle(data.remediationDescriptor);
            data.modalTitle = getRemediationTitleWithReferenceSuffix(modalBaseTitle, data.updateEntries);
            data.remediationHtml = buildRemediationTitleCellHtml(data.remediation);
            const updateDisplay = buildSeparatedRemediationUpdateDisplay(data.remediation, data.remediationDescriptor, data.updateEntries);
            data.updateValue = updateDisplay.value;
            data.updateHtml = updateDisplay.html;
            delete data.descriptorObservationMap;
            delete data.updateEntryMap;
            return data;
        })
        .sort((a, b) => b.vulnerabilities.size - a.vulnerabilities.size);

    return cache.remediationTableData;
}

function getRemediationDetailsData() {
    const cache = getAggregateCache();
    if (cache.remediationDetailsData) return cache.remediationDetailsData;

    const remediationByDate = {};
    const remediationRows = getProvenRemediationRows();

    remediationRows.forEach(v => {
        const lastSeenDate = v._remediationDate;
        const remediation = buildRemediationDescriptor(v);
        const key = `${lastSeenDate}|${remediation.key}`;

        if (!remediationByDate[key]) {
            remediationByDate[key] = {
                date: lastSeenDate,
                remediationDescriptor: remediation,
                descriptorObservationMap: new Map(),
                remediation: remediation.title,
                updateEntryMap: new Map(),
                devices: new Set(),
                vulnerabilities: new Set(),
                details: [],
                _modalCache: null
            };
        }

        observeRemediationDescriptor(remediationByDate[key], remediation);
        addRemediationUpdateEntry(remediationByDate[key].updateEntryMap, remediation);
        remediationByDate[key].devices.add(getDeviceIdentityKey(v));
        remediationByDate[key].vulnerabilities.add(v.CveId);
        remediationByDate[key].details.push(v);
    });

    const mergedRemediationByDate = mergeRemediationObjectBuckets(remediationByDate, mergeRemediationDetailsBuckets);

    cache.remediationDetailsData = Object.values(mergedRemediationByDate)
        .map(data => {
            data.remediationDescriptor = getDominantRemediationDescriptor(data) || data.remediationDescriptor;
            data.updateEntries = finalizeRemediationUpdateEntries(data.updateEntryMap);
            data.updateUrl = getSingleRemediationUpdateUrlFromEntries(data.updateEntries) || data.remediationDescriptor.updateUrl;
            data.remediation = getScopedRemediationDisplayTitle(data.remediationDescriptor);
            data.remediationHtml = buildRemediationTitleCellHtml(data.remediation);
            const updateDisplay = buildSeparatedRemediationUpdateDisplay(data.remediation, data.remediationDescriptor, data.updateEntries);
            data.updateValue = updateDisplay.value;
            data.updateHtml = updateDisplay.html;
            delete data.descriptorObservationMap;
            delete data.updateEntryMap;
            return data;
        })
        .sort((a, b) => b.date.localeCompare(a.date));

    return cache.remediationDetailsData;
}

function getRemediationChartData() {
    const { startDate, endDate } = filterState;
    if (!startDate || !endDate) {
        return null;
    }

    const cache = getAggregateCache();
    const cacheKey = filterState.key + '|' + mostRecentLastSeenDate;
    if (cache.remediationChartDataKey === cacheKey && cache.remediationChartData) {
        return cache.remediationChartData;
    }

    const sortedDates = generateDateRange(startDate, endDate);
    const severityCounts = createEmptySeveritySeries();
    const totalRemediationCounts = [];
    const deviceCounts = [];
    const remediationIndex = new Map();

    getProvenRemediationRows().forEach(v => {
        const lastSeenDate = v._remediationDate;
        if (!remediationIndex.has(lastSeenDate)) remediationIndex.set(lastSeenDate, []);
        remediationIndex.get(lastSeenDate).push(v);
    });

    sortedDates.forEach(date => {
        if (date > mostRecentLastSeenDate) {
            severityCounts.Critical.push(0);
            severityCounts.High.push(0);
            severityCounts.Medium.push(0);
            severityCounts.Low.push(0);
            totalRemediationCounts.push(0);
            deviceCounts.push(0);
            return;
        }

        const vulnsOnDate = remediationIndex.get(date);
        if (!vulnsOnDate) {
            severityCounts.Critical.push(0);
            severityCounts.High.push(0);
            severityCounts.Medium.push(0);
            severityCounts.Low.push(0);
            totalRemediationCounts.push(0);
            deviceCounts.push(0);
            return;
        }

        const remediationsOnDate = new Set();
        const devicesOnDate = new Set();
        const severityRemediations = createEmptySeverityCounts();

        vulnsOnDate.forEach(v => {
            remediationsOnDate.add(v._index);
            devicesOnDate.add(getDeviceIdentityKey(v));
            if (severityRemediations[v.VulnerabilitySeverityLevel] !== undefined) {
                severityRemediations[v.VulnerabilitySeverityLevel]++;
            }
        });

        severityCounts.Critical.push(severityRemediations.Critical);
        severityCounts.High.push(severityRemediations.High);
        severityCounts.Medium.push(severityRemediations.Medium);
        severityCounts.Low.push(severityRemediations.Low);
        totalRemediationCounts.push(remediationsOnDate.size);
        deviceCounts.push(devicesOnDate.size);
    });

    cache.remediationChartDataKey = cacheKey;
    cache.remediationChartData = {
        sortedDates,
        severityCounts,
        totalRemediationCounts,
        deviceCounts
    };

    return cache.remediationChartData;
}

function getImpactAnalysisData() {
    const cache = getAggregateCache();
    if (cache.impactData) return cache.impactData;

    const remediationMap = {};
    const activeRows = getActiveRowsForCurrentSelection();
    const remediationDescriptors = new Array(activeRows.length);
    const versionBucketsByBaseKey = new Map();

    for (let i = 0, len = activeRows.length; i < len; i++) {
        const v = activeRows[i];
        const remediation = buildRemediationDescriptor(v);
        const formattedSoftware = formatSoftwarePart(v.SoftwareName);
        const baseKey = remediation.key;
        const canSplitByOsVersion = shouldSplitRemediationByOsVersion(formattedSoftware, v.OSPlatform);
        const versionBucket = normalizeOsVersionGroupingLabel(v.OSPlatform, v.OSVersion);

        remediationDescriptors[i] = remediation;

        if (!canSplitByOsVersion || !versionBucket) {
            continue;
        }

        let versionBuckets = versionBucketsByBaseKey.get(baseKey);
        if (!versionBuckets) {
            versionBuckets = new Set();
            versionBucketsByBaseKey.set(baseKey, versionBuckets);
        }

        versionBuckets.add(versionBucket);
    }

    activeRows.forEach((v, index) => {
        const remediation = remediationDescriptors[index];
        const formattedSoftware = formatSoftwarePart(v.SoftwareName);
        const baseKey = remediation.key;
        const splitByVersion = shouldSplitRemediationByOsVersion(formattedSoftware, v.OSPlatform)
            && (versionBucketsByBaseKey.get(baseKey)?.size || 0) > 1;
        const impactName = getVersionAwareImpactDisplayName(remediation, formattedSoftware, v.OSPlatform, v.OSVersion, splitByVersion);
        const key = splitByVersion ? `${baseKey}|${impactName}` : baseKey;

        if (!remediationMap[key]) {
            remediationMap[key] = {
                remediationDescriptor: remediation,
                descriptorObservationMap: new Map(),
                name: impactName,
                updateEntryMap: new Map(),
                devices: new Set(),
                vulnerabilities: []
            };
        }

        observeRemediationDescriptor(remediationMap[key], remediation);
        addRemediationUpdateEntry(remediationMap[key].updateEntryMap, remediation);
        remediationMap[key].devices.add(getDeviceIdentityKey(v));
        remediationMap[key].vulnerabilities.push(v);
    });

    const mergedRemediationMap = mergeRemediationObjectBuckets(remediationMap, mergeImpactRemediationBuckets);

    const top25 = Object.values(mergedRemediationMap)
        .map(data => ({
            remediationDescriptor: getDominantRemediationDescriptor(data) || data.remediationDescriptor,
            name: data.name,
            updateEntries: finalizeRemediationUpdateEntries(data.updateEntryMap),
            impact: data.devices.size * new Set(data.vulnerabilities.map(v => v.CveId)).size,
            vulnerabilities: data.vulnerabilities
        }))
        .map(data => {
            const name = data.name || getScopedRemediationDisplayTitle(data.remediationDescriptor);
            const updateDisplay = buildSeparatedRemediationUpdateDisplay(name, data.remediationDescriptor, data.updateEntries);
            return {
                name: name,
                nameHtml: buildRemediationTitleCellHtml(name),
                updateEntries: data.updateEntries,
                updateValue: updateDisplay.value,
                updateHtml: updateDisplay.html,
                impact: data.impact,
                vulnerabilities: data.vulnerabilities
            };
        })
        .sort((a, b) => b.impact - a.impact)
        .slice(0, 25);

    const top25VulnIds = new Set();
    top25.forEach(rem => {
        rem.vulnerabilities.forEach(v => {
            top25VulnIds.add(v._index);
        });
    });

    cache.impactData = {
        top25,
        top25VulnIds
    };

    return cache.impactData;
}

function getImpactAnalysisTableData() {
    const cache = getAggregateCache();
    if (cache.impactAnalysisTableData) return cache.impactAnalysisTableData;

    const { top25 } = getImpactAnalysisData();
    cache.impactAnalysisTableData = top25.map((item, index) => {
        const cveIds = new Set(item.vulnerabilities.map(v => v.CveId));
        const devices = new Set(item.vulnerabilities.map(v => getDeviceIdentityKey(v)));
        return {
            rank: index + 1,
            name: item.name,
            nameHtml: item.nameHtml || escapeHtml(item.name),
            updateValue: item.updateValue || '',
            updateHtml: item.updateHtml || '-',
            devices: devices.size,
            cveIds: cveIds.size,
            impact: item.impact,
            details: item
        };
    });

    return cache.impactAnalysisTableData;
}

function getImpactChartData() {
    const { startDate, endDate } = filterState;
    if (!startDate || !endDate) {
        return null;
    }

    const cache = getAggregateCache();
    const cacheKey = filterState.key + '|' + mostRecentLastSeenDate;
    if (cache.impactChartDataKey === cacheKey && cache.impactChartData) {
        return cache.impactChartData;
    }

    const { top25VulnIds } = getImpactAnalysisData();
    const sortedDates = generateDateRange(startDate, endDate);
    const series = buildImpactChartSeries(filteredData, top25VulnIds, sortedDates);

    cache.impactChartDataKey = cacheKey;
    cache.impactChartData = {
        sortedDates,
        ...series
    };

    return cache.impactChartData;
}

function updateTableSortState(tableId, activeColumnIndex, ascending) {
    const headers = document.querySelectorAll(`#${tableId} thead th`);
    headers.forEach((header, index) => {
        header.setAttribute(
            'aria-sort',
            index === activeColumnIndex ? (ascending ? 'ascending' : 'descending') : 'none'
        );
    });
}

/**
 * Render the remediation table
 */
function renderTable() {
    const tbody = document.getElementById('remediationTableBody');
    tbody.innerHTML = '';

    remediationAllData = getRemediationTableData().slice();

    // Reset loaded count and render initial batch
    remediationLoadedCount = 0;
    
    renderRemediationTablePage();
}

/**
 * Render remediation table (initial load or full refresh)
 */
function renderRemediationTablePage() {
    const tbody = document.getElementById('remediationTableBody');
    tbody.innerHTML = '';
    
    if (remediationExpanded) {
        appendRemediationRows(tbody, 0, remediationAllData.length);
        remediationLoadedCount = remediationAllData.length;
    } else {
        const endIdx = Math.min(TABLE_PAGE_SIZE, remediationAllData.length);
        appendRemediationRows(tbody, 0, endIdx);
        remediationLoadedCount = endIdx;
    }
    
    updateRemediationScrollInfo();
}

/**
 * Create a remediation table row
 */
function createRemediationRow(rem, index) {
    const row = document.createElement('tr');
    row.dataset.rowIndex = String(index);
    row.innerHTML = `
        <td>${rem.vendor}</td>
        <td>${rem.software}</td>
        <td>${rem.remediationHtml}</td>
        <td class="update-details-column">${rem.updateHtml}</td>
        <td>${rem.devices.size}</td>
        <td>${rem.vulnerabilities.size}</td>
        <td>${rem.exploits.size}</td>
        <td>${rem.kits.size}</td>
    `;
    return row;
}

function appendRemediationRows(tbody, startIdx, endIdx) {
    const fragment = document.createDocumentFragment();
    for (let i = startIdx; i < endIdx; i++) {
        fragment.appendChild(createRemediationRow(remediationAllData[i], i));
    }
    tbody.appendChild(fragment);
}

/**
 * Load more remediation rows on scroll
 */
function loadMoreRemediationRows() {
    const tbody = document.getElementById('remediationTableBody');
    const startIdx = remediationLoadedCount;
    const endIdx = Math.min(startIdx + TABLE_PAGE_SIZE, remediationAllData.length);

    appendRemediationRows(tbody, startIdx, endIdx);
    
    remediationLoadedCount = endIdx;
    updateRemediationScrollInfo();
}

/**
 * Update remediation scroll info
 */
function updateRemediationScrollInfo() {
    const scrollInfo = document.getElementById('remediationScrollInfo');
    
    if (remediationExpanded) {
        scrollInfo.textContent = `Showing all ${remediationAllData.length} rows`;
    } else {
        scrollInfo.textContent = `Showing ${remediationLoadedCount} of ${remediationAllData.length}`;
    }
}

/**
 * Expand/collapse all remediation rows
 */
function expandAllRemediationRows() {
    remediationExpanded = !remediationExpanded;
    renderRemediationTablePage();
}

/**
 * Sort the remediation table by column
 * @param {number} columnIndex - The column index to sort by
 */
function sortTable(columnIndex) {
    sortDirection[columnIndex] = !sortDirection[columnIndex];
    const ascending = sortDirection[columnIndex];

    remediationAllData.sort((a, b) => {
        let aValue, bValue;
        switch(columnIndex) {
            case 0: aValue = a.vendor; bValue = b.vendor; break;
            case 1: aValue = a.software; bValue = b.software; break;
            case 2: aValue = a.remediation; bValue = b.remediation; break;
            case 3: aValue = a.updateValue || ''; bValue = b.updateValue || ''; break;
            case 4: aValue = a.devices.size; bValue = b.devices.size; break;
            case 5: aValue = a.vulnerabilities.size; bValue = b.vulnerabilities.size; break;
            case 6: aValue = a.exploits.size; bValue = b.exploits.size; break;
            case 7: aValue = a.kits.size; bValue = b.kits.size; break;
        }

        if (aValue < bValue) return ascending ? -1 : 1;
        if (aValue > bValue) return ascending ? 1 : -1;
        return 0;
    });

    // Reset scroll and re-render
    remediationLoadedCount = 0;
    renderRemediationTablePage();
    updateTableSortState('remediationTable', columnIndex, ascending);
}

// =============================================================================
// REMEDIATION ACTIVITY CHART
// =============================================================================

/**
 * Render remediation chart with custom styling
 */
function renderRemediationChart() {
    const canvas = document.getElementById('remediationChart');
    if (!canvas) return;
    
    const context = canvas.getContext('2d');
    
    const { startDate, endDate } = filterState;
    
    if (!startDate || !endDate) {
        logDebug('No date range selected for remediation chart');
        return;
    }
    const chartData = getRemediationChartData();
    const { sortedDates, severityCounts, totalRemediationCounts, deviceCounts } = chartData;
    
    // Find the index where we transition from actual data to projected (dashed) data
    const cutoffIndex = sortedDates.findIndex(date => date > mostRecentLastSeenDate);
    const remDataArrays = [severityCounts.Critical, severityCounts.High, severityCounts.Medium, severityCounts.Low, totalRemediationCounts, deviceCounts];

    if (remediationChartInstance && remediationChartInstance.data.datasets.length === remDataArrays.length) {
        remediationChartInstance.data.labels = sortedDates;
        remDataArrays.forEach((arr, idx) => {
            remediationChartInstance.data.datasets[idx].data = arr;
            remediationChartInstance.data.datasets[idx].segment = createSegmentStyle(cutoffIndex);
        });
        remediationChartInstance.update('none');
    } else {
        if (remediationChartInstance) remediationChartInstance.destroy();
        try {
            remediationChartInstance = new Chart(context, {
            type: 'line',
            data: {
                labels: sortedDates,
                datasets: [
                    {
                        label: 'Critical',
                        data: severityCounts.Critical,
                        borderColor: '#d13438',
                        backgroundColor: 'rgba(209, 52, 56, 0.3)',
                        tension: 0.3,
                        yAxisID: 'y',
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'High',
                        data: severityCounts.High,
                        borderColor: '#ff6b35',
                        backgroundColor: 'rgba(255, 107, 53, 0.3)',
                        tension: 0.3,
                        yAxisID: 'y',
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Medium',
                        data: severityCounts.Medium,
                        borderColor: '#ffa500',
                        backgroundColor: 'rgba(255, 165, 0, 0.3)',
                        tension: 0.3,
                        yAxisID: 'y',
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Low',
                        data: severityCounts.Low,
                        borderColor: '#4caf50',
                        backgroundColor: 'rgba(76, 175, 80, 0.3)',
                        tension: 0.3,
                        yAxisID: 'y',
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Total Remediations',
                        data: totalRemediationCounts,
                        borderColor: '#9c27b0',
                        backgroundColor: 'rgba(156, 39, 176, 0.3)',
                        tension: 0.3,
                        yAxisID: 'y',
                        borderWidth: 3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex),
                        hidden: true
                    },
                    {
                        label: 'Devices',
                        data: deviceCounts,
                        borderColor: '#000000',
                        backgroundColor: 'rgba(0, 0, 0, 0.2)',
                        tension: 0.3,
                        yAxisID: 'y1',
                        borderWidth: 2,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex)
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Remediation Activity Over Time',
                        font: { size: 16 }
                    },
                    legend: {
                        position: 'top'
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        stacked: false,
                        title: {
                            display: true,
                            text: 'Remediations'
                        },
                        position: 'left'
                    },
                    y1: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Devices'
                        },
                        position: 'right',
                        grid: {
                            drawOnChartArea: false
                        }
                    }
                }
            }
        });
        } catch (error) {
            console.error('Error creating remediation chart:', error);
        }
    }
}

// =============================================================================
// REMEDIATION DETAILS TABLE
// =============================================================================

/**
 * Render the remediation details table
 */
function renderRemediationDetailsTable() {
    const tbody = document.getElementById('remediationDetailsTableBody');
    tbody.innerHTML = '';
    remediationDetailsAllData = getRemediationDetailsData().slice();
    
    // Reset loaded count and render initial batch
    remediationDetailsLoadedCount = 0;
    
    renderRemediationDetailsTablePage();
}

/**
 * Render remediation details table (initial load or full refresh)
 */
function renderRemediationDetailsTablePage() {
    const tbody = document.getElementById('remediationDetailsTableBody');
    tbody.innerHTML = '';
    
    if (remediationDetailsExpanded) {
        appendRemediationDetailsRows(tbody, 0, remediationDetailsAllData.length);
        remediationDetailsLoadedCount = remediationDetailsAllData.length;
    } else {
        const endIdx = Math.min(TABLE_PAGE_SIZE, remediationDetailsAllData.length);
        appendRemediationDetailsRows(tbody, 0, endIdx);
        remediationDetailsLoadedCount = endIdx;
    }
    
    updateRemediationDetailsScrollInfo();
}

/**
 * Append a single row to the remediation details table
 */
function createRemediationDetailsRow(data, index) {
    const total = data.devices.size * data.vulnerabilities.size;
    const row = document.createElement('tr');
    row.dataset.rowIndex = String(index);
    row.innerHTML = `
        <td>${data.date}</td>
        <td>${data.remediationHtml}</td>
        <td class="update-details-column">${data.updateHtml}</td>
        <td>${data.devices.size}</td>
        <td>${data.vulnerabilities.size}</td>
        <td>${total}</td>
    `;
    return row;
}

function appendRemediationDetailsRows(tbody, startIdx, endIdx) {
    const fragment = document.createDocumentFragment();
    for (let i = startIdx; i < endIdx; i++) {
        fragment.appendChild(createRemediationDetailsRow(remediationDetailsAllData[i], i));
    }
    tbody.appendChild(fragment);
}

/**
 * Load more remediation details rows on scroll
 */
function loadMoreRemediationDetailsRows() {
    const tbody = document.getElementById('remediationDetailsTableBody');
    const startIdx = remediationDetailsLoadedCount;
    const endIdx = Math.min(startIdx + TABLE_PAGE_SIZE, remediationDetailsAllData.length);

    appendRemediationDetailsRows(tbody, startIdx, endIdx);
    
    remediationDetailsLoadedCount = endIdx;
    updateRemediationDetailsScrollInfo();
}

/**
 * Update remediation details scroll info
 */
function updateRemediationDetailsScrollInfo() {
    const scrollInfo = document.getElementById('remediationDetailsScrollInfo');
    
    if (remediationDetailsExpanded) {
        scrollInfo.textContent = `Showing all ${remediationDetailsAllData.length} rows`;
    } else {
        scrollInfo.textContent = `Showing ${remediationDetailsLoadedCount} of ${remediationDetailsAllData.length}`;
    }
}

/**
 * Expand/collapse all remediation details rows
 */
function expandAllRemediationDetailsRows() {
    remediationDetailsExpanded = !remediationDetailsExpanded;
    renderRemediationDetailsTablePage();
}

/**
 * Sort the remediation details table by column
 * @param {number} columnIndex - The column index to sort by
 */
function sortRemediationDetailsTable(columnIndex) {
    sortRemediationDetailsDirection[columnIndex] = !sortRemediationDetailsDirection[columnIndex];
    const ascending = sortRemediationDetailsDirection[columnIndex];

    remediationDetailsAllData.sort((a, b) => {
        let aValue, bValue;
        switch(columnIndex) {
            case 0: aValue = a.date; bValue = b.date; break;
            case 1: aValue = a.remediation; bValue = b.remediation; break;
            case 2: aValue = a.updateValue || ''; bValue = b.updateValue || ''; break;
            case 3: aValue = a.devices.size; bValue = b.devices.size; break;
            case 4: aValue = a.vulnerabilities.size; bValue = b.vulnerabilities.size; break;
            case 5: aValue = a.devices.size * a.vulnerabilities.size; bValue = b.devices.size * b.vulnerabilities.size; break;
        }

        if (aValue < bValue) return ascending ? -1 : 1;
        if (aValue > bValue) return ascending ? 1 : -1;
        return 0;
    });

    // Reset scroll and re-render
    remediationDetailsLoadedCount = 0;
    renderRemediationDetailsTablePage();
    updateTableSortState('remediationDetailsTable', columnIndex, ascending);
}

// =============================================================================
// IMPACT ANALYSIS CHART
// =============================================================================

/**
 * Build the impact chart time series for current and projected counts.
 * @param {Array} rows
 * @param {Set<number>} top25VulnIds
 * @param {Array<string>} sortedDates
 * @returns {{currentSeverityCounts: Object, projectedSeverityCounts: Object, currentTotalCounts: Array<number>, projectedTotalCounts: Array<number>}}
 */
function buildImpactChartSeries(rows, top25VulnIds, sortedDates) {
    const currentSeverityCounts = createEmptySeveritySeries();
    const projectedSeverityCounts = createEmptySeveritySeries();
    const currentTotalCounts = [];
    const projectedTotalCounts = [];

    if (!Array.isArray(sortedDates) || sortedDates.length === 0) {
        return {
            currentSeverityCounts,
            projectedSeverityCounts,
            currentTotalCounts,
            projectedTotalCounts
        };
    }

    const impactEvents = new Map();
    const getImpactEventBucket = (date) => {
        let bucket = impactEvents.get(date);
        if (!bucket) {
            bucket = {
                currentStartTotal: 0,
                currentEndTotal: 0,
                projectedStartTotal: 0,
                projectedEndTotal: 0,
                currentStarts: createEmptySeverityCounts(),
                currentEnds: createEmptySeverityCounts(),
                projectedStarts: createEmptySeverityCounts(),
                projectedEnds: createEmptySeverityCounts()
            };
            impactEvents.set(date, bucket);
        }
        return bucket;
    };

    rows.forEach(v => {
        const severity = v.VulnerabilitySeverityLevel;
        const isTop25 = top25VulnIds.has(v._index);
        const startDate = v._firstSeenDate;
        let endDate = nextDay(v._effectiveOpenEndDate);

        if (endDate <= startDate) {
            endDate = nextDay(startDate);
        }

        const startBucket = getImpactEventBucket(startDate);
        startBucket.currentStartTotal++;
        if (startBucket.currentStarts[severity] !== undefined) {
            startBucket.currentStarts[severity]++;
        }

        const endBucket = getImpactEventBucket(endDate);
        endBucket.currentEndTotal++;
        if (endBucket.currentEnds[severity] !== undefined) {
            endBucket.currentEnds[severity]++;
        }

        if (!isTop25) {
            startBucket.projectedStartTotal++;
            if (startBucket.projectedStarts[severity] !== undefined) {
                startBucket.projectedStarts[severity]++;
            }

            endBucket.projectedEndTotal++;
            if (endBucket.projectedEnds[severity] !== undefined) {
                endBucket.projectedEnds[severity]++;
            }
        }
    });

    let sweepCurrentTotal = 0;
    let sweepProjectedTotal = 0;
    const sweepCurrentSev = createEmptySeverityCounts();
    const sweepProjectedSev = createEmptySeverityCounts();
    const applyImpactEvent = (bucket) => {
        sweepCurrentTotal += bucket.currentStartTotal - bucket.currentEndTotal;
        sweepProjectedTotal += bucket.projectedStartTotal - bucket.projectedEndTotal;

        sweepCurrentSev.Critical += bucket.currentStarts.Critical - bucket.currentEnds.Critical;
        sweepCurrentSev.High += bucket.currentStarts.High - bucket.currentEnds.High;
        sweepCurrentSev.Medium += bucket.currentStarts.Medium - bucket.currentEnds.Medium;
        sweepCurrentSev.Low += bucket.currentStarts.Low - bucket.currentEnds.Low;

        sweepProjectedSev.Critical += bucket.projectedStarts.Critical - bucket.projectedEnds.Critical;
        sweepProjectedSev.High += bucket.projectedStarts.High - bucket.projectedEnds.High;
        sweepProjectedSev.Medium += bucket.projectedStarts.Medium - bucket.projectedEnds.Medium;
        sweepProjectedSev.Low += bucket.projectedStarts.Low - bucket.projectedEnds.Low;
    };

    const rangeStart = sortedDates[0];
    const allImpactDates = [...impactEvents.keys()].sort();
    for (const eventDate of allImpactDates) {
        if (eventDate >= rangeStart) break;
        applyImpactEvent(impactEvents.get(eventDate));
    }

    sortedDates.forEach(date => {
        const bucket = impactEvents.get(date);
        if (bucket) {
            applyImpactEvent(bucket);
        }

        currentTotalCounts.push(sweepCurrentTotal);
        projectedTotalCounts.push(sweepProjectedTotal);
        currentSeverityCounts.Critical.push(sweepCurrentSev.Critical);
        currentSeverityCounts.High.push(sweepCurrentSev.High);
        currentSeverityCounts.Medium.push(sweepCurrentSev.Medium);
        currentSeverityCounts.Low.push(sweepCurrentSev.Low);
        projectedSeverityCounts.Critical.push(sweepProjectedSev.Critical);
        projectedSeverityCounts.High.push(sweepProjectedSev.High);
        projectedSeverityCounts.Medium.push(sweepProjectedSev.Medium);
        projectedSeverityCounts.Low.push(sweepProjectedSev.Low);
    });

    return {
        currentSeverityCounts,
        projectedSeverityCounts,
        currentTotalCounts,
        projectedTotalCounts
    };
}

/**
 * Render the impact analysis chart
 */
/**
 * Render impact chart with custom styling
 */
function renderImpactChart() {
    const canvas = document.getElementById('impactChart');
    if (!canvas) return;
    
    const context = canvas.getContext('2d');
    
    const { startDate, endDate } = filterState;
    
    if (!startDate || !endDate) {
        logDebug('No date range selected for impact chart');
        return;
    }
    const {
        sortedDates,
        currentSeverityCounts,
        projectedSeverityCounts,
        currentTotalCounts,
        projectedTotalCounts
    } = getImpactChartData();
    
    // Find the index where we transition from actual data to projected (dashed) data
    const cutoffIndex = sortedDates.findIndex(date => date > mostRecentLastSeenDate);
    const impactDataArrays = [
        currentSeverityCounts.Critical, currentSeverityCounts.High, currentSeverityCounts.Medium, currentSeverityCounts.Low, currentTotalCounts,
        projectedSeverityCounts.Critical, projectedSeverityCounts.High, projectedSeverityCounts.Medium, projectedSeverityCounts.Low, projectedTotalCounts
    ];

    if (impactChartInstance && impactChartInstance.data.datasets.length === impactDataArrays.length) {
        impactChartInstance.data.labels = sortedDates;
        impactDataArrays.forEach((arr, idx) => {
            impactChartInstance.data.datasets[idx].data = arr;
            impactChartInstance.data.datasets[idx].segment = createSegmentStyle(cutoffIndex);
        });
        impactChartInstance.update('none');
    } else {
        if (impactChartInstance) impactChartInstance.destroy();
        try {
            impactChartInstance = new Chart(context, {
            type: 'line',
            data: {
                labels: sortedDates,
                datasets: [
                    {
                        label: 'Current - Critical',
                        data: currentSeverityCounts.Critical,
                        borderColor: '#d13438',
                        backgroundColor: 'rgba(209, 52, 56, 0.3)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        borderWidth: 2,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Current - High',
                        data: currentSeverityCounts.High,
                        borderColor: '#ff6b35',
                        backgroundColor: 'rgba(255, 107, 53, 0.3)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        borderWidth: 2,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Current - Medium',
                        data: currentSeverityCounts.Medium,
                        borderColor: '#ffa500',
                        backgroundColor: 'rgba(255, 165, 0, 0.3)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        borderWidth: 2,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Current - Low',
                        data: currentSeverityCounts.Low,
                        borderColor: '#4caf50',
                        backgroundColor: 'rgba(76, 175, 80, 0.3)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        borderWidth: 2,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Current Total',
                        data: currentTotalCounts,
                        borderColor: '#9c27b0',
                        backgroundColor: 'rgba(156, 39, 176, 0.3)',
                        tension: 0.3,
                        borderWidth: 3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex),
                        hidden: true
                    },
                    {
                        label: 'After Top 25 - Critical',
                        data: projectedSeverityCounts.Critical,
                        borderColor: '#ff9999',
                        backgroundColor: 'rgba(255, 153, 153, 0.2)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        borderWidth: 2,
                        borderDash: [5, 5],
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'After Top 25 - High',
                        data: projectedSeverityCounts.High,
                        borderColor: '#ffb380',
                        backgroundColor: 'rgba(255, 179, 128, 0.2)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        borderWidth: 2,
                        borderDash: [5, 5],
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'After Top 25 - Medium',
                        data: projectedSeverityCounts.Medium,
                        borderColor: '#ffcc66',
                        backgroundColor: 'rgba(255, 204, 102, 0.2)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        borderWidth: 2,
                        borderDash: [5, 5],
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'After Top 25 - Low',
                        data: projectedSeverityCounts.Low,
                        borderColor: '#90ee90',
                        backgroundColor: 'rgba(144, 238, 144, 0.2)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        borderWidth: 2,
                        borderDash: [5, 5],
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'After Top 25 Total',
                        data: projectedTotalCounts,
                        borderColor: '#d9a3ff',
                        backgroundColor: 'rgba(217, 163, 255, 0.2)',
                        tension: 0.3,
                        borderWidth: 3,
                        borderDash: [5, 5],
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 6,
                        segment: createSegmentStyle(cutoffIndex),
                        hidden: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Impact of Addressing Top 25 Remediations',
                        font: { size: 16 }
                    },
                    legend: {
                        position: 'top'
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        stacked: false,
                        title: {
                            display: true,
                            text: 'Total Vulnerabilities'
                        }
                    }
                }
            }
        });
        } catch (error) {
            console.error('Error creating impact chart:', error);
        }
    }
    
}

// =============================================================================
// IMPACT ANALYSIS TABLE
// =============================================================================

/**
 * Render the impact analysis table
 */
function renderImpactAnalysisTable() {
    const tbody = document.getElementById('impactAnalysisTableBody');
    tbody.innerHTML = '';

    impactAnalysisAllData = getImpactAnalysisTableData().slice();
    if (!impactAnalysisAllData || impactAnalysisAllData.length === 0) {
        const row = tbody.insertRow();
        row.innerHTML = '<td colspan="6">No data available</td>';
        updateImpactAnalysisScrollInfo();
        return;
    }
    
    // Reset loaded count and render initial batch
    impactAnalysisLoadedCount = 0;
    
    renderImpactAnalysisTablePage();
}

/**
 * Render impact analysis table (initial load or full refresh)
 */
function renderImpactAnalysisTablePage() {
    const tbody = document.getElementById('impactAnalysisTableBody');
    tbody.innerHTML = '';
    
    if (impactAnalysisAllData.length === 0) {
        const row = tbody.insertRow();
        row.innerHTML = '<td colspan="6">No data available</td>';
        updateImpactAnalysisScrollInfo();
        return;
    }
    
    if (impactAnalysisExpanded) {
        appendImpactAnalysisRows(tbody, 0, impactAnalysisAllData.length);
        impactAnalysisLoadedCount = impactAnalysisAllData.length;
    } else {
        const endIdx = Math.min(TABLE_PAGE_SIZE, impactAnalysisAllData.length);
        appendImpactAnalysisRows(tbody, 0, endIdx);
        impactAnalysisLoadedCount = endIdx;
    }
    
    updateImpactAnalysisScrollInfo();
}

/**
 * Append a single row to the impact analysis table
 */
function createImpactAnalysisRow(item, index) {
    const row = document.createElement('tr');
    row.dataset.rowIndex = String(index);
    row.innerHTML = `
        <td>${item.rank}</td>
        <td>${item.nameHtml}</td>
        <td class="update-details-column">${item.updateHtml}</td>
        <td>${item.devices}</td>
        <td>${item.cveIds}</td>
        <td>${item.impact}</td>
    `;
    return row;
}

function appendImpactAnalysisRows(tbody, startIdx, endIdx) {
    const fragment = document.createDocumentFragment();
    for (let i = startIdx; i < endIdx; i++) {
        fragment.appendChild(createImpactAnalysisRow(impactAnalysisAllData[i], i));
    }
    tbody.appendChild(fragment);
}

/**
 * Load more impact analysis rows on scroll
 */
function loadMoreImpactAnalysisRows() {
    const tbody = document.getElementById('impactAnalysisTableBody');
    const startIdx = impactAnalysisLoadedCount;
    const endIdx = Math.min(startIdx + TABLE_PAGE_SIZE, impactAnalysisAllData.length);

    appendImpactAnalysisRows(tbody, startIdx, endIdx);
    
    impactAnalysisLoadedCount = endIdx;
    updateImpactAnalysisScrollInfo();
}

/**
 * Update impact analysis scroll info
 */
function updateImpactAnalysisScrollInfo() {
    const scrollInfo = document.getElementById('impactAnalysisScrollInfo');
    
    if (impactAnalysisExpanded) {
        scrollInfo.textContent = `Showing all ${impactAnalysisAllData.length} rows`;
    } else {
        scrollInfo.textContent = `Showing ${impactAnalysisLoadedCount} of ${impactAnalysisAllData.length}`;
    }
}

/**
 * Expand/collapse all impact analysis rows
 */
function expandAllImpactAnalysisRows() {
    impactAnalysisExpanded = !impactAnalysisExpanded;
    renderImpactAnalysisTablePage();
}

/**
 * Sort the impact analysis table by column
 * @param {number} columnIndex - The column index to sort by
 */
function sortImpactAnalysisTable(columnIndex) {
    sortImpactAnalysisDirection[columnIndex] = !sortImpactAnalysisDirection[columnIndex];
    const ascending = sortImpactAnalysisDirection[columnIndex];

    impactAnalysisAllData.sort((a, b) => {
        let aValue, bValue;
        switch(columnIndex) {
            case 0: aValue = a.rank; bValue = b.rank; break;
            case 1: aValue = a.name; bValue = b.name; break;
            case 2: aValue = a.updateValue || ''; bValue = b.updateValue || ''; break;
            case 3: aValue = a.devices; bValue = b.devices; break;
            case 4: aValue = a.cveIds; bValue = b.cveIds; break;
            case 5: aValue = a.impact; bValue = b.impact; break;
        }

        if (aValue < bValue) return ascending ? -1 : 1;
        if (aValue > bValue) return ascending ? 1 : -1;
        return 0;
    });

    // Reset scroll and re-render
    impactAnalysisLoadedCount = 0;
    renderImpactAnalysisTablePage();
    updateTableSortState('impactAnalysisTable', columnIndex, ascending);
}

// =============================================================================
// DEVICES BY REMEDIATION REPORT
// =============================================================================

/**
 * Parse vulnerability description to extract sections
 */
function parseVulnerabilityDescription(description) {
    const result = { summary: '', impact: '', additionalInfo: '' };
    if (!description) return result;
    
    // Remove [Generated by AI] noise
    description = description.replace(/\s*\[Generated by AI\]\s*/gi, ' ');
    
    // Match sections - stop at the next section marker or end
    const summaryMatch = description.match(/Summary:\s*([^]*?)(?=\s*(?:Impact:|AdditionalInformation:|Additional Information:|Remediation:|$))/i);
    const impactMatch = description.match(/Impact:\s*([^]*?)(?=\s*(?:AdditionalInformation:|Additional Information:|Remediation:|$))/i);
    const additionalMatch = description.match(/(?:Additional Information|AdditionalInformation):\s*([^]*?)(?=\s*(?:Remediation:|$))/i);
    
    if (summaryMatch) result.summary = summaryMatch[1].trim();
    if (impactMatch) result.impact = impactMatch[1].trim();
    if (additionalMatch) result.additionalInfo = additionalMatch[1].trim();
    
    return result;
}

/**
 * Capitalize first letter of a string
 */
function capitalizeFirst(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Format CVE ID for compact badge display
 * @param {string} cveId - Raw CVE ID (e.g., CVE-2025-1234)
 * @returns {string} Display CVE ID without the CVE- prefix
 */
function formatCveDisplayId(cveId) {
    return String(cveId || '').replace(/^CVE-/i, '');
}

/**
 * Generate tooltip HTML for CVE badge
 */
function generateCveTooltipContent(cveDetail) {
    const vendor = capitalizeFirst(cveDetail.softwareVendor || '');
    const name = capitalizeFirst(cveDetail.softwareName || '');
    const versions = cveDetail.versions ? Array.from(cveDetail.versions).sort().join(', ') : 'N/A';
    const parsed = parseVulnerabilityDescription(cveDetail.description);
    const cveId = cveDetail.cve || cveDetail.id || 'N/A';
    const cvssScore = cveDetail.cvssScore != null ? String(cveDetail.cvssScore) : 'N/A';
    const severity = cveDetail.severity || 'Unknown';
    const published = formatDateYMD(cveDetail.publishedDate);
    const firstSeen = formatDateYMD(cveDetail.firstSeen);
    const lastSeen = formatDateYMD(cveDetail.lastSeen);
    
    let tooltip = `<div class="tooltip-title">${escapeHtml(cveId)} - ${escapeHtml(vendor)} ${escapeHtml(name)}</div>`;
    tooltip += `<div class="tooltip-row"><strong>Versions:</strong> ${escapeHtml(versions)}</div>`;
    tooltip += `<div class="tooltip-row"><strong>Severity:</strong> ${escapeHtml(cvssScore)} (${escapeHtml(severity)})</div>`;
    tooltip += `<div class="tooltip-row"><strong>Published:</strong> ${escapeHtml(published)}</div>`;
    tooltip += `<div class="tooltip-row"><strong>Environment First Seen:</strong> ${escapeHtml(firstSeen)}</div>`;
    tooltip += `<div class="tooltip-row"><strong>Last Seen:</strong> ${escapeHtml(lastSeen)}</div>`;
    
    if (parsed.summary) {
        tooltip += `<div class="tooltip-row"><strong>Summary:</strong> ${escapeHtml(parsed.summary)}</div>`;
    }
    if (parsed.impact) {
        tooltip += `<div class="tooltip-row"><strong>Impact:</strong> ${escapeHtml(parsed.impact)}</div>`;
    }
    if (parsed.additionalInfo) {
        tooltip += `<div class="tooltip-row"><strong>Additional Information:</strong> ${escapeHtml(parsed.additionalInfo)}</div>`;
    }
    
    return tooltip;
}

// Global CVE tooltip data store
const cveTooltipData = {};

let cveTooltipIdCounter = 0;

// Global severity badge tooltip data store
const severityTooltipData = {};

// Counter for unique severity badge IDs
let severityBadgeIdCounter = 0;

/**
 * Render the devices by remediation report (card-based layout)
 */
function renderDevicesByRemediationTable() {
    clearTooltipCaches();
    const cache = getAggregateCache();
    if (!cache.devicesByRemediationData) {
        const remediationByKey = {};
        const activeRows = getRemediationReportRows();

        activeRows.forEach(v => {
            materializeRow(v);
            const remediation = buildRemediationDescriptor(v);
            const key = remediation.key;

            if (!remediationByKey[key]) {
                remediationByKey[key] = {
                    remediationDescriptor: remediation,
                    descriptorObservationMap: new Map(),
                    title: remediation.title,
                    familyTitle: remediation.familyTitle,
                    productLabel: remediation.productLabel,
                    updateName: remediation.updateName,
                    updateId: remediation.updateId,
                    osPlatforms: new Set(),
                    updateEntryMap: new Map(),
                    devices: new Map(),
                    cves: new Set(),
                    severities: { Critical: 0, High: 0, Medium: 0, Low: 0 },
                    cveDetails: new Map()
                };
            }

            if (remediation.osPlatform && remediation.osPlatform !== 'Unknown') {
                remediationByKey[key].osPlatforms.add(remediation.osPlatform);
            }

            observeRemediationDescriptor(remediationByKey[key], remediation);

            const deviceKey = getDeviceIdentityKey(v);
            if (!remediationByKey[key].devices.has(deviceKey)) {
                remediationByKey[key].devices.set(deviceKey, {
                    DeviceId: deviceKey,
                    DeviceName: v.DeviceName,
                    IpAddress: v.MachineInfo?.ip || '',
                    MachineTags: v.MachineTags || [],
                    RbacGroupName: normalizeGroupName(v.RbacGroupName)
                });
            }

            remediationByKey[key].cves.add(v.CveId);

            if (!remediationByKey[key].cveDetails.has(v.CveId)) {
                remediationByKey[key].cveDetails.set(v.CveId, {
                    cveId: v.CveId,
                    cveBatchUrl: v.CveBatchUrl,
                    publishedDate: v.PublishedDate,
                    description: v.VulnerabilityDescription,
                    affectedSoftware: v.AffectedSoftware,
                    severityLevel: v.VulnerabilitySeverityLevel,
                    cvssScore: v.CvssScore,
                    epssScore: v.EpssScore,
                    firstSeenTimestamp: getEnvironmentFirstSeenDate(v),
                    lastSeenTimestamp: v._lastSeenDate,
                    exploitabilityLevel: v.ExploitabilityLevel,
                    softwareVendor: v.SoftwareVendor,
                    softwareName: v.SoftwareName,
                    versions: new Set()
                });
            }

            const cveDetails = remediationByKey[key].cveDetails.get(v.CveId);
            cveDetails.firstSeenTimestamp = getEarliestYmdDate([cveDetails.firstSeenTimestamp, getEnvironmentFirstSeenDate(v)]);
            cveDetails.lastSeenTimestamp = getMostRecentYmdDate([cveDetails.lastSeenTimestamp, getLastSeenDate(v)]);

            if (v.SoftwareVersion) {
                cveDetails.versions.add(v.SoftwareVersion);
            }

            addRemediationUpdateEntry(remediationByKey[key].updateEntryMap, remediation);
        });

        const mergedRemediationByKey = mergeRemediationObjectBuckets(remediationByKey, mergeDevicesByRemediationBuckets);

        Object.values(mergedRemediationByKey).forEach(data => {
            data.cveDetails.forEach(cveDetail => {
                if (data.severities.hasOwnProperty(cveDetail.severityLevel)) {
                    data.severities[cveDetail.severityLevel]++;
                }
            });

            data.remediationDescriptor = getDominantRemediationDescriptor(data) || data.remediationDescriptor;
            data.updateEntries = finalizeRemediationUpdateEntries(data.updateEntryMap);
            data.patchReference = summarizeRemediationUpdateEntries(data.updateEntries);
            data.updateUrl = getSingleRemediationUpdateUrlFromEntries(data.updateEntries) || data.remediationDescriptor.updateUrl;
            data.title = getScopedRemediationDisplayTitle(data.remediationDescriptor);
            data.familyTitle = data.remediationDescriptor.familyTitle;
            data.productLabel = data.remediationDescriptor.productLabel;
            data.updateName = data.remediationDescriptor.updateName;
            data.updateId = data.remediationDescriptor.updateId;
            data.osPlatform = summarizeRemediationPlatforms(data.osPlatforms);
        });

        cache.devicesByRemediationData = Object.entries(mergedRemediationByKey).map(([key, data]) => ({
            key: key,
            title: data.title,
            familyTitle: data.familyTitle,
            productLabel: data.productLabel,
            patchReference: data.patchReference,
            updateName: data.updateName,
            updateId: data.updateId,
            updateUrl: data.updateUrl,
            updateEntries: data.updateEntries,
            osPlatform: data.osPlatform,
            devices: data.devices,
            deviceCount: data.devices.size,
            cveCount: data.cves.size,
            severities: data.severities,
            cveDetails: data.cveDetails
        })).sort((a, b) => b.deviceCount - a.deviceCount);
    }

    devicesByRemediationAllData = cache.devicesByRemediationData.slice();

    // Reset loaded count and render initial batch
    devicesByRemediationLoadedCount = 0;
    renderDevicesByRemediationTablePage();
}

/**
 * Generate tooltip content for severity badges showing CVE IDs
 */
function generateSeverityTooltipContent(cveIds) {
    if (!cveIds || cveIds.length === 0) return '<div class="severity-tooltip-empty">No CVEs</div>';
    
    // Sort CVE IDs alphabetically and filter out any undefined/null values
    const sortedCveIds = [...cveIds].filter(id => id).sort();
    
    if (sortedCveIds.length === 0) return '<div class="severity-tooltip-empty">No valid CVE IDs</div>';
    
    // Return simple comma-separated list
    return `<div class="severity-tooltip-content">${sortedCveIds.join(', ')}</div>`;
}

/**
 * Initialize CVE and severity badge tooltip system
 */
function initCveTooltips() {
    // Create global tooltip element if it doesn't exist
    let tooltip = document.getElementById('cve-global-tooltip');
    if (!tooltip) {
        tooltip = document.createElement('div');
        tooltip.id = 'cve-global-tooltip';
        document.body.appendChild(tooltip);
    }
    
    // Add event delegation for CVE badge hover
    document.addEventListener('mouseover', function(e) {
        const cveBadge = e.target.closest('.cve-severity-badge');
        if (cveBadge && cveBadge.dataset.tooltipId) {
            const content = cveTooltipData[cveBadge.dataset.tooltipId];
            if (content) {
                tooltip.innerHTML = content;
                tooltip.style.display = 'block';
                tooltip.classList.add('cve-tooltip');
                tooltip.classList.remove('severity-tooltip');
                
                // Position tooltip relative to badge
                const badgeRect = cveBadge.getBoundingClientRect();
                const tooltipRect = tooltip.getBoundingClientRect();
                const viewportHeight = window.innerHeight;
                const viewportWidth = window.innerWidth;
                const gap = 8; // Gap between badge and tooltip
                
                // Calculate available space above and below the badge
                const spaceAbove = badgeRect.top;
                const spaceBelow = viewportHeight - badgeRect.bottom;
                
                // Position vertically: prefer below, but use above if more space
                let top;
                if (spaceBelow >= tooltipRect.height + gap || spaceBelow >= spaceAbove) {
                    // Position below badge
                    top = badgeRect.bottom + gap;
                } else {
                    // Position above badge
                    top = badgeRect.top - tooltipRect.height - gap;
                }
                
                // Ensure tooltip doesn't go off top or bottom of viewport
                top = Math.max(gap, Math.min(top, viewportHeight - tooltipRect.height - gap));
                
                // Position horizontally: center on badge, but keep within viewport
                let left = badgeRect.left + (badgeRect.width / 2) - (tooltipRect.width / 2);
                left = Math.max(gap, Math.min(left, viewportWidth - tooltipRect.width - gap));
                
                tooltip.style.top = top + 'px';
                tooltip.style.left = left + 'px';
            }
            return;
        }
        
        // Check for severity badge hover
        const severityBadge = e.target.closest('.severity-badge[data-tooltip-id]');
        if (severityBadge && severityBadge.dataset.tooltipId) {
            const content = severityTooltipData[severityBadge.dataset.tooltipId];
            if (content) {
                tooltip.innerHTML = content;
                tooltip.style.display = 'block';
                tooltip.classList.add('severity-tooltip');
                tooltip.classList.remove('cve-tooltip');
                
                // Position tooltip relative to badge
                const badgeRect = severityBadge.getBoundingClientRect();
                const tooltipRect = tooltip.getBoundingClientRect();
                const viewportHeight = window.innerHeight;
                const viewportWidth = window.innerWidth;
                const gap = 8;
                
                // Calculate available space
                const spaceAbove = badgeRect.top;
                const spaceBelow = viewportHeight - badgeRect.bottom;
                
                // Position vertically
                let top;
                if (spaceBelow >= tooltipRect.height + gap || spaceBelow >= spaceAbove) {
                    top = badgeRect.bottom + gap;
                } else {
                    top = badgeRect.top - tooltipRect.height - gap;
                }
                top = Math.max(gap, Math.min(top, viewportHeight - tooltipRect.height - gap));
                
                // Position horizontally
                let left = badgeRect.left + (badgeRect.width / 2) - (tooltipRect.width / 2);
                left = Math.max(gap, Math.min(left, viewportWidth - tooltipRect.width - gap));
                
                tooltip.style.top = top + 'px';
                tooltip.style.left = left + 'px';
            }
        }
    });
    
    document.addEventListener('mouseout', function(e) {
        const cveBadge = e.target.closest('.cve-severity-badge');
        const severityBadge = e.target.closest('.severity-badge[data-tooltip-id]');
        if ((cveBadge && cveBadge.dataset.tooltipId) || (severityBadge && severityBadge.dataset.tooltipId)) {
            tooltip.style.display = 'none';
        }
    });
}

/**
 * Render the devices by remediation cards page
 */
function renderDevicesByRemediationTablePage() {
    const container = document.getElementById('devicesByRemediationContainer');
    container.innerHTML = '';
    
    // Initialize tooltip system once
    if (!document.getElementById('cve-global-tooltip')) {
        initCveTooltips();
    }
    
    if (devicesByRemediationAllData.length === 0) {
        container.innerHTML = '<div class="loading-message">No data available with current filters</div>';
        updateDevicesByRemediationScrollInfo();
        return;
    }
    
    const endIdx = devicesByRemediationExpanded 
        ? devicesByRemediationAllData.length 
        : Math.min(CARD_PAGE_SIZE, devicesByRemediationAllData.length);

    appendDevicesByRemediationCards(container, 0, endIdx);
    
    devicesByRemediationLoadedCount = endIdx;
    updateDevicesByRemediationScrollInfo();
}

/**
 * Append a single remediation card to the container
 */
function appendDevicesByRemediationCard(container, data, index) {
    const card = document.createElement('div');
    card.className = 'remediation-card';
    
    const headerText = data.title;
    
    // Extract CVE details
    let mostRecentDate = null;
    const cveList = [];
    
    if (data.cveDetails && data.cveDetails.size > 0) {
        data.cveDetails.forEach(details => {
            // Track most recent published date
            if (details.publishedDate) {
                const normalized = formatDateYMD(details.publishedDate);
                if (normalized && normalized !== '-' && (!mostRecentDate || normalized > mostRecentDate)) {
                    mostRecentDate = normalized;
                }
            }
            
            // Collect CVE details for badge display
            if (details.cveId) {
                cveList.push({
                    cve: details.cveId,
                    id: details.cveId,
                    url: details.cveBatchUrl,
                    severity: details.severityLevel || 'Unknown',
                    cvssScore: details.cvssScore,
                    epssScore: details.epssScore,
                    description: details.description,
                    firstSeen: details.firstSeenTimestamp,
                    lastSeen: details.lastSeenTimestamp,
                    exploitability: details.exploitabilityLevel,
                    softwareVendor: details.softwareVendor || '',
                    softwareName: details.softwareName || '',
                    versions: details.versions || new Set()
                });
            }
        });
    }
    
    // Build CVE details section
    const detailBadges = [];

    if (data.osPlatform && data.osPlatform !== 'Unknown') {
        detailBadges.push(`<span class="stat-badge">Platform: ${escapeHtml(data.osPlatform)}</span>`);
    }

    if (mostRecentDate) {
        detailBadges.push(`<span class="stat-badge">Published: ${mostRecentDate}</span>`);
    }

    (data.updateEntries || []).filter(entry => entry && entry.referenceText).forEach(entry => {
        detailBadges.push(buildRemediationUpdateBadgeHtml(entry.referenceText, entry.referenceUrl, 'Patch: '));
    });

    const cveDetailsHtml = detailBadges.length > 0
        ? `<div class="cve-details remediation-card-summary">${detailBadges.join('')}</div>`
        : '';
    
    // Create severity summary with tooltips showing CVE IDs per severity
    const cveBySeverity = { Critical: [], High: [], Medium: [], Low: [] };
    if (data.cveDetails && data.cveDetails.size > 0) {
        data.cveDetails.forEach((details, cveId) => {
            if (cveId && cveBySeverity.hasOwnProperty(details.severityLevel)) {
                cveBySeverity[details.severityLevel].push(cveId);
            }
        });
    }
    
    const severityBadges = ['Critical', 'High', 'Medium', 'Low']
        .filter(sev => data.severities[sev] > 0)
        .map(sev => {
            const tooltipId = `severity-${severityBadgeIdCounter++}`;
            severityTooltipData[tooltipId] = generateSeverityTooltipContent(cveBySeverity[sev]);
            return `<span class="severity-badge ${sev.toLowerCase()}" data-tooltip-id="${tooltipId}">${sev}: ${data.severities[sev]}</span>`;
        })
        .join(' ');
    
    // Build CVE badges section with header and flexible wrapping badges
    let cveBadgesSection = '';
    if (cveList.length > 0) {
        // Sort CVEs by severity (highest first), then alphabetically
        const severityOrder = { 'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'Unknown': 5 };
        cveList.sort((a, b) => {
            const severityDiff = (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
            if (severityDiff !== 0) return severityDiff;
            return a.id.localeCompare(b.id);
        });
        
        cveBadgesSection = '<div class="cve-badges-section">';
        cveBadgesSection += '<div class="cve-badges-header">';
        cveBadgesSection += '<h4>Exposed CVEs</h4>';
        cveBadgesSection += `<div class="severity-badges">${severityBadges}</div>`;
        cveBadgesSection += '</div>';
        cveBadgesSection += '<div class="cve-badges-container">';
        
        cveList.forEach(cve => {
            const severityClass = (cve.severity || 'Unknown').toLowerCase();
            
            // Remove CVE- prefix for cleaner display
            const displayId = formatCveDisplayId(cve.id);
            
            // Store tooltip content in global data store
            const tooltipId = `cve-${++cveTooltipIdCounter}`;
            cveTooltipData[tooltipId] = generateCveTooltipContent(cve);
            
            const badgeHtml = cve.url 
                ? `<a href="${cve.url}" target="_blank" rel="noopener noreferrer" class="cve-severity-badge ${severityClass}" data-tooltip-id="${tooltipId}">
                     ${escapeHtml(displayId)}
                   </a>`
                : `<span class="cve-severity-badge ${severityClass}" data-tooltip-id="${tooltipId}">
                     ${escapeHtml(displayId)}
                   </span>`;
            
            cveBadgesSection += badgeHtml;
        });
        
        cveBadgesSection += '</div>';
        cveBadgesSection += '</div>';
    }
    
    // Sort devices alphabetically
    const sortedDevices = Array.from(data.devices.values()).sort((a, b) => 
        a.DeviceName.localeCompare(b.DeviceName)
    );
    
    // Build device rows
    const deviceRows = sortedDevices.map(device => {
        const tagsDisplay = device.MachineTags.length > 0 
            ? device.MachineTags.join(', ') 
            : '(No Tags)';
        
        return `
            <tr>
                <td>${device.DeviceName}</td>
                <td>${device.IpAddress}</td>
                <td>${device.RbacGroupName}</td>
                <td>${tagsDisplay}</td>
            </tr>
        `;
    }).join('');
    
    card.innerHTML = `
        <div class="remediation-card-header">
            <div class="remediation-card-title-block">
                <h3>${headerText}</h3>
                ${cveDetailsHtml}
            </div>
            <div class="remediation-stats">
                <div class="stat-badges">
                    <span class="stat-badge">Devices: ${data.deviceCount}</span>
                    <span class="stat-badge">CVEs: ${data.cveCount}</span>
                </div>
            </div>
        </div>
        ${cveBadgesSection}
        <div class="devices-header-row">
            <h4>Vulnerable Devices</h4>
        </div>
        <div class="devices-table-container">
            <table class="devices-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>IP Address</th>
                        <th>Device Group</th>
                        <th>Tags</th>
                    </tr>
                </thead>
                <tbody>
                    ${deviceRows}
                </tbody>
            </table>
        </div>
    `;
    
    container.appendChild(card);
}

function appendDevicesByRemediationCards(container, startIdx, endIdx) {
    const fragment = document.createDocumentFragment();
    for (let i = startIdx; i < endIdx; i++) {
        appendDevicesByRemediationCard(fragment, devicesByRemediationAllData[i], i + 1);
    }
    container.appendChild(fragment);
}

/**
 * Load more cards for devices by remediation report
 */
function loadMoreDevicesByRemediationRows() {
    const container = document.getElementById('devicesByRemediationContainer');
    const startIdx = devicesByRemediationLoadedCount;
    const endIdx = Math.min(startIdx + CARD_RENDER_BATCH_SIZE, devicesByRemediationAllData.length);

    appendDevicesByRemediationCards(container, startIdx, endIdx);
    
    devicesByRemediationLoadedCount = endIdx;
    updateDevicesByRemediationScrollInfo();
}

/**
 * Update devices by remediation scroll info
 */
function updateDevicesByRemediationScrollInfo() {
    const scrollInfo = document.getElementById('devicesByRemediationScrollInfo');
    
    if (devicesByRemediationExpanded) {
        scrollInfo.textContent = `Showing all ${devicesByRemediationAllData.length} remediations`;
    } else {
        scrollInfo.textContent = `Showing ${devicesByRemediationLoadedCount} of ${devicesByRemediationAllData.length}`;
    }
}

/**
 * Sort the devices by remediation data (not needed for card view, but kept for compatibility)
 */
function sortDevicesByRemediationTable(columnIndex) {
    // Not applicable in card view, but function is kept for compatibility
}

// =============================================================================
// REMEDIATIONS BY DEVICE REPORT
// =============================================================================

/**
 * Calculate a score for a remediation to prioritize Critical/High over larger numbers of Medium/Low
 */
function calculateRemediationScore(severities) {
    return (severities.Critical * 1000) + (severities.High * 100) + (severities.Medium * 10) + severities.Low;
}

function getSortedDeviceRemediations(remediationMap) {
    return Array.from(remediationMap.values()).sort((a, b) => {
        const scoreDelta = b.score - a.score;
        if (scoreDelta !== 0) {
            return scoreDelta;
        }

        const cveDelta = b.cves.size - a.cves.size;
        if (cveDelta !== 0) {
            return cveDelta;
        }

        return String(a.title || '').localeCompare(String(b.title || ''));
    });
}

function splitDeviceRemediationsForDisplay(sortedRemediations, maxVisible = MAX_VISIBLE_DEVICE_REMEDIATIONS) {
    const safeMaxVisible = Math.max(1, maxVisible);
    return {
        visible: sortedRemediations.slice(0, safeMaxVisible),
        overflow: sortedRemediations.slice(safeMaxVisible)
    };
}

function buildRemediationsByDeviceRowHtml(remediations) {
    return remediations.map(rem => {
        const remediationName = rem.title;
        const referenceText = rem.patchReference || (rem.updateName !== 'Unknown' ? rem.updateName : '');
        const updateCell = buildRemediationUpdateCellHtml(rem.updateEntries, referenceText, rem.updateUrl);

        const severityBadges = ['Critical', 'High', 'Medium', 'Low']
            .filter(sev => rem.severities[sev] > 0)
            .map(sev => {
                const tooltipId = `severity-${severityBadgeIdCounter++}`;
                severityTooltipData[tooltipId] = generateSeverityTooltipContent(rem.cvesBySeverity[sev]);
                return `<span class="severity-badge ${sev.toLowerCase()}" data-tooltip-id="${tooltipId}">${sev}: ${rem.severities[sev]}</span>`;
            })
            .join(' ');

        const cveCount = rem.cves.size;
        const publishedDate = rem.mostRecentDate || '';

        return `
            <tr>
                <td>${escapeHtml(remediationName)}</td>
                <td class="update-details-column">${updateCell}</td>
                <td>${severityBadges}</td>
                <td>${cveCount}</td>
                <td>${publishedDate}</td>
            </tr>
        `;
    }).join('');
}

/**
 * Render the remediations by device table
 */
function renderRemediationsByDeviceTable() {
    clearTooltipCaches();
    const cache = getAggregateCache();
    if (!cache.remediationsByDeviceData) {
        const deviceByKey = {};
        const deviceCveDetails = {};
        const activeRows = getRemediationReportRows();

        activeRows.forEach(v => {
            materializeRow(v);
            const deviceId = getDeviceIdentityKey(v);

            if (!deviceByKey[deviceId]) {
                deviceByKey[deviceId] = {
                    deviceId: deviceId,
                    deviceName: v.DeviceName,
                    ipAddress: v.MachineInfo?.ip || '',
                    machineTags: v.MachineTags || [],
                    rbacGroupName: normalizeGroupName(v.RbacGroupName),
                    remediations: new Map(),
                    cves: new Set(),
                    deviceSeverities: { Critical: 0, High: 0, Medium: 0, Low: 0 }
                };
                deviceCveDetails[deviceId] = new Map();
            }

            const remediation = buildRemediationDescriptor(v);
            const remKey = remediation.key;

            if (!deviceByKey[deviceId].remediations.has(remKey)) {
                deviceByKey[deviceId].remediations.set(remKey, {
                    remediationDescriptor: remediation,
                    descriptorObservationMap: new Map(),
                    title: remediation.title,
                    familyTitle: remediation.familyTitle,
                    productLabel: remediation.productLabel,
                    updateName: remediation.updateName,
                    updateId: remediation.updateId,
                    osPlatform: remediation.osPlatform,
                    updateEntryMap: new Map(),
                    cves: new Set(),
                    cveDetails: new Map(),
                    severities: { Critical: 0, High: 0, Medium: 0, Low: 0 },
                    publishedDates: []
                });
            }

            const rem = deviceByKey[deviceId].remediations.get(remKey);
            observeRemediationDescriptor(rem, remediation);
            addRemediationUpdateEntry(rem.updateEntryMap, remediation);
            rem.cves.add(v.CveId);

            if (!rem.cveDetails.has(v.CveId)) {
                rem.cveDetails.set(v.CveId, {
                    severityLevel: v.VulnerabilitySeverityLevel,
                    publishedDate: v.PublishedDate
                });

                if (v.PublishedDate) {
                    rem.publishedDates.push(formatDateYMD(v.PublishedDate));
                }
            }

            if (!deviceCveDetails[deviceId].has(v.CveId)) {
                deviceCveDetails[deviceId].set(v.CveId, {
                    severityLevel: v.VulnerabilitySeverityLevel
                });
            }

            deviceByKey[deviceId].cves.add(v.CveId);
        });

        Object.values(deviceByKey).forEach(device => {
            device.deviceCvesBySeverity = { Critical: [], High: [], Medium: [], Low: [] };
            deviceCveDetails[device.deviceId].forEach((cveDetail, cveId) => {
                if (device.deviceSeverities.hasOwnProperty(cveDetail.severityLevel)) {
                    device.deviceSeverities[cveDetail.severityLevel]++;
                    device.deviceCvesBySeverity[cveDetail.severityLevel].push(cveId);
                }
            });

            device.remediations = mergeRemediationMapBuckets(device.remediations, mergeDeviceRemediationBuckets);

            device.remediations.forEach(rem => {
                rem.cvesBySeverity = { Critical: [], High: [], Medium: [], Low: [] };
                rem.cveDetails.forEach((cveDetail, cveId) => {
                    if (rem.severities.hasOwnProperty(cveDetail.severityLevel)) {
                        rem.severities[cveDetail.severityLevel]++;
                        rem.cvesBySeverity[cveDetail.severityLevel].push(cveId);
                    }
                });

                rem.remediationDescriptor = getDominantRemediationDescriptor(rem) || rem.remediationDescriptor;
                rem.mostRecentDate = getMostRecentYmdDate(rem.publishedDates);
                rem.updateEntries = finalizeRemediationUpdateEntries(rem.updateEntryMap);
                rem.patchReference = summarizeRemediationUpdateEntries(rem.updateEntries);
                rem.updateUrl = getSingleRemediationUpdateUrlFromEntries(rem.updateEntries) || rem.remediationDescriptor.updateUrl;
                rem.title = getScopedRemediationDisplayTitle(rem.remediationDescriptor);
                rem.familyTitle = rem.remediationDescriptor.familyTitle;
                rem.productLabel = rem.remediationDescriptor.productLabel;
                rem.updateName = rem.remediationDescriptor.updateName;
                rem.updateId = rem.remediationDescriptor.updateId;
                rem.score = calculateRemediationScore(rem.severities);
            });
        });

        cache.remediationsByDeviceData = Object.values(deviceByKey).map(data => ({
            deviceId: data.deviceId,
            deviceName: data.deviceName,
            ipAddress: data.ipAddress,
            machineTags: data.machineTags,
            rbacGroupName: data.rbacGroupName,
            remediations: data.remediations,
            remediationCount: data.remediations.size,
            cveCount: data.cves.size,
            deviceSeverities: data.deviceSeverities,
            deviceCvesBySeverity: data.deviceCvesBySeverity,
            deviceScore: calculateRemediationScore(data.deviceSeverities)
        })).sort((a, b) => {
            if (b.deviceScore !== a.deviceScore) {
                return b.deviceScore - a.deviceScore;
            }
            return b.remediationCount - a.remediationCount;
        });
    }

    remediationsByDeviceAllData = cache.remediationsByDeviceData.slice();

    // Reset loaded count and render initial batch
    remediationsByDeviceLoadedCount = 0;
    renderRemediationsByDeviceTablePage();
}

/**
 * Render the remediations by device table page
 */
function renderRemediationsByDeviceTablePage() {
    const container = document.getElementById('remediationsByDeviceContainer');
    container.innerHTML = '';
    
    if (remediationsByDeviceAllData.length === 0) {
        container.innerHTML = '<div class="loading-message">No data available with current filters</div>';
        updateRemediationsByDeviceScrollInfo();
        return;
    }
    
    const endIdx = remediationsByDeviceExpanded 
        ? remediationsByDeviceAllData.length 
        : Math.min(CARD_PAGE_SIZE, remediationsByDeviceAllData.length);

    appendRemediationsByDeviceCards(container, 0, endIdx);
    
    remediationsByDeviceLoadedCount = endIdx;
    updateRemediationsByDeviceScrollInfo();
}

/**
 * Append a single device card to the container
 */
function appendRemediationsByDeviceCard(container, data, index) {
    const card = document.createElement('div');
    card.className = 'remediation-card';
    
    // Build header with device name
    const headerText = `${index}. ${data.deviceName}`;
    
    // Build device info section with IP, Group, Tags
    const tagsDisplay = data.machineTags.length > 0 
        ? data.machineTags.join(', ') 
        : '(No Tags)';
    
    const deviceInfoHtml = `
        <div class="cve-details">
            <span class="stat-badge">IP: ${data.ipAddress}</span>
            <span class="stat-badge">Group: ${data.rbacGroupName}</span>
            <span class="stat-badge">Tags: ${tagsDisplay}</span>
        </div>
    `;
    
    // Create device-level severity summary with tooltips
    const deviceSeverityBadges = ['Critical', 'High', 'Medium', 'Low']
        .filter(sev => data.deviceSeverities[sev] > 0)
        .map(sev => {
            const tooltipId = `severity-${severityBadgeIdCounter++}`;
            severityTooltipData[tooltipId] = generateSeverityTooltipContent(data.deviceCvesBySeverity[sev]);
            return `<span class="severity-badge ${sev.toLowerCase()}" data-tooltip-id="${tooltipId}">${sev}: ${data.deviceSeverities[sev]}</span>`;
        })
        .join(' ');
    
    const sortedRemediations = getSortedDeviceRemediations(data.remediations);
    const remediationDisplay = splitDeviceRemediationsForDisplay(sortedRemediations);
    const remediationRows = buildRemediationsByDeviceRowHtml(remediationDisplay.visible);
    const overflowRows = buildRemediationsByDeviceRowHtml(remediationDisplay.overflow);
    const remediationHeading = remediationDisplay.overflow.length > 0 ? 'Top Remediations' : 'Remediations Needed';
    const densityNote = remediationDisplay.overflow.length > 0
        ? `<div class="remediation-density-note">Showing the top ${remediationDisplay.visible.length} remediations first, ranked by severity score. Expand to review the remaining ${remediationDisplay.overflow.length}.</div>`
        : '';
    const overflowSection = remediationDisplay.overflow.length > 0
        ? `
        <details class="remediation-overflow">
            <summary>Show remaining ${remediationDisplay.overflow.length} remediations</summary>
            <div class="devices-table-container remediation-overflow-table">
                <table class="devices-table">
                    <thead>
                        <tr>
                            <th>Remediation</th>
                            <th class="update-details-column">Update Details</th>
                            <th>Severities</th>
                            <th>CVEs</th>
                            <th>Published</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${overflowRows}
                    </tbody>
                </table>
            </div>
        </details>`
        : '';
    
    card.innerHTML = `
        <div class="remediation-card-header">
            <h3>${headerText}</h3>
            ${deviceInfoHtml}
        </div>
        <div class="cve-badges-section">
            <div class="cve-badges-header">
                <h4>Device Vulnerability Summary</h4>
                <div class="severity-badges">${deviceSeverityBadges}</div>
            </div>
        </div>
        <div class="devices-header-row">
            <h4>${remediationHeading}</h4>
            <div class="remediation-stats">
                <div class="stat-badges">
                    <span class="stat-badge">Remediations: ${data.remediationCount}</span>
                    <span class="stat-badge">CVEs: ${data.cveCount}</span>
                </div>
            </div>
        </div>
        ${densityNote}
        <div class="devices-table-container">
            <table class="devices-table">
                <thead>
                    <tr>
                        <th>Remediation</th>
                        <th class="update-details-column">Update Details</th>
                        <th>Severities</th>
                        <th>CVEs</th>
                        <th>Published</th>
                    </tr>
                </thead>
                <tbody>
                    ${remediationRows}
                </tbody>
            </table>
        </div>
        ${overflowSection}
    `;
    
    container.appendChild(card);
}

function appendRemediationsByDeviceCards(container, startIdx, endIdx) {
    const fragment = document.createDocumentFragment();
    for (let i = startIdx; i < endIdx; i++) {
        appendRemediationsByDeviceCard(fragment, remediationsByDeviceAllData[i], i + 1);
    }
    container.appendChild(fragment);
}

/**
 * Load more cards for remediations by device report
 */
function loadMoreRemediationsByDeviceRows() {
    const container = document.getElementById('remediationsByDeviceContainer');
    const startIdx = remediationsByDeviceLoadedCount;
    const endIdx = Math.min(startIdx + CARD_RENDER_BATCH_SIZE, remediationsByDeviceAllData.length);

    appendRemediationsByDeviceCards(container, startIdx, endIdx);
    
    remediationsByDeviceLoadedCount = endIdx;
    updateRemediationsByDeviceScrollInfo();
}

/**
 * Update remediations by device scroll info
 */
function updateRemediationsByDeviceScrollInfo() {
    const scrollInfo = document.getElementById('remediationsByDeviceScrollInfo');
    
    if (remediationsByDeviceExpanded) {
        scrollInfo.textContent = `Showing all ${remediationsByDeviceAllData.length} devices`;
    } else {
        scrollInfo.textContent = `Showing ${remediationsByDeviceLoadedCount} of ${remediationsByDeviceAllData.length}`;
    }
}

/**
 * Sort the remediations by device table (not needed for card view, but kept for compatibility)
 */
function sortRemediationsByDeviceTable(columnIndex) {
    // Not applicable in card view, but function is kept for compatibility
}

// =============================================================================
// MODALS
// =============================================================================

/**
 * Initialize evidence tooltip positioning
 * Uses event delegation to handle dynamically created tooltips
 */
function initEvidenceTooltips() {
    document.addEventListener('mouseenter', function(e) {
        if (!e.target || !e.target.closest) return;
        const cell = e.target.closest('.evidence-cell');
        if (!cell) return;
        
        const tooltip = cell.querySelector('.evidence-tooltip');
        if (!tooltip) return;
        if (tooltip.classList.contains('pinned')) return; // Don't reposition pinned tooltips
        
        // Get the indicator position
        const indicator = cell.querySelector('.evidence-indicator');
        if (!indicator) return;
        
        const rect = indicator.getBoundingClientRect();
        
        // Position tooltip above the indicator, centered
        tooltip.style.display = 'block';
        
        // Calculate position
        let left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2);
        let top = rect.top - tooltip.offsetHeight - 8;
        
        // Keep within viewport bounds
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        
        // Horizontal bounds
        if (left < 10) left = 10;
        if (left + tooltip.offsetWidth > viewportWidth - 10) {
            left = viewportWidth - tooltip.offsetWidth - 10;
        }
        
        // If tooltip would go above viewport, show it below instead
        if (top < 10) {
            top = rect.bottom + 8;
        }
        
        tooltip.style.left = left + 'px';
        tooltip.style.top = top + 'px';
    }, true);
    
    document.addEventListener('mouseleave', function(e) {
        if (!e.target || !e.target.closest) return;
        const cell = e.target.closest('.evidence-cell');
        if (!cell) return;
        
        const tooltip = cell.querySelector('.evidence-tooltip');
        if (tooltip && !tooltip.classList.contains('pinned')) {
            tooltip.style.display = 'none';
        }
    }, true);

    // Click to pin/unpin tooltip (allows text selection & copying)
    document.addEventListener('click', function(e) {
        if (!e.target || !e.target.closest) return;
        const cell = e.target.closest('.evidence-cell');
        if (cell) {
            const tooltip = cell.querySelector('.evidence-tooltip');
            if (tooltip) {
                const wasPinned = tooltip.classList.contains('pinned');
                // Unpin all others first
                document.querySelectorAll('.evidence-tooltip.pinned').forEach(t => {
                    t.classList.remove('pinned');
                    t.style.display = 'none';
                });
                if (!wasPinned) {
                    tooltip.classList.add('pinned');
                    tooltip.style.display = 'block';
                }
                e.stopPropagation();
                return;
            }
        }
        // Click outside — unpin all
        document.querySelectorAll('.evidence-tooltip.pinned').forEach(t => {
            t.classList.remove('pinned');
            t.style.display = 'none';
        });
    });
}

/**
 * Build evidence tooltip HTML for DiskPaths and RegistryPaths
 * @param {Object} v - Vulnerability object with DiskPaths and RegistryPaths
 * @returns {string} HTML for evidence cell
 */
function buildEvidenceHtml(v) {
    materializeRow(v);
    const diskPaths = v.DiskPaths || [];
    const regPaths = v.RegistryPaths || [];
    const totalEvidence = diskPaths.length + regPaths.length;
    
    if (totalEvidence === 0) {
        return '<td>-</td>';
    }
    
    let tooltipHtml = '';
    if (diskPaths.length > 0) {
        tooltipHtml += '<h5>Disk Paths:</h5><ul>';
        diskPaths.forEach(p => tooltipHtml += `<li>${escapeHtml(p)}</li>`);
        tooltipHtml += '</ul>';
    }
    if (regPaths.length > 0) {
        tooltipHtml += '<h5>Registry Paths:</h5><ul>';
        regPaths.forEach(p => tooltipHtml += `<li>${escapeHtml(p)}</li>`);
        tooltipHtml += '</ul>';
    }
    
    return `<td class="evidence-cell">
        <span class="evidence-indicator">${totalEvidence} path${totalEvidence > 1 ? 's' : ''}</span>
        <div class="evidence-tooltip">${tooltipHtml}</div>
    </td>`;
}

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Build device bubble HTML with machine-info tooltip
 * @param {Object} v - Denormalized vulnerability object (for DeviceName, DeviceId, MachineInfo)
 * @returns {string} HTML for a device bubble
 */
function buildDeviceBubbleHtml(v) {
    let tooltipContent = `<strong>${escapeHtml(v.DeviceName)}</strong>`;
    if (v.DeviceId) {
        tooltipContent += `<br><span class="tooltip-label">ID:</span> ${escapeHtml(v.DeviceId)}`;
    }
    if (v.MachineInfo) {
        const mi = v.MachineInfo;
            const users = Array.isArray(mi.u) ? mi.u : (typeof mi.u === 'string' && mi.u ? [mi.u] : []);
        if (mi.ip)  tooltipContent += `<br><span class="tooltip-label">IP:</span> ${escapeHtml(mi.ip)}`;
        if (mi.eip) tooltipContent += `<br><span class="tooltip-label">External IP:</span> ${escapeHtml(mi.eip)}`;
            if (users.length > 0) tooltipContent += `<br><span class="tooltip-label">Users:</span> ${escapeHtml(users.join(', '))}`;
        if (mi.hs)  tooltipContent += `<br><span class="tooltip-label">Health:</span> ${escapeHtml(mi.hs)}`;
        if (mi.rs)  tooltipContent += `<br><span class="tooltip-label">Risk:</span> ${escapeHtml(mi.rs)}`;
        if (mi.el)  tooltipContent += `<br><span class="tooltip-label">Exposure:</span> ${escapeHtml(mi.el)}`;
        if (mi.dv)  tooltipContent += `<br><span class="tooltip-label">Value:</span> ${escapeHtml(mi.dv)}`;
        if (mi.mb)  tooltipContent += `<br><span class="tooltip-label">Managed By:</span> ${escapeHtml(mi.mb)}`;
        if (mi.aad != null) tooltipContent += `<br><span class="tooltip-label">AAD Joined:</span> ${mi.aad ? 'Yes' : 'No'}`;
        if (mi.ls)  tooltipContent += `<br><span class="tooltip-label">Last Seen:</span> ${escapeHtml(formatDateYMD(mi.ls))}`;
        if (mi.fs)  tooltipContent += `<br><span class="tooltip-label">First Seen:</span> ${escapeHtml(formatDateYMD(mi.fs))}`;
    }
    return `<span class="evidence-cell device-bubble-wrapper">` +
        `<span class="evidence-indicator device-bubble">${escapeHtml(v.DeviceName)}</span>` +
        `<div class="evidence-tooltip device-tooltip">${tooltipContent}</div>` +
        `</span>`;
}

/**
 * Build CVE link HTML with description tooltip
 * @param {Object} v - Denormalized vulnerability object
 * @returns {string} HTML for a CVE link cell with optional description tooltip
 */
function buildCveLinkHtml(v) {
    materializeRow(v);
    const cveUrl = v.CveBatchUrl || `https://msrc.microsoft.com/update-guide/vulnerability/${v.CveId}`;
    const displayId = formatCveDisplayId(v.CveId);
    const severityClass = (v.VulnerabilitySeverityLevel || 'unknown').toLowerCase();
    const tooltipId = `modal-cve-${++severityBadgeIdCounter}`;
    const versions = new Set();
    if (v.SoftwareVersion) {
        versions.add(v.SoftwareVersion);
    }

    cveTooltipData[tooltipId] = generateCveTooltipContent({
        cve: v.CveId,
        id: v.CveId,
        softwareVendor: v.SoftwareVendor,
        softwareName: v.SoftwareName,
        versions: versions,
        description: v.VulnerabilityDescription,
        cvssScore: v.CvssScore,
        severity: v.VulnerabilitySeverityLevel || 'Unknown',
        publishedDate: v.PublishedDate,
        firstSeen: getEnvironmentFirstSeenDate(v),
        lastSeen: v._lastSeenDate
    });

    if (cveUrl) {
        return `<td><a href="${escapeHtml(cveUrl)}" target="_blank" rel="noopener noreferrer" class="cve-severity-badge ${severityClass}" data-tooltip-id="${tooltipId}">${escapeHtml(displayId)}</a></td>`;
    }

    return `<td><span class="cve-severity-badge ${severityClass}" data-tooltip-id="${tooltipId}">${escapeHtml(displayId)}</span></td>`;
}

/**
 * Group devices by their shared CVE signature (identical set of CVE IDs)
 */
function groupDevicesByCveSignature(details) {
    const mergeModalObservationRow = (existing, candidate) => {
        materializeRow(existing);
        materializeRow(candidate);
        const existingFirstSeen = getFirstSeenDate(existing);
        const candidateFirstSeen = getFirstSeenDate(candidate);
        const existingLastSeen = getLastSeenDate(existing);
        const candidateLastSeen = getLastSeenDate(candidate);
        const existingEnvironmentFirstSeen = getEnvironmentFirstSeenDate(existing);
        const candidateEnvironmentFirstSeen = getEnvironmentFirstSeenDate(candidate);
        const existingRecency = getMostRecentYmdDate([existingLastSeen, getRowLatestActivityDate(existing)]);
        const candidateRecency = getMostRecentYmdDate([candidateLastSeen, getRowLatestActivityDate(candidate)]);
        const useCandidateMetadata = Boolean(candidateRecency && (!existingRecency || candidateRecency >= existingRecency));
        const merged = useCandidateMetadata
            ? { ...existing, ...candidate }
            : { ...candidate, ...existing };

        const earliestFirstSeen = getEarliestYmdDate([existingFirstSeen, candidateFirstSeen]);
        const latestLastSeen = getMostRecentYmdDate([existingLastSeen, candidateLastSeen]);
        const earliestEnvironmentFirstSeen = getEarliestYmdDate([existingEnvironmentFirstSeen, candidateEnvironmentFirstSeen]);

        if (earliestFirstSeen) {
            merged._firstSeenDate = earliestFirstSeen;
            merged.FirstSeenTimestamp = earliestFirstSeen;
        }

        if (latestLastSeen) {
            merged._lastSeenDate = latestLastSeen;
            merged.LastSeenTimestamp = latestLastSeen;
        }

        if (earliestEnvironmentFirstSeen) {
            merged._environmentFirstSeenDate = earliestEnvironmentFirstSeen;
            merged.EnvironmentFirstSeenTimestamp = earliestEnvironmentFirstSeen;
        }

        merged.DiskPaths = Array.from(new Set([...(existing.DiskPaths || []), ...(candidate.DiskPaths || [])]));
        merged.RegistryPaths = Array.from(new Set([...(existing.RegistryPaths || []), ...(candidate.RegistryPaths || [])]));
        merged.AffectedSoftware = Array.from(new Set([...(existing.AffectedSoftware || []), ...(candidate.AffectedSoftware || [])]));
        merged.MachineTags = Array.from(new Set([...(existing.MachineTags || []), ...(candidate.MachineTags || [])]));
        merged._observationWindowCount = Number(existing._observationWindowCount || 1) + Number(candidate._observationWindowCount || 1);

        return merged;
    };

    // Build per-device CVE map
    const deviceMap = new Map();
    for (let i = 0; i < details.length; i++) {
        const d = details[i];
        const key = getDeviceIdentityKey(d);
        let dev = deviceMap.get(key);
        if (!dev) {
            dev = {
                DeviceName: d.DeviceName,
                DeviceId: d.DeviceId,
                MachineInfo: d.MachineInfo,
                cveIds: new Set(),
                vulnsByCve: {}
            };
            deviceMap.set(key, dev);
        }
        dev.cveIds.add(d.CveId);
        if (!dev.vulnsByCve[d.CveId]) {
            dev.vulnsByCve[d.CveId] = d;
        } else {
            dev.vulnsByCve[d.CveId] = mergeModalObservationRow(dev.vulnsByCve[d.CveId], d);
        }
    }

    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const sortVulns = (vulns) => {
        vulns.sort((a, b) => {
            const aSev = sevOrder[a.VulnerabilitySeverityLevel?.toLowerCase()] ?? 9;
            const bSev = sevOrder[b.VulnerabilitySeverityLevel?.toLowerCase()] ?? 9;
            return aSev !== bSev ? aSev - bSev : a.CveId.localeCompare(b.CveId);
        });
        return vulns;
    };

    const devices = Array.from(deviceMap.values());

    // If only one device, return a single group with all its CVEs
    if (devices.length <= 1) {
        const dev = devices[0];
        return [{
            devices: [{ DeviceName: dev.DeviceName, DeviceId: dev.DeviceId, MachineInfo: dev.MachineInfo }],
            vulns: sortVulns(Object.values(dev.vulnsByCve))
        }];
    }

    // Find CVEs shared by ALL devices vs CVEs unique to some devices
    const allDeviceKeys = devices.map(d => getDeviceIdentityKey(d));
    const cveCounts = new Map(); // cveId -> Set of device keys that have it
    for (const dev of devices) {
        const devKey = getDeviceIdentityKey(dev);
        for (const cveId of dev.cveIds) {
            if (!cveCounts.has(cveId)) cveCounts.set(cveId, new Set());
            cveCounts.get(cveId).add(devKey);
        }
    }

    const totalDevices = devices.length;
    const sharedCves = new Set();
    for (const [cveId, devKeys] of cveCounts) {
        if (devKeys.size === totalDevices) sharedCves.add(cveId);
    }

    const result = [];

    // Group 1: Shared CVEs (all devices together)
    if (sharedCves.size > 0) {
        const refDev = devices[0];
        const sharedVulns = [];
        for (const cveId of sharedCves) {
            if (refDev.vulnsByCve[cveId]) sharedVulns.push(refDev.vulnsByCve[cveId]);
        }
        result.push({
            devices: devices.map(d => ({ DeviceName: d.DeviceName, DeviceId: d.DeviceId, MachineInfo: d.MachineInfo })),
            vulns: sortVulns(sharedVulns)
        });
    }

    // Remaining groups: per-device unique CVEs (only for devices that have non-shared CVEs)
    for (const dev of devices) {
        const uniqueVulns = [];
        for (const cveId of dev.cveIds) {
            if (!sharedCves.has(cveId) && dev.vulnsByCve[cveId]) {
                uniqueVulns.push(dev.vulnsByCve[cveId]);
            }
        }
        if (uniqueVulns.length > 0) {
            result.push({
                devices: [{ DeviceName: dev.DeviceName, DeviceId: dev.DeviceId, MachineInfo: dev.MachineInfo }],
                vulns: sortVulns(uniqueVulns)
            });
        }
    }

    // Sort groups: most devices first, then most vulns
    result.sort((a, b) => {
        if (b.devices.length !== a.devices.length) return b.devices.length - a.devices.length;
        return b.vulns.length - a.vulns.length;
    });
    return result;
}

/**
 * Show vulnerability details modal
 * @param {string} remediation - The remediation name
 * @param {Array} details - Array of vulnerability details
 */
/**
 * Threshold: tables with more rows than this use virtual scrolling
 */
const VIRTUAL_SCROLL_THRESHOLD = 50;

/**
 * Build a detail-row HTML string for showDetails CVE tables
 */
function buildDetailRow(v, includeEvidenceColumn) {
    const severityClass = v.VulnerabilitySeverityLevel.toLowerCase();
    const epssDisplay = v.EpssScore != null ? v.EpssScore.toFixed(5) : '-';
    const publishedDisplay = formatDateYMD(v.PublishedDate);
    const firstSeenDisplay = getEnvironmentFirstSeenDate(v);

    return '<tr>' +
        buildCveLinkHtml(v) +
        '<td>' + escapeHtml(v.SoftwareVersion) + '</td>' +
        '<td><span class="badge ' + severityClass + '">' + v.VulnerabilitySeverityLevel + '</span></td>' +
        '<td>' + v.CvssScore + '</td>' +
        '<td>' + epssDisplay + '</td>' +
        '<td>' + formatExploitLevel(v.ExploitabilityLevel) + '</td>' +
        (includeEvidenceColumn ? buildEvidenceHtml(v) : '') +
        '<td class="modal-date-col">' + publishedDisplay + '</td>' +
        '<td class="modal-date-col">' + firstSeenDisplay + '</td>' +
        '</tr>';
}

/**
 * Build a remediation-row HTML string for showRemediationDetails CVE tables
 */
function buildRemediationRow(v, includeEvidenceColumn) {
    const severityClass = v.VulnerabilitySeverityLevel.toLowerCase();
    const epssDisplay = v.EpssScore != null ? v.EpssScore.toFixed(5) : '-';
    const publishedDisplay = formatDateYMD(v.PublishedDate);
    const firstSeenDisplay = getEnvironmentFirstSeenDate(v);

    return '<tr>' +
        buildCveLinkHtml(v) +
        '<td>' + escapeHtml(v.SoftwareVersion) + '</td>' +
        '<td><span class="badge ' + severityClass + '">' + v.VulnerabilitySeverityLevel + '</span></td>' +
        '<td>' + v.CvssScore + '</td>' +
        '<td>' + epssDisplay + '</td>' +
        (includeEvidenceColumn ? buildEvidenceHtml(v) : '') +
        '<td class="modal-date-col">' + publishedDisplay + '</td>' +
        '<td class="modal-date-col">' + firstSeenDisplay + '</td>' +
        '</tr>';
}

/**
 * Check whether any vulnerability in a list has evidence paths
 * @param {Array} vulnerabilities - Array of vulnerability objects
 * @returns {boolean} True when evidence exists
 */
function hasAnyEvidence(vulnerabilities) {
    for (let i = 0; i < vulnerabilities.length; i++) {
        const vulnerability = vulnerabilities[i];
        if ((vulnerability.DiskPaths && vulnerability.DiskPaths.length > 0) ||
            (vulnerability.RegistryPaths && vulnerability.RegistryPaths.length > 0)) {
            return true;
        }
    }
    return false;
}

/**
 * After modal innerHTML is set, attach VirtualModalTable to each tbody
 * that has a data-vt-rows attribute storing row data.
 */
function attachVirtualTables(scrollContainer, vtRowData) {
    activeVirtualTables.forEach(vt => vt.destroy());
    activeVirtualTables = [];

    for (const [vtId, config] of Object.entries(vtRowData)) {
        const tbody = scrollContainer.querySelector(`tbody[data-vt-id="${vtId}"]`);
        if (!tbody) continue;

        if (config.items.length > VIRTUAL_SCROLL_THRESHOLD) {
            activeVirtualTables.push(new VirtualModalTable(scrollContainer, tbody, config.items, config.rowBuilder));
        } else if (tbody) {
            tbody.innerHTML = config.items.map(config.rowBuilder).join('');
        }
    }
}

function buildModalGroupCache(details) {
    return {
        groups: groupDevicesByCveSignature(details),
        includeEvidenceColumn: hasAnyEvidence(details),
        totalDevices: new Set(details.map(d => getDeviceIdentityKey(d))).size,
        totalCves: new Set(details.map(d => d.CveId)).size
    };
}

function focusModalCloseButton() {
    const closeButton = document.getElementById('closeModalButton');
    if (closeButton) {
        closeButton.focus();
    }
}

function getModalFocusableElements() {
    const modal = document.getElementById('detailModal');
    if (!modal || !modal.classList.contains('active')) {
        return [];
    }

    return Array.from(modal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'))
        .filter(element => !element.hasAttribute('disabled') && !element.getAttribute('aria-hidden'));
}

/**
 * Show vulnerability details modal
 * @param {Object} remediationData - Remediation aggregate row
 */
function showDetails(remediationData) {
    const modal = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    const details = remediationData.details;
    const remediation = remediationData.modalTitle
        || remediationData.remediation
        || [remediationData.vendor, remediationData.software].filter(Boolean).join(' ')
        || 'Remediation Details';

    modalTitle.textContent = remediation;
    modalBody.innerHTML = '<p class="loading">Loading details...</p>';
    lastFocusedElementBeforeModal = (typeof HTMLElement !== 'undefined' && document.activeElement instanceof HTMLElement) ? document.activeElement : null;
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    hideGlobalTooltip();
    focusModalCloseButton();

    if (!document.getElementById('cve-global-tooltip')) {
        initCveTooltips();
    }

    // Defer heavy work so the modal + loading indicator render first
    requestAnimationFrame(() => {
        const modalCache = remediationData._modalCache || buildModalGroupCache(details);
        remediationData._modalCache = modalCache;
        const { groups, includeEvidenceColumn, totalDevices, totalCves } = modalCache;
        const updateEntries = remediationData.updateEntries && remediationData.updateEntries.length > 0
            ? remediationData.updateEntries
            : buildRemediationUpdateEntriesFromDetails(details);

        const parts = [];
        const vtRowData = {};

        parts.push('<h3>Affected Devices and Vulnerabilities</h3>');

        const updateLinksHtml = buildRemediationModalUpdateLinksHtml(updateEntries);
        if (updateLinksHtml) {
            parts.push(updateLinksHtml);
        }

        parts.push('<p class="modal-summary-text">' +
            totalDevices + ' device' + (totalDevices !== 1 ? 's' : '') + ', ' +
            totalCves + ' CVE' + (totalCves !== 1 ? 's' : '') + '</p>');

        for (let gi = 0; gi < groups.length; gi++) {
            const group = groups[gi];
            const vtId = 'det_' + gi;

            // Device bubbles
            parts.push('<div class="device-bubbles-container">');
            group.devices.sort((a, b) => a.DeviceName.localeCompare(b.DeviceName));
            for (let di = 0; di < group.devices.length; di++) {
                parts.push(buildDeviceBubbleHtml(group.devices[di]));
            }
            parts.push('</div>');

            // CVE table with empty tbody (rows added via virtual scroll)
            parts.push('<div class="modal-table-container"><table class="detail-table"><thead><tr>',
                '<th>CVE ID</th><th>Version</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Exploitability</th>' +
                (includeEvidenceColumn ? '<th>Evidence</th>' : '') +
                '<th class="modal-date-col">Published</th><th class="modal-date-col">Environment First Seen</th>',
                '</tr></thead><tbody data-vt-id="', vtId, '"></tbody></table></div>');

            vtRowData[vtId] = {
                items: group.vulns,
                rowBuilder: vuln => buildDetailRow(vuln, includeEvidenceColumn)
            };

            if (gi < groups.length - 1) parts.push('<hr class="modal-section-divider">');
        }

        modalBody.innerHTML = parts.join('');
        const scrollContainer = modalBody.closest('.modal-content');
        attachVirtualTables(scrollContainer, vtRowData);
    });
}

/**
 * Show remediation details modal
 * @param {Object} data - The remediation data object
 */
function showRemediationDetails(data) {
    const modal = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    
    modalTitle.textContent = `Remediation on ${data.date}: ${data.remediation}`;
    modalBody.innerHTML = '<p class="loading">Loading details...</p>';
    lastFocusedElementBeforeModal = (typeof HTMLElement !== 'undefined' && document.activeElement instanceof HTMLElement) ? document.activeElement : null;
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    hideGlobalTooltip();
    focusModalCloseButton();

    if (!document.getElementById('cve-global-tooltip')) {
        initCveTooltips();
    }

    requestAnimationFrame(() => {
        const modalCache = data._modalCache || buildModalGroupCache(data.details);
        data._modalCache = modalCache;
        const { groups, includeEvidenceColumn } = modalCache;
        const vtRowData = {};
        const updateEntries = data.updateEntries && data.updateEntries.length > 0
            ? data.updateEntries
            : buildRemediationUpdateEntriesFromDetails(data.details);

        const parts = [];
        parts.push('<h3>Summary</h3>',
            '<div class="modal-table-container"><table class="detail-table"><tr>',
            '<td><strong>Date:</strong> ', escapeHtml(data.date), '</td>',
            '<td><strong>Assets Remediated:</strong> ', String(data.devices.size), '</td>',
            '<td><strong>Vulnerabilities Remediated:</strong> ', String(data.vulnerabilities.size), '</td>',
            '</tr></table></div>');

        const updateLinksHtml = buildRemediationModalUpdateLinksHtml(updateEntries);
        if (updateLinksHtml) {
            parts.push(updateLinksHtml);
        }

        parts.push('<br>',
            '<h3>Devices Patched</h3>');

        for (let gi = 0; gi < groups.length; gi++) {
            const group = groups[gi];
            const vtId = 'rem_' + gi;

            // Device bubbles
            parts.push('<div class="device-bubbles-container">');
            group.devices.sort((a, b) => a.DeviceName.localeCompare(b.DeviceName));
            for (let di = 0; di < group.devices.length; di++) {
                parts.push(buildDeviceBubbleHtml(group.devices[di]));
            }
            parts.push('</div>');

            // CVE table with empty tbody
            parts.push('<div class="modal-table-container"><table class="detail-table"><thead><tr>',
                '<th>CVE ID</th><th>Version</th><th>Severity</th><th>CVSS</th><th>EPSS</th>' +
                (includeEvidenceColumn ? '<th>Evidence</th>' : '') +
                '<th class="modal-date-col">Published</th><th class="modal-date-col">Environment First Seen</th>',
                '</tr></thead><tbody data-vt-id="', vtId, '"></tbody></table></div>');

            vtRowData[vtId] = {
                items: group.vulns,
                rowBuilder: vuln => buildRemediationRow(vuln, includeEvidenceColumn)
            };

            if (gi < groups.length - 1) parts.push('<hr class="modal-section-divider">');
        }

        modalBody.innerHTML = parts.join('');
        const scrollContainer = modalBody.closest('.modal-content');
        attachVirtualTables(scrollContainer, vtRowData);
    });
}

/**
 * Show impact analysis details modal
 * @param {Object} item - The impact analysis item
 */
function showImpactAnalysisDetails(item) {
    const modal = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    
    modalTitle.textContent = `Remediation Details: ${item.name}`;

    if (!document.getElementById('cve-global-tooltip')) {
        initCveTooltips();
    }
    
    // Group vulnerabilities by device (using DeviceId as key)
    const deviceMap = {};
    item.vulnerabilities.forEach(v => {
        const deviceKey = getDeviceIdentityKey(v);
        if (!deviceMap[deviceKey]) {
            deviceMap[deviceKey] = {
                name: v.DeviceName,
                id: v.DeviceId,
                cves: new Set()
            };
        }
        deviceMap[deviceKey].cves.add(v.CveId);
    });

    const updateLinksHtml = buildRemediationModalUpdateLinksHtml(
        item.updateEntries && item.updateEntries.length > 0
            ? item.updateEntries
            : buildRemediationUpdateEntriesFromDetails(item.vulnerabilities)
    );
    
    let html = '<h3>Affected Devices</h3>';
    if (updateLinksHtml) {
        html = updateLinksHtml + html;
    }
    html += '<div class="modal-table-container"><table class="detail-table"><thead><tr>';
    html += '<th>Device Name</th><th>Device ID</th><th>CVE Count</th><th>CVE IDs</th>';
    html += '</tr></thead><tbody>';
    
    // Sort devices by CVE count descending
    const sortedDevices = Object.values(deviceMap).sort((a, b) => b.cves.size - a.cves.size);
    
    sortedDevices.forEach(device => {
        const cveList = Array.from(device.cves).sort().join(', ');
        const deviceIdShort = device.id ? device.id.substring(0, 12) + '...' : '-';
        
        html += `<tr>
            <td>${escapeHtml(device.name)}</td>
            <td title="${escapeHtml(device.id || '')}">${escapeHtml(deviceIdShort)}</td>
            <td>${device.cves.size}</td>
            <td class="modal-cve-list-cell">${escapeHtml(cveList)}</td>
        </tr>`;
    });
    
    html += '</tbody></table></div>';
    
    modalBody.innerHTML = html;
    lastFocusedElementBeforeModal = (typeof HTMLElement !== 'undefined' && document.activeElement instanceof HTMLElement) ? document.activeElement : null;
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    focusModalCloseButton();
}

/**
 * Close the modal and clean up virtual tables
 */
function closeModal() {
    activeVirtualTables.forEach(vt => vt.destroy());
    activeVirtualTables = [];
    hideGlobalTooltip();
    const modal = document.getElementById('detailModal');
    modal.classList.remove('active');
    modal.setAttribute('aria-hidden', 'true');
    if (lastFocusedElementBeforeModal && typeof document.contains === 'function' && document.contains(lastFocusedElementBeforeModal)) {
        lastFocusedElementBeforeModal.focus();
    }
    lastFocusedElementBeforeModal = null;
}

// Close modal when clicking outside
window.addEventListener('click', function(event) {
    const modal = document.getElementById('detailModal');
    if (event.target === modal) {
        closeModal();
    }
});

// Close modal on Escape key
window.addEventListener('keydown', function(event) {
    const modal = document.getElementById('detailModal');
    if (!modal || !modal.classList.contains('active')) {
        return;
    }

    if (event.key === 'Tab') {
        const focusableElements = getModalFocusableElements();
        if (focusableElements.length === 0) {
            event.preventDefault();
            return;
        }

        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        if (event.shiftKey && document.activeElement === firstElement) {
            event.preventDefault();
            lastElement.focus();
            return;
        }

        if (!event.shiftKey && document.activeElement === lastElement) {
            event.preventDefault();
            firstElement.focus();
            return;
        }
    }

    if (event.key === 'Escape') {
        closeModal();
    }
});

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
                            throw new Error('PDF export bundle did not initialize correctly.');
                        }
                        pdfLibrariesLoaded = true;
                        logDebug('PDF libraries loaded successfully');
                        resolve();
                    })
                    .catch(reject);
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
            console.error('Failed to load PDF libraries:', error);
            reject(error);
        }
    }).catch(error => {
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
    let wasExpanded = false;
    
    switch (selectedReport) {
        case 'active-vulnerabilities':
            wasExpanded = remediationExpanded;
            if (!remediationExpanded) {
                remediationExpanded = true;
                renderRemediationTablePage();
            }
            break;
        case 'remediation-activity':
            wasExpanded = remediationDetailsExpanded;
            if (!remediationDetailsExpanded) {
                remediationDetailsExpanded = true;
                renderRemediationDetailsTablePage();
            }
            break;
        case 'impact-analysis':
            wasExpanded = impactAnalysisExpanded;
            if (!impactAnalysisExpanded) {
                impactAnalysisExpanded = true;
                renderImpactAnalysisTablePage();
            }
            break;
        case 'devices-by-remediation':
            wasExpanded = devicesByRemediationExpanded;
            if (!devicesByRemediationExpanded) {
                devicesByRemediationExpanded = true;
                renderDevicesByRemediationTablePage();
            }
            break;
        case 'remediations-by-device':
            wasExpanded = remediationsByDeviceExpanded;
            if (!remediationsByDeviceExpanded) {
                remediationsByDeviceExpanded = true;
                renderRemediationsByDeviceTablePage();
            }
            break;
    }
    
    return wasExpanded;
}

/**
 * Restore report to previous expansion state
 * @param {string} selectedReport - The report type identifier
 * @param {boolean} wasExpanded - The previous expansion state
 */
function restoreReportState(selectedReport, wasExpanded) {
    if (wasExpanded) return;
    
    switch (selectedReport) {
        case 'active-vulnerabilities':
            remediationExpanded = false;
            renderRemediationTablePage();
            break;
        case 'remediation-activity':
            remediationDetailsExpanded = false;
            renderRemediationDetailsTablePage();
            break;
        case 'impact-analysis':
            impactAnalysisExpanded = false;
            renderImpactAnalysisTablePage();
            break;
        case 'devices-by-remediation':
            devicesByRemediationExpanded = false;
            renderDevicesByRemediationTablePage();
            break;
        case 'remediations-by-device':
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
    
    updateProgress(25, 'Expanding data...');
    button.textContent = '📄 Expanding data...';
    
    const wasExpanded = expandReportForPdf(selectedReport);
    await new Promise(resolve => setTimeout(resolve, 100));
    
    updateProgress(30, 'Generating PDF...');
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
                { text: 'Device Groups: ', bold: true },
                { text: deviceGroupsText }
            ],
            margin: [0, 2, 0, 2],
            fontSize: 10
        });

        filterContent.push({
            text: [
                { text: 'Device Tags: ', bold: true },
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

        updateProgress(80, 'Checking page count...');
        const pdfDoc = pdfMake.createPdf(docDefinition);
        const shouldContinue = await maybeConfirmLargePdfExport(selectedReport, reportName, pdfDoc);
        if (!shouldContinue) {
            setDashboardStatus('PDF export canceled.', 'info');
            return;
        }
        
        updateProgress(90, 'Creating PDF...');
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

// =============================================================================
// PAGE INITIALIZATION
// =============================================================================

window.addEventListener('DOMContentLoaded', function() {
    initEvidenceTooltips();
    init().catch(error => {
        console.error('Dashboard initialization failed:', error);
        setDashboardStatus('Failed to initialize the dashboard. If you are using split-assets mode, open it from an HTTP host with the required asset files.', 'error');
    });
});
