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
const loadedScriptPromises = new Map();

// Device facet catalog used by cascading device filters
let deviceFilterCatalog = [];
let cascadingFilterOptions = {};
let cascadingFilterState = {};

// Constant for devices without tags
const NO_TAGS_VALUE = '(No Tags)';

// Constant for devices without an RBAC group
const NO_GROUP_VALUE = '(none)';
const DEVICE_INACTIVITY_WINDOW_DAYS = 30;

const CASCADING_FILTER_IDS = ['filterRbacGroup', 'filterDeviceTags', 'filterDeviceName'];
const CASCADING_FILTER_CONFIG = {
    filterRbacGroup: {
        allLabel: 'All Groups',
        getValuesForVuln: v => [normalizeGroupName(v.RbacGroupName)]
    },
    filterDeviceTags: {
        allLabel: 'All Tags',
        getValuesForVuln: v => (v.MachineTags && v.MachineTags.length > 0 ? v.MachineTags : [NO_TAGS_VALUE])
    },
    filterDeviceName: {
        allLabel: 'All Devices',
        getValuesForVuln: v => [getDeviceNameFilterValue(v)]
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
const CARD_RENDER_BATCH_SIZE = 10;
const APPLY_FILTER_DEBOUNCE_MS = 50;
const REPORT_IDS = [
    'active-vulnerabilities',
    'remediation-activity',
    'impact-analysis',
    'devices-by-remediation',
    'remediations-by-device'
];

let applyFiltersTimer = null;
let activeReportId = 'active-vulnerabilities';
const initializedReports = new Set();
const dirtyReports = new Set(REPORT_IDS);

let filterState = createEmptyFilterState();
let aggregateCacheKey = null;
let aggregateCache = createEmptyAggregateCache();
let cascadingFilterCountCacheKey = null;
let cascadingFilterCountCache = null;
let chartDataCacheKey = null;
let chartDataCache = null;

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
        startDate: '',
        endDate: '',
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

function createEmptyAggregateCache() {
    return {
        activeRowsAsOfDate: null,
        activeRowsAsOfDateKey: null,
        activeRowsForCurrentSelection: null,
        activeRowsForCurrentSelectionKey: null,
        provenRemediationRows: null,
        provenRemediationRowsKey: null,
        remediationTableData: null,
        remediationDetailsData: null,
        impactData: null,
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

function buildFilterStateKey(state) {
    return [
        state.startDate,
        state.endDate,
        state.deviceNames.join('\u001f'),
        state.rbacGroups.join('\u001f'),
        state.deviceTags.join('\u001f'),
        state.severities.join('\u001f'),
        state.osPlatforms.join('\u001f')
    ].join('\u001e');
}

function syncFilterStateFromDom() {
    const nextState = createEmptyFilterState();
    nextState.startDate = document.getElementById('filterStartDate').value;
    nextState.endDate = document.getElementById('filterEndDate').value;
    nextState.deviceNames = getCascadingFilterSelectionValues('filterDeviceName');
    nextState.rbacGroups = getCascadingFilterSelectionValues('filterRbacGroup');
    nextState.deviceTags = getCascadingFilterSelectionValues('filterDeviceTags');
    nextState.severities = getSelectedCheckboxValues('filterSeverity');
    nextState.osPlatforms = getSelectedCheckboxValues('filterOSPlatform');

    nextState.hasDeviceNames = hasAnyCascadingFilterSelection('filterDeviceName');
    nextState.hasRbacGroups = hasAnyCascadingFilterSelection('filterRbacGroup');
    nextState.hasDeviceTags = hasAnyCascadingFilterSelection('filterDeviceTags');
    nextState.hasSeverities = hasAnyChecked('filterSeverity');
    nextState.hasOsPlatforms = hasAnyChecked('filterOSPlatform');

    nextState.deviceNameSet = new Set(nextState.deviceNames);
    nextState.rbacGroupSet = new Set(nextState.rbacGroups);
    nextState.deviceTagSet = new Set(nextState.deviceTags);
    nextState.severitySet = new Set(nextState.severities);
    nextState.osPlatformSet = new Set(nextState.osPlatforms);
    nextState.key = buildFilterStateKey(nextState);

    filterState = nextState;
    return nextState;
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
    severityBadgeIdCounter = 0;

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
        });

    return chartJsLoadPromise;
}

// =============================================================================
// INDEXEDDB CACHE
// =============================================================================

const VULNDB_NAME = 'VulnDashboardCache';
const VULNDB_VERSION = 1;
const VULNDB_STORE = 'denormalized';

/**
 * Compute a lightweight fingerprint for the embedded dataset.
 * Samples records evenly across the array to detect changes anywhere,
 * not just at the boundaries.
 */
function computeDataFingerprint() {
    const len = getRawVulnCount();
    if (len === 0) return 'empty';
    // Sample up to 10 records evenly distributed across the array
    const sampleCount = Math.min(10, len);
    let sample = '' + len;
    for (let i = 0; i < sampleCount; i++) {
        const idx = Math.floor(i * len / sampleCount);
        sample += JSON.stringify(getRawVulnRecord(idx));
    }
    // Include key lookup-table slices so enrichment-only changes invalidate cache
    if (lookups) {
        const lookupKeys = ['groups', 'devices', 'cves', 'updates', 'dates', 'batchTitles', 'affSoftware'];
        for (let i = 0; i < lookupKeys.length; i++) {
            const key = lookupKeys[i];
            const arr = lookups[key] || [];
            sample += `|${key}:${arr.length}`;
            if (arr.length > 0) sample += JSON.stringify(arr[0]);
            if (arr.length > 1) sample += JSON.stringify(arr[arr.length - 1]);
        }
    }
    // djb2 hash of the combined sample
    let hash = 5381;
    for (let i = 0; i < sample.length; i++) {
        hash = ((hash << 5) + hash + sample.charCodeAt(i)) | 0;
    }
    return 'fp_' + len + '_' + (hash >>> 0).toString(36);
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
            req.onsuccess = () => resolve(req.result ? req.result.data : null);
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
        store.put({ fingerprint, data, ts: Date.now() });
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
self.onmessage = function(e) {
    var lookups = e.data.lookups;
    var rawVulns = e.data.rawVulns;

    // If compressed data was transferred, decompress it first
    if (e.data.compressedBytes) {
        var decompressed = pako.inflate(e.data.compressedBytes, { to: 'string' });
        var data = JSON.parse(decompressed);
        lookups = data.lookups;
        rawVulns = data.vulns;
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
            rawVulns.rp[index]
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
    var rawCount = getRawVulnCount();
    var result = new Array(rawCount);
    for (var i = 0; i < rawCount; i++) {
        var v = getRawVulnRecord(i);
        var device = lookups.devices[v[0]];
        var cve = lookups.cves[v[1]];
        var software = lookups.software[v[2]];

        var tagNames;
        if (device.t && device.t.length > 0) {
            tagNames = [];
            for (var ti = 0; ti < device.t.length; ti++) {
                tagNames.push(lookups.tags[device.t[ti]]);
            }
        } else {
            tagNames = [];
        }

        var vendorName = getLookupValue(lookups.vendors, software.v);
        var softwareName = software.n;
        var updateObj = v[7] >= 0 ? lookups.updates[v[7]] : null;
        var updateName = updateObj ? (updateObj.n || updateObj) : null;
        var updateId = updateObj ? updateObj.id : null;
        var updateUrl = updateObj ? updateObj.url : null;

        // Resolve version from lookup
        var version = v[3] >= 0 ? lookups.versions[v[3]] : null;
        // Resolve dates from lookup
        var firstSeen = v[4] >= 0 ? normalizeDateYMD(lookups.dates[v[4]]) : '';
        var lastSeen = v[5] >= 0 ? normalizeDateYMD(lookups.dates[v[5]]) : '';
        // Resolve evidence paths from lookup indices
        var diskPaths = [];
        if (v[8] && v[8].length > 0) {
            for (var di = 0; di < v[8].length; di++) {
                diskPaths.push(lookups.diskPaths[v[8][di]]);
            }
        }
        var regPathsArr = [];
        if (v[9] && v[9].length > 0) {
            for (var ri = 0; ri < v[9].length; ri++) {
                regPathsArr.push(lookups.regPaths[v[9][ri]]);
            }
        }
        // Resolve batch title from lookup
        var batchTitle = cve.bt >= 0 ? lookups.batchTitles[cve.bt] : null;
        // Resolve affected software from lookup indices
        var affSoftware = null;
        if (cve.as && cve.as.length > 0) {
            affSoftware = [];
            for (var ai = 0; ai < cve.as.length; ai++) {
                affSoftware.push(lookups.affSoftware[cve.as[ai]]);
            }
        }

        result[i] = {
            DeviceId: device.id,
            DeviceName: device.n,
            RbacGroupName: (getLookupValue(lookups.groups, device.g) && String(getLookupValue(lookups.groups, device.g)).trim() !== '') ? getLookupValue(lookups.groups, device.g) : '(none)',
            OSPlatform: getLookupValue(lookups.platforms, device.o),
            OSVersion: device.ov,
            MachineTags: tagNames,
            MachineInfo: device.m || null,
            CveId: cve.id,
            CvssScore: cve.sc,
            VulnerabilitySeverityLevel: getLookupValue(lookups.severities, cve.sv),
            ExploitabilityLevel: cve.ex >= 0 ? lookups.exploitLevels[cve.ex] : null,
            CveBatchUrl: cve.u,
            CveBatchTitle: batchTitle,
            PublishedDate: normalizeDateYMD(cve.pd) || null,
            VulnerabilityDescription: cve.desc || null,
            EpssScore: cve.ep != null ? cve.ep : null,
            AffectedSoftware: affSoftware,
            SoftwareVendor: vendorName,
            SoftwareName: softwareName,
            SoftwareVersion: version,
            RecommendationReference: software.r,
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
    self.postMessage({ rows: result, lookups: lookups, rawVulns: rawVulns });
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
                worker.postMessage({ compressedBytes }, [compressedBytes.buffer]);
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
        pendingCompressedBytes = Uint8Array.from(atob(compressedBase64), c => c.charCodeAt(0));
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
        rawVulns.rp[index]
    ];
}

/**
 * Denormalize a single vulnerability record from compact array format
 * @param {Array} v - Compact vulnerability record [devIdx, cveIdx, swIdx, version, firstSeen, lastSeen, updateAvail, updIdx, diskPaths, regPaths]
 * @param {number} index - Index in the array
 * @returns {Object} Expanded vulnerability object
 */
function denormalizeVuln(v, index) {
    const device = lookups.devices[v[0]];
    const cve = lookups.cves[v[1]];
    const software = lookups.software[v[2]];
    
    // Get tag names from indices
    const tagNames = device.t.length > 0 
        ? device.t.map(idx => lookups.tags[idx])
        : [];
    
    // Resolve version from lookup
    const version = v[3] >= 0 ? lookups.versions[v[3]] : null;
    // Resolve dates from lookup
    const firstSeen = v[4] >= 0 ? (formatDateYMD(lookups.dates[v[4]]) || '') : '';
    const lastSeen = v[5] >= 0 ? (formatDateYMD(lookups.dates[v[5]]) || '') : '';
    // Resolve evidence paths from lookup indices
    const diskPaths = v[8] && v[8].length > 0 ? v[8].map(idx => lookups.diskPaths[idx]) : [];
    const regPaths = v[9] && v[9].length > 0 ? v[9].map(idx => lookups.regPaths[idx]) : [];
    // Resolve batch title from lookup
    const batchTitle = cve.bt >= 0 ? lookups.batchTitles[cve.bt] : null;
    // Resolve affected software from lookup indices
    const affSoftware = cve.as && cve.as.length > 0 ? cve.as.map(idx => lookups.affSoftware[idx]) : null;
    
    return {
        // Device info
        DeviceId: device.id,
        DeviceName: device.n,
        RbacGroupName: (getLookupValue(lookups.groups, device.g) && String(getLookupValue(lookups.groups, device.g)).trim() !== '') ? getLookupValue(lookups.groups, device.g) : '(none)',
        OSPlatform: getLookupValue(lookups.platforms, device.o),
        OSVersion: device.ov,
        MachineTags: tagNames,
        MachineInfo: device.m || null,
        
        // CVE info
        CveId: cve.id,
        CvssScore: cve.sc,
        VulnerabilitySeverityLevel: getLookupValue(lookups.severities, cve.sv),
        ExploitabilityLevel: cve.ex >= 0 ? lookups.exploitLevels[cve.ex] : null,
        CveBatchUrl: cve.u,
        CveBatchTitle: batchTitle,
        PublishedDate: formatDateYMD(cve.pd) || null,
        VulnerabilityDescription: cve.desc || null,
        EpssScore: cve.ep ?? null,
        AffectedSoftware: affSoftware,
        
        // Software info
        SoftwareVendor: getLookupValue(lookups.vendors, software.v),
        SoftwareName: software.n,
        SoftwareVersion: version,
        RecommendationReference: software.r,
        
        // Timestamps (resolved from lookup)
        _firstSeenDate: firstSeen,
        _lastSeenDate: lastSeen,
        FirstSeenTimestamp: firstSeen,
        LastSeenTimestamp: lastSeen,
        
        // Update info
        SecurityUpdateAvailable: v[6] === 1,
        RecommendedSecurityUpdate: v[7] >= 0 ? (lookups.updates[v[7]].n || lookups.updates[v[7]]) : null,
        RecommendedSecurityUpdateId: v[7] >= 0 && lookups.updates[v[7]].id ? lookups.updates[v[7]].id : null,
        RecommendedSecurityUpdateUrl: v[7] >= 0 && lookups.updates[v[7]].url ? lookups.updates[v[7]].url : null,
        
        // Evidence (resolved from lookup)
        DiskPaths: diskPaths,
        RegistryPaths: regPaths,
        
        // Pre-computed fields
        _remediationKey: (() => {
            const uObj = v[7] >= 0 ? lookups.updates[v[7]] : null;
            const uName = uObj ? (uObj.n || uObj) : null;
            return uName
                ? `${lookups.vendors[software.v]} ${software.n} - ${uName}`
                : `${lookups.vendors[software.v]} ${software.n}`;
        })(),
        _index: index
    };
}

/**
 * Denormalize all vulnerability records (main-thread fallback)
 */
function denormalizeAllVulns() {
    const rawCount = getRawVulnCount();
    logDebug('Denormalizing', rawCount, 'records (main thread)...');
    const startTime = performance.now();

    vulnerabilityData = new Array(rawCount);
    for (let i = 0; i < rawCount; i++) {
        vulnerabilityData[i] = denormalizeVuln(getRawVulnRecord(i), i);
    }
    
    const elapsed = Math.round(performance.now() - startTime);
    logDebug('Denormalization complete in', elapsed, 'ms');
}

/**
 * Denormalize with Worker + IndexedDB caching.
 * Falls back to main-thread denormalization on any failure.
 * @returns {Promise<void>}
 */
async function denormalizeWithCaching() {
    const hasCompressed = !!pendingCompressedBytes;

    // For compressed data, fingerprint and cache checks happen after decompression
    if (!hasCompressed) {
        const fingerprint = computeDataFingerprint();
        const rawCount = getRawVulnCount();
        logDebug('Data fingerprint:', fingerprint);

        // 1. Try IndexedDB cache
        const cached = await getCachedData(fingerprint);
        if (cached && cached.length === rawCount) {
            logDebug('Loaded', cached.length, 'records from IndexedDB cache');
            vulnerabilityData = cached;
            applyDerivedVulnerabilityFields(vulnerabilityData);
            return;
        }
    }

    // 2. Try Web Worker (with optional decompression)
    const compBytes = pendingCompressedBytes;
    pendingCompressedBytes = null;
    try {
        const label = compBytes ? 'decompressing + denormalizing' : 'denormalizing';
        logDebug(label, compBytes ? '(compressed bytes)' : getRawVulnCount(), 'records via Web Worker...');
        const startTime = performance.now();
        const result = await denormalizeInWorker(compBytes);
        vulnerabilityData = result.rows;
        if (result.lookups) lookups = result.lookups;
        if (result.rawVulns) rawVulns = result.rawVulns;
        const elapsed = Math.round(performance.now() - startTime);
        logDebug('Worker complete in', elapsed, 'ms');
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

    applyDerivedVulnerabilityFields(vulnerabilityData);

    // Log counts after data is available
    logDebug('Loaded lookups:', lookups ? Object.keys(lookups) : 'none');
    logDebug('Loaded', getRawVulnCount(), 'vulnerability records');

    // 3. Cache the result (fire-and-forget)
    const fingerprint = computeDataFingerprint();
    logDebug('Data fingerprint:', fingerprint);
    setCachedData(fingerprint, vulnerabilityData);
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize the dashboard on page load
 */
async function init() {
    setDashboardStatus('Loading dashboard data...');

    // Load and process data
    await loadData();
    await denormalizeWithCaching();
    await ensureChartJsLoaded();
    mostRecentLastSeenDate = getMostRecentLastSeen();
    
    logDebug('Initializing dashboard with', vulnerabilityData.length, 'vulnerabilities');
    buildDeviceFilterCatalog();
    populateFilters();
    updateDataQualitySummary();
    attachEventListeners();
    setupInfiniteScroll();
    activeReportId = getCurrentReportId();
    setDateRange('1m');
    clearDashboardStatus();
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
        rbacGroup: getDeviceGroupName(device),
        deviceTags: device.t && device.t.length > 0
            ? device.t.map(tagIndex => lookups.tags[tagIndex])
            : [NO_TAGS_VALUE]
    }));
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
    document.querySelectorAll('.date-range-option').forEach(option => {
        option.addEventListener('click', handleDateRangeChange);
    });
    document.getElementById('filterStartDate').addEventListener('change', handleManualDateChange);
    document.getElementById('filterEndDate').addEventListener('change', handleManualDateChange);
    document.getElementById('reportSelector').addEventListener('change', handleReportChange);
    document.getElementById('exportPdfButton').addEventListener('click', exportToPDF);
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
 * @param {string} range - The range preset (1m, 3m, 6m, 12m)
 */
function setDateRange(range) {
    const endDate = new Date();
    let startDate = new Date();
    
    switch(range) {
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
    }
    
    document.getElementById('filterStartDate').value = startDate.toISOString().split('T')[0];
    document.getElementById('filterEndDate').value = endDate.toISOString().split('T')[0];
    scheduleApplyFilters(true);
}

// =============================================================================
// FILTER MANAGEMENT
// =============================================================================

/**
 * Populate all filter dropdowns with unique values from lookups
 * Uses normalized lookups for efficiency instead of iterating all records
 */
function populateFilters() {
    const osPlatforms = [...lookups.platforms].sort();
    const severities = ['Critical', 'High', 'Medium', 'Low'];

    cascadingFilterOptions = buildCascadingFilterOptions();
    cascadingFilterState = createDefaultCascadingFilterState();

    renderCascadingFilter('filterRbacGroup');
    renderCascadingFilter('filterDeviceTags');
    renderCascadingFilter('filterDeviceName');
    populateCheckboxes('filterOSPlatform', osPlatforms, 'All Platforms', handleOSPlatformChange);
    populateCheckboxes('filterSeverity', severities, 'All Severities', handleSeverityChange);
}

/**
 * Build the option catalog for the cascading device filters.
 * @returns {Object<string, string[]>} Ordered options for each cascading filter
 */
function buildCascadingFilterOptions() {
    const rbacGroups = Array.from(new Set(deviceFilterCatalog.map(device => device.rbacGroup))).sort((a, b) => {
        if (a === NO_GROUP_VALUE && b !== NO_GROUP_VALUE) return -1;
        if (b === NO_GROUP_VALUE && a !== NO_GROUP_VALUE) return 1;
        return a.localeCompare(b);
    });
    const deviceTags = Array.from(new Set(deviceFilterCatalog.flatMap(device => device.deviceTags))).sort((a, b) => {
        if (a === NO_TAGS_VALUE && b !== NO_TAGS_VALUE) return -1;
        if (b === NO_TAGS_VALUE && a !== NO_TAGS_VALUE) return 1;
        return a.localeCompare(b);
    });
    const duplicateNameCounts = deviceFilterCatalog.reduce((counts, device) => {
        counts.set(device.deviceName, (counts.get(device.deviceName) || 0) + 1);
        return counts;
    }, new Map());
    const deviceNames = deviceFilterCatalog
        .map(device => {
            const filterValue = getDeviceNameFilterValue(device);
            const hasDuplicateName = (duplicateNameCounts.get(device.deviceName) || 0) > 1;
            const label = hasDuplicateName && device.deviceId
                ? `${device.deviceName} (${device.deviceId})`
                : device.deviceName;
            return {
                value: filterValue,
                label,
                searchText: hasDuplicateName && device.deviceId
                    ? `${device.deviceName} ${device.deviceId}`
                    : device.deviceName,
                showCount: false
            };
        })
        .sort((a, b) => a.label.localeCompare(b.label));

    return {
        filterRbacGroup: rbacGroups.map(value => ({ value, label: value, searchText: value, showCount: true })),
        filterDeviceTags: deviceTags.map(value => ({ value, label: value, searchText: value, showCount: true })),
        filterDeviceName: deviceNames
    };
}

/**
 * Populate a checkbox filter container
 * @param {string} containerId - The container element ID
 * @param {Array} values - The values to create checkboxes for
 * @param {string} allLabel - Label for the "All" checkbox
 * @param {Function} onChange - Optional callback for change events
 */
function populateCheckboxes(containerId, values, allLabel, onChange) {
    const container = document.getElementById(containerId);
    const filterGroup = container.parentElement;
    container.innerHTML = '';
    
    // Remove existing search input if present
    const existingSearch = filterGroup.querySelector('.filter-search');
    if (existingSearch) existingSearch.remove();
    
    // Add search input BEFORE container if there are more than 1 item
    // Mark the filter group as having search enabled for future rebuilds
    if (values.length > 1) {
        filterGroup.setAttribute('data-has-search', 'true');
        const searchInput = document.createElement('input');
        searchInput.type = 'text';
        searchInput.className = 'filter-search';
        searchInput.placeholder = 'Filter...';
        searchInput.id = `${containerId}_search`;
        let searchTimer = null;
        searchInput.addEventListener('input', function() {
            if (searchTimer) clearTimeout(searchTimer);
            const searchTerm = this.value.toLowerCase();
            searchTimer = window.setTimeout(() => {
                const items = container.querySelectorAll('.checkbox-item:not(:first-child)');
                items.forEach(item => {
                    const label = item.querySelector('label');
                    if (label) {
                        const text = label.textContent.toLowerCase();
                        item.style.display = text.includes(searchTerm) ? 'flex' : 'none';
                    }
                });
            }, APPLY_FILTER_DEBOUNCE_MS);
        });
        filterGroup.insertBefore(searchInput, container);
    }
    
    // Add "All" checkbox
    const allDiv = document.createElement('div');
    allDiv.className = 'checkbox-item';
    const allCheckbox = document.createElement('input');
    allCheckbox.type = 'checkbox';
    allCheckbox.id = `${containerId}_all`;
    allCheckbox.checked = true;
    allCheckbox.addEventListener('change', function() {
        this.indeterminate = false;
        const checkboxes = container.querySelectorAll('input[type="checkbox"]:not(#' + this.id + ')');
        checkboxes.forEach(cb => {
            if (!cb.disabled) {
                cb.checked = this.checked;
            }
        });
        if (onChange) onChange();
        else scheduleApplyFilters();
    });
    const allLabel2 = document.createElement('label');
    allLabel2.setAttribute('for', allCheckbox.id);
    allLabel2.textContent = allLabel;
    allDiv.appendChild(allCheckbox);
    allDiv.appendChild(allLabel2);
    container.appendChild(allDiv);
    
    // Add individual checkboxes
    values.forEach((value, idx) => {
        const div = document.createElement('div');
        div.className = 'checkbox-item';
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.value = value;
        checkbox.id = `${containerId}_${idx}`;
        checkbox.checked = true;
        checkbox.addEventListener('change', function() {
            updateAllCheckbox(containerId);
            if (onChange) onChange();
            else scheduleApplyFilters();
        });
        const label = document.createElement('label');
        label.setAttribute('for', checkbox.id);
        label.textContent = value;
        div.appendChild(checkbox);
        div.appendChild(label);
        container.appendChild(div);
    });
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
    container.innerHTML = '';

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

    const allDiv = document.createElement('div');
    allDiv.className = 'checkbox-item checkbox-item-all';
    const allCheckbox = document.createElement('input');
    allCheckbox.type = 'checkbox';
    allCheckbox.id = `${containerId}_all`;
    allCheckbox.checked = filterEntry.mode === 'all';
    allCheckbox.indeterminate = filterEntry.mode === 'subset' && filterEntry.selectedValues.size > 0;
    allCheckbox.addEventListener('change', function() {
        setCascadingFilterAllMode(containerId, this.checked);
        scheduleApplyFilters(true);
    });

    const allLabel = document.createElement('label');
    allLabel.setAttribute('for', allCheckbox.id);
    allLabel.textContent = CASCADING_FILTER_CONFIG[containerId].allLabel;
    allDiv.appendChild(allCheckbox);
    allDiv.appendChild(allLabel);
    container.appendChild(allDiv);

    options.forEach((option, idx) => {
        const { value, label: optionLabel, searchText, showCount } = option;
        const div = document.createElement('div');
        const count = countMap.get(value) || 0;
        const isExplicitlySelected = filterEntry.mode === 'subset' && filterEntry.selectedValues.has(value);
        if (containerId === 'filterDeviceName' && count === 0 && !isExplicitlySelected) {
            return;
        }
        div.className = count === 0 ? 'checkbox-item checkbox-item-zero' : 'checkbox-item';
        div.dataset.filterLabel = (searchText || optionLabel).toLowerCase();

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.value = value;
        checkbox.id = `${containerId}_${idx}`;
        checkbox.checked = filterEntry.mode === 'all' || filterEntry.selectedValues.has(value);
        checkbox.addEventListener('change', function() {
            toggleCascadingFilterValue(containerId, value, this.checked);
            scheduleApplyFilters(true);
        });

        const label = document.createElement('label');
        label.setAttribute('for', checkbox.id);

        const labelText = document.createElement('span');
        labelText.className = 'checkbox-label-text';
        labelText.textContent = optionLabel;

        label.appendChild(labelText);
        if (showCount) {
            const labelCount = document.createElement('span');
            labelCount.className = 'checkbox-count';
            labelCount.textContent = String(count);
            label.appendChild(labelCount);
        }
        div.appendChild(checkbox);
        div.appendChild(label);
        container.appendChild(div);
    });

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
        if (!matchesFilterStateDate(v, filterState)) return false;
        if (filterState.severitySet.size > 0 && !filterState.severitySet.has(v.VulnerabilitySeverityLevel)) return false;
        if (filterState.osPlatformSet.size > 0 && !filterState.osPlatformSet.has(v.OSPlatform)) return false;
        return true;
    });

    baseRows.forEach(v => {
        CASCADING_FILTER_IDS.forEach(targetFilterId => {
            if (!matchesFiltersForFacetCount(v, targetFilterId)) return;

            const deviceKey = getDeviceIdentityKey(v);
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
    if (targetFilterId !== 'filterDeviceName' && filterState.deviceNameSet.size > 0 && !filterState.deviceNameSet.has(getDeviceNameFilterValue(v))) {
        return false;
    }

    if (targetFilterId !== 'filterRbacGroup' && filterState.rbacGroupSet.size > 0 && !filterState.rbacGroupSet.has(normalizeGroupName(v.RbacGroupName))) {
        return false;
    }

    if (targetFilterId !== 'filterDeviceTags' && filterState.deviceTagSet.size > 0) {
        const vulnTags = CASCADING_FILTER_CONFIG.filterDeviceTags.getValuesForVuln(v);
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
    if (CASCADING_FILTER_IDS.includes(containerId)) {
        return getCascadingFilterSelectionLabels(containerId);
    }

    return isAllChecked(containerId) ? [] : getSelectedCheckboxValues(containerId);
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

function matchesFilterStateNonDate(v, state = filterState) {
    if (state.deviceNameSet.size > 0 && !state.deviceNameSet.has(getDeviceNameFilterValue(v))) return false;
    if (state.rbacGroupSet.size > 0 && !state.rbacGroupSet.has(normalizeGroupName(v.RbacGroupName))) return false;

    if (state.deviceTagSet.size > 0) {
        const vulnTags = v.MachineTags && v.MachineTags.length > 0 ? v.MachineTags : [NO_TAGS_VALUE];
        if (!vulnTags.some(tag => state.deviceTagSet.has(tag))) return false;
    }

    if (state.severitySet.size > 0 && !state.severitySet.has(v.VulnerabilitySeverityLevel)) return false;
    if (state.osPlatformSet.size > 0 && !state.osPlatformSet.has(v.OSPlatform)) return false;
    return true;
}

function matchesFilterStateDate(v, state = filterState) {
    if (!state.startDate && !state.endDate) return true;

    const firstSeen = getFirstSeenDate(v);
    const effectiveEnd = getEffectiveOpenEndDate(v);
    if (state.startDate && effectiveEnd < state.startDate) return false;
    if (state.endDate && firstSeen > state.endDate) return false;
    return true;
}

function matchesFilterState(v, state = filterState) {
    return matchesFilterStateNonDate(v, state) && matchesFilterStateDate(v, state);
}

/**
 * Apply all filters to the vulnerability data
 */
function applyFilters() {
    syncFilterStateFromDom();
    refreshCascadingFilters();

    if (!filterState.hasDeviceNames || !filterState.hasRbacGroups || !filterState.hasDeviceTags || !filterState.hasSeverities || !filterState.hasOsPlatforms) {
        filteredData = [];
        invalidateAggregateCache();
        updateStats();
        markAllReportsDirty();
        renderActiveReport(true);
        return;
    }

    filteredData = vulnerabilityData.filter(v => matchesFilterState(v, filterState));

    invalidateAggregateCache();
    updateStats();
    markAllReportsDirty();
    renderActiveReport(true);
}

// =============================================================================
// STATISTICS
// =============================================================================

/**
 * Update the statistics summary cards
 */
function updateStats() {
    const statsRows = getActiveRowsForCurrentSelection();
    const severityCounts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    };

    statsRows.forEach(v => {
        if (severityCounts.hasOwnProperty(v.VulnerabilitySeverityLevel)) {
            severityCounts[v.VulnerabilitySeverityLevel]++;
        }
    });

    document.getElementById('criticalCount').textContent = severityCounts['Critical'];
    document.getElementById('highCount').textContent = severityCounts['High'];
    document.getElementById('mediumCount').textContent = severityCounts['Medium'];
    document.getElementById('lowCount').textContent = severityCounts['Low'];
}

/**
 * Render data quality summary for the loaded dataset.
 */
function updateDataQualitySummary() {
    if (!document.querySelector('.data-quality-panel')) return;
    if (!Array.isArray(vulnerabilityData) || vulnerabilityData.length === 0) return;

    const totalRecords = vulnerabilityData.length;
    const uniqueDevices = new Set();
    const uniqueCves = new Set();
    let missingPublished = 0;
    let nonYmdPublished = 0;
    let invertedRanges = 0;

    vulnerabilityData.forEach(v => {
        const deviceKey = getDeviceIdentityKey(v);
        if (deviceKey) uniqueDevices.add(deviceKey);
        if (v.CveId) uniqueCves.add(v.CveId);

        const publishedDate = v.PublishedDate;
        if (!publishedDate) {
            missingPublished++;
        } else {
            const normalizedPublished = formatDateYMD(publishedDate);
            if (normalizedPublished === '-' || !/^\d{4}-\d{2}-\d{2}$/.test(normalizedPublished)) {
                nonYmdPublished++;
            }
        }

        const firstSeen = getFirstSeenDate(v);
        const lastSeen = getLastSeenDate(v);
        if (firstSeen && firstSeen !== '-' && lastSeen && lastSeen !== '-' && firstSeen > lastSeen) {
            invertedRanges++;
        }
    });

    const setText = (id, value) => {
        const element = document.getElementById(id);
        if (element) element.textContent = value.toLocaleString();
    };

    setText('dqTotalRecords', totalRecords);
    setText('dqUniqueDevices', uniqueDevices.size);
    setText('dqUniqueCves', uniqueCves.size);
    setText('dqMissingPublished', missingPublished);
    setText('dqNonYmdPublished', nonYmdPublished);
    setText('dqInvertedRanges', invertedRanges);
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
function formatSoftwareName(vendor, product) {
    if (!vendor || !product) return 'Unknown';
    
    // Capitalize first letter of each word and replace underscores with spaces
    const formatPart = (text) => {
        return text
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
            .join(' ');
    };
    
    return `${formatPart(vendor)} - ${formatPart(product)}`;
}

/**
 * Find the most recent LastSeenTimestamp across all data
 * @returns {string} The most recent date in YYYY-MM-DD format
 */
function getMostRecentLastSeen() {
    let mostRecentLastSeen = '';
    vulnerabilityData.forEach(v => {
        const lastSeenDate = getRowLatestActivityDate(v);
        if (lastSeenDate > mostRecentLastSeen) {
            mostRecentLastSeen = lastSeenDate;
        }
    });
    return mostRecentLastSeen;
}

function getPointInTimeReferenceDate() {
    return filterState.endDate || mostRecentLastSeenDate;
}

function hasSelectedDateWindow(state = filterState) {
    return Boolean(state.startDate || state.endDate);
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
    const cacheKey = hasSelectedDateWindow()
        ? `range:${filterState.startDate || ''}:${filterState.endDate || ''}`
        : `point:${getPointInTimeReferenceDate()}`;

    if (cache.activeRowsForCurrentSelectionKey === cacheKey && cache.activeRowsForCurrentSelection) {
        return cache.activeRowsForCurrentSelection;
    }

    cache.activeRowsForCurrentSelectionKey = cacheKey;
    cache.activeRowsForCurrentSelection = hasSelectedDateWindow()
        ? filteredData
        : getPointInTimeActiveRows();
    return cache.activeRowsForCurrentSelection;
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
function nextDay(dateStr) {
    return formatUtcDateAsYmd(addDaysToUtcDate(parseYmdDateAsUtc(dateStr), 1));
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
    const firstSeen = getFirstSeenDate(v);
    const effectiveEnd = getEffectiveOpenEndDate(v);
    if (!firstSeen || !effectiveEnd) return false;
    return firstSeen <= dateStr && effectiveEnd >= dateStr;
}

function applyDerivedVulnerabilityFields(rows) {
    if (!Array.isArray(rows)) return;

    const earliestEnvironmentFirstSeenByIssue = new Map();

    rows.forEach(v => {
        const issueKey = getEnvironmentIssueKey(v);
        const firstSeenDate = getFirstSeenDate(v);
        if (!issueKey || !firstSeenDate) return;

        const existing = earliestEnvironmentFirstSeenByIssue.get(issueKey);
        if (!existing || firstSeenDate < existing) {
            earliestEnvironmentFirstSeenByIssue.set(issueKey, firstSeenDate);
        }
    });

    rows.forEach(v => {
        const machineLastSeenDate = getMachineLastSeenDate(v);
        const latestActivityDate = getRowLatestActivityDate(v);
        const remediationEvidence = hasKnownPatchEvidence(v);
        const effectiveOpenEndDate = getEffectiveOpenEndDate(v);
        const environmentFirstSeenDate = earliestEnvironmentFirstSeenByIssue.get(getEnvironmentIssueKey(v)) || getFirstSeenDate(v);

        v._machineLastSeenDate = machineLastSeenDate;
        v._latestActivityDate = latestActivityDate;
        v._hasPatchEvidence = remediationEvidence;
        v._effectiveOpenEndDate = effectiveOpenEndDate;
        v._remediationDate = remediationEvidence ? getLastSeenDate(v) : '';
        v._environmentFirstSeenDate = environmentFirstSeenDate;
        v.EnvironmentFirstSeenTimestamp = environmentFirstSeenDate;
    });
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

/**
 * Build remediation HTML with link from vulnerability data.
 * Returns an <a> tag linking to RecommendedSecurityUpdateUrl when available,
 * otherwise returns plain escaped text.
 * @param {Object} v - Vulnerability object (or any object with RecommendedSecurityUpdate/Id/Url)
 * @returns {string} HTML string for the remediation cell
 */
function buildRemediationHtml(v) {
    const text = buildRemediationString(v);
    if (v.RecommendedSecurityUpdateUrl) {
        return `<a href="${escapeHtml(v.RecommendedSecurityUpdateUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)}</a>`;
    }
    return escapeHtml(text);
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
        sortedDates = generateDateRange(startDate, endDate);
        severityCounts = { Critical: [], High: [], Medium: [], Low: [] };
        totalCounts = [];
        deviceCounts = [];
        const candidates = filteredData;

        const events = new Map();
        candidates.forEach(v => {
            const sd = getFirstSeenDate(v);
            let ed = nextDay(getEffectiveOpenEndDate(v));
            if (ed <= sd) { ed = nextDay(sd); }
            if (!events.has(sd)) events.set(sd, { starts: [], ends: [] });
            events.get(sd).starts.push(v);
            if (!events.has(ed)) events.set(ed, { starts: [], ends: [] });
            events.get(ed).ends.push(v);
        });

        let sweepTotal = 0;
        const sweepSeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        const deviceActive = new Map();
        const processStart = (v) => {
            sweepTotal++;
            const sev = v.VulnerabilitySeverityLevel;
            if (sweepSeverity[sev] !== undefined) sweepSeverity[sev]++;
            const deviceKey = getDeviceIdentityKey(v);
            deviceActive.set(deviceKey, (deviceActive.get(deviceKey) || 0) + 1);
        };
        const processEnd = (v) => {
            if (sweepTotal > 0) sweepTotal--;
            const sev = v.VulnerabilitySeverityLevel;
            if (sweepSeverity[sev] !== undefined && sweepSeverity[sev] > 0) sweepSeverity[sev]--;
            const deviceKey = getDeviceIdentityKey(v);
            const dc = deviceActive.get(deviceKey);
            if (dc <= 1) deviceActive.delete(deviceKey);
            else deviceActive.set(deviceKey, dc - 1);
        };

        const rangeStart = sortedDates[0];
        const allEventDates = [...events.keys()].sort();
        for (const eventDate of allEventDates) {
            if (eventDate >= rangeStart) break;
            const ev = events.get(eventDate);
            ev.starts.forEach(processStart);
            ev.ends.forEach(processEnd);
        }

        sortedDates.forEach(date => {
            const ev = events.get(date);
            if (ev) {
                ev.starts.forEach(processStart);
                ev.ends.forEach(processEnd);
            }
            totalCounts.push(sweepTotal);
            deviceCounts.push(deviceActive.size);
            severityCounts.Critical.push(sweepSeverity.Critical);
            severityCounts.High.push(sweepSeverity.High);
            severityCounts.Medium.push(sweepSeverity.Medium);
            severityCounts.Low.push(sweepSeverity.Low);
        });

        chartDataCache = { sortedDates, severityCounts, totalCounts, deviceCounts };
        chartDataCacheKey = cacheKey;
    }

    const cutoffIndex = sortedDates.findIndex(date => date > mostRecentLastSeenDate);

    if (chartInstance) {
        chartInstance.destroy();
    }

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

// =============================================================================
// ACTIVE VULNERABILITIES TABLE
// =============================================================================

function getRemediationTableData() {
    const cache = getAggregateCache();
    if (cache.remediationTableData) return cache.remediationTableData;

    const remediationMap = {};
    const activeRows = getActiveRowsForCurrentSelection();

    activeRows.forEach(v => {
        const remediation = buildRemediationString(v);
        const formatPart = (text) => {
            if (!text) return 'Unknown';
            return text.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()).join(' ');
        };
        const vendor = formatPart(v.SoftwareVendor);
        const software = formatPart(v.SoftwareName);
        const key = `${vendor}|${software}|${remediation}`;

        if (!remediationMap[key]) {
            remediationMap[key] = {
                vendor: vendor,
                software: software,
                remediation: remediation,
                remediationHtml: buildRemediationHtml(v),
                devices: new Set(),
                vulnerabilities: new Set(),
                exploits: new Set(),
                kits: new Set(),
                details: [],
                _modalCache: null
            };
        }

        remediationMap[key].devices.add(getDeviceIdentityKey(v));
        remediationMap[key].vulnerabilities.add(v.CveId);

        if (v.ExploitabilityLevel === 'ExploitIsVerified' || v.ExploitabilityLevel === 'ExploitIsPublic' || v.ExploitabilityLevel === 'ExploitIsInKit') {
            remediationMap[key].exploits.add(v.CveId);
        }

        if (v.ExploitabilityLevel === 'ExploitIsInKit') {
            remediationMap[key].kits.add(v.CveId);
        }

        remediationMap[key].details.push(v);
    });

    cache.remediationTableData = Object.values(remediationMap)
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
        const remediation = buildRemediationString(v);
        const key = `${lastSeenDate}|${remediation}`;

        if (!remediationByDate[key]) {
            remediationByDate[key] = {
                date: lastSeenDate,
                remediation: remediation,
                remediationHtml: buildRemediationHtml(v),
                devices: new Set(),
                vulnerabilities: new Set(),
                details: [],
                _modalCache: null
            };
        }

        remediationByDate[key].devices.add(getDeviceIdentityKey(v));
        remediationByDate[key].vulnerabilities.add(v.CveId);
        remediationByDate[key].details.push(v);
    });

    cache.remediationDetailsData = Object.values(remediationByDate)
        .sort((a, b) => b.date.localeCompare(a.date));

    return cache.remediationDetailsData;
}

function getImpactAnalysisData() {
    const cache = getAggregateCache();
    if (cache.impactData) return cache.impactData;

    const remediationMap = {};
    const activeRows = getActiveRowsForCurrentSelection();
    activeRows.forEach(v => {
        const remediation = buildRemediationString(v);

        if (!remediationMap[remediation]) {
            remediationMap[remediation] = {
                remediationHtml: buildRemediationHtml(v),
                devices: new Set(),
                vulnerabilities: []
            };
        }

        remediationMap[remediation].devices.add(getDeviceIdentityKey(v));
        remediationMap[remediation].vulnerabilities.push(v);
    });

    const top25 = Object.entries(remediationMap)
        .map(([name, data]) => ({
            name: name,
            nameHtml: data.remediationHtml,
            impact: data.devices.size * new Set(data.vulnerabilities.map(v => v.CveId)).size,
            vulnerabilities: data.vulnerabilities
        }))
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
            case 3: aValue = a.devices.size; bValue = b.devices.size; break;
            case 4: aValue = a.vulnerabilities.size; bValue = b.vulnerabilities.size; break;
            case 5: aValue = a.exploits.size; bValue = b.exploits.size; break;
            case 6: aValue = a.kits.size; bValue = b.kits.size; break;
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
    
    const sortedDates = generateDateRange(startDate, endDate);
    
    // Track remediations (vulnerabilities that ended) per day
    const severityCounts = {
        Critical: [],
        High: [],
        Medium: [],
        Low: []
    };
    const totalRemediationCounts = [];
    const deviceCounts = [];
    
    // Build remediation index: O(F) pre-computation instead of O(D×F) scanning
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
        const severityRemediations = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        
        vulnsOnDate.forEach(v => {
            const severity = v.VulnerabilitySeverityLevel;
            remediationsOnDate.add(v._index);
            devicesOnDate.add(getDeviceIdentityKey(v));
            if (severityRemediations[severity] !== undefined) severityRemediations[severity]++;
        });
        
        severityCounts.Critical.push(severityRemediations.Critical);
        severityCounts.High.push(severityRemediations.High);
        severityCounts.Medium.push(severityRemediations.Medium);
        severityCounts.Low.push(severityRemediations.Low);
        totalRemediationCounts.push(remediationsOnDate.size);
        deviceCounts.push(devicesOnDate.size);
    });
    
    // Find the index where we transition from actual data to projected (dashed) data
    const cutoffIndex = sortedDates.findIndex(date => date > mostRecentLastSeenDate);
    
    if (remediationChartInstance) {
        remediationChartInstance.destroy();
    }
    
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
            case 2: aValue = a.devices.size; bValue = b.devices.size; break;
            case 3: aValue = a.vulnerabilities.size; bValue = b.vulnerabilities.size; break;
            case 4: aValue = a.devices.size * a.vulnerabilities.size; bValue = b.devices.size * b.vulnerabilities.size; break;
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
    
    const { top25, top25VulnIds } = getImpactAnalysisData();
    const sortedDates = generateDateRange(startDate, endDate);
    
    // Calculate current and projected counts for each date
    const currentSeverityCounts = {
        Critical: [],
        High: [],
        Medium: [],
        Low: []
    };
    const projectedSeverityCounts = {
        Critical: [],
        High: [],
        Medium: [],
        Low: []
    };
    const currentTotalCounts = [];
    const projectedTotalCounts = [];
    
    // Build start/end events for sweep-line
    const impactEvents = new Map();
    
    filteredData.forEach(v => {
        const isTop25 = top25VulnIds.has(v._index);
        const sd = getFirstSeenDate(v);
        let ed = nextDay(getEffectiveOpenEndDate(v));
        
        // Data validation: ensure end date is after start date
        if (ed <= sd) {
            ed = nextDay(sd);
        }
        
        if (!impactEvents.has(sd)) impactEvents.set(sd, { starts: [], ends: [], isTop25Starts: new Set(), isTop25Ends: new Set() });
        impactEvents.get(sd).starts.push(v);
        if (isTop25) impactEvents.get(sd).isTop25Starts.add(v._index);
        if (!impactEvents.has(ed)) impactEvents.set(ed, { starts: [], ends: [], isTop25Starts: new Set(), isTop25Ends: new Set() });
        impactEvents.get(ed).ends.push(v);
        if (isTop25) impactEvents.get(ed).isTop25Ends.add(v._index);
    });
    
    let sweepCurrentTotal = 0;
    let sweepProjectedTotal = 0;
    let sweepCurrentSev = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    let sweepProjectedSev = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    
    const processImpactStart = (v, isTop25) => {
        sweepCurrentTotal++;
        const sev = v.VulnerabilitySeverityLevel;
        if (sweepCurrentSev[sev] !== undefined) sweepCurrentSev[sev]++;
        if (!isTop25) {
            sweepProjectedTotal++;
            if (sweepProjectedSev[sev] !== undefined) sweepProjectedSev[sev]++;
        }
    };
    
    const processImpactEnd = (v, isTop25) => {
        if (sweepCurrentTotal > 0) sweepCurrentTotal--;
        const sev = v.VulnerabilitySeverityLevel;
        if (sweepCurrentSev[sev] !== undefined && sweepCurrentSev[sev] > 0) sweepCurrentSev[sev]--;
        if (!isTop25) {
            if (sweepProjectedTotal > 0) sweepProjectedTotal--;
            if (sweepProjectedSev[sev] !== undefined && sweepProjectedSev[sev] > 0) sweepProjectedSev[sev]--;
        }
    };
    
    const impactRangeStart = sortedDates[0];
    const allImpactDates = [...impactEvents.keys()].sort();
    for (const eventDate of allImpactDates) {
        if (eventDate >= impactRangeStart) break;
        const ev = impactEvents.get(eventDate);
        ev.starts.forEach(v => processImpactStart(v, ev.isTop25Starts.has(v._index)));
        ev.ends.forEach(v => processImpactEnd(v, ev.isTop25Ends.has(v._index)));
    }
    
    // Sweep through visible dates
    sortedDates.forEach(date => {
        const ev = impactEvents.get(date);
        if (ev) {
            ev.starts.forEach(v => processImpactStart(v, ev.isTop25Starts.has(v._index)));
            ev.ends.forEach(v => processImpactEnd(v, ev.isTop25Ends.has(v._index)));
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
    
    // Find the index where we transition from actual data to projected (dashed) data
    const cutoffIndex = sortedDates.findIndex(date => date > mostRecentLastSeenDate);
    
    if (impactChartInstance) {
        impactChartInstance.destroy();
    }
    
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

// =============================================================================
// IMPACT ANALYSIS TABLE
// =============================================================================

/**
 * Render the impact analysis table
 */
function renderImpactAnalysisTable() {
    const tbody = document.getElementById('impactAnalysisTableBody');
    tbody.innerHTML = '';

    const { top25 } = getImpactAnalysisData();
    if (!top25 || top25.length === 0) {
        const row = tbody.insertRow();
        row.innerHTML = '<td colspan="5">No data available</td>';
        updateImpactAnalysisScrollInfo();
        return;
    }

    impactAnalysisAllData = top25.map((item, index) => {
        const cveIds = new Set(item.vulnerabilities.map(v => v.CveId));
        const devices = new Set(item.vulnerabilities.map(v => getDeviceIdentityKey(v)));
        return {
            rank: index + 1,
            name: item.name,
            nameHtml: item.nameHtml || escapeHtml(item.name),
            devices: devices.size,
            cveIds: cveIds.size,
            impact: item.impact,
            details: item
        };
    });
    
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
        row.innerHTML = '<td colspan="5">No data available</td>';
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
            case 2: aValue = a.devices; bValue = b.devices; break;
            case 3: aValue = a.cveIds; bValue = b.cveIds; break;
            case 4: aValue = a.impact; bValue = b.impact; break;
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
        const activeRows = getActiveRowsForCurrentSelection();

        activeRows.forEach(v => {
            const updateName = v.RecommendedSecurityUpdate || 'Unknown';
            const updateId = v.RecommendedSecurityUpdateId || '';
            const osPlatform = v.OSPlatform || 'Unknown';
            const batchTitle = v.CveBatchTitle || updateName;
            const key = `${updateName}|${updateId}|${osPlatform}`;

            if (!remediationByKey[key]) {
                remediationByKey[key] = {
                    updateName: updateName,
                    batchTitle: batchTitle,
                    updateId: updateId,
                    updateUrl: v.RecommendedSecurityUpdateUrl,
                    osPlatform: osPlatform,
                    devices: new Map(),
                    cves: new Set(),
                    severities: { Critical: 0, High: 0, Medium: 0, Low: 0 },
                    cveDetails: new Map()
                };
            }

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
                    lastSeenTimestamp: v.LastSeenTimestamp,
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
        });

        Object.values(remediationByKey).forEach(data => {
            data.cveDetails.forEach(cveDetail => {
                if (data.severities.hasOwnProperty(cveDetail.severityLevel)) {
                    data.severities[cveDetail.severityLevel]++;
                }
            });
        });

        cache.devicesByRemediationData = Object.entries(remediationByKey).map(([key, data]) => ({
            key: key,
            updateName: data.updateName,
            batchTitle: data.batchTitle,
            updateId: data.updateId,
            updateUrl: data.updateUrl,
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
    
    // Build header using CveBatchTitle
    const kbText = data.updateId ? ` (KB${data.updateId})` : '';
    const headerText = `${index}. ${data.batchTitle}${kbText}`;
    
    // Extract CVE details
    let mostRecentDate = null;
    const affectedSoftwareSet = new Set();
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
            
            // Collect unique affected software
            if (details.affectedSoftware && Array.isArray(details.affectedSoftware)) {
                details.affectedSoftware.forEach(sw => affectedSoftwareSet.add(sw));
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
    
    // Build update link with icon
    const updateLink = data.updateUrl 
        ? `<a href="${data.updateUrl}" target="_blank" rel="noopener noreferrer" class="remediation-link">
             <svg class="link-icon" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
               <path fill="currentColor" d="M7.775 3.275a.75.75 0 001.06 1.06l1.25-1.25a2 2 0 112.83 2.83l-2.5 2.5a2 2 0 01-2.83 0 .75.75 0 00-1.06 1.06 3.5 3.5 0 004.95 0l2.5-2.5a3.5 3.5 0 00-4.95-4.95l-1.25 1.25zm-4.69 9.64a2 2 0 010-2.83l2.5-2.5a2 2 0 012.83 0 .75.75 0 001.06-1.06 3.5 3.5 0 00-4.95 0l-2.5 2.5a3.5 3.5 0 004.95 4.95l1.25-1.25a.75.75 0 00-1.06-1.06l-1.25 1.25a2 2 0 01-2.83 0z"></path>
             </svg>
             Recommended Update
           </a>`
        : '';
    
    // Build CVE details section
    let cveDetailsHtml = '';
    if (mostRecentDate || data.updateName !== 'Unknown') {
        cveDetailsHtml = '<div class="cve-details">';
        
        // Published date badge
        if (mostRecentDate) {
            cveDetailsHtml += `<span class="stat-badge">Published: ${mostRecentDate}</span>`;
        }
        
        // Recommended Update badge
        if (data.updateUrl) {
            cveDetailsHtml += `<a href="${data.updateUrl}" target="_blank" rel="noopener noreferrer" class="stat-badge remediation-update-badge">
                <span>Update: ${escapeHtml(data.updateName)}</span>
                <svg class="link-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                    <polyline points="15 3 21 3 21 9"></polyline>
                    <line x1="10" y1="14" x2="21" y2="3"></line>
                </svg>
            </a>`;
        } else if (data.updateName && data.updateName !== 'Unknown') {
            cveDetailsHtml += `<span class="stat-badge">Update: ${escapeHtml(data.updateName)}</span>`;
        }
        
        cveDetailsHtml += '</div>';
    }
    
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
            const tooltipId = `cve-${cve.id}`;
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
            <h3>${headerText}</h3>
            ${cveDetailsHtml}
        </div>
        ${cveBadgesSection}
        <div class="devices-header-row">
            <h4>Vulnerable Devices</h4>
            <div class="remediation-stats">
                <div class="stat-badges">
                    <span class="stat-badge">Devices: ${data.deviceCount}</span>
                    <span class="stat-badge">CVEs: ${data.cveCount}</span>
                </div>
            </div>
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

/**
 * Render the remediations by device table
 */
function renderRemediationsByDeviceTable() {
    clearTooltipCaches();
    const cache = getAggregateCache();
    if (!cache.remediationsByDeviceData) {
        const deviceByKey = {};
        const deviceCveDetails = {};
        const activeRows = getActiveRowsForCurrentSelection();

        activeRows.forEach(v => {
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

            const batchTitle = v.CveBatchTitle || v.RecommendedSecurityUpdate || 'Unknown';
            const updateName = v.RecommendedSecurityUpdate || 'Unknown';
            const updateId = v.RecommendedSecurityUpdateId || '';
            const osPlatform = v.OSPlatform || 'Unknown';
            const remKey = `${batchTitle}|${updateId}|${osPlatform}`;

            if (!deviceByKey[deviceId].remediations.has(remKey)) {
                deviceByKey[deviceId].remediations.set(remKey, {
                    batchTitle: batchTitle,
                    updateName: updateName,
                    updateId: updateId,
                    updateUrl: v.RecommendedSecurityUpdateUrl,
                    osPlatform: osPlatform,
                    cves: new Set(),
                    cveDetails: new Map(),
                    severities: { Critical: 0, High: 0, Medium: 0, Low: 0 },
                    publishedDates: []
                });
            }

            const rem = deviceByKey[deviceId].remediations.get(remKey);
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

            device.remediations.forEach(rem => {
                rem.cvesBySeverity = { Critical: [], High: [], Medium: [], Low: [] };
                rem.cveDetails.forEach((cveDetail, cveId) => {
                    if (rem.severities.hasOwnProperty(cveDetail.severityLevel)) {
                        rem.severities[cveDetail.severityLevel]++;
                        rem.cvesBySeverity[cveDetail.severityLevel].push(cveId);
                    }
                });

                rem.mostRecentDate = getMostRecentYmdDate(rem.publishedDates);
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
    
    // Convert remediations map to array and sort by score (highest first)
    const sortedRemediations = Array.from(data.remediations.values()).sort((a, b) => b.score - a.score);
    
    // Build remediation table rows
    const remediationRows = sortedRemediations.map(rem => {
        // Column 1: Remediation name (batch title + KB)
        const kbText = rem.updateId ? ` (KB${rem.updateId})` : '';
        const remediationName = `${rem.batchTitle}${kbText}`;
        
        // Column 2: Update link
        const updateCell = rem.updateUrl 
            ? `<a href="${rem.updateUrl}" target="_blank" rel="noopener noreferrer" class="remediation-update-badge">
                 <span>${escapeHtml(rem.updateName)}</span>
                 <svg class="link-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                     <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                     <polyline points="15 3 21 3 21 9"></polyline>
                     <line x1="10" y1="14" x2="21" y2="3"></line>
                 </svg>
               </a>`
            : escapeHtml(rem.updateName);
        
        // Column 3: Severities with tooltips
        const severityBadges = ['Critical', 'High', 'Medium', 'Low']
            .filter(sev => rem.severities[sev] > 0)
            .map(sev => {
                const tooltipId = `severity-${severityBadgeIdCounter++}`;
                severityTooltipData[tooltipId] = generateSeverityTooltipContent(rem.cvesBySeverity[sev]);
                return `<span class="severity-badge ${sev.toLowerCase()}" data-tooltip-id="${tooltipId}">${sev}: ${rem.severities[sev]}</span>`;
            })
            .join(' ');
        
        // Column 4: CVE count
        const cveCount = rem.cves.size;
        
        // Column 5: Published date
        const publishedDate = rem.mostRecentDate || '';
        
        return `
            <tr>
                <td>${escapeHtml(remediationName)}</td>
                <td>${updateCell}</td>
                <td>${severityBadges}</td>
                <td>${cveCount}</td>
                <td>${publishedDate}</td>
            </tr>
        `;
    }).join('');
    
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
            <h4>Remediations Needed</h4>
            <div class="remediation-stats">
                <div class="stat-badges">
                    <span class="stat-badge">Remediations: ${data.remediationCount}</span>
                    <span class="stat-badge">CVEs: ${data.cveCount}</span>
                </div>
            </div>
        </div>
        <div class="devices-table-container">
            <table class="devices-table">
                <thead>
                    <tr>
                        <th>Remediation</th>
                        <th>Update</th>
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
        if (mi.ip)  tooltipContent += `<br><span class="tooltip-label">IP:</span> ${escapeHtml(mi.ip)}`;
        if (mi.eip) tooltipContent += `<br><span class="tooltip-label">External IP:</span> ${escapeHtml(mi.eip)}`;
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
        lastSeen: v._lastSeenDate || v.LastSeenTimestamp
    });

    if (cveUrl) {
        return `<td><a href="${escapeHtml(cveUrl)}" target="_blank" rel="noopener noreferrer" class="cve-severity-badge ${severityClass}" data-tooltip-id="${tooltipId}">${escapeHtml(displayId)}</a></td>`;
    }

    return `<td><span class="cve-severity-badge ${severityClass}" data-tooltip-id="${tooltipId}">${escapeHtml(displayId)}</span></td>`;
}

/**
 * Group devices by their shared CVE signature (identical set of CVE IDs)
 * @param {Array} details - Array of denormalized vulnerability objects
 * @returns {Array} Array of { signature, deviceBubbles: [{DeviceName,DeviceId,MachineInfo}], vulns: [unique vuln per CVE] }
 */
function groupDevicesByCveSignature(details) {
    const mergeModalObservationRow = (existing, candidate) => {
        const existingFirstSeen = getFirstSeenDate(existing);
        const candidateFirstSeen = getFirstSeenDate(candidate);
        const existingLastSeen = getLastSeenDate(existing);
        const candidateLastSeen = getLastSeenDate(candidate);
        const existingRecency = getMostRecentYmdDate([existingLastSeen, getRowLatestActivityDate(existing)]);
        const candidateRecency = getMostRecentYmdDate([candidateLastSeen, getRowLatestActivityDate(candidate)]);
        const useCandidateMetadata = Boolean(candidateRecency && (!existingRecency || candidateRecency >= existingRecency));
        const merged = useCandidateMetadata
            ? { ...existing, ...candidate }
            : { ...candidate, ...existing };

        const earliestFirstSeen = getEarliestYmdDate([existingFirstSeen, candidateFirstSeen]);
        const latestLastSeen = getMostRecentYmdDate([existingLastSeen, candidateLastSeen]);

        if (earliestFirstSeen) {
            merged.FirstSeenTimestamp = earliestFirstSeen;
            merged._firstSeenDate = earliestFirstSeen;
        }

        if (latestLastSeen) {
            merged.LastSeenTimestamp = latestLastSeen;
            merged._lastSeenDate = latestLastSeen;
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
    const remediation = remediationData.vendor + ' ' + remediationData.software + ' - ' + remediationData.remediation;

    modalTitle.textContent = remediation;
    modalBody.innerHTML = '<p class="loading">Loading details...</p>';
    lastFocusedElementBeforeModal = (typeof HTMLElement !== 'undefined' && document.activeElement instanceof HTMLElement) ? document.activeElement : null;
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    clearTooltipCaches();
    focusModalCloseButton();

    if (!document.getElementById('cve-global-tooltip')) {
        initCveTooltips();
    }

    // Defer heavy work so the modal + loading indicator render first
    requestAnimationFrame(() => {
        const modalCache = remediationData._modalCache || buildModalGroupCache(details);
        remediationData._modalCache = modalCache;
        const { groups, includeEvidenceColumn, totalDevices, totalCves } = modalCache;

        const parts = [];
        const vtRowData = {};

        parts.push('<h3>Affected Devices and Vulnerabilities</h3>');

        // Add update link above the table (right-aligned) if URL is available
        const updateUrl = details.find(d => d.RecommendedSecurityUpdateUrl);
        if (updateUrl) {
            const updateText = buildRemediationString(updateUrl);
            parts.push('<div class="modal-update-link-row">');
            parts.push('<strong>Update Details:</strong><br>');
            parts.push('<a class="modal-update-link" href="' + escapeHtml(updateUrl.RecommendedSecurityUpdateUrl) + '" target="_blank" rel="noopener noreferrer">&#x1F517; ' + escapeHtml(updateText) + '</a>');
            parts.push('</div>');
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
    clearTooltipCaches();
    focusModalCloseButton();

    if (!document.getElementById('cve-global-tooltip')) {
        initCveTooltips();
    }

    requestAnimationFrame(() => {
        const modalCache = data._modalCache || buildModalGroupCache(data.details);
        data._modalCache = modalCache;
        const { groups, includeEvidenceColumn } = modalCache;
        const vtRowData = {};

        const parts = [];
        parts.push('<h3>Summary</h3>',
            '<div class="modal-table-container"><table class="detail-table"><tr>',
            '<td><strong>Date:</strong> ', escapeHtml(data.date), '</td>',
            '<td><strong>Assets Remediated:</strong> ', String(data.devices.size), '</td>',
            '<td><strong>Vulnerabilities Remediated:</strong> ', String(data.vulnerabilities.size), '</td>',
            '</tr></table></div><br>',
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
    
    let html = '<h3>Affected Devices</h3>';
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
    clearTooltipCaches();
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

/**
 * Load PDF libraries on demand.
 * The embedded bundle contains html2canvas + pdfmake + vfs_fonts.
 */
function loadPdfLibraries() {
    if (pdfLibrariesLoaded) {
        return Promise.resolve();
    }
    
    return new Promise((resolve, reject) => {
        try {
            const pdfBundleMode = dashboardConfig.pdfExportBundleMode || 'embedded';
            if (pdfBundleMode === 'external') {
                loadExternalScript(dashboardConfig.pdfExportBundleUrl)
                    .then(() => {
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
                if (typeof pdfMake !== 'undefined' && typeof pdfMake.createPdf === 'function' && typeof html2canvas === 'function') {
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
    });
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
    const maxCards = Math.min(cards.length, 50); // Limit to 50 cards
    const isDevicesByRemediation = selectedReport === 'devices-by-remediation';
    
    for (let i = 0; i < maxCards; i++) {
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
        const table = card.querySelector('.devices-table');
        let tableBody = [];
        let tableHeaders = [];
        let tableWidths = [];
        
        if (table) {
            const headerCells = table.querySelectorAll('thead th');
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
    
    if (cards.length > maxCards) {
        docContent.push({
            text: `Note: Only the first ${maxCards} remediation items are included in this PDF. The full report contains ${cards.length} items.`,
            fontSize: 10,
            italics: true,
            color: '#666666',
            margin: [0, 10, 0, 0]
        });
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
        if (tableHeaders.length === 7) {
            columnWidths = [60, 70, '*', 40, 40, 40, 30];
        } else if (tableHeaders.length === 5) {
            // Differentiate between Remediation Activity and Impact Analysis reports
            if (selectedReport === 'impact-analysis') {
                // Impact Analysis: Rank, Remediation, Devices, CVE IDs, Impact Score
                columnWidths = [36, '*', 40, 40, 66];
            } else {
                // Remediation Activity: Date, Remediation, Assets Remediated, Vulnerabilities Remediated, Total Vulnerabilities Remediated
                columnWidths = [55, '*', 60, 69, 69];
            }
        } else {
            columnWidths = Array(tableHeaders.length).fill('*');
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
        const startDate = document.getElementById('filterStartDate').value;
        const endDate = document.getElementById('filterEndDate').value;
        const selectedDateRange = document.querySelector('#filterDateRange .date-range-option.selected');
        const dateRangeText = selectedDateRange ? selectedDateRange.textContent.trim() : 'Custom';
        
        const deviceGroups = getSelectedFilterValuesForExport('filterRbacGroup');
        const deviceNames = getSelectedFilterValuesForExport('filterDeviceName');
        const osPlatforms = getSelectedFilterValuesForExport('filterOSPlatform');
        const severities = getSelectedFilterValuesForExport('filterSeverity');
        
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
                { text: deviceGroups.length > 0 ? deviceGroups.join(', ') : 'All Groups' }
            ],
            margin: [0, 2, 0, 2],
            fontSize: 10
        });
        
        if (deviceNames.length > 0 && deviceNames.length <= 10) {
            filterContent.push({
                text: [
                    { text: 'Device Names: ', bold: true },
                    { text: deviceNames.join(', ') }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 10
            });
        } else if (deviceNames.length > 10) {
            filterContent.push({
                text: [
                    { text: 'Device Names: ', bold: true },
                    { text: `${deviceNames.length} devices selected` }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 10
            });
        } else {
            filterContent.push({
                text: [
                    { text: 'Device Names: ', bold: true },
                    { text: 'All Devices' }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 10
            });
        }
        
        filterContent.push({
            text: [
                { text: 'OS Platforms: ', bold: true },
                { text: osPlatforms.length > 0 ? osPlatforms.join(', ') : 'All Platforms' }
            ],
            margin: [0, 2, 0, 2],
            fontSize: 10
        });
        
        filterContent.push({
            text: [
                { text: 'Severities: ', bold: true },
                { text: severities.length > 0 ? severities.join(', ') : 'All Severities' }
            ],
            margin: [0, 2, 0, 2],
            fontSize: 10
        });
        
        docDefinition.content.push(...filterContent);
        
        updateProgress(90, 'Creating PDF...');
        pdfMake.createPdf(docDefinition).download(fileName);
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
