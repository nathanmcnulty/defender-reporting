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

// Data format: 'normalized' or 'compressed'
const dataFormat = document.getElementById('dataFormat').textContent.trim();

// Lookup tables and raw vulnerability array (loaded from embedded data)
let lookups = null;
let rawVulns = null;
let dataQualityMeta = { firstLastSwapped: 0, generatedOnUtc: null };

// Denormalized vulnerability data (expanded from normalized format)
let vulnerabilityData = [];

// Filtered data based on current filter selections
let filteredData = [];

// Chart instances (for cleanup on re-render)
let chartInstance = null;
let remediationChartInstance = null;
let impactChartInstance = null;

// Device group to device name mapping
let allDevicesByGroup = {};

// All unique tags across all devices
let allDeviceTags = new Set();

// Constant for devices without tags
const NO_TAGS_VALUE = '(No Tags)';

// Table sort state
let sortDirection = {};
let sortRemediationDetailsDirection = {};
let sortImpactAnalysisDirection = {};

// Infinite scroll state
const PAGE_SIZE = 100; // Number of rows to load per scroll batch

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
    const len = rawVulns.length;
    if (len === 0) return 'empty';
    // Sample up to 10 records evenly distributed across the array
    const sampleCount = Math.min(10, len);
    let sample = '' + len;
    for (let i = 0; i < sampleCount; i++) {
        const idx = Math.floor(i * len / sampleCount);
        sample += JSON.stringify(rawVulns[idx]);
    }
    // Include key lookup-table slices so enrichment-only changes invalidate cache
    if (lookups) {
        const lookupKeys = ['cves', 'updates', 'dates', 'batchTitles', 'affSoftware'];
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
 * Build the Web Worker source code as a string.
 * The worker receives lookups + rawVulns and returns the denormalized array.
 */
function buildWorkerSource() {
    // We stringify the denormalize logic so it runs inside the worker context
    return `
'use strict';
self.onmessage = function(e) {
    var lookups = e.data.lookups;
    var rawVulns = e.data.rawVulns;
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
    var result = new Array(rawVulns.length);
    for (var i = 0; i < rawVulns.length; i++) {
        var v = rawVulns[i];
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

        var vendorName = lookups.vendors[software.v];
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
            RbacGroupName: lookups.groups[device.g],
            OSPlatform: lookups.platforms[device.o],
            OSVersion: device.ov,
            MachineTags: tagNames,
            MachineInfo: device.m || null,
            CveId: cve.id,
            CvssScore: cve.sc,
            VulnerabilitySeverityLevel: lookups.severities[cve.sv],
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
    self.postMessage(result);
};
`;
}

/**
 * Run denormalization in a Web Worker.
 * Falls back to main-thread if Worker is unavailable.
 * @returns {Promise<Array>}
 */
function denormalizeInWorker() {
    return new Promise((resolve, reject) => {
        try {
            const blob = new Blob([buildWorkerSource()], { type: 'application/javascript' });
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

            // Transfer data to worker
            worker.postMessage({ lookups, rawVulns });
        } catch (err) {
            reject(err);
        }
    });
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
     * @param {Array} rows - Array of HTML strings, one per <tr>
     * @param {number} rowHeight - Estimated row height in px
     */
    constructor(scrollContainer, tbody, rows, rowHeight = 36) {
        this.container = scrollContainer;
        this.tbody = tbody;
        this.rows = rows;
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
        const totalRows = this.rows.length;
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
        this.topSpacer.innerHTML = `<td colspan="99" style="height:${topH}px;padding:0;border:0;"></td>`;
        fragment.appendChild(this.topSpacer);

        // Visible rows
        const template = document.createElement('template');
        template.innerHTML = this.rows.slice(startIdx, endIdx).join('');
        fragment.appendChild(template.content);

        // Bottom spacer
        const bottomH = (totalRows - endIdx) * this.rowHeight;
        this.bottomSpacer.innerHTML = `<td colspan="99" style="height:${bottomH}px;padding:0;border:0;"></td>`;
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
 * Load and decompress data from embedded scripts
 */
function loadData() {
    console.log('Loading data, format:', dataFormat);
    
    if (dataFormat === 'compressed') {
        // Decompress using pako
        const compressedBase64 = document.getElementById('vulnsData').textContent.trim();
        const compressedBytes = Uint8Array.from(atob(compressedBase64), c => c.charCodeAt(0));
        const decompressed = pako.inflate(compressedBytes, { to: 'string' });
        const data = JSON.parse(decompressed);
        lookups = data.lookups;
        rawVulns = data.vulns;
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
    
    console.log('Loaded lookups:', Object.keys(lookups));
    console.log('Loaded', rawVulns.length, 'vulnerability records');
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
        RbacGroupName: lookups.groups[device.g],
        OSPlatform: lookups.platforms[device.o],
        OSVersion: device.ov,
        MachineTags: tagNames,
        MachineInfo: device.m || null,
        
        // CVE info
        CveId: cve.id,
        CvssScore: cve.sc,
        VulnerabilitySeverityLevel: lookups.severities[cve.sv],
        ExploitabilityLevel: cve.ex >= 0 ? lookups.exploitLevels[cve.ex] : null,
        CveBatchUrl: cve.u,
        CveBatchTitle: batchTitle,
        PublishedDate: formatDateYMD(cve.pd) || null,
        VulnerabilityDescription: cve.desc || null,
        EpssScore: cve.ep ?? null,
        AffectedSoftware: affSoftware,
        
        // Software info
        SoftwareVendor: lookups.vendors[software.v],
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
    console.log('Denormalizing', rawVulns.length, 'records (main thread)...');
    const startTime = performance.now();
    
    vulnerabilityData = rawVulns.map((v, i) => denormalizeVuln(v, i));
    
    const elapsed = Math.round(performance.now() - startTime);
    console.log('Denormalization complete in', elapsed, 'ms');
}

/**
 * Denormalize with Worker + IndexedDB caching.
 * Falls back to main-thread denormalization on any failure.
 * @returns {Promise<void>}
 */
async function denormalizeWithCaching() {
    const fingerprint = computeDataFingerprint();
    console.log('Data fingerprint:', fingerprint);

    // 1. Try IndexedDB cache
    const cached = await getCachedData(fingerprint);
    if (cached && cached.length === rawVulns.length) {
        console.log('Loaded', cached.length, 'records from IndexedDB cache');
        vulnerabilityData = cached;
        return;
    }

    // 2. Try Web Worker
    try {
        console.log('Denormalizing', rawVulns.length, 'records via Web Worker...');
        const startTime = performance.now();
        vulnerabilityData = await denormalizeInWorker();
        const elapsed = Math.round(performance.now() - startTime);
        console.log('Worker denormalization complete in', elapsed, 'ms');
    } catch (err) {
        console.warn('Web Worker failed, falling back to main thread:', err);
        denormalizeAllVulns();
    }

    // 3. Cache the result (fire-and-forget)
    setCachedData(fingerprint, vulnerabilityData);
}

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize the dashboard on page load
 */
async function init() {
    // Load and process data
    loadData();
    await denormalizeWithCaching();
    
    console.log('Initializing dashboard with', vulnerabilityData.length, 'vulnerabilities');
    buildDeviceGroupMap();
    buildDeviceTagsSet();
    populateFilters();
    setDateRange('1m'); // Set default to 1 month
    updateDataQualitySummary();
    updateStats();
    renderChart();
    renderTable();
    attachEventListeners();
    setupInfiniteScroll();
    renderRemediationChart();
    renderRemediationDetailsTable();
    renderImpactChart();
    renderImpactAnalysisTable();
}

/**
 * Set up infinite scroll event listeners using window scroll
 */
function setupInfiniteScroll() {
    // Use window scroll since tables don't have fixed height containers
    window.addEventListener('scroll', handleWindowScroll);
}

/**
 * Handle window scroll for infinite loading
 */
function handleWindowScroll() {
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
 * Build device group to device name mapping for filter cascading
 * Uses lookups data from normalized structure
 */
function buildDeviceGroupMap() {
    allDevicesByGroup = {};
    
    // Build from lookups - each device has a group index
    lookups.devices.forEach(device => {
        const groupName = lookups.groups[device.g];
        if (!allDevicesByGroup[groupName]) {
            allDevicesByGroup[groupName] = new Set();
        }
        allDevicesByGroup[groupName].add(device.n);
    });
}

/**
 * Build set of all unique device tags from lookups data
 */
function buildDeviceTagsSet() {
    allDeviceTags = new Set();
    
    // Add all tags from lookups
    lookups.tags.forEach(tag => allDeviceTags.add(tag));
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

    // Hide all report sections
    document.querySelectorAll('.report-section').forEach(section => {
        section.classList.remove('active');
    });

    // Show selected report section
    const activeSection = document.getElementById(selectedReport + '-section');
    if (activeSection) {
        activeSection.classList.add('active');
    }
}

/**
 * Handle date range preset selection
 */
function handleDateRangeChange(event) {
    const row = event.currentTarget;
    const range = row.getAttribute('data-range');
    
    // Remove selected class from all rows
    document.querySelectorAll('.date-range-table tr').forEach(tr => {
        tr.classList.remove('selected');
    });
    
    // Add selected class to clicked row
    row.classList.add('selected');
    
    // Update dates based on selection
    setDateRange(range);
}

/**
 * Handle manual date input change
 */
function handleManualDateChange() {
    // Remove selected class from all rows when dates are manually changed
    document.querySelectorAll('.date-range-table tr').forEach(tr => {
        tr.classList.remove('selected');
    });
    applyFilters();
}

/**
 * Handle device group filter change (triggers cascade to other device filters)
 */
function handleDeviceGroupChange() {
    updateDeviceFiltersCascade('filterRbacGroup');
}

/**
 * Handle device tags filter change (triggers cascade to other device filters)
 */
function handleDeviceTagsChange() {
    updateDeviceFiltersCascade('filterDeviceTags');
}

/**
 * Handle device name filter change (triggers cascade to other device filters)
 */
function handleDeviceNameChange() {
    updateDeviceFiltersCascade('filterDeviceName');
}

/**
 * Handle OS platform filter change (no cascade, just apply filters)
 */
function handleOSPlatformChange() {
    applyFilters();
}

/**
 * Handle severity filter change (no cascade, just apply filters)
 */
function handleSeverityChange() {
    applyFilters();
}

/**
 * Attach event listeners to filter controls
 */
function attachEventListeners() {
    document.querySelectorAll('.date-range-table tr').forEach(row => {
        row.addEventListener('click', handleDateRangeChange);
    });
    document.getElementById('filterStartDate').addEventListener('change', handleManualDateChange);
    document.getElementById('filterEndDate').addEventListener('change', handleManualDateChange);
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
    applyFilters();
}

// =============================================================================
// FILTER MANAGEMENT
// =============================================================================

/**
 * Populate all filter dropdowns with unique values from lookups
 * Uses normalized lookups for efficiency instead of iterating all records
 */
function populateFilters() {
    // Get values directly from lookups - much faster than iterating all records
    const rbacGroups = [...lookups.groups].sort();
    const osPlatforms = [...lookups.platforms].sort();
    const severities = ['Critical', 'High', 'Medium', 'Low'];
    
    // Device names from lookups.devices
    const deviceNames = lookups.devices.map(d => d.n).sort();
    
    // Build device tags list including "(No Tags)" option
    const deviceTags = buildDeviceTagsList();

    populateCheckboxes('filterRbacGroup', rbacGroups, 'All Groups', handleDeviceGroupChange);
    populateCheckboxes('filterDeviceTags', deviceTags, 'All Tags', handleDeviceTagsChange);
    populateCheckboxes('filterDeviceName', deviceNames, 'All Devices', handleDeviceNameChange);
    populateCheckboxes('filterOSPlatform', osPlatforms, 'All Platforms', handleOSPlatformChange);
    populateCheckboxes('filterSeverity', severities, 'All Severities', handleSeverityChange);
}

/**
 * Build the device tags list including "(No Tags)" option if needed
 * @returns {Array} Sorted array of tag names
 */
function buildDeviceTagsList() {
    // Get tags from lookups
    const tags = [...lookups.tags].sort();
    
    // Move "(No Tags)" to the front if it exists
    const idx = tags.indexOf(NO_TAGS_VALUE);
    if (idx > 0) {
        tags.splice(idx, 1);
        tags.unshift(NO_TAGS_VALUE);
    }
    
    return tags;
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
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const items = container.querySelectorAll('.checkbox-item:not(:first-child)');
            items.forEach(item => {
                const label = item.querySelector('label');
                if (label) {
                    const text = label.textContent.toLowerCase();
                    item.style.display = text.includes(searchTerm) ? 'flex' : 'none';
                }
            });
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
        const checkboxes = container.querySelectorAll('input[type="checkbox"]:not(#' + this.id + ')');
        checkboxes.forEach(cb => cb.checked = this.checked);
        if (onChange) onChange();
        else applyFilters();
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
            else applyFilters();
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
 * Update the "All" checkbox state based on individual checkboxes
 * @param {string} containerId - The container element ID
 */
function updateAllCheckbox(containerId) {
    const container = document.getElementById(containerId);
    const allCheckbox = container.querySelector(`#${containerId}_all`);
    const otherCheckboxes = container.querySelectorAll('input[type="checkbox"]:not(#' + allCheckbox.id + ')');
    const allChecked = Array.from(otherCheckboxes).every(cb => cb.checked);
    allCheckbox.checked = allChecked;
}

/**
 * Update cascading filters for device-related filters only
 * Device Group, Device Tags, and Device Name cascade with each other
 * OS Platform and Severity do NOT cascade - they just filter the data
 * @param {string} changedFilter - The device filter that was just changed
 */
function updateDeviceFiltersCascade(changedFilter) {
    // Only device filters cascade with each other
    const deviceFilters = {
        filterRbacGroup: { getValue: v => v.RbacGroupName },
        filterDeviceTags: { getValue: v => v.MachineTags && v.MachineTags.length > 0 ? v.MachineTags : [NO_TAGS_VALUE] },
        filterDeviceName: { getValue: v => v.DeviceName }
    };
    
    // Get current selection from the filter that changed
    const changedSelection = getSelectedCheckboxValues(changedFilter);
    const isChangedFilterAllChecked = isAllChecked(changedFilter);
    
    // Get date range for filtering
    const startDate = document.getElementById('filterStartDate').value;
    const endDate = document.getElementById('filterEndDate').value;
    
    // Create a filter function for the changed filter
    const changedFilterSet = new Set(changedSelection);
    const changedConfig = deviceFilters[changedFilter];
    
    const passesChangedFilter = (v) => {
        if (isChangedFilterAllChecked || changedFilterSet.size === 0) return true;
        const value = changedConfig.getValue(v);
        if (Array.isArray(value)) {
            return value.some(val => changedFilterSet.has(val));
        }
        return changedFilterSet.has(value);
    };
    
    // Date filter
    const passesDateFilter = (v) => {
        if (!startDate && !endDate) return true;
        const firstSeen = getFirstSeenDate(v);
        const lastSeen = getLastSeenDate(v);
        if (startDate && lastSeen < startDate) return false;
        if (endDate && firstSeen > endDate) return false;
        return true;
    };
    
    // Calculate available values for other device filters
    const availableValues = {
        filterRbacGroup: new Set(),
        filterDeviceTags: new Set(),
        filterDeviceName: new Set()
    };
    
    // Single pass through data to collect available values
    vulnerabilityData.forEach(v => {
        if (!passesDateFilter(v)) return;
        if (!passesChangedFilter(v)) return;
        
        // This record passes the changed filter, so add its values to other device filters
        for (const [filterId, config] of Object.entries(deviceFilters)) {
            if (filterId === changedFilter) continue; // Skip the filter that changed
            
            const value = config.getValue(v);
            if (Array.isArray(value)) {
                value.forEach(val => availableValues[filterId].add(val));
            } else {
                availableValues[filterId].add(value);
            }
        }
    });
    
    // Update checkbox states in other device filters only
    for (const filterId of Object.keys(deviceFilters)) {
        if (filterId === changedFilter) continue;
        updateCheckboxStates(filterId, availableValues[filterId]);
    }
    
    applyFilters();
}

/**
 * Update checkbox states in a filter - check items that have data, uncheck items that don't
 * All checkboxes remain visible, only their checked state changes
 * @param {string} containerId - The filter container ID
 * @param {Set} availableValues - Set of values that have matching data
 */
function updateCheckboxStates(containerId, availableValues) {
    const container = document.getElementById(containerId);
    const checkboxes = container.querySelectorAll('input[type="checkbox"]:not(#' + containerId + '_all)');
    
    checkboxes.forEach(cb => {
        // Check the box if its value has matching data
        cb.checked = availableValues.has(cb.value);
    });
    
    // Update "All" checkbox state
    updateAllCheckbox(containerId);
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

/**
 * Apply all filters to the vulnerability data
 */
function applyFilters() {
    const startDate = document.getElementById('filterStartDate').value;
    const endDate = document.getElementById('filterEndDate').value;
    const deviceNames = getSelectedCheckboxValues('filterDeviceName');
    const rbacGroups = getSelectedCheckboxValues('filterRbacGroup');
    const deviceTags = getSelectedCheckboxValues('filterDeviceTags');
    const severities = getSelectedCheckboxValues('filterSeverity');
    const osPlatforms = getSelectedCheckboxValues('filterOSPlatform');

    // Check if any checkboxes are selected for each filter
    const hasDeviceNames = hasAnyChecked('filterDeviceName');
    const hasRbacGroups = hasAnyChecked('filterRbacGroup');
    const hasDeviceTags = hasAnyChecked('filterDeviceTags');
    const hasSeverities = hasAnyChecked('filterSeverity');
    const hasOsPlatforms = hasAnyChecked('filterOSPlatform');

    // Early exit if any filter has nothing selected - show no data
    if (!hasDeviceNames || !hasRbacGroups || !hasDeviceTags || !hasSeverities || !hasOsPlatforms) {
        filteredData = [];
        updateStats();
        renderChart();
        renderTable();
        renderRemediationChart();
        renderRemediationDetailsTable();
        renderImpactChart();
        renderImpactAnalysisTable();
        return;
    }

    // Convert to Sets for O(1) lookups
    const deviceNameSet = new Set(deviceNames);
    const rbacGroupSet = new Set(rbacGroups);
    const deviceTagSet = new Set(deviceTags);
    const severitySet = new Set(severities);
    const osPlatformSet = new Set(osPlatforms);

    filteredData = vulnerabilityData.filter(v => {
        // Date filtering: vulnerability must overlap with the date range
        // Vulnerability is active from FirstSeenTimestamp to LastSeenTimestamp
        if (startDate || endDate) {
            // Use pre-computed dates (falls back to split if not available)
            const firstSeen = getFirstSeenDate(v);
            const lastSeen = getLastSeenDate(v);
            
            // Check if vulnerability period overlaps with filter period
            if (startDate && lastSeen < startDate) return false; // Ended before range starts
            if (endDate && firstSeen > endDate) return false; // Started after range ends
        }
        
        // Apply selected checkbox filters using Set.has() for O(1) lookups
        if (deviceNameSet.size > 0 && !deviceNameSet.has(v.DeviceName)) return false;
        if (rbacGroupSet.size > 0 && !rbacGroupSet.has(v.RbacGroupName)) return false;
        
        // Device Tags filter with OR logic
        if (deviceTagSet.size > 0) {
            const vulnTags = v.MachineTags && v.MachineTags.length > 0 ? v.MachineTags : [NO_TAGS_VALUE];
            // OR logic: device matches if it has ANY of the selected tags
            const hasMatchingTag = vulnTags.some(tag => deviceTagSet.has(tag));
            if (!hasMatchingTag) return false;
        }
        
        if (severitySet.size > 0 && !severitySet.has(v.VulnerabilitySeverityLevel)) return false;
        if (osPlatformSet.size > 0 && !osPlatformSet.has(v.OSPlatform)) return false;
        return true;
    });

    updateStats();
    renderChart();
    renderTable();
    renderRemediationChart();
    renderRemediationDetailsTable();
    renderImpactChart();
    renderImpactAnalysisTable();
    renderDevicesByRemediationTable();
    renderRemediationsByDeviceTable();
}

// =============================================================================
// STATISTICS
// =============================================================================

/**
 * Update the statistics summary cards
 */
function updateStats() {
    const severityCounts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    };

    filteredData.forEach(v => {
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
        if (v.DeviceId) uniqueDevices.add(v.DeviceId);
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
        // Use pre-computed date (falls back to split if not available)
        const lastSeenDate = getLastSeenDate(v);
        if (lastSeenDate > mostRecentLastSeen) {
            mostRecentLastSeen = lastSeenDate;
        }
    });
    return mostRecentLastSeen;
}

/**
 * Generate array of dates between start and end
 * @param {string} startDate - Start date in YYYY-MM-DD format
 * @param {string} endDate - End date in YYYY-MM-DD format
 * @returns {Array} Array of date strings
 */
function generateDateRange(startDate, endDate) {
    const sortedDates = [];
    let currentDate = new Date(startDate);
    const end = new Date(endDate);
    
    while (currentDate <= end) {
        sortedDates.push(currentDate.toISOString().split('T')[0]);
        currentDate.setDate(currentDate.getDate() + 1);
    }
    return sortedDates;
}

/**
 * Get the next day as a YYYY-MM-DD string
 * @param {string} dateStr - Date in YYYY-MM-DD format
 * @returns {string} Next day in YYYY-MM-DD format
 */
function nextDay(dateStr) {
    const d = new Date(dateStr);
    d.setDate(d.getDate() + 1);
    return d.toISOString().split('T')[0];
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

/**
 * Get first-seen date as normalized YYYY-MM-DD (or empty string).
 * @param {Object} v - Vulnerability object
 * @returns {string}
 */
function getFirstSeenDate(v) {
    const normalized = formatDateYMD(v._firstSeenDate || v.FirstSeenTimestamp);
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
        return `<a href="${escapeHtml(v.RecommendedSecurityUpdateUrl)}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">${escapeHtml(text)}</a>`;
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
    
    const startDate = document.getElementById('filterStartDate').value;
    const endDate = document.getElementById('filterEndDate').value;
    
    if (!startDate || !endDate) {
        console.log('No date range selected');
        return;
    }

    const mostRecentLastSeen = getMostRecentLastSeen();
    const sortedDates = generateDateRange(startDate, endDate);
    
    // For each date in range, count ALL vulnerabilities (from full dataset) that are active
    // Apply non-date filters to determine which vulnerabilities to count
    const deviceNames = getSelectedCheckboxValues('filterDeviceName');
    const rbacGroups = getSelectedCheckboxValues('filterRbacGroup');
    const deviceTags = getSelectedCheckboxValues('filterDeviceTags');
    const severities = getSelectedCheckboxValues('filterSeverity');
    const osPlatforms = getSelectedCheckboxValues('filterOSPlatform');
    
    const hasDeviceNames = hasAnyChecked('filterDeviceName');
    const hasRbacGroups = hasAnyChecked('filterRbacGroup');
    const hasDeviceTags = hasAnyChecked('filterDeviceTags');
    const hasSeverities = hasAnyChecked('filterSeverity');
    const hasOsPlatforms = hasAnyChecked('filterOSPlatform');
    
    const severityCounts = {
        Critical: [],
        High: [],
        Medium: [],
        Low: []
    };
    const totalCounts = [];
    const deviceCounts = [];
    
    let lastActualTotal = 0;
    let lastActualDeviceCount = 0;
    let lastActualSeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    
    // Pre-convert filter arrays to Sets for O(1) lookups in the inner loop
    const deviceNameSet = new Set(deviceNames);
    const rbacGroupSet = new Set(rbacGroups);
    const deviceTagSet = new Set(deviceTags);
    const severitySet = new Set(severities);
    const osPlatformSet = new Set(osPlatforms);
    
    // Pre-filter: apply non-date filters once instead of D×N times
    let candidates;
    if (!hasDeviceNames || !hasRbacGroups || !hasDeviceTags || !hasSeverities || !hasOsPlatforms) {
        candidates = [];
    } else {
        candidates = vulnerabilityData.filter(v => {
            if (deviceNameSet.size > 0 && !deviceNameSet.has(v.DeviceName)) return false;
            if (rbacGroupSet.size > 0 && !rbacGroupSet.has(v.RbacGroupName)) return false;
            if (deviceTagSet.size > 0) {
                const vulnTags = v.MachineTags && v.MachineTags.length > 0 ? v.MachineTags : [NO_TAGS_VALUE];
                if (!vulnTags.some(tag => deviceTagSet.has(tag))) return false;
            }
            if (severitySet.size > 0 && !severitySet.has(v.VulnerabilitySeverityLevel)) return false;
            if (osPlatformSet.size > 0 && !osPlatformSet.has(v.OSPlatform)) return false;
            return true;
        });
    }
    
    filteredData = candidates;
    
    // Build start/end events for sweep-line algorithm
    const events = new Map();
    candidates.forEach(v => {
        const sd = getFirstSeenDate(v);
        let ed = nextDay(getLastSeenDate(v));
        
        // Data validation: ensure end date is after start date
        if (ed <= sd) {
            ed = nextDay(sd);
        }
        
        if (!events.has(sd)) events.set(sd, { starts: [], ends: [] });
        events.get(sd).starts.push(v);
        if (!events.has(ed)) events.set(ed, { starts: [], ends: [] });
        events.get(ed).ends.push(v);
    });
    
    // Running sweep state
    let sweepTotal = 0;
    const sweepSeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    const deviceActive = new Map(); // deviceName -> active vuln count
    
    const processStart = (v) => {
        sweepTotal++;
        const sev = v.VulnerabilitySeverityLevel;
        if (sweepSeverity[sev] !== undefined) sweepSeverity[sev]++;
        deviceActive.set(v.DeviceName, (deviceActive.get(v.DeviceName) || 0) + 1);
    };
    const processEnd = (v) => {
        if (sweepTotal > 0) sweepTotal--;
        const sev = v.VulnerabilitySeverityLevel;
        if (sweepSeverity[sev] !== undefined && sweepSeverity[sev] > 0) sweepSeverity[sev]--;
        const dc = deviceActive.get(v.DeviceName);
        if (dc <= 1) deviceActive.delete(v.DeviceName);
        else deviceActive.set(v.DeviceName, dc - 1);
    };
    
    // Process events before the visible date range to establish initial state
    const rangeStart = sortedDates[0];
    const allEventDates = [...events.keys()].sort();
    for (const eventDate of allEventDates) {
        if (eventDate >= rangeStart) break;
        const ev = events.get(eventDate);
        ev.starts.forEach(processStart);
        ev.ends.forEach(processEnd);
    }
    
    // Sweep through visible dates
    sortedDates.forEach(date => {
        if (date > mostRecentLastSeen) {
            totalCounts.push(lastActualTotal);
            deviceCounts.push(lastActualDeviceCount);
            severityCounts.Critical.push(lastActualSeverity.Critical);
            severityCounts.High.push(lastActualSeverity.High);
            severityCounts.Medium.push(lastActualSeverity.Medium);
            severityCounts.Low.push(lastActualSeverity.Low);
            return;
        }
        
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
        
        lastActualTotal = sweepTotal;
        lastActualDeviceCount = deviceActive.size;
        lastActualSeverity = { ...sweepSeverity };
    });
    
    // Find the index where we transition from actual data to projected (dashed) data
    const cutoffIndex = sortedDates.findIndex(date => date > mostRecentLastSeen);

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
                        text: 'Active Vulnerabilities Over Time',
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

/**
 * Render the remediation table
 */
function renderTable() {
    const remediationMap = {};

    filteredData.forEach(v => {
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
                details: []
            };
        }

        remediationMap[key].devices.add(v.DeviceId);
        remediationMap[key].vulnerabilities.add(v.CveId);
        
        if (v.ExploitabilityLevel === 'ExploitIsVerified' || v.ExploitabilityLevel === 'ExploitIsPublic' || v.ExploitabilityLevel === 'ExploitIsInKit') {
            remediationMap[key].exploits.add(v.CveId);
        }
        
        if (v.ExploitabilityLevel === 'ExploitIsInKit') {
            remediationMap[key].kits.add(v.CveId);
        }

        remediationMap[key].details.push(v);
    });

    const tbody = document.getElementById('remediationTableBody');
    tbody.innerHTML = '';

    // Sort by vulnerabilities count descending and store for infinite scroll
    remediationAllData = Object.values(remediationMap)
        .sort((a, b) => b.vulnerabilities.size - a.vulnerabilities.size);

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
        // Show all rows
        remediationAllData.forEach(rem => {
            appendRemediationRow(tbody, rem);
        });
        remediationLoadedCount = remediationAllData.length;
    } else {
        // Show initial batch
        const endIdx = Math.min(PAGE_SIZE, remediationAllData.length);
        for (let i = 0; i < endIdx; i++) {
            appendRemediationRow(tbody, remediationAllData[i]);
        }
        remediationLoadedCount = endIdx;
    }
    
    updateRemediationScrollInfo();
}

/**
 * Append a single row to the remediation table
 */
function appendRemediationRow(tbody, rem) {
    const row = tbody.insertRow();
    row.innerHTML = `
        <td>${rem.vendor}</td>
        <td>${rem.software}</td>
        <td>${rem.remediationHtml}</td>
        <td>${rem.devices.size}</td>
        <td>${rem.vulnerabilities.size}</td>
        <td>${rem.exploits.size}</td>
        <td>${rem.kits.size}</td>
    `;
    row.onclick = () => showDetails(rem.vendor + ' ' + rem.software + ' - ' + rem.remediation, rem.details);
}

/**
 * Load more remediation rows on scroll
 */
function loadMoreRemediationRows() {
    const tbody = document.getElementById('remediationTableBody');
    const startIdx = remediationLoadedCount;
    const endIdx = Math.min(startIdx + PAGE_SIZE, remediationAllData.length);
    
    for (let i = startIdx; i < endIdx; i++) {
        appendRemediationRow(tbody, remediationAllData[i]);
    }
    
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
    
    const startDate = document.getElementById('filterStartDate').value;
    const endDate = document.getElementById('filterEndDate').value;
    
    if (!startDate || !endDate) {
        console.log('No date range selected for remediation chart');
        return;
    }
    
    const mostRecentLastSeen = getMostRecentLastSeen();
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
    filteredData.forEach(v => {
        const lastSeenDate = getLastSeenDate(v);
        if (!remediationIndex.has(lastSeenDate)) remediationIndex.set(lastSeenDate, []);
        remediationIndex.get(lastSeenDate).push(v);
    });
    
    sortedDates.forEach(date => {
        if (date > mostRecentLastSeen) {
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
            devicesOnDate.add(v.DeviceName);
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
    const cutoffIndex = sortedDates.findIndex(date => date > mostRecentLastSeen);
    
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
    const remediationByDate = {};
    
    filteredData.forEach(v => {
        // Use pre-computed date (falls back to split if not available)
        const lastSeenDate = getLastSeenDate(v);
        const remediation = buildRemediationString(v);
        const key = `${lastSeenDate}|${remediation}`;
        
        if (!remediationByDate[key]) {
            remediationByDate[key] = {
                date: lastSeenDate,
                remediation: remediation,
                remediationHtml: buildRemediationHtml(v),
                devices: new Set(),
                vulnerabilities: new Set(),
                details: []
            };
        }
        
        remediationByDate[key].devices.add(v.DeviceName);
        remediationByDate[key].vulnerabilities.add(v.CveId);
        remediationByDate[key].details.push(v);
    });
    
    const tbody = document.getElementById('remediationDetailsTableBody');
    tbody.innerHTML = '';
    
    // Sort by date descending and store for infinite scroll
    remediationDetailsAllData = Object.values(remediationByDate).sort((a, b) => {
        return b.date.localeCompare(a.date);
    });
    
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
        // Show all rows
        remediationDetailsAllData.forEach(data => {
            appendRemediationDetailsRow(tbody, data);
        });
        remediationDetailsLoadedCount = remediationDetailsAllData.length;
    } else {
        // Show initial batch
        const endIdx = Math.min(PAGE_SIZE, remediationDetailsAllData.length);
        for (let i = 0; i < endIdx; i++) {
            appendRemediationDetailsRow(tbody, remediationDetailsAllData[i]);
        }
        remediationDetailsLoadedCount = endIdx;
    }
    
    updateRemediationDetailsScrollInfo();
}

/**
 * Append a single row to the remediation details table
 */
function appendRemediationDetailsRow(tbody, data) {
    const total = data.devices.size * data.vulnerabilities.size;
    const row = tbody.insertRow();
    row.innerHTML = `
        <td>${data.date}</td>
        <td>${data.remediationHtml}</td>
        <td>${data.devices.size}</td>
        <td>${data.vulnerabilities.size}</td>
        <td>${total}</td>
    `;
    row.onclick = () => showRemediationDetails(data);
}

/**
 * Load more remediation details rows on scroll
 */
function loadMoreRemediationDetailsRows() {
    const tbody = document.getElementById('remediationDetailsTableBody');
    const startIdx = remediationDetailsLoadedCount;
    const endIdx = Math.min(startIdx + PAGE_SIZE, remediationDetailsAllData.length);
    
    for (let i = startIdx; i < endIdx; i++) {
        appendRemediationDetailsRow(tbody, remediationDetailsAllData[i]);
    }
    
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
    
    const startDate = document.getElementById('filterStartDate').value;
    const endDate = document.getElementById('filterEndDate').value;
    
    if (!startDate || !endDate) {
        console.log('No date range selected for impact chart');
        return;
    }
    
    // Build remediation map to find top 25
    const remediationMap = {};
    filteredData.forEach(v => {
        const remediation = buildRemediationString(v);
        
        if (!remediationMap[remediation]) {
            remediationMap[remediation] = {
                remediationHtml: buildRemediationHtml(v),
                devices: new Set(),
                vulnerabilities: []
            };
        }
        
        remediationMap[remediation].devices.add(v.DeviceName);
        remediationMap[remediation].vulnerabilities.push(v);
    });
    
    // Calculate impact for each remediation and get top 25
    const remediationImpacts = Object.entries(remediationMap).map(([name, data]) => {
        const impact = data.devices.size * new Set(data.vulnerabilities.map(v => v.CveId)).size;
        return {
            name: name,
            nameHtml: data.remediationHtml,
            impact: impact,
            vulnerabilities: data.vulnerabilities
        };
    });
    
    // Sort by impact and get top 25
    const top25 = remediationImpacts
        .sort((a, b) => b.impact - a.impact)
        .slice(0, 25);
    
    // Create set of vulnerability IDs that would be removed
    const top25VulnIds = new Set();
    top25.forEach(rem => {
        rem.vulnerabilities.forEach(v => {
            top25VulnIds.add(v._index);
        });
    });
    
    const mostRecentLastSeen = getMostRecentLastSeen();
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
    
    let lastActualCurrentTotal = 0;
    let lastActualProjectedTotal = 0;
    let lastActualCurrentSeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    let lastActualProjectedSeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    
    // Build start/end events for sweep-line
    const impactEvents = new Map();
    
    filteredData.forEach(v => {
        const isTop25 = top25VulnIds.has(v._index);
        const sd = getFirstSeenDate(v);
        let ed = nextDay(getLastSeenDate(v));
        
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
        if (date > mostRecentLastSeen) {
            currentTotalCounts.push(lastActualCurrentTotal);
            projectedTotalCounts.push(lastActualProjectedTotal);
            currentSeverityCounts.Critical.push(lastActualCurrentSeverity.Critical);
            currentSeverityCounts.High.push(lastActualCurrentSeverity.High);
            currentSeverityCounts.Medium.push(lastActualCurrentSeverity.Medium);
            currentSeverityCounts.Low.push(lastActualCurrentSeverity.Low);
            projectedSeverityCounts.Critical.push(lastActualProjectedSeverity.Critical);
            projectedSeverityCounts.High.push(lastActualProjectedSeverity.High);
            projectedSeverityCounts.Medium.push(lastActualProjectedSeverity.Medium);
            projectedSeverityCounts.Low.push(lastActualProjectedSeverity.Low);
            return;
        }
        
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
        
        lastActualCurrentTotal = sweepCurrentTotal;
        lastActualProjectedTotal = sweepProjectedTotal;
        lastActualCurrentSeverity = { ...sweepCurrentSev };
        lastActualProjectedSeverity = { ...sweepProjectedSev };
    });
    
    // Find the index where we transition from actual data to projected (dashed) data
    const cutoffIndex = sortedDates.findIndex(date => date > mostRecentLastSeen);
    
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
    
    window.top25RemediationsData = top25;
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
    
    if (!window.top25RemediationsData || window.top25RemediationsData.length === 0) {
        const row = tbody.insertRow();
        row.innerHTML = '<td colspan="5">No data available</td>';
        updateImpactAnalysisScrollInfo();
        return;
    }
    
    // Store for infinite scroll
    impactAnalysisAllData = window.top25RemediationsData.map((item, index) => {
        const cveIds = new Set(item.vulnerabilities.map(v => v.CveId));
        const devices = new Set(item.vulnerabilities.map(v => v.DeviceName));
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
        // Show all rows
        impactAnalysisAllData.forEach(item => {
            appendImpactAnalysisRow(tbody, item);
        });
        impactAnalysisLoadedCount = impactAnalysisAllData.length;
    } else {
        // Show initial batch
        const endIdx = Math.min(PAGE_SIZE, impactAnalysisAllData.length);
        for (let i = 0; i < endIdx; i++) {
            appendImpactAnalysisRow(tbody, impactAnalysisAllData[i]);
        }
        impactAnalysisLoadedCount = endIdx;
    }
    
    updateImpactAnalysisScrollInfo();
}

/**
 * Append a single row to the impact analysis table
 */
function appendImpactAnalysisRow(tbody, item) {
    const row = tbody.insertRow();
    row.innerHTML = `
        <td>${item.rank}</td>
        <td>${item.nameHtml}</td>
        <td>${item.devices}</td>
        <td>${item.cveIds}</td>
        <td>${item.impact}</td>
    `;
    row.onclick = () => showImpactAnalysisDetails(item.details);
}

/**
 * Load more impact analysis rows on scroll
 */
function loadMoreImpactAnalysisRows() {
    const tbody = document.getElementById('impactAnalysisTableBody');
    const startIdx = impactAnalysisLoadedCount;
    const endIdx = Math.min(startIdx + PAGE_SIZE, impactAnalysisAllData.length);
    
    for (let i = startIdx; i < endIdx; i++) {
        appendImpactAnalysisRow(tbody, impactAnalysisAllData[i]);
    }
    
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
    tooltip += `<div class="tooltip-row"><strong>First Seen:</strong> ${escapeHtml(firstSeen)}</div>`;
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
    const remediationByKey = {};
    
    filteredData.forEach(v => {
        // Build remediation key from update info and OS platform
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
                devices: new Map(), // Map of DeviceId -> device details
                cves: new Set(),
                severities: { Critical: 0, High: 0, Medium: 0, Low: 0 },
                cveDetails: new Map() // Map of CveId -> CVE details (publishedDate, description, affectedSoftware)
            };
        }
        
        // Add device details
        if (!remediationByKey[key].devices.has(v.DeviceId)) {
            remediationByKey[key].devices.set(v.DeviceId, {
                DeviceId: v.DeviceId,
                DeviceName: v.DeviceName,
                IpAddress: v.MachineInfo?.ip || '',
                MachineTags: v.MachineTags || [],
                RbacGroupName: v.RbacGroupName || '(No Group)'
            });
        }
        
        // Track CVEs
        remediationByKey[key].cves.add(v.CveId);
        
        // Collect CVE details (accumulate for each CVE ID)
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
                firstSeenTimestamp: v.FirstSeenTimestamp,
                lastSeenTimestamp: v.LastSeenTimestamp,
                exploitabilityLevel: v.ExploitabilityLevel,
                softwareVendor: v.SoftwareVendor,
                softwareName: v.SoftwareName,
                versions: new Set()
            });
        }
        
        // Add version to this CVE
        if (v.SoftwareVersion) {
            remediationByKey[key].cveDetails.get(v.CveId).versions.add(v.SoftwareVersion);
        }
    });
    
    // Calculate severity counts from unique CVEs
    Object.values(remediationByKey).forEach(data => {
        data.cveDetails.forEach(cveDetail => {
            if (data.severities.hasOwnProperty(cveDetail.severityLevel)) {
                data.severities[cveDetail.severityLevel]++;
            }
        });
    });
    
    // Convert to array and sort by device count (descending)
    devicesByRemediationAllData = Object.entries(remediationByKey).map(([key, data]) => {
        return {
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
        };
    }).sort((a, b) => b.deviceCount - a.deviceCount);
    
    // Reset loaded count and render initial batch
    devicesByRemediationLoadedCount = 0;
    renderDevicesByRemediationTablePage();
}

/**
 * Generate tooltip content for severity badges showing CVE IDs
 */
function generateSeverityTooltipContent(cveIds) {
    if (!cveIds || cveIds.length === 0) return '<div style="padding: 10px; font-size: 13px;">No CVEs</div>';
    
    // Sort CVE IDs alphabetically and filter out any undefined/null values
    const sortedCveIds = [...cveIds].filter(id => id).sort();
    
    if (sortedCveIds.length === 0) return '<div style="padding: 10px; font-size: 13px;">No valid CVE IDs</div>';
    
    // Return simple comma-separated list
    return `<div style="padding: 10px; font-size: 13px; max-width: 600px; word-wrap: break-word;">${sortedCveIds.join(', ')}</div>`;
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
        : Math.min(PAGE_SIZE, devicesByRemediationAllData.length);
    
    for (let i = 0; i < endIdx; i++) {
        appendDevicesByRemediationCard(container, devicesByRemediationAllData[i], i + 1);
    }
    
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
        cveBadgesSection += '<h4>Exposed CVEs:</h4>';
        cveBadgesSection += `<div class="severity-badges">${severityBadges}</div>`;
        cveBadgesSection += '</div>';
        cveBadgesSection += '<div class="cve-badges-container">';
        
        cveList.forEach(cve => {
            const severityClass = (cve.severity || 'Unknown').toLowerCase();
            
            // Remove CVE- prefix for cleaner display
            const displayId = cve.id.replace(/^CVE-/i, '');
            
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
            <h4>Vulnerable devices:</h4>
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

/**
 * Load more cards for devices by remediation report
 */
function loadMoreDevicesByRemediationRows() {
    const container = document.getElementById('devicesByRemediationContainer');
    const startIdx = devicesByRemediationLoadedCount;
    const endIdx = Math.min(startIdx + PAGE_SIZE, devicesByRemediationAllData.length);
    
    for (let i = startIdx; i < endIdx; i++) {
        appendDevicesByRemediationCard(container, devicesByRemediationAllData[i], i + 1);
    }
    
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
    const deviceByKey = {};
    const deviceCveDetails = {}; // Track all CVEs per device with details
    
    filteredData.forEach(v => {
        const deviceId = v.DeviceId;
        
        if (!deviceByKey[deviceId]) {
            deviceByKey[deviceId] = {
                deviceId: deviceId,
                deviceName: v.DeviceName,
                ipAddress: v.MachineInfo?.ip || '',
                machineTags: v.MachineTags || [],
                rbacGroupName: v.RbacGroupName || '(No Group)',
                remediations: new Map(), // Map of remediation key -> remediation details
                cves: new Set(),
                deviceSeverities: { Critical: 0, High: 0, Medium: 0, Low: 0 } // Device-level severity totals
            };
            deviceCveDetails[deviceId] = new Map(); // Track unique CVEs for device with their severity
        }
        
        // Build remediation key - use batch title like in Devices by Remediation
        const batchTitle = v.CveBatchTitle || v.RecommendedSecurityUpdate || 'Unknown';
        const updateName = v.RecommendedSecurityUpdate || 'Unknown';
        const updateId = v.RecommendedSecurityUpdateId || '';
        const osPlatform = v.OSPlatform || 'Unknown';
        const remKey = `${batchTitle}|${updateId}|${osPlatform}`;
        
        // Add or update remediation
        if (!deviceByKey[deviceId].remediations.has(remKey)) {
            deviceByKey[deviceId].remediations.set(remKey, {
                batchTitle: batchTitle,
                updateName: updateName,
                updateId: updateId,
                updateUrl: v.RecommendedSecurityUpdateUrl,
                osPlatform: osPlatform,
                cves: new Set(),
                cveDetails: new Map(), // Track CVE details for severity calculation
                severities: { Critical: 0, High: 0, Medium: 0, Low: 0 },
                publishedDates: [] // Track all published dates to find most recent
            });
        }
        
        const rem = deviceByKey[deviceId].remediations.get(remKey);
        rem.cves.add(v.CveId);
        
        // Track CVE details for proper severity counting per remediation
        if (!rem.cveDetails.has(v.CveId)) {
            rem.cveDetails.set(v.CveId, {
                severityLevel: v.VulnerabilitySeverityLevel,
                publishedDate: v.PublishedDate
            });
            
            // Add published date if available
            if (v.PublishedDate) {
                rem.publishedDates.push(formatDateYMD(v.PublishedDate));
            }
        }
        
        // Track CVE at device level for device severity totals
        if (!deviceCveDetails[deviceId].has(v.CveId)) {
            deviceCveDetails[deviceId].set(v.CveId, {
                severityLevel: v.VulnerabilitySeverityLevel
            });
        }
        
        deviceByKey[deviceId].cves.add(v.CveId);
    });
    
    // Calculate severity counts from unique CVEs for each device's remediations
    Object.values(deviceByKey).forEach(device => {
        // Calculate device-level severity totals and track CVE IDs by severity
        device.deviceCvesBySeverity = { Critical: [], High: [], Medium: [], Low: [] };
        deviceCveDetails[device.deviceId].forEach((cveDetail, cveId) => {
            if (device.deviceSeverities.hasOwnProperty(cveDetail.severityLevel)) {
                device.deviceSeverities[cveDetail.severityLevel]++;
                device.deviceCvesBySeverity[cveDetail.severityLevel].push(cveId);
            }
        });
        
        // Calculate remediation-level severity counts and track CVE IDs by severity
        device.remediations.forEach(rem => {
            rem.cvesBySeverity = { Critical: [], High: [], Medium: [], Low: [] };
            rem.cveDetails.forEach((cveDetail, cveId) => {
                if (rem.severities.hasOwnProperty(cveDetail.severityLevel)) {
                    rem.severities[cveDetail.severityLevel]++;
                    rem.cvesBySeverity[cveDetail.severityLevel].push(cveId);
                }
            });
            
            // Find most recent published date
            rem.mostRecentDate = getMostRecentYmdDate(rem.publishedDates);
            
            // Calculate score for sorting
            rem.score = calculateRemediationScore(rem.severities);
        });
    });
    
    // Calculate device-level score for sorting devices
    function calculateDeviceScore(device) {
        return calculateRemediationScore(device.deviceSeverities);
    }
    
    // Convert to array and sort by device score (highest severity first), then by remediation count
    remediationsByDeviceAllData = Object.values(deviceByKey).map(data => {
        return {
            deviceId: data.deviceId,
            deviceName: data.deviceName,
            ipAddress: data.ipAddress,
            machineTags: data.machineTags,
            rbacGroupName: data.rbacGroupName,
            remediations: data.remediations,
            remediationCount: data.remediations.size,
            cveCount: data.cves.size,
            deviceSeverities: data.deviceSeverities,
            deviceCvesBySeverity: data.deviceCvesBySeverity, // Add CVE IDs by severity
            deviceScore: calculateDeviceScore(data)
        };
    }).sort((a, b) => {
        // First by score (highest first), then by remediation count (highest first)
        if (b.deviceScore !== a.deviceScore) {
            return b.deviceScore - a.deviceScore;
        }
        return b.remediationCount - a.remediationCount;
    });
    
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
        : Math.min(PAGE_SIZE, remediationsByDeviceAllData.length);
    
    for (let i = 0; i < endIdx; i++) {
        appendRemediationsByDeviceCard(container, remediationsByDeviceAllData[i], i + 1);
    }
    
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
                <h4>Device Vulnerability Summary:</h4>
                <div class="severity-badges">${deviceSeverityBadges}</div>
            </div>
        </div>
        <div class="devices-header-row">
            <h4>Remediations needed:</h4>
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

/**
 * Load more cards for remediations by device report
 */
function loadMoreRemediationsByDeviceRows() {
    const container = document.getElementById('remediationsByDeviceContainer');
    const startIdx = remediationsByDeviceLoadedCount;
    const endIdx = Math.min(startIdx + PAGE_SIZE, remediationsByDeviceAllData.length);
    
    for (let i = startIdx; i < endIdx; i++) {
        appendRemediationsByDeviceCard(container, remediationsByDeviceAllData[i], i + 1);
    }
    
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
    if (v.VulnerabilityDescription) {
        return `<td class="evidence-cell">` +
            `<a href="${cveUrl}" target="_blank" class="evidence-indicator cve-link">${escapeHtml(v.CveId)}</a>` +
            `<div class="evidence-tooltip cve-description-tooltip">${escapeHtml(v.VulnerabilityDescription)}</div>` +
            `</td>`;
    }
    return `<td class="evidence-cell"><a href="${cveUrl}" target="_blank" class="evidence-indicator cve-link">${escapeHtml(v.CveId)}</a></td>`;
}

/**
 * Group devices by their shared CVE signature (identical set of CVE IDs)
 * @param {Array} details - Array of denormalized vulnerability objects
 * @returns {Array} Array of { signature, deviceBubbles: [{DeviceName,DeviceId,MachineInfo}], vulns: [unique vuln per CVE] }
 */
function groupDevicesByCveSignature(details) {
    // Build per-device CVE map
    const deviceMap = new Map();
    for (let i = 0; i < details.length; i++) {
        const d = details[i];
        const key = d.DeviceId || d.DeviceName;
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
    const allDeviceKeys = devices.map(d => d.DeviceId || d.DeviceName);
    const cveCounts = new Map(); // cveId -> Set of device keys that have it
    for (const dev of devices) {
        const devKey = dev.DeviceId || dev.DeviceName;
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
function buildDetailRow(v) {
    const severityClass = v.VulnerabilitySeverityLevel.toLowerCase();
    const epssDisplay = v.EpssScore != null ? v.EpssScore.toFixed(5) : '-';
    const publishedDisplay = formatDateYMD(v.PublishedDate);
    const firstSeenDisplay = formatDateYMD(v._firstSeenDate || v.FirstSeenTimestamp);

    return '<tr>' +
        buildCveLinkHtml(v) +
        '<td>' + escapeHtml(v.SoftwareVersion) + '</td>' +
        '<td><span class="badge ' + severityClass + '">' + v.VulnerabilitySeverityLevel + '</span></td>' +
        '<td>' + v.CvssScore + '</td>' +
        '<td>' + epssDisplay + '</td>' +
        '<td>' + formatExploitLevel(v.ExploitabilityLevel) + '</td>' +
        buildEvidenceHtml(v) +
        '<td>' + publishedDisplay + '</td>' +
        '<td>' + firstSeenDisplay + '</td>' +
        '</tr>';
}

/**
 * Build a remediation-row HTML string for showRemediationDetails CVE tables
 */
function buildRemediationRow(v) {
    const severityClass = v.VulnerabilitySeverityLevel.toLowerCase();
    const epssDisplay = v.EpssScore != null ? v.EpssScore.toFixed(5) : '-';
    const publishedDisplay = formatDateYMD(v.PublishedDate);
    const firstSeenDisplay = formatDateYMD(v._firstSeenDate || v.FirstSeenTimestamp);

    return '<tr>' +
        buildCveLinkHtml(v) +
        '<td>' + escapeHtml(v.SoftwareVersion) + '</td>' +
        '<td><span class="badge ' + severityClass + '">' + v.VulnerabilitySeverityLevel + '</span></td>' +
        '<td>' + v.CvssScore + '</td>' +
        '<td>' + epssDisplay + '</td>' +
        buildEvidenceHtml(v) +
        '<td>' + publishedDisplay + '</td>' +
        '<td>' + firstSeenDisplay + '</td>' +
        '</tr>';
}

/**
 * After modal innerHTML is set, attach VirtualModalTable to each tbody
 * that has a data-vt-rows attribute storing row data.
 */
function attachVirtualTables(scrollContainer, vtRowData) {
    activeVirtualTables.forEach(vt => vt.destroy());
    activeVirtualTables = [];

    for (const [vtId, rows] of Object.entries(vtRowData)) {
        const tbody = scrollContainer.querySelector(`tbody[data-vt-id="${vtId}"]`);
        if (tbody && rows.length > VIRTUAL_SCROLL_THRESHOLD) {
            activeVirtualTables.push(new VirtualModalTable(scrollContainer, tbody, rows));
        } else if (tbody) {
            // Small table — render all rows directly
            tbody.innerHTML = rows.join('');
        }
    }
}

/**
 * Show vulnerability details modal
 * @param {string} remediation - The remediation name
 * @param {Array} details - Array of vulnerability details
 */
function showDetails(remediation, details) {
    const modal = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');

    modalTitle.textContent = remediation;
    modalBody.innerHTML = '<p class="loading">Loading details...</p>';
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');

    // Defer heavy work so the modal + loading indicator render first
    requestAnimationFrame(() => {
        const groups = groupDevicesByCveSignature(details);
        const totalDevices = new Set(details.map(d => d.DeviceId || d.DeviceName)).size;
        const totalCves = new Set(details.map(d => d.CveId)).size;

        const parts = [];
        const vtRowData = {}; // vtId → array of row HTML strings

        parts.push('<h3>Affected Devices and Vulnerabilities</h3>');

        // Add update link above the table (right-aligned) if URL is available
        const updateUrl = details.find(d => d.RecommendedSecurityUpdateUrl);
        if (updateUrl) {
            const updateText = buildRemediationString(updateUrl);
            parts.push('<div style="text-align:right;margin-bottom:var(--spacing-sm);">');
            parts.push('<strong>Update details:</strong><br>');
            parts.push('<a href="' + escapeHtml(updateUrl.RecommendedSecurityUpdateUrl) + '" target="_blank" rel="noopener noreferrer" style="color:#0078d4;">&#x1F517; ' + escapeHtml(updateText) + '</a>');
            parts.push('</div>');
        }

        parts.push('<p style="color:var(--color-text-muted);margin-bottom:var(--spacing-md);">' +
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
            parts.push('<table class="detail-table"><thead><tr>',
                '<th>CVE ID</th><th>Version</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Exploitability</th><th>Evidence</th><th>Published</th><th>First Seen</th>',
                '</tr></thead><tbody data-vt-id="', vtId, '"></tbody></table>');

            // Build row data for this group
            const rows = new Array(group.vulns.length);
            for (let vi = 0; vi < group.vulns.length; vi++) {
                rows[vi] = buildDetailRow(group.vulns[vi]);
            }
            vtRowData[vtId] = rows;

            if (gi < groups.length - 1) parts.push('<hr style="margin:var(--spacing-lg) 0;border-color:var(--color-border);">');
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
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');

    requestAnimationFrame(() => {
        const groups = groupDevicesByCveSignature(data.details);
        const vtRowData = {};

        const parts = [];
        parts.push('<h3>Summary</h3>',
            '<table class="detail-table"><tr>',
            '<td><strong>Date:</strong> ', escapeHtml(data.date), '</td>',
            '<td><strong>Assets Remediated:</strong> ', String(data.devices.size), '</td>',
            '<td><strong>Vulnerabilities Remediated:</strong> ', String(data.vulnerabilities.size), '</td>',
            '</tr></table><br>',
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
            parts.push('<table class="detail-table"><thead><tr>',
                '<th>CVE ID</th><th>Version</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Evidence</th><th>Published</th><th>First Seen</th>',
                '</tr></thead><tbody data-vt-id="', vtId, '"></tbody></table>');

            // Build row data
            const rows = new Array(group.vulns.length);
            for (let vi = 0; vi < group.vulns.length; vi++) {
                rows[vi] = buildRemediationRow(group.vulns[vi]);
            }
            vtRowData[vtId] = rows;

            if (gi < groups.length - 1) parts.push('<hr style="margin:var(--spacing-lg) 0;border-color:var(--color-border);">');
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
    
    // Group vulnerabilities by device (using DeviceId as key)
    const deviceMap = {};
    item.vulnerabilities.forEach(v => {
        const deviceKey = v.DeviceId || v.DeviceName;
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
    html += '<table class="detail-table"><thead><tr>';
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
            <td style="max-width: 500px; word-wrap: break-word;">${escapeHtml(cveList)}</td>
        </tr>`;
    });
    
    html += '</tbody></table>';
    
    modalBody.innerHTML = html;
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
}

/**
 * Close the modal and clean up virtual tables
 */
function closeModal() {
    activeVirtualTables.forEach(vt => vt.destroy());
    activeVirtualTables = [];
    const modal = document.getElementById('detailModal');
    modal.classList.remove('active');
    modal.setAttribute('aria-hidden', 'true');
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
    if (event.key === 'Escape') {
        const modal = document.getElementById('detailModal');
        if (modal && modal.classList.contains('active')) {
            closeModal();
        }
    }
});

// =============================================================================
// PDF EXPORT
// =============================================================================

// Track whether PDF libraries have been loaded
let pdfLibrariesLoaded = false;

/**
 * Load PDF libraries on demand (pdfmake, vfsfonts, html2pdf, html2canvas)
 * Libraries are stored as text/plain script tags and executed when needed
 */
function loadPdfLibraries() {
    if (pdfLibrariesLoaded) {
        return Promise.resolve();
    }
    
    return new Promise((resolve, reject) => {
        try {
            // Load libraries in correct order: html2canvas first, then pdfmake, vfsfonts, html2pdf
            const libraryIds = ['html2canvasLib', 'pdfmakeLib', 'vfsfontsLib', 'html2pdfLib'];
            
            for (const libId of libraryIds) {
                const libScript = document.getElementById(libId);
                if (libScript && libScript.type === 'text/plain') {
                    const execScript = document.createElement('script');
                    execScript.textContent = libScript.textContent;
                    document.head.appendChild(execScript);
                    // Mark as loaded by changing type
                    libScript.type = 'text/javascript-loaded';
                }
            }
            
            // Wait for pdfMake to be available (it may take a moment to initialize)
            let attempts = 0;
            const checkPdfMake = setInterval(() => {
                attempts++;
                if (typeof pdfMake !== 'undefined' && typeof pdfMake.createPdf === 'function') {
                    clearInterval(checkPdfMake);
                    pdfLibrariesLoaded = true;
                    console.log('PDF libraries loaded successfully');
                    resolve();
                } else if (attempts > 50) { // 5 seconds timeout
                    clearInterval(checkPdfMake);
                    reject(new Error('pdfMake failed to initialize after 5 seconds'));
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
    button.textContent = '📄 Loading libraries...';
    
    try {
        await loadPdfLibraries();
    } catch (error) {
        console.error('Failed to load PDF libraries:', error);
        alert('Failed to load PDF export libraries. Please try again.');
        button.disabled = false;
        button.textContent = '📄 Export to PDF';
        return;
    }
    
    const selector = document.getElementById('reportSelector');
    const selectedReport = selector.value;
    const reportName = selector.options[selector.selectedIndex].text;
    
    button.textContent = '📄 Expanding data...';
    
    const wasExpanded = expandReportForPdf(selectedReport);
    await new Promise(resolve => setTimeout(resolve, 100));
    
    button.textContent = '📄 Generating PDF...';
    
    try {
        const fileName = `Vulnerability_Dashboard_${reportName.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.pdf`;
        
        // Choose export strategy based on report type
        let docDefinition;
        if (selectedReport === 'devices-by-remediation' || selectedReport === 'remediations-by-device') {
            docDefinition = await exportCardBasedReportToPdf(selectedReport, reportName);
        } else {
            docDefinition = await exportTableBasedReportToPdf(selectedReport, reportName);
        }
        
        // Add filter information  
        const startDate = document.getElementById('filterStartDate').value;
        const endDate = document.getElementById('filterEndDate').value;
        const selectedDateRange = document.querySelector('#filterDateRange tr.selected');
        const dateRangeText = selectedDateRange ? selectedDateRange.textContent.trim() : 'Custom';
        
        const deviceGroups = getSelectedCheckboxValues('filterRbacGroup');
        const deviceNames = getSelectedCheckboxValues('filterDeviceName');
        const osPlatforms = getSelectedCheckboxValues('filterOSPlatform');
        const severities = getSelectedCheckboxValues('filterSeverity');
        
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
        
        pdfMake.createPdf(docDefinition).download(fileName);
        
        restoreReportState(selectedReport, wasExpanded);
        
        button.disabled = false;
        button.textContent = '📄 Export to PDF';
    } catch (err) {
        console.error('PDF generation failed:', err);
        alert('Failed to generate PDF: ' + err.message);
        
        restoreReportState(selectedReport, wasExpanded);
        
        button.disabled = false;
        button.textContent = '📄 Export to PDF';
    }
}

// =============================================================================
// PAGE INITIALIZATION
// =============================================================================

window.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, checking for Chart.js...');
    if (typeof Chart === 'undefined') {
        console.error('Chart.js not loaded!');
    } else {
        console.log('Chart.js loaded successfully');
    }
    initEvidenceTooltips();
    init();
});
