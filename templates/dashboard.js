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

// =============================================================================
// INDEXEDDB CACHE
// =============================================================================

const VULNDB_NAME = 'VulnDashboardCache';
const VULNDB_VERSION = 1;
const VULNDB_STORE = 'denormalized';

/**
 * Compute a lightweight fingerprint for the embedded dataset.
 * Uses record count + first/last raw record JSON to detect data changes.
 */
function computeDataFingerprint() {
    const len = rawVulns.length;
    if (len === 0) return 'empty';
    const first = JSON.stringify(rawVulns[0]);
    const last = JSON.stringify(rawVulns[len - 1]);
    // Simple hash: length + djb2 of first+last
    let hash = 5381;
    const sample = first + last + len;
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
        var updateName = v[7] >= 0 ? lookups.updates[v[7]] : null;

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
            CveBatchTitle: cve.bt,
            PublishedDate: cve.pd || null,
            VulnerabilityDescription: cve.desc || null,
            EpssScore: cve.ep != null ? cve.ep : null,
            SoftwareVendor: vendorName,
            SoftwareName: softwareName,
            SoftwareVersion: v[3],
            RecommendationReference: software.r,
            _firstSeenDate: v[4],
            _lastSeenDate: v[5],
            FirstSeenTimestamp: v[4],
            LastSeenTimestamp: v[5],
            SecurityUpdateAvailable: v[6] === 1,
            RecommendedSecurityUpdate: updateName,
            RecommendedSecurityUpdateId: null,
            DiskPaths: v[8] || [],
            RegistryPaths: v[9] || [],
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
        CveBatchTitle: cve.bt,
        PublishedDate: cve.pd || null,
        VulnerabilityDescription: cve.desc || null,
        EpssScore: cve.ep ?? null,
        
        // Software info
        SoftwareVendor: lookups.vendors[software.v],
        SoftwareName: software.n,
        SoftwareVersion: v[3],
        RecommendationReference: software.r,
        
        // Timestamps (already in YYYY-MM-DD format)
        _firstSeenDate: v[4],
        _lastSeenDate: v[5],
        FirstSeenTimestamp: v[4],
        LastSeenTimestamp: v[5],
        
        // Update info
        SecurityUpdateAvailable: v[6] === 1,
        RecommendedSecurityUpdate: v[7] >= 0 ? lookups.updates[v[7]] : null,
        
        // Evidence
        DiskPaths: v[8] || [],
        RegistryPaths: v[9] || [],
        
        // Pre-computed fields
        _remediationKey: v[7] >= 0 && lookups.updates[v[7]]
            ? `${lookups.vendors[software.v]} ${software.n} - ${lookups.updates[v[7]]}`
            : `${lookups.vendors[software.v]} ${software.n}`,
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
    values.forEach(value => {
        const div = document.createElement('div');
        div.className = 'checkbox-item';
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.value = value;
        checkbox.id = `${containerId}_${value.replace(/\s+/g, '_')}`;
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
        const firstSeen = v._firstSeenDate || v.FirstSeenTimestamp.split(' ')[0];
        const lastSeen = v._lastSeenDate || v.LastSeenTimestamp.split(' ')[0];
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
            const firstSeen = v._firstSeenDate || v.FirstSeenTimestamp.split(' ')[0];
            const lastSeen = v._lastSeenDate || v.LastSeenTimestamp.split(' ')[0];
            
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
        const lastSeenDate = v._lastSeenDate || v.LastSeenTimestamp.split(' ')[0];
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
 * Build remediation string from vulnerability data
 * @param {Object} v - Vulnerability object
 * @returns {string} Formatted remediation string
 */
function buildRemediationString(v) {
    if (v.RecommendedSecurityUpdate && v.RecommendedSecurityUpdateId) {
        return `${v.RecommendedSecurityUpdate} (${v.RecommendedSecurityUpdateId})`;
    } else if (v.RecommendedSecurityUpdate) {
        return v.RecommendedSecurityUpdate;
    } else if (v.RecommendedSecurityUpdateId) {
        return v.RecommendedSecurityUpdateId;
    }
    return 'Not Specified';
}

// =============================================================================
// ACTIVE VULNERABILITIES CHART
// =============================================================================

/**
 * Render the main vulnerability chart
 */
function renderChart() {
    const ctx = document.getElementById('vulnerabilityChart');
    if (!ctx) {
        console.error('Canvas element not found');
        return;
    }
    
    const context = ctx.getContext('2d');
    if (!context) {
        console.error('Could not get 2D context');
        return;
    }

    // Get date range from filters
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
    
    sortedDates.forEach(date => {
        // If date is after most recent LastSeenTimestamp, use previous day's count
        if (date > mostRecentLastSeen) {
            totalCounts.push(lastActualTotal);
            deviceCounts.push(lastActualDeviceCount);
            severityCounts.Critical.push(lastActualSeverity.Critical);
            severityCounts.High.push(lastActualSeverity.High);
            severityCounts.Medium.push(lastActualSeverity.Medium);
            severityCounts.Low.push(lastActualSeverity.Low);
            return;
        }
        
        let count = 0;
        const devicesWithVulns = new Set();
        const severityForDate = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        
        vulnerabilityData.forEach(v => {
            // Use pre-computed dates (falls back to split if not available)
            const firstSeenDate = v._firstSeenDate || v.FirstSeenTimestamp.split(' ')[0];
            const lastSeenDate = v._lastSeenDate || v.LastSeenTimestamp.split(' ')[0];
            const severity = v.VulnerabilitySeverityLevel;
            
            // Check if vulnerability is active on this date
            if (firstSeenDate <= date && lastSeenDate >= date) {
                // Apply non-date filters
                if (!hasDeviceNames) return;
                if (!hasRbacGroups) return;
                if (!hasDeviceTags) return;
                if (!hasSeverities) return;
                if (!hasOsPlatforms) return;
                
                // Use Set.has() for O(1) lookups
                if (deviceNameSet.size > 0 && !deviceNameSet.has(v.DeviceName)) return;
                if (rbacGroupSet.size > 0 && !rbacGroupSet.has(v.RbacGroupName)) return;
                
                // Device Tags filter with OR logic
                if (deviceTagSet.size > 0) {
                    const vulnTags = v.MachineTags && v.MachineTags.length > 0 ? v.MachineTags : [NO_TAGS_VALUE];
                    const hasMatchingTag = vulnTags.some(tag => deviceTagSet.has(tag));
                    if (!hasMatchingTag) return;
                }
                
                if (severitySet.size > 0 && !severitySet.has(v.VulnerabilitySeverityLevel)) return;
                if (osPlatformSet.size > 0 && !osPlatformSet.has(v.OSPlatform)) return;
                
                count++;
                devicesWithVulns.add(v.DeviceName);
                
                if (severityForDate[severity] !== undefined) {
                    severityForDate[severity]++;
                }
            }
        });
        
        totalCounts.push(count);
        deviceCounts.push(devicesWithVulns.size);
        severityCounts.Critical.push(severityForDate.Critical);
        severityCounts.High.push(severityForDate.High);
        severityCounts.Medium.push(severityForDate.Medium);
        severityCounts.Low.push(severityForDate.Low);
        
        // Update last actual counts
        lastActualTotal = count;
        lastActualDeviceCount = devicesWithVulns.size;
        lastActualSeverity = { ...severityForDate };
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
                        backgroundColor: 'rgba(209, 52, 56, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y',
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'High',
                        data: severityCounts.High,
                        borderColor: '#ff6b35',
                        backgroundColor: 'rgba(255, 107, 53, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y',
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Medium',
                        data: severityCounts.Medium,
                        borderColor: '#ffa500',
                        backgroundColor: 'rgba(255, 165, 0, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y',
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Low',
                        data: severityCounts.Low,
                        borderColor: '#4caf50',
                        backgroundColor: 'rgba(76, 175, 80, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y',
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Total',
                        data: totalCounts,
                        borderColor: '#9c27b0',
                        backgroundColor: 'rgba(156, 39, 176, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y',
                        borderWidth: 3,
                        segment: createSegmentStyle(cutoffIndex),
                        hidden: true
                    },
                    {
                        label: 'Devices',
                        data: deviceCounts,
                        borderColor: '#000000',
                        backgroundColor: 'rgba(0, 0, 0, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y1',
                        borderWidth: 2,
                        pointRadius: 3,
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
                                let total = 0;
                                tooltipItems.forEach(item => {
                                    total += item.parsed.y;
                                });
                                return 'Total: ' + total;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        },
                        title: {
                            display: true,
                            text: 'Vulnerabilities'
                        },
                        position: 'left'
                    },
                    y1: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        },
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
        console.log('Chart rendered successfully');
    } catch (error) {
        console.error('Error creating chart:', error);
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
        const software = formatSoftwareName(v.SoftwareVendor, v.SoftwareName);
        const key = `${software}|${remediation}`;

        if (!remediationMap[key]) {
            remediationMap[key] = {
                software: software,
                remediation: remediation,
                devices: new Set(),
                vulnerabilities: new Set(),
                exploits: new Set(),
                kits: new Set(),
                details: []
            };
        }

        remediationMap[key].devices.add(v.DeviceId);
        remediationMap[key].vulnerabilities.add(v.Id);
        
        if (v.ExploitabilityLevel === 'ExploitIsVerified') {
            remediationMap[key].exploits.add(v.Id);
        }
        
        if (v.ExploitabilityLevel === 'ExploitIsInKit') {
            remediationMap[key].kits.add(v.Id);
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
        <td>${rem.software}</td>
        <td>${rem.remediation}</td>
        <td>${rem.devices.size}</td>
        <td>${rem.vulnerabilities.size}</td>
        <td>${rem.exploits.size}</td>
        <td>${rem.kits.size}</td>
    `;
    row.onclick = () => showDetails(rem.remediation, rem.details);
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
            case 0: aValue = a.software; bValue = b.software; break;
            case 1: aValue = a.remediation; bValue = b.remediation; break;
            case 2: aValue = a.devices.size; bValue = b.devices.size; break;
            case 3: aValue = a.vulnerabilities.size; bValue = b.vulnerabilities.size; break;
            case 4: aValue = a.exploits.size; bValue = b.exploits.size; break;
            case 5: aValue = a.kits.size; bValue = b.kits.size; break;
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
 * Render the remediation activity chart
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
    
    sortedDates.forEach(date => {
        // If date is after most recent LastSeenTimestamp, set to 0
        if (date > mostRecentLastSeen) {
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
        const severityRemediations = {
            Critical: new Set(),
            High: new Set(),
            Medium: new Set(),
            Low: new Set()
        };
        
        filteredData.forEach(v => {
            // Use pre-computed date (falls back to split if not available)
            const lastSeenDate = v._lastSeenDate || v.LastSeenTimestamp.split(' ')[0];
            const severity = v.VulnerabilitySeverityLevel;
            
            // Count as remediation if this is the last day it was seen
            if (lastSeenDate === date) {
                remediationsOnDate.add(v.Id);
                devicesOnDate.add(v.DeviceName);
                
                if (severityRemediations[severity]) {
                    severityRemediations[severity].add(v.Id);
                }
            }
        });
        
        severityCounts.Critical.push(severityRemediations.Critical.size);
        severityCounts.High.push(severityRemediations.High.size);
        severityCounts.Medium.push(severityRemediations.Medium.size);
        severityCounts.Low.push(severityRemediations.Low.size);
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
                        backgroundColor: 'rgba(209, 52, 56, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y',
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'High',
                        data: severityCounts.High,
                        borderColor: '#ff6b35',
                        backgroundColor: 'rgba(255, 107, 53, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y',
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Medium',
                        data: severityCounts.Medium,
                        borderColor: '#ffa500',
                        backgroundColor: 'rgba(255, 165, 0, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y',
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Low',
                        data: severityCounts.Low,
                        borderColor: '#4caf50',
                        backgroundColor: 'rgba(76, 175, 80, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y',
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Total Remediations',
                        data: totalRemediationCounts,
                        borderColor: '#9c27b0',
                        backgroundColor: 'rgba(156, 39, 176, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y',
                        borderWidth: 3,
                        segment: createSegmentStyle(cutoffIndex),
                        hidden: true
                    },
                    {
                        label: 'Devices',
                        data: deviceCounts,
                        borderColor: '#000000',
                        backgroundColor: 'rgba(0, 0, 0, 0.1)',
                        tension: 0.3,
                        yAxisID: 'y1',
                        borderWidth: 2,
                        pointRadius: 3,
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
                        ticks: {
                            stepSize: 1
                        },
                        title: {
                            display: true,
                            text: 'Remediations'
                        },
                        position: 'left'
                    },
                    y1: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        },
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
        const lastSeenDate = v._lastSeenDate || v.LastSeenTimestamp.split(' ')[0];
        const remediation = buildRemediationString(v);
        const key = `${lastSeenDate}|${remediation}`;
        
        if (!remediationByDate[key]) {
            remediationByDate[key] = {
                date: lastSeenDate,
                remediation: remediation,
                devices: new Set(),
                vulnerabilities: new Set(),
                details: []
            };
        }
        
        remediationByDate[key].devices.add(v.DeviceName);
        remediationByDate[key].vulnerabilities.add(v.Id);
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
        <td>${data.remediation}</td>
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
            top25VulnIds.add(v.Id);
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
    
    sortedDates.forEach(date => {
        // If date is after most recent LastSeenTimestamp, use previous day's count
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
        
        let currentTotal = 0;
        let projectedTotal = 0;
        const currentSeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        const projectedSeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        
        filteredData.forEach(v => {
            // Use pre-computed dates (falls back to split if not available)
            const firstSeenDate = v._firstSeenDate || v.FirstSeenTimestamp.split(' ')[0];
            const lastSeenDate = v._lastSeenDate || v.LastSeenTimestamp.split(' ')[0];
            const severity = v.VulnerabilitySeverityLevel;
            
            // Check if vulnerability is active on this date
            if (firstSeenDate <= date && lastSeenDate >= date) {
                currentTotal++;
                if (currentSeverity[severity] !== undefined) {
                    currentSeverity[severity]++;
                }
                
                // Only count in projected if not in top 25
                if (!top25VulnIds.has(v.Id)) {
                    projectedTotal++;
                    if (projectedSeverity[severity] !== undefined) {
                        projectedSeverity[severity]++;
                    }
                }
            }
        });
        
        currentTotalCounts.push(currentTotal);
        projectedTotalCounts.push(projectedTotal);
        currentSeverityCounts.Critical.push(currentSeverity.Critical);
        currentSeverityCounts.High.push(currentSeverity.High);
        currentSeverityCounts.Medium.push(currentSeverity.Medium);
        currentSeverityCounts.Low.push(currentSeverity.Low);
        projectedSeverityCounts.Critical.push(projectedSeverity.Critical);
        projectedSeverityCounts.High.push(projectedSeverity.High);
        projectedSeverityCounts.Medium.push(projectedSeverity.Medium);
        projectedSeverityCounts.Low.push(projectedSeverity.Low);
        
        // Update last actual counts
        lastActualCurrentTotal = currentTotal;
        lastActualProjectedTotal = projectedTotal;
        lastActualCurrentSeverity = { ...currentSeverity };
        lastActualProjectedSeverity = { ...projectedSeverity };
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
                        backgroundColor: 'rgba(209, 52, 56, 0.1)',
                        tension: 0.3,
                        borderWidth: 2,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Current - High',
                        data: currentSeverityCounts.High,
                        borderColor: '#ff6b35',
                        backgroundColor: 'rgba(255, 107, 53, 0.1)',
                        tension: 0.3,
                        borderWidth: 2,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Current - Medium',
                        data: currentSeverityCounts.Medium,
                        borderColor: '#ffa500',
                        backgroundColor: 'rgba(255, 165, 0, 0.1)',
                        tension: 0.3,
                        borderWidth: 2,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Current - Low',
                        data: currentSeverityCounts.Low,
                        borderColor: '#4caf50',
                        backgroundColor: 'rgba(76, 175, 80, 0.1)',
                        tension: 0.3,
                        borderWidth: 2,
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'Current Total',
                        data: currentTotalCounts,
                        borderColor: '#9c27b0',
                        backgroundColor: 'rgba(156, 39, 176, 0.1)',
                        tension: 0.3,
                        borderWidth: 3,
                        segment: createSegmentStyle(cutoffIndex),
                        hidden: true
                    },
                    {
                        label: 'After Top 25 - Critical',
                        data: projectedSeverityCounts.Critical,
                        borderColor: '#d13438',
                        backgroundColor: 'rgba(209, 52, 56, 0.05)',
                        tension: 0.3,
                        borderWidth: 1,
                        borderDash: [3, 3],
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'After Top 25 - High',
                        data: projectedSeverityCounts.High,
                        borderColor: '#ff6b35',
                        backgroundColor: 'rgba(255, 107, 53, 0.05)',
                        tension: 0.3,
                        borderWidth: 1,
                        borderDash: [3, 3],
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'After Top 25 - Medium',
                        data: projectedSeverityCounts.Medium,
                        borderColor: '#ffa500',
                        backgroundColor: 'rgba(255, 165, 0, 0.05)',
                        tension: 0.3,
                        borderWidth: 1,
                        borderDash: [3, 3],
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'After Top 25 - Low',
                        data: projectedSeverityCounts.Low,
                        borderColor: '#4caf50',
                        backgroundColor: 'rgba(76, 175, 80, 0.05)',
                        tension: 0.3,
                        borderWidth: 1,
                        borderDash: [3, 3],
                        segment: createSegmentStyle(cutoffIndex)
                    },
                    {
                        label: 'After Top 25 Total',
                        data: projectedTotalCounts,
                        borderColor: '#9c27b0',
                        backgroundColor: 'rgba(156, 39, 176, 0.1)',
                        tension: 0.3,
                        borderWidth: 3,
                        borderDash: [3, 3],
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
                        intersect: false,
                        callbacks: {
                            footer: function(tooltipItems) {
                                // Find Current Total and After Top 25 Total
                                let currentTotal = 0;
                                let projectedTotal = 0;
                                
                                tooltipItems.forEach(item => {
                                    if (item.dataset.label === 'Current Total') {
                                        currentTotal = item.parsed.y;
                                    } else if (item.dataset.label === 'After Top 25 Total') {
                                        projectedTotal = item.parsed.y;
                                    }
                                });
                                
                                if (currentTotal > 0) {
                                    const reduction = currentTotal - projectedTotal;
                                    const percent = ((reduction / currentTotal) * 100).toFixed(1);
                                    return `Reduction: ${reduction} (${percent}%)`;
                                }
                                return '';
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        },
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
    
    // Store top25 data for table rendering
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
        <td>${item.name}</td>
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
// MODALS
// =============================================================================

/**
 * Initialize evidence tooltip positioning
 * Uses event delegation to handle dynamically created tooltips
 */
function initEvidenceTooltips() {
    document.addEventListener('mouseenter', function(e) {
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
        const cell = e.target.closest('.evidence-cell');
        if (!cell) return;
        
        const tooltip = cell.querySelector('.evidence-tooltip');
        if (tooltip && !tooltip.classList.contains('pinned')) {
            tooltip.style.display = 'none';
        }
    }, true);

    // Click to pin/unpin tooltip (allows text selection & copying)
    document.addEventListener('click', function(e) {
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
        if (mi.ls)  tooltipContent += `<br><span class="tooltip-label">Last Seen:</span> ${escapeHtml(mi.ls)}`;
        if (mi.fs)  tooltipContent += `<br><span class="tooltip-label">First Seen:</span> ${escapeHtml(mi.fs)}`;
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
    const cveUrl = v.CveBatchUrl || `https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/${v.CveId}`;
    if (v.VulnerabilityDescription) {
        return `<td class="evidence-cell">` +
            `<a href="${cveUrl}" target="_blank" class="evidence-indicator cve-link">${escapeHtml(v.CveId)}</a>` +
            `<div class="evidence-tooltip cve-description-tooltip">${escapeHtml(v.VulnerabilityDescription)}</div>` +
            `</td>`;
    }
    return `<td><a href="${cveUrl}" target="_blank">${escapeHtml(v.CveId)}</a></td>`;
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

    // Group devices by signature (sorted CVE ID list)
    const signatureMap = new Map();
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    for (const dev of deviceMap.values()) {
        const sig = Array.from(dev.cveIds).sort().join('|');
        let group = signatureMap.get(sig);
        if (!group) {
            // Build sorted vulns immediately from this device
            const vulns = Object.values(dev.vulnsByCve);
            vulns.sort((a, b) => {
                const aSev = sevOrder[a.VulnerabilitySeverityLevel?.toLowerCase()] ?? 9;
                const bSev = sevOrder[b.VulnerabilitySeverityLevel?.toLowerCase()] ?? 9;
                return aSev !== bSev ? aSev - bSev : a.CveId.localeCompare(b.CveId);
            });
            group = { devices: [], vulns };
            signatureMap.set(sig, group);
        }
        group.devices.push({
            DeviceName: dev.DeviceName,
            DeviceId: dev.DeviceId,
            MachineInfo: dev.MachineInfo
        });
    }

    // Sort groups by device count desc, then vuln count desc
    const result = Array.from(signatureMap.values());
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
    let recommendedUpdate;
    if (v.RecommendedSecurityUpdate && v.RecommendedSecurityUpdateId) {
        recommendedUpdate = v.RecommendedSecurityUpdate + ' (' + v.RecommendedSecurityUpdateId + ')';
    } else {
        recommendedUpdate = v.RecommendedSecurityUpdate || v.RecommendedSecurityUpdateId || '-';
    }
    const epssDisplay = v.EpssScore != null ? v.EpssScore.toFixed(5) : '-';
    const publishedDisplay = v.PublishedDate ? v.PublishedDate.split('T')[0] : '-';

    return '<tr>' +
        buildCveLinkHtml(v) +
        '<td>' + escapeHtml(v.SoftwareVendor) + ' - ' + escapeHtml(v.SoftwareName) + '</td>' +
        '<td>' + escapeHtml(v.SoftwareVersion) + '</td>' +
        '<td><span class="badge ' + severityClass + '">' + v.VulnerabilitySeverityLevel + '</span></td>' +
        '<td>' + v.CvssScore + '</td>' +
        '<td>' + epssDisplay + '</td>' +
        '<td>' + (v.ExploitabilityLevel || '-') + '</td>' +
        '<td>' + escapeHtml(recommendedUpdate) + '</td>' +
        buildEvidenceHtml(v) +
        '<td>' + publishedDisplay + '</td>' +
        '</tr>';
}

/**
 * Build a remediation-row HTML string for showRemediationDetails CVE tables
 */
function buildRemediationRow(v) {
    const severityClass = v.VulnerabilitySeverityLevel.toLowerCase();
    const epssDisplay = v.EpssScore != null ? v.EpssScore.toFixed(5) : '-';
    const publishedDisplay = v.PublishedDate ? v.PublishedDate.split('T')[0] : '-';

    return '<tr>' +
        buildCveLinkHtml(v) +
        '<td>' + escapeHtml(v.SoftwareVendor) + ' - ' + escapeHtml(v.SoftwareName) + '</td>' +
        '<td>' + escapeHtml(v.SoftwareVersion) + '</td>' +
        '<td><span class="badge ' + severityClass + '">' + v.VulnerabilitySeverityLevel + '</span></td>' +
        '<td>' + v.CvssScore + '</td>' +
        '<td>' + epssDisplay + '</td>' +
        buildEvidenceHtml(v) +
        '<td>' + publishedDisplay + '</td>' +
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

    // Defer heavy work so the modal + loading indicator render first
    requestAnimationFrame(() => {
        const groups = groupDevicesByCveSignature(details);
        const totalDevices = new Set(details.map(d => d.DeviceId || d.DeviceName)).size;
        const totalCves = new Set(details.map(d => d.CveId)).size;

        const parts = [];
        const vtRowData = {}; // vtId → array of row HTML strings

        parts.push('<h3>Affected Devices and Vulnerabilities</h3>');
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
                '<th>CVE ID</th><th>Software</th><th>Version</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Exploitability</th><th>Recommended Update</th><th>Evidence</th><th>Published</th>',
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
                '<th>CVE ID</th><th>Software</th><th>Version</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Evidence</th><th>Published</th>',
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
            <td>${device.name}</td>
            <td title="${device.id || ''}">${deviceIdShort}</td>
            <td>${device.cves.size}</td>
            <td style="max-width: 500px; word-wrap: break-word;">${cveList}</td>
        </tr>`;
    });
    
    html += '</tbody></table>';
    
    modalBody.innerHTML = html;
    modal.classList.add('active');
}

/**
 * Close the modal and clean up virtual tables
 */
function closeModal() {
    activeVirtualTables.forEach(vt => vt.destroy());
    activeVirtualTables = [];
    document.getElementById('detailModal').classList.remove('active');
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('detailModal');
    if (event.target === modal) {
        closeModal();
    }
};

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
async function exportToPDF() {
    const button = document.querySelector('.export-pdf-btn');
    button.disabled = true;
    button.textContent = '📄 Loading libraries...';
    
    // Load PDF libraries on first use
    try {
        await loadPdfLibraries();
    } catch (error) {
        console.error('Failed to load PDF libraries:', error);
        alert('Failed to load PDF export libraries. Please try again.');
        button.disabled = false;
        button.textContent = '📄 Export to PDF';
        return;
    }
    
    button.textContent = '📄 Expanding tables...';
    
    // Expand all rows for the active section before PDF generation
    const selector = document.getElementById('reportSelector');
    const selectedReport = selector.value;
    
    // Track original expanded state to restore after
    let wasExpanded = false;
    
    if (selectedReport === 'active-vulnerabilities') {
        wasExpanded = remediationExpanded;
        if (!remediationExpanded) {
            remediationExpanded = true;
            renderRemediationTablePage();
        }
    } else if (selectedReport === 'remediation-activity') {
        wasExpanded = remediationDetailsExpanded;
        if (!remediationDetailsExpanded) {
            remediationDetailsExpanded = true;
            renderRemediationDetailsTablePage();
        }
    } else if (selectedReport === 'impact-analysis') {
        wasExpanded = impactAnalysisExpanded;
        if (!impactAnalysisExpanded) {
            impactAnalysisExpanded = true;
            renderImpactAnalysisTablePage();
        }
    }
    
    // Small delay to ensure DOM is updated
    await new Promise(resolve => setTimeout(resolve, 100));
    
    button.textContent = '📄 Generating PDF...';

    try {
        // Get current report name
        const selector = document.getElementById('reportSelector');
        const reportName = selector.options[selector.selectedIndex].text;
        const fileName = `Vulnerability_Dashboard_${reportName.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.pdf`;

        // Get the elements to include in PDF
        const container = document.querySelector('.container');
        const activeSection = document.querySelector('.report-section.active');

        // Capture title and stats as image
        const headerDiv = document.createElement('div');
        headerDiv.style.backgroundColor = 'white';
        headerDiv.style.padding = '0';
        headerDiv.style.fontFamily = 'Arial, sans-serif';
        headerDiv.style.width = '800px';
        
        // Add title
        const title = document.createElement('h1');
        title.textContent = `🛡️ Vulnerability Dashboard - ${reportName}`;
        title.style.fontSize = '28px';
        title.style.color = '#0078d4';
        title.style.marginBottom = '20px';
        headerDiv.appendChild(title);

        // Add stats summary
        const statsClone = container.querySelector('.stats-summary').cloneNode(true);
        headerDiv.appendChild(statsClone);
        
        document.body.appendChild(headerDiv);
        const headerCanvas = await html2canvas(headerDiv, {
            scale: 2,
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
            // Get headers
            const headers = table.querySelectorAll('thead th');
            headers.forEach(th => {
                tableHeaders.push({
                    text: th.textContent.trim(),
                    style: 'tableHeader',
                    fillColor: '#0078d4',
                    color: '#ffffff'
                });
            });

            // Get rows
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

        // Build PDF document definition
        const docDefinition = {
            pageSize: 'A4',
            pageMargins: [40, 40, 40, 40],
            content: [
                {
                    image: headerImg,
                    width: 515,
                    margin: [0, 0, 0, 10]
                }
            ],
            styles: {
                tableHeader: {
                    bold: true,
                    fontSize: 10,
                    color: 'white',
                    fillColor: '#0078d4'
                }
            }
        };

        // Add chart if available
        if (chartImg) {
            docDefinition.content.push({
                table: {
                    body: [
                        [{
                            image: chartImg,
                            width: 515
                        }]
                    ]
                },
                layout: {
                    hLineWidth: function () { return 1; },
                    vLineWidth: function () { return 1; },
                    hLineColor: function () { return '#cccccc'; },
                    vLineColor: function () { return '#cccccc'; },
                    paddingLeft: function () { return 0; },
                    paddingRight: function () { return 0; },
                    paddingTop: function () { return 0; },
                    paddingBottom: function () { return 0; }
                },
                margin: [0, 0, 0, 10]
            });
        }

        // Add table if available
        if (tableBody.length > 0) {
            docDefinition.content.push({
                table: {
                    headerRows: 1,
                    widths: tableHeaders.length === 6 ? [80, '*', 45, 70, 45, 35] : Array(tableHeaders.length).fill('*'),
                    body: [
                        tableHeaders,
                        ...tableBody
                    ]
                },
                layout: {
                    fillColor: function (rowIndex) {
                        return rowIndex === 0 ? '#0078d4' : null;
                    },
                    hLineWidth: function () { return 1; },
                    vLineWidth: function () { return 1; },
                    hLineColor: function () { return '#dddddd'; },
                    vLineColor: function () { return '#dddddd'; },
                    paddingLeft: function () { return 8; },
                    paddingRight: function () { return 8; },
                    paddingTop: function () { return 6; },
                    paddingBottom: function () { return 6; }
                },
                fontSize: 9,
                margin: [0, 0, 0, 15]
            });
        }

        // Extract filter details
        const startDate = document.getElementById('filterStartDate').value;
        const endDate = document.getElementById('filterEndDate').value;
        const selectedDateRange = document.querySelector('#filterDateRange tr.selected');
        const dateRangeText = selectedDateRange ? selectedDateRange.textContent.trim() : 'Custom';
        
        const deviceGroups = getSelectedCheckboxValues('filterRbacGroup');
        const deviceNames = getSelectedCheckboxValues('filterDeviceName');
        const osPlatforms = getSelectedCheckboxValues('filterOSPlatform');
        const severities = getSelectedCheckboxValues('filterSeverity');

        // Build filter content
        const filterContent = [];
        
        filterContent.push({
            text: 'Applied Filters',
            style: 'filterHeader',
            margin: [0, 10, 0, 5]
        });

        // Date Range
        if (startDate && endDate) {
            filterContent.push({
                text: [
                    { text: 'Date Range: ', bold: true },
                    { text: `${startDate} to ${endDate}` }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        } else {
            filterContent.push({
                text: [
                    { text: 'Date Range: ', bold: true },
                    { text: dateRangeText }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        }

        // Device Groups
        if (deviceGroups.length > 0) {
            filterContent.push({
                text: [
                    { text: 'Device Groups: ', bold: true },
                    { text: deviceGroups.join(', ') }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        } else {
            filterContent.push({
                text: [
                    { text: 'Device Groups: ', bold: true },
                    { text: 'All Groups' }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        }

        // Device Names
        if (deviceNames.length > 0 && deviceNames.length <= 10) {
            filterContent.push({
                text: [
                    { text: 'Device Names: ', bold: true },
                    { text: deviceNames.join(', ') }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        } else if (deviceNames.length > 10) {
            filterContent.push({
                text: [
                    { text: 'Device Names: ', bold: true },
                    { text: `${deviceNames.length} devices selected` }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        } else {
            filterContent.push({
                text: [
                    { text: 'Device Names: ', bold: true },
                    { text: 'All Devices' }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        }

        // OS Platforms
        if (osPlatforms.length > 0) {
            filterContent.push({
                text: [
                    { text: 'OS Platforms: ', bold: true },
                    { text: osPlatforms.join(', ') }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        } else {
            filterContent.push({
                text: [
                    { text: 'OS Platforms: ', bold: true },
                    { text: 'All Platforms' }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        }

        // Severities
        if (severities.length > 0) {
            filterContent.push({
                text: [
                    { text: 'Severities: ', bold: true },
                    { text: severities.join(', ') }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        } else {
            filterContent.push({
                text: [
                    { text: 'Severities: ', bold: true },
                    { text: 'All Severities' }
                ],
                margin: [0, 2, 0, 2],
                fontSize: 9
            });
        }

        // Add filter content to document
        docDefinition.content.push(...filterContent);

        // Add filter header style
        docDefinition.styles.filterHeader = {
            fontSize: 12,
            bold: true,
            color: '#0078d4',
            margin: [0, 10, 0, 5]
        };

        // Generate and download PDF
        pdfMake.createPdf(docDefinition).download(fileName);

        // Restore table to previous state (collapsed with infinite scroll)
        if (!wasExpanded) {
            if (selectedReport === 'active-vulnerabilities') {
                remediationExpanded = false;
                renderRemediationTablePage();
            } else if (selectedReport === 'remediation-activity') {
                remediationDetailsExpanded = false;
                renderRemediationDetailsTablePage();
            } else if (selectedReport === 'impact-analysis') {
                impactAnalysisExpanded = false;
                renderImpactAnalysisTablePage();
            }
        }

        button.disabled = false;
        button.textContent = '📄 Export to PDF';
    } catch (err) {
        console.error('PDF generation failed:', err);
        alert('Failed to generate PDF: ' + err.message);
        
        // Restore table state on error too
        if (!wasExpanded) {
            if (selectedReport === 'active-vulnerabilities') {
                remediationExpanded = false;
                renderRemediationTablePage();
            } else if (selectedReport === 'remediation-activity') {
                remediationDetailsExpanded = false;
                renderRemediationDetailsTablePage();
            } else if (selectedReport === 'impact-analysis') {
                impactAnalysisExpanded = false;
                renderImpactAnalysisTablePage();
            }
        }
        
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
