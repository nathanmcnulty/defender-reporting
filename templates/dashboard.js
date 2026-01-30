/**
 * Vulnerability Dashboard - Main JavaScript
 * 
 * This file contains all the client-side logic for the vulnerability dashboard.
 * It handles data filtering, chart rendering, table management, and PDF export.
 */

// =============================================================================
// GLOBAL STATE
// =============================================================================

// Load the vulnerability data from embedded script tag
const vulnerabilityData = JSON.parse(document.getElementById('vulnerabilityData').textContent);

// Load pre-computed filter indexes (for O(1) lookups)
const filterIndexes = JSON.parse(document.getElementById('filterIndexes').textContent);

// Filtered data based on current filter selections
let filteredData = [...vulnerabilityData];

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

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize the dashboard on page load
 */
function init() {
    console.log('Initializing dashboard with', vulnerabilityData.length, 'vulnerabilities');
    console.log('Using pre-computed indexes:', Object.keys(filterIndexes));
    buildDeviceGroupMap();
    buildDeviceTagsSet();
    populateFilters();
    setDateRange('1m'); // Set default to 1 month
    updateStats();
    renderChart();
    renderTable();
    attachEventListeners();
    renderRemediationChart();
    renderRemediationDetailsTable();
    renderImpactChart();
    renderImpactAnalysisTable();
}

/**
 * Build device group to device name mapping for filter cascading
 * Uses pre-computed index if available
 */
function buildDeviceGroupMap() {
    allDevicesByGroup = {};
    
    // Use pre-computed index if available
    if (filterIndexes.byRbacGroup) {
        Object.keys(filterIndexes.byRbacGroup).forEach(group => {
            allDevicesByGroup[group] = new Set();
            filterIndexes.byRbacGroup[group].forEach(idx => {
                allDevicesByGroup[group].add(vulnerabilityData[idx].DeviceName);
            });
        });
    } else {
        // Fallback to building manually
        vulnerabilityData.forEach(v => {
            if (!allDevicesByGroup[v.RbacGroupName]) {
                allDevicesByGroup[v.RbacGroupName] = new Set();
            }
            allDevicesByGroup[v.RbacGroupName].add(v.DeviceName);
        });
    }
}

/**
 * Build set of all unique device tags from vulnerability data
 * Uses pre-computed index if available
 */
function buildDeviceTagsSet() {
    allDeviceTags = new Set();
    
    // Use pre-computed index if available
    if (filterIndexes.byTag) {
        Object.keys(filterIndexes.byTag).forEach(tag => allDeviceTags.add(tag));
    } else {
        // Fallback to building manually
        vulnerabilityData.forEach(v => {
            if (v.MachineTags && Array.isArray(v.MachineTags)) {
                v.MachineTags.forEach(tag => allDeviceTags.add(tag));
            }
        });
    }
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
 * Handle device group filter change (triggers bidirectional cascade)
 */
function handleDeviceGroupChange() {
    updateCascadingFilters('filterRbacGroup');
}

/**
 * Handle device tags filter change (triggers bidirectional cascade)
 */
function handleDeviceTagsChange() {
    updateCascadingFilters('filterDeviceTags');
}

/**
 * Handle device name filter change (triggers bidirectional cascade)
 */
function handleDeviceNameChange() {
    updateCascadingFilters('filterDeviceName');
}

/**
 * Handle OS platform filter change (triggers bidirectional cascade)
 */
function handleOSPlatformChange() {
    updateCascadingFilters('filterOSPlatform');
}

/**
 * Handle severity filter change (triggers bidirectional cascade)
 */
function handleSeverityChange() {
    updateCascadingFilters('filterSeverity');
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
 * Populate all filter dropdowns with unique values from data
 */
function populateFilters() {
    const rbacGroups = [...new Set(vulnerabilityData.map(v => v.RbacGroupName))].sort();
    const deviceNames = [...new Set(vulnerabilityData.map(v => v.DeviceName))].sort();
    const osPlatforms = [...new Set(vulnerabilityData.map(v => v.OSPlatform))].sort();
    const severities = ['Critical', 'High', 'Medium', 'Low'];
    
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
    const tags = [...allDeviceTags].sort();
    
    // Check if "(No Tags)" is already in the list (from pre-computed index)
    const hasNoTagsAlready = tags.includes(NO_TAGS_VALUE);
    
    // Check if any device has no tags
    const hasDevicesWithoutTags = vulnerabilityData.some(v => 
        !v.MachineTags || v.MachineTags.length === 0
    );
    
    // Only add "(No Tags)" if not already present and there are devices without tags
    if (hasDevicesWithoutTags && !hasNoTagsAlready) {
        tags.unshift(NO_TAGS_VALUE);
    } else if (hasNoTagsAlready) {
        // Move "(No Tags)" to the front if it exists
        const idx = tags.indexOf(NO_TAGS_VALUE);
        if (idx > 0) {
            tags.splice(idx, 1);
            tags.unshift(NO_TAGS_VALUE);
        }
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
 * Update cascading filters bidirectionally
 * When any filter changes, update checkbox states in all other filters
 * All options remain visible - we just check/uncheck based on what data matches
 * @param {string} changedFilter - The filter that was just changed
 */
function updateCascadingFilters(changedFilter) {
    // Get current selections from filters - only for filters where "All" is NOT checked
    // When "All" is checked, we treat it as "no filter" (include all)
    const selections = {
        rbacGroups: isAllChecked('filterRbacGroup') ? [] : getSelectedCheckboxValues('filterRbacGroup'),
        deviceTags: isAllChecked('filterDeviceTags') ? [] : getSelectedCheckboxValues('filterDeviceTags'),
        deviceNames: isAllChecked('filterDeviceName') ? [] : getSelectedCheckboxValues('filterDeviceName'),
        osPlatforms: isAllChecked('filterOSPlatform') ? [] : getSelectedCheckboxValues('filterOSPlatform'),
        severities: isAllChecked('filterSeverity') ? [] : getSelectedCheckboxValues('filterSeverity')
    };
    
    // Calculate which values exist in the data when filtered by OTHER filters
    // This tells us what values should be checked in each filter
    const availableValues = getAvailableValuesForFilters(selections, changedFilter);
    
    // Update checkbox states in each filter (except the one that changed)
    if (changedFilter !== 'filterRbacGroup') {
        updateCheckboxStates('filterRbacGroup', availableValues.rbacGroups);
    }
    if (changedFilter !== 'filterDeviceTags') {
        updateCheckboxStates('filterDeviceTags', availableValues.deviceTags);
    }
    if (changedFilter !== 'filterDeviceName') {
        updateCheckboxStates('filterDeviceName', availableValues.deviceNames);
    }
    if (changedFilter !== 'filterOSPlatform') {
        updateCheckboxStates('filterOSPlatform', availableValues.osPlatforms);
    }
    if (changedFilter !== 'filterSeverity') {
        updateCheckboxStates('filterSeverity', availableValues.severities);
    }
    
    applyFilters();
}

/**
 * Get available values for each filter based on data filtered by OTHER filters
 * @param {Object} selections - Current filter selections
 * @param {string} excludeFilter - Filter to exclude (the one that triggered the update)
 * @returns {Object} Sets of available values for each filter
 */
function getAvailableValuesForFilters(selections, excludeFilter) {
    const startDate = document.getElementById('filterStartDate').value;
    const endDate = document.getElementById('filterEndDate').value;
    
    // Convert selections to Sets for O(1) lookups
    const rbacSet = new Set(selections.rbacGroups);
    const tagsSet = new Set(selections.deviceTags);
    const deviceSet = new Set(selections.deviceNames);
    const osSet = new Set(selections.osPlatforms);
    const severitySet = new Set(selections.severities);
    
    // Date filter
    const dateFilter = (v) => {
        if (!startDate && !endDate) return true;
        const firstSeen = v._firstSeenDate || v.FirstSeenTimestamp.split(' ')[0];
        const lastSeen = v._lastSeenDate || v.LastSeenTimestamp.split(' ')[0];
        if (startDate && lastSeen < startDate) return false;
        if (endDate && firstSeen > endDate) return false;
        return true;
    };
    
    // Individual filter functions
    const rbacFilter = (v) => rbacSet.size === 0 || rbacSet.has(v.RbacGroupName);
    const tagsFilter = (v) => {
        if (tagsSet.size === 0) return true;
        const vulnTags = v.MachineTags && v.MachineTags.length > 0 ? v.MachineTags : [NO_TAGS_VALUE];
        return vulnTags.some(tag => tagsSet.has(tag));
    };
    const deviceFilter = (v) => deviceSet.size === 0 || deviceSet.has(v.DeviceName);
    const osFilter = (v) => osSet.size === 0 || osSet.has(v.OSPlatform);
    const severityFilter = (v) => severitySet.size === 0 || severitySet.has(v.VulnerabilitySeverityLevel);
    
    // Collect available values for each filter based on data filtered by OTHER filters
    const result = {
        rbacGroups: new Set(),
        deviceTags: new Set(),
        deviceNames: new Set(),
        osPlatforms: new Set(),
        severities: new Set()
    };
    
    vulnerabilityData.forEach(v => {
        if (!dateFilter(v)) return;
        
        // For each filter, check if record passes all OTHER filters
        // If so, add this record's value to that filter's available set
        
        // RbacGroup: filtered by tags, devices, os, severity
        if (tagsFilter(v) && deviceFilter(v) && osFilter(v) && severityFilter(v)) {
            result.rbacGroups.add(v.RbacGroupName);
        }
        
        // DeviceTags: filtered by rbac, devices, os, severity
        if (rbacFilter(v) && deviceFilter(v) && osFilter(v) && severityFilter(v)) {
            const tags = v.MachineTags && v.MachineTags.length > 0 ? v.MachineTags : [NO_TAGS_VALUE];
            tags.forEach(tag => result.deviceTags.add(tag));
        }
        
        // DeviceName: filtered by rbac, tags, os, severity
        if (rbacFilter(v) && tagsFilter(v) && osFilter(v) && severityFilter(v)) {
            result.deviceNames.add(v.DeviceName);
        }
        
        // OSPlatform: filtered by rbac, tags, devices, severity
        if (rbacFilter(v) && tagsFilter(v) && deviceFilter(v) && severityFilter(v)) {
            result.osPlatforms.add(v.OSPlatform);
        }
        
        // Severity: filtered by rbac, tags, devices, os
        if (rbacFilter(v) && tagsFilter(v) && deviceFilter(v) && osFilter(v)) {
            result.severities.add(v.VulnerabilitySeverityLevel);
        }
    });
    
    return result;
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

    // Sort by vulnerabilities count descending
    const sortedRemediations = Object.values(remediationMap)
        .sort((a, b) => b.vulnerabilities.size - a.vulnerabilities.size);

    sortedRemediations.forEach(rem => {
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
    });
}

/**
 * Sort the remediation table by column
 * @param {number} columnIndex - The column index to sort by
 */
function sortTable(columnIndex) {
    const table = document.getElementById('remediationTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    sortDirection[columnIndex] = !sortDirection[columnIndex];

    rows.sort((a, b) => {
        let aValue = a.cells[columnIndex].textContent;
        let bValue = b.cells[columnIndex].textContent;

        // Convert to numbers if possible
        if (!isNaN(aValue) && !isNaN(bValue)) {
            aValue = parseFloat(aValue);
            bValue = parseFloat(bValue);
        }

        if (aValue < bValue) return sortDirection[columnIndex] ? -1 : 1;
        if (aValue > bValue) return sortDirection[columnIndex] ? 1 : -1;
        return 0;
    });

    tbody.innerHTML = '';
    rows.forEach(row => tbody.appendChild(row));
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
    
    // Sort by date descending
    const sortedEntries = Object.values(remediationByDate).sort((a, b) => {
        return b.date.localeCompare(a.date);
    });
    
    sortedEntries.forEach(data => {
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
    });
}

/**
 * Sort the remediation details table by column
 * @param {number} columnIndex - The column index to sort by
 */
function sortRemediationDetailsTable(columnIndex) {
    const table = document.getElementById('remediationDetailsTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    sortRemediationDetailsDirection[columnIndex] = !sortRemediationDetailsDirection[columnIndex];

    rows.sort((a, b) => {
        let aValue = a.cells[columnIndex].textContent;
        let bValue = b.cells[columnIndex].textContent;

        if (!isNaN(aValue) && !isNaN(bValue)) {
            aValue = parseFloat(aValue);
            bValue = parseFloat(bValue);
        }

        if (aValue < bValue) return sortRemediationDetailsDirection[columnIndex] ? -1 : 1;
        if (aValue > bValue) return sortRemediationDetailsDirection[columnIndex] ? 1 : -1;
        return 0;
    });

    tbody.innerHTML = '';
    rows.forEach(row => tbody.appendChild(row));
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
        return;
    }
    
    window.top25RemediationsData.forEach((item, index) => {
        const cveIds = new Set(item.vulnerabilities.map(v => v.CveId));
        const devices = new Set(item.vulnerabilities.map(v => v.DeviceName));
        
        const row = tbody.insertRow();
        row.innerHTML = `
            <td>${index + 1}</td>
            <td>${item.name}</td>
            <td>${devices.size}</td>
            <td>${cveIds.size}</td>
            <td>${item.impact}</td>
        `;
        row.onclick = () => showImpactAnalysisDetails(item);
    });
}

/**
 * Sort the impact analysis table by column
 * @param {number} columnIndex - The column index to sort by
 */
function sortImpactAnalysisTable(columnIndex) {
    const table = document.getElementById('impactAnalysisTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    sortImpactAnalysisDirection[columnIndex] = !sortImpactAnalysisDirection[columnIndex];

    rows.sort((a, b) => {
        let aValue = a.cells[columnIndex].textContent;
        let bValue = b.cells[columnIndex].textContent;

        if (!isNaN(aValue) && !isNaN(bValue)) {
            aValue = parseFloat(aValue);
            bValue = parseFloat(bValue);
        }

        if (aValue < bValue) return sortImpactAnalysisDirection[columnIndex] ? -1 : 1;
        if (aValue > bValue) return sortImpactAnalysisDirection[columnIndex] ? 1 : -1;
        return 0;
    });

    tbody.innerHTML = '';
    rows.forEach(row => tbody.appendChild(row));
}

// =============================================================================
// MODALS
// =============================================================================

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

    // Group by device
    const deviceMap = {};
    details.forEach(d => {
        if (!deviceMap[d.DeviceName]) {
            deviceMap[d.DeviceName] = [];
        }
        deviceMap[d.DeviceName].push(d);
    });

    let html = '<h3>Affected Devices and Vulnerabilities</h3>';
    
    Object.entries(deviceMap).forEach(([deviceName, vulns]) => {
        html += `<h4>${deviceName}</h4>`;
        html += '<table class="detail-table"><thead><tr>';
        html += '<th>CVE ID</th><th>Software</th><th>Version</th><th>Severity</th><th>CVSS Score</th><th>Exploitability</th><th>Recommended Update</th>';
        html += '</tr></thead><tbody>';

        vulns.forEach(v => {
            const severityClass = v.VulnerabilitySeverityLevel.toLowerCase();
            const cveUrl = v.CveBatchUrl || `https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/${v.CveId}`;
            
            // Format recommended update
            let recommendedUpdate = '';
            if (v.RecommendedSecurityUpdate && v.RecommendedSecurityUpdateId) {
                recommendedUpdate = `${v.RecommendedSecurityUpdate} (${v.RecommendedSecurityUpdateId})`;
            } else if (v.RecommendedSecurityUpdate) {
                recommendedUpdate = v.RecommendedSecurityUpdate;
            } else if (v.RecommendedSecurityUpdateId) {
                recommendedUpdate = v.RecommendedSecurityUpdateId;
            } else {
                recommendedUpdate = '-';
            }
            
            html += `<tr>
                <td><a href="${cveUrl}" target="_blank">${v.CveId}</a></td>
                <td>${v.SoftwareVendor} - ${v.SoftwareName}</td>
                <td>${v.SoftwareVersion}</td>
                <td><span class="badge ${severityClass}">${v.VulnerabilitySeverityLevel}</span></td>
                <td>${v.CvssScore}</td>
                <td>${v.ExploitabilityLevel}</td>
                <td>${recommendedUpdate}</td>
            </tr>`;
        });

        html += '</tbody></table><br>';
    });

    modalBody.innerHTML = html;
    modal.classList.add('active');
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
    
    let html = '<h3>Summary</h3>';
    html += '<table class="detail-table"><tr>';
    html += `<td><strong>Date:</strong> ${data.date}</td>`;
    html += `<td><strong>Assets Remediated:</strong> ${data.devices.size}</td>`;
    html += `<td><strong>Vulnerabilities Remediated:</strong> ${data.vulnerabilities.size}</td>`;
    html += '</tr></table><br>';
    
    // Group by device
    const deviceMap = {};
    data.details.forEach(d => {
        if (!deviceMap[d.DeviceName]) {
            deviceMap[d.DeviceName] = [];
        }
        deviceMap[d.DeviceName].push(d);
    });
    
    html += '<h3>Devices Patched</h3>';
    
    Object.entries(deviceMap).forEach(([deviceName, vulns]) => {
        html += `<h4>${deviceName} (${vulns.length} vulnerabilities)</h4>`;
        html += '<table class="detail-table"><thead><tr>';
        html += '<th>CVE ID</th><th>Software</th><th>Version</th><th>Severity</th><th>CVSS Score</th>';
        html += '</tr></thead><tbody>';
        
        vulns.forEach(v => {
            const severityClass = v.VulnerabilitySeverityLevel.toLowerCase();
            const cveUrl = v.CveBatchUrl || `https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/${v.CveId}`;
            
            html += `<tr>
                <td><a href="${cveUrl}" target="_blank">${v.CveId}</a></td>
                <td>${v.SoftwareVendor} - ${v.SoftwareName}</td>
                <td>${v.SoftwareVersion}</td>
                <td><span class="badge ${severityClass}">${v.VulnerabilitySeverityLevel}</span></td>
                <td>${v.CvssScore}</td>
            </tr>`;
        });
        
        html += '</tbody></table><br>';
    });
    
    modalBody.innerHTML = html;
    modal.classList.add('active');
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
    
    // Group vulnerabilities by device
    const deviceMap = {};
    item.vulnerabilities.forEach(v => {
        if (!deviceMap[v.DeviceName]) {
            deviceMap[v.DeviceName] = new Set();
        }
        deviceMap[v.DeviceName].add(v.CveId);
    });
    
    let html = '<h3>Affected Devices</h3>';
    html += '<table class="detail-table"><thead><tr>';
    html += '<th>Device Name</th><th>CVE Count</th><th>CVE IDs</th>';
    html += '</tr></thead><tbody>';
    
    // Sort devices by CVE count descending
    const sortedDevices = Object.entries(deviceMap).sort((a, b) => b[1].size - a[1].size);
    
    sortedDevices.forEach(([deviceName, cveSet]) => {
        const cveList = Array.from(cveSet).sort().join(', ');
        
        html += `<tr>
            <td>${deviceName}</td>
            <td>${cveSet.size}</td>
            <td style="max-width: 500px; word-wrap: break-word;">${cveList}</td>
        </tr>`;
    });
    
    html += '</tbody></table>';
    
    modalBody.innerHTML = html;
    modal.classList.add('active');
}

/**
 * Close the modal
 */
function closeModal() {
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
            // Load libraries in correct order
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
            
            pdfLibrariesLoaded = true;
            console.log('PDF libraries loaded successfully');
            resolve();
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

        button.disabled = false;
        button.textContent = '📄 Export to PDF';
    } catch (err) {
        console.error('PDF generation failed:', err);
        alert('Failed to generate PDF: ' + err.message);
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
    init();
});
