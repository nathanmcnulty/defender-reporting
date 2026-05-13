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
    filterState = createDefaultFilterState();
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
            h.push('<span class="checkbox-count">', escapeHtml(count), '</span>');
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
    cancelDeferredVisibleReportRender();
    invalidateAggregateCache();
    syncUrlViewState();

    if (!filterState.hasDeviceNames || !filterState.hasRbacGroups || !filterState.hasDeviceTags || !filterState.hasSeverities || !filterState.hasOsPlatforms) {
        filteredData = [];
        updateDeviceSearchSummary([]);
        updateFilterSummary(filterState);
        updateStats();
        updateRemediationReportModeUi(activeReportId);
        markAllReportsDirty();
        renderActiveReport(true);
        dashboardMetrics.counts.applyFilters += 1;
        recordDashboardPhaseTiming('applyFiltersMs', performance.now() - _t0);
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
    dashboardMetrics.counts.applyFilters += 1;
    const applyFiltersDurationMs = performance.now() - _t0;
    recordDashboardPhaseTiming('applyFiltersMs', applyFiltersDurationMs);
    requestAnimationFrame(() => {
        renderActiveReport(true);
        scheduleReportDataWarmup();
        publishDashboardDiagnostics();
    });
    console.log(`[perf] applyFilters: ${applyFiltersDurationMs.toFixed(1)}ms  (${result.length}/${len} rows passed)`);
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
    publishDashboardDiagnostics();
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