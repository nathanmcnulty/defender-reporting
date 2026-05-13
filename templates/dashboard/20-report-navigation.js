// =============================================================================
// EVENT HANDLERS
// =============================================================================

/**
 * Handle report view change from toolbar report controls.
 */
async function handleReportChange() {
    const selector = document.getElementById('reportSelector');
    if (!selector) {
        return;
    }

    const selectedReport = selector.value;
    if (reportRequiresChartRuntime(selectedReport) && typeof Chart === 'undefined') {
        const loadStatusMessage = `Loading chart runtime for ${REPORT_LABELS[selectedReport] || 'report'}...`;
        setDashboardStatus(loadStatusMessage);
        try {
            await ensureChartJsLoaded();
        } catch (error) {
            console.error('Failed to load chart runtime:', error);
            setDashboardStatus('Failed to load chart runtime. Please refresh and try again.', 'error');
            return;
        } finally {
            const status = document.getElementById('dashboardStatus');
            if (status && status.textContent === loadStatusMessage && status.dataset.statusKind !== 'error') {
                clearDashboardStatus();
            }
        }
    }

    if (selector.value !== selectedReport) {
        return;
    }

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
    syncReportNavigationUi();
    syncUrlViewState();
    publishDashboardDiagnostics();
    scheduleVisibleReportRender(selectedReport);
}

function handleReportSelectorButtonClick(event) {
    event.preventDefault();
    toggleReportSelectorPopover();
}

function handleReportSelectorPopoverClick(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
        return;
    }

    if (target.id === 'reportSelectorPopoverCloseButton') {
        closeReportSelectorPopover({ restoreFocus: true });
        return;
    }

    const optionButton = target.closest('.report-selector-option');
    if (!optionButton || !optionButton.dataset.reportId) {
        return;
    }

    selectReportById(optionButton.dataset.reportId);
    closeReportSelectorPopover();
}

async function handleExportPdfClick(event) {
    const button = event && event.currentTarget instanceof HTMLElement
        ? event.currentTarget
        : document.getElementById('exportPdfButton');
    const requiresRuntimeLoad = (dashboardConfig.pdfExportRuntimeMode || 'embedded') === 'external'
        && typeof exportToPDF !== 'function';
    const previousLabel = button ? button.textContent : '';

    if (button && requiresRuntimeLoad) {
        button.disabled = true;
        button.dataset.loading = 'true';
        button.setAttribute('aria-busy', 'true');
        button.textContent = 'Loading Export...';
    }

    try {
        await ensurePdfExportRuntimeLoaded();
    } catch (error) {
        console.error('Failed to load PDF export runtime:', error);
        alert('Unable to load the PDF export tools. Please refresh and try again.');
        return;
    } finally {
        if (button && requiresRuntimeLoad) {
            button.disabled = false;
            button.removeAttribute('aria-busy');
            delete button.dataset.loading;
            button.textContent = previousLabel;
        }
    }

    await exportToPDF();
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
        ? `<span class="checkbox-count">${escapeHtml(option.count)}</span>`
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

    closeReportSelectorPopover();
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
    const target = event.target;
    if (!(target instanceof Element)) {
        closeActiveFilterPopover();
        closeReportSelectorPopover();
        return;
    }

    const filterPopover = document.getElementById('filterPopover');
    if (activeFilterPopoverKey && filterPopover && !filterPopover.contains(target) && !target.closest('.filter-pill[data-filter-key]')) {
        closeActiveFilterPopover();
    }

    const reportPopover = document.getElementById('reportSelectorPopover');
    const reportButton = document.getElementById('reportSelectorButton');
    if (reportSelectorPopoverOpen && reportPopover && reportButton && !reportPopover.contains(target) && !reportButton.contains(target)) {
        closeReportSelectorPopover();
    }
}

function handleDocumentKeyDown(event) {
    if (event.key === 'Escape') {
        if (activeFilterPopoverKey) {
            closeActiveFilterPopover();
        }
        if (reportSelectorPopoverOpen) {
            closeReportSelectorPopover({ restoreFocus: true });
        }
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
    document.getElementById('reportSelectorButton')?.addEventListener('click', handleReportSelectorButtonClick);
    document.getElementById('reportSelectorPopover')?.addEventListener('click', handleReportSelectorPopoverClick);
    document.getElementById('exportPdfButton').addEventListener('click', handleExportPdfClick);
    document.getElementById('copyViewLinkButton')?.addEventListener('click', handleCopyViewLinkClick);
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
