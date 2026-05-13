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
        const splitByVersion = (versionBucketsByBaseKey.get(baseKey)?.size || 0) > 1;
        const softwareLabel = getVersionAwareSoftwareLabel(software, v.OSPlatform, v.OSVersion, splitByVersion);
        const key = softwareLabel !== software ? `${baseKey}|${softwareLabel}` : baseKey;

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
    const remediationBaseKeys = new Array(activeRows.length);
    const remediationFormattedSoftware = new Array(activeRows.length);
    const remediationCanSplitByOsVersion = new Array(activeRows.length);
    const remediationRawKeys = new Array(activeRows.length);
    const versionBucketsByBaseKey = new Map();
    const rawKeyToMergedKey = new Map();

    for (let i = 0, len = activeRows.length; i < len; i++) {
        const v = activeRows[i];
        const remediation = buildRemediationDescriptor(v);
        const formattedSoftware = formatSoftwarePart(v.SoftwareName);
        const baseKey = remediation.key;
        const canSplitByOsVersion = shouldSplitRemediationByOsVersion(formattedSoftware, v.OSPlatform);

        remediationDescriptors[i] = remediation;
        remediationBaseKeys[i] = baseKey;
        remediationFormattedSoftware[i] = formattedSoftware;
        remediationCanSplitByOsVersion[i] = canSplitByOsVersion;

        if (!canSplitByOsVersion) {
            continue;
        }

        const versionBucket = normalizeOsVersionGroupingLabel(v.OSPlatform, v.OSVersion);
        if (!versionBucket) {
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
        const formattedSoftware = remediationFormattedSoftware[index];
        const baseKey = remediationBaseKeys[index];
        const splitByVersion = (versionBucketsByBaseKey.get(baseKey)?.size || 0) > 1;
        const baseImpactName = getScopedRemediationDisplayTitle(remediation);
        const impactName = getVersionAwareImpactDisplayName(remediation, formattedSoftware, v.OSPlatform, v.OSVersion, splitByVersion);
        const key = impactName !== baseImpactName ? `${baseKey}|${impactName}` : baseKey;
        remediationRawKeys[index] = key;

        if (!remediationMap[key]) {
            remediationMap[key] = {
                remediationDescriptor: remediation,
                descriptorObservationMap: new Map(),
                name: impactName,
                updateEntryMap: new Map(),
                devices: new Set(),
                cveIds: new Set()
            };
        }

        observeRemediationDescriptor(remediationMap[key], remediation);
        addRemediationUpdateEntry(remediationMap[key].updateEntryMap, remediation);
        remediationMap[key].devices.add(getDeviceIdentityKey(v));
        remediationMap[key].cveIds.add(v.CveId);
    });

    Object.entries(remediationMap).forEach(([key, bucket]) => {
        rawKeyToMergedKey.set(key, getRemediationAdvisoryFamilyMergeKey(bucket, key));
    });

    const mergedRemediationMap = mergeRemediationObjectBuckets(remediationMap, mergeImpactRemediationBuckets);

    const top25 = Object.entries(mergedRemediationMap)
        .map(([key, data]) => ({
            key,
            remediationDescriptor: getDominantRemediationDescriptor(data) || data.remediationDescriptor,
            name: data.name,
            updateEntries: finalizeRemediationUpdateEntries(data.updateEntryMap),
            impact: data.devices.size * data.cveIds.size,
            vulnerabilities: []
        }))
        .map(data => {
            const name = data.name || getScopedRemediationDisplayTitle(data.remediationDescriptor);
            const updateDisplay = buildSeparatedRemediationUpdateDisplay(name, data.remediationDescriptor, data.updateEntries);
            return {
                key: data.key,
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

    const top25ByKey = new Map(top25.map(item => [item.key, item]));
    for (let index = 0, len = activeRows.length; index < len; index++) {
        const v = activeRows[index];
        const rawKey = remediationRawKeys[index];
        const mergedKey = rawKeyToMergedKey.get(rawKey) || rawKey;
        const top25Entry = top25ByKey.get(mergedKey);
        if (top25Entry) {
            top25Entry.vulnerabilities.push(v);
        }
    }

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
let remediationTablePager = null;

function getRemediationTablePager() {
    if (!remediationTablePager) {
        remediationTablePager = new PaginatedRenderer({
            containerId: 'remediationTableBody',
            scrollInfoId: 'remediationScrollInfo',
            pageSize: TABLE_PAGE_SIZE,
            allItemsLabel: 'rows',
            appendRange: appendRemediationRows
        });
    }

    return remediationTablePager;
}

function renderTable() {
    remediationAllData = getRemediationTableData().slice();
    renderRemediationTablePage();
}

/**
 * Render remediation table (initial load or full refresh)
 */
function renderRemediationTablePage() {
    const pager = getRemediationTablePager();
    const state = pager.render({
        items: remediationAllData,
        expanded: remediationExpanded
    });
    remediationLoadedCount = state.loadedCount;
}

/**
 * Create a remediation table row
 */
function createRemediationRow(rem, index) {
    const row = document.createElement('tr');
    row.dataset.rowIndex = String(index);
    row.innerHTML = `
        <td>${escapeHtml(rem.vendor)}</td>
        <td>${escapeHtml(rem.software)}</td>
        <td>${rem.remediationHtml}</td>
        <td class="update-details-column">${rem.updateHtml}</td>
        <td>${rem.devices.size}</td>
        <td>${rem.vulnerabilities.size}</td>
        <td>${rem.exploits.size}</td>
        <td>${rem.kits.size}</td>
    `;
    return row;
}

function appendRemediationRows(tbody, rows, startIdx, endIdx) {
    const fragment = document.createDocumentFragment();
    for (let i = startIdx; i < endIdx; i++) {
        fragment.appendChild(createRemediationRow(rows[i], i));
    }
    tbody.appendChild(fragment);
}

/**
 * Load more remediation rows on scroll
 */
function loadMoreRemediationRows() {
    const state = getRemediationTablePager().loadMore();
    remediationLoadedCount = state.loadedCount;
}

/**
 * Update remediation scroll info
 */
function updateRemediationScrollInfo() {
    getRemediationTablePager().updateScrollInfo();
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
