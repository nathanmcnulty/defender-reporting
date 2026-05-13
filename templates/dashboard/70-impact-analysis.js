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
let impactAnalysisPager = null;

function getImpactAnalysisPager() {
    if (!impactAnalysisPager) {
        impactAnalysisPager = new PaginatedRenderer({
            containerId: 'impactAnalysisTableBody',
            scrollInfoId: 'impactAnalysisScrollInfo',
            pageSize: TABLE_PAGE_SIZE,
            allItemsLabel: 'rows',
            emptyStateHtml: '<tr><td colspan="6">No data available</td></tr>',
            appendRange: appendImpactAnalysisRows
        });
    }

    return impactAnalysisPager;
}

function renderImpactAnalysisTable() {
    impactAnalysisAllData = getImpactAnalysisTableData().slice();
    renderImpactAnalysisTablePage();
}

/**
 * Render impact analysis table (initial load or full refresh)
 */
function renderImpactAnalysisTablePage() {
    const state = getImpactAnalysisPager().render({
        items: impactAnalysisAllData,
        expanded: impactAnalysisExpanded
    });
    impactAnalysisLoadedCount = state.loadedCount;
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

function appendImpactAnalysisRows(tbody, rows, startIdx, endIdx) {
    const fragment = document.createDocumentFragment();
    for (let i = startIdx; i < endIdx; i++) {
        fragment.appendChild(createImpactAnalysisRow(rows[i], i));
    }
    tbody.appendChild(fragment);
}

/**
 * Load more impact analysis rows on scroll
 */
function loadMoreImpactAnalysisRows() {
    const state = getImpactAnalysisPager().loadMore();
    impactAnalysisLoadedCount = state.loadedCount;
}

/**
 * Update impact analysis scroll info
 */
function updateImpactAnalysisScrollInfo() {
    getImpactAnalysisPager().updateScrollInfo();
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
