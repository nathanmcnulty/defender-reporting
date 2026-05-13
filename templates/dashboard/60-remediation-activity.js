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
let remediationDetailsPager = null;

function getRemediationDetailsPager() {
    if (!remediationDetailsPager) {
        remediationDetailsPager = new PaginatedRenderer({
            containerId: 'remediationDetailsTableBody',
            scrollInfoId: 'remediationDetailsScrollInfo',
            pageSize: TABLE_PAGE_SIZE,
            allItemsLabel: 'rows',
            appendRange: appendRemediationDetailsRows
        });
    }

    return remediationDetailsPager;
}

function renderRemediationDetailsTable() {
    remediationDetailsAllData = getRemediationDetailsData().slice();
    renderRemediationDetailsTablePage();
}

/**
 * Render remediation details table (initial load or full refresh)
 */
function renderRemediationDetailsTablePage() {
    const state = getRemediationDetailsPager().render({
        items: remediationDetailsAllData,
        expanded: remediationDetailsExpanded
    });
    remediationDetailsLoadedCount = state.loadedCount;
}

/**
 * Append a single row to the remediation details table
 */
function createRemediationDetailsRow(data, index) {
    const total = data.devices.size * data.vulnerabilities.size;
    const row = document.createElement('tr');
    row.dataset.rowIndex = String(index);
    row.innerHTML = `
        <td>${escapeHtml(data.date)}</td>
        <td>${data.remediationHtml}</td>
        <td class="update-details-column">${data.updateHtml}</td>
        <td>${data.devices.size}</td>
        <td>${data.vulnerabilities.size}</td>
        <td>${total}</td>
    `;
    return row;
}

function appendRemediationDetailsRows(tbody, rows, startIdx, endIdx) {
    const fragment = document.createDocumentFragment();
    for (let i = startIdx; i < endIdx; i++) {
        fragment.appendChild(createRemediationDetailsRow(rows[i], i));
    }
    tbody.appendChild(fragment);
}

/**
 * Load more remediation details rows on scroll
 */
function loadMoreRemediationDetailsRows() {
    const state = getRemediationDetailsPager().loadMore();
    remediationDetailsLoadedCount = state.loadedCount;
}

/**
 * Update remediation details scroll info
 */
function updateRemediationDetailsScrollInfo() {
    getRemediationDetailsPager().updateScrollInfo();
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
