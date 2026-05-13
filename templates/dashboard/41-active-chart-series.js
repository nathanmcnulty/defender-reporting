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