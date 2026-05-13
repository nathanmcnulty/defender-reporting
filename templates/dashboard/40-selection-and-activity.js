// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

const formatSoftwarePartCache = new Map();
const remediationDescriptorCache = new Map();
const splitRemediationByOsVersionCache = new Map();
const versionAwareImpactDisplayNameCache = new Map();

function buildMemoCacheKey(parts) {
    return parts.map(value => value == null ? '' : String(value)).join('\u001f');
}

/**
 * Format software name from vendor and product
 * @param {string} vendor - The software vendor
 * @param {string} product - The software product name
 * @returns {string} Formatted software name
 */
function formatSoftwarePart(text) {
    if (!text) return '';

    const cacheKey = String(text);
    const cached = formatSoftwarePartCache.get(cacheKey);
    if (cached !== undefined) {
        return cached;
    }

    const formatted = cacheKey
        .trim()
        .split('_')
        .filter(Boolean)
        .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
        .join(' ');

    formatSoftwarePartCache.set(cacheKey, formatted);
    return formatted;
}

function formatSoftwareName(vendor, product) {
    const vendorPart = formatSoftwarePart(vendor);
    const productPart = formatSoftwarePart(product);

    if (!vendorPart && !productPart) return 'Unknown';
    if (!vendorPart) return productPart;
    if (!productPart) return vendorPart;

    return `${vendorPart} - ${productPart}`;
}

function formatOsPlatformLabel(osPlatform) {
    const platformText = normalizeRemediationText(osPlatform);
    if (!platformText) {
        return '';
    }

    const normalized = platformText
        .replace(/_/g, ' ')
        .replace(/([a-z])([A-Z])/g, '$1 $2')
        .replace(/([A-Za-z])(\d+)/g, '$1 $2')
        .replace(/(\d)([A-Za-z]+)/g, '$1 $2')
        .replace(/\s+/g, ' ')
        .trim();

    const releaseNormalized = normalized.replace(/\bR\s+(\d)\b/g, 'R$1');

    const lower = releaseNormalized.toLowerCase();
    if (lower === 'mac os') {
        return 'macOS';
    }

    if (lower === 'i os') {
        return 'iOS';
    }

    return releaseNormalized;
}

function normalizeOsVersionGroupingLabel(osPlatform, osVersion) {
    const versionText = normalizeRemediationText(osVersion);
    if (!versionText) {
        return '';
    }

    const versionParts = versionText
        .split('.')
        .map(part => part.trim())
        .filter(part => /^\d+$/.test(part));

    if (versionParts.length === 0) {
        return versionText;
    }

    const normalizedParts = versionParts.slice(0, Math.min(3, versionParts.length));
    const platformText = normalizeRemediationText(osPlatform).toLowerCase();

    if (!platformText.startsWith('windows')) {
        while (normalizedParts.length > 1 && normalizedParts[normalizedParts.length - 1] === '0') {
            normalizedParts.pop();
        }
    }

    return normalizedParts.join('.');
}

function getOsFamilyComparisonKey(text) {
    return normalizeRemediationText(text)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '');
}

function isOsFamilySoftwareLabel(software) {
    const softwareKey = getOsFamilyComparisonKey(software);
    return /^(windows|macos|ubuntu|debian|linux|android|ios|chromeos)/.test(softwareKey);
}

function getVersionAwareSoftwareLabel(software, osPlatform, osVersion, splitByVersion) {
    if (!software || software === 'Unknown') {
        return software;
    }

    if (!splitByVersion) {
        return software;
    }

    if (shouldSplitRemediationByOsVersion(software, osPlatform)) {
        const versionLabel = normalizeOsVersionGroupingLabel(osPlatform, osVersion);
        if (versionLabel) {
            return `${software} (${versionLabel})`;
        }
    }

    return `${software} (version unavailable)`;
}

function shouldSplitRemediationByOsVersion(software, osPlatform) {
    const cacheKey = buildMemoCacheKey([software, osPlatform]);
    const cached = splitRemediationByOsVersionCache.get(cacheKey);
    if (cached !== undefined) {
        return cached;
    }

    const softwareKey = getOsFamilyComparisonKey(software);
    const platformKey = getOsFamilyComparisonKey(osPlatform);

    if (!softwareKey || !platformKey) {
        splitRemediationByOsVersionCache.set(cacheKey, false);
        return false;
    }

    const shouldSplit = softwareKey === platformKey
        || softwareKey.startsWith(platformKey)
        || platformKey.startsWith(softwareKey);

    splitRemediationByOsVersionCache.set(cacheKey, shouldSplit);
    return shouldSplit;
}

function getVersionAwareImpactDisplayName(descriptor, software, osPlatform, osVersion, splitByVersion) {
    const cacheKey = buildMemoCacheKey([
        descriptor?.key,
        descriptor?.title,
        software,
        osPlatform,
        osVersion,
        splitByVersion ? '1' : '0'
    ]);
    const cached = versionAwareImpactDisplayNameCache.get(cacheKey);
    if (cached !== undefined) {
        return cached;
    }

    const baseName = getScopedRemediationDisplayTitle(descriptor);
    const baseSoftwareLabel = normalizeRemediationText(software)
        || normalizeRemediationText(descriptor?.softwareLabel)
        || normalizeRemediationText(descriptor?.scopeLabel)
        || 'Unknown';
    const versionedSoftwareLabel = getVersionAwareSoftwareLabel(baseSoftwareLabel, osPlatform, osVersion, splitByVersion);

    if (!versionedSoftwareLabel || versionedSoftwareLabel === baseSoftwareLabel) {
        versionAwareImpactDisplayNameCache.set(cacheKey, baseName);
        return baseName;
    }

    const separatorIndex = baseName.indexOf(':');
    if (separatorIndex >= 0) {
        const suffix = baseName.slice(separatorIndex + 1).trim();
        const scopedName = suffix ? `${versionedSoftwareLabel}: ${suffix}` : versionedSoftwareLabel;
        versionAwareImpactDisplayNameCache.set(cacheKey, scopedName);
        return scopedName;
    }

    const versionAwareName = `${versionedSoftwareLabel}: ${baseName}`;
    versionAwareImpactDisplayNameCache.set(cacheKey, versionAwareName);
    return versionAwareName;
}

function getPointInTimeReferenceDate(state = filterState) {
    return state.endDate || mostRecentLastSeenDate;
}

function hasSelectedDateWindow(state = filterState) {
    return Boolean(state.startDate || state.endDate);
}

function getCurrentSelectionCacheKey(state = filterState) {
    return hasSelectedDateWindow(state)
        ? `range:${state.startDate || ''}:${state.endDate || ''}`
        : `point:${getPointInTimeReferenceDate(state)}`;
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
    const cacheKey = getCurrentSelectionCacheKey();

    if (cache.activeRowsForCurrentSelectionKey === cacheKey && cache.activeRowsForCurrentSelection) {
        return cache.activeRowsForCurrentSelection;
    }

    cache.activeRowsForCurrentSelectionKey = cacheKey;
    cache.activeRowsForCurrentSelection = hasSelectedDateWindow()
        ? filteredData
        : getPointInTimeActiveRows();
    return cache.activeRowsForCurrentSelection;
}

function getRemediationReportRows() {
    const cache = getAggregateCache();
    const cacheKey = `${getCurrentSelectionCacheKey()}|${remediationReportMode}`;

    if (cache.remediationReportRowsKey === cacheKey && cache.remediationReportRows) {
        return cache.remediationReportRows;
    }

    cache.remediationReportRowsKey = cacheKey;
    cache.remediationReportRows = (remediationReportMode === REMEDIATION_REPORT_MODE_RANGE && hasSelectedDateWindow())
        ? filteredData
        : getPointInTimeActiveRows();
    return cache.remediationReportRows;
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
const _nextDayCache = new Map();
function nextDay(dateStr) {
    let result = _nextDayCache.get(dateStr);
    if (result === undefined) {
        result = formatUtcDateAsYmd(addDaysToUtcDate(parseYmdDateAsUtc(dateStr), 1));
        _nextDayCache.set(dateStr, result);
    }
    return result;
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
    const firstSeen = v._firstSeenDate;
    const effectiveEnd = v._effectiveOpenEndDate;
    if (!firstSeen || !effectiveEnd) return false;
    return firstSeen <= dateStr && effectiveEnd >= dateStr;
}

function applyDerivedVulnerabilityFields(rows) {
    if (!Array.isArray(rows)) return;

    const earliestEnvironmentFirstSeenByIssue = new Map();
    const qualitySummary = createEmptyDataQualitySummary();
    const qualityDeviceKeys = new Set();
    const qualityCveIds = new Set();

    rows.forEach(v => {
        const issueKey = getEnvironmentIssueKey(v);
        const firstSeenDate = getFirstSeenDate(v);
        if (!issueKey || !firstSeenDate) return;

        const existing = earliestEnvironmentFirstSeenByIssue.get(issueKey);
        if (!existing || firstSeenDate < existing) {
            earliestEnvironmentFirstSeenByIssue.set(issueKey, firstSeenDate);
        }
    });

    let _maxLatest = '';
    rows.forEach(v => {
        const machineLastSeenDate = getMachineLastSeenDate(v);
        const latestActivityDate = getRowLatestActivityDate(v);
        if (latestActivityDate > _maxLatest) _maxLatest = latestActivityDate;
        const remediationEvidence = hasKnownPatchEvidence(v);
        const firstSeenDate = getFirstSeenDate(v);
        const lastSeenDate = getLastSeenDate(v);
        const effectiveOpenEndDate = getEffectiveOpenEndDate(v);
        const environmentFirstSeenDate = earliestEnvironmentFirstSeenByIssue.get(getEnvironmentIssueKey(v)) || firstSeenDate;

        v._firstSeenDate = firstSeenDate;
        v._machineLastSeenDate = machineLastSeenDate;
        v._latestActivityDate = latestActivityDate;
        v._hasPatchEvidence = remediationEvidence;
        v._effectiveOpenEndDate = effectiveOpenEndDate;
        v._remediationDate = remediationEvidence ? lastSeenDate : '';
        v._remediationString = buildRemediationString(v);
        v._environmentFirstSeenDate = environmentFirstSeenDate;
        v._deviceFilterKey = v.DeviceId || v.DeviceName || '';
        v._deviceSearchText = `${v.DeviceName || ''} ${v.DeviceId || ''}`.toLowerCase();
        v._normalizedGroup = normalizeGroupName(v.RbacGroupName);
        v._tagValues = v.MachineTags && v.MachineTags.length > 0 ? v.MachineTags : NO_TAGS_ARRAY;

        qualitySummary.totalRecords++;
        if (v._deviceFilterKey) qualityDeviceKeys.add(v._deviceFilterKey);
        if (v.CveId) qualityCveIds.add(v.CveId);

        if (!v.PublishedDate) {
            qualitySummary.missingPublished++;
        } else if (!/^\d{4}-\d{2}-\d{2}$/.test(v.PublishedDate)) {
            qualitySummary.nonYmdPublished++;
        }

        if (firstSeenDate && lastSeenDate && firstSeenDate > lastSeenDate) {
            qualitySummary.invertedRanges++;
        }
    });
    qualitySummary.uniqueDevices = qualityDeviceKeys.size;
    qualitySummary.uniqueCves = qualityCveIds.size;
    dataQualitySummary = qualitySummary;
    mostRecentLastSeenDate = _maxLatest;
}

/**
 * Create segment styling function for dashed lines after cutoff date
 * @param {number} cutoffIdx - Index where data transitions to projected
 * @returns {Object} Segment style configuration
 */