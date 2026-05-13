// =============================================================================
// DATA LOADING AND DENORMALIZATION
// =============================================================================

/**
 * Load and decompress data from embedded scripts.
 * For compressed formats, stores raw bytes for Worker-based decompression.
 */
let pendingCompressedBytes = null;
let pendingCompressedBytesPromise = null;
let dashboardPayloadSummary = null;

async function loadExternalCompressedPayloadBytes(url) {
    const response = await fetch(url, { cache: 'no-cache' });
    if (!response.ok) {
        throw new Error(`Failed to load dashboard payload (${response.status} ${response.statusText}).`);
    }

    return new Uint8Array(await response.arrayBuffer());
}

async function ensurePendingCompressedBytesLoaded() {
    if (pendingCompressedBytes) {
        return;
    }

    if (!pendingCompressedBytesPromise) {
        return;
    }

    pendingCompressedBytes = await pendingCompressedBytesPromise;
    pendingCompressedBytesPromise = null;
}

async function loadData() {
    logDebug('Loading data, format:', dataFormat);
    dashboardPayloadSummary = null;
    pendingCompressedBytesPromise = null;

    if (dataFormat === 'external-compressed') {
        if (!dashboardConfig.payloadUrl) {
            throw new Error('Split-assets mode requires dashboardConfig.payloadUrl.');
        }

        if (dashboardConfig.payloadSummaryUrl) {
            const compressedBytesPromise = loadExternalCompressedPayloadBytes(dashboardConfig.payloadUrl);
            const summaryResponse = await fetch(dashboardConfig.payloadSummaryUrl, { cache: 'no-cache' });
            if (!summaryResponse.ok) {
                throw new Error(`Failed to load dashboard summary (${summaryResponse.status} ${summaryResponse.statusText}).`);
            }

            dashboardPayloadSummary = await summaryResponse.json();
            if (dashboardPayloadSummary && dashboardPayloadSummary.filterCatalog) {
                lookups = {
                    devices: Array.isArray(dashboardPayloadSummary.filterCatalog.devices) ? dashboardPayloadSummary.filterCatalog.devices : [],
                    groups: Array.isArray(dashboardPayloadSummary.filterCatalog.groups) ? dashboardPayloadSummary.filterCatalog.groups : [],
                    tags: Array.isArray(dashboardPayloadSummary.filterCatalog.tags) ? dashboardPayloadSummary.filterCatalog.tags : []
                };
            }
            pendingCompressedBytesPromise = compressedBytesPromise;
        } else {
            pendingCompressedBytes = await loadExternalCompressedPayloadBytes(dashboardConfig.payloadUrl);
        }
    } else if (dataFormat === 'compressed') {
        // Base64 decode on main thread (fast), defer inflate to Worker
        const compressedBase64 = document.getElementById('vulnsData').textContent.replace(/\s+/g, '');
        const binaryString = atob(compressedBase64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = binaryString.charCodeAt(i);
        pendingCompressedBytes = bytes;
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

    if (lookups) {
        logDebug('Loaded lookups:', Object.keys(lookups));
        logDebug('Loaded', getRawVulnCount(), 'vulnerability records');
    } else {
        logDebug('Compressed data loaded, will decompress in Worker');
    }
}

function isColumnarRawVulnData(value) {
    return !!(value && !Array.isArray(value) && Array.isArray(value.d));
}

function hasFullDenormalizationLookups(value) {
    return !!(
        value
        && Array.isArray(value.devices)
        && Array.isArray(value.cves)
        && Array.isArray(value.software)
        && Array.isArray(value.groups)
        && Array.isArray(value.tags)
        && Array.isArray(value.platforms)
        && Array.isArray(value.versions)
        && Array.isArray(value.dates)
        && Array.isArray(value.updates)
        && Array.isArray(value.vendors)
        && Array.isArray(value.severities)
        && Array.isArray(value.exploitLevels)
        && Array.isArray(value.batchTitles)
        && Array.isArray(value.affSoftware)
    );
}

function getRawVulnCount() {
    if (!rawVulns) {
        return 0;
    }

    if (Array.isArray(rawVulns)) {
        return rawVulns.length;
    }

    if (isColumnarRawVulnData(rawVulns)) {
        return rawVulns.d.length;
    }

    return 0;
}

function getRawVulnRecord(index) {
    if (Array.isArray(rawVulns)) {
        return rawVulns[index];
    }

    if (!isColumnarRawVulnData(rawVulns)) {
        return null;
    }

    return [
        rawVulns.d[index],
        rawVulns.c[index],
        rawVulns.s[index],
        rawVulns.v[index],
        rawVulns.f[index],
        rawVulns.l[index],
        rawVulns.ua[index],
        rawVulns.u[index],
        rawVulns.dp[index],
        rawVulns.rp[index],
        rawVulns.iv ? rawVulns.iv[index] : -1
    ];
}

function getLookupRecord(lookup, index) {
    const value = getLookupValue(lookup, index);
    return value == null ? null : value;
}

/**
 * Denormalize a single vulnerability record from compact array format
 * @param {Array} v - Compact vulnerability record [devIdx, cveIdx, swIdx, version, firstSeen, lastSeen, updateAvail, updIdx, diskPaths, regPaths, inventoryIdx]
 * @param {number} index - Index in the array
 * @returns {Object} Expanded vulnerability object
 */
function createDenormalizeYieldState(rawCount, options = {}) {
    const configuredThreshold = Number(options.yieldThreshold);
    const configuredInterval = Number(options.yieldEveryRows);
    const threshold = Number.isFinite(configuredThreshold) && configuredThreshold >= 0
        ? Math.floor(configuredThreshold)
        : DENORMALIZE_YIELD_ROW_THRESHOLD;
    const interval = Number.isFinite(configuredInterval) && configuredInterval > 0
        ? Math.floor(configuredInterval)
        : DENORMALIZE_YIELD_ROW_INTERVAL;
    const canUseTimer = typeof window !== 'undefined' && typeof window.setTimeout === 'function';
    const enabled = options.allowYield === true && canUseTimer && rawCount >= threshold && interval > 0;

    return {
        enabled,
        interval,
        nextYieldAt: interval,
        yieldCount: 0
    };
}

async function maybeYieldDuringDenormalization(state, processedRows, totalRows) {
    if (!state.enabled || processedRows < state.nextYieldAt) {
        return;
    }

    state.yieldCount++;
    state.nextYieldAt += state.interval;

    if (totalRows > 0) {
        const percent = Math.min(99, Math.floor((processedRows / totalRows) * 100));
        setDashboardStatus(`Preparing dashboard rows (${percent}%)...`);
    }

    await new Promise(resolve => window.setTimeout(resolve, 0));
}

/**
 * Denormalize all vulnerability records (main-thread fallback)
 */
async function denormalizeAllVulns(options = {}) {
    const rawCount = getRawVulnCount();
    logDebug('Denormalizing', rawCount, 'records (main thread)...');
    const startTime = performance.now();
    const yieldState = createDenormalizeYieldState(rawCount, options);

    vulnerabilityData = new Array(rawCount);
    let rowCount = 0;
    let skippedInvalidRows = 0;

    // Direct column references for hot loop — avoids getRawVulnRecord overhead
    const isColumnar = isColumnarRawVulnData(rawVulns);
    const dCol = isColumnar ? rawVulns.d : null;
    const cCol = isColumnar ? rawVulns.c : null;
    const sCol = isColumnar ? rawVulns.s : null;
    const vCol = isColumnar ? rawVulns.v : null;
    const fCol = isColumnar ? rawVulns.f : null;
    const lCol = isColumnar ? rawVulns.l : null;
    const uCol = isColumnar ? rawVulns.u : null;
    const ivCol = isColumnar ? rawVulns.iv : null;

    // Cache lookup arrays locally
    const lkDevices = lookups.devices;
    const lkCves = lookups.cves;
    const lkSoftware = lookups.software;
    const lkGroups = lookups.groups;
    const lkPlatforms = lookups.platforms;
    const lkTags = lookups.tags;
    const lkVersions = lookups.versions;
    const lkDates = lookups.dates;
    const lkUpdates = lookups.updates;
    const lkVendors = lookups.vendors;
    const lkSeverities = lookups.severities;
    const lkExploitLevels = lookups.exploitLevels;
    const lkBatchTitles = lookups.batchTitles;
    const lkAffSoftware = lookups.affSoftware;
    const lkInventory = lookups.inventory || [];

    // Pre-format all date strings once (lkDates typically has ~365 entries)
    const preFormattedDates = new Array(lkDates ? lkDates.length : 0);
    for (let di = 0; di < preFormattedDates.length; di++) {
        const d = formatDateYMD(lkDates[di]);
        preFormattedDates[di] = d === '-' ? '' : d;
    }

    // Pre-compute addDays(date, DEVICE_INACTIVITY_WINDOW_DAYS) for every date index
    const addDaysByDateIdx = new Array(preFormattedDates.length);
    for (let di = 0; di < preFormattedDates.length; di++) {
        addDaysByDateIdx[di] = preFormattedDates[di]
            ? addDaysYmd(preFormattedDates[di], DEVICE_INACTIVITY_WINDOW_DAYS)
            : '';
    }

    // Pre-compute per-device values (one per unique device, ~20K)
    const noTagsArr = NO_TAGS_ARRAY;
    const EMPTY_PATHS = [];
    for (let di = 0; di < lkDevices.length; di++) {
        const dev = lkDevices[di];
        if (!dev) continue;
        const mi = dev.m;
        const ls = mi ? (mi.ls || mi.lastSeen || '') : '';
        const fmt = formatDateYMD(ls);
        dev._mlsFmt = fmt === '-' ? '' : fmt;
        dev._mlsInactivity = dev._mlsFmt
            ? addDaysYmd(dev._mlsFmt, DEVICE_INACTIVITY_WINDOW_DAYS)
            : '';
        // Tag names
        const deviceTags = dev.t;
        if (deviceTags && deviceTags.length > 0) {
            dev._tagNames = new Array(deviceTags.length);
            for (let ti = 0; ti < deviceTags.length; ti++) dev._tagNames[ti] = lkTags[deviceTags[ti]];
        } else {
            dev._tagNames = [];
        }
        dev._tagValues = dev._tagNames.length > 0 ? dev._tagNames : noTagsArr;
        dev._deviceFilterKey = dev.id || dev.n || '';
        dev._deviceSearchText = `${dev.n || ''} ${dev.id || ''}`.toLowerCase();
        // RBAC group
        const gVal = (dev.g >= 0 && dev.g < lkGroups.length) ? lkGroups[dev.g] : null;
        dev._rbacGroupName = (gVal && String(gVal).trim() !== '') ? gVal : '(none)';
        dev._normalizedGroup = normalizeGroupName(dev._rbacGroupName);
    }

    // Pre-compute per-CVE values (~30K items)
    for (let ci = 0; ci < lkCves.length; ci++) {
        const cve = lkCves[ci];
        if (!cve) continue;
        cve._pdFmt = cve.pd ? (formatDateYMD(cve.pd) || null) : null;
        cve._isExploitAvailable = cve.ea == null ? null : cve.ea === true;
        const nvdLastModified = cve.nlm ? formatDateYMD(cve.nlm) : '-';
        cve._nvdLastModifiedFmt = nvdLastModified === '-' ? null : nvdLastModified;
        const nvdKevDate = cve.nkev ? formatDateYMD(cve.nkev) : '-';
        cve._nvdKevFmt = nvdKevDate === '-' ? null : nvdKevDate;
        const nvdActionDue = cve.ndu ? formatDateYMD(cve.ndu) : '-';
        cve._nvdActionDueFmt = nvdActionDue === '-' ? null : nvdActionDue;
        cve._nvdWeaknesses = cve.nw && cve.nw.length > 0 ? cve.nw : null;
        const cveAs = cve.as;
        if (cveAs && cveAs.length > 0) {
            cve._affSw = new Array(cveAs.length);
            for (let ai = 0; ai < cveAs.length; ai++) cve._affSw[ai] = lkAffSoftware[cveAs[ai]];
        } else {
            cve._affSw = null;
        }
    }

    for (let ii = 0; ii < lkInventory.length; ii++) {
        const inventory = lkInventory[ii];
        if (!inventory) continue;
        const eod = inventory.eod ? formatDateYMD(inventory.eod) : '-';
        inventory._endOfSupportDateFmt = eod === '-' ? null : eod;
    }

    // Pre-compute per-(software, update) remediation key is no longer needed
    // (_remediationKey was set but never read)

    // Pre-compute per-(update, batchTitle) remediation string
    const remStrCache = new Map();
    function getRemediationStrCached(updIdx, btIdx) {
        const ck = (updIdx + 1) * 100000 + (btIdx + 1);
        let cached = remStrCache.get(ck);
        if (cached !== undefined) return cached;
        const uo = updIdx >= 0 ? lkUpdates[updIdx] : null;
        const un = uo ? (uo.n || uo) : null;
        const uid = uo ? (uo.id || null) : null;
        const bt = btIdx >= 0 ? lkBatchTitles[btIdx] : null;
        const kb = uid ? (String(uid).startsWith('KB') ? uid : 'KB' + uid) : null;
        if (bt) { cached = kb ? bt + ' (' + kb + ')' : bt; }
        else if (un && kb) { cached = un + ' (' + kb + ')'; }
        else if (un) { cached = un; }
        else if (kb) { cached = kb; }
        else { cached = 'Not Specified'; }
        remStrCache.set(ck, cached);
        return cached;
    }

    const earliestFirstSeenByIssue = new Map();
    const qualitySummary = createEmptyDataQualitySummary();
    const qualityDeviceKeys = new Set();
    const qualityCveIds = new Set();
    let _maxLatestActivity = '';

    for (let i = 0; i < rawCount; i++) {
        let devIdx, cveIdx, swIdx, verIdx, fsIdx, lsIdx, updIdx, invIdx;
        if (isColumnar) {
            devIdx = dCol[i]; cveIdx = cCol[i]; swIdx = sCol[i]; verIdx = vCol[i];
            fsIdx = fCol[i]; lsIdx = lCol[i]; updIdx = uCol[i]; invIdx = ivCol ? ivCol[i] : -1;
        } else {
            const row = rawVulns[i];
            devIdx = row[0]; cveIdx = row[1]; swIdx = row[2]; verIdx = row[3];
            fsIdx = row[4]; lsIdx = row[5]; updIdx = row[7]; invIdx = row.length > 10 ? row[10] : -1;
        }

        const device = getLookupRecord(lkDevices, devIdx);
        const cve = getLookupRecord(lkCves, cveIdx);
        const software = getLookupRecord(lkSoftware, swIdx);
        if (!device || !cve || !software) {
            skippedInvalidRows++;
            continue;
        }
        const inventory = invIdx >= 0 && invIdx < lkInventory.length ? lkInventory[invIdx] : null;

        const vendorName = software.v >= 0 && software.v < lkVendors.length ? lkVendors[software.v] : null;
        const updateObj = updIdx >= 0 ? lkUpdates[updIdx] : null;
        const updateName = updateObj ? (updateObj.n || updateObj) : null;

        const firstSeen = fsIdx >= 0 ? preFormattedDates[fsIdx] : '';
        const lastSeen = lsIdx >= 0 ? preFormattedDates[lsIdx] : '';

        // --- Inline derived fields using pre-computed device/cve values ---
        const machineLastSeen = device._mlsFmt;
        const latestActivity = (!machineLastSeen) ? lastSeen
            : (!lastSeen) ? machineLastSeen
            : (machineLastSeen > lastSeen ? machineLastSeen : lastSeen);
        const hasPatchEvidence = !!(lastSeen && latestActivity && latestActivity > lastSeen);
        if (latestActivity > _maxLatestActivity) _maxLatestActivity = latestActivity;
        let effectiveOpenEndDate = '';
        if (lastSeen) {
            if (latestActivity > lastSeen) {
                effectiveOpenEndDate = lastSeen;
            } else if (latestActivity === machineLastSeen && machineLastSeen) {
                effectiveOpenEndDate = device._mlsInactivity;
            } else {
                effectiveOpenEndDate = lsIdx >= 0 ? addDaysByDateIdx[lsIdx] : '';
            }
        }

        // Track earliest first-seen per environment issue key (numeric key avoids string concat)
        const issueKey = cveIdx * 1000000 + swIdx * 10000 + (verIdx + 1);
        if (firstSeen) {
            const existing = earliestFirstSeenByIssue.get(issueKey);
            if (!existing || firstSeen < existing) {
                earliestFirstSeenByIssue.set(issueKey, firstSeen);
            }
        }

        vulnerabilityData[rowCount++] = {
            DeviceId: device.id,
            DeviceName: device.n,
            RbacGroupName: device._rbacGroupName,
            OSPlatform: device.o >= 0 && device.o < lkPlatforms.length ? lkPlatforms[device.o] : null,
            MachineTags: device._tagNames,
            MachineInfo: device.m || null,
            CveId: cve.id,
            CvssScore: cve.sc,
            VulnerabilitySeverityLevel: cve.sv >= 0 && cve.sv < lkSeverities.length ? lkSeverities[cve.sv] : null,
            ExploitabilityLevel: cve.ex >= 0 ? lkExploitLevels[cve.ex] : null,
            PublishedDate: cve._pdFmt,
            EpssScore: cve.ep != null ? cve.ep : null,
            IsExploitAvailable: cve._isExploitAvailable,
            NvdLastModifiedDate: cve._nvdLastModifiedFmt,
            NvdBaseScore: cve.nbs != null ? cve.nbs : null,
            NvdBaseSeverity: cve.nsv || null,
            NvdVector: cve.nvec || null,
            NvdKevDate: cve._nvdKevFmt,
            NvdActionDue: cve._nvdActionDueFmt,
            NvdRequiredAction: cve.nact || null,
            NvdWeaknesses: cve._nvdWeaknesses,
            SoftwareVendor: vendorName,
            SoftwareName: software.n,
            SoftwareVersion: verIdx >= 0 ? lkVersions[verIdx] : null,
            ProductCodeCpe: inventory ? (inventory.cpe || null) : null,
            EndOfSupportStatus: inventory ? (inventory.eos || null) : null,
            EndOfSupportDate: inventory ? (inventory._endOfSupportDateFmt || null) : null,
            _firstSeenDate: firstSeen,
            _lastSeenDate: lastSeen,
            RecommendedSecurityUpdate: updateName,
            _index: i,
            _issueKey: issueKey,
            // Derived fields (inlined, using pre-computed device values)
            _machineLastSeenDate: machineLastSeen,
            _latestActivityDate: latestActivity,
            _hasPatchEvidence: hasPatchEvidence,
            _effectiveOpenEndDate: effectiveOpenEndDate,
            _remediationDate: hasPatchEvidence ? lastSeen : '',
            _remediationString: getRemediationStrCached(updIdx, cve.bt),
            _deviceFilterKey: device._deviceFilterKey,
            _deviceSearchText: device._deviceSearchText,
            _normalizedGroup: device._normalizedGroup,
            _tagValues: device._tagValues
        };

        if (yieldState.enabled && (i + 1) >= yieldState.nextYieldAt) {
            await maybeYieldDuringDenormalization(yieldState, i + 1, rawCount);
        }
    }

    vulnerabilityData.length = rowCount;

    // Second pass: assign _environmentFirstSeenDate (uses stored _issueKey)
    const totalDenormalizeWork = rawCount + vulnerabilityData.length;
    for (let i = 0; i < vulnerabilityData.length; i++) {
        const v = vulnerabilityData[i];
        v._environmentFirstSeenDate = earliestFirstSeenByIssue.get(v._issueKey) || v._firstSeenDate;

        qualitySummary.totalRecords++;
        const deviceKey = getDeviceIdentityKey(v);
        if (deviceKey) qualityDeviceKeys.add(deviceKey);
        if (v.CveId) qualityCveIds.add(v.CveId);

        if (!v.PublishedDate) {
            qualitySummary.missingPublished++;
        } else if (!/^\d{4}-\d{2}-\d{2}$/.test(v.PublishedDate)) {
            qualitySummary.nonYmdPublished++;
        }

        if (v._firstSeenDate && v._lastSeenDate && v._firstSeenDate > v._lastSeenDate) {
            qualitySummary.invertedRanges++;
        }

        if (yieldState.enabled && (rawCount + i + 1) >= yieldState.nextYieldAt) {
            await maybeYieldDuringDenormalization(yieldState, rawCount + i + 1, totalDenormalizeWork);
        }
    }

    qualitySummary.uniqueDevices = qualityDeviceKeys.size;
    qualitySummary.uniqueCves = qualityCveIds.size;
    dataQualitySummary = qualitySummary;
    mostRecentLastSeenDate = _maxLatestActivity;
    if (skippedInvalidRows > 0) {
        console.warn('Skipped', skippedInvalidRows, 'vulnerability records with missing lookup references during denormalization.');
    }
    const elapsed = Math.round(performance.now() - startTime);
    if (yieldState.yieldCount > 0) {
        dashboardMetrics.counts.denormalizeYields = (dashboardMetrics.counts.denormalizeYields || 0) + yieldState.yieldCount;
        publishDashboardDiagnostics();
        logDebug('Denormalization yielded', yieldState.yieldCount, 'time(s) while preparing rows');
    }
    logDebug('Denormalization complete in', elapsed, 'ms');
}

/**
 * Lazily resolve deferred detail properties on a vulnerability row.
 * Properties like DiskPaths, RegistryPaths, CveBatchUrl, etc. are only
 * needed for table/card/modal detail views (not for filtering or charts).
 * This avoids 1.5M array allocations during denormalization.
 * @param {Object} v - Vulnerability row object
 * @returns {Object} The same object, enriched with deferred properties
 */
function materializeRow(v) {
    if (v._mat) return v;
    // For rows loaded from IndexedDB cache, properties are already set;
    // rawVulns may not be available in that case
    if (!rawVulns || v._index == null || getRawVulnCount() === 0) {
        v._mat = true;
        return v;
    }
    const idx = v._index;
    if (idx < 0 || idx >= getRawVulnCount()) {
        v._mat = true;
        return v;
    }
    const rec = getRawVulnRecord(idx);
    const device = getLookupRecord(lookups.devices, rec[0]);
    const cve = getLookupRecord(lookups.cves, rec[1]);
    const software = getLookupRecord(lookups.software, rec[2]);
    if (!device || !cve || !software) {
        v.DiskPaths = v.DiskPaths || [];
        v.RegistryPaths = v.RegistryPaths || [];
        v.CveBatchUrl = v.CveBatchUrl || null;
        v.CveBatchTitle = v.CveBatchTitle || null;
        v.VulnerabilityDescription = v.VulnerabilityDescription || null;
        v.AffectedSoftware = v.AffectedSoftware || null;
        v.RecommendedSecurityUpdateId = v.RecommendedSecurityUpdateId || null;
        v.RecommendedSecurityUpdateUrl = v.RecommendedSecurityUpdateUrl || null;
        v.OSVersion = v.OSVersion || null;
        v.SecurityUpdateAvailable = v.SecurityUpdateAvailable === true;
        v.RecommendationReference = v.RecommendationReference || null;
        v._mat = true;
        return v;
    }
    const updIdx = rec[7];
    const updateObj = updIdx >= 0 ? getLookupValue(lookups.updates, updIdx) : null;

    // Evidence paths (resolved from lookup indices)
    const dpArr = rec[8];
    const rpArr = rec[9];
    if (dpArr && dpArr.length > 0) {
        v.DiskPaths = [];
        for (let i = 0; i < dpArr.length; i++) {
            const diskPath = getLookupValue(lookups.diskPaths, dpArr[i]);
            if (diskPath != null) v.DiskPaths.push(diskPath);
        }
    } else {
        v.DiskPaths = [];
    }
    if (rpArr && rpArr.length > 0) {
        v.RegistryPaths = [];
        for (let i = 0; i < rpArr.length; i++) {
            const regPath = getLookupValue(lookups.regPaths, rpArr[i]);
            if (regPath != null) v.RegistryPaths.push(regPath);
        }
    } else {
        v.RegistryPaths = [];
    }

    // Detail-only properties
    v.CveBatchUrl = cve.u;
    v.CveBatchTitle = cve.bt >= 0 ? getLookupValue(lookups.batchTitles, cve.bt) : null;
    v.VulnerabilityDescription = cve.desc || null;
    v.AffectedSoftware = cve._affSw;
    v.RecommendedSecurityUpdateId = updateObj ? (updateObj.id || null) : null;
    v.RecommendedSecurityUpdateUrl = updateObj ? (updateObj.url || null) : null;
    v.OSVersion = device.ov;
    v.SecurityUpdateAvailable = rec[6] === 1;
    v.RecommendationReference = software.r;

    v._mat = true;
    return v;
}

/**
 * Denormalize with Worker + IndexedDB caching.
 * Falls back to main-thread denormalization on any failure.
 * @returns {Promise<void>}
 */
async function denormalizeWithCaching() {
    await ensurePendingCompressedBytesLoaded();
    const hasCompressed = !!pendingCompressedBytes;
    let compressedFp = null;
    let fingerprint = null;

    // For compressed data, try cache using a fingerprint of the raw compressed bytes
    if (hasCompressed) {
        compressedFp = await computeCompressedFingerprint(pendingCompressedBytes);
        logDebug('Compressed fingerprint:', compressedFp);
        const cached = await getCachedData(compressedFp);
        if (cached && cached.data && cached.data.length > 0) {
            logDebug('Loaded', cached.data.length, 'records from IndexedDB cache (compressed fingerprint)');
            vulnerabilityData = cached.data;
            const decompressed = pako.inflate(pendingCompressedBytes, { to: 'string' });
            const payload = JSON.parse(decompressed);
            if (cached.lookups) {
                lookups = cached.lookups;
                logDebug('Restored lookups from IndexedDB cache');
            } else {
                lookups = payload.lookups;
            }
            rawVulns = payload.vulns;
            pendingCompressedBytes = null;
            applyDerivedVulnerabilityFields(vulnerabilityData);
            return;
        }
    }

    if (!hasCompressed) {
        fingerprint = await computeDataFingerprint();
        const rawCount = getRawVulnCount();
        logDebug('Data fingerprint:', fingerprint);

        // 1. Try IndexedDB cache
        const cached = await getCachedData(fingerprint);
        if (cached && cached.data && cached.data.length === rawCount) {
            logDebug('Loaded', cached.data.length, 'records from IndexedDB cache');
            if (cached.lookups) lookups = cached.lookups;
            vulnerabilityData = cached.data;
            applyDerivedVulnerabilityFields(vulnerabilityData);
            return;
        }
    }

    // 2. Try Web Worker (with optional decompression)
    const compBytes = pendingCompressedBytes;
    pendingCompressedBytes = null;
    try {
        const label = compBytes ? 'decompressing' : 'denormalizing';
        logDebug(label, compBytes ? '(compressed bytes via Worker)' : getRawVulnCount(), 'records via Web Worker...');
        const startTime = performance.now();
        const result = await denormalizeInWorker(compBytes);
        if (result.lookups) lookups = result.lookups;
        if (result.rawVulns) rawVulns = result.rawVulns;
        if (result.skippedInvalidRows > 0) {
            console.warn('Skipped', result.skippedInvalidRows, 'vulnerability records with missing lookup references during Worker denormalization.');
        }
        if (result.rows) {
            // Worker returned fully denormalized rows (non-compressed path)
            vulnerabilityData = result.rows;
            applyDerivedVulnerabilityFields(vulnerabilityData);
        } else {
            // Decompress-only path: Worker returned lookups + rawVulns, denormalize here
            const decompElapsed = Math.round(performance.now() - startTime);
            console.log('[perf] Worker decompress: ' + decompElapsed + 'ms');
            await denormalizeAllVulns({ allowYield: true });
        }
        const elapsed = Math.round(performance.now() - startTime);
        logDebug('Worker + denormalize complete in', elapsed, 'ms');
    } catch (err) {
        console.warn('Web Worker failed, falling back to main thread:', err);
        // Hosted summary-first loading seeds a lightweight lookup catalog before the
        // full payload arrives, so the fallback must detect incomplete lookups too.
        if (compBytes && (!hasFullDenormalizationLookups(lookups) || !rawVulns)) {
            const decompressed = pako.inflate(compBytes, { to: 'string' });
            const data = JSON.parse(decompressed);
            lookups = data.lookups;
            rawVulns = data.vulns;
        }
        await denormalizeAllVulns({ allowYield: true });
    }

    // Derived fields are computed inline in denormalizeAllVulns(); Worker rows
    // and IndexedDB-cached data use applyDerivedVulnerabilityFields above.

    // Log counts after data is available
    logDebug('Loaded lookups:', lookups ? Object.keys(lookups) : 'none');
    logDebug('Loaded', getRawVulnCount(), 'vulnerability records');

    // 3. Cache the result (fire-and-forget) — skip for very large datasets
    // IndexedDB structured clone fails with out-of-memory for 500K+ records
    if (vulnerabilityData.length < 500000) {
        if (!fingerprint) {
            fingerprint = await computeDataFingerprint();
        }
        logDebug('Data fingerprint:', fingerprint);
        setCachedData(fingerprint, vulnerabilityData);
        if (compressedFp) {
            setCachedData(compressedFp, vulnerabilityData);
        }
    } else {
        console.log('[perf] Skipping IndexedDB cache for', vulnerabilityData.length, 'records (too large for structured clone)');
    }
}
