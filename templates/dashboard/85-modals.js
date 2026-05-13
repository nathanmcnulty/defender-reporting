// =============================================================================
// MODALS
// =============================================================================

/**
 * Initialize evidence tooltip positioning
 * Uses event delegation to handle dynamically created tooltips
 */
function initEvidenceTooltips() {
    document.addEventListener('mouseenter', function(e) {
        if (!e.target || !e.target.closest) return;
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
        if (!e.target || !e.target.closest) return;
        const cell = e.target.closest('.evidence-cell');
        if (!cell) return;
        
        const tooltip = cell.querySelector('.evidence-tooltip');
        if (tooltip && !tooltip.classList.contains('pinned')) {
            tooltip.style.display = 'none';
        }
    }, true);

    // Click to pin/unpin tooltip (allows text selection & copying)
    document.addEventListener('click', function(e) {
        if (!e.target || !e.target.closest) return;
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
    materializeRow(v);
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
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function getSafeExternalUrl(url) {
    if (url === null || url === undefined) {
        return '';
    }

    const candidate = String(url).trim();
    if (!candidate) {
        return '';
    }

    try {
        const parsedUrl = new URL(candidate);
        return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:'
            ? parsedUrl.href
            : '';
    } catch {
        return '';
    }
}

function getSeverityClassName(severity) {
    const normalized = String(severity || '').trim().toLowerCase();
    return ['critical', 'high', 'medium', 'low'].includes(normalized)
        ? normalized
        : 'unknown';
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
            const users = Array.isArray(mi.u) ? mi.u : (typeof mi.u === 'string' && mi.u ? [mi.u] : []);
        if (mi.ip)  tooltipContent += `<br><span class="tooltip-label">IP:</span> ${escapeHtml(mi.ip)}`;
        if (mi.eip) tooltipContent += `<br><span class="tooltip-label">External IP:</span> ${escapeHtml(mi.eip)}`;
            if (users.length > 0) tooltipContent += `<br><span class="tooltip-label">Users:</span> ${escapeHtml(users.join(', '))}`;
        if (mi.hs)  tooltipContent += `<br><span class="tooltip-label">Health:</span> ${escapeHtml(mi.hs)}`;
        if (mi.rs)  tooltipContent += `<br><span class="tooltip-label">Risk:</span> ${escapeHtml(mi.rs)}`;
        if (mi.el)  tooltipContent += `<br><span class="tooltip-label">Exposure:</span> ${escapeHtml(mi.el)}`;
        if (mi.dv)  tooltipContent += `<br><span class="tooltip-label">Value:</span> ${escapeHtml(mi.dv)}`;
        if (mi.mb)  tooltipContent += `<br><span class="tooltip-label">Managed By:</span> ${escapeHtml(mi.mb)}`;
        if (mi.aad != null) tooltipContent += `<br><span class="tooltip-label">AAD Joined:</span> ${mi.aad ? 'Yes' : 'No'}`;
        if (mi.ls)  tooltipContent += `<br><span class="tooltip-label">Last Seen:</span> ${escapeHtml(formatDateYMD(mi.ls))}`;
        if (mi.fs)  tooltipContent += `<br><span class="tooltip-label">First Seen:</span> ${escapeHtml(formatDateYMD(mi.fs))}`;
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
    materializeRow(v);
    const cveUrl = getSafeExternalUrl(v.CveBatchUrl)
        || getSafeExternalUrl(`https://msrc.microsoft.com/update-guide/vulnerability/${encodeURIComponent(v.CveId || '')}`);
    const displayId = formatCveDisplayId(v.CveId);
    const severityClass = getSeverityClassName(v.VulnerabilitySeverityLevel);
    const tooltipId = `modal-cve-${++severityBadgeIdCounter}`;
    const versions = new Set();
    if (v.SoftwareVersion) {
        versions.add(v.SoftwareVersion);
    }

    cveTooltipData[tooltipId] = generateCveTooltipContent({
        cve: v.CveId,
        id: v.CveId,
        softwareVendor: v.SoftwareVendor,
        softwareName: v.SoftwareName,
        versions: versions,
        description: v.VulnerabilityDescription,
        cvssScore: v.CvssScore,
        severity: v.VulnerabilitySeverityLevel || 'Unknown',
        publishedDate: v.PublishedDate,
        firstSeen: getEnvironmentFirstSeenDate(v),
        lastSeen: v._lastSeenDate
    });

    if (cveUrl) {
        return `<td><a href="${escapeHtml(cveUrl)}" target="_blank" rel="noopener noreferrer" class="cve-severity-badge ${severityClass}" data-tooltip-id="${tooltipId}">${escapeHtml(displayId)}</a></td>`;
    }

    return `<td><span class="cve-severity-badge ${severityClass}" data-tooltip-id="${tooltipId}">${escapeHtml(displayId)}</span></td>`;
}

/**
 * Group devices by their shared CVE signature (identical set of CVE IDs)
 */
function groupDevicesByCveSignature(details) {
    const mergeModalObservationRow = (existing, candidate) => {
        materializeRow(existing);
        materializeRow(candidate);
        const existingFirstSeen = getFirstSeenDate(existing);
        const candidateFirstSeen = getFirstSeenDate(candidate);
        const existingLastSeen = getLastSeenDate(existing);
        const candidateLastSeen = getLastSeenDate(candidate);
        const existingEnvironmentFirstSeen = getEnvironmentFirstSeenDate(existing);
        const candidateEnvironmentFirstSeen = getEnvironmentFirstSeenDate(candidate);
        const existingRecency = getMostRecentYmdDate([existingLastSeen, getRowLatestActivityDate(existing)]);
        const candidateRecency = getMostRecentYmdDate([candidateLastSeen, getRowLatestActivityDate(candidate)]);
        const useCandidateMetadata = Boolean(candidateRecency && (!existingRecency || candidateRecency >= existingRecency));
        const merged = useCandidateMetadata
            ? { ...existing, ...candidate }
            : { ...candidate, ...existing };

        const earliestFirstSeen = getEarliestYmdDate([existingFirstSeen, candidateFirstSeen]);
        const latestLastSeen = getMostRecentYmdDate([existingLastSeen, candidateLastSeen]);
        const earliestEnvironmentFirstSeen = getEarliestYmdDate([existingEnvironmentFirstSeen, candidateEnvironmentFirstSeen]);

        if (earliestFirstSeen) {
            merged._firstSeenDate = earliestFirstSeen;
            merged.FirstSeenTimestamp = earliestFirstSeen;
        }

        if (latestLastSeen) {
            merged._lastSeenDate = latestLastSeen;
            merged.LastSeenTimestamp = latestLastSeen;
        }

        if (earliestEnvironmentFirstSeen) {
            merged._environmentFirstSeenDate = earliestEnvironmentFirstSeen;
            merged.EnvironmentFirstSeenTimestamp = earliestEnvironmentFirstSeen;
        }

        merged.DiskPaths = Array.from(new Set([...(existing.DiskPaths || []), ...(candidate.DiskPaths || [])]));
        merged.RegistryPaths = Array.from(new Set([...(existing.RegistryPaths || []), ...(candidate.RegistryPaths || [])]));
        merged.AffectedSoftware = Array.from(new Set([...(existing.AffectedSoftware || []), ...(candidate.AffectedSoftware || [])]));
        merged.MachineTags = Array.from(new Set([...(existing.MachineTags || []), ...(candidate.MachineTags || [])]));
        merged._observationWindowCount = Number(existing._observationWindowCount || 1) + Number(candidate._observationWindowCount || 1);

        return merged;
    };

    // Build per-device CVE map
    const deviceMap = new Map();
    for (let i = 0; i < details.length; i++) {
        const d = details[i];
        const key = getDeviceIdentityKey(d);
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
        } else {
            dev.vulnsByCve[d.CveId] = mergeModalObservationRow(dev.vulnsByCve[d.CveId], d);
        }
    }

    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    const sortVulns = (vulns) => {
        vulns.sort((a, b) => {
            const aSev = sevOrder[a.VulnerabilitySeverityLevel?.toLowerCase()] ?? 9;
            const bSev = sevOrder[b.VulnerabilitySeverityLevel?.toLowerCase()] ?? 9;
            return aSev !== bSev ? aSev - bSev : a.CveId.localeCompare(b.CveId);
        });
        return vulns;
    };

    const devices = Array.from(deviceMap.values());

    // If only one device, return a single group with all its CVEs
    if (devices.length <= 1) {
        const dev = devices[0];
        return [{
            devices: [{ DeviceName: dev.DeviceName, DeviceId: dev.DeviceId, MachineInfo: dev.MachineInfo }],
            vulns: sortVulns(Object.values(dev.vulnsByCve))
        }];
    }

    // Find CVEs shared by ALL devices vs CVEs unique to some devices
    const allDeviceKeys = devices.map(d => getDeviceIdentityKey(d));
    const cveCounts = new Map(); // cveId -> Set of device keys that have it
    for (const dev of devices) {
        const devKey = getDeviceIdentityKey(dev);
        for (const cveId of dev.cveIds) {
            if (!cveCounts.has(cveId)) cveCounts.set(cveId, new Set());
            cveCounts.get(cveId).add(devKey);
        }
    }

    const totalDevices = devices.length;
    const sharedCves = new Set();
    for (const [cveId, devKeys] of cveCounts) {
        if (devKeys.size === totalDevices) sharedCves.add(cveId);
    }

    const result = [];

    // Group 1: Shared CVEs (all devices together)
    if (sharedCves.size > 0) {
        const refDev = devices[0];
        const sharedVulns = [];
        for (const cveId of sharedCves) {
            if (refDev.vulnsByCve[cveId]) sharedVulns.push(refDev.vulnsByCve[cveId]);
        }
        result.push({
            devices: devices.map(d => ({ DeviceName: d.DeviceName, DeviceId: d.DeviceId, MachineInfo: d.MachineInfo })),
            vulns: sortVulns(sharedVulns)
        });
    }

    // Remaining groups: per-device unique CVEs (only for devices that have non-shared CVEs)
    for (const dev of devices) {
        const uniqueVulns = [];
        for (const cveId of dev.cveIds) {
            if (!sharedCves.has(cveId) && dev.vulnsByCve[cveId]) {
                uniqueVulns.push(dev.vulnsByCve[cveId]);
            }
        }
        if (uniqueVulns.length > 0) {
            result.push({
                devices: [{ DeviceName: dev.DeviceName, DeviceId: dev.DeviceId, MachineInfo: dev.MachineInfo }],
                vulns: sortVulns(uniqueVulns)
            });
        }
    }

    // Sort groups: most devices first, then most vulns
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
const DENSE_MODAL_DETAIL_THRESHOLD = 15000;
const DENSE_MODAL_DEVICE_THRESHOLD = 2500;

/**
 * Build a detail-row HTML string for showDetails CVE tables
 */
function buildDetailRow(v, includeEvidenceColumn) {
    const severityClass = getSeverityClassName(v.VulnerabilitySeverityLevel);
    const epssDisplay = v.EpssScore != null ? v.EpssScore.toFixed(5) : '-';
    const publishedDisplay = formatDateYMD(v.PublishedDate);
    const firstSeenDisplay = getEnvironmentFirstSeenDate(v);

    return '<tr>' +
        buildCveLinkHtml(v) +
        '<td>' + escapeHtml(v.SoftwareVersion) + '</td>' +
        '<td><span class="badge ' + severityClass + '">' + escapeHtml(v.VulnerabilitySeverityLevel) + '</span></td>' +
        '<td>' + escapeHtml(v.CvssScore) + '</td>' +
        '<td>' + escapeHtml(epssDisplay) + '</td>' +
        '<td>' + escapeHtml(formatExploitLevel(v.ExploitabilityLevel)) + '</td>' +
        (includeEvidenceColumn ? buildEvidenceHtml(v) : '') +
        '<td class="modal-date-col">' + escapeHtml(publishedDisplay) + '</td>' +
        '<td class="modal-date-col">' + escapeHtml(firstSeenDisplay) + '</td>' +
        '</tr>';
}

/**
 * Build a remediation-row HTML string for showRemediationDetails CVE tables
 */
function buildRemediationRow(v, includeEvidenceColumn) {
    const severityClass = getSeverityClassName(v.VulnerabilitySeverityLevel);
    const epssDisplay = v.EpssScore != null ? v.EpssScore.toFixed(5) : '-';
    const publishedDisplay = formatDateYMD(v.PublishedDate);
    const firstSeenDisplay = getEnvironmentFirstSeenDate(v);

    return '<tr>' +
        buildCveLinkHtml(v) +
        '<td>' + escapeHtml(v.SoftwareVersion) + '</td>' +
        '<td><span class="badge ' + severityClass + '">' + escapeHtml(v.VulnerabilitySeverityLevel) + '</span></td>' +
        '<td>' + escapeHtml(v.CvssScore) + '</td>' +
        '<td>' + escapeHtml(epssDisplay) + '</td>' +
        (includeEvidenceColumn ? buildEvidenceHtml(v) : '') +
        '<td class="modal-date-col">' + escapeHtml(publishedDisplay) + '</td>' +
        '<td class="modal-date-col">' + escapeHtml(firstSeenDisplay) + '</td>' +
        '</tr>';
}

function buildModalSummaryCounts(details, summarySource) {
    return {
        totalDetails: details.length,
        totalDevices: summarySource && summarySource.devices instanceof Set
            ? summarySource.devices.size
            : new Set(details.map(d => getDeviceIdentityKey(d))).size,
        totalCves: summarySource && summarySource.vulnerabilities instanceof Set
            ? summarySource.vulnerabilities.size
            : new Set(details.map(d => d.CveId)).size
    };
}

function shouldUseDenseDetailsModalLayout(summaryCounts) {
    return summaryCounts.totalDetails > DENSE_MODAL_DETAIL_THRESHOLD
        || summaryCounts.totalDevices > DENSE_MODAL_DEVICE_THRESHOLD;
}

function formatModalDeviceId(deviceId) {
    if (!deviceId) {
        return '-';
    }

    return deviceId.length > 12 ? deviceId.substring(0, 12) + '...' : deviceId;
}

function buildDenseModalDeviceRows(details) {
    const deviceMap = new Map();

    for (let i = 0; i < details.length; i++) {
        const detail = details[i];
        const key = getDeviceIdentityKey(detail);
        let device = deviceMap.get(key);

        if (!device) {
            device = {
                DeviceName: detail.DeviceName || 'Unknown',
                DeviceId: detail.DeviceId || '',
                MachineInfo: detail.MachineInfo || null,
                cveIds: new Set(),
                lastSeen: getLastSeenDate(detail)
            };
            deviceMap.set(key, device);
        }

        device.cveIds.add(detail.CveId);
        const candidateLastSeen = getLastSeenDate(detail);
        if (candidateLastSeen && (!device.lastSeen || candidateLastSeen > device.lastSeen)) {
            device.lastSeen = candidateLastSeen;
        }
    }

    return Array.from(deviceMap.values()).sort((a, b) => {
        if (b.cveIds.size !== a.cveIds.size) {
            return b.cveIds.size - a.cveIds.size;
        }

        return a.DeviceName.localeCompare(b.DeviceName);
    });
}

function buildDenseModalDeviceRow(device) {
    const ipAddress = device.MachineInfo && device.MachineInfo.ip ? device.MachineInfo.ip : '-';

    return '<tr>' +
        '<td>' + escapeHtml(device.DeviceName) + '</td>' +
        '<td title="' + escapeHtml(device.DeviceId || '') + '">' + escapeHtml(formatModalDeviceId(device.DeviceId)) + '</td>' +
        '<td>' + device.cveIds.size + '</td>' +
        '<td>' + escapeHtml(ipAddress) + '</td>' +
        '<td class="modal-date-col">' + escapeHtml(formatDateYMD(device.lastSeen)) + '</td>' +
        '</tr>';
}

function buildDenseDetailRow(v, includeEvidenceColumn) {
    const severityClass = getSeverityClassName(v.VulnerabilitySeverityLevel);
    const epssDisplay = v.EpssScore != null ? v.EpssScore.toFixed(5) : '-';
    const publishedDisplay = formatDateYMD(v.PublishedDate);
    const firstSeenDisplay = getEnvironmentFirstSeenDate(v);

    return '<tr>' +
        '<td>' + escapeHtml(v.DeviceName || 'Unknown') + '</td>' +
        '<td title="' + escapeHtml(v.DeviceId || '') + '">' + escapeHtml(formatModalDeviceId(v.DeviceId)) + '</td>' +
        buildCveLinkHtml(v) +
        '<td>' + escapeHtml(v.SoftwareVersion) + '</td>' +
        '<td><span class="badge ' + severityClass + '">' + escapeHtml(v.VulnerabilitySeverityLevel) + '</span></td>' +
        '<td>' + escapeHtml(v.CvssScore) + '</td>' +
        '<td>' + escapeHtml(epssDisplay) + '</td>' +
        '<td>' + escapeHtml(formatExploitLevel(v.ExploitabilityLevel)) + '</td>' +
        (includeEvidenceColumn ? buildEvidenceHtml(v) : '') +
        '<td class="modal-date-col">' + escapeHtml(publishedDisplay) + '</td>' +
        '<td class="modal-date-col">' + escapeHtml(firstSeenDisplay) + '</td>' +
        '</tr>';
}

    function buildDenseRemediationDetailRow(v, includeEvidenceColumn) {
        const severityClass = getSeverityClassName(v.VulnerabilitySeverityLevel);
        const epssDisplay = v.EpssScore != null ? v.EpssScore.toFixed(5) : '-';
        const publishedDisplay = formatDateYMD(v.PublishedDate);
        const firstSeenDisplay = getEnvironmentFirstSeenDate(v);

        return '<tr>' +
        '<td>' + escapeHtml(v.DeviceName || 'Unknown') + '</td>' +
        '<td title="' + escapeHtml(v.DeviceId || '') + '">' + escapeHtml(formatModalDeviceId(v.DeviceId)) + '</td>' +
        buildCveLinkHtml(v) +
        '<td>' + escapeHtml(v.SoftwareVersion) + '</td>' +
        '<td><span class="badge ' + severityClass + '">' + escapeHtml(v.VulnerabilitySeverityLevel) + '</span></td>' +
        '<td>' + escapeHtml(v.CvssScore) + '</td>' +
        '<td>' + escapeHtml(epssDisplay) + '</td>' +
        (includeEvidenceColumn ? buildEvidenceHtml(v) : '') +
        '<td class="modal-date-col">' + escapeHtml(publishedDisplay) + '</td>' +
        '<td class="modal-date-col">' + escapeHtml(firstSeenDisplay) + '</td>' +
        '</tr>';
    }

/**
 * Check whether any vulnerability in a list has evidence paths
 * @param {Array} vulnerabilities - Array of vulnerability objects
 * @returns {boolean} True when evidence exists
 */
function hasAnyEvidence(vulnerabilities) {
    for (let i = 0; i < vulnerabilities.length; i++) {
        const vulnerability = vulnerabilities[i];
        if ((vulnerability.DiskPaths && vulnerability.DiskPaths.length > 0) ||
            (vulnerability.RegistryPaths && vulnerability.RegistryPaths.length > 0)) {
            return true;
        }
    }
    return false;
}

/**
 * After modal innerHTML is set, attach VirtualModalTable to each tbody
 * that has a data-vt-rows attribute storing row data.
 */
function attachVirtualTables(scrollContainer, vtRowData) {
    destroyManagedVirtualTables(activeVirtualTables);
    attachManagedVirtualTables(scrollContainer, vtRowData, activeVirtualTables);
}

function buildModalGroupCache(details, summaryCounts) {
    const summary = summaryCounts || buildModalSummaryCounts(details);

    return {
        ...summary,
        layoutMode: 'grouped',
        groups: groupDevicesByCveSignature(details),
        includeEvidenceColumn: hasAnyEvidence(details),
        totalDevices: summary.totalDevices,
        totalCves: summary.totalCves
    };
}

function buildDenseDetailsModalCache(details, summaryCounts) {
    return {
        ...summaryCounts,
        layoutMode: 'dense',
        includeEvidenceColumn: hasAnyEvidence(details),
        deviceRows: buildDenseModalDeviceRows(details)
    };
}

function getDetailsModalCache(remediationData) {
    if (remediationData._modalCache) {
        return remediationData._modalCache;
    }

    const summaryCounts = buildModalSummaryCounts(remediationData.details, remediationData);
    remediationData._modalCache = shouldUseDenseDetailsModalLayout(summaryCounts)
        ? buildDenseDetailsModalCache(remediationData.details, summaryCounts)
        : buildModalGroupCache(remediationData.details, summaryCounts);

    return remediationData._modalCache;
}

function buildGroupedDetailsModalSections(modalCache, updateEntries) {
    const { groups, includeEvidenceColumn, totalDevices, totalCves } = modalCache;
    const parts = [];
    const vtRowData = {};

    parts.push('<h3>Affected Devices and Vulnerabilities</h3>');

    const updateLinksHtml = buildRemediationModalUpdateLinksHtml(updateEntries);
    if (updateLinksHtml) {
        parts.push(updateLinksHtml);
    }

    parts.push('<p class="modal-summary-text">' +
        totalDevices + ' device' + (totalDevices !== 1 ? 's' : '') + ', ' +
        totalCves + ' CVE' + (totalCves !== 1 ? 's' : '') + '</p>');

    for (let gi = 0; gi < groups.length; gi++) {
        const group = groups[gi];
        const vtId = 'det_' + gi;

        parts.push('<div class="device-bubbles-container">');
        group.devices.sort((a, b) => a.DeviceName.localeCompare(b.DeviceName));
        for (let di = 0; di < group.devices.length; di++) {
            parts.push(buildDeviceBubbleHtml(group.devices[di]));
        }
        parts.push('</div>');

        parts.push('<div class="modal-table-container"><table class="detail-table"><thead><tr>',
            '<th>CVE ID</th><th>Version</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Exploitability</th>' +
            (includeEvidenceColumn ? '<th>Evidence</th>' : '') +
            '<th class="modal-date-col">Published</th><th class="modal-date-col">Environment First Seen</th>',
            '</tr></thead><tbody data-vt-id="', vtId, '"></tbody></table></div>');

        vtRowData[vtId] = {
            items: group.vulns,
            rowBuilder: vuln => buildDetailRow(vuln, includeEvidenceColumn)
        };

        if (gi < groups.length - 1) {
            parts.push('<hr class="modal-section-divider">');
        }
    }

    return {
        layoutMode: 'grouped',
        parts,
        vtRowData
    };
}

function buildDenseDetailsModalSections(details, modalCache, updateEntries) {
    const { includeEvidenceColumn, totalDevices, totalCves, deviceRows } = modalCache;
    const parts = [];
    const vtRowData = {};

    parts.push('<h3>Affected Devices and Vulnerabilities</h3>');

    const updateLinksHtml = buildRemediationModalUpdateLinksHtml(updateEntries);
    if (updateLinksHtml) {
        parts.push(updateLinksHtml);
    }

    parts.push('<p class="modal-summary-text">' +
        totalDevices + ' device' + (totalDevices !== 1 ? 's' : '') + ', ' +
        totalCves + ' CVE' + (totalCves !== 1 ? 's' : '') + '</p>');
    parts.push('<p class="modal-summary-text">Large result set detected. Showing a virtualized flat view to keep this modal responsive.</p>');

    parts.push('<h3>Affected Devices</h3>');
    parts.push('<div class="modal-table-container"><table class="detail-table"><thead><tr>',
        '<th>Device Name</th><th>Device ID</th><th>CVE Count</th><th>IP</th><th class="modal-date-col">Last Seen</th>',
        '</tr></thead><tbody data-vt-id="det_dense_devices"></tbody></table></div>');

    vtRowData.det_dense_devices = {
        items: deviceRows,
        rowBuilder: buildDenseModalDeviceRow
    };

    parts.push('<h3>Vulnerability Details</h3>');
    parts.push('<div class="modal-table-container"><table class="detail-table"><thead><tr>',
        '<th>Device Name</th><th>Device ID</th><th>CVE ID</th><th>Version</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Exploitability</th>' +
        (includeEvidenceColumn ? '<th>Evidence</th>' : '') +
        '<th class="modal-date-col">Published</th><th class="modal-date-col">Environment First Seen</th>',
        '</tr></thead><tbody data-vt-id="det_dense_details"></tbody></table></div>');

    vtRowData.det_dense_details = {
        items: details,
        rowBuilder: vuln => buildDenseDetailRow(vuln, includeEvidenceColumn)
    };

    return {
        layoutMode: 'dense',
        parts,
        vtRowData
    };
}

function buildDetailsModalSections(remediationData) {
    const modalCache = getDetailsModalCache(remediationData);
    const updateEntries = remediationData.updateEntries && remediationData.updateEntries.length > 0
        ? remediationData.updateEntries
        : buildRemediationUpdateEntriesFromDetails(remediationData.details);

    return modalCache.layoutMode === 'dense'
        ? buildDenseDetailsModalSections(remediationData.details, modalCache, updateEntries)
        : buildGroupedDetailsModalSections(modalCache, updateEntries);
}

function buildGroupedRemediationDetailsModalSections(remediationData, modalCache) {
    const { groups, includeEvidenceColumn } = modalCache;
    const parts = ['<br>', '<h3>Devices Patched</h3>'];
    const vtRowData = {};

    for (let gi = 0; gi < groups.length; gi++) {
        const group = groups[gi];
        const vtId = 'rem_' + gi;

        parts.push('<div class="device-bubbles-container">');
        group.devices.sort((a, b) => a.DeviceName.localeCompare(b.DeviceName));
        for (let di = 0; di < group.devices.length; di++) {
            parts.push(buildDeviceBubbleHtml(group.devices[di]));
        }
        parts.push('</div>');

        parts.push('<div class="modal-table-container"><table class="detail-table"><thead><tr>',
            '<th>CVE ID</th><th>Version</th><th>Severity</th><th>CVSS</th><th>EPSS</th>' +
            (includeEvidenceColumn ? '<th>Evidence</th>' : '') +
            '<th class="modal-date-col">Published</th><th class="modal-date-col">Environment First Seen</th>',
            '</tr></thead><tbody data-vt-id="', vtId, '"></tbody></table></div>');

        vtRowData[vtId] = {
            items: group.vulns,
            rowBuilder: vuln => buildRemediationRow(vuln, includeEvidenceColumn)
        };

        if (gi < groups.length - 1) {
            parts.push('<hr class="modal-section-divider">');
        }
    }

    return {
        layoutMode: 'grouped',
        parts,
        vtRowData
    };
}

function buildDenseRemediationDetailsModalSections(remediationData, modalCache) {
    const { includeEvidenceColumn, deviceRows } = modalCache;
    const parts = [
        '<br>',
        '<h3>Devices Patched</h3>',
        '<p class="modal-summary-text">Large result set detected. Showing a virtualized flat view to keep this modal responsive.</p>'
    ];
    const vtRowData = {};

    parts.push('<div class="modal-table-container"><table class="detail-table"><thead><tr>',
        '<th>Device Name</th><th>Device ID</th><th>CVE Count</th><th>IP</th><th class="modal-date-col">Last Seen</th>',
        '</tr></thead><tbody data-vt-id="rem_dense_devices"></tbody></table></div>');

    vtRowData.rem_dense_devices = {
        items: deviceRows,
        rowBuilder: buildDenseModalDeviceRow
    };

    parts.push('<h3>Patched Vulnerabilities</h3>');
    parts.push('<div class="modal-table-container"><table class="detail-table"><thead><tr>',
        '<th>Device Name</th><th>Device ID</th><th>CVE ID</th><th>Version</th><th>Severity</th><th>CVSS</th><th>EPSS</th>' +
        (includeEvidenceColumn ? '<th>Evidence</th>' : '') +
        '<th class="modal-date-col">Published</th><th class="modal-date-col">Environment First Seen</th>',
        '</tr></thead><tbody data-vt-id="rem_dense_details"></tbody></table></div>');

    vtRowData.rem_dense_details = {
        items: remediationData.details,
        rowBuilder: vuln => buildDenseRemediationDetailRow(vuln, includeEvidenceColumn)
    };

    return {
        layoutMode: 'dense',
        parts,
        vtRowData
    };
}

function buildRemediationDetailsModalSections(remediationData) {
    const modalCache = getDetailsModalCache(remediationData);

    return modalCache.layoutMode === 'dense'
        ? buildDenseRemediationDetailsModalSections(remediationData, modalCache)
        : buildGroupedRemediationDetailsModalSections(remediationData, modalCache);
}

function deferModalContentRender(modal, renderContent) {
    const scheduleFrame = (typeof window !== 'undefined' && typeof window.requestAnimationFrame === 'function')
        ? window.requestAnimationFrame.bind(window)
        : (typeof requestAnimationFrame === 'function'
            ? requestAnimationFrame
            : callback => window.setTimeout(callback, 0));

    scheduleFrame(() => {
        scheduleFrame(() => {
            if (!modal || !modal.classList || !modal.classList.contains('active')) {
                return;
            }

            renderContent();
        });
    });
}

function focusModalCloseButton() {
    const closeButton = document.getElementById('closeModalButton');
    if (closeButton) {
        closeButton.focus();
    }
}

function getModalFocusableElements() {
    const modal = document.getElementById('detailModal');
    if (!modal || !modal.classList.contains('active')) {
        return [];
    }

    return Array.from(modal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'))
        .filter(element => !element.hasAttribute('disabled') && !element.getAttribute('aria-hidden'));
}

/**
 * Show vulnerability details modal
 * @param {Object} remediationData - Remediation aggregate row
 */
function showDetails(remediationData) {
    const modal = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    const remediation = remediationData.modalTitle
        || remediationData.remediation
        || [remediationData.vendor, remediationData.software].filter(Boolean).join(' ')
        || 'Remediation Details';

    modalTitle.textContent = remediation;
    modalBody.innerHTML = '<p class="loading">Loading details...</p>';
    lastFocusedElementBeforeModal = (typeof HTMLElement !== 'undefined' && document.activeElement instanceof HTMLElement) ? document.activeElement : null;
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    hideGlobalTooltip();
    focusModalCloseButton();

    if (!document.getElementById('cve-global-tooltip')) {
        initCveTooltips();
    }

    deferModalContentRender(modal, () => {
        const { parts, vtRowData } = buildDetailsModalSections(remediationData);
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
    lastFocusedElementBeforeModal = (typeof HTMLElement !== 'undefined' && document.activeElement instanceof HTMLElement) ? document.activeElement : null;
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    hideGlobalTooltip();
    focusModalCloseButton();

    if (!document.getElementById('cve-global-tooltip')) {
        initCveTooltips();
    }

    deferModalContentRender(modal, () => {
        const modalSections = buildRemediationDetailsModalSections(data);
        const updateEntries = data.updateEntries && data.updateEntries.length > 0
            ? data.updateEntries
            : buildRemediationUpdateEntriesFromDetails(data.details);

        const parts = [];
        parts.push('<h3>Summary</h3>',
            '<div class="modal-table-container"><table class="detail-table"><tr>',
            '<td><strong>Date:</strong> ', escapeHtml(data.date), '</td>',
            '<td><strong>Assets Remediated:</strong> ', String(data.devices.size), '</td>',
            '<td><strong>Vulnerabilities Remediated:</strong> ', String(data.vulnerabilities.size), '</td>',
            '</tr></table></div>');

        const updateLinksHtml = buildRemediationModalUpdateLinksHtml(updateEntries);
        if (updateLinksHtml) {
            parts.push(updateLinksHtml);
        }

        parts.push(...modalSections.parts);

        modalBody.innerHTML = parts.join('');
        const scrollContainer = modalBody.closest('.modal-content');
        attachVirtualTables(scrollContainer, modalSections.vtRowData);
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
    modalBody.innerHTML = '<p class="loading">Loading details...</p>';
    lastFocusedElementBeforeModal = (typeof HTMLElement !== 'undefined' && document.activeElement instanceof HTMLElement) ? document.activeElement : null;
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    hideGlobalTooltip();
    focusModalCloseButton();

    if (!document.getElementById('cve-global-tooltip')) {
        initCveTooltips();
    }

    deferModalContentRender(modal, () => {
        // Group vulnerabilities by device (using DeviceId as key)
        const deviceMap = {};
        item.vulnerabilities.forEach(v => {
            const deviceKey = getDeviceIdentityKey(v);
            if (!deviceMap[deviceKey]) {
                deviceMap[deviceKey] = {
                    name: v.DeviceName,
                    id: v.DeviceId,
                    cves: new Set()
                };
            }
            deviceMap[deviceKey].cves.add(v.CveId);
        });

        const updateLinksHtml = buildRemediationModalUpdateLinksHtml(
            item.updateEntries && item.updateEntries.length > 0
                ? item.updateEntries
                : buildRemediationUpdateEntriesFromDetails(item.vulnerabilities)
        );

        let html = '<h3>Affected Devices</h3>';
        if (updateLinksHtml) {
            html = updateLinksHtml + html;
        }
        html += '<div class="modal-table-container"><table class="detail-table"><thead><tr>';
        html += '<th>Device Name</th><th>Device ID</th><th>CVE Count</th><th>CVE IDs</th>';
        html += '</tr></thead><tbody>';

        // Sort devices by CVE count descending
        const sortedDevices = Object.values(deviceMap).sort((a, b) => b.cves.size - a.cves.size);

        sortedDevices.forEach(device => {
            const cveList = Array.from(device.cves).sort().join(', ');
            const deviceIdShort = device.id ? device.id.substring(0, 12) + '...' : '-';

            html += `<tr>
            <td>${escapeHtml(device.name)}</td>
            <td title="${escapeHtml(device.id || '')}">${escapeHtml(deviceIdShort)}</td>
            <td>${device.cves.size}</td>
            <td class="modal-cve-list-cell">${escapeHtml(cveList)}</td>
        </tr>`;
        });

        html += '</tbody></table></div>';

        modalBody.innerHTML = html;
    });
}

/**
 * Close the modal and clean up virtual tables
 */
function closeModal() {
    destroyManagedVirtualTables(activeVirtualTables);
    hideGlobalTooltip();
    const modal = document.getElementById('detailModal');
    modal.classList.remove('active');
    modal.setAttribute('aria-hidden', 'true');
    if (lastFocusedElementBeforeModal && typeof document.contains === 'function' && document.contains(lastFocusedElementBeforeModal)) {
        lastFocusedElementBeforeModal.focus();
    }
    lastFocusedElementBeforeModal = null;
}

// Close modal when clicking outside
window.addEventListener('click', function(event) {
    const modal = document.getElementById('detailModal');
    if (event.target === modal) {
        closeModal();
    }
});

// Close modal on Escape key
window.addEventListener('keydown', function(event) {
    const modal = document.getElementById('detailModal');
    if (!modal || !modal.classList.contains('active')) {
        return;
    }

    if (event.key === 'Tab') {
        const focusableElements = getModalFocusableElements();
        if (focusableElements.length === 0) {
            event.preventDefault();
            return;
        }

        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        if (event.shiftKey && document.activeElement === firstElement) {
            event.preventDefault();
            lastElement.focus();
            return;
        }

        if (!event.shiftKey && document.activeElement === lastElement) {
            event.preventDefault();
            firstElement.focus();
            return;
        }
    }

    if (event.key === 'Escape') {
        closeModal();
    }
});