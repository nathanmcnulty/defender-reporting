function formatExploitLevel(level) {
    switch (level) {
        case 'NoExploit': return 'No known exploits';
        case 'ExploitIsVerified': return 'Exploit verified by vendor';
        case 'ExploitIsPublic': return 'Exploit publicly available';
        case 'ExploitIsInKit': return 'Exploit in attacker toolkits';
        default: return level || '-';
    }
}

/**
 * Format a date string to YYYY-MM-DD, handling ISO ('T') and space-separated timestamps.
 * @param {string|null} dateStr - Raw date string
 * @returns {string} YYYY-MM-DD or '-'
 */
function formatDateYMD(dateStr) {
    if (!dateStr) return '-';
    // Strip time portion from ISO or space-separated timestamps
    const datePart = dateStr.split(/[T ]/)[0];
    // If already YYYY-MM-DD, return as-is
    if (/^\d{4}-\d{2}-\d{2}$/.test(datePart)) return datePart;
    // Handle M/D/YYYY format → YYYY-MM-DD
    const slash = datePart.split('/');
    if (slash.length === 3) {
        return slash[2] + '-' + slash[0].padStart(2, '0') + '-' + slash[1].padStart(2, '0');
    }
    return datePart;
}

function getLookupValue(lookup, index) {
    if (!lookup || index == null || index < 0 || index >= lookup.length) {
        return null;
    }
    return lookup[index];
}

/**
 * Get first-seen date as normalized YYYY-MM-DD (or empty string).
 * @param {Object} v - Vulnerability object
 * @returns {string}
 */
function getFirstSeenDate(v) {
    const normalized = formatDateYMD(v._firstSeenDate || v.FirstSeenTimestamp);
    return normalized === '-' ? '' : normalized;
}

function getEnvironmentIssueKey(v) {
    return [
        v.CveId || '',
        v.SoftwareVendor || '',
        v.SoftwareName || '',
        v.SoftwareVersion || ''
    ].join('|');
}

function getEnvironmentFirstSeenDate(v) {
    const normalized = formatDateYMD(v._environmentFirstSeenDate || v.EnvironmentFirstSeenTimestamp || v._firstSeenDate || v.FirstSeenTimestamp);
    return normalized === '-' ? '' : normalized;
}

/**
 * Get last-seen date as normalized YYYY-MM-DD (or empty string).
 * @param {Object} v - Vulnerability object
 * @returns {string}
 */
function getLastSeenDate(v) {
    const normalized = formatDateYMD(v._lastSeenDate || v.LastSeenTimestamp);
    return normalized === '-' ? '' : normalized;
}

/**
 * Return the most recent date from a list of date-like values, normalized to YYYY-MM-DD.
 * @param {Array<string>} dates
 * @returns {string|null}
 */
function getMostRecentYmdDate(dates) {
    if (!dates || dates.length === 0) return null;
    let maxDate = null;
    for (let i = 0; i < dates.length; i++) {
        const normalized = formatDateYMD(dates[i]);
        if (!normalized || normalized === '-') continue;
        if (!maxDate || normalized > maxDate) {
            maxDate = normalized;
        }
    }
    return maxDate;
}

function getEarliestYmdDate(dates) {
    if (!dates || dates.length === 0) return null;
    let minDate = null;
    for (let i = 0; i < dates.length; i++) {
        const normalized = formatDateYMD(dates[i]);
        if (!normalized || normalized === '-') continue;
        if (!minDate || normalized < minDate) {
            minDate = normalized;
        }
    }
    return minDate;
}

/**
 * Format affected software string for display.
 * Transforms CPE-like strings (e.g., 'microsoft:windows_server_2012_r2')
 * into human-readable format (e.g., 'Microsoft Windows Server 2012 R2').
 * @param {string} softwareStr - Raw software string
 * @returns {string} Formatted software name
 */
function formatAffectedSoftware(softwareStr) {
    if (!softwareStr) return softwareStr;
    
    // Split by colon to separate vendor and product
    const parts = softwareStr.split(':');
    
    // Capitalize first letter of each part and replace underscores with spaces
    const formatted = parts.map(part => {
        return part
            .split('_')
            .map(word => {
                // Special handling for version numbers and abbreviations
                if (/^[0-9]/.test(word)) return word.toUpperCase();
                if (word === 'r2' || word === 'esr' || word === 'esxi') return word.toUpperCase();
                // Capitalize first letter
                return word.charAt(0).toUpperCase() + word.slice(1);
            })
            .join(' ');
    }).join(' ');
    
    return formatted;
}

/**
 * Build remediation string from vulnerability data.
 * Prefers CveBatchTitle as the primary text (groups all CVEs in the same batch).
 * Appends KB number when available. Falls back to RecommendedSecurityUpdate + KB
 * if CveBatchTitle is absent.
 * @param {Object} v - Vulnerability object
 * @returns {string} Formatted remediation string
 */
function buildRemediationString(v) {
    materializeRow(v);
    const kbId = v.RecommendedSecurityUpdateId
        ? (v.RecommendedSecurityUpdateId.toString().startsWith('KB') ? v.RecommendedSecurityUpdateId : 'KB' + v.RecommendedSecurityUpdateId)
        : null;
    // Prefer CveBatchTitle — it groups all CVEs for the same vendor advisory
    if (v.CveBatchTitle) {
        return kbId ? `${v.CveBatchTitle} (${kbId})` : v.CveBatchTitle;
    }
    // Fallback: use RecommendedSecurityUpdate + KB
    if (v.RecommendedSecurityUpdate && kbId) {
        return `${v.RecommendedSecurityUpdate} (${kbId})`;
    } else if (v.RecommendedSecurityUpdate) {
        return v.RecommendedSecurityUpdate;
    } else if (kbId) {
        return kbId;
    }
    return 'Not Specified';
}