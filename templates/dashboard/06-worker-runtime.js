// =============================================================================
// WEB WORKER (Blob-based, self-contained)
// =============================================================================

/**
 * Build a Worker source that decompresses (if given compressed bytes) and denormalizes.
 * When compressed bytes are provided via Transferable, pako.inflate runs off-main-thread.
 */
function buildWorkerSource() {
    return `
'use strict';
self.onmessage = async function(e) {
    var lookups = e.data.lookups;
    var rawVulns = e.data.rawVulns;
    var decompressOnly = !!e.data.decompressOnly;

    // If compressed data was transferred, decompress it first
    if (e.data.compressedBytes) {
        var data;
        if (typeof DecompressionStream !== 'undefined') {
            // Native gzip decompression — significantly faster than pako
            var ds = new DecompressionStream('gzip');
            var blob = new Blob([e.data.compressedBytes]);
            var decompressedStream = blob.stream().pipeThrough(ds);
            var text = await new Response(decompressedStream).text();
            data = JSON.parse(text);
        } else {
            var decompressed = pako.inflate(e.data.compressedBytes, { to: 'string' });
            data = JSON.parse(decompressed);
        }
        lookups = data.lookups;
        rawVulns = data.vulns;
    }

    // For large compressed datasets, return raw data without denormalizing
    // to avoid structured-clone memory limits on postMessage
    if (decompressOnly) {
        self.postMessage({ rows: null, lookups: lookups, rawVulns: rawVulns });
        return;
    }

    function isColumnarRawVulnData(value) {
        return !!(value && !Array.isArray(value) && Array.isArray(value.d));
    }
    function getRawVulnCount() {
        if (!rawVulns) return 0;
        if (Array.isArray(rawVulns)) return rawVulns.length;
        if (isColumnarRawVulnData(rawVulns)) return rawVulns.d.length;
        return 0;
    }
    function getRawVulnRecord(index) {
        if (Array.isArray(rawVulns)) return rawVulns[index];
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
    function normalizeDateYMD(value) {
        if (!value) return null;
        var datePart = String(value).split(/[T ]/)[0];
        if (/^\d{4}-\d{2}-\d{2}$/.test(datePart)) return datePart;
        var slash = datePart.split('/');
        if (slash.length === 3) {
            var m = slash[0].padStart(2, '0');
            var d = slash[1].padStart(2, '0');
            var y = slash[2].slice(0, 4);
            if (/^\d{4}$/.test(y)) return y + '-' + m + '-' + d;
        }
        return datePart;
    }
    function getLookupValue(lookup, index) {
        if (!lookup || index == null || index < 0 || index >= lookup.length) {
            return null;
        }
        return lookup[index];
    }
    function getLookupRecord(lookup, index) {
        var value = getLookupValue(lookup, index);
        return value == null ? null : value;
    }
    var rawCount = getRawVulnCount();
    var result = new Array(rawCount);
    var resultCount = 0;
    var skippedInvalidRows = 0;
    for (var i = 0; i < rawCount; i++) {
        var v = getRawVulnRecord(i);
        var device = getLookupRecord(lookups.devices, v[0]);
        var cve = getLookupRecord(lookups.cves, v[1]);
        var software = getLookupRecord(lookups.software, v[2]);
        if (!device || !cve || !software) {
            skippedInvalidRows++;
            continue;
        }

        var tagNames;
        if (device.t && device.t.length > 0) {
            tagNames = [];
            for (var ti = 0; ti < device.t.length; ti++) {
                var tagName = getLookupValue(lookups.tags, device.t[ti]);
                if (tagName != null) {
                    tagNames.push(tagName);
                }
            }
        } else {
            tagNames = [];
        }

        var vendorName = getLookupValue(lookups.vendors, software.v);
        var softwareName = software.n;
        var updateObj = v[7] >= 0 ? lookups.updates[v[7]] : null;
        var inventory = (v.length > 10 && v[10] >= 0 && lookups.inventory) ? getLookupValue(lookups.inventory, v[10]) : null;
        var updateName = updateObj ? (updateObj.n || updateObj) : null;
        var updateId = updateObj ? updateObj.id : null;
        var updateUrl = updateObj ? updateObj.url : null;

        // Resolve version from lookup
        var version = v[3] >= 0 ? getLookupValue(lookups.versions, v[3]) : null;
        // Resolve dates from lookup
        var firstSeenValue = v[4] >= 0 ? getLookupValue(lookups.dates, v[4]) : null;
        var lastSeenValue = v[5] >= 0 ? getLookupValue(lookups.dates, v[5]) : null;
        var firstSeen = firstSeenValue ? normalizeDateYMD(firstSeenValue) : '';
        var lastSeen = lastSeenValue ? normalizeDateYMD(lastSeenValue) : '';
        // Resolve evidence paths from lookup indices
        var diskPaths = [];
        if (v[8] && v[8].length > 0) {
            for (var di = 0; di < v[8].length; di++) {
                var diskPath = getLookupValue(lookups.diskPaths, v[8][di]);
                if (diskPath != null) {
                    diskPaths.push(diskPath);
                }
            }
        }
        var regPathsArr = [];
        if (v[9] && v[9].length > 0) {
            for (var ri = 0; ri < v[9].length; ri++) {
                var regPath = getLookupValue(lookups.regPaths, v[9][ri]);
                if (regPath != null) {
                    regPathsArr.push(regPath);
                }
            }
        }
        // Resolve batch title from lookup
        var batchTitle = cve.bt >= 0 ? getLookupValue(lookups.batchTitles, cve.bt) : null;
        // Resolve affected software from lookup indices
        var affSoftware = null;
        if (cve.as && cve.as.length > 0) {
            affSoftware = [];
            for (var ai = 0; ai < cve.as.length; ai++) {
                var affectedSoftwareValue = getLookupValue(lookups.affSoftware, cve.as[ai]);
                if (affectedSoftwareValue != null) {
                    affSoftware.push(affectedSoftwareValue);
                }
            }
            if (affSoftware.length === 0) affSoftware = null;
        }

        var groupName = getLookupValue(lookups.groups, device.g);
        result[resultCount++] = {
            DeviceId: device.id,
            DeviceName: device.n,
            RbacGroupName: (groupName && String(groupName).trim() !== '') ? groupName : '(none)',
            OSPlatform: getLookupValue(lookups.platforms, device.o),
            OSVersion: device.ov,
            MachineTags: tagNames,
            MachineInfo: device.m || null,
            CveId: cve.id,
            CvssScore: cve.sc,
            VulnerabilitySeverityLevel: getLookupValue(lookups.severities, cve.sv),
            ExploitabilityLevel: cve.ex >= 0 ? getLookupValue(lookups.exploitLevels, cve.ex) : null,
            CveBatchUrl: cve.u,
            CveBatchTitle: batchTitle,
            PublishedDate: normalizeDateYMD(cve.pd) || null,
            VulnerabilityDescription: cve.desc || null,
            EpssScore: cve.ep != null ? cve.ep : null,
            AffectedSoftware: affSoftware,
            IsExploitAvailable: cve.ea == null ? null : cve.ea === true,
            NvdLastModifiedDate: normalizeDateYMD(cve.nlm) || null,
            NvdBaseScore: cve.nbs != null ? cve.nbs : null,
            NvdBaseSeverity: cve.nsv || null,
            NvdVector: cve.nvec || null,
            NvdKevDate: normalizeDateYMD(cve.nkev) || null,
            NvdActionDue: normalizeDateYMD(cve.ndu) || null,
            NvdRequiredAction: cve.nact || null,
            NvdWeaknesses: cve.nw && cve.nw.length > 0 ? cve.nw.slice() : null,
            SoftwareVendor: vendorName,
            SoftwareName: softwareName,
            SoftwareVersion: version,
            RecommendationReference: software.r,
            ProductCodeCpe: inventory ? (inventory.cpe || null) : null,
            EndOfSupportStatus: inventory ? (inventory.eos || null) : null,
            EndOfSupportDate: inventory ? (normalizeDateYMD(inventory.eod) || null) : null,
            _firstSeenDate: firstSeen,
            _lastSeenDate: lastSeen,
            FirstSeenTimestamp: firstSeen,
            LastSeenTimestamp: lastSeen,
            SecurityUpdateAvailable: v[6] === 1,
            RecommendedSecurityUpdate: updateName,
            RecommendedSecurityUpdateId: updateId || null,
            RecommendedSecurityUpdateUrl: updateUrl || null,
            DiskPaths: diskPaths,
            RegistryPaths: regPathsArr,
            _remediationKey: updateName
                ? vendorName + ' ' + softwareName + ' - ' + updateName
                : vendorName + ' ' + softwareName,
            _index: i
        };
    }
    result.length = resultCount;
    self.postMessage({ rows: result, lookups: lookups, rawVulns: rawVulns, skippedInvalidRows: skippedInvalidRows });
};
`;
}

/**
 * Run denormalization in a Web Worker.
 * When compressedBytes is provided, decompression also runs in the Worker (off main thread).
 * Falls back to main-thread if Worker is unavailable.
 * @param {Uint8Array} [compressedBytes] - Optional compressed payload bytes
 * @returns {Promise<{rows: Array, lookups?: Object, rawVulns?: Object}>}
 */
async function denormalizeInWorker(compressedBytes) {
    // When decompressing in Worker, include pako source in the blob
    let workerParts = [];
    if (compressedBytes) {
        const pakoSource = await getPakoSource();
        if (pakoSource) {
            workerParts.push(pakoSource + '\n');
        } else {
            // pako source unavailable for Worker — fall back to main-thread decompression
            const decompressed = pako.inflate(compressedBytes, { to: 'string' });
            const data = JSON.parse(decompressed);
            lookups = data.lookups;
            rawVulns = data.vulns;
            compressedBytes = null;
        }
    }
    workerParts.push(buildWorkerSource());

    return new Promise((resolve, reject) => {
        try {
            const blob = new Blob(workerParts, { type: 'application/javascript' });
            const url = URL.createObjectURL(blob);
            const worker = new Worker(url);
            const timeoutId = setTimeout(() => {
                worker.terminate();
                URL.revokeObjectURL(url);
                reject(new Error('Worker denormalization timed out.'));
            }, WORKER_OPERATION_TIMEOUT_MS);

            worker.onmessage = function(e) {
                clearTimeout(timeoutId);
                worker.terminate();
                URL.revokeObjectURL(url);
                resolve(e.data);
            };
            worker.onerror = function(err) {
                clearTimeout(timeoutId);
                worker.terminate();
                URL.revokeObjectURL(url);
                reject(err);
            };

            if (compressedBytes) {
                // For compressed data, use decompress-only mode to avoid
                // structured-clone memory limits on postMessage with 1M+ records.
                // Main thread will denormalize after receiving lookups + rawVulns.
                worker.postMessage({ compressedBytes, decompressOnly: true });
            } else {
                worker.postMessage({ lookups, rawVulns });
            }
        } catch (err) {
            reject(err);
        }
    });
}

/**
 * Get pako library source code for injection into a Worker.
 * Checks external scripts first (split-assets mode), then inline (embedded mode).
 * Inline match requires 10KB+ to avoid false positives from small helper scripts.
 * @returns {Promise<string|null>}
 */
async function getPakoSource() {
    const scripts = document.querySelectorAll('script');
    // Try fetching external pako script (split-assets / hosted mode)
    for (const script of scripts) {
        if (script.src && script.src.indexOf('pako') !== -1) {
            try {
                const response = await fetch(script.src);
                if (response.ok) return await response.text();
            } catch (e) { /* ignore — will try inline or fall back */ }
        }
    }
    // Try inline script (embedded mode) — require 10KB+ to skip small helper scripts
    for (const script of scripts) {
        if (script.textContent && script.textContent.length > 10000 && script.textContent.indexOf('pako') !== -1 && script.textContent.indexOf('inflate') !== -1 && !script.id) {
            return script.textContent;
        }
    }
    return null;
}