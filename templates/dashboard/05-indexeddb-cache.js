// =============================================================================
// INDEXEDDB CACHE
// =============================================================================

const VULNDB_NAME = 'VulnDashboardCache';
const VULNDB_VERSION = 1;
const VULNDB_STORE = 'denormalized';
const DIGEST_TIMEOUT_MS = 2000;
const IDB_OPERATION_TIMEOUT_MS = 2000;
const WORKER_OPERATION_TIMEOUT_MS = 10000;

function bytesToHex(bytes) {
    let output = '';
    for (let index = 0; index < bytes.length; index++) {
        output += bytes[index].toString(16).padStart(2, '0');
    }
    return output;
}

function computeFallbackDigestHex(bytes) {
    let hash = 0xcbf29ce484222325n;
    const prime = 0x100000001b3n;
    for (let index = 0; index < bytes.length; index++) {
        hash ^= BigInt(bytes[index]);
        hash = BigInt.asUintN(64, hash * prime);
    }
    return hash.toString(16).padStart(16, '0');
}

async function computeDigestHex(bytes) {
    const subtle = globalThis.crypto && globalThis.crypto.subtle ? globalThis.crypto.subtle : null;
    if (subtle) {
        try {
            const digest = await Promise.race([
                subtle.digest('SHA-256', bytes),
                new Promise((_, reject) => {
                    setTimeout(() => reject(new Error('SHA-256 digest timed out.')), DIGEST_TIMEOUT_MS);
                })
            ]);
            return bytesToHex(new Uint8Array(digest));
        } catch (error) {
            console.warn('Web Crypto SHA-256 digest failed, using deterministic fallback digest.', error);
        }
    }

    if (typeof require === 'function') {
        try {
            const nodeCrypto = require('crypto');
            return nodeCrypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');
        } catch (error) {
            console.warn('Node SHA-256 fallback unavailable, using deterministic fallback digest.', error);
        }
    }

    return computeFallbackDigestHex(bytes);
}

function getEmbeddedPayloadFingerprintInput() {
    const lookupsText = getScriptElementText('lookupsData');
    const vulnsText = getScriptElementText('vulnsData');

    if (lookupsText || vulnsText) {
        return `${lookupsText.length}:${lookupsText}\n${vulnsText.length}:${vulnsText}`;
    }

    const fallbackLookups = lookups ? JSON.stringify(lookups) : '';
    const fallbackVulns = rawVulns ? JSON.stringify(rawVulns) : '';
    return `${fallbackLookups.length}:${fallbackLookups}\n${fallbackVulns.length}:${fallbackVulns}`;
}

/**
 * Compute a fingerprint for the embedded dataset using the full payload.
 * @returns {Promise<string>}
 */
async function computeDataFingerprint() {
    const len = getRawVulnCount();
    if (len === 0) return 'empty';

    const input = getEmbeddedPayloadFingerprintInput();
    const bytes = new TextEncoder().encode(input);
    const hash = await computeDigestHex(bytes);
    return `fp_${len}_${hash}`;
}

/**
 * Compute a fingerprint from raw compressed bytes so we can check the
 * IndexedDB cache *before* decompressing / denormalizing.
 * @param {Uint8Array} bytes
 * @returns {Promise<string>}
 */
async function computeCompressedFingerprint(bytes) {
    const len = bytes.length;
    const hash = await computeDigestHex(bytes);
    return `cfp_${len}_${hash}`;
}

/**
 * Open (or create) the IndexedDB cache database.
 * @returns {Promise<IDBDatabase>}
 */
function openVulnDB() {
    if (typeof indexedDB === 'undefined' || !indexedDB || typeof indexedDB.open !== 'function') {
        return Promise.reject(new Error('IndexedDB is unavailable.'));
    }

    return new Promise((resolve, reject) => {
        let settled = false;
        let req = null;
        const timeoutId = setTimeout(() => {
            if (settled) {
                return;
            }

            settled = true;
            try { req?.result?.close(); } catch { /* ignore close failures */ }
            reject(new Error('IndexedDB open timed out.'));
        }, IDB_OPERATION_TIMEOUT_MS);

        const settleResolve = value => {
            if (settled) {
                return;
            }

            settled = true;
            clearTimeout(timeoutId);
            resolve(value);
        };

        const settleReject = error => {
            if (settled) {
                return;
            }

            settled = true;
            clearTimeout(timeoutId);
            reject(error || new Error('IndexedDB open failed.'));
        };

        req = indexedDB.open(VULNDB_NAME, VULNDB_VERSION);
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(VULNDB_STORE)) {
                db.createObjectStore(VULNDB_STORE, { keyPath: 'fingerprint' });
            }
        };
        req.onsuccess = () => settleResolve(req.result);
        req.onerror = () => settleReject(req.error);
        req.onblocked = () => settleReject(new Error('IndexedDB open was blocked.'));
    });
}

/**
 * Retrieve cached denormalized data from IndexedDB.
 * @param {string} fingerprint
 * @returns {Promise<Array|null>}
 */
async function getCachedData(fingerprint) {
    let db = null;
    try {
        db = await openVulnDB();
        return await new Promise((resolve) => {
            let settled = false;
            const settle = value => {
                if (settled) {
                    return;
                }

                settled = true;
                clearTimeout(timeoutId);
                try { db.close(); } catch { /* ignore close failures */ }
                resolve(value);
            };

            const timeoutId = setTimeout(() => {
                try { tx.abort(); } catch { /* ignore abort failures */ }
                settle(null);
            }, IDB_OPERATION_TIMEOUT_MS);
            const tx = db.transaction(VULNDB_STORE, 'readonly');
            const store = tx.objectStore(VULNDB_STORE);
            const req = store.get(fingerprint);
            req.onsuccess = () => {
                if (!req.result) return settle(null);
                // Return both data and cached lookups (if available)
                return settle({ data: req.result.data, lookups: req.result.lookups || null });
            };
            req.onerror = () => settle(null);
            tx.onabort = () => settle(null);
        });
    } catch (error) {
        logDebug('IndexedDB cache read skipped:', error && error.message ? error.message : error);
        try { db?.close(); } catch { /* ignore close failures */ }
        return null;
    }
}

/**
 * Store denormalized data in IndexedDB cache.
 * Clears old entries first to avoid unbounded growth.
 * @param {string} fingerprint
 * @param {Array} data
 */
async function setCachedData(fingerprint, data) {
    let db = null;
    try {
        db = await openVulnDB();
        await new Promise(resolve => {
            let settled = false;
            const settle = () => {
                if (settled) {
                    return;
                }

                settled = true;
                clearTimeout(timeoutId);
                try { db.close(); } catch { /* ignore close failures */ }
                resolve();
            };

            const tx = db.transaction(VULNDB_STORE, 'readwrite');
            const store = tx.objectStore(VULNDB_STORE);
            const timeoutId = setTimeout(() => {
                try { tx.abort(); } catch { /* ignore abort failures */ }
                settle();
            }, IDB_OPERATION_TIMEOUT_MS);

            store.clear(); // Keep only the latest dataset
            store.put({ fingerprint, data, lookups: lookups || null, ts: Date.now() });
            tx.oncomplete = () => settle();
            tx.onerror = () => settle();
            tx.onabort = () => settle();
        });
    } catch (error) {
        logDebug('IndexedDB cache write skipped:', error && error.message ? error.message : error);
        try { db?.close(); } catch { /* ignore close failures */ }
    }
}