function normalizeRemediationText(value) {
    if (value === null || value === undefined) return '';

    const text = String(value).trim();
    if (!text || text.toLowerCase() === 'unknown') {
        return '';
    }

    return text;
}

function normalizeKbId(value, allowNumeric = true) {
    const text = normalizeRemediationText(value);
    if (!text) return '';

    const explicitKbMatch = text.match(/\bKB\d+\b/i);
    if (explicitKbMatch) {
        return explicitKbMatch[0].toUpperCase();
    }

    return allowNumeric && /^\d+$/.test(text) ? 'KB' + text : '';
}

function isNumericRemediationReference(value) {
    return /^\d+$/.test(value) || /^KB\d+$/i.test(value);
}

function isCveRemediationReference(value) {
    return /^CVE-\d{4}-\d+$/i.test(value);
}

function isUrlLikeText(value) {
    return /^https?:\/\//i.test(normalizeRemediationText(value));
}

function escapeRegExp(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isOpaqueRemediationReference(value) {
    const text = normalizeRemediationText(value);
    return text.includes('_-_');
}

function getFriendlyRecommendationReference(value) {
    const text = normalizeRemediationText(value);
    if (!text || isOpaqueRemediationReference(text)) {
        return '';
    }

    return text;
}

function extractScopedRemediationReference(updateName, scopeLabels) {
    const text = normalizeRemediationText(updateName);
    if (!text || !scopeLabels || scopeLabels.length === 0) {
        return null;
    }

    const labels = Array.from(new Set(scopeLabels
        .map(label => normalizeRemediationText(label))
        .filter(Boolean)));

    for (let i = 0; i < labels.length; i++) {
        const scopeLabel = labels[i];
        const pattern = new RegExp(`^${escapeRegExp(scopeLabel)}\\s*[-:]\\s*(.+)$`, 'i');
        const match = pattern.exec(text);
        if (!match) continue;

        const reference = normalizeRemediationText(match[1]);
        if (!reference) continue;

        if (isNumericRemediationReference(reference)) {
            return {
                scopeLabel: scopeLabel,
                reference: reference,
                title: `${scopeLabel} patch ${reference}`
            };
        }

        if (isCveRemediationReference(reference)) {
            return {
                scopeLabel: scopeLabel,
                reference: reference,
                title: `${scopeLabel} advisory ${reference}`
            };
        }
    }

    return null;
}

function getRemediationDisplayRank(descriptor) {
    if (!descriptor) return 0;
    if (descriptor.advisoryTitle) return 4;
    if (descriptor.scopedUpdateReference) return 3;
    if (descriptor.updateName && !isNumericRemediationReference(descriptor.updateName) && !isCveRemediationReference(descriptor.updateName)) {
        return 3;
    }
    if (descriptor.friendlyRecommendationReference) return 2;
    if (descriptor.kbId || descriptor.updateName || descriptor.recommendationReference) return 1;
    return 0;
}

function shouldPreferRemediationDescriptor(candidate, current) {
    if (!current) return true;

    const candidateRank = candidate.displayRank || 0;
    const currentRank = current.displayRank || 0;
    if (candidateRank !== currentRank) {
        return candidateRank > currentRank;
    }

    if (!!candidate.updateUrl !== !!current.updateUrl) {
        return !!candidate.updateUrl;
    }

    return (candidate.title || '').length > (current.title || '').length;
}

function getRemediationDescriptorObservationKey(descriptor) {
    return normalizeRemediationText(descriptor?.title)
        || normalizeRemediationText(descriptor?.familyTitle)
        || 'Not Specified';
}

function observeRemediationDescriptor(target, descriptor) {
    if (!target || !descriptor) {
        return;
    }

    if (!(target.descriptorObservationMap instanceof Map)) {
        target.descriptorObservationMap = new Map();
    }

    const observationKey = getRemediationDescriptorObservationKey(descriptor);
    const existing = target.descriptorObservationMap.get(observationKey);

    if (!existing) {
        target.descriptorObservationMap.set(observationKey, {
            descriptor: descriptor,
            count: 1
        });
        return;
    }

    existing.count++;
    if (shouldPreferRemediationDescriptor(descriptor, existing.descriptor)) {
        existing.descriptor = descriptor;
    }
}

function getDominantRemediationDescriptor(target) {
    if (!target) {
        return null;
    }

    let dominantDescriptor = target.remediationDescriptor || null;
    let dominantCount = -1;
    const observations = target.descriptorObservationMap instanceof Map
        ? Array.from(target.descriptorObservationMap.values())
        : [];

    observations.forEach(observation => {
        if (!observation || !observation.descriptor) {
            return;
        }

        if (observation.count > dominantCount) {
            dominantDescriptor = observation.descriptor;
            dominantCount = observation.count;
            return;
        }

        if (observation.count === dominantCount && shouldPreferRemediationDescriptor(observation.descriptor, dominantDescriptor)) {
            dominantDescriptor = observation.descriptor;
        }
    });

    return dominantDescriptor;
}

function mergeDescriptorObservationMaps(targetMap, sourceMap) {
    if (!(targetMap instanceof Map) || !(sourceMap instanceof Map)) {
        return;
    }

    sourceMap.forEach((observation, key) => {
        if (!observation || !observation.descriptor) {
            return;
        }

        const existing = targetMap.get(key);
        if (!existing) {
            targetMap.set(key, {
                descriptor: observation.descriptor,
                count: observation.count || 0
            });
            return;
        }

        existing.count += observation.count || 0;
        if (shouldPreferRemediationDescriptor(observation.descriptor, existing.descriptor)) {
            existing.descriptor = observation.descriptor;
        }
    });
}

function mergeRemediationUpdateEntryMaps(targetMap, sourceMap) {
    if (!(targetMap instanceof Map) || !(sourceMap instanceof Map)) {
        return;
    }

    sourceMap.forEach((entry, key) => {
        if (!entry) {
            return;
        }

        const existing = targetMap.get(key);
        if (!existing) {
            targetMap.set(key, {
                referenceText: entry.referenceText,
                referenceUrl: entry.referenceUrl || ''
            });
            return;
        }

        if (!existing.referenceUrl && entry.referenceUrl) {
            existing.referenceUrl = entry.referenceUrl;
        }
    });
}

function getRemediationAdvisoryFamilyMergeKey(target, fallbackKey = '') {
    if (!target) {
        return fallbackKey;
    }

    const descriptor = getDominantRemediationDescriptor(target) || target.remediationDescriptor;
    const recommendationReference = normalizeRemediationText(descriptor?.recommendationReference);
    const advisoryTitle = normalizeRemediationText(descriptor?.advisoryTitle);
    const updateName = normalizeRemediationText(descriptor?.updateName);
    if (!recommendationReference || !advisoryTitle || !updateName) {
        return fallbackKey;
    }

    if (!isCveRemediationReference(updateName) && !isNumericRemediationReference(updateName)) {
        return fallbackKey;
    }

    const datePart = normalizeRemediationText(target?.date);
    const displayScope = normalizeRemediationText(target?.software)
        || normalizeRemediationText(target?.name);
    const mergeKey = displayScope
        ? `${recommendationReference}|${advisoryTitle}|${displayScope}`
        : `${recommendationReference}|${advisoryTitle}`;
    return datePart ? `${datePart}|${mergeKey}` : mergeKey;
}

function mergeRemediationObjectBuckets(bucketObject, mergeBucket) {
    const mergedBuckets = {};

    Object.entries(bucketObject || {}).forEach(([key, bucket]) => {
        const mergeKey = getRemediationAdvisoryFamilyMergeKey(bucket, key);
        if (!mergedBuckets[mergeKey]) {
            mergedBuckets[mergeKey] = bucket;
            return;
        }

        mergeBucket(mergedBuckets[mergeKey], bucket);
    });

    return mergedBuckets;
}

function mergeRemediationMapBuckets(bucketMap, mergeBucket) {
    const mergedBuckets = new Map();

    Array.from((bucketMap || new Map()).entries()).forEach(([key, bucket]) => {
        const mergeKey = getRemediationAdvisoryFamilyMergeKey(bucket, key);
        if (!mergedBuckets.has(mergeKey)) {
            mergedBuckets.set(mergeKey, bucket);
            return;
        }

        mergeBucket(mergedBuckets.get(mergeKey), bucket);
    });

    return mergedBuckets;
}

function mergeRemediationDetailMaps(targetMap, sourceMap) {
    if (!(targetMap instanceof Map) || !(sourceMap instanceof Map)) {
        return;
    }

    sourceMap.forEach((detail, key) => {
        if (!detail) {
            return;
        }

        const existing = targetMap.get(key);
        if (!existing) {
            targetMap.set(key, detail);
            return;
        }

        if (detail.firstSeenTimestamp || existing.firstSeenTimestamp) {
            existing.firstSeenTimestamp = getEarliestYmdDate([existing.firstSeenTimestamp, detail.firstSeenTimestamp]);
        }

        if (detail.lastSeenTimestamp || existing.lastSeenTimestamp) {
            existing.lastSeenTimestamp = getMostRecentYmdDate([existing.lastSeenTimestamp, detail.lastSeenTimestamp]);
        }

        if (detail.versions instanceof Set) {
            if (!(existing.versions instanceof Set)) {
                existing.versions = new Set();
            }

            detail.versions.forEach(version => existing.versions.add(version));
        }

        [
            'cveBatchUrl',
            'publishedDate',
            'description',
            'affectedSoftware',
            'severityLevel',
            'cvssScore',
            'epssScore',
            'exploitabilityLevel',
            'softwareVendor',
            'softwareName'
        ].forEach(property => {
            if ((existing[property] === undefined || existing[property] === null || existing[property] === '')
                && detail[property] !== undefined) {
                existing[property] = detail[property];
            }
        });
    });
}

function mergeActiveRemediationBuckets(target, source) {
    mergeDescriptorObservationMaps(target.descriptorObservationMap, source.descriptorObservationMap);
    mergeRemediationUpdateEntryMaps(target.updateEntryMap, source.updateEntryMap);
    source.devices.forEach(device => target.devices.add(device));
    source.vulnerabilities.forEach(vulnerability => target.vulnerabilities.add(vulnerability));
    source.exploits.forEach(exploit => target.exploits.add(exploit));
    source.kits.forEach(kit => target.kits.add(kit));
    target.details.push(...source.details);
    if (shouldPreferRemediationDescriptor(source.remediationDescriptor, target.remediationDescriptor)) {
        target.remediationDescriptor = source.remediationDescriptor;
    }
}

function mergeRemediationDetailsBuckets(target, source) {
    mergeDescriptorObservationMaps(target.descriptorObservationMap, source.descriptorObservationMap);
    mergeRemediationUpdateEntryMaps(target.updateEntryMap, source.updateEntryMap);
    source.devices.forEach(device => target.devices.add(device));
    source.vulnerabilities.forEach(vulnerability => target.vulnerabilities.add(vulnerability));
    target.details.push(...source.details);
    if (shouldPreferRemediationDescriptor(source.remediationDescriptor, target.remediationDescriptor)) {
        target.remediationDescriptor = source.remediationDescriptor;
    }
}

function mergeImpactRemediationBuckets(target, source) {
    mergeDescriptorObservationMaps(target.descriptorObservationMap, source.descriptorObservationMap);
    mergeRemediationUpdateEntryMaps(target.updateEntryMap, source.updateEntryMap);
    source.devices.forEach(device => target.devices.add(device));
    if (source.cveIds instanceof Set) {
        source.cveIds.forEach(cveId => target.cveIds.add(cveId));
    }
    if (Array.isArray(source.vulnerabilities) && Array.isArray(target.vulnerabilities)) {
        target.vulnerabilities.push(...source.vulnerabilities);
    }
    if (shouldPreferRemediationDescriptor(source.remediationDescriptor, target.remediationDescriptor)) {
        target.remediationDescriptor = source.remediationDescriptor;
    }
}

function mergeDevicesByRemediationBuckets(target, source) {
    mergeDescriptorObservationMaps(target.descriptorObservationMap, source.descriptorObservationMap);
    mergeRemediationUpdateEntryMaps(target.updateEntryMap, source.updateEntryMap);
    source.osPlatforms.forEach(platform => target.osPlatforms.add(platform));
    source.devices.forEach((device, key) => {
        if (!target.devices.has(key)) {
            target.devices.set(key, device);
        }
    });
    source.cves.forEach(cveId => target.cves.add(cveId));
    mergeRemediationDetailMaps(target.cveDetails, source.cveDetails);
    if (shouldPreferRemediationDescriptor(source.remediationDescriptor, target.remediationDescriptor)) {
        target.remediationDescriptor = source.remediationDescriptor;
    }
}

function mergeDeviceRemediationBuckets(target, source) {
    mergeDescriptorObservationMaps(target.descriptorObservationMap, source.descriptorObservationMap);
    mergeRemediationUpdateEntryMaps(target.updateEntryMap, source.updateEntryMap);
    source.cves.forEach(cveId => target.cves.add(cveId));
    mergeRemediationDetailMaps(target.cveDetails, source.cveDetails);
    target.publishedDates.push(...source.publishedDates);
    if (shouldPreferRemediationDescriptor(source.remediationDescriptor, target.remediationDescriptor)) {
        target.remediationDescriptor = source.remediationDescriptor;
    }
}

function getMatchingRemediationUrlFallback(updateName, updateId, advisoryUrl) {
    const normalizedUrl = normalizeRemediationText(advisoryUrl);
    if (!normalizedUrl) {
        return '';
    }

    const lowerUrl = normalizedUrl.toLowerCase();
    const tokens = Array.from(new Set([
        normalizeKbId(updateId),
        normalizeRemediationText(updateId),
        normalizeRemediationText(updateName)
    ].filter(Boolean).map(token => token.toLowerCase())));

    if (tokens.length === 0) {
        return '';
    }

    return tokens.some(token => lowerUrl.includes(token) || lowerUrl.includes(encodeURIComponent(token)))
        ? normalizedUrl
        : '';
}

function getCompactRemediationTitle(descriptor) {
    if (!descriptor) return 'Not Specified';

    if (descriptor.advisoryTitle) {
        return descriptor.familyTitle;
    }

    if (descriptor.scopedUpdateReference) {
        return descriptor.familyTitle;
    }

    if (descriptor.kbId) {
        return descriptor.familyTitle;
    }

    if (descriptor.updateName && !isOpaqueRemediationReference(descriptor.updateName)) {
        return descriptor.familyTitle;
    }

    if (descriptor.friendlyRecommendationReference) {
        return descriptor.familyTitle;
    }

    return descriptor.title;
}

function getRemediationFamilyKey(recommendationReference, advisoryTitle, updateName, kbId, friendlyRecommendationReference, scopeLabel) {
    const familyIdentity = updateName
        || advisoryTitle
        || kbId
        || friendlyRecommendationReference
        || recommendationReference
        || scopeLabel
        || 'Not Specified';

    if (recommendationReference && familyIdentity && familyIdentity !== recommendationReference) {
        return `${recommendationReference}|${familyIdentity}`;
    }

    return familyIdentity;
}

function buildRemediationDescriptor(v) {
    materializeRow(v);

    const descriptorCacheKey = buildMemoCacheKey([
        v.SoftwareVendor,
        v.SoftwareName,
        v.CveBatchTitle,
        v.RecommendedSecurityUpdate,
        v.RecommendedSecurityUpdateId,
        v.RecommendedSecurityUpdateUrl,
        v.OSPlatform,
        v.RecommendationReference,
        v.CveBatchUrl
    ]);
    const cachedDescriptor = remediationDescriptorCache.get(descriptorCacheKey);
    if (cachedDescriptor) {
        return cachedDescriptor;
    }

    const rawVendor = normalizeRemediationText(v.SoftwareVendor);
    const rawSoftware = normalizeRemediationText(v.SoftwareName);
    const advisoryTitle = normalizeRemediationText(v.CveBatchTitle);
    const updateName = normalizeRemediationText(v.RecommendedSecurityUpdate);
    const updateId = normalizeRemediationText(v.RecommendedSecurityUpdateId);
    const kbId = normalizeKbId(updateId) || normalizeKbId(updateName, false) || normalizeKbId(v.RecommendedSecurityUpdateUrl, false);
    const updateUrl = normalizeRemediationText(v.RecommendedSecurityUpdateUrl)
        || getMatchingRemediationUrlFallback(updateName, updateId, v.CveBatchUrl);
    const osPlatform = normalizeRemediationText(v.OSPlatform) || 'Unknown';
    const recommendationReference = normalizeRemediationText(v.RecommendationReference);
    const vendorPart = formatSoftwarePart(rawVendor);
    const productPart = formatSoftwarePart(rawSoftware);
    const productLabel = formatSoftwareName(v.SoftwareVendor, v.SoftwareName);
    const scopeLabel = productPart || productLabel || vendorPart || 'Unknown';
    const friendlyRecommendationReference = getFriendlyRecommendationReference(recommendationReference);
    const combinedProductLabel = [vendorPart, productPart].filter(Boolean).join(' ');
    const scopedUpdateReference = extractScopedRemediationReference(updateName, [combinedProductLabel, productLabel, scopeLabel, vendorPart]);
    const scopeKey = recommendationReference
        || [rawVendor, rawSoftware].filter(Boolean).join('|')
        || scopeLabel;
    const familyKey = getRemediationFamilyKey(
        recommendationReference,
        advisoryTitle,
        updateName,
        kbId,
        friendlyRecommendationReference,
        scopeLabel
    );
    const familyTitle = advisoryTitle
        || friendlyRecommendationReference
        || (scopedUpdateReference ? scopedUpdateReference.reference : '')
        || updateName
        || kbId
        || recommendationReference
        || 'Not Specified';

    let title = familyTitle;
    if (scopeLabel !== 'Unknown') {
        const lowerScopeLabel = scopeLabel.toLowerCase();
        const lowerProductLabel = productLabel.toLowerCase();
        if (advisoryTitle) {
            title = advisoryTitle.toLowerCase().includes(lowerScopeLabel)
                || (productLabel && advisoryTitle.toLowerCase().includes(lowerProductLabel))
                ? advisoryTitle
                : `${scopeLabel}: ${advisoryTitle}`;
        } else if (scopedUpdateReference) {
            title = scopedUpdateReference.title;
        } else if (updateName) {
            if (isNumericRemediationReference(updateName)) {
                title = `${scopeLabel} patch ${updateName}`;
            } else if (isCveRemediationReference(updateName)) {
                title = `${scopeLabel} advisory ${updateName}`;
            } else if (updateName.toLowerCase().includes(lowerScopeLabel)
                || (productLabel && updateName.toLowerCase().includes(lowerProductLabel))) {
                title = updateName;
            } else {
                title = `${scopeLabel}: ${updateName}`;
            }
        } else if (kbId) {
            title = `${scopeLabel} patch ${kbId}`;
        } else if (friendlyRecommendationReference && friendlyRecommendationReference !== scopeLabel) {
            title = friendlyRecommendationReference.toLowerCase().includes(lowerScopeLabel)
                || (productLabel && friendlyRecommendationReference.toLowerCase().includes(lowerProductLabel))
                ? friendlyRecommendationReference
                : `${scopeLabel}: ${friendlyRecommendationReference}`;
        } else {
            title = scopeLabel;
        }
    }

    let patchReference = '';
    if (kbId && !remediationTitleIncludesReference(title, kbId) && !remediationTitleIncludesReference(familyTitle, kbId)) {
        patchReference = kbId;
    } else if (scopedUpdateReference) {
        patchReference = scopedUpdateReference.reference !== familyTitle ? scopedUpdateReference.reference : '';
    } else if (updateName && updateName !== familyTitle && !isUrlLikeText(updateName)) {
        patchReference = updateName;
    }

    const descriptor = {
        key: `${scopeKey}|${familyKey}`,
        title: title,
        familyKey: familyKey,
        familyTitle: familyTitle,
        productLabel: productLabel,
        vendorLabel: vendorPart,
        softwareLabel: productPart,
        rawVendor: rawVendor,
        rawSoftware: rawSoftware,
        scopeLabel: scopeLabel,
        patchReference: patchReference,
        updateName: updateName || 'Unknown',
        updateId: updateId,
        updateUrl: updateUrl,
        osPlatform: osPlatform,
        advisoryTitle: advisoryTitle,
        kbId: kbId,
        recommendationReference: recommendationReference,
        friendlyRecommendationReference: friendlyRecommendationReference,
        scopedUpdateReference: scopedUpdateReference
    };

    descriptor.displayRank = getRemediationDisplayRank(descriptor);
    remediationDescriptorCache.set(descriptorCacheKey, descriptor);

    return descriptor;
}

function buildRemediationTitleHtml(text, url) {
    if (!text) {
        return '-';
    }

    const safeUrl = getSafeExternalUrl(url);
    if (safeUrl) {
        return `<a href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(text)}</a>`;
    }

    return escapeHtml(text);
}

function buildRemediationReferenceHtml(referenceText, referenceUrl) {
    if (!referenceText) {
        return '-';
    }

    return buildRemediationUpdateBadgeHtml(referenceText, referenceUrl);
}

function getRemediationUpdateReferenceText(remediation) {
    if (!remediation) {
        return '';
    }

    if (remediation.kbId) {
        return remediation.kbId;
    }

    if (remediation.patchReference) {
        return remediation.patchReference;
    }

    if (remediation.updateName && remediation.updateName !== 'Unknown' && !isUrlLikeText(remediation.updateName)) {
        return remediation.updateName;
    }

    if (remediation.updateUrl || isUrlLikeText(remediation.updateName)) {
        return 'Update Details';
    }

    return '';
}

function addRemediationUpdateEntry(updateEntryMap, remediation) {
    if (!(updateEntryMap instanceof Map) || !remediation) {
        return;
    }

    let referenceText = normalizeRemediationText(getRemediationUpdateReferenceText(remediation));
    let referenceUrl = normalizeRemediationText(remediation.updateUrl);

    if (!referenceUrl && isUrlLikeText(remediation.updateName)) {
        referenceUrl = normalizeRemediationText(remediation.updateName);
    }

    if (!referenceUrl && /^KB\d+$/i.test(referenceText)) {
        referenceUrl = `https://catalog.update.microsoft.com/v7/site/Search.aspx?q=${encodeURIComponent(referenceText.toUpperCase())}`;
    }

    if (!referenceText && referenceUrl) {
        referenceText = 'Update Details';
    }

    if (!referenceText && !referenceUrl) {
        return;
    }

    const entryKey = referenceText || referenceUrl;
    const existing = updateEntryMap.get(entryKey);

    if (!existing) {
        updateEntryMap.set(entryKey, {
            referenceText: referenceText || 'Update Details',
            referenceUrl: referenceUrl || '',
            observationCount: 1
        });
        return;
    }

    existing.observationCount = (existing.observationCount || 0) + 1;

    if (!existing.referenceUrl && referenceUrl) {
        existing.referenceUrl = referenceUrl;
    }
}

function finalizeRemediationUpdateEntries(updateEntryMap) {
    const entries = Array.from((updateEntryMap || new Map()).values())
        .filter(entry => entry && entry.referenceText)
        .map(entry => ({
            referenceText: entry.referenceText,
            referenceUrl: entry.referenceUrl || '',
            observationCount: entry.observationCount > 0 ? entry.observationCount : 1
        }));

    let filteredEntries = entries;
    const kbEntries = entries.filter(entry => /^KB\d+$/i.test(entry.referenceText || ''));
    if (entries.length > 1 && kbEntries.length === entries.length) {
        const sortedByCount = [...entries].sort((a, b) => b.observationCount - a.observationCount);
        const dominantEntry = sortedByCount[0];
        const totalObservations = sortedByCount.reduce((sum, entry) => sum + entry.observationCount, 0);

        if (dominantEntry && totalObservations > 0 && (dominantEntry.observationCount / totalObservations) >= 0.9) {
            filteredEntries = sortedByCount.filter(entry => entry.observationCount === dominantEntry.observationCount);
        }
    }

    return filteredEntries
        .sort((a, b) => {
            const referenceCompare = a.referenceText.localeCompare(
                b.referenceText,
                undefined,
                { numeric: true, sensitivity: 'base' }
            );

            if (referenceCompare !== 0) {
                return referenceCompare;
            }

            return (a.referenceUrl || '').localeCompare(
                b.referenceUrl || '',
                undefined,
                { numeric: true, sensitivity: 'base' }
            );
        })
        .map(entry => ({
            referenceText: entry.referenceText,
            referenceUrl: entry.referenceUrl || ''
        }));
}

function summarizeRemediationUpdateEntries(updateEntries) {
    return summarizeRemediationReferences(
        new Set((updateEntries || []).map(entry => entry.referenceText).filter(Boolean))
    );
}

function getSingleRemediationUpdateUrlFromEntries(updateEntries) {
    const entries = (updateEntries || []).filter(entry => entry && entry.referenceText);

    if (entries.length !== 1) {
        return '';
    }

    return entries[0].referenceUrl || '';
}

function remediationTitleIncludesReference(title, referenceText) {
    if (!title || !referenceText) {
        return false;
    }

    const normalizedTitle = normalizeRemediationText(title).toLowerCase();
    const normalizedReference = normalizeRemediationText(referenceText).toLowerCase();

    return normalizedTitle === normalizedReference
        || normalizedTitle.endsWith(normalizedReference)
        || normalizedTitle.endsWith(`: ${normalizedReference}`)
        || normalizedTitle.endsWith(` patch ${normalizedReference}`)
        || normalizedTitle.endsWith(` advisory ${normalizedReference}`)
        || normalizedTitle.includes(`(${normalizedReference})`);
}

function getRemediationTitleWithReferenceSuffix(title, updateEntries) {
    const entries = (updateEntries || []).filter(entry => entry && /^KB\d+$/i.test(entry.referenceText || ''));

    if (entries.length !== 1) {
        return title;
    }

    const kbId = entries[0].referenceText;
    if (remediationTitleIncludesReference(title, kbId)) {
        return title;
    }

    return `${title} (${kbId})`;
}

function buildRemediationUpdateBadgeHtml(referenceText, referenceUrl, prefix = '') {
    const badgeText = prefix ? `${prefix}${referenceText}` : referenceText;
    const safeUrl = getSafeExternalUrl(referenceUrl);

    if (safeUrl) {
        return `<a href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer" class="stat-badge remediation-update-badge">
                 <span>${escapeHtml(badgeText)}</span>
                 <svg class="link-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                     <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                     <polyline points="15 3 21 3 21 9"></polyline>
                     <line x1="10" y1="14" x2="21" y2="3"></line>
                 </svg>
               </a>`;
    }

    return `<span class="stat-badge">${escapeHtml(badgeText)}</span>`;
}

function buildRemediationUpdateBadgesHtml(updateEntries, prefix = '', containerClass = 'remediation-update-entry-list') {
    const entries = (updateEntries || []).filter(entry => entry && entry.referenceText);

    if (entries.length === 0) {
        return '';
    }

    return `<div class="${escapeHtml(containerClass)}">${entries.map(entry => buildRemediationUpdateBadgeHtml(entry.referenceText, entry.referenceUrl, prefix)).join('')}</div>`;
}

function buildRemediationUpdateCellHtml(updateEntries, fallbackText = '', fallbackUrl = '') {
    const entries = (updateEntries || []).filter(entry => entry && entry.referenceText);

    if (entries.length === 0) {
        return fallbackText
            ? buildRemediationReferenceHtml(fallbackText, fallbackUrl)
            : '-';
    }

    if (entries.length === 1) {
        return buildRemediationReferenceHtml(entries[0].referenceText, entries[0].referenceUrl);
    }

    return buildRemediationUpdateBadgesHtml(entries);
}

function buildRemediationCellHtml(title, titleUrl, updateEntries) {
    const entries = (updateEntries || []).filter(entry => entry && entry.referenceText);
    const titleHtml = buildRemediationTitleHtml(title, '');

    if (entries.length === 0) {
        return titleHtml;
    }

    return `<div class="remediation-title-with-updates"><div>${titleHtml}</div>${buildRemediationUpdateBadgesHtml(entries, 'Patch: ')}</div>`;
}

function buildRemediationTitleCellHtml(title, titleUrl = '') {
    return buildRemediationTitleHtml(title, titleUrl);
}

function stripLeadingRemediationPrefix(title, prefix) {
    const text = normalizeRemediationText(title);
    const normalizedPrefix = normalizeRemediationText(prefix);

    if (!text || !normalizedPrefix) {
        return text;
    }

    const scopedPattern = new RegExp(`^${escapeRegExp(normalizedPrefix)}\\s*[:\\-]\\s*`, 'i');
    if (scopedPattern.test(text)) {
        return normalizeRemediationText(text.replace(scopedPattern, ''));
    }

    const wordPattern = new RegExp(`^${escapeRegExp(normalizedPrefix)}\\s+`, 'i');
    if (wordPattern.test(text)) {
        return normalizeRemediationText(text.replace(wordPattern, ''));
    }

    return text;
}

function getRemediationTitlePrefixCandidates(descriptor) {
    if (!descriptor) {
        return [];
    }

    return Array.from(new Set([
        descriptor.scopeLabel,
        descriptor.productLabel,
        descriptor.softwareLabel,
        descriptor.vendorLabel,
        descriptor.rawSoftware,
        descriptor.rawVendor
    ].map(value => normalizeRemediationText(value)).filter(Boolean)));
}

function stripLeadingRemediationPrefixes(title, prefixes) {
    let cleanedTitle = normalizeRemediationText(title);
    if (!cleanedTitle) {
        return cleanedTitle;
    }

    (prefixes || []).forEach(prefix => {
        cleanedTitle = stripLeadingRemediationPrefix(cleanedTitle, prefix) || cleanedTitle;
    });

    return cleanedTitle;
}

function getScopedRemediationDisplayTitle(descriptor) {
    if (!descriptor) {
        return 'Not Specified';
    }

    const title = normalizeRemediationText(descriptor.title) || 'Not Specified';
    const prefixCandidates = getRemediationTitlePrefixCandidates(descriptor);
    const vendorLabel = normalizeRemediationText(descriptor.vendorLabel);
    const softwareLabel = normalizeRemediationText(descriptor.softwareLabel);
    const scopeLabel = normalizeRemediationText(descriptor.scopeLabel);
    const advisoryTitle = normalizeRemediationText(descriptor.advisoryTitle);
    if (!vendorLabel || !title.includes(':')) {
        if (advisoryTitle
            && title === advisoryTitle
            && (!softwareLabel || softwareLabel === vendorLabel || scopeLabel === vendorLabel)) {
            return title;
        }

        return stripLeadingRemediationPrefixes(title, prefixCandidates) || title;
    }

    const separatorIndex = title.indexOf(':');
    const scopePrefix = title.slice(0, separatorIndex).trim();
    const scopedTitle = title.slice(separatorIndex + 1).trim();
    const withoutVendor = stripLeadingRemediationPrefixes(scopedTitle, prefixCandidates);

    return withoutVendor ? `${scopePrefix}: ${withoutVendor}` : title;
}

function getActiveRemediationTableTitle(descriptor) {
    if (!descriptor) {
        return 'Not Specified';
    }

    const baseTitle = normalizeRemediationText(getCompactRemediationTitle(descriptor))
        || normalizeRemediationText(descriptor.familyTitle)
        || normalizeRemediationText(descriptor.title)
        || 'Not Specified';
    const cleanedTitle = stripLeadingRemediationPrefixes(baseTitle, getRemediationTitlePrefixCandidates(descriptor));

    return cleanedTitle || baseTitle;
}

function buildSeparatedRemediationUpdateDisplay(title, descriptor, updateEntries) {
    const normalizedTitle = normalizeRemediationText(title);
    const entries = (updateEntries || []).filter(entry => entry && entry.referenceText);

    if (entries.length === 0) {
        const fallbackText = normalizeRemediationText(getRemediationUpdateReferenceText(descriptor));
        const fallbackUrl = normalizeRemediationText(descriptor?.updateUrl);

        if (!fallbackText) {
            return {
                value: '',
                html: '-'
            };
        }

        if (!fallbackUrl && remediationTitleIncludesReference(normalizedTitle, fallbackText)) {
            return {
                value: '',
                html: '-'
            };
        }

        return {
            value: fallbackText,
            html: buildRemediationReferenceHtml(fallbackText, fallbackUrl)
        };
    }

    if (entries.length === 1) {
        const [entry] = entries;

        if (!entry.referenceUrl && remediationTitleIncludesReference(normalizedTitle, entry.referenceText)) {
            return {
                value: '',
                html: '-'
            };
        }

        return {
            value: entry.referenceText,
            html: buildRemediationReferenceHtml(entry.referenceText, entry.referenceUrl)
        };
    }

    return {
        value: summarizeRemediationUpdateEntries(entries),
        html: buildRemediationUpdateBadgesHtml(entries)
    };
}

function buildRemediationModalUpdateLinksHtml(updateEntries) {
    const badgesHtml = buildRemediationUpdateBadgesHtml(updateEntries, 'Patch: ');

    if (!badgesHtml) {
        return '';
    }

    return `<div class="modal-update-link-row"><strong>Update Details:</strong>${badgesHtml}</div>`;
}

function buildRemediationUpdateEntriesFromDetails(details) {
    const updateEntryMap = new Map();

    (details || []).forEach(detail => {
        addRemediationUpdateEntry(updateEntryMap, buildRemediationDescriptor(detail));
    });

    return finalizeRemediationUpdateEntries(updateEntryMap);
}

function summarizeRemediationReferences(referenceSet) {
    const values = Array.from(referenceSet || [])
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));

    if (values.length === 0) {
        return '';
    }

    if (values.length === 1) {
        return values[0];
    }

    if (values.length === 2) {
        return `${values[0]}, ${values[1]}`;
    }

    return `${values[0]} +${values.length - 1} more`;
}

function summarizeRemediationPlatforms(platformSet) {
    const values = Array.from(platformSet || [])
        .map(value => normalizeRemediationText(value))
        .filter(value => value && value !== 'Unknown')
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));

    if (values.length === 0) {
        return '';
    }

    if (values.length === 1) {
        return values[0];
    }

    if (values.length === 2) {
        return `${values[0]}, ${values[1]}`;
    }

    return `${values[0]}, ${values[1]} +${values.length - 2} more`;
}

function getSingleRemediationUpdateUrl(urlSet, referenceSet) {
    const urls = Array.from(urlSet || []).filter(Boolean);
    const references = Array.from(referenceSet || []).filter(Boolean);

    if (urls.length !== 1 || references.length !== 1) {
        return '';
    }

    return urls[0];
}

/**
 * Build remediation HTML with link from vulnerability data.
 * Returns an <a> tag linking to RecommendedSecurityUpdateUrl when available,
 * otherwise returns plain escaped text.
 * @param {Object} v - Vulnerability object (or any object with RecommendedSecurityUpdate/Id/Url)
 * @returns {string} HTML string for the remediation cell
 */
function buildRemediationHtml(v) {
    const remediation = buildRemediationDescriptor(v);
    const updateEntryMap = new Map();
    addRemediationUpdateEntry(updateEntryMap, remediation);
    return buildRemediationCellHtml(
        remediation.title,
        remediation.updateUrl,
        finalizeRemediationUpdateEntries(updateEntryMap)
    );
}