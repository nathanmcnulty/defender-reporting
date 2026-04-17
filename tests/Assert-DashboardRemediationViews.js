const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function createStubElement() {
    return {
        textContent: '',
        innerHTML: '',
        value: '',
        checked: false,
        disabled: false,
        style: {},
        dataset: {},
        classList: {
            add() {},
            remove() {},
            toggle() {},
            contains() { return false; }
        },
        appendChild() {},
        removeChild() {},
        remove() {},
        setAttribute() {},
        getAttribute() { return null; },
        addEventListener() {},
        removeEventListener() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
        closest() { return null; },
        focus() {},
        click() {},
        getBoundingClientRect() {
            return { top: 0, bottom: 0, left: 0, width: 0, height: 0 };
        }
    };
}

function createDocumentStub() {
    const elements = new Map();

    function getOrCreateElement(id) {
        if (!elements.has(id)) {
            const element = createStubElement();
            if (id === 'dataFormat') {
                element.textContent = 'normalized';
            }
            elements.set(id, element);
        }

        return elements.get(id);
    }

    return {
        body: {
            classList: {
                add() {},
                remove() {}
            },
            appendChild() {}
        },
        getElementById(id) {
            return getOrCreateElement(id);
        },
        querySelector() {
            return null;
        },
        querySelectorAll() {
            return [];
        },
        createElement() {
            return createStubElement();
        },
        createDocumentFragment() {
            return createStubElement();
        },
        addEventListener() {},
        removeEventListener() {}
    };
}

function loadDashboardHarness() {
    const dashboardPath = path.join(__dirname, '..', 'templates', 'dashboard.js');
    const dashboardSource = fs.readFileSync(dashboardPath, 'utf8');
    const exportSource = `
module.exports = {
    createEmptyFilterState,
    applyDerivedVulnerabilityFields,
    buildRemediationDescriptor,
    buildRemediationModalUpdateLinksHtml,
    getImpactAnalysisData,
    getRemediationTableData,
    getScopedRemediationDisplayTitle,
    matchesFilterState,
    getPointInTimeActiveRows,
    getRemediationReportRows,
    setRemediationReportMode,
    splitDeviceRemediationsForDisplay,
    setDashboardState(state, rows, latestObservedDate) {
        filterState = state;
        vulnerabilityData = rows;
        filteredData = rows.filter(v => matchesFilterState(v, state));
        mostRecentLastSeenDate = latestObservedDate || '';
        invalidateAggregateCache();
    }
};
`;

    const sandbox = {
        console,
        require,
        module: { exports: {} },
        exports: {},
        document: createDocumentStub(),
        window: {
            addEventListener() {},
            removeEventListener() {},
            innerHeight: 1080,
            innerWidth: 1920
        },
        navigator: {
            clipboard: {
                writeText: async () => {}
            }
        },
        performance: {
            now() { return 0; }
        },
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
        alert() {},
        confirm() { return true; }
    };

    vm.runInNewContext(`${dashboardSource}\n${exportSource}`, sandbox, { filename: dashboardPath });
    return sandbox.module.exports;
}

function createTestRow(overrides = {}) {
    return {
        DeviceId: 'device-001',
        DeviceName: 'device-001.contoso.com',
        RbacGroupName: 'Servers',
        MachineTags: ['Prod'],
        OSPlatform: 'Windows 11',
        VulnerabilitySeverityLevel: 'High',
        CveId: 'CVE-2025-9999',
        SoftwareVendor: 'contoso',
        SoftwareName: 'widget',
        RecommendedSecurityUpdate: 'Monthly Security Update',
        RecommendedSecurityUpdateId: '',
        RecommendedSecurityUpdateUrl: '',
        FirstSeenTimestamp: '2025-09-15',
        LastSeenTimestamp: '2025-09-20',
        MachineInfo: {
            ls: '2025-09-20',
            ip: '10.0.0.10'
        },
        ...overrides
    };
}

function main() {
    const dashboard = loadDashboardHarness();
    const rows = [
        createTestRow({
            DeviceId: 'device-old',
            DeviceName: 'device-old.contoso.com',
            CveId: 'CVE-2025-1000',
            FirstSeenTimestamp: '2025-09-15',
            LastSeenTimestamp: '2025-09-20',
            MachineInfo: {
                ls: '2025-09-20',
                ip: '10.0.0.10'
            }
        }),
        createTestRow({
            DeviceId: 'device-open',
            DeviceName: 'device-open.contoso.com',
            CveId: 'CVE-2025-1001',
            FirstSeenTimestamp: '2025-10-15',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.11'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(rows);

    const historicalRangeState = dashboard.createEmptyFilterState();
    historicalRangeState.startDate = '2025-09-01';
    historicalRangeState.endDate = '2025-12-01';
    historicalRangeState.key = 'historical-2025-09-01-to-2025-12-01';

    dashboard.setDashboardState(historicalRangeState, rows, '2025-12-01');

    assert.strictEqual(
        dashboard.getRemediationReportRows().length,
        1,
        'Expected remediation reports to default to unresolved-only snapshot mode.'
    );

    dashboard.setRemediationReportMode('range');
    assert.strictEqual(
        dashboard.getRemediationReportRows().length,
        2,
        'Expected observed-in-window remediation mode to include rows active anywhere in the selected range.'
    );

    dashboard.setRemediationReportMode('snapshot');
    const snapshotRows = dashboard.getRemediationReportRows();
    assert.strictEqual(
        snapshotRows.length,
        1,
        'Expected snapshot remediation mode to keep only rows still open on the range end date.'
    );
    assert.strictEqual(snapshotRows[0].CveId, 'CVE-2025-1001');

    const split = dashboard.splitDeviceRemediationsForDisplay([
        { title: 'Top-1' },
        { title: 'Top-2' },
        { title: 'Hidden-1' },
        { title: 'Hidden-2' }
    ], 2);

    assert.deepStrictEqual(
        split.visible.map(item => item.title),
        ['Top-1', 'Top-2'],
        'Expected the device-card display helper to keep the leading remediation slice visible.'
    );
    assert.deepStrictEqual(
        split.overflow.map(item => item.title),
        ['Hidden-1', 'Hidden-2'],
        'Expected the device-card display helper to push the long tail into the overflow slice.'
    );

    const defaultSplit = dashboard.splitDeviceRemediationsForDisplay(
        Array.from({ length: 11 }, (_, index) => ({ title: `Remediation-${index + 1}` }))
    );
    assert.strictEqual(
        defaultSplit.visible.length,
        10,
        'Expected remediations-by-device cards to show the top 10 remediations before collapsing the overflow.'
    );
    assert.strictEqual(
        defaultSplit.overflow.length,
        1,
        'Expected remediations-by-device cards to keep only the remainder in the overflow section after the top 10.'
    );

    const duplicateFamilyRows = [
        createTestRow({
            DeviceId: 'python-001',
            DeviceName: 'python-001.contoso.com',
            SoftwareVendor: 'python',
            SoftwareName: 'python_for_mac',
            OSPlatform: 'macOS',
            CveId: 'CVE-2023-27043',
            RecommendationReference: 'va-_-python-_-python_for_mac',
            RecommendedSecurityUpdate: 'CVE-2023-27043',
            CveBatchTitle: 'Python March 2023 Vulnerabilities',
            FirstSeenTimestamp: '2025-11-15',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.21'
            }
        }),
        createTestRow({
            DeviceId: 'python-002',
            DeviceName: 'python-002.contoso.com',
            SoftwareVendor: 'python',
            SoftwareName: 'python_for_mac',
            OSPlatform: 'macOS',
            CveId: 'CVE-2023-27043',
            RecommendationReference: 'va-_-python-_-python_for_mac',
            RecommendedSecurityUpdate: 'CVE-2023-27043',
            CveBatchTitle: '',
            FirstSeenTimestamp: '2025-11-20',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.22'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(duplicateFamilyRows);
    dashboard.setDashboardState(historicalRangeState, duplicateFamilyRows, '2025-12-01');

    const remediationTableRows = dashboard.getRemediationTableData();
    assert.strictEqual(
        remediationTableRows.length,
        1,
        'Expected active remediation rows with the same recommendation family to collapse into one entry.'
    );
    assert.strictEqual(
        remediationTableRows[0].remediation,
        'March 2023 Vulnerabilities',
        'Expected the active remediation table to show the advisory title without repeating the vendor or software name.'
    );
    assert.strictEqual(
        remediationTableRows[0].modalTitle,
        'Python For Mac: March 2023 Vulnerabilities',
        'Expected active remediation drill-in to keep the fuller product-scoped title for modal context.'
    );

    const impactData = dashboard.getImpactAnalysisData();
    assert.strictEqual(
        impactData.top25.length,
        1,
        'Expected impact analysis to reuse the same remediation-family collapse as the active remediation table.'
    );
    assert.strictEqual(
        impactData.top25[0].name,
        'Python For Mac: March 2023 Vulnerabilities',
        'Expected impact analysis to keep the product-scoped advisory title without repeating the vendor name.'
    );
    assert.ok(
        impactData.top25[0].updateHtml.includes('class="stat-badge"')
            && impactData.top25[0].updateHtml.includes('CVE-2023-27043'),
        'Expected impact analysis to surface the recommendation reference in an Update Details badge when it differs from the advisory title.'
    );
    assert.strictEqual(
        dashboard.getScopedRemediationDisplayTitle(dashboard.buildRemediationDescriptor(duplicateFamilyRows[0])),
        'Python For Mac: March 2023 Vulnerabilities',
        'Expected product-scoped remediation titles to strip the repeated vendor name in card-style views.'
    );

    const kbSuffixRows = [
        createTestRow({
            DeviceId: 'aspnet-001',
            DeviceName: 'aspnet-001.contoso.com',
            SoftwareVendor: 'microsoft',
            SoftwareName: 'asp_net_core',
            RecommendationReference: 'va-_-microsoft-_-asp_net_core',
            RecommendedSecurityUpdate: 'October 2025 Security Updates',
            RecommendedSecurityUpdateId: '5066131',
            RecommendedSecurityUpdateUrl: 'https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5066131',
            CveBatchTitle: 'Microsoft October 2025 Security Updates',
            FirstSeenTimestamp: '2025-11-22',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.24'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(kbSuffixRows);
    dashboard.setDashboardState(historicalRangeState, kbSuffixRows, '2025-12-01');

    const kbSuffixTableRows = dashboard.getRemediationTableData();
    assert.strictEqual(kbSuffixTableRows.length, 1, 'Expected the KB suffix scenario to produce one remediation row.');
    assert.strictEqual(
        kbSuffixTableRows[0].remediation,
        'October 2025 Security Updates',
        'Expected the active remediation title to stay concise when Patch Ref has its own column.'
    );
    assert.ok(
        kbSuffixTableRows[0].remediationHtml.includes('October 2025 Security Updates')
            && !kbSuffixTableRows[0].remediationHtml.includes('KB5066131'),
        'Expected the active remediation cell to render only the cleaned remediation title.'
    );
    assert.ok(
        kbSuffixTableRows[0].updateHtml.includes('KB5066131')
            && kbSuffixTableRows[0].updateHtml.includes('href="https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5066131"'),
        'Expected the active remediation Patch Ref column to carry the KB link.'
    );
    assert.ok(
        kbSuffixTableRows[0].modalTitle.endsWith('Asp Net Core: October 2025 Security Updates (KB5066131)'),
        'Expected remediation modal titles to retain the fuller scoped title plus the KB suffix.'
    );

    const redundantBadgeRows = [
        createTestRow({
            DeviceId: 'edge-single',
            DeviceName: 'edge-single.contoso.com',
            SoftwareVendor: 'microsoft',
            SoftwareName: 'edge_chromium-based',
            RecommendationReference: 'va-_-microsoft-_-edge_chromium-based',
            CveId: 'CVE-2026-1000',
            RecommendedSecurityUpdate: 'April 2026 Security Updates',
            RecommendedSecurityUpdateId: '',
            RecommendedSecurityUpdateUrl: '',
            CveBatchTitle: 'Microsoft April 2026 Security Updates',
            FirstSeenTimestamp: '2025-11-10',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.40'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(redundantBadgeRows);
    dashboard.setDashboardState(historicalRangeState, redundantBadgeRows, '2025-12-01');

    const redundantBadgeTableRows = dashboard.getRemediationTableData();
    assert.strictEqual(
        redundantBadgeTableRows[0].remediation,
        'April 2026 Security Updates',
        'Expected scoped remediation titles to drop the repeated vendor name in the active table.'
    );
    assert.strictEqual(
        redundantBadgeTableRows[0].updateHtml,
        '-',
        'Expected Patch Ref to stay empty when it would only duplicate the remediation title without a linkable reference.'
    );

    const mixedFirefoxRows = [
        createTestRow({
            DeviceId: 'firefox-majority-1',
            DeviceName: 'firefox-majority-1.contoso.com',
            SoftwareVendor: 'mozilla',
            SoftwareName: 'firefox',
            RecommendationReference: 'va-_-mozilla-_-firefox',
            CveId: 'CVE-2026-4691',
            RecommendedSecurityUpdate: 'mfsa2026-24',
            RecommendedSecurityUpdateId: '',
            RecommendedSecurityUpdateUrl: '',
            CveBatchTitle: 'Mozilla March 2026 Vulnerabilities',
            CveBatchUrl: 'https://www.mozilla.org/en-US/security/advisories/mfsa2026-24/',
            PublishedDate: '2026-03-24',
            FirstSeenTimestamp: '2025-11-12',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.50'
            }
        }),
        createTestRow({
            DeviceId: 'firefox-majority-2',
            DeviceName: 'firefox-majority-2.contoso.com',
            SoftwareVendor: 'mozilla',
            SoftwareName: 'firefox',
            RecommendationReference: 'va-_-mozilla-_-firefox',
            CveId: 'CVE-2026-4692',
            RecommendedSecurityUpdate: 'mfsa2026-24',
            RecommendedSecurityUpdateId: '',
            RecommendedSecurityUpdateUrl: '',
            CveBatchTitle: 'Mozilla March 2026 Vulnerabilities',
            CveBatchUrl: 'https://www.mozilla.org/en-US/security/advisories/mfsa2026-24/',
            PublishedDate: '2026-03-24',
            FirstSeenTimestamp: '2025-11-13',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.51'
            }
        }),
        createTestRow({
            DeviceId: 'firefox-stale',
            DeviceName: 'firefox-stale.contoso.com',
            SoftwareVendor: 'mozilla',
            SoftwareName: 'firefox',
            RecommendationReference: 'va-_-mozilla-_-firefox',
            CveId: 'CVE-2025-59375',
            RecommendedSecurityUpdate: 'mfsa2026-24',
            RecommendedSecurityUpdateId: '',
            RecommendedSecurityUpdateUrl: '',
            CveBatchTitle: 'Mozilla September 2025 Vulnerabilities',
            CveBatchUrl: 'https://www.mozilla.org/en-US/security/advisories/mfsa2026-24/',
            PublishedDate: '2025-09-15',
            FirstSeenTimestamp: '2025-11-14',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.52'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(mixedFirefoxRows);
    dashboard.setDashboardState(historicalRangeState, mixedFirefoxRows, '2025-12-01');

    const mixedFirefoxTableRows = dashboard.getRemediationTableData();
    assert.strictEqual(mixedFirefoxTableRows.length, 1, 'Expected the mixed Firefox advisory rows to stay grouped together.');
    assert.strictEqual(
        mixedFirefoxTableRows[0].remediation,
        'March 2026 Vulnerabilities',
        'Expected grouped remediation rows to choose the dominant advisory title without repeating the vendor name in the active table.'
    );
    assert.ok(
        mixedFirefoxTableRows[0].updateHtml.includes('mfsa2026-24')
            && mixedFirefoxTableRows[0].updateHtml.includes('https://www.mozilla.org/en-US/security/advisories/mfsa2026-24/'),
        'Expected advisory Patch Ref links to inherit the advisory URL when the update identifier matches the batch URL.'
    );
    assert.strictEqual(
        dashboard.getScopedRemediationDisplayTitle(dashboard.buildRemediationDescriptor(mixedFirefoxRows[0])),
        'Firefox: March 2026 Vulnerabilities',
        'Expected card-style remediation titles to keep the product scope while dropping the repeated vendor name.'
    );

    const opensslAdvisoryRows = [
        createTestRow({
            DeviceId: 'openssl-001',
            DeviceName: 'openssl-001.contoso.com',
            SoftwareVendor: 'openssl',
            SoftwareName: 'openssl',
            RecommendationReference: 'va-_-openssl-_-openssl',
            CveId: 'CVE-2025-15467',
            RecommendedSecurityUpdate: 'CVE-2025-15467',
            RecommendedSecurityUpdateId: '',
            RecommendedSecurityUpdateUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-15467',
            CveBatchTitle: 'Openssl January 2026 Vulnerabilities',
            PublishedDate: '2026-01-26',
            FirstSeenTimestamp: '2025-11-22',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.61'
            }
        }),
        createTestRow({
            DeviceId: 'openssl-002',
            DeviceName: 'openssl-002.contoso.com',
            SoftwareVendor: 'openssl',
            SoftwareName: 'openssl',
            RecommendationReference: 'va-_-openssl-_-openssl',
            CveId: 'CVE-2025-68160',
            RecommendedSecurityUpdate: 'CVE-2025-68160',
            RecommendedSecurityUpdateId: '',
            RecommendedSecurityUpdateUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-68160',
            CveBatchTitle: 'Openssl January 2026 Vulnerabilities',
            PublishedDate: '2026-01-27',
            FirstSeenTimestamp: '2025-11-23',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.62'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(opensslAdvisoryRows);
    dashboard.setDashboardState(historicalRangeState, opensslAdvisoryRows, '2025-12-01');

    const opensslTableRows = dashboard.getRemediationTableData();
    assert.strictEqual(
        opensslTableRows.length,
        1,
        'Expected advisory-family rows with per-CVE update references to collapse into one remediation entry.'
    );
    assert.strictEqual(
        opensslTableRows[0].remediation,
        'January 2026 Vulnerabilities',
        'Expected the active remediation table to keep the concise advisory title when the software has its own column.'
    );

    const opensslDescriptor = dashboard.buildRemediationDescriptor(opensslAdvisoryRows[0]);
    assert.strictEqual(
        dashboard.getScopedRemediationDisplayTitle(opensslDescriptor),
        'Openssl January 2026 Vulnerabilities',
        'Expected card-style remediation titles to retain the product identity when the advisory title is the only product cue.'
    );

    const opensslImpact = dashboard.getImpactAnalysisData();
    assert.strictEqual(
        opensslImpact.top25.length,
        1,
        'Expected impact analysis to collapse same-family advisory rows even when the update field is a per-CVE reference.'
    );
    assert.strictEqual(
        opensslImpact.top25[0].name,
        'Openssl January 2026 Vulnerabilities',
        'Expected impact analysis to keep the full advisory title when stripping the vendor would hide the product identity.'
    );
    assert.ok(
        opensslImpact.top25[0].updateHtml.includes('CVE-2025-15467')
            && opensslImpact.top25[0].updateHtml.includes('CVE-2025-68160'),
        'Expected grouped advisory-family rows to retain each CVE reference in the Update Details content.'
    );

    const notepadRows = [
        createTestRow({
            DeviceId: 'notepad-001',
            DeviceName: 'notepad-001.contoso.com',
            SoftwareVendor: 'notepad_plus_plus',
            SoftwareName: 'notepad++',
            RecommendationReference: 'va-_-notepad_plus_plus-_-notepad++',
            CveId: 'CVE-2025-15556',
            RecommendedSecurityUpdate: 'CVE-2025-15556',
            RecommendedSecurityUpdateId: '',
            RecommendedSecurityUpdateUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2025-15556',
            CveBatchTitle: 'Notepad_plus_plus February 2026 Vulnerabilities',
            PublishedDate: '2026-02-18',
            FirstSeenTimestamp: '2025-11-24',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.63'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(notepadRows);
    dashboard.setDashboardState(historicalRangeState, notepadRows, '2025-12-01');

    const notepadDescriptor = dashboard.buildRemediationDescriptor(notepadRows[0]);
    assert.strictEqual(
        dashboard.getScopedRemediationDisplayTitle(notepadDescriptor),
        'Notepad++: February 2026 Vulnerabilities',
        'Expected scoped remediation titles to remove raw underscore-heavy product prefixes when a formatted product label already provides the context.'
    );

    const notepadTableRows = dashboard.getRemediationTableData();
    assert.strictEqual(notepadTableRows.length, 1, 'Expected the Notepad++ title-format case to produce one remediation row.');
    assert.strictEqual(
        notepadTableRows[0].remediation,
        'February 2026 Vulnerabilities',
        'Expected the active remediation table to keep the concise advisory title when the software column already identifies Notepad++.'
    );
    assert.strictEqual(
        notepadTableRows[0].modalTitle,
        'Notepad++: February 2026 Vulnerabilities',
        'Expected remediation modal titles to retain the formatted Notepad++ scope without leaking the raw underscore-heavy token.'
    );

    const notepadImpact = dashboard.getImpactAnalysisData();
    assert.strictEqual(
        notepadImpact.top25[0].name,
        'Notepad++: February 2026 Vulnerabilities',
        'Expected impact analysis to surface the formatted Notepad++ scope instead of the raw underscore-heavy advisory prefix.'
    );

    const multiKbRows = [
        createTestRow({
            DeviceId: 'server-mar',
            DeviceName: 'server-mar.contoso.com',
            SoftwareVendor: 'microsoft',
            SoftwareName: 'windows_server_2022',
            RecommendationReference: 'va-_-microsoft-_-windows_server_2022',
            CveId: 'CVE-2026-23672',
            RecommendedSecurityUpdate: 'March 2026 Security Updates',
            RecommendedSecurityUpdateId: '5078737',
            RecommendedSecurityUpdateUrl: '',
            CveBatchTitle: 'Microsoft March 2026 Security Updates',
            FirstSeenTimestamp: '2025-11-12',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.43'
            }
        }),
        createTestRow({
            DeviceId: 'server-mar',
            DeviceName: 'server-mar.contoso.com',
            SoftwareVendor: 'microsoft',
            SoftwareName: 'windows_server_2022',
            RecommendationReference: 'va-_-microsoft-_-windows_server_2022',
            CveId: 'CVE-2026-23668',
            RecommendedSecurityUpdate: 'March 2026 Security Updates',
            RecommendedSecurityUpdateId: '5078766',
            RecommendedSecurityUpdateUrl: 'https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5078766',
            CveBatchTitle: 'Microsoft March 2026 Security Updates',
            FirstSeenTimestamp: '2025-11-13',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.43'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(multiKbRows);
    dashboard.setDashboardState(historicalRangeState, multiKbRows, '2025-12-01');

    const multiKbTableRows = dashboard.getRemediationTableData();
    assert.strictEqual(multiKbTableRows.length, 1, 'Expected same-month multi-KB remediation rows to stay grouped together.');
    assert.ok(
        multiKbTableRows[0].remediationHtml.includes('March 2026 Security Updates')
            && !multiKbTableRows[0].remediationHtml.includes('KB5078766'),
        'Expected multi-KB remediation rows to render a plain remediation title separate from the Patch Ref column.'
    );
    assert.ok(
        multiKbTableRows[0].updateHtml.includes('https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5078737'),
        'Expected missing KB URLs to fall back to the Microsoft Update Catalog search page in the Patch Ref column.'
    );
    assert.ok(
        multiKbTableRows[0].updateHtml.includes('https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5078766'),
        'Expected explicit update URLs to remain linked in multi-KB Patch Ref entries.'
    );

    const monthSplitRows = [
        createTestRow({
            DeviceId: 'windows-jan',
            DeviceName: 'windows-jan.contoso.com',
            SoftwareVendor: 'microsoft',
            SoftwareName: 'windows_11',
            RecommendationReference: 'va-_-microsoft-_-windows_11',
            CveId: 'CVE-2026-1001',
            RecommendedSecurityUpdate: 'January 2026 Security Updates',
            RecommendedSecurityUpdateId: '5074109',
            RecommendedSecurityUpdateUrl: 'https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5074109',
            CveBatchTitle: 'Microsoft January 2026 Security Updates',
            FirstSeenTimestamp: '2025-11-10',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.41'
            }
        }),
        createTestRow({
            DeviceId: 'windows-feb',
            DeviceName: 'windows-feb.contoso.com',
            SoftwareVendor: 'microsoft',
            SoftwareName: 'windows_11',
            RecommendationReference: 'va-_-microsoft-_-windows_11',
            CveId: 'CVE-2026-1002',
            RecommendedSecurityUpdate: 'February 2026 Security Updates',
            RecommendedSecurityUpdateId: '5077181',
            RecommendedSecurityUpdateUrl: 'https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5077181',
            CveBatchTitle: 'Microsoft February 2026 Security Updates',
            FirstSeenTimestamp: '2025-11-15',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.42'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(monthSplitRows);
    dashboard.setDashboardState(historicalRangeState, monthSplitRows, '2025-12-01');

    const monthSplitTableRows = dashboard.getRemediationTableData();
    assert.strictEqual(
        monthSplitTableRows.length,
        2,
        'Expected distinct monthly updates for the same recommendation family to remain separate remediation rows.'
    );

    const crossPlatformRows = [
        createTestRow({
            DeviceId: 'edge-client',
            DeviceName: 'edge-client.contoso.com',
            SoftwareVendor: 'microsoft',
            SoftwareName: 'edge_chromium-based',
            OSPlatform: 'Windows 11',
            CveId: 'CVE-2026-4000',
            RecommendationReference: 'va-_-microsoft-_-edge_chromium-based',
            RecommendedSecurityUpdate: 'April 2026 Security Updates',
            RecommendedSecurityUpdateId: '5060001',
            RecommendedSecurityUpdateUrl: 'https://support.microsoft.com/help/5060001',
            CveBatchTitle: 'April 2026 Security Updates',
            FirstSeenTimestamp: '2025-11-15',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.31'
            }
        }),
        createTestRow({
            DeviceId: 'edge-server',
            DeviceName: 'edge-server.contoso.com',
            SoftwareVendor: 'microsoft',
            SoftwareName: 'edge_chromium-based',
            OSPlatform: 'Windows Server 2022',
            CveId: 'CVE-2026-4000',
            RecommendationReference: 'va-_-microsoft-_-edge_chromium-based',
            RecommendedSecurityUpdate: 'April 2026 Security Updates',
            RecommendedSecurityUpdateId: '5060002',
            RecommendedSecurityUpdateUrl: 'https://support.microsoft.com/help/5060002',
            CveBatchTitle: 'April 2026 Security Updates',
            FirstSeenTimestamp: '2025-11-20',
            LastSeenTimestamp: '2025-12-01',
            MachineInfo: {
                ls: '2025-12-01',
                ip: '10.0.0.32'
            }
        })
    ];

    dashboard.applyDerivedVulnerabilityFields(crossPlatformRows);
    dashboard.setDashboardState(historicalRangeState, crossPlatformRows, '2025-12-01');

    const clientDescriptor = dashboard.buildRemediationDescriptor(crossPlatformRows[0]);
    const serverDescriptor = dashboard.buildRemediationDescriptor(crossPlatformRows[1]);
    assert.strictEqual(
        clientDescriptor.key,
        serverDescriptor.key,
        'Expected remediation family keys to collapse the same software advisory across OS platforms.'
    );

    const crossPlatformRemediationRows = dashboard.getRemediationTableData();
    assert.strictEqual(
        crossPlatformRemediationRows.length,
        1,
        'Expected active remediation rows to collapse the same family across client and server OS platforms.'
    );
    assert.strictEqual(
        crossPlatformRemediationRows[0].remediation,
        'April 2026 Security Updates',
        'Expected the active remediation table to omit the repeated software name when the software has its own column.'
    );
    assert.strictEqual(
        crossPlatformRemediationRows[0].modalTitle,
        'Edge Chromium-based: April 2026 Security Updates',
        'Expected the active remediation modal title to retain the fuller product-scoped advisory name.'
    );
    assert.ok(
        crossPlatformRemediationRows[0].updateHtml.includes('KB5060001')
            && crossPlatformRemediationRows[0].updateHtml.includes('KB5060002'),
        'Expected collapsed remediation rows to retain both KB references in the Patch Ref column.'
    );
    assert.ok(
        crossPlatformRemediationRows[0].updateHtml.includes('https://support.microsoft.com/help/5060001')
            && crossPlatformRemediationRows[0].updateHtml.includes('https://support.microsoft.com/help/5060002'),
        'Expected collapsed remediation rows to retain both KB links in the Patch Ref column.'
    );

    const crossPlatformModalLinks = dashboard.buildRemediationModalUpdateLinksHtml(crossPlatformRemediationRows[0].updateEntries);
    assert.ok(
        crossPlatformModalLinks.includes('KB5060001')
            && crossPlatformModalLinks.includes('KB5060002'),
        'Expected remediation modals to retain each collapsed KB reference.'
    );
    assert.ok(
        crossPlatformModalLinks.includes('https://support.microsoft.com/help/5060001')
            && crossPlatformModalLinks.includes('https://support.microsoft.com/help/5060002'),
        'Expected remediation modals to retain each collapsed KB link.'
    );

    const crossPlatformImpact = dashboard.getImpactAnalysisData();
    assert.strictEqual(
        crossPlatformImpact.top25.length,
        1,
        'Expected impact analysis to collapse the same remediation family across OS platforms.'
    );
    assert.strictEqual(
        crossPlatformImpact.top25[0].name,
        'Edge Chromium-based: April 2026 Security Updates',
        'Expected the impact analysis report to keep the product-scoped remediation title where there is no separate software column.'
    );
    assert.ok(
        crossPlatformImpact.top25[0].updateHtml.includes('KB5060001')
            && crossPlatformImpact.top25[0].updateHtml.includes('KB5060002'),
        'Expected impact analysis Patch Ref content to retain collapsed KB references.'
    );

    const appleDescriptor = dashboard.buildRemediationDescriptor(createTestRow({
        SoftwareVendor: 'apple',
        SoftwareName: 'mac_os',
        OSPlatform: 'macOS',
        RecommendedSecurityUpdate: 'Apple Mac Os - 126798',
        RecommendedSecurityUpdateId: '',
        CveBatchTitle: '',
        RecommendationReference: ''
    }));
    assert.strictEqual(
        appleDescriptor.title,
        'Apple Mac Os patch 126798',
        'Expected scoped numeric remediation labels to render as product patch references.'
    );

    console.log('Remediation report mode and density helpers passed.');
}

main();