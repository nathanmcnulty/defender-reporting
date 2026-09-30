const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

const reportOptions = [
    ['active-vulnerabilities', 'Active Vulnerabilities'],
    ['remediation-activity', 'Remediation Activity'],
    ['impact-analysis', 'Impact Analysis'],
    ['devices-by-remediation', 'Devices by Remediation'],
    ['remediations-by-device', 'Remediations by Device']
];

const requiredElementIds = [
    'dashboardMain',
    'reportSelectorShell',
    'reportSelectorButton',
    'reportSelector',
    'reportSelectorPopover',
    'reportSelectorOptions',
    'exportPdfButton',
    'dashboardStatus',
    'statsSummary',
    'criticalCount',
    'highCount',
    'mediumCount',
    'lowCount',
    'filterToolbar',
    'filterPillDate',
    'filterPillRbacGroup',
    'filterPillDeviceTags',
    'filterPillOSPlatform',
    'filterPillSeverity',
    'filterPillDeviceName',
    'clearAllFiltersButton',
    'active-vulnerabilities-section',
    'remediation-activity-section',
    'impact-analysis-section',
    'devices-by-remediation-section',
    'remediations-by-device-section',
    'remediationTable',
    'remediationDetailsTable',
    'impactAnalysisTable',
    'devicesByRemediationContainer',
    'remediationsByDeviceContainer',
    'dashboardConfig',
    'dataFormat',
    'lookupsData',
    'vulnsData'
];

const activeVulnerabilityColumnLabels = [
    'Vendor',
    'Software',
    'Remediation',
    'Update Details',
    'Assets',
    'Vulnerabilities',
    'Exploits',
    'Kits'
];

const hostedAssets = [
    'runtime/dashboard.css',
    'runtime/dashboard.js',
    'runtime/pako.js',
    'vendor/chart.js',
    'data/summary.json',
    'optional/pdf-export.runtime.js',
    'optional/pdf-export.bundle.js',
    'data/payload.json.gz'
];

function assertFileExists(filePath, message) {
    assert(fs.existsSync(filePath), message);
}

function readUtf8(filePath) {
    assertFileExists(filePath, `Expected file to exist: ${filePath}`);
    return fs.readFileSync(filePath, 'utf8');
}

function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function assertContains(text, expected, message) {
    assert(text.includes(expected), message);
}

function assertMatches(text, expression, message) {
    assert(expression.test(text), message);
}

function validateCommonHtml(html, label) {
    const unresolvedPlaceholders = html.match(/__[A-Z0-9_]+__/g) || [];
    assert.strictEqual(
        unresolvedPlaceholders.length,
        0,
        `${label}: unresolved placeholders found: ${unresolvedPlaceholders.join(', ')}`
    );

    requiredElementIds.forEach(id => {
        assertMatches(html, new RegExp(`id="${escapeRegex(id)}"`), `${label}: missing required element id '${id}'.`);
    });

    reportOptions.forEach(([value, optionLabel]) => {
        assertMatches(
            html,
            new RegExp(`<option[^>]*value="${escapeRegex(value)}"[^>]*>${escapeRegex(optionLabel)}</option>`),
            `${label}: missing report option '${optionLabel}'.`
        );
    });

    activeVulnerabilityColumnLabels.forEach(columnLabel => {
        assertContains(html, columnLabel, `${label}: missing Active Vulnerabilities column label '${columnLabel}'.`);
    });

    ['Critical', 'High', 'Medium', 'Low', 'Report', 'Export PDF', 'Dashboard filters', 'Clear All'].forEach(text => {
        assertContains(html, text, `${label}: missing required text '${text}'.`);
    });

    assertContains(html, 'class="filter-toolbar"', `${label}: missing filter toolbar shell.`);
    assertContains(html, 'class="report-selector-shell"', `${label}: missing report selector shell.`);
}

function validateSelfContained(selfContainedPath) {
    const html = readUtf8(selfContainedPath);
    validateCommonHtml(html, 'self-contained');
    assertContains(html, '"deliveryMode":"self-contained"', 'self-contained: delivery mode marker is missing or incorrect.');
    assertContains(html, '<style>', 'self-contained: expected embedded CSS block.');
    assertContains(html, '<script id="chartJsLib" type="application/gzip-base64">', 'self-contained: missing embedded Chart.js payload.');
    assertContains(html, '<script id="pdfExportBundleLib" type="application/gzip-base64">', 'self-contained: missing embedded PDF export payload.');
    assert(!html.includes('.assets/'), 'self-contained: should not reference hosted dashboard asset paths.');
}

function validateHosted(hostedPath) {
    const html = readUtf8(hostedPath);
    validateCommonHtml(html, 'hosted');
    assertContains(html, '"deliveryMode":"split-assets"', 'hosted: delivery mode marker is missing or incorrect.');

    const hostedDirectoryName = `${path.basename(hostedPath, path.extname(hostedPath))}.assets`;
    const hostedDirectoryPath = path.join(path.dirname(hostedPath), hostedDirectoryName);
    assertFileExists(hostedDirectoryPath, `hosted: expected asset directory '${hostedDirectoryPath}' to exist.`);

    hostedAssets.forEach(assetName => {
        const assetPath = path.join(hostedDirectoryPath, assetName);
        assertFileExists(assetPath, `hosted: expected asset '${assetName}' to exist.`);
        assertContains(html, `${hostedDirectoryName}/${assetName}`, `hosted: expected HTML to reference '${assetName}'.`);
    });

    const hostedRuntimeJs = readUtf8(path.join(hostedDirectoryPath, 'runtime/dashboard.js'));
    const hostedPdfRuntimeJs = readUtf8(path.join(hostedDirectoryPath, 'optional/pdf-export.runtime.js'));
    const hostedSummaryJson = JSON.parse(readUtf8(path.join(hostedDirectoryPath, 'data/summary.json')));
    assert(hostedSummaryJson && hostedSummaryJson.filterCatalog, 'hosted: expected summary asset to contain hosted filter catalog data.');
    assert(Array.isArray(hostedSummaryJson.filterCatalog.devices), 'hosted: expected summary asset to contain filter catalog devices.');
    assertContains(html, `"payloadSummaryUrl":"${hostedDirectoryName}/data/summary.json"`, 'hosted: expected hosted summary payload URL to be configured.');
    assertContains(html, '"pdfExportRuntimeMode":"external"', 'hosted: expected hosted PDF export controller to be deferred.');
    assertContains(html, `"pdfExportRuntimeUrl":"${hostedDirectoryName}/optional/pdf-export.runtime.js"`, 'hosted: expected hosted PDF export controller URL to be configured.');
    assert(!hostedRuntimeJs.includes('async function exportToPDF'), 'hosted: expected runtime/dashboard.js to exclude the deferred PDF export controller.');
    assertContains(hostedPdfRuntimeJs, 'async function exportToPDF', 'hosted: expected optional PDF runtime asset to contain the export controller.');

    assertContains(
        html,
        `<link rel="stylesheet" href="${hostedDirectoryName}/runtime/dashboard.css">`,
        'hosted: expected external stylesheet reference.'
    );
    assertContains(
        html,
        `<script src="${hostedDirectoryName}/runtime/pako.js"></script>`,
        'hosted: expected external pako reference.'
    );
    assertContains(
        html,
        `<script src="${hostedDirectoryName}/runtime/dashboard.js"></script>`,
        'hosted: expected external dashboard script reference.'
    );
    assert(!html.includes('<style>'), 'hosted: should not contain embedded stylesheet markup.');
}

function validatePackageParity(selfContainedPath, hostedPath) {
    const html = readUtf8(selfContainedPath);
    const embeddedPayload = html.match(/<script id="vulnsData" type="application\/json">\s*([A-Za-z0-9+/=\s]+)<\/script>/);
    assert(embeddedPayload, 'self-contained: expected embedded gzip payload.');
    const selfPayload = JSON.parse(zlib.gunzipSync(Buffer.from(embeddedPayload[1].replace(/\s/g, ''), 'base64')));
    const assetDirectory = path.join(path.dirname(hostedPath), `${path.basename(hostedPath, path.extname(hostedPath))}.assets`, 'data');
    const hostedBytes = fs.readFileSync(path.join(assetDirectory, 'payload.json.gz'));
    const hostedPayload = JSON.parse(zlib.gunzipSync(hostedBytes));
    assert.deepStrictEqual(selfPayload, hostedPayload, 'dual-package: expected identical rows and lookups.');

    const summary = JSON.parse(readUtf8(path.join(assetDirectory, 'summary.json')));
    const rowCount = Array.isArray(hostedPayload.vulns) ? hostedPayload.vulns.length : hostedPayload.vulns.d.length;
    assert(rowCount > 0, 'dual-package: expected nonempty synthetic fixture rows.');
    assert.strictEqual(summary.meta.vulnCount, rowCount, 'summary: vulnerability count must match both payloads.');
    assert.strictEqual(summary.meta.deviceCount, hostedPayload.lookups.devices.length, 'summary: device count must match both payloads.');
    assert.strictEqual(summary.meta.cveCount, hostedPayload.lookups.cves.length, 'summary: CVE count must match both payloads.');
    assert.strictEqual(summary.filterCatalog.devices.length, hostedPayload.lookups.devices.length, 'summary: device catalog must match the payload.');
    assert.strictEqual(summary.meta.payloadSha256, crypto.createHash('sha256').update(hostedBytes).digest('hex'), 'summary: payload hash must match the hosted asset.');
}

function main() {
    const [, , selfContainedPath, hostedPath] = process.argv;
    if (!selfContainedPath || !hostedPath) {
        console.error('Usage: node tests/Validate-DashboardGeneratedArtifacts.js <self-contained-html> <hosted-html>');
        process.exit(1);
    }

    validateSelfContained(path.resolve(selfContainedPath));
    validateHosted(path.resolve(hostedPath));
    validatePackageParity(path.resolve(selfContainedPath), path.resolve(hostedPath));
}

main();
