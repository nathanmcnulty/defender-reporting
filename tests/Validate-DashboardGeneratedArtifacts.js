const assert = require('assert');
const fs = require('fs');
const path = require('path');

const reportOptions = [
    ['active-vulnerabilities', 'Active Vulnerabilities'],
    ['remediation-activity', 'Remediation Activity'],
    ['impact-analysis', 'Impact Analysis'],
    ['devices-by-remediation', 'Devices by Remediation'],
    ['remediations-by-device', 'Remediations by Device']
];

const requiredElementIds = [
    'dashboardMain',
    'reportSelector',
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
    'dashboard.css',
    'dashboard.js',
    'pako.js',
    'chart.js',
    'pdf-export.bundle.js',
    'payload.json.gz'
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

    ['Critical', 'High', 'Medium', 'Low', 'Report:', 'Export to PDF', 'Dashboard filters'].forEach(text => {
        assertContains(html, text, `${label}: missing required text '${text}'.`);
    });
}

function validateSelfContained(selfContainedPath) {
    const html = readUtf8(selfContainedPath);
    validateCommonHtml(html, 'self-contained');
    assertContains(html, '"deliveryMode":"self-contained"', 'self-contained: delivery mode marker is missing or incorrect.');
    assertContains(html, '<style>', 'self-contained: expected embedded CSS block.');
    assertContains(html, '<script id="chartJsLib" type="application/gzip-base64">', 'self-contained: missing embedded Chart.js payload.');
    assertContains(html, '<script id="pdfExportBundleLib" type="application/gzip-base64">', 'self-contained: missing embedded PDF export payload.');
    assert(!html.includes('.assets/dashboard.js'), 'self-contained: should not reference hosted dashboard asset paths.');
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

    assertContains(
        html,
        `<link rel="stylesheet" href="${hostedDirectoryName}/dashboard.css">`,
        'hosted: expected external stylesheet reference.'
    );
    assertContains(
        html,
        `<script src="${hostedDirectoryName}/pako.js"></script>`,
        'hosted: expected external pako reference.'
    );
    assertContains(
        html,
        `<script src="${hostedDirectoryName}/dashboard.js"></script>`,
        'hosted: expected external dashboard script reference.'
    );
    assert(!html.includes('<style>'), 'hosted: should not contain embedded stylesheet markup.');
}

function main() {
    const [, , selfContainedPath, hostedPath] = process.argv;
    if (!selfContainedPath || !hostedPath) {
        console.error('Usage: node tests/Validate-DashboardGeneratedArtifacts.js <self-contained-html> <hosted-html>');
        process.exit(1);
    }

    validateSelfContained(path.resolve(selfContainedPath));
    validateHosted(path.resolve(hostedPath));
}

main();