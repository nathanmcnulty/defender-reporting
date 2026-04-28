const assert = require('assert');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

const dashboard = loadDashboardHarness(`
module.exports = {
    buildCveLinkHtml,
    buildRemediationTitleHtml,
    buildRemediationUpdateBadgeHtml,
    buildRemediationsByDeviceRowHtml,
    escapeHtml,
    generateSeverityTooltipContent,
    getSafeExternalUrl,
    getSeverityClassName
};
`, { URL });

assert.strictEqual(
    dashboard.escapeHtml('<img src=x onerror=alert(1)> & "quoted"'),
    '&lt;img src=x onerror=alert(1)&gt; &amp; &quot;quoted&quot;'
);
assert.strictEqual(dashboard.escapeHtml(0), '0');

assert.strictEqual(dashboard.getSafeExternalUrl('https://contoso.example/path?q=1'), 'https://contoso.example/path?q=1');
assert.strictEqual(dashboard.getSafeExternalUrl('http://contoso.example/path'), 'http://contoso.example/path');
assert.strictEqual(dashboard.getSafeExternalUrl('javascript:alert(1)'), '');
assert.strictEqual(dashboard.getSafeExternalUrl('data:text/html,<script>alert(1)</script>'), '');
assert.strictEqual(dashboard.getSafeExternalUrl('/relative/path'), '');

assert.strictEqual(dashboard.getSeverityClassName('Critical'), 'critical');
assert.strictEqual(dashboard.getSeverityClassName('High" onclick="alert(1)'), 'unknown');

const remediationTitle = dashboard.buildRemediationTitleHtml('<b>Patch</b>', 'javascript:alert(1)');
assert.strictEqual(remediationTitle, '&lt;b&gt;Patch&lt;/b&gt;');

const remediationLink = dashboard.buildRemediationTitleHtml('Patch', 'https://updates.example/kb');
assert.ok(remediationLink.includes('href="https://updates.example/kb"'));
assert.ok(remediationLink.includes('>Patch</a>'));

const unsafeBadge = dashboard.buildRemediationUpdateBadgeHtml('KB<script>', 'javascript:alert(1)');
assert.ok(!unsafeBadge.includes('<a '));
assert.ok(unsafeBadge.includes('KB&lt;script&gt;'));

const tooltip = dashboard.generateSeverityTooltipContent(['CVE-2026-0001<script>alert(1)</script>']);
assert.ok(!tooltip.includes('<script>'));
assert.ok(tooltip.includes('&lt;script&gt;'));

const rowHtml = dashboard.buildRemediationsByDeviceRowHtml([{
    title: '<img src=x onerror=alert(1)>',
    patchReference: 'KB123',
    updateName: 'KB123',
    updateUrl: 'javascript:alert(1)',
    updateEntries: [{ referenceText: 'KB123<script>', referenceUrl: 'javascript:alert(1)' }],
    severities: { Critical: 1, High: 0, Medium: 0, Low: 0 },
    cves: new Set(['CVE-2026-0001']),
    cvesBySeverity: {
        Critical: ['CVE-2026-0001<script>'],
        High: [],
        Medium: [],
        Low: []
    },
    mostRecentDate: '2026-04-27<script>'
}]);
assert.ok(!rowHtml.includes('<img'));
assert.ok(!rowHtml.includes('javascript:alert'));
assert.ok(rowHtml.includes('&lt;img'));
assert.ok(rowHtml.includes('2026-04-27&lt;script&gt;'));

const cveHtml = dashboard.buildCveLinkHtml({
    CveBatchUrl: 'javascript:alert(1)',
    CveId: 'CVE-2026-0001<script>',
    VulnerabilitySeverityLevel: 'Critical" onclick="alert(1)',
    SoftwareVersion: '1.0',
    SoftwareVendor: 'Vendor',
    SoftwareName: 'Product',
    VulnerabilityDescription: '<script>alert(1)</script>',
    CvssScore: 9.8,
    PublishedDate: '2026-04-27',
    _lastSeenDate: '2026-04-27'
});
assert.ok(!cveHtml.includes('javascript:alert'));
assert.ok(!cveHtml.includes('onclick'));
assert.ok(cveHtml.includes('class="cve-severity-badge unknown"'));

console.log('Dashboard sanitization assertions passed.');