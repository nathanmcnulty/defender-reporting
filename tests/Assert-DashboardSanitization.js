const assert = require('assert');
const { loadDashboardHarness } = require('./helpers/dashboard-test-harness');

const dashboard = loadDashboardHarness(`
module.exports = {
    buildDeviceBubbleHtml,
    buildDenseModalDeviceRow,
    buildCveLinkHtml,
    buildRemediationTitleHtml,
    buildRemediationUpdateBadgeHtml,
    buildRemediationsByDeviceRowHtml,
    escapeHtml,
    generateCveTooltipContent,
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

const denseModalDeviceRow = dashboard.buildDenseModalDeviceRow({
    DeviceName: 'device<img src=x onerror=alert(1)>',
    DeviceId: 'device-id<script>',
    MachineInfo: { ip: '10.0.0.1<script>' },
    cveIds: new Set(['CVE-2026-0001']),
    lastSeen: 'not-a-date<script>alert(1)</script>'
});
assert.ok(!denseModalDeviceRow.includes('<img'));
assert.ok(!denseModalDeviceRow.includes('<script'));
assert.ok(denseModalDeviceRow.includes('not-a-date&lt;script&gt;alert(1)&lt;/script&gt;'));

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

const safePrimaryCveHtml = dashboard.buildCveLinkHtml({
    CveBatchUrl: 'https://updates.example/cve?name=<script>',
    CveId: 'CVE-2026-0002',
    VulnerabilitySeverityLevel: 'High',
    SoftwareVersion: '2.0',
    SoftwareVendor: 'Vendor',
    SoftwareName: 'Product',
    VulnerabilityDescription: 'Safe description',
    CvssScore: 7.2,
    PublishedDate: '2026-04-27',
    _lastSeenDate: '2026-04-27'
});
assert.ok(safePrimaryCveHtml.includes('href="https://updates.example/cve?name=%3Cscript%3E"'));
assert.ok(!safePrimaryCveHtml.includes('<script>'));

const cveTooltip = dashboard.generateCveTooltipContent({
    cve: 'CVE-2026-0003<script>',
    softwareVendor: 'Vendor<img src=x onerror=alert(1)>',
    softwareName: 'Product<script>',
    versions: new Set(['1.0<script>']),
    description: 'Summary: <img src=x onerror=alert(1)>\nImpact: <script>alert(1)</script>',
    cvssScore: '9.9<script>',
    severity: 'Critical" onclick="alert(1)',
    publishedDate: '2026-04-27',
    firstSeen: '2026-04-27',
    lastSeen: '2026-04-28'
});
assert.ok(!cveTooltip.includes('<script'));
assert.ok(!cveTooltip.includes('<img'));
assert.ok(!cveTooltip.includes('onclick="'));
assert.ok(cveTooltip.includes('&lt;script&gt;'));

const deviceBubble = dashboard.buildDeviceBubbleHtml({
    DeviceName: 'device<img src=x onerror=alert(1)>',
    DeviceId: 'id<script>',
    MachineInfo: {
        ip: '10.0.0.1<script>',
        eip: '203.0.113.10<img>',
        u: ['user@example.com<script>'],
        hs: 'Healthy<script>',
        rs: 'High" onclick="alert(1)',
        el: 'Medium<script>',
        dv: 'Normal<script>',
        mb: 'MDE<script>',
        aad: true,
        ls: '2026-04-27<script>',
        fs: '2026-04-01<script>'
    }
});
assert.ok(!deviceBubble.includes('<img'));
assert.ok(!deviceBubble.includes('<script'));
assert.ok(!deviceBubble.includes('onclick="'));
assert.ok(deviceBubble.includes('device&lt;img'));

console.log('Dashboard sanitization assertions passed.');