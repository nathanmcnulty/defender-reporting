/**
 * Exports each dashboard report to PDF using a headless Chromium browser.
 *
 * Usage: node .github/scripts/export-pdf-reports.js [path/to/VulnerabilityDashboard.html]
 *
 * Output: reports/<ReportName>_<YYYY-MM-DD>.pdf
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const REPORTS = [
    { id: 'active-vulnerabilities', label: 'Active_Vulnerabilities' },
    { id: 'remediation-activity',   label: 'Remediation_Activity'   },
    { id: 'impact-analysis',        label: 'Impact_Analysis'        },
    { id: 'devices-by-remediation', label: 'Devices_by_Remediation' },
    { id: 'remediations-by-device', label: 'Remediations_by_Device' },
];

const PDF_GENERATE_TIMEOUT_MS = 120_000;
const RENDER_SETTLE_MS        = 1_500;
const DATA_INIT_MS            = 2_000;

(async () => {
    const htmlFile = path.resolve(process.argv[2] ?? 'VulnerabilityDashboard.html');

    if (!fs.existsSync(htmlFile)) {
        console.error(`Dashboard HTML not found: ${htmlFile}`);
        process.exit(1);
    }

    const reportsDir = path.resolve('reports');
    fs.mkdirSync(reportsDir, { recursive: true });

    const date = new Date().toISOString().slice(0, 10);

    const browser = await chromium.launch();
    const context = await browser.newContext({ acceptDownloads: true });
    const page    = await context.newPage();

    page.on('console', msg => {
        if (msg.type() === 'error') console.error('[page]', msg.text());
    });

    console.log(`Opening: ${htmlFile}`);
    await page.goto(`file://${htmlFile}`);

    // Wait for the dashboard to finish initialising data
    await page.waitForSelector('#reportSelector', { state: 'visible' });
    await page.waitForTimeout(DATA_INIT_MS);

    for (const report of REPORTS) {
        console.log(`Exporting: ${report.label}...`);

        await page.selectOption('#reportSelector', report.id);
        await page.waitForTimeout(RENDER_SETTLE_MS);

        const [download] = await Promise.all([
            page.waitForEvent('download', { timeout: PDF_GENERATE_TIMEOUT_MS }),
            page.click('.export-pdf-btn'),
        ]);

        const fileName = `${report.label}_${date}.pdf`;
        await download.saveAs(path.join(reportsDir, fileName));
        console.log(`  Saved: reports/${fileName}`);
    }

    await browser.close();
    console.log('All reports exported.');
})().catch(err => {
    console.error(err);
    process.exit(1);
});
