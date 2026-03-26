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
const os = require('os');

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

function copyFileIntoDirectory(sourcePath, directoryPath, fileName) {
    const targetPath = path.join(directoryPath, fileName);
    fs.copyFileSync(sourcePath, targetPath);
    return targetPath;
}

function listExistingReportFiles(reportsDir) {
    const existingFiles = [];

    for (const report of REPORTS) {
        const filePattern = new RegExp(`^${report.label}_\\d{4}-\\d{2}-\\d{2}\\.pdf$`);
        for (const entry of fs.readdirSync(reportsDir, { withFileTypes: true })) {
            if (!entry.isFile()) continue;
            if (!filePattern.test(entry.name)) continue;
            existingFiles.push(entry.name);
        }
    }

    return [...new Set(existingFiles)];
}

(async () => {
    const htmlFile = path.resolve(process.argv[2] ?? 'VulnerabilityDashboard.html');

    if (!fs.existsSync(htmlFile)) {
        console.error(`Dashboard HTML not found: ${htmlFile}`);
        process.exit(1);
    }

    const reportsDir = path.resolve('reports');
    fs.mkdirSync(reportsDir, { recursive: true });
    const stagingDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dashboard-pdf-export-'));
    const finalizationDir = fs.mkdtempSync(path.join(reportsDir, '.dashboard-pdf-finalize-'));
    const backupDir = fs.mkdtempSync(path.join(reportsDir, '.dashboard-pdf-backup-'));

    const date = new Date().toISOString().slice(0, 10);
    let browser;
    let context;
    const installedFiles = [];
    const backedUpFiles = [];

    try {
        browser = await chromium.launch();
        context = await browser.newContext({ acceptDownloads: true });
        const page = await context.newPage();

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
            await download.saveAs(path.join(stagingDir, fileName));
            console.log(`  Staged: reports/${fileName}`);
        }

        for (const fileName of fs.readdirSync(stagingDir)) {
            copyFileIntoDirectory(path.join(stagingDir, fileName), finalizationDir, fileName);
        }

        for (const fileName of listExistingReportFiles(reportsDir)) {
            fs.renameSync(
                path.join(reportsDir, fileName),
                path.join(backupDir, fileName),
            );
            backedUpFiles.push(fileName);
        }

        try {
            for (const fileName of fs.readdirSync(finalizationDir)) {
                fs.renameSync(
                    path.join(finalizationDir, fileName),
                    path.join(reportsDir, fileName),
                );
                installedFiles.push(fileName);
                console.log(`  Saved: reports/${fileName}`);
            }
        }
        catch (error) {
            for (const fileName of installedFiles) {
                const targetPath = path.join(reportsDir, fileName);
                if (fs.existsSync(targetPath)) {
                    fs.rmSync(targetPath, { force: true });
                }
            }

            for (const fileName of backedUpFiles) {
                const backupPath = path.join(backupDir, fileName);
                if (fs.existsSync(backupPath)) {
                    fs.renameSync(backupPath, path.join(reportsDir, fileName));
                }
            }

            throw error;
        }

        console.log('All reports exported.');
    }
    finally {
        if (context) {
            await context.close().catch(() => {});
        }
        if (browser) {
            await browser.close().catch(() => {});
        }

        fs.rmSync(stagingDir, { recursive: true, force: true });
        fs.rmSync(finalizationDir, { recursive: true, force: true });
        fs.rmSync(backupDir, { recursive: true, force: true });
    }
})().catch(err => {
    console.error(err);
    process.exit(1);
});
