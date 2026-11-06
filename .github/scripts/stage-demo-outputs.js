// Stage only the pipeline's canonical outputs, including removed history/PDF files.
// Output directories remain ignored to keep ordinary local git add operations safe.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const exportName = /^(?:VulnExport_current|VulnContentDictionary|VulnCurrentRefs|VulnHistory(?:Rows|Refs)?_\d{4}(?:Q[1-4])?|Machines_Current|Machines_History(?:_\d{4}Q[1-4]|_\d{8}T\d{6}Z_[a-f0-9]{8})?|AdvancedHunting_Current)\.json\.gz$/;
const pdfName = /^(?:Active_Vulnerabilities|Remediation_Activity|Impact_Analysis|Devices_by_Remediation|Remediations_by_Device)_\d{4}-\d{2}-\d{2}\.pdf$/;

function isAllowedRepository(repository, event) {
    return repository === 'nathanmcnulty/defender-reporting' || event?.repository?.private === true;
}

function isOutput(mode, file) {
    if (mode === 'dashboard') {
        return file === 'VulnerabilityDashboard.html' ||
            (file.startsWith('exports/') && exportName.test(file.slice('exports/'.length)));
    }
    if (mode === 'pdf') return file.startsWith('reports/') && pdfName.test(file.slice('reports/'.length));
    throw new Error('Unknown output mode');
}

function stageOutputs(mode, cwd = process.cwd()) {
    if (!['dashboard', 'pdf'].includes(mode)) throw new Error('Unknown output mode');
    const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8' });
    if (git('diff', '--cached', '--name-only', '-z')) throw new Error('Expected an empty index');
    const files = new Set(git('ls-files', '-z').split('\0').filter(Boolean));
    for (const directory of mode === 'dashboard' ? ['exports'] : ['reports']) {
        const fullPath = path.join(cwd, directory);
        if (!fs.existsSync(fullPath)) continue;
        if (!fs.lstatSync(fullPath).isDirectory() || fs.lstatSync(fullPath).isSymbolicLink()) {
            throw new Error('Output directory must be a real directory');
        }
        for (const entry of fs.readdirSync(fullPath)) files.add(`${directory}/${entry}`);
    }
    if (mode === 'dashboard' && fs.existsSync(path.join(cwd, 'VulnerabilityDashboard.html'))) {
        files.add('VulnerabilityDashboard.html');
    }
    const outputs = [...files].filter(file => isOutput(mode, file)).sort();
    // Validate the entire set before staging any of it. Never follow output symlinks.
    for (const file of outputs) {
        const fullPath = path.join(cwd, file);
        let stat;
        try { stat = fs.lstatSync(fullPath); }
        catch (error) { if (error.code !== 'ENOENT') throw error; }
        if (stat && !stat.isFile()) throw new Error('Output must be a regular file');
    }
    for (const file of outputs) git('add', '--force', '--all', '--', file);
    return outputs.length;
}

if (require.main === module) {
    const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    if (!isAllowedRepository(process.env.GITHUB_REPOSITORY, event)) throw new Error('Live publication is not allowed in this repository');
    stageOutputs(process.argv[2]);
}

module.exports = { isAllowedRepository, isOutput, stageOutputs };
