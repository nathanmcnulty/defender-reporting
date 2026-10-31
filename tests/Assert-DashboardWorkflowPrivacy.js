const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync } = require('node:child_process');
const { isAllowedRepository, isOutput, stageOutputs } = require('../.github/scripts/stage-demo-outputs');

const root = path.resolve(__dirname, '..');
const guard = "github.repository == 'nathanmcnulty/defender-reporting' || github.event.repository.private == true";
const matrix = [
    ['nathanmcnulty/defender-reporting', false, true],
    ['nathanmcnulty/defender-reporting', true, true],
    ['someone/fork', true, true],
    ['someone/fork', false, false],
    ['nathanmcnulty/another-repo', false, false],
    ['someone/defender-reporting', undefined, false],
    ['someone/fork', 'true', false],
];
for (const name of ['update-vulnerability-dashboard', 'export-pdf-reports']) {
    const yaml = fs.readFileSync(path.join(root, `.github/workflows/${name}.yml`), 'utf8').replace(/\r\n/g, '\n');
    // The admission condition must be job-level, ahead of every checkout/auth/logging step.
    const match = yaml.match(/jobs:\s*\n  [\w-]+:\s*\n    if: \$\{\{ (.+) \}\}/);
    assert.equal(match?.[1], guard);
    for (const [repository, privateValue, allowed] of matrix) {
        const event = { repository: { private: privateValue } };
        // GitHub compares booleans with coercion; missing context values behave as null.
        // Event privacy is a GitHub-provided boolean, never a workflow input.
        if (typeof privateValue === 'boolean' || privateValue === undefined) {
            assert.equal(vm.runInNewContext(match[1], { github: { repository, event } }), allowed);
        }
        assert.equal(isAllowedRepository(repository, event), allowed);
    }
    assert.match(yaml, /    permissions:\n      contents: write/);
    assert.doesNotMatch(yaml, /git add|always\(\)/);
    assert.match(yaml, /node \.github\/scripts\/stage-demo-outputs\.js/);
    assert.match(yaml, /git push origin "HEAD:\$GITHUB_REF"/);
}
assert.equal(isAllowedRepository('someone/fork', {}), false);
const validation = fs.readFileSync(path.join(root, '.github/workflows/validate-dashboard.yml'), 'utf8');
assert.doesNotMatch(validation, /repository\.private|AZURE_CLIENT_ID|id-token: write/);
const preflight = fs.readFileSync(path.join(root, 'build/Invoke-RegressionValidation.ps1'), 'utf8');
assert.match(preflight, /Assert-Dashboard\*\.js/);
assert.match(preflight, /tests\\fixtures\\legacy-migration/);
assert.doesNotMatch(preflight, /Join-Path \$repoRoot 'exports'/);
for (const file of ['exports/token.json', 'exports/response.json', 'exports/.lock', 'exports/.staging/Machines_Current.json.gz', 'reports/secret.pdf']) {
    assert.equal(isOutput('dashboard', file) || isOutput('pdf', file), false);
}
for (const file of ['VulnHistory_2025', 'VulnHistoryRows_2025', 'VulnHistoryRefs_2025', 'VulnHistoryRefs_2026Q1']) {
    assert.equal(isOutput('dashboard', `exports/${file}.json.gz`), true);
}

// Exercise actual Git staging with ignored outputs, history deletion, and unrelated files.
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'dashboard-publication-test-'));
const git = (...args) => execFileSync('git', args, { cwd: temp, encoding: 'utf8' });
const write = (file, content = 'synthetic') => {
    fs.mkdirSync(path.dirname(path.join(temp, file)), { recursive: true });
    fs.writeFileSync(path.join(temp, file), content);
};
try {
    git('init', '--quiet');
    git('config', 'user.name', 'Offline Test');
    git('config', 'user.email', 'test@example.invalid');
    write('.gitignore', '/exports/\n/VulnerabilityDashboard.html\n/reports/*.pdf\n');
    write('exports/Machines_History_2026Q1.json.gz');
    write('reports/Active_Vulnerabilities_2026-01-01.pdf');
    git('add', '--force', '--', '.gitignore', 'exports/Machines_History_2026Q1.json.gz', 'reports/Active_Vulnerabilities_2026-01-01.pdf');
    git('commit', '--quiet', '-m', 'Synthetic baseline');
    fs.unlinkSync(path.join(temp, 'exports/Machines_History_2026Q1.json.gz'));
    write('exports/Machines_Current.json.gz');
    write('exports/client-secret.json', 'dummy-test-value');
    write('exports/.staging/Machines_Current.json.gz');
    write('VulnerabilityDashboard.html');
    write('unrelated.txt');
    stageOutputs('dashboard', temp);
    assert.deepEqual(git('diff', '--cached', '--no-renames', '--name-only').trim().split(/\r?\n/), [
        'VulnerabilityDashboard.html', 'exports/Machines_Current.json.gz', 'exports/Machines_History_2026Q1.json.gz',
    ]);
    assert.throws(() => stageOutputs('pdf', temp), /empty index/);
    git('reset', '--quiet');
    fs.unlinkSync(path.join(temp, 'reports/Active_Vulnerabilities_2026-01-01.pdf'));
    write('reports/Active_Vulnerabilities_2026-10-31.pdf');
    write('reports/secret.pdf');
    stageOutputs('pdf', temp);
    assert.deepEqual(git('diff', '--cached', '--no-renames', '--name-only').trim().split(/\r?\n/), [
        'reports/Active_Vulnerabilities_2026-01-01.pdf', 'reports/Active_Vulnerabilities_2026-10-31.pdf',
    ]);
    git('reset', '--quiet');
    assert.throws(() => stageOutputs('unknown', temp), /Unknown output mode/);
    // A directory at an allowlisted filename cannot be staged recursively.
    fs.unlinkSync(path.join(temp, 'exports/Machines_Current.json.gz'));
    fs.mkdirSync(path.join(temp, 'exports/Machines_Current.json.gz'));
    assert.throws(() => stageOutputs('dashboard', temp), /regular file/);
    assert.equal(git('diff', '--cached', '--name-only'), '');
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}
console.log('Workflow admission matrix and isolated demo staging regressions passed.');
