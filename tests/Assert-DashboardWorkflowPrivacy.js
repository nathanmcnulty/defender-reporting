const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync, spawnSync } = require('node:child_process');
const { isAllowedRepository, isOutput, stageOutputs } = require('../.github/scripts/stage-demo-outputs');
const root = path.resolve(__dirname, '..');
const guard = "(github.repository == 'nathanmcnulty/defender-reporting' && github.ref == 'refs/heads/main') || github.event.repository.private == true";
const yaml = fs.readFileSync(path.join(root, '.github/workflows/update-vulnerability-dashboard.yml'), 'utf8').replace(/\r\n/g, '\n');
const match = yaml.match(/jobs:\s*\n  [\w-]+:\s*\n    if: \$\{\{ (.+) \}\}/);
assert.equal(match?.[1], guard, 'Admission must precede all checkout/auth/live steps');
let cases = 0;
for (const repository of ['nathanmcnulty/defender-reporting', 'someone/fork', 'nathanmcnulty/another-repo']) {
    for (const ref of ['refs/heads/main', 'refs/heads/feature', 'refs/tags/main', undefined]) {
        for (const privacy of [true, false, undefined, null, 'true']) {
            const event = { repository: { private: privacy } };
            const expected = privacy === true || (repository === 'nathanmcnulty/defender-reporting' && ref === 'refs/heads/main');
            assert.equal(isAllowedRepository(repository, event, ref), expected);
            // GitHub's repository privacy is boolean/null, never user input.
            assert.equal(vm.runInNewContext(match[1], { github: { repository, ref, event } }), expected);
            cases++;
        }
    }
}
assert.equal(isAllowedRepository('someone/fork', {}, 'refs/heads/main'), false);
assert.match(yaml, /cron: '0 2 \* \* \*'/);
assert.match(yaml, /    permissions:\n      contents: write\n      id-token: write/);
assert.match(yaml, /node \.github\/scripts\/stage-demo-outputs\.js dashboard/);
assert.match(yaml, /git push origin "HEAD:\$GITHUB_REF"/);
assert.doesNotMatch(yaml, /git add|always\(\)|reports\/|Export-Pdf/i);
assert.equal((yaml.match(/if: \$\{\{ !inputs\.dry_run \}\}/g) || []).length, 3);
assert.match(yaml, /path: VulnerabilityDashboard\.html\n          if-no-files-found: error\n          retention-days: 30/);
assert.match(yaml, /-UseRepositoryOutputPaths -ValidationOutputPath \.local\/dashboard-audit\.json -ManifestOutputPath \.local\/dashboard-live-run-manifest\.json/);
// PDF stays read-only, private-only and manual; this change grants it no publication path.
const pdf = fs.readFileSync(path.join(root, '.github/workflows/export-pdf-reports.yml'), 'utf8');
assert.match(pdf, /if: \$\{\{ github\.event\.repository\.private == true \}\}/);
assert.match(pdf, /permissions:\n  actions: read\n  contents: read/);
assert.doesNotMatch(pdf, /contents: write|id-token: write|git push|upload-artifact|stage-demo-outputs/);
assert.throws(() => isOutput('pdf', 'reports/Active_Vulnerabilities_2026-01-01.pdf'), /Unknown output mode/);
const validation = fs.readFileSync(path.join(root, '.github/workflows/validate-dashboard.yml'), 'utf8');
assert.doesNotMatch(validation, /repository\.private|AZURE_CLIENT_ID|id-token: write/);
assert.match(validation, /\.github\/scripts\/stage-demo-outputs\.js/);
for (const file of ['exports/token.json', 'exports/response.json', 'exports/.lock', 'exports/.staging/Machines_Current.json.gz', 'exports/NvdCve_Current.json.gz', 'reports/secret.pdf', 'dashboard-audit.json', 'exports/Machines_Current.json.gz/extra', 'exports/Machines_History_2026Q5.json.gz']) {
    assert.equal(isOutput('dashboard', file), false, file);
}
for (const file of ['VulnExport_current', 'VulnContentDictionary', 'VulnCurrentRefs', 'VulnHistory_2025', 'VulnHistoryRows_2025', 'VulnHistoryRefs_2025', 'VulnHistoryRefs_2026Q1', 'Machines_Current', 'Machines_History', 'Machines_History_2026Q1', 'Machines_History_20260101T000000Z_abcdef01', 'AdvancedHunting_Current']) {
    assert.equal(isOutput('dashboard', `exports/${file}.json.gz`), true, file);
}
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
    git('add', '--force', '--', '.gitignore', 'exports/Machines_History_2026Q1.json.gz');
    git('commit', '--quiet', '-m', 'Synthetic baseline');
    fs.unlinkSync(path.join(temp, 'exports/Machines_History_2026Q1.json.gz'));
    write('exports/Machines_Current.json.gz');
    write('exports/client-secret.json', 'synthetic-placeholder');
    write('exports/.staging/Machines_Current.json.gz');
    write('VulnerabilityDashboard.html');
    write('unrelated.txt');
    stageOutputs('dashboard', temp);
    assert.deepEqual(git('diff', '--cached', '--no-renames', '--name-only').trim().split(/\r?\n/), [
        'VulnerabilityDashboard.html', 'exports/Machines_Current.json.gz', 'exports/Machines_History_2026Q1.json.gz',
    ]);
    assert.throws(() => stageOutputs('dashboard', temp), /empty index/);
    git('reset', '--quiet');
    assert.throws(() => stageOutputs('pdf', temp), /Unknown output mode/);
    assert.throws(() => stageOutputs('unknown', temp), /Unknown output mode/);
    // Exercise the actual CLI guard with synthetic events, without any authentication.
    write('event.json', JSON.stringify({ repository: { private: false } }));
    for (const [repository, ref] of [['someone/fork', 'refs/heads/main'], ['nathanmcnulty/defender-reporting', 'refs/heads/feature'], ['nathanmcnulty/defender-reporting', 'refs/tags/main']]) {
        const result = spawnSync(process.execPath, [path.join(root, '.github/scripts/stage-demo-outputs.js'), 'dashboard'], {
            cwd: temp, encoding: 'utf8', env: { ...process.env, GITHUB_EVENT_PATH: path.join(temp, 'event.json'), GITHUB_REPOSITORY: repository, GITHUB_REF: ref },
        });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /Live publication is not allowed/);
        assert.equal(git('diff', '--cached', '--name-only'), '');
    }
    // Check the admitted CLI path as well as the pure admission function.
    execFileSync(process.execPath, [path.join(root, '.github/scripts/stage-demo-outputs.js'), 'dashboard'], {
        cwd: temp, env: { ...process.env, GITHUB_EVENT_PATH: path.join(temp, 'event.json'), GITHUB_REPOSITORY: 'nathanmcnulty/defender-reporting', GITHUB_REF: 'refs/heads/main' },
    });
    assert.match(git('diff', '--cached', '--name-only'), /VulnerabilityDashboard\.html/);
    git('reset', '--quiet');
    // Whole-set validation rejects a directory or symlink before staging anything.
    fs.unlinkSync(path.join(temp, 'exports/Machines_Current.json.gz'));
    fs.mkdirSync(path.join(temp, 'exports/Machines_Current.json.gz'));
    assert.throws(() => stageOutputs('dashboard', temp), /regular file/);
    assert.equal(git('diff', '--cached', '--name-only'), '');
    fs.rmdirSync(path.join(temp, 'exports/Machines_Current.json.gz'));
    fs.symlinkSync('../unrelated.txt', path.join(temp, 'exports/Machines_Current.json.gz'));
    assert.throws(() => stageOutputs('dashboard', temp), /regular file/);
    assert.equal(git('diff', '--cached', '--name-only'), '');
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}
console.log(`Dashboard admission (${cases} cases), allowlist, isolated staging and PDF nonpublication checks passed.`);
