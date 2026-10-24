'use strict';

// Offline diagnostic only. Native process APIs and root matching are mocked.
// This driver asserts a known defect in pinned revisions, not cleanup acceptance.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const pwsh = process.env.PWSH_EXECUTABLE || 'pwsh';
const refs = {
    parent: { sha: '63bf26ad27a274cd84aefc47f1f0779b4d397956', sha256: '53943bd0b2afc877670ed3d057365e2bee56291f8ffca8798e1cc638d120f6e6' },
    head: { sha: '5fdd5de9a2b0a048dea1235313472d4e5041c7b2', sha256: '1a82b09fa1a902ab5859ec19711d676e9e7cab471dc81f268c442c79580e01c9' }
};
const sourcePath = 'tests/Measure-DashboardWorkerTransfer.js';
let runRoot;
const fixture = [
    "$script:items = @($env:REVIEW_ITEMS | ConvertFrom-Json | ForEach-Object { $_.CreationDate = [datetime]$_.CreationDate; $_ })",
    "$script:killed = @()",
    "function Get-CimInstance {",
    " param($ClassName, $Filter, $ErrorAction)",
    " $copy = @($script:items | Select-Object *)",
    " if ($Filter -and $Filter.StartsWith('ProcessId=102 ')) { ($copy | Where-Object ProcessId -eq 102).CreationDate = $null }",
    " return $copy",
    "}",
    "function Get-Process {",
    " param($Id, $ErrorAction)",
    " $item = $script:items | Where-Object ProcessId -eq $Id",
    " if (-not $item) { return }",
    " $process = [pscustomobject]@{ Id=$Id; StartTime=$item.CreationDate; PrivateMemorySize64=1; HasExited=$false }",
    " $process | Add-Member ScriptMethod Kill { $script:killed += $this.Id; $this.HasExited=$true }",
    " $process | Add-Member ScriptMethod WaitForExit { param($remaining); return $true }",
    " $process",
    "}"
].join('\n');
const rootMatchShim = "function Test-OwnedRoot($item) { return $item.ProcessId -eq 101 -and $item.CommandLine -ceq 'owned-root' }\n$issue70Phase = 'cim'";

function load(label, repoRoot) {
    const ref = refs[label];
    const bytes = execFileSync('git', ['show', ref.sha + ':' + sourcePath], { cwd: repoRoot, timeout: 10000, maxBuffer: 1024 * 1024 });
    assert.strictEqual(crypto.createHash('sha256').update(bytes).digest('hex'), ref.sha256, 'Pinned source bytes differ.');
    const unused = () => { throw new Error('Dashboard loading is outside this diagnostic.'); };
    const scopedRequire = name => name === './helpers/dashboard-test-harness'
        ? { loadDashboardSource: unused, loadDashboardHarness: unused }
        : require(name);
    const sandbox = {
        require: scopedRequire, module: { exports: {} }, exports: {},
        process: { platform: 'win32', env: process.env }, console,
        __filename: sourcePath, __dirname: 'tests', Buffer,
        setTimeout, clearTimeout, setInterval, clearInterval, AbortController
    };
    vm.runInNewContext(bytes.toString('utf8') + '\nmodule.exports = { ownedProcesses, cleanupOwned };', sandbox, { filename: sourcePath });
    return sandbox.module.exports;
}
const item = (pid, parent, command, minute = 0) => ({
    ProcessId: pid, ParentProcessId: parent, Name: 'msedge.exe', CommandLine: command,
    CreationDate: '2026-10-24T00:0' + minute + ':00Z', WorkingSetSize: 1
});

async function exercise(label, mode, repoRoot) {
    const api = load(label, repoRoot);
    let items = [item(101, 0, 'owned-root')];
    if (mode === 'known-child-root-reuse') items.push(item(102, 101, 'renderer', 1));
    const trace = [];
    let started = false;
    const execute = async (script, environment) => {
        const terminating = script.includes("$issue70Phase = 'termination'");
        if (terminating && !started) {
            started = true;
            if (mode === 'new-child-orphan') items.push(item(102, 101, 'renderer', 1));
        }
        const adapted = script.replace("$issue70Phase = 'cim'", rootMatchShim);
        assert.notStrictEqual(adapted, script, 'Expected root-matching shim insertion point.');
        const wrapper = fixture + "\ntry { $result = . {\n" + adapted + "\n}; @{ result=($result | ConvertFrom-Json); killed=@($script:killed) } | ConvertTo-Json -Depth 8 -Compress } catch { @{ failure=$_.Exception.Message; killed=@($script:killed) } | ConvertTo-Json -Depth 8 -Compress }\n";
        const raw = execFileSync(pwsh, ['-NoLogo', '-NoProfile', '-Command', wrapper], {
            env: {
                ...process.env, ...environment, REVIEW_ITEMS: JSON.stringify(items),
                XDG_CACHE_HOME: path.join(runRoot, 'cache'),
                XDG_CONFIG_HOME: path.join(runRoot, 'config'),
                XDG_DATA_HOME: path.join(runRoot, 'data')
            },
            encoding: 'utf8', timeout: 20000, maxBuffer: 1024 * 1024,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        const response = JSON.parse(raw.trim());
        items = items.filter(row => !response.killed.includes(row.ProcessId));
        if (terminating && mode === 'known-child-root-reuse' && response.killed.includes(101)) {
            items.push(item(101, 0, 'unrelated-new-root', 2));
        }
        trace.push({
            phase: terminating ? 'termination' : 'inventory', result: response.result,
            failure: response.failure, killed: response.killed, liveSyntheticPids: items.map(row => row.ProcessId)
        });
        if (response.failure) throw new Error(response.failure);
        return response.result;
    };
    const profile = fs.mkdtempSync(path.join(runRoot, 'profile-'));
    try {
        const owned = api.ownedProcesses(profile, execute);
        await owned.inventory();
        const cleanup = await api.cleanupOwned({ profile, owned });
        const result = { revision: label, sourceCommit: refs[label].sha, mode, cleanup, liveSyntheticPids: items.map(row => row.ProcessId), trace };
        if (label === 'head') {
            assert.strictEqual(cleanup.remainingOwned, 0);
            assert.strictEqual(cleanup.profileExists, false);
            assert.strictEqual(cleanup.errors.length, 0);
            assert(items.some(row => row.ProcessId === 102));
        } else {
            assert(cleanup.errors.includes('Owned family termination'));
            assert.strictEqual(cleanup.profileExists, true);
        }
        return result;
    } finally {
        fs.rmSync(profile, { recursive: true, force: true });
    }
}

(async () => {
    const repoRoot = execFileSync('git', ['rev-parse', '--show-toplevel'], {
        cwd: __dirname, encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'pipe']
    }).trim();
    runRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'defender-review-offline-'));
    for (const name of ['cache', 'config', 'data']) fs.mkdirSync(path.join(runRoot, name));
    try {
        const results = [];
        for (const mode of ['new-child-orphan', 'known-child-root-reuse']) {
            for (const label of ['parent', 'head']) results.push(await exercise(label, mode, repoRoot));
        }
        console.log(JSON.stringify({
            scope: 'Offline pinned-source diagnostic; native process APIs/root matching are mocked. Exit zero confirms defect reproduction, not cleanup acceptance.',
            results
        }, null, 2));
    } finally {
        fs.rmSync(runRoot, { recursive: true, force: true });
    }
})().catch(() => {
    console.error('Offline diagnostic failed. Check existing Git/Node/PowerShell prerequisites and pinned source availability. No native process operations were requested.');
    process.exitCode = 1;
});

