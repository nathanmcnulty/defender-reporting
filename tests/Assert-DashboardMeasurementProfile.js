'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Module = require('module');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { LaunchBoundClient } = require('./helpers/launch-bound-owner');

// Exercise the production profile creation boundary, stopping before any owner
// process or browser is started. A real filesystem profile catches Windows 8.3
// aliases that differ from .NET GetFullPath's expanded spelling.
(async () => {
    const filename = path.join(__dirname, 'Measure-DashboardWorkerTransfer.js');
    const loaded = new Module(filename, module);
    loaded.filename = filename;
    loaded.paths = Module._nodeModulePaths(__dirname);
    const originalRequire = loaded.require.bind(loaded);
    let profile, rawProfile;
    const stopped = new Error('Profile boundary captured');
    loaded.require = name => {
        if (name === './helpers/launch-bound-owner') return { LaunchBoundClient: class { constructor(value) { profile = value; throw stopped; } } };
        if (name === 'fs') return { ...fs, mkdtempSync(prefix) { rawProfile = fs.mkdtempSync(prefix); return rawProfile; } };
        return originalRequire(name);
    };
    loaded._compile(fs.readFileSync(filename, 'utf8') + '\nmodule.exports.profileBoundary = measureIteration;', filename);
    try {
        await assert.rejects(loaded.exports.profileBoundary({ evidence: { cleanups: [] }, iteration: 1, profileFinalizers: [] }), error => error === stopped);
        assert(profile && fs.statSync(profile).isDirectory());
        assert.strictEqual(profile, fs.realpathSync.native(profile), 'Measurement profile must use its native canonical spelling');
        const aliasExercised = rawProfile !== fs.realpathSync.native(rawProfile);
        if (process.env.MEASUREMENT_PROFILE_REQUIRE_ALIAS === '1') assert(aliasExercised, 'This confirmation must exercise an actual filesystem alias');
        const runId = 'a'.repeat(32);
        const key = crypto.createHash('sha256').update(path.resolve(profile).replace(/\//g, '\\').replace(/\\+$/, '').toUpperCase()).digest('hex');
        assert.throws(() => LaunchBoundClient.prototype.validate.call({ runId, key }, { RunId: runId, ProfileKey: '0'.repeat(64) }), assert.AssertionError);
        if (process.platform === 'win32') {
            const powerShell = path.join(process.env.ProgramFiles, 'PowerShell', '7', 'pwsh.exe');
            const probe = spawnSync(powerShell, ['-NoProfile', '-NonInteractive', '-Command',
                "Add-Type -Path $env:PROFILE_TEST_SOURCE; $p=[IO.Path]::GetFullPath($env:PROFILE_TEST_PATH); [LaunchBound.JobOwner]::new(('a'*32),$p).ProfileKey"],
            { windowsHide: true, encoding: 'utf8', timeout: 30000, maxBuffer: 65536,
                env: { ...process.env, PROFILE_TEST_SOURCE: path.join(__dirname, 'helpers', 'LaunchBoundJob.cs'), PROFILE_TEST_PATH: profile } });
            assert(!probe.error && probe.status === 0, 'Browser-free .NET profile-key probe must complete');
            assert.strictEqual(probe.stdout.trim(), key, 'Production profile must yield the same Node and .NET key');
        }
        console.log('PASS native measurement profile spelling, Node/.NET key agreement on Windows, and mismatched-key rejection; no owner or browser launched.');
        console.log(JSON.stringify({ aliasExercised, windowsKeyProbe: process.platform === 'win32' }));
    } finally {
        if (profile) fs.rmdirSync(profile);
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
