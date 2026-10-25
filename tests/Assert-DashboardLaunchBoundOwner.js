'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const Module = require('module');
const { EventEmitter } = require('events');
const { Writable, PassThrough } = require('stream');
const { spawnSync } = require('child_process');
const { LaunchBoundClient, parseProtocol } = require('./helpers/launch-bound-owner');

function fakeOwner(mode = '') {
    let client, terminal = false, exited = false;
    const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
    const exit = (code, signal = null) => { if (!exited) { exited = true; child.emit('exit', code, signal); child.stdout.end(); } };
    child.kill = () => { exit(125, 'SIGTERM'); return true; };
    child.stdin = new Writable({ write(bytes, encoding, done) {
        const request = JSON.parse(bytes.toString());
        client.testCommands.push(request.command);
        if (request.command === 'terminate') terminal = true;
        const value = { RunId: client.runId, ProfileKey: client.key, Created: true, Assigned: true, Resumed: true, Sealed: true,
            Terminal: terminal, Confirmed: terminal, Forced: terminal, StreamsComplete: terminal, WorkingSetBytes: terminal ? 0 : 11,
            PrivateBytes: terminal ? 0 : 17, ActiveProcesses: terminal ? 0 : 2, Pids: terminal ? [] : [101, 102], ExitCode: terminal ? 0 : null };
        let response = { v: 1, nonce: client.nonce, runId: client.runId, profile: client.profile, seq: request.seq, command: request.command, ok: true, value };
        if (request.command === 'query') {
            if (mode === 'wrong-run') response.runId = '0'.repeat(32);
            if (mode === 'wrong-profile') response.profile += '-neighbor';
            if (mode === 'wrong-nonce') response.nonce = '0'.repeat(64);
            if (mode === 'stale') response.seq--;
            if (mode === 'unknown-field') response.extra = true;
            if (mode === 'negative') value.PrivateBytes = -1;
            if (mode === 'missing-counter') delete value.WorkingSetBytes;
            if (mode === 'wrong-proof') value.ProfileKey = '0'.repeat(64);
            if (mode === 'false-clean') value.Confirmed = true;
            if (mode === 'cap') value.WorkingSetBytes = 2 * 1024 ** 3 + 1;
            if (mode === 'native-error') response = {v:1,nonce:client.nonce,runId:client.runId,profile:client.profile,seq:request.seq,ok:false,category:'owner-operation',nativeErrorCode:5,setup:{...value,Resumed:false}};
        }
        if (request.command === 'terminate' && mode === 'incomplete-stream') { value.Confirmed = false; value.StreamsComplete = false; }
        let text = JSON.stringify(response);
        if (request.command === 'query' && mode === 'duplicate') text = text.replace('"ok":true', '"ok":false,"ok":true');
        if (request.command === 'query' && mode === 'nested-duplicate') text = text.replace('"Forced":false', '"Forced":true,"Forced":false');
        queueMicrotask(() => {
            if (mode === 'owner-eof' && request.command === 'query' || mode === 'lost-completion' && request.command === 'dispose') exit(0);
            else { child.stdout.write(text + '\n'); if (request.command === 'dispose') setImmediate(() => exit(0)); }
        });
        done();
    } });
    client = new LaunchBoundClient(path.join(os.tmpdir(), 'synthetic-owner-profile'), () => child);
    client.testCommands = [];
    setImmediate(() => child.stdout.write(JSON.stringify({ v: 1, nonce: 'a'.repeat(64), ready: true }) + '\n'));
    return client;
}

async function checks() {
    assert.throws(() => parseProtocol('{"a":1,"a":2}'));
    assert.throws(() => parseProtocol('{"a":{"b":1,"b":2}}'));
    assert.deepStrictEqual(parseProtocol('{"a":["escaped\\\"key",1,true,null]}'), { a: ['escaped"key', 1, true, null] });
    const good = fakeOwner(); await good.ready;
    assert.deepStrictEqual(await good.inventory(), { bytes: 0, privateBytes: 0, pids: [] });
    await good.start('synthetic.exe', []);
    await assert.rejects(good.start('synthetic.exe', []), /One launch/);
    assert.deepStrictEqual(await good.inventory(), { bytes: 11, privateBytes: 17, pids: [101, 102] });
    await good.terminate(); await good.terminate();
    assert((await good.finish()).Confirmed && !good.failed);
    for (const mode of ['wrong-run','wrong-profile','wrong-nonce','stale','unknown-field','negative','missing-counter','wrong-proof','false-clean','duplicate','nested-duplicate','owner-eof','native-error']) {
        const owner = fakeOwner(mode); await owner.start('synthetic.exe', []);
        await assert.rejects(owner.inventory()); assert(owner.failed, mode);
        if (mode === 'native-error') assert(owner.setup.NativeErrorCode === 5 && owner.setup.Resumed === false);
        await assert.rejects(owner.inventory());
    }
    for (const mode of ['incomplete-stream','lost-completion']) {
        const owner = fakeOwner(mode); await owner.start('synthetic.exe', []);
        await assert.rejects(owner.finish()); assert(owner.failed, mode);
    }
    // Exercise the actual consumer cleanup and server/profile ordering without an OS process.
    const file = path.join(__dirname, 'Measure-DashboardWorkerTransfer.js');
    const loaded = new Module(file, module); loaded.filename = file; loaded.paths = Module._nodeModulePaths(__dirname);
    loaded._compile(fs.readFileSync(file, 'utf8') + '\nmodule.exports.ownerCleanup=cleanupOwned; module.exports.ownerServer=withServer; module.exports.ownerGuard=launchOwnerGuard;', file);
    for (const mode of ['', 'cap']) {
        const owner = fakeOwner(mode); await owner.start('synthetic.exe', []);
        const guard = loaded.exports.ownerGuard({ authority: owner }, { browserFamilyBytes: 2 * 1024 ** 3, freeMemoryBytes: 0 });
        if (mode === 'cap') await assert.rejects(guard.sample('bound-owner'), /cap exceeded/);
        else {
            await guard.sample('bound-owner');
            assert.strictEqual(guard.trace[0].browserFamilyBytes, 11);
            assert.strictEqual(guard.trace[0].browserFamilyPrivateBytes, 17);
            assert.strictEqual(guard.trace[0].ownedProcessCount, 2);
        }
        assert(owner.testCommands.includes('query'), 'Actual consumer guard must query the owner, never prelaunch zeros.');
        await guard.stop(); await owner.finish();
    }
    const retained = fs.mkdtempSync(path.join(os.tmpdir(), 'owner-unknown-fixture-'));
    try {
        const owner = fakeOwner('lost-completion'); await owner.start('synthetic.exe', []);
        const finalizers = [];
        const result = await loaded.exports.ownerCleanup({ profile: retained, authority: owner, profileFinalizers: finalizers });
        assert.strictEqual(result.remainingOwned, null); assert(result.profileExists && fs.existsSync(retained));
        assert(result.errors.includes('Final owned inventory'));
        await assert.rejects(finalizers[0](true));
        assert(result.errors.includes('Profile removal') && fs.existsSync(retained));
    } finally { assert(path.resolve(retained).startsWith(path.resolve(os.tmpdir()) + path.sep)); fs.rmSync(retained, {recursive:true,force:true}); }
    const notCreated = fs.mkdtempSync(path.join(os.tmpdir(), 'owner-constructor-fixture-'));
    try {
        const finalizers = [];
        const result = await loaded.exports.ownerCleanup({ launchBoundMode: true, profile: notCreated, profileFinalizers: finalizers });
        assert.strictEqual(result.remainingOwned, null); assert(result.profileExists && fs.existsSync(notCreated));
        await assert.rejects(finalizers[0](true)); assert(fs.existsSync(notCreated));
    } finally { assert(path.resolve(notCreated).startsWith(path.resolve(os.tmpdir()) + path.sep)); fs.rmSync(notCreated, {recursive:true,force:true}); }
    for (const failServer of [false,true]) {
        const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'owner-cleanup-fixture-'));
        try {
            const owner = fakeOwner(); await owner.start('synthetic.exe', []);
            const finalizers = []; const cleanup = await loaded.exports.ownerCleanup({ profile, authority: owner, profileFinalizers: finalizers, owned: { terminate() { throw Error('Legacy PID path forbidden'); } } });
            assert.strictEqual(cleanup.remainingOwned, 0); assert(cleanup.profileExists && cleanup.profileDeferred);
            const server = new EventEmitter(); server.listening = false;
            server.listen = (port, host, callback) => { server.listening = true; callback(); }; server.address = () => ({port:1});
            server.close = callback => { if (!failServer) server.listening = false; callback(failServer ? Error('synthetic') : undefined); }; server.closeAllConnections = () => {};
            const result = loaded.exports.ownerServer(server, {}, async () => {}, finalizers);
            if (failServer) { await assert.rejects(result); assert(fs.existsSync(profile)); }
            else { await result; assert(!fs.existsSync(profile)); assert(!cleanup.profileExists && !cleanup.profileDeferred); }
        } finally { assert(path.resolve(profile).startsWith(path.resolve(os.tmpdir()) + path.sep)); fs.rmSync(profile, {recursive:true,force:true}); }
    }
    const aggregate = spawnSync('pwsh', ['-NoProfile', '-File', path.join(__dirname, 'Invoke-LaunchBoundOwnerRegression.ps1')], { windowsHide: true, encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024 });
    assert(!aggregate.error && aggregate.status === 0, 'PowerShell synthetic owner/finalizer contract failed.');
    console.log('PASS launch-bound sole-client bindings, duplicate/stale/wrong receipts, EOF, memory units, double cleanup, stream uncertainty, and actual server-before-profile gate; PowerShell aggregate contract passed (synthetic only).');
}
checks().catch(error => { console.error(error); process.exitCode = 1; });
