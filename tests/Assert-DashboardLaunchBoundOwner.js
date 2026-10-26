'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const Module = require('module');
const { EventEmitter } = require('events');
const { Writable, PassThrough } = require('stream');
const { TextDecoder } = require('util');
const { spawnSync } = require('child_process');
const { LaunchBoundClient, parseProtocol } = require('./helpers/launch-bound-owner');
const { fixtureArguments,controlledArguments,verifyProduct } = require('./Assert-DashboardLaunchBoundNative');
const fakeOwnedPids=[101,102].map(pid=>pid===process.pid?103:pid);

function fakeOwner(mode = '', splitAt = null) {
    let client, startupExpected,terminal = false, exited = false;
    const child = new EventEmitter(); child.pid=process.pid+100000;child.stdout = new PassThrough(); child.stderr = new PassThrough();
    let exitCode,exitSignal,closed=false;
    const recordExit = (code, signal = null) => { if (!exited) { exited = true;exitCode=code;exitSignal=signal;child.emit('exit', code, signal); } };
    const close = () => { if(closed)return;closed=true;child.stdout.end();child.stderr.end();setImmediate(()=>child.emit('close',exitCode,exitSignal)); };
    const exit = (code, signal = null) => { recordExit(code,signal);close(); };
    child.kill = () => { exit(125, 'SIGTERM'); return true; };
    child.stdin = new Writable({ write(bytes, encoding, done) {
        const request = JSON.parse(bytes.toString());
        if(request.command==='bridge-ready'){
            assert(startupExpected);assert.deepStrictEqual(Object.keys(request).sort(),['actor','bridgeNonce','command','v']);assert(request.v===1&&request.bridgeNonce===startupExpected.nonce);assert.deepStrictEqual(request.actor,startupExpected.owner);client.testStartupAck=true;done();return;
        }
        client.testCommands.push(request.command);
        if (request.command === 'terminate') terminal = true;
        const value = { RunId: client.runId, ProfileKey: client.key, Created: true, Assigned: true, Resumed: true, Sealed: true, RootInOuterBeforeInner:true, OuterPolicyConfirmed:true, OuterJobLimitBytes:2*1024**3,
            Terminal: terminal, Confirmed: terminal, Forced: terminal, StreamsComplete: terminal, WorkingSetBytes: terminal ? 0 : 11,
            PrivateBytes: terminal ? 0 : 17, ActiveProcesses: terminal ? 0 : 2, Pids: terminal ? [] : fakeOwnedPids, ExitCode: terminal ? 0 : null };
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
            if (mode === 'unsafe-outer') value.OuterPolicyConfirmed = false;
            if (mode === 'root-outside') value.RootInOuterBeforeInner = false;
            if (mode === 'wrong-outer-cap') value.OuterJobLimitBytes = 4 * 1024 ** 3;
            if (mode === 'native-error') response = {v:1,nonce:client.nonce,runId:client.runId,profile:client.profile,seq:request.seq,ok:false,category:'owner-operation',nativeErrorCode:5,setup:{...value,Resumed:false}};
        }
        if (request.command === 'terminate' && mode === 'incomplete-stream') { value.Confirmed = false; value.StreamsComplete = false; }
        let text = JSON.stringify(response);
        if (request.command === 'query' && mode === 'duplicate') text = text.replace('"ok":true', '"ok":false,"ok":true');
        if (request.command === 'query' && mode === 'nested-duplicate') text = text.replace('"Forced":false', '"Forced":true,"Forced":false');
        queueMicrotask(() => {
            if (mode === 'owner-eof' && request.command === 'query' || mode === 'lost-completion' && request.command === 'dispose') exit(0);
            else {
                if(request.command==='query'&&mode==='query-after-exit')recordExit(0);
                if(request.command==='dispose'&&['exit-before-dispose','deferred-close','missing-dispose'].includes(mode))recordExit(0);
                if(request.command==='dispose'&&mode==='missing-dispose'){close();return;}
                const bytes=Buffer.from(text+(request.command==='dispose'&&mode==='unterminated'?'':'\n'));
                if(request.command==='query'&&mode==='invalid-utf8')child.stdout.write(Buffer.from([0xff,10]));
                else if(splitAt!==null){const at=bytes.indexOf(Buffer.from(client.profile))+splitAt;child.stdout.write(bytes.subarray(0,at));child.stdout.write(bytes.subarray(at));}
                else child.stdout.write(bytes);
                if(request.command==='dispose') {
                    recordExit(0);
                    if(mode==='deferred-close')return;
                    setImmediate(()=>{
                        if(mode==='late-tail')child.stdout.write('trailing');
                        if(mode==='extra-line')child.stdout.write('{}\n');
                        if(mode==='truncated-utf8')child.stdout.write(Buffer.from([0xc3]));
                        if(mode==='late-stderr')child.stderr.write(Buffer.alloc(32769));
                        close();
                    });
                }
            }
        });
        done();
    } });
    client = new LaunchBoundClient(path.join(os.tmpdir(), 'synthetic-owner-é😀'), () => child);
    client.testClose=close;
    client.testCommands = [];
    setImmediate(() => {
        const actor=(Pid,ParentPid,ImagePath)=>({Pid,ParentPid,ImagePath,CreationFileTime:'1'});
        const owner=actor(child.pid+1,child.pid,path.join(os.tmpdir(),'pwsh.exe'));
        const bridge={v:1,bridge:true,nonce:'b'.repeat(64),owner,bootstrap:actor(child.pid,process.pid,owner.ImagePath),node:actor(process.pid,process.ppid,process.execPath)};
        const ready={v:1,nonce:'a'.repeat(64),ready:true,bridgeNonce:bridge.nonce,actor:{...owner}};
        if(mode==='bridge-parent')bridge.bootstrap.ParentPid++;
        if(mode==='bridge-owner-pid')bridge.owner.ParentPid++;
        if(mode==='bridge-node-image')bridge.node.ImagePath=path.join(os.tmpdir(),'wrong-node.exe');
        if(mode==='actor-time')bridge.owner.CreationFileTime+='\n';
        if(mode==='ready-actor')ready.actor.CreationFileTime='2';
        if(mode==='ready-nonce')ready.bridgeNonce='c'.repeat(64);
        if(mode==='unknown-bridge-field')bridge.extra=true;
        startupExpected=bridge;
        const line=value=>child.stdout.write(JSON.stringify(value)+'\n');
        if(mode==='legacy-ready'){line({v:1,nonce:'a'.repeat(64),ready:true});return;}
        if(mode!=='missing-bridge')line(bridge);
        if(mode==='duplicate-bridge')line(bridge);
        if(!client.failed)line(ready);
    });
    return client;
}

async function checks() {
    for(const mode of ['bridge-parent','bridge-owner-pid','bridge-node-image','actor-time','ready-actor','ready-nonce','unknown-bridge-field','missing-bridge','duplicate-bridge','legacy-ready']){
        const client=fakeOwner(mode);await assert.rejects(client.start('fixture',[]));assert(client.failed && client.testCommands.length===0);
    }
    for(const value of ['', 'C:\\space path\\é', '\\\\server\\share\\path', 'colon:value quote" whitespace\t unicode-é😀', '\uFEFFleading BOM']) {
        const args=fixtureArguments('fixture.ps1','exit',value,'C:\\owned\\profile','a'.repeat(32),123,value);
        assert.strictEqual(args[6],'--directory-b64='+Buffer.from(value,'utf8').toString('base64'));
        assert.strictEqual(args[7],'--user-data-dir=C:\\owned\\profile');
        assert.strictEqual(args[10],'--echo-b64='+Buffer.from(value,'utf8').toString('base64'));
        assert.strictEqual(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(Buffer.from(args[6].slice('--directory-b64='.length),'base64')),value);
    }
    assert.throws(()=>fixtureArguments('fixture.ps1','exit','\uD800','C:\\owned\\profile','a'.repeat(32),123));
    for(const value of ['', 'spaces quote" trailing\\ unicode-é😀', '\uFEFFleading BOM']) {
        const args=controlledArguments('exit',value,'C:\\fixture\\profile','a'.repeat(32),123,'C:\\product\\fixture.product.json','b'.repeat(64),value);
        assert.deepStrictEqual(args,['--mode=exit','--directory-b64='+Buffer.from(value).toString('base64'),'--user-data-dir=C:\\fixture\\profile','--fixture-run='+'a'.repeat(32),'--parent-pid=123','--product-b64='+Buffer.from('C:\\product\\fixture.product.json').toString('base64'),'--product-sha256='+'b'.repeat(64),'--echo-b64='+Buffer.from(value).toString('base64')]);
    }
    for(const [mode,run,parent,hash] of [['unknown','a'.repeat(32),123,'b'.repeat(64)],['root','a'.repeat(32)+'\n',123,'b'.repeat(64)],['root','A'.repeat(32),123,'b'.repeat(64)],['root','a'.repeat(32),0,'b'.repeat(64)],['root','a'.repeat(32),123,'b'.repeat(64)+'\n']])assert.throws(()=>controlledArguments(mode,'C:\\fixture','C:\\fixture\\profile',run,parent,'C:\\product\\fixture.product.json',hash));
    assert.throws(()=>controlledArguments('exit','\uD800','C:\\fixture\\profile','a'.repeat(32),123,'C:\\product\\fixture.product.json','b'.repeat(64)));
    // File-content/PE checks use inert bytes; no assembly or executable is loaded.
    const productDirectory=fs.mkdtempSync(path.join(os.tmpdir(),'synthetic-product-'));
    const productPath=path.join(productDirectory,'fixture.product.json'),sha=bytes=>require('crypto').createHash('sha256').update(bytes).digest('hex');
    const executable=Buffer.alloc(256);executable.writeUInt16LE(0x5a4d,0);executable.writeInt32LE(64,0x3c);executable.writeUInt32LE(0x4550,64);executable.writeUInt16LE(0x8664,68);executable.writeUInt16LE(0x20b,88);executable.writeUInt16LE(2,156);
    const productNames=['LaunchBoundFixture.exe','LaunchBoundFixture.dll','LaunchBoundFixture.deps.json','LaunchBoundFixture.runtimeconfig.json'];
    const product={schema:1,runtimeVersion:'10.0.12',runtimeDirectory:path.resolve(productDirectory,'runtime'),sourceSha256:'a'.repeat(64),toolchainBindingSha256:'b'.repeat(64),files:productNames.map((name,index)=>{const bytes=index===0?executable:Buffer.from('inert'+index);fs.writeFileSync(path.join(productDirectory,name),bytes);return {path:name,bytes:bytes.length,sha256:sha(bytes)};})};
    const saveProduct=()=>{const bytes=Buffer.from(JSON.stringify(product));fs.writeFileSync(productPath,bytes);return sha(bytes);};
    let productHash=saveProduct();assert.strictEqual(verifyProduct(productPath,productHash).executable,path.join(productDirectory,productNames[0]));
    assert.throws(()=>verifyProduct(productPath,'c'.repeat(64)));
    fs.writeFileSync(path.join(productDirectory,'extra.dll'),'unbound');assert.throws(()=>verifyProduct(productPath,productHash));fs.unlinkSync(path.join(productDirectory,'extra.dll'));
    fs.appendFileSync(path.join(productDirectory,productNames[1]),'changed');assert.throws(()=>verifyProduct(productPath,productHash));fs.writeFileSync(path.join(productDirectory,productNames[1]),'inert1');
    executable.writeUInt16LE(3,156);fs.writeFileSync(path.join(productDirectory,productNames[0]),executable);product.files[0].sha256=sha(executable);productHash=saveProduct();assert.throws(()=>verifyProduct(productPath,productHash));
    // Preserve this tiny directory if any assertion fails; clean only this exact
    // mkdtemp-owned flat inventory after all expected outcomes are established.
    for(const name of [...productNames,'fixture.product.json'])fs.unlinkSync(path.join(productDirectory,name));fs.rmdirSync(productDirectory);
    assert.throws(() => parseProtocol('{"a":1,"a":2}'));
    assert.throws(() => parseProtocol('{"a":{"b":1,"b":2}}'));
    assert.deepStrictEqual(parseProtocol('{"a":["escaped\\\"key",1,true,null]}'), { a: ['escaped"key', 1, true, null] });
    const good = fakeOwner(); await good.ready;
    assert.deepStrictEqual(await good.inventory(), { bytes: 0, privateBytes: 0, pids: [] });
    await good.start('synthetic.exe', []);
    await assert.rejects(good.start('synthetic.exe', []), /One launch/);
    assert.deepStrictEqual(await good.inventory(), { bytes: 11, privateBytes: 17, pids: fakeOwnedPids });
    await good.terminate(); await good.terminate();
    assert((await good.finish()).Confirmed && !good.failed);
    for (const mode of ['wrong-run','wrong-profile','wrong-nonce','stale','unknown-field','negative','missing-counter','wrong-proof','false-clean','duplicate','nested-duplicate','owner-eof','native-error','unsafe-outer','root-outside','wrong-outer-cap','invalid-utf8','query-after-exit']) {
        const owner = fakeOwner(mode); await owner.start('synthetic.exe', []);
        await assert.rejects(owner.inventory()); assert(owner.failed, mode);
        if (mode === 'native-error') assert(owner.setup.NativeErrorCode === 5 && owner.setup.Resumed === false);
        await assert.rejects(owner.inventory());
    }
    for (const mode of ['incomplete-stream','lost-completion','missing-dispose','unterminated','late-tail','extra-line','truncated-utf8','late-stderr']) {
        const owner = fakeOwner(mode); await owner.start('synthetic.exe', []);
        await assert.rejects(owner.finish()); assert(owner.failed, mode);
    }
    for(let split=0;split<=Buffer.byteLength(good.profile);split++) {
        const owner=fakeOwner('',split);await owner.start('synthetic.exe',[]);await owner.inventory();assert((await owner.finish()).Confirmed&&!owner.failed);
    }
    const ordered=fakeOwner('exit-before-dispose');await ordered.start('synthetic.exe',[]);assert((await ordered.finish()).Confirmed&&!ordered.failed);
    const deferred=fakeOwner('deferred-close');await deferred.start('synthetic.exe',[]);let finished=false;
    const finishing=deferred.finish().then(value=>{finished=true;return value;});await new Promise(resolve=>setImmediate(resolve));
    assert(deferred.exited&&!finished,'Protocol success must await both streams and close');deferred.testClose();assert((await finishing).Confirmed);
    // The read-only observer must also drain a final line that arrives after process exit.
    const {observeOriginals}=require('./Assert-DashboardLaunchBoundNative');
    const observerFixture=fs.mkdtempSync(path.join(os.tmpdir(),'owner-observer-order-'));
    try {
        for(const mode of ['normal','missing','trailing']) {
            const directory=path.join(observerFixture,mode);fs.mkdirSync(directory);
            const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.stdin=new PassThrough();child.kill=()=>true;
            const observer=observeOriginals([{pid:1,creationFileTime:'1'}],directory,'synthetic.exe',()=>child);
            const reply=observer.next();child.emit('exit',0,null);
            if(mode!=='missing')child.stdout.write(JSON.stringify({runId:observer.runId,stage:'observed',allExited:true})+'\n');
            if(mode==='trailing')child.stdout.write(JSON.stringify({runId:observer.runId,stage:'observed',allExited:true})+'\n');
            child.stdout.end();child.stderr.end();await new Promise(resolve=>setImmediate(resolve));child.emit('close',0,null);
            if(mode==='missing'){await assert.rejects(reply);assert(observer.failed);}else{assert((await reply).allExited);await observer.exit;assert(observer.failed===(mode==='trailing')&&observer.code===0);}
        }
    } finally {assert(path.resolve(observerFixture).startsWith(path.resolve(os.tmpdir())+path.sep));fs.rmSync(observerFixture,{recursive:true,force:true});}
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
