'use strict';
// Explicit native contract entry point; default test discovery performs no native action.
// Requires the existing outer supervisor and an already installed Python fixture runtime.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
const { spawn } = require('child_process');
const { LaunchBoundClient } = require('./helpers/launch-bound-owner');

function observeOriginals(targets, directory) {
    const runId=crypto.randomBytes(16).toString('hex'),file=path.join(directory,'observed-identities.json');
    fs.writeFileSync(file,JSON.stringify(targets));
    const child=spawn('pwsh',['-NoProfile','-NonInteractive','-File',path.join(__dirname,'helpers/Wait-LaunchBoundFixtureExit.ps1'),'-TargetsPath',file,'-RunId',runId],{windowsHide:true,stdio:['pipe','pipe','pipe']});
    const input=readline.createInterface({input:child.stdout,crlfDelay:Infinity}); const queued=[];let pending,ended=false,code;
    const reject=()=>{if(pending){clearTimeout(pending.timer);pending.reject(Error('Read-only exit observer failed'));pending=null;}};
    input.on('line',line=>{
        try{assert(line.length<65536);const message=JSON.parse(line);assert(message.runId===runId);if(pending){const p=pending;pending=null;clearTimeout(p.timer);p.resolve(message);}else queued.push(message);}catch{reject();}
    });
    child.on('error',reject);const exit=new Promise(resolve=>child.once('exit',c=>{ended=true;code=c;reject();resolve();}));
    let stderr=0;child.stderr.on('data',b=>{stderr+=b.length;if(stderr>65536)reject();});
    const next=()=>queued.length?Promise.resolve(queued.shift()):ended?Promise.reject(Error('Observer endpoint ended')):new Promise((resolve,rejectPromise)=>{assert(!pending);pending={resolve,reject:rejectPromise,timer:setTimeout(reject,5000)};});
    return {child,next,exit,get code(){return code;},close(){if(!ended)child.kill();input.close();}};
}

async function main() {
    const [python, root] = process.argv.slice(2);
    assert(process.platform === 'win32' && python && root && path.isAbsolute(python) && path.isAbsolute(root));
    assert(!fs.existsSync(root), 'Fresh native fixture evidence required'); fs.mkdirSync(root, {recursive:true});
    const fixture = path.join(__dirname, 'helpers/launch-bound-fixture.py'); const results = [];
    const wait = async name => { const start = Date.now(); while (!fs.existsSync(name)) { assert(Date.now()-start < 5000, 'Fixture readiness exceeded budget'); await new Promise(r=>setTimeout(r,10)); } };
    for (const mode of ['normal','owner-crash','client-eof']) {
        const directory = path.join(root,mode), profile = path.join(directory,'profile'); fs.mkdirSync(profile,{recursive:true});
        const owner = new LaunchBoundClient(profile);
        let observer;
        try {
            await owner.start(python, [fixture,'--mode','root','--directory',directory,`--user-data-dir=${profile}`]);
            await wait(path.join(directory,'grandchild.json')); await wait(path.join(directory,'root-done'));
            const proof = await owner.request('query');
            assert(proof.ExitCode === 0 && proof.ActiveProcesses >= 2 && !proof.Terminal, 'Root exit lost descendants');
            if (mode==='normal') {
                const ended=await owner.finish(); assert(ended.Confirmed && ended.StreamsComplete && ended.ActiveProcesses===0);
                results.push({mode,confirmed:true});
            } else {
                const identities=['child','grandchild'].map(name=>JSON.parse(fs.readFileSync(path.join(directory,name+'.json'),'utf8')));
                const rootIdentity=JSON.parse(fs.readFileSync(path.join(directory,'root.json'),'utf8'));
                assert(new Set(identities.map(x=>x.pid)).size===2 && identities.every(x=>proof.Pids.includes(x.pid)));
                assert(proof.Pids.every(pid=>[rootIdentity.pid,...identities.map(x=>x.pid)].includes(pid)),'Unexpected native fixture member');
                observer=observeOriginals(identities,directory);
                const pinned=await observer.next();assert(pinned.stage==='pinned'&&pinned.count===2);
                if(mode==='owner-crash')owner.child.kill();else owner.child.stdin.end();
                await Promise.race([owner.exit,new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(Error('Owner loss exceeded budget')),5000);t.unref();})]);
                await assert.rejects(owner.inventory()); assert(owner.failed);
                const observed=observer.next();observer.child.stdin.end('observe\n');
                const exited=await observed;assert(exited.stage==='observed'&&exited.allExited===true);
                await observer.exit;assert(observer.code===0);
                results.push({mode,confirmed:false,originalHandleExitObserved:true,scope:'Owner loss is containment only, never a successful receipt.'});
            }
        } finally { if (!owner.exited) owner.abort();observer?.close(); }
    }
    fs.writeFileSync(path.join(root,'result.json'),JSON.stringify({status:'passed',cases:results,scope:'Native Node-owner IPC contract, not browser or historical qualification.'},null,2));
}
if (process.argv.length===2) console.log('SKIP explicit launch-bound native control: no native action requested.');
else main().catch(error=>{ console.error(error);process.exitCode=1; });
