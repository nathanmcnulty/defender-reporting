'use strict';
// Explicit existing-Node adapter controls. PowerShell constructs and orchestrates fixtures.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Module = require('module');
const { TextDecoder } = require('util');
const { spawn } = require('child_process');
const { LaunchBoundClient, parseProtocol } = require('./helpers/launch-bound-owner');

function encode(value) {assert(typeof value==='string');const bytes=Buffer.from(value,'utf8');assert(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes)===value,'Invalid fixture Unicode');return bytes.toString('base64');}
function fixtureArguments(fixture,mode,directory,profile,run,parent,echo='') {
    return ['-NoLogo','-NoProfile','-NonInteractive','-File',fixture,'--mode='+mode,'--directory-b64='+encode(directory),'--user-data-dir='+profile,'--fixture-run='+run,'--parent-pid='+parent,'--echo-b64='+encode(echo)];
}
function controlledArguments(mode,directory,profile,run,parent,manifest,hash,echo='') {
    assert(['root','late','child','grandchild','hold','fanout','exit','output','breakaway','early-error','early-error-output'].includes(mode));
    assert(typeof run==='string'&&run.length===32&&/^[a-f0-9]{32}$/.test(run)&&typeof hash==='string'&&hash.length===64&&/^[a-f0-9]{64}$/.test(hash)&&Number.isSafeInteger(parent)&&parent>0);
    return ['--mode='+mode,'--directory-b64='+encode(directory),'--user-data-dir='+profile,'--fixture-run='+run,'--parent-pid='+parent,'--product-b64='+encode(manifest),'--product-sha256='+hash,'--echo-b64='+encode(echo)];
}
function verifyProduct(manifest,hash) {
    assert(path.isAbsolute(manifest)&&path.basename(manifest)==='fixture.product.json'&&typeof hash==='string'&&hash.length===64&&/^[a-f0-9]{64}$/.test(hash));
    const read=(file,limit)=>{const fd=fs.openSync(file,'r');try{const size=fs.fstatSync(fd).size;assert(size>0&&size<=limit);const bytes=Buffer.alloc(size);let offset=0;while(offset<size){const count=fs.readSync(fd,bytes,offset,size-offset,null);assert(count>0);offset+=count;}assert(fs.fstatSync(fd).size===size);return bytes;}finally{fs.closeSync(fd);}};
    const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex'),bytes=read(manifest,65536);assert(sha(bytes)===hash);
    const product=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)),directory=path.dirname(manifest);
    assert(product.schema===1&&product.runtimeVersion==='10.0.12'&&path.isAbsolute(product.runtimeDirectory)&&/^[a-f0-9]{64}$/.test(product.sourceSha256)&&/^[a-f0-9]{64}$/.test(product.toolchainBindingSha256));
    const names=['LaunchBoundFixture.exe','LaunchBoundFixture.dll','LaunchBoundFixture.deps.json','LaunchBoundFixture.runtimeconfig.json'];
    assert.deepStrictEqual(product.files.map(file=>file.path),names);
    assert.deepStrictEqual(fs.readdirSync(directory).sort(),[...names,'fixture.product.json'].sort());
    for(const file of product.files){const data=read(path.join(directory,file.path),1024*1024);assert(data.length===file.bytes&&sha(data)===file.sha256);if(file.path.endsWith('.exe')){assert(data.length>=256&&data.readUInt16LE(0)===0x5a4d);const pe=data.readInt32LE(0x3c);assert(pe>=64&&pe<=data.length-94&&data.readUInt32LE(pe)===0x4550&&data.readUInt16LE(pe+4)===0x8664&&data.readUInt16LE(pe+24)===0x20b&&data.readUInt16LE(pe+92)===2);}}
    return {executable:path.join(directory,names[0]),manifest,hash,runtimeDirectory:product.runtimeDirectory};
}

function observeOriginals(targets, directory, powerShell, create = spawn) {
    const runId=crypto.randomBytes(16).toString('hex'),file=path.join(directory,'observed-identities.json');
    fs.writeFileSync(file,JSON.stringify(targets));
    const child=create(powerShell,['-NoProfile','-NonInteractive','-File',path.join(__dirname,'helpers/Wait-LaunchBoundFixtureExit.ps1'),'-TargetsPath',file,'-RunId',runId],{windowsHide:true,stdio:['pipe','pipe','pipe']});
    const queued=[];let pending,closed=false,exited=false,code,signal,stdoutEnded=false,stderrEnded=false,failed=false,buffer=Buffer.alloc(0);
    const decoder=new TextDecoder('utf-8',{fatal:true});
    const reject=()=>{failed=true;if(pending){clearTimeout(pending.timer);pending.reject(Error('Read-only exit observer failed'));pending=null;}};
    child.stdout.on('data',bytes=>{
        if(failed)return;
        buffer=Buffer.concat([buffer,bytes]);if(buffer.length>1024*1024)return reject();
        let end;while((end=buffer.indexOf(10))>=0){const frame=buffer.subarray(0,end);buffer=buffer.subarray(end+1);
            try{const message=parseProtocol(decoder.decode(frame));assert(message.runId===runId&&!failed);if(pending){const p=pending;pending=null;clearTimeout(p.timer);p.resolve(message);}else{assert(queued.length<4);queued.push(message);}}catch{reject();}
        }
    });
    child.stdout.once('end',()=>{stdoutEnded=true;if(buffer.length)reject();});
    child.stderr.once('end',()=>{stderrEnded=true;});
    for(const stream of [child.stdout,child.stderr,child.stdin])stream.once('error',reject);
    child.once('error',reject);child.once('exit',(c,s)=>{exited=true;code=c;signal=s;});
    const exit=new Promise(resolve=>child.once('close',(c,s)=>{closed=true;if(!exited||c!==code||s!==signal||!stdoutEnded||!stderrEnded||buffer.length||pending||queued.length)reject();resolve();}));
    let stderr=0;child.stderr.on('data',b=>{stderr+=b.length;if(stderr>65536)reject();});
    const next=()=>failed?Promise.reject(Error('Observer protocol unknown')):queued.length?Promise.resolve(queued.shift()):closed?Promise.reject(Error('Observer endpoint ended')):new Promise((resolve,rejectPromise)=>{assert(!pending);pending={resolve,reject:rejectPromise,timer:setTimeout(reject,5000)};});
    return {child,next,exit,get code(){return code;},get failed(){return failed;},get runId(){return runId;},get completion(){return {closed,exited,code,signal,stdoutEnded,stderrEnded,failed,bufferBytes:buffer.length,pending:!!pending,queued:queued.length};},close(){if(!exited)child.kill();}};
}
async function bounded(operation) {
    let timer;try{return await Promise.race([operation,new Promise((resolve,reject)=>{timer=setTimeout(()=>reject(Error('Fixture endpoint exceeded budget')),5000);})]);}finally{clearTimeout(timer);}
}
async function crashOriginalOwner(owner,powerShell,directory,rejectIdentity=false){
    const suffix=rejectIdentity?'identity-rejected':'owner-terminated';
    const context={Owner:{...owner.actor},Bootstrap:{...owner.bridge.bootstrap},Node:{...owner.bridge.node},RunId:owner.runId,ProfileKey:owner.key,SessionNonce:owner.nonce,BridgeNonce:owner.bridge.nonce};
    if(rejectIdentity)context.Owner.CreationFileTime=(BigInt(context.Owner.CreationFileTime)+1n).toString();
    const contextPath=path.join(directory,suffix+'.context.json'),proofPath=path.join(directory,suffix+'.proof.json');
    const bytes=Buffer.from(JSON.stringify(context)),hash=crypto.createHash('sha256').update(bytes).digest('hex');fs.writeFileSync(contextPath,bytes,{flag:'wx'});
    const child=spawn(powerShell,['-NoProfile','-NonInteractive','-File',path.join(__dirname,'helpers/Stop-LaunchBoundOwnerFixture.ps1'),'-ContextPath',contextPath,'-ContextSha256',hash,'-ProofPath',proofPath],{windowsHide:true,stdio:['pipe','pipe','pipe']});
    let stdout=Buffer.alloc(0),stderr=Buffer.alloc(0),outEnd=false,errEnd=false,failed=false;
    const fail=()=>{failed=true;try{child.kill();}catch{}};
    for(const stream of [child.stdin,child.stdout,child.stderr])stream.once('error',fail);child.once('error',fail);
    child.stdout.on('data',data=>{const keep=Math.min(data.length,65536-stdout.length);stdout=Buffer.concat([stdout,data.subarray(0,keep)]);if(keep!==data.length)fail();});
    child.stderr.on('data',data=>{const keep=Math.min(data.length,65536-stderr.length);stderr=Buffer.concat([stderr,data.subarray(0,keep)]);if(keep!==data.length)fail();});
    child.stdout.once('end',()=>outEnd=true);child.stderr.once('end',()=>errEnd=true);
    let timer;const ended=await new Promise(resolve=>{timer=setTimeout(fail,5000);child.once('close',(code,signal)=>resolve({code,signal}));});clearTimeout(timer);
    fs.writeFileSync(path.join(directory,suffix+'.stdout.log'),stdout,{flag:'wx'});fs.writeFileSync(path.join(directory,suffix+'.stderr.log'),stderr,{flag:'wx'});
    const endpoint={...ended,outEnd,errEnd,failed};fs.writeFileSync(path.join(directory,suffix+'.endpoint.json'),JSON.stringify(endpoint),{flag:'wx'});
    assert(!failed&&ended.signal===null&&outEnd&&errEnd,'Original owner crash control endpoint incomplete');
    assert(fs.statSync(proofPath).size<=131072,'Crash control proof exceeds cap');
    const proof=JSON.parse(fs.readFileSync(proofPath,'utf8'));
    if(rejectIdentity)assert(ended.code!==0&&proof.status==='failed'&&proof.category==='actor-identity-mismatch');
    else{
        assert(ended.code===0&&proof.status==='passed');const value=proof.proof;
        assert(value.ContextSha256===hash&&value.RunId===owner.runId&&value.ProfileKey===owner.key&&value.SessionNonce===owner.nonce&&value.BridgeNonce===owner.bridge.nonce&&value.OriginalHandleExitObserved===true&&value.ExitCode===125&&value.OuterPolicyConfirmed===true);
        assert.deepStrictEqual(value.Owner,owner.actor);assert.deepStrictEqual(value.Bootstrap,owner.bridge.bootstrap);assert.deepStrictEqual(value.Node,owner.bridge.node);
    }
    return {contextSha256:hash,endpoint,proof};
}
async function main() {
    const [powerShell, root, productManifest, productHash] = process.argv.slice(2);
    assert(process.platform==='win32'&&powerShell&&root&&path.isAbsolute(powerShell)&&path.isAbsolute(root)&&path.basename(powerShell).toLowerCase()==='pwsh.exe');
    assert(!fs.existsSync(root),'Fresh native fixture evidence required');fs.mkdirSync(root,{recursive:true});
    const product=verifyProduct(productManifest,productHash),results=[];
    const write=()=>fs.writeFileSync(path.join(root,'result.json'),JSON.stringify({status:results.length===4&&results.every(x=>x.status==='passed')?'passed':'failed',powerShell,product,cases:results,scope:'Controlled native family with real PowerShell IPC owner and restricted bootstrap; historical PowerShell host provenance, Edge and large-data acceptance remain separate.'},null,2));
    const wait=async name=>{const start=performance.now();while(!fs.existsSync(name)){assert(performance.now()-start<5000,'Fixture readiness exceeded budget');await new Promise(r=>setTimeout(r,10));}};
    const file=path.join(__dirname,'Measure-DashboardWorkerTransfer.js'),loaded=new Module(file,module);loaded.filename=file;loaded.paths=Module._nodeModulePaths(__dirname);
    loaded._compile(fs.readFileSync(file,'utf8')+'\nmodule.exports.ownerCleanup=cleanupOwned;',file);
    try {
        for(const mode of ['normal','owner-crash','bootstrap-crash','client-eof']) {
            const directory=path.join(root,mode),profile=path.join(directory,'profile');fs.mkdirSync(profile,{recursive:true});
            const outcome={mode,status:'running',confirmed:false};results.push(outcome);write();
            let owner,observer;
            try {
                owner=new LaunchBoundClient(profile);
                await owner.ready;outcome.actor=owner.actor;outcome.bridge=owner.bridge;outcome.stage='ready';write();
                assert(path.resolve(owner.actor.ImagePath).toUpperCase()===path.resolve(powerShell).toUpperCase());
                verifyProduct(productManifest,productHash);
                await owner.start(product.executable,controlledArguments('root',directory,profile,owner.runId,owner.actor.Pid,productManifest,productHash));
                await wait(path.join(directory,'grandchild.json'));await wait(path.join(directory,'root-done'));
                const proof=await owner.request('query');outcome.proof=proof;outcome.stage='census';write();
                const markers=[],markerErrors=[];
                for(const name of ['root','child','grandchild']){try{markers.push(JSON.parse(fs.readFileSync(path.join(directory,name+'.json'),'utf8')));}catch{markerErrors.push(name);}}
                const targets=[...proof.Pids.map(pid=>({pid,creationFileTime:markers.find(m=>m.pid===pid)?.creationFileTime||null})),{pid:owner.actor.Pid,creationFileTime:owner.actor.CreationFileTime}];
                const census={ownerPid:owner.actor.Pid,proof,markers,markerErrors};const saveCensus=()=>fs.writeFileSync(path.join(directory,'census.json'),JSON.stringify(census,null,2));saveCensus();
                if(proof.Pids.length===0||proof.Pids.length>128){census.retained={ready:false,members:proof.Pids.length?proof.Pids.map(Pid=>({Pid,State:'inspection-capacity-unknown'})):[{State:'empty-membership-unknown'}]};saveCensus();throw Error('Fixture member inspection unavailable');}
                observer=observeOriginals(targets,directory,powerShell);
                census.retained=await observer.next();saveCensus();
                assert(proof.ExitCode===0&&proof.ActiveProcesses>=2&&!proof.Terminal,'Root exit lost descendants');
                assert(markerErrors.length===0&&new Set(markers.map(m=>m.pid)).size===3&&markers.every(m=>m.runId===owner.runId&&m.productSha256===productHash));
                assert(census.retained.stage==='pinned'&&census.retained.count===proof.Pids.length+1&&census.retained.ready===true);
                const ownerMembers=census.retained.members.filter(member=>member.Pid===owner.actor.Pid);
                assert(ownerMembers.length===1);const actorMember=ownerMembers[0];
                assert(actorMember.State==='identified'&&actorMember.Live&&actorMember.ParentPid===owner.actor.ParentPid&&actorMember.CreationFileTime===owner.actor.CreationFileTime&&path.resolve(actorMember.ImagePath).toUpperCase()===path.resolve(powerShell).toUpperCase());
                census.fixtureMembers=census.retained.members.filter(member=>member.Pid!==owner.actor.Pid);census.ownerMember=actorMember;saveCensus();
                const [rootIdentity,child,grandchild]=markers;
                assert.deepStrictEqual(markers.map(marker=>marker.mode),['root','child','grandchild']);
                assert(rootIdentity.parent===owner.actor.Pid&&child.parent===rootIdentity.pid&&grandchild.parent===child.pid);
                assert(proof.Pids.length===2&&proof.Pids.includes(child.pid)&&proof.Pids.includes(grandchild.pid),'Unexpected native fixture member');
                census.births=[];
                for(const member of census.fixtureMembers){const marker=markers.find(m=>m.pid===member.Pid),birth=JSON.parse(fs.readFileSync(path.join(directory,'launch-diagnostics','birth-'+member.Pid+'.json'),'utf8'));census.births.push(birth);saveCensus();assert(marker&&member.State==='identified'&&member.Live&&member.ParentPid===marker.parent&&member.CreationFileTime===marker.creationFileTime&&path.resolve(member.ImagePath).toUpperCase()===path.resolve(product.executable).toUpperCase()&&path.resolve(marker.image).toUpperCase()===path.resolve(product.executable).toUpperCase());assert(birth.pid===member.Pid&&birth.parent===member.ParentPid&&birth.creationFileTime===member.CreationFileTime&&birth.runId===owner.runId&&birth.productSha256===productHash&&birth.mode===marker.mode&&path.resolve(birth.image).toUpperCase()===path.resolve(product.executable).toUpperCase());}
                const second=await owner.request('query');census.membershipRecheck=second;saveCensus();assert.deepStrictEqual(second.Pids,proof.Pids);
                const live=observer.next();observer.child.stdin.write('live\n');census.retainedLiveRecheck=await live;saveCensus();assert(census.retainedLiveRecheck.stage==='live'&&census.retainedLiveRecheck.allLive===true);
                outcome.stage='fully-identified';write();
                if(mode==='normal'){const ended=await owner.finish();outcome.completion=ended;write();assert(ended.Confirmed&&ended.StreamsComplete&&ended.ActiveProcesses===0&&ended.Pids.length===0);outcome.confirmed=true;}
                else {
                    if(mode==='owner-crash'){
                        outcome.identityRejection=await crashOriginalOwner(owner,powerShell,directory,true);write();
                        const unchanged=await owner.request('query');outcome.identityRejectionRecheck=unchanged;write();assert.deepStrictEqual(unchanged.Pids,proof.Pids);
                        assert(unchanged.WorkingSetBytes>0&&unchanged.PrivateBytes>0&&unchanged.ExitCode===0&&!unchanged.Terminal);
                        outcome.actorCrash=await crashOriginalOwner(owner,powerShell,directory);write();
                    }else if(mode==='bootstrap-crash')owner.child.kill();else owner.child.stdin.end();
                    await bounded(owner.exit);await assert.rejects(owner.inventory());assert(owner.failed);
                    const finalizers=[],cleanup=await loaded.exports.ownerCleanup({authority:owner,launchBoundMode:true,profile,profileFinalizers:finalizers});
                    await assert.rejects(finalizers[0](true));assert(cleanup.remainingOwned===null&&cleanup.profileExists&&fs.existsSync(profile));outcome.cleanup=cleanup;
                }
                const observed=observer.next();observer.child.stdin.end('observe\n');const exited=await observed;
                outcome.exitObservation=exited;write();assert(exited.stage==='observed'&&exited.allExited===true);await bounded(observer.exit);outcome.observerCompletion=observer.completion;write();assert(observer.code===0&&!observer.failed);
                verifyProduct(productManifest,productHash);outcome.originalHandleExitObserved=true;outcome.status='passed';outcome.stage='complete';write();
            } catch(error) {outcome.status='failed';outcome.ownerSetup=owner?.setup??null;outcome.actor=owner?.actor??null;outcome.bridge=owner?.bridge??null;outcome.error={type:error.name,message:error.message};throw error;}
            finally {if(owner&&!owner.exited)owner.abort();observer?.close();write();}
        }
    } finally {write();}
}
module.exports={observeOriginals,fixtureArguments,controlledArguments,verifyProduct};
if(require.main===module){if(process.argv.length===2)console.log('SKIP explicit launch-bound native control: no native action requested.');else main().catch(error=>{console.error(error);process.exitCode=1;});}
