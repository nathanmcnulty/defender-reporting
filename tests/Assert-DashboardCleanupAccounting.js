'use strict';
// Process APIs and Windows argv/platform behavior are explicitly synthetic; only fresh fixture profiles are removed.
const assert=require('assert'),fs=require('fs'),vm=require('vm'),cp=require('child_process'),path=require('path'),os=require('os');
assert(process.argv.length===2 || (process.argv.length===4 && process.argv[2]==='--source'),'Usage: node Assert-DashboardCleanupAccounting.js [--source EXACT_SOURCE]');
const source=fs.readFileSync(process.argv[3]||path.join(__dirname,'Measure-DashboardWorkerTransfer.js'),'utf8');
const pwshExecutable='pwsh';
const workRoot=fs.mkdtempSync(path.join(os.tmpdir(),'defender-js-lifetime-'));
function extract(s,a,b){const i=s.indexOf(a),j=s.indexOf(b,i);assert(i>=0&&j>i,'Missing production anchors');return s.slice(i,j);}
const preamble=`$ErrorActionPreference='Stop'
function Test-OwnedRoot($item){$item.Name-eq'msedge.exe'-and$item.CommandLine-ceq('msedge.exe --user-data-dir="'+$env:ISSUE70_PROFILE+'"')}
function Get-Created($item){if($null-eq$item-or$item.CreationDate-isnot[datetime]){throw 'Unknown owned identity.'};$item.CreationDate.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)}
`;
let run=0;
function safeExec(file,args,options,callback){
 if(file!=='pwsh')throw Error('Forbidden executable');
 const s=args[2],a=s.indexOf("$ErrorActionPreference = 'Stop'"),b=s.indexOf("$issue70Phase = 'cim'",a);if(a<0||b<0)throw Error('Missing selection preamble');
 const adapted=s.slice(0,a)+preamble+s.slice(b);
 if(/DllImport|Stop-Process|taskkill|Process\]::Get|Start-Process/.test(adapted))throw Error('Native action token');
 if(!adapted.includes('function Get-CimInstance')||!adapted.includes('function Get-Process'))throw Error('Missing mocks');
 fs.writeFileSync(path.join(workRoot,`late-birth-real-${run++}.ps1`),adapted);
 return cp.execFile(pwshExecutable,['-NoProfile','-Command',adapted],{...options,env:{...options.env,XDG_CACHE_HOME:path.join(workRoot,'xdg/cache'),XDG_CONFIG_HOME:path.join(workRoot,'xdg/config'),XDG_DATA_HOME:path.join(workRoot,'xdg/data')},timeout:12000},callback);
}
const fixture=`
$script:operations=@();$script:objects=@();$script:killed=@();$script:wrongKills=0
$script:items=@($env:MOCK_ITEMS|ConvertFrom-Json|ForEach-Object{$_.CreationDate=[datetime]$_.CreationDate;$_})
function Get-CimInstance {param($ClassName,$Filter,$Property,$ErrorAction) if($Filter){$ids=@([regex]::Matches($Filter,'ProcessId=(\\d+)')|ForEach-Object{[int]$_.Groups[1].Value});return @($script:items|Where-Object{$_.ProcessId-in$ids})};$script:items}
function Get-Process {
 param($Id,$ErrorAction)
 if($env:MOCK_MODE-eq'memory-open-forbidden'){throw 'Inventory must not open process'}
 $item=@($script:items|Where-Object ProcessId -eq $Id)[0]
 $p=[pscustomobject]@{Id=$Id;BoundCreated=$item.CreationDate;Pinned=$false;Exited=$false;Disposals=0}
 $p|Add-Member ScriptProperty SafeHandle {$script:operations+='open';if($env:MOCK_MODE-eq'handle-null'){return $null};$this.Pinned=$true;[pscustomobject]@{IsInvalid=$false;IsClosed=$false}}
 $p|Add-Member ScriptProperty StartTime {$script:operations+='start';if($env:MOCK_MODE-eq'start-throws'){throw 'unknown start'};if($env:MOCK_MODE-eq'reuse-after-start'){$script:items=@([pscustomobject]@{ProcessId=$this.Id;ParentProcessId=0;Name='replacement.exe';CommandLine='replacement';CreationDate=$this.BoundCreated.AddHours(1);WorkingSetSize=1;PrivatePageCount=1});$this.Exited=$true};$this.BoundCreated}
 $p|Add-Member ScriptProperty HasExited {$script:operations+='exit-check';if($env:MOCK_MODE-eq'exit-check-throws'){throw 'unknown exit state'};$this.Exited}
 $p|Add-Member ScriptMethod Kill {
  $script:operations+='kill'
  if($env:MOCK_MODE-eq'exit-then-kill-throws'){$this.Exited=$true;throw [ComponentModel.Win32Exception]::new(5)}
  if($env:MOCK_MODE-in@('exit-check-throws','dispose-and-kill-throws')){throw [ComponentModel.Win32Exception]::new(87)}
  if($env:MOCK_MODE-eq'late-birth'){$script:items+=[pscustomobject]@{ProcessId=102;ParentProcessId=$this.Id;Name='child.exe';CommandLine='child';CreationDate=$this.BoundCreated.AddSeconds(1);WorkingSetSize=1;PrivatePageCount=1}}
  if($env:MOCK_MODE-eq'reuse-after-start'-and$this.Pinned){return}
  if($env:MOCK_MODE-eq'reuse-after-start'-and-not$this.Pinned){$script:wrongKills++}
  $script:killed+=$this.Id;$script:items=@($script:items|Where-Object ProcessId -ne $this.Id);$this.Exited=$true
 }
 $p|Add-Member ScriptMethod WaitForExit {param($Milliseconds)$script:operations+='wait';$this.Exited}
 $p|Add-Member ScriptMethod Dispose {$script:operations+='dispose';$this.Disposals++;if($env:MOCK_MODE-eq'dispose-and-kill-throws'){throw 'dispose error'}}
 $script:objects+=$p;$p
}
`;

async function runChecks(){
 const results=[];
 for(const mode of ['late-birth','root-exit-before-termination','root-pid-reuse','profile-unreadable','identity-unreadable','child-gone-root-live','own-pid-reuse','termination-failure','empty-positive','unrelated-positive','unobserved-orphan-boundary']){
  const profile=fs.mkdtempSync(path.join(workRoot,'profile-'));fs.writeFileSync(path.join(profile,'sentinel.txt'),'fixture');
  assert(path.resolve(profile).startsWith(path.resolve(workRoot)+path.sep));
  const root=()=>({ProcessId:101,ParentProcessId:0,Name:'msedge.exe',CommandLine:'msedge.exe --user-data-dir="'+profile+'"',CreationDate:'2026-01-01T00:00:00Z',WorkingSetSize:11,PrivatePageCount:17});
  const child=()=>({...root(),ProcessId:102,ParentProcessId:101,Name:'child.exe',CommandLine:'child',CreationDate:'2026-01-01T00:00:01Z'});
  let items=['empty-positive','unrelated-positive','unobserved-orphan-boundary'].includes(mode)?[]:[root()];
  if(['root-pid-reuse','child-gone-root-live','own-pid-reuse'].includes(mode))items.push(child());
  if(mode==='unrelated-positive')items=[{...root(),Name:'unrelated.exe',CommandLine:'unrelated'}];
  if(mode==='unobserved-orphan-boundary')items=[child()];
  let executions=0;const killed=[],handles=[],snapshots=[];
  const execute=async(script,environment,timeout)=>{
   executions++;
   const terminating=script.includes("$issue70Phase = 'termination'");
   const augmented=fixture.replace('$script:operations=@();','$script:fullCalls=0;$script:operations=@();').replace('if($Filter){$ids=', 'if(-not $Filter){$script:fullCalls++};if($Filter){$ids=');
   const text=augmented+'\n$failed=$false;$value=$null;try{$text=. {\n'+script+'\n};$value=$text|ConvertFrom-Json}catch{$failed=$true}\n@{failed=$failed;value=$value;items=@($script:items);operations=@($script:operations);fullCalls=$script:fullCalls;wrongKills=$script:wrongKills;disposals=@($script:objects|ForEach-Object{$_.Disposals});killed=@($script:killed)}|ConvertTo-Json -Depth 12 -Compress';
   const r=await powershell(text,{...environment,MOCK_MODE:mode==='termination-failure'?'dispose-and-kill-throws':mode,MOCK_ITEMS:JSON.stringify(items)},timeout||12000);
   assert.strictEqual(r.fullCalls,1,'One full CIM snapshot per operation');
   assert.strictEqual(r.wrongKills,0,'No replacement kill');
   assert(r.disposals.every(n=>n===1),'Every acquired handle disposed exactly once');
   if(!terminating)assert.deepStrictEqual(r.operations,[],'Inventory must not open processes');
   else handles.push(...r.operations.filter(x=>x==='open'));
   killed.push(...r.killed);items=r.items;snapshots.push(r.value);
   if(r.failed)throw Error('Synthetic process operation failed');return r.value;
  };
  const owned=ownedProcesses(profile,execute);await owned.inventory();
  if(mode==='root-exit-before-termination')items=[child()];
  if(mode==='root-pid-reuse')items[0]={...root(),Name:'replacement.exe',CommandLine:'replacement',CreationDate:'2026-01-01T01:00:00Z'};
  if(mode==='profile-unreadable')items[0].CommandLine=null;
  if(mode==='identity-unreadable')items[0].CreationDate=null;
  if(mode==='child-gone-root-live'){items=[root()];assert.deepStrictEqual((await owned.inventory()).pids,[101]);}
  if(mode==='own-pid-reuse'){items[1]={...child(),Name:'replacement.exe',CommandLine:'replacement',ParentProcessId:0,CreationDate:'2026-01-01T01:00:00Z'};assert.deepStrictEqual((await owned.inventory()).pids,[101]);}
  const cleanup=await cleanupOwned({profile,owned});
  const clean=['empty-positive','unrelated-positive','unobserved-orphan-boundary'].includes(mode);
  if(clean){assert.strictEqual(cleanup.remainingOwned,0);assert.strictEqual(cleanup.profileExists,false);assert.deepStrictEqual(cleanup.errors,[]);assert.deepStrictEqual(killed,[]);}
  else{
   assert.strictEqual(cleanup.remainingOwned,null,'Unproved absence must not publish zero');assert.strictEqual(cleanup.profileExists,true);assert(fs.existsSync(path.join(profile,'sentinel.txt')));assert(cleanup.errors.includes('Final owned inventory'));
   if(['root-exit-before-termination','root-pid-reuse','profile-unreadable','identity-unreadable','termination-failure'].includes(mode))assert.deepStrictEqual(killed,[],'History grants no new kill authority');
   else assert.deepStrictEqual(killed,[101],'Only selected root may be killed');
   if(mode==='late-birth')assert(items.some(x=>x.ProcessId===102));
   if(mode==='own-pid-reuse')assert(items.some(x=>x.ProcessId===102&&x.Name==='replacement.exe'));
   items=[];const before=executions;await assert.rejects(owned.inventory(),/accounting is incomplete/);assert.strictEqual(executions,before,'Sticky failure refuses before new inventory');
   const repeated=await cleanupOwned({profile,owned});assert.strictEqual(repeated.remainingOwned,null);assert.strictEqual(repeated.profileExists,true);assert(fs.existsSync(profile));
  }
  results.push({mode,outsideProof:mode==='unobserved-orphan-boundary',remainingOwned:cleanup.remainingOwned,profileExists:cleanup.profileExists,errors:cleanup.errors,killed,executions});
 }
 return results;
}
(async()=>{
 try{
  const context=vm.createContext({assert,fixture,fs,path,workRoot,execFile:safeExec,process:{platform:'win32',env:process.env},console,setTimeout,clearTimeout,performance:require('perf_hooks').performance});
  const code=extract(source,'function safeInventoryDiagnostic(','function safeFailure(')+extract(source,'async function bounded(','function powershell(')+extract(source,'function powershell(','function ownedProcesses(')+extract(source,'function ownedProcesses(','async function terminateSpawned(')+extract(source,'async function terminateSpawned(','async function withServer(');
  const results=await vm.runInContext(code+'\n'+runChecks.toString()+'\nrunChecks()',context);
  console.log(JSON.stringify({kind:'synthetic source-driven lifetime regression, not native qualification',cases:results},null,2));
  console.log('PASS observed-root lifetime accounting, late child, sticky cleanup/profile retention, PID reuse, one-snapshot/no-open invariants, and empty controls; unobserved-orphan boundary remains outside proof.');
 }finally{
  assert(path.resolve(workRoot).startsWith(path.resolve(os.tmpdir())+path.sep));fs.rmSync(workRoot,{recursive:true,force:true});
 }
})().catch(error=>{console.error(error);process.exitCode=1});
