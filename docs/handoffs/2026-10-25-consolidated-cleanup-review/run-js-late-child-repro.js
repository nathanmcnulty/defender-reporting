'use strict';
// Offline counterexample only: process APIs are mocked; no browser or native process is stopped.
// Uses an existing PowerShell 7 executable and only freshly created temporary filesystem fixtures.
const fs=require('fs'),vm=require('vm'),cp=require('child_process'),path=require('path'),os=require('os'),crypto=require('crypto');
const options={};
for(let i=2;i<process.argv.length;i+=2){
 const key=process.argv[i];
 if(!['--source-root','--baseline-root','--pwsh'].includes(key)||!process.argv[i+1]||Object.hasOwn(options,key))throw Error('Usage: node run-js-late-child-repro.js --source-root EXACT_CHECKOUT [--baseline-root EXACT_BASELINE] [--pwsh EXISTING_EXECUTABLE]');
 options[key]=process.argv[i+1];
}
if(!options['--source-root'])throw Error('--source-root is required; do not use this documentation branch as source.');
function readExact(root,expected){
 const bytes=fs.readFileSync(path.join(path.resolve(root),'tests/Measure-DashboardWorkerTransfer.js'));
 if(crypto.createHash('sha256').update(bytes).digest('hex')!==expected)throw Error('Exact reviewed source SHA-256 mismatch; no source was executed.');
 return bytes.toString('utf8');
}
const current=readExact(options['--source-root'],'ddeb7aa6b453afc3b1ace747019be1ff9b8ce15af1d6ddc4f009e9e54bafcda2');
const baseline=options['--baseline-root']?readExact(options['--baseline-root'],'aecef4a72374f95b723cf46a640f454ad1e375b9c3cbb51ad9a9e38c18f5e931'):null;
const pwshExecutable=options['--pwsh']||'pwsh';
const workRoot=fs.mkdtempSync(path.join(os.tmpdir(),'defender-js-late-child-'));
function sanitize(value){
 if(Array.isArray(value))return value.map(sanitize);
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,item])=>[key,sanitize(item)]));
 if(typeof value==='string'&&value.startsWith('msedge.exe --user-data-dir="')&&value.includes(workRoot))return 'msedge.exe --user-data-dir="<synthetic-profile>"';
 if(typeof value==='string'&&value.includes(workRoot))throw Error('Unexpected temporary path in diagnostic output.');
 return value;
}
function extract(s,a,b){let i=s.indexOf(a),j=s.indexOf(b,i);if(i<0||j<0)throw Error('Missing anchors');return s.slice(i,j);}
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
const suite=`
async function runChecks(label){
 const out=[];
 const profile=fs.mkdtempSync(path.join(__dirname,'late-birth-profile-'));fs.writeFileSync(path.join(profile,'fixture-sentinel.txt'),'review-created fixture only');
 const make=()=>[{ProcessId:101,ParentProcessId:0,Name:'msedge.exe',CommandLine:'msedge.exe --user-data-dir="'+profile+'"',CreationDate:'2026-01-01T00:00:00Z',WorkingSetSize:11,PrivatePageCount:17}];
 for(const mode of ['late-birth']){
  let items=make(),responses=[],removed=false,exists=true;
  const execute=async(script,environment,timeout)=>{
   const scriptBody=fixture+'\\n$failed=$false;$value=$null;try{$text=. {\\n'+script+'\\n};$value=$text|ConvertFrom-Json}catch{$failed=$true}\\n@{failed=$failed;value=$value;items=@($script:items);operations=@($script:operations);wrongKills=$script:wrongKills;disposals=@($script:objects|ForEach-Object{$_.Disposals});step=$issue70Step}|ConvertTo-Json -Depth 12 -Compress';
   const r=await powershell(scriptBody,{...environment,MOCK_MODE:mode,MOCK_ITEMS:JSON.stringify(items)},timeout||12000);responses.push(r);items=r.items;if(r.failed)throw Error('Mock production operation failed');return r.value;
  };
  const owned=ownedProcesses(profile,execute);
  if(mode==='late-birth'){
   await owned.inventory();
   assert(fs.existsSync(profile));
   assert(profile.startsWith(__dirname+path.sep+"late-birth-profile-"));const cleanup=await cleanupOwned({profile,owned});removed=!fs.existsSync(profile);
   out.push({label,mode,cleanup,removed,remainingFixture:items,responses});
   assert.strictEqual(items.length,1);assert.strictEqual(items[0].ProcessId,102);assert.strictEqual(cleanup.remainingOwned,0);assert.strictEqual(removed,true);
  }else if(mode==='memory-open-forbidden'){
   const inventory=await owned.inventory();out.push({label,mode,inventory,responses});assert.strictEqual(inventory.bytes,11);assert.strictEqual(inventory.privateBytes,17);
  }else{
   let failed=false;try{await owned.terminate()}catch{failed=true};out.push({label,mode,failed,remainingFixture:items,responses});
   if(label==='current'){
    assert.strictEqual(responses[0].wrongKills,0);
    assert.strictEqual(responses[0].disposals[0],1);
    if(mode==='reuse-after-start'){assert.strictEqual(items[0].Name,'replacement.exe');assert.strictEqual(failed,false)}
    if(mode==='exit-then-kill-throws'){assert.strictEqual(failed,false);assert(responses[0].operations.includes('exit-check'));assert(responses[0].operations.includes('wait'))}
    if(['exit-check-throws','start-throws','handle-null','dispose-and-kill-throws'].includes(mode))assert.strictEqual(failed,true);
    if(mode==='dispose-and-kill-throws')assert.strictEqual(responses[0].step,'kill-exit-check');
   }
  }
 }
 return out;
}
`;
(async()=>{
 let results=[];
 const sources=[['current',current]];if(baseline)sources.push(['baseline',baseline]);
 try{
  for(const[label,source]of sources){
   const c=vm.createContext({assert:require('assert'),fixture,fs,path,__dirname:workRoot,execFile:safeExec,process:{platform:'win32',env:process.env},console,setTimeout,clearTimeout,performance:require('perf_hooks').performance});
   const code=extract(current,'function safeInventoryDiagnostic(','function safeFailure(')+extract(current,'async function bounded(','function powershell(')+extract(current,'function powershell(','function ownedProcesses(')+extract(source,'function ownedProcesses(','async function terminateSpawned(')+extract(current,'async function terminateSpawned(','async function withServer(');
   results.push(...await vm.runInContext(code+suite+`\nrunChecks('${label}')`,c));
  }
  console.log(JSON.stringify({kind:'synthetic counterexample, not native qualification',reviewedHead:'f0dd25699f310647c763c29c92aeb250493f5c39',baseline:baseline?'e4da5bdfa9487eac7f18c193c12245716edd1c38':null,cases:sanitize(results)},null,2));
 }finally{fs.rmSync(workRoot,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
