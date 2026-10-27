#Requires -Version 7.6
# Disposable fixture only. No network, downloads, credentials, or existing processes.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Read-FixtureOption {
    param([object[]]$Arguments)
    $parsed=@{}
    for($index=0;$index -lt $Arguments.Count;$index++) {
        $argument=$Arguments[$index]
        if($argument -isnot [string]) { throw 'Invalid fixture argument type.' }
        # pwsh -File splits this one canonical drive-qualified switch at its first colon.
        if($argument -cmatch '^--user-data-dir=([A-Za-z])\z') {
            $drive=$Matches[1]
            if(++$index -ge $Arguments.Count -or $Arguments[$index] -isnot [string] -or -not $Arguments[$index].StartsWith('\',[StringComparison]::Ordinal)) { throw 'Malformed fixture profile split.' }
            $argument='--user-data-dir='+$drive+':'+$Arguments[$index]
        }
        if($argument -cnotmatch '^--(mode|directory-b64|user-data-dir|echo-b64|parent-pid|fixture-run)=(.*)\z' -or $parsed.ContainsKey($Matches[1])) { throw 'Invalid fixture arguments.' }
        $parsed[$Matches[1]]=$Matches[2]
    }
    foreach($key in @('mode','directory-b64','user-data-dir','fixture-run','parent-pid')) { if(-not $parsed.ContainsKey($key)) { throw 'Missing fixture argument.' } }
    foreach($key in @('directory','echo')) {
        $encodedKey=$key+'-b64'
        $encoded=if($parsed.ContainsKey($encodedKey)){$parsed[$encodedKey]}else{''}
        if($encoded -cnotmatch '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\z') { throw 'Malformed fixture value encoding.' }
        $bytes=[Convert]::FromBase64String($encoded)
        if([Convert]::ToBase64String($bytes) -cne $encoded) { throw 'Noncanonical fixture value encoding.' }
        $parsed[$key]=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
        [void]$parsed.Remove($encodedKey)
    }
    $parent=0
    if($parsed.mode -cnotmatch '^[a-z][a-z-]*\z' -or $parsed['fixture-run'] -cnotmatch '^[a-f0-9]{32}\z' -or $parsed['parent-pid'] -cnotmatch '^[1-9][0-9]*\z' -or -not [int]::TryParse($parsed['parent-pid'],[ref]$parent) -or -not [IO.Path]::IsPathFullyQualified($parsed.directory) -or -not [IO.Path]::IsPathFullyQualified($parsed['user-data-dir'])) { throw 'Invalid fixture identity.' }
    $parsed
}
function Select-FixtureAssemblyPreparation {
    param([bool]$Descendant,[bool]$DllExists,[bool]$ManifestExists)
    if($Descendant) { if(-not $DllExists -or -not $ManifestExists) { throw 'Fixture helper cache incomplete.' };return 'load' }
    if($DllExists -or $ManifestExists) { throw 'Fixture helper cache must be fresh.' }
    'compile'
}
function Read-FixtureAssemblyData {
    param([string]$Path,[int]$MaximumBytes)
    $file=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($file.Length -le 0 -or $file.Length -gt $MaximumBytes) { throw 'Fixture helper artifact size invalid.' }
        $bytes=[byte[]]::new([int]$file.Length);$file.ReadExactly($bytes,0,$bytes.Length)
        return ,$bytes
    } finally { $file.Dispose() }
}
function Confirm-FixtureAssemblyCache {
    param([byte[]]$DllBytes,[byte[]]$ManifestBytes,[string]$RunId,[string]$SourceSha256)
    if($DllBytes.Length -le 0 -or $DllBytes.Length -gt 1MB -or $ManifestBytes.Length -le 0 -or $ManifestBytes.Length -gt 8192 -or $RunId -cnotmatch '^[a-f0-9]{32}\z' -or $SourceSha256 -cnotmatch '^[a-f0-9]{64}\z') { throw 'Fixture helper cache inputs invalid.' }
    $json=[Text.UTF8Encoding]::new($false,$true).GetString($ManifestBytes)
    $document=[Text.Json.JsonDocument]::Parse($json)
    try {
        $properties=@($document.RootElement.EnumerateObject());$names=@($properties.Name)
        if($properties.Count -ne 4 -or @($names|Select-Object -Unique).Count -ne 4 -or @($names|Where-Object {$_ -cnotin @('schema','runId','sourceSha256','assemblySha256')}).Count -ne 0) { throw 'Fixture helper manifest fields invalid.' }
        $root=$document.RootElement
        if($root.GetProperty('schema').GetInt32() -ne 1 -or $root.GetProperty('runId').GetString() -cne $RunId -or $root.GetProperty('sourceSha256').GetString() -cne $SourceSha256 -or $root.GetProperty('assemblySha256').GetString() -cnotmatch '^[a-f0-9]{64}\z') { throw 'Fixture helper manifest binding invalid.' }
        $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($DllBytes)).ToLowerInvariant()
        if($hash -cne $root.GetProperty('assemblySha256').GetString()) { throw 'Fixture helper assembly hash mismatch.' }
        return ,$DllBytes
    } finally { $document.Dispose() }
}
function Get-FixtureNativeSourceHash {
    param([string[]]$Paths)
    $names=@('LaunchBoundJob.cs','LaunchBoundNativeControls.cs','LaunchBoundExitObserver.cs')
    if($Paths.Count -ne 3) { throw 'Fixture native source set incomplete.' }
    $items=@(for($i=0;$i -lt 3;$i++) {
        if(-not [IO.Path]::IsPathFullyQualified($Paths[$i]) -or [IO.Path]::GetFileName($Paths[$i]) -cne $names[$i]) { throw 'Fixture native source order changed.' }
        $bytes=Read-FixtureAssemblyData $Paths[$i] 1MB
        [ordered]@{name=$names[$i];sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()}
    })
    $encoded=[Text.UTF8Encoding]::new($false).GetBytes(($items|ConvertTo-Json -Compress))
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($encoded)).ToLowerInvariant()
}
function Save-FixtureConsoleHoldSnapshot {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Writes only a fresh diagnostic in this disposable fixture family.')]
    param()
    $window=[LaunchBoundFixtureConsole]::ObserveWindow()
    $snapshotPath=Join-Path $consoleDirectory ('console-before-hold-'+$PID+'.json')
    $file=[IO.File]::Open($snapshotPath,[IO.FileMode]::CreateNew)
    try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{mode=$options.mode;runId=$options['fixture-run'];pid=$PID;window=$window;scope='caller console association immediately before existing hold; not console-host identity or exit'}|ConvertTo-Json -Compress));$file.Write($bytes,0,$bytes.Length) } finally { $file.Dispose() }
}
$phase='arguments'
try {
if(-not $IsWindows) { throw 'Windows fixture required.' }
$options=Read-FixtureOption $args
# PowerShell has initialized its console host; detach only this disposable fixture.
$phase='console-detachment'
$consoleSource=@'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class LaunchBoundFixtureConsole {
    public sealed class ConsoleObservation { public long Before,After;public bool Changed; }
    class Calls {
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GetStdHandle(int slot);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr handle);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool FreeConsole();
        [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
        internal virtual long Window() { return GetConsoleWindow().ToInt64(); }
        internal virtual IntPtr Standard(int slot) { return GetStdHandle(slot); }
        internal virtual void Pipe(IntPtr handle) {
            if(handle==IntPtr.Zero || handle==new IntPtr(-1))throw new InvalidOperationException("Fixture pipe missing.");
            uint type=GetFileType(handle);int error=Marshal.GetLastWin32Error();
            if(type==0)throw new Win32Exception(error);
            if(type!=3)throw new InvalidOperationException("Fixture output is not a pipe.");
        }
        internal virtual void Free() { if(!FreeConsole())throw new Win32Exception(Marshal.GetLastWin32Error()); }
    }
    static ConsoleObservation Detach(Calls calls) {
        long before=calls.Window();
        IntPtr input=calls.Standard(-10),output=calls.Standard(-11),error=calls.Standard(-12);
        calls.Pipe(output);calls.Pipe(error);
        calls.Free();
        long after=calls.Window();
        calls.Pipe(output);calls.Pipe(error);
        if(calls.Standard(-10)!=input || calls.Standard(-11)!=output || calls.Standard(-12)!=error)throw new InvalidOperationException("Fixture standard handles changed after detachment.");
        return new ConsoleObservation{Before=before,After=after,Changed=before!=after};
    }
    public static ConsoleObservation Detach() { return Detach(new Calls()); }
    public static long ObserveWindow() { return new Calls().Window(); }
    sealed class Fault : Calls {
        internal string Failure;internal int Frees,Pipes;
        internal override long Window() { return Frees==0?111:0; }
        internal override IntPtr Standard(int slot) {
            if(Failure=="missing-output" && slot==-11)return IntPtr.Zero;
            if(Failure=="invalid-error" && slot==-12)return new IntPtr(-1);
            if(Frees>0 && Failure=="slot"+slot)return new IntPtr(99);
            return new IntPtr(-slot);
        }
        internal override void Pipe(IntPtr handle) {
            Pipes++;
            if(handle==IntPtr.Zero || handle==new IntPtr(-1) || Failure=="not-pipe" || Failure=="post-pipe" && Frees>0)throw new InvalidOperationException("Synthetic pipe failure.");
            if(Failure=="pipe-native")throw new Win32Exception(6);
        }
        internal override void Free() { Frees++;if(Failure=="free-native")throw new Win32Exception(5); }
    }
    public static void OfflineContracts() {
        foreach(string failure in new[]{"none","missing-output","invalid-error","not-pipe","pipe-native","free-native","post-pipe","slot-10","slot-11","slot-12"}) {
            var calls=new Fault{Failure=failure};bool threw=false;int? code=null;ConsoleObservation observed=null;
            try{observed=Detach(calls);}catch(Win32Exception error){threw=true;code=error.NativeErrorCode;}catch(InvalidOperationException){threw=true;}
            if(threw!=(failure!="none") || calls.Frees!=(failure=="missing-output" || failure=="invalid-error" || failure=="not-pipe" || failure=="pipe-native"?0:1))throw new InvalidOperationException("Fixture detachment failure hidden or misordered.");
            if(failure=="none" && (observed.Before!=111 || observed.After!=0 || !observed.Changed))throw new InvalidOperationException("Fixture console snapshot order changed.");
            if(failure=="free-native" && code!=5 || failure=="pipe-native" && code!=6 || failure=="none" && calls.Pipes!=4)throw new InvalidOperationException("Fixture detachment native error/handle checks changed.");
        }
    }
}
'@
$consoleClock=[Diagnostics.Stopwatch]::StartNew()
$consoleDirectory=Join-Path ([IO.Path]::GetFullPath($options.directory)) 'launch-diagnostics'
[void][IO.Directory]::CreateDirectory($consoleDirectory)
$consoleDll=Join-Path $consoleDirectory 'fixture-console.dll'
$consoleManifest=Join-Path $consoleDirectory 'fixture-console.json'
$consoleSourceHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes($consoleSource))).ToLowerInvariant()
$preparationAction=Select-FixtureAssemblyPreparation ($options.mode -cin @('child','grandchild','hold')) ([IO.File]::Exists($consoleDll)) ([IO.File]::Exists($consoleManifest))
$helperCompileMs=0
if($preparationAction -ceq 'compile') {
    Add-Type -TypeDefinition $consoleSource -OutputAssembly $consoleDll
    $helperCompileMs=$consoleClock.ElapsedMilliseconds
    $producedBytes=Read-FixtureAssemblyData $consoleDll 1MB
    $producedHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($producedBytes)).ToLowerInvariant()
    $manifestFile=[IO.File]::Open($consoleManifest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{schema=1;runId=$options['fixture-run'];sourceSha256=$consoleSourceHash;assemblySha256=$producedHash}|ConvertTo-Json -Compress));$manifestFile.Write($bytes,0,$bytes.Length);$manifestFile.Flush($true) } finally { $manifestFile.Dispose() }
}
$helperBytes=Read-FixtureAssemblyData $consoleDll 1MB
$manifestBytes=Read-FixtureAssemblyData $consoleManifest 8192
$verifiedHelper=Confirm-FixtureAssemblyCache $helperBytes $manifestBytes $options['fixture-run'] $consoleSourceHash
# Load the checked snapshot, not a second unchecked path read.
[void][Reflection.Assembly]::Load([byte[]]$verifiedHelper)
$helperPreparationMs=$consoleClock.ElapsedMilliseconds
$consoleDetachment=[LaunchBoundFixtureConsole]::Detach()
$consoleRecord=[IO.File]::Open((Join-Path $consoleDirectory ('console-prepare-'+$PID+'.json')),[IO.FileMode]::CreateNew)
try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{mode=$options.mode;runId=$options['fixture-run'];parent=[int]$options['parent-pid'];action=$preparationAction;compileElapsedMs=$helperCompileMs;loadPreparationElapsedMs=$helperPreparationMs;totalElapsedMs=$consoleClock.ElapsedMilliseconds;sourceSha256=$consoleSourceHash;assemblySha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($verifiedHelper)).ToLowerInvariant();detached=$true;windowBeforeDetach=$consoleDetachment.Before;windowAfterDetach=$consoleDetachment.After;windowChanged=$consoleDetachment.Changed}|ConvertTo-Json -Compress));$consoleRecord.Write($bytes,0,$bytes.Length) } finally { $consoleRecord.Dispose() }
$phase='identity'
$directory = [IO.Path]::GetFullPath($options.directory)
[void][IO.Directory]::CreateDirectory($directory)
$current = [Diagnostics.Process]::GetCurrentProcess()
try {
    $held = $current.SafeHandle
    if ($held.IsInvalid -or $held.IsClosed) { throw 'Fixture identity unavailable.' }
    $creation = $current.StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
    $identity = @{pid=$PID;parent=[int]$options['parent-pid'];creationFileTime=$creation;image=[Environment]::ProcessPath;runId=$options['fixture-run'];mode=$options.mode}
} finally { $current.Dispose() }
$markerName = if ($options.mode -eq 'hold') { 'hold-' + $PID } else { $options.mode }
$marker = Join-Path $directory ($markerName + '.json')
$temporary = $marker + '.' + $PID + '.tmp'
$phase='marker'
[IO.File]::WriteAllText($temporary,($identity | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
[IO.File]::Move($temporary,$marker)

function Start-FixtureChild {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Starts only a new disposable child in this run-owned fixture family.')]
    param([string]$Mode)
    $encodedDirectory=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false,$true).GetBytes($directory))
    $launchArguments=@('-NoLogo','-NoProfile','-NonInteractive','-File',$PSCommandPath,('--mode='+$Mode),('--directory-b64='+$encodedDirectory),('--user-data-dir='+$options['user-data-dir']),('--fixture-run='+$options['fixture-run']),('--parent-pid='+$PID))
    $diagnosticDirectory=Join-Path $directory 'launch-diagnostics'
    [void][IO.Directory]::CreateDirectory($diagnosticDirectory)
    $preparationClock=[Diagnostics.Stopwatch]::StartNew()
    $preparationKey='preparation-'+[Guid]::NewGuid().ToString('N')
    $preparationStart=Join-Path $diagnosticDirectory ($preparationKey+'-start.json')
    $preparationFile=[IO.File]::Open($preparationStart,[IO.FileMode]::CreateNew)
    try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{mode=$Mode;parent=$PID;runId=$options['fixture-run'];stage='before-type-load'}|ConvertTo-Json -Compress));$preparationFile.Write($bytes,0,$bytes.Length) } finally { $preparationFile.Dispose() }
    $nativePreparationAction='already-loaded';$nativeCompileMs=0
    if (-not ('LaunchBound.NativeControls' -as [type])) {
        $nativeSourcePaths=@((Join-Path $PSScriptRoot 'LaunchBoundJob.cs'),(Join-Path $PSScriptRoot 'LaunchBoundNativeControls.cs'),(Join-Path $PSScriptRoot 'LaunchBoundExitObserver.cs'))
        $nativeSourceHash=Get-FixtureNativeSourceHash $nativeSourcePaths
        $nativeDll=Join-Path $diagnosticDirectory 'launch-native.dll'
        $nativeManifest=Join-Path $diagnosticDirectory 'launch-native.json'
        $nativePreparationAction=Select-FixtureAssemblyPreparation ($options.mode -cin @('child','grandchild','hold')) ([IO.File]::Exists($nativeDll)) ([IO.File]::Exists($nativeManifest))
        if($nativePreparationAction -ceq 'compile') {
            $nativeCompileClock=[Diagnostics.Stopwatch]::StartNew()
            Add-Type -Path $nativeSourcePaths -OutputAssembly $nativeDll
            $nativeCompileMs=$nativeCompileClock.ElapsedMilliseconds
            if((Get-FixtureNativeSourceHash $nativeSourcePaths) -cne $nativeSourceHash) { throw 'Fixture native sources changed during compilation.' }
            $producedBytes=Read-FixtureAssemblyData $nativeDll 1MB
            $producedHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($producedBytes)).ToLowerInvariant()
            $manifestFile=[IO.File]::Open($nativeManifest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
            try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{schema=1;runId=$options['fixture-run'];sourceSha256=$nativeSourceHash;assemblySha256=$producedHash}|ConvertTo-Json -Compress));$manifestFile.Write($bytes,0,$bytes.Length);$manifestFile.Flush($true) } finally { $manifestFile.Dispose() }
        }
        $nativeBytes=Read-FixtureAssemblyData $nativeDll 1MB
        $manifestBytes=Read-FixtureAssemblyData $nativeManifest 8192
        $verifiedNative=Confirm-FixtureAssemblyCache $nativeBytes $manifestBytes $options['fixture-run'] $nativeSourceHash
        [void][Reflection.Assembly]::Load([byte[]]$verifiedNative)
    }
    $nativePreparationMs=$preparationClock.ElapsedMilliseconds
    [LaunchBound.NativeControls]::StartFixtureDescendant([Environment]::ProcessPath,[string[]]$launchArguments,$options['user-data-dir'])
    $preparationFile=[IO.File]::Open((Join-Path $diagnosticDirectory ($preparationKey+'-done.json')),[IO.FileMode]::CreateNew)
    try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes((@{mode=$Mode;parent=$PID;runId=$options['fixture-run'];stage='native-launch-returned';nativePreparationAction=$nativePreparationAction;nativeCompileElapsedMs=$nativeCompileMs;nativePreparationElapsedMs=$nativePreparationMs;totalElapsedMs=$preparationClock.ElapsedMilliseconds}|ConvertTo-Json -Compress));$preparationFile.Write($bytes,0,$bytes.Length) } finally { $preparationFile.Dispose() }
}
$phase='children'
switch -CaseSensitive ($options.mode) {
    { $_ -cin @('root','late') } {
        if ($options.mode -ceq 'late') {
            $clock = [Diagnostics.Stopwatch]::StartNew()
            while (-not [IO.File]::Exists((Join-Path $directory 'go'))) { if ($clock.ElapsedMilliseconds -ge 10000) { throw 'Fixture signal absent.' }; Start-Sleep -Milliseconds 10 }
        }
        Start-FixtureChild 'child'
        [IO.File]::WriteAllText((Join-Path $directory 'root-done'),'done')
    }
    'child' { Start-FixtureChild 'grandchild'; Save-FixtureConsoleHoldSnapshot; Start-Sleep -Seconds 60 }
    { $_ -cin @('hold','grandchild') } { Save-FixtureConsoleHoldSnapshot; Start-Sleep -Seconds 60 }
    'fanout' { 1..3 | ForEach-Object { Start-FixtureChild 'hold' }; [IO.File]::WriteAllText((Join-Path $directory 'fanout-done'),'done') }
    'exit' { [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::Out.WriteLine($options.echo) }
    'output' {
        $buffer = [byte[]]::new(8192); [Array]::Fill[byte]($buffer,120)
        $output = [Console]::OpenStandardOutput(); $errorOutput = [Console]::OpenStandardError()
        for ($i=0;$i -lt 8192;$i++) { $output.Write($buffer,0,$buffer.Length) }; $output.WriteByte(120); $output.Flush()
        [Array]::Fill[byte]($buffer,101)
        for ($i=0;$i -lt 8;$i++) { $errorOutput.Write($buffer,0,$buffer.Length) }; $errorOutput.WriteByte(101); $errorOutput.Flush()
    }
    'breakaway' {
        Add-Type -Path @((Join-Path $PSScriptRoot 'LaunchBoundJob.cs'),(Join-Path $PSScriptRoot 'LaunchBoundNativeControls.cs'),(Join-Path $PSScriptRoot 'LaunchBoundExitObserver.cs'))
        [LaunchBound.NativeControls]::AssertBreakawayDenied([Environment]::ProcessPath,$PSCommandPath,$directory,$options['user-data-dir'],$options['fixture-run'])
        [IO.File]::WriteAllText((Join-Path $directory 'breakaway-denied'),'denied')
    }
    'early-error-output' {
        $buffer=[byte[]]::new(8192);[Array]::Fill[byte]($buffer,101);$errorOutput=[Console]::OpenStandardError()
        for($i=0;$i -lt 16;$i++){$errorOutput.Write($buffer,0,$buffer.Length)};$errorOutput.Flush()
        throw 'Synthetic fixture diagnostic failure.'
    }
    default { throw 'Unknown fixture mode.' }
}
} catch {
    [Console]::Error.WriteLine(('fixture-failure phase='+$phase+' type='+$_.Exception.GetType().Name))
    throw
}
