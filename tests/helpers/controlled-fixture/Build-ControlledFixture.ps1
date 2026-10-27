#Requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidencePath,
    [Parameter(Mandatory)][string]$ToolchainBindingPath,
    [Parameter(Mandatory)][string]$ToolchainBindingSha256
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference=$false
. (Join-Path $PSScriptRoot 'InstalledInventory.ps1')
function Get-Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Require([bool]$Condition,[string]$Message) { if(-not $Condition){throw $Message} }
function Write-NewJson([string]$Path,$Value) {
    $file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 16));$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}
function Assert-Toolchain {
    Require ((Get-Sha $ToolchainBindingPath) -ceq $ToolchainBindingSha256) 'Toolchain binding changed.'
    Require ($toolchain.schema -eq 1 -and $toolchain.sdkVersion -ceq '10.0.401' -and $toolchain.runtimeVersion -ceq '10.0.12') 'Unreviewed installed toolchain.'
    Assert-InstalledInventory -Manifest $toolchain -Kind toolchain
}
function Invoke-BuildCommand([string]$Name,[string[]]$Arguments) {
    $stdout=Join-Path $EvidencePath ($Name+'.stdout.log');$stderr=Join-Path $EvidencePath ($Name+'.stderr.log')
    Require (-not(Test-Path $stdout) -and -not(Test-Path $stderr)) 'Fresh build logs required.'
    Write-NewJson (Join-Path $EvidencePath ($Name+'.intent.json')) ([ordered]@{executable=$toolchain.dotnet;executableSha256=$toolchain.dotnetSha256;arguments=$Arguments;cwd=$projectDirectory;toolchainSha256=$ToolchainBindingSha256})
    $process=[Diagnostics.Process]::new()
    try {
        $process.StartInfo=[Diagnostics.ProcessStartInfo]::new($toolchain.dotnet);$process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
        $process.StartInfo.WorkingDirectory=$projectDirectory;$process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
        $process.StartInfo.Environment.Clear()
        foreach($key in $environment.Keys){$process.StartInfo.Environment[$key]=[string]$environment[$key]}
        foreach($argument in $Arguments){$process.StartInfo.ArgumentList.Add($argument)}
        $outFile=[IO.File]::Open($stdout,[IO.FileMode]::CreateNew);$errFile=[IO.File]::Open($stderr,[IO.FileMode]::CreateNew)
        try {
            Require ($process.Start()) 'Offline SDK process did not start.'
            $outTask=[ControlledBuildDrain]::Copy($process.StandardOutput.BaseStream,$outFile,1MB);$errTask=[ControlledBuildDrain]::Copy($process.StandardError.BaseStream,$errFile,1MB)
            $process.WaitForExit();$outDrain=$outTask.GetAwaiter().GetResult();$errDrain=$errTask.GetAwaiter().GetResult();$code=$process.ExitCode
        } finally {$outFile.Dispose();$errFile.Dispose()}
    } finally {$process.Dispose()}
    $record.commands+=@{name=$Name;exitCode=$code;stdoutSha256=Get-Sha $stdout;stderrSha256=Get-Sha $stderr;stdout=$outDrain;stderr=$errDrain}
    Require ($outDrain.Eof -and $errDrain.Eof -and -not $outDrain.Overflow -and -not $errDrain.Overflow -and (Get-Item $stdout).Length -eq $outDrain.Retained -and (Get-Item $stderr).Length -eq $errDrain.Retained) 'Build log overflow or incomplete drain; bounded prefixes retained.'
    Require ($code -eq 0) 'Offline fixture build command failed; no dependency download fallback.'
}
Require ($IsWindows -and [IO.Path]::IsPathFullyQualified($EvidencePath) -and [IO.Path]::IsPathFullyQualified($ToolchainBindingPath) -and $ToolchainBindingSha256 -cmatch '^[a-f0-9]{64}\z') 'Invalid build boundary.'
Require (-not(Test-Path -LiteralPath $EvidencePath)) 'Fresh build evidence required.'
Require ((Get-Sha $ToolchainBindingPath) -ceq $ToolchainBindingSha256) 'Untrusted toolchain binding.'
$toolchain=Read-InstalledInventory -Path $ToolchainBindingPath -Sha256 $ToolchainBindingSha256
Assert-Toolchain
# An explicit outer supervisor must be established by the reviewed invoking controller.
# This helper additionally proves current job membership; commands never request breakaway.
Add-Type -TypeDefinition @'
using System;using System.ComponentModel;using System.Runtime.InteropServices;
using System.IO;using System.Threading.Tasks;
public sealed class ControlledBuildDrainResult {public long Bytes,Retained;public bool Overflow,Eof;}
public static class ControlledBuildDrain {
 public static async Task<ControlledBuildDrainResult> Copy(Stream input,Stream output,long maximum){if(maximum<1)throw new ArgumentOutOfRangeException(nameof(maximum));var result=new ControlledBuildDrainResult();byte[] buffer=new byte[8192];int count;while((count=await input.ReadAsync(buffer,0,buffer.Length))>0){result.Bytes=checked(result.Bytes+count);int retained=(int)Math.Min(count,maximum-result.Retained);if(retained>0){await output.WriteAsync(buffer,0,retained);result.Retained+=retained;}if(result.Bytes>maximum)result.Overflow=true;}await output.FlushAsync();result.Eof=true;return result;}
 public static void Contracts(){byte[] input={1,2,3,4,5};foreach(int maximum in new[]{3,5,7}){using(var source=new MemoryStream(input))using(var output=new MemoryStream()){var result=Copy(source,output,maximum).GetAwaiter().GetResult();byte[] prefix=output.ToArray();if(!result.Eof||result.Bytes!=5||result.Retained!=Math.Min(maximum,5)||prefix.Length!=result.Retained||result.Overflow!=(maximum<5))throw new InvalidOperationException("Build drain accounting changed.");for(int i=0;i<prefix.Length;i++)if(prefix[i]!=input[i])throw new InvalidOperationException("Build drain prefix changed.");}}}
}
public static class ControlledBuildBoundary {
 [StructLayout(LayoutKind.Sequential)] struct Basic {public long process,job;public uint flags;public UIntPtr min,max;public uint active;public UIntPtr affinity;public uint priority,scheduling;}
 [StructLayout(LayoutKind.Sequential)] struct IO {public ulong r,w,o,rb,wb,ob;}
 [StructLayout(LayoutKind.Sequential)] struct Extended {public Basic basic;public IO io;public UIntPtr process,job,peakProcess,peakJob;}
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,IntPtr value,int size,IntPtr returned);
 public static void RequireJob(){bool member;if(!IsProcessInJob(GetCurrentProcess(),IntPtr.Zero,out member))throw new Win32Exception(Marshal.GetLastWin32Error());if(!member)throw new InvalidOperationException("Outer build supervisor required.");IntPtr buffer=Marshal.AllocHGlobal(Marshal.SizeOf<Extended>());try{if(!QueryInformationJobObject(IntPtr.Zero,9,buffer,Marshal.SizeOf<Extended>(),IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());var limits=Marshal.PtrToStructure<Extended>(buffer);if(limits.basic.flags!=0x2200 || limits.job.ToUInt64()!=3UL*1024*1024*1024)throw new InvalidOperationException("Reviewed3GiB outer build job required.");if(!QueryInformationJobObject(IntPtr.Zero,4,buffer,4,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());if(Marshal.ReadInt32(buffer)!=0)throw new InvalidOperationException("Unexpected build job UI restrictions.");}finally{Marshal.FreeHGlobal(buffer);}}
}
'@
[ControlledBuildBoundary]::RequireJob()
[ControlledBuildDrain]::Contracts()
foreach($name in @('DOTNET_STARTUP_HOOKS','DOTNET_ADDITIONAL_DEPS','DOTNET_SHARED_STORE','CORECLR_ENABLE_PROFILING','COR_ENABLE_PROFILING','MSBuildSDKsPath','MSBUILD_EXE_PATH','NUGET_PLUGIN_PATHS','NUGET_CREDENTIALPROVIDERS_PATH')) {Require ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name,'Process'))) 'Unbound build/runtime injection variable.'}
[void][IO.Directory]::CreateDirectory($EvidencePath)
$inputs=Join-Path $EvidencePath 'inputs';$projectDirectory=Join-Path $inputs 'controlled-fixture';$output=Join-Path $EvidencePath 'product'
[void][IO.Directory]::CreateDirectory($projectDirectory);[void][IO.Directory]::CreateDirectory($output)
$record=[ordered]@{schema=1;status='failed';sourceStartVerified=$false;sourceEndVerified=$false;toolchainStartVerified=$true;toolchainEndVerified=$false;toolchainBindingSha256=$ToolchainBindingSha256;commands=@();sourceFiles=@();productManifestSha256=$null;failureStage='source';exceptionType=$null}
$recordFile=[IO.File]::Open((Join-Path $EvidencePath 'build.result.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$environment=@{
    SystemRoot=$env:SystemRoot;WINDIR=$env:WINDIR;SystemDrive=$env:SystemDrive;COMSPEC=$env:COMSPEC;
    PATH=($toolchain.dotnetRoot+';'+(Join-Path $env:SystemRoot 'System32')+';'+$env:SystemRoot);
    USERPROFILE=(Join-Path $EvidencePath 'cli-home');HOME=(Join-Path $EvidencePath 'cli-home');APPDATA=(Join-Path $EvidencePath 'appdata');LOCALAPPDATA=(Join-Path $EvidencePath 'localappdata');TEMP=(Join-Path $EvidencePath 'temp');TMP=(Join-Path $EvidencePath 'temp');
    PROGRAMFILES=(Join-Path $EvidencePath 'program-files');'PROGRAMFILES(X86)'=(Join-Path $EvidencePath 'program-files-x86');PROGRAMDATA=(Join-Path $EvidencePath 'program-data');ALLUSERSPROFILE=(Join-Path $EvidencePath 'program-data');
    DOTNET_CLI_HOME=(Join-Path $EvidencePath 'cli-home');NUGET_PACKAGES=(Join-Path $EvidencePath 'packages');NUGET_HTTP_CACHE_PATH=(Join-Path $EvidencePath 'http-cache');
    DOTNET_ROOT=$toolchain.dotnetRoot;DOTNET_ROOT_X64=$toolchain.dotnetRoot;DOTNET_MULTILEVEL_LOOKUP='0';DOTNET_ROLL_FORWARD='Disable';
    DOTNET_CLI_TELEMETRY_OPTOUT='1';DOTNET_NOLOGO='1';DOTNET_GENERATE_ASPNET_CERTIFICATE='false';DOTNET_ADD_GLOBAL_TOOLS_TO_PATH='false';
    DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true';DOTNET_SDK_VULNERABILITY_CHECK_DISABLE='true';DOTNET_CLI_USE_MSBUILD_SERVER='0';
    MSBUILDDISABLENODEREUSE='1';MSBuildEnableWorkloadResolver='false';DOTNET_DISABLE_GUI_ERRORS='1';DOTNET_CLI_UI_LANGUAGE='en-US'
}
try {
    foreach($key in @('DOTNET_CLI_HOME','APPDATA','LOCALAPPDATA','TEMP','NUGET_PACKAGES','NUGET_HTTP_CACHE_PATH','PROGRAMFILES','PROGRAMFILES(X86)','PROGRAMDATA')){[void][IO.Directory]::CreateDirectory($environment[$key])}
    foreach($name in @('ControlledFixture.csproj','Program.cs','global.json','NuGet.Config')) {
        $source=Join-Path $PSScriptRoot $name;$destination=Join-Path $projectDirectory $name
        Copy-Item -LiteralPath $source -Destination $destination
        $record.sourceFiles+=@{path=$name;sha256=Get-Sha $source;copiedSha256=Get-Sha $destination}
    }
    $jobSource=Join-Path (Split-Path $PSScriptRoot) 'LaunchBoundJob.cs';Copy-Item -LiteralPath $jobSource -Destination (Join-Path $inputs 'LaunchBoundJob.cs')
    $record.sourceFiles+=@{path='../LaunchBoundJob.cs';sha256=Get-Sha $jobSource;copiedSha256=Get-Sha (Join-Path $inputs 'LaunchBoundJob.cs')}
    foreach($file in $record.sourceFiles){Require ($file.sha256 -ceq $file.copiedSha256) 'Build input copy changed.'}
    [xml]$project=Get-Content (Join-Path $projectDirectory 'ControlledFixture.csproj') -Raw
    foreach($element in @('PackageReference','ProjectReference','Import','Target')){Require ($project.GetElementsByTagName($element).Count -eq 0) 'Fixture build has an external or custom project dependency.'}
    $sourceHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false).GetBytes(($record.sourceFiles|ConvertTo-Json -Compress)))).ToLowerInvariant()
    $record.sourceSha256=$sourceHash;$record.sourceStartVerified=$true
    $emptyPackages=Join-Path $inputs 'Directory.Packages.props';[IO.File]::WriteAllText($emptyPackages,'<Project />',[Text.UTF8Encoding]::new($false))
    $properties=@('/p:ImportDirectoryBuildProps=false','/p:ImportDirectoryBuildTargets=false',('/p:DirectoryPackagesPropsPath='+$emptyPackages),'/p:ManagePackageVersionsCentrally=false','/p:NuGetAudit=false','/p:RestoreSources=','/p:RestoreFallbackFolders=','/p:RestoreAdditionalProjectSources=','/p:RestoreAdditionalProjectFallbackFolders=','/p:UseSharedCompilation=false','/p:BuildInParallel=false','/p:MSBuildEnableWorkloadResolver=false','/nodeReuse:false','/m:1')
    foreach($name in @('ImportByWildcardBeforeMicrosoftCommonProps','ImportByWildcardAfterMicrosoftCommonProps','ImportUserLocationsByWildcardBeforeMicrosoftCommonProps','ImportUserLocationsByWildcardAfterMicrosoftCommonProps','ImportByWildcardBeforeMicrosoftCommonTargets','ImportByWildcardAfterMicrosoftCommonTargets','ImportUserLocationsByWildcardBeforeMicrosoftCommonTargets','ImportUserLocationsByWildcardAfterMicrosoftCommonTargets')){$properties+=('/p:'+$name+'=false')}
    # Each hook gets a distinct empty input; repeatedly importing one file emits
    # MSB4011 and can hide which isolation hook was actually evaluated.
    foreach($name in @('CustomBeforeDirectoryBuildProps','CustomAfterDirectoryBuildProps','CustomBeforeMicrosoftCommonProps','CustomAfterMicrosoftCommonProps','CustomBeforeMicrosoftCommonTargets','CustomAfterMicrosoftCommonTargets','CustomBeforeMicrosoftCSharpTargets','CustomAfterMicrosoftCSharpTargets')){$emptyHook=Join-Path $inputs ($name+'.props');[IO.File]::WriteAllText($emptyHook,'<Project />',[Text.UTF8Encoding]::new($false));$properties+=('/p:'+$name+'='+$emptyHook)}
    Push-Location -LiteralPath $projectDirectory
    try {
        $record.failureStage='restore'
        Invoke-BuildCommand 'restore' (@('restore','ControlledFixture.csproj','--configfile','NuGet.Config','--packages',$environment.NUGET_PACKAGES,'--disable-parallel','--disable-build-servers','--verbosity','minimal')+$properties)
        $record.failureStage='build'
        Invoke-BuildCommand 'build' (@('build','ControlledFixture.csproj','--no-restore','--no-dependencies','--disable-build-servers','--configuration','Release','--output',$output,'--verbosity','minimal')+$properties)
    } finally {Pop-Location}
    $record.failureStage='product'
    $assets=Get-Content (Join-Path $projectDirectory 'obj/project.assets.json') -Raw|ConvertFrom-Json -AsHashtable
    Require (@($assets.libraries.Keys).Count -eq 0) 'Offline fixture unexpectedly resolved a package library.'
    Require (@(Get-ChildItem -LiteralPath $environment.NUGET_PACKAGES -File -Recurse -ErrorAction SilentlyContinue).Count -eq 0) 'Offline fixture unexpectedly populated a package cache.'
    $config=Get-Content (Join-Path $output 'LaunchBoundFixture.runtimeconfig.json') -Raw|ConvertFrom-Json -AsHashtable
    Require ($config.runtimeOptions.framework.name -ceq 'Microsoft.NETCore.App' -and $config.runtimeOptions.framework.version -ceq '10.0.12' -and $config.runtimeOptions.rollForward -ceq 'Disable') 'Fixture runtime config changed.'
    $deps=Get-Content (Join-Path $output 'LaunchBoundFixture.deps.json') -Raw|ConvertFrom-Json -AsHashtable
    Require ($deps.libraries.Count -eq 1 -and @($deps.libraries.Values|Where-Object {$_.type -cne 'project'}).Count -eq 0) 'Fixture dependency closure contains a package.'
    $expectedFiles=@('LaunchBoundFixture.exe','LaunchBoundFixture.dll','LaunchBoundFixture.deps.json','LaunchBoundFixture.runtimeconfig.json')
    $actualFiles=@(Get-ChildItem -LiteralPath $output -Recurse -Force|ForEach-Object {[IO.Path]::GetRelativePath($output,$_.FullName)})
    Require ($actualFiles.Count -eq $expectedFiles.Count -and @(Compare-Object $expectedFiles $actualFiles -CaseSensitive).Count -eq 0) 'Unexpected fixture build output.'
    $files=@(foreach($name in @('LaunchBoundFixture.exe','LaunchBoundFixture.dll','LaunchBoundFixture.deps.json','LaunchBoundFixture.runtimeconfig.json')){$p=Join-Path $output $name;Require ((Get-Item $p).Length -le 1MB) 'Fixture product size invalid.';[ordered]@{path=$name;bytes=(Get-Item $p).Length;sha256=Get-Sha $p}})
    $bytes=[IO.File]::ReadAllBytes((Join-Path $output 'LaunchBoundFixture.exe'));Require ($bytes.Length -ge 256 -and $bytes[0] -eq 0x4d -and $bytes[1] -eq 0x5a) 'Fixture apphost is not PE.'
    $pe=[BitConverter]::ToInt32($bytes,0x3c);Require ($pe -ge 64 -and $pe -le $bytes.Length-94 -and [BitConverter]::ToUInt32($bytes,$pe) -eq 0x00004550 -and [BitConverter]::ToUInt16($bytes,$pe+4) -eq 0x8664 -and [BitConverter]::ToUInt16($bytes,$pe+24) -eq 0x20b -and [BitConverter]::ToUInt16($bytes,$pe+92) -eq 2) 'Fixture apphost is not x64 GUI subsystem.'
    Write-NewJson (Join-Path $output 'fixture.product.json') ([ordered]@{schema=1;sourceSha256=$sourceHash;toolchainBindingSha256=$ToolchainBindingSha256;runtimeVersion='10.0.12';runtimeDirectory=$toolchain.runtimeDirectory;files=$files})
    $record.productManifestSha256=Get-Sha (Join-Path $output 'fixture.product.json');$record.peSubsystem=2
    # This builder is already an isolated supervised PowerShell process. Loading the
    # verified just-built assembly invokes only inert contracts, never its Main.
    $record.failureStage='inert-contracts'
    $assembly=[Reflection.Assembly]::LoadFile((Join-Path $output 'LaunchBoundFixture.dll'))
    $fixtureType=$assembly.GetType('LaunchBoundTests.ControlledFixture',$true)
    # Reflection does not unwrap PSObject elements in an object[] argument list.
    # A CLR string[] enforces the method's actual three string parameter types.
    [string[]]$verifyArguments=@((Join-Path $output 'LaunchBoundFixture.exe'),(Join-Path $output 'fixture.product.json'),$record.productManifestSha256)
    [void]$fixtureType.GetMethod('VerifyProduct').Invoke($null,[object[]]$verifyArguments)
    [void]$fixtureType.GetMethod('OfflineContracts').Invoke($null,@())
    $record.inertContractsPassed=$true
    foreach($file in $record.sourceFiles){$p=if($file.path.StartsWith('../',[StringComparison]::Ordinal)){$jobSource}else{Join-Path $PSScriptRoot $file.path};Require ((Get-Sha $p) -ceq $file.sha256) 'Fixture source changed during build.'}
    $record.sourceEndVerified=$true;$record.failureStage='post-toolchain';Assert-Toolchain;$record.toolchainEndVerified=$true;$record.status='passed';$record.failureStage=$null
} catch {$record.exceptionType=$_.Exception.GetType().Name;throw}
finally {
    try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 20));$recordFile.Write($bytes,0,$bytes.Length);$recordFile.Flush($true)}finally{$recordFile.Dispose()}
}
