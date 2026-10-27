#Requires -Version 7.6
# Explicit synthetic owner-crash control, separate from the read-only observer.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ContextPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}\z')][string]$ContextSha256,
    [Parameter(Mandatory)][string]$ProofPath,
    [switch]$Worker
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($path in @($ContextPath,$ProofPath)){if(-not[IO.Path]::IsPathFullyQualified($path)){throw 'Absolute private control path required.'}}
if(-not $Worker){
    # A normal .NET child omits libuv's silent-breakaway job. The worker proves
    # the actual strict outer policy before opening any termination handle.
    $process=[Diagnostics.Process]::new()
    $started=$false;$held=$null
    try{
        $process.StartInfo=[Diagnostics.ProcessStartInfo]::new([Environment]::ProcessPath)
        $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
        foreach($argument in @('-NoProfile','-NonInteractive','-File',$PSCommandPath,'-ContextPath',$ContextPath,'-ContextSha256',$ContextSha256,'-ProofPath',$ProofPath,'-Worker')){$process.StartInfo.ArgumentList.Add($argument)}
        if(-not $process.Start()){throw 'Crash control worker did not start.'}
        $started=$true
        $held=$process.SafeHandle;if($held.IsInvalid -or $held.IsClosed){throw 'Crash control original worker handle missing.'}
        $process.WaitForExit();$code=$process.ExitCode
    }catch{
        $failure=$_
        try{if($started){if($null -eq $held -or $held.IsInvalid -or $held.IsClosed){throw 'Crash control original worker handle unavailable.'};if(-not $process.HasExited){$process.Kill();if(-not $process.WaitForExit(5000)){throw 'Crash control worker rollback unconfirmed.'}}}}
        catch{throw [AggregateException]::new('Crash control worker and rollback failed.',[Exception[]]@($failure.Exception,$_.Exception))}
        throw
    }finally{$process.Dispose()}
    exit $code
}
Add-Type -Path @((Join-Path $PSScriptRoot 'LaunchBoundJob.cs'),(Join-Path $PSScriptRoot 'LaunchBoundOwnerCrash.cs'))
$record=[ordered]@{status='failed';proof=$null;exceptionType=$null;category=$null;nativeErrorCode=$null}
$file=[IO.File]::Open($ProofPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$record.proof=[LaunchBound.OwnerCrash]::Run($ContextPath,$ContextSha256);$record.status='passed'}
catch{$cause=$_.Exception.GetBaseException();$record.exceptionType=$cause.GetType().Name;$record.category=if($cause.Message -ceq 'Crash original actor identity mismatch.'){'actor-identity-mismatch'}else{'control-failure'};if($cause -is [ComponentModel.Win32Exception]){$record.nativeErrorCode=$cause.NativeErrorCode};throw}
finally{try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record|ConvertTo-Json -Depth 8));$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
