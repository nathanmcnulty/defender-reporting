#Requires -Version 7.6
[CmdletBinding()]
param(
    [switch]$Owner,
    [string]$FixtureProfile,
    [string]$Marker,
    [Parameter(ValueFromRemainingArguments)][string[]]$Remaining
)
$ErrorActionPreference = 'Stop'
if (-not $Owner) {
    if ($Remaining.Count -ne 1 -or $Remaining[0] -cnotlike '--user-data-dir=*') { exit 1 }
    Start-Sleep -Seconds 10
    exit 0
}
try {
    Add-Type -Path (Join-Path $PSScriptRoot 'LaunchBoundJob.cs')
    $job = [LaunchBound.JobOwner]::new([guid]::NewGuid().ToString('N'), $FixtureProfile)
    try {
        $arguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $PSCommandPath, "--user-data-dir=$FixtureProfile")
        $snapshot = $job.Start([Environment]::ProcessPath, $arguments, $FixtureProfile)
        if (-not $snapshot.OuterPolicyConfirmed -or $snapshot.OuterJobLimitBytes -ne 2GB -or -not $snapshot.RootInOuterBeforeInner) { throw 'Inner outer policy rejected.' }
        Start-Sleep -Seconds 1
        $finish = $job.Stop(5000)
        if (-not $finish.Confirmed -or -not $finish.StreamsComplete -or $finish.ActiveProcesses -ne 0) { throw 'Inner cleanup unknown.' }
    }
    finally { $job.Dispose() }
    [IO.File]::WriteAllText($Marker, 'passed')
    Start-Sleep -Seconds 1
    exit 0
}
catch { exit 1 }
