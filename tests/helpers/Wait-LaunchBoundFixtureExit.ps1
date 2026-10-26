[CmdletBinding()]
param([Parameter(Mandatory)][string]$TargetsPath,[Parameter(Mandatory)][string]$RunId)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false,$true)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false,$true)
if ($RunId -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid observer identity.' }
$targets = @(Get-Content -LiteralPath $TargetsPath -Raw | ConvertFrom-Json)
Add-Type -Path (Join-Path $PSScriptRoot 'LaunchBoundExitObserver.cs')
$observer = [LaunchBoundTests.ExitObserver]::new([int[]]@($targets.pid),[string[]]@($targets.creationFileTime))
try {
    [Console]::Out.WriteLine((@{runId=$RunId;stage='pinned';count=$targets.Count;ready=$observer.Ready;members=@($observer.Members)}|ConvertTo-Json -Compress -Depth 5));[Console]::Out.Flush()
    if (-not $observer.Ready -or [Console]::In.ReadLine() -cne 'live') { throw 'Observer identity or endpoint unknown.' }
    [Console]::Out.WriteLine((@{runId=$RunId;stage='live';allLive=$observer.AllLive()}|ConvertTo-Json -Compress));[Console]::Out.Flush()
    if ([Console]::In.ReadLine() -cne 'observe') { throw 'Observer endpoint lost.' }
    $allExited = $observer.Wait(5000)
    [Console]::Out.WriteLine((@{runId=$RunId;stage='observed';allExited=$allExited}|ConvertTo-Json -Compress));[Console]::Out.Flush()
    if (-not $allExited) { throw 'Original fixture handles did not signal.' }
} finally { $observer.Dispose() }
