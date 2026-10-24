#Requires -Version 7.0
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Mocks preserve real CIM/process parameter bindings without external queries or waits.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Child-scope mocks exercise exact production cleanup without touching real processes.')]
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'helpers/HostedSmokeDiagnostics.ps1')
Initialize-HostedSmokeCapture
if (-not $IsWindows) { return }

function Assert-OwnedSmoke([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$ownedProfilePath = Join-Path ([IO.Path]::GetTempPath()) 'ownership private profile'
$exact = 'msedge.exe --user-data-dir="' + $ownedProfilePath + '"'
Assert-OwnedSmoke ([HostedSmoke.Capture]::OwnsProfile($exact, $ownedProfilePath)) 'Quoted exact profile rejected.'
Assert-OwnedSmoke ([HostedSmoke.Capture]::OwnsProfile(('msedge.exe --user-data-dir "' + $ownedProfilePath + '"'), $ownedProfilePath)) 'Split exact profile rejected.'
foreach ($command in @(
    ('msedge.exe --user-data-dir="' + $ownedProfilePath + '-neighbor"'),
    ('msedge.exe --note="' + $ownedProfilePath + '" --user-data-dir="C:\unrelated"'),
    ($exact + ' --user-data-dir="' + $ownedProfilePath + '"'),
    'msedge.exe --user-data-dir=relative'
)) { Assert-OwnedSmoke (-not [HostedSmoke.Capture]::OwnsProfile($command, $ownedProfilePath)) 'Ambiguous, literal or neighboring profile accepted.' }

foreach ($case in @('exit-before-get', 'pid-reuse', 'child-exits', 'kill-failure', 'root-reuse-child', 'lingering', 'first-orphan', 'kill-exit-race', 'enumeration-incomplete')) {
    & {
        $created = [datetime]'2026-01-01T00:00:00Z'
        $script:items = @([pscustomobject]@{ Name = 'msedge.exe'; CommandLine = $exact; ProcessId = 1001; ParentProcessId = 0; CreationDate = $created })
        if ($case -in @('child-exits', 'root-reuse-child')) {
            $script:items += [pscustomobject]@{ Name = 'non-edge-child.exe'; CommandLine = 'private'; ProcessId = 1002; ParentProcessId = 1001; CreationDate = $created.AddSeconds(1) }
        }
        if ($case -eq 'first-orphan') { $script:items = @([pscustomobject]@{ Name = 'non-edge-child.exe'; CommandLine = 'private'; ProcessId = 1002; ParentProcessId = 1001; CreationDate = $created.AddSeconds(1) }) }
        $script:killed = [Collections.Generic.List[int]]::new()
        $script:queries = 0
        function Get-CimInstance {
            [CmdletBinding()] param($ClassName, $Filter)
            if ($case -eq 'enumeration-incomplete') { throw 'Private provider failure' }
            $script:queries++
            if ($script:queries -gt 1 -and $case -eq 'pid-reuse') {
                $script:items[0].CreationDate = $created.AddHours(1)
                $script:items[0].CommandLine = 'msedge.exe --user-data-dir=C:\unrelated'
            }
            if ($script:queries -gt 1 -and $case -eq 'root-reuse-child') {
                $script:items[0].CreationDate = $created.AddHours(1)
                $script:items[0].CommandLine = 'msedge.exe --user-data-dir=C:\unrelated'
            }
            return $script:items
        }
        function Get-Process {
            [CmdletBinding()] param($Id)
            if ($case -eq 'exit-before-get') { $script:items = @(); return }
            $item = @($script:items | Where-Object ProcessId -eq $Id)[0]
            $process = [pscustomobject]@{ Id = $Id; StartTime = $item.CreationDate; HasExited = $false; SafeHandle = [pscustomobject]@{ IsInvalid = $false; IsClosed = $false } }
            $process | Add-Member ScriptMethod Kill {
                if ($case -eq 'kill-exit-race') { $this.HasExited = $true; $script:items = @(); throw [ComponentModel.Win32Exception]::new(87) }
                if ($case -eq 'kill-failure') { throw [ComponentModel.Win32Exception]::new(5) }
                $script:killed.Add($this.Id)
                $this.HasExited = $true
                if ($case -ne 'lingering') { $script:items = @($script:items | Where-Object ProcessId -ne $this.Id) }
                if ($case -eq 'child-exits') { $script:items = @() }
            }
            $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) return $this.HasExited }
            $process | Add-Member ScriptMethod Dispose { }
            return $process
        }
        $result = Stop-HostedSmokeProfileProcess -ProfilePath $ownedProfilePath -AccountingIncomplete:($case -in @('first-orphan','enumeration-incomplete'))
        Assert-OwnedSmoke (-not $result.Confirmed -and $result.Failures.Count -gt 0) "Observed root lifetime/ownership uncertainty passed: $case."
        if ($case -in @('pid-reuse', 'root-reuse-child')) { Assert-OwnedSmoke ($script:killed.Count -eq 0) 'Reused or unverified identity was killed.' }
        if ($case -eq 'child-exits') { Assert-OwnedSmoke ($script:killed.Count -eq 1 -and $script:killed[0] -eq 1002) 'Child-first termination/race handling failed.' }
        if ($case -eq 'kill-failure') { Assert-OwnedSmoke ($result.Failures -contains 'process-access-denied') 'Live kill failure disappeared.' }
        if ($case -eq 'enumeration-incomplete') { Assert-OwnedSmoke (-not $result.Confirmed -and $result.Failures -contains 'process-enumeration-failure' -and $result.Failures -contains 'process-accounting-incomplete') 'Early failure lost incomplete accounting.' }
        if ($case -eq 'first-orphan') { Assert-OwnedSmoke (-not $result.Confirmed -and $result.Failures -contains 'process-accounting-incomplete' -and $script:killed.Count -eq 0) 'Unseeded orphan cleanup falsely confirmed or killed an unverified process.' }
        if ($case -eq 'kill-exit-race') { Assert-OwnedSmoke ($result.Diagnostics -contains 'process-exited-during-termination') 'Exited-race diagnostic missing.' }
        if ($case -eq 'lingering') { Assert-OwnedSmoke (-not $result.Confirmed -and $result.Failures -contains 'owned-process-remains') 'Remaining identity was lost.' }
    }
}
Write-Output 'Hosted smoke ownership regressions passed (exact argv, neighbor/literal/duplicate rejection, PID reuse, missing root/child races, access failure and retained identities).'
