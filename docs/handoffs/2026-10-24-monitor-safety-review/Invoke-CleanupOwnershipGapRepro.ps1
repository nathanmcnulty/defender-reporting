# Safe offline review fixture. No OS inventory, browser or real process stop occurs.
# Optional -RealTemporaryFiles deletes only directories created by this fixture under /tmp.
# Uses the unmodified production PowerShell helper and AST-extracted final cleanup.
# The Windows platform variable and native argv matcher are explicitly replaced for Linux.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceRoot,
    [switch]$RealTemporaryFiles
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Refuse to exercise any source except the exact reviewed public snapshot.
$head = (Resolve-Path -LiteralPath $SourceRoot).Path
$sourceHashes = @{
    'tests/helpers/HostedSmokeDiagnostics.ps1' = '830f566cdd7bb0f08224d37331e54fbf40662939e76f37d8bb725215d4823ea8'
    'tests/Invoke-HostedDashboardRuntimeSmoke.ps1' = '86449cfe90049ebf301f03ddc8c7003b19cb4f50bdf1538afc998a93c25d6128'
}
foreach ($relative in $sourceHashes.Keys) {
    $actual = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath (Join-Path $head $relative) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $sourceHashes[$relative]) { throw "Exact reviewed source hash mismatch: $relative" }
}
Set-Variable -Name IsWindows -Value $true -Scope Script -Force
Add-Type -TypeDefinition @'
namespace HostedSmoke {
 public static class Capture {
  public static string ExpectedProfile;
  public static bool OwnsProfile(string command, string profile) {
   return command == "synthetic-owned-root" && profile == ExpectedProfile;
  }
 }
}
'@
. (Join-Path $head 'tests/helpers/HostedSmokeDiagnostics.ps1')
$script:created = [datetime]'2026-01-01T00:00:00Z'
$profilePath = '/review/synthetic-profile'
if ($RealTemporaryFiles) {
    $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('defender-cleanup-review-' + [guid]::NewGuid().ToString('N'))
    $profilePath = Join-Path $fixtureRoot 'profile'
    [void](New-Item -ItemType Directory -Path $profilePath)
    'fixture-only sentinel' | Microsoft.PowerShell.Management\Set-Content -LiteralPath (Join-Path $profilePath 'sentinel.txt')
}
[HostedSmoke.Capture]::ExpectedProfile = $profilePath
function New-MockRecord([int]$Id, [int]$Parent, [bool]$Root) {
    [pscustomobject]@{ Name = $(if ($Root) { 'msedge.exe' } else { 'non-edge-child.exe' }); CommandLine = $(if ($Root) { 'synthetic-owned-root' } else { 'no profile argument' }); ProcessId = $Id; ParentProcessId = $Parent; CreationDate = $script:created.AddSeconds($(if ($Root) { 0 } else { 1 })) }
}
function Get-CimInstance {
    [CmdletBinding()] param($ClassName, $Filter)
    $script:inventoryCalls++
    if ($Filter) {
        $ids = @([regex]::Matches($Filter, 'ProcessId=(\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
        return @($script:items | Where-Object { $_.ProcessId -in $ids })
    }
    return @($script:items)
}
function Get-Process {
    [CmdletBinding()] param($Id)
    $item = @($script:items | Where-Object ProcessId -eq $Id)
    if ($item.Count -eq 0) { return }
    $process = [pscustomobject]@{ Id = [int]$Id; StartTime = $item[0].CreationDate; HasExited = $false; BoundCreated = $item[0].CreationDate; MockHandlePinned = $false }
    $process | Add-Member ScriptProperty SafeHandle { $this.MockHandlePinned = $true; return $this }
    if ($script:scenario -eq 'pid-reuse-after-starttime') {
        $process | Add-Member ScriptProperty StartTime {
            # Model verified .NET Windows semantics: StartTime reads through a temporary
            # handle, releases it, and does not pin the Process object. The original
            # process then exits and its PID is reused before Kill opens its own handle.
            $originalCreation = $this.BoundCreated
            $script:items = @([pscustomobject]@{ Name = 'unrelated.exe'; CommandLine = 'unrelated'; ProcessId = $this.Id; ParentProcessId = 0; CreationDate = $originalCreation.AddHours(1) })
            return $originalCreation
        } -Force
    }
    $process | Add-Member ScriptMethod Kill {
        if ($script:scenario -eq 'failed-child-two-passes' -and $this.Id -eq 1002) {
            throw [ComponentModel.Win32Exception]::new(5)
        }
        if ($script:scenario -eq 'late-born-child' -and $this.Id -eq 1001) {
            # Birth after initial inventory/fresh root validation and before root termination.
            $script:items += New-MockRecord 1002 1001 $false
        }
        if ($script:scenario -eq 'pid-reuse-after-starttime') {
            if ($this.MockHandlePinned) { $this.HasExited = $true; return }
            $script:terminatedIdentities.Add(@($script:items | Where-Object ProcessId -eq $this.Id)[0])
        }
        $script:killed.Add($this.Id)
        $script:items = @($script:items | Where-Object ProcessId -ne $this.Id)
        $this.HasExited = $true
    }
    $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) return $this.HasExited }
    $process | Add-Member ScriptMethod Dispose { }
    return $process
}
function Assert-Repro([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
$results = [Collections.Generic.List[object]]::new()

$script:scenario = 'late-born-child'
$script:items = @(New-MockRecord 1001 0 $true)
$script:killed = [Collections.Generic.List[int]]::new()
$script:inventoryCalls = 0
$lateBorn = Stop-HostedSmokeProfileProcess -ProfilePath $profilePath
Assert-Repro ($lateBorn.Confirmed -and $lateBorn.Failures.Count -eq 0 -and $script:items.Count -eq 1 -and $script:items[0].ProcessId -eq 1002) 'Late-child reproduction did not discriminate.'
$results.Add([pscustomobject]@{ Scenario = $script:scenario; Confirmed = $lateBorn.Confirmed; Failures = $lateBorn.Failures; KilledPids = $script:killed.ToArray(); RemainingPids = @($script:items.ProcessId); InventoryCalls = $script:inventoryCalls })

$script:scenario = 'pid-reuse-after-starttime'
$script:items = @(New-MockRecord 1001 0 $true)
$script:killed = [Collections.Generic.List[int]]::new()
$script:terminatedIdentities = [Collections.Generic.List[object]]::new()
$script:inventoryCalls = 0
$reusedAfterStartTime = Stop-HostedSmokeProfileProcess -ProfilePath $profilePath
Assert-Repro ($script:terminatedIdentities.Count -eq 1 -and $script:terminatedIdentities[0].Name -eq 'unrelated.exe' -and $reusedAfterStartTime.Confirmed) 'Late PID reuse reproduction did not discriminate.'
$results.Add([pscustomobject]@{ Scenario = $script:scenario; Result = $reusedAfterStartTime; TerminatedMockIdentities = $script:terminatedIdentities.ToArray(); InventoryCalls = $script:inventoryCalls; Model = 'Primary-source-supported Windows handle-lifetime model, not native PID-reuse evidence' })

$script:scenario = 'failed-child-two-passes'
$script:items = @((New-MockRecord 1001 0 $true), (New-MockRecord 1002 1001 $false))
$script:killed = [Collections.Generic.List[int]]::new()
$script:inventoryCalls = 0
$first = Stop-HostedSmokeProfileProcess -ProfilePath $profilePath
Assert-Repro (-not $first.Confirmed -and $first.Failures -contains 'process-access-denied' -and $first.Failures -contains 'owned-process-remains' -and $script:items.Count -eq 1) 'First-pass retained-child failure did not discriminate.'
$tokens = $null; $parseErrors = $null
$smokeAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $head 'tests/Invoke-HostedDashboardRuntimeSmoke.ps1'), [ref]$tokens, [ref]$parseErrors)
Assert-Repro ($parseErrors.Count -eq 0) 'Production script did not parse.'
$mainTry = $smokeAst.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] } | Select-Object -Last 1
$finallyText = $mainTry.Finally.Extent.Text
$priorCleanupFailures = @($first.Failures)
$priorCleanupDiagnostics = @($first.Diagnostics)
$canaryResult = [pscustomobject]@{ drainIncomplete = $false }
$dashboardResult = $null
$serverJob = $null
$outcome = 'cleanup-failure'
$setupPhase = 'canary-capture'
$failureClass = 'runtime'; $failureLine = 587; $ControlFixture = $false; $extensionSessionCount = 0
$diagnosticRunPath = '/review/synthetic-diagnostics'; $smokeRoot = '/review/synthetic-site'
if ($RealTemporaryFiles) { $smokeRoot = Join-Path $fixtureRoot 'site'; [void](New-Item -ItemType Directory -Path $smokeRoot) }
$script:profileExists = $true; $script:siteExists = $true
$script:removed = [Collections.Generic.List[string]]::new()
$script:runRecord = $null
function Test-Path {
    [CmdletBinding()] param($LiteralPath)
    if ($RealTemporaryFiles -and $LiteralPath -in @($profilePath, $smokeRoot)) { return Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath }
    if ($LiteralPath -eq $profilePath) { return $script:profileExists }
    if ($LiteralPath -eq $smokeRoot) { return $script:siteExists }
    throw 'Unexpected filesystem query in mock.'
}
function Remove-Item {
    [CmdletBinding()] param($LiteralPath, [switch]$Recurse, [switch]$Force)
    $script:removed.Add($LiteralPath)
    if ($RealTemporaryFiles -and $LiteralPath -in @($profilePath, $smokeRoot)) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Recurse -Force }
    if ($LiteralPath -eq $profilePath) { $script:profileExists = $false; return }
    if ($LiteralPath -eq $smokeRoot) { $script:siteExists = $false; return }
    throw 'Unexpected filesystem deletion in mock.'
}
function Set-Content {
    [CmdletBinding()] param($LiteralPath, $Encoding, [Parameter(ValueFromPipeline)]$Value)
    process { $script:runRecord = $Value | ConvertFrom-Json }
}
. ([scriptblock]::Create('try { } finally ' + $finallyText))
Assert-Repro ($script:runRecord.processCleanupConfirmed -and $script:runRecord.profileRemoved -and $script:items.Count -eq 1 -and $script:items[0].ProcessId -eq 1002 -and $script:runRecord.outcome -eq 'cleanup-failure') 'Final-pass false cleanup confirmation/profile removal did not discriminate.'
$results.Add([pscustomobject]@{ Scenario = $script:scenario; FirstPass = $first; FinalPassRecord = $script:runRecord; KilledPids = $script:killed.ToArray(); RemainingPids = @($script:items.ProcessId); RemovedPaths = $script:removed.ToArray(); ActualTemporaryProfileDeletion = [bool]$RealTemporaryFiles; InventoryCalls = $script:inventoryCalls })
$results | ConvertTo-Json -Depth 10
if ($RealTemporaryFiles) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
