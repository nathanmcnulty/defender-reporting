#Requires -Version 7.6
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Synthetic process APIs retain actual production bindings.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Child-scoped mocks never inventory or stop native processes.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Removal mock restricts deletion to freshly created fixture directories.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are consumed by the actual AST-extracted finally block.')]
[CmdletBinding()]
param([string]$SourceRoot = (Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $SourceRoot 'tests/helpers/HostedSmokeDiagnostics.ps1')
Initialize-HostedSmokeCapture
if (-not $IsWindows) { return }
function Assert-Safety([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $SourceRoot 'tests/Invoke-HostedDashboardRuntimeSmoke.ps1'), [ref]$tokens, [ref]$errors)
Assert-Safety ($errors.Count -eq 0) 'Runtime smoke parse failed.'
$mainTry = $ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] } | Select-Object -Last 1
$finallyText = $mainTry.Finally.Extent.Text
foreach ($scenario in @('late-child','after-starttime','handle-denied','handle-invalid','handle-closed','dispose-failure','wait-failure','two-passes','sticky-empty','empty-positive')) {
    & {
        $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('smoke-safety-' + [guid]::NewGuid().ToString('N'))
        $profilePath = Join-Path $fixtureRoot 'profile'
        $smokeRoot = Join-Path $fixtureRoot 'site'
        $diagnosticRunPath = Join-Path $fixtureRoot 'diagnostics'
        [void](New-Item -ItemType Directory -Path $profilePath,$smokeRoot,$diagnosticRunPath)
        function Remove-FixturePath([string]$Path) {
            $full = [IO.Path]::GetFullPath($Path)
            $parent = [IO.Path]::GetFullPath($fixtureRoot)
            if ($full -ne $parent -and -not $full.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Out-of-scope fixture removal.' }
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath $full -Recurse -Force
        }
        try {
            $created = [datetime]::UtcNow.AddMinutes(-2)
            $rootCommand = 'msedge.exe --user-data-dir="' + $profilePath + '"'
            function New-SyntheticRecord([int]$Id, [int]$Parent, [bool]$Root) {
                [pscustomobject]@{ Name = $(if ($Root) { 'msedge.exe' } else { 'non-edge-child.exe' }); CommandLine = $(if ($Root) { $rootCommand } else { 'no-profile' }); ProcessId = $Id; ParentProcessId = $Parent; CreationDate = $created.AddSeconds($(if ($Root) { 0 } else { 1 })) }
            }
            $script:items = @()
            if ($scenario -ne 'empty-positive') { $script:items = @(New-SyntheticRecord 1001 0 $true) }
            if ($scenario -in @('two-passes','sticky-empty')) { $script:items += New-SyntheticRecord 1002 1001 $false }
            $script:processObjects = [Collections.Generic.List[object]]::new()
            $script:replacementKills = 0
            $script:runRecord = $null
            function Get-CimInstance {
                [CmdletBinding()] param($ClassName, $Filter)
                if ($Filter) {
                    $ids = @([regex]::Matches($Filter, 'ProcessId=(\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
                    return @($script:items | Where-Object { $_.ProcessId -in $ids })
                }
                return $script:items
            }
            function Get-Process {
                [CmdletBinding()] param($Id)
                $item = @($script:items | Where-Object ProcessId -eq $Id)
                if (-not $item.Count) { return }
                $process = [pscustomobject]@{ Id = [int]$Id; BoundCreated = $item[0].CreationDate; Pinned = $false; HasExited = $false; StartReads = 0; KillCalls = 0; WaitCalls = 0; DisposeCalls = 0 }
                $process | Add-Member ScriptProperty SafeHandle {
                    if ($scenario -eq 'handle-denied') { throw [ComponentModel.Win32Exception]::new(5) }
                    $this.Pinned = $true
                    return [pscustomobject]@{ IsInvalid = ($scenario -eq 'handle-invalid'); IsClosed = ($scenario -eq 'handle-closed') }
                }
                $process | Add-Member ScriptProperty StartTime {
                    $this.StartReads++
                    if ($scenario -eq 'after-starttime') {
                        $script:items = @([pscustomobject]@{ Name = 'unrelated.exe'; CommandLine = 'unrelated'; ProcessId = $this.Id; ParentProcessId = 0; CreationDate = $this.BoundCreated.AddHours(1) })
                        $this.HasExited = $true
                    }
                    return $this.BoundCreated
                }
                $process | Add-Member ScriptMethod Kill {
                    $this.KillCalls++
                    if (-not $this.Pinned) { $script:replacementKills++; throw 'Unpinned kill.' }
                    if ($scenario -eq 'after-starttime') { return }
                    if ($scenario -in @('two-passes','sticky-empty') -and $this.Id -eq 1002) { throw [ComponentModel.Win32Exception]::new(5) }
                    if ($scenario -eq 'late-child') { $script:items += New-SyntheticRecord 1002 1001 $false }
                    $script:items = @($script:items | Where-Object ProcessId -ne $this.Id)
                    $this.HasExited = $true
                }
                $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) $this.WaitCalls++; return $scenario -ne 'wait-failure' }
                $process | Add-Member ScriptMethod Dispose { $this.DisposeCalls++; if ($scenario -eq 'dispose-failure') { throw 'Synthetic disposal failure.' } }
                $script:processObjects.Add($process)
                return $process
            }
            $first = Stop-HostedSmokeProfileProcess -ProfilePath $profilePath
            if ($scenario -eq 'empty-positive') { Assert-Safety ($first.Confirmed -and $first.Failures.Count -eq 0) 'Empty positive control failed.' }
            else { Assert-Safety (-not $first.Confirmed -and $first.Failures.Count -gt 0) "Unresolved cleanup falsely confirmed: $scenario." }
            if ($scenario -eq 'late-child') {
                Assert-Safety ($script:items.Count -eq 1 -and $script:items[0].ProcessId -eq 1002 -and $first.Diagnostics -contains 'process-descendant-unresolved') 'Late birth was lost or incorrectly killed.'
            }
            if ($scenario -eq 'after-starttime') { Assert-Safety ($script:replacementKills -eq 0 -and $script:items.Count -eq 1 -and $script:items[0].Name -eq 'unrelated.exe') 'Post-StartTime reuse killed replacement.' }
            foreach ($process in $script:processObjects) {
                Assert-Safety ($process.DisposeCalls -eq 1) "Process not disposed exactly once: $scenario."
                if ($scenario -in @('handle-denied','handle-invalid','handle-closed')) { Assert-Safety ($process.StartReads -eq 0 -and $process.KillCalls -eq 0 -and $process.WaitCalls -eq 0) 'Handle failure reached identity/kill/wait.' }
            }
            if ($scenario -eq 'sticky-empty') { $script:items = @() }
            # Exercise the actual finalizer and real deletion branch across both calls.
            $cleanupLedger = $first.Ledger
            $priorCleanupUnconfirmed = -not $first.Confirmed -or $first.Failures.Count -gt 0
            $priorCleanupFailures = @($first.Failures); $priorCleanupDiagnostics = @($first.Diagnostics)
            $canaryResult = [pscustomobject]@{ drainIncomplete = $false }; $dashboardResult = $null
            $serverJob = $null; $outcome = $(if ($priorCleanupUnconfirmed) { 'cleanup-failure' } else { 'passed' })
            $setupPhase = 'canary-capture'; $failureClass = $null; $failureLine = $null; $ControlFixture = $false; $extensionSessionCount = 0; $runId = 'synthetic'
            function Remove-Item { [CmdletBinding()] param($LiteralPath, [switch]$Recurse, [switch]$Force) Remove-FixturePath $LiteralPath }
            function Set-Content { [CmdletBinding()] param($LiteralPath, $Encoding, [Parameter(ValueFromPipeline)]$Value) process { $script:runRecord = $Value | ConvertFrom-Json } }
            . ([scriptblock]::Create('try { } finally ' + $finallyText))
            if ($scenario -eq 'empty-positive') {
                Assert-Safety ($script:runRecord.processCleanupConfirmed -and $script:runRecord.profileRemoved -and -not (Test-Path -LiteralPath $profilePath)) 'Positive finalizer did not remove absent/clean fixture.'
            }
            else {
                Assert-Safety (-not $script:runRecord.processCleanupConfirmed -and -not $script:runRecord.profileRemoved -and (Test-Path -LiteralPath $profilePath)) "Finalizer forgot unresolved ownership: $scenario."
            }
        }
        finally { if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $fixtureRoot) { Remove-FixturePath $fixtureRoot } }
    }
}
# Untrusted state may prevent cleanup confirmation, but never authorize a kill.
foreach ($ledgerCase in @('absent-root','missing-property','bad-parent','wrong-profile','accounting-only')) {
    & {
        $ledgerProfilePath = Join-Path ([IO.Path]::GetTempPath()) 'synthetic-ledger-profile'
        $created = [datetime]'2026-01-01T00:00:00Z'
        $root = [pscustomobject]@{ Pid=1001; Created=$created; RootPid=1001; RootCreated=$created; ParentPid=0 }
        $child = [pscustomobject]@{ Pid=1002; Created=$created.AddSeconds(1); RootPid=1001; RootCreated=$created; ParentPid=1001 }
        $ledger = [pscustomobject]@{ PSTypeName='HostedSmoke.CleanupLedger'; Version=1; Profile=$ledgerProfilePath; Known=@($root,$child); AccountingIncomplete=$false }
        switch ($ledgerCase) {
            'absent-root' { $ledger.Known=@($child) }
            'missing-property' { $child.PSObject.Properties.Remove('ParentPid') }
            'bad-parent' { $child.ParentPid=9999 }
            'wrong-profile' { $ledger.Profile=$ledgerProfilePath+'-other' }
        }
        $script:ledgerInventories=0; $script:ledgerProcessOpens=0
        function Get-CimInstance {
            [CmdletBinding()] param($ClassName,$Filter)
            $script:ledgerInventories++
            [pscustomobject]@{Name='unrelated.exe';ProcessId=1002;ParentProcessId=1001;CreationDate=$created.AddSeconds(1);CommandLine='unrelated'}
        }
        function Get-Process { [CmdletBinding()] param($Id) $script:ledgerProcessOpens++; throw 'Untrusted state reached process open.' }
        $result=Stop-HostedSmokeProfileProcess -ProfilePath $ledgerProfilePath -Ledger $ledger
        Assert-Safety (-not $result.Confirmed -and $result.Failures -contains 'process-accounting-incomplete' -and $script:ledgerProcessOpens -eq 0) 'Ledger granted kill authority or false confirmation.'
        if ($ledgerCase -ne 'accounting-only') {
            Assert-Safety ($script:ledgerInventories -eq 0 -and $result.Failures -contains 'process-ledger-invalid' -and -not [object]::ReferenceEquals($result.Ledger,$ledger)) 'Malformed/wrong-profile ledger was trusted.'
        }
        else { Assert-Safety ($result.Ledger.AccountingIncomplete -and $result.Failures -contains 'owned-process-remains') 'Historical match lost from accounting.' }
    }
}
Write-Output 'Hosted smoke safety regressions passed (retained handle, late birth, cross-call ledger, real profile-retention branch, and positive absence).'
