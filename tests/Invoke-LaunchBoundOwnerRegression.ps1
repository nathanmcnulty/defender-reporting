#Requires -Version 7.0
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Synthetic authority/profile APIs keep production parameter bindings.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Child-scoped fixture mocks; no native process or external filesystem action.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Only freshly created canonicalized fixture paths may be removed.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are consumed by the actual extracted finally block.')]
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'helpers/LaunchBoundOwner.ps1')
function Assert-Owner([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function New-SyntheticAttempt($RunId, $Failure) {
    $proof = [pscustomobject]@{ RunId = $RunId; ProfileKey = ('c' * 64); Created = $true; Assigned = $true; Resumed = $true; Sealed = $true; Terminal = $true; Confirmed = $true; StreamsComplete = $true; ActiveProcesses = 0; Pids = @() }
    switch ($Failure) {
        'wrong-run' { $proof.RunId = ('0' * 32) }
        'wrong-profile' { $proof.ProfileKey = ('0' * 64) }
        'not-resumed' { $proof.Resumed = $false }
        'nonzero' { $proof.ActiveProcesses = 1; $proof.Pids = @(101) }
        'stream-unknown' { $proof.StreamsComplete = $false }
    }
    $owner = [pscustomobject]@{ Proof = $proof; Failure = $Failure; Disposals = 0 }
    $owner | Add-Member ScriptMethod Stop { param($Milliseconds) if ($this.Failure -eq 'query-failure') { throw 'Synthetic query failure.' }; return $this.Proof }
    $owner | Add-Member ScriptMethod Dispose { $this.Disposals++; if ($this.Failure -eq 'dispose-failure') { throw 'Synthetic close failure.' } }
    return [pscustomobject]@{ Owner = $owner; RunId = $RunId; ProfileKey = ('c' * 64); ProfilePath = 'synthetic'; Failed = ($Failure -eq 'prior-failure'); Confirmed = $false; Receipt = $null }
}
function Assert-LaunchBoundProfileContained { param($Owner, $ProfilePath) if ($Owner.Failure -eq 'outside-profile') { throw 'Synthetic outside member.' } }
foreach ($case in @('good','wrong-run','wrong-profile','not-resumed','nonzero','stream-unknown','query-failure','prior-failure','outside-profile')) {
    $attempt = New-SyntheticAttempt ('a' * 32) $case
    $result = Complete-LaunchBoundAttempt -Attempt $attempt
    Assert-Owner ($result.Confirmed -eq ($case -eq 'good')) "Wrong authority result: $case."
    if ($case -ne 'good') {
        $attempt.Owner.Proof.RunId = $attempt.RunId; $attempt.Owner.Proof.ProfileKey = $attempt.ProfileKey; $attempt.Owner.Proof.Resumed = $true
        $attempt.Owner.Proof.ActiveProcesses = 0; $attempt.Owner.Proof.Pids = @(); $attempt.Owner.Proof.StreamsComplete = $true; $attempt.Owner.Failure = ''
        Assert-Owner (-not (Complete-LaunchBoundAttempt -Attempt $attempt).Confirmed) 'An unknown attempt became clean on retry.'
    }
}
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-HostedDashboardRuntimeSmoke.ps1'), [ref]$tokens, [ref]$errors)
Assert-Owner ($errors.Count -eq 0) 'Main parse failure.'
$main = $ast.EndBlock.Statements | Where-Object { $_ -is [Management.Automation.Language.TryStatementAst] } | Select-Object -Last 1
foreach ($case in @('good','first-unknown','second-unknown','dispose-failure','no-launch')) {
    & {
        $fixture = Join-Path ([IO.Path]::GetTempPath()) ('launch-bound-finally-' + [guid]::NewGuid().ToString('N'))
        $profilePath = Join-Path $fixture 'profile'; $smokeRoot = Join-Path $fixture 'site'; $diagnosticRunPath = $fixture
        [void](New-Item -ItemType Directory -Path $profilePath,$smokeRoot)
        function Remove-Fixture($Path) {
            $full = [IO.Path]::GetFullPath($Path); $parent = [IO.Path]::GetFullPath($fixture)
            if ($full -ne $parent -and -not $full.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Out-of-scope fixture removal.' }
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath $full -Recurse -Force
        }
        try {
            $launchBoundAttempts = [Collections.Generic.List[object]]::new()
            if ($case -ne 'no-launch') {
                $launchBoundAttempts.Add((New-SyntheticAttempt ('a' * 32) $(if ($case -eq 'first-unknown') { 'query-failure' } elseif ($case -eq 'dispose-failure') { 'dispose-failure' } else { '' })))
                $launchBoundAttempts.Add((New-SyntheticAttempt ('b' * 32) $(if ($case -eq 'second-unknown') { 'stream-unknown' } else { '' })))
            }
            $priorCleanupUnconfirmed = $false; $priorCleanupFailures = @(); $priorCleanupDiagnostics = @(); $cleanupLedger = $null
            $canaryResult = [pscustomobject]@{drainIncomplete=$false}; $dashboardResult = [pscustomobject]@{drainIncomplete=$false}
            $serverJob = $null; $outcome = 'passed'; $setupPhase = 'synthetic'; $failureClass = $null; $failureLine = $null; $ControlFixture = $false; $extensionSessionCount = 0
            $script:record = $null
            function Stop-HostedSmokeProfileProcess { throw 'Legacy cleanup must never authorize an owner run.' }
            function Remove-Item { [CmdletBinding()] param($LiteralPath,[switch]$Recurse,[switch]$Force) Remove-Fixture $LiteralPath }
            function Set-Content { [CmdletBinding()] param($LiteralPath,$Encoding,[Parameter(ValueFromPipeline)]$Value) process { $script:record = $Value | ConvertFrom-Json } }
            . ([scriptblock]::Create('try {} finally ' + $main.Finally.Extent.Text))
            Assert-Owner ($script:record.processCleanupConfirmed -eq ($case -eq 'good')) "Wrong aggregate: $case."
            Assert-Owner ($script:record.profileRemoved -eq ($case -eq 'good')) "Wrong profile gate: $case."
            foreach ($attempt in $launchBoundAttempts) { Assert-Owner ($attempt.Owner.Disposals -eq 1) 'A later owner was abandoned after earlier failure.' }
        } finally { if (Test-Path -LiteralPath $fixture) { Remove-Fixture $fixture } }
    }
}
Write-Output 'PASS launch-bound PowerShell proof binding/sticky unknown and actual two-attempt finalizer/profile gate; synthetic authority only.'
