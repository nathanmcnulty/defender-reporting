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
    $proof = [pscustomobject]@{ RunId = $RunId; ProfileKey = ('c' * 64); Created = $true; Assigned = $true; Resumed = $true; Sealed = $true; RootInOuterBeforeInner = $true; OuterPolicyConfirmed = $true; OuterJobLimitBytes = 2GB; Terminal = $true; Confirmed = $true; StreamsComplete = $true; ActiveProcesses = 0; Pids = @() }
    switch ($Failure) {
        'wrong-run' { $proof.RunId = ('0' * 32) }
        'wrong-profile' { $proof.ProfileKey = ('0' * 64) }
        'not-resumed' { $proof.Resumed = $false }
        'outer-policy' { $proof.OuterPolicyConfirmed = $false }
        'root-outside' { $proof.RootInOuterBeforeInner = $false }
        'outer-cap' { $proof.OuterJobLimitBytes = 4GB }
        'nonzero' { $proof.ActiveProcesses = 1; $proof.Pids = @(101) }
        'stream-unknown' { $proof.StreamsComplete = $false }
    }
    $owner = [pscustomobject]@{ Proof = $proof; Failure = $Failure; Disposals = 0 }
    $owner | Add-Member ScriptMethod Stop { param($Milliseconds) if ($this.Failure -eq 'query-failure') { throw 'Synthetic query failure.' }; return $this.Proof }
    $owner | Add-Member ScriptMethod Dispose { $this.Disposals++; if ($this.Failure -eq 'dispose-failure') { throw 'Synthetic close failure.' } }
    return [pscustomobject]@{ Owner = $owner; RunId = $RunId; ProfileKey = ('c' * 64); ProfilePath = 'synthetic'; Failed = ($Failure -eq 'prior-failure'); Confirmed = $false; Receipt = $null }
}
function Assert-LaunchBoundProfileContained { param($Owner, $ProfilePath) if ($Owner.Failure -eq 'outside-profile') { throw 'Synthetic outside member.' } }
foreach ($case in @('good','wrong-run','wrong-profile','not-resumed','outer-policy','root-outside','outer-cap','nonzero','stream-unknown','query-failure','prior-failure','outside-profile')) {
    $attempt = New-SyntheticAttempt ('a' * 32) $case
    $result = Complete-LaunchBoundAttempt -Attempt $attempt
    Assert-Owner ($result.Confirmed -eq ($case -eq 'good')) "Wrong authority result: $case."
    if ($case -ne 'good') {
        $attempt.Owner.Proof.RunId = $attempt.RunId; $attempt.Owner.Proof.ProfileKey = $attempt.ProfileKey; $attempt.Owner.Proof.Resumed = $true
        $attempt.Owner.Proof.ActiveProcesses = 0; $attempt.Owner.Proof.Pids = @(); $attempt.Owner.Proof.StreamsComplete = $true; $attempt.Owner.Failure = ''
        $attempt.Owner.Proof.RootInOuterBeforeInner = $true; $attempt.Owner.Proof.OuterPolicyConfirmed = $true; $attempt.Owner.Proof.OuterJobLimitBytes = 2GB
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
# Exercise the actual adapter body/parser with an inert owner sentinel. Every
# rejected activation is followed by an otherwise valid start request, so a
# bypass would increment the constructor/start counters rather than go unnoticed.
Assert-Owner (-not ('LaunchBound.JobOwner' -as [type])) 'Activation sentinel would replace a loaded native owner.'
Add-Type -TypeDefinition @'
namespace LaunchBound {
 public sealed class GateActor {public int Pid=4242,ParentPid=4241;public string CreationFileTime="123",ImagePath;}
 public sealed class JobOwner {
  public static int Constructed,Started,Disposed;public static string Image;public string Failure="";
  public JobOwner(string run,string profile){Constructed++;}
  public static object ReadActorIdentity(){return new GateActor{ImagePath=Image};}
  public static void Reset(){Constructed=Started=Disposed=0;}
  public object Start(string executable,string[] arguments,string profile){Started++;return new{synthetic=true};}
  public void Dispose(){Disposed++;}
 }
}
'@
$tokens=$null;$errors=$null
$adapterAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'helpers/Invoke-LaunchBoundOwner.ps1'),[ref]$tokens,[ref]$errors)
Assert-Owner ($errors.Count -eq 0) 'Actual activation adapter parse failure.'
foreach($name in @('Read-OwnerRequest','Write-OwnerReply')){
    $definition=@($adapterAst.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
    Assert-Owner ($definition.Count -eq 1) 'Activation function extraction mismatch.'
    . ([scriptblock]::Create($definition[0].Extent.Text))
}
$adapterMain=@($adapterAst.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})
Assert-Owner ($adapterMain.Count -eq 1) 'Actual activation body extraction mismatch.'
$actualGateBody=[scriptblock]::Create('try '+$adapterMain[0].Body.Extent.Text+' finally '+$adapterMain[0].Finally.Extent.Text)
foreach($gateCase in @('valid','nonce','actor-pid','actor-time','actor-image','pid-type','version-type','command-type','nonce-type','extra-root','extra-actor','missing-actor','duplicate-root','duplicate-actor','oversize','malformed','eof')){
    & {
        [LaunchBound.JobOwner]::Reset();[LaunchBound.JobOwner]::Image=Join-Path ([IO.Path]::GetTempPath()) 'synthetic-pwsh.exe'
        $owner=$null;$runId=$null;$profilePath=$null;$sequence=0;$nonce='a'*64;$BridgeNonce='b'*64
        $ack=[ordered]@{v=1;command='bridge-ready';bridgeNonce=$BridgeNonce;actor=[ordered]@{Pid=4242;ParentPid=4241;CreationFileTime='123';ImagePath=[LaunchBound.JobOwner]::Image}}
        switch($gateCase){
            'nonce'{$ack.bridgeNonce='c'*64}
            'actor-pid'{$ack.actor.Pid=4243}
            'actor-time'{$ack.actor.CreationFileTime='124'}
            'actor-image'{$ack.actor.ImagePath+='-foreign'}
            'pid-type'{$ack.actor.Pid='4242'}
            'version-type'{$ack.v='1'}
            'command-type'{$ack.command=@('bridge-ready')}
            'nonce-type'{$ack.bridgeNonce=@($BridgeNonce)}
            'extra-root'{$ack.extra=$true}
            'extra-actor'{$ack.actor.extra=$true}
            'missing-actor'{$ack.Remove('actor')}
        }
        $line=$ack|ConvertTo-Json -Compress -Depth 8
        if($gateCase -ceq 'duplicate-root'){$line=$line.Replace('"v":1','"v":1,"v":1')}
        if($gateCase -ceq 'duplicate-actor'){$line=$line.Replace('"Pid":4242','"Pid":4242,"Pid":4243')}
        if($gateCase -ceq 'oversize'){$line='x'*65537}
        if($gateCase -ceq 'malformed'){$line='{invalid'}
        $start=@{v=1;nonce=$nonce;runId=('d'*32);profile=(Join-Path ([IO.Path]::GetTempPath()) 'synthetic-activation-profile');seq=1;command='start';executable='synthetic';arguments=@()}|ConvertTo-Json -Compress
        $inputText=if($gateCase -ceq 'eof'){''}else{$line+"`n"+$start+"`n"}
        $savedInput=[Console]::In;$savedOutput=[Console]::Out;$inputReader=[IO.StringReader]::new($inputText);$outputWriter=[IO.StringWriter]::new();$accepted=$false
        try{[Console]::SetIn($inputReader);[Console]::SetOut($outputWriter);try{. $actualGateBody;$accepted=$true}catch{$accepted=$false}}
        finally{[Console]::SetIn($savedInput);[Console]::SetOut($savedOutput);$inputReader.Dispose();$outputWriter.Dispose()}
        $expected=[int]($gateCase -ceq 'valid')
        Assert-Owner ($accepted -eq ($expected -eq 1) -and [LaunchBound.JobOwner]::Constructed -eq $expected -and [LaunchBound.JobOwner]::Started -eq $expected -and [LaunchBound.JobOwner]::Disposed -eq $expected) "Actual bridge gate escaped construction/start barrier: $gateCase."
    }
}
Write-Output 'PASS launch-bound PowerShell proof binding/sticky unknown, actual finalizer/profile gate and source-bound activation parser/validator/EOF barrier; synthetic authority only.'
