#Requires -Version 7.6
# Prepared only under instruction 0004. Source-bound inert checks; no fixture or process is launched.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'options', Justification='Consumed by the exact extracted Start-FixtureChild ArgumentList construction dot-sourced below.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'Mode', Justification='Consumed by the exact extracted Start-FixtureChild ArgumentList construction dot-sourced below.')]
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(-not $IsWindows) { throw 'Windows fixture path contracts required.' }
$fixture=Join-Path $PSScriptRoot 'helpers/LaunchBoundFixture.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($fixture,[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0) { throw 'Fixture source parse failed.' }
function Assert-Contract([bool]$Condition,[string]$Message) { if(-not $Condition) { throw $Message } }
foreach($name in @('Read-FixtureOption','Start-FixtureChild')) {
    $definitions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    Assert-Contract ($definitions.Count -eq 1) 'Fixture definition is ambiguous.'
    if($name -ceq 'Read-FixtureOption') { . ([scriptblock]::Create($definitions[0].Extent.Text)) }
    else { $childDefinition=$definitions[0] }
}
# Actual pure cache-selection and byte-binding functions; no filesystem/assembly load.
foreach($name in @('Select-FixtureAssemblyPreparation','Confirm-FixtureAssemblyCache')) {
    $definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    Assert-Contract ($definitions.Count -eq 1) 'Fixture cache definition ambiguous.'
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
foreach($descendant in @($false,$true)) { foreach($dllExists in @($false,$true)) { foreach($manifestExists in @($false,$true)) {
    $expected=if($descendant){$dllExists -and $manifestExists}else{-not $dllExists -and -not $manifestExists}
    $rejected=$false;$selection=$null;try{$selection=Select-FixtureAssemblyPreparation $descendant $dllExists $manifestExists}catch{$rejected=$true}
    Assert-Contract ($rejected -eq (-not $expected)) 'Cache regeneration or stale root cache accepted.'
    if($expected){Assert-Contract ($selection -ceq $(if($descendant){'load'}else{'compile'})) 'Wrong fixture cache preparation action.'}
} } }
$cacheRun='a'*32;$cacheSource='b'*64;$cacheBytes=[byte[]]@(1,2,3,4)
$cacheHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($cacheBytes)).ToLowerInvariant()
$cacheManifest=@{schema=1;runId=$cacheRun;sourceSha256=$cacheSource;assemblySha256=$cacheHash}
function ConvertTo-FixtureManifestData($Value){[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Compress))}
$returned=Confirm-FixtureAssemblyCache $cacheBytes (ConvertTo-FixtureManifestData $cacheManifest) $cacheRun $cacheSource
Assert-Contract ([Convert]::ToHexString($returned) -ceq '01020304') 'Verified cache bytes changed.'
foreach($key in @('schema','runId','sourceSha256','assemblySha256')){
    $badManifest=$cacheManifest.Clone();$badManifest[$key]=if($key -ceq 'schema'){2}else{'c'*64}
    $rejected=$false;try{[void](Confirm-FixtureAssemblyCache $cacheBytes (ConvertTo-FixtureManifestData $badManifest) $cacheRun $cacheSource)}catch{$rejected=$true};Assert-Contract $rejected 'Mismatched cache metadata accepted.'
    $badManifest=$cacheManifest.Clone();$badManifest.Remove($key)
    $rejected=$false;try{[void](Confirm-FixtureAssemblyCache $cacheBytes (ConvertTo-FixtureManifestData $badManifest) $cacheRun $cacheSource)}catch{$rejected=$true};Assert-Contract $rejected 'Partial cache metadata accepted.'
}
foreach($badBytes in @([byte[]]@(),[byte[]]@(1,2,3,5),[byte[]]::new(1048577))){$rejected=$false;try{[void](Confirm-FixtureAssemblyCache $badBytes (ConvertTo-FixtureManifestData $cacheManifest) $cacheRun $cacheSource)}catch{$rejected=$true};Assert-Contract $rejected 'Invalid cache assembly accepted.'}
foreach($badJson in @('{','{}','{"schema":1,"schema":1,"runId":"'+$cacheRun+'","sourceSha256":"'+$cacheSource+'","assemblySha256":"'+$cacheHash+'"}')){$rejected=$false;try{[void](Confirm-FixtureAssemblyCache $cacheBytes ([Text.UTF8Encoding]::new($false).GetBytes($badJson)) $cacheRun $cacheSource)}catch{$rejected=$true};Assert-Contract $rejected 'Malformed or duplicate cache metadata accepted.'}
# The same selector/byte validator binds both caches; native sources remain the exact three files.
foreach($name in @('Read-FixtureAssemblyData','Get-FixtureNativeSourceHash')) {
    $definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    Assert-Contract ($definitions.Count -eq 1) 'Fixture native source fingerprint definition ambiguous.'
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
$nativeSourcePaths=@((Join-Path $PSScriptRoot 'helpers/LaunchBoundJob.cs'),(Join-Path $PSScriptRoot 'helpers/LaunchBoundNativeControls.cs'),(Join-Path $PSScriptRoot 'helpers/LaunchBoundExitObserver.cs'))
Assert-Contract ((Get-FixtureNativeSourceHash $nativeSourcePaths) -cmatch '^[a-f0-9]{64}\z') 'Native source fingerprint unavailable.'
foreach($badPaths in @(@($nativeSourcePaths[0]),@($nativeSourcePaths[1],$nativeSourcePaths[0],$nativeSourcePaths[2]))) { $rejected=$false;try{[void](Get-FixtureNativeSourceHash $badPaths)}catch{$rejected=$true};Assert-Contract $rejected 'Incomplete/reordered native source set accepted.' }
$nativeCompilers=@($childDefinition.Body.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Add-Type'},$true))
Assert-Contract ($nativeCompilers.Count -eq 1 -and $nativeCompilers[0].Extent.Text -ceq 'Add-Type -Path $nativeSourcePaths -OutputAssembly $nativeDll') 'Native compiler source/output binding changed.'
# Compile and test the exact fixture-only detachment workflow with inert calls.
$consoleAssignments=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$consoleSource'},$true))
Assert-Contract ($consoleAssignments.Count -eq 1) 'Fixture console source is ambiguous.'
. ([scriptblock]::Create($consoleAssignments[0].Extent.Text))
Add-Type -TypeDefinition $consoleSource
[LaunchBoundFixtureConsole]::OfflineContracts()
$detachCalls=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Static -and $node.Expression.Extent.Text -ceq '[LaunchBoundFixtureConsole]' -and $node.Member.Value -ceq 'Detach'},$true))
$markerAssignments=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$markerName'},$true))
Assert-Contract ($detachCalls.Count -eq 1 -and ($null -eq $detachCalls[0].Arguments -or $detachCalls[0].Arguments.Count -eq 0) -and $markerAssignments.Count -eq 1 -and $consoleAssignments[0].Extent.StartOffset -lt $detachCalls[0].Extent.StartOffset -and $detachCalls[0].Extent.EndOffset -lt $markerAssignments[0].Extent.StartOffset -and $detachCalls[0].Extent.EndOffset -lt $childDefinition.Extent.StartOffset) 'Fixture detachment must precede its marker and descendants.'
# Extract the actual child's two argument statements, excluding loading and the native launch.
$construction=@($childDefinition.Body.EndBlock.Statements|Where-Object {$_.Extent.Text.StartsWith('$encodedDirectory=',[StringComparison]::Ordinal) -or $_.Extent.Text.StartsWith('$launchArguments=',[StringComparison]::Ordinal)})
Assert-Contract ($construction.Count -eq 2) 'Child argument source has changed.'
$childArguments=[scriptblock]::Create(($construction|ForEach-Object {$_.Extent.Text}) -join "`n")
$launchCalls=@($childDefinition.Body.FindAll({param($node) $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Static -and $node.Member.Value -ceq 'StartFixtureDescendant'},$true))
Assert-Contract ($launchCalls.Count -eq 1 -and $launchCalls[0].Expression.Extent.Text -ceq '[LaunchBound.NativeControls]' -and $launchCalls[0].Arguments.Count -eq 3) 'Fixture native launch endpoint changed.'
Assert-Contract ($launchCalls[0].Arguments[0].Extent.Text -ceq '[Environment]::ProcessPath' -and $launchCalls[0].Arguments[1].Extent.Text -ceq '[string[]]$launchArguments' -and $launchCalls[0].Arguments[2].Extent.Text -ceq '$options[''user-data-dir'']') 'Fixture native launch inputs changed.'
# Execute the actual diagnostic-directory expression only; no filesystem or launch action.
$diagnosticAssignment=@($childDefinition.Body.EndBlock.Statements|Where-Object {$_.Extent.Text.StartsWith('$diagnosticDirectory=',[StringComparison]::Ordinal)})
Assert-Contract ($diagnosticAssignment.Count -eq 1) 'Fixture diagnostic directory expression missing.'
$directory='C:\fixture'
. ([scriptblock]::Create($diagnosticAssignment[0].Extent.Text))
Assert-Contract ($diagnosticDirectory -ceq 'C:\fixture\launch-diagnostics') 'Fixture diagnostics entered marker set.'
$preparationPaths=@($childDefinition.Body.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Join-Path' -and $node.Extent.Text.Contains('$preparationKey')},$true))
Assert-Contract ($preparationPaths.Count -eq 2 -and @($preparationPaths|Where-Object {$_.CommandElements[1].Extent.Text -cne '$diagnosticDirectory'}).Count -eq 0) 'Fixture preparation files entered marker set.'
# Observations remain before the unchanged two 60-second holds and outside marker paths.
$holdSnapshots=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Save-FixtureConsoleHoldSnapshot'},$true)|Sort-Object {$_.Extent.StartOffset})
$holds=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.CommandAst] -and $node.Extent.Text -ceq 'Start-Sleep -Seconds 60'},$true)|Sort-Object {$_.Extent.StartOffset})
Assert-Contract ($holdSnapshots.Count -eq 2 -and $holds.Count -eq 2 -and $holdSnapshots[0].Extent.EndOffset -lt $holds[0].Extent.StartOffset -and $holdSnapshots[1].Extent.EndOffset -lt $holds[1].Extent.StartOffset) 'Console observation must precede unchanged hold.'
$holdDefinition=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Save-FixtureConsoleHoldSnapshot'},$true))
Assert-Contract ($holdDefinition.Count -eq 1 -and $holdDefinition[0].Extent.Text.Contains("Join-Path `$consoleDirectory ('console-before-hold-")) 'Console observation entered marker set.'
$utf8=[Text.UTF8Encoding]::new($false,$true)
function Encode([string]$Value) { [Convert]::ToBase64String($utf8.GetBytes($Value)) }
$run='a'*32
$ownedProfile='C:\owned\profile'
$valid=@('--mode=exit',('--directory-b64='+(Encode 'C:\owned')),'--user-data-dir=C:\owned\profile',('--fixture-run='+$run),'--parent-pid=123','--echo-b64=')

foreach($directory in @('C:\space path\é😀','\\server\share\unicode-é','C:\owned')) {
    foreach($echo in @('', 'colon:value', 'spaces quote" trailing\', "line`nnext`tunicode-é😀", '--option-looking=value', ([string][char]0xFEFF+'leading BOM'))) {
        $vector=$valid.Clone();$vector[1]='--directory-b64='+(Encode $directory);$vector[5]='--echo-b64='+(Encode $echo)
        $parsed=Read-FixtureOption $vector
        Assert-Contract ($parsed.directory -ceq $directory -and $parsed.echo -ceq $echo -and $parsed['user-data-dir'] -ceq $ownedProfile) 'Fixture values changed.'
    }
}
$split=@($valid[0],$valid[1],'--user-data-dir=C','\owned\profile',$valid[3],$valid[4],$valid[5])
Assert-Contract ((Read-FixtureOption $split)['user-data-dir'] -ceq $ownedProfile) 'Canonical drive split was not reconstructed.'
$unc=$valid.Clone();$unc[2]='--user-data-dir=\\server\share\profile'
Assert-Contract ((Read-FixtureOption $unc)['user-data-dir'] -ceq '\\server\share\profile') 'UNC profile changed.'

# Every mutation is rejected by the actual parser, without joining arbitrary neighboring tokens.
$bad=[Collections.Generic.List[object]]::new()
foreach($index in 0..4) { $bad.Add(@($valid[0..($valid.Count-1)]|Where-Object {$_ -cne $valid[$index]})) }
$bad.Add(@($valid)+@($valid[0]));$bad.Add(@($valid)+@('--unknown=value'))
$bad.Add(@($valid)+@('orphan'));$bad.Add(@($valid)+@('--echo=value'))
foreach($replacement in @('--directory-b64=%%%','--directory-b64=YQ=','--directory-b64=YR==','--directory-b64= YQ==','--directory-b64=/w==','--directory-b64=')) {
    $vector=$valid.Clone();$vector[1]=$replacement;$bad.Add($vector)
}
foreach($replacement in @('--user-data-dir=','--user-data-dir=relative','--user-data-dir=C','--user-data-dir=C:relative','--USER-DATA-DIR=C:\owned\profile',' --user-data-dir=C:\owned\profile')) {
    $vector=$valid.Clone();$vector[2]=$replacement;$bad.Add($vector)
}
foreach($tail in @('relative','--mode=hold','','/owned/profile')) { $bad.Add(@($valid[0],$valid[1],'--user-data-dir=C',$tail,$valid[3],$valid[4],$valid[5])) }
$bad.Add(@($valid[0],$valid[1],'--user-data-dir=\\server\share','profile',$valid[3],$valid[4],$valid[5]))
$bad.Add(@($valid)+@('--user-data-dir=C','\other\profile'))
foreach($replacement in @('--parent-pid=0','--parent-pid=-1','--parent-pid=+1','--parent-pid=01','--parent-pid=2147483648','--parent-pid=1x')) {
    $vector=$valid.Clone();$vector[4]=$replacement;$bad.Add($vector)
}
$vector=$valid.Clone();$vector[4]="--parent-pid=123`n";$bad.Add($vector)
$vector=$valid.Clone();$vector[0]="--mode=exit`n";$bad.Add($vector)
$vector=$valid.Clone();$vector[3]='--fixture-run='+('A'*32);$bad.Add($vector)
$vector=$valid.Clone();$vector[0]='--mode=';$bad.Add($vector)
$bad.Add(@($valid)+@($null));$bad.Add(@($valid)+@(123))
foreach($vector in $bad) {
    $rejected=$false;try { [void](Read-FixtureOption $vector) } catch { $rejected=$true }
    Assert-Contract $rejected 'Malformed fixture vector accepted.'
}

$directory='C:\child space\é😀';$options=@{'user-data-dir'=$ownedProfile;'fixture-run'=$run};$Mode='child'
. $childArguments
$tail=@($launchArguments|Select-Object -Skip 5)
$parsed=Read-FixtureOption $tail
Assert-Contract ($parsed.mode -ceq 'child' -and $parsed.directory -ceq $directory -and $parsed['user-data-dir'] -ceq $ownedProfile -and $parsed.echo -ceq '') 'Actual child argument construction changed values.'
Assert-Contract ($launchArguments[7] -ceq '--user-data-dir=C:\owned\profile') 'Child no longer supplies canonical owned profile.'
# Native handle ownership/failure contracts run through the actual workflow in Analyze's OfflineContracts.
Write-Output 'PASS source-bound fixture parser and native-child argument construction; no process/fixture/native action.'
