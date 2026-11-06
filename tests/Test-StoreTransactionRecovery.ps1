#Requires -Version 7.6
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../build/Import-SharedHelpers.ps1')

function Assert-Recovery([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Get-ExactFileState([string]$Path) {
    $state = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -File -Force)) {
        $state[$file.Name] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))
    }
    return $state
}
function Assert-ExactStore([string]$Path, [hashtable]$Expected) {
    $actual = Get-ExactFileState $Path
    Assert-Recovery ($actual.Count -eq $Expected.Count) 'Store file set changed or a journal/temp file leaked.'
    foreach ($name in $Expected.Keys) {
        Assert-Recovery ($actual.ContainsKey($name) -and $actual[$name] -ceq $Expected[$name]) "Exact canonical/sentinel bytes changed: $name"
    }
    Assert-Recovery (@(Get-ChildItem -LiteralPath $Path -Directory -Force).Count -eq 0) 'Transaction directory leaked.'
}
function New-RecoveryCase {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Creates only a disposable, test-owned fixture; never modifies user stores.')]
    param([string]$Name)
    $case = Join-Path $root $Name
    $base = Join-Path $case 'store'
    $stage = Join-Path $case 'external-staging'
    [void][IO.Directory]::CreateDirectory($base)
    [void][IO.Directory]::CreateDirectory($stage)
    foreach ($entry in @{ 'canonical-a.dat'='original A'; 'remove-one.dat'='original removal one'; 'remove-two.dat'='original removal two'; 'unrelated-sentinel.dat'='preserve sentinel exactly' }.GetEnumerator()) {
        [IO.File]::WriteAllText((Join-Path $base $entry.Key), $entry.Value, [Text.UTF8Encoding]::new($false))
    }
    $sourceA = Join-Path $stage 'replacement-a.dat'
    $sourceB = Join-Path $stage 'new-b.dat'
    [IO.File]::WriteAllText($sourceA, ('replacement A ' + [char]0x00e9 + [char]0x6f22 + [char]0x5b57), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($sourceB, 'new B', [Text.UTF8Encoding]::new($false))
    return [pscustomobject]@{
        Base=$base; Stage=$stage; SourceA=$sourceA; SourceB=$sourceB
        TargetA=(Join-Path $base 'canonical-a.dat'); TargetB=(Join-Path $base 'canonical-b.dat')
        RemoveOne=(Join-Path $base 'remove-one.dat'); RemoveTwo=(Join-Path $base 'remove-two.dat')
        Before=(Get-ExactFileState $base); StagedBefore=(Get-ExactFileState $stage)
        Files=@([pscustomobject]@{StagePath=$sourceA;TargetPath=(Join-Path $base 'canonical-a.dat')},[pscustomobject]@{StagePath=$sourceB;TargetPath=(Join-Path $base 'canonical-b.dat')})
    }
}

$parent = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../.local'))
[void][IO.Directory]::CreateDirectory($parent)
for ($ancestor = Get-Item -LiteralPath $parent; $null -ne $ancestor; $ancestor=$ancestor.Parent) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point test parent refused.' }
}
$root = Join-Path $parent ('store-transaction-recovery-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
$passed = $false
try {
    # The source files are outside both the transaction root AND BasePath.
    # Successful adoption must preserve the complete bytes and remove both old files.
    $case = New-RecoveryCase success
    $expected = @{ 'canonical-a.dat'=$case.StagedBefore['replacement-a.dat']; 'canonical-b.dat'=$case.StagedBefore['new-b.dat']; 'unrelated-sentinel.dat'=$case.Before['unrelated-sentinel.dat'] }
    Publish-StoreFilesTransactional -BasePath $case.Base -StoreName focused -Files $case.Files -RemovePaths @($case.RemoveOne,$case.RemoveTwo)
    Assert-ExactStore $case.Base $expected
    Assert-Recovery (-not (Test-Path -LiteralPath $case.SourceA) -and -not (Test-Path -LiteralPath $case.SourceB)) 'Successful adoption retained staged originals.'

    # Fail during the second removal, after replacements + first removal happened.
    $case = New-RecoveryCase publish-failure
    $script:RemovalFailurePath = $case.RemoveTwo
    $script:RemovalFailureSeen = $false
    $script:RecoveryCase = $case
    function Move-Item {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Scoped fault injection exercises real transaction rollback; qualified cmdlet handles all other moves.')]
        [CmdletBinding()]
        param([string]$LiteralPath, [string]$Destination, [switch]$Force)
        if (-not $script:RemovalFailureSeen -and $LiteralPath -ceq $script:RemovalFailurePath) {
            Assert-Recovery ((Test-Path -LiteralPath $script:RecoveryCase.TargetB) -and -not (Test-Path -LiteralPath $script:RecoveryCase.RemoveOne)) 'Publish fault occurred before replacement/new-file/first-removal work completed.'
            Assert-Recovery ([Convert]::ToBase64String([IO.File]::ReadAllBytes($script:RecoveryCase.TargetA)) -ceq $script:RecoveryCase.StagedBefore['replacement-a.dat']) 'Replacement did not precede injected publish failure.'
            $script:RemovalFailureSeen=$true
            throw 'injected second-removal publish failure'
        }
        Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force -ErrorAction Stop
    }
    $failed = $false
    try { Publish-StoreFilesTransactional -BasePath $case.Base -StoreName focused -Files $case.Files -RemovePaths @($case.RemoveOne,$case.RemoveTwo) }
    catch { if ($_.Exception.Message -notlike '*injected second-removal publish failure*') { throw }; $failed=$true }
    finally { Remove-Item Function:Move-Item }
    Assert-Recovery ($failed -and $script:RemovalFailureSeen) 'Publish failure injection did not execute.'
    Assert-ExactStore $case.Base $case.Before

    # Short writes must never erase the Prepared rollback journal. These invoke
    # the REAL atomic journal writer; only its Set-Content call is faulted.
    foreach ($phase in @('Prepared','Committed')) {
        $case = New-RecoveryCase ('partial-' + $phase)
        $script:JournalFaultPhase = $phase
        $script:JournalFaultSeen = $false
        $script:PreparedJournalPreserved = $false
        $script:FaultJournal = Get-StoreTransactionJournalPath -BasePath $case.Base -StoreName focused
        function Set-Content {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Scoped partial-write fault injection; all unrelated writes call the qualified cmdlet.')]
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Scoped test fault injection implements Set-Content pipeline binding without interactive behavior.')]
            [CmdletBinding()]
            param([Parameter(ValueFromPipeline)]$Value, [string]$LiteralPath, [string]$Encoding)
            process {
                if ($LiteralPath -like ($script:FaultJournal + '.write-*') -and $Value -match ('"Phase"\s*:\s*"' + $script:JournalFaultPhase + '"')) {
                    $script:JournalFaultSeen=$true
                    $beforeJournal = if (Test-Path -LiteralPath $script:FaultJournal) { [IO.File]::ReadAllBytes($script:FaultJournal) } else { $null }
                    if ($script:JournalFaultPhase -eq 'Committed') {
                        $state = [IO.File]::ReadAllText($script:FaultJournal) | ConvertFrom-Json
                        Assert-Recovery ($state.Phase -eq 'Prepared') 'Prepared journal was not readable before partial Committed write.'
                    }
                    [IO.File]::WriteAllText($LiteralPath, '{partial journal write')
                    if ($script:JournalFaultPhase -eq 'Committed') {
                        $script:PreparedJournalPreserved = [Convert]::ToBase64String($beforeJournal) -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:FaultJournal))
                    }
                    throw ('injected partial ' + $script:JournalFaultPhase + ' journal write')
                }
                Microsoft.PowerShell.Management\Set-Content -LiteralPath $LiteralPath -Value $Value -Encoding $Encoding -ErrorAction Stop
            }
        }
        $failed=$false
        try { Publish-StoreFilesTransactional -BasePath $case.Base -StoreName focused -Files $case.Files -RemovePaths @($case.RemoveOne,$case.RemoveTwo) }
        catch { if ($_.Exception.Message -notlike ('*injected partial ' + $phase + ' journal write*')) { throw }; $failed=$true }
        finally { Remove-Item Function:Set-Content }
        Assert-Recovery ($failed -and $script:JournalFaultSeen) "Partial $phase injection did not execute."
        if ($phase -eq 'Committed') { Assert-Recovery $script:PreparedJournalPreserved 'Partial Committed write altered Prepared journal bytes.' }
        Assert-ExactStore $case.Base $case.Before
    }

    # All invalid ownership/alias inputs must reject BEFORE moving any source.
    foreach ($scenario in @('target-alias','removal-alias','duplicate-source')) {
        $case = New-RecoveryCase $scenario
        $files = switch ($scenario) {
            'target-alias' { @([pscustomobject]@{StagePath=(Join-Path $case.Stage '../store/canonical-a.dat');TargetPath=$case.TargetA}) }
            'removal-alias' { @([pscustomobject]@{StagePath=$case.RemoveOne;TargetPath=$case.TargetA}) }
            'duplicate-source' { @([pscustomobject]@{StagePath=$case.SourceA;TargetPath=$case.TargetA},[pscustomobject]@{StagePath=$case.SourceA;TargetPath=$case.TargetB}) }
        }
        $failed=$false
        try { Publish-StoreFilesTransactional -BasePath $case.Base -StoreName focused -Files @($files) -RemovePaths @($case.RemoveOne,$case.RemoveTwo) }
        catch { if ($_.Exception.Message -notlike '*Invalid or duplicate transaction stage source*') { throw }; $failed=$true }
        Assert-Recovery $failed "Unsafe source was accepted: $scenario"
        Assert-ExactStore $case.Base $case.Before
        $stagedAfter=Get-ExactFileState $case.Stage
        Assert-Recovery ($stagedAfter.Count -eq $case.StagedBefore.Count) 'Preflight rejection consumed a source.'
        foreach ($name in $case.StagedBefore.Keys) { Assert-Recovery ($stagedAfter[$name] -ceq $case.StagedBefore[$name]) 'Preflight rejection changed staged bytes.' }
    }
    $passed=$true
    Write-Output 'PASS: transaction-owned adoption, exact publication, replacement/removal rollback, partial Prepared/Committed writes and alias/duplicate rejection.'
}
finally {
    Remove-Variable -Name RemovalFailurePath,RemovalFailureSeen,RecoveryCase,JournalFaultPhase,JournalFaultSeen,PreparedJournalPreserved,FaultJournal -Scope Script -ErrorAction SilentlyContinue
    if ($passed) {
        $absolute=[IO.Path]::GetFullPath($root)
        if ([IO.Path]::GetDirectoryName($absolute) -cne $parent -or [IO.Path]::GetFileName($absolute) -notmatch '^store-transaction-recovery-[a-f0-9]{32}$') { throw 'Test cleanup scope escaped.' }
        [IO.Directory]::Delete($absolute,$true)
    }
    else { Write-Warning "Failed tiny recovery fixture retained at $root" }
}
