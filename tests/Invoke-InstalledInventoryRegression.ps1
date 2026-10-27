#Requires -Version 7.6
# Bespoke finite filesystem checks. Synthetic executable-named files are never launched.
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'helpers/controlled-fixture/InstalledInventory.ps1')
$utf8=[Text.UTF8Encoding]::new($false,$true)
$run=[guid]::NewGuid().ToString('N')
$temporaryParent=[IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
$temporaryRoot=Join-Path $temporaryParent ('installed-inventory-regression-'+$run)
if(Test-Path -LiteralPath $temporaryRoot){throw 'Fresh inventory regression directory required.'}
[void][IO.Directory]::CreateDirectory($temporaryRoot)
$ownershipPath=Join-Path $temporaryRoot 'regression-owner.txt'
[IO.File]::WriteAllText($ownershipPath,$run,$utf8)
$passed=0
function Assert-Regression([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Get-SyntheticFileRecord([string]$Root,[string]$Relative){
    $path=Join-Path $Root $Relative
    [ordered]@{path=$Relative;bytes=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
}
function New-SyntheticInventory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Creates only synthetic files beneath this regression run-owned temporary directory; no external mutation.')]
    param([string]$Name)
    $caseRoot=Join-Path $temporaryRoot $Name
    Assert-Regression (-not (Test-Path -LiteralPath $caseRoot)) 'Duplicate regression case path.'
    [void][IO.Directory]::CreateDirectory($caseRoot)
    $dotnetRoot=Join-Path $caseRoot 'dotnet';[void][IO.Directory]::CreateDirectory($dotnetRoot)
    $dotnet=Join-Path $dotnetRoot 'dotnet.exe';[IO.File]::WriteAllText($dotnet,'SYNTHETIC FILE, NEVER EXECUTE',$utf8)
    $roots=[ordered]@{sdk='sdk/10.0.401';reference='packs/Microsoft.NETCore.App.Ref/10.0.12';apphost='packs/Microsoft.NETCore.App.Host.win-x64/10.0.12';runtime='shared/Microsoft.NETCore.App/10.0.12';hostfxr='host/fxr'}
    $groups=@(foreach($id in $roots.Keys){
        $root=Join-Path $dotnetRoot $roots[$id]
        [void][IO.Directory]::CreateDirectory((Join-Path $root 'nested'))
        [IO.File]::WriteAllText((Join-Path $root 'nested/one.bin'),('synthetic-'+$id+'-'+[char]0x00e9),$utf8)
        [IO.File]::WriteAllText((Join-Path $root 'two.bin'),('second-'+$id),$utf8)
        [ordered]@{id=$id;root=$root;files=@((Get-SyntheticFileRecord $root 'nested/one.bin'),(Get-SyntheticFileRecord $root 'two.bin'))}
    })
    $toolchain=[ordered]@{schema=1;kind='toolchain';sdkVersion='10.0.401';runtimeVersion='10.0.12';dotnetRoot=$dotnetRoot;dotnet=$dotnet;dotnetSha256=(Get-FileHash -LiteralPath $dotnet -Algorithm SHA256).Hash.ToLowerInvariant();runtimeDirectory=(Join-Path $dotnetRoot $roots.runtime);groups=$groups}
    $powerShellRoot=Join-Path $caseRoot 'powershell';[void][IO.Directory]::CreateDirectory($powerShellRoot)
    $powerShell=Join-Path $powerShellRoot 'pwsh.exe';[IO.File]::WriteAllText($powerShell,'SYNTHETIC POWERSHELL FILE, NEVER EXECUTE',$utf8)
    [IO.File]::WriteAllText((Join-Path $powerShellRoot 'runtime.bin'),'synthetic managed dependency',$utf8)
    $powerShellSha256=(Get-FileHash -LiteralPath $powerShell -Algorithm SHA256).Hash.ToLowerInvariant()
    $hostInventory=[ordered]@{schema=1;kind='powershell';root=$powerShellRoot;version='7.6.6';executableSha256=$powerShellSha256;files=@((Get-SyntheticFileRecord $powerShellRoot 'pwsh.exe'),(Get-SyntheticFileRecord $powerShellRoot 'runtime.bin'))}
    [pscustomobject]@{Root=$caseRoot;Toolchain=$toolchain;PowerShellInventory=$hostInventory;Executable=$powerShell;ExecutableSha256=$powerShellSha256;Version='7.6.6'}
}
function Assert-SyntheticInventory($State,[string]$Kind){
    if($Kind -ceq 'toolchain'){Assert-InstalledInventory -Manifest $State.Toolchain -Kind toolchain}
    else{Assert-InstalledInventory -Manifest $State.PowerShellInventory -Kind powershell -Executable $State.Executable -ExecutableSha256 $State.ExecutableSha256 -Version $State.Version}
}
function Assert-RejectedInventory([string]$Name,[string]$Kind,[scriptblock]$Mutation){
    $state=New-SyntheticInventory $Name
    & $Mutation $state
    $rejected=$false
    try{Assert-SyntheticInventory $state $Kind}catch{$rejected=$true}
    Assert-Regression $rejected ('Invalid installed inventory accepted: '+$Name)
    $script:passed++
}
function Write-SyntheticJson([string]$Path,[string]$Text){
    $bytes=$utf8.GetBytes($Text);[IO.File]::WriteAllBytes($Path,$bytes)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}
function Assert-RejectedReader([string]$Name,[string]$Text){
    $path=Join-Path $temporaryRoot ($Name+'.json');$digest=Write-SyntheticJson $path $Text;$rejected=$false
    try{[void](Read-InstalledInventory -Path $path -Sha256 $digest)}catch{$rejected=$true}
    Assert-Regression $rejected ('Invalid inventory JSON accepted: '+$Name)
    $script:passed++
}
try{
    # Positive controls use the complete real directory sets and actual verifier/reader.
    $positive=New-SyntheticInventory 'complete-positive'
    Assert-SyntheticInventory $positive 'toolchain';Assert-SyntheticInventory $positive 'powershell';$passed+=2
    foreach($kind in @('toolchain','powershell')){
        $manifest=if($kind -ceq 'toolchain'){$positive.Toolchain}else{$positive.PowerShellInventory}
        $path=Join-Path $positive.Root ($kind+'.json');$digest=Write-SyntheticJson $path ($manifest|ConvertTo-Json -Depth 12)
        $read=Read-InstalledInventory -Path $path -Sha256 $digest
        if($kind -ceq 'toolchain'){Assert-InstalledInventory -Manifest $read -Kind toolchain}
        else{Assert-InstalledInventory -Manifest $read -Kind powershell -Executable $positive.Executable -ExecutableSha256 $positive.ExecutableSha256 -Version $positive.Version}
        $passed++
    }
    $positive.Toolchain.meaning='synthetic installed toolchain inventory'
    $positive.PowerShellInventory.fileVersion='7.6.6'
    $positive.PowerShellInventory.bundledCoreRuntime='10.0.12'
    Assert-SyntheticInventory $positive 'toolchain';Assert-SyntheticInventory $positive 'powershell';$passed+=2
    foreach($kind in @('toolchain','powershell')){
        $requiredFields=if($kind -ceq 'toolchain'){@('schema','kind','sdkVersion','runtimeVersion','dotnetRoot','dotnet','dotnetSha256','runtimeDirectory','groups')}else{@('schema','kind','root','executableSha256','version','files')}
        foreach($missingField in $requiredFields){
            Assert-RejectedInventory ($kind+'-missing-required-'+$missingField) $kind {
                param($s)
                $manifest=if($kind -ceq 'toolchain'){$s.Toolchain}else{$s.PowerShellInventory}
                $manifest.Remove($missingField)
            }
        }
        Assert-RejectedInventory ($kind+'-unknown-top-field') $kind {
            param($s)
            $manifest=if($kind -ceq 'toolchain'){$s.Toolchain}else{$s.PowerShellInventory}
            $manifest['unexpected']='not part of the inventory schema'
        }
        $metadataFields=if($kind -ceq 'toolchain'){@('meaning')}else{@('fileVersion','bundledCoreRuntime')}
        foreach($metadataField in $metadataFields){
            foreach($metadataValue in @($null,'',1,@(),@{})){
                Assert-RejectedInventory ($kind+'-invalid-metadata-'+$passed) $kind {
                    param($s)
                    $manifest=if($kind -ceq 'toolchain'){$s.Toolchain}else{$s.PowerShellInventory}
                    $manifest[$metadataField]=$metadataValue
                }
            }
        }
    }
    Assert-RejectedInventory 'empty-groups' toolchain {param($s)$s.Toolchain.groups=@()}
    Assert-RejectedInventory 'missing-groups' toolchain {param($s)$s.Toolchain.Remove('groups')}
    Assert-RejectedInventory 'omitted-group' toolchain {param($s)$s.Toolchain.groups=@($s.Toolchain.groups[0..3])}
    Assert-RejectedInventory 'duplicate-group' toolchain {param($s)$s.Toolchain.groups[4]=$s.Toolchain.groups[0]}
    Assert-RejectedInventory 'unknown-group' toolchain {param($s)$s.Toolchain.groups[4].id='unknown'}
    Assert-RejectedInventory 'wrong-case-group' toolchain {param($s)$s.Toolchain.groups[0].id='SDK'}
    Assert-RejectedInventory 'empty-group-record' toolchain {param($s)$s.Toolchain.groups[0]=@{}}
    Assert-RejectedInventory 'unknown-group-field' toolchain {param($s)$s.Toolchain.groups[0].unexpected='not a group field'}
    Assert-RejectedInventory 'empty-toolchain-manifest' toolchain {param($s)$s.Toolchain.Clear()}
    Assert-RejectedInventory 'empty-powershell-manifest' powershell {param($s)$s.PowerShellInventory.Clear()}
    Assert-RejectedInventory 'wrong-group-root' toolchain {param($s)$s.Toolchain.groups[0].root=$s.Toolchain.groups[1].root}
    Assert-RejectedInventory 'missing-group-root' toolchain {param($s)$s.Toolchain.groups[0].root=Join-Path $s.Root 'not-present'}
    Assert-RejectedInventory 'relative-group-root' toolchain {param($s)$s.Toolchain.groups[0].root='relative'}
    Assert-RejectedInventory 'wrong-runtime-root' toolchain {param($s)$s.Toolchain.runtimeDirectory=$s.Toolchain.groups[0].root}
    Assert-RejectedInventory 'wrong-dotnet-root-binding' toolchain {param($s)$s.Toolchain.dotnet=$s.Executable}
    Assert-RejectedInventory 'changed-dotnet-hash' toolchain {param($s)$s.Toolchain.dotnetSha256='0'*64}

    Assert-RejectedInventory 'empty-files' toolchain {param($s)$s.Toolchain.groups[0].files=@()}
    Assert-RejectedInventory 'missing-files' toolchain {param($s)$s.Toolchain.groups[0].Remove('files')}
    Assert-RejectedInventory 'omitted-file' toolchain {param($s)$s.Toolchain.groups[0].files=@($s.Toolchain.groups[0].files[0])}
    Assert-RejectedInventory 'extra-file-record' toolchain {param($s)$s.Toolchain.groups[0].files+=@(@{path='not-present.bin';bytes=0;sha256=('0'*64)})}
    Assert-RejectedInventory 'extra-installed-file' toolchain {param($s)[IO.File]::WriteAllText((Join-Path $s.Toolchain.groups[0].root 'extra.bin'),'unbound')}
    Assert-RejectedInventory 'missing-installed-file' toolchain {param($s)[IO.File]::Delete((Join-Path $s.Toolchain.groups[0].root 'two.bin'))}
    Assert-RejectedInventory 'duplicate-file' toolchain {param($s)$s.Toolchain.groups[0].files+=@($s.Toolchain.groups[0].files[0])}
    Assert-RejectedInventory 'case-duplicate-file' toolchain {param($s)$s.Toolchain.groups[0].files[1].path='NESTED/ONE.BIN'}
    foreach($relative in @('../outside.bin','nested/../two.bin','nested/./one.bin','nested//one.bin','nested\one.bin','/rooted.bin','C:/rooted.bin','two.bin.','two.bin ')){
        $invalidRelative=$relative
        Assert-RejectedInventory ('bad-relative-'+$passed) toolchain {param($s)$s.Toolchain.groups[0].files[0].path=$invalidRelative}
    }
    Assert-RejectedInventory 'changed-file-hash' toolchain {param($s)$s.Toolchain.groups[0].files[0].sha256='0'*64}
    Assert-RejectedInventory 'changed-file-size' toolchain {param($s)$s.Toolchain.groups[0].files[0].bytes++}
    Assert-RejectedInventory 'string-file-size' toolchain {param($s)$s.Toolchain.groups[0].files[0].bytes=[string]$s.Toolchain.groups[0].files[0].bytes}
    Assert-RejectedInventory 'extra-file-field' toolchain {param($s)$s.Toolchain.groups[0].files[0].extra=$true}
    Assert-RejectedInventory 'wrong-kind' toolchain {param($s)$s.Toolchain.kind='powershell'}
    Assert-RejectedInventory 'wrong-kind-case' toolchain {param($s)$s.Toolchain.kind='Toolchain'}
    Assert-RejectedInventory 'wrong-schema' toolchain {param($s)$s.Toolchain.schema=2}
    Assert-RejectedInventory 'string-schema' toolchain {param($s)$s.Toolchain.schema='1'}
    Assert-RejectedInventory 'boolean-schema' toolchain {param($s)$s.Toolchain.schema=$true}

    Assert-RejectedInventory 'powershell-wrong-root' powershell {param($s)$s.PowerShellInventory.root=$s.Toolchain.dotnetRoot}
    Assert-RejectedInventory 'powershell-relative-root' powershell {param($s)$s.PowerShellInventory.root='relative'}
    Assert-RejectedInventory 'powershell-wrong-executable' powershell {param($s)$s.Executable=$s.Toolchain.dotnet}
    Assert-RejectedInventory 'powershell-wrong-executable-binding' powershell {param($s)$s.ExecutableSha256='0'*64}
    Assert-RejectedInventory 'powershell-wrong-manifest-hash' powershell {param($s)$s.PowerShellInventory.executableSha256='0'*64}
    Assert-RejectedInventory 'powershell-wrong-version' powershell {param($s)$s.PowerShellInventory.version='7.4.0'}
    Assert-RejectedInventory 'powershell-unsupported-independent-version' powershell {param($s)$s.Version='7.4.0';$s.PowerShellInventory.version='7.4.0'}
    Assert-RejectedInventory 'powershell-confused-groups' powershell {param($s)$s.PowerShellInventory.groups=@()}
    Assert-RejectedInventory 'powershell-wrong-kind' powershell {param($s)$s.PowerShellInventory.kind='toolchain'}
    Assert-RejectedInventory 'powershell-string-schema' powershell {param($s)$s.PowerShellInventory.schema='1'}
    Assert-RejectedInventory 'powershell-empty-files' powershell {param($s)$s.PowerShellInventory.files=@()}
    Assert-RejectedInventory 'powershell-missing-file' powershell {param($s)[IO.File]::Delete((Join-Path $s.PowerShellInventory.root 'runtime.bin'))}
    Assert-RejectedInventory 'powershell-extra-file' powershell {param($s)[IO.File]::WriteAllText((Join-Path $s.PowerShellInventory.root 'extra.bin'),'unbound')}
    Assert-RejectedInventory 'powershell-changed-size' powershell {param($s)$s.PowerShellInventory.files[0].bytes++}

    Assert-RejectedReader 'duplicate-root-key' '{"schema":1,"Schema":1,"kind":"toolchain"}'
    Assert-RejectedReader 'duplicate-nested-key' '{"schema":1,"kind":"toolchain","groups":[{"id":"sdk","files":[{"path":"a","PATH":"b"}]}]}'
    Assert-RejectedReader 'duplicate-exact-key' '{"schema":1,"kind":"powershell","root":"a","root":"b"}'
    Assert-RejectedReader 'array-root' ('['+($positive.Toolchain|ConvertTo-Json -Depth 12 -Compress)+']')
    Assert-RejectedReader 'null-root' 'null'
    Assert-RejectedReader 'scalar-root' '1'
    $jsonPath=Join-Path $temporaryRoot 'digest-change.json';$digest=Write-SyntheticJson $jsonPath '{"schema":1}'
    [IO.File]::AppendAllText($jsonPath,' ',$utf8);$rejected=$false
    try{[void](Read-InstalledInventory -Path $jsonPath -Sha256 $digest)}catch{$rejected=$true}
    Assert-Regression $rejected 'Reader accepted changed inventory bytes.';$passed++

    # Recheck the SAME accepted manifest after actual bytes change, not a newly generated inventory.
    foreach($kind in @('toolchain','powershell')){
        $state=New-SyntheticInventory ('revalidation-'+$kind)
        Assert-SyntheticInventory $state $kind
        $path=if($kind -ceq 'toolchain'){Join-Path $state.Toolchain.groups[0].root 'nested/one.bin'}else{$state.Executable}
        $bytes=[IO.File]::ReadAllBytes($path);$bytes[0]=$bytes[0] -bxor 1;[IO.File]::WriteAllBytes($path,$bytes)
        $rejected=$false;try{Assert-SyntheticInventory $state $kind}catch{$rejected=$true}
        Assert-Regression $rejected ('Revalidation trusted mutated '+$kind+' bytes.');$passed++
    }

    # Success cleanup is restricted to this exact direct child and its unmodified ownership marker.
    $resolved=[IO.Path]::GetFullPath($temporaryRoot)
    Assert-Regression ([IO.Directory]::GetParent($resolved).FullName -ceq $temporaryParent -and [IO.Path]::GetFileName($resolved) -ceq ('installed-inventory-regression-'+$run) -and [IO.File]::ReadAllText($ownershipPath,$utf8) -ceq $run) 'Regression cleanup ownership changed.'
    Assert-Regression (((Get-Item -LiteralPath $resolved -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and @(Get-ChildItem -LiteralPath $resolved -Recurse -Force|Where-Object {($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}).Count -eq 0) 'Linked regression cleanup target.'
    Remove-Item -LiteralPath $resolved -Recurse -Force
    Write-Output ('PASS installed-inventory regression: '+$passed+' finite checks; no process, SDK build or installation.')
}catch{
    Write-Warning ('Installed-inventory regression failed; retained synthetic tree: '+$temporaryRoot)
    throw
}
