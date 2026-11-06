#Requires -Version 7.6
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'build/Import-SharedHelpers.ps1')
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'build/azure/runbook-source.ps1'), [ref]$null, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in @('Assert-ExportGenerationManifest', 'Get-ExportPublicationSnapshot', 'Receive-ExportGeneration', 'Publish-ExportGeneration', 'Compress-GzipFile', 'Expand-GzipFile')) {
    $definition = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if (-not $definition) { throw "Missing production function $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$fixtureAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Run-SharedHelperRegression.ps1'), [ref]$null, [ref]$null)
$fixtureDefinition = $fixtureAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-TestVulnRow' }, $true)
. ([scriptblock]::Create($fixtureDefinition.Extent.Text))

$Script:BlobContainers = @{ Exports = 'exports' }
$Script:BlobAccessTiers = @{ Exports = 'Hot' }
$script:Blobs = @{}
$script:Version = 0
$script:UploadCount = 0
$script:FailAt = 0
$script:CommitThenFail = $false
$script:FailRead = $false
$script:HideReadbackOnFailure = $false
$script:CorruptUploadAt = 0
$script:ObserveUploads = $false
$script:ExpectedId = 'old'
$script:PointerName = '_publication/exports.current.json'

function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Failure([scriptblock]$Action, [string]$Message) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    Assert-True $failed $Message
}
function Invoke-HttpFailure([int]$Code) {
    $exception = [System.Exception]::new("Synthetic HTTP $Code")
    $exception.Data['StatusCode'] = $Code
    throw $exception
}
function Get-BlobErrorStatusCode {
    param($ErrorRecord)
    return $ErrorRecord.Exception.Data['StatusCode']
}
function Get-BlobHeader {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'In-memory storage mock preserves production signature.')]
    param($StorageToken)
    return @{}
}
function Invoke-WebRequestWithRetry {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'In-memory storage mock preserves production signature.')]
    param($Uri, $Method, $Headers)
    if ($script:FailRead) { throw 'Synthetic unavailable pointer readback' }
    Assert-True ($Uri -like "*/exports/$script:PointerName") 'Unexpected snapshot request.'
    if (-not $script:Blobs.ContainsKey($script:PointerName)) { Invoke-HttpFailure 404 }
    return [pscustomobject]@{
        Headers = @{ ETag = @('"version-' + $script:Version + '"') }
        Content = [System.Text.Encoding]::UTF8.GetString($script:Blobs[$script:PointerName])
    }
}
function Get-BlobContent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'In-memory storage mock preserves production signature.')]
    param($AccountName, $Container, $BlobName, $DestinationPath, $StorageToken)
    if ($script:FailRead) { throw 'Synthetic unavailable readback' }
    if (-not $script:Blobs.ContainsKey($BlobName)) { Invoke-HttpFailure 404 }
    [void](New-Item -Path (Split-Path $DestinationPath -Parent) -ItemType Directory -Force)
    [System.IO.File]::WriteAllBytes($DestinationPath, $script:Blobs[$BlobName])
}
function Set-BlobContent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'In-memory storage mock.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'In-memory storage mock preserves production signature.')]
    param($AccountName, $Container, $BlobName, $SourcePath, $StorageToken, $ContentType, $AccessTier, $Conditions)
    $script:UploadCount++
    if ($Conditions.ContainsKey('If-None-Match') -and $script:Blobs.ContainsKey($BlobName)) { Invoke-HttpFailure 412 }
    if ($Conditions.ContainsKey('If-Match') -and $Conditions['If-Match'] -cne ('"version-' + $script:Version + '"')) { Invoke-HttpFailure 412 }
    if ($script:UploadCount -eq $script:FailAt -and -not $script:CommitThenFail) { throw 'Synthetic upload interruption' }
    $script:Blobs[$BlobName] = [System.IO.File]::ReadAllBytes($SourcePath)
    if ($script:UploadCount -eq $script:CorruptUploadAt) { $script:Blobs[$BlobName] = [byte[]]@(0, 1, 2) }
    if ($BlobName -eq $script:PointerName) { $script:Version++ }
    if ($script:ObserveUploads) {
        $expected = if ($BlobName -eq $script:PointerName) { 'new' } else { $script:ExpectedId }
        Assert-VisibleStore -ExpectedId $expected
    }
    if ($script:UploadCount -eq $script:FailAt -and $script:CommitThenFail) {
        if ($script:HideReadbackOnFailure) { $script:FailRead = $true }
        throw 'Synthetic committed response loss'
    }
}
function Publish-Store([string]$Path, $Snapshot) {
    Publish-ExportGeneration -AccountName fixture -StorageToken synthetic -ExportsPath $Path -Snapshot $Snapshot
}
function Get-Snapshot { Get-ExportPublicationSnapshot -AccountName fixture -StorageToken synthetic }
function Assert-VisibleStore([string]$ExpectedId, $Snapshot = (Get-Snapshot)) {
    $readPath = Join-Path $script:Root ([guid]::NewGuid().ToString('N'))
    [void](New-Item -Path $readPath -ItemType Directory)
    Receive-ExportGeneration -AccountName fixture -StorageToken synthetic -Snapshot $Snapshot -DestinationPath $readPath
    $rows = @(Read-VulnContentStoreRow -BasePath $readPath)
    $current = @($rows | Where-Object { $_.Id -eq $ExpectedId })
    Assert-True ($current.Count -eq 1) 'Expected intact dictionary/ref identity.'
    Assert-True ($current[0].DeviceId -eq "device-$ExpectedId") 'Dictionary/ref device mismatch.'
    Assert-True ($current[0].SoftwareVersion -eq $(if ($ExpectedId -eq 'old') { '1.0' } else { '2.0' })) 'Dictionary/ref version mismatch.'
    Assert-True (Test-VulnContentStoreExistence -BasePath $readPath) 'Expected complete content store.'
    foreach ($file in $Snapshot.Manifest.Files) {
        Assert-True ((Get-FileSha256Hex -Path (Join-Path $readPath $file.Name)) -ceq $file.Sha256) 'Raw/current/history file parity failed.'
    }
}

$script:Root = Join-Path ([System.IO.Path]::GetTempPath()) ('atomic-export-regression-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -Path $script:Root -ItemType Directory)
try {
    $old = Join-Path $script:Root 'old'
    $new = Join-Path $script:Root 'new'
    [void](New-Item -Path $old, $new -ItemType Directory)
    foreach ($pair in @(@($old, 'old', '2026-01-01', '1.0'), @($new, 'new', '2026-01-02', '2.0'))) {
        if ($pair[1] -eq 'new') {
            foreach ($name in (Get-ExportTransferArtifactNames -BasePath $old)) { Copy-Item -LiteralPath (Join-Path $old $name) -Destination $new }
        }
        $source = Join-Path $pair[0] ("VulnExport_1_$($pair[2]).json")
        $row = Get-TestVulnRow -Id $pair[1] -CveId $(if ($pair[1] -eq 'old') { 'CVE-2026-0001' } else { 'CVE-2026-0002' }) -SnapshotDate $pair[2] -Version $pair[3]
        $row.DeviceId = "device-$($pair[1])"
        Write-NdjsonRecordsFile -Path $source -Records @($row)
        Publish-VulnerabilityHistoryStore -OutputPath $pair[0] -DownloadedFiles @($source) | Out-Null
        # Enrichment travels in the same generation as the vulnerability files.
        foreach ($name in @($Script:MachineCurrentFileName, $Script:AdvancedHuntingCurrentFileName)) {
            Write-GzipTextFile -Path (Join-Path $pair[0] $name) -Content ('{"generation":"' + $pair[1] + '"}')
        }
        Set-Content -LiteralPath (Join-Path $pair[0] 'synthetic-manifest.json') -Value ('{"generation":"' + $pair[1] + '"}') -Encoding utf8
    }
    $absent = Get-Snapshot
    Assert-True ($null -eq $absent.Manifest) 'Missing pointer should admit read-only legacy migration.'
    # Frozen pre-migration root files must never be overwritten or deleted.
    foreach ($file in (Get-ChildItem -LiteralPath $old -File)) { $script:Blobs[$file.Name] = [System.IO.File]::ReadAllBytes($file.FullName) }
    $legacy = $script:Blobs.Clone()
    Publish-Store $old $absent
    Assert-VisibleStore old
    $baseline = $script:Blobs.Clone()
    $baselineVersion = $script:Version
    $oldSnapshot = Get-Snapshot
    $fileCount = @(Get-ExportTransferArtifactNames -BasePath $new).Count
    Assert-True (@(Get-ExportTransferArtifactNames -BasePath $new | Where-Object { $_ -like 'VulnHistory*' }).Count -gt 0) 'Expected real history files in upload boundary coverage.'

    # Interruption at every immutable-file and pointer upload boundary leaves
    # the entire old generation readable. Retrying recovers to the new one.
    foreach ($boundary in 1..($fileCount + 1)) {
        $script:Blobs = $baseline.Clone(); $script:Version = $baselineVersion
        $script:UploadCount = 0; $script:FailAt = $boundary
        Assert-Failure { Publish-Store $new $oldSnapshot } "Upload boundary $boundary should interrupt."
        Assert-VisibleStore old
        $script:FailAt = 0
        Publish-Store $new (Get-Snapshot)
        Assert-VisibleStore new
        Assert-VisibleStore old $oldSnapshot
    }
    # Every committed-but-lost response is reconciled from real stored bytes.
    foreach ($boundary in 1..($fileCount + 1)) {
        $script:Blobs = $baseline.Clone(); $script:Version = $baselineVersion
        $script:UploadCount = 0; $script:FailAt = $boundary; $script:CommitThenFail = $true
        Publish-Store $new $oldSnapshot
        Assert-VisibleStore new
    }
    # If response loss cannot be reconciled, stop. A committed pointer is still
    # coherent; an uncommitted pointer still selects the complete prior store.
    $script:HideReadbackOnFailure = $true
    foreach ($boundary in 1..($fileCount + 1)) {
        $script:Blobs = $baseline.Clone(); $script:Version = $baselineVersion
        $script:UploadCount = 0; $script:FailAt = $boundary
        Assert-Failure { Publish-Store $new $oldSnapshot } 'Unavailable response-loss readback must stop.'
        $script:FailRead = $false
        Assert-VisibleStore $(if ($boundary -eq $fileCount + 1) { 'new' } else { 'old' })
    }
    $script:HideReadbackOnFailure = $false
    $script:FailAt = 0; $script:CommitThenFail = $false
    $script:Blobs = $baseline.Clone(); $script:Version = $baselineVersion
    $script:UploadCount = 0; $script:CorruptUploadAt = 1
    Assert-Failure { Publish-Store $new $oldSnapshot } 'Incorrect successful upload bytes must not publish.'
    Assert-VisibleStore old
    $script:CorruptUploadAt = 0
    $script:Blobs = $baseline.Clone(); $script:Version = $baselineVersion
    $script:ObserveUploads = $true
    Publish-Store $new $oldSnapshot
    $script:ObserveUploads = $false
    Assert-Failure { Publish-Store $old $oldSnapshot } 'A stale concurrent publisher must not replace the winner.'
    Assert-VisibleStore new
    Assert-VisibleStore old $oldSnapshot

    # Two first-generation writers use create-only CAS, never last-writer wins.
    $script:Blobs = $legacy.Clone(); $script:Version = 0
    Publish-Store $new $absent
    Assert-Failure { Publish-Store $old $absent } 'A stale legacy publisher must not replace a new pointer.'
    Assert-VisibleStore new
    foreach ($name in $legacy.Keys) {
        Assert-True ([Convert]::ToBase64String($legacy[$name]) -ceq [Convert]::ToBase64String($script:Blobs[$name])) 'Legacy canonical bytes were changed.'
    }

    $snapshot = Get-Snapshot
    $entry = $snapshot.Manifest.Files[0]
    $saved = $script:Blobs[$entry.BlobName]
    $script:Blobs[$entry.BlobName] = [byte[]]@(0, 1, 2)
    Assert-Failure { Assert-VisibleStore new } 'Corrupt immutable bytes must fail closed.'
    $script:Blobs.Remove($entry.BlobName)
    Assert-Failure { Assert-VisibleStore new } 'Missing immutable bytes must fail closed.'
    $script:Blobs[$entry.BlobName] = $saved
    $script:Blobs[$script:PointerName] = [System.Text.Encoding]::UTF8.GetBytes('{broken')
    Assert-Failure { Get-Snapshot } 'Malformed pointer must not fall back to legacy.'
    $missingFieldManifest = [pscustomobject]@{ Version = 1; Generation = 'a' * 32 }
    Assert-Failure { Assert-ExportGenerationManifest -Manifest $missingFieldManifest } 'Missing manifest fields must fail closed.'
    Assert-Failure { Set-StrictMode -Off; Assert-ExportGenerationManifest -Manifest $missingFieldManifest } 'Validation must not rely on caller StrictMode.'
    $integerManifest = $snapshot.Manifest | ConvertTo-Json -Depth 12 | ConvertFrom-Json -Depth 12
    $integerManifest.Files[0].Length = [int]$integerManifest.Files[0].Length
    Assert-ExportGenerationManifest -Manifest $integerManifest
    $integerManifest.Files[0].Name = '../VulnCurrentRefs.json.gz'
    Assert-Failure { Assert-ExportGenerationManifest -Manifest $integerManifest } 'Integer lengths must not bypass path validation.'
    $snapshot.Manifest.Files[0].Name = '../VulnCurrentRefs.json.gz'
    Assert-Failure { Assert-ExportGenerationManifest -Manifest $snapshot.Manifest } 'Path traversal must be rejected.'

    # Exercise both legacy compression modes without mutating the source path.
    $plain = Join-Path $script:Root 'plain'
    [void](New-Item -Path $plain -ItemType Directory)
    $plainName = 'VulnExport_1_2026-01-03.json'
    $plainPath = Join-Path $plain $plainName
    Set-Content -LiteralPath $plainPath -Value '{"synthetic":"compression-control"}' -Encoding utf8
    foreach ($gzip in @($true, $false)) {
        $script:Blobs = @{}; $script:Version = 0
        Publish-ExportGeneration -AccountName fixture -StorageToken synthetic -ExportsPath $plain -Snapshot $absent -UseGzip $gzip
        $snapshot = Get-Snapshot
        $expectedName = if ($gzip) { "$plainName.gz" } else { $plainName }
        Assert-True ($snapshot.Manifest.Files[0].Name -ceq $expectedName) 'Incorrect compressed generation filename.'
        $received = Join-Path $script:Root ([guid]::NewGuid().ToString('N'))
        Receive-ExportGeneration -AccountName fixture -StorageToken synthetic -Snapshot $snapshot -DestinationPath $received
        $receivedPath = Join-Path $received $expectedName
        if ($gzip) {
            Expand-GzipFile -InputPath $receivedPath -OutputPath (Join-Path $received $plainName)
            $receivedPath = Join-Path $received $plainName
        }
        Assert-True ((Get-FileSha256Hex -Path $receivedPath) -ceq (Get-FileSha256Hex -Path $plainPath)) 'Compressed/uncompressed transfer changed source bytes.'
        Assert-True (-not (Test-Path -LiteralPath "$plainPath.gz")) 'Publication must not add compressed files to source exports.'
    }

    # Keep production wiring tied to the initial read snapshot, not a later GET.
    Assert-True ($ast.Extent.Text.Contains('dashboard-pipeline-$Script:PipelineRunId')) 'Concurrent runs must use unique local export workspaces.'
    $calls = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Export-ToBlobStorage' }, $true))
    Assert-True ($calls.Count -eq 3 -and @($calls | Where-Object { $_.Extent.Text -notlike '*-ExportSnapshot $exportSnapshot*' }).Count -eq 0) 'All production export targets must retain the read snapshot.'
    Write-Host "Atomic export publication passed: $fileCount file boundaries, pointer CAS, retries, response loss, concurrent readers/writers, hash failures and legacy migration."
}
finally {
    Remove-Item -LiteralPath $script:Root -Recurse -Force
}
