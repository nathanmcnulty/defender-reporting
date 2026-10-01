#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('DeviceCardinalityFirst', 'BalancedMediumHeavy', 'CurrentDensity')]
    [string]$Preset = 'BalancedMediumHeavy',

    [Parameter(Mandatory = $false)]
    [string]$SourcePath = $PSScriptRoot,

    [Parameter(Mandatory = $false)]
    [string]$RawSyntheticOutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-import-coverage\synthetic-raw'),

    [Parameter(Mandatory = $false)]
    [string]$RawLiveOutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-import-coverage\synthetic-raw-live'),

    [Parameter(Mandatory = $false)]
    [string]$LegacySnapshotOutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-import-coverage\synthetic-legacy-vuln'),

    [Parameter(Mandatory = $false)]
    [string]$AzureReplayOutputPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-import-coverage\azure-replay-existing-exports'),

    [Parameter(Mandatory = $false)]
    [string]$LegacyImportValidationPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) '.local\large-import-coverage\legacy-import-validation'),

    [Parameter(Mandatory = $false)]
    [string]$TargetLatestDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd'),

    [Parameter(Mandatory = $false)]
    [string[]]$SnapshotDates,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 31)]
    [int]$SnapshotCount = 2,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 200000)]
    [int]$TargetDeviceCount = 0,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50000000)]
    [int]$TargetTotalVulnRows = 0,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 200000)]
    [int]$PlanningSourceMachineLimit = 50000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 500000)]
    [int]$PlanningSourceRowLimit = 100000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 200000)]
    [int]$SafetyDeviceLimit = 25000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50000000)]
    [int]$SafetyRowLimit = 2500000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0.5, 256.0)]
    [double]$MinimumAvailableMemoryGB = 0.5,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 2048)]
    [int]$MinimumFreeDiskGB = 10,

    [Parameter(Mandatory = $false)]
    [int]$Seed = 20260322,

    [Parameter(Mandatory = $false)]
    [string]$GenerationDate = (Get-Date).ToString('yyyy-MM-dd'),

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 50000000)]
    [int]$ContentTemplateCount = 0,

    [Parameter(Mandatory = $false)]
    [switch]$AllowLargeDataset,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSyntheticGeneration,

    [Parameter(Mandatory = $false)]
    [switch]$SkipLiveShift,

    [Parameter(Mandatory = $false)]
    [switch]$SkipLegacySnapshotGeneration,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAzureReplayDatasetBuild,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRawValidation,

    [Parameter(Mandatory = $false)]
    [switch]$SkipLegacyImportValidation,

    [Parameter(Mandatory = $false)]
    [switch]$ProfileFreshImport,

    [Parameter(Mandatory = $false)]
    [switch]$ProfileCompiledPartitionReader,

    [Parameter(Mandatory = $false)]
    [switch]$TestCompiledPartitionReaderParity,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'build\Import-SharedHelpers.ps1')

function Invoke-RepoScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativeScriptPath,

        [Parameter(Mandatory = $false)]
        [hashtable]$Arguments = @{}
    )

    $scriptPath = Join-Path -Path $repoRoot -ChildPath $RelativeScriptPath
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Script not found: $scriptPath"
    }

    Push-Location $repoRoot
    try {
        & $scriptPath @Arguments
    }
    finally {
        Pop-Location
    }
}

function Reset-DirectoryPath {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal test helper recreates temporary directories in a controlled script flow.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path -PathType Container) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }

    $null = New-Item -Path $Path -ItemType Directory -Force
}

function Copy-ArtifactIfPresent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationDirectory
    )

    if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
        return $false
    }

    Copy-Item -LiteralPath $SourcePath -Destination (Join-Path $DestinationDirectory (Split-Path -Path $SourcePath -Leaf)) -Force
    return $true
}

function Invoke-LegacySnapshotImportValidation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SnapshotSourcePath,

        [Parameter(Mandatory = $true)]
        [string]$ValidationPath,

        [Parameter(Mandatory = $true)]
        [bool]$ResetValidationPath
    )

    if ($ResetValidationPath) {
        Reset-DirectoryPath -Path $ValidationPath
    }
    elseif (-not (Test-Path -LiteralPath $ValidationPath -PathType Container)) {
        $null = New-Item -Path $ValidationPath -ItemType Directory -Force
    }

    $snapshotFiles = @(
        Get-ChildItem -Path $SnapshotSourcePath -Filter 'VulnExport_*.json.gz' -File -ErrorAction SilentlyContinue |
            Sort-Object Name
    )
    if ($snapshotFiles.Count -eq 0) {
        throw "No legacy snapshot files were found in '$SnapshotSourcePath'."
    }

    foreach ($snapshotFile in $snapshotFiles) {
        Copy-Item -LiteralPath $snapshotFile.FullName -Destination (Join-Path $ValidationPath $snapshotFile.Name) -Force
    }

    $publishResult = Publish-VulnStoreFromBulkSnapshot -BasePath $ValidationPath -RemoveSnapshotFiles:$false
    if (-not (Test-Path -LiteralPath (Get-VulnCurrentPath -BasePath $ValidationPath) -PathType Leaf)) {
        throw "Legacy import validation did not materialize a canonical current store in '$ValidationPath'."
    }

    return [PSCustomObject]@{
        validationPath = $ValidationPath
        publishResult = $publishResult
        snapshotFileCount = $snapshotFiles.Count
    }
}

function Invoke-Issue67ProfileOperation {
    param([string]$Name, [scriptblock]$Action)

    $started = [System.Diagnostics.Stopwatch]::GetTimestamp()
    $allocated = [GC]::GetAllocatedBytesForCurrentThread()
    try { & $Action }
    finally {
        if (-not $script:Issue67Profile.ContainsKey($Name)) {
            $script:Issue67Profile[$Name] = @{ calls = 0L; ticks = 0L; allocatedBytes = 0L }
        }
        $entry = $script:Issue67Profile[$Name]
        $entry.calls++
        $entry.ticks += [System.Diagnostics.Stopwatch]::GetTimestamp() - $started
        $entry.allocatedBytes += [GC]::GetAllocatedBytesForCurrentThread() - $allocated
    }
}

function Get-Issue67StoreDigest {
    param([string]$BasePath)

    $digests = [ordered]@{}
    foreach ($file in @(Get-ChildItem -LiteralPath $BasePath -Filter '*.json.gz' -File | Sort-Object Name)) {
        $inputStream = [System.IO.File]::OpenRead($file.FullName)
        $gzip = [System.IO.Compression.GZipStream]::new($inputStream, [System.IO.Compression.CompressionMode]::Decompress)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $digests[$file.Name] = [Convert]::ToHexString($sha.ComputeHash($gzip)).ToLowerInvariant() }
        finally { $sha.Dispose(); $gzip.Dispose(); $inputStream.Dispose() }
    }
    return $digests
}

function Initialize-Issue67CompiledPartitionReader {
    if ('DefenderReporting.Tests.Issue67PartitionReader' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DefenderReporting.Tests {
    public static class Issue67PartitionReader {
        public static IEnumerable<string> Read(string path) {
            using (var input = File.OpenRead(path))
            using (var carry = new MemoryStream()) {
                var buffer = new byte[65536];
                int bytesRead;
                while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0) {
                    int segmentStart = 0;
                    for (int index = 0; index < bytesRead; index++) {
                        if (buffer[index] != 0x0A) continue;
                        int segmentLength = index - segmentStart;
                        if (segmentLength > 0 && buffer[index - 1] == 0x0D) segmentLength--;
                        string line = null;
                        if (carry.Length > 0) {
                            if (segmentLength > 0) carry.Write(buffer, segmentStart, segmentLength);
                            line = Encoding.UTF8.GetString(carry.ToArray());
                            carry.SetLength(0);
                        } else if (segmentLength > 0) {
                            line = Encoding.UTF8.GetString(buffer, segmentStart, segmentLength);
                        }
                        if (!String.IsNullOrWhiteSpace(line)) yield return line;
                        segmentStart = index + 1;
                    }
                    int remainingLength = bytesRead - segmentStart;
                    if (remainingLength > 0) carry.Write(buffer, segmentStart, remainingLength);
                }
                if (carry.Length > 0) {
                    var lineBytes = carry.ToArray();
                    int lineLength = lineBytes.Length;
                    if (lineLength > 0 && lineBytes[lineLength - 1] == 0x0D) lineLength--;
                    if (lineLength > 0) {
                        string line = Encoding.UTF8.GetString(lineBytes, 0, lineLength);
                        if (!String.IsNullOrWhiteSpace(line)) yield return line;
                    }
                }
            }
        }
    }
}
'@
}

function Test-Issue67CompiledPartitionReaderParity {
    Initialize-Issue67CompiledPartitionReader
    $unicode = [char]0x03A9
    $cases = [ordered]@{
        empty = ''
        lf = "{`"Id`":`"fixture`"}`n"
        crlf = "{`"Id`":`"fixture`"}`r`n"
        noFinalLf = '{"Id":"fixture"}'
        trailingCr = "{`"Id`":`"fixture`"}`r"
        blanks = "`n `r`n`t`n{`"Id`":`"fixture`"}`n`n"
        bareCr = "{`"Id`":`"first`"}`r{`"Id`":`"second`"}`n"
        inlineCr = "{`"Id`":`"fi`rxture`"}`n"
        escapesUnicode = "{`"Id`":`"fixture`",`"Value`":`"\n\r\u03a9$unicode`"}`n"
        malformedRawLf = "{`"Id`":`"fi`nxture`"}`n"
        boundaryLf = (' ' * 65535) + "`n{`"Id`":`"fixture`"}`n"
        boundaryCrCarry = (' ' * 65534) + "x`r`n{`"Id`":`"fixture`"}`n"
        boundaryCrLf = (' ' * 65533) + "x`r`n{`"Id`":`"fixture`"}`n"
        multiBuffer = '{"Id":"fixture","Value":"' + ('x' * 131072) + '"}'
        bom = [byte[]](0xEF, 0xBB, 0xBF) + [Text.Encoding]::UTF8.GetBytes("{`"Id`":`"fixture`"}`n")
        invalidUtf8 = [Text.Encoding]::UTF8.GetBytes('{"Id":"fixture","Value":"') + [byte[]](0xC3, 0x28, 0xFF) + [Text.Encoding]::UTF8.GetBytes("`"}`n")
    }
    $path = Join-Path ([IO.Path]::GetTempPath()) ('issue67-reader-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
        foreach ($caseName in $cases.Keys) {
            $value = $cases[$caseName]
            if ($value -is [string]) { $bytes = [Text.Encoding]::UTF8.GetBytes($value) }
            else { $bytes = [byte[]]$value }
            [IO.File]::WriteAllBytes($path, $bytes)
            $original = @(Read-VulnNdjsonLinesFromPath -Path $path)
            $candidate = @([DefenderReporting.Tests.Issue67PartitionReader]::Read($path))
            if ($original.Count -ne $candidate.Count) { throw "Reader line count parity failed: $caseName" }
            for ($lineIndex = 0; $lineIndex -lt $original.Count; $lineIndex++) {
                if ($original[$lineIndex] -cne $candidate[$lineIndex]) { throw "Reader exact line parity failed: $caseName" }
                $outcomes = foreach ($line in @($original[$lineIndex], $candidate[$lineIndex])) {
                    try { $null = $line | ConvertFrom-Json -Depth 20; 'parsed' }
                    catch { $_.FullyQualifiedErrorId }
                }
                if ($outcomes[0] -cne $outcomes[1]) { throw "Reader parse outcome parity failed: $caseName" }
            }
        }
        [pscustomobject]@{ passed = $true; cases = $cases.Count; runtime = [Environment]::Version.ToString() }
    }
    finally {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
}

function Read-Issue67ProfilePartitionLines {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    param([string]$Path)

    $useCompiled = $script:Issue67UseCompiledReader -and (
        $Path.EndsWith('.ndjson', [StringComparison]::OrdinalIgnoreCase) -or
        $Path.EndsWith('.json', [StringComparison]::OrdinalIgnoreCase))
    $operation = if ($useCompiled) { 'Partition.Reader.Compiled' } else { 'Partition.Reader.Legacy' }
    Invoke-Issue67ProfileOperation -Name $operation -Action {
        if ($useCompiled) {
            $enumerator = ([System.Collections.IEnumerable][DefenderReporting.Tests.Issue67PartitionReader]::Read($Path)).GetEnumerator()
            try {
                while ($enumerator.MoveNext()) {
                    $enumerator.Current
                }
            }
            finally {
                if ($enumerator -is [IDisposable]) { $enumerator.Dispose() }
            }
        }
        else {
            Read-VulnNdjsonLinesFromPath -Path $Path
        }
    }
}

function Invoke-ProfiledFreshImport {
    param([string]$SnapshotSourcePath, [string]$ValidationPath, [string]$ReferencePath, [switch]$CompiledPartitionReader)

    if (Test-Path -LiteralPath $ValidationPath) {
        throw 'Fresh import profiling requires a new validation directory; existing stores are not replayed or removed.'
    }
    $manifestPath = Join-Path $ReferencePath 'synthetic-manifest.json'
    $legacyManifestPath = Join-Path $SnapshotSourcePath 'synthetic-legacy-manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath) -or -not (Test-Path -LiteralPath $legacyManifestPath)) {
        throw 'Fresh import profiling requires procedural synthetic and legacy manifests, not live exports.'
    }
    $referenceManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 30
    if ($referenceManifest.modelVersion -ne 'procedural-v1') {
        throw 'Fresh import profiling accepts only the procedural synthetic reference lane.'
    }
    if (@(Get-ChildItem -LiteralPath $SnapshotSourcePath -Filter 'VulnExport_*.json.gz' -File).Count -eq 0) {
        throw 'Fresh import profiling requires legacy synthetic snapshot files.'
    }
    if ($CompiledPartitionReader) { Initialize-Issue67CompiledPartitionReader }
    $script:Issue67UseCompiledReader = [bool]$CompiledPartitionReader
    $script:Issue67Profile = @{}
    $originals = @{}
    $names = @(
        'Publish-VulnStoreFromBulkSnapshot', 'Split-VulnJsonPartition', 'Read-VulnPartitionMapFile',
        'Get-VulnCanonicalRowSignature', 'New-OpenVulnRecord', 'New-ClosedVulnEntry',
        'Add-VulnHistoryEntryToAppendStore', 'Write-VulnPartitionMapFile',
        'Write-VulnCurrentFileFromPartition', 'Test-VulnCurrentFile',
        'Write-VulnHistoryDocumentFromAppendFile', 'Write-VulnHistoryRowsFileFromAppendFile',
        'Publish-StoreFilesTransactional', 'Publish-VulnContentStoreUnlocked',
        'Initialize-CompiledVulnContentProjector'
    )
    try {
        foreach ($name in $names) {
            $command = Get-Command -Name $name -CommandType Function -ErrorAction Stop
            $originals[$name] = $command.ScriptBlock
            $functionAst = $command.ScriptBlock.Ast
            if ($functionAst -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
                $functionAst = $functionAst.Body
            }
            $bodyStart = $functionAst.EndBlock.Statements[0].Extent.StartOffset
            $bodyEnd = $functionAst.EndBlock.Statements[-1].Extent.EndOffset
            $body = $functionAst.EndBlock.Extent.Text.Substring(
                $bodyStart - $functionAst.EndBlock.Extent.StartOffset, $bodyEnd - $bodyStart)
            $instrumentedBody = $body
            $jsonPipelines = @($functionAst.EndBlock.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.PipelineAst] -and
                ($node.Extent.Text -match '^\[void\]\[DefenderReporting.Store.VulnContentProjector\]::Project\(' -or
                @($node.PipelineElements | Where-Object {
                    $_ -is [System.Management.Automation.Language.CommandAst] -and
                    $_.GetCommandName() -in @('ConvertFrom-Json', 'ConvertTo-Json')
                }).Count -gt 0)
            }, $true) | Sort-Object { $_.Extent.StartOffset } -Descending)
            foreach ($pipeline in $jsonPipelines) {
                $operation = if ($pipeline.Extent.Text -match '::Project\(') { 'Content.CompiledProject' }
                    elseif ($pipeline.Extent.Text -match 'ConvertFrom-Json') { 'Json.Parse' } else { 'Json.Serialize' }
                $offset = $pipeline.Extent.StartOffset - $bodyStart
                $replacement = "Invoke-Issue67ProfileOperation -Name '$operation' -Action { " + $pipeline.Extent.Text + ' }'
                $instrumentedBody = $instrumentedBody.Remove($offset, $pipeline.Extent.Text.Length).Insert($offset, $replacement)
            }
            if ($name -eq 'Read-VulnPartitionMapFile') {
                $readerCall = 'Read-VulnNdjsonLinesFromPath -Path $Path'
                if (-not $instrumentedBody.Contains($readerCall)) { throw 'Partition reader probe anchor changed.' }
                $instrumentedBody = $instrumentedBody.Replace($readerCall, 'Read-Issue67ProfilePartitionLines -Path $Path')
            }
            $prefix = $command.ScriptBlock.ToString()
            $bodyOffset = $prefix.IndexOf($body, [System.StringComparison]::Ordinal)
            if ($bodyOffset -lt 0) { throw "Cannot identify the body for $name." }
            $replacementBody = @'
$issue67Started = [System.Diagnostics.Stopwatch]::GetTimestamp()
$issue67Allocated = [GC]::GetAllocatedBytesForCurrentThread()
try {
'@ + $instrumentedBody + @'

} finally {
    if (-not $script:Issue67Profile.ContainsKey('__NAME__')) {
        $script:Issue67Profile['__NAME__'] = @{ calls = 0L; ticks = 0L; allocatedBytes = 0L }
    }
    $issue67Entry = $script:Issue67Profile['__NAME__']
    $issue67Entry.calls++
    $issue67Entry.ticks += [System.Diagnostics.Stopwatch]::GetTimestamp() - $issue67Started
    $issue67Entry.allocatedBytes += [GC]::GetAllocatedBytesForCurrentThread() - $issue67Allocated
}
'@
            $replacementBody = $replacementBody.Replace('__NAME__', $name)
            $wrapped = $prefix.Remove($bodyOffset, $body.Length).Insert($bodyOffset, $replacementBody)
            Set-Item -LiteralPath ('Function:script:' + $name) -Value ([scriptblock]::Create($wrapped))
        }
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $profiled = Invoke-LegacySnapshotImportValidation -SnapshotSourcePath $SnapshotSourcePath -ValidationPath $ValidationPath -ResetValidationPath $false
        $profiledSeconds = $timer.Elapsed.TotalSeconds
    }
    finally {
        foreach ($name in $originals.Keys) {
            Set-Item -LiteralPath ('Function:script:' + $name) -Value $originals[$name]
        }
        $script:Issue67UseCompiledReader = $false
    }
    if ($CompiledPartitionReader -and -not $script:Issue67Profile.ContainsKey('Partition.Reader.Compiled')) {
        throw 'Compiled partition probe did not execute; do not accept fallback-only measurements.'
    }
    $baselinePath = $ValidationPath + '-unprofiled'
    if (Test-Path -LiteralPath $baselinePath) { throw 'The unprofiled twin directory must not already exist.' }
    $timer.Restart()
    $baseline = Invoke-LegacySnapshotImportValidation -SnapshotSourcePath $SnapshotSourcePath -ValidationPath $baselinePath -ResetValidationPath $false
    $baselineSeconds = $timer.Elapsed.TotalSeconds
    $profiledDigest = Get-Issue67StoreDigest -BasePath $ValidationPath
    $baselineDigest = Get-Issue67StoreDigest -BasePath $baselinePath
    $parity = ($profiledDigest | ConvertTo-Json -Compress) -ceq ($baselineDigest | ConvertTo-Json -Compress)
    if (-not $parity -or $profiled.publishResult.CurrentRows -ne $baseline.publishResult.CurrentRows) {
        throw 'Profiled/unprofiled fresh import store parity failed.'
    }
    $expectedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Read-VulnNdjsonRecordsFromPath -Path (Get-VulnCurrentPath -BasePath $ReferencePath) | ForEach-Object {
        if ((Get-VulnPropertyValue -InputObject $_ -Name 'IsOnboarded') -eq $true) {
            [void]$expectedIds.Add([string](Get-VulnPropertyValue -InputObject $_ -Name 'Id'))
        }
    }
    $actualIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Read-VulnNdjsonRecordsFromPath -Path (Get-VulnCurrentPath -BasePath $ValidationPath) | ForEach-Object {
        [void]$actualIds.Add([string](Get-VulnPropertyValue -InputObject $_ -Name 'Id'))
    }
    if (-not $expectedIds.SetEquals($actualIds) -or $actualIds.Count -ne $profiled.publishResult.CurrentRows) {
        throw 'Fresh import current IDs differ from the authoritative onboarded reference projection.'
    }
    $snapshotInputs = @(Get-ChildItem -LiteralPath $SnapshotSourcePath -Filter 'VulnExport_*.json.gz' -File | Sort-Object Name | ForEach-Object {
        [ordered]@{ name = $_.Name; bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
    $evidence = [ordered]@{
        schemaVersion = 1
        lane = 'local-synthetic-fresh-import-not-Azure-not-completed-store-replay'
        sourceCommit = (& git -C $repoRoot rev-parse HEAD)
        runtime = $PSVersionTable.PSVersion.ToString()
        dotnetRuntime = [Environment]::Version.ToString()
        compiledPartitionReader = [bool]$CompiledPartitionReader
        readerScope = 'Test-only plaintext .ndjson/.json partition maps; production/default reader and gzip paths unchanged.'
        sourceHashes = @('tests/Invoke-LargeImportCoverage.ps1', 'src/powershell/Shared/Core/Core.ps1', 'build/generated/shared-helpers.ps1') | ForEach-Object {
            [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath (Join-Path $repoRoot $_) -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
        profiledSeconds = $profiledSeconds
        unprofiledSeconds = $baselineSeconds
        parity = $parity
        expectedCurrentIds = $expectedIds.Count
        actualCurrentIds = $actualIds.Count
        referenceManifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        legacyManifestSha256 = (Get-FileHash -LiteralPath $legacyManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        snapshotInputs = $snapshotInputs
        controls = [ordered]@{
            model = $referenceManifest.modelVersion
            seed = $referenceManifest.seed
            targetDevices = $referenceManifest.targetDeviceCount
            targetObservations = $referenceManifest.targetTotalVulnRows
            contentTemplates = $referenceManifest.contentTemplateCount
        }
        storeDigests = $profiledDigest
        publishResult = $profiled.publishResult
        attribution = 'Inclusive nested timings and thread allocations; do not sum. Per-call instrumentation overhead is included. No Azure extrapolation.'
        operations = @($script:Issue67Profile.Keys | Sort-Object | ForEach-Object {
            $entry = $script:Issue67Profile[$_]
            [ordered]@{
                name = $_
                calls = $entry.calls
                seconds = $entry.ticks / [double][System.Diagnostics.Stopwatch]::Frequency
                allocatedBytes = $entry.allocatedBytes
            }
        })
    }
    $evidence | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $ValidationPath 'fresh-import-profile.json') -Encoding utf8
    return $profiled
}

if ($TestCompiledPartitionReaderParity) {
    Test-Issue67CompiledPartitionReaderParity
    return
}

$resolvedSourcePath = [System.IO.Path]::GetFullPath($SourcePath)
$resolvedRawSyntheticOutputPath = [System.IO.Path]::GetFullPath($RawSyntheticOutputPath)
$resolvedRawLiveOutputPath = [System.IO.Path]::GetFullPath($RawLiveOutputPath)
$resolvedLegacySnapshotOutputPath = [System.IO.Path]::GetFullPath($LegacySnapshotOutputPath)
$resolvedAzureReplayOutputPath = [System.IO.Path]::GetFullPath($AzureReplayOutputPath)
$resolvedLegacyImportValidationPath = [System.IO.Path]::GetFullPath($LegacyImportValidationPath)

if ($ProfileFreshImport -and $SkipLegacyImportValidation) {
    throw 'ProfileFreshImport cannot be combined with SkipLegacyImportValidation.'
}
if ($ProfileCompiledPartitionReader -and -not $ProfileFreshImport) {
    throw 'ProfileCompiledPartitionReader requires ProfileFreshImport; this is not a production runtime flag.'
}

if (-not (Test-Path -LiteralPath $resolvedSourcePath -PathType Container)) {
    throw "Source path not found: $resolvedSourcePath"
}

if (-not $SkipSyntheticGeneration) {
    $generatorArgs = @{
        Preset = $Preset
        SourcePath = $resolvedSourcePath
        OutputPath = $resolvedRawSyntheticOutputPath
        Seed = $Seed
        GenerationDate = $GenerationDate
        ContentTemplateCount = $ContentTemplateCount
        CleanOutput = $true
        IncludeRawRows = $true
        PlanningSourceMachineLimit = $PlanningSourceMachineLimit
        PlanningSourceRowLimit = $PlanningSourceRowLimit
        SafetyDeviceLimit = $SafetyDeviceLimit
        SafetyRowLimit = $SafetyRowLimit
        MinimumAvailableMemoryGB = $MinimumAvailableMemoryGB
        MinimumFreeDiskGB = $MinimumFreeDiskGB
    }
    if ($TargetDeviceCount -gt 0) {
        $generatorArgs.TargetDeviceCount = $TargetDeviceCount
    }
    if ($TargetTotalVulnRows -gt 0) {
        $generatorArgs.TargetTotalVulnRows = $TargetTotalVulnRows
    }
    if ($AllowLargeDataset) {
        $generatorArgs.AllowLargeDataset = $true
    }

    Write-Host 'Generating raw synthetic dataset...' -ForegroundColor Cyan
    Invoke-RepoScript -RelativeScriptPath 'tests/Generate-SyntheticLargeExports.ps1' -Arguments $generatorArgs
}
elseif (-not (Test-Path -LiteralPath $resolvedRawSyntheticOutputPath -PathType Container)) {
    throw "Raw synthetic dataset path not found: $resolvedRawSyntheticOutputPath"
}

if (-not $SkipLiveShift) {
    Write-Host 'Shifting raw synthetic dataset to a live sidecar-free form...' -ForegroundColor Cyan
    Invoke-RepoScript -RelativeScriptPath 'tests/New-SyntheticLiveExport.ps1' -Arguments @{
        SourcePath = $resolvedRawSyntheticOutputPath
        OutputPath = $resolvedRawLiveOutputPath
        TargetLatestDate = $TargetLatestDate
        SkipContentStoreSidecars = $true
        Force = $true
    }
}
elseif (-not (Test-Path -LiteralPath $resolvedRawLiveOutputPath -PathType Container)) {
    throw "Raw live dataset path not found: $resolvedRawLiveOutputPath"
}

if (-not $SkipLegacySnapshotGeneration) {
    $legacyArgs = @{
        SourcePath = $resolvedRawLiveOutputPath
        OutputPath = $resolvedLegacySnapshotOutputPath
        SnapshotCount = $SnapshotCount
        Force = $true
    }
    if ($null -ne $SnapshotDates -and $SnapshotDates.Count -gt 0) {
        $legacyArgs.SnapshotDates = $SnapshotDates
    }

    Write-Host 'Materializing deterministic legacy vulnerability snapshots...' -ForegroundColor Cyan
    Invoke-RepoScript -RelativeScriptPath 'tests/New-SyntheticLegacyVulnSnapshotSet.ps1' -Arguments $legacyArgs
}
elseif (-not (Test-Path -LiteralPath $resolvedLegacySnapshotOutputPath -PathType Container)) {
    throw "Legacy snapshot dataset path not found: $resolvedLegacySnapshotOutputPath"
}

if (-not $SkipAzureReplayDatasetBuild) {
    if ($Force) {
        Reset-DirectoryPath -Path $resolvedAzureReplayOutputPath
    }
    elseif (-not (Test-Path -LiteralPath $resolvedAzureReplayOutputPath -PathType Container)) {
        $null = New-Item -Path $resolvedAzureReplayOutputPath -ItemType Directory -Force
    }

    Write-Host 'Building Azure replay dataset with existing-export files...' -ForegroundColor Cyan
    $machineCopied = Copy-ArtifactIfPresent -SourcePath (Get-MachineCurrentPath -BasePath $resolvedRawLiveOutputPath) -DestinationDirectory $resolvedAzureReplayOutputPath
    if (-not $machineCopied) {
        throw "Expected machine current export was not found in '$resolvedRawLiveOutputPath'."
    }

    $null = Copy-ArtifactIfPresent -SourcePath (Get-AdvancedHuntingCurrentPath -BasePath $resolvedRawLiveOutputPath) -DestinationDirectory $resolvedAzureReplayOutputPath
    $null = Copy-ArtifactIfPresent -SourcePath (Join-Path $resolvedRawLiveOutputPath 'synthetic-manifest.json') -DestinationDirectory $resolvedAzureReplayOutputPath
    $null = Copy-ArtifactIfPresent -SourcePath (Join-Path $resolvedLegacySnapshotOutputPath 'synthetic-legacy-manifest.json') -DestinationDirectory $resolvedAzureReplayOutputPath

    foreach ($snapshotFile in @(Get-ChildItem -Path $resolvedLegacySnapshotOutputPath -Filter 'VulnExport_*.json.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        Copy-Item -LiteralPath $snapshotFile.FullName -Destination (Join-Path $resolvedAzureReplayOutputPath $snapshotFile.Name) -Force
    }
}

if (-not $SkipRawValidation) {
    Write-Host 'Running raw sidecar-free local validation...' -ForegroundColor Cyan
    Invoke-RepoScript -RelativeScriptPath 'tests/Invoke-LargeDatasetValidation.ps1' -Arguments @{
        SkipSyntheticGeneration = $true
        SyntheticOutputPath = $resolvedRawLiveOutputPath
        Validate = $true
    }
}

$legacyImportValidationResult = $null
if (-not $SkipLegacyImportValidation) {
    Write-Host 'Running local legacy vulnerability import validation...' -ForegroundColor Cyan
    if ($ProfileFreshImport) {
        $legacyImportValidationResult = Invoke-ProfiledFreshImport -SnapshotSourcePath $resolvedLegacySnapshotOutputPath -ValidationPath $resolvedLegacyImportValidationPath -ReferencePath $resolvedRawSyntheticOutputPath -CompiledPartitionReader:$ProfileCompiledPartitionReader
    }
    else {
        $legacyImportValidationResult = Invoke-LegacySnapshotImportValidation -SnapshotSourcePath $resolvedLegacySnapshotOutputPath -ValidationPath $resolvedLegacyImportValidationPath -ResetValidationPath $Force.IsPresent
    }
}

$legacyManifestPath = Join-Path $resolvedLegacySnapshotOutputPath 'synthetic-legacy-manifest.json'
$legacyManifest = if (Test-Path -LiteralPath $legacyManifestPath -PathType Leaf) {
    Get-Content -LiteralPath $legacyManifestPath -Raw | ConvertFrom-Json -Depth 20
}
else {
    $null
}

$workflowManifest = [ordered]@{
    preset = 'LargeImportCoverageWorkflow'
    generatedOnUtc = [datetime]::UtcNow.ToString('o')
    sourcePath = $resolvedSourcePath
    rawSyntheticOutputPath = $resolvedRawSyntheticOutputPath
    rawLiveOutputPath = $resolvedRawLiveOutputPath
    legacySnapshotOutputPath = $resolvedLegacySnapshotOutputPath
    azureReplayOutputPath = if ($SkipAzureReplayDatasetBuild) { $null } else { $resolvedAzureReplayOutputPath }
    legacyImportValidationPath = if ($SkipLegacyImportValidation) { $null } else { $resolvedLegacyImportValidationPath }
    targetLatestDate = $TargetLatestDate
    snapshotDates = if ($null -ne $legacyManifest -and $legacyManifest.PSObject.Properties['snapshotDates']) { @($legacyManifest.snapshotDates) } elseif ($null -ne $SnapshotDates) { @($SnapshotDates) } else { @() }
    snapshotCount = if ($null -ne $legacyManifest -and $legacyManifest.PSObject.Properties['snapshotCount']) { [int]$legacyManifest.snapshotCount } else { $SnapshotCount }
    skipped = [ordered]@{
        syntheticGeneration = [bool]$SkipSyntheticGeneration
        liveShift = [bool]$SkipLiveShift
        legacySnapshotGeneration = [bool]$SkipLegacySnapshotGeneration
        azureReplayDatasetBuild = [bool]$SkipAzureReplayDatasetBuild
        rawValidation = [bool]$SkipRawValidation
        legacyImportValidation = [bool]$SkipLegacyImportValidation
    }
    legacyImportValidation = if ($null -eq $legacyImportValidationResult) {
        $null
    }
    else {
        [ordered]@{
            snapshotFileCount = [int]$legacyImportValidationResult.snapshotFileCount
            publishResult = $legacyImportValidationResult.publishResult
        }
    }
}

$workflowManifestPath = Join-Path $resolvedAzureReplayOutputPath 'large-import-coverage-manifest.json'
if ($SkipAzureReplayDatasetBuild) {
    $workflowManifestPath = Join-Path $resolvedLegacySnapshotOutputPath 'large-import-coverage-manifest.json'
}
if (-not $ProfileFreshImport) {
    $workflowManifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $workflowManifestPath -Encoding utf8
}

Write-Host ''
Write-Host ('Large import coverage workflow completed.') -ForegroundColor Green
Write-Host ('  Raw synthetic dataset: {0}' -f $resolvedRawSyntheticOutputPath)
Write-Host ('  Raw live dataset: {0}' -f $resolvedRawLiveOutputPath)
Write-Host ('  Legacy vulnerability snapshots: {0}' -f $resolvedLegacySnapshotOutputPath)
if (-not $SkipAzureReplayDatasetBuild) {
    Write-Host ('  Azure replay dataset: {0}' -f $resolvedAzureReplayOutputPath)
}
if ($null -ne $legacyImportValidationResult) {
    Write-Host ('  Legacy import validation latest snapshot: {0}' -f [string]$legacyImportValidationResult.publishResult.LatestSnapshotDate)
    Write-Host ('  Legacy import validation current rows: {0}' -f [int]$legacyImportValidationResult.publishResult.CurrentRows)
}
