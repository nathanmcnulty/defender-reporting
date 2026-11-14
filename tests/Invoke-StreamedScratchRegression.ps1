#Requires -Version 7.6
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'build/Import-SharedHelpers.ps1')
$fixtureAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Run-SharedHelperRegression.ps1'), [ref]$null, [ref]$null)
$fixture = $fixtureAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-TestVulnRow' }, $true)
. ([scriptblock]::Create($fixture.Extent.Text))
function Assert-True([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Failure([scriptblock]$Action, [string]$Message) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    Assert-True $failed $Message
}
function Write-Snapshot([string]$Root, [string]$Name, [object[]]$Rows) {
    $path = Join-Path $Root $Name
    $text = (@($Rows | ForEach-Object { $_ | ConvertTo-Json -Depth 30 -Compress }) -join "`r`n") # No final newline.
    if ($Name.EndsWith('.gz')) { Write-GzipTextFile -Path $path -Content $text }
    else { [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false)) }
    return $path
}
function Get-CanonicalFileState([string]$Root) {
    $result = [ordered]@{}
    foreach ($file in @(Get-ChildItem -LiteralPath $Root -File | Where-Object { $_.Name -match '^Vuln(Export_current|History|ContentDictionary|CurrentRefs)' } | Sort-Object Name)) {
        $result[$file.Name] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))
    }
    return ($result | ConvertTo-Json -Compress -Depth 10)
}
function Get-TypedSummary($Summary) {
    $types = @($Summary.PSObject.Properties | ForEach-Object { $_.Name + ':' + $(if ($null -eq $_.Value) { 'null' } else { $_.Value.GetType().FullName }) })
    return (($types -join ',') + '|' + ($Summary | ConvertTo-Json -Depth 30 -Compress))
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('streamed-scratch-' + [guid]::NewGuid().ToString('N'))
$originalPartitions = $Script:VulnDiskPartitionCount
$originalJournal = ${function:Write-StoreTransactionState}
$originalPartitionWriter = ${function:Open-VulnPartitionWriter}
$originalIntegrityWriter = ${function:Write-VulnTemporaryPartitionIntegrity}
$originalSplitter = ${function:Split-VulnJsonPartition}
try {
    [void][IO.Directory]::CreateDirectory($root)
    # Force collisions in these tiny fixtures, including case variants. This is
    # correctness coverage, not a change to production's 128-partition profile.
    $Script:VulnDiskPartitionCount = 1
    $script:ScratchWriterModes = [Collections.Generic.List[object]]::new()
    Set-Item Function:Open-VulnPartitionWriter -Value {
        param($Path, [switch]$Append, [switch]$CompressTemporaryPartitions, [System.Collections.IDictionary]$TemporaryPartitionIntegrity)
        $script:ScratchWriterModes.Add(@{ Path = $Path; Compressed = [bool]$CompressTemporaryPartitions })
        & $originalPartitionWriter -Path $Path -Append:$Append -CompressTemporaryPartitions:$CompressTemporaryPartitions -TemporaryPartitionIntegrity $TemporaryPartitionIntegrity
    }
    $one = Get-TestVulnRow -Id 'same' -CveId 'CVE-2026-0001' -SnapshotDate '2026-01-01' -Version '1'
    $last = Get-TestVulnRow -Id 'SAME' -CveId 'CVE-2026-0001' -SnapshotDate '2026-01-01' -Version '2'
    $last.DeviceName = 'Unicode-' + [char]0x03A9 + [char]0x6D4B + ('x' * 70000)
    $last | Add-Member -NotePropertyName ExtraProbe -NotePropertyValue @{ amount = [decimal]1.25; flag = $true; empty = $null; values = @('UPPER', 'lower', $null) }
    $second = Get-TestVulnRow -Id 'other' -CveId 'CVE-2026-0002' -SnapshotDate '2026-01-01' -Version '1'
    $offboarded = Get-TestVulnRow -Id 'excluded' -CveId 'CVE-2026-0003' -SnapshotDate '2026-01-01' -Version '1'
    $offboarded.IsOnboarded = $false
    $baseline = Join-Path $root 'baseline'; $candidate = Join-Path $root 'candidate'
    foreach ($path in @($baseline, $candidate)) { [void][IO.Directory]::CreateDirectory($path) }
    foreach ($step in 1..3) {
        $summaries = @(); $rows = @()
        foreach ($compressed in @($false, $true)) {
            $path = if ($compressed) { $candidate } else { $baseline }
            $files = if ($step -eq 1) {
                @((Write-Snapshot $path 'VulnExport_1_2026-01-01.json' @($one, $offboarded)), (Write-Snapshot $path 'VulnExport_2_2026-01-01.json.gz' @($second, $last)))
            }
            elseif ($step -eq 2) {
                # Change ID casing/signature and version, remove other and add new.
                $changed = Get-TestVulnRow -Id 'same' -CveId 'CVE-2026-0001' -SnapshotDate '2026-01-02' -Version '3'
                $new = Get-TestVulnRow -Id 'new' -CveId 'CVE-2026-0004' -SnapshotDate '2026-01-02' -Version '1'
                @((Write-Snapshot $path 'VulnExport_1_2026-01-02.json.gz' @($changed, $new)))
            }
            else { @((Write-Snapshot $path 'VulnExport_1_2026-01-03.json' @($offboarded))) }
            $arguments = @{ OutputPath = $path; DownloadedFiles = $files }
            if ($compressed) { $arguments.CompressTemporaryPartitions = $true }
            $script:ScratchWriterModes.Clear()
            $summary = Publish-VulnerabilityHistoryStore @arguments
            Assert-True ($script:ScratchWriterModes.Count -gt 0) 'Expected the real generic importer to open temporary partitions.'
            foreach ($mode in $script:ScratchWriterModes) {
                Assert-True ($mode.Compressed -eq $compressed -and $mode.Path.EndsWith('.gz') -eq $compressed) 'Production import did not thread the selected temporary format consistently.'
            }
            $summaries += Get-TypedSummary $summary
            $rows += ,(@(Read-VulnContentStoreRow -BasePath $path) | ConvertTo-Json -Depth 50 -Compress)
            Assert-True (@(Get-ChildItem -LiteralPath $path -Force | Where-Object { $_.Name -match '^\.vuln|^VulnExport_[0-9]+_' }).Count -eq 0) 'Import left raw snapshots or staging/transaction artifacts.'
        }
        Assert-True ($summaries[0] -ceq $summaries[1]) "Typed import summary differs at step $step."
        Assert-True ((Get-CanonicalFileState $baseline) -ceq (Get-CanonicalFileState $candidate)) "Complete canonical bytes differ at step $step."
        Assert-True ($rows[0] -ceq $rows[1]) "Full expanded row values/order differ at step $step."
    }
    # A single invocation with several dates must preserve same-date last wins
    # and cross-date history, as well as incremental imports above.
    $results = @()
    foreach ($compressed in @($false, $true)) {
        $path = Join-Path $root "all-dates-$compressed"; [void][IO.Directory]::CreateDirectory($path)
        $files = @((Write-Snapshot $path 'VulnExport_1_2026-01-01.json' @($one)), (Write-Snapshot $path 'VulnExport_2_2026-01-01.json' @($last, $second)), (Write-Snapshot $path 'VulnExport_1_2026-01-02.json.gz' @($last)))
        $summary = Publish-VulnerabilityHistoryStore -OutputPath $path -DownloadedFiles $files -CompressTemporaryPartitions:$compressed
        $results += @((Get-TypedSummary $summary), (Get-CanonicalFileState $path)) -join '|'
    }
    Assert-True ($results[0] -ceq $results[1]) 'Multi-date import differs.'
    # Opt-in changes only temporary partitions; it must not bypass an existing
    # procedural initial-import shortcut when that shortcut is applicable.
    $fastResults = @()
    foreach ($compressed in @($false, $true)) {
        $path = Join-Path $root "procedural-$compressed"; [void][IO.Directory]::CreateDirectory($path)
        [IO.File]::WriteAllText((Join-Path $path 'synthetic-manifest.json'), '{"modelVersion":"procedural-v1"}')
        $file = Write-Snapshot $path 'VulnExport_1_2026-01-01.json' @($one)
        $script:ScratchWriterModes.Clear()
        $summary = Publish-VulnerabilityHistoryStore -OutputPath $path -DownloadedFiles @($file) -CompressTemporaryPartitions:$compressed
        Assert-True ($script:ScratchWriterModes.Count -eq 0) 'The option bypassed the procedural shortcut and entered temporary partitioning.'
        $fastResults += @((Get-TypedSummary $summary), (Get-CanonicalFileState $path)) -join '|'
    }
    Assert-True ($fastResults[0] -ceq $fastResults[1]) 'Opt-in altered the procedural shortcut or its existing raw-retention behavior.'
    # The shared plain ID-validation spool keeps its original path and reader.
    Assert-True ((Get-VulnPartitionFilePath -Root $root -Prefix id -Index 0).EndsWith('id-00.ndjson')) 'Default ID partition contract changed.'
    foreach ($compressed in @($false, $true)) {
        $integrity = @{}
        $parts = Join-Path $root "parts-$compressed"
        $sourcePath = Write-Snapshot $root "source-$compressed.json" @($one, $last)
        $script:PartitionWriterCalls = 0
        Set-Item Function:Open-VulnPartitionWriter -Value {
            param($Path, [switch]$Append, [switch]$CompressTemporaryPartitions, [System.Collections.IDictionary]$TemporaryPartitionIntegrity)
            $script:PartitionWriterCalls++
            & $originalPartitionWriter -Path $Path -Append:$Append -CompressTemporaryPartitions:$CompressTemporaryPartitions -TemporaryPartitionIntegrity $TemporaryPartitionIntegrity
        }
        try {
            for ($repeat = 0; $repeat -lt 2; $repeat++) { [void](Split-VulnJsonPartition -InputPaths @($sourcePath) -OutputRoot $parts -Prefix current -PartitionCount 1 -CompressTemporaryPartitions:$compressed -TemporaryPartitionIntegrity $integrity) }
            Assert-True ($script:PartitionWriterCalls -eq 2) 'Expected one retained writer per partition per splitter invocation, not per row.'
        }
        finally { Set-Item Function:Open-VulnPartitionWriter -Value $originalPartitionWriter }
        if ($compressed) { Assert-True (@(Get-ChildItem -LiteralPath $parts -Recurse -File | Where-Object { $_.Name -notlike '*.gz' }).Count -eq 0) 'Compressed splitter created plaintext scratch.' }
        $partition = Get-VulnPartitionFilePath -Root $parts -Prefix current -Index 0 -CompressTemporaryPartitions:$compressed
        $lines = @(Read-VulnNdjsonLinesFromPath -Path $partition)
        Assert-True ($lines.Count -eq 4 -and $lines[1] -ceq $lines[3]) 'Append/concatenated members lost row text or order.'
        $map = Read-VulnPartitionMapFile -Path $partition -CompressTemporaryPartitions:$compressed -TemporaryPartitionIntegrity $integrity
        Assert-True ($map.Count -eq 1 -and $map.same.Signature -ceq 'SAME') 'Case-insensitive last-wins map changed.'
        [void](Write-VulnPartitionMapFile -Path $partition -RowsById $map -CompressTemporaryPartitions:$compressed -TemporaryPartitionIntegrity $integrity)
        Assert-True (@(Read-VulnNdjsonLinesFromPath -Path $partition).Count -eq 1) 'Map rewrite appended stale rows.'
        $final = Join-Path $root "current-$compressed.gz"
        [void](Write-VulnCurrentFileFromPartition -PartitionRoot $parts -PartitionPrefix current -OutputPath $final -PartitionCount 1 -CompressTemporaryPartitions:$compressed -TemporaryPartitionIntegrity $integrity)
        [void](Write-VulnPartitionMapFile -Path $partition -RowsById @{} -CompressTemporaryPartitions:$compressed -TemporaryPartitionIntegrity $integrity)
        Assert-True (-not(Test-Path -LiteralPath $partition)) 'Empty map did not remove its partition.'
        $bad = Join-Path $root "bad-$compressed.json"; [IO.File]::WriteAllText($bad, ($one | ConvertTo-Json -Depth 20 -Compress) + "`n{broken")
        $badParts = Join-Path $root "bad-parts-$compressed"
        Assert-Failure { Split-VulnJsonPartition -InputPaths @($bad) -OutputRoot $badParts -Prefix bad -PartitionCount 1 -CompressTemporaryPartitions:$compressed -TemporaryPartitionIntegrity $integrity } 'Malformed input should fail.'
        foreach ($file in @($bad) + @(Get-ChildItem -LiteralPath $badParts -File | Select-Object -ExpandProperty FullName)) {
            $exclusive = [IO.File]::Open($file, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None); $exclusive.Dispose()
        }
    }
    Assert-True ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $root 'current-False.gz'))) -ceq [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $root 'current-True.gz')))) 'Final canonical GZip bytes changed.'
    # An unfinished GZip member/trailer can yield a valid prefix in the legacy
    # reader. The new opt-in path must reject it before reading or appending.
    $appendInput = Write-Snapshot $root 'append-source.json' @([pscustomobject]@{ Id = 'c' })
    foreach ($damage in @('PartialMember', 'Trailer', 'SameLengthCorruption', 'MissingFile')) {
        $parts = Join-Path $root ('integrity-' + $damage); [void][IO.Directory]::CreateDirectory($parts)
        $partition = Get-VulnPartitionFilePath -Root $parts -Prefix current -Index 0 -CompressTemporaryPartitions
        $integrity = @{}
        $writer = Open-VulnPartitionWriter -Path $partition -CompressTemporaryPartitions -TemporaryPartitionIntegrity $integrity
        try {
            $writer.WriteLine('{"Id":"a"}'); $writer.Flush()
            $prefixLength = $writer.BaseStream.BaseStream.Length
            $writer.WriteLine('{"Id":"b"}')
        }
        finally { $writer.Dispose() }
        Write-VulnTemporaryPartitionIntegrity -Path $partition -TemporaryPartitionIntegrity $integrity
        $complete = [IO.File]::ReadAllBytes($partition)
        if ($damage -eq 'PartialMember') { [IO.File]::WriteAllBytes($partition, $complete[0..($prefixLength - 1)]) }
        elseif ($damage -eq 'Trailer') { [IO.File]::WriteAllBytes($partition, $complete[0..($complete.Length - 9)]) }
        elseif ($damage -eq 'SameLengthCorruption') { $complete[-1] = $complete[-1] -bxor 1; [IO.File]::WriteAllBytes($partition, $complete) }
        else { [IO.File]::Delete($partition) }
        if ($damage -in @('PartialMember', 'Trailer')) {
            $legacyRows = @(Read-VulnNdjsonLinesFromPath -Path $partition)
            $expectedPrefixRows = if ($damage -eq 'PartialMember') { 1 } else { 2 }
            Assert-True ($legacyRows.Count -eq $expectedPrefixRows) 'Legacy incomplete-member control did not reproduce.'
        }
        Assert-Failure { Read-VulnPartitionMapFile -Path $partition -CompressTemporaryPartitions -TemporaryPartitionIntegrity $integrity } "New temporary reader accepted $damage."
        Assert-Failure { Write-VulnCurrentFileFromPartition -PartitionRoot $parts -PartitionPrefix current -OutputPath (Join-Path $root ("rejected-$damage.gz")) -PartitionCount 1 -CompressTemporaryPartitions -TemporaryPartitionIntegrity $integrity } "Final assembly accepted $damage."
        $damagedBytes = if (Test-Path -LiteralPath $partition) { [Convert]::ToBase64String([IO.File]::ReadAllBytes($partition)) } else { 'missing' }
        Assert-Failure { Split-VulnJsonPartition -InputPaths @($appendInput) -OutputRoot $parts -Prefix current -PartitionCount 1 -CompressTemporaryPartitions -TemporaryPartitionIntegrity $integrity } "Append legitimized $damage."
        Assert-Failure { Write-VulnPartitionMapFile -Path $partition -RowsById @{ c = [pscustomobject]@{ Json = '{"Id":"c"}' } } -CompressTemporaryPartitions -TemporaryPartitionIntegrity $integrity } "Map rewrite legitimized $damage."
        $after = if (Test-Path -LiteralPath $partition) { [Convert]::ToBase64String([IO.File]::ReadAllBytes($partition)) } else { 'missing' }
        Assert-True ($after -ceq $damagedBytes) 'Rejected append/rewrite changed damaged input.'
    }
    # Failed metadata finalization closes all streams and cannot bless bytes.
    $readOnlyIntegrity = [Collections.Specialized.OrderedDictionary]::new().AsReadOnly()
    $metadataParts = Join-Path $root 'metadata-readonly'
    Assert-Failure { Split-VulnJsonPartition -InputPaths @($appendInput) -OutputRoot $metadataParts -Prefix current -PartitionCount 1 -CompressTemporaryPartitions -TemporaryPartitionIntegrity $readOnlyIntegrity } 'Read-only metadata must stop the splitter.'
    $metadataPath = Get-VulnPartitionFilePath -Root $metadataParts -Prefix current -Index 0 -CompressTemporaryPartitions
    Assert-Failure { Read-VulnPartitionMapFile -Path $metadataPath -CompressTemporaryPartitions -TemporaryPartitionIntegrity @{} } 'Missing finalized metadata must reject complete-looking bytes.'
    $exclusive = [IO.File]::Open($metadataPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None); $exclusive.Dispose()
    # Preserve original parse/row failures when closing the compressed stream
    # also fails. No successful-operation metadata may be recorded in that case.
    Set-Item Function:Open-VulnPartitionWriter -Value {
        param($Path, [switch]$Append, [switch]$CompressTemporaryPartitions, [System.Collections.IDictionary]$TemporaryPartitionIntegrity)
        $inner = & $originalPartitionWriter -Path $Path -Append:$Append -CompressTemporaryPartitions:$CompressTemporaryPartitions -TemporaryPartitionIntegrity $TemporaryPartitionIntegrity
        $wrapper = [pscustomobject]@{ Inner = $inner }
        $wrapper | Add-Member -MemberType ScriptMethod -Name WriteLine -Value { param($Line) $this.Inner.WriteLine($Line) }
        $wrapper | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.Inner.Dispose(); throw 'Injected secondary close failure.' }
        return $wrapper
    }
    try {
        $bad = Join-Path $root 'primary-source-error.json'; [IO.File]::WriteAllText($bad, '{"Id":"a"}' + [Environment]::NewLine + '{broken')
        $failure = $null; $integrity = @{}; $badParts = Join-Path $root 'primary-source-error'
        try { [void](Split-VulnJsonPartition -InputPaths @($bad) -OutputRoot $badParts -Prefix current -PartitionCount 1 -CompressTemporaryPartitions -TemporaryPartitionIntegrity $integrity) } catch { $failure = $_ }
        Assert-True ($null -ne $failure -and $failure.Exception.Message -notlike '*Injected secondary close failure*' -and $failure.Exception.Data.Contains('TemporaryPartitionCloseFailure')) 'Splitter replaced its original source failure.'
        Assert-True ($integrity.Count -eq 0) 'Failed source operation finalized metadata.'
        $mapPath = Get-VulnPartitionFilePath -Root $badParts -Prefix current -Index 0 -CompressTemporaryPartitions
        $exclusive = [IO.File]::Open($mapPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None); $exclusive.Dispose()
        $mapPath = Join-Path $root 'primary-map-error.ndjson.gz'
        $badRow = $null # StrictMode rejects an invalid map entry before closing.
        $failure = $null; $integrity = @{}
        try { [void](Write-VulnPartitionMapFile -Path $mapPath -RowsById @{ a = $badRow } -CompressTemporaryPartitions -TemporaryPartitionIntegrity $integrity) } catch { $failure = $_ }
        Assert-True ($null -ne $failure -and $failure.Exception.Message -notlike '*Injected secondary close failure*' -and $failure.Exception.Data.Contains('TemporaryPartitionCloseFailure')) 'Map writer replaced its original row failure.'
        Assert-True ($integrity.Count -eq 0) 'Failed map write finalized metadata.'
        $exclusive = [IO.File]::Open($mapPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None); $exclusive.Dispose()
    }
    finally { Set-Item Function:Open-VulnPartitionWriter -Value $originalPartitionWriter }
    # Real-import metadata failure must preserve canonical bytes and raw input.
    $metadataStore = Join-Path $root 'metadata-import'; [void][IO.Directory]::CreateDirectory($metadataStore)
    $first = Write-Snapshot $metadataStore 'VulnExport_1_2026-01-01.json' @($one)
    [void](Publish-VulnerabilityHistoryStore -OutputPath $metadataStore -DownloadedFiles @($first))
    $beforeMetadata = Get-CanonicalFileState $metadataStore
    $nextMetadata = Write-Snapshot $metadataStore 'VulnExport_1_2026-01-02.json' @($second)
    Set-Item Function:Write-VulnTemporaryPartitionIntegrity -Value { throw 'Injected integrity metadata failure.' }
    try { Assert-Failure { Publish-VulnerabilityHistoryStore -OutputPath $metadataStore -DownloadedFiles @($nextMetadata) -CompressTemporaryPartitions } 'Metadata failure must abort the real importer.' }
    finally { Set-Item Function:Write-VulnTemporaryPartitionIntegrity -Value $originalIntegrityWriter }
    Assert-True ((Get-CanonicalFileState $metadataStore) -ceq $beforeMetadata -and (Test-Path -LiteralPath $nextMetadata)) 'Metadata failure changed canonical bytes or retired raw input.'
    [void](Publish-VulnerabilityHistoryStore -OutputPath $metadataStore -DownloadedFiles @($nextMetadata) -CompressTemporaryPartitions)
    Assert-True (-not(Test-Path -LiteralPath $nextMetadata)) 'Metadata-failure retry did not complete.'
    # A deleted first-date snapshot partition must not take the importer's
    # ordinary both-paths-missing fast skip and silently publish an empty store.
    $missingStore = Join-Path $root 'missing-partition-import'; [void][IO.Directory]::CreateDirectory($missingStore)
    $missingInput = Write-Snapshot $missingStore 'VulnExport_1_2026-01-01.json' @($one)
    Set-Item Function:Split-VulnJsonPartition -Value {
        param($InputPaths, $OutputRoot, $Prefix, [switch]$OnboardedOnly, [int]$PartitionCount, [switch]$CompressTemporaryPartitions, [System.Collections.IDictionary]$TemporaryPartitionIntegrity)
        $indexes = @(& $originalSplitter @PSBoundParameters)
        if ($CompressTemporaryPartitions -and $Prefix -eq 'snapshot') {
            $missing = Get-VulnPartitionFilePath -Root $OutputRoot -Prefix $Prefix -Index $indexes[0] -CompressTemporaryPartitions
            [IO.File]::Delete($missing)
        }
        return $indexes
    }
    try { Assert-Failure { Publish-VulnerabilityHistoryStore -OutputPath $missingStore -DownloadedFiles @($missingInput) -CompressTemporaryPartitions } 'A deleted first-date partition must fail the real importer.' }
    finally { Set-Item Function:Split-VulnJsonPartition -Value $originalSplitter }
    Assert-True (-not(Test-VulnStoreExistence -BasePath $missingStore) -and (Test-Path -LiteralPath $missingInput)) 'A missing partition created a canonical store or retired its raw input.'
    [void](Publish-VulnerabilityHistoryStore -OutputPath $missingStore -DownloadedFiles @($missingInput) -CompressTemporaryPartitions)
    $corrupt = Join-Path $root 'corrupt.ndjson.gz'; [IO.File]::WriteAllBytes($corrupt, [byte[]](1..32))
    Assert-Failure { Read-VulnPartitionMapFile -Path $corrupt } 'Corrupt compression should fail.'
    $exclusive = [IO.File]::Open($corrupt, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None); $exclusive.Dispose()
    # Inject after canonical replacement but before the commit marker. The real
    # journal/restore path must retain prior canonical bytes and new raw inputs.
    foreach ($compressed in @($false, $true)) {
        $path = Join-Path $root "rollback-$compressed"; [void][IO.Directory]::CreateDirectory($path)
        $initial = Write-Snapshot $path 'VulnExport_1_2026-01-01.json' @($one)
        [void](Publish-VulnerabilityHistoryStore -OutputPath $path -DownloadedFiles @($initial) -CompressTemporaryPartitions:$compressed)
        $before = Get-CanonicalFileState $path
        $next = Write-Snapshot $path 'VulnExport_1_2026-01-02.json.gz' @($second)
        Set-Item Function:Write-StoreTransactionState -Value {
            param($State, $Path)
            if ($State.Phase -ceq 'Committed') { throw 'Injected commit-marker failure.' }
            & $originalJournal -State $State -Path $Path
        }
        try { Assert-Failure { Publish-VulnerabilityHistoryStore -OutputPath $path -DownloadedFiles @($next) -CompressTemporaryPartitions:$compressed } 'Commit-marker injection must fail.' }
        finally { Set-Item Function:Write-StoreTransactionState -Value $originalJournal }
        Assert-True ((Get-CanonicalFileState $path) -ceq $before) 'Failed transaction changed prior canonical bytes.'
        Assert-True (Test-Path -LiteralPath $next) 'Failed transaction discarded raw inputs.'
        [void](Publish-VulnerabilityHistoryStore -OutputPath $path -DownloadedFiles @($next) -CompressTemporaryPartitions:$compressed)
        Assert-True (-not(Test-Path -LiteralPath $next)) 'Successful retry did not retire raw inputs.'
    }
    Write-Output 'Streamed temporary GZip partition parity, lifecycle and rollback checks passed.'
}
finally {
    Set-Item Function:Write-StoreTransactionState -Value $originalJournal
    Set-Item Function:Open-VulnPartitionWriter -Value $originalPartitionWriter
    $Script:VulnDiskPartitionCount = $originalPartitions
    Set-Item Function:Write-VulnTemporaryPartitionIntegrity -Value $originalIntegrityWriter
    Set-Item Function:Split-VulnJsonPartition -Value $originalSplitter
    if (Test-Path -LiteralPath $root) {
        $resolved = [IO.Path]::GetFullPath($root)
        $resolvedTempParent = [IO.Path]::TrimEndingDirectorySeparator([IO.Path]::GetFullPath([IO.Path]::GetTempPath()))
        if (-not [string]::Equals([IO.Path]::GetDirectoryName($resolved), $resolvedTempParent, [StringComparison]::Ordinal)) { throw 'Test cleanup escaped its named temp parent.' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
