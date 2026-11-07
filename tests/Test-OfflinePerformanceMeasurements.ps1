#Requires -Version 7.6
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Generator parse failed.' }
foreach ($name in @('Get-LocalDiagnosticMemorySnapshot', 'Write-LocalDiagnosticMemoryMarker', 'Write-MemoryUsage', 'Initialize-LocalDiagnosticPhaseLog', 'Write-LocalDiagnosticPhaseLogEvent', 'Write-LocalDiagnosticRetentionMarker', 'Get-LocalDiagnosticPhaseContext', 'Complete-LocalDiagnosticPhase')) {
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $false)
    if ($null -eq $function) { throw "Missing diagnostic function: $name" }
    . ([scriptblock]::Create($function.Extent.Text))
}
# Execute the actual source-load statements with controlled reader boundaries; no fixture import.
$generatorText = $ast.Extent.Text
$loadStart = $generatorText.IndexOf("            `$phaseContext = Get-LocalDiagnosticPhaseContext -Name 'Load source data'", [StringComparison]::Ordinal)
$loadEnd = $generatorText.IndexOf("            `$phaseContext = Get-LocalDiagnosticPhaseContext -Name 'Normalize source data'", $loadStart, [StringComparison]::Ordinal)
if ($loadStart -lt 0 -or $loadEnd -le $loadStart) { throw 'Missing source-load diagnostic block.' }
$sourceLoadBlock = [scriptblock]::Create($generatorText.Substring($loadStart, $loadEnd - $loadStart))
function Invoke-SourceLoadDiagnosticControl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'DirectMergeDeviceLookup', Justification = 'Consumed by the dot-invoked production source-load block.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'effectiveSkipObservedWindowMerge', Justification = 'Consumed by the dot-invoked production source-load block.')]
    param([string]$LogPath, [string]$FailureStage = '', [switch]$DirectMerge, [switch]$Bucketed)
    Initialize-LocalDiagnosticPhaseLog -Path $LogPath
    $DirectoryPath = 'controlled-source'
    $DirectMergeDeviceLookup = [bool]$DirectMerge
    $BucketedMachineLookup = [bool]$Bucketed
    $effectiveSkipObservedWindowMerge = $false
    $localPhaseTimings = [Collections.Generic.List[object]]::new()
    $calls = [Collections.Generic.List[string]]::new()
    $machineRows = @{ device = 'machine-tuple' }
    $cveRows = @{ cve = 'cve-enrichment' }
    $userRows = @{ device = 'users' }
    $inventoryRows = @{ inventory = 'software-enrichment' }
    $nvdRows = @{ cve = 'nvd-enrichment' }
    function Sync-VulnContentStoreSidecar { param($BasePath) if ($BasePath -cne $DirectoryPath) { throw 'Sidecar path changed.' }; return $true }
    function Read-NormalizationMachineLookup {
        param($Path, [switch]$FileBacked, [switch]$Bucketed)
        $calls.Add('machines')
        if ($Path -cne $DirectoryPath -or -not $FileBacked -or [bool]$Bucketed -ne $BucketedMachineLookup) { throw 'Machine reader arguments changed.' }
        if ($FailureStage -eq 'machines') { throw 'reader-failed-machines' }
        return $machineRows
    }
    function Read-AdvancedHuntingBundle {
        param($Path, [switch]$IncludeDeviceUsers, [switch]$IncludeInventoryData)
        $calls.Add('advanced-hunting')
        if ($Path -cne $DirectoryPath -or -not $IncludeDeviceUsers -or -not $IncludeInventoryData) { throw 'AH inventory/user enrichment arguments changed.' }
        if ($FailureStage -eq 'advanced-hunting') { throw 'reader-failed-advanced-hunting' }
        return [pscustomobject]@{ AdvancedHuntingData = $cveRows; DeviceUsers = $userRows; InventoryData = $inventoryRows }
    }
    function Read-NvdCveData {
        param($Path)
        $calls.Add('nvd')
        if ($Path -cne $DirectoryPath) { throw 'NVD reader path changed.' }
        if ($FailureStage -eq 'nvd') { throw 'reader-failed-nvd' }
        return $nvdRows
    }
    function Get-NormalizationMachineLookupCount { param($Machines) return $Machines.Count }
    function Get-DashboardSourceSummary {
        param($BasePath, $MachineCount, $AdvancedHuntingCveCount, $AdvancedHuntingDeviceUserCount, $AdvancedHuntingInventoryTupleCount, $NvdCveCount, $NormalizationMode, [switch]$SkipObservedWindowMerge)
        if ($BasePath -cne $DirectoryPath -or $AdvancedHuntingCveCount -ne 1 -or $AdvancedHuntingDeviceUserCount -ne 1 -or $AdvancedHuntingInventoryTupleCount -ne 1 -or $NvdCveCount -ne 1 -or $NormalizationMode -cne 'live-normalization' -or $SkipObservedWindowMerge) { throw 'Source metadata changed.' }
        return @{ MachineCount = $MachineCount }
    }
    $failureMessage = $null
    try { . $sourceLoadBlock }
    catch { $failureMessage = $_.Exception.Message }
    if ($FailureStage) {
        if ($failureMessage -cne ('reader-failed-' + $FailureStage)) { throw "Reader exception was replaced: $failureMessage" }
    }
    else {
        if ($failureMessage) { throw $failureMessage }
        foreach ($pair in @(@($advancedHuntingData, $cveRows), @($advancedHuntingDeviceUsers, $userRows), @($advancedHuntingInventoryData, $inventoryRows), @($nvdCveData, $nvdRows))) {
            if (-not [object]::ReferenceEquals($pair[0], $pair[1])) { throw 'Diagnostics changed reader result identity.' }
        }
        if ($DirectMerge) {
            if ($machines.Count -ne 0 -or $calls.Contains('machines')) { throw 'Direct-merge skip changed.' }
        }
        elseif (-not [object]::ReferenceEquals($machines, $machineRows)) { throw 'Machine lookup identity changed.' }
    }
    return [pscustomobject]@{ Calls = @($calls); Phases = @($localPhaseTimings); Failure = $failureMessage }
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('offline-metrics-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
try {
    Initialize-LocalDiagnosticPhaseLog -Path ''
    $plain = Get-LocalDiagnosticMemorySnapshot
    if ($plain.PSObject.Properties['allocated_bytes']) { throw 'Disabled diagnostic log should not collect extra counters.' }
    $log = Join-Path $root 'phases.tsv'
    Initialize-LocalDiagnosticPhaseLog -Path $log
    $before = Write-LocalDiagnosticMemoryMarker -PhaseName 'synthetic phase' -Checkpoint start
    $buffer = [byte[]]::new(100000)
    [GC]::KeepAlive($buffer)
    $after = Write-LocalDiagnosticMemoryMarker -PhaseName 'synthetic phase' -Checkpoint end
    $lines = @(Get-Content -LiteralPath $log)
    if ($lines.Count -ne 2) { throw 'Expected exactly two memory checkpoints.' }
    foreach ($line in $lines) {
        $parts = $line -split "`t"
        if ($parts.Count -ne 4 -or $parts[1] -cne 'memory-checkpoint') { throw 'Invalid TSV checkpoint.' }
        $record = $parts[3] | ConvertFrom-Json
        foreach ($name in @('working_set_mb', 'private_memory_mb', 'gc_heap_mb', 'allocated_bytes', 'last_gc_heap_bytes', 'last_gc_loh_size_after_bytes', 'process_peak_working_set_bytes')) {
            if ($record.$name -lt 0) { throw "Invalid metric: $name" }
        }
        if ($record.gc_collections.Count -ne 3) { throw 'Expected all three GC generation counters.' }
    }
    if ($after.allocated_bytes -le $before.allocated_bytes) { throw 'Allocation counter did not advance.' }
    for ($generation = 0; $generation -lt 3; $generation++) {
        if ($after.gc_collections[$generation] -lt $before.gc_collections[$generation]) { throw 'GC counter regressed.' }
    }
    $null = Write-MemoryUsage
    $last = (Get-Content -LiteralPath $log -Tail 1) -split "`t"
    if ($last[1] -cne 'memory-detail' -or $last[2] -cne 'memory') { throw 'Default memory label logging failed.' }
    $fixture = Join-Path $root 'fixture'
    $null = New-Item -ItemType Directory -Path $fixture
    $nested = Join-Path $fixture 'output'
    $message = $null
    try { & (Join-Path $PSScriptRoot 'Invoke-OfflinePerformanceLane.ps1') -Lane FreshImport -FixturePath $fixture -Destination $nested }
    catch { $message = $_.Exception.Message }
    if ($message -cne 'Destination overlaps immutable input root.' -or (Test-Path -LiteralPath $nested)) { throw 'Nested destination guard failed.' }
    $raw = Join-Path $fixture 'raw'
    $null = New-Item -ItemType Directory -Path $raw
    '{"modelVersion":"procedural-v1"}' | Set-Content (Join-Path $raw 'synthetic-manifest.json')
    $destination = Join-Path $root 'replay-output'
    $message = $null
    try { & (Join-Path $PSScriptRoot 'Invoke-OfflinePerformanceLane.ps1') -Lane CompletedStoreReplay -FixturePath $fixture -Destination $destination -LibrariesPath $fixture -TemplatesPath $fixture }
    catch { $message = $_.Exception.Message }
    if ($message -notlike 'Missing canonical replay input:*' -or (Test-Path -LiteralPath $destination)) { throw 'Incomplete canonical replay guard failed.' }
    $freshOutput = Join-Path $root 'fresh-output'
    $message = $null
    try { & (Join-Path $PSScriptRoot 'Invoke-OfflinePerformanceLane.ps1') -Lane FreshImport -FixturePath $fixture -Destination $freshOutput }
    catch { $message = $_.Exception.Message }
    if ($null -eq $message -or (Test-Path -LiteralPath $freshOutput)) { throw 'Missing fresh inputs must fail before creating output.' }
    if ($IsWindows) {
        $junction = Join-Path $root 'alias'
        $null = New-Item -ItemType Junction -Path $junction -Target $fixture
        try {
            $message = $null
            try { & (Join-Path $PSScriptRoot 'Invoke-OfflinePerformanceLane.ps1') -Lane FreshImport -FixturePath $fixture -Destination (Join-Path $junction 'output') }
            catch { $message = $_.Exception.Message }
            if ($message -cne 'Reparse-point output ancestors are not supported.' -or (Test-Path -LiteralPath $nested)) { throw 'Junction destination guard failed.' }
        }
        finally { Remove-Item -LiteralPath $junction -Force }
    }
    $sourceLog = Join-Path $root 'source-phases.tsv'
    $control = Invoke-SourceLoadDiagnosticControl -LogPath $sourceLog
    $expectedNames = @('Load source data/machines', 'Load source data/advanced-hunting', 'Load source data/nvd', 'Load source data')
    if (($control.Phases.Name -join '|') -cne ($expectedNames -join '|') -or @($control.Phases | Where-Object Status -ne completed).Count) { throw 'Source subphase/parent summaries changed.' }
    $records = @(Get-Content -LiteralPath $sourceLog | ForEach-Object { $fields = $_ -split "`t", 4; [pscustomobject]@{ Event = $fields[1]; Name = $fields[2]; Value = if ($fields.Count -gt 3) { $fields[3] } else { '' } } })
    $boundaries = @($records | Where-Object Event -in @('phase-start', 'phase-end') | ForEach-Object { $_.Event + ':' + $_.Name })
    $expectedBoundaries = @('phase-start:Load source data', 'phase-start:Load source data/machines', 'phase-end:Load source data/machines', 'phase-start:Load source data/advanced-hunting', 'phase-end:Load source data/advanced-hunting', 'phase-start:Load source data/nvd', 'phase-end:Load source data/nvd', 'phase-end:Load source data')
    if (($boundaries -join '|') -cne ($expectedBoundaries -join '|')) { throw 'Nested phase boundaries lost parent or reader order.' }
    foreach ($name in $expectedNames) {
        $checkpoints = @($records | Where-Object { $_.Event -eq 'memory-checkpoint' -and $_.Name.StartsWith($name + '/', [StringComparison]::Ordinal) -and $_.Name.Substring($name.Length + 1) -in @('start', 'end') })
        if ($checkpoints.Count -ne 2) { throw "Missing source counters for $name" }
        $start = $checkpoints[0].Value | ConvertFrom-Json
        $end = $checkpoints[1].Value | ConvertFrom-Json
        if ($end.allocated_bytes -lt $start.allocated_bytes -or $end.process_peak_working_set_bytes -lt $start.process_peak_working_set_bytes) { throw 'Cumulative source counters regressed.' }
    }
    $counts = @($records | Where-Object Event -eq 'retention-checkpoint')
    if ($counts.Count -ne 1 -or $counts[0].Name -cne 'Load source data/inputs-loaded') { throw 'Missing machine-readable retained counts.' }
    $counts = $counts[0].Value | ConvertFrom-Json
    foreach ($name in @('machines', 'advancedHuntingCves', 'advancedHuntingDeviceUsers', 'advancedHuntingInventoryTuples', 'nvdCves')) {
        if ($counts.$name -ne 1) { throw "Retained count changed: $name" }
    }
    $disabled = Invoke-SourceLoadDiagnosticControl -LogPath ''
    if ($disabled.Phases.Count -ne 1 -or $disabled.Phases[0].Name -cne 'Load source data') { throw 'Disabled diagnostics added source phases.' }
    $null = Invoke-SourceLoadDiagnosticControl -LogPath '' -DirectMerge
    $null = Invoke-SourceLoadDiagnosticControl -LogPath '' -Bucketed
    foreach ($stage in @('machines', 'advanced-hunting', 'nvd')) {
        $failedLog = Join-Path $root ($stage + '-failed.tsv')
        $failed = Invoke-SourceLoadDiagnosticControl -LogPath $failedLog -FailureStage $stage
        if ($failed.Phases[-1].Name -cne ('Load source data/' + $stage) -or $failed.Phases[-1].Status -cne 'failed') { throw 'Failed reader was labelled completed.' }
        $failureEnd = (Get-Content -LiteralPath $failedLog -Tail 1) -split "`t", 4
        if ($failureEnd[1] -cne 'phase-end' -or $failureEnd[2] -cne ('Load source data/' + $stage) -or $failureEnd[3] -cne 'failed' -or $failed.Calls[-1] -cne $stage) { throw 'Failure crossed reader boundary or lost diagnostic status.' }
    }
    Write-Output 'PASS offline measurement counters, source subphases and lane guards.'
}
finally {
    $script:LocalDiagnosticPhaseLogPath = $null
    if ([IO.Path]::GetFullPath($root).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
