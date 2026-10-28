#Requires -Version 7.6
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Generator parse failed.' }
foreach ($name in @('Get-LocalDiagnosticMemorySnapshot', 'Write-LocalDiagnosticMemoryMarker', 'Write-MemoryUsage', 'Initialize-LocalDiagnosticPhaseLog', 'Write-LocalDiagnosticPhaseLogEvent')) {
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $false)
    if ($null -eq $function) { throw "Missing diagnostic function: $name" }
    . ([scriptblock]::Create($function.Extent.Text))
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
    Write-Output 'PASS offline measurement counters and lane guards.'
}
finally {
    $script:LocalDiagnosticPhaseLogPath = $null
    if ([IO.Path]::GetFullPath($root).StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
