#Requires -Version 7.6
<#
.SYNOPSIS
Runs one synthetic offline measurement cell under an external owned-process supervisor.
.DESCRIPTION
FreshImport measures one import; -ProfileImport adds the profiler's parity twin. CompletedStoreReplay
normalizes canonical sidecars without raw snapshots or a payload-cache hit.
PackageOnly consumes an explicit normalized payload. Never compare their elapsed times.
The caller must pin inputs/source/runtime, serialize cells and enforce admission,
time and process-family limits. This inner operation is not a supervisor.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('FreshImport', 'CompletedStoreReplay', 'PackageOnly')][string]$Lane,
    [Parameter(Mandatory)][string]$FixturePath,
    [Parameter(Mandatory)][string]$Destination,
    [string]$LibrariesPath,
    [string]$TemplatesPath,
    [string]$PayloadPath,
    [string]$PayloadManifestPath,
    [switch]$ProfileImport,
    [ValidateSet('Hosted', 'Dual')][string]$Mode = 'Dual'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
$Destination = [IO.Path]::GetFullPath($Destination)
$FixturePath = [IO.Path]::GetFullPath($FixturePath)
function Assert-SeparateInputRoot([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $root = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    if ($Destination.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
        $Destination.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Destination overlaps immutable input root.'
    }
    $item = Get-Item -LiteralPath $root -ErrorAction Stop
    for ($ancestor = $item; $null -ne $ancestor; $ancestor = $ancestor.Parent) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point input roots are not supported.' }
    }
    if (@(Get-ChildItem -LiteralPath $root -Recurse -Force -Attributes ReparsePoint).Count) { throw 'Reparse-point inputs are not supported.' }
}
if (Test-Path -LiteralPath $Destination) { throw 'A fresh destination is required; preserve prior evidence.' }
$existingParent = Split-Path $Destination -Parent
while (-not (Test-Path -LiteralPath $existingParent)) { $existingParent = Split-Path $existingParent -Parent }
for ($ancestor = Get-Item -LiteralPath $existingParent; $null -ne $ancestor; $ancestor = $ancestor.Parent) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point output ancestors are not supported.' }
}
if (-not (Test-Path -LiteralPath $FixturePath -PathType Container)) { throw 'Missing immutable synthetic fixture.' }
Assert-SeparateInputRoot $FixturePath
foreach ($path in @($LibrariesPath, $TemplatesPath)) { Assert-SeparateInputRoot $path }
if ($Lane -ne 'FreshImport') {
    foreach ($path in @($LibrariesPath, $TemplatesPath)) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Container)) { throw 'Existing offline libraries and templates are required.' }
    }
}
if ($Lane -eq 'PackageOnly') {
    foreach ($path in @($PayloadPath, $PayloadManifestPath)) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'PackageOnly requires explicit normalized payload and manifest.' }
    }
    foreach ($path in @($PayloadPath, $PayloadManifestPath)) { Assert-SeparateInputRoot (Split-Path ([IO.Path]::GetFullPath($path)) -Parent) }
}
if ($Lane -eq 'CompletedStoreReplay') {
    $raw = Join-Path $FixturePath 'raw'
    $manifest = Get-Content -LiteralPath (Join-Path $raw 'synthetic-manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.modelVersion -cne 'procedural-v1') { throw 'CompletedStoreReplay requires procedural synthetic inputs.' }
    foreach ($name in @('Machines_Current.json.gz', 'VulnContentDictionary.json.gz', 'VulnCurrentRefs.json.gz')) {
        if (-not (Test-Path -LiteralPath (Join-Path $raw $name) -PathType Leaf)) { throw "Missing canonical replay input: $name" }
    }
}
if ($Lane -eq 'FreshImport') {
    $snapshots = @(Get-ChildItem -LiteralPath (Join-Path $FixturePath 'snapshots') -Filter 'VulnExport_*.json.gz' -File)
    if ($snapshots.Count -eq 0) { throw 'FreshImport requires dated synthetic snapshots.' }
    $manifest = Get-Content -LiteralPath (Join-Path $FixturePath 'raw/synthetic-manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.modelVersion -cne 'procedural-v1') { throw 'FreshImport requires procedural synthetic inputs.' }
}
$null = New-Item -ItemType Directory -Path $Destination
function Invoke-WebRequest {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Offline measurement shim rejects network access in this script scope.')]
    param()
    throw 'Network disabled in offline measurement.'
}
function Invoke-RestMethod {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Offline measurement shim rejects network access in this script scope.')]
    param()
    throw 'Network disabled in offline measurement.'
}
$allocated = [GC]::GetTotalAllocatedBytes($true)
$collections = @(0..2 | ForEach-Object { [GC]::CollectionCount($_) })
$clock = [Diagnostics.Stopwatch]::StartNew()
if ($Lane -eq 'FreshImport') {
    if ($ProfileImport) {
    & (Join-Path $PSScriptRoot 'Invoke-LargeImportCoverage.ps1') -SourcePath $PSScriptRoot `
        -RawSyntheticOutputPath (Join-Path $FixturePath 'raw') -RawLiveOutputPath (Join-Path $FixturePath 'live') `
        -LegacySnapshotOutputPath (Join-Path $FixturePath 'snapshots') -LegacyImportValidationPath (Join-Path $Destination 'store') `
        -SkipSyntheticGeneration -SkipLiveShift -SkipLegacySnapshotGeneration -SkipRawValidation -SkipAzureReplayDatasetBuild -ProfileFreshImport
    }
    else {
        . (Join-Path $repoRoot 'build/Import-SharedHelpers.ps1')
        $store = Join-Path $Destination 'store'
        $null = New-Item -ItemType Directory -Path $store
        $snapshots | Copy-Item -Destination $store
        $importClock = [Diagnostics.Stopwatch]::StartNew()
        $importAllocated = [GC]::GetTotalAllocatedBytes($true)
        $result = Publish-VulnStoreFromBulkSnapshot -BasePath $store -RemoveSnapshotFiles:$false
        [ordered]@{seconds=$importClock.Elapsed.TotalSeconds; allocatedBytes=([GC]::GetTotalAllocatedBytes($true)-$importAllocated); result=$result} |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Destination 'import.json')
    }
}
else {
    $data = Join-Path $Destination 'data'
    $cache = Join-Path $data '.dashboard-cache/libraries'
    $null = New-Item -ItemType Directory -Path $cache -Force
    Copy-Item -Path (Join-Path $LibrariesPath '*.js') -Destination $cache
    if ($Lane -eq 'CompletedStoreReplay') {
        Get-ChildItem -LiteralPath (Join-Path $FixturePath 'raw') -File |
            Where-Object { $_.Name -notlike 'VulnExport_*' } | Copy-Item -Destination $data
    }
    $arguments = @{
        DirectoryPath = $data; ExportMachineData = $false; TemplatesPath = $TemplatesPath
        OutputPath = (Join-Path $Destination 'dashboard.html')
        DiagnosticPhaseLogPath = (Join-Path $Destination 'phases.tsv')
    }
    if ($Lane -eq 'CompletedStoreReplay') {
        $arguments.NormalizeOnly = $true
        $arguments.NormalizedPayloadOutputPath = Join-Path $Destination 'payload.json.gz'
        $arguments.NormalizedPayloadManifestOutputPath = Join-Path $Destination 'payload.manifest.json'
    }
    else {
        $arguments.PackageOnly = $true
        $arguments.NormalizedPayloadInputPath = $PayloadPath
        $arguments.NormalizedPayloadManifestInputPath = $PayloadManifestPath
        if ($Mode -eq 'Hosted') { $arguments.SplitAssets = $true } else { $arguments.DualPackage = $true }
    }
    & (Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1') @arguments
}
$clock.Stop()
[ordered]@{
    lane = $Lane; mode = $Mode; profiledImport = [bool]$ProfileImport; seconds = $clock.Elapsed.TotalSeconds
    allocatedBytes = ([GC]::GetTotalAllocatedBytes($true) - $allocated)
    gcCollections = @(0..2 | ForEach-Object { [GC]::CollectionCount($_) - $collections[$_] })
    processPeakWorkingSetBytes = [Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64
    runtime = $PSVersionTable.PSVersion.ToString(); dotnet = [Environment]::Version.ToString()
    sourceCommit = (& git -C $repoRoot rev-parse HEAD)
    generatorSha256 = (Get-FileHash (Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1')).Hash
    attribution = 'Whole inner cell; phase TSV counters are cumulative observations, not sampled peaks. ProfileImport includes parity twin and checks; unprofiled import.json excludes setup.'
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Destination 'cell.json') -Encoding utf8
