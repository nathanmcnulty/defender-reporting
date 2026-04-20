#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DatasetId = 'benchmark-medium-v1',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0.5, 256.0)]
    [double]$MinimumAvailableMemoryGB = 3,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 2048)]
    [int]$MinimumFreeDiskGB = 10,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Import-BenchmarkDatasetCatalog.ps1')

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$definition = Get-BenchmarkDatasetDefinition -DatasetId $DatasetId -RepoRoot $repoRoot
if ($null -eq $definition) {
    throw "Benchmark dataset definition '$DatasetId' was not found."
}

$resolvedOutputPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    Resolve-BenchmarkDatasetOutputPath -Definition $definition -RepoRoot $repoRoot
}
else {
    [System.IO.Path]::GetFullPath($OutputPath)
}

$manifestPath = Join-Path $resolvedOutputPath 'synthetic-manifest.json'
$metadataPath = Get-BenchmarkDatasetMetadataPath -DatasetPath $resolvedOutputPath

if ((-not $Force) -and (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    $existingManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
    if (Test-BenchmarkDatasetDefinitionMatch -Definition $definition -Manifest $existingManifest) {
        if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
            $metadata = [ordered]@{
                id = [string]$definition.id
                description = [string]$definition.description
                preset = [string]$definition.preset
                seed = [int]$definition.seed
                targetDeviceCount = [int]$definition.targetDeviceCount
                targetTotalVulnRows = [int]$definition.targetTotalVulnRows
                sourcePath = Resolve-BenchmarkDatasetSourcePath -Definition $definition -RepoRoot $repoRoot
                datasetPath = $resolvedOutputPath
                generatedBy = 'New-BenchmarkDataset.ps1'
                generatedOnUtc = [datetime]::UtcNow.ToString('o')
                historyTags = @($definition.historyTags)
            }
            $metadata | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $metadataPath -Encoding utf8
        }

        Write-Host ('Benchmark dataset already present: {0}' -f $resolvedOutputPath) -ForegroundColor Green
        return
    }
}

$sourcePath = Resolve-BenchmarkDatasetSourcePath -Definition $definition -RepoRoot $repoRoot
$generatorScriptPath = Join-Path $repoRoot 'tests\Generate-SyntheticLargeExports.ps1'

if (-not (Test-Path -LiteralPath $generatorScriptPath -PathType Leaf)) {
    throw "Synthetic dataset generator not found: $generatorScriptPath"
}

if ((Test-Path -LiteralPath $resolvedOutputPath) -and $Force) {
    Remove-Item -LiteralPath $resolvedOutputPath -Recurse -Force -ErrorAction SilentlyContinue
}

& $generatorScriptPath `
    -Preset ([string]$definition.preset) `
    -SourcePath $sourcePath `
    -OutputPath $resolvedOutputPath `
    -TargetDeviceCount ([int]$definition.targetDeviceCount) `
    -TargetTotalVulnRows ([int]$definition.targetTotalVulnRows) `
    -Seed ([int]$definition.seed) `
    -MinimumAvailableMemoryGB $MinimumAvailableMemoryGB `
    -MinimumFreeDiskGB $MinimumFreeDiskGB `
    -CleanOutput

$metadata = [ordered]@{
    id = [string]$definition.id
    description = [string]$definition.description
    preset = [string]$definition.preset
    seed = [int]$definition.seed
    targetDeviceCount = [int]$definition.targetDeviceCount
    targetTotalVulnRows = [int]$definition.targetTotalVulnRows
    sourcePath = $sourcePath
    datasetPath = $resolvedOutputPath
    generatedBy = 'New-BenchmarkDataset.ps1'
    generatedOnUtc = [datetime]::UtcNow.ToString('o')
    historyTags = @($definition.historyTags)
}
$metadata | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $metadataPath -Encoding utf8

Write-Host ('Benchmark dataset ready: {0}' -f $resolvedOutputPath) -ForegroundColor Green