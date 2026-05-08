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
    [switch]$AllowLargeDataset,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Import-BenchmarkDatasetCatalog.ps1')

function Get-BenchmarkDatasetMetadataRecord {
    [CmdletBinding()]
    [OutputType([ordered])]
    param(
        [Parameter(Mandatory = $true)]
        $Definition,

        [Parameter(Mandatory = $true)]
        [string]$DatasetPath,

        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Manifest
    )

    $generatedOnUtc = if ($null -ne $Manifest -and $Manifest.PSObject.Properties['generatedOnUtc']) {
        $Manifest.generatedOnUtc
    }
    else {
        [datetime]::UtcNow.ToString('o')
    }

    $metadata = [ordered]@{
        id = [string]$Definition.id
        description = [string]$Definition.description
        preset = [string]$Definition.preset
        seed = [int]$Definition.seed
        targetDeviceCount = [int]$Definition.targetDeviceCount
        targetTotalVulnRows = [int]$Definition.targetTotalVulnRows
        sourcePath = $SourcePath
        datasetPath = $DatasetPath
        generatedBy = 'New-BenchmarkDataset.ps1'
        generatedOnUtc = $generatedOnUtc
        historyTags = @($Definition.historyTags)
    }

    if ($null -ne $Manifest) {
        foreach ($propertyName in @('contentTemplateCount', 'uniqueCveIdCount', 'normalizedCveLookupCount')) {
            $property = $Manifest.PSObject.Properties[$propertyName]
            if ($null -ne $property) {
                $metadata[$propertyName] = $property.Value
            }
        }
    }

    return $metadata
}

function Test-BenchmarkDatasetMetadataBreadthSupport {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Metadata,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Manifest
    )

    if ($null -eq $Metadata) {
        return $false
    }

    if (-not (Test-BenchmarkDatasetManifestBreadthSupport -Manifest $Manifest)) {
        return $true
    }

    foreach ($propertyName in @('contentTemplateCount', 'uniqueCveIdCount', 'normalizedCveLookupCount')) {
        if ($null -eq $Metadata.PSObject.Properties[$propertyName]) {
            return $false
        }
    }

    return $true
}

function Test-BenchmarkDatasetManifestBreadthSupport {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Manifest
    )

    if ($null -eq $Manifest) {
        return $false
    }

    foreach ($propertyName in @('contentTemplateCount', 'uniqueCveIdCount', 'normalizedCveLookupCount')) {
        if ($null -ne $Manifest.PSObject.Properties[$propertyName]) {
            return $true
        }
    }

    return $false
}

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
        $existingMetadata = if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
            Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json -Depth 20
        }
        else {
            $null
        }

        if (-not (Test-BenchmarkDatasetMetadataBreadthSupport -Metadata $existingMetadata -Manifest $existingManifest)) {
            $metadata = Get-BenchmarkDatasetMetadataRecord -Definition $definition -DatasetPath $resolvedOutputPath -SourcePath (Resolve-BenchmarkDatasetSourcePath -Definition $definition -RepoRoot $repoRoot) -Manifest $existingManifest
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
    -AllowLargeDataset:$AllowLargeDataset `
    -CleanOutput

$generatedManifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 20
$metadata = Get-BenchmarkDatasetMetadataRecord -Definition $definition -DatasetPath $resolvedOutputPath -SourcePath $sourcePath -Manifest $generatedManifest
$metadata | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $metadataPath -Encoding utf8

Write-Host ('Benchmark dataset ready: {0}' -f $resolvedOutputPath) -ForegroundColor Green
