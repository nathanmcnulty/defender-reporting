Set-StrictMode -Version Latest

function Get-BenchmarkDatasetCatalogPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$RepoRoot = (Split-Path -Path $PSScriptRoot -Parent)
    )

    return (Join-Path $RepoRoot 'tests\benchmark-datasets.json')
}

function Import-BenchmarkDatasetCatalog {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Internal helper returns the full benchmark dataset catalog by design.')]
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$RepoRoot = (Split-Path -Path $PSScriptRoot -Parent)
    )

    $catalogPath = Get-BenchmarkDatasetCatalogPath -RepoRoot $RepoRoot
    if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
        throw "Benchmark dataset catalog not found: $catalogPath"
    }

    return @((Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json -Depth 20))
}

function Get-BenchmarkDatasetDefinition {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatasetId,

        [Parameter(Mandatory = $false)]
        [string]$RepoRoot = (Split-Path -Path $PSScriptRoot -Parent)
    )

    return @(
        Import-BenchmarkDatasetCatalog -RepoRoot $RepoRoot | Where-Object { [string]$_.id -eq $DatasetId }
    ) | Select-Object -First 1
}

function Resolve-BenchmarkDatasetSourcePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Definition,

        [Parameter(Mandatory = $false)]
        [string]$RepoRoot = (Split-Path -Path $PSScriptRoot -Parent)
    )

    $sourceRelativePath = [string]$Definition.sourceRelativePath
    if ([string]::IsNullOrWhiteSpace($sourceRelativePath)) {
        return (Join-Path $RepoRoot 'exports')
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $sourceRelativePath))
}

function Resolve-BenchmarkDatasetOutputPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        $Definition,

        [Parameter(Mandatory = $false)]
        [string]$RepoRoot = (Split-Path -Path $PSScriptRoot -Parent)
    )

    $outputRelativePath = [string]$Definition.outputRelativePath
    if ([string]::IsNullOrWhiteSpace($outputRelativePath)) {
        throw 'Benchmark dataset definition does not declare outputRelativePath.'
    }

    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $outputRelativePath))
}

function Get-BenchmarkDatasetMetadataPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatasetPath
    )

    return (Join-Path ([System.IO.Path]::GetFullPath($DatasetPath)) 'benchmark-dataset.json')
}

function Get-BenchmarkDatasetMetadata {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Metadata is a fixed benchmark sidecar concept in this repository and matches benchmark-dataset.json.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DatasetPath
    )

    $metadataPath = Get-BenchmarkDatasetMetadataPath -DatasetPath $DatasetPath
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        return $null
    }

    return (Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json -Depth 20)
}

function Test-BenchmarkDatasetDefinitionMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Definition,

        [Parameter(Mandatory = $true)]
        $Manifest
    )

    if ($null -eq $Manifest) {
        return $false
    }

    return (
        ([string]$Manifest.preset -eq [string]$Definition.preset) -and
        ([int]$Manifest.seed -eq [int]$Definition.seed) -and
        ([int]$Manifest.targetDeviceCount -eq [int]$Definition.targetDeviceCount) -and
        ([int]$Manifest.targetTotalVulnRows -eq [int]$Definition.targetTotalVulnRows) -and
        ((-not $Definition.PSObject.Properties['contentTemplateCount']) -or ([int]$Manifest.contentTemplateCount -eq [int]$Definition.contentTemplateCount)) -and
        ((-not $Definition.PSObject.Properties['modelVersion']) -or ([string]$Manifest.modelVersion -eq [string]$Definition.modelVersion)) -and
        ((-not $Definition.PSObject.Properties['snapshotCount']) -or ([int]$Manifest.snapshotCount -eq [int]$Definition.snapshotCount)) -and
        ((-not $Definition.PSObject.Properties['churnRate']) -or ([double]$Manifest.model.churnRate -eq [double]$Definition.churnRate)) -and
        ((-not $Definition.PSObject.Properties['optionalFieldSparsity']) -or ([double]$Manifest.model.optionalFieldSparsity -eq [double]$Definition.optionalFieldSparsity))
    )
}

function Find-BenchmarkDatasetDefinitionForManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Manifest,

        [Parameter(Mandatory = $false)]
        [string]$RepoRoot = (Split-Path -Path $PSScriptRoot -Parent)
    )

    foreach ($definition in @(Import-BenchmarkDatasetCatalog -RepoRoot $RepoRoot)) {
        if (Test-BenchmarkDatasetDefinitionMatch -Definition $definition -Manifest $Manifest) {
            return $definition
        }
    }

    return $null
}
