#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DatasetPath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $false)][ValidateSet('RawReplay', 'Exact')][string]$Mode = 'RawReplay'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedDatasetPath = [System.IO.Path]::GetFullPath($DatasetPath)
if (-not (Test-Path -LiteralPath $resolvedDatasetPath -PathType Container)) { throw "Dataset path '$resolvedDatasetPath' was not found." }
$manifestPath = Join-Path $resolvedDatasetPath 'synthetic-manifest.json'
$manifest = if (Test-Path -LiteralPath $manifestPath -PathType Leaf) { Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 40 } else { $null }
$expectedByName = @{}
if ($null -ne $manifest -and $manifest.PSObject.Properties['artifacts']) {
    foreach ($artifact in @($manifest.artifacts)) { $expectedByName[[string]$artifact.name] = $artifact }
}

$selectedFiles = if ($Mode -eq 'RawReplay') {
    @(Get-ChildItem -LiteralPath $resolvedDatasetPath -File | Where-Object {
            $_.Name -match '^VulnExport_.+_\d{4}-\d{2}-\d{2}\.json\.gz$' -or
            $_.Name -in @('Machines_Current.json.gz', 'AdvancedHunting_Current.json.gz', 'NvdCve_Current.json.gz', 'synthetic-manifest.json', 'benchmark-dataset.json')
        })
}
else {
    @(Get-ChildItem -LiteralPath $resolvedDatasetPath -File | Where-Object {
            $_.Name -match '\.json(\.gz)?$' -and $_.Name -notlike '.synthetic-progress*' -and $_.Name -notlike '*validation-report*'
        })
}

if ($Mode -eq 'RawReplay' -and @($selectedFiles | Where-Object { $_.Name -match '^VulnExport_.+_\d{4}-\d{2}-\d{2}\.json\.gz$' }).Count -eq 0) {
    throw 'RawReplay requires at least one dated VulnExport group artifact.'
}

$records = foreach ($file in @($selectedFiles | Sort-Object Name)) {
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = $expectedByName[$file.Name]
    if ($null -ne $expected -and -not [string]::IsNullOrWhiteSpace([string]$expected.sha256) -and $hash -ne ([string]$expected.sha256).ToLowerInvariant()) {
        throw "Artifact '$($file.Name)' failed manifest SHA-256 validation."
    }
    [ordered]@{ name = $file.Name; path = $file.FullName; bytes = [int64]$file.Length; sha256 = $hash }
}

$totalBytes = 0L
foreach ($record in @($records)) { $totalBytes += [int64]$record['bytes'] }
$uploadManifest = [ordered]@{
    uploadManifestVersion = 1
    mode = $Mode
    datasetPath = $resolvedDatasetPath
    datasetId = if ($null -ne $manifest -and $manifest.PSObject.Properties['datasetId']) { [string]$manifest.datasetId } else { $null }
    parentDatasetId = if ($null -ne $manifest -and $manifest.PSObject.Properties['parentDatasetId']) { [string]$manifest.parentDatasetId } else { $null }
    overlayChainDepth = if ($null -ne $manifest -and $manifest.PSObject.Properties['overlayChainDepth']) { [int]$manifest.overlayChainDepth } else { 0 }
    generatedUtc = [datetime]::UtcNow.ToString('o')
    artifacts = @($records)
    totalBytes = $totalBytes
}

$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Path $resolvedOutputPath -Parent
if (-not (Test-Path -LiteralPath $outputDirectory)) { [void](New-Item -Path $outputDirectory -ItemType Directory -Force) }
$stagePath = $resolvedOutputPath + '.stage-' + [guid]::NewGuid().ToString('N')
try {
    [System.IO.File]::WriteAllText($stagePath, ($uploadManifest | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $stagePath -Destination $resolvedOutputPath -Force
}
finally { if (Test-Path -LiteralPath $stagePath) { Remove-Item -LiteralPath $stagePath -Force -ErrorAction SilentlyContinue } }

$uploadManifest
