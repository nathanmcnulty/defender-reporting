#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('DeviceCardinalityFirst', 'BalancedMediumHeavy', 'CurrentDensity')]
    [string]$Preset = 'BalancedMediumHeavy',

    [Parameter(Mandatory = $false)]
    [string]$SourcePath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports'),

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
    [double]$MinimumAvailableMemoryGB = 8,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 2048)]
    [int]$MinimumFreeDiskGB = 10,

    [Parameter(Mandatory = $false)]
    [int]$Seed = 20260322,

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

$resolvedSourcePath = [System.IO.Path]::GetFullPath($SourcePath)
$resolvedRawSyntheticOutputPath = [System.IO.Path]::GetFullPath($RawSyntheticOutputPath)
$resolvedRawLiveOutputPath = [System.IO.Path]::GetFullPath($RawLiveOutputPath)
$resolvedLegacySnapshotOutputPath = [System.IO.Path]::GetFullPath($LegacySnapshotOutputPath)
$resolvedAzureReplayOutputPath = [System.IO.Path]::GetFullPath($AzureReplayOutputPath)
$resolvedLegacyImportValidationPath = [System.IO.Path]::GetFullPath($LegacyImportValidationPath)

if (-not (Test-Path -LiteralPath $resolvedSourcePath -PathType Container)) {
    throw "Source path not found: $resolvedSourcePath"
}

if (-not $SkipSyntheticGeneration) {
    $generatorArgs = @{
        Preset = $Preset
        SourcePath = $resolvedSourcePath
        OutputPath = $resolvedRawSyntheticOutputPath
        Seed = $Seed
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
    $legacyImportValidationResult = Invoke-LegacySnapshotImportValidation -SnapshotSourcePath $resolvedLegacySnapshotOutputPath -ValidationPath $resolvedLegacyImportValidationPath -ResetValidationPath $Force.IsPresent
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
$workflowManifest | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $workflowManifestPath -Encoding utf8

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