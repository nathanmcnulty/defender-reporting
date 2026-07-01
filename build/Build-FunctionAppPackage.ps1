#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$MetadataPath
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'private\AzureArtifactBuildTools.ps1')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$azureBuildContext = Get-AzureArtifactBuildContext -BuildScriptRoot (Join-Path $PSScriptRoot 'azure')

if (-not $PSBoundParameters.ContainsKey('OutputPath')) {
    $OutputPath = Get-AzureFunctionAppPackageDefaultOutputPath -RepoRoot $repoRoot
}

if (-not $PSBoundParameters.ContainsKey('MetadataPath')) {
    $MetadataPath = Get-AzurePackageManifestPath -PackagePath $OutputPath
}

Write-Output 'Building Azure Function App deployment package...'
$functionAppArtifactState = Initialize-AzureFunctionAppArtifactState -BuildContext $azureBuildContext

Initialize-ParentDirectory -Path $OutputPath
Initialize-ParentDirectory -Path $MetadataPath
if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
    Remove-Item -LiteralPath $OutputPath -Force
}

if (Test-Path -LiteralPath $MetadataPath -PathType Leaf) {
    Remove-Item -LiteralPath $MetadataPath -Force
}

$packageRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('function-app-package-' + [guid]::NewGuid().ToString('N'))
$stagingRoot = Join-Path -Path $packageRoot -ChildPath 'payload'

try {
    New-Item -Path $stagingRoot -ItemType Directory -Force | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $azureBuildContext.FunctionAppRoot -Force -ErrorAction Stop) {
        Copy-Item -LiteralPath $item.FullName -Destination $stagingRoot -Recurse -Force
    }

    Compress-Archive -Path (Join-Path -Path $stagingRoot -ChildPath '*') -DestinationPath $OutputPath -Force
}
finally {
    if (Test-Path -LiteralPath $packageRoot) {
        Remove-Item -LiteralPath $packageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$outputItem = Get-Item -LiteralPath $OutputPath
$packageManifest = [PSCustomObject]@{
    generatedOnUtc = [datetime]::UtcNow.ToString('o')
    buildScript = 'build/Build-FunctionAppPackage.ps1'
    packagePath = $outputItem.FullName
    packageSha256 = Get-FileContentSha256Hex -Path $outputItem.FullName
    packageSizeBytes = $outputItem.Length
    sourcePath = 'azure/function-app'
    functionAppEntryPoint = 'azure/function-app/ExportAndGenerate/run.ps1'
    functionAppEntryPointSha256 = Get-FileContentSha256Hex -Path $functionAppArtifactState.EntryPointPath
    functionAppEntryPointFingerprint = $functionAppArtifactState.EntryPointFingerprintState.Fingerprint
    sharedHelpersFingerprint = $functionAppArtifactState.SharedHelpersFingerprint
    stagedAzAccountsModule = [PSCustomObject]@{
        version = $functionAppArtifactState.ModuleSummary.ModuleVersion
        bundledVersions = @($functionAppArtifactState.ModuleSummary.BundledVersions)
        fileCount = $functionAppArtifactState.ModuleSummary.FileCount
        manifestPath = $functionAppArtifactState.ModuleSummary.ManifestDisplayPath
        manifestPaths = @($functionAppArtifactState.ModuleSummary.BundledManifestPaths)
    }
}
Write-Utf8BomFile -Path $MetadataPath -Content (($packageManifest | ConvertTo-Json -Depth 10) + [Environment]::NewLine)

Write-Output ("Created Function App package: {0}" -f $outputItem.FullName)
Write-Output ("Package size: {0:N2} MB" -f ($outputItem.Length / 1MB))
Write-Output ("Function App fingerprint: {0}" -f $functionAppArtifactState.EntryPointFingerprintState.Fingerprint)
Write-Output ("Staged Az.Accounts module: v{0} ({1} files)" -f $functionAppArtifactState.ModuleSummary.ModuleVersion, $functionAppArtifactState.ModuleSummary.FileCount)
Write-Output ("Function App package manifest: {0}" -f $MetadataPath)
