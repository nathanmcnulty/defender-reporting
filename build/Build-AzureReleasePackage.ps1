#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

. (Join-Path -Path $PSScriptRoot -ChildPath 'private\AzureArtifactBuildTools.ps1')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$buildRoot = $PSScriptRoot
$repoRoot = Split-Path -Path $buildRoot -Parent
$azureBuildContext = Get-AzureArtifactBuildContext -BuildScriptRoot (Join-Path $buildRoot 'azure')
$azureProvisioningSourcePath = Join-Path $repoRoot 'src\powershell\Provisioning\Azure\AzureProvisioning.ps1'

if (-not $PSBoundParameters.ContainsKey('OutputPath')) {
    $defaultName = 'Azure-' + ([datetime]::UtcNow).ToString('yyMMdd') + '.zip'
    $OutputPath = Join-Path $repoRoot ('.local\local-reports\azure-release-package\' + $defaultName)
}

Write-Output 'Building Azure runbook artifact...'
& (Join-Path $buildRoot 'azure\Build-Runbook.ps1')

Write-Output 'Building Azure Function App artifact...'
$functionAppArtifactState = Initialize-AzureFunctionAppArtifactState -BuildContext $azureBuildContext

$requiredLeafPaths = @(
    Join-Path $repoRoot 'Setup-AzureResources.ps1'
    Join-Path $repoRoot 'azure\Invoke-DashboardPipeline.ps1'
    Join-Path $repoRoot 'azure\function-app\ExportAndGenerate\run.ps1'
    $azureProvisioningSourcePath
)

foreach ($path in $requiredLeafPaths) {
    Assert-BuildPath -Path $path -PathType Leaf
}

$requiredContainerPaths = @(
    Join-Path $repoRoot 'templates'
    Join-Path $repoRoot 'azure'
    Join-Path $repoRoot 'azure\function-app\Modules\Az.Accounts'
)

foreach ($path in $requiredContainerPaths) {
    Assert-BuildPath -Path $path -PathType Container
}

$sharedHelpersFingerprint = Read-PowerShellArtifactEmbeddedFingerprint -Path $azureBuildContext.SharedHelpersPath
if ([string]::IsNullOrWhiteSpace($sharedHelpersFingerprint)) {
    throw "Generated shared helpers '$($azureBuildContext.SharedHelpersPath)' are missing fingerprint metadata."
}
$runbookFingerprintState = Assert-AzureArtifactFingerprint -ArtifactPath $azureBuildContext.RunbookOutputPath -ExpectedFingerprint $sharedHelpersFingerprint -ArtifactDescription 'Azure Automation runbook artifact'
$functionAppEntryPointPath = $functionAppArtifactState.EntryPointPath
$functionAppFingerprintState = $functionAppArtifactState.EntryPointFingerprintState
$stagedModuleSummary = $functionAppArtifactState.ModuleSummary

Initialize-ParentDirectory -Path $OutputPath
if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
    Remove-Item -LiteralPath $OutputPath -Force
}

$packageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('azure-release-package-' + [guid]::NewGuid().ToString('N'))
$stagingRoot = Join-Path $packageRoot 'payload'

try {
    New-Item -Path $stagingRoot -ItemType Directory -Force | Out-Null
    Copy-Item -Path (Join-Path $repoRoot 'Setup-AzureResources.ps1') -Destination $stagingRoot -Force
    Copy-Item -Path (Join-Path $repoRoot 'templates') -Destination $stagingRoot -Recurse -Force
    Copy-Item -Path (Join-Path $repoRoot 'azure') -Destination $stagingRoot -Recurse -Force

    $stagedProvisioningHelperPath = Join-Path $stagingRoot 'azure\AzureProvisioning.ps1'
    Copy-Item -Path $azureProvisioningSourcePath -Destination $stagedProvisioningHelperPath -Force
    Assert-BuildPath -Path $stagedProvisioningHelperPath -PathType Leaf

    Compress-Archive -Path (Join-Path $stagingRoot '*') -DestinationPath $OutputPath -Force
}
finally {
    if (Test-Path -LiteralPath $packageRoot) {
        Remove-Item -LiteralPath $packageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$outputItem = Get-Item -LiteralPath $OutputPath
$manifestPath = Get-AzurePackageManifestPath -PackagePath $OutputPath
$packageManifest = [PSCustomObject]@{
    generatedOnUtc = [datetime]::UtcNow.ToString('o')
    packagePath = $outputItem.FullName
    packageSha256 = Get-FileContentSha256Hex -Path $outputItem.FullName
    packageSizeBytes = $outputItem.Length
    sharedHelpersFingerprint = $sharedHelpersFingerprint
    runbookFingerprint = $runbookFingerprintState.Fingerprint
    functionAppFingerprint = $functionAppFingerprintState.Fingerprint
    stagedAzAccountsModule = [PSCustomObject]@{
        version = $stagedModuleSummary.ModuleVersion
        bundledVersions = @($stagedModuleSummary.BundledVersions)
        fileCount = $stagedModuleSummary.FileCount
        manifestPath = $stagedModuleSummary.ManifestDisplayPath
        manifestPaths = @($stagedModuleSummary.BundledManifestPaths)
    }
    payloadFiles = @(
        [PSCustomObject]@{
            path = 'Setup-AzureResources.ps1'
            sha256 = Get-FileContentSha256Hex -Path (Join-Path $repoRoot 'Setup-AzureResources.ps1')
        }
        [PSCustomObject]@{
            path = 'azure/Invoke-DashboardPipeline.ps1'
            sha256 = Get-FileContentSha256Hex -Path $azureBuildContext.RunbookOutputPath
        }
        [PSCustomObject]@{
            path = 'azure/function-app/ExportAndGenerate/run.ps1'
            sha256 = Get-FileContentSha256Hex -Path $functionAppEntryPointPath
        }
        [PSCustomObject]@{
            path = 'src/powershell/Provisioning/Azure/AzureProvisioning.ps1'
            sha256 = Get-FileContentSha256Hex -Path $azureProvisioningSourcePath
        }
    )
}
Write-Utf8BomFile -Path $manifestPath -Content (($packageManifest | ConvertTo-Json -Depth 10) + [Environment]::NewLine)
Write-Output ("Created Azure release package: {0}" -f $outputItem.FullName)
Write-Output ("Package size: {0:N2} MB" -f ($outputItem.Length / 1MB))
Write-Output ("Shared helper fingerprint: {0}" -f $sharedHelpersFingerprint)
Write-Output ("Staged Az.Accounts module: v{0} ({1} files)" -f $stagedModuleSummary.ModuleVersion, $stagedModuleSummary.FileCount)
Write-Output ("Azure package manifest: {0}" -f $manifestPath)
