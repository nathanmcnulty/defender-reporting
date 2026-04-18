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
$azureProvisioningSourcePath = Join-Path $repoRoot 'src\powershell\Provisioning\Azure\AzureProvisioning.ps1'

if (-not $PSBoundParameters.ContainsKey('OutputPath')) {
    $defaultName = 'Azure-' + ([datetime]::UtcNow).ToString('yyMMdd') + '.zip'
    $OutputPath = Join-Path $repoRoot ('.local\local-reports\azure-release-package\' + $defaultName)
}

Write-Output 'Building Azure runbook artifact...'
& (Join-Path $buildRoot 'azure\Build-Runbook.ps1')

Write-Output 'Building Azure Function App artifact...'
& (Join-Path $buildRoot 'azure\Build-FunctionApp.ps1')

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
Write-Output ("Created Azure release package: {0}" -f $outputItem.FullName)
Write-Output ("Package size: {0:N2} MB" -f ($outputItem.Length / 1MB))
