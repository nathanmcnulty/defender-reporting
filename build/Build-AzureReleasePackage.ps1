#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$buildRoot = $PSScriptRoot
$repoRoot = Split-Path -Path $buildRoot -Parent

if (-not $PSBoundParameters.ContainsKey('OutputPath')) {
    $defaultName = 'Azure-' + ([datetime]::UtcNow).ToString('yyMMdd') + '.zip'
    $OutputPath = Join-Path $repoRoot ('.local\local-reports\azure-release-package\' + $defaultName)
}

function Initialize-ParentDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parentPath = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentPath) -and -not (Test-Path -LiteralPath $parentPath -PathType Container)) {
        New-Item -Path $parentPath -ItemType Directory -Force | Out-Null
    }
}

function Assert-RequiredPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Leaf', 'Container')]
        [string]$PathType
    )

    if (-not (Test-Path -LiteralPath $Path -PathType $PathType)) {
        throw "Required path not found: $Path"
    }
}

Write-Output 'Building Azure runbook artifact...'
& (Join-Path $buildRoot 'azure\Build-Runbook.ps1')

Write-Output 'Building Azure Function App artifact...'
& (Join-Path $buildRoot 'azure\Build-FunctionApp.ps1')

$requiredLeafPaths = @(
    Join-Path $repoRoot 'Setup-AzureResources.ps1'
    Join-Path $repoRoot 'azure\Invoke-DashboardPipeline.ps1'
    Join-Path $repoRoot 'azure\function-app\ExportAndGenerate\run.ps1'
)

foreach ($path in $requiredLeafPaths) {
    Assert-RequiredPath -Path $path -PathType Leaf
}

$requiredContainerPaths = @(
    Join-Path $repoRoot 'templates'
    Join-Path $repoRoot 'azure'
    Join-Path $repoRoot 'azure\function-app\Modules\Az.Accounts'
)

foreach ($path in $requiredContainerPaths) {
    Assert-RequiredPath -Path $path -PathType Container
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
