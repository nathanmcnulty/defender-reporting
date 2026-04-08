#Requires -Version 7.0

[CmdletBinding(DefaultParameterSetName = 'ExistingAzContext')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'GitHubOidc')]
    [ValidateNotNullOrEmpty()]
    [string]$AzureClientId,

    [Parameter(Mandatory = $true, ParameterSetName = 'GitHubOidc')]
    [ValidateNotNullOrEmpty()]
    [string]$AzureTenantId,

    [Parameter(Mandatory = $true, ParameterSetName = 'ExistingAzContext')]
    [switch]$UseExistingAzContext,

    [Parameter(Mandatory = $false)]
    [string]$ExportsPath,

    [Parameter(Mandatory = $false)]
    [string]$DashboardPath,

    [Parameter(Mandatory = $false)]
    [string]$ValidationOutputPath,

    [Parameter(Mandatory = $false)]
    [string]$ManifestOutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$UseRepositoryOutputPaths,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAdvancedHunting
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = $PSScriptRoot
$defaultOutputRoot = Join-Path $repoRoot '.local\local-reports\live-dashboard-dry-run'

function Resolve-RepoPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

if ($UseRepositoryOutputPaths) {
    if (-not $PSBoundParameters.ContainsKey('ExportsPath')) {
        $ExportsPath = Join-Path $repoRoot 'exports'
    }

    if (-not $PSBoundParameters.ContainsKey('DashboardPath')) {
        $DashboardPath = Join-Path $repoRoot 'VulnerabilityDashboard.html'
    }

    if (-not $PSBoundParameters.ContainsKey('ValidationOutputPath')) {
        $ValidationOutputPath = Join-Path $repoRoot 'dashboard-audit.json'
    }

    if (-not $PSBoundParameters.ContainsKey('ManifestOutputPath')) {
        $ManifestOutputPath = Join-Path $repoRoot 'dashboard-live-run-manifest.json'
    }
}
else {
    if (-not $PSBoundParameters.ContainsKey('ExportsPath')) {
        $ExportsPath = Join-Path $defaultOutputRoot 'exports'
    }

    if (-not $PSBoundParameters.ContainsKey('DashboardPath')) {
        $DashboardPath = Join-Path $defaultOutputRoot 'VulnerabilityDashboard.html'
    }

    if (-not $PSBoundParameters.ContainsKey('ValidationOutputPath')) {
        $ValidationOutputPath = Join-Path $defaultOutputRoot 'dashboard-audit.json'
    }

    if (-not $PSBoundParameters.ContainsKey('ManifestOutputPath')) {
        $ManifestOutputPath = Join-Path $defaultOutputRoot 'dashboard-live-run-manifest.json'
    }
}

$ExportsPath = Resolve-RepoPath -Path $ExportsPath
$DashboardPath = Resolve-RepoPath -Path $DashboardPath
$ValidationOutputPath = Resolve-RepoPath -Path $ValidationOutputPath
$ManifestOutputPath = Resolve-RepoPath -Path $ManifestOutputPath

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

function Resolve-AzureTenantId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantIdentifier
    )

    $tenantGuid = [guid]::Empty
    if ([guid]::TryParse($TenantIdentifier, [ref]$tenantGuid)) {
        return $tenantGuid.Guid
    }

    $openidConfigUri = "https://login.microsoftonline.com/$TenantIdentifier/v2.0/.well-known/openid-configuration"
    $openidConfig = Invoke-RestMethod -Uri $openidConfigUri -ErrorAction Stop
    $issuer = [string]$openidConfig.issuer
    $issuerMatch = [regex]::Match($issuer, 'https://login\.microsoftonline\.com/(?<tenantId>[0-9a-fA-F-]{36})/v2\.0/?$')
    if (-not $issuerMatch.Success) {
        throw "Unable to resolve tenant identifier '$TenantIdentifier' to a tenant id from issuer '$issuer'."
    }

    return $issuerMatch.Groups['tenantId'].Value
}

function Test-LastExitCodeFailed {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $exitCode = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction Ignore
    return ($null -ne $exitCode -and [int]$exitCode.Value -ne 0)
}

function Reset-LastExitCode {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Internal helper only resets the session LASTEXITCODE used by wrapper checks.')]
    [CmdletBinding()]
    param()

    Set-Variable -Name LASTEXITCODE -Scope Global -Value 0
}

function Connect-GitHubActionsFederatedAzAccount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    if (-not (Get-Command -Name Connect-AzAccount -ErrorAction Ignore)) {
        throw 'Connect-AzAccount is not available. Install Az.Accounts before running this script.'
    }

    if ([string]::IsNullOrWhiteSpace($env:ACTIONS_ID_TOKEN_REQUEST_TOKEN) -or [string]::IsNullOrWhiteSpace($env:ACTIONS_ID_TOKEN_REQUEST_URL)) {
        throw 'GitHub Actions OIDC environment variables are not available.'
    }

    Write-Output 'Connecting to Azure using GitHub Actions federated credentials...'
    $resolvedTenantId = Resolve-AzureTenantId -TenantIdentifier $TenantId
    $tokenResponse = Invoke-RestMethod -Uri ($env:ACTIONS_ID_TOKEN_REQUEST_URL + '&audience=api://AzureADTokenExchange') -Headers @{ Authorization = "Bearer $($env:ACTIONS_ID_TOKEN_REQUEST_TOKEN)" }
    Connect-AzAccount -ServicePrincipal -ApplicationId $ClientId -Tenant $resolvedTenantId -FederatedToken $tokenResponse.value | Out-Null
}

function Assert-AzContextAvailable {
    [CmdletBinding()]
    param()

    if (-not (Get-Command -Name Get-AzContext -ErrorAction Ignore)) {
        throw 'Get-AzContext is not available. Install Az.Accounts before running this script.'
    }

    $context = Get-AzContext
    if ($null -eq $context -or $null -eq $context.Account) {
        throw 'No Azure context is available. Run Connect-AzAccount first or use the GitHub OIDC parameter set.'
    }
}

function Get-DefenderApiAccessToken {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not (Get-Command -Name Get-AzAccessToken -ErrorAction Ignore)) {
        throw 'Get-AzAccessToken is not available. Install Az.Accounts before running this script.'
    }

    Write-Verbose 'Getting Microsoft Defender API access token...'
    $tokenResponse = Get-AzAccessToken -ResourceUrl 'https://api.securitycenter.microsoft.com' -AsSecureString
    $secureStringPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResponse.Token)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($secureStringPointer)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secureStringPointer)
    }
}

function Get-OutputFileDetail {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $item = Get-Item -LiteralPath $Path
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256
    return [PSCustomObject]@{
        path = $item.FullName
        length = [int64]$item.Length
        sha256 = $hash.Hash
        lastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')
    }
}

Initialize-ParentDirectory -Path (Join-Path $ExportsPath 'placeholder.txt')
Initialize-ParentDirectory -Path $DashboardPath
Initialize-ParentDirectory -Path $ValidationOutputPath
Initialize-ParentDirectory -Path $ManifestOutputPath

switch ($PSCmdlet.ParameterSetName) {
    'GitHubOidc' {
        Connect-GitHubActionsFederatedAzAccount -ClientId $AzureClientId -TenantId $AzureTenantId
    }
    'ExistingAzContext' {
        $null = $UseExistingAzContext
        Assert-AzContextAvailable
    }
}

$accessToken = Get-DefenderApiAccessToken

Write-Output 'Refreshing Defender exports...'
Reset-LastExitCode
& (Join-Path $repoRoot 'Invoke-VulnerabilityExport.ps1') -AccessToken $accessToken -OutputPath $ExportsPath -IncludeAdvancedHunting:(-not $SkipAdvancedHunting)
if (Test-LastExitCodeFailed) {
    throw 'Invoke-VulnerabilityExport.ps1 failed.'
}

Write-Output 'Generating and validating dashboard output...'
Reset-LastExitCode
& (Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1') -DirectoryPath $ExportsPath -OutputPath $DashboardPath -ExportMachineData:$false -Validate -ValidationOutputPath $ValidationOutputPath
if (Test-LastExitCodeFailed) {
    throw 'Generate-VulnerabilityDashboard.ps1 failed.'
}

if (-not (Test-Path -LiteralPath $DashboardPath -PathType Leaf)) {
    throw "Dashboard output was not created at '$DashboardPath'."
}

if (-not (Test-Path -LiteralPath $ValidationOutputPath -PathType Leaf)) {
    throw "Validation audit was not created at '$ValidationOutputPath'."
}

$exportFiles = @(
    Get-ChildItem -Path $ExportsPath -File -ErrorAction Stop |
        Sort-Object Name |
        ForEach-Object {
            Get-OutputFileDetail -Path $_.FullName
        }
)

$manifest = [ordered]@{
    generatedAtUtc = [datetime]::UtcNow.ToString('o')
    authenticationMode = $PSCmdlet.ParameterSetName
    includeAdvancedHunting = (-not $SkipAdvancedHunting)
    exportsPath = (Get-Item -LiteralPath $ExportsPath).FullName
    dashboardPath = $DashboardPath
    validationOutputPath = $ValidationOutputPath
    files = [ordered]@{
        dashboard = Get-OutputFileDetail -Path $DashboardPath
        validationAudit = Get-OutputFileDetail -Path $ValidationOutputPath
        exports = $exportFiles
    }
}

[System.IO.File]::WriteAllText(
    $ManifestOutputPath,
    ($manifest | ConvertTo-Json -Depth 8),
    [System.Text.UTF8Encoding]::new($true)
)

Write-Output "Live dashboard dry run completed successfully. Manifest written to $ManifestOutputPath"