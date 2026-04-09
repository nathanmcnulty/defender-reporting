[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$HtmlPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'VulnerabilityDashboard.html'),

    [Parameter(Mandatory = $false)]
    [string]$ExportsPath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'exports'),

    [Parameter(Mandatory = $false)]
    [AllowEmptyString()]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$KeepAuditFile,

    [Parameter(Mandatory = $false)]
    [string]$BaselineAuditPath,

    [Parameter(Mandatory = $false)]
    [string]$BaselineDashboardHtmlPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeLegacyFixtureRegression,

    [Parameter(Mandatory = $false)]
    [string]$LegacyFixturePath = (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'tests\fixtures\legacy-migration')
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$generateScript = Join-Path $repoRoot 'Generate-VulnerabilityDashboard.ps1'

& $generateScript `
    -DirectoryPath $ExportsPath `
    -OutputPath $HtmlPath `
    -ExportMachineData:$false `
    -ValidateOnly `
    -ValidationOutputPath $OutputPath `
    -KeepValidationAuditFile:$KeepAuditFile `
    -BaselineAuditPath $BaselineAuditPath `
    -BaselineDashboardHtmlPath $BaselineDashboardHtmlPath `
    -IncludeLegacyFixtureRegression:$IncludeLegacyFixtureRegression `
    -LegacyFixturePath $LegacyFixturePath

exit $LASTEXITCODE
