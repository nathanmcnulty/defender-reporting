[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$HtmlPath = (Join-Path $PSScriptRoot 'VulnerabilityDashboard.html'),

    [Parameter(Mandatory = $false)]
    [string]$ExportsPath = (Join-Path $PSScriptRoot 'exports'),

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
    [string]$LegacyFixturePath = (Join-Path $PSScriptRoot 'tests\fixtures\legacy-migration')
)

$ErrorActionPreference = 'Stop'

$generateScript = Join-Path $PSScriptRoot 'Generate-VulnerabilityDashboard.ps1'

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
