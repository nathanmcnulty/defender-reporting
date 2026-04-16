function Get-DashboardValidationFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Audit
    )

    $failures = [System.Collections.Generic.List[string]]::new()

    if (-not $Audit.RowComparison.Match) {
        $failures.Add("Dashboard row comparison failed. Missing=$($Audit.RowComparison.MissingCount) Extra=$($Audit.RowComparison.ExtraCount)")
    }

    if (($Audit.EnrichmentAudit.PublishedDateMismatchCount + $Audit.EnrichmentAudit.DescriptionMismatchCount + $Audit.EnrichmentAudit.EpssMismatchCount + $Audit.EnrichmentAudit.AffectedSoftwareMismatchCount) -gt 0) {
        $failures.Add('Dashboard enrichment fields do not match the source data.')
    }

    if (
        $Audit.PSObject.Properties['PayloadParity'] -and
        -not $Audit.PayloadParity.Match -and
        (-not $Audit.PSObject.Properties['SemanticParity'] -or -not $Audit.SemanticParity.Match)
    ) {
        $failures.Add('Dashboard payload does not match the cached normalized payload bytes or row count.')
    }

    foreach ($report in @($Audit.ReportComparisons | Where-Object { -not $_.Match })) {
        $failures.Add("Report comparison failed for $($report.Name).")
    }

    if ($Audit.PSObject.Properties['RegressionComparison'] -and -not $Audit.RegressionComparison.Match) {
        $failures.Add("Baseline audit comparison failed for $($Audit.RegressionComparison.BaselineAuditPath).")
    }

    if ($Audit.PSObject.Properties['BaselineDashboardCoverage'] -and -not $Audit.BaselineDashboardCoverage.ContainsAllBaselineRows) {
        $failures.Add("Baseline dashboard coverage failed for $($Audit.BaselineDashboardCoverage.BaselineHtmlPath).")
    }

    if ($Audit.LegacyMigrationAudit.Enabled) {
        if ($Audit.LegacyMigrationAudit.PSObject.Properties['Error'] -and -not [string]::IsNullOrWhiteSpace([string]$Audit.LegacyMigrationAudit.Error)) {
            $failures.Add("Legacy migration audit failed: $($Audit.LegacyMigrationAudit.Error)")
        }
        elseif ($Audit.LegacyMigrationAudit.ComparableToCanonical -and $Audit.LegacyMigrationAudit.PSObject.Properties['RowComparison'] -and -not $Audit.LegacyMigrationAudit.RowComparison.Match) {
            $failures.Add('Legacy migration current-row parity check failed.')
        }
    }

    if ($Audit.PSObject.Properties['LegacyFixtureRegression'] -and -not $Audit.LegacyFixtureRegression.Match) {
        $failures.Add('Legacy migration fixture regression failed.')
    }

    return @($failures)
}

function Write-DashboardAuditResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Audit,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AuditPath,

        [Parameter(Mandatory = $false)]
        [switch]$KeepDefaultAuditFile
    )

    $resolvedAuditPath = $AuditPath
    if ($KeepDefaultAuditFile -and [string]::IsNullOrWhiteSpace($resolvedAuditPath)) {
        $resolvedAuditPath = Join-Path $PSScriptRoot 'sample-reports\dashboard-audit.json'
    }

    if (-not [string]::IsNullOrWhiteSpace($resolvedAuditPath)) {
        $outputDirectory = Split-Path -Path $resolvedAuditPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
            [void](New-Item -Path $outputDirectory -ItemType Directory -Force)
        }

        $Audit | ConvertTo-Json -Depth 100 | Set-Content -Path $resolvedAuditPath -Encoding utf8
    }

    $Audit | ConvertTo-Json -Depth 20
}

function Invoke-DashboardValidation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath,

        [Parameter(Mandatory = $true)]
        [string]$ExportsPath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AuditPath,

        [Parameter(Mandatory = $false)]
        [switch]$KeepDefaultAuditFile,

        [Parameter(Mandatory = $false)]
        [string]$ResolvedBaselineAuditPath,

        [Parameter(Mandatory = $false)]
        [string]$ResolvedBaselineDashboardHtmlPath,

        [Parameter(Mandatory = $false)]
        [switch]$RunLegacyFixtureRegression,

        [Parameter(Mandatory = $false)]
        [string]$ResolvedLegacyFixturePath
    )

    Write-Host "`nRunning dashboard integrity audit..." -ForegroundColor Cyan
    $audit = Get-DashboardAuditResult -ResolvedHtmlPath $HtmlPath -ResolvedExportsPath $ExportsPath -ResolvedBaselineAuditPath $ResolvedBaselineAuditPath -ResolvedBaselineDashboardHtmlPath $ResolvedBaselineDashboardHtmlPath -RunLegacyFixtureRegression:$RunLegacyFixtureRegression -ResolvedLegacyFixturePath $ResolvedLegacyFixturePath
    Write-DashboardAuditResult -Audit $audit -AuditPath $AuditPath -KeepDefaultAuditFile:$KeepDefaultAuditFile
    $failures = @(Get-DashboardValidationFailure -Audit $audit)
    if ($failures.Count -gt 0) {
        throw ("Dashboard validation failed:`n - " + ($failures -join "`n - "))
    }

    Write-Host 'Dashboard validation passed.' -ForegroundColor Green
    return $audit
}
