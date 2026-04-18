#Requires -Version 7.0

<#
.SYNOPSIS
    Exports compact NVD CVE enrichment for the current Defender dashboard dataset.

.DESCRIPTION
    Discovers the CVEs currently present in the local export set, fetches missing
    CVEs directly from the NVD CVE 2.0 API, and uses modified-date delta sync to
    refresh previously cached CVEs. The resulting compact cache is written to
    NvdCve_Current.json.gz in the exports directory and is consumed automatically
    by Generate-VulnerabilityDashboard.ps1 when present.

    The initial backfill path is intentionally targeted rather than a full NVD
    mirror. That keeps the cache focused on the dashboard's current CVE set.

.PARAMETER DirectoryPath
    Directory containing the canonical vulnerability exports. Defaults to .\exports.

.PARAMETER ApiKey
    Optional NVD API key. If omitted, the script will use $env:NVD_API_KEY when
    available.

.PARAMETER CveId
    Optional explicit CVE IDs to sync instead of discovering them from the local
    export set.

.PARAMETER ForceFullRefresh
    Ignore any existing cache contents and refetch the full target CVE set.

.PARAMETER SkipObservedWindowMerge
    Skip observed-window merge when discovering target CVEs from a synthetic dataset.

.PARAMETER ThrottleSeconds
    Delay between NVD requests. Defaults to 6 seconds to align with NVD guidance.

.PARAMETER CatalogBootstrapThreshold
    When the number of missing target CVEs is at least this value, the exporter
    will bootstrap from paged NVD CVE collection requests instead of starting
    with one targeted cveId request per missing CVE. Defaults to 250.

.PARAMETER RequestTimeoutSeconds
    Per-request timeout for NVD API calls. Defaults to 120 seconds so a single
    slow page request cannot block the export indefinitely.

.EXAMPLE
    .\Invoke-NvdCveExport.ps1

.EXAMPLE
    .\Invoke-NvdCveExport.ps1 -ApiKey $env:NVD_API_KEY

.EXAMPLE
    .\Invoke-NvdCveExport.ps1 -CveId CVE-2021-44228,CVE-2024-3094 -ForceFullRefresh
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if (-not (Test-Path -Path $_ -PathType Container)) {
            throw "Directory '$_' does not exist or is not accessible."
        }
        return $true
    })]
    [string]$DirectoryPath = '.\exports',

    [Parameter(Mandatory = $false)]
    [AllowEmptyString()]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [string[]]$CveId,

    [Parameter(Mandatory = $false)]
    [switch]$ForceFullRefresh,

    [Parameter(Mandatory = $false)]
    [switch]$SkipObservedWindowMerge,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 30)]
    [int]$ThrottleSeconds = 6,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1000000)]
    [int]$CatalogBootstrapThreshold = 250,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3600)]
    [int]$RequestTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'build\Import-SharedHelpers.ps1')

$resolvedApiKey = Resolve-NvdApiKey -RequestedApiKey $ApiKey
$headers = Get-NvdApiHeader -ResolvedApiKey $resolvedApiKey
$targetCveIds = Get-NvdTargetCveIdSet -BasePath $DirectoryPath -ExplicitCveIds $CveId -SkipObservedWindowMerge:$SkipObservedWindowMerge

if ($targetCveIds.Count -eq 0) {
    Write-Warning 'No target CVEs were discovered. Nothing to export.'
    exit 0
}

$existingDocument = if ($ForceFullRefresh) { $null } else { Read-NvdCacheDocument -BasePath $DirectoryPath }
$recordsByCve = @{}
if ($existingDocument -and $existingDocument.records) {
    foreach ($record in @($existingDocument.records)) {
        if ($null -eq $record) { continue }
        $cveId = [string]$record.CveId
        if (-not [string]::IsNullOrWhiteSpace($cveId)) {
            $recordsByCve[$cveId] = $record
        }
    }
}

$targetCveIdList = @($targetCveIds | Sort-Object)
$missingCveIds = @(Get-NvdMissingTargetCveIdList -TargetCveIds $targetCveIds -RecordsByCve $recordsByCve | Sort-Object)

Write-Host ("Target CVEs: {0}" -f $targetCveIds.Count) -ForegroundColor Cyan
Write-Host ("Cached CVEs: {0}" -f $recordsByCve.Count) -ForegroundColor Gray
Write-Host ("Missing CVEs: {0}" -f $missingCveIds.Count) -ForegroundColor Gray

if ([string]::IsNullOrWhiteSpace($resolvedApiKey)) {
    Write-Warning 'No NVD API key was provided. Targeted backfill may take longer and may be rate-limited more aggressively.'
}

$catalogBootstrapResult = [PSCustomObject]@{
    RequestCount = 0
    UpdatedCount = 0
    RemainingCount = $missingCveIds.Count
    TotalResults = 0
}

if ($missingCveIds.Count -ge $CatalogBootstrapThreshold) {
    $catalogBootstrapResult = Invoke-NvdCatalogBootstrap -Headers $headers -TargetCveIds $targetCveIds -RecordsByCve $recordsByCve -ThrottleSeconds $ThrottleSeconds -RequestTimeoutSeconds $RequestTimeoutSeconds
    $missingCveIds = @(Get-NvdMissingTargetCveIdList -TargetCveIds $targetCveIds -RecordsByCve $recordsByCve | Sort-Object)
    Write-Host ("Remaining CVEs after catalog bootstrap: {0}" -f $missingCveIds.Count) -ForegroundColor Gray
}

if ($missingCveIds.Count -gt 1 -and $ThrottleSeconds -gt 0) {
    $estimatedMinutes = [int][math]::Ceiling((($missingCveIds.Count - 1) * $ThrottleSeconds) / 60.0)
    Write-Warning ("Targeted NVD backfill still needs {0} cveId request(s). At {1}s throttle that remaining request path alone is at least about {2} minute(s)." -f $missingCveIds.Count, $ThrottleSeconds, $estimatedMinutes)
}

$targetedResult = if ($missingCveIds.Count -gt 0) {
    Invoke-NvdTargetedBackfill -Headers $headers -CveIds $missingCveIds -RecordsByCve $recordsByCve -ThrottleSeconds $ThrottleSeconds -RequestTimeoutSeconds $RequestTimeoutSeconds
}
else {
    [PSCustomObject]@{
        RequestCount = 0
        UpdatedCount = 0
        MissingCveIds = @()
    }
}

$syncStartUtc = $null
if (-not $ForceFullRefresh -and $existingDocument -and -not [string]::IsNullOrWhiteSpace([string]$existingDocument.lastModifiedEndUtc)) {
    try {
        $syncStartUtc = [datetimeoffset]$existingDocument.lastModifiedEndUtc
    }
    catch {
        Write-Warning "Ignoring invalid lastModifiedEndUtc in existing NVD cache: $($_.Exception.Message)"
    }
}

$syncEndUtc = [datetimeoffset]::UtcNow
$deltaResult = if ($null -ne $syncStartUtc) {
    Write-Host ("Refreshing cached CVEs using NVD last-modified delta from {0} to {1}..." -f $syncStartUtc.UtcDateTime.ToString('u').TrimEnd(), $syncEndUtc.UtcDateTime.ToString('u').TrimEnd()) -ForegroundColor Cyan
    Invoke-NvdDeltaSync -Headers $headers -TargetCveIds $targetCveIds -RecordsByCve $recordsByCve -StartUtc $syncStartUtc -EndUtc $syncEndUtc -ThrottleSeconds $ThrottleSeconds -RequestTimeoutSeconds $RequestTimeoutSeconds
}
else {
    [PSCustomObject]@{
        RequestCount = 0
        UpdatedCount = 0
    }
}

$finalRecords = [System.Collections.Generic.List[object]]::new()
foreach ($cveId in $targetCveIdList) {
    if ($recordsByCve.ContainsKey([string]$cveId)) {
        $finalRecords.Add($recordsByCve[[string]$cveId])
    }
}

$document = [PSCustomObject]@{
    version = 'nvd-cve-cache-v1'
    syncedAtUtc = $syncEndUtc.UtcDateTime.ToString('o')
    lastModifiedStartUtc = if ($null -ne $syncStartUtc) { $syncStartUtc.UtcDateTime.ToString('o') } else { $null }
    lastModifiedEndUtc = $syncEndUtc.UtcDateTime.ToString('o')
    targetCveCount = $targetCveIds.Count
    recordCount = $finalRecords.Count
    missingCveCount = [math]::Max(0, ($targetCveIds.Count - $finalRecords.Count))
    missingCveIdsSample = @($targetCveIdList | Where-Object { -not $recordsByCve.ContainsKey([string]$_) } | Select-Object -First 20)
    catalogBootstrapRequestCount = $catalogBootstrapResult.RequestCount
    targetedRequestCount = $targetedResult.RequestCount
    deltaRequestCount = $deltaResult.RequestCount
    records = @($finalRecords)
}

Write-NvdCacheDocument -BasePath $DirectoryPath -Document $document

$outputPath = Get-NvdCveCurrentPath -BasePath $DirectoryPath
Write-Host ("Wrote NVD cache: {0}" -f $outputPath) -ForegroundColor Green
Write-Host ("  Records written: {0}" -f $finalRecords.Count) -ForegroundColor Gray
Write-Host ("  Catalog bootstrap requests: {0}" -f $catalogBootstrapResult.RequestCount) -ForegroundColor Gray
Write-Host ("  Targeted requests: {0}" -f $targetedResult.RequestCount) -ForegroundColor Gray
Write-Host ("  Delta requests: {0}" -f $deltaResult.RequestCount) -ForegroundColor Gray
if ($targetedResult.MissingCveIds.Count -gt 0) {
    Write-Warning ("NVD returned no result for {0} targeted CVE(s). Sample: {1}" -f $targetedResult.MissingCveIds.Count, (($targetedResult.MissingCveIds | Select-Object -First 10) -join ', '))
}