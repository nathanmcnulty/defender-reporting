# Shared NVD export helpers used by local NVD cache sync and downstream
# enrichment consumers.

function Resolve-NvdApiKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$RequestedApiKey
    )

    if (-not [string]::IsNullOrWhiteSpace($RequestedApiKey)) {
        return $RequestedApiKey.Trim()
    }

    if (-not [string]::IsNullOrWhiteSpace($env:NVD_API_KEY)) {
        return $env:NVD_API_KEY.Trim()
    }

    return ''
}

function Get-NvdApiHeader {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ResolvedApiKey
    )

    $headers = @{
        Accept = 'application/json'
    }

    if (-not [string]::IsNullOrWhiteSpace($ResolvedApiKey)) {
        $headers.apiKey = $ResolvedApiKey
    }

    return $headers
}

function Format-NvdApiDate {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [datetimeoffset]$Value
    )

    return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function Invoke-NvdApiRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxTransientRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(100, 30000)]
        [int]$InitialTransientDelayMs = 1000,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3600)]
        [int]$TimeoutSeconds = 120
    )

    $attempt = 0
    $delayMs = $InitialTransientDelayMs

    while ($true) {
        try {
            return (Invoke-RestMethodWithRetry -Uri $Uri -Headers $Headers -Method Get -TimeoutSec $TimeoutSeconds)
        }
        catch {
            $attempt++
            $exceptionText = @(
                [string]$_.Exception.Message
                [string]$_.Exception.InnerException?.Message
            ) -join "`n"

            $isTransientTransportFailure = $exceptionText -match 'ResponseEnded|response ended prematurely|An error occurred while sending the request|The underlying connection was closed|The request was canceled|timed out'
            if (-not $isTransientTransportFailure -or $attempt -ge $MaxTransientRetries) {
                throw
            }

            Write-Warning ("Transient NVD transport failure (attempt {0}/{1}): {2}. Retrying in {3}s..." -f $attempt, $MaxTransientRetries, $_.Exception.Message, [math]::Round($delayMs / 1000, 1))
            Start-Sleep -Milliseconds $delayMs
            $delayMs = [int]($delayMs * 2)
        }
    }
}

function Get-NvdTargetCveIdSet {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $false)]
        [string[]]$ExplicitCveIds,

        [Parameter(Mandatory = $false)]
        [switch]$SkipObservedWindowMerge
    )

    $targetCveIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($value in @($ExplicitCveIds)) {
        $cveId = [string]$value
        if (-not [string]::IsNullOrWhiteSpace($cveId)) {
            [void]$targetCveIds.Add($cveId.Trim())
        }
    }

    if ($targetCveIds.Count -gt 0) {
        return (, $targetCveIds)
    }

    Write-Host 'Discovering target CVEs from local exports...' -ForegroundColor Cyan
    $processedCount = 0
    Get-NormalizationSourceRows -DataPath $BasePath -SkipObservedWindowMerge:$SkipObservedWindowMerge | ForEach-Object {
        $row = $_
        $cveId = [string]$row.PSObject.Properties['CveId']?.Value
        if (-not [string]::IsNullOrWhiteSpace($cveId)) {
            [void]$targetCveIds.Add($cveId)
        }

        $processedCount++
        if (($processedCount % 250000) -eq 0) {
            Write-Information ("  Indexed CVEs from {0} source row(s)..." -f $processedCount) -InformationAction Continue
        }
    }

    return (, $targetCveIds)
}

function Get-NvdEnglishDescription {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Descriptions
    )

    foreach ($description in @($Descriptions)) {
        if ($null -eq $description) { continue }
        $lang = [string](Get-NvdObjectPropertyValue -InputObject $description -PropertyName 'lang')
        $value = [string](Get-NvdObjectPropertyValue -InputObject $description -PropertyName 'value')
        if ($lang -eq 'en' -and -not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    foreach ($description in @($Descriptions)) {
        if ($null -eq $description) { continue }
        $value = [string](Get-NvdObjectPropertyValue -InputObject $description -PropertyName 'value')
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value
        }
    }

    return $null
}

function Get-NvdWeaknessList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Weaknesses
    )

    $values = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($weakness in @($Weaknesses)) {
        foreach ($description in @(Get-NvdObjectPropertyValue -InputObject $weakness -PropertyName 'description')) {
            $text = [string](Get-NvdObjectPropertyValue -InputObject $description -PropertyName 'value')
            if (-not [string]::IsNullOrWhiteSpace($text) -and $seen.Add($text)) {
                $values.Add($text)
            }
        }
    }

    if ($values.Count -eq 0) {
        return $null
    }

    return [string[]]$values.ToArray()
}

function Get-NvdObjectPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($PropertyName)) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Get-NvdPreferredMetric {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Metrics
    )

    if ($null -eq $Metrics) {
        return $null
    }

    foreach ($propertyName in @('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2')) {
        $property = $Metrics.PSObject.Properties[$propertyName]
        if ($null -eq $property) {
            continue
        }

        $candidates = @($property.Value | Where-Object { $null -ne $_ })
        if ($candidates.Count -eq 0) {
            continue
        }

        $primary = $candidates | Where-Object { [string]$_.type -eq 'Primary' } | Select-Object -First 1
        if ($null -ne $primary) {
            return $primary
        }

        return $candidates[0]
    }

    return $null
}

function Convert-NvdVulnerabilityToRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        $Vulnerability
    )

    $cve = Get-NvdObjectPropertyValue -InputObject $Vulnerability -PropertyName 'cve'
    $cveId = [string](Get-NvdObjectPropertyValue -InputObject $cve -PropertyName 'id')
    if ($null -eq $cve -or [string]::IsNullOrWhiteSpace($cveId)) {
        return $null
    }

    $metric = Get-NvdPreferredMetric -Metrics (Get-NvdObjectPropertyValue -InputObject $cve -PropertyName 'metrics')
    $cvssData = if ($metric) { Get-NvdObjectPropertyValue -InputObject $metric -PropertyName 'cvssData' } else { $null }
    $weaknesses = Get-NvdWeaknessList -Weaknesses (Get-NvdObjectPropertyValue -InputObject $cve -PropertyName 'weaknesses')
    $baseScore = if ($cvssData) {
        Get-NvdObjectPropertyValue -InputObject $cvssData -PropertyName 'baseScore'
    }
    else {
        Get-NvdObjectPropertyValue -InputObject $metric -PropertyName 'baseScore'
    }
    $baseSeverity = if ($cvssData) {
        [string](Get-NvdObjectPropertyValue -InputObject $cvssData -PropertyName 'baseSeverity')
    }
    else {
        [string](Get-NvdObjectPropertyValue -InputObject $metric -PropertyName 'baseSeverity')
    }

    return [PSCustomObject]@{
        CveId = $cveId
        PublishedDate = Convert-ToYmdDate -DateValue (Get-NvdObjectPropertyValue -InputObject $cve -PropertyName 'published')
        LastModifiedDate = Convert-ToYmdDate -DateValue (Get-NvdObjectPropertyValue -InputObject $cve -PropertyName 'lastModified')
        VulnerabilityDescription = Get-NvdEnglishDescription -Descriptions (Get-NvdObjectPropertyValue -InputObject $cve -PropertyName 'descriptions')
        BaseScore = $baseScore
        BaseSeverity = $baseSeverity
        Vector = if ($cvssData) { [string](Get-NvdObjectPropertyValue -InputObject $cvssData -PropertyName 'vectorString') } else { $null }
        CisaExploitAdd = Convert-ToYmdDate -DateValue (Get-NvdObjectPropertyValue -InputObject $cve -PropertyName 'cisaExploitAdd')
        CisaActionDue = Convert-ToYmdDate -DateValue (Get-NvdObjectPropertyValue -InputObject $cve -PropertyName 'cisaActionDue')
        CisaRequiredAction = if ([string]::IsNullOrWhiteSpace([string](Get-NvdObjectPropertyValue -InputObject $cve -PropertyName 'cisaRequiredAction'))) { $null } else { [string](Get-NvdObjectPropertyValue -InputObject $cve -PropertyName 'cisaRequiredAction') }
        Weaknesses = $weaknesses
    }
}

function Read-NvdCacheDocument {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    $currentPath = Get-NvdCveCurrentPath -BasePath $BasePath
    if (-not (Test-Path -LiteralPath $currentPath -PathType Leaf)) {
        return $null
    }

    $json = Read-GzipTextFile -Path $currentPath
    if ([string]::IsNullOrWhiteSpace($json)) {
        return $null
    }

    return ($json | ConvertFrom-Json -Depth 100)
}

function Write-NvdCacheDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Document
    )

    $documentToWrite = $Document

    Invoke-WithStoreLock -BasePath $BasePath -StoreName 'nvdcve' -ScriptBlock {
        Restore-StoreTransaction -BasePath $BasePath -StoreName 'nvdcve'

        $currentPath = Get-NvdCveCurrentPath -BasePath $BasePath
        $stageRoot = Join-Path $BasePath ('.nvdcve-store-staging-' + [guid]::NewGuid().ToString('N'))
        [void](New-Item -Path $stageRoot -ItemType Directory -Force)

        try {
            $stagedCurrentPath = Join-Path $stageRoot (Split-Path -Leaf $currentPath)
            $json = $documentToWrite | ConvertTo-Json -Compress -Depth 100
            Write-GzipTextFile -Path $stagedCurrentPath -Content $json
            Publish-StoreFilesTransactional -BasePath $BasePath -StoreName 'nvdcve' -Files @([PSCustomObject]@{
                StagePath = $stagedCurrentPath
                TargetPath = $currentPath
            })
        }
        finally {
            if (Test-Path -LiteralPath $stageRoot) {
                Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    } | Out-Null
}

function Invoke-NvdTargetedBackfill {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string[]]$CveIds,

        [Parameter(Mandatory = $true)]
        [hashtable]$RecordsByCve,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$ThrottleSeconds = 6,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3600)]
        [int]$RequestTimeoutSeconds = 120
    )

    $requestCount = 0
    $updatedCount = 0
    $missing = [System.Collections.Generic.List[string]]::new()
    $baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    for ($index = 0; $index -lt $CveIds.Count; $index++) {
        $cveId = [string]$CveIds[$index]
        if ([string]::IsNullOrWhiteSpace($cveId)) {
            continue
        }

        $uri = $baseUrl + '?cveId=' + [System.Uri]::EscapeDataString($cveId)
        $response = Invoke-NvdApiRequest -Headers $Headers -Uri $uri -TimeoutSeconds $RequestTimeoutSeconds
        $requestCount++
        $vulnerabilities = @($response.vulnerabilities | Where-Object { $null -ne $_ })
        if ($vulnerabilities.Count -eq 0) {
            $missing.Add($cveId)
        }
        else {
            $record = Convert-NvdVulnerabilityToRecord -Vulnerability $vulnerabilities[0]
            if ($null -ne $record) {
                $RecordsByCve[[string]$record.CveId] = $record
                $updatedCount++
            }
        }

        if (((($index + 1) % 25) -eq 0) -or (($index + 1) -eq $CveIds.Count)) {
            Write-Information ("  Targeted NVD backfill: {0}/{1} CVE(s) processed..." -f ($index + 1), $CveIds.Count) -InformationAction Continue
        }

        if ($ThrottleSeconds -gt 0 -and ($index + 1) -lt $CveIds.Count) {
            Start-Sleep -Seconds $ThrottleSeconds
        }
    }

    return [PSCustomObject]@{
        RequestCount = $requestCount
        UpdatedCount = $updatedCount
        MissingCveIds = @($missing)
    }
}

function Get-NvdMissingTargetCveIdList {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$TargetCveIds,

        [Parameter(Mandatory = $true)]
        [hashtable]$RecordsByCve
    )

    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($targetCveId in $TargetCveIds) {
        $cveId = [string]$targetCveId
        if (-not $RecordsByCve.ContainsKey($cveId)) {
            $missing.Add($cveId)
        }
    }

    return [string[]]$missing.ToArray()
}

function Invoke-NvdCatalogBootstrap {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$TargetCveIds,

        [Parameter(Mandatory = $true)]
        [hashtable]$RecordsByCve,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$ThrottleSeconds = 6,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 2000)]
        [int]$ResultsPerPage = 2000,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3600)]
        [int]$RequestTimeoutSeconds = 120
    )

    $remainingTargets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($targetCveId in $TargetCveIds) {
        $cveId = [string]$targetCveId
        if (-not $RecordsByCve.ContainsKey($cveId)) {
            [void]$remainingTargets.Add($cveId)
        }
    }

    if ($remainingTargets.Count -eq 0) {
        return [PSCustomObject]@{
            RequestCount = 0
            UpdatedCount = 0
            RemainingCount = 0
            TotalResults = 0
        }
    }

    Write-Host 'Cold-start bootstrap: reverse-scanning newest NVD catalog pages until the missing target CVEs are found...' -ForegroundColor Cyan

    $baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    $requestCount = 0
    $pageRequestCount = 0
    $updatedCount = 0
    $totalResults = 0
    $totalPages = 0

    $metadataUri = $baseUrl + '?resultsPerPage=1&startIndex=0'
    $metadataResponse = Invoke-NvdApiRequest -Headers $Headers -Uri $metadataUri -TimeoutSeconds $RequestTimeoutSeconds
    $requestCount++
    $totalResults = [int]$metadataResponse.totalResults
    $totalPages = [int][math]::Ceiling($totalResults / [double]$ResultsPerPage)
    $startIndex = [int]([math]::Floor(([math]::Max(0, $totalResults - 1)) / [double]$ResultsPerPage) * $ResultsPerPage)

    Write-Information ("  Missing target CVEs before bootstrap: {0}. The full catalog is about {1} page(s) at {2} result(s) per page; the scan stops early once every missing target CVE is found." -f $remainingTargets.Count, $totalPages, $ResultsPerPage) -InformationAction Continue
    if ($ThrottleSeconds -gt 0) {
        $estimatedMinutes = [int][math]::Ceiling((([math]::Max(0, $totalPages - 1)) * $ThrottleSeconds) / 60.0)
        Write-Information ("  Worst-case full-catalog scan at {0}s throttle would take about {1} minute(s), but most runs should stop earlier." -f $ThrottleSeconds, $estimatedMinutes) -InformationAction Continue
    }

    do {
        $uri = $baseUrl + '?' + (@(
                'resultsPerPage=' + $ResultsPerPage
                'startIndex=' + $startIndex
            ) -join '&')

        $response = Invoke-NvdApiRequest -Headers $Headers -Uri $uri -TimeoutSeconds $RequestTimeoutSeconds
        $requestCount++
        $pageRequestCount++

        $vulnerabilities = @($response.vulnerabilities | Where-Object { $null -ne $_ })
        foreach ($vulnerability in $vulnerabilities) {
            $record = Convert-NvdVulnerabilityToRecord -Vulnerability $vulnerability
            if ($null -eq $record) {
                continue
            }

            $recordCveId = [string]$record.CveId
            if (-not $remainingTargets.Contains($recordCveId)) {
                continue
            }

            $RecordsByCve[$recordCveId] = $record
            if ($remainingTargets.Remove($recordCveId)) {
                $updatedCount++
            }
        }

        if ((($pageRequestCount % 5) -eq 0) -or ($remainingTargets.Count -eq 0)) {
            $catalogPageNumber = if ($totalPages -gt 0) { ([int][math]::Floor($startIndex / [double]$ResultsPerPage) + 1) } else { $pageRequestCount }
            $scannedPercent = if ($totalPages -gt 0) { [int][math]::Round(($pageRequestCount / [double]$totalPages) * 100) } else { 100 }
            Write-Information ("  Catalog bootstrap progress: scanned {0}/{1} page(s) ({2}% of worst-case path); current catalog page {3}; matched {4} target CVE(s); remaining {5}." -f $pageRequestCount, $totalPages, $scannedPercent, $catalogPageNumber, $updatedCount, $remainingTargets.Count) -InformationAction Continue
        }

        if ($remainingTargets.Count -eq 0) {
            break
        }

        if ($startIndex -le 0) {
            break
        }

        $startIndex = [math]::Max(0, ($startIndex - $ResultsPerPage))

        if ($ThrottleSeconds -gt 0) {
            Start-Sleep -Seconds $ThrottleSeconds
        }
    } while ($true)

    return [PSCustomObject]@{
        RequestCount = $requestCount
        UpdatedCount = $updatedCount
        RemainingCount = $remainingTargets.Count
        TotalResults = $totalResults
    }
}

function Invoke-NvdDeltaSync {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$TargetCveIds,

        [Parameter(Mandatory = $true)]
        [hashtable]$RecordsByCve,

        [Parameter(Mandatory = $true)]
        [datetimeoffset]$StartUtc,

        [Parameter(Mandatory = $true)]
        [datetimeoffset]$EndUtc,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 30)]
        [int]$ThrottleSeconds = 6,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3600)]
        [int]$RequestTimeoutSeconds = 120
    )

    if ($StartUtc -ge $EndUtc) {
        return [PSCustomObject]@{
            RequestCount = 0
            UpdatedCount = 0
        }
    }

    $baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    $requestCount = 0
    $updatedCount = 0
    $startIndex = 0
    do {
        $uri = $baseUrl + '?' + (
            @(
                'lastModStartDate=' + [System.Uri]::EscapeDataString((Format-NvdApiDate -Value $StartUtc))
                'lastModEndDate=' + [System.Uri]::EscapeDataString((Format-NvdApiDate -Value $EndUtc))
                'startIndex=' + $startIndex
            ) -join '&'
        )

        $response = Invoke-NvdApiRequest -Headers $Headers -Uri $uri -TimeoutSeconds $RequestTimeoutSeconds
        $requestCount++
        $vulnerabilities = @($response.vulnerabilities | Where-Object { $null -ne $_ })
        foreach ($vulnerability in $vulnerabilities) {
            $record = Convert-NvdVulnerabilityToRecord -Vulnerability $vulnerability
            if ($null -eq $record) {
                continue
            }

            if ($TargetCveIds.Contains([string]$record.CveId) -or $RecordsByCve.ContainsKey([string]$record.CveId)) {
                $RecordsByCve[[string]$record.CveId] = $record
                $updatedCount++
            }
        }

        $resultsPerPage = [int]$response.resultsPerPage
        if ($resultsPerPage -le 0) {
            break
        }

        $startIndex += $resultsPerPage
        if ($startIndex -lt [int]$response.totalResults) {
            if ($ThrottleSeconds -gt 0) {
                Start-Sleep -Seconds $ThrottleSeconds
            }
        }
        else {
            break
        }
    } while ($true)

    return [PSCustomObject]@{
        RequestCount = $requestCount
        UpdatedCount = $updatedCount
    }
}